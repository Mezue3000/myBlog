# import dependencies
from app.cores.logging import get_logger
from app.models import Tenant, User, StripeCheckoutSession, BillingAudit
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
from fastapi import HTTPException, status
from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy.orm import selectinload
import stripe
from app.utility.stripe.helpers import get_active_plan, ensure_no_active_subscription, ensure_stripe_customer, expire_open_checkout_sessions, ensure_plan_compatible_with_tenant, update_webhook_status
from asyncio import to_thread
from app.services.stripe.idempotency import register_webhook_event, DuplicateWebhookEvent
from app.utility.tenant.tenant_router import validate_tenant





# initialize logging
logger = get_logger(__name__)



# function to create checkout session
async def create_checkout_session(
    tenant: Tenant,
    current_user: User,
    plan_id: int,
    db: AsyncSession
) -> str:

    try:

        plan = await get_active_plan(plan_id=plan_id, db=db)
        
        await ensure_plan_compatible_with_tenant(tenant=tenant, plan=plan)
          
        await ensure_no_active_subscription(tenant=tenant, db=db)

        customer_id = await ensure_stripe_customer(
            tenant=tenant,
            current_user=current_user,
            db=db
        )

        await expire_open_checkout_sessions(tenant=tenant, db=db)
        
        # since my service is already async, offload the blocking Stripe call to a worker thread.
        session =  await to_thread(
            stripe.checkout.Session.create,
            customer=customer_id,
            mode="subscription",
            client_reference_id=str(tenant.tenant_id),
            line_items=[
                {
                    "price": plan.stripe_price_id,
                    "quantity": 1
                }
            ],
            success_url="http://localhost:8000/billing/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url="http://localhost:8000/billing/cancel",
            metadata={
                "tenant_id": str(tenant.tenant_id),
                "plan_id": str(plan.plan_id),
                "tenant_type": tenant.tenant_type,
                "billing_interval": plan.billing_interval
            },
        )

        checkout = StripeCheckoutSession(
            tenant_id=tenant.tenant_id,
            plan_id=plan.plan_id,
            stripe_session_id=session.id,
            stripe_customer_id=session.customer,
            status=session.status,
            payment_status=session.payment_status,
            # convert stripe datetime to python datetime
            expires_at=datetime.fromtimestamp(session.expires_at, tz=timezone.utc)
        )

        db.add(checkout)
        await db.flush()

        logger.info(
            "Checkout session %s created for tenant %s.",
            session.id,
            tenant.tenant_id
        )

        return session.url

    except HTTPException:
        raise

    except stripe.error.StripeError:
        logger.exception(
            "Stripe checkout creation failed for tenant %s.",
            tenant.tenant_id
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to create Stripe Checkout session."
        )

    except Exception:
        await db.rollback()
        logger.exception(
            "Unexpected checkout creation error for tenant %s.",
            tenant.tenant_id
        )
        raise





# function to handle stripe checkout session completion 
async def handle_checkout_completed(
    *,
    event: dict,
    db: AsyncSession
) -> None:
    """
    Handle Stripe checkout.session.completed.

    This event ONLY confirms that Checkout completed.

    Subscription activation happens in invoice.paid.
    """

    # register webhook
    try:

        await register_webhook_event(event=event, db=db)

    except DuplicateWebhookEvent:
        logger.info(
            "Duplicate Stripe event '%s'.",
            event["id"]
        )

        return

    try:

        session = event["data"]["object"]

        # validate payload
        if session.get("mode") != "subscription":
            raise ValueError("Unexpected checkout mode.")
        
        tenant_id = session.get("client_reference_id")

        stripe_customer_id = session.get("customer")

        stripe_session_id = session.get("id")

        stripe_subscription_id = session.get("subscription")

        if not all(
            [
                tenant_id,
                stripe_customer_id,
                stripe_session_id,
                stripe_subscription_id
            ]
        ):
            raise ValueError("Incomplete checkout session.")

        # lock tenant
        statement = (
            select(Tenant)
            .where(Tenant.tenant_id == UUID(tenant_id))
            .options(selectinload(Tenant.plan))
            .with_for_update()
        )

        result = await db.exec(statement)

        tenant = result.first()
        
        validate_tenant(tenant=tenant)
        
        # verify customer
        if tenant.stripe_customer_id != stripe_customer_id:
            logger.warning(
                "Stripe customer mismatch for tenant %s.",
                tenant.tenant_id
            )

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Stripe customer mismatch."
            )

        # lock checkout session
        statement = (
            select(StripeCheckoutSession)
            .where(StripeCheckoutSession.stripe_session_id == stripe_session_id)
            .with_for_update()
        )

        result = await db.exec(statement)

        checkout = result.first()

        if checkout is None:
            raise ValueError("Checkout session not found.")

        # update checkout
        checkout.status = "complete"

        db.add(checkout)

        # billing audit
        db.add(
            BillingAudit(
                tenant_id=tenant.tenant_id,
                event_type="checkout.session.completed",
                stripe_event_id=event["id"]
            )
        )
        
        # mark processed
        await update_webhook_status(
            event_id=event["id"],
            processed=True,
            db=db
        )

        await db.commit()

        logger.info(
            "Checkout completed for tenant %s.",
            tenant.tenant_id
        )

    except Exception as exc:
        await db.rollback()
        await update_webhook_status(
            event_id=event["id"],
            processed=False,
            error=exc,
            db=db
        )
        
        await db.commit()
        logger.exception("Failed processing checkout.session.completed.")

        raise
