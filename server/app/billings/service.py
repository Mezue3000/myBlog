# import dependencies
from app.cores.logging import get_logger
from app.models import Tenant, Subscription, Plan, CreditLog, User, StripeCheckoutSession, BillingAudit
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
from fastapi import HTTPException, status
from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy.orm import selectinload
import stripe
from app.billings.helpers import get_active_plan, ensure_no_active_subscription, ensure_stripe_customer, expire_open_checkout_sessions, ensure_plan_compatible_with_tenant
from asyncio import to_thread
from app.billings.helpers import register_webhook_event, update_webhook_status, DuplicateWebhookEvent
from app.utility.tenant.tenant_router import validate_tenant





# initialize logging
logger = get_logger(__name__)



# function to reset credit
async def reset_credits_if_needed(tenant: Tenant, db: AsyncSession) -> None:
    """
    Resets a tenant's credits when a new billing period begins.

    This function:
    - finds the active subscription.
    - loads the associated plan.
    - checks whether a credit reset is due.
    - restores credits.
    - creates a credit-log entry.
    - flushes changes only (no commit).
    """

    # active subscription
    statement = (
        select(Subscription)
        .where(
            Subscription.tenant_id == tenant.tenant_id,
            Subscription.status == "active"
        )
    )

    result = await db.exec(statement)
    subscription = result.first()

    if subscription is None:
        return

    # load plan
    statement = (
        select(Plan)
        .where(Plan.plan_id == subscription.plan_id, Plan.is_active.is_(True))
    )

    result = await db.exec(statement)
    plan = result.first()

    if plan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Subscription plan not found."
        )

    if tenant.next_credits_reset_at is None:
        should_reset = True

    elif subscription.current_period_start is None:
        should_reset = False

    else:
        should_reset = tenant.next_credits_reset_at < subscription.current_period_start

    if not should_reset:
        return

    # reset credits
    tenant.credits_remaining = plan.credits
    tenant.next_credits_reset_at = subscription.current_period_end

    db.add(
        CreditLog(
            tenant_id=tenant.tenant_id,
            amount=plan.credits,
            balance_after=tenant.credits_remaining,
            action="renewal",
            description="Monthly credit allocation"
        )
    )

    db.add(tenant)
    await db.flush()
 
 
 
 

# function to deduct allocated credits
async def consume_credits(
    tenant_id: UUID,
    cost: int,
    action: str,
    description: str,
    db: AsyncSession
) -> Tenant:
    
    # validate cost
    if cost <= 0:
        raise ValueError("Credit cost must be greater than zero.")

    # lock tenant row to prevent race conditions during rapid requests
    statement = (
        select(Tenant)
        .where(Tenant.tenant_id == tenant_id)
        .options(selectinload(Tenant.plan))
        .with_for_update()
    )

    result = await db.exec(statement)
    tenant = result.first()

    if tenant is None or tenant.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found."
        )

    if not tenant.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant is inactive."
        )

    # reset credits if a new billing period has started
    await reset_credits_if_needed(tenant=tenant, db=db)

    if tenant.credits_remaining < cost:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "insufficient_credits",
                "credits_remaining": tenant.credits_remaining,
                "credits_required": cost
            },
        )
    
    # deduct balance from memory string and update the tenant table state
    tenant.credits_remaining -= cost

    db.add(
        CreditLog(
            tenant_id=tenant.tenant_id,
            amount=-cost,
            balance_after=tenant.credits_remaining,
            action=action,
            description=description
        )
    )

    db.add(tenant)
    await db.flush()

    return tenant   





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

        await register_webhook_event(
            event=event,
            db=db,
        )

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
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unexpected checkout mode."
            )

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
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incomplete checkout session."
            )

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
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Checkout session not found."
            )

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





# define cost
# CREDIT_COSTS = {
#     "text_generation": 20,
#     "image_generation": 100,
#     "speech_to_text": 10,
# }

# @router.post("/generate")
# async def generate_text(
#     payload: GenerateRequest,
#     current_tenant: Tenant = Depends(get_current_tenant),
#     db: AsyncSession = Depends(get_db)
# ):
#     try:
#         # consume credits first
#         await consume_credits(
#             tenant_id=current_tenant.tenant_id,
#             cost=CREDIT_COSTS["text_generation"],
#             action="text_generation",
#             description="AI text generation",
#             db=db
#         )

#         # call your AI provider
#         response = await ai_service.generate(payload.prompt)

#         # save generation history
#         history = AIHistory(
#             tenant_id=current_tenant.tenant_id,
#             prompt=payload.prompt,
#             response=response
#         )

#         db.add(history)

#         # Commit everything together
#         await db.commit()

#         return {
#             "credits_remaining": current_tenant.credits_remaining,
#             "response": response
#         }

#     except HTTPException:
#         await db.rollback()
#         raise

#     except Exception:
#         await db.rollback()
#         raise