# import dependencies
from app.cores.logging import get_logger
from app.models import Tenant, User, Plan, Subscription, StripeCheckoutSession, WebhookEvent
from sqlmodel.ext.asyncio.session import AsyncSession
import stripe, json
from sqlmodel import select
from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from typing import Optional
from datetime import datetime, timezone





# initialize logging
logger = get_logger(__name__)



# function to create stripe customer
async def ensure_stripe_customer(
    tenant: Tenant,
    current_user: User,
    db: AsyncSession
) -> str:
    """
    Creates a Stripe Customer for a tenant.

    Billing is tenant-based, but the owner's email is used as the
    Stripe customer's email.

    This function does not commit the transaction.
    """
    
    # already linked to Stripe
    if tenant.stripe_customer_id:
        logger.info(
            "Stripe customer already exists. tenant_id=%s stripe_customer_id=%s",
            tenant.tenant_id,
            tenant.stripe_customer_id
        )
        return tenant.stripe_customer_id

    try:
        customer = stripe.Customer.create(
            email=current_user.email,
            name=tenant.name,
            metadata={
                "tenant_id": str(tenant.tenant_id),
                "owner_id": str(current_user.user_id),
                "tenant_type": tenant.type
            },
            options={
                "idempotency_key": (
                    f"tenant-customer-{tenant.tenant_id}"
                ),
            },
        )
       
        tenant.stripe_customer_id = customer.id

        db.add(tenant)
        await db.flush()

        logger.info(
            "Stripe customer created successfully. tenant_id=%s stripe_customer_id=%s",
            tenant.tenant_id,
            customer.id
        )

        return customer.id

    except stripe.error.CardError:
        logger.exception(
            "Stripe card error while creating customer. tenant_id=%s",
            tenant.tenant_id
        )
        raise

    except stripe.error.RateLimitError:
        logger.exception(
            "Stripe rate limit reached. tenant_id=%s",
            tenant.tenant_id
        )
        raise

    except stripe.error.AuthenticationError:
        logger.exception("Invalid Stripe API credentials.")
        raise

    except stripe.error.APIConnectionError:
        logger.exception("Unable to connect to Stripe.")
        raise

    except stripe.error.InvalidRequestError:
        logger.exception(
            "Invalid request sent to Stripe. tenant_id=%s",
            tenant.tenant_id
        )
        raise

    except stripe.error.StripeError:
        logger.exception(
            "Unexpected Stripe error while creating customer. tenant_id=%s",
            tenant.tenant_id
        )
        raise

    except Exception:
        logger.exception(
            "Unexpected error creating Stripe customer. tenant_id=%s",
            tenant.tenant_id
        )
        raise





# function to get active plan
async def get_active_plan(plan_id: int, db: AsyncSession) -> Plan:

    statement = (
        select(Plan)
        .where(
            Plan.plan_id == plan_id,
            Plan.is_active.is_(True)
        )
    )

    result = await db.exec(statement)

    plan = result.first()

    if not plan:
        logger.warning("Plan %s not found or inactive.", plan_id)

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Plan not found."
        )

    return plan





# function to check tenant has no active subscription
async def ensure_no_active_subscription(
    tenant: Tenant,
    db: AsyncSession
) -> None:
    existing = await db.exec(
        select(Subscription).where(
            Subscription.tenant_id == tenant.tenant_id,
            Subscription.status.in_(
                [
                    "active",
                    "trialing",
                    "past_due"
                ]
            )
        )
    )

    existing = existing.first()

    if existing:
           logger.warning(
               "Tenant %s already has an active subscription.",
               tenant.tenant_id
            )

           raise HTTPException(
               status_code=status.HTTP_409_CONFLICT,
               detail="Tenant already has an active subscription."
            )





# function to check expire existing stripe checkout session
async def expire_open_checkout_sessions(
    tenant: Tenant,
    db: AsyncSession
) -> None:

    statement = (
        select(StripeCheckoutSession)
        .where(
            StripeCheckoutSession.tenant_id == tenant.tenant_id,
            StripeCheckoutSession.status == "open"
        )
    )

    result = await db.exec(statement)
    sessions = result.all()

    for checkout in sessions:
        
        try:
            stripe.checkout.Session.expire(checkout.stripe_session_id)

            checkout.status = "expired"

            db.add(checkout)

        except stripe.error.StripeError:
            logger.exception(
                "Unable to expire checkout session %s",
                checkout.stripe_session_id
            )

    await db.flush()
    
    
    
    
    
# function to validate plan compatibility
async def ensure_plan_compatible_with_tenant(tenant: Tenant, plan: Plan) -> None:
    
    # ensures the selected plan is compatible with the tenant.
    if tenant.type != plan.tenant_type:
        logger.warning(
            "Tenant %s attempted to subscribe to incompatible plan %s.",
            tenant.tenant_id,
            plan.plan_id
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"This {plan.name} plan is only available "
                f"for {plan.tenant_type} workspaces."
            ),
        )





# function to route stripe events
EVENT_HANDLERS = {
#     "checkout.session.completed": handle_checkout_completed,
#     "invoice.paid": handle_invoice_paid,
#     "invoice.payment_failed": handle_invoice_payment_failed,
#     "customer.subscription.updated": handle_subscription_updated,
#     "customer.subscription.deleted": handle_subscription_deleted,
}



async def dispatch_webhook(
    *,
    event: stripe.Event,
    db: AsyncSession
) -> None:
    """
    Dispatch a Stripe webhook event to its handler.

    Unsupported events are ignored
    """

    event_id = event["id"]
    event_type = event["type"]

    handler = EVENT_HANDLERS.get(event_type)

    if handler is None:
        logger.info(
            "Ignoring unsupported Stripe event '%s' (%s).",
            event_type,
            event_id
        )
        return

    logger.info(
        "Dispatching Stripe event '%s' (%s).",
        event_type,
        event_id
    )

    try:
        await handler(event=event, db=db)

    except stripe.error.StripeError:
        logger.exception(
            "Stripe SDK error while processing '%s' (%s).",
            event_type,
            event_id
        )
        raise

    except Exception:
        logger.exception(
            "Unexpected error while processing '%s' (%s).",
            event_type,
            event_id
        )
        raise

    logger.info(
        "Successfully processed Stripe event '%s' (%s).",
        event_type,
        event_id
    )





 # raised when Stripe retries an already registered event
class DuplicateWebhookEvent(Exception):
    pass
   
    
    
# function to register stripe webhook
async def register_webhook_event( 
    *,
    event: dict,
    db: AsyncSession
) -> None:
    """
    Register a Stripe webhook.

    This owns its own transaction so the event
    is permanently recorded before any business
    logic starts.
    """

    webhook = WebhookEvent(
        stripe_event_id=event["id"],
        event_type=event["type"],
        payload=json.dumps(event)
    )

    db.add(webhook)

    try:
        await db.commit()

    except IntegrityError as exc:
        await db.rollback()
        raise DuplicateWebhookEvent from exc

    logger.info("Registered Stripe webhook %s.", event["id"])





# function to get webhook event
async def get_webhook_event(
    *,
    event_id: str,
    db: AsyncSession
) -> Optional[WebhookEvent]:

    statement = (
        select(WebhookEvent)
        .where(WebhookEvent.stripe_event_id == event_id)
    )

    result = await db.exec(statement)
    
    return result.first()





# fuction to update webhook event--- both processed and failed 
async def update_webhook_status(
    *,
    event_id: str,
    processed: bool,
    db: AsyncSession,
    error: Optional[Exception] = None
) -> None:
    """
    Update webhook processing state.

    Does NOT commit.
    """

    webhook = await get_webhook_event(event_id=event_id, db=db)

    if webhook is None:
        return

    webhook.processed = processed

    if processed:
        webhook.processed_at = datetime.now(timezone.utc)
        webhook.processing_error = None

    else:
        webhook.retry_count += 1
        if error is not None:
            webhook.processing_error = str(error)[:1000]

    db.add(webhook)

    await db.flush()
