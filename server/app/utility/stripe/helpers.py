# import dependencies
from app.cores.logging import get_logger
from app.models import Tenant, User, Plan, Subscription, StripeCheckoutSession, WebhookEvent, BillingAudit
from sqlmodel.ext.asyncio.session import AsyncSession
import stripe, asyncio
from sqlmodel import select
from fastapi import HTTPException, status
from typing import Optional, Any
from datetime import datetime, timezone
from sqlalchemy.orm import selectinload
from uuid import UUID
from app.utility.tenant.tenant_router import validate_tenant
from sqlalchemy.exc import IntegrityError





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





# function to retrieve a previously registered stripe webhook event.
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
    Records the processing outcome in the current transaction.

    processed=True:
        - Marks the webhook as successfully processed.
        - Records processed_at.
        - Clears any previous processing error.

    processed=False:
        - Increments retry_count.
        - Records the processing error, if supplied.
    """

    webhook = await get_webhook_event(event_id=event_id, db=db)

    # event may have been removed or may not exist.
    if webhook is None:
        return

    if processed:
        webhook.processed = True
        webhook.processed_at = datetime.now(timezone.utc)
        webhook.processing_error = None

    else:
        webhook.processed = False
        webhook.retry_count += 1
        
        if error is not None:
            webhook.processing_error = str(error)[:1000]

    db.add(webhook)
    await db.flush()





# function to convert raw stripe subscription object into a normalized Python structure.
def extract_subscription_data(
    stripe_subscription: dict[str, Any]
) -> dict[str, Any]:
    
    # normalize a stripe subscription object into application fields.
    items = stripe_subscription.get("items", {}).get("data", [])

    if not items:
        raise ValueError("Stripe subscription contains no subscription items.")

    price = items[0].get("price")

    if price is None:
        raise ValueError("Stripe subscription item has no price.")

    return {
        "stripe_subscription_id": stripe_subscription["id"],
        "stripe_customer_id": stripe_subscription["customer"],
        "stripe_price_id": price["id"],
        "status": stripe_subscription["status"],
        "current_period_start": datetime.fromtimestamp(
            stripe_subscription["current_period_start"],
            tz=timezone.utc
        ),
        
        "current_period_end": datetime.fromtimestamp(
            stripe_subscription["current_period_end"],
            tz=timezone.utc
        ),
        
        "cancel_at_period_end": stripe_subscription["cancel_at_period_end"],
        "cancelled_at": (
            datetime.fromtimestamp(
                stripe_subscription["canceled_at"],
                tz=timezone.utc
            )
            if stripe_subscription.get("canceled_at")
            else None
        ),
    }





# function to get locked tenant
async def get_locked_tenant(
    *,
    stripe_customer_id: str,
    db: AsyncSession
) -> Tenant:
    """
    Returns a locked tenant row.

    The row is locked for the lifetime of the current transaction
    to prevent concurrent webhook handlers from modifying billing data.
    """

    statement = (
        select(Tenant)
        .where(Tenant.stripe_customer_id == stripe_customer_id)
        .options(selectinload(Tenant.plan))
        .with_for_update()
    )

    result = await db.exec(statement)
    tenant = result.first()
    
    validate_tenant(tenant=tenant)

    return tenant





# function to get plan by stripe price id
async def get_plan_by_price_id(
    *,
    stripe_price_id: str,
    db: AsyncSession
) -> Plan:
    
    # returns the plan associated with a Stripe price id
    statement = (
        select(Plan)
        .where(
            Plan.stripe_price_id == stripe_price_id,
            Plan.is_active.is_(True)
        )
    )

    result = await db.exec(statement)
    plan = result.first()

    if plan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Subscription plan not found."
        )

    return plan




# function to get tenant subscription
async def get_subscription_by_tenant(
    *,
    tenant_id: UUID,
    db: AsyncSession,
) -> Subscription | None:
    
    # returns the tenant subscription if one exists
    statement = (
        select(Subscription)
        .where(Subscription.tenant_id == tenant_id)
    )

    result = await db.exec(statement)
    return result.first()




# function to update or insert subscription
async def upsert_subscription(
    *,
    tenant: Tenant,
    plan: Plan,
    subscription_data: dict,
    db: AsyncSession
) -> Subscription:
    
    """
    Responsibilities:
        create if missing
        otherwise update
    """
    # creates or updates the tenant subscription.
    subscription = await get_subscription_by_tenant(
        tenant_id=tenant.tenant_id,
        db=db
    )

    if subscription is None:

        subscription = Subscription(
            tenant_id=tenant.tenant_id,
            plan_id=plan.plan_id,
            stripe_subscription_id=subscription_data["stripe_subscription_id"],
            status=subscription_data["status"],
            current_period_start=subscription_data["current_period_start"],
            current_period_end=subscription_data["current_period_end"],
            cancel_at_period_end=subscription_data["cancel_at_period_end"],
            cancelled_at=subscription_data["cancelled_at"]
        )

    else:
        subscription.plan_id = plan.plan_id
        subscription.stripe_subscription_id = subscription_data["stripe_subscription_id"]
        subscription.status = subscription_data["status"]
        subscription.current_period_start = subscription_data["current_period_start"]
        subscription.current_period_end = subscription_data["current_period_end"]
        subscription.cancel_at_period_end = subscription_data["cancel_at_period_end"]
        subscription.cancelled_at = subscription_data["cancelled_at"]

    db.add(subscription)
    await db.flush()

    return 




# function to update tenant subscription
async def update_tenant_subscription(
    *,
    tenant: Tenant,
    plan: Plan,
    subscription: Subscription,
    db: AsyncSession
) -> None:
    """
    Synchronizes tenant billing information.

    Credit allocation is NOT performed here.
    """

    tenant.plan_id = plan.plan_id
    tenant.next_credits_reset_at = subscription.current_period_end

    db.add(tenant)

    await db.flush()




# function to retrieve an existing billing audit by Stripe event id.
async def get_billing_audit(
    *,
    stripe_event_id: str,
    db: AsyncSession
) -> Optional[BillingAudit]:
    
    statement = (
        select(BillingAudit)
        .where(BillingAudit.stripe_event_id == stripe_event_id)
    )

    result = await db.exec(statement)

    return result.first()





# function to generate audit record
async def create_billing_audit(
    *,
    tenant_id: UUID,
    stripe_event_id: str,
    event_type: str,
    db: AsyncSession
) -> BillingAudit:
    """
    Create an idempotent billing audit.

    Does not commit.

    Uses a nested transaction so a concurrent unique-key
    conflict does not roll back the caller's main transaction.
    """

    if not tenant_id:
        raise ValueError("Tenant ID is required.")

    if not stripe_event_id:
        raise ValueError("Stripe event ID is required.")

    if not event_type:
        raise ValueError("Stripe event type is required.")

    # existing audit
    existing_audit = await get_billing_audit(stripe_event_id=stripe_event_id, db=db)

    if existing_audit is not None:
        return existing_audit

    # insert using SAVEPOINT
    try:
        async with db.begin_nested():
            audit = BillingAudit(
                tenant_id=tenant_id,
                stripe_event_id=stripe_event_id,
                event_type=event_type
            )

            db.add(audit)
            await db.flush()

        logger.info("Created billing audit for Stripe event '%s'.", stripe_event_id)

        return audit

    except IntegrityError:
        logger.info(
            "Billing audit for Stripe event '%s' "
            "was created concurrently.",
            stripe_event_id
        )

        # The nested transaction has rolled back only the
        # failed INSERT. The caller's transaction remains alive.

        existing_audit = await get_billing_audit(stripe_event_id=stripe_event_id, db=db)

        if existing_audit is None:
            raise

        return existing_audit





# function to retrive stripe subscription
async def retrieve_stripe_subscription(*, subscription_id: str) -> dict:
    """
    Retrieve the complete Stripe Subscription.

    Stripe's SDK call is synchronous, so execute it in a
    worker thread rather than blocking the async event loop.
    """

    if not subscription_id:
        raise ValueError("Stripe subscription ID is required.")

    try:
        subscription = await asyncio.to_thread(stripe.Subscription.retrieve, subscription_id)

    except stripe.error.StripeError:
        logger.exception("Failed retrieving Stripe subscription '%s'.", subscription_id)
        raise

    if not subscription:
        raise ValueError(f"Stripe subscription '{subscription_id}' was not returned.")

    return subscription
