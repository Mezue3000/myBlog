# import dependencies
from app.cores.logging import get_logger
from app.models import Tenant, User, Plan, Subscription, StripeCheckoutSession
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.tenant.tenant_router import lock_tenant
import stripe
from sqlmodel import select
from fastapi import HTTPException, status





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
    
    # acquire row lock to prevent concurrent customer creation.
    tenant = await lock_tenant(tenant_id=tenant.tenant_id, db=db)
    
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
