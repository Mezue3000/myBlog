# import dependencies
from app.cores.logging import get_logger
from typing import Any
from sqlmodel.ext.asyncio.session import AsyncSession
from app.models import Subscription, Tenant
from app.utility.stripe.helpers import (
    extract_subscription_data,
    get_locked_tenant,
    get_plan_by_price_id,
    update_tenant_subscription,
    upsert_subscription
)





# initialize logging
logger = get_logger(__name__)



# function to sync database with stripe's subscription state
async def sync_subscription_from_stripe(
    *,
    stripe_subscription: dict[str, Any],
    db: AsyncSession
) -> tuple[Tenant, Subscription]:
    """
    Synchronize local billing state with a Stripe Subscription object.

    This function never commits or rolls back.
    The caller owns the transaction.
    """
    # normalize stripe object
    subscription_data = extract_subscription_data(stripe_subscription)
    
    # lock tenant
    tenant = await get_locked_tenant(stripe_customer_id=subscription_data["stripe_customer_id"], db=db)
    
    # load plan
    plan = await get_plan_by_price_id(stripe_price_id=subscription_data["stripe_price_id"], db=db)
    
    # upsert subscription
    subscription = await upsert_subscription(
        tenant=tenant,
        plan=plan,
        subscription_data=subscription_data,
        db=db
    )
    
    # update tenant
    await update_tenant_subscription(
        tenant=tenant,
        plan=plan,
        subscription=subscription,
        db=db
    )
    
    # log info
    logger.info(
        "Synchronized Stripe subscription '%s' for tenant '%s'.",
        subscription.stripe_subscription_id,
        tenant.tenant_id
    )
    
    return tenant, subscription
