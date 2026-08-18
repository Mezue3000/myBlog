# import dependencies
from app.cores.logging import get_logger
from app.models import Tenant, Subscription, Plan, CreditLog
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
from fastapi import HTTPException, status
from uuid import UUID
from sqlalchemy.orm import selectinload
from app.utility.tenant.tenant_router import validate_tenant
from typing import Optional
from datetime import datetime, timezone, timedelta





# initialize logging
logger = get_logger(__name__)



# define tenant types
FREE_CREDIT_TENANT_TYPES = {
    "personal",
    "team",
    "headless_api"
}


# define credit reset hours
FREE_CREDIT_RESET_HOURS = 3



# function to reset credit
async def reset_free_plan_credits_if_due(
    *,
    tenant: Tenant,
    db: AsyncSession
) -> bool:
    """
    Reset credits for Free personal/team/headless_api tenants
    after the 3-hour exhaustion period.

    Does not commit.
    """

    if tenant.type not in FREE_CREDIT_TENANT_TYPES:
        return False

    if tenant.plan is None:
        return False

    if tenant.plan.name != "free":
        return False

    if tenant.next_credits_reset_at is None:
        return False

    now = datetime.now(timezone.utc)

    if now < tenant.next_credits_reset_at:
        return False

    tenant.credits_remaining = tenant.plan.credits

    tenant.next_credits_reset_at = None

    db.add(
        CreditLog(
            tenant_id=tenant.tenant_id,
            amount=tenant.plan.credits,
            balance_after=tenant.credits_remaining,
            action="free_reset",
            description="Free plan credit reset after exhaustion."
        )
    )

    db.add(tenant)
    await db.flush()

    return True
 
 
 
 

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

    validate_tenant(tenant=tenant)

    if (
        tenant.type in FREE_CREDIT_TENANT_TYPES
        and tenant.plan is not None
        and tenant.plan.name == "free"
    ):
        await reset_free_plan_credits_if_due(tenant=tenant, db=db)
    
    if tenant.credits_remaining < cost:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "credits_exhausted",
                "message": (
                    "Your credits have been exhausted. "
                    "Please wait for your credits to reset."
                ),
                "credits_remaining": tenant.credits_remaining,
                "credits_required": cost,
                "next_credits_reset_at": (
                    tenant.next_credits_reset_at.isoformat()
                    if tenant.next_credits_reset_at
                    else None
                ),
            }
        )
    # deduct balance from memory string and update the tenant table state
    tenant.credits_remaining -= cost
    
    now = datetime.now(timezone.utc)
    
    if (
        tenant.type in FREE_CREDIT_TENANT_TYPES
        and tenant.plan is not None
        and tenant.plan.slug == "free"
        and tenant.credits_remaining == 0
    ):
        tenant.next_credits_reset_at = now + timedelta(hours=FREE_CREDIT_RESET_HOURS)

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





# function to allocate credit to newly paid stripe billing
async def allocate_paid_plan_credits(
    *,
    tenant: Tenant,
    subscription: Subscription,
    db: AsyncSession
) -> bool:
    """
    Allocate credits for a newly paid Stripe billing period.

    This function is intended to be called from invoice.paid.

    Returns:
        True  -> credits allocated
        False -> allocation skipped

    Does not commit.
    """

    # validate tenant plan
    if tenant.plan is None:
        return False

    # never allocate paid credits to Free plans
    if tenant.plan.name == "free":
        return False

    # validate subscription period
    if subscription.current_period_start is None:
        return False

    if subscription.current_period_end is None:
        return False

    # prevent duplicate allocation
    if (
        tenant.next_credits_reset_at is not None
        and tenant.next_credits_reset_at
        >= subscription.current_period_start
    ):
        return False

    # allocate credits
    credits = tenant.plan.credits
    tenant.credits_remaining = credits

    # the next allocation occurs at the next Stripe billing-period boundary.
    tenant.next_credits_reset_at = subscription.current_period_end

    db.add(
        CreditLog(
            tenant_id=tenant.tenant_id,
            amount=credits,
            balance_after=tenant.credits_remaining,
            action="renewal",
            description="Paid plan credit allocation for stripe billing period."
        )
    )

    db.add(tenant)
    await db.flush()

    return True






# define cost
# CREDIT_COSTS = {
#     "text_generation": 20,
#     "image_generation": 100,
#     "speech_to_text": 10
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
