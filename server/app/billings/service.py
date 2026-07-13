# import dependencies
from app.models import Tenant, Subscription, Plan, CreditLog
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
from fastapi import HTTPException, status
from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy.orm import selectinload





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

    now = datetime.now(timezone.utc)

    if tenant.credits_last_reset_at is None:
        should_reset = True

    elif subscription.current_period_start is None:
        should_reset = False

    else:
        should_reset = tenant.credits_last_reset_at < subscription.current_period_start

    if not should_reset:
        return

    # reset credits
    tenant.credits_remaining = plan.credits
    tenant.credits_last_reset_at = now

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
 
 
 
 

# service function to deduct allocated credits
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
            detail="Tenant not found"
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
    
    # deduct balance from memory string and update the Tenant table state
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
#     db: AsyncSession = Depends(get_db),
# ):
#     try:
#         # Consume credits first
#         await consume_credits(
#             tenant_id=current_tenant.tenant_id,
#             cost=CREDIT_COSTS["text_generation"],
#             action="text_generation",
#             description="AI text generation",
#             db=db,
#         )

#         # Call your AI provider
#         response = await ai_service.generate(payload.prompt)

#         # Save generation history
#         history = AIHistory(
#             tenant_id=current_tenant.tenant_id,
#             prompt=payload.prompt,
#             response=response,
#         )

#         db.add(history)

#         # Commit everything together
#         await db.commit()

#         return {
#             "credits_remaining": current_tenant.credits_remaining,
#             "response": response,
#         }

#     except HTTPException:
#         await db.rollback()
#         raise

#     except Exception:
#         await db.rollback()
#         raise