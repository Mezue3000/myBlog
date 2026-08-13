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
from datetime import datetime, timezone





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

    validate_tenant(tenant=tenant)

    # reset credits if a new billing period has started
    await reset_credits_if_needed(tenant=tenant, db=db)

    if tenant.credits_remaining < cost:
        raise ValueError(
            {
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





# function to retrieve existing credit log
async def get_credit_log_by_reference(
    *,
    tenant_id: UUID,
    reference_id: str,
    action: str,
    db: AsyncSession
) -> Optional[CreditLog]:
    """
    Retrieve an existing credit log using its reference.

    For invoice.paid, reference_id is the Stripe invoice ID.

    The caller owns the transaction.
    """

    statement = (
        select(CreditLog)
        .where(
            CreditLog.tenant_id == tenant_id,
            CreditLog.reference_id == reference_id,
            CreditLog.action == action
        )
    )

    result = await db.exec(statement)

    return result.first()





# function to allocate subscription credits
async def allocate_invoice_credits(
    *,
    tenant: Tenant,
    subscription: Subscription,
    invoice_id: str,
    db: AsyncSession
) -> None:
    """
    Allocate plan credits after a successful Stripe invoice.
    
    Idempotency
    -----------
    The Stripe invoice ID is stored in CreditLog.reference_id.

    The combination of:
        tenant_id
        reference_id
        action
    identifies a particular credit allocation.

    Transaction
    -----------
    Does NOT commit.
    The caller owns the transaction.
    """

    # validate inputs
    if tenant is None:
        raise ValueError("Tenant is required.")

    if subscription is None:
        raise ValueError("Subscription is required.")

    if not invoice_id:
        raise ValueError("Stripe invoice ID is required.")

    # get subscription plan
    plan = subscription.plan

    if plan is None:
        raise ValueError(
            f"Subscription "
            f"'{subscription.stripe_subscription_id}' "
            "has no associated plan."
        )

    # validate plan credits
    if plan.credits <= 0:
        raise ValueError(
            f"Plan '{plan.name}' has an invalid "
            f"credit allocation: {plan.credits}."
        )

    # idempotency check
    existing_log = await get_credit_log_by_reference(
        tenant_id=tenant.tenant_id,
        reference_id=invoice_id,
        action="subscription_credit",
        db=db
    )

    if existing_log is not None:
        logger.info(
            "Credits for invoice '%s' have already "
            "been allocated to tenant '%s'.",
            invoice_id,
            tenant.tenant_id
        )

        return
    
    # calculate new balance
    previous_balance = tenant.credits_remaining
    allocated_credits = plan.credits
    new_balance = allocated_credits

    # update tenant balance
    tenant.credits_remaining = new_balance
    tenant.next_credits_reset_at = subscription.current_period_end

    db.add(tenant)

    # create credit log
    credit_log = CreditLog(
        tenant_id=tenant.tenant_id,
        amount=allocated_credits,
        balance_after=new_balance,
        action="subscription_credit",
        description=(
            f"{plan.name} plan credit allocation "
            f"for invoice {invoice_id}."
        ),
        reference_id=invoice_id
    )

    db.add(credit_log)
    await db.flush()

    logger.info(
        "Allocated %s credits to tenant '%s' "
        "for invoice '%s'. Balance: %s -> %s.",
        allocated_credits,
        tenant.tenant_id,
        invoice_id,
        previous_balance,
        new_balance
    )








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