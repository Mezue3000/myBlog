# import dependencies
from fastapi import Depends, HTTPException, status
from sqlmodel import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.utility.platform.database import get_db
from app.utility.platform.user import get_current_active_user
from app.utility.tenant.tenant_router import get_current_tenant
from app.models import User, Tenant, TenantMembership, TenantInvitation
from typing import Optional
from datetime import datetime, timezone
from app.rate_limit.resolver import get_plan_feature
from uuid import UUID





# create current membership function
async def get_current_membership(
    current_user: User = Depends(get_current_active_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
) -> TenantMembership:

    statement = select(TenantMembership).where(
        TenantMembership.user_id == current_user.user_id,
        TenantMembership.tenant_id == tenant.tenant_id,
        TenantMembership.is_deleted.is_(False),
        TenantMembership.is_active.is_(True)
    )
    
    result = await db.exec(statement)
    membership = result.first()

    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a member of this tenant"
        )

    return membership





# get maximum members allowed by current plan
def get_max_team_members(
    *,
    tenant: Tenant
) -> int:
    """
    Return the maximum number of members allowed by the
    tenant's current plan.

    Example:
        Free       -> 3
        Pro        -> 10
        Enterprise -> 100

    The actual values come from Plan.features.
    """

    if tenant.type != "team":
        raise ValueError("Only team workspaces have member limits.")
    
    max_members = get_plan_feature(tenant=tenant, feature="max_team_members")

    if max_members is None:
        raise ValueError("Plan configuration error: " "max_team_members is missing.")
    
    # make sure the value stored in JSON is usable.
    try:
        max_members = int(max_members)
    except (TypeError, ValueError):
        raise ValueError("Plan configuration error: " "max_team_members must be an integer.")

    if max_members < 1:
        raise ValueError("Plan configuration error: " "max_team_members must be greater than zero.")

    return max_members





# function to count the remaining members a tenant can have
async def get_remaining_team_slots(
    *,
    tenant: Tenant,
    db: AsyncSession,
    exclude_invitation_id: Optional[int] = None
) -> int:
    """
    Returns the number of available team member slots.

    Capacity =
        max_team_members
        - active_members
        - active_pending_invitations

    The invitation being accepted can be excluded from the pending
    invitation count by passing exclude_invitation_id.

    Args:
        tenant: The team workspace.
        db: Async database session.
        exclude_invitation_id: The invitation currently being accepted.

    Returns:
        The number of remaining team member slots.
    """

    # maximum members allowed by the tenant's current plan
    max_members = get_max_team_members(tenant=tenant)
  
    # count active workspace members
    member_statement = (
        select(func.count(TenantMembership.user_id))
        .where(
            TenantMembership.tenant_id == tenant.tenant_id,
            TenantMembership.is_deleted.is_(False),
            TenantMembership.is_active.is_(True)
        )
    )

    result = await db.exec(member_statement)
    active_members = result.one()

    # count active, pending invitations
    
    now = datetime.now(timezone.utc)

    invitation_conditions = [
        TenantInvitation.tenant_id == tenant.tenant_id,
        TenantInvitation.is_accepted.is_(False),
        TenantInvitation.accepted_at.is_(None),
        TenantInvitation.expires_at > now
    ]

    if exclude_invitation_id is not None:
        invitation_conditions.append(TenantInvitation.invite_id != exclude_invitation_id)

    invitation_statement = (
        select(func.count(TenantInvitation.invite_id))
        .where(*invitation_conditions)
    )

    result = await db.exec(invitation_statement)
    pending_invitations = result.one()

    # calculate remaining capacity
    remaining_slots = (
        max_members
        - active_members
        - pending_invitations
    )

    return max(remaining_slots, 0)





# function to ensure workspace can accept more members
async def ensure_team_has_capacity(
    *,
    tenant: Tenant,
    db: AsyncSession,
    exclude_invitation_id: Optional[int] = None
) -> int:
    """
    Ensures that a team workspace has capacity for one more member.

    Args:
        tenant: The team workspace.
        db: Async database session.
        exclude_invitation_id: Invitation ID to exclude from the pending
            invitation count. Used when accepting an existing invitation.

    Returns:
        The number of remaining member slots.

    Raises:
        HTTPException(403): If the workspace is not a team workspace.
        ValueError: If the workspace has reached its member limit.
    """

    if tenant.type != "team":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only team workspaces can have members."
        )

    remaining_slots = await get_remaining_team_slots(
        tenant=tenant,
        db=db,
        exclude_invitation_id=exclude_invitation_id
    )

    if remaining_slots <= 0:
        raise ValueError(
            "This workspace has reached the maximum number "
            "of members allowed by its current plan."
        )

    return remaining_slots





# get tenant-members by tenant_id
async def get_members_by_tenant_id(tenant_id: UUID, db: AsyncSession):
    # select statement joining TenantMembership and User
    statement = (
        select(TenantMembership, User)
        .join(User, TenantMembership.user_id == User.user_id)
        .where(TenantMembership.tenant_id == tenant_id)
    )
    
    result = await db.exec(statement)
    return result.all()
