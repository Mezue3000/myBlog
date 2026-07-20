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





# function to count the remaining members a tenant can have
async def get_remaining_team_slots(
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

    The invitation being accepted can be excluded from the pending invitation
    count by passing exclude_invitation_id.
    """
    
    # retrieve a plan feature.
    max_members = get_plan_feature(tenant=tenant, feature="max_team_members")
    
    if max_members is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Plan configuration error: " "max_team_members is missing."
        )
        
    # count both active/deactivated members
    statement = (
        select(func.count())
        .select_from(TenantMembership)
        .where(
            TenantMembership.tenant_id == tenant.tenant_id,
            TenantMembership.is_deleted.is_(False),
            TenantMembership.is_active.is_(True),
            TenantMembership.is_active.is_(False)
        )
    )

    result = await db.exec(statement)
    active_members = result.one()

    # Count active pending invitations
    conditions = [
        TenantInvitation.tenant_id == tenant.tenant_id,
        TenantInvitation.accepted_at.is_(None),
        TenantInvitation.expires_at > datetime.now(timezone.utc)
    ]

    if exclude_invitation_id is not None:
        conditions.append(
            TenantInvitation.invitation_id != exclude_invitation_id
        )

    statement = (
        select(func.count())
        .select_from(TenantInvitation)
        .where(*conditions)
    )

    result = await db.exec(statement)
    pending_invitations = result.one()

    remaining_slots = max_members - active_members - pending_invitations

    return max(remaining_slots, 0)





# function to ensure workspace can accept more member
async def ensure_team_has_capacity(
    tenant: Tenant,
    db: AsyncSession,
    exclude_invitation_id: Optional[int] = None
) -> int:
    """
    Ensures a team workspace has capacity for one more member.

    Args:
        tenant: The team workspace.
        db: Database session.
        exclude_invitation_id: Invitation to exclude from the pending
            invitation count. Used when accepting an invitation.

    Returns:
        The number of remaining slots.

    Raises:
        HTTPException(403): If the workspace is not a team workspace or
            has reached its member limit.
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
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This workspace has reached the maximum number "
                "of members allowed by its current subscription."
            )
        )

    return remaining_slots
