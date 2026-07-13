# import dependencies
from fastapi import Depends, HTTPException, status
from sqlmodel import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.utility.platform.database import get_db
from app.utility.platform.user import get_current_active_user
from app.utility.tenant.tenant_router import get_current_tenant
from app.models import User, Tenant, TenantMembership
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
        TenantMembership.is_deleted == False,
        TenantMembership.is_active == True
    )
    
    result = await db.exec(statement)
    membership = result.first()

    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a member of this tenant"
        )

    return membership





# function to validate team-member limit
async def validate_team_member_limit(tenant: Tenant, db: AsyncSession) -> None:

    if tenant.type != "team":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only team tenants can invite members."
        )

    max_members = get_plan_feature(tenant, "max_team_members")

    statement = (
        select(func.count())
        .select_from(TenantMembership)
        .where(
            TenantMembership.tenant_id == tenant.tenant_id,
            TenantMembership.is_deleted.is_(False)
        )
    )

    result = await db.exec(statement)
    current_members = result.one()

    if current_members >= max_members:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Your {tenant.plan.name} plan allows a maximum of {max_members} team members."
        )
