# import dependencies
from app.utility.tenant.tenant_router import get_current_tenant
from app.utility.platform.user import get_current_active_user
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from fastapi import HTTPException, status, Depends
from uuid import UUID
from app.utility.tenant.tenant_router import get_active_tenant_membership
from app.models import User, Tenant, TenantMembership
from app.utility.tenant.members_router import get_current_membership





# tenant-type aware authorization
def require_tenant_owner():

    async def checker(
        tenant: Tenant = Depends(get_current_tenant),
        current_user: User = Depends(get_current_active_user),
        db: AsyncSession = Depends(get_db)
    ):
        # personal and headless API tenants use tenant.owner_id
        if tenant.type in {"personal", "headless_api"}:

            if tenant.owner_id != current_user.user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only the tenant owner can perform this action"
                )

            return tenant

        # team tenants use tenant-membership.role
        if tenant.type == "team":

            membership = await get_current_membership(
                current_user=current_user,
                tenant=tenant,
                db=db
            )

            if membership.role != "owner":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only the tenant owner can perform this action"
                )

            return tenant

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid tenant type"
        )

    return checker





# initiate role hierarchy
ROLE_PRIORITY = {
    "owner": 3,
    "admin": 2,
    "member": 1
}




# function to validate privileges
async def validate_tenant_role_hierarchy(
    actor_user_id: int,
    target_user_id: int,
    tenant_id: UUID,
    db: AsyncSession
):
    actor_membership = await get_active_tenant_membership(
        user_id=actor_user_id,
        tenant_id=tenant_id,
        db=db
    )

    target_membership = await get_active_tenant_membership(
        user_id=target_user_id,
        tenant_id=tenant_id,
        db=db
    )

    if not actor_membership:
        raise ValueError("Actor membership not found")

    if not target_membership:
        raise ValueError("Target membership not found")

    actor_level = ROLE_PRIORITY.get(actor_membership.role, 0)

    target_level = ROLE_PRIORITY.get(target_membership.role, 0)

    if actor_level <= target_level:
        raise ValueError("You cannot modify a member with equal or higher privileges")

    return target_membership





# role checker validation
def require_tenant_role(*allowed_roles: str):

    async def checker(membership: TenantMembership = Depends(get_current_membership)) -> TenantMembership:
        
        if membership.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )

        return membership

    return checker



require_owner = require_tenant_role("owner")

require_admin = require_tenant_role("owner", "admin")
