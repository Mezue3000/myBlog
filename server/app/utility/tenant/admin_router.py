# import dependencies
from uuid import UUID
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.tenant.tenant_router import get_active_tenant_membership
from fastapi import HTTPException, status





# initiate role hierarchy
ROLE_PRIORITY = {
    "owner": 3,
    "admin": 2,
    "member": 1,
}




# function to validate privileges
async def validate_tenant_role_hierarchy(
    actor_user_id: int,
    target_user_id: int,
    tenant_id: UUID,
    db: AsyncSession,
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
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Actor membership not found"
        )

    if not target_membership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target membership not found"
        )

    actor_level = ROLE_PRIORITY.get(actor_membership.role, 0)

    target_level = ROLE_PRIORITY.get(target_membership.role, 0)

    if actor_level <= target_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot modify a member with equal or higher privileges"
        )

    return target_membership