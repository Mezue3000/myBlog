# import dependencies
from fastapi import Depends, HTTPException, status
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.utility.platform.database import get_db
from app.utility.platform.user import get_current_active_user
from app.utility.tenant.tenant_router import get_current_tenant
from app.models import User, Tenant, TenantMembership





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