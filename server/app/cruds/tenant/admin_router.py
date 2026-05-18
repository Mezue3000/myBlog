from fastapi import  APIRouter,  Depends, HTTPException, status
from uuid import UUID
from app.models import Tenant, User
from app.utility.tenant.tenant_router import get_current_tenant
from app.utility.platform.user import get_current_active_user
from pydantic import EmailStr
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.services.tenant.admin_router import invite_member_service




# # initialize router
router = APIRouter(prefix="/admin",  tags=["admins"])
    
    
    
# member invitation endpoint
@router.post("/tenants/{tenant_id}/invitations")
async def invite_member(
    tenant_id: UUID,
    email: EmailStr,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    # prevent tenant mismatch
    if tenant_id != tenant.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant mismatch detected"
        )

    return await invite_member_service(
        tenant=tenant,
        email=email,
        current_user=current_user,
        db=db,
    ) 