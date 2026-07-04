# import dependencies
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status, Request
from app.rate_limit.limiter import limiter
from app.rate_limit.policy import TENANT_LIMITS
from app.rate_limit.keys import tenant_key_func
from uuid import UUID
from app.schemas.tenant.admin_router import InviteMembersRequest, AcceptInvitationRequest
from app.models import Tenant, User, TenantMembership
from app.utility.tenant.tenant_router import get_current_tenant
from app.utility.platform.user import get_current_active_user
from app.utility.tenant.admin_router import require_admin, require_owner 
from pydantic import EmailStr
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.services.tenant.admin_router import invite_members_service, accept_invitation_service, register_invited_member, delete_member_service, deactivate_member_service, activate_member_service
from app.schemas.platform.users import UserCreate




# initialize router
router = APIRouter(prefix="/v1/Tenant-admin",  tags=["tenant-admins"])

    
 
# endpoint for member invitation
@router.post("/tenants/{tenant_id}/invitations", dependencies=[Depends(require_admin)])

@limiter.limit(TENANT_LIMITS["admin_iv"], key_func=tenant_key_func)
async def invite_members(
    request: Request,
    tenant_id: UUID,
    data: InviteMembersRequest,
    background_tasks: BackgroundTasks,
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

    return await invite_members_service(
        tenant=tenant,
        emails=data.emails,
        current_user=current_user,
        background_tasks=background_tasks,
        db=db
    )
    
    
    
    
    
# soft-delete member endpoint
@router.delete("/members/{member_id}", dependencies=[Depends(require_admin)])

@limiter.limit(TENANT_LIMITS["admin_delete"], key_func=tenant_key_func)
async def remove_member(
    request: Request,
    member_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    return await delete_member_service(
        tenant=tenant,
        member_id=member_id,
        current_user=current_user,
        db=db
    )
    
    


    
    
# endpoint to deactivate member
@router.patch("/{member_id}/deactivate", dependencies=[Depends(require_admin)], status_code=status.HTTP_200_OK)

@limiter.limit(TENANT_LIMITS["admin_patch"], key_func=tenant_key_func)
async def deactivate_member(
    request: Request,
    member_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    return await deactivate_member_service(
        tenant=tenant,
        member_id=member_id,
        current_user=current_user,
        db=db
    )
    
    
    
    
    
# endpoint to activate member
@router.patch("/{member_id}/activate",  dependencies=[Depends(require_admin)], status_code=status.HTTP_200_OK)

@limiter.limit(TENANT_LIMITS["admin_patch"], key_func=tenant_key_func)
async def activate_member(
    request: Request,
    member_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    return await activate_member_service(
        tenant=tenant,
        member_id=member_id,
        current_user=current_user,
        db=db
    )




#    _: TenantMembership = Depends(require_admin)