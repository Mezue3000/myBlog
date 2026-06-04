# import dependencies
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from uuid import UUID
from app.schemas.tenant.admin_router import InviteMembersRequest, AcceptInvitationRequest
from app.models import Tenant, User
from app.utility.tenant.tenant_router import get_current_tenant
from app.utility.platform.user import get_current_active_user
from pydantic import EmailStr
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.services.tenant.admin_router import invite_members_service, accept_invitation_service, register_invited_member, delete_member_service, delete_tenant_service, deactivate_member_service, activate_member_service
from server.app.schemas.platform.users import UserCreate




# initialize router
router = APIRouter(prefix="/admin",  tags=["admins"])

    
 
# endpoint for member invitation
@router.post("/tenants/{tenant_id}/invitations")
async def invite_members(
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
            detail="Tenant mismatch detected",
        )

    return await invite_members_service(
        tenant=tenant,
        emails=data.emails,
        current_user=current_user,
        background_tasks=background_tasks,
        db=db,
    )





# endpoint to accept iv
@router.post("/invitations/accept")
async def accept_invitation(
    data: AcceptInvitationRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    return await accept_invitation_service(
        token=data.token,
        current_user=current_user,
        db=db,
    )





# endpoint to register invited member
@router.post("/auth/register/invited")
async def register_invited_user(
    user: UserCreate,
    token: str,
    db: AsyncSession = Depends(get_db),
):
    return await register_invited_member(
        user=user,
        token=token,
        db=db
    )
    
    
    
    
    
# soft-delete member endpoint
@router.delete("/members/{member_id}")
async def remove_member(
    member_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return await delete_member_service(
        tenant=tenant,
        member_id=member_id,
        current_user=current_user,
        db=db,
    )
    
    
    
    
    
# endpoint to soft-delete tenant
@router.delete("/tenants")
async def delete_tenant(
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    return await delete_tenant_service(
        tenant=tenant,
        current_user=current_user,
        db=db,
    )
    
    
    
    
    
# endpoint to deactivate member
@router.patch("/{member_id}/deactivate", status_code=status.HTTP_200_OK)
async def deactivate_member(
    member_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return await deactivate_member_service(
        tenant=tenant,
        member_id=member_id,
        current_user=current_user,
        db=db,
    )
    
    
    
    
    
# endpoint to activate member
@router.patch("/{member_id}/activate", status_code=status.HTTP_200_OK)
async def activate_member(
    member_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return await activate_member_service(
        tenant=tenant,
        member_id=member_id,
        current_user=current_user,
        db=db,
    )