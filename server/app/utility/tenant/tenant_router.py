# import dependencies
from sqlmodel.ext.asyncio.session import AsyncSession
from app.models import Tenant, TenantMembership, User, TenantInvitation
from sqlmodel import select
from fastapi import HTTPException, status, Depends, Header, Request
from app.utility.platform.user import get_current_active_user
from app.utility.platform.database import get_db
from typing import Optional
from uuid import UUID
import secrets
from pydantic import EmailStr
from datetime import datetime, timezone
from contextvars import ContextVar






# function to get personal workspace
async def get_personal_tenant(user_id: int, db: AsyncSession) -> Tenant:
    # personal workspace via ownership
    statement = select(Tenant).where(
        Tenant.owner_id == user_id,
        Tenant.type == "personal",
        Tenant.is_active == True,
        Tenant.is_deleted == False
    )
    
    result = await db.exec(statement)
    tenant = result.first()
    
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Personal workspace not found"
        )
    
    return tenant





# check tenant name uniqueness
async def validate_tenant_uniqueness(name: str, db: AsyncSession):
    statement = select(Tenant).where(Tenant.name == name)

    existing_tenant = db.exec(statement).first()

    if existing_tenant:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tenant name already exists")
    
    
    
    
    
# function to list all user team-space by type 
async def get_user_tenants_by_type(
    user_id: int, 
    db: AsyncSession, 
    tenant_type: str = "team"
) -> list[tuple[Tenant, str]]:
    
    statement = (
        select(Tenant, TenantMembership.role)
        .join(TenantMembership)
        .where(
            TenantMembership.user_id == user_id,
            TenantMembership.is_active == True,
            TenantMembership.is_deleted == False,
            
            Tenant.type == "team",
            Tenant.is_active == True,
            Tenant.is_deleted  == False
        )
        .order_by(Tenant.name.asc())
    )

    result = await db.exec(statement)

    return result.all()





# function to get tenant-membership
async def get_tenant_membership(
    user_id: int,
    tenant_id: UUID,
    db: AsyncSession
):
    statement = select(TenantMembership).where(
        TenantMembership.user_id == user_id,
        TenantMembership.tenant_id == tenant_id,
        TenantMembership.is_deleted == False
    )

    result = await db.exec(statement)

    return result.first()





# function to get active members
async def get_active_tenant_membership(
    user_id: int,
    tenant_id: UUID,
    db: AsyncSession
):
    statement = select(TenantMembership).where(
        TenantMembership.user_id == user_id,
        TenantMembership.tenant_id == tenant_id,
        TenantMembership.is_active == True,
        TenantMembership.is_deleted == False
    )

    result = await db.exec(statement)

    return result.first()





# function to validate tenant access
async def validate_tenant_access(tenant: Tenant, current_user: User, db: AsyncSession):
    # personal tenant
    if tenant.type == "personal":
        if tenant.owner_id != current_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to personal tenant"
            )

        return True

    # team/api tenants
    membership = await get_tenant_membership(
        user_id=current_user.user_id,
        tenant_id=tenant.tenant_id,
        db=db
    )

    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to tenant"
        )

    return True





# fuction to get current tenant
async def get_current_tenant(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    x_tenant_id: Optional[UUID] = Header(default=None, alias="X-Tenant-ID")
):
    tenant_id = (x_tenant_id or current_user.active_tenant_id)

    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active tenant selected"
        )

    tenant = await db.get(Tenant, tenant_id)

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found"
        )
    
    if tenant.is_deleted:
        raise HTTPException(
           status_code=status.HTTP_410_GONE,
           detail="Workspace has been deleted"
        )

    if not tenant.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Workspace is suspended"
        )
        
    # centralized access validation
    await validate_tenant_access(
        tenant=tenant,
        current_user=current_user,
        db=db
    )
    
    request.state.tenant = tenant
    request.state.tenant_id = tenant.tenant_id
    request.state.tenant_plan = tenant.plan
    request.state.tenant_type = tenant.type

    return tenant





# function to generate token 
def generate_invite_token():
    return secrets.token_urlsafe(32)





# function to check tenant active members by email
async def get_tenant_membership_by_email(
    tenant_id: UUID,
    email: EmailStr,
    db: AsyncSession,
):
    statement = (
        select(TenantMembership)
        .join(
            User,
            User.user_id == TenantMembership.user_id,
        )
        .where(
            TenantMembership.tenant_id == tenant_id,
            User.email == email,
        )
    )

    result = await db.exec(statement)

    return result.first()





# function to prevent duplicate active invitations
async def has_active_invitation(
    tenant_id: UUID,
    email: EmailStr,
    db: AsyncSession
):
    statement = select(TenantInvitation).where(
        TenantInvitation.tenant_id == tenant_id,
        TenantInvitation.email == email,
        TenantInvitation.is_accepted == False,
        TenantInvitation.expires_at > datetime.now(timezone.utc)
    )

    result = await db.exec(statement)

    return result.first() is not None





# function to get iv by token
async def get_invitation_by_token(
    token: str,
    db: AsyncSession
):
    statement = select(TenantInvitation).where(TenantInvitation.token == token)

    result = await db.exec(statement)

    return result.first()





# function to validate tenant
def validate_tenant(tenant: Tenant):
    
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workspace not found."
        )

    if tenant.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Workspace deleted."
        )

    if not tenant.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Workspace suspended."
        )





# function to count tenant members
async def count_active_non_owner_members(
    tenant_id: UUID,
    owner_id: int,
    db: AsyncSession
) -> int:

    statement = (
        select(TenantMembership)
        .where(
            TenantMembership.tenant_id == tenant_id, 
            TenantMembership.is_deleted == False,
            TenantMembership.user_id != owner_id,
        )
    )

    result = await db.exec(statement)

    memberships = result.all()

    return len(memberships)





# store tenant context
current_tenant_id = ContextVar("current_tenant_id", default=None)


bypass_rls = ContextVar("bypass_rls", default=False)