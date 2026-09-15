# import dependencies
from sqlmodel.ext.asyncio.session import AsyncSession
from app.models import Tenant, TenantMembership, User, TenantInvitation, Plan, TenantScopedMixin
from sqlmodel import select, func
from fastapi import HTTPException, status, Depends, Header, Request
from app.utility.platform.user import get_current_active_user
from app.utility.platform.database import get_db
from typing import Optional
from uuid import UUID
import secrets
from sqlalchemy.orm import selectinload, Session, Mapper, with_loader_criteria
from sqlalchemy import event, type_coerce, Uuid
from pydantic import EmailStr
from datetime import datetime, timezone
from contextvars import ContextVar






# function to get personal workspace
async def get_personal_tenant(user_id: int, db: AsyncSession) -> Tenant:
    # personal workspace via ownership
    statement = select(Tenant).where(
        Tenant.owner_id == user_id,
        Tenant.type == "personal",
        Tenant.is_active.is_(True),
        Tenant.is_deleted.is_(False)
    )
    
    result = await db.exec(statement)
    tenant = result.first()
    
    if not tenant:
        raise ValueError("Personal workspace not found")
    
    return tenant





# check tenant name uniqueness
async def validate_tenant_uniqueness(name: str, db: AsyncSession):
    statement = select(Tenant).where(Tenant.name == name)

    result = await db.exec(statement)
    
    existing_tenant = result.first()

    if existing_tenant:
        raise ValueError("Tenant name already exists")
    
    
    
    
    
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
            TenantMembership.is_active.is_(True),
            TenantMembership.is_deleted.is_(False),
            
            Tenant.type == "team",
            Tenant.is_active.is_(True),
            Tenant.is_deleted.is_(False)
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
        TenantMembership.is_deleted.is_(False)
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
        TenantMembership.is_active.is_(True),
        TenantMembership.is_deleted.is_(False)
    )

    result = await db.exec(statement)

    return result.first()





# function to validate tenant access
async def validate_tenant_access(
    tenant: Tenant,
    current_user: User,
    db: AsyncSession
) -> bool:

    # personal tenant
    if tenant.type == "personal":
        if tenant.owner_id != current_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to personal tenant"
            ) 

        return True

    # headless API tenant
    if tenant.type == "headless_api":
        if tenant.owner_id != current_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to API tenant"
            )

        return True

    # team tenant
    if tenant.type == "team":
        membership = await get_tenant_membership(
            user_id=current_user.user_id,
            tenant_id=tenant.tenant_id,
            db=db
        )

        if not membership:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to team tenant"
            )

        if not membership.is_active or membership.is_deleted:
            raise ValueError("Tenant membership is inactive")

        return True

    # unknown tenant type
    raise ValueError("Invalid tenant type")




# function to validate tenant
def validate_tenant(tenant: Tenant):
    
    if tenant is None:
        raise ValueError("Workspace not found.")
    
    if tenant.is_deleted:
        raise ValueError("Workspace deleted.")
    
    if not tenant.is_active:
        raise ValueError("Workspace suspended.")




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

    statement = (
        select(Tenant)
        .where(Tenant.tenant_id == tenant_id)
        .options(selectinload(Tenant.plan))
    )

    result = await db.exec(statement)
    tenant = result.first()
    
    # ensure tenant is alive
    validate_tenant(tenant=tenant)
        
    # centralized access validation
    await validate_tenant_access(
        tenant=tenant,
        current_user=current_user,
        db=db
    )
    
    current_tenant_id.set(tenant.tenant_id)

    request.state.tenant = tenant
    request.state.tenant_id = tenant.tenant_id
    request.state.tenant_plan = tenant.plan
    request.state.features = tenant.plan.features
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
            User.user_id == TenantMembership.user_id
        )
        .where(
            TenantMembership.tenant_id == tenant_id,
            User.email == email
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
        TenantInvitation.is_accepted.is_(False),
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



# function to count tenant members
async def count_active_non_owner_members(
    tenant_id: UUID,
    owner_id: int,
    db: AsyncSession
) -> int:

    statement = (
        select(func.count(TenantMembership.user_id))
        .where(
            TenantMembership.tenant_id == tenant_id,
            TenantMembership.is_deleted.is_(False),
            TenantMembership.is_active.is_(True),
            TenantMembership.user_id != owner_id
        )
    )

    result = await db.exec(statement)
    return result.one()




# function to resolve tenant types
async def get_tenant_owner(
    *,
    tenant: Tenant,
    db: AsyncSession
) -> User:

    # Personal / headless_api tenants
    # Tenant.owner_id -> User.user_id
    if tenant.type in {"personal", "headless_api"}:

        if tenant.owner_id is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Tenant has no owner assigned"
            )

        statement = (
            select(User)
            .where(User.user_id == tenant.owner_id)
            .options(selectinload(User.role))
        )

        result = await db.exec(statement)
        owner = result.first()

        if owner is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Tenant owner could not be found"
            )

        return owner
    
    # Team tenant
    # Tenant.members -> TenantMembership.user -> User
    if tenant.type == "team":

        statement = (
            select(User)
            .join(
                TenantMembership,
                TenantMembership.user_id == User.user_id
            )
            .where(
                TenantMembership.tenant_id == tenant.tenant_id,
                TenantMembership.role == "owner",
                TenantMembership.is_deleted.is_(False),
                TenantMembership.is_active.is_(True)
            )
            .options(selectinload(User.role))
        )

        result = await db.exec(statement)
        owner = result.first()

        if owner is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Team tenant has no active owner"
            )

        return owner

    # unknown tenant type
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"Unknown tenant type '{tenant.type}'",
    )





# event hanlers to auto add tenant_id/bypass
@event.listens_for(Session, "do_orm_execute")
def add_tenant_filter(execute_state):

    if not execute_state.is_select:
        return

    if bypass_rls.get():
        return

    tenant_id = current_tenant_id.get()

    if tenant_id is None:
        return

    execute_state.statement = execute_state.statement.options(
        with_loader_criteria(
            TenantScopedMixin,
            lambda cls: cls.tenant_id == type_coerce(tenant_id, Uuid()),
            include_aliases=True
        )
    )



@event.listens_for(Session, "before_flush")
def set_tenant_id(session, flush_context, instances):

    tenant_id = current_tenant_id.get()

    if tenant_id is None:
        return

    # new objects
    for obj in session.new:

        if not isinstance(obj, TenantScopedMixin):
            continue

        obj_tenant_id = getattr(obj, "tenant_id", None)

        if obj_tenant_id is None:
            setattr(obj, "tenant_id", tenant_id)

        elif obj_tenant_id != tenant_id:
            raise ValueError("Cannot create a tenant-scoped object for a different tenant.")

    # modified objects
    for obj in session.dirty:

        if not isinstance(obj, TenantScopedMixin):
            continue

        obj_tenant_id = getattr(obj, "tenant_id", None)

        if obj_tenant_id != tenant_id:
            raise ValueError("Cannot move a tenant-scoped object to a different tenant.")
        
    # deleted objects
    for obj in session.deleted:

        if not isinstance(obj, TenantScopedMixin):
            continue

        obj_tenant_id = getattr(obj, "tenant_id", None)

        if obj_tenant_id != tenant_id:
            raise ValueError("Cannot delete a tenant-scoped object belonging to a different tenant.")





# store tenant context
current_tenant_id: ContextVar[UUID | None] = ContextVar("current_tenant_id", default=None)

bypass_rls = ContextVar("bypass_rls", default=False)





# function to lock tenant row against race conditions
async def lock_tenant(tenant_id: UUID, db: AsyncSession) -> Tenant:
    """
    Acquires a pessimistic lock on a tenant row.

    Blocks concurrent transactions until the current
    transaction commits or rolls back.
    """

    statement = (
        select(Tenant)
        .where(
            Tenant.tenant_id == tenant_id,
            Tenant.is_deleted.is_(False),
            Tenant.is_active.is_(True)
        )
        .with_for_update()
    )

    result = await db.exec(statement)
    tenant = result.first()

    if tenant is None:
        raise ValueError("Tenant not found.")

    return tenant
