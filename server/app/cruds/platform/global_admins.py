# import dependencies
from fastapi import APIRouter, Depends, Query, status, Response, Request
from app.cores.logging import get_logger
from app.rate_limit.limiter import limiter
from app.rate_limit.policy import AUTH_LIMITS
from app.rate_limit.keys import user_key_func
from typing import Annotated, Optional
from app.schemas.platform.global_admin import UserRead, PaginatedUsers, UserUpdate, UserUpdateRead, PaginatedTenants
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from sqlmodel import select, or_, func
from app.models import User, Role, AuditLog
from app.utility.platform.security import hash_password, verify_password, require_super_admin, require_admin, require_moderator
from app.utility.platform.user import get_current_active_user
from app.services.platform.global_admin import get_paginated_users, admin_change_user, admins_deactivate_user, admin_get_user_activated, admin_delete_user_account, admin_restore_user_account, get_paginated_tenants, admins_deactivate_tenant, admins_activate_tenant
from uuid import UUID




# initialize logger
logger = get_logger(__name__) 


# initialize router
router = APIRouter(
    prefix="/v1/global_admin", 
    tags=["global_admins"], 
    dependencies=[Depends(get_current_active_user)]
)

# admin endpoint to retrieve users
@router.get("/users", response_model=PaginatedUsers)


@limiter.limit(AUTH_LIMITS["ip_admins_read"])      
@limiter.limit(AUTH_LIMITS["get_data"], key_func=user_key_func)
async def get_users_paginated(
    request: Request,
    *,
    page: Annotated[int, Query(ge=1, description="Page number (starts at 1)")] = 1,
    size: Annotated[int, Query(ge=1, le=100, description="Items per page (max 100)")] = 10,
    search: Annotated[Optional[str], Query(description="Search by username or email")] = None,
    is_active: Annotated[Optional[bool], Query(description="Filter by active status")] = None,
    is_deleted: Annotated[Optional[bool], Query(description="Filter by delete status")] = None,
    country: Annotated[Optional[str], Query(description="Filter by country")] = None,
    current_user: User = Depends(require_moderator),
    db: AsyncSession = Depends(get_db)
):
    return await get_paginated_users(
        request=request,
        page=page,
        size=size,
        search=search,
        is_active=is_active,
        is_deleted=is_deleted,
        country=country,
        current_user=current_user,
        db=db
    ) 
   
    
    
    
# admin update-user endpoint
@router.patch("/users/{user_id}", response_model=UserUpdateRead)


@limiter.limit(AUTH_LIMITS["ip_admin_write"])      
@limiter.limit(AUTH_LIMITS["admin_patch"], key_func=user_key_func)
async def admin_update_user(
    request: Request,
    user_id: int,
    user_data: UserUpdate,
    current_user: User = Depends(require_moderator),
    db: AsyncSession = Depends(get_db)
):
    return await admin_change_user(
        request=request,
        user_id=user_id,
        user_data=user_data,
        current_user=current_user,
        db=db
    )




# admin deactivate user endpoint
@router.patch("/users/{user_id}/deactivate", status_code=status.HTTP_200_OK)

@limiter.limit(AUTH_LIMITS["ip_admin_write"])      
@limiter.limit(AUTH_LIMITS["admin_patch"], key_func=user_key_func)
async def admin_deactivate_user(
    request: Request,
    user_id: int,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    return await admins_deactivate_user(
        request=request,
        user_id=user_id,
        current_user=current_user,
        db=db
    )




# admin activate user endpoint
@router.patch("/users/{user_id}/activate", status_code=status.HTTP_200_OK)

@limiter.limit(AUTH_LIMITS["ip_admin_write"])      
@limiter.limit(AUTH_LIMITS["admin_patch"], key_func=user_key_func)
async def admin_activate_user(
    request: Request,
    user_id: int,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    return await admin_get_user_activated(
        user_id=user_id,
        request=request,
        current_user=current_user,
        db=db
    )




# admin delete user endpoint
@router.patch("/users/{user_id}/delete", status_code=status.HTTP_200_OK)

@limiter.limit(AUTH_LIMITS["ip_admin_write"])      
@limiter.limit(AUTH_LIMITS["admin_delete"], key_func=user_key_func)
async def admin_delete_user(
    request: Request,
    user_id: int,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    return await admin_delete_user_account(
        user_id=user_id,
        request=request,
        current_user=current_user,
        db=db
    )
   



# admin restore user endpoint
@router.patch("/users/{user_id}/restore", status_code=status.HTTP_200_OK)

@limiter.limit(AUTH_LIMITS["ip_admin_write"])      
@limiter.limit(AUTH_LIMITS["admin_restore"], key_func=user_key_func)
async def admin_restore_user(
    request: Request,
    user_id: int,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
   return await admin_restore_user_account(
       request=request,
       user_id=user_id,
       current_user=current_user,
       db=db
    )
   
   
   
   
   
# admin endpoint to retrieve tenants
@router.get("/tenants", response_model=PaginatedTenants)


@limiter.limit(AUTH_LIMITS["ip_admins_read"])      
@limiter.limit(AUTH_LIMITS["get_data"], key_func=user_key_func)
async def get_tenants_paginated(
    request: Request,
    *,
    page: Annotated[int, Query(ge=1, description="Page number (starts at 1)")] = 1,
    size: Annotated[int, Query(ge=1, le=100, description="Items per page (max 100)")] = 10,
    search: Annotated[Optional[str], Query(description="Search by tenant name or slug")] = None,
    tenant_type: Annotated[Optional[str], Query(description="Filter by tenant type")] = None,
    plan: Annotated[Optional[str], Query(description="Filter by subscription plan")] = None,
    is_active: Annotated[Optional[bool], Query(description="Filter by active status")] = None,
    is_deleted: Annotated[Optional[bool], Query(description="Filter by deleted status")] = None,
    current_user: User = Depends(require_moderator),
    db: AsyncSession = Depends(get_db)
):
    return await get_paginated_tenants(
        request=request,
        page=page,
        size=size,
        search=search,
        tenant_type=tenant_type,
        plan=plan,
        is_active=is_active,
        is_deleted=is_deleted,
        current_user=current_user,
        db=db
    )
    
    
    
    
    
# endpoint to deactivate tenant
@router.patch("/tenants/{tenant_id}/deactivate", status_code=status.HTTP_200_OK)

@limiter.limit(AUTH_LIMITS["ip_admin_write"])      
@limiter.limit(AUTH_LIMITS["admin_deactivate"], key_func=user_key_func)
async def deactivate_tenant(
    request: Request,
    tenant_id: UUID,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    return await admins_deactivate_tenant(
        request=request,
        tenant_id=tenant_id,
        current_user=current_user,
        db=db
    )
    
    
    
    
    
# endpoint to activate tenant
@router.patch("/tenants/{tenant_id}/activate", status_code=status.HTTP_200_OK)

@limiter.limit(AUTH_LIMITS["ip_admin_write"])      
@limiter.limit(AUTH_LIMITS["admin_restore"], key_func=user_key_func)
async def activate_tenant(
    request: Request,
    tenant_id: UUID,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    return await admins_activate_tenant(
        request=request,
        tenant_id=tenant_id,
        current_user=current_user,
        db=db
    )
