# import dependencies
from fastapi import APIRouter, Depends, Query, status, Response, Request
from app.cores.logging import get_logger
from fastapi_limiter.depends import RateLimiter
from typing import Annotated, Optional
from app.schemas.admin import UserRead, PaginatedUsers, UserUpdate, UserUpdateRead
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.database import get_db
from sqlmodel import select, or_, func
from app.models import User, Role, AuditLog
from app.utility.security import get_identifier_factory, hash_password, verify_password
from app.utility.user import get_current_active_user
from app.services.admin import get_paginated, admin_change_user, admins_deactivate_user, admins_activate_user, admin_delete_user_account, admin_restore_user_account




# initialize logger
logger = get_logger(__name__)


# initialize router
router = APIRouter(prefix="/admin", tags=["admins"], dependencies=[Depends(get_current_active_user)])

# admin endpoint to retrieve users
@router.get("/users", response_model=PaginatedUsers)
async def get_users_paginated(
    *,
    page: Annotated[int, Query(ge=1, description="Page number (starts at 1)")] = 1,
    size: Annotated[int, Query(ge=1, le=100, description="Items per page (max 100)")] = 10,
    search: Annotated[Optional[str], Query(description="Search by username or email")] = None,
    # add more filters
    is_active: Annotated[Optional[bool], Query(description="Filter by active status")] = None,
    is_deleted: Annotated[Optional[bool], Query(description="Filter by delete status")] = None,
    country: Annotated[Optional[str], Query(description="Filter by country")] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return await get_paginated(
        page=page,
        size=size,
        search=search,
        is_active=is_active,
        is_deleted=is_deleted,
        country=country,
        current_user=current_user,
        db=db,
    )
   
    
    
    
# admin update-user endpoint
@router.patch(
    "/users/{user_id}",
    dependencies=[
        Depends(
            RateLimiter(
                times=5,
                minutes=10,
                identifier=get_identifier_factory("admin_update_user")
            )
        )
    ],
    response_model=UserUpdateRead
)
 
async def admin_update_user(
    user_id: int,
    request: Request,
    user_data: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return await admin_change_user(
        user_id=user_id,
        request=request,
        user_data=user_data,
        current_user=current_user,
        db=db
    )




# admin deactivate user endpoint
@router.patch(
    "/users/{user_id}/deactivate",
    dependencies=[
        Depends(
            RateLimiter(
                times=5,
                minutes=10,
                identifier=get_identifier_factory("admin_deactivate_user")
            )
        )
    ],
    status_code=status.HTTP_200_OK
)

async def admin_deactivate_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return await admins_deactivate_user(
        user_id=user_id,
        request=request,
        current_user=current_user,
        db=db,
    )




# admin activate user endpoint
@router.patch(
    "/users/{user_id}/activate",
    dependencies=[
        Depends(
            RateLimiter(
                times=5,
                minutes=10,
                identifier=get_identifier_factory("admin_activate_user")
            )
        )
    ],
    status_code=status.HTTP_200_OK
)

async def admin_activate_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return await admins_activate_user(
        user_id=user_id,
        request=request,
        current_user=current_user,
        db=db,
    )




# admin delete user endpoint
@router.patch(
    "/users/{user_id}/delete",
    dependencies=[
        Depends(
            RateLimiter(
                times=5,
                minutes=10,
                identifier=get_identifier_factory("admin_delete_user")
            )
        )
    ],
    status_code=status.HTTP_200_OK
)

async def admin_delete_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    return await admin_delete_user_account(
        user_id=user_id,
        request=request,
        current_user=current_user,
        db=db
    )
   



# admin restore user endpoint
@router.patch(
    "/users/{user_id}/restore", 
    dependencies=[
        Depends(
            RateLimiter(
                times=5,
                minutes=10,
                identifier=get_identifier_factory("admin_restore_user")
            )
        )
    ],
    status_code=status.HTTP_200_OK
)

async def admin_restore_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
   return await admin_restore_user_account(
       user_id=user_id,
       request=request,
       current_user=current_user,
       db=db
    )