# import dependencies
from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks, Response, Request
from app.utility.logging import get_logger
import logging
from fastapi_limiter.depends import RateLimiter
from math import ceil
from typing import Annotated, Optional
from pydantic import EmailStr
from app.schemas.admin import UserRead, PaginatedUsers, UserUpdate, UserUpdateRead
from sqlalchemy.orm import selectinload 
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.database import get_db
from sqlmodel import select, or_, func
from app.models import User, Role, AuditLog
from app.utility.email_auth import create_email_otp, send_verification_otp_email, verify_email_otp
from app.utility.security import get_identifier_factory, hash_password, verify_password
from app.utility.auth import verify_admin_ownership, get_current_active_user, logout_all_devices_for_user, build_audit_context
from sqlalchemy.exc import IntegrityError, SQLAlchemyError



# initialize logger
logger = get_logger("auth")


# role hierarchy (module level)
ROLE_HIERARCHY = {
    "superadmin": 4,
    "admin": 3,
    "moderator": 2,
    "user": 1,
}


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
    # role validation
    if current_user.role.name not in ROLE_HIERARCHY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    current_level = ROLE_HIERARCHY.get(current_user.role.name)

    if current_level <= ROLE_HIERARCHY["user"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to view users"
        )

    filters = []

    # search filter
    if search:
        search_pattern = f"%{search.strip()}%"
        filters.append(
            or_(
                User.username.ilike(search_pattern),
                User.email.ilike(search_pattern)
            )
        )

    # additional filters
    if is_active is not None:
        filters.append(User.is_active == is_active)

    if country is not None:
        filters.append(User.country == country)

    if is_deleted is not None:
        filters.append(User.country == is_deleted)
        
    # strict downward visibility
    allowed_roles = [
        role_name
        for role_name, level in ROLE_HIERARCHY.items()
        if level < current_level
    ]

    if not allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to view users"
        )

    filters.append(
        User.role.has(Role.name.in_(allowed_roles))
    )

    # count query
    count_stmt = select(func.count(User.user_id))
    if filters:
        count_stmt = count_stmt.where(*filters)

    total_users = (await db.exec(count_stmt)).one()

    # pagination
    offset = (page - 1) * size
    total_pages = ceil(total_users / size) if total_users > 0 else 1

    # data query
    stmt = (
        select(User)
        .options(selectinload(User.role))
        .order_by(User.created_at.desc())
        .offset(offset)
        .limit(size)
    )

    if filters:
        stmt = stmt.where(*filters)

    users = (await db.exec(stmt)).all()

    # response
    return PaginatedUsers(
        items=users,
        total=total_users,
        page=page,
        size=size,
        total_pages=total_pages
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
    # fetch target user
    stmt = (
        select(User)
        .where(User.user_id == user_id)
        .options(selectinload(User.role))
    )

    target_user = (await db.exec(stmt)).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # extract update fields
    update_fields = user_data.model_dump(exclude_unset=True)

    # resolve new role (if provided)
    new_role_name = None

    if "role_id" in update_fields:
        new_role = await db.get(Role, update_fields["role_id"])

        if not new_role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid role"
            )

        new_role_name = new_role.name

    # centralized hierarchy enforcement(includes escalation prevention)
    verify_admin_ownership(resource_owner=target_user, current_user=current_user, new_role_name=new_role_name)

    # duplicate username check
    if "username" in update_fields:
        existing_user = (
            await db.exec(
                select(User).where(User.username == update_fields["username"])
            )
        ).first()

        if existing_user and existing_user.user_id != target_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken."
            )

    # duplicate email check
    if "email" in update_fields:
        existing_user = (await db.exec(select(User).where(User.email == update_fields["email"]))).first()

        if existing_user and existing_user.user_id != target_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use."
            )

    # capture original values(before update)
    original_values = {
        field: getattr(target_user, field)
        for field in update_fields.keys()
    }

    # apply updates
    for key, value in update_fields.items():
        setattr(target_user, key, value)

    # build audit changes (old → new)
    changes = {}

    for key, old_value in original_values.items():
        new_value = getattr(target_user, key)

        if old_value != new_value:
            changes[key] = {
                "old": str(old_value),
                "new": str(new_value)
            }

    # commit transaction + audit log
    try:
        db.add(target_user)
        
        # extract metadata
        context = build_audit_context(request)
        
        # only log if something changed
        if changes:
            audit_entry = AuditLog(
                actor_id=current_user.user_id,
                target_user_id=target_user.user_id,
                action="UPDATE_USER",
                changes=changes,
                **context
            )
            db.add(audit_entry)

        await db.commit()

    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Integrity error while updating user."
        )

    await db.refresh(target_user)

    return target_user




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
    db: AsyncSession = Depends(get_db)
):
    # fetch target user
    stmt = (
        select(User)
        .where(User.user_id == user_id)
        .options(selectinload(User.role))
    )

    target_user = (await db.exec(stmt)).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # prevent self deactivation
    if current_user.user_id == target_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account"
        )

    # enforce hierarchy rules
    verify_admin_ownership(
        resource_owner=target_user,
        current_user=current_user
    )

    # prevent double deactivation
    if not target_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account already deactivated"
        )

    try:
        # deactivate account
        target_user.is_active = False
        db.add(target_user)
        
        # extract metadata
        context = build_audit_context(request)

        # audit log
        audit_entry = AuditLog(
            actor_id=current_user.user_id,
            target_user_id=target_user.user_id,
            action="DEACTIVATE_USER",
            changes={
                "is_active": {
                    "old": True,
                    "new": False
                }
            },
            **context
        )

        db.add(audit_entry)

        await db.commit()

    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate user"
        ) from e

    return {"detail": "User account deactivated successfully"} 





# admin activate user endpoint
@router.patch(
    "/users/{user_id}/activate",
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

async def admin_activate_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    # fetch target user
    stmt = (
        select(User)
        .where(User.user_id == user_id)
        .options(selectinload(User.role))
    )

    target_user = (await db.exec(stmt)).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # prevent self activation
    if current_user.user_id == target_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot activate your own account"
        )

    # enforce hierarchy rules
    verify_admin_ownership(
        resource_owner=target_user,
        current_user=current_user
    )

    # prevent double activation
    if target_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account already activated"
        )

    try:
        # activate account
        target_user.is_active = True
        db.add(target_user)

        # extract metadata
        context = build_audit_context(request)

        # audit log
        audit_entry = AuditLog(
            actor_id=current_user.user_id,
            target_user_id=target_user.user_id,
            action="ACTIVATE_USER",
            changes={
                "is_active": {
                    "old": False,
                    "new": True
                }
            },
            **context
        )

        db.add(audit_entry)

        await db.commit()

    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate user"
        ) from e

    return {"detail": "User account activated successfully"} 




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
    # fetch target user
    stmt = (
        select(User)
        .where(User.user_id == user_id)
        .options(selectinload(User.role))
    )

    target_user = (await db.exec(stmt)).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # prevent self deletion
    if current_user.user_id == target_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account"
        )

    # enforce hierarchy rules
    verify_admin_ownership(
        resource_owner=target_user,
        current_user=current_user
    )

    # prevent double deletion
    if target_user.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account already deleted"
        )

    try:
        # delete account
        target_user.is_deleted = True
        db.add(target_user)

        # force logout (invalidate sessions)
        await logout_all_devices_for_user(target_user.user_id)
        
        # extract metadata
        context = build_audit_context(request)

        # audit log
        audit_entry = AuditLog(
            actor_id=current_user.user_id,
            target_user_id=target_user.user_id,
            action="DELETE_USER",
            changes={
                "is_deleted": {
                    "old": False,
                    "new": True
                }
            },
            **context
        )

        db.add(audit_entry)

        await db.commit()

    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        ) from e

    return {"detail": "User account deleted successfully"} 




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
    # fetch target user
    stmt = (
        select(User)
        .where(User.user_id == user_id)
        .options(selectinload(User.role))
    )

    target_user = (await db.exec(stmt)).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # prevent self restoration
    if current_user.user_id == target_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot restore your own account"
        )

    # enforce hierarchy rules
    verify_admin_ownership(
        resource_owner=target_user,
        current_user=current_user
    )

    # prevent double activation
    if target_user.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is alive"
        )

    try:
        # restore account
        target_user.is_deleted = False
        db.add(target_user)

        # extract metadata
        context = build_audit_context(request)

        # audit log
        audit_entry = AuditLog(
            actor_id=current_user.user_id,
            target_user_id=target_user.user_id,
            action="RESTORE_USER",
            changes={
                "is_deleted": {
                    "old": True,
                    "new": False
                }
            },
            **context
        )

        db.add(audit_entry)

        await db.commit()

    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to restore user"
        ) from e

    return {"detail": "User account restored successfully"} 