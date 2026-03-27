# import dependencies
from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks, Response, Request
from app.utility.logging import get_logger
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
from app.utility.email_auth import create_email_otp, send_verification_otp_email, verify_email_otp, create_auth_audit_log_bg
from app.utility.security import get_identifier_factory, hash_password, verify_password
from app.utility.user_service import verify_admin_ownership, get_current_active_user, logout_all_devices_for_user, build_audit_context, validate_unique_fields
from sqlalchemy.exc import IntegrityError, SQLAlchemyError




logger = get_logger()


# role hierarchy (module level)
ROLE_HIERARCHY = {
    "superadmin": 4,
    "admin": 3,
    "moderator": 2,
    "user": 1,
}




# role validation function
def validate_admin_access(current_user: User) -> int:
    role_name = current_user.role.name

    if role_name not in ROLE_HIERARCHY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    current_level = ROLE_HIERARCHY[role_name]

    if current_level <= ROLE_HIERARCHY["user"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not allowed to view users"
        )

    return current_level




# function to build filters 
def build_user_filters(
    *,
    search: Optional[str],
    is_active: Optional[bool],
    is_deleted: Optional[bool],
    country: Optional[str],
    current_level: int
):
    filters = []

    # Search filter
    if search:
        pattern = f"%{search.strip()}%"
        filters.append(
            or_(
                User.username.ilike(pattern),
                User.email.ilike(pattern)
            )
        )

    # optional filters
    if is_active is not None:
        filters.append(User.is_active == is_active)

    if is_deleted is not None:
        filters.append(User.is_deleted == is_deleted)

    if country:
        filters.append(User.country == country)

    # role visibility (strict downward)
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

    return filters




# function to coumt users
async def count_users(db: AsyncSession, filters: list) -> int:
    stmt = select(func.count(User.user_id))

    if filters:
        stmt = stmt.where(*filters)

    result = await db.exec(stmt)
    return result.one()




# function to fetch users
async def fetch_users(
    db: AsyncSession,
    filters: list,
    offset: int,
    limit: int
):
    stmt = (
        select(User)
        .options(selectinload(User.role))
        .order_by(User.created_at.desc())
        .offset(offset)
        .limit(limit)
    )

    if filters:
        stmt = stmt.where(*filters)

    result = await db.exec(stmt)
    return result.all()




# function to retrieve users with pagination
async def get_paginated(
    *,
    page: int,
    size: int,
    search: Optional[str],
    is_active: Optional[bool],
    is_deleted: Optional[bool],
    country: Optional[str],
    current_user: User,
    db: AsyncSession,
):
    # validate access
    current_level = validate_admin_access(current_user)
    
    # Log admin action
    logger.info(
        "admin_view_users",
        extra={
            "admin_id": current_user.user_id,
            "page": page,
            "size": size,
            "filters": {
                "search": search,
                "is_active": is_active,
                "is_deleted": is_deleted,
                "country": country
            }
        }
    )
    
    # build filters
    filters = build_user_filters(
        search=search,
        is_active=is_active,
        is_deleted=is_deleted,
        country=country,
        current_level=current_level
    )

    # count query
    total_users = await count_users(db, filters)

    # pagination
    offset = (page - 1) * size
    total_pages = ceil(total_users / size) if total_users > 0 else 1

    # fetch users
    users = await fetch_users(
        db=db,
        filters=filters,
        offset=offset,
        limit=size
    )

    # response
    return PaginatedUsers(
        items=users,
        total=total_users,
        page=page,
        size=size,
        total_pages=total_pages
    )
    
    
    
    
# function to get user with role
async def get_user_by_id_with_role(db: AsyncSession, user_id: int) -> User:
    stmt = (
        select(User)
        .where(User.user_id == user_id)
        .options(selectinload(User.role))
    )

    user = (await db.exec(stmt)).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user




# function to validate role
async def resolve_new_role(db: AsyncSession, update_fields: dict) -> Optional[str]:
    if "role_id" not in update_fields:
        return None

    role = await db.get(Role, update_fields["role_id"])

    if not role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role"
        )

    return role.name




# function to apply update and track changes
def apply_updates_and_track_changes(user: User, update_fields: dict) -> dict:
    changes = {}

    for key, new_value in update_fields.items():
        old_value = getattr(user, key)

        if old_value != new_value:
            changes[key] = {
                "old": str(old_value),
                "new": str(new_value)
            }
            setattr(user, key, new_value)

    return changes




# function to add auditLog infos
async def persist_with_audit(
    *,
    db: AsyncSession,
    request: Request,
    actor: User,
    target: User,
    action: str,
    changes: Optional[dict] = None,
    update_callback: Optional[callable] = None,
    background_tasks: Optional[BackgroundTasks] = None,
    use_background: bool = False
):
    try:
        # apply update (if provided)
        if update_callback:
            update_callback(target)

        db.add(target)

        # handle audit logging
        if changes:
            context = build_audit_context(request)

            if use_background and background_tasks:
                # safe background logging
                background_tasks.add_task(
                    create_auth_audit_log_bg,
                    action=action,
                    user_id=actor.user_id,
                    metadata=changes,
                    context=context,
                )
            else:
                # critical → same transaction
                audit_entry = AuditLog(
                    actor_id=actor.user_id,
                    target_user_id=target.user_id,
                    action=action,
                    changes=changes,
                    **context
                )
                db.add(audit_entry)

        # Commit
        await db.commit()
        await db.refresh(target)

    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Integrity error while processing request."
        )
        
        
        
         
# function to update user
async def admin_change_user(
    *,
    user_id: int,
    request: Request,
    user_data: UserUpdate,
    current_user: User,
    db: AsyncSession,
):
    # fetch target user
    target_user = await get_user_by_id_with_role(db, user_id)
    
    # log admin action
    logger.info(
        "admin_update_user",
        extra={
            "admin_id": current_user.user_id,
            "target_user_id": user_id
        }
    )

    # extract update fields
    update_fields = user_data.model_dump(exclude_unset=True)

    # resolve role change (if any)
    new_role_name = await resolve_new_role(db, update_fields)

    # enforce RBAC + hierarchy
    verify_admin_ownership(
        resource_owner=target_user,
        current_user=current_user,
        new_role_name=new_role_name
    )

    # validate unique fields
    await validate_unique_fields(
        db=db,
        fields=update_fields,
        exclude_user_id=target_user.user_id
    )

    # apply updates + track changes
    changes = apply_updates_and_track_changes(
        target_user,
        update_fields
    )

    # persist + audit
    await persist_with_audit(
        db=db,
        request=request,
        actor=current_user,
        target=target_user,
        action="UPDATE_USER",
        changes=changes,
    )

    return target_user




# function to prevent self action
def prevent_self_action(current_user: User, target_user: User, action: str):
    if current_user.user_id == target_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"You cannot {action} your own account"
        )
        
        
        
        
# function to ensure active users
def ensure_user_state(
    user: User,
    *,
    field: str,
    expected: bool,
    error_message: str
):
    current_value = getattr(user, field)

    if current_value != expected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )
        
        
        
        
# function to deactivate user      
async def admins_deactivate_user(
    *,
    user_id: int,
    request: Request,
    current_user: User,
    db: AsyncSession,
):
    # fetch target user
    target_user = await get_user_by_id_with_role(db, user_id)
    
    # add logging
    logger.info(
        "admin_deactivate_user",
        extra={
            "admin_id": current_user.user_id,
            "target_user_id": user_id
        }
    )

    # prevent self-action
    prevent_self_action(current_user, target_user, action="deactivate")

    # enforce RBAC hierarchy
    verify_admin_ownership(
        resource_owner=target_user,
        current_user=current_user
    )

    # prevent redundant operation
    ensure_user_state(
        target_user,
        field="is_active",
        expected=True,
        error_message="User account already deactivated"
    )

    # apply state change + audit
    changes = {"is_active": {"old": True, "new": False}}

    await persist_with_audit(
        db=db,
        request=request,
        current_user=current_user,
        target_user=target_user,
        action="DEACTIVATE_USER",
        changes=changes,
        update_callback=lambda user: setattr(user, "is_active", False),
    )

    return {"detail": "User account deactivated successfully"}




# function to activate user
async def admins_activate_user(
    *,
    user_id: int,
    request: Request,
    current_user: User,
    db: AsyncSession,
):
    # fetch target user
    target_user = await get_user_by_id_with_role(db, user_id)
    
    # add logging
    logger.info(
        "admin_activate_user",
        extra={
            "admin_id": current_user.user_id,
            "target_user_id": user_id
        }
    )

    # prevent self-action
    prevent_self_action(current_user, target_user, action="activate")

    # enforce RBAC hierarchy
    verify_admin_ownership(
        resource_owner=target_user,
        current_user=current_user
    )

    # prevent redundant operation
    ensure_user_state(
        target_user,
        field="is_active",
        expected=False,
        error_message="User account already active"
    )

    # apply state change + audit
    changes = {"is_active": {"old": False, "new": True}}

    await persist_with_audit(
        db=db,
        request=request,
        current_user=current_user,
        target_user=target_user,
        action="ACTIVATE_USER",
        changes=changes,
        update_callback=lambda user: setattr(user, "is_active", True)
    )

    return {"detail": "User account activated successfully"} 




# function to delete user
async def admin_delete_user_account(
    *,
    user_id: int,
    request: Request,
    current_user: User,
    db: AsyncSession,
):
    # fetch user
    target_user = await get_user_by_id_with_role(db, user_id)
    
    # add logging
    logger.info(
        "admin_delete_user",
        extra={
            "admin_id": current_user.user_id,
            "target_user_id": user_id
        }
    )
    
    # prevent self deletion
    prevent_self_action(current_user, target_user, action="delete")

    # enforce RBAC hierarchy
    verify_admin_ownership(
        resource_owner=target_user,
        current_user=current_user
    )

    # prevent duplicate deletion
    ensure_user_state(
        target_user,
        field="is_deleted",
        expected=False,
        error_message="User account already deleted"
    )

    # define audit changes
    changes = {
        "is_deleted": {
            "old": False,
            "new": True
        }
    }

    # persist + audit (transactional)
    await persist_with_audit(
        db=db,
        request=request,
        actor=current_user,
        target=target_user,
        action="DELETE_USER",
        changes=changes,
        update_callback=lambda u: setattr(u, "is_deleted", True),
    )

    # force logout (post-commit, non-transactional)
    await logout_all_devices_for_user(target_user.user_id)

    return {"detail": "User account deleted successfully"}




# function to restore deleted user
async def admin_restore_user_account(
    *,
    user_id: int,
    request: Request,
    current_user: User,
    db: AsyncSession,
):
    # fetch user
    target_user = await get_user_by_id_with_role(db, user_id)
    
    # add logging
    logger.info(
        "admin_restore_user",
        extra={
            "admin_id": current_user.user_id,
            "target_user_id": user_id
        }
    )
    
    # prevent self deletion
    prevent_self_action(current_user, target_user, action="restore")

    # enforce RBAC hierarchy
    verify_admin_ownership(
        resource_owner=target_user,
        current_user=current_user
    )

    # prevent duplicate deletion
    ensure_user_state(
        target_user,
        field="is_deleted",
        expected=True,
        error_message="User account is not deleted"
    )

    # define audit changes
    changes = {
        "is_deleted": {
            "old": True,
            "new": False
        }
    }

    # persist + audit (transactional)
    await persist_with_audit(
        db=db,
        request=request,
        actor=current_user,
        target=target_user,
        action="RESTORE_USER",
        changes=changes,
        update_callback=lambda u: setattr(u, "is_deleted", False)
    )

    return {"detail": "User account restored successfully"}