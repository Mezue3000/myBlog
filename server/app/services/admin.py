# import dependencies
from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks, Response, Request
from app.cores.logging import get_logger
from app.utility.admin import validate_admin_access, build_user_filters, fetch_users, count_users, get_user_by_id_with_role 
from math import ceil
from typing import Annotated, Optional
from app.schemas.admin import UserRead, PaginatedUsers, UserUpdate, UserUpdateRead
from sqlmodel.ext.asyncio.session import AsyncSession
from app.models import User, Role, AuditLog
from app.utility.user import get_current_active_user, logout_all_devices_for_user, validate_unique_fields
from app.utility.admin import resolve_new_role, apply_updates_and_track_changes, persist_with_audit, prevent_self_action, ensure_user_state, verify_admin_ownership, build_audit_context, create_auth_audit_log_bg





logger = get_logger(__name__)  



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
    changes = apply_updates_and_track_changes(target_user, update_fields)

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
    verify_admin_ownership(resource_owner=target_user, current_user=current_user)

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
async def admin_get_user_activated( 
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
    verify_admin_ownership(resource_owner=target_user, current_user=current_user)

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
    verify_admin_ownership(resource_owner=target_user, current_user=current_user)

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
    verify_admin_ownership(resource_owner=target_user, current_user=current_user)

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