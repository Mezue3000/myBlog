# import dependencies
from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks, Response, Request
from app.cores.logging import get_logger
from fastapi_limiter.depends import RateLimiter
from math import ceil
from typing import Annotated, Optional
from sqlalchemy.orm import selectinload 
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.database import get_db
from sqlmodel import select, or_, func
from app.models import User, Role, AuditLog
from app.utility.security import build_audit_context, create_auth_audit_log_bg
from sqlalchemy.exc import IntegrityError, SQLAlchemyError




logger = get_logger(__name__)


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




# admin ownership verifiction
def verify_admin_ownership(
    resource_owner: User,
    current_user: User,
    new_role_name: Optional[str] = None
) -> None:
    
    def get_level(role_name: Optional[str]) -> int:
        if not role_name:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="User has no role assigned"
            )

        level = ROLE_HIERARCHY.get(role_name)
        if level is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Unknown role '{role_name}' — contact administrator"
            )
        return level

    owner_level = get_level(resource_owner.role.name)
    current_level = get_level(current_user.role.name)

    # cannot modify superior or equal-level account (unless self)
    if owner_level >= current_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot modify a superior account"
        )

    # prevent role escalation
    if new_role_name:
        new_role_level = get_level(new_role_name)

        # cannot assign equal or higher role than yourself
        if new_role_level >= current_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You cannot assign this role"
            )
    return None


 


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




# function to count users
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