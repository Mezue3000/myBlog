# import dependencies
from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks, Response
from app.utility.logging import get_logger
import logging
from fastapi_limiter.depends import RateLimiter
from math import ceil
from typing import Annotated, Optional
from pydantic import EmailStr
from app.schemas.admin import UserRead, PaginatedUsers
from sqlalchemy.orm import selectinload 
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.database import get_db
from sqlmodel import select, or_, func
from app.models import User, Role
from app.utility.email_auth import create_email_otp, send_verification_otp_email, verify_email_otp
from app.utility.security import get_identifier_factory, hash_password, verify_password
from app.utility.auth import verify_admin_ownership, get_current_user, get_current_active_user



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

@router.get("/users", response_model=PaginatedUsers)
async def get_users_paginated(
    *,
    page: Annotated[int, Query(ge=1, description="Page number (starts at 1)")] = 1,
    size: Annotated[int, Query(ge=1, le=100, description="Items per page (max 100)")] = 10,
    search: Annotated[Optional[str], Query(description="Search by username or email")] = None,
    # add more filters
    is_active: Annotated[Optional[bool], Query(description="Filter by active status")] = None,
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