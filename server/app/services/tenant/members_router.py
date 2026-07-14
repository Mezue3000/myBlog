# import dependencies
from app.cores.logging import get_logger 
from pydantic import EmailStr
from fastapi import Depends, HTTPException, status, BackgroundTasks
from app.utility.platform.user import get_current_active_user
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.models import Tenant, User, TenantInvitation, TenantMembership, AuditLog
from app.utility.tenant.tenant_router import get_tenant_membership, generate_invite_token, get_tenant_membership_by_email, has_active_invitation, get_invitation_by_token, count_active_non_owner_members, lock_tenant, get_current_tenant
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from datetime import datetime, timezone
import os
from app.schemas.platform.users import UserCreate, UserRead
from app.utility.platform.user import validate_unique_fields, slugify
from app.utility.platform.security import hash_password
from typing import Optional
from app.utility.tenant.members_router import ensure_team_has_capacity
from app.utility.tenant.invite import accept_workspace_invitation







# initialize logging
logger = get_logger(__name__)




     
# function to accept IV
async def accept_invitation_service(
    token: str,
    current_user: User,
    db: AsyncSession
):
    logger.info(
        "Accept invitation started",
        extra={
            "user_id": current_user.user_id,
            "email": current_user.email,
            "token": token
        },
    )

    try:
        invitation = await get_invitation_by_token(token=token, db=db)

        if invitation is None:
            logger.warning("Invitation not found", extra={"token": token})
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invitation not found."
            )

        now = datetime.now(timezone.utc)

        # expired?
        if (
            invitation.expires_at is not None
            and invitation.expires_at < now
        ):
            logger.warning("Invitation expired", extra={"token": token})

            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Invitation has expired."
            )

        # already accepted?
        if invitation.is_accepted:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invitation already accepted."
            )

        # email mismatch?
        if (
            invitation.email.lower()
            != current_user.email.lower()
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invitation belongs to another user."
            )

        # already a member?
        existing_membership = await get_tenant_membership(
            user_id=current_user.user_id,
            tenant_id=invitation.tenant_id,
            db=db
        )

        if existing_membership:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Already a member."
            )

        # lock tenant
        tenant = await lock_tenant(tenant_id=invitation.tenant_id, db=db)

        # revalidate capacity
        if tenant.type == "team":
            await ensure_team_has_capacity(
                tenant=tenant,
                db=db,
                exclude_invitation_id=invitation.invitation_id
            )

        # create membership
        membership = TenantMembership(
            tenant_id=tenant.tenant_id,
            user_id=current_user.user_id
        )

        db.add(membership)

        # mark invitation accepted
        invitation.is_accepted = True
        invitation.accepted_at = now

        db.add(invitation)

        await db.flush()
        await db.commit()

        logger.info(
            "Invitation accepted successfully",
            extra={
                "tenant_id": str(tenant.tenant_id),
                "user_id": current_user.user_id
            },
        )

        return {
            "message": "Successfully joined workspace.",
            "tenant_id": tenant.tenant_id
        }

    except HTTPException:
        await db.rollback()
        raise

    except Exception:
        await db.rollback()
        logger.exception("Unexpected error accepting invitation.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to accept invitation."
        )


        
        
        
# function to register invited member
async def register_invited_member(
    user: UserCreate,
    token: str,
    db: AsyncSession
) -> UserRead:
    """
    Register a new user from a workspace invitation.

    Flow:
        1. Validate invitation.
        2. Create user.
        3. Create personal tenant.
        4. Commit registration.
        5. Accept workspace invitation.
        6. Return created user.
    """

    # validate invitation
    invitation = await get_invitation_by_token(token=token, db=db)

    if invitation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found."
        )

    now = datetime.now(timezone.utc)

    if invitation.is_accepted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invitation has already been accepted."
        )

    if (
        invitation.expires_at is not None
        and invitation.expires_at < now
    ):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Invitation has expired."
        )

    email = invitation.email.lower()

    # validate unique fields
    await validate_unique_fields(
        db=db,
        fields={
            "username": user.username.lower(),
            "email": email
        }
    )

    hashed_password = await hash_password(user.password)

    slug = slugify(user.username) + "-workspace"

    role_id = int(os.getenv("USERS_ROLE_ID"))

    try:
        
        # TRANSACTION 1
        # create account + personal tenant
        new_user = User(
            username=user.username.lower(),
            email=email,
            password_hash=hashed_password,
            biography=user.biography,
            country=user.country.lower(),
            city=user.city.lower(),
            role_id=role_id
        )

        db.add(new_user)
        await db.flush()

        personal_tenant = Tenant(
            name=f"{new_user.username}'s Workspace",
            slug=slug,
            owner_id=new_user.user_id
        )

        db.add(personal_tenant)
        await db.commit()
        await db.refresh(new_user)
        logger.info(
            "Invited user created successfully.",
            extra={
                "user_id": new_user.user_id,
                "email": new_user.email
            }
        )

    except IntegrityError:
        await db.rollback()
        logger.exception("Integrity error creating invited user.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to create account."
        )

    except Exception:
        await db.rollback()
        logger.exception("Failed creating invited user.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed."    
        )





    # TRANSACTION 2
    # join workspace
  
    workspace_joined = False
    message = None
    
    # initialize invitation
    invitation: Optional[TenantInvitation] = None
    
    try:
        invitation = await get_invitation_by_token(token=token, db=db)

        if invitation is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invitation no longer exists."
            )

        await accept_workspace_invitation(
            invitation=invitation,
            user=new_user,
            db=db
        )

        await db.commit()

        workspace_joined = True

        logger.info(
            "Invited user joined workspace successfully.",
            extra={
                "user_id": new_user.user_id,
                "tenant_id": str(invitation.tenant_id),
                "invitation_id": invitation.invitation_id
            }
    )

    except HTTPException as exc:
        await db.rollback()

        if exc.status_code == status.HTTP_403_FORBIDDEN:
            message = exc.detail
            logger.warning(
                "Account created but workspace join failed.",
                extra={
                    "user_id": new_user.user_id,
                    "tenant_id": str(invitation.tenant_id),
                    "invitation_id": invitation.invitation_id,
                    "reason": exc.detail
                }
        )

        else:
            logger.warning(
                "Invitation acceptance failed after registration.",
                extra={
                    "user_id": new_user.user_id,
                    "status_code": exc.status_code,
                    "reason": exc.detail
                }
        )
        raise

    except Exception:
        await db.rollback()
        logger.exception(
            "Unexpected error while joining invited workspace.",
            extra={
                "user_id": new_user.user_id,
                "tenant_id": (
                    str(invitation.tenant_id)
                    if invitation is not None
                    else None
                ),
            },
        )
        raise

    return {
        "user": UserRead.model_validate(new_user),
        "workspace_joined": workspace_joined,
        "message": message
    }
