# import dependencies
from app.cores.logging import get_logger 
from pydantic import EmailStr
from fastapi import Depends, HTTPException, status, BackgroundTasks
from sqlmodel.ext.asyncio.session import AsyncSession
from app.models import Tenant, User, TenantInvitation, TenantMembership, AuditLog
from app.utility.tenant.tenant_router import get_active_tenant_membership_by_user, get_invitation_by_token, lock_tenant
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from datetime import datetime, timezone
import os
from app.schemas.platform.users import UserCreate, UserRead, InvitedRegistrationResponse
from app.schemas.tenant.tenant_router import TenantMemberRead
from app.utility.platform.user import validate_unique_fields, slugify
from app.utility.platform.security import hash_password
from typing import Optional
from app.utility.tenant.members_router import ensure_team_has_capacity, get_members_by_tenant_id
from app.utility.tenant.invite import accept_workspace_invitation
from app.utility.stripe.helpers import get_plan_for_tenant_type
from uuid import UUID






# initialize logging
logger = get_logger(__name__)




# accept invitation service function
async def accept_invitation_service(
    token: str,
    current_user: User,
    db: AsyncSession
):
    user_id = current_user.user_id
    user_email = current_user.email

    try:
        logger.info(
            "Accept invitation started",
            extra={
                "user_id": user_id,
                "email": user_email
            },
        )

        invitation = await get_invitation_by_token(token=token, db=db)

        if invitation is None:
            logger.warning(
                "Invitation not found",
                extra={"user_id": user_id},
            )
            raise ValueError("Invitation not found.")

        now = datetime.now()

        if (
            invitation.expires_at is not None
            and invitation.expires_at < now
        ):
            logger.warning(
                "Invitation expired",
                extra={
                    "user_id": user_id,
                    "invitation_id": invitation.invitation_id
                },
            )
            raise ValueError("Invitation has expired.")

        if invitation.is_accepted:
            raise ValueError("Invitation already accepted.")

        if invitation.email.lower() != user_email.lower():
            raise ValueError("Invitation belongs to another user.")

        tenant_id = invitation.tenant_id

        existing_membership = await get_active_tenant_membership_by_user(
            user_id=user_id,
            tenant_id=tenant_id,
            db=db
        )

        if existing_membership:
            raise ValueError("Already a member.")

        tenant = await lock_tenant(tenant_id=tenant_id, db=db)

        if tenant.type == "team":
            await ensure_team_has_capacity(
                tenant=tenant,
                db=db,
                exclude_invitation_id=invitation.invite_id
            )

        membership = TenantMembership(tenant_id=tenant.tenant_id, user_id=user_id)

        db.add(membership)

        invitation.is_accepted = True
        invitation.accepted_at = now

        await db.flush()
        await db.commit()

        logger.info(
            "Invitation accepted successfully",
            extra={
                "tenant_id": str(tenant.tenant_id),
                "user_id": user_id,
                "invitation_id": invitation.invite_id
            },
        )

        return {
            "message": "Successfully joined workspace.",
            "tenant_id": tenant.tenant_id
        }

    except HTTPException:
        await db.rollback()
        raise

    except ValueError:
        await db.rollback()
        raise

    except SQLAlchemyError:
        await db.rollback()
        logger.exception(
            "Database error accepting invitation",
            extra={"user_id": user_id}
        )
        raise

    except Exception:
        await db.rollback()
        logger.exception(
            "Unexpected error accepting invitation",
            extra={"user_id": user_id}
        )
        raise
    
    
    
    

# function to register invited member
async def register_invited_member(
    user: UserCreate,
    token: str,
    db: AsyncSession
) -> InvitedRegistrationResponse:
    """
    Register a new user from a workspace invitation.

    Flow:
        1. Validate invitation.
        2. Validate unique user fields.
        3. Create user.
        4. Create personal tenant.
        5. Commit account creation.
        6. Accept workspace invitation.
        7. Commit workspace membership.
        8. Return registration result.
    """

    # validate invitation
    invitation = await get_invitation_by_token(token=token, db=db)

    if invitation is None:
        raise ValueError("Invitation not found.")

    if invitation.is_accepted:
        raise ValueError("Invitation has already been accepted.")

    now = datetime.now(timezone.utc)

    # MySQL DATETIME may return a naive datetime.
    expires_at = invitation.expires_at

    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < now:
            raise ValueError("Invitation has expired.")

    email = invitation.email.strip().lower()

    # keep the invitation tenant available before transaction 1.
    invitation_tenant_id = invitation.tenant_id
    invite_id = invitation.invite_id

    # validate unique fields
    await validate_unique_fields(
        db=db,
        fields={
            "username": user.username.strip().lower(),
            "email": email
        },
    )

    # prepare account data
    username = user.username.strip().lower()
    hashed_password = await hash_password(user.password)
    slug = f"{slugify(username)}-workspace"

    try:
        role_id = int(os.getenv("USERS_ROLE_ID", ""))

    except (TypeError, ValueError):
        logger.exception("USERS_ROLE_ID is not configured correctly.")
        raise RuntimeError("User role configuration is invalid.")

    # TRANSACTION 1
    # create account + personal tenant
    try:
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            role_id=role_id
        )

        db.add(new_user)

        # needed to obtain new_user.user_id before creating
        # the personal tenant.
        await db.flush()

        # retrieve personal free plan.
        free_plan = await get_plan_for_tenant_type(
            tenant_type="personal",
            plan_name="free",
            db=db
        )

        if free_plan is None:
            raise ValueError("Personal free plan is not configured.")

        personal_tenant = Tenant(
            name=f"{new_user.username}'s Workspace",
            slug=slug,
            owner_id=new_user.user_id,
            plan_id=free_plan.plan_id,
            credits_remaining=free_plan.credits
        )

        db.add(personal_tenant)

        # commit transaction 1.
        await db.commit()

        # refresh after commit because the session may expire
        # ORM attributes after commit.
        await db.refresh(new_user)

        logger.info(
            "Invited user account created successfully.",
            extra={
                "user_id": new_user.user_id,
                "email": new_user.email,
                "invitation_id": invite_id
            },
        )

    except IntegrityError:
        await db.rollback()

        logger.exception(
            "Integrity error creating invited user.",
            extra={
                "email": email,
                "invitation_id": invite_id
            },
        )

        raise ValueError("Unable to create account.")

    except ValueError:
        await db.rollback()

        logger.exception(
            "Validation error creating invited user.",
            extra={
                "email": email,
                "invitation_id": invite_id
            },
        )

        raise

    except Exception:
        await db.rollback()

        logger.exception(
            "Unexpected error creating invited user.",
            extra={
                "email": email,
                "invitation_id": invite_id
            },
        )

        raise


    # TRANSACTION 2
    # join invited workspace
    
    workspace_joined = False
    message: str | None = None

    # keep the ORM object intact.
    # capture scalar values before transaction boundaries so
    # rollback/expiration cannot trigger implicit database I/O.
    new_user_id = new_user.user_id
    new_user_email = new_user.email

    invite_id = invitation.invite_id
    invitation_tenant_id = invitation.tenant_id

    try:
        # re-fetch the invitation because transaction 1 committed.
        # this gives a fresh ORM instance.
        invitation = await get_invitation_by_token(token=token, db=db)

        if invitation is None:
            raise ValueError("Invitation no longer exists.")

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
                "user_id": new_user_id,
                "tenant_id": str(invitation_tenant_id),
                "invitation_id": invite_id,
                "email": new_user_email
        },
    )

    except HTTPException as exc:
        await db.rollback()

        # A forbidden workspace join should not destroy
        # the already-created account.
        if exc.status_code == status.HTTP_403_FORBIDDEN:
            workspace_joined = False
            message = str(exc.detail)

            logger.warning(
                "Account created but workspace join was denied.",
                extra={
                    "user_id": new_user_id,
                    "tenant_id": str(invitation_tenant_id),
                    "invitation_id": invite_id,
                    "reason": exc.detail
                },
            )

        else:
            logger.warning(
                "Invitation acceptance failed after registration.",
                extra={
                    "user_id": new_user_id,
                    "tenant_id": str(invitation_tenant_id),
                    "invitation_id": invite_id,
                    "status_code": exc.status_code,
                    "reason": exc.detail
                },
            )

        raise

    except ValueError:
        await db.rollback()

        logger.exception(
            "Invitation validation failed after registration.",
            extra={
                "user_id": new_user_id,
                "tenant_id": str(invitation_tenant_id),
                "invitation_id": invite_id
            },
        )

        raise

    except Exception:
        await db.rollback()

        logger.exception(
            "Unexpected error while joining invited workspace.",
            extra={
                "user_id": new_user_id,
                "tenant_id": str(invitation_tenant_id),
                "invitation_id": invite_id
            },
        )

        raise

    # return registration result
    return InvitedRegistrationResponse(
        user=UserRead.model_validate(new_user),
        workspace_joined=workspace_joined,
        message=message
    )





# service function to list specific tenant members
async def get_tenant_members_service(
    tenant_id: UUID, 
    current_user: User, 
    db: AsyncSession
):
    try:
        # fetch results containing membership and user details
        results = await get_members_by_tenant_id(tenant_id=tenant_id, db=db)

        members = [
            TenantMemberRead(
                membership_id=membership.membership_id,
                email=user.email,
                name=user.username,
                role=membership.role
            )
            for membership, user in results
        ]

        return members

    except Exception as e:
        logger.error(f"Error fetching members for tenant {tenant_id}: {str(e)}")
        raise ValueError("Failed to fetch tenant members")
