# import dependencies
from app.cores.logging import get_logger 
from dotenv import load_dotenv
from pydantic import EmailStr
from fastapi import Depends, HTTPException, status, BackgroundTasks
from app.utility.platform.user import get_current_active_user
from app.utility.tenant.tenant_router import get_current_tenant
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.models import Tenant, User, TenantInvitation, TenantMembership
from app.utility.tenant.tenant_router import get_tenant_membership, generate_invite_token, get_tenant_membership_by_email, has_active_invitation, get_invitation_by_token
from app.utility.tenant.invite import send_tenant_invitation_email, send_bulk_invitation_emails
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from datetime import datetime, timezone
import os
from server.app.schemas.platform.users import UserCreate, UserRead
from server.app.utility.platform.user import validate_unique_fields, slugify
from server.app.utility.platform.security import hash_password






# initialize logging
logger = get_logger(__name__)



# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/platform/.env") 



# add rate-limit for emails
MAX_INVITATIONS_PER_REQUEST = 20



# function for members invitation
async def invite_members_service(
    tenant: Tenant,
    emails: list[EmailStr],
    current_user: User,
    background_tasks: BackgroundTasks,
    db: AsyncSession,
):
    try:
        # prevent inviting to personal tenants
        if tenant.type == "personal":          
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN ,
                detail="Personal workspace cannot invite members. Please upgrade to team plan."
            )

        # ensure current user has permission to invite
        membership = await get_tenant_membership(
            user_id=current_user.user_id,
            tenant_id=tenant.tenant_id,
            db=db
        )

        if not membership or membership.role not in ["admin", "owner"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admin and owner can invite members."
            )
        
        # validate email list
        if not emails:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one email is required.",
            )

        if len(emails) > MAX_INVITATIONS_PER_REQUEST:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Maximum of "
                    f"{MAX_INVITATIONS_PER_REQUEST} "
                    f"invitations allowed per request."
                ),
            )
        
        # remove duplicates
        normalized_emails = {
            email.lower().strip()
            for email in emails
        }

        invited_emails = []
        skipped_emails = []

        # process each email
        for normalized_email in normalized_emails:
        
            # check if user is already a member
            existing_member = await get_tenant_membership_by_email(
                tenant_id=tenant.tenant_id,
                email=normalized_email,
                db=db
            )
        
            if existing_member:
                skipped_emails.append(
                    {
                        "email": normalized_email,
                        "reason": "Already a member",
                    }
                )
                
                continue
         
            existing_invitation = (
                await has_active_invitation(
                    tenant_id=tenant.tenant_id,
                    email=normalized_email,
                    db=db,
                )
            )

            if existing_invitation:
                skipped_emails.append(
                    {
                        "email": normalized_email,
                        "reason": (
                            "Active invitation exists"
                        ),
                    }
                )
                
                continue
            
            # generate invite token
            token = generate_invite_token()

            invitation = TenantInvitation(
            tenant_id=tenant.tenant_id,
            email=normalized_email,
            token=token,
            invited_by=current_user.user_id
        )

            db.add(invitation)
            invited_emails.append(
                {
                    "email": normalized_email,
                    "token": token,
                }
            )
            
        await db.flush()
        await db.commit()
   
   
        # send invitation emails concurrently
        if invited_emails:

            background_tasks.add_task(
                send_bulk_invitation_emails,
                invitations=invited_emails,
                tenant_name=tenant.name,
                invited_by=current_user.username,
            )

        logger.info(
            f"User {current_user.user_id} "
            f"invited {len(invited_emails)} members "
            f"to tenant {tenant.tenant_id}"
        )

        return {
            "message": ("Invitations processed successfully"),
            "invited_count": len(invited_emails),
            "skipped_count": len(skipped_emails),
            "invited": [item["email"] for item in invited_emails],
            "skipped": skipped_emails,
        }

    except HTTPException:
        raise
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error inviting members: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error",
        )

    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to invite members: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to invite members",
        )
        
        
        
        
        
# function to accept IV
async def accept_invitation_service(
    token: str,
    current_user: User,
    db: AsyncSession,
):
    logger.info(
        "Accept invitation started",
        extra={
            "user_id": current_user.user_id,
            "email": current_user.email,
            "token": token,
        },
    )

    try:
        invitation = await get_invitation_by_token(token=token, db=db)

        if not invitation:
            logger.warning(
                "Invitation not found",
                extra={"token": token},
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invitation not found"
            )

        # expiry check
        now = datetime.now(timezone.utc)

        if invitation.expires_at and invitation.expires_at < now:
            logger.warning(
                "Invitation expired",
                extra={
                    "token": token,
                    "expires_at": str(invitation.expires_at),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Invitation has expired",
            )

        if invitation.is_accepted:
            logger.warning(
                "Invitation already accepted",
                extra={"token": token},
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invitation already accepted",
            )

        if invitation.email.lower() != current_user.email.lower():
            logger.warning(
                "Invitation email mismatch",
                extra={
                    "invitation_email": invitation.email,
                    "user_email": current_user.email,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invitation belongs to another user",
            )

        membership = await get_tenant_membership(
            user_id=current_user.user_id,
            tenant_id=invitation.tenant_id,
            db=db,
        )

        if membership:
            logger.info(
                "User already a member",
                extra={
                    "user_id": current_user.user_id,
                    "tenant_id": str(invitation.tenant_id),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Already a member",
            )

        new_membership = TenantMembership(
            tenant_id=invitation.tenant_id,
            user_id=current_user.user_id
        )

        db.add(new_membership)

        invitation.is_accepted = True

        await db.commit()

        logger.info(
            "Invitation accepted successfully",
            extra={
                "user_id": current_user.user_id,
                "tenant_id": str(invitation.tenant_id),
            },
        )

        return {
            "message": "Successfully joined workspace",
            "tenant_id": str(invitation.tenant_id),
        }

    except HTTPException:
        # let fastapi handle intended errors
        await db.rollback()
        raise

    except Exception as e:
        logger.exception(
            "Unexpected error while accepting invitation"
        )
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e
        
        
        
        

# function to register invited member
async def register_invited_member(
    user: UserCreate,
    token: str,
    db: AsyncSession,
):
    try:
        # validate invitation
        invitation = await get_invitation_by_token(token=token, db=db)

        if not invitation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invitation not found",
            )

        if invitation.is_accepted:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invitation already accepted",
            )

        if invitation.expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invitation expired",
            )

        # email comes from invitation
        email = invitation.email.lower()

        # validate unique fields
        await validate_unique_fields(
            db=db,
            fields={
                "username": user.username.lower(),
                "email": email,
            },
        )

        # hash password
        hashed_password = await hash_password(user.password)

        role_id = os.getenv("USERS_ROLE_ID")

        slug = (slugify(user.username)+ "-workspace")

        # create user
        new_user = User(
            email=email,
            username=user.username.lower(),
            password_hash=hashed_password,
            biography=user.biography,
            country=user.country.lower(),
            city=user.city.lower(),
            role_id=role_id,
        )

        db.add(new_user)

        await db.flush()

        # create personal workspace
        personal_tenant = Tenant(
            name="private",
            slug=slug,
            type="personal",
            owner_id=new_user.user_id,
        )

        db.add(personal_tenant)

        # create membership in invited workspace
        membership = TenantMembership(
            tenant_id=invitation.tenant_id,
            user_id=new_user.user_id
        )

        db.add(membership)

        # mark invitation as accepted
        invitation.is_accepted = True

        await db.commit()

        await db.refresh(new_user)

        logger.info(
            f"Invited user registered successfully: "
            f"{email}"
        )

        return UserRead.model_validate(new_user)

    except HTTPException:
        await db.rollback()
        raise

    except IntegrityError:

        await db.rollback()

        logger.error(
            f"Integrity error during invited "
            f"registration: {user.username}"
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists",
        )

    except Exception as e:

        await db.rollback()

        logger.error(
            f"Failed invited registration: "
            f"{str(e)}"
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed",
        )