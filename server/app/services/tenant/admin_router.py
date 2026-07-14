# import dependencies
from app.cores.logging import get_logger 
from dotenv import load_dotenv
from pydantic import EmailStr
from fastapi import Depends, HTTPException, status, BackgroundTasks
from app.utility.platform.user import get_current_active_user
from app.utility.tenant.tenant_router import get_current_tenant
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.models import Tenant, User, TenantInvitation, TenantMembership, AuditLog
from app.utility.tenant.tenant_router import get_tenant_membership, generate_invite_token, get_tenant_membership_by_email, has_active_invitation, get_invitation_by_token, count_active_non_owner_members, lock_tenant
from app.utility.tenant.admin_router import validate_tenant_role_hierarchy
from app.utility.tenant.invite import send_tenant_invitation_email, send_bulk_invitation_emails
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from datetime import datetime, timezone
import os
from app.schemas.platform.users import UserCreate, UserRead
from app.utility.platform.user import validate_unique_fields, slugify
from app.utility.platform.security import hash_password
from app.utility.platform.email import create_email_otp, verify_email_otp, send_verification_otp_email
from app.utility.tenant.members_router import get_remaining_team_slots





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
        # personal tenants cannot invite
        if tenant.type == "personal":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Personal workspace cannot invite members. Please upgrade to a team plan."
            )

        # RBAC
        membership = await get_tenant_membership(
            user_id=current_user.user_id,
            tenant_id=tenant.tenant_id,
            db=db
        )

        if (
            membership is None
            or membership.role not in ["owner", "admin"]
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only owners and admins can invite members."
            )

        # validate request
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
                    "emails per request."
                ),
            )

        normalized_emails = {
            email.lower().strip()
            for email in emails
        }

        # lock tenant
        tenant = await lock_tenant(tenant_id=tenant.tenant_id, db=db)

        # calculate remaining capacity
        remaining_slots = await get_remaining_team_slots(tenant=tenant, db=db)

        invited_emails = []
        skipped_emails = []

        # process invitations
        for normalized_email in normalized_emails:

            # no more capacity
            if remaining_slots <= 0:
                skipped_emails.append(
                    {
                        "email": normalized_email,
                        "reason": "Team member limit reached."
                    }
                )
                continue

            # already a member?
            existing_member = (
                await get_tenant_membership_by_email(
                    tenant_id=tenant.tenant_id,
                    email=normalized_email,
                    db=db
                )
            )

            if existing_member:
                skipped_emails.append(
                    {
                        "email": normalized_email,
                        "reason": "Already a member."
                    }
                )
                continue

            # already invited?
            existing_invitation = (
                await has_active_invitation(
                    tenant_id=tenant.tenant_id,
                    email=normalized_email,
                    db=db
                )
            )

            if existing_invitation:
                skipped_emails.append(
                    {
                        "email": normalized_email,
                        "reason": "Active invitation exists."
                    }
                )
                continue

            # create invitation
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
                    "token": token
                }
            )

            # consume one available slot
            remaining_slots -= 1

        # persist
        await db.flush()
        await db.commit()

        # send emails after commit
        if invited_emails:
            background_tasks.add_task(
                send_bulk_invitation_emails,
                invitations=invited_emails,
                tenant_name=tenant.name,
                invited_by=current_user.username
            )

        logger.info(
            "User %s invited %s members to tenant %s.",
            current_user.user_id,
            len(invited_emails),
            tenant.tenant_id
        )

        return {
            "message": "Invitations processed successfully.",
            "invited_count": len(invited_emails),
            "skipped_count": len(skipped_emails),
            "invited": [
                item["email"]
                for item in invited_emails
            ],
            "skipped": skipped_emails
        }

    except HTTPException:
        raise

    except SQLAlchemyError as e:
        await db.rollback()
        logger.exception("Database error inviting members.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error."
        ) from e

    except Exception as e:
        await db.rollback()
        logger.exception("Unexpected error inviting members.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to invite members."
        ) from e
        
        
        
        
   
# function to soft-delete member
async def delete_member_service(
    tenant: Tenant,
    member_id: int,
    current_user: User,
    db: AsyncSession
):
    try:
        logger.info(
            f"User {current_user.user_id} "
            f"attempting to delete member "
            f"{member_id} from tenant "
            f"{tenant.tenant_id}"
        )

        # prevent admin from removing themselves
        if member_id == current_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Use leave workspace endpoint instead"
            )
        
        # validate role hierarchy
        target_membership = await validate_tenant_role_hierarchy(
            actor_user_id=current_user.user_id,
            target_user_id=member_id,
            tenant_id=tenant.tenant_id,
            db=db
        )
        
        if target_membership.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Member is already deleted"
            )

        # soft delete membership
        target_membership.is_deleted = True
        target_membership.is_active = False
        target_membership.deleted_at = datetime.now(timezone.utc)
        target_membership.deleted_by = current_user.user_id

        # create audit log
        audit_log = AuditLog(
            tenant_id=tenant.tenant_id,
            actor_user_id=current_user.user_id,
            target_user_id=member_id,
            action="member.deleted",
            resource_type="tenant_membership",
            resource_id=str(target_membership.membership_id),
            metadata={"role": target_membership.role}
        )

        db.add(audit_log)
        await db.commit()

        logger.info(
            f"Member {member_id} deleted "
            f"from tenant "
            f"{tenant.tenant_id} by "
            f"{current_user.user_id}"
        )

        return {"message": ("Member deleted successfully")}

    except HTTPException:
        raise

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(
            f"Database error deleting member "
            f"{member_id}: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error"
        )

    except Exception as e:
        await db.rollback()
        logger.exception(
            f"Unexpected error deleting "
            f"member {member_id}: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete member"
        )
        
        
        
        
        
# function to request deletion OTP
async def request_delete_tenant_otp(
    *,
    background_tasks: BackgroundTasks,
    tenant: Tenant,
    current_user: User,
    db: AsyncSession
):
    logger.info(
        f"User {current_user.user_id} "
        f"requesting deletion OTP for tenant "
        f"{tenant.tenant_id}"
    )
    
    # personal workspace cannot be deleted
    if tenant.type == "personal":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Personal workspace cannot be deleted"
        )

    # ensure all members are removed
    remaining_members = await count_active_non_owner_members(
        tenant_id=tenant.tenant_id,
        owner_id=tenant.owner_id,
        db=db
    )

    if remaining_members > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="delete all members before deleting the workspace."
        )

    # generate OTP
    otp = await create_email_otp(
        email=current_user.email,
        scope="delete_tenant"
    )

    # send email
    background_tasks.add_task(
        send_verification_otp_email,
        email=current_user.email,
        otp=otp,
        scope="delete_tenant"
    )

    return {"detail": "A verification code has been sent to your email."}
        
        
        
        

# confirm tenant deletion
async def delete_tenant_service(
    *,
    tenant: Tenant,
    current_user: User,
    otp: int,
    db: AsyncSession
):
    # verify deletion OTP
    await verify_email_otp(
        email=current_user.email,
        otp=otp,
        scope="delete_tenant"
    )

    try:
        logger.info(
            f"User {current_user.user_id} "
            f"confirmed deletion of tenant "
            f"{tenant.tenant_id}"
        )

        tenant.is_active = False
        tenant.is_deleted = True
        tenant.deleted_at = datetime.now(timezone.utc)
        tenant.deleted_by = current_user.user_id

        audit_log = AuditLog(
            tenant_id=tenant.tenant_id,
            actor_user_id=current_user.user_id,
            action="tenant.deleted",
            resource_type="tenant",
            resource_id=str(tenant.tenant_id),
            metadata={
                "tenant_name": tenant.name,
                "deleted_by": current_user.user_id
            }
        )

        db.add(audit_log)
        await db.commit()

        logger.info(f"Tenant {tenant.tenant_id} deleted successfully")

        return {"message": "Workspace deleted successfully."}

    except HTTPException:
        raise

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(
            f"Database error deleting tenant "
            f"{tenant.tenant_id}: {e}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error"
        )

    except Exception as e:
        await db.rollback()
        logger.exception(
            f"Failed to delete tenant "
            f"{tenant.tenant_id}: {e}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete tenant"
        )





# function to softly-deactivate user
async def deactivate_member_service(
    tenant: Tenant,
    member_id: int,
    current_user: User,
    db: AsyncSession
):
    try:
        logger.info(
            f"User {current_user.user_id} "
            f"attempting to deactivate "
            f"member {member_id}"
        )
        
        if member_id == current_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot deactivate yourself"
            )
        
        target_membership = await validate_tenant_role_hierarchy(
            actor_user_id=current_user.user_id,
            target_user_id=member_id,
            tenant_id=tenant.tenant_id,
            db=db
        )
        
        if not target_membership.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Member is already inactive"
            )

        target_membership.is_active = False
        
        db.add(target_membership)
        await db.flush()

        audit_log = AuditLog(
            tenant_id=tenant.tenant_id,
            actor_user_id=current_user.user_id,
            target_user_id=member_id,
            action="member.deactivated",
            resource_type="tenant_membership",
            resource_id=str(target_membership.membership_id),
            changes={"is_active": {"old": True, "new": False}}
        )

        db.add(audit_log)
        await db.commit()

        logger.info(
            f"Member {member_id} "
            f"deactivated successfully"
        )

        return {"message": ("Member deactivated successfully")}

    except HTTPException:
        raise

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(
            "tenant_member_deactivate_failed",
            extra={
                "tenant_id": tenant.tenant_id,
                "actor_id": current_user.user_id,
                "target_user_id": member_id
            },
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error"
        )

    except Exception as e:
        await db.rollback()
        logger.exception(f"Failed to deactivate member: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate member"
        )
        
        
        
        

# function to softly-activate member
async def activate_member_service(
    tenant: Tenant,
    member_id: int,
    current_user: User,
    db: AsyncSession
):
    try:
        logger.info(
            f"User {current_user.user_id} "
            f"attempting to activate "
            f"member {member_id}"
        )

        if member_id == current_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot activate yourself"
            )
        
        target_membership = await validate_tenant_role_hierarchy(
            actor_user_id=current_user.user_id,
            target_user_id=member_id,
            tenant_id=tenant.tenant_id,
            db=db
        )
            
        if target_membership.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Member is already active"
            )

        target_membership.is_active = True
        
        db.add(target_membership)
        await db.flush()
        
        audit_log = AuditLog(
            tenant_id=tenant.tenant_id,
            actor_user_id=current_user.user_id,
            target_user_id=member_id,
            action="member.activated",
            resource_type="tenant_membership",
            resource_id=str(target_membership.membership_id),
            changes={
                "is_active": {
                    "old": False,
                    "new": True
                }
            }
        )

        db.add(audit_log)
        await db.commit()

        logger.info(
            f"Member {member_id} "
            f"activated successfully"
        )

        return {"message": ("Member activated successfully")}

    except HTTPException:
        raise

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(
            "tenant_member_activate_failed",
            extra={
                "tenant_id": tenant.tenant_id,
                "actor_id": current_user.user_id,
                "target_user_id": member_id
            },
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error"
        )

    except Exception as e:
        await db.rollback()
        logger.exception(f"Failed to activate member: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate member"
        )
