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
from app.utility.tenant.tenant_router import get_active_tenant_membership_by_user, generate_invite_token, get_tenant_membership_by_email, has_active_invitation, get_invitation_by_token, count_active_non_owner_members, lock_tenant
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
    db: AsyncSession
):
    try:
        # personal tenants cannot invite
        if tenant.type == "personal":
            raise ValueError("Personal workspace cannot invite members. Please upgrade to a team plan.")

        # RBAC
        membership = await get_active_tenant_membership_by_user(
            user_id=current_user.user_id,
            tenant_id=tenant.tenant_id,
            db=db
        )
        
        # service-layer guard
        if (
            membership is None
            or membership.role not in ["owner", "admin"]
        ):
            raise ValueError("Only owners and admins can invite members.")

        # validate request
        if not emails:
            raise ValueError("At least one email is required.")

        if len(emails) > MAX_INVITATIONS_PER_REQUEST:
            raise ValueError(
                f"Maximum of "
                f"{MAX_INVITATIONS_PER_REQUEST} "
                "emails per request."  
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
    membership_id: int,
    current_user: User,
    db: AsyncSession
):
    tenant_id = tenant.tenant_id

    try:
        # validate role hierarchy and get target membership
        target_membership = await validate_tenant_role_hierarchy(
            actor_user_id=current_user.user_id,
            target_membership_id=membership_id,
            tenant_id=tenant_id,
            db=db
        )

        # prevent self-removal
        if target_membership.user_id == current_user.user_id:
            raise ValueError("You cannot remove yourself from the tenant")

        # preserve values needed after deletion
        target_user_id = target_membership.user_id
        target_role = target_membership.role
        target_membership_id = target_membership.membership_id

        # hard delete membership
        await db.delete(target_membership)
        await db.flush()

        # create audit log
        audit_log = AuditLog(
            tenant_id=tenant_id,
            actor_id=current_user.user_id,
            target_user_id=target_user_id,
            action="member.deleted",
            resource_type="tenant_membership",
            resource_id=str(target_membership_id),
            metadata={"role": target_role}
        )

        db.add(audit_log)
        await db.commit()

        logger.info(
            f"Member {target_membership_id} deleted "
            f"from tenant {tenant_id} "
            f"by {current_user.user_id}"
        )

        return {"message": "Member deleted successfully"}

    except HTTPException:
        raise

    except SQLAlchemyError as e:
        await db.rollback()

        logger.error(
            f"Database error deleting member "
            f"{membership_id}: {str(e)}"
        )

        raise 

    except ValueError:
        await db.rollback()
        raise

    except Exception:
        await db.rollback()

        logger.exception(
            f"Unexpected error deleting member "
            f"{membership_id}"
        )

        raise
        
        
        
        
        
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
        raise ValueError("Personal workspace cannot be deleted")

    # ensure all members are removed
    remaining_members = await count_active_non_owner_members(
        tenant_id=tenant.tenant_id,
        db=db
    )
    
    logger.info(
        "Workspace member count before deletion",
        extra={
            "tenant_id": str(tenant.tenant_id),
            "owner_id": tenant.owner_id,
            "active_non_owner_members": remaining_members,
        }
    )
    
    if remaining_members > 0:
        raise ValueError("Remove all workspace members before deleting the workspace.")

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
    otp: str,
    db: AsyncSession
):
    tenant_id = tenant.tenant_id
    
    # verify deletion OTP
    await verify_email_otp(otp_code=otp, scope="delete_tenant")

    try:
        logger.info(
            f"User {current_user.user_id} "
            f"confirmed deletion of tenant "
            f"{tenant_id}"
        )

        tenant.is_active = False
        tenant.is_deleted = True
        tenant.deleted_at = datetime.now(timezone.utc)
        tenant.deleted_by = current_user.user_id

        audit_log = AuditLog(
            tenant_id=tenant.tenant_id,
            actor_id=current_user.user_id,
            action="tenant.deleted",
            resource_type="tenant",
            resource_id=str(tenant_id),
            metadata={
                "tenant_name": tenant.name,
                "deleted_by": current_user.user_id
            }
        )

        db.add(audit_log)
        await db.commit()

        logger.info(f"Tenant {tenant_id} deleted successfully")

        return {"detail": "Workspace deleted successfully."}

    except HTTPException:
        raise

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(
            f"Database error deleting tenant "
            f"{tenant_id}: {e}"
        )
        raise ValueError("Database error")

    except Exception as e:
        await db.rollback()
        logger.exception(
            f"Failed to delete tenant "
            f"{tenant_id}: {e}"
        )
        
        raise ValueError("Failed to delete tenant")





# function to softly-deactivate user
async def deactivate_member_service(
    tenant: Tenant,
    membership_id: int,
    current_user: User,
    db: AsyncSession
):
    tenant_id = tenant.tenant_id

    try:
        logger.info(
            f"User {current_user.user_id} "
            f"attempting to deactivate "
            f"membership {membership_id} "
            f"in tenant {tenant_id}"
        )

        # validate role hierarchy
        target_membership = await validate_tenant_role_hierarchy(
            actor_user_id=current_user.user_id,
            target_membership_id=membership_id,
            tenant_id=tenant_id,
            db=db
        )

        # prevent self-deactivation
        if target_membership.user_id == current_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot deactivate yourself"
            )

        # guard for service-level safety.
        if not target_membership.is_active:
            raise ValueError("Member is already inactive")

        # preserve values needed for audit/logging
        target_user_id = target_membership.user_id
        target_membership_id = target_membership.membership_id

        # deactivate membership
        target_membership.is_active = False
        await db.flush()

        # create audit log
        audit_log = AuditLog(
            tenant_id=tenant_id,
            actor_id=current_user.user_id,
            target_user_id=target_user_id,
            action="member.deactivated",
            changes={"is_active": {"old": True, "new": False}}
        )

        db.add(audit_log)
        await db.commit()
        logger.info(
            f"Membership {target_membership_id} "
            f"for user {target_user_id} "
            f"deactivated successfully "
            f"in tenant {tenant_id}"
        )

        return {"message": "Member deactivated successfully"}

    except HTTPException:
        raise

    except ValueError:
        await db.rollback()
        raise

    except SQLAlchemyError:
        await db.rollback()
        logger.exception(f"Database error deactivating membership {membership_id}")
        raise

    except Exception:
        await db.rollback()
        logger.exception(f"Unexpected error deactivating membership {membership_id}")
        raise





# function to softly-activate member
async def activate_member_service(
    tenant: Tenant,
    membership_id: int,
    current_user: User,
    db: AsyncSession
):
    tenant_id = tenant.tenant_id

    try:
        logger.info(
            f"User {current_user.user_id} "
            f"attempting to activate "
            f"membership {membership_id} "
            f"in tenant {tenant_id}"
        )

        # validate role hierarchy
        target_membership = await validate_tenant_role_hierarchy(
            actor_user_id=current_user.user_id,
            target_membership_id=membership_id,
            tenant_id=tenant_id,
            db=db
        )

        # prevent self-activation
        if target_membership.user_id == current_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot activate yourself"
            )

        # membership must currently be inactive
        if target_membership.is_active:
            raise ValueError("Member is already active")

        # preserve values needed for audit/logging
        target_user_id = target_membership.user_id
        target_membership_id = target_membership.membership_id

        # activate membership
        target_membership.is_active = True
        await db.flush()

        # create audit log
        audit_log = AuditLog(
            tenant_id=tenant_id,
            actor_id=current_user.user_id,
            target_user_id=target_user_id,
            action="member.activated",
            changes={"is_active": {"old": False, "new": True}}
        )

        db.add(audit_log)
        await db.commit()
        logger.info(
            f"Membership {target_membership_id} "
            f"for user {target_user_id} "
            f"activated successfully "
            f"in tenant {tenant_id}"
        )

        return {"message": "Member activated successfully"}

    except HTTPException:
        raise

    except ValueError:
        await db.rollback()
        raise

    except SQLAlchemyError:
        await db.rollback()
        logger.exception(f"Database error activating membership {membership_id}")
        raise

    except Exception:
        await db.rollback()
        logger.exception(f"Unexpected error activating membership {membership_id}")
        raise
