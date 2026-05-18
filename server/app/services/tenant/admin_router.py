# import dependencies
from app.cores.logging import get_logger
from pydantic import EmailStr
from fastapi import Depends, HTTPException, status, BackgroundTasks
from app.utility.platform.user import get_current_active_user
from app.utility.tenant.tenant_router import get_current_tenant
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.models import Tenant, User, TenantInvitation
from app.utility.tenant.tenant_router import get_tenant_membership, generate_invite_token, get_tenant_membership_by_email, has_active_invitation
from app.utility.tenant.invite import send_tenant_invitation_email, send_bulk_invitation_emails
from sqlalchemy.exc import SQLAlchemyError





# initialize logging
logger = get_logger(__name__)




# function for members invitation
async def invite_member_service(
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
        
        
        # add rate-limit for emails
        MAX_INVITATIONS_PER_REQUEST = 20

        if len(emails) > MAX_INVITATIONS_PER_REQUEST:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Maximum of "
                    f"{MAX_INVITATIONS_PER_REQUEST} "
                    f"invitations allowed per request."
                ),
            )
        
        invited_emails = []
        skipped_emails = []

        # process each email
        for email in emails:
            normalized_email = (email.lower().strip())
        
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
        background_tasks.add_task(
            send_bulk_invitation_emails,
            invitations=invited_emails,
            tenant_name=tenant.name,
            invited_by=current_user.username,
        )

        logger.info(
            f"{len(invited_emails)} invitations "
            f"created for tenant "
            f"{tenant.tenant_id}"
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