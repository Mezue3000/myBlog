# import dependencies
from app.cores.logging import get_logger
from dotenv import load_dotenv
from app.schemas.users import UserUpdate, UserPasswordUpdate, EmailUpdate, DeleteUserRequest, EmailRequest, UserCreate, UserRead, PasswordResetConfirm
from app.utility.user import validate_unique_fields, get_user_by_email, validate_user_credentials, verify_users_ownership, logout_all_devices_for_user
from fastapi import Depends, HTTPException, status, Request, Response, BackgroundTasks
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
import os
from app.models import RolePermission, Role, Permission, User, AuditLog
from app.utility.security import hash_password, verify_password, handle_password_reset_request, update_user_password_with_audit, verify_reset_otp, build_audit_context, create_auth_audit_log_bg
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from app.utility.email import create_email_otp, verify_email_otp, send_verification_otp_email, cleanup_reset_otp
from app.utility.auth import extract_refresh_token, get_refresh_token_payload, clear_auth_cookies


 


# initialize logging
logger = get_logger(__name__)



# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/.env") 



# function to initialize registration
async def initiate_registration(
    user_data: EmailRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession,
):
    update_fields = user_data.model_dump(exclude_unset=True)
    
    # check if email already exists
    await validate_unique_fields(db=db, fields=update_fields)
   
    # generate OTP
    otp = await create_email_otp(email=user_data.email, scope="registration")

    # send verificataon email in background
    background_tasks.add_task(send_verification_otp_email, user_data.email, otp, "registration")

    return {
        "message": "Registration started. If the email exists, a verification code has been sent."
    }




# function to complete registration
async def finalize_registration(user: UserCreate, otp_code: str, db: AsyncSession):
    update_fields = user.model_dump(exclude_unset=True)
    
    # check if username already exists
    await validate_unique_fields(db=db, fields=update_fields)
   
    # verify OTP and extract email
    try:
        email = await verify_email_otp(otp_code=otp_code, scope="registration")
        logger.info("OTP verified successfully for email: %s", email)
    except HTTPException as exc:
        logger.warning("OTP verification failed: %s", exc.detail)
        raise exc
    
    # hash password
    hashed_password = await hash_password(user.password)
    
    # get users role id
    role_id = os.getenv("USERS_ROLE_ID")

    # create user
    new_user = User(
        email=email,
        username=user.username.lower(),
        password_hash=hashed_password,
        biography=user.biography,
        country=user.country.lower(),
        city=user.city.lower(),
        role_id=role_id
    )

    try:
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        logger.info("User created successfully: %s", email) 
    except IntegrityError:
        await db.rollback()
        logger.error("Integrity error during registration for email: %s", email)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists",
        )

    return UserRead.model_validate(new_user)




# request for reset password
async def demand_password_reset(
    email: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession
):
    # normalize email
    normalized_email = email.lower().strip()

    # fetch user
    user = await get_user_by_email(db, normalized_email)

    # if user exists → send OTP
    if user:
        await handle_password_reset_request(
            user=user,
            email=normalized_email,
            background_tasks=background_tasks
        )

    return {
        "message": "If the email exists, a password reset code has been sent."
    }




# pasword reset confirmation
async def verify_password_reset(
    request: Request,
    data: PasswordResetConfirm,
    db: AsyncSession
):
    # verify OTP → get email
    email = await verify_reset_otp(data.otp)

    # fetch user
    user = await get_user_by_email(db, email)

    # validate user
    validate_user_credentials(user)

    # update password + audit
    await update_user_password_with_audit(
        user=user,
        new_password=data.new_password,
        request=request,
        db=db
    )

    # force logout all sessions
    await logout_all_devices_for_user(user.user_id)

    # cleanup OTP
    await cleanup_reset_otp(email)

    # log success
    logger.info(
        "password_reset_success",
        extra={"user_id": user.user_id}
    )

    return {
        "message": "Password reset successful. Please log in again."
    }
    
    


# function to update user data
async def update_user_info(
    user_data: UserUpdate,
    current_user: User,
    db: AsyncSession
):

    update_fields = user_data.model_dump(exclude_unset=True)

    # ownership validation
    verify_users_ownership(current_user.user_id, current_user)

    # validate fields
    await validate_unique_fields(db=db, fields=update_fields, exclude_user_id=current_user.user_id)

    for key, value in update_fields.items():
        setattr(current_user, key, value)

    try:
        db.add(current_user)
        await db.commit()
        await db.refresh(current_user)

    except IntegrityError:
        await db.rollback()
        
        logger.exception(
            "Database error while updating password",
             extra={"user_id": current_user.user_id},
        )

        raise HTTPException(
            status_code=400,
            detail="Integrity error while updating user."
        )

    return current_user
 
 
 
 
# function to update password
async def change_password(
    current_user: User, 
    request: Request,
    payload: UserPasswordUpdate,
    db: AsyncSession
):
    # validate ownership rules
    verify_users_ownership(current_user.user_id, current_user)
     
    # validate old password
    if not await verify_password(payload.old_password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Old password is incorrect")
    
    # hash and update password
    current_user.password_hash = await hash_password(payload.new_password)
    
    # update and save      
    try:
        db.add(current_user)
        
        # extract metadata
        context = build_audit_context(request)

        # audit log context
        audit_entry = AuditLog(
            actor_id=current_user.user_id,
            target_user_id=current_user.user_id,
            action="UPDATE_PASSWORD",
            changes={
                "password": "[REDACTED]"
            },
            **context
        )

        db.add(audit_entry)
        await db.commit()
        await db.refresh(current_user)

    except IntegrityError: 
        await db.rollback()

        logger.warning(
           "Integrity error while updating password",
            extra={"user_id": current_user.user_id},
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password update violates database constraints",
        )

    except SQLAlchemyError:
        await db.rollback()
        logger.exception(
            "Database error while updating password",
             extra={"user_id": current_user.user_id},
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected database error occurred",
        )
    
    # logout all devices
    await logout_all_devices_for_user(current_user.user_id)
    
    return{
        "status": "Success",
        "message": "Password updated succesfully",
    }




# function to initiate email update
async def initiate_email_update(
    payload: EmailUpdate,
    background_tasks: BackgroundTasks,
    current_user: User,
    db: AsyncSession
):
    # validate ownership rules
    verify_users_ownership(current_user.user_id, current_user)
    
    new_email = payload.new_email.lower().strip()

    # check if new email already exists
    result = await db.exec(select(User).where(User.email == new_email))
    existing_email = result.first()

    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already exists",
        )

    # verify password
    if not await verify_password(current_user.password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password incorrect")

    # generate OTP
    otp = await create_email_otp(email=new_email, scope="update")

    # send verification email in background
    background_tasks.add_task(send_verification_otp_email, email=new_email, otp=otp, scope="update")

    return {
        "status": "success",
        "message": "Verification code sent to your new email address",  
    }




# function to complete email update
async def finalize_email_update(
    otp_code: str, 
    request: Request,
    current_user: User,
    db: AsyncSession
): 
    # validate ownership rules
    verify_users_ownership(current_user.user_id, current_user)
    
    # verify otp
    try: 
        new_email = verify_email_otp(otp_code=otp_code, scope="update")
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
    
    # capture old data for the Audit Log
    old_email = current_user.email
    
    # update and safe
    try:
        current_user.email = new_email
        db.add(current_user)
        
        # extract metadata
        context = build_audit_context(request)

        # audit log
        audit_entry = AuditLog(
            actor_id=current_user.user_id,
            target_user_id=current_user.user_id,
            action="UPDATE_EMAIL",
            changes={
                "email": {
                    "old": old_email,
                    "new": new_email
                }
            },
            **context
        )

        db.add(audit_entry)
        await db.commit()
        await db.refresh(current_user)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Integrity error while updating user.")
        
    return{"detail": "Email updated succesfully"} 



  
# function to logout all devices
async def signout_all_devices(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks
):
    # extract refresh token
    refresh_token = await extract_refresh_token(request)

    # get session payload
    payload = await get_refresh_token_payload(refresh_token, request)

    # extract user_id
    user_id = payload.get("user_id")

    # invalidate all sessions
    await logout_all_devices_for_user(user_id)
    
    # extract context metas
    context = build_audit_context(request)
        
    # audit-log 
    background_tasks.add_task(
        create_auth_audit_log_bg,        
        action="LOGOUT_ALL_DEVICES",
        user_id=user_id,
        metadata={},
        context=context
    )

    # clear cookies
    clear_auth_cookies(response)
    
    # log success
    logger.info("Logout_success", extra={"user_id": user_id})


    return {"detail": "Logged out successfully from all devices"} 




# function to delete user(soft-delete)
async def delete_user_account(
    data: DeleteUserRequest,
    request: Request,
    current_user: User,
    db: AsyncSession
):
    # verify password belong to the owner
    if not verify_password(data.password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password. Deletion aborted."
        )
        
    # validate ownership rules
    verify_users_ownership(current_user.user_id, current_user)
    
    try:
        current_user.is_deleted = True
        db.add(current_user)
        await logout_all_devices_for_user(current_user.user_id)
        
         # extract metadata
        context = build_audit_context(request)

        # audit log
        audit_entry = AuditLog(
            actor_id=current_user.user_id,
            target_user_id=current_user.user_id,
            action="DELETE_USER",
            changes={
                "is_deleted": {
                    "old": False,
                    "new": True
                }
            },
            **context
        )

        db.add(audit_entry)
        await db.commit()
        await db.refresh(current_user)
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        ) from e

    return {"detail": "Account deleted successfully"}