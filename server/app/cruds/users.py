# import dependencies
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Response
import logging
from fastapi_limiter.depends import RateLimiter
from pydantic import EmailStr
from app.schemas.users import EmailRequest, UserRead, UserCreate, UserBase, UserUpdateRead, UserUpdate, UserPasswordUpdate, EmailUpdate, ResendVerificationEmail, PasswordResetConfirm
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.database import get_db
from sqlmodel import select, or_
from app.models import User
from app.utility.email_auth import create_email_otp, send_verification_otp_email, verify_email_otp, resend_verification_otp
from app.utility.security import get_identifier, hash_password, verify_password
from app.utility.auth import logout_all_devices_for_user, get_current_user, get_current_active_user
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from app.utility.logging import get_logger
from app.cores.redis import redis_client




logger = logging.getLogger(__name__)

# initialize router
router = APIRouter(tags=["Users"], prefix="/users") 


# create endpoint to start registration by verifying email
@router.post(
    "/start_registration",
    dependencies=[Depends(RateLimiter(times=3, minutes=5, identifier=get_identifier))]
)

async def start_registration(
    user_data: EmailRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    # check if email already exists
    try:
        result = await db.exec(select(User).where(User.email == user_data.email))
        existing_user = result.first()
    except Exception:
        logger.exception("Database failure while checking existing email.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred while checking email",
        )

    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")

    # generate OTP
    otp = await create_email_otp(email=user_data.email, scope="registration")

    # send verification email in background
    background_tasks.add_task(send_verification_otp_email, user_data.email, otp, "registration")

    return {
        "message": "Registration started. Please check your email for the verification code.",
    }

    

 

logger = get_logger("auth")


@router.post(
    "/resend-verification-email",
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RateLimiter(times=2, minutes=10, identifier=get_identifier))
    ],
)

async def resend_verification_email(
    payload: ResendVerificationEmail, 
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
     # check if email already exists
    try:
        result = await db.exec(select(User).where(User.email == payload.email))
        existing_user = result.first()
    except Exception:
        logger.exception("Database failure while checking existing email.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred while checking email",
        )

    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")


    await resend_verification_otp(payload.email.lower(), background_tasks)

    logger.info(
        "resend_verification_requested",
        extra={"email": payload.email}
    )

    return {
        "detail": "If the email exists, a verification code has been sent."
    }

 
 
 
# create endpoint to complete registration
logger = logging.getLogger(__name__)

@router.post("/complete_registration", response_model=UserRead)

async def complete_registration(user: UserCreate, otp_code: str, db: AsyncSession = Depends(get_db)):
    
    logger.info("Starting registration completion")

    # check username first
    result = await db.exec(select(User).where(User.username == user.username.lower()))
    existing_user = result.first()
    
    if existing_user:
        logger.warning("Username already exists: %s", user.username)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")

    # verify OTP and extract email
    try:
        email = await verify_email_otp(otp_code=otp_code, scope="registration")
        logger.info("OTP verified successfully for email: %s", email)
    except HTTPException as exc:
        logger.warning("OTP verification failed: %s", exc.detail)
        raise exc
    
    # hash password
    hashed_password = await hash_password(user.password)

    # create user
    new_user = User(
        email=email.lower(),
        username=user.username.lower(),
        password_hash=hashed_password,
        first_name=user.first_name.lower(),
        last_name=user.last_name.lower(),
        biography=user.biography,
        country=user.country.lower(),
        city=user.city.lower(),
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




# create endpoint to retrieve username
@router.get("/get_username")
async def get_username(current_user: User = Depends(get_current_user)):
    return f"Hello {current_user.username}"  

  
  
  
# create endpoint to retrieve user info
@router.get("/read_user", response_model=UserRead) 
async def read_user(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    return current_user 
  
  
  
# create user update endpoint
@router.put("/update_user", response_model=UserUpdateRead)

async def update_user(
    user_data: UserUpdate, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_active_user)
):
    update_fields = user_data.model_dump(exclude_unset=True)
    
    # Check for duplicate username
    if "username" in update_fields:
        stmt_username = select(User).where(User.username == update_fields["username"])
        result = await db.exec(stmt_username)
        existing_user = result.first() 
    if existing_user and existing_user.user_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken."
        )

    # Check for duplicate email
    if "email" in update_fields:
       stmt_email = select(User).where(User.email == update_fields["email"])
       result = await db.exec(stmt_email)
       existing_user = result.first()
    if existing_user and existing_user.user_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already in use."
        )


    # Apply updates
    for key, value in update_fields.items():
        setattr(current_user, key, value)

    try:
        db.add(current_user)
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Integrity error while updating user.")

    await db.refresh(current_user)
    return current_user




# create endpoint to change user password
@router.put("/update_password", status_code=status.HTTP_200_OK)

async def update_password(
    payload: UserPasswordUpdate, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_active_user)
):
    # validate old password
    if not await verify_password(payload.old_password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Old password is incorrect")
    
    
    # prevent password reuse (extra guard at service level)
    if await verify_password(payload.new_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the old password",
        )
        
    # hash and update password
    current_user.password_hash = await hash_password(payload.new_password)
    
    # update and save      
    try:
        db.add(current_user)
        await db.commit()
        await db.refresh(current_user)

    except IntegrityError: 
        await db.rollback()

        logger.warning(
           "Integrity error while updating password",
            extra={"user_id": current_user.id},
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password update violates database constraints",
        )

    except SQLAlchemyError:
        await db.rollback()
        logger.exception(
            "Database error while updating password",
             extra={"user_id": current_user.id},
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected database error occurred",
        )
    
    # logout all devices
    await logout_all_devices_for_user(current_user.user_id)
    
    return{
        "status": "Success",
        "message": "Password updated succesful",
    }


     
     
# endpoint to update email
@router.put( 
    "/update_email", 
    dependencies=[Depends(RateLimiter(times=3, minutes=5, identifier=get_identifier))],
    status_code=status.HTTP_200_OK
)

async def update_email(
    user: EmailUpdate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    new_email = user.new_email.lower().strip()

    # check if new email already exists
    result = await db.exec(select(User).where(User.email == new_email))
    existing_email = result.first()

    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already exists",
        )

    # verify password
    if not await verify_password(user.password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password incorrect")

    # generate OTP
    otp = await create_email_otp(email=new_email, scope="update")

    # send verification email in background
    background_tasks.add_task(send_verification_otp_email, email=new_email, otp=otp, scope="update")

    return {
        "status": "success",
        "message": "Verification code sent to your new email address",  
    }




# complete email update endpoint
@router.post("/complete_email_update", status_code=status.HTTP_200_OK)

async def complete_email_update(
    otp_code: str, 
    db: AsyncSession=Depends(get_db), 
    current_user: User = Depends(get_current_active_user)
): 
    # verify otp
    try: 
        email = verify_email_otp(otp_code=otp_code, scope="update")
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
    
    current_user.email = email
    # update and safe
    try:
        db.add(current_user)
        await db.commit()
        await db.refresh(current_user)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Integrity error while updating user.")
        
    return{"detail": "Email updated succesfully"} 




# endpoint for forgot_password
@router.post(
    "/password-reset/request",
    dependencies=[Depends(RateLimiter(times=3, minutes=10, identifier=get_identifier))]
)

async def request_password_reset(
    user_data: EmailRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    email = user_data.email.lower().strip()

    # check user exists
    result = await db.exec(select(User).where(User.email == email))
    user = result.first()

    # important: do not reveal whether user exists
    if user:
        otp = await create_email_otp(email=email, scope="password_reset")

        background_tasks.add_task(send_verification_otp_email, email, otp, "password_reset")

        logger.info("password_reset_requested", extra={"user_id": user.user_id})

    return {
        "message": "If the email exists, a password reset code has been sent."
    }




# confirm password reset
@router.post(
    "/password-reset/confirm",
    dependencies=[Depends(RateLimiter(times=2, minutes=10, identifier=get_identifier))]
)

async def confirm_password_reset(data: PasswordResetConfirm, db: AsyncSession = Depends(get_db)):
    # verify OTP
    email = await verify_email_otp(otp_code=data.otp, scope="password_reset")

    if not email:
        logger.warning("password_reset_failed", extra={"email": email, "reason": "invalid_otp"})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification code"
        )

    # fetch user
    result = await db.exec(select(User).where(User.email == email))
    user = result.first()

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request")

    # update password
    try:
        user.password_hash = await hash_password(data.new_password)
        db.add(user)
        await db.commit()
    except Exception as e:
        await db.rollback()     
        logger.error(f"Failed to update password for user {user.user_id}: {str(e)}", exc_info=True)
        raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to update password. Please try again."
    )

    # logout all devices
    await logout_all_devices_for_user(user.user_id)

    # cleanup OTP
    await redis_client.delete(f"email_otp:password_reset:{email}")

    logger.info(
        "password_reset_success", 
        extra={"user_id": user.user_id}
    )

    return {"message": "Password reset successful. Please log in again."}




# create endpoint to delete user
@router.delete("/delete_user", status_code=status.HTTP_200_OK)
async def delete_user(
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_active_user),
):
    
    try:
        await db.delete(current_user)
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        ) from e

    return {"detail": "User deleted successfully"}  