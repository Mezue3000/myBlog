# import dependencies
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Response
from app.utility.logging import get_logger
import logging
from fastapi_limiter.depends import RateLimiter
from pydantic import EmailStr
from app.schemas.users import EmailRequest, UserRead, UserCreate, UserBase, UserUpdateRead, UserUpdate, UserPasswordUpdate, EmailUpdate, DeleteUserRequest
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.database import get_db
from sqlmodel import select, or_
from app.models import User
from app.utility.email_auth import create_email_otp, send_verification_otp_email, verify_email_otp
from app.utility.security import get_identifier_factory, hash_password, verify_password
from app.utility.auth import verify_users_ownership, logout_all_devices_for_user, get_current_user, get_current_active_user
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from app.cores.redis import redis_client





logger = get_logger("auth")

# initialize router
router = APIRouter(tags=["users"], dependencies=[Depends(get_current_active_user)])

# create endpoint to retrieve username
@router.get("/get_username")
async def get_username(current_user: User = Depends(get_current_user)):
    return f"Hello {current_user.username}"  

  
  
  
# create endpoint to retrieve user info
@router.get("/read_user", response_model=UserRead) 
async def read_user(current_user: User  = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return current_user 
  
  
  
# create user update endpoint
@router.put(
    "/update_user", 
    dependencies=[Depends(RateLimiter(times=3, minutes=5, identifier=get_identifier_factory("update_user")))],
    response_model=UserUpdateRead
)

async def update_user(
    user_data: UserUpdate, 
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db), 
):
    update_fields = user_data.model_dump(exclude_unset=True)
    
    # check ownership rules
    verify_users_ownership(current_user.user_id, current_user)
    
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
@router.put(
    "/update_password", 
    dependencies=[
        Depends(
            RateLimiter(times=3, minutes=5, identifier=get_identifier_factory("update_password"))
        )
    ],
    status_code=status.HTTP_200_OK
)

async def update_password(
    payload: UserPasswordUpdate, 
    current_user: User  = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    # validate ownership rules
    verify_users_ownership(current_user.user_id, current_user)
     
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
    dependencies=[Depends(RateLimiter(times=3, minutes=5, identifier=get_identifier_factory("update_email")))],
    status_code=status.HTTP_200_OK
)

async def update_email(
    user: EmailUpdate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    # validate ownership rules
    verify_users_ownership(current_user.user_id, current_user)
    
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
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession=Depends(get_db)
): 
    # validate ownership rules
    verify_users_ownership(current_user.user_id, current_user)
    
    # verify otp
    try: 
        email = verify_email_otp(otp_code=otp_code, scope="update")
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
    
    # update and safe
    try:
        current_user.email = email
        db.add(current_user)
        await db.commit()
        await db.refresh(current_user)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Integrity error while updating user.")
        
    return{"detail": "Email updated succesfully"} 


 
# create endpoint to delete user
@router.delete(
    "/delete_user", 
    dependencies=[Depends(RateLimiter(times=3, minutes=10, identifier=get_identifier_factory("delete_user")))],
    status_code=status.HTTP_200_OK
)

async def soft_delete_user(
    data: DeleteUserRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    # verify password belong to the owner
    if not verify_password(data.password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password. Deactivation aborted."
        )
        
    # validate ownership rules
    verify_users_ownership(current_user.user_id, current_user)
    
    try:
        current_user.is_active = False 
        db.add(current_user)
        await logout_all_devices_for_user(current_user.user_id)
        await db.commit()
        await db.refresh(current_user)
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        ) from e

    return {"detail": "Account deactivated successfully"}   