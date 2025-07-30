# import dependencies
from fastapi import APIRouter, Depends, HTTPException, status
from app.schemas.users import EmailRequest, UserRead, UserCreate, UserBase, UserUpdateRead, UserUpdate, UserPasswordUpdate
from sqlalchemy.ext.asyncio import AsyncSession
from app.utility.database import get_db
from sqlmodel import select, or_
from app.models import User
from app.utility.email_auth import create_email_token, send_verification_email, decode_token
from datetime import timedelta
from app.utility.security import hash_password, verify_password, validate_password_strength
from app.utility.auth import get_current_user
from sqlalchemy.exc import IntegrityError




# initialize router
router = APIRouter(tags=["Users"], prefix="/users") 


# create endpoint to start registration by verifying email
@router.post("/start_registration")
async def start_registration(user_data: EmailRequest, db: AsyncSession = Depends(get_db)):
    # check if email already exist
    result = await db.execute(select(User).where(User.email == user_data.email))
    db_user = result.scalars().first() 
    
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exist")
    
    # generate token
    token = create_email_token(user_data.email) 
    try:
        await send_verification_email(user_data.email, token)
        return {"message": "Verification email sent, check your email to verify"}   
    except ConnectionRefusedError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
            detail="Service Unavailable: Unable to connect to email server"
        )
    except TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT, 
            detail="Gateway Timeout: Email sending timed out"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"Internal Server Error: {str(e)}"
        )





# create endpoint to verify email
@router.get("/verify-email")
async def verify_email(token: str):
    expire_token = timedelta(minutes=30)
    try:
        email = decode_token(token)
        new_token = create_email_token(email, expire_token)
        return {"message": "Email verified", "verified_token": new_token}
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")





# create endpoint to complete registration
@router.post("/complete_registration", response_model=UserRead)
async def complete_registration(user: UserCreate, token: str, db: AsyncSession=Depends(get_db)): 
    # decode token to auto-extract verified email
    try:
        email = decode_token(token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
    
    # validate password
    validate_password_strength(user.password)
    
    # validate comfirm password field
    if user.password != user.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password do not match")
    
    # check if username is already taken
    statement = select(User).where(User.username == user.username)
    result = await db.execute(statement)
    existing_user = result.scalars().first()
    
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exist")
    
    hashed_password = await hash_password(user.password)
        
    # create new user with hash password function
    new_user = User(
        email= email,
        first_name=user.first_name.lower(),
        last_name=user.last_name.lower(),
        username=user.username.lower(),
        biography=user.biography,
        password_hash=hashed_password,
        country=user.country.lower(),
        city=user.city.lower()  
    )
    try:
       db.add(new_user)
       await db.commit()
       await db.refresh(new_user)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or email already exists")
    
    return UserRead.model_validate(new_user)





# create endpoint to retrieve username
@router.get("/get_username")
async def get_username(current_user: User = Depends(get_current_user)):
    return f"Hello {current_user.username}"  

  
  
  
  
# create endpoint to retrieve user info
@router.get("/read_user", response_model=UserBase) 
async def read_user(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Retrieve the current user's info
    result = await db.execute(select(User).where(User.user_id == current_user.user_id))
    db_user = result.scalars().first()
    
    return db_user
  
  
  
  

# create user update endpoint
@router.put("/update_user", response_model=UserUpdateRead)
async def update_user(
    user_data: UserUpdate, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_user)
): 
    # Retrieve the current user's full record
    result = await db.execute(select(User).where(User.user_id == current_user.user_id))
    db_user = result.scalars().first()
    
    if not db_user: 
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    update_fields = user_data.model_dump(exclude_unset=True)
    
    # check for duplicates in username and email
    if "username" in update_fields and "email" in update_fields:
        statement = select(User).where(
            or_(User.username == update_fields.get("username"), User.email == update_fields.get('email'))
        )
    result = await db.execute(statement)
    existing_user = result.scalars().first()
    
    if existing_user and existing_user.user_id != current_user.user_id:
            if existing_user.username == update_fields.get("username"):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken.")
            if existing_user.email == update_fields.get("email"):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use.")

     # Apply updates
    for key, value in update_fields.items():
        setattr(db_user, key, value)

    db.add(db_user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Integrity error while updating user.")

    await db.refresh(db_user)
    return db_user





# create endpoint to change user password
@router.put("/update_password", status_code=status.HTTP_200_OK)
async def update_password(
    payload: UserPasswordUpdate, 
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(User).where(User.user_id == current_user.user_id))
    db_user = result.scalars().first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    # validate old password
    if not await verify_password(payload.old_password, db_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Old password is incorrect")
    
    # ensure new password is not same with old password
    if payload.new_password == payload.old_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be different")
    
    # ensure new password is same with confirm password
    if payload.new_password != payload.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="New password and confirm password must be the same"
        )   
    
    # validate strength
    validate_password_strength(payload.new_password)
    
     # hash and assign the new password
    db_user.password_hash = await hash_password(payload.new_password)
    
    # update and save 
    await db.commit()
    await db.refresh(db_user)
    
    return {"detail": "Password updated successfully"}
     
     
     
     
    
# create endpoint to delete user
@router.delete("/delete_user", status_code=status.HTTP_200_OK)
async def delete_user(
    db: AsyncSession = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(User).where(User.user_id == current_user.user_id))
    db_user = result.scalars().first()
    
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    await db.delete(db_user)
    await db.commit()
    
    return {"detail": "User deleted successfully"} 
