# import dependencies
from fastapi import APIRouter, Depends, HTTPException, status
from app.schemas.users import UserRead, UserCreate, UserUpdateRead, UserUpdate, UserPasswordUpdate
from sqlalchemy.ext.asyncio import AsyncSession
from app.utility.database import get_db
from sqlmodel import select, or_
from app.models import User
from app.utility.security import hash_password, verify_password, validate_password_strength
from app.utility.auth import get_current_user




# initialize router
router = APIRouter(tags=["Users"], prefix="/users") 



# create endpoint for user registration
@router.post("/", response_model=UserRead)
async def create_user(user:UserCreate, db:AsyncSession=Depends(get_db)):
    # validate password
    validate_password_strength(user.password)
    
    # validate comfirm password field
    if user.password != user.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password do not match")
    
    # check if username or email is already taken 
    statement = select(User).where(or_(User.username == user.username, User.email == user.email))
    result = await db.execute(statement)
    existing_user = result.first()
    
    if existing_user:
        if existing_user.username == user.username:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exist")
        if existing_user.email == user.email:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exist")
        
    # create new user with hash password function
    new_user = User(
        first_name=user.first_name.lower(),
        last_name=user.last_name.lower(),
        username=user.username.lower(),
        email=user.email.lower(),
        biography=user.biography,
        password_hash=hash_password(user.password),
        country=user.country.lower(),
        city=user.city.lower() 
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    return UserRead.model_validate(new_user)




# create endpoint to retrieve user
@router.get("/me", response_model=UserRead)
async def read_user(db:AsyncSession=Depends(get_db), current_user:User=Depends(get_current_user)):
    result = await db.execute(select(User).where(User.user_id == current_user.user_id))
    return result.one_or_none




# create user update endpoint
@router.put("/me", response_model=UserUpdateRead)
async def update_user(user_data:UserUpdate,
                      db:AsyncSession=Depends(get_db), 
                      current_user:User=Depends(get_current_user)): 
    result = await db.execute(select(User).where(User.user_id == current_user.user_id))
    db_user = result.one_or_none
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    db_user.first_name = user_data.first_name
    db_user.last_name = user_data.last_name
    db_user.username = user_data.username
    db_user.email = user_data.email
    db_user.biography = user_data.biography
    db_user.country = user_data.country
    db_user.city = user_data.city
    
    await db.commit()
    await db.refresh(db_user)
    return db_user




# create endpoint to change user password
@router.put("/me", status_code=status.HTTP_200_OK)
async def update_password(payload:UserPasswordUpdate, 
                          db:AsyncSession=Depends(get_db), 
                          current_user:User=Depends(get_current_user)):
    result = await db.execute(select(User).where(User.user_id == current_user.user_id))
    db_user = result.one_or_none
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    # validate old password
    if not verify_password(payload.old_password, db_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Old password is incorrect")
    
    # ensure new password is not same with old password
    if payload.new_password == payload.old_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be different")
    
    # ensure new password is same with confirm password
    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                            detail="New password and confirm password must be the same")
    
    # validate strength
    validate_password_strength(payload.new_password)
    
    # update and save 
    db.commit()
    db.refresh(db_user)
    
    return {"detail": "Password updated successfully"}
     
     
    
# create endpoint to delete user
@router.delete("/me", status_code=status.HTTP_200_OK)
async def delete_user(db:AsyncSession=Depends(get_db), current_user:User=Depends(get_current_user)):
    result = await db.execute(select(User).where(User.user_id == current_user.user_id))
    db_user = result.one_or_none
    
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    await db.delete(db_user)
    await db.commit()
    
    return {"detail": "User deleted successfully"} 