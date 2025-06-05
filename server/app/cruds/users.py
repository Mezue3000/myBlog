# import dependencies
from fastapi import APIRouter, Depends, HTTPException, status
from app.schemas.users import UserRead, UserCreate
from sqlalchemy.ext.asyncio import AsyncSession
from app.utility.database import get_db
from sqlmodel import select, or_
from app.models import User
from app.utility.security import hash_password



# initialize router
router = APIRouter(tags=["Users"], prefix="/users")



# create endpoint for user registration
@router.post("/", response_model=UserRead)
async def create_user(user:UserCreate, db:AsyncSession=Depends(get_db)):
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
        biography=user.biography.lower(),
        password_hash=hash_password(user.password),
        country=user.country.lower(),
        city=user.city.lower() 
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    return UserRead.model_validate(new_user)