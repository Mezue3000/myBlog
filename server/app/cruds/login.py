# import necessary dependencies
from fastapi import APIRouter, Depends, HTTPException, status
from app.schemas.jwts import Token
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from app.utility.database import get_db
from sqlmodel import select, or_
from app.models import User
from app.utility.security import verify_password
from app.utility.auth import create_access_token

# initialize router
router = APIRouter(tags=["authenticate"])

# create an endpoint to sign_in and grab token
@router.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    # OAuth2PasswordRequestForm uses "username" for both email and username   
    login_identifier = form_data.username.lower()
    password = form_data.password   
    
    # check user by email/username
    statement = select(User).where(or_(User.email == login_identifier, User.username == login_identifier))
    result = await db.execute(statement)
    user = result.scalars().first()
    
    verified_password = await verify_password(password, user.password_hash)
    if not user or not verified_password: 
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email/username or password"
        )
    
    # generate jwt access token 
    access_token = create_access_token(data = {"sub": user.username})
    
    return {"access_token": access_token, "token_type": "bearer"} 
