# import necessary dependencies
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response 
from fastapi_limiter.depends import RateLimiter
from fastapi_csrf_protect import CsrfProtect
from app.schemas.jwts import get_csrf_config
from app.schemas.jwts import Token
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel.ext.asyncio.session import AsyncSession 
from app.utility.database import get_db 
from sqlmodel import select, or_
from app.models import User
from app.utility.security import get_identifier, verify_password
from app.utility.auth import create_access_token, create_refresh_token, rotate_refresh_token, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS
import secrets
from redis.asyncio import Redis
from app.main import redis, password




# initialize router
router = APIRouter(tags=["authenticate"])

# create an endpoint to sign_in and grab token
@router.post(
    "/token", 
    dependencies=[Depends(RateLimiter(times=3, minutes=5, identifier=get_identifier))], 
    response_model=Token
)
async def login(
    response: Response,
    csfr_protect: CsrfProtect = Depends(),
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: AsyncSession = Depends(get_db)
):
    # OAuth2PasswordRequestForm uses "username" for both email and username   
    login_identifier = form_data.username.lower()
    password = form_data.password   
    
    # fetch user by email/username
    statement = select(User).where(or_(User.email == login_identifier, User.username == login_identifier))  
    result = await db.exec(statement)
    user = result.first()
    
    # Validate user existence
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid email/username or password")
    
    # validate password
    verified_password = await verify_password(password, user.password_hash)
    if not verified_password: 
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email/username or password"
        )
    
    # generate jwt tokens
    access_token = create_access_token(data = {"sub": user.username})
    refresh_token = await create_refresh_token(data = {"sub": user.username})
    
    # set all cookies 
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True, 
        secure=True,
        samesite="Lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/"
    )
    
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/"
    )
    
    # generate csrf token
    csrf_token = csfr_protect.generate_csrf()   
    response.headers["X-CSRF-Token"] = csrf_token
    
    return {"access_token": access_token, "token_type": "bearer"}  



# create refresh token endpoint
@router.post("/refresh_token")
async def refresh_token(request: Request,  response: Response):
    old_refresh_token = request.cookies.get(refresh_token)
    if not old_refresh_token:
       raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")
    
    # invalidate old refresh token(applicable for one-device-only policy)
    new_refresh_token = await rotate_refresh_token(old_refresh_token)
    if not new_refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    # get user id from Redis (new token stored by create_refresh_token)
    user_id = await redis.get(f"refresh:{new_refresh_token}")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    # issue new token 
    new_access_token = create_access_token({"sub": user_id})
    
    # set cookies 
    response.set_cookie(
        key="new_access_token",
        value=new_access_token,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/"
    )
     
    response.set_cookie(
        key="new_refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/"
    )
    
    return {"access_token": "rotated"}
    