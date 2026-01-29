# import necessary dependencies
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response 
from fastapi_limiter.depends import RateLimiter
from app.schemas.jwts import Token
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel.ext.asyncio.session import AsyncSession 
from app.utility.database import get_db 
from sqlmodel import select, or_
from app.models import User
from app.utility.security import get_identifier, verify_password
from app.utility.auth import create_access_token, create_refresh_token, rotate_refresh_token, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS, set_auth_cookies, log_refresh_failure
import secrets
from app.cores.redis import redis_client




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
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: AsyncSession = Depends(get_db),
):
    # OAuth2PasswordRequestForm uses "username" for both email and username   
    login_identifier = form_data.username.lower().strip()
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
    access_token = create_access_token(subject=user.username)
    refresh_token = create_refresh_token(user_id=user.username)
    
    # # generate csrf token (double-submit)
    # csrf_token = secrets.token_urlsafe(32)
    
    # set cookies
    set_auth_cookies(response, access_token, refresh_token)
     
    return {"access_token": access_token, "token_type": "bearer"}  




# create refresh token endpoint
@router.post("/refresh_token")
async def refresh_token(request: Request, response: Response):
    # Get the old refresh token from the browser cookie
    old_refresh_token = request.cookies.get("refresh_token")
    
    if not old_refresh_token:
       await log_refresh_failure(request, reason="missing_cookie")
       raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")
    
    # invalidate old refresh token(applicable for one-device-only policy)
    new_refresh_token = await rotate_refresh_token(old_refresh_token)
    
    if not new_refresh_token:
        await log_refresh_failure(request, reason="reuse_or_invalid")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    # get user id from Redis (new token stored by create_refresh_token)
    data = await redis_client.hgetall(f"refresh:{new_refresh_token}")

    if not data:
        await log_refresh_failure(request, reason="redis_miss")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    user_id = data[b"user_id"].decode()

    new_access_token = create_access_token(subject=user_id)

    set_auth_cookies(response, new_access_token, new_refresh_token)

    return {"detail": "Token refreshed"}