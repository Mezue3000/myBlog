# import necessary dependencies
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, BackgroundTasks
from fastapi_limiter.depends import RateLimiter
from app.schemas.jwts import Token
from typing import Union
from app.schemas.users import TwoFAChallenge
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel.ext.asyncio.session import AsyncSession 
from app.utility.database import get_db 
from sqlmodel import select, or_
from app.models import User
from app.utility.security import get_identifier, verify_password
from app.utility.auth import create_access_token, create_refresh_token, rotate_refresh_token, logout_all_devices_for_user,  ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS, set_auth_cookies, log_refresh_failure, create_trusted_device, is_trusted_device, set_trusted_device_cookie
import secrets, json, logging
from app.cores.redis import redis_client
from app.utility.email_auth import create_email_otp, send_verification_otp_email, verify_email_otp
from app.schemas.users import TwoFAVerify





logger = logging.getLogger(__name__)


# initialize router
router = APIRouter(tags=["authenticate"])


# create an endpoint to sign_in and grab token
@router.post(
    "/token", 
    dependencies=[Depends(RateLimiter(times=3, minutes=5, identifier=get_identifier))], 
    response_model=Union[Token, TwoFAChallenge]
)

async def login(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
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
    
    # validate active user
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account deactivated")
    
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
    
    # 2FA is mandatory
    trusted_device = request.cookies.get("trusted_device")

    if trusted_device and await is_trusted_device(user.user_id, trusted_device):
        logger.info("trusted_device_login", extra={"user_id": user.user_id})
        
        # generate tokens
        access_token = create_access_token(subject=user.username)
        refresh_token = await create_refresh_token(user.username)
        
        # generate csrf token(double submit token)
        # csrf_token = secrets.token_urlsafe(32)
        
        # set cookies
        set_auth_cookies(response, access_token, refresh_token)

        return {"access_token": access_token, "token_type": "bearer"}

    # if not trusted → trigger OTP
    otp = await create_email_otp(email=user.email, scope="2FA")
 
    # send verification using background task
    background_tasks.add_task(send_verification_otp_email, user.email, otp, "2FA")

    logger.info("2fa_challenge_sent", extra={"user_id": user.user_id})

    return {
        "detail": "2FA code sent to your email",
        "requires_2fa": True,
    }




# endpoint for 2FA verification
@router.post(
    "/2fa/verify",
    dependencies=[Depends(RateLimiter(times=3, minutes=10, identifier=get_identifier))],
)

async def verify_2fa(
    request: Request,
    response: Response,
    data: TwoFAVerify,
    db: AsyncSession = Depends(get_db),
):
    # email is derived from OTP
    email = await verify_email_otp(otp_code=data.otp, scope="2FA")

    result = await db.exec(select(User).where(User.email == email))
    user = result.first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid request")

    # generate tokens
    access_token = create_access_token(subject=user.username)
    refresh_token = await create_refresh_token(user.username)
    # csrf_token = secrets.token_urlsafe(32)
    
    # set cookies
    set_auth_cookies(response, access_token, refresh_token)

    # remember device if requested
    if data.remember_device:
        device_id = await create_trusted_device(user.user_id)
        set_trusted_device_cookie(response, device_id)

    logger.info("2fa_success", extra={"user_id": user.user_id})

    return {"access_token": access_token, "token_type": "bearer"}




# create refresh token endpoint
@router.post("/refresh_token")
async def refresh_token(request: Request, response: Response):
    old_refresh_token = request.cookies.get("refresh_token")

    if not old_refresh_token:
        await log_refresh_failure(request, reason="missing_cookie")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing refresh token"
        )

    # rotate token (delete old + issue new)
    new_refresh_token = await rotate_refresh_token(old_refresh_token)

    if not new_refresh_token:
        await log_refresh_failure(request, reason="reuse_or_invalid")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    # fetch new token payload from redis
    token_data = await redis_client.get(f"refresh:{new_refresh_token}")
    if not token_data:
        await log_refresh_failure(request, reason="redis_miss")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized"
        )

    try:
        payload = json.loads(token_data)
        user_id = payload["user_id"]
    except (KeyError, json.JSONDecodeError):
        await log_refresh_failure(request, reason="corrupt_data")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized"
        )

    new_access_token = create_access_token(subject=user_id)

    set_auth_cookies(response, new_access_token, new_refresh_token)

    return {"detail": "Token refreshed"}




# create all_device logout endpoint
@router.post("/logout-all")
async def logout_all_devices(request: Request, response: Response):
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    # validate refresh token
    data = await redis_client.get(f"refresh:{refresh_token}")
    if not data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # extract user_id
    payload = json.loads(data)
    user_id = payload.get("user_id")

    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

    # call plain async function
    await logout_all_devices_for_user(user_id)

    # clear cookies
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("csrf")

    return {"detail": "Logged out from all devices"}




# create endpoint for single-session logout 
@router.post("/logout")
async def single_session_logout(request: Request, response: Response):
    refresh_token = request.cookies.get("refresh_token")
    # delete in Redis (if exists)
    if refresh_token:
        await redis_client.delete(f"refresh:{refresh_token}")

    # Clear cookies
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("csrf_token")

    return {"message": "Logged out succesfully"}