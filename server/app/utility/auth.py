# import dependencies 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from typing import Optional
import json, secrets, os, pyotp, httpx, jwt
from app.models import User
from pydantic import EmailStr
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, status, BackgroundTasks, Request, Response
from app.cores.redis import redis_client
from app.cores.logging import get_logger
from app.utility.email import create_email_otp, send_verification_otp_email





# get environ key
key = os.getenv("SPIRIT_KEY")
fernet = Fernet(key)


# load private key from file
with open("C:/Users/HP/Desktop/Python-Notes/myBlog/server/ec_private.pem.enc", "rb") as f:
     ENCRYPTED_PRIVATE_KEY = f.read()



# decrypt the encrypted version
DECRYPTED_PRIVATE_KEY = fernet.decrypt(ENCRYPTED_PRIVATE_KEY)
private_key = serialization.load_pem_private_key(DECRYPTED_PRIVATE_KEY, password=None) 




# define jwt params
ALGORITHM = "ES256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15 
REFRESH_TOKEN_EXPIRE_DAYS = 7




# function to create jwt access token 
def create_access_token(user_id: str, expire_delta: Optional[timedelta] = None) -> str:
    
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "scope": "access",
        "iat": int(now.timestamp()),
        "exp": now + (expire_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)), 
    }
    
    encoded_jwt = jwt.encode(payload, private_key, algorithm=ALGORITHM)
    
    return encoded_jwt
    
    
    
    
# function to create jwt refresh token
async def create_refresh_token(user_id: str) -> str:
    if not user_id:
        raise ValueError("create_refresh_token called with empty user_id")

    # generate token
    token = secrets.token_urlsafe(48)
    
    # internal tracking id
    refresh_id = secrets.token_hex(16)
    
    # time to elapse
    ttl = int(timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS).total_seconds())

    token_key = f"refresh:{token}"
    user_key = f"user_refresh:{user_id}"

    payload = {
        "user_id": user_id,
        "refresh_id": refresh_id,
    }

    # store token
    await redis_client.setex(token_key, ttl, json.dumps(payload))
    
    # index token for logout-all
    await redis_client.sadd(user_key, token)
    await redis_client.expire(user_key, ttl)

    return token




# function to rotate/invalidate old refresh token
async def rotate_refresh_token(old_token: str) -> Optional[str]:
    if not old_token:
        logger.warning("refresh_failed", extra={"reason": "missing_token"})
        return None

    token_key = f"refresh:{old_token}"

    # fetch data
    json_data = await redis_client.get(token_key)
    if not json_data:
        logger.warning("refresh_failed", extra={"reason": "reuse_or_invalid"})
        return None

    try:
        data = json.loads(json_data)
        user_id = data["user_id"]
    except (KeyError, json.JSONDecodeError, TypeError):
        logger.error("refresh_failed", extra={"reason": "corrupt_data"})
        return None

    user_key = f"user_refresh:{user_id}"

    # token cleanup
    await redis_client.delete(token_key)
    await redis_client.srem(user_key, old_token)

    # issue new token
    return await create_refresh_token(user_id)




# function to get refresh failures
logger = get_logger("auth")

async def log_refresh_failure(request, reason: str):
    logger.warning(
        "refresh_failed",
        extra={
            "extra": {
                "reason": reason,
                "ip": request.client.host,
                "ua": request.headers.get("user-agent"),
                "path": request.url.path,
            }
        },
    )




# generate and store trusted device
async def create_trusted_device(user_id: str) -> str:
    device_id = secrets.token_urlsafe(48)
    key = f"trusted_device:{user_id}:{device_id}"

    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_used": datetime.now(timezone.utc).isoformat(),
    }

    await redis_client.setex(
        key,
        int(timedelta(days=30).total_seconds()),
        json.dumps(payload),
    )

    return device_id




# verify trusted device
async def is_trusted_device(user_id: str, device_id: str) -> bool:
    if not device_id:
        return False

    key = f"trusted_device:{user_id}:{device_id}"
    exists = await redis_client.exists(key)

    if exists:
        await redis_client.expire(
            key,
            int(timedelta(days=30).total_seconds())
        )

    return bool(exists)




# function set cookies
COOKIE_DOMAIN = ""

def set_auth_cookies(
    response: Response, 
    access_token: str = None, 
    refresh_token: str = None,
    csrf_token: str = None
):
    # access token logic
    if access_token:
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,    # Always True in production for HTTPS
            samesite="Lax", # Use "Strict" if you don't need cross-site navigation
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            domain=COOKIE_DOMAIN,
            path="/",
        )

    # refresh token logic
    if refresh_token:
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=False,
            samesite="Lax",
            max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            domain=COOKIE_DOMAIN,
            path="/",
        )
        
    # csrf token Logic
    if csrf_token:
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            httponly=False,
            secure=False,
            samesite="Lax",
            max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            path="/",
        )


 
 
# function for device_id cookie
def set_trusted_device_cookie(response: Response, device_id: str):
    response.set_cookie(
        key="trusted_device",
        value=device_id,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=60 * 60 * 24 * 30,  # 30 days
    )




# handle trusted device(for 2fa)
async def handle_trusted_device_login(user: User, response: Response):

    logger.info("trusted_device_login", extra={"user_id": user.user_id})

    access_token = create_access_token(user_id=user.user_id)
    refresh_token = await create_refresh_token(user.user_id)
    # generate csrf token(double submit token)
    csrf_token = secrets.token_urlsafe(32)

    set_auth_cookies(response, access_token, refresh_token, csrf_token)

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }
    
    
    
    
# fuction to trigger OTP if not trusted
async def handle_2fa_challenge(
    user: User,
    background_tasks: BackgroundTasks
):
    otp = await create_email_otp(email=user.email, scope="2FA")

    background_tasks.add_task(
        send_verification_otp_email,
        user.email,
        otp,
        "2FA"
    )

    logger.info("2fa_challenge_sent", extra={"user_id": user.user_id})

    return {
        "detail": "2FA code sent to your email",
        "requires_2fa": True,
    }
    
    
    
    
# generate authentication tokens
async def generate_auth_tokens(user: User):
    access_token = create_access_token(user_id=user.user_id)
    refresh_token = await create_refresh_token(user.user_id)
    csrf_token = secrets.token_urlsafe(32)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "csrf_token": csrf_token
    }
    
    
    
    
# handle remember device
async def handle_remember_device(user: User, response: Response):
    device_id = await create_trusted_device(user.user_id)
    set_trusted_device_cookie(response, device_id)
    
    
    
    
# function to extract refresh token from cookies
async def extract_refresh_token(request: Request) -> str:
    token = request.cookies.get("refresh_token")

    if not token:
        await log_refresh_failure(request, reason="missing_cookie")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing refresh token/not authenticated"
        )

    return token




# fuction to extact user_id
async def get_refresh_token_payload(
    refresh_token: str,
    request: Request
) -> dict:
    token_data = await redis_client.get(f"refresh:{refresh_token}")

    if not token_data:
        await log_refresh_failure(request, reason="redis_miss")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized"
        )

    try:
        payload = json.loads(token_data)
        return payload

    except (KeyError, json.JSONDecodeError):
        await log_refresh_failure(request, reason="corrupt_data")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized"
        )
        
        
        
 
# function to clear token cookies
def clear_auth_cookies(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("csrf_token")