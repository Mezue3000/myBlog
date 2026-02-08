# import dependencies
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from datetime import timedelta, datetime, timezone
import jwt, uuid
from app.cores.redis import redis_client
import secrets, json
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status, Request, Response
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.database import get_db
from typing import Optional
from app.schemas.jwts import TokenData
from jwt import PyJWKError, ExpiredSignatureError
from sqlmodel import select
from app.models import User
from app.utility.logging import get_logger




# get environ key
key = os.getenv("SPIRIT_KEY")
fernet = Fernet(key)


# load private key from file
with open("C:/Users/HP/Desktop/Python-Notes/myBlog/server/ec_private.pem.enc", "rb") as f:
     ENCRYPTED_PRIVATE_KEY = f.read()



# decrypt the encrypted version
DECRYPTED_PRIVATE_KEY = fernet.decrypt(ENCRYPTED_PRIVATE_KEY)
private_key = serialization.load_pem_private_key(DECRYPTED_PRIVATE_KEY, password=None) 



# load public key from file
with open("C:/Users/HP/Desktop/Python-Notes/myBlog/server/ec_public.pem", "rb") as f: 
     PUBLIC_KEY = f.read() 

public_key = serialization.load_pem_public_key(PUBLIC_KEY)



# define jwt params
ALGORITHM = "ES256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15 
REFRESH_TOKEN_EXPIRE_DAYS = 7



# function to create jwt access token 
def create_access_token(subject: str, expire_delta: Optional[timedelta] = None) -> str:
    
    now = datetime.now(timezone.utc)

    payload = {
        "sub": subject,
        "scope": "access",
        "iat": now,
        "exp": now + (expire_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)),
        "jti": str(uuid.uuid4()),
    }
    
    encoded_jwt = jwt.encode(payload, private_key, algorithm=ALGORITHM)
    
    return encoded_jwt
    
    


# function to create jwt refresh token
async def create_refresh_token(user_id: str) -> str:
    if not user_id:
        raise ValueError("create_refresh_token called with empty user_id")

    # generate token
    token = secrets.token_urlsafe(48)
    
    # internal tracking id (optional)
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





ALLOWED_ORIGINS = {
    # "https://app.myblog.com",
}



# function to verify origin
async def verify_origin(request: Request):
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")

    if origin and origin not in ALLOWED_ORIGINS:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid origin")

    if referer:
        for allowed in ALLOWED_ORIGINS:
            if referer.startswith(allowed):
                return
    
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid referer")
    



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


 

# function for all-device logout
async def logout_all_devices_for_user(user_id: str) -> int:
    # call with an id
    if not user_id:
        raise ValueError("logout_all_devices_for_user called with empty user_id")

    # refresh tokens
    user_key = f"user_refresh:{user_id}"
    tokens = await redis_client.smembers(user_key)

    revoked = 0

    if tokens:
        refresh_keys = [f"refresh:{t}" for t in tokens]
        await redis_client.delete(*refresh_keys)
        revoked = len(tokens)

    # delete index
    await redis_client.delete(user_key)

    # # trusted devices (2FA)
    # trusted_keys = await redis_client.keys(f"trusted_device:{user_id}:*")
    # if trusted_keys:
    #     await redis_client.delete(*trusted_keys)

    logger.info(
        "logout_all_devices",
        extra={
            "user_id": user_id,
            "refresh_token_count": revoked,
            # "trusted_devices_revoked": len(trusted_keys),
        },
    )

    return revoked




# testing the function    
# if __name__ == "__main__":
#     data = {"user_id": 1,}
#     expire_delta = timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS) 
#     toky = create_access_token(data, expire_delta) 
#     deco =jwt.decode(toky, public_key, algorithms=ALGORITHM)
#     print(deco) 




# function to get current user
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    credential_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED, 
        detail = "Invalid credentials", 
        headers = {"WWW.Authenticate": "Bearer"})
    
    expired_token_error = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = "Session Timeout",
        headers = {"WWW-Authenticate": "Bearer"})
    
    try:
        payload = jwt.decode(token, public_key, algorithms=ALGORITHM)
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credential_exception
        token_data = TokenData(username=username)
        
    except ExpiredSignatureError:
        raise expired_token_error
        
    except jwt.PyJWTError:
        raise credential_exception 
    
    statement = select(User).where(User.username == token_data.username)
    result = await db.exec(statement)
    user = result.first()
    
    if user is None:
        raise credential_exception
    return user 




# function to get active users
async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is inactive or suspended")
    return current_user

