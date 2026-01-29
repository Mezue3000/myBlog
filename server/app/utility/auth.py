# import dependencies
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from datetime import timedelta, datetime, timezone
import jwt, uuid
from app.cores.redis import redis_client
import secrets
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
    refresh_token = secrets.token_urlsafe(48)
    
    # internal tracking only
    refresh_id = str(uuid.uuid4()) 

    ttl = int(timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS).total_seconds())

    key = f"refresh:{refresh_token}"
    
    value = {
        "user_id": user_id,
        "refresh_id": refresh_id,
    }

    await redis_client.hset(key, mapping=value)
    await redis_client.expire(key, ttl)

    return refresh_token




# function to rotate/invalidate old refresh token
async def rotate_refresh_token(old_token: str) -> Optional[str]:
    key = f"refresh:{old_token}"
    
    # get all refresh data
    data = await redis_client.hgetall(key)
    if not data:
        return None  

    user_id = data.get(b"user_id").decode()

    # invalidate old token first
    await redis_client.delete(key)

    # issue new refresh token
    return await create_refresh_token(user_id)




# function to get refresh failures
logger = get_logger("auth")

async def log_refresh_failure(reason: str, request):
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

