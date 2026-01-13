# import dependencies
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from datetime import timedelta, datetime, timezone
import jwt 
from redis.asyncio import Redis
import secrets
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.database import get_db
from typing import Optional
from app.schemas.jwts import TokenData
from jwt import PyJWKError, ExpiredSignatureError
from sqlmodel import select
from app.models import User



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



# set up redis client
password = os.getenv("PASSWORD")
redis = Redis(host="localhost", port=6380, db=0, password=password, decode_responses=True) 


 
# function to create jwt access token 
def create_access_token(data: dict, expire_delta: timedelta=None) -> str:
    to_encode = data.copy() 
    expire = datetime.now(timezone.utc) + (expire_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, private_key, algorithm=ALGORITHM) 
    return encoded_jwt
    
    

# function to create jwt refresh token
async def create_refresh_token(user_id: str) -> str: 
    refresh_token = secrets.token_urlsafe(48)
    
    # Compute ttl
    expire = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    ttl = int(expire.total_seconds())

    # Redis key
    key = f"refresh:{refresh_token}"

    # Store in redis
    await redis.setex(key, ttl, user_id)
    
    return refresh_token
 


# function to rotate/invalidate old refresh token
async def rotate_refresh_token(old_token: str) -> Optional[str]:
    user_id = await redis.get(f"refresh: {old_token}")
    if not user_id:
        return None
    
    # invalidate old_token
    await redis.delete(f"refresh: {old_token}")
    
    # issue new refresh token
    return await create_refresh_token(user_id)




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

