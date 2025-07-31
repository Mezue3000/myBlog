# import dependencies
from cryptography.hazmat.primitives import serialization
from datetime import timedelta, datetime, timezone
import jwt
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.database import get_db
from typing import Optional
from app.schemas.jwts import TokenData
from jwt import PyJWKError, ExpiredSignatureError
from sqlmodel import select
from app.models import User




# load private key from file
with open("C:/Users/HP/Desktop/Python-Notes/myBlog/server/ec_private.pem", "rb") as f:
     PRIVATE_KEY = f.read()

private_key = serialization.load_pem_private_key(PRIVATE_KEY, password=None) 




# load public key from file
with open("C:/Users/HP/Desktop/Python-Notes/myBlog/server/ec_public.pem", "rb") as f: 
     PUBLIC_KEY = f.read() 

public_key = serialization.load_pem_public_key(PUBLIC_KEY)



# define jwt params
ALGORITHM = "ES256"
ACCESS_TOKEN_EXPIRE_HOURS = 3



# function to create jwt access token 
def create_access_token(data: dict, expire_delta: timedelta=None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expire_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, private_key, algorithm=ALGORITHM) 
    return encoded_jwt
    
    
    
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
    result = await db.execute(statement)
    user = result.scalars().first()
    
    if user is None:
        raise credential_exception
    return user
