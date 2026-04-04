# import dependencies
from app.cores.logging import get_logger
import jwt, uuid, os
from app.cores.redis import redis_client
from cryptography.hazmat.primitives import serialization
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status, Request, Response, BackgroundTasks
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.database import get_db
from typing import Optional
from sqlalchemy.orm import selectinload
from jwt import PyJWKError, ExpiredSignatureError
from sqlmodel import select, or_
from app.models import RolePermission, Role, Permission, User, AuditLog






# initialize logging
logger = get_logger(__name__)




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

    logger.info(
        "logout_all_devices",
        extra={
            "user_id": user_id,
            "refresh_token_count": revoked,
        },
    )

    return revoked  




# users ownership verification
def verify_users_ownership(resource_owner_id: int, current_user: User):
    """
    Checks if the current user is the owner OR a superadmin group.
    """
    # superadmin/admin/moderator bypass
    if current_user.role.name in ["superadmin", "admin", "moderator"]:
        return True
        
    # ownership check
    if resource_owner_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to modify this resource"
        )
        
    return True




# load public key from file
with open("C:/Users/HP/Desktop/Python-Notes/myBlog/server/ec_public.pem", "rb") as f: 
     PUBLIC_KEY = f.read() 

public_key = serialization.load_pem_public_key(PUBLIC_KEY)



# define jwt params
ALGORITHM = "ES256"



# function to get current user
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

credential_exception = HTTPException(
    status_code = status.HTTP_404_NOT_FOUND, 
    detail = "User not found", 
    headers = {"WWW-Authenticate": "Bearer"})
    
expired_token_error = HTTPException(
    status_code = status.HTTP_401_UNAUTHORIZED,
    detail = "Session Timeout",
    headers = {"WWW-Authenticate": "Bearer"})
    

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])
        
        user_id: Optional[str] = payload.get("sub")
        scope: Optional[str] = payload.get("scope")
        
        if user_id is None or scope != "access":
            raise credential_exception
        
        user_id = int(user_id)
        
    except ExpiredSignatureError:
        raise expired_token_error
        
    except jwt.PyJWTError:
        raise credential_exception 

    statement = (
        select(User)
        .where(User.user_id == user_id)
        .options(selectinload(User.role).selectinload(Role.permissions))
    )
    
    result = await db.exec(statement)
    user = result.first()
    
    if not user or user.is_deleted:
        raise credential_exception
    return user 
 



# function to get active users
async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    # check if the account is merely inactive/suspended
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Account is inactive or suspended"
        )
    return current_user

 
 

# function to validate unique fields
async def validate_unique_fields(
    db: AsyncSession,
    fields: dict,
    *,
    exclude_user_id: Optional[int] = None,  
):
    unique_fields = {
        "username": "Username already taken.",
        "email": "Email already in use."
    }

    for field, error_message in unique_fields.items():

        value = fields.get(field)
        if value is None:
            continue

        stmt = select(User).where(getattr(User, field) == value)
        result = await db.exec(stmt)
        existing = result.first()

        # If user exists and it's not the excluded user → conflict
        if existing and (exclude_user_id is None or existing.user_id != exclude_user_id):

            logger.warning(
                "Unique constraint violation",
                extra={
                    "field": field,
                    "value": value,
                    "existing_user_id": existing.user_id,
                },
            )

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_message
            ) 
            
            
            


# fetch user by email/username
async def get_user_by_identifier(db: AsyncSession, identifier: str):
    stmt = select(User).where(or_(User.email == identifier, User.username == identifier))
    result = await db.exec(stmt)
    return result.first()





# validate users existence
def validate_user_credentials(user: User):
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid username/email or password"
        )
    
    if user.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
        
        
        
        
# get user by email    
async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.exec(select(User).where(User.email == email))
    return result.first()




# validate user(2fa context)
def validate_2fa_user(user: User):
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request"
        )

    if user.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )