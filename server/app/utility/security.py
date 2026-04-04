# import dependencies
# from passlib.context import CryptContext
from pwdlib import PasswordHash
import asyncio
from fastapi import Request, Depends, Response, HTTPException, status, BackgroundTasks
from app.utility.user import get_current_active_user 
from app.models import User, AuditLog
from typing import Optional
from app.utility.database import async_engine
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.email import create_email_otp, send_verification_otp_email, verify_email_otp
from app.cores.logging import get_logger





# initialize logging
logger = get_logger(__name__)



# initialize hash function
password_hash = PasswordHash.recommended()
# pwd_context = CryptContext(schemes=["argon2"], default="argon2")




# function to hash password
async def hash_password(password: str) -> str:
    return await asyncio.to_thread(password_hash.hash, password)




# function to verify password
async def verify_password(plain_password: str, hashed_password: str) -> bool:
    return await asyncio.to_thread(password_hash.verify, plain_password, hashed_password)






# if __name__ == "__main__":
#     hasy = asyncio.run(hash_password("monday345"))
#     asyncio.run(verify_password("monday345", hasy))
#     print(hasy)





# key function to identify users by email/username and ip-address(rate-limiter)
async def get_identifier(request: Request) -> str:
    body_data = getattr(request.state, "body_data", {}) or {}
    
    prefix = request.client.host or "unknown_ip"
    
    if email := body_data.get("email"):
        return f"{prefix}:{email}"
    
    if username := body_data.get("username"):
        return f"{prefix}:{username}"
    
    return prefix




# key function to identify authenticated users by id(rate-limiter)
def get_identifier_factory(action: str):
    async def identifier(request: Request, user: User = Depends(get_current_active_user)) -> str:
        if user:
            return f"user:{user.user_id}:{action}"
        
        # fallback for unauthenticated requests
        ip = request.headers.get("x-forwarded-for")
        
        if ip:
            ip = ip.split(",")[0].strip()
        else:
            ip = request.client.host or "unknown"
            
        return f"ip:{ip}:{action}"
    
    return identifier



     
# validate password 
async def validate_password(plain_password: str, hashed_password: str):
    if not await verify_password(plain_password, hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email/username or password"
        )
        
        
        
        
# function to create audit-log with background task
async def create_auth_audit_log_bg(
    *,
    action: str,
    user_id: Optional[int] = None,
    metadata: dict,
    context: dict,
):
    async with AsyncSession(async_engine) as db:
        audit_entry = AuditLog(
            actor_id=user_id,
            target_user_id=user_id,
            action=action,
            changes=metadata or {},
            **context
        )

        db.add(audit_entry)
        await db.commit()
        
        
        
          
# handle reset-password
async def handle_password_reset_request(
    user: User,
    email: str,
    background_tasks: BackgroundTasks
):
    otp = await create_email_otp(email=email, scope="password_reset")

    background_tasks.add_task(
        send_verification_otp_email,
        email,
        otp,
        "password_reset"
    )

    logger.info(
        "password_reset_requested",
        extra={"user_id": user.user_id}
    )
    
    
    
    
# password email verification/extraction
async def verify_reset_otp(otp: str) -> str:
    email = await verify_email_otp(
        otp_code=otp,
        scope="password_reset"
    )

    if not email:
        logger.warning(
            "password_reset_failed",
            extra={"reason": "invalid_otp"}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification code"
        )

    return email




# function to update password + audit
async def update_user_password_with_audit(
    user: User,
    new_password: str,
    request: Request,
    db: AsyncSession
):
    # validate password difference
    if await verify_password(new_password, user.password_hash):
        raise HTTPException(
            status_code=400,
            detail="New password must be different from old password"
        )
    
    try:
        # hash password
        user.password_hash = await hash_password(new_password)
        db.add(user)

        # build audit context
        context = build_audit_context(request)

        audit_entry = AuditLog(
            actor_id=user.user_id,
            target_user_id=user.user_id,
            action="PASSWORD_RESET_CONFIRM",
            changes={"password": "[REDACTED]"},
            **context
        )

        db.add(audit_entry)

        await db.commit()

    except Exception as e:
        await db.rollback()

        logger.error(
            "password_reset_db_failure",
            extra={"user_id": user.user_id},
            exc_info=True
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password. Please try again."
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




# general permissions verification function
def require_permission(required_permission: str):

    async def checker(current_user: User = Depends(get_current_active_user)):

        if required_permission not in current_user["permissions"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient privileges"
            )

        return current_user

    return checker



# current_user: User = Depends(require_permission("activate_user"))



# function to extract metadata for audit-log
def build_audit_context(request: Request):
    # extract metadatas
    ip_address = request.headers.get("x-forwarded-for", request.client.host)
    user_agent = request.headers.get("user-agent")
    endpoint = request.url.path

    return {
        "ip_address": ip_address,
        "user_agent": user_agent,
        "endpoint": endpoint,
    } 