# import dependencies 
import os, jwt, logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv
from typing import Optional
import json, secrets
import pyotp
import httpx
from pydantic import EmailStr
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, status, BackgroundTasks, Response, Request
from app.cores.redis import redis_client
from jwt import ExpiredSignatureError, PyJWKError
from app.utility.logging import get_logger
from app.schemas.users import EmailRequest, UserCreate, UserRead, TwoFAVerify, PasswordResetConfirm
from app.utility.user_service import validate_unique_fields, create_access_token, create_refresh_token, set_auth_cookies, is_trusted_device, create_trusted_device, set_trusted_device_cookie, build_audit_context, logout_all_devices_for_user, log_refresh_failure, rotate_refresh_token
from sqlmodel.ext.asyncio.session import AsyncSession
from app.models import User, AuditLog
from sqlalchemy.exc import IntegrityError
from app.utility.database import async_engine
from sqlmodel import select, or_
from app.utility.security import hash_password, verify_password
from fastapi.security import OAuth2PasswordRequestForm




# instantiate logging
logger = logging.getLogger(__name__)

 
# #  load environment variable
# load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/.env")



# # get environ key
# key = os.getenv("SPIRIT_KEY").encode()
# fernet = Fernet(key)



# # get database environment variable
# encrypted_secret_key = os.getenv("ENCRYPTED_SECRET_KEY")
# decrypted_secret_key = fernet.decrypt(encrypted_secret_key).decode()




# # define jwt params
# email_secret_key = decrypted_secret_key
# algorithms = os.getenv("ALGORITHMS")
# email_token_expire_minutes = 15



# function to create email otp
EMAIL_OTP_EXPIRE_MINUTES = 10
EMAIL_OTP_COOLDOWN_SECONDS = 180

async def create_email_otp(email: EmailStr, scope: str, expire_delta: Optional[timedelta] = None) -> str:
    
    email = email.lower().strip()

    expire_time = expire_delta or timedelta(minutes=EMAIL_OTP_EXPIRE_MINUTES)
    redis_key = f"email_otp:{scope}:{email}"

    try:
        existing = await redis_client.get(redis_key)

        # OTP exists → check cooldown
        if existing:
            payload = json.loads(existing)

            created_at = datetime.fromisoformat(payload["created_at"])
            now = datetime.now(timezone.utc)

            # within cooldown → return same OTP
            if (now - created_at).total_seconds() < EMAIL_OTP_COOLDOWN_SECONDS:
                totp = pyotp.TOTP(
                    payload["secret"],
                    interval=payload["interval"],
                )
                return totp.now().zfill(6)

        # generate new OTP
        secret = pyotp.random_base32()
        interval = int(expire_time.total_seconds())
        totp = pyotp.TOTP(secret, interval=interval)
        otp_code = totp.now().zfill(6)
        
        payload = {
            "secret": secret,
            "interval": interval,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + expire_time).isoformat(),
        }

        await redis_client.setex(
            redis_key,
            interval,
            json.dumps(payload),
        )

        return otp_code

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate OTP",
        )


 

# function to verify email otp
async def verify_email_otp(otp_code: str, scope: str) -> str:
    """
    Verifies an email OTP and returns the verified email.
    OTP is single-use and scope-bound.
    """
    otp_code = str(otp_code).strip()
    pattern = f"email_otp:{scope}:*"

    now = datetime.now(timezone.utc)

    async for key in redis_client.scan_iter(match=pattern):
        raw = await redis_client.get(key)
        if not raw:
            continue

        try:
            payload = json.loads(raw)
            expires_at = datetime.fromisoformat(payload["expires_at"])
        except (KeyError, ValueError, json.JSONDecodeError):
            await redis_client.delete(key)
            continue

        # expired → cleanup
        if now > expires_at:
            await redis_client.delete(key)
            continue

        totp = pyotp.TOTP(
            payload["secret"],
            interval=payload["interval"],
        )

        if totp.verify(otp_code, valid_window=1):
            email = key.split(":")[-1]

            # single-use OTP
            await redis_client.delete(key)

            logger.info(
                "email_otp_verified",
                extra={
                    "email": email,
                    "scope": scope,
                },
            )

            return email

    logger.warning(
        "email_otp_failed",
        extra={
            "scope": scope,
        },
    )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired OTP",
    )




# fetch email credentials
MAIL_API_KEY = os.getenv("MAIL_API_KEY")
MAIL_FROM = os.getenv("MAIL_FROM")

if not MAIL_API_KEY or not MAIL_FROM:
    raise RuntimeError("Missing RESEND_API_KEY or MAIL_FROM")


RESEND_API_URL = "https://api.resend.com/emails"



# function to send verification OTP email
async def send_verification_otp_email(email: EmailStr, otp: int, scope: str):
    # message per scope
    if scope == "registration":
        user_message = (
            "Thank you for signing up! To complete your registration, "
            "please verify your email address by entering this code on our website:"
        )
        subject = "BlogMap Verification Email - Registration"
        endnote = "If you did not request this, please ignore this email."

    elif scope == "2FA": 
        user_message = (
            "We noticed a login attempt on your account. "
            "If that was you, please enter this code below:"
        )
        subject = "BlogMap Login Verification Code"
        endnote = (
            "If you did not try to access your BlogMap account, "
            "please reset your password immediately."
        )

    elif scope == "update":
        user_message = (
            f"You requested to update your email address to {email}. "
            "To confirm this change, please enter this code:"
        )
        subject = "BlogMap Email Change Confirmation"
        endnote = "If you did not request this change, contact support immediately."

    elif scope == "password_reset":
        user_message = (
            "You requested to reset your password. "
            "Please enter this code to proceed:"
        )
        subject = "BlogMap Password Reset Code "
        endnote = "If you did not request this, please ignore this email."

    else:
        user_message = "Use the verification code below."
        subject = "Fraud Alert....Be Alert"
        endnote = "If you did not request this, please ignore this email."

    # html setup
    html_content = f"""
<div style="font-family:Arial,sans-serif;max-width:480px;margin:20px auto;padding:24px;background:var(--bg,#fff);color:var(--text,#111);border:1px solid var(--border,#ddd);border-radius:12px;text-align:center;">
  <style>
    :root{{--bg:#fff;--text:#111;--otp-bg:#f8f9fa;--border:#e0e0e0;}}
    @media (prefers-color-scheme:dark){{:root{{--bg:#111;--text:#eee;--otp-bg:#333;--border:#444;}}}}
  </style>
  <h1 style="margin:0 0 20px;color:var(--text);">BlogMap</h1>
  <p style="margin:0 0 12px;">Hi {email},</p>
  <p style="margin:0 0 20px;">{user_message}</p>
  <div style="background:var(--otp-bg);padding:16px 24px;margin:24px auto;max-width:240px;border-radius:10px;border:1px solid var(--border);">
    <div style="font-family:monospace;font-size:40px;font-weight:bold;letter-spacing:0;color:var(--text);">
      {otp}
    </div>
  </div>
  <p style="margin:0 0 12px;font-size:14px;color:#666;">Expires in 7 minutes</p>
  <p style="margin:0 0 20px;">{endnote}</p>
  <div style="border-top: 1px solid #dddddd; margin: 25px 0; line-height: 1px; font-size: 1px;">&nbsp;</div>
  <p style="margin:0;font-size:13px;color:#777;">Best regards,<br/>BlogMap Team</p>
</div>
"""

    payload = {
        "from": MAIL_FROM,
        "to": [email],
        "subject": subject,
        "html": html_content,
    }

    headers = {
        "Authorization": f"Bearer {MAIL_API_KEY}",
        "Content-Type": "application/json",
    }

    # send email
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.post(
                RESEND_API_URL,
                json=payload,
                headers=headers,
            )

        response.raise_for_status()  

        logger.info(f"OTP email sent successfully to {email} (scope: {scope})")
            

    except httpx.HTTPStatusError as e:
        logger.error(
            f"Resend API error sending OTP to {email}: {e.response.status_code} - {e.response.text}",
            exc_info=True
        )

    except httpx.TimeoutException:
        logger.error(f"Timeout sending OTP email to {email}", exc_info=True)

    except httpx.RequestError as e:
        logger.error(f"Network error sending OTP to {email}: {str(e)}", exc_info=True)

    except Exception as e:
        logger.exception(f"Unexpected error sending OTP to {email}")
        
        
        
        
        
async def initiate_registration(
    user_data: EmailRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession,
):
    update_fields = user_data.model_dump(exclude_unset=True)
    
    # check if email already exists
    await validate_unique_fields(db=db, fields=update_fields)
   
    # generate OTP
    otp = await create_email_otp(email=user_data.email, scope="registration")

    # send verificataon email in background
    background_tasks.add_task(send_verification_otp_email, user_data.email, otp, "registration")

    return {
        "message": "Registration started. If the email exists, a verification code has been sent."
    }





async def finalize_registration(user: UserCreate, otp_code: str, db: AsyncSession):
    update_fields = user.model_dump(exclude_unset=True)
    
    # check if username already exists
    await validate_unique_fields(db=db, fields=update_fields)
   
    # verify OTP and extract email
    try:
        email = await verify_email_otp(otp_code=otp_code, scope="registration")
        logger.info("OTP verified successfully for email: %s", email)
    except HTTPException as exc:
        logger.warning("OTP verification failed: %s", exc.detail)
        raise exc
    
    # hash password
    hashed_password = await hash_password(user.password)
    roleid=16 

    # create user
    new_user = User(
        email=email.lower(),
        username=user.username.lower(),
        password_hash=hashed_password,
        biography=user.biography,
        country=user.country.lower(),
        city=user.city.lower(),
        role_id=roleid
    )

    try:
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        logger.info("User created successfully: %s", email)
    except IntegrityError:
        await db.rollback()
        logger.error("Integrity error during registration for email: %s", email)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists",
        )

    return UserRead.model_validate(new_user)




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
    
    
    
    
# login function
async def authenticate_users(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    form_data: OAuth2PasswordRequestForm,
    db: AsyncSession
):
    # OAuth2PasswordRequestForm uses "username" for both email and username  
    login_identifier = form_data.username.lower().strip()
    password = form_data.password

    # fetch user
    user = await get_user_by_identifier(db, login_identifier)

    # validate user
    validate_user_credentials(user)

    # validate password
    await validate_password(password, user.password_hash)

    # check trusted device (2FA bypass)
    trusted_device = request.cookies.get("trusted_device")

    if trusted_device and await is_trusted_device(user.user_id, trusted_device):
        # extract context metas
        context = build_audit_context(request)
        
        # audit-log success (bypass 2FA)
        background_tasks.add_task(
            create_auth_audit_log_bg,        
            action="LOGIN_SUCCESS",
            user_id=user.user_id,
            metadata={"method": "trusted_device"},
            context=context
        )
        return await handle_trusted_device_login(user, response)

    # handle 2FA challenge
    return await handle_2fa_challenge(
        user=user,
        background_tasks=background_tasks
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
    
    
    
    
# function to verify 2fa authentiction 
async def confirm_2fa(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    data: TwoFAVerify,
    db: AsyncSession
):
    # verify OTP → returns email
    email = await verify_email_otp(
        otp_code=data.otp,
        scope="2FA"
    )

    # fetch user
    user = await get_user_by_email(db, email)

    # validate user
    validate_2fa_user(user)

    # generate tokens
    tokens = await generate_auth_tokens(user)

    # set cookies
    set_auth_cookies(response, tokens["access_token"], tokens["refresh_token"], tokens["csrf_token"])

    # remember device (optional)
    if data.remember_device:
        await handle_remember_device(user, response)
    
    # extract context metas
    context = build_audit_context(request)
        
    # audit-log success
    background_tasks.add_task(
        create_auth_audit_log_bg,        
        action="2FA_SUCCESS",
        user_id=user.user_id,
        metadata={"remember_device": data.remember_device},
        context=context
    )

    # log success
    logger.info("2fa_success", extra={"user_id": user.user_id})

    return {
        "access_token": tokens["access_token"],
        "token_type": "bearer"
    }
    
    
    
    
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
    
    
    
    
# request for reset password
async def demand_password_reset(
    email: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession
):
    # normalize email
    normalized_email = email.lower().strip()

    # fetch user
    user = await get_user_by_email(db, normalized_email)

    # if user exists → send OTP
    if user:
        await handle_password_reset_request(
            user=user,
            email=normalized_email,
            background_tasks=background_tasks
        )

    # always return same response (prevent enumeration)
    return {
        "message": "If the email exists, a password reset code has been sent."
    }
    
    
    
    
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
        
        
        

# function to delete email-OTP from redis
async def cleanup_reset_otp(email: str):
    await redis_client.delete(f"email_otp:password_reset:{email}")
    
    
    

# pasword reset confirmation
async def verify_password_reset(
    request: Request,
    data: PasswordResetConfirm,
    db: AsyncSession
):
    # verify OTP → get email
    email = await verify_reset_otp(data.otp)

    # fetch user
    user = await get_user_by_email(db, email)

    # validate user
    validate_user_credentials(user)

    # update password + audit
    await update_user_password_with_audit(
        user=user,
        new_password=data.new_password,
        request=request,
        db=db
    )

    # force logout all sessions
    await logout_all_devices_for_user(user.user_id)

    # cleanup OTP
    await cleanup_reset_otp(email)

    # log success
    logger.info(
        "password_reset_success",
        extra={"user_id": user.user_id}
    )

    return {
        "message": "Password reset successful. Please log in again."
    }
    
    
    
    
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
        
        
        
        
# function to refresh token
async def refresh_session_token(request: Request, response: Response):
    # extract refresh token from cookies
    old_refresh_token = extract_refresh_token(request)

    # rotate refresh token
    new_refresh_token = await rotate_refresh_token(old_refresh_token, request)

    # get token payload from Redis
    payload = await get_refresh_token_payload(new_refresh_token, request)

    # generate new access token
    access_token = create_access_token(user_id=payload.get("user_id"))

    # set cookies
    set_auth_cookies(response, access_token, new_refresh_token)

    return {"detail": "Token refreshed"}




# function to clear token cookies
def clear_auth_cookies(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("csrf_token")
    
    
    

# function to logout all devices
async def signout_all_devices(
    request: Request,
    response: Response,
):
    # extract refresh token
    refresh_token = await extract_refresh_token(request)

    # get session payload
    payload = await get_refresh_token_payload(refresh_token, request)

    # extract user_id
    user_id = payload.get(user_id)

    # invalidate all sessions
    await logout_all_devices_for_user(user_id)

    # clear cookies
    clear_auth_cookies(response)

    return {"detail": "Logged out successfully from all devices"} 