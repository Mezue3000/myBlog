# import dependencies 
import os, jwt, logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv
from typing import Optional
import json
import pyotp
import httpx
from pydantic import EmailStr
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, status, BackgroundTasks
from app.cores.redis import redis_client
from jwt import ExpiredSignatureError, PyJWKError
from app.utility.logging import get_logger




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
        
        
        
        
 
logger = get_logger("email")

# 5 minutes
OTP_TTL_SECONDS = 300  
# function to resend verification email
async def resend_verification_otp(email: str, background_tasks:BackgroundTasks) -> None:
    
    otp = await create_email_otp(email, scope="registration")

    key = f"email_otp:{email}"

    # overwrite existing OTP
    try:
        await redis_client.setex(key, OTP_TTL_SECONDS, str(otp))
    except Exception as e:
        logger.error("redis_otp_storage_failed", extra={"email": email, "error": str(e)})
        raise HTTPException(status_code=500, detail="Could not generate code")

    # background this: The user shouldn't wait for the email API to respond
    background_tasks.add_task(
        send_verification_otp_email,
        email=email,
        otp=otp,
        scope="registration"
    )

    logger.info("verification_otp_queued", extra={"email": email})
