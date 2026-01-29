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
from fastapi import HTTPException, status
from app.cores.redis import redis_client
from jwt import ExpiredSignatureError, PyJWKError




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
EMAIL_OTP_COOLDOWN_SECONDS = 60

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
    # verifies OTP and returns the verified email.
    pattern = f"email_otp:{scope}:*"
    keys = await redis_client.keys(pattern)

    if not keys:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP expired or invalid",
        )

    now = datetime.now(timezone.utc)

    for key in keys:
        raw = await redis_client.get(key)
        if not raw:
            continue

        payload = json.loads(raw)
        expires_at = datetime.fromisoformat(payload["expires_at"])

        if now > expires_at:
            await redis_client.delete(key)
            continue

        totp = pyotp.TOTP(payload["secret"], interval=payload["interval"])

        if totp.verify(str(otp_code), valid_window=1):
            email = key.split(":")[-1]

            # single-use
            await redis_client.delete(key)

            return email

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

    elif scope == "reset":
        user_message = (
            "You requested to reset your password. "
            "Please enter this code to proceed:"
        )
        subject = "BlogMap Password Reset Code "
        endnote = "If you did not request this, please ignore this email."

    else:
        user_message = "Use the verification code below."
        subject = "BlogMap Email Verification Code"
        endnote = "If you did not request this, please ignore this email."

    # html setup
    html_content = f"""
    <div style="font-family: Arial; padding: 20px; border: 1px solid #ddd;
                border-radius: 12px; text-align: center;">
        <h1 style="font-weight: bold;">BlogMap</h1>

        <p>Hi {email},</p>
        <p>{user_message}</p>

        <div style="
            display: inline-block;
            font-size: 32px;
            font-weight: bold;
            letter-spacing: 8px;
            padding: 12px 24px;
            background: #f2f7ff;
            border-radius: 8px;
            margin: 20px 0;
        ">
            {otp}
        </div>

        <p>This code will expire in 7 minutes.</p>
        <p>{endnote}</p>

        <hr/>
        <p>Best regards,<br/>BlogMap Inc</p>
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
        async with httpx.AsyncClient(timeout=10) as client:
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