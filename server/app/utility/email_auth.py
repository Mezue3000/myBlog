# import dependencies 
import os, jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv
import json
import pyotp
from pydantic import EmailStr
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, status
from redis.asyncio import Redis
from app.main import redis, password
from jwt import ExpiredSignatureError, PyJWKError
from fastapi_mail import FastMail, ConnectionConfig, MessageSchema




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

async def create_email_otp(email: EmailStr, scope: str, expire_delta: timedelta = None) -> str:
    
    try:
        expire_time = expire_delta or timedelta(minutes=EMAIL_OTP_EXPIRE_MINUTES)

        # generate a unique secret per OTP session
        secret = pyotp.random_base32()

        # create TOTP generator
        totp = pyotp.TOTP(secret, interval=int(expire_time.total_seconds()))

        # generate 6-digit OTP
        otp_code = totp.now()

        # redis key includes scope
        redis_key = f"email_otp:{scope}:{email}"

        # clear previous OTP
        await redis.delete(redis_key)

        # store secret + expiry; OTP is regenerated via TOTP
        payload = {
            "secret": secret,
            "expires_at": (datetime.now(timezone.utc) + expire_time).isoformat()
        }

        ttl_seconds = int(expire_time.total_seconds())
        await redis.setex(redis_key, ttl_seconds, json.dumps(payload))

        return otp_code

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate OTP: {str(e)}"
        )


 

# function to verify email otp
async def verify_email_otp(email: EmailStr, scope: str, otp_code: int) -> str:
    redis_key = f"email_otp:{scope}:{email}"

    data = await redis.get(redis_key)

    if not data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP expired or not found. Please request a new one."
        )

    payload = json.loads(data)
    secret = payload["secret"]
    expires_at = datetime.fromisoformat(payload["expires_at"])
    stored_email = email  # email already tied to key  

    # Check expiry
    if datetime.now(timezone.utc) > expires_at:
        await redis.delete(redis_key)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP has expired. Please request a new one."
        )

    # Verify OTP
    totp = pyotp.TOTP(secret, interval=int((expires_at - datetime.now(timezone.utc)).total_seconds()))

    if not totp.verify(otp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP. Please try again."
        )

    # Delete OTP after success
    await redis.delete(redis_key)

    return stored_email

       


# define fastapi mail config params 
mail_config = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=587,
    MAIL_SERVER=(os.getenv("MAIL_SERVER")), 
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)




# function to send a verification OTP email
async def send_verification_otp_email(email: EmailStr, otp: int, scope: str):
    
    # message based on scope 
    if scope == "registration":
        user_message = (
            "Thank you for signing up! To complete your registration, please verify your email "
            "address by entering this code on our website:"
        )
        subject = "BlogMap Verification Email - Registration"
        endnote = "If you did not request this, please ignore this email."
        
    elif scope == "2FA":
        user_message = (
            "We noticed a log-in attempt on your account. If that was you, please enter this code below:"
        )
        subject = "BlogMap Login Verification Code"
        endnote = (
            "If you did not try to access your BlogMap account, please reset your password immediately "
            "and review your account activity."
        )
        
    elif scope == "update":
        user_message = (
            f"You have requested to update your email address to {email}. To confirm this change, "
            "please enter this code on our website:"
 
        )
        subject = "BlogMap Email Change Confirmation"
        endnote = "If you did not request this change, please contact our support team immediately."
        
    elif scope == "reset":
        user_message = (
            "You have requested to reset your password. To proceed, please enter this code on our website:"
        )
        subject = "BlogMap Password Reset Code"
        endnote = "If you did not request this password reset, please ignore this email."
        
    else:
        user_message = "Use the verification code below."
        subject = "BlogMap Email Verification Code"
        endnote = "If you did not request this, please ignore this email."
    

    # HTML email content
    html_content = f"""
    <div style="font-family: Arial; padding: 20px; border: 1px solid #ddd; border-radius: 12px; text-align: center;"> 
        <h1 style="font-weight: bold; color: #333333; font-family: Arial black;">BlogMap</h1>
        
        <p>Hi {email},</p> 
        <br/>
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

        <hr style="margin-top: 30px;"/>
        <p>Best regards,</p>
        <p>BlogMap Inc</p>
    </div>
    """

    message = MessageSchema(
        subject=subject,
        recipients=[email],
        body=html_content,
        subtype="html"
    )

    fast_mail = FastMail(mail_config)

    try:
        await fast_mail.send_message(message)

    except ConnectionRefusedError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to connect to email server."
        )

    except TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Email sending timed out."
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send verification email: {str(e)}"
        )





# async def send_verification_email(
#     email: EmailStr, 
#     token: str,
#     link: str,
#     template_type: str
# ):
#     if template_type == "registration":
#         message = "You need to verify your email address to complete your registration. Click the button below to verify your email address"
#     elif template_type == "update":
#         message = "You need to verify your new email address to complete your update. Click the button below to verify your new email address"
#     else:
#         message = "please verify your email"
#     # verification link(will later change to f"http://localhost:3000/{frontend_path}?token={token}")
#     verification_link = f"http://localhost:8000/{link}?token={token}"
#     html_content = f"""
#     <div style="font-family: Arial; padding: 20px; border: 1px solid; border-radius: 9px; text-align: center;">
#         <h1 style="font-weight: Bold; color: blue;">blog-map</h1>
#         <h2>Verify your email address</h2> 
#         <hr/>
#         <p>{message}</p>
#         <a href="{verification_link}" style="
#             display: inline-block;
#             padding: 12px 24px;
#             font-size: 15px;
#             color: white;
#             background-color: #007BFF;
#             text-decoration: none;
#             border-radius: 8px;
#             margin-top: 10px;
#         ">Verify Email</a>
#         <p>If you did not request this, please ignore this email.</p>
#     </div>
#     """

#     message = MessageSchema(
#         subject="Email Verification",
#         recipients=[email],
#         body=html_content,
#         subtype="html"
#     )

#     fast_mail = FastMail(mail_config)
#     await fast_mail.send_message(message) 
    