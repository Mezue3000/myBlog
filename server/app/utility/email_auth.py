# import dependencies 
import os, jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv
from pydantic import EmailStr
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, status
from jwt import ExpiredSignatureError, PyJWKError
from fastapi_mail import FastMail, ConnectionConfig, MessageSchema




#  load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/.env")



# get environ key
key = os.getenv("SPIRIT_KEY").encode()
fernet = Fernet(key)



# get database environment variable
encrypted_secret_key = os.getenv("ENCRYPTED_SECRET_KEY")
decrypted_secret_key = fernet.decrypt(encrypted_secret_key).decode()




# define jwt params
email_secret_key = decrypted_secret_key
algorithms = os.getenv("ALGORITHMS")
email_token_expire_minutes = 15




# function to create email access token
def create_email_token(email: EmailStr, expire_delta: timedelta = None) -> str:
    expire = datetime.now(timezone.utc) + (expire_delta or timedelta(minutes=email_token_expire_minutes))
    data = {"sub": str(email), "scope":"email_verification", "exp": expire}
    encoded_jwt = jwt.encode(data, email_secret_key, algorithm=algorithms)
    return encoded_jwt




# function to decode verified token
def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, email_secret_key, algorithms=[algorithms])
        if payload.get("scope") != "email_verification":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token scope")
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.PyJWKError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    



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




# Asynchronous function to send a verification email
async def send_verification_email(
    email: EmailStr, 
    token: str,
    link: str,
    template_type: str
):
    if template_type == "registration":
        message = "You need to verify your email address to complete your registration. Click the button below to verify your email address"
    elif template_type == "update":
        message = "You need to verify your new email address to complete your update. Click the button below to verify your new email address"
    else:
        message = "please verify your email"
    # verification link(will later change to f"http://localhost:3000/{frontend_path}?token={token}")
    verification_link = f"http://localhost:8000/{link}?token={token}"
    html_content = f"""
    <div style="font-family: Arial; padding: 20px; border: 1px solid; border-radius: 9px; text-align: center;">
        <h1 style="font-weight: Bold; color: blue;">blog-map</h1>
        <h2>Verify your email address</h2> 
        <hr/>
        <p>{message}</p>
        <a href="{verification_link}" style="
            display: inline-block;
            padding: 12px 24px;
            font-size: 15px;
            color: white;
            background-color: #007BFF;
            text-decoration: none;
            border-radius: 8px;
            margin-top: 10px;
        ">Verify Email</a>
        <p>If you did not request this, please ignore this email.</p>
    </div>
    """

    message = MessageSchema(
        subject="Email Verification",
        recipients=[email],
        body=html_content,
        subtype="html"
    )

    fast_mail = FastMail(mail_config)
    await fast_mail.send_message(message) 
    