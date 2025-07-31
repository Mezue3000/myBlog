# import dependencies 
import os, jwt
from dotenv import load_dotenv
from pydantic import EmailStr
from datetime import datetime, timezone, timedelta
from fastapi_mail import FastMail, ConnectionConfig, MessageSchema




#  load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/.env")




# define jwt params
email_secret_key = os.getenv("SECRET_KEY")
algorithms = os.getenv("ALGORITHMS")
email_token_expire_minutes = 15




# function to create email access token
def create_email_token(email: EmailStr, expire_delta: timedelta = None) -> str:
    expire = datetime.now(timezone.utc) + (expire_delta or timedelta(minutes=email_token_expire_minutes))
    data = {"sub": email, "exp": expire}
    encoded_jwt = jwt.encode(data, email_secret_key, algorithm=algorithms)
    return encoded_jwt




# function to decode verified token
def decode_token(token: str) -> str:
    payload = jwt.decode(token, email_secret_key, algorithms=[algorithms])
    return payload["sub"]
    




# define fastapi mail config params 
config = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=int(os.getenv("MAIL_PORT")),
    MAIL_SERVER=(os.getenv("MAIL_SERVER")), 
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)



# function to send verification mail
async def send_verification_email(email: EmailStr, token: str):          
    link = f"http://localhost:8000/verify-email?token={token}"
    body = f"""
    <h3>Verify your email address</h3>
    <p>you need to verify your email address to continue with your registration. Click the button below to verify your email address:<p/>
    <a href="{link}" style="
        display: inline-block;
        padding: 10px 20px;
        font-size: 16px;
        color: white;
        background-color: #007BFF;
        text-decoration: none;
        border-radius: 7px;
    ">Verify Email</a>
    """
    
    message = MessageSchema(
        subject="Email verification",
        recipients=[email],
        body=body,
        subtype="html"
    )
    fm = FastMail(config)
    await fm.send_message(message)
    


