# import dependencies
from sqlmodel import SQLModel
from typing import Optional
import os
from dotenv import load_dotenv
from fastapi_csrf_protect import CsrfProtect


# token schema
class Token(SQLModel):
    access_token: str
    token_type: str    


# token data schema 
class TokenData(SQLModel):
    username: Optional[str] = None
    


# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/.env")



# csrf data schema configuration
class CsrfSettings(SQLModel):
    secret_key: str = os.getenv("CSRF_SECRET")
    token_in: str = "header"
    token_key: str = "X-CSRF-Token"
    cookie_csrf: bool = False
    
    

@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()
