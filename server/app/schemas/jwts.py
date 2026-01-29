# import dependencies
from sqlmodel import SQLModel
from typing import Optional



# token schema
class Token(SQLModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str    



# token data schema 
class TokenData(SQLModel):
    username: Optional[str] = None
    

