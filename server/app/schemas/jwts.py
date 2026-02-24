# import dependencies
from sqlmodel import SQLModel
from typing import Optional



# token schema
class Token(SQLModel):
    access_token: str
    refresh_token: Optional[str] = None
    csrf_token: Optional[str] = None
    token_type: str    