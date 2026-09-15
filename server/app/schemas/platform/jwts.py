# import dependencies
from sqlmodel import SQLModel
from uuid import UUID
from typing import Optional



# token schema
class Token(SQLModel):
    access_token: str
    csrf_token: str
    tenant_id: UUID
    name: str
    tenant_type: str
    token_type: str    
