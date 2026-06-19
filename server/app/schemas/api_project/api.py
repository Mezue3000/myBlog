# import dependencies
from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime





# create project schema
class ApiProjectCreate(SQLModel):
    name: str = Field(max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    environment: str = Field(default="live", max_length=20)
    
    
    



# create api-key schema
class ApiKeyCreate(SQLModel):
    name: str = Field(max_length=100)
    expires_at: Optional[datetime] = None