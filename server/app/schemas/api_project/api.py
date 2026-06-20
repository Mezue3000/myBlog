# import dependencies
from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime
from uuid import UUID
from pydantic import ConfigDict





# create project schema
class ApiProjectCreate(SQLModel):
    name: str = Field(max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    environment: str = Field(default="live", max_length=20)
    
    
    


# create api-key schema
class ApiKeyCreate(SQLModel):
    name: str = Field(max_length=100)
    expires_at: Optional[datetime] = None
    
    
    


# create api-response schema
class ApiKeyRead(SQLModel):
    api_key_id: UUID
    project_id: int
    project_name: str
    name: str
    key_prefix: str
    is_revoked: bool
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
    
    
    
    
    
    
# create api-usage schema
class APIUsageLogRead(SQLModel):
    log_id: int
    project_id: int
    project_name: str
    api_key_id: Optional[UUID]
    api_key_name: Optional[str]
    endpoint: str
    method: str
    status_code: int
    response_time_ms: int
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
    
