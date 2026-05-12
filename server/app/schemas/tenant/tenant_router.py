# import dependencies
from sqlmodel import SQLModel, Field
from uuid import UUID
from pydantic import ConfigDict




# schema to create tenant
class TenantCreate(SQLModel):
    name: str = Field(min_length=2, max_length=125)
    
    
    
    

# schema to read tenant
class TenantRead(SQLModel):
    tenant_id: UUID
    name: str
    slug: str
    role: str
    
    model_config = ConfigDict(from_attributes=True)
   