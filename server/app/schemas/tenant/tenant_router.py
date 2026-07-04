# import dependencies
from sqlmodel import SQLModel, Field
from uuid import UUID
from pydantic import ConfigDict
from typing import Optional




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
   
   
   

# schema to update tenant brand
class TenantBrandingUpdate(SQLModel):
    name: Optional[str] = Field(
        default=None,
        min_length=2,
        max_length=255
    )

    logo_url: Optional[str] = Field(
        default=None,
        max_length=500
    )

    primary_color: Optional[str] = Field(
        default=None,
        max_length=20
    )
    
    
    
    
    
# schema to read tenant brand
class TenantBrandingRead(SQLModel):
    tenant_id: UUID
    name: str
    slug: str
    logo_url: Optional[str]
    primary_color: str
    
    model_config = ConfigDict(from_attributes=True)
    
    
    
    

# delete tenant schema
class DeleteTenantRequest(SQLModel):
    otp: int
