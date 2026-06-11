# import dependencies
from sqlmodel import SQLModel
from datetime import datetime
from pydantic import EmailStr, ConfigDict
from typing import List, Optional 
from uuid import UUID




# individual user read schema
class UserRead(SQLModel):
    user_id: int
    username: str
    country: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)




# users paginated response schema
class PaginatedUsers(SQLModel):
    items: List[UserRead]
    total: int
    page: int
    size: int
    total_pages: int


 

# schema to update user fields
class UserUpdate(SQLModel):
    username: Optional[str] = None
    biography: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
     
     
     


class UserUpdateRead(UserRead):
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
    
    
    
    

# tenant summary schema
class TenantSummary(SQLModel):
    tenant_id: UUID
    name: str
    slug: str
    is_active: bool
    is_deleted: bool
    owner_name: str | None = None
    owner_email: str | None = None
    member_count: int
    created_at: datetime
    
    
    
    

# tenants paginated response schema
class PaginatedTenants(SQLModel):
    items: list[TenantSummary] 
    total: int
    page: int
    size: int
    total_pages: int