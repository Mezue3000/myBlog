# import dependencies
from sqlmodel import SQLModel
from datetime import datetime
from pydantic import EmailStr, ConfigDict
from typing import List, Optional 



# individual user read schema
class UserRead(SQLModel):
    user_id: int
    username: str
    country: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)




# paginated response schema
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
    