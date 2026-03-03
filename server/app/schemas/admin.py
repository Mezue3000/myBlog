# import dependencies
from sqlmodel import SQLModel
from datetime import datetime
from pydantic import EmailStr, ConfigDict
from typing import List



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
