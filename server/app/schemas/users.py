# import dependencies
from sqlmodel import SQLModel, Field
from pydantic import EmailStr, ConfigDict
from datetime import datetime



# base schema for common fields
class UserBase(SQLModel):
    first_name: str = Field(min_length=2, max_length=25)
    last_name: str = Field(min_length=2, max_length=25)
    username: str = Field(min_length=2, max_length=55)
    email: EmailStr
    country: str
    city: str
    


# schema for creating user
class UserCreate(UserBase):
    password: str = Field(min_length=12)
    confirm_password: str = Field(min_length=12)



# schema for read user
class UserRead(UserBase):
    user_id: int
    created_at: datetime
    # posts: List["PostReadShort"] = []
    
    model_config = ConfigDict(from_attributes=True)
    