# import dependencies
from sqlmodel import SQLModel, Field
from pydantic import EmailStr, ConfigDict
from datetime import datetime
from typing import Optional



# base schema for common fields
class UserBase(SQLModel):
    first_name: str = Field(min_length=2, max_length=25)
    last_name: str = Field(min_length=2, max_length=25)
    username: str = Field(min_length=2, max_length=55)
    email: EmailStr
    biography: str
    country: str
    city: str
    


# schema for creating user
class UserCreate(UserBase):
    password: str = Field(min_length=12)
    confirm_password: str = Field(min_length=12)



# schema for reading user
class UserRead(UserBase):
    user_id: int
    created_at: datetime
    updated_at: Optional[datetime]
    
    model_config = ConfigDict(from_attributes=True)
    
    

# schema to update user fields
class UserUpadate(SQLModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    biography: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    
     

class UserUpdateRead(UserBase):
    updated_at: datetime
    
    
    model_config = ConfigDict(from_attributes=True)
    
    
    
    
# schema to update user password  
class UserPasswordUpdate(SQLModel):
    old_password: str = Field(min_length=12)
    new_password: str = Field(min_length=12)
    confirm_password: str = Field(min_length=12)  