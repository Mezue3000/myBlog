# import dependencies
from sqlmodel import SQLModel, Field
from pydantic import EmailStr, field_validator, model_validator, ConfigDict
from datetime import datetime
from typing import Optional



# base schema for common fields
class UserBase(SQLModel):
    first_name: str = Field(min_length=2, max_length=25)
    last_name: str = Field(min_length=2, max_length=25)
    username: str = Field(min_length=2, max_length=55)
    biography: Optional[str] = Field(default=None)
    country: str
    city: str 
    
    


# schema for creating user
class UserCreate(UserBase):
    password: str = Field(min_length=12)
    confirm_password: str = Field(min_length=12) 
    
    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str):
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c in "!@#$%^&*()-_=+[{]};:<>?|/" for c in v):
            raise ValueError("Password must contain at least one special character")
        return v
    
        @model_validator(mode='after')
        def check_passwords_match(self) -> 'UserCreate':
            pw1 = self.password
            pw2 = self.confirm_password
            if pw1 is not None and pw2 is not None and pw1 != pw2:
                raise ValueError("passwords do not match")
            return self



# schema for reading user
class UserRead(UserBase):
    user_id: int
    email: EmailStr
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)
    
    

# schema to update user fields
class UserUpdate(SQLModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
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
    
    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str):
        if not any(c.isupper() for c in v):
            raise ValueError("New password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("New password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("New password must contain at least one digit")
        if not any(c in "!@#$%^&*()-_=+[{]};:<>?|/" for c in v):
            raise ValueError("New password must contain at least one special character")
        return v

    @model_validator(mode="after")
    def validate_password_logic(self) -> "UserPasswordUpdate":
        if self.new_password == self.old_password:
            raise ValueError("New password cannot be the same as the old password")
        if self.new_password != self.confirm_password:
            raise ValueError("New password and confirm password do not match")

        return self
    

# schema for email verification
class EmailRequest(SQLModel):
    email: EmailStr
    
    
    
    
# schema for update email
class EmailUpdate(SQLModel):
    new_email: EmailStr
    password: str




# schems for resend email
class ResendVerificationEmail(SQLModel):
    email: EmailStr




# schema for password-reset
class PasswordResetConfirm(SQLModel):
    otp: str
    new_password: str
    confirm_password: str
    
    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str):
        if not any(c.isupper() for c in v):
            raise ValueError("New password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("New password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("New password must contain at least one digit")
        if not any(c in "!@#$%^&*()-_=+[{]};:<>?|/" for c in v):
            raise ValueError("New password must contain at least one special character")
        return v
    
    @model_validator(mode="after")
    def validate_password_logic(self) -> "PasswordResetConfirm":
        if self.new_password != self.confirm_password:
            raise ValueError("New password and confirm password do not match")

        return self




# schema for otp verification
class TwoFAVerify(SQLModel): 
    otp: str
    remember_device: bool = False
