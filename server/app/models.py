# import dependencies
from sqlmodel import SQLModel, Field, Relationship, func
from typing import Optional, List
from pydantic import EmailStr
from datetime import datetime, timezone
from sqlalchemy.orm import Mapped



# create user model
class User(SQLModel, table=True):
    __tablename__ = "users"
    
    user_id: Optional[int] = Field(default=None, primary_key=True)
    first_name: str = Field(max_length=25, nullable=False)
    last_name: str = Field(max_length=25, nullable=False)
    username: str = Field(max_length=75, nullable=False, index=True)
    email: EmailStr = Field(max_length=75, nullable=False)
    password_hash: str = Field(max_length=255, nullable=False)
    country: str = Field(max_length=25, nullable=False)
    city: str = Field(max_length=25, nullable=False)
    created_at: datetime = Field(default_factory = lambda: datetime.now(timezone.utc), nullable=False)
    # create relationship
    posts: Mapped[List["Post"]] = Relationship(back_populates = "user")
    comments: Mapped[List["Comment"]] = Relationship(back_populates = "user")
    
    


# create post model
class Post(SQLModel, table=True):
    __tablename__ = "posts"
    
    post_id: Optional[str] = Field(default_factory=None, primary_key=True)
    title: str = Field(max_length=125, nullable=False, index=True)
    content: str = Field(max_length=450, nullable=False)
    created_at: datetime = Field(default_factory = lambda: datetime.now(timezone.utc), nullable=False)
    updated_at: datetime = Field(
        default_factory = lambda: datetime.now(timezone.utc), 
        sa_column_kwargs= {"onupdate": func.now()})
    # add foreign key
    user_id: int = Field(foreign_key = "users.user_id")
    # create relationship
    user: Mapped["User"] = Relationship(back_populates = "posts")
    comments: Mapped[List["Comment"]] = Relationship(back_populates = "post")




class Comment(SQLModel, table=True):
    __tablename__ = "comments"
    
    comment_id: Optional[str] = Field(default_factory=None, primary_key=True)
    content: str = Field(max_length=450, index=True, nullable=False)
    created_at: datetime = Field(default_factory = lambda: datetime.now(timezone.utc), nullable=False)
    updated_at: datetime = Field(
        default_factory = lambda: datetime.now(timezone.utc), 
        sa_column_kwargs= {"onupdate": func.now()})
    # add foreign key
    post_id: int = Field(foreign_key = "posts.post_id")
    # create relationship
    user: Mapped["User"] = Relationship(back_populates = "comments")
    post: Mapped["Post"] = Relationship(back_populates = "comments")
    
    

# rebuild models
User.model_rebuild()
Post.model_rebuild()
Comment.model_rebuild()    