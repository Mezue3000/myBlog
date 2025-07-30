# import dependencies
# from __future__ import annotations
from sqlmodel import SQLModel, Field, Relationship, func, Index
from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Mapped
import sqlalchemy as sa
from sqlalchemy import ForeignKey 





# create user model
class User(SQLModel, table=True):
    __tablename__ = "users"
    
    user_id: Optional[int] = Field(default=None, primary_key=True) 
    first_name: str = Field(max_length=25, nullable=False)
    last_name: str = Field(max_length=25, nullable=False)
    username: str = Field(max_length=75, nullable=False, unique=True, index=True)
    email: str = Field(max_length=75, nullable=False, unique=True)
    biography: str = Field(max_length=350, nullable=True)
    password_hash: str = Field(max_length=255, nullable=False)
    country: str = Field(max_length=25, nullable=False)
    city: str = Field(max_length=25, nullable=False)
    created_at: datetime = Field(default_factory=lambda:datetime.now(timezone.utc), nullable=False)
    updated_at: datetime = Field(sa_column_kwargs={"onupdate":func.now()}, nullable=True)
    # create relationship
    posts: Mapped[List["Post"]] = Relationship(back_populates="user")
    comments: Mapped[List["Comment"]] = Relationship(back_populates="user")    
    




# create post model
class Post(SQLModel, table=True):
    __tablename__ = "posts"
    
    post_id: Optional[int] = Field(default_factory=None, primary_key=True)
    title: str = Field(max_length=125, nullable=False, index=True)
    content: str = Field(max_length=450, nullable=False)
    created_at: datetime = Field(default_factory=lambda:datetime.now(timezone.utc), nullable=False)
    updated_at: datetime = Field(sa_column_kwargs={"onupdate":func.now()}, nullable=True)    
    # add foreign key with cascade and restrict 
    user_id: int = Field(
        sa_column=sa.Column(
            sa.Integer,
            ForeignKey("users.user_id", onupdate="CASCADE", ondelete="RESTRICT"),
            nullable=False
        )
    )  
    # create relationship
    user: Mapped["User"] = Relationship(back_populates = "posts")
    comments: Mapped[List["Comment"]] = Relationship(back_populates="post")
    
    # add fulltext index on title and comment columns 
    __table_args__ = (
        Index('post_title_idx', 'title', 'content', mysql_prefix='FULLTEXT'),
        ) 
    




# create comment model
class Comment(SQLModel, table=True):
    __tablename__ = "comments"
    
    comment_id: Optional[int] = Field(default_factory=None, primary_key=True)
    content: str = Field(max_length=225, index=True, nullable=False)
    created_at: datetime = Field(default_factory=lambda:datetime.now(timezone.utc), nullable=False) 
    # add foreign key
    post_id: int = Field(foreign_key="posts.post_id")
    user_id: int = Field(foreign_key="users.user_id")
    # create relationship
    user: Mapped["User"] = Relationship(back_populates="comments")
    post: Mapped["Post"] = Relationship(back_populates="comments")
    
    
    
    
# resolve forward reference
User.model_rebuild()
Post.model_rebuild()
Comment.model_rebuild()     