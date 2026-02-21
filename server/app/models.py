# import dependencies
# from __future__ import annotations
from sqlmodel import SQLModel, Field, Relationship, func, Index
from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Mapped
import sqlalchemy as sa
from sqlalchemy import ForeignKey 




# create link table(m-m r/ship)
class RolePermission(SQLModel, table=True):
    __tablename__ = "role_permissions"

    role_id: int = Field(foreign_key="roles.role_id", primary_key=True)
    permission_id: int = Field(foreign_key="permissions.permission_id", primary_key=True)




# create role model
class Role(SQLModel, table=True):
    __tablename__ = "roles"

    role_id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True, max_length=50)

    # relationships
    users: List["User"] = Relationship(back_populates="role")
    permissions: List["Permission"] = Relationship(back_populates="roles", link_model=RolePermission)




# create permission model
class Permission(SQLModel, table=True):
    __tablename__ = "permissions"

    permission_id: Optional[int] = Field(default=None, primary_key=True)
    code: str = Field(index=True, unique=True, max_length=100)
    description: Optional[str] = Field(default=None, max_length=255)
    
    # relationships
    roles: List[Role] = Relationship(back_populates="permissions", link_model=RolePermission)




# create user model
class User(SQLModel, table=True):
    __tablename__ = "users"
    
    user_id: Optional[int] = Field(default=None, primary_key=True) 
    username: str = Field(max_length=55, nullable=False, unique=True, index=True)
    email: str = Field(max_length=75, nullable=False, unique=True, index=True)
    biography: str = Field(max_length=350, nullable=True)
    password_hash: str = Field(max_length=255, nullable=False)
    country: str = Field(max_length=25, nullable=False)
    city: str = Field(max_length=25, nullable=False)
    is_active: bool = Field(default=True, sa_column_kwargs={"server_default": sa.true()}, nullable=False)
    created_at: datetime = Field(
        default_factory=lambda:datetime.now(timezone.utc), 
        sa_column_kwargs={"server_default": func.now()},
        nullable=False
    )
    updated_at: datetime = Field(sa_column_kwargs={"onupdate":func.now()}, nullable=True)
    # add foreign key
    role_id: Optional[int] = Field(foreign_key="roles.role_id", index=True, nullable=False)
    # create relationship
    role: Optional[Role] = Relationship(back_populates="users")
    posts: Mapped[List["Post"]] = Relationship(back_populates="user")   
    



# create post model
class Post(SQLModel, table=True):
    __tablename__ = "posts"
    
    post_id: Optional[int] = Field(default_factory=None, primary_key=True)
    title: str = Field(max_length=125, nullable=False, index=True)
    content: str = Field(max_length=450, nullable=False)
    created_at: datetime = Field(
        default_factory=lambda:datetime.now(timezone.utc), 
        sa_column_kwargs={"server_default": func.now()},
        nullable=False
    )
    updated_at: datetime = Field(sa_column_kwargs={"onupdate":func.now()}, nullable=True)    
    # add foreign key with cascade and restrict 
    user_id: int = Field(
        sa_column=sa.Column(
            sa.Integer,
            ForeignKey("users.user_id", onupdate="CASCADE", ondelete="RESTRICT"),
            index=True,
            nullable=False
        ),
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
    created_at: datetime = Field(
        default_factory=lambda:datetime.now(timezone.utc), 
        sa_column_kwargs={"server_default": func.now()},
        nullable=False
    ) 
    # add foreign key
    post_id: int = Field(foreign_key="posts.post_id", index=True)
    # create relationship
    post: Mapped["Post"] = Relationship(back_populates="comments")
    
    
    
    
# fix forward reference
RolePermission.model_rebuild()
Role.model_rebuild()
Permission.model_rebuild()
User.model_rebuild()
Post.model_rebuild()
Comment.model_rebuild()