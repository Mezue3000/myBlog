# import dependencies
import asyncio
from dotenv import load_dotenv
import os
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from server.app.models import User, Role, Permission, RolePermission




# define roles and Permissions
ROLES = ["superadmin", "admin", "moderator", "user"]

PERMISSIONS = {
    "admin": [
        "admin:access",
        "user:ban",
        "user:delete",
        "role:assign",
    ],
    "post": [
        "post:create",
        "post:update",
        "post:delete",
        "post:publish",
    ],
    "comment": [
        "comment:create",
        "comment:delete",
        "comment:moderate",
    ],
}




# map roles with permissions
ROLE_PERMISSION_MAP = {
    "superadmin": [
        "*",  # wildcard (handled manually)
    ],
    "admin": [
        "admin:access",
        "user:ban",
        "user:delete",
        "role:assign",
        "post:create",
        "post:update",
        "post:delete",
        "comment:moderate",
    ],
    "moderator": [
        "comment:moderate",
        "comment:delete",
    ],
    "user": [
        "post:create",
        "comment:create",
    ],
}




# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/.env")



DATABASE_URL = os.getenv("DATABASE_URL") 



# create asynchronous engine  
async_engine = create_async_engine(DATABASE_URL, echo=True)



# function to seed values into roles and permission tables
async def seed_rbac():
    async with AsyncSession(async_engine) as session:
        print("Starting RBAC seeding...")

        # ----------------------
        # 1. Create roles
        # ----------------------
        roles = {}

        for role_name in ROLES:
            result = await session.exec(
                select(Role).where(Role.name == role_name)
            )
            role = result.first()

            if not role:
                role = Role(name=role_name)
                session.add(role)
                await session.flush()

            roles[role_name] = role

        # ----------------------
        # 2. Create permissions
        # ----------------------
        permissions = {}

        for group in PERMISSIONS.values():
            for code in group:
                result = await session.exec(
                    select(Permission).where(Permission.code == code)
                )
                perm = result.first()

                if not perm:
                    perm = Permission(
                        code=code,
                        description=code.replace(":", " ").title(),
                    )
                    session.add(perm)
                    await session.flush()

                permissions[code] = perm

        # ----------------------
        # 3. Assign permissions
        # ----------------------
        for role_name, perm_codes in ROLE_PERMISSION_MAP.items():
            role = roles[role_name]

            if "*" in perm_codes:
                for perm in permissions.values():  
                    session.add(
                        RolePermission(
                            role_id=role.role_id,
                            permission_id=perm.permission_id,
                        )
                    )
                    
                continue

            for code in perm_codes:
                perm = permissions.get(code)
                if not perm:
                    continue

                result = await session.exec(
                    select(RolePermission).where(
                        RolePermission.role_id == role.role_id,
                        RolePermission.permission_id == perm.permission_id,
                    )
                )

                if not result.first():
                    session.add(
                        RolePermission(
                            role_id=role.role_id,
                            permission_id=perm.permission_id,
                        )
                    )

        await session.commit()
        print("RBAC seed completed successfully")

if __name__ == "__main__":
    asyncio.run(seed_rbac())
    
    
    
# this two script functions above and below should be ran seperately



# import dependencies
import asyncio
from dotenv import load_dotenv
import os
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from server.app.models import User, Role
from pwdlib import PasswordHash




# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/.env")



DATABASE_URL = os.getenv("DATABASE_URL") 



# create asynchronous engine  
async_engine = create_async_engine(DATABASE_URL, echo=True)



# initialize hash function
password_hash = PasswordHash.recommended()


# function to hash password
async def hash_password(password: str) -> str:
    return await asyncio.to_thread(password_hash.hash, password)




# function to seed superadmin into users table
async def create_superadmin():
    async with AsyncSession(async_engine) as session:
        role = (await session.exec(select(Role).where(Role.name == "superadmin"))).first()

        if not role:
            raise RuntimeError("Superadmin role not found")

        exists = (await session.exec(select(User).where(User.email == "admin@example.com"))).first()

        if exists:
            print("Superadmin already exists")
            return
        
        # hash the password
        hashed_pwd = await hash_password("Secure-Password@99")
        
        user = User(
            username="superadmin",
            email="admin@example.com",
            password_hash=hashed_pwd,
            country="nigeria",
            city="enugu",
            role_id=role.role_id,
            is_active=True,
        )

        session.add(user)
        await session.commit()
        print("Superadmin created")
        
        
import asyncio
if __name__ == "__main__":
    asyncio.run(create_superadmin())