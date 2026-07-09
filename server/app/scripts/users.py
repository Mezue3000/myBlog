# import dependencies
import asyncio, os
from dotenv import load_dotenv
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from app.models import User, Role
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
            is_active=True
        )

        session.add(user)
        await session.commit()
        print("Superadmin created")
        
        
import asyncio
if __name__ == "__main__":
    asyncio.run(create_superadmin())
