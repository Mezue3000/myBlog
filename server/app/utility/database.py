# import dependencies
from sqlmodel import SQLModel
import asyncmy
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv
import os
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from app.models import User, Post, Comment
import asyncio  
 



# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/.env")



# get environ key
key = os.getenv("SPIRIT_KEY").encode()
fernet = Fernet(key)



# get database environment variable
encrypted_database_url = os.getenv("ENCRYPTED_DATABASE_KEY")
decrypted_database_url = fernet.decrypt(encrypted_database_url).decode()


# create asynchronous engine
async_engine = create_async_engine(decrypted_database_url, echo=True)



# SQLModel async session
async_session = sessionmaker(bind=async_engine, class_=AsyncSession, expire_on_commit=False)



# function to get session
async def get_db():
    async with async_session() as session:
        yield session
        



# function to create table
async def create_table():
    async with async_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    await async_engine.dispose() 
    



# run async function
def main():
    asyncio.run(create_table())
    
    
    
if __name__ == "__main__":
    main()