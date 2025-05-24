# import dependencies
from sqlmodel import SQLModel
import asyncmy
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.models import User, Post, Comment
import os
from dotenv import load_dotenv
import asyncio


# load environment variable
load_dotenv()


# get database environment variable
database_url = os.getenv("DATABASE_URL")


# create asynchronous engine
async_engine = create_async_engine(database_url, echo=True)


# create async session factory
AsyncSessionLocal = async_sessionmaker(bind=async_engine, class_=AsyncSession, autoflush=False)


# function to get session
async def get_db():
    async with AsyncSessionLocal() as session:
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