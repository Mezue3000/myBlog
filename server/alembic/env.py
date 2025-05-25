# import dependencies
import sys
import os
import asyncio
from logging.config import fileConfig
from sqlalchemy.ext.asyncio import async_engine_from_config
from sqlalchemy.ext.asyncio import AsyncSession
from alembic import context
from dotenv import load_dotenv
from sqlmodel import SQLModel 


# make path easy to find
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))


#load environmental variable
load_dotenv("C:/Users/HP/Desktop/Python-Notes/blog_post/server/app/utility/.env")


# get Alembic config object
config = context.config


# get environmental variable
database_url = os.getenv("DATABASE_URL")
config.set_main_option("sqlalchemy.url", database_url)


# Alembic configuration
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


# Import your models
from app.models import User, Post, Comment 
target_metadata = SQLModel.metadata


async def run_migrations_online(): 
    """Run migrations asynchronously."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        future=True
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    if sys.platform.startswith("win"):   # for window users
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(run_migrations_online())

