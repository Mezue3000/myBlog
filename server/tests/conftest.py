# import dependencies
import pytest_asyncio, os

# Inject dummy or test environment variables so imports don't fail during test collection
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("REDIS_PORT", "6379")
os.environ.setdefault("REDIS_PASSWORD", "mock_redis_password")
os.environ.setdefault("SECRET_KEY", "test_secret_key")

from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy import event, type_coerce, Uuid
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session, with_loader_criteria
from app.utility.tenant.tenant_router import current_tenant_id
from app.models import TenantScopedMixin
import sqlite3
from uuid import UUID

# import your models so SQLModel.metadata contains all tables.
from app.models import (
    Role,
    Permission,
    RolePermission,
    User,
    Tenant,
    TenantMembership,
    ApiProject,
    APIKey,
    APIUsageLog,
    AuditLog,
    Plan,
    Subscription,
    StripeCheckoutSession,
    CreditLog,
    WebhookEvent,
    BillingAudit
)



# test database
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    connect_args={
        "check_same_thread": False,
    },
    poolclass=StaticPool
)



# Tell SQLite how to adapt Python UUID to a string
sqlite3.register_adapter(UUID, lambda u: str(u))

# Tell SQLite how to convert a database string back to a Python UUID (if needed)
sqlite3.register_converter("GUID", lambda v: UUID(v.decode("utf-8")))
sqlite3.register_converter("VARCHAR", lambda v: UUID(v.decode("utf-8")) if len(v) == 36 else v) # Optional fallback



# enable sqllite foreign key
@event.listens_for(test_engine.sync_engine, "connect")
def enable_sqlite_foreign_keys(dbapi_connection, connection_record):
    """
    SQLite does not enforce foreign keys by default.
    Enable them for the test database.
    """

    cursor = dbapi_connection.cursor()

    cursor.execute("PRAGMA foreign_keys=ON")

    cursor.close()



# test session factory
TestSessionLocal = sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False
)



# database setup/tear-down
@pytest_asyncio.fixture(
    scope="session",
    autouse=True
)
async def setup_test_database():
    """
    Create all database tables before the test suite
    and drop them after the test suite finishes.
    """

    async with test_engine.begin() as conn:

        await conn.run_sync(SQLModel.metadata.create_all, checkfirst=True)

    yield

    async with test_engine.begin() as conn:

        await conn.run_sync(SQLModel.metadata.drop_all)

    await test_engine.dispose()



@event.listens_for(Session, "do_orm_execute")
def add_tenant_isolation_filter(execute_state):
    """
    Automatically apply tenant isolation filtering to all SELECT queries
    if a tenant ID is active in the context variable.
    """
    # Only intercept select statements (ignore inserts, updates, deletes)
    if execute_state.is_select and not execute_state.is_column_load:
        tenant_id = current_tenant_id.get()
        if tenant_id:
            # Apply the filter to any model inheriting from TenantScopedMixin
            execute_state.statement = execute_state.statement.options(
                with_loader_criteria(
                    TenantScopedMixin,
                    lambda cls: cls.tenant_id == type_coerce(tenant_id, Uuid()),
                    include_aliases=True,
                    track_closure_variables=False
                )
            )




# database session
@pytest_asyncio.fixture
async def db():
    """
    Provide a fresh AsyncSession to each test.
    """

    async with TestSessionLocal() as session:

        try:
            yield session

        finally:
            await session.rollback()
            await session.close()
