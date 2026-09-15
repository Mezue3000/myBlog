# import dependencies
import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from app.models import Tenant, User, Plan, Role
from app.utility.platform.database import get_db
from app.cores.middleware import TenantContextMiddleware
from app.utility.tenant.tenant_router import current_tenant_id, get_current_tenant
from app.utility.platform.user import get_current_active_user







@pytest.mark.asyncio
async def test_tenant_context_lifecycle(
    db,
):
    # ---------------------------------------------------------
    # Create plan
    # ---------------------------------------------------------
    plan = Plan(
        plan_id=1,
        name="Personal Plan",
        billing_interval="monthly",
        tenant_type="personal",
        stripe_price_id="price_dummy_123",
        credits=100
    )

    db.add(plan)
    await db.flush()

    # ---------------------------------------------------------
    # Create role
    # ---------------------------------------------------------
    role = Role(
        role_id=1,
        name="user"
    )

    db.add(role)
    await db.flush()

    # ---------------------------------------------------------
    # Create tenant
    # ---------------------------------------------------------
    tenant = Tenant(
        name="Lifecycle Tenant",
        type="personal",
        plan_id=1,
        slug="lifecycle-tenant",
        credits_remaining=100
    )

    db.add(tenant)
    await db.flush()

    # ---------------------------------------------------------
    # Create user
    # ---------------------------------------------------------
    user = User(
        username="lifecycle_user",
        email="lifecycle@example.com",
        password_hash="dummy_hash",
        role_id=1,
        active_tenant_id=tenant.tenant_id
    )

    db.add(user)
    await db.flush()

    # Set tenant owner after user_id exists.
    tenant.owner_id = user.user_id

    await db.flush()

    # ---------------------------------------------------------
    # Make sure the parent test context is clean
    # ---------------------------------------------------------
    assert current_tenant_id.get() is None

    # ---------------------------------------------------------
    # Create a small FastAPI application
    # ---------------------------------------------------------
    app = FastAPI()

    # Real production middleware.
    app.add_middleware(TenantContextMiddleware)
    
    async def override_get_db():
        yield db
        
    app.dependency_overrides[get_db] = override_get_db
    
    # Override authentication for this test.
    async def override_current_active_user():
        return user

    app.dependency_overrides[
        get_current_active_user
    ] = override_current_active_user

    # ---------------------------------------------------------
    # Endpoint using the REAL get_current_tenant dependency
    # ---------------------------------------------------------
    @app.get("/tenant")
    async def tenant_endpoint(
        current_tenant: Tenant = Depends(get_current_tenant),
    ):
        context_tenant_id = current_tenant_id.get()

        return {
            "tenant_id": str(current_tenant.tenant_id),
            "context_tenant_id": str(context_tenant_id),
        }

    # ---------------------------------------------------------
    # Make request WITHOUT X-Tenant-ID
    # ---------------------------------------------------------
    with TestClient(app) as client:
        response = client.get("/tenant")

    # ---------------------------------------------------------
    # HTTP response
    # ---------------------------------------------------------
    assert response.status_code == 200

    data = response.json()

    assert data["tenant_id"] == str(tenant.tenant_id)

    assert data["context_tenant_id"] == str(
        tenant.tenant_id
    )

    # ---------------------------------------------------------
    # Middleware must clean up the ContextVar
    # ---------------------------------------------------------
    assert current_tenant_id.get() is None