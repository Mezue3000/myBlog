import pytest
from fastapi import Request
from app.models import Tenant, User, Plan, Role
from app.utility.tenant.tenant_router import current_tenant_id, get_current_tenant




@pytest.mark.asyncio
async def test_get_current_tenant_active_tenant_sets_context(db):

    # Create plan
    default_plan = Plan(
        plan_id=1,
        name="Personal Plan",
        billing_interval="monthly",
        tenant_type="personal",
        stripe_price_id="price_dummy_123",
        credits=100
    )

    db.add(default_plan)
    await db.flush()

    # create role
    role = Role(
        role_id=1,
        name="user"
    )

    db.add(role)
    await db.flush()

    # Create personal tenant
    tenant = Tenant(
        name="Personal Tenant",
        type="personal",
        owner_id=None,
        plan_id=1,
        slug="personal-tenant",
        credits_remaining=100
    )

    db.add(tenant)
    await db.flush()

    # create user
    user = User(
        username="testuser",
        email="test@example.com",
        password_hash="dummy_hash",
        role_id=1,
        active_tenant_id=tenant.tenant_id
    )

    db.add(user)
    await db.flush()

    # establish tenant ownership now that user_id exists
    tenant.owner_id = user.user_id

    await db.flush()
  
    # make sure the test starts without an ORM tenant context
    assert current_tenant_id.get() is None

    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/test",
        "headers": []
    })

    # no X-Tenant-ID header.
    resolved_tenant = await get_current_tenant(
        request=request,
        current_user=user,
        db=db,
        x_tenant_id=None
    )

    # get_current_tenant() should resolve the user's active tenant
    assert resolved_tenant.tenant_id == tenant.tenant_id

    # this is the important assertion.
    assert current_tenant_id.get() == tenant.tenant_id
    
    current_tenant_id.set(None)

    assert current_tenant_id.get() is None