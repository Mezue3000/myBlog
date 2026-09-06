# import dependencies
import pytest
from app.models import Tenant, ApiProject, Plan
from app.utility.tenant.tenant_router import current_tenant_id


@pytest.mark.asyncio
async def test_cross_tenant_delete_is_blocked(db):
    
    # create plan
    default_plan = Plan(
        plan_id=1,
        name="Standard Plan",
        billing_interval="monthly",
        tenant_type="team",
        stripe_price_id="price_dummy_delete",
        credits=100
    )

    db.add(default_plan)
    await db.flush()

    # create tenant A
    tenant_a = Tenant(
        name="Tenant A",
        type="team",
        plan_id=1,
        slug="tenant-a-delete",
        credits_remaining=100
    )

    db.add(tenant_a)
    await db.flush()

    # create tenant B
    tenant_b = Tenant(
        name="Tenant B",
        type="team",
        plan_id=1,
        slug="tenant-b-delete",
        credits_remaining=100
    )

    db.add(tenant_b)
    await db.flush()
    
    # create project belonging to tenant B
    token = current_tenant_id.set(tenant_b.tenant_id)

    try:
        project_b = ApiProject(
            name="Tenant B Project",
            description="Tenant B project",
            environment="live"
        )

        db.add(project_b)
        await db.flush()

    finally:
        current_tenant_id.reset(token)

    assert project_b.tenant_id == tenant_b.tenant_id

    # tenant A attempts to delete tenant B's project
    token = current_tenant_id.set(tenant_a.tenant_id)

    try:
        
        await db.delete(project_b)

        with pytest.raises(ValueError, match="tenant"):
            await db.flush()

    finally:
        current_tenant_id.reset(token)

    # roll back the failed transaction so the session remains usable.
    await db.rollback()
