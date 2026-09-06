# import dependencies
import pytest
from app.models import Tenant, ApiProject, Plan
from app.utility.tenant.tenant_router import current_tenant_id


@pytest.mark.asyncio
async def test_cross_tenant_update_is_blocked(db):
    
    # create plan
    default_plan = Plan(
        plan_id=1,
        name="Standard Plan",
        billing_interval="monthly",
        tenant_type="team",
        stripe_price_id="price_dummy_update",
        credits=100
    )

    db.add(default_plan)
    await db.flush()

    # create tenant A
    tenant_a = Tenant(
        name="Tenant A",
        type="team",
        plan_id=1,
        slug="tenant-a-update",
        credits_remaining=100
    )

    db.add(tenant_a)
    await db.flush()

    # create tenant B
    tenant_b = Tenant(
        name="Tenant B",
        type="team",
        plan_id=1,
        slug="tenant-b-update",
        credits_remaining=100
    )

    db.add(tenant_b)
    await db.flush()

    # create project belonging to tenant A
    token = current_tenant_id.set(tenant_a.tenant_id)

    try:
        project = ApiProject(
            name="Tenant A Project",
            description="Original Tenant A project",
            environment="live"
        )

        db.add(project)
        await db.flush()

    finally:
        current_tenant_id.reset(token)

    assert project.tenant_id == tenant_a.tenant_id

    # try to move tenant A project to tenant B
    # while operating in tenant A context
    token = current_tenant_id.set(tenant_a.tenant_id)

    try:
        project.tenant_id = tenant_b.tenant_id

        with pytest.raises(ValueError, match="tenant"):
            await db.flush()

    finally:
        current_tenant_id.reset(token)

    # roll back the failed transaction so the test session remains usable.
    await db.rollback()
