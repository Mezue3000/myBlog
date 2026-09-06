# import dependencies
import pytest
from sqlmodel import select
from app.models import Tenant, ApiProject, Plan
from app.utility.tenant.tenant_router import current_tenant_id



@pytest.mark.asyncio
async def test_cross_tenant_insert_is_blocked(db):
    # populate plan table
    default_plan = Plan(
        plan_id=1,                    
        name="Standard Plan",
        billing_interval="monthly",    
        tenant_type="team",        
        stripe_price_id="price_dummy_123", 
        credits=100
    )
    
    db.add(default_plan)
    await db.flush()
    
    # create tenant A
    tenant_a = Tenant(
        name="Tenant A",
        type="team",
        plan_id=1,
        slug="tenant-a-cross",
        credits_remaining=100
    )

    db.add(tenant_a)
    await db.flush()

    # create tenant B
    tenant_b = Tenant(
        name="Tenant B",
        type="team",
        plan_id=1,
        slug="tenant-b-cross",
        credits_remaining=100
    )

    db.add(tenant_b)
    await db.flush()

    # tenant A is the active tenant
    token = current_tenant_id.set(tenant_a.tenant_id)

    try:
        # deliberately attempt to create a tenant B project
        # while tenant A is the active tenant
        project = ApiProject(
            name="Cross Tenant Project",
            description="Should not be allowed",
            environment="live",
            tenant_id=tenant_b.tenant_id
        )

        db.add(project)

        # the flush should fail if cross-tenant assignment
        # is correctly protected.
        with pytest.raises(ValueError, match="tenant"):
            await db.flush()

    finally:
        current_tenant_id.reset(token)

    await db.rollback()
