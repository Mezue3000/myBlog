# import dependencies
import pytest
from sqlmodel import select
from app.models import Tenant, ApiProject, Plan
from app.utility.tenant.tenant_router import current_tenant_id, bypass_rls





@pytest.mark.asyncio
async def test_bypass_rls_allows_cross_tenant_access(db):
    
    # create plan
    default_plan = Plan(
        plan_id=1,
        name="Standard Plan",
        billing_interval="monthly",
        tenant_type="team",
        stripe_price_id="price_dummy_bypass",
        credits=100
    )

    db.add(default_plan)
    await db.flush()

    # create tenant A
    tenant_a = Tenant(
        name="Tenant A",
        type="team",
        plan_id=1,
        slug="tenant-a-bypass",
        credits_remaining=100
    )

    db.add(tenant_a)
    await db.flush()

    # create tenant B
    tenant_b = Tenant(
        name="Tenant B",
        type="team",
        plan_id=1,
        slug="tenant-b-bypass",
        credits_remaining=100
    )

    db.add(tenant_b)
    await db.flush()

    # create project for tenant A
    token = current_tenant_id.set(tenant_a.tenant_id)

    try:
        project_a = ApiProject(
            name="Tenant A Project",
            description="Tenant A project",
            environment="live"
        )

        db.add(project_a)
        await db.flush()

    finally:
        current_tenant_id.reset(token)

    # create project for tenant B
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

    # normal tenant A query
    # should only see tenant A's project
    token = current_tenant_id.set(tenant_a.tenant_id)

    try:
        statement = select(ApiProject)

        result = await db.exec(statement)
        projects = result.all()

        assert len(projects) == 1
        assert projects[0].tenant_id == tenant_a.tenant_id

    finally:
        current_tenant_id.reset(token)

    # privileged query with bypass_rls=True
    # should see both tenants' projects.
    tenant_token = current_tenant_id.set(tenant_a.tenant_id)
    bypass_token = bypass_rls.set(True)

    try:
        statement = select(ApiProject)

        result = await db.exec(statement)
        projects = result.all()

    finally:
        bypass_rls.reset(bypass_token)
        current_tenant_id.reset(tenant_token)

    assert len(projects) == 2

    project_tenant_ids = {
        project.tenant_id
        for project in projects
    }

    assert tenant_a.tenant_id in project_tenant_ids
    assert tenant_b.tenant_id in project_tenant_ids
    
    # Verify bypass_rls was properly reset.
    # Tenant A should again see only its own project.
    token = current_tenant_id.set(tenant_a.tenant_id)

    try:
        statement = select(ApiProject)

        result = await db.exec(statement)
        projects = result.all()

    finally:
        current_tenant_id.reset(token)

    assert len(projects) == 1
    assert projects[0].tenant_id == tenant_a.tenant_id
    assert projects[0].project_id == project_a.project_id
