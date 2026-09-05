# import dependencies
import pytest
from sqlmodel import select
from app.models import Tenant, ApiProject, Plan
from sqlalchemy.orm import session
from app.utility.tenant.tenant_router import current_tenant_id


@pytest.mark.asyncio
async def test_tenant_isolation(
    db
):
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
        slug="tenant-a",
        credits_remaining=100
    )

    db.add(tenant_a)
    await db.flush()


    # create tenant B
    tenant_b = Tenant(
        name="Tenant B",
        type="team",
        plan_id=1,
        slug="tenant-b",
        credits_remaining=100
    )

    db.add(tenant_b)
    await db.flush()

    # create projects for tenant A
    token = current_tenant_id.set(tenant_a.tenant_id)

    try:
        project_a1 = ApiProject(
            name="Project A1",
            description="Tenant A project",
            environment="live"
        )



        project_a2 = ApiProject(
            name="Project A2",
            description="Tenant A second project",
            environment="test"
        )

        db.add(project_a1)
        db.add(project_a2)

        await db.flush()

    finally:
        current_tenant_id.reset(token)

    # create project for tenant B
    token = current_tenant_id.set(tenant_b.tenant_id)

    try:
        project_b1 = ApiProject(
            name="Project B1",
            description="Tenant B project",
            environment="live"
        )

        db.add(project_b1)

        await db.flush()

    finally:
        current_tenant_id.reset(token)

    # verify tenant IDs were automatically assigned
    assert project_a1.tenant_id == tenant_a.tenant_id
    assert project_a2.tenant_id == tenant_a.tenant_id
    assert project_b1.tenant_id == tenant_b.tenant_id


    # tenant A should see ONLY Tenant A projects
    token = current_tenant_id.set(tenant_a.tenant_id)

    try:
        statement = select(ApiProject)

        result = await db.exec(statement)

        projects = result.all()

    finally:
        current_tenant_id.reset(token)

    assert len(projects) == 2

    project_ids = {
        project.project_id
        for project in projects
    }

    assert project_a1.project_id in project_ids
    assert project_a2.project_id in project_ids

    assert project_b1.project_id not in project_ids

    assert all(
        project.tenant_id == tenant_a.tenant_id
        for project in projects
    )


    # tenant B should see ONLY tenant B projects
    token = current_tenant_id.set(tenant_b.tenant_id)

    try:
        statement = select(ApiProject)

        result = await db.exec(statement)

        projects = result.all()

    finally:
        current_tenant_id.reset(token)

    assert len(projects) == 1

    assert projects[0].project_id == project_b1.project_id
    assert projects[0].tenant_id == tenant_b.tenant_id

    # tenant A projects must not be visible.
    assert projects[0].project_id != project_a1.project_id
    assert projects[0].project_id != project_a2.project_id
