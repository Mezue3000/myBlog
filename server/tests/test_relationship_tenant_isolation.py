# import dependencies
import pytest
from sqlmodel import select
from sqlalchemy.orm import selectinload
from app.models import Tenant, ApiProject, Plan
from app.utility.tenant.tenant_router import current_tenant_id




@pytest.mark.asyncio
async def test_relationship_loading_is_tenant_isolated(db):
    
    # create plan
    default_plan = Plan(
        plan_id=1,
        name="Standard Plan",
        billing_interval="monthly",
        tenant_type="team",
        stripe_price_id="price_dummy_relationship",
        credits=100
    )

    db.add(default_plan)
    await db.flush()

    # create tenant A
    tenant_a = Tenant(
        name="Tenant A",
        type="team",
        plan_id=1,
        slug="tenant-a-relationship",
        credits_remaining=100
    )

    db.add(tenant_a)
    await db.flush()

    # create tenant B
    tenant_b = Tenant(
        name="Tenant B",
        type="team",
        plan_id=1,
        slug="tenant-b-relationship",
        credits_remaining=100
    )

    db.add(tenant_b)
    await db.flush()

    # create tenant A projects
    token = current_tenant_id.set(tenant_a.tenant_id)

    try:
        project_a1 = ApiProject(
            name="Tenant A Project 1",
            description="Tenant A project 1",
            environment="live"
        )

        project_a2 = ApiProject(
            name="Tenant A Project 2",
            description="Tenant A project 2",
            environment="live"
        )

        db.add(project_a1)
        db.add(project_a2)

        await db.flush()

    finally:
        current_tenant_id.reset(token)

    # create tenant B project
    token = current_tenant_id.set(tenant_b.tenant_id)

    try:
        project_b1 = ApiProject(
            name="Tenant B Project 1",
            description="Tenant B project",
            environment="live"
        )

        db.add(project_b1)

        await db.flush()

    finally:
        current_tenant_id.reset(token)

    await db.commit()

    # query tenant A with selectinload(Tenant.projects)
    token = current_tenant_id.set(tenant_a.tenant_id)

    try:
        statement = (
            select(Tenant)
            .where(Tenant.tenant_id == tenant_a.tenant_id)
            .options(
                selectinload(Tenant.projects)
            )
        )

        result = await db.exec(statement)

        loaded_tenant = result.one()

        # verify tenant A's relationship
        projects = loaded_tenant.projects

        assert len(projects) == 2

        project_ids = {
            project.project_id
            for project in projects
        }

        assert project_a1.project_id in project_ids
        assert project_a2.project_id in project_ids

        # most important assertion:
        # tenant B's project must not appear
        assert project_b1.project_id not in project_ids

        assert all(
            project.tenant_id == tenant_a.tenant_id
            for project in projects
        )

    finally:
        current_tenant_id.reset(token)
