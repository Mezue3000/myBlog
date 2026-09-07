# import dependencies
import pytest
from sqlmodel import select
from sqlalchemy.orm import selectinload
from app.models import Tenant, ApiProject, Plan
from app.utility.tenant.tenant_router import current_tenant_id





@pytest.mark.asyncio
async def test_project_tenant_relationship_is_tenant_isolated(db):
    
    # create plan
    default_plan = Plan(
        plan_id=1,
        name="Standard Plan",
        billing_interval="monthly",
        tenant_type="team",
        stripe_price_id="price_dummy_project_tenant",
        credits=100
    )

    db.add(default_plan)
    await db.flush()

    # create tenant A
    tenant_a = Tenant(
        name="Tenant A",
        type="team",
        plan_id=1,
        slug="tenant-a-project-tenant",
        credits_remaining=100
    )

    db.add(tenant_a)
    await db.flush()

    # create tenant B
    tenant_b = Tenant(
        name="Tenant B",
        type="team",
        plan_id=1,
        slug="tenant-b-project-tenant",
        credits_remaining=100
    )

    db.add(tenant_b)
    await db.flush()

    # create project A
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

    # create project B
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

    await db.commit()

    # query project A and eagerly load its tenant
    token = current_tenant_id.set(tenant_a.tenant_id)

    try:
        statement = (
            select(ApiProject)
            .where(ApiProject.project_id == project_a.project_id)
            .options(
                selectinload(ApiProject.tenant)
            )
        )

        result = await db.exec(statement)

        loaded_project = result.one()

        # verify project A belongs to tenant A
        assert loaded_project.project_id == project_a.project_id
        assert loaded_project.tenant_id == tenant_a.tenant_id

        # verify relationship resolves to tenant A
        assert loaded_project.tenant is not None
        assert loaded_project.tenant.tenant_id == tenant_a.tenant_id
        assert loaded_project.tenant.name == "Tenant A"

        # verify tenant B is NOT accidentally loaded
        assert loaded_project.tenant.tenant_id != tenant_b.tenant_id

    finally:
        current_tenant_id.reset(token)