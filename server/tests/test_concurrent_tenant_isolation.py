# import dependencies
import asyncio, pytest
from sqlmodel import select
from app.models import Tenant, ApiProject, Plan
from app.utility.tenant.tenant_router import current_tenant_id
from tests.conftest import TestSessionLocal


async def query_projects_for_tenant(tenant_id):
    """
    Simulate one request running under a specific tenant context.
    Each concurrent task gets its own AsyncSession.
    """

    token = current_tenant_id.set(tenant_id)

    try:
        # force task switching so the two requests can interleave.
        await asyncio.sleep(0)

        async with TestSessionLocal() as session:
            statement = select(ApiProject)

            result = await session.exec(statement)
            projects = result.all()

            # force another task switch while the query result
            # is being processed.
            await asyncio.sleep(0)

            return projects

    finally:
        current_tenant_id.reset(token)


@pytest.mark.asyncio
async def test_concurrent_tasks_are_tenant_isolated(db):

    # create shared test data
    default_plan = Plan(
        plan_id=1,
        name="Standard Plan",
        billing_interval="monthly",
        tenant_type="team",
        stripe_price_id="price_dummy_concurrent",
        credits=100
    )

    db.add(default_plan)
    await db.flush()

    tenant_a = Tenant(
        name="Tenant A",
        type="team",
        plan_id=1,
        slug="tenant-a-concurrent",
        credits_remaining=100
    )

    tenant_b = Tenant(
        name="Tenant B",
        type="team",
        plan_id=1,
        slug="tenant-b-concurrent",
        credits_remaining=100
    )

    db.add(tenant_a)
    db.add(tenant_b)

    await db.flush()

    # create tenant A project
    token = current_tenant_id.set(tenant_a.tenant_id)

    try:
        project_a = ApiProject(
            name="Tenant A Concurrent Project",
            description="Tenant A project",
            environment="live"
        )

        db.add(project_a)
        await db.flush()

    finally:
        current_tenant_id.reset(token)

    # create tenant B project
    token = current_tenant_id.set(tenant_b.tenant_id)

    try:
        project_b = ApiProject(
            name="Tenant B Concurrent Project",
            description="Tenant B project",
            environment="live"
        )

        db.add(project_b)
        await db.flush()

    finally:
        current_tenant_id.reset(token)

    await db.commit()

    # run tenant A and tenant B requests concurrently
    projects_a, projects_b = await asyncio.gather(
        query_projects_for_tenant(tenant_a.tenant_id),
        query_projects_for_tenant(tenant_b.tenant_id),
    )

    # verify tenant A only sees tenant A
    assert len(projects_a) == 1

    assert projects_a[0].project_id == project_a.project_id
    assert projects_a[0].tenant_id == tenant_a.tenant_id

    assert all(
        project.tenant_id == tenant_a.tenant_id
        for project in projects_a
    )

    # verify tenant B only sees tenant B
    assert len(projects_b) == 1

    assert projects_b[0].project_id == project_b.project_id
    assert projects_b[0].tenant_id == tenant_b.tenant_id

    assert all(
        project.tenant_id == tenant_b.tenant_id
        for project in projects_b
    )


    # verify the two tasks did not leak into each other
    assert projects_a[0].tenant_id != projects_b[0].tenant_id

    # parent context must still be clean
    assert current_tenant_id.get() is None