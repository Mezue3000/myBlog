import asyncio, pytest
from uuid import uuid4
from app.utility.tenant.tenant_router import current_tenant_id, bypass_rls





async def read_tenant_context(expected_tenant_id, expected_bypass):
    # force task switching so the two tasks interleave
    await asyncio.sleep(0)

    assert current_tenant_id.get() == expected_tenant_id
    assert bypass_rls.get() == expected_bypass

    await asyncio.sleep(0)

    return (
        current_tenant_id.get(),
        bypass_rls.get()
    )


@pytest.mark.asyncio
async def test_contextvars_are_isolated_between_async_tasks():
    tenant_a = uuid4()
    tenant_b = uuid4()

    # create task A while tenant A context is active
    tenant_a_token = current_tenant_id.set(tenant_a)
    bypass_a_token = bypass_rls.set(False)

    try:
        task_a = asyncio.create_task(
            read_tenant_context(
                tenant_a,
                False
            )
        )
    finally:
        bypass_rls.reset(bypass_a_token)
        current_tenant_id.reset(tenant_a_token)

    # create task B while tenant B context is active
    tenant_b_token = current_tenant_id.set(tenant_b)
    bypass_b_token = bypass_rls.set(True)

    try:
        task_b = asyncio.create_task(
            read_tenant_context(
                tenant_b,
                True
            )
        )
    finally:
        bypass_rls.reset(bypass_b_token)
        current_tenant_id.reset(tenant_b_token)

    result_a, result_b = await asyncio.gather(
        task_a,
        task_b
    )

    # each task must retain its own context
    assert result_a == (tenant_a, False)
    assert result_b == (tenant_b, True)

    # parent context must remain clean after the tasks finish
    assert current_tenant_id.get() is None
    assert bypass_rls.get() is False
