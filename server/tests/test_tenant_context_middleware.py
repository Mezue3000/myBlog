# import dependencies
from uuid import UUID, uuid4
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from app.utility.tenant.tenant_router import current_tenant_id
from app.cores.middleware import TenantContextMiddleware



# initialize fastapi
app = FastAPI()


app.add_middleware(TenantContextMiddleware)



@app.get("/test-tenant-context")
async def test_tenant_context():
    tenant_id = current_tenant_id.get()

    return {
        "tenant_id": str(tenant_id),
        "tenant_id_type": type(tenant_id).__name__
    }


@pytest.mark.asyncio
async def test_tenant_context_middleware_sets_and_resets_context():

    tenant_id = uuid4()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:

        response = await client.get(
            "/test-tenant-context",
            headers={
                "X-Tenant-ID": str(tenant_id)
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["tenant_id"] == str(tenant_id)
    assert data["tenant_id_type"] == "UUID"

    # middleware must reset contextvar
    assert current_tenant_id.get() is None
