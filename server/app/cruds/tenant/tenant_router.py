# import dependencies
from fastapi import APIRouter, Depends
from fastapi_limiter.depends import RateLimiter
from server.app.utility.platform.security import get_identifier
from app.schemas.tenant.tenant_router import TenantCreate
from app.models import User
from sqlmodel.ext.asyncio.session import AsyncSession
from server.app.utility.platform.database import get_db
from app.utility.platform.user import get_current_active_user
from app.services.tenant.tenant_router import create_team_service




# initialize router
router = APIRouter(tags=["tenants"])




# endpoint to create team workspace
@router.post(
    "/tenants",
    dependencies=[Depends(RateLimiter(times=2, minutes=10, identifier=get_identifier))]
)

async def create_team_workspace(
    data: TenantCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    tenant = await create_team_service(
        data=data,
        current_user=current_user,
        db=db,
    )

    return {
        "message": "Tenant created successfully",
        "tenant_id": tenant.tenant_id
    }