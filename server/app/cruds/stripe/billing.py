# import dependencies
from fastapi import APIRouter, Depends
from app.models import Tenant, User
from app.utility.tenant.tenant_router import get_current_tenant
from app.utility.platform.user import get_current_active_user
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.billings.service import create_checkout_session





# initialize router
router = APIRouter(prefix="/v1/billings", tags=["tenant_billings"])  



# endpoint to create checkout session
@router.post("/checkout/{plan_id}")


async def create_checkout(
    plan_id: int,
    current_tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    return await create_checkout_session(
        tenant=current_tenant,
        current_user=current_user,
        plan_id=plan_id,
        db=db
    )
