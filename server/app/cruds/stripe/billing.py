# import dependencies
from fastapi import APIRouter, Request, Depends
from app.utility.tenant.admin_router import require_owner 
from app.rate_limit.keys import tenant_key_func
from app.rate_limit.policy import TENANT_LIMITS
from app.rate_limit.limiter import limiter
from app.models import Tenant, User
from app.utility.tenant.tenant_router import get_current_tenant
from app.utility.platform.user import get_current_active_user
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.billings.service import create_checkout_session





# initialize router
router = APIRouter(prefix="/v1/billings", tags=["tenant_billings"])  



# endpoint to create checkout session
@router.post("/checkout/{plan_id}", dependencies=[Depends(require_owner)])

@limiter.limit(TENANT_LIMITS["create_session"], key_func=tenant_key_func)
async def create_checkout(
    request: Request,
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
