# import dependencies
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi_limiter.depends import RateLimiter
from app.utility.platform.security import get_identifier
from app.schemas.tenant.tenant_router import TenantCreate, TenantRead, TenantBrandingRead, TenantBrandingUpdate
from app.models import User, Tenant, TenantMembership
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.utility.platform.user import get_current_active_user
from app.services.tenant.tenant_router import create_team_service, get_tenants_service, switch_tenant_service, update_service_branding
from app.services.tenant.admin_router import get_current_tenant, delete_tenant_service
from uuid import UUID
from app.utility.tenant.admin_router import require_owner 




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
        db=db
    )

    return {
        "message": "Tenant created successfully",
        "tenant_id": str(tenant.tenant_id)
    }
    
    
    
    
    
# endpoint to list all user team space
@router.get(
    "/tenants",
    response_model=list[TenantRead],
)
async def list_all_user_tenants(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return await get_tenants_service(
        current_user=current_user,
        db=db
    )
    
    
    
    
    
# create switch-tenant endpoint
@router.post("/tenants/{tenant_id}/switch")
async def switch_tenant(
    tenant_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    return await switch_tenant_service(
        tenant_id=tenant_id,
        current_user=current_user,
        db=db
    )





# endpoint to update tenant brand
@router.patch(
    "/tenant/branding",
    response_model=TenantBrandingRead
)
async def update_tenant_brand(
    data: TenantBrandingUpdate,
    current_tenant: Tenant = Depends(get_current_tenant),
    _: TenantMembership = Depends(require_owner),
    db: AsyncSession = Depends(get_db)
):
    try:
        tenant = await update_service_branding(
            db=db,
            tenant=current_tenant,
            data=data
        )

        await db.commit()
        await db.refresh(tenant)

        return tenant

    except Exception:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update tenant branding"
        )





# endpoint to soft-delete tenant
@router.delete("/tenants")
async def delete_tenant(
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_active_user),
    _: TenantMembership = Depends(require_owner),
    db: AsyncSession = Depends(get_db)
):
    return await delete_tenant_service(
        tenant=tenant,
        current_user=current_user,
        db=db
    )
    