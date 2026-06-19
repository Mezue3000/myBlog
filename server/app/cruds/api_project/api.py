# import dependecies
from fastapi import APIRouter, Depends, HTTPException, status
from app.schemas.api_project.api import ApiProjectCreate, ApiKeyCreate
from app.utility.tenant.tenant_router import get_current_tenant
from app.models import Tenant, ApiProject, TenantMembership
from sqlalchemy.ext.asyncio import AsyncSession
from app.utility.platform.database import get_db
from app.services.api_project.api import create_service_project, create_service_key, revoke_service_api_key
from app.utility.api_project.api import get_project_by_tenant, get_current_project
from app.utility.tenant.admin_router import require_admin





# initialize router
router = APIRouter(prefix="/api/v1",  tags=["headless_api"])



# endpoint to create api-project
@router.post("/projects")
async def create_api_project(
    data: ApiProjectCreate,
    current_tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    try:
        project = await create_service_project(
            db=db,
            tenant=current_tenant,
            data=data
        )

        await db.commit()
        await db.refresh(project)

        return {
            "message": "Project created",
            "project_id": project.project_id,
            "name": project.name
        }

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create project"
        )
        
        
        
        
        
# endpoint to create api-key
@router.post("/projects/{project_id}/keys")
async def generate_project_api_key(
    data: ApiKeyCreate,
    project: ApiProject = Depends(get_current_project),
    _: TenantMembership = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    api_key, raw_key = await create_service_key(
        db=db,
        project=project,
        data=data
    )

    await db.commit()
    await db.refresh(api_key)

    return {
        "message": "Copy this key now. It will never be shown again.",
        "api_key": raw_key,
        "key_id": api_key.api_key_id
    }





# endpoint to revoke key
@router.post(
    "/keys/{api_key_id}/revoke",
    status_code=status.HTTP_200_OK,
)
async def revoke_project_api_key(
    api_key_id: int,
    current_tenant: Tenant = Depends(get_current_tenant),
    _: TenantMembership = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    try:
        api_key = await revoke_service_api_key(
            db=db,
            tenant_id=current_tenant.tenant_id,
            api_key_id=api_key_id
        )

        await db.commit()
        await db.refresh(api_key)

        return {
            "message": "API key revoked successfully",
            "api_key_id": api_key.api_key_id
        }

    except HTTPException:
        raise

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke API key"
        )