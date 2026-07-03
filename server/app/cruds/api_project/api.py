# import dependecies
from fastapi import APIRouter, Depends, HTTPException, status, Request
from app.rate_limit.limiter import limiter
from app.rate_limit.policy import API_LIMITS
from app.rate_limit.keys import tenant_key_func
from app.schemas.api_project.api import ApiProjectCreate, ApiKeyCreate, ApiKeyRead, APIUsageLogRead
from app.utility.tenant.tenant_router import get_current_tenant
from app.models import Tenant, ApiProject, TenantMembership
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.services.api_project.api import create_headless_api_service, create_service_key, revoke_service_api_key, get_tenant_api_keys, get_tenant_usage_logs
from app.utility.api_project.api import get_project_by_tenant, get_current_project
from app.utility.tenant.admin_router import require_admin
from uuid import UUID
from typing import Optional





# initialize router
router = APIRouter(prefix="/api/v1",  tags=["headless_api"])



# endpoint to create api-project
@router.post("/projects")
   
@limiter.limit(API_LIMITS["create_project"], key_func=tenant_key_func)
async def create_api_project(
    request: Request,
    data: ApiProjectCreate,
    current_tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    try:
        project = await create_headless_api_service(
            request=request,
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

@limiter.limit(API_LIMITS["generate_key"], key_func=tenant_key_func)
async def generate_project_api_key(
    request: Request,
    data: ApiKeyCreate,
    project: ApiProject = Depends(get_current_project),
    db: AsyncSession = Depends(get_db)
):
    api_key, raw_key = await create_service_key(
        request=request,
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





# endpoint to list tenant api-keys
@router.get("/keys", response_model=list[ApiKeyRead])

@limiter.limit(API_LIMITS["list_key"], key_func=tenant_key_func)
async def list_tenant_api_keys(
    request: Request,
    project_id: Optional[int] = None,
    current_tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    return await get_tenant_api_keys(
        request=request,
        db=db,
        tenant_id=current_tenant.tenant_id,
        project_id=project_id
    )





# endpoint to list tenant usuge log
@router.get("/usage-logs", response_model=list[APIUsageLogRead])

@limiter.limit(API_LIMITS["usage_logs"], key_func=tenant_key_func)
async def list_tenant_usage_logs(
    request: Request,
    project_id: Optional[int] = None, 
    api_key_id: Optional[UUID] = None,
    offset: int = 0,
    limit: int = 50,
    current_tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    return await get_tenant_usage_logs(
        request=request,
        db=db,
        tenant_id=current_tenant.tenant_id,
        project_id=project_id,
        api_key_id=api_key_id,
        offset=offset,
        limit=limit
    )





# endpoint to revoke tenant api-key
@router.post("/keys/{api_key_id}/revoke", status_code=status.HTTP_200_OK)

@limiter.limit(API_LIMITS["revoke_key"], key_func=tenant_key_func) 
async def revoke_project_api_key(
    request: Request,
    api_key_id: int,
    current_tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    try:
        api_key = await revoke_service_api_key(
            request=request,
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
