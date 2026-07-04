# import dependecies
from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from app.rate_limit.limiter import limiter
from app.rate_limit.policy import API_LIMITS
from app.rate_limit.keys import tenant_key_func
from app.schemas.api_project.api import ApiProjectCreate, ApiKeyCreate, ApiKeyRead, APIUsageLogRead, RevokeApiKeyRequest
from app.schemas.platform.users import MessageResponse
from app.utility.tenant.tenant_router import get_current_tenant
from app.models import Tenant, ApiProject, TenantMembership, User
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.services.api_project.api import create_headless_api_service, create_service_key, revoke_service_api_key, get_tenant_api_keys, get_tenant_usage_logs, request_revoke_api_key_otp
from app.utility.api_project.api import get_project_by_tenant, get_current_project
from app.utility.tenant.admin_router import require_admin
from uuid import UUID
from typing import Optional
from app.utility.platform.user import get_current_active_user





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
        db=db,
        tenant_id=current_tenant.tenant_id,
        project_id=project_id,
        api_key_id=api_key_id,
        offset=offset,
        limit=limit
    )





# endpoint for OTP request api-key
@router.post(
    "/keys/{api_key_id}/revoke/request",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponse
)

@limiter.limit(API_LIMITS["revoke_key"], key_func=tenant_key_func)
async def request_revoke_api_key_otp_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    api_key_id: UUID,
    current_user: User = Depends(get_current_active_user),
    current_tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    return await request_revoke_api_key_otp(
        background_tasks=background_tasks,
        current_user=current_user,
        tenant_id=current_tenant.tenant_id,
        api_key_id=api_key_id,
        db=db
    )





# confirm revoke api-key endpoint
@router.patch("/keys/{api_key_id}/revoke", status_code=status.HTTP_200_OK)

@limiter.limit(API_LIMITS["revoke_key"], key_func=tenant_key_func)
async def revoke_project_api_key(
    request: Request,
    api_key_id: UUID,
    data: RevokeApiKeyRequest,
    current_user: User = Depends(get_current_active_user),
    current_tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    try:
        api_key = await revoke_service_api_key(
            db=db,
            tenant_id=current_tenant.tenant_id,
            api_key_id=api_key_id,
            current_user=current_user,
            otp=data.otp
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
