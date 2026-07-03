# import dependencies
from app.cores.logging import get_logger
import secrets, hashlib
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from uuid import UUID
from app.models import ApiProject, Tenant, APIKey
from fastapi import HTTPException, status, Depends, Request
from app.utility.platform.database import get_db
from app.utility.tenant.tenant_router import get_current_tenant
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import selectinload
from datetime import datetime, timezone
from app.utility.tenant.tenant_router import validate_tenant





# initialize logging
logger = get_logger(__name__)




# function to create api-key
def generate_api_key() -> str:
    return f"fk_live_{secrets.token_urlsafe(32)}"




# function to hash api-key
def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()




# function to get project by tenant
async def get_project_by_tenant(
    *,
    db: AsyncSession,
    tenant_id: UUID,
    project_id: int
) -> ApiProject:

    statement = select(ApiProject).where(
        ApiProject.project_id == project_id,
        ApiProject.tenant_id == tenant_id
    )
    
    result = await db.exec(statement)
    project = result.first()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )

    return project





# function to get current project
async def get_current_project(
    project_id: int,
    current_tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
) -> ApiProject:

    project = await get_project_by_tenant(
        db=db,
        tenant_id=current_tenant.tenant_id,
        project_id=project_id
    )

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )

    return project





# function to validate project uniqueness
async def validate_project_uniqueness(
    *,
    tenant_id: UUID,
    project_name: str,
    db: AsyncSession
):
    statement = select(ApiProject).where(
        ApiProject.tenant_id == tenant_id,
        ApiProject.name == project_name
    )

    result = await db.exec(statement)
    project = result.first()

    if project:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Project already exists"
        )





# function to validate project
def validate_project(project: ApiProject):
    
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found."
        )

    if project.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Project deleted."
        )

    if not project.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Project disabled."
        )






# function to get real client ip
def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")

    if forwarded:
        return forwarded.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")

    if real_ip:
        return real_ip.strip()

    if request.client:
        return request.client.host

    return "unknown"





# function to update api-key usage
async def update_api_key_usage(
    *,
    db: AsyncSession,
    api_key: APIKey,
    request: Request
) -> None:
    
    api_key.last_used_at = datetime.now(timezone.utc)

    db.add(api_key)
    await db.commit()





# function to log api auth success
def log_api_auth_success(*, request: Request, api_key: APIKey):
    
    logger.info(
        "API key authenticated.",
        extra={
            "api_key_id": api_key.api_key_id,
            "project_id": api_key.project.project_id,
            "tenant_id": api_key.project.tenant.tenant_id,
            "ip": get_client_ip(request)
        },
    )





# function to log api auth failure
def log_api_auth_failure(*, request: Request, reason: str):
    
    logger.warning(
        "API authentication failed.",
        extra={
            "reason": reason,
            "ip": get_client_ip(request)
        },
    )





# function to validate api key format
def validate_api_key_format(api_key: str) -> str:
    
    api_key = api_key.strip()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required."
        )

    if not api_key.startswith("fk_live_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key."
        )

    if len(api_key) < 32:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key."
        )

    return api_key





# function to get hashed api-key
async def get_api_key_by_hash(
    *,
    db: AsyncSession,
    key_hash: str,
) -> APIKey | None:
    
    statement = (
        select(APIKey)
        .where(APIKey.key_hash == key_hash)
        .options(
            selectinload(APIKey.project)
            .selectinload(ApiProject.tenant)
        )
    )

    result = await db.exec(statement)

    return result.first()





# function to validate api-key
def validate_api_key(api_key: APIKey):
    
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key."
        )

    if api_key.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key revoked."
        )

    if not api_key.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key disabled."
        )

    if (
        api_key.expires_at
        and api_key.expires_at <= datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key expired."
        )





# function to attach context
def attach_api_context(request: Request, api_key: APIKey) -> None:

    project = api_key.project
    tenant = project.tenant

    request.state.api_key = api_key
    request.state.api_key_id = api_key.api_key_id

    request.state.api_project = project
    request.state.project_id = project.project_id

    request.state.tenant = tenant
    request.state.tenant_id = tenant.tenant_id
    request.state.tenant_plan = tenant.plan
    request.state.tenant_type = tenant.type





# initialize security
security = HTTPBearer(auto_error=False)



# dependency to authenticate api-key
async def authenticate_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> APIKey:

    if credentials is None:
        log_api_auth_failure(request=request, reason="missing_credentials")
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required."
        )

    raw_key = validate_api_key_format(credentials.credentials)

    hashed_key = hash_api_key(raw_key)

    api_key = await get_api_key_by_hash(db=db, key_hash=hashed_key)

    validate_api_key(api_key)

    project = api_key.project

    validate_project(project)

    tenant = project.tenant

    validate_tenant(tenant)

    await update_api_key_usage(db=db, api_key=api_key, request=request)

    attach_api_context(request=request, api_key=api_key)

    log_api_auth_success(request=request, api_key=api_key)

    return api_key
