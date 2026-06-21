# import dependencies
from app.cores.logging import get_logger
from sqlmodel.ext.asyncio.session import AsyncSession
from app.models import User, Tenant, TenantMembership, ApiProject, APIKey, APIUsageLog
from app.schemas.api_project.api import ApiProjectCreate, ApiKeyCreate, ApiKeyRead, APIUsageLogRead
from app.utility.tenant.tenant_router import validate_tenant_uniqueness
from sqlmodel import select
from fastapi import HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from app.utility.api_project.api import generate_api_key, hash_api_key, get_project_by_tenant, validate_project_uniqueness
from app.utility.platform.user import slugify
from typing import Optional
from sqlalchemy.orm import selectinload
from uuid import UUID




# initialize logging
logger = get_logger(__name__)



# service fuction to create api project
async def create_headless_api_service(
    *,
    data: ApiProjectCreate,
    current_user: User,
    db: AsyncSession
):
    try:
        logger.info(f"Creating API workspace: {data.name}")

        # validate tenant uniqueness
        await validate_tenant_uniqueness(name=data.name, db=db)
        
        # generate slug
        slug = slugify(data.name, db)

        # create tenant
        tenant = Tenant(
            name=data.name,
            type="headless_api",
            slug=slug
        )

        db.add(tenant)
        await db.flush()
        
        # owner membership
        membership = TenantMembership(
            user_id=current_user.user_id,
            tenant_id=tenant.tenant_id,
            role="owner"
        )

        db.add(membership)
        await db.flush()
        
        # validate project uniqueness
        await validate_project_uniqueness(
            tenant_id=tenant.tenant_id,
            project_name=data.project_name,
            db=db
        )

        # create first project
        project = ApiProject(
            tenant_id=tenant.tenant_id,
            name=data.project_name,
            description=data.description
        )
        
        db.add(project)
        await db.commit()

        await db.refresh(tenant)
        await db.refresh(membership)
        await db.refresh(project)

        logger.info(
            "API workspace created successfully. "
            f"tenant_id={tenant.tenant_id}, "
            f"project_id={project.project_id}"
        )

        return {
            "tenant": tenant,
            "project": project
        }

    except HTTPException:
        raise

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error creating API workspace: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error"
        )

    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error creating API workspace: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Something went wrong"
        )
    
    
    
    

# create api-key service function
async def create_service_key(
    *,
    db: AsyncSession,
    project: ApiProject,
    data: ApiKeyCreate
) -> tuple[APIKey, str]:
    try:
        raw_key = generate_api_key()

        hashed_key = hash_api_key(raw_key)

        api_key = APIKey(
            project_id=project.project_id,
            name=data.name,
            key_hash=hashed_key,
            key_prefix=raw_key[:15],
            expires_at=data.expires_at
        )

        db.add(api_key)
        await db.flush()

        logger.info(
            "API key created successfully. "
            f"api_key_id={api_key.api_key_id}, "
            f"project_id={project.project_id}, "
            f"tenant_id={project.tenant_id}"
        )

        return api_key, raw_key

    except Exception as e:
        await db.rollback()
        logger.exception(
            "API key creation failed. "
            f"project_id={project.project_id}, "
            f"tenant_id={project.tenant_id}, "
            f"error={str(e)}"
        )

        raise
    
    
    


# function to list tenant api-keys 
async def get_tenant_api_keys(
    *,
    db: AsyncSession,
    tenant_id: UUID,
    project_id: Optional[int] = None
) -> list[ApiKeyRead]:
    statement = (
        select(APIKey)
        .where(APIKey.project.has(ApiProject.tenant_id == tenant_id))
        .options(selectinload(APIKey.project))
    )
    
    # Optional project filter
    if project_id:
        # Keep your tenant authorization check intact
        await get_project_by_tenant(
            db=db,
            tenant_id=tenant_id,
            project_id=project_id
        )

        statement = statement.where(
            APIKey.project_id == project_id
        )

    # add ordering constraint
    statement = statement.order_by(
        APIKey.created_at.desc()
    )
    
    result = await db.exec(statement)
    api_keys = result.all()

    # build response schemas cleanly via dot notation
    return [
        ApiKeyRead(
            api_key_id=api_key.key_id,  # Maps cleanly to your key identifier
            project_id=api_key.project_id,
            project_name=api_key.project.name if api_key.project else "Unknown Project",
            name=api_key.name,
            key_prefix=api_key.key_prefix,
            is_revoked=api_key.is_revoked,
            last_used_at=api_key.last_used_at,
            expires_at=api_key.expires_at,
            created_at=api_key.created_at
        )
        for api_key in api_keys
    ]





# function to get tenant usage log
async def get_tenant_usage_logs(
    *,
    db: AsyncSession,
    tenant_id: UUID,
    project_id: Optional[int] = None,
    api_key_id: Optional[UUID] = None,
    offset: int = 0,
    limit: int = 50
) -> list[APIUsageLogRead]:
    statement = (
        select(APIUsageLog)
        .where(APIUsageLog.tenant_id == tenant_id)
        .options(
            # eagerly loads log.api_key and subsequently loads api_key.project
            selectinload(APIUsageLog.api_key).selectinload(APIKey.project)
        )
    )

    # apply dynamic filters safely using relationship attribute paths
    if api_key_id:
        statement = statement.where(APIUsageLog.api_key_id == api_key_id)

    if project_id:
        statement = statement.where(
            APIUsageLog.api_key.has(APIKey.project_id == project_id)
        )

    # add pagination bounds and ordering
    statement = (
        statement
        .order_by(APIUsageLog.created_at.desc())
        .offset(offset)
        .limit(limit)
    )

    result = await db.exec(statement)
    logs = result.all()  

    return [
        APIUsageLogRead(
            log_id=log.log_id,
            # access deep nested attributes cleanly via python dots
            project_id=log.api_key.project.project_id if log.api_key and log.api_key.project else None,
            project_name=log.api_key.project.name if log.api_key and log.api_key.project else "Unknown Project",
            api_key_id=log.api_key_id,
            api_key_name=log.api_key.name if log.api_key else None,
            endpoint=log.endpoint,
            method=log.method,
            status_code=log.status_code,
            response_time_ms=log.response_time_ms
        )
        for log in logs
    ]





# function to revoke api-key
async def revoke_service_api_key(
    *,
    db: AsyncSession,
    tenant_id: UUID,
    api_key_id: UUID
) -> APIKey:
    statement = (
        select(APIKey)
        .where(APIKey.api_key_id == api_key_id)
        # multi-tenant security guard: filter by tenant_id via the project relationship
        .where(APIKey.project.has(ApiProject.tenant_id == tenant_id))
        # eager loader: fetch the project data efficiently in a secondary step
        .options(selectinload(APIKey.project))
    )

    result = await db.exec(statement)
    api_key = result.first()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )

    if api_key.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="API key already revoked"
        )

    api_key.is_revoked = True

    db.add(api_key)
    await db.flush()

    return api_key
