# import dependencies
from app.cores.logging import get_logger
from sqlmodel.ext.asyncio.session import AsyncSession
from app.models import Tenant, ApiProject, APIKey
from app.schemas.api_project.api import ApiProjectCreate, ApiKeyCreate
from sqlmodel import select
from fastapi import HTTPException, status
from app.utility.api_project.api import generate_api_key, hash_api_key




# initialize logging
logger = get_logger(__name__)



# service fuction to create api project
async def create_service_project(
    *,
    db: AsyncSession,
    tenant: Tenant,
    data: ApiProjectCreate
) -> ApiProject:
    try:
        statement = select(ApiProject).where(
            ApiProject.tenant_id == tenant.tenant_id,
            ApiProject.name == data.name
        )

        result = await db.exec(statement)
        existing_project = result.first()

        if existing_project:
            raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Project already exists"
        )
            
        project = ApiProject(
            tenant_id=tenant.tenant_id,
            name=data.name,
            description=data.description,
            environment=data.environment
        )

        db.add(project)
        await db.flush()

        logger.info(
            "Project created successfully. "
            f"project_id={project.project_id}, "
            f"tenant_id={tenant.tenant_id}"
        )

        return project

    except Exception as e:
        await db.rollback()
        logger.exception(
            "Project creation failed. "
            f"tenant_id={tenant.tenant_id}, "
            f"error={str(e)}"
        )
        raise
    
    
    
    

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
    
    
    


# function to revoke api-key
async def revoke_service_api_key(
    *,
    db: AsyncSession,
    tenant_id: int,
    api_key_id: int,
) -> APIKey:

    statement = (
        select(APIKey)
        .join(ApiProject)
        .where(
            APIKey.api_key_id == api_key_id,
            ApiProject.tenant_id == tenant_id
        )
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