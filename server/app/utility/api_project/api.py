# import dependencies
import secrets, hashlib
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from uuid import UUID
from app.models import ApiProject, Tenant
from fastapi import HTTPException, status, Depends, status
from app.utility.platform.database import get_db
from app.utility.tenant.tenant_router import get_current_tenant





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
