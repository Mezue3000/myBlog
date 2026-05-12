# import dependencies
from sqlmodel.ext.asyncio.session import AsyncSession
from app.models import Tenant
from sqlmodel import select
from fastapi import HTTPException, status





# function to get personal workspace
async def get_personal_tenant(user_id: int, db: AsyncSession) -> Tenant:
    # personal workspace via ownership
    statement = select(Tenant).where(
        Tenant.owner_id == user_id,
        Tenant.type == "personal",
        Tenant.is_active == True,
        Tenant.is_deleted == False
    )
    
    result = await db.exec(statement)
    tenant = result.first()
    
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Personal workspace not found"
        )
    
    return tenant





# check tenant name uniqueness
async def validate_tenant_uniqueness(name: str, db: AsyncSession):
    statement = select(Tenant).where(Tenant.name == name)

    existing_tenant = db.exec(statement).first()

    if existing_tenant:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tenant name already exists")