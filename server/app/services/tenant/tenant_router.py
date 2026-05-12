# import dependencies
from app.cores.logging import get_logger
from app.schemas.tenant.tenant_router import TenantCreate
from fastapi import HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel.ext.asyncio.session import AsyncSession
from app.models import User, Tenant, TenantMembership
from app.utility.tenant.tenant_router import validate_tenant_uniqueness
from app.utility.platform.user import slugify






# initialize logging
logger = get_logger(__name__)





# create organisation workspace
async def create_team_service(data: TenantCreate, current_user: User, db: AsyncSession): 
    try:
        logger.info(f"Creating tenant: {data.name}")
        
        # validate tenant uniqueness
        await validate_tenant_uniqueness(name=data.name, db=db)

        # extract slug from tenant-name
        slug = slugify(data.name, db)
        
        # create tenant
        tenant = Tenant(
            name=data.name,
            type="team",
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

        await db.commit()
        await db.refresh(tenant)
        await db.refresh(membership)

        logger.info(f"Tenant created with id={tenant.tenant_id}")

        return tenant
    
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error creating tenant: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error"
        )

    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Something went wrong"
        )