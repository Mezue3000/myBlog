# import dependencies
from app.cores.logging import get_logger
from app.schemas.tenant.tenant_router import TenantCreate, TenantRead
from fastapi import HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel.ext.asyncio.session import AsyncSession
from app.models import User, Tenant, TenantMembership
from app.utility.tenant.tenant_router import validate_tenant_uniqueness, get_user_tenants_by_type, validate_tenant_access
from app.utility.platform.user import slugify
from uuid import UUID






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
        
        
        
        
        
# list all user team workspaces by type
async def get_tenants_service( current_user: User, db: AsyncSession):
    try:
        results = await get_user_tenants_by_type(user_id=current_user.user_id, db=db, tenant_type="team")

        tenants = [
            TenantRead(
                tenant_id=str(tenant.tenant_id),
                name=tenant.name,
                slug=tenant.slug,
                role=role
            )
            for tenant, role in results
        ]

        return tenants

    except Exception as e:
        logger.error(f"Error fetching tenants: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Failed to fetch tenants"
        ) 
        
        
        
        
        
# switch teanant function
async def switch_tenant_service(
    tenant_id: UUID,
    current_user: User,
    db: AsyncSession,
):
    try:
        tenant = await db.get(Tenant, tenant_id)

        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tenant not found",
            )

        # validate access
        await validate_tenant_access(
            tenant=tenant,
            current_user=current_user,
            db=db,
        )

        # save active tenant
        current_user.active_tenant_id = tenant.tenant_id

        db.add(current_user)
        await db.commit()
        await db.refresh(current_user)

        logger.info(
            f"User {current_user.user_id} switched "
            f"to tenant {tenant.tenant_id}"
        )

        return {
            "message": "Tenant switched successfully",
            "active_tenant_id": tenant.tenant_id,
        }

    except HTTPException:
        raise

    except SQLAlchemyError as e:
        await db.rollback()

        logger.error(f"Database error switching tenant: {str(e)}")

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error"
        )

    except Exception as e:
        await db.rollback()

        logger.error(f"Unexpected error switching tenant: {str(e)}")

        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Something went wrong")