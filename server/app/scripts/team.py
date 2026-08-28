# import dependencies
from app.cores.logging import get_logger
import asyncio, os
from dotenv import load_dotenv

# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/platform/.env")

from app.models import User, Tenant, TenantMembership
from datetime import datetime, timedelta, timezone
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.stripe.helpers import get_plan_for_tenant_type
from app.utility.tenant.tenant_router import validate_tenant_uniqueness
from app.utility.platform.user import slugify
from app.utility.platform.database import async_engine
from sqlalchemy.ext.asyncio import create_async_engine





# initialize logging
logger = get_logger(__name__)





DATABASE_URL = os.getenv("DATABASE_URL") 



# create asynchronous engine  
async_engine = create_async_engine(DATABASE_URL, echo=True)





async def seed_team_workspace(
    db: AsyncSession
) -> Tenant:
    """
    Seed a Team Free workspace and its owner membership.

    The user is identified by email
    """

    # find the seed user
    user_statement = (
        select(User)
        .where(User.email == "user1@example.com")
    )

    result = await db.exec(user_statement)
    user = result.first()

    if user is None:
        raise RuntimeError(
            "Seed user 'admin@example.com' does not exist. "
            "Seed the user before the team workspace."
        )

    # get team free plan
    free_plan = await get_plan_for_tenant_type(
        tenant_type="team",
        plan_name="free", 
        db=db
    )

    # validate tenant uniqueness
    await validate_tenant_uniqueness(name="demoteam1", db=db)
    
    # extract slug from tenant-name
    slug = slugify("demoteam1")

    # create Team tenant
    tenant = Tenant(
        name="demoteam1",
        type="team",
        slug=slug,
        plan_id=free_plan.plan_id,
        credits_remaining=free_plan.credits
    )

    db.add(tenant)

    # generate tenant_id before creating membership.
    await db.flush()

    # create owner membership
    membership = TenantMembership(
        tenant_id=tenant.tenant_id,
        user_id=user.user_id,
        role="owner"
    )

    db.add(membership)

    # flush tenant + membership together
    await db.flush()

    return tenant






async def main() -> None:

    async with AsyncSession(async_engine) as db:

        try:
            
            # team tenant + owner membership
            await seed_team_workspace(db=db)

            # commit everything
            await db.commit()

            logger.info(
                "User, plan, tenant and membership "
                "seeding completed."
            )

        except Exception:
            await db.rollback()

            logger.exception(
                "User, plan, tenant and membership "
                "seeding failed."
            )

            raise


if __name__ == "__main__":
    asyncio.run(main())
