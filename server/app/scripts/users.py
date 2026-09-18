# import dependencies
from app.cores.logging import get_logger
import asyncio, os
from dotenv import load_dotenv
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine
from app.utility.platform.database import async_engine
from app.models import User, Role, Tenant
from pwdlib import PasswordHash
from app.utility.platform.user import slugify
from app.utility.stripe.helpers import get_plan_for_tenant_type





# initialize logging
logger = get_logger(__name__)



# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/platform/.env")



DATABASE_URL = os.getenv("DATABASE_URL") 



# create asynchronous engine  
async_engine = create_async_engine(DATABASE_URL, echo=True)



# initialize hash function
password_hash = PasswordHash.recommended()


# function to hash password
async def hash_password(password: str) -> str:
    return await asyncio.to_thread(password_hash.hash, password)





# seed users
SEED_USERS = [
    {
        "email": "mezueworld@gmail.com",
        "username": "global_admin",
        "password": "Angelcode123$",
        "role_id": 2
    },
    
    {
        "email": "mezueworld@yahoo.com",
        "username": "superadmin",
        "password": "Angelcode1234@",
        "role_id": 1
    },
    
    {
        "email": "user1@example.com",
        "username": "demo_user1",
        "password": "UserPassword123!",
        "role_id": 4
    },
    
    {
        "email": "user2@example.com",
        "username": "demo_user2",
        "password": "UserPassword1234!",
        "role_id": 4
    },
    
    {
        "email": "user3@example.com",
        "username": "demo_user3",
        "password": "UserPassword234!",
        "role_id": 4
    }
]



# create personal tenant
async def create_personal_tenant(
    *,
    user: User,
    db: AsyncSession
) -> Tenant:
    """
    Create the personal tenant for a user.

    Every user is a tenant.

    Personal tenants:
        - have type='personal'
        - use the Personal Free plan
        - use owner_id as proof of ownership
        - do not require TenantMembership

    Does not commit.
    """

    # check whether personal tenant already exists
    statement = (
        select(Tenant)
        .where(
            Tenant.owner_id == user.user_id,
            Tenant.type == "personal",
            Tenant.is_deleted.is_(False)
        )
    )

    result = await db.exec(statement)

    tenant = result.first()

    if tenant is not None:
        return tenant

    # get personal free plan
    free_plan = await get_plan_for_tenant_type(
        tenant_type="personal",
        plan_name="free",
        db=db
    )

    # generate unique slug
    slug = slugify(user.username)

    # create personal tenant
    tenant = Tenant(
        name="private",
        slug=slug,
        owner_id=user.user_id,
        plan_id=free_plan.plan_id,
        credits_remaining=free_plan.credits
    )

    db.add(tenant)
    await db.flush()

    logger.info(
        "Created personal tenant %s for user %s.",
        tenant.tenant_id,
        user.user_id
    )

    return tenant


# seed users
async def seed_users(
    *,
    db: AsyncSession
) -> None:
    """
    Seed users and their personal tenants.

    The operation is idempotent.
    """

    for user_data in SEED_USERS:

        # check existing user
        statement = (
            select(User)
            .where(User.email == user_data["email"])
        )

        result = await db.exec(statement)

        user = result.first()

        # existing user
        if user is not None:

            logger.info(
                "User '%s' already exists.",
                user.email
            )

            # make sure their personal tenant exists.
            await create_personal_tenant(
                user=user,
                db=db
            )

            continue

        # create user
        user = User(
            email=user_data["email"],
            username=user_data["username"].lower(),
            password_hash=await hash_password(user_data["password"]),
            role_id=user_data["role_id"]
        )

        db.add(user)
        await db.flush()

        # every user gets a personal tenant
        await create_personal_tenant(user=user, db=db)

        logger.info(
            "Created user '%s' and personal tenant.",
            user.email
        )



# main
async def main() -> None:

    async with AsyncSession(async_engine) as db:

        try:
            await seed_users(db=db)
            await db.commit()
            logger.info("User and tenant seeding completed.")

        except Exception:
            await db.rollback()
            logger.exception("User and tenant seeding failed.")

            raise


if __name__ == "__main__":
    asyncio.run(main())
