# import dependencies
import asyncio, os
from dotenv import load_dotenv
from sqlmodel import select
from app.models import Plan
from sqlalchemy.ext.asyncio import create_async_engine
from app.utility.platform.database import async_engine
from sqlmodel.ext.asyncio.session import AsyncSession






# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/platform/.env")


DATABASE_URL = os.getenv("DATABASE_URL") 


# create asynchronous engine  
async_engine = create_async_engine(DATABASE_URL, echo=True)





# get stripe price id's
price_personal_pro_monthly = os.getenv("price_personal_pro_monthly") 
price_personal_pro_yearly = os.getenv("price_personal_pro_yearly")
price_personal_enterprise_monthly = os.getenv("price_personal_enterprise_monthly")
price_personal_enterprise_yearly = os.getenv("price_personal_enterprise_yearly")


price_team_pro_monthly = os.getenv("price_team_pro_monthly")
price_team_pro_yearly = os.getenv("price_team_pro_yearly")
price_team_enterprise_monthly = os.getenv("price_team_enterprise_monthly")
price_team_enterprise_yearly = os.getenv("price_team_enterprise_yearly")


price_api_pro_monthly = os.getenv("price_api_pro_monthly")
price_api_pro_yearly = os.getenv("price_api_pro_yearly")
price_api_enterprise_monthly = os.getenv("price_api_enterprise_monthly")
price_api_enterprise_yearly = os.getenv("price_api_enterprise_yearly")





PLANS = [
    
    # personal
    {
        "name": "Pro",
        "tenant_type": "personal",
        "billing_interval": "monthly",
        "amount": 10,
        "currency": "USD",
        "stripe_price_id": price_personal_pro_monthly,
    },
    
    {
        "name": "Pro",
        "tenant_type": "personal",
        "billing_interval": "yearly",
        "amount": 100,
        "currency": "USD",
        "stripe_price_id": price_personal_pro_yearly,
    },
    
    {
        "name": "Enterprise",
        "tenant_type": "personal",
        "billing_interval": "monthly",
        "amount": 30,
        "currency": "USD",
        "stripe_price_id": price_personal_enterprise_monthly,
    },
    
    {
        "name": "Enterprise",
        "tenant_type": "personal",
        "billing_interval": "yearly",
        "amount": 300,
        "currency": "USD",
        "stripe_price_id": price_personal_enterprise_yearly,
    },

    # team
    {
        "name": "Pro",
        "tenant_type": "team",
        "billing_interval": "monthly",
        "amount": 25,
        "currency": "USD",
        "stripe_price_id": price_team_pro_monthly,
    },
    
    {
        "name": "Pro",
        "tenant_type": "team",
        "billing_interval": "yearly",
        "amount": 250,
        "currency": "USD",
        "stripe_price_id": price_team_pro_yearly,
    },
    
    {
        "name": "Enterprise",
        "tenant_type": "team",
        "billing_interval": "monthly",
        "amount": 75,
        "currency": "USD",
        "stripe_price_id": price_team_enterprise_monthly,
    },
    
    {
        "name": "Enterprise",
        "tenant_type": "team",
        "billing_interval": "yearly",
        "amount": 750,
        "currency": "USD",
        "stripe_price_id": price_team_enterprise_yearly,
    },

    # headless API
    {
        "name": "Pro",
        "tenant_type": "headless_api",
        "billing_interval": "monthly",
        "amount": 49,
        "currency": "USD",
        "stripe_price_id": price_api_pro_monthly,
    },
    
    {
        "name": "Pro",
        "tenant_type": "headless_api",
        "billing_interval": "yearly",
        "amount": 490,
        "currency": "USD",
        "stripe_price_id": price_api_pro_yearly,
    },
    
    {
        "name": "Enterprise",
        "tenant_type": "headless_api",
        "billing_interval": "monthly",
        "amount": 199,
        "currency": "USD",
        "stripe_price_id": price_api_enterprise_monthly,
    },
    
    {
        "name": "Enterprise",
        "tenant_type": "headless_api",
        "billing_interval": "yearly",
        "amount": 1990,
        "currency": "USD",
        "stripe_price_id": price_api_enterprise_yearly,
    },
]




async def seed_plans():
    async with AsyncSession(async_engine) as db:

        try:
            for data in PLANS:

                statement = (
                    select(Plan)
                    .where(
                        Plan.name == data["name"],
                        Plan.tenant_type == data["tenant_type"],
                        Plan.billing_interval == data["billing_interval"]
                    )
                )

                result = await db.exec(statement)

                if result.first():
                    continue

                db.add(Plan(**data))

            await db.commit()

        except Exception:
            await db.rollback()
            raise



if __name__ == "__main__":
    asyncio.run(seed_plans())
