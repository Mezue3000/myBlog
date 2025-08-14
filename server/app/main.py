# import dependencies
from fastapi import FastAPI
from redis.asyncio import Redis
from fastapi_limiter import FastAPILimiter
from contextlib import asynccontextmanager
from app.utility.security import CacheRequestBodyMiddleware
from app.cruds import users, login



# initialize redis
redis = Redis(host="localhost", port=6380, db=0, decode_responses=True)



# define lifespan function
@asynccontextmanager
async def lifespan(app: FastAPI):
    await FastAPILimiter.init(redis)
    yield
    await redis.close()



# initialize fastapi app with lifespan
app = FastAPI(lifespan=lifespan)

 

# Add middleware before routes
app.add_middleware(CacheRequestBodyMiddleware)



# include all routers
app.include_router(users.router)
app.include_router(login.router)