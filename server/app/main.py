# import dependencies
import os
from fastapi import FastAPI
from redis.asyncio import Redis
from fastapi_limiter import FastAPILimiter
from contextlib import asynccontextmanager
from app.utility.security import CacheRequestBodyMiddleware
from app.cruds import users, login     




redis_client: Redis | None = None


# fetch redis credentials
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REDIS_USER = os.getenv("REDIS_USER", "default")

REDIS_URL = f"rediss://{REDIS_USER}:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}"



# initialize redis
@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client

    # initialize Redis client 
    redis_client = Redis.from_url(
        REDIS_URL,
        decode_responses=True,        
        socket_timeout=5,
        socket_connect_timeout=5,
    )




 # Initialize FastAPI Limiter
    await FastAPILimiter.init(redis_client)

    try:
        yield
    finally:
        await redis_client.close()



# initialize fastapi app with lifespan
app = FastAPI(lifespan=lifespan)

 

# Add middleware before routes
app.add_middleware(CacheRequestBodyMiddleware)
 


# include all routers
app.include_router(users.router)
app.include_router(login.router)