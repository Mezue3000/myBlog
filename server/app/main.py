# import dependencies
from dotenv import load_dotenv
from app.utility.logging import setup_logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi_limiter import FastAPILimiter
from app.cores.redis import redis_client
from app.cores.middleware import(
    request_id_middleware,
    CacheRequestBodyMiddleware, 
    SecurityHeadersMiddleware, 
    CustomCORSMiddleware
)
from app.cores.exceptions import (
    http_exception_handler,
    starlette_http_exception_handler,
    unhandled_exception_handler,
)
from app.cruds import users, login




# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/.env")



setup_logging()



@asynccontextmanager
async def lifespan(app: FastAPI):
    await FastAPILimiter.init(redis_client)
    try:
        yield
    finally:
        if redis_client:
            await redis_client.close()
        
        
        
        
# initialize fastapi
app = FastAPI(lifespan=lifespan)



# add exception handlers
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(StarletteHTTPException, starlette_http_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)



# add middlewares
app.add_middleware(CustomCORSMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.middleware("http")(request_id_middleware)
app.add_middleware(CacheRequestBodyMiddleware)



# include routers
app.include_router(users.router)
app.include_router(login.router)