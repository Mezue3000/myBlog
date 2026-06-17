# import dependencies
from dotenv import load_dotenv
import os

# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/platform/.env")


from app.cores.logging import setup_logging
from contextlib import asynccontextmanager
from guard.lifespan import guard_lifespan
from fastapi import FastAPI, HTTPException
from app.models import AuditLog, TenantScopedMixin
from sqlalchemy import event 
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi_limiter import FastAPILimiter
from app.cores.redis import redis_client
from app.cores.middleware import(
    RequestIDMiddleware,
    CacheRequestBodyMiddleware, 
    SecurityHeadersMiddleware, 
    CustomCORSMiddleware,
    TenantContextMiddleware
)
from app.cores.exceptions import (
    http_exception_handler,
    starlette_http_exception_handler,
    unhandled_exception_handler,
)
from app.cruds.platform import users
from app.cruds.platform import global_admins, login, social_login
from app.cruds.tenant import admin_router, members_router, tenant_router
from sqlalchemy import event
from sqlalchemy.orm import Session, Mapper
from sqlalchemy.orm import with_loader_criteria
from app.utility.tenant.tenant_router import current_tenant_id, bypass_rls
from guard import SecurityMiddleware
from app.cores.security import security_config
from starlette.middleware.sessions import SessionMiddleware





# set up logging
setup_logging()



authlib_secret_key=os.getenv("AUTHLIB_SECRET_KEY")




# add event listener to prevent delete/upgrade of audit table
@event.listens_for(AuditLog, "before_update")
def prevent_update(mapper, connection, target):
    raise ValueError("Audit logs cannot be modified")

@event.listens_for(AuditLog, "before_delete")
def prevent_delete(mapper, connection, target):
    raise ValueError("Audit logs cannot be deleted")





# event hanlers to auto add tenant_id/bypass
@event.listens_for(Session, "do_orm_execute")
def add_tenant_filter(execute_state):
    
    # only apply to SELECT queries
    if not execute_state.is_select:
        return
    
    # skip tenant filtering when explicitly bypassing RLS
    if bypass_rls.get():
        return
    
    tenant_id = current_tenant_id.get()

    if tenant_id is None:
        return

    execute_state.statement = execute_state.statement.options(
        with_loader_criteria(
            TenantScopedMixin,
            lambda cls: cls.tenant_id == tenant_id,
            include_aliases=True
        )
    )
    
    
@event.listens_for(Session, "before_flush")
def set_tenant_id(session, flush_context, instances):

    tenant_id = current_tenant_id.get()

    if tenant_id is None:
        return

    for obj in session.new:

        if hasattr(obj, "tenant_id"):
            current_value = getattr(obj, "tenant_id", None)
            if current_value is None:
                setattr(obj, "tenant_id", tenant_id)

    
    
    
    
# add rate-limit
@asynccontextmanager
async def lifespan(app: FastAPI):
    # nest inside the fastapi-guard
    async with guard_lifespan(app):
        
        # initialize rate limiter sharing the redis connection instance
        await FastAPILimiter.init(redis_client)
        
        try:
            yield
        finally:
            # close connection pools on server shutdown signals
            if redis_client:
                await redis_client.close()
        
        
        
        
# initialize fastapi
app = FastAPI(lifespan=lifespan)



# add global exception handlers
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(StarletteHTTPException, starlette_http_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)





# add middlewares
app.add_middleware(
    SessionMiddleware, 
    secret_key=authlib_secret_key,
    session_cookie="agentic_auth_session",
    max_age=300,
    same_site="lax",
    https_only=False
)
app.add_middleware(TenantContextMiddleware)
app.middleware(RequestIDMiddleware)
app.add_middleware(CacheRequestBodyMiddleware)
app.add_middleware(SecurityMiddleware, config=security_config)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CustomCORSMiddleware)






# include routers
app.include_router(login.router)
app.include_router(users.router)
app.include_router(global_admins.router) 
app.include_router(admin_router.router)
# app.include_router(members_router.router)
app.include_router(tenant_router.router)
app.include_router(social_login.router)