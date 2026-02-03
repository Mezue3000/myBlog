# import dependencies
import logging
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR
from app.utility.logging import get_logger


logger = get_logger(__name__)



# FastAPI HTTPException handler
async def http_exception_handler(
    request: Request,
    exc: HTTPException,
):
    logger.warning(
        "http_exception",
        extra={
            "path": request.url.path,
            "method": request.method,
            "status_code": exc.status_code,
            "detail": exc.detail,
            "client_ip": request.client.host if request.client else None,
        },
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )




# Starlette HTTPException handler (404, 405, etc.)
async def starlette_http_exception_handler(
    request: Request,
    exc: StarletteHTTPException,
):
    logger.warning(
        "starlette_http_exception",
        extra={
            "path": request.url.path,
            "method": request.method,
            "status_code": exc.status_code,
            "detail": exc.detail,
            "client_ip": request.client.host if request.client else None,
        },
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )




# Unhandled / unexpected exceptions
async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
):
    logger.exception(
        "unhandled_exception",
        extra={
            "path": request.url.path,
            "method": request.method,
            "user_id": getattr(request.state, "user_id", "anonymous"),
            "client_ip": request.client.host if request.client else None,
        },
    )

    return JSONResponse(
        status_code=HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )