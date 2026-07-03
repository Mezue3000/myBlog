# import dependencies
from app.cores.logging import get_logger
from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
import json, uuid
from fastapi.middleware.cors import CORSMiddleware
from app.utility.tenant.tenant_router import current_tenant_id
from app.cores.redis import redis_client





# initialize logging
logger = get_logger(__name__)




# middleware function to cache the body once
class CacheRequestBodyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Cache body only if not already set
        request.state.body_data = {}
        try:
            body_bytes = await request.body()
            if body_bytes:
                request.state.body_data = json.loads(body_bytes.decode())
        except json.JSONDecodeError:
            pass
        response = await call_next(request)
        return response
    
    
    
    
 
# middleware function for csp security headers(protect against xss attack)
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            # Scripts — allow common CDNs + unsafe-eval (needed by many bundlers)
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "https://cdn.jsdelivr.net https://cdnjs.cloudflare.com "
            "https://cdn.tailwindcss.com https://unpkg.com; "
    
            # Styles — unsafe-inline
            "style-src 'self' 'unsafe-inline' "
            "https://fonts.googleapis.com https://cdn.jsdelivr.net; "
    
            # Fonts
            "font-src 'self' data: https://fonts.gstatic.com; "
    
            # Images — very permissive 
            "img-src 'self' data: blob: https:; "
    
            # Connect external services(add Stripe)
            "connect-src 'self' https://api.resend.com "
            "https://*.sentry.io wss:; "
    
            # Media
            "media-src 'self'; "
    
            # Frames
            "frame-src 'self'; "
            "frame-ancestors 'none'; "
    
            # Strong protections
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none'; "
            "upgrade-insecure-requests;"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"  
        
        return response





# cors middleware class
class CustomCORSMiddleware(CORSMiddleware):
    def __init__(self, app, **kwargs):
        super().__init__(
            app,
            allow_origins=[
                # "http://localhost:3000",
                # "http://localhost:5173",
                # "https://your-frontend-domain.com",
            ],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=[
                "Accept",
                "Authorization",
                "Content-Type",
                "X-CSRF-Token",
            ],
            # Let frontend read the CSRF response header
            expose_headers=["X-CSRF-Token"],
            max_age=3600,
            **kwargs,
        )
        




# debug lifesaver middleware for logging
class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # generate or extract a unique tracing id for monitoring
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id
        
        response = await call_next(request)
        
        # append it back to the client headers for logging parity
        response.headers["X-Request-ID"] = request_id
        return response





# create tenant context middleware
class TenantContextMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request, call_next):

        tenant_id = getattr(request.state, "tenant_id", None)

        if not tenant_id:
            # safely extract tenant via headers or subdomains 
            tenant_id = request.headers.get("X-Tenant-ID") 
            request.state.tenant_id = tenant_id

        token = current_tenant_id.set(tenant_id)

        try:
            response = await call_next(request)
            return response

        finally:
            current_tenant_id.reset(token)





MAX_CACHE_SIZE = 100 * 1024


# idempotency middleware
class IdempotencyMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next
    ):
        # skip unsupported methods
        if request.method not in {"POST", "PUT", "PATCH"}:
            return await call_next(request)

        idempotency_key = request.headers.get("Idempotency-Key")

        if not idempotency_key:
            return await call_next(request)

        # build scoped cache key
        tenant_id = request.headers.get("X-Tenant-ID", "anonymous")

        cache_key = (
            f"idemp:"
            f"{tenant_id}:"
            f"{request.method}:"
            f"{request.url.path}:"
            f"{idempotency_key}"
        )

        processing_token = (f"PROCESSING:{uuid.uuid4().hex}")

        # try to acquire lock
        is_new_request = await redis_client.set(
            cache_key,
            processing_token,
            ex=120,
            nx=True
        )

        # existing key found
        if not is_new_request:
            cached_data = await redis_client.get(cache_key)

            if not cached_data:
                return await call_next(request)

            cached_data = cached_data.decode()

            if cached_data.startswith("PROCESSING:"):
                return Response(
                    content=json.dumps(
                        {
                            "detail":
                            "Duplicate request is currently processing"
                        }
                    ),
                    media_type="application/json",
                    status_code=status.HTTP_409_CONFLICT
                )

            cached_response = json.loads(cached_data)

            return Response(
                content=cached_response["body"],
                status_code=cached_response["status_code"],
                headers=cached_response.get("headers", {},),
                media_type="application/json"
            )

        # execute request
        try:
            response = await call_next(request)

            response_body = b""

            async for chunk in response.body_iterator:
                response_body += chunk

            # only cache successful responses
            if (
                response.status_code < 400
                and len(response_body)
                <= MAX_CACHE_SIZE
            ):

                payload = {
                    "status_code":
                        response.status_code,

                    "headers":
                        dict(response.headers),

                    "body":
                        response_body.decode("utf-8", errors="ignore")
                }

                await redis_client.setex(
                    cache_key,
                    86400,
                    json.dumps(payload)
                )

            else:
                # remove processing lock
                await redis_client.delete(cache_key)

            return Response(
                content=response_body,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type
            )

        except Exception:
            # release lock so client can retry
            await redis_client.delete(cache_key)
            logger.exception("Idempotency middleware error")

            raise 
        
        
        
        
        


# "geolocation=(); "           # No location
#     "microphone=(); "            # No audio
#     "camera=(); "                # No video
#     "payment=(); "               # No Payment Request API
#     "usb=(); "                   # No USB devices
#     "vr=(); "                    # No VR/AR
#     "accelerometer=(); "         # No motion sensors
#     "ambient-light-sensor=(); "  # No light sensors
#     "gyroscope=(); "             # No rotation sensors
#     "magnetometer=(); "          # No magnetic field
#     "fullscreen=(self); "        # Allow fullscreen only for your site
#     "document-domain=()"
