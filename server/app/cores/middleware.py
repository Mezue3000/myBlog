# import dependencies
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import json
from fastapi.middleware.cors import CORSMiddleware
import uuid



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
    
            # Connect external services
            "connect-src 'self' https://api.resend.com "
            "https://*.sentry.io wss:; "  # add Stripe
    
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
async def request_id_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response




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