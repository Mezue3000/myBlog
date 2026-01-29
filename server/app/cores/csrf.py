# import dependencies
from fastapi import Request, HTTPException, status
from app.utility.auth import verify_origin




# CSRF validation dependency/function(for protected routes)
async def verify_csrf(request: Request):
    # check origin
    await verify_origin(request)
    
    # double-submit token check
    csrf_cookie = request.cookies.get("csrf_token")
    csrf_header = request.headers.get("X-CSRF-Token")

    if not csrf_cookie or not csrf_header:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing")

    if csrf_cookie != csrf_header:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")
