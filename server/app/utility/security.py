# import dependencies
from passlib.context import CryptContext
import asyncio
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
import json
from fastapi import Request, Depends
from app.utility.auth import get_current_user  
from app.models import User 




# initialize crypt context
pwd_context = CryptContext(schemes=["argon2"], default="argon2")




# function to hash password
async def hash_password(password: str) -> str:
    return await asyncio.to_thread(pwd_context.hash, password)




# function to verify password
async def verify_password(plain_password: str, hash_password: str) -> bool:
    return await asyncio.to_thread(pwd_context.verify, plain_password, hash_password)




# Utilities to check password strength
def validate_password_strength(password: str) -> None:
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    if not any(c in "!@#$%^&*()-_=+[{]};:<>?|/" for c in password):
        raise ValueError("Password must contain at least one special character")




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


 


# key function to identify users by email or username(rate-limiter)
async def get_identifier(request: Request):
    data = getattr(request.state, "body_data", {}) or {}
    identifier = data.get("email") or data.get("username") or request.client.host
    return identifier



# key function to identify authenticated users by id
def get_identifier_factory(action: str):
    async def identifier(request: Request, user: User = Depends(get_current_user)) -> str:
        if user:
            return f"user:{user.id}:{action}"
        # fallback for unauthenticated requests
        ip = request.headers.get("x-forwarded-for")
        if ip:
            ip = ip.split(",")[0].strip()
        else:
            ip = request.client.host or "unknown"
        return f"ip:{ip}:{action}"
    return identifier




# if __name__ == "__main__":
#     hasy = asyncio.run(hash_password("monday345"))
#     asyncio.run(verify_password("monday345", hasy))
#     print(hasy)