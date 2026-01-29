# import dependencies
# from passlib.context import CryptContext
from pwdlib import PasswordHash
import asyncio
from fastapi import Request
from fastapi import Request, Depends
from app.utility.auth import get_current_user  
from app.models import User 




# initialize hash function
password_hash = PasswordHash.recommended()
# pwd_context = CryptContext(schemes=["argon2"], default="argon2")




# function to hash password
async def hash_password(password: str) -> str:
    return await asyncio.to_thread(password_hash.hash, password)




# function to verify password
async def verify_password(plain_password: str, hashed_password: str) -> bool:
    return await asyncio.to_thread(password_hash.verify, plain_password, hashed_password)





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