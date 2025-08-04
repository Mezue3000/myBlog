# import dependencies
from passlib.context import CryptContext
import asyncio
from fastapi import HTTPException, status, Request
import re
import asyncio
import time




# initialize crypt context
pwd_context = CryptContext(schemes=["argon2"], default="argon2")




# function to hash password
async def hash_password(password: str) -> str:
    return await asyncio.to_thread(pwd_context.hash, password)




# function to verify password
async def verify_password(plain_password: str, hash_password: str) -> bool:
    return await asyncio.to_thread(pwd_context.verify, plain_password, hash_password)




# Utility to check password strength
def validate_password_strength(password: str):
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Password must contain at least one lowercase letter")
    if not re.search(r"\d", password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Password must contain at least one digit")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Password must contain at least one special character") 




# if __name__ == "__main__":
#     hasy = asyncio.run(hash_password("monday345"))
#     asyncio.run(verify_password("monday345", hasy))
#     print(hasy) 




# Define rate limiting in-memory store
RATE_LIMIT_STORE = {} 
LOCKED_OUT_USERS = {}  
RATE_LIMIT = 3  # Max attempts
RATE_WINDOW = 60  # In seconds
LOCKOUT_TIME = 180  # Lockout duration in seconds (3 minutes)
RATE_LIMIT_LOCK = asyncio.Lock()



# Thread-safe rate limiting dependency
async def rate_limit(request: Request):
    ip = request.client.host
    now = time.time()

    async with RATE_LIMIT_LOCK:
        # Check if user is locked out
        if ip in LOCKED_OUT_USERS:
            lockout_end = LOCKED_OUT_USERS[ip]
            if now < lockout_end:
                remaining = int(lockout_end - now)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS, 
                    detail=f"Too many attempts. Try again in {remaining} seconds")
            else:
                del LOCKED_OUT_USERS[ip]  # Unlock after lockout ends

        attempts = RATE_LIMIT_STORE.get(ip, [])
        # Filter old attempts outside the window
        attempts = [ts for ts in attempts if now - ts < RATE_WINDOW]

        if len(attempts) >= RATE_LIMIT:
            LOCKED_OUT_USERS[ip] = now + LOCKOUT_TIME
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS, 
                detail="Too many login attempts. Try again later.")

        # Record current attempt
        attempts.append(now)
        RATE_LIMIT_STORE[ip] = attempts

    