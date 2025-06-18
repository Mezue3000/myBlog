# import dependencies
from passlib.context import CryptContext
import asyncio
from fastapi import HTTPException, status
import re


# initialize crypt context
pwd_context = CryptContext(schemes=["argon2"], default="argon2")


# function to hash password
async def hash_password(password):
    return await asyncio.to_thread(pwd_context.hash, password)


# function to verify password
async def verify_password(plain_password, hash_password):
    return await asyncio.to_thread(pwd_context.verify, plain_password, hash_password)


# Utility to check password strength
def validate_password_strength(password):
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
    