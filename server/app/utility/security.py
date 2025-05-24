# import dependencies
from passlib.context import CryptContext
import asyncio


# initialize crypt context
pwd_context = CryptContext(schemes=["argon2"], default="argon2")


# function to hash password
async def hash_password(password):
    return await asyncio.to_thread(pwd_context.hash, password)


# function to verify password
async def verify_password(plain_password, hash_password):
    return await asyncio.to_thread(pwd_context.verify, plain_password, hash_password) 


# if __name__ == "__main__":
#     hasy = asyncio.run(hash_password("monday345"))
#     print(hasy)
    