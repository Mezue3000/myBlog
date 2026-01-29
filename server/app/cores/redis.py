from dotenv import load_dotenv
import os
from redis.asyncio import Redis



# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/.env")



# fetch redis credentials
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REDIS_USER = os.getenv("REDIS_USER", "default")


if not all([REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_USER]):
    raise ValueError("Missing required Redis env vars: REDIS_HOST, REDIS_PORT, REDIS_PASSWORD")

try:
    redis_port = int(REDIS_PORT)
except ValueError:
    raise ValueError("REDIS_PORT must be a valid integer")



# initialize redis
redis_client = Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    username=REDIS_USER,
    password=REDIS_PASSWORD,
    decode_responses=True, 
    socket_timeout=15,
    socket_connect_timeout=15,
    retry_on_timeout=True,
    health_check_interval=30,               
)
