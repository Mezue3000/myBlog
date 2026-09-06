# import dependencies
from dotenv import load_dotenv
import os
from limits.aio.storage import RedisStorage
from slowapi import Limiter
from slowapi.util import get_remote_address




# load environment variable
load_dotenv(dotenv_path="C:/Users/HP/Desktop/Python-Notes/myBlog/server/app/utility/platform/.env")



# fetch redis credentials
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REDIS_USER = os.getenv("REDIS_USER", "default")



# Build the secure async URI string
storage_url = f"rediss://{REDIS_USER}:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}"




limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=storage_url,
    storage_options={"implementation": "redispy"},
    headers_enabled=True,
    in_memory_fallback_enabled=True,
    strategy="moving-window"
)
