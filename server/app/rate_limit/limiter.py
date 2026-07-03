# import dependencies
from limits.aio.storage import RedisStorage
from app.cores.redis import redis_client
from slowapi import Limiter
from slowapi.util import get_remote_address



storage = RedisStorage(redis_client)



limiter = Limiter(
    key_func=get_remote_address,
    storage=storage,
    headers_enabled=True,
    in_memory_fallback_enabled=True,
    strategy="moving-window"
)
