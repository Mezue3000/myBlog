# import dependencies
from app.cores.redis import redis_client




class SecurityStore:

    async def add_score(self, ip: str, score: int):
        key = f"sec:score:{ip}"
        total = await redis_client.incrby(key, score)
        await redis_client.expire(key, 3600)
        return total

    async def get_score(self, ip: str):
        val = await redis_client.get(f"sec:score:{ip}")
        return int(val) if val else 0

    async def ban(self, ip: str, duration: int):
        await redis_client.set(f"sec:ban:{ip}", "1", ex=duration)

    async def is_banned(self, ip: str):
        return await redis_client.exists(f"sec:ban:{ip}")