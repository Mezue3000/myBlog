# import dependency
from datetime import timedelta
from app.cores.redis import redis_client
from fastapi import HTTPException, status




# define security constants
MAX_LOGIN_FAILURES = 5

LOGIN_LOCK_DURATION = timedelta(minutes=15)

LOGIN_FAILURE_WINDOW = timedelta(minutes=15)



# redis key builders
def login_failure_key(identifier: str) -> str:

    return (
        f"login:failures:"
        f"{identifier.lower()}"
    )


def login_lock_key(identifier: str) -> str:

    return (
        f"login:lock:"
        f"{identifier.lower()}"
    )





# function to check lock
async def is_login_locked(identifier: str) -> bool:

    return (
        await redis_client.exists(login_lock_key(identifier)) == 1
    )





# function to get remaining lock time
async def get_remaining_lock_seconds(identifier: str) -> int:

    ttl = await redis_client.ttl(
        login_lock_key(identifier)
    )

    return max(ttl, 0)





# function to create lock
async def lock_login(identifier: str):

    await redis_client.set(
        login_lock_key(identifier),
        "locked",
        ex=int(LOGIN_LOCK_DURATION.total_seconds()),
    )





# function to increment login failures
async def increment_login_failures(identifier: str) -> int:

    key = login_failure_key(identifier)

    failures = await redis_client.incr(key)

    if failures == 1:

        await redis_client.expire(
            key,
            int(LOGIN_FAILURE_WINDOW.total_seconds()),
        )

    return failures





# function to clear login failures
async def clear_login_failures(identifier: str):

    await redis_client.delete(login_failure_key(identifier))

    await redis_client.delete(login_lock_key(identifier))





# function to validate login is active
async def ensure_login_not_locked(identifier: str):

    if not await is_login_locked(identifier):
        return

    remaining = await get_remaining_lock_seconds(identifier)

    raise HTTPException(
        status_code=status.HTTP_423_LOCKED,
        detail={
            "message": "Too many failed login attempts.",
            "retry_after": remaining,
        },
    )
    
    
    

# function to record failed login
async def record_failed_login(identifier: str) -> bool:

    # returns True only when a lock was created
    failures = await increment_login_failures(identifier)

    if failures < MAX_LOGIN_FAILURES:
        return False

    await lock_login(identifier)

    return True





async def handle_failed_login(identifier: str, exception: HTTPException) -> None:

    await record_failed_login(identifier)

    raise exception
