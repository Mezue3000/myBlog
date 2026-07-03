# import dependencies
from fastapi import Request, HTTPException, status




# tenant rate-limit key
def tenant_key_func(request: Request) -> str:
    tenant_id = getattr(request.state, "tenant_id", None)

    if tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Tenant context missing."
        )

    return f"tenant:{tenant_id}"




# authenticated user rate-limit key
def user_key_func(request: Request) -> str:
    user_id = getattr(request.state, "user_id", None)

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User context missing."
        )

    return f"user:{user_id}"




# email-verification key function
def email_key_func(request: Request):
    email = getattr(request.state, "email", None)

    if not email:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Email missing."
        )

    return f"email:{email}"




# login key function
def email_username_key_func(request: Request):
    identifier = getattr(request.state, "identifier", None)

    if not identifier:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Identifier missing."
        )

    return f"login:{identifier}"
