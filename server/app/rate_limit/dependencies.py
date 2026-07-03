# import dependency
from fastapi import Request, HTTPException




# function to attach email for verification
async def attach_email(request: Request):
    try:
        data = await request.json()
        email = data.get("email")
        if isinstance(email, str):
            request.state.email = email.strip().lower()
    except Exception:
        pass





# function to attach email/username on login
async def attach_identifier(request: Request):
    try:
        data = await request.json()
        identifier = (
            data.get("email")
            or data.get("username")
            or data.get("identifier")
        )
        if isinstance(identifier, str):
            request.state.identifier = identifier.strip().lower()
    except Exception:
        pass
