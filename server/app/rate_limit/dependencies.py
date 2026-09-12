# import dependencies
from fastapi import Depends, Request, HTTPException
from fastapi.security import OAuth2PasswordRequestForm




# function to attach email for verification
async def attach_email(request: Request):
    
    request.state.email = None

    try:
        data = await request.json()
    except ValueError:
        return

    email = data.get("email")

    if isinstance(email, str) and email.strip():
        request.state.email = email.strip().lower()




# function to attach email/username on login
async def attach_identifier(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    identifier = form_data.username

    if isinstance(identifier, str) and identifier.strip():
        request.state.identifier = identifier.strip().lower()
