# import necessary dependencies
from fastapi import APIRouter, Depends, Request, Response, BackgroundTasks
from app.rate_limit.dependencies import attach_identifier
from app.rate_limit.limiter import limiter
from app.rate_limit.policy import AUTH_LIMITS
from app.rate_limit.keys import email_username_key_func
from app.schemas.platform.jwts import Token
from typing import Union
from app.schemas.platform.users import EmailRequest, UserRead, UserCreate, TwoFAChallenge, PasswordResetConfirm
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel.ext.asyncio.session import AsyncSession 
from app.utility.platform.database import get_db 
from app.services.platform.auth import authenticate_users, confirm_2fa, refresh_session_token
from app.schemas.platform.users import TwoFAVerify 




# initialize router
router = APIRouter(prefix="/v1/auth", tags=["authenticate"])




# create an endpoint to sign_in and grab token
@router.post("/token", dependencies=[Depends(attach_identifier)], response_model=Union[Token, TwoFAChallenge])

@limiter.limit(AUTH_LIMITS["ip"])  
@limiter.limit(AUTH_LIMITS["login"], key_func=email_username_key_func)
async def login(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: AsyncSession = Depends(get_db)
):
    return await authenticate_users(
        request=request,
        response=response,
        background_tasks=background_tasks,
        form_data=form_data,
        db=db
    )




# endpoint for 2FA verification
@router.post("/2fa/verify", dependencies=[Depends(attach_identifier)])

@limiter.limit(AUTH_LIMITS["ip"])  
@limiter.limit(AUTH_LIMITS["login"], key_func=email_username_key_func)
async def verify_2fa(
    request: Request,
    response: Response,
    data: TwoFAVerify,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    return await confirm_2fa(
        request=request,
        response=response, 
        data=data,  
        background_tasks=background_tasks,
        db=db
    )
   
   
   

# create refresh token endpoint
@router.post("/refresh_token")
async def refresh_token(request: Request, response: Response):
    return await refresh_session_token(request=request, response=response)
