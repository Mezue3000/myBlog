# import necessary dependencies
from fastapi import APIRouter, Depends, Request, Response, BackgroundTasks
from fastapi_limiter.depends import RateLimiter
from app.schemas.jwts import Token
from typing import Union
from app.schemas.users import EmailRequest, UserRead, UserCreate, TwoFAChallenge, PasswordResetConfirm
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel.ext.asyncio.session import AsyncSession 
from app.utility.database import get_db 
from app.utility.security import get_identifier
from app.services.auth import authenticate_users, confirm_2fa, refresh_session_token
from app.schemas.users import TwoFAVerify 




# initialize router
router = APIRouter(tags=["authenticate"])




# create an endpoint to sign_in and grab token
@router.post(
    "/token", 
    dependencies=[Depends(RateLimiter(times=3, minutes=15, identifier=get_identifier))], 
    response_model=Union[Token, TwoFAChallenge]
)

async def login(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: AsyncSession = Depends(get_db),
):
    return await authenticate_users(
        request=request,
        response=response,
        background_tasks=background_tasks,
        form_data=form_data,
        db=db
    )




# endpoint for 2FA verification
@router.post(
    "/2fa/verify",
    dependencies=[Depends(RateLimiter(times=3, minutes=10, identifier=get_identifier))],
)

async def verify_2fa(
    request: Request,
    response: Response,
    data: TwoFAVerify,
    db: AsyncSession = Depends(get_db),
):
    return await confirm_2fa(request=request, response=response, data=data, db=db)
   
   
   

# create refresh token endpoint
@router.post("/refresh_token")
async def refresh_token(request: Request, response: Response):
    return await refresh_session_token(request=request, response=response)