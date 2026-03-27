# import necessary dependencies
from app.utility.logging import get_logger
from fastapi import APIRouter, Depends, Request, Response, BackgroundTasks
from fastapi_limiter.depends import RateLimiter
from app.schemas.jwts import Token
from typing import Union
from app.schemas.users import EmailRequest, UserRead, UserCreate, TwoFAChallenge, PasswordResetConfirm
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel.ext.asyncio.session import AsyncSession 
from app.utility.database import get_db 
from app.utility.security import get_identifier
from app.utility.email_auth import initiate_registration, finalize_registration, authenticate_users, confirm_2fa, demand_password_reset, verify_password_reset, refresh_session_token, signout_all_devices
from app.schemas.users import TwoFAVerify




# initialize logging
logger = get_logger("auth")


# initialize router
router = APIRouter(tags=["authenticate"])


# create endpoint to start user registration by verifying email
@router.post(
    "/start_registration",
    dependencies=[Depends(RateLimiter(times=3, minutes=5, identifier=get_identifier))]
)

async def start_registration(
    user_data: EmailRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    return await initiate_registration(user_data=user_data, background_tasks=background_tasks, db=db) 

    

 
# create endpoint to complete user registration
@router.post("/complete_registration", response_model=UserRead)

async def complete_registration(user: UserCreate, otp_code: str, db: AsyncSession = Depends(get_db)):
    return await finalize_registration(user=user, otp_code=otp_code, db=db)




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
   
   
   
   
# endpoint for forgot_password
@router.post(
    "/password-reset/request",
    dependencies=[Depends(RateLimiter(times=3, minutes=10, identifier=get_identifier))]
)

async def request_password_reset(
    user_data: EmailRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    return await demand_password_reset(email=user_data.email, background_tasks=background_tasks, db=db)
    



# confirm password reset endpoint
@router.post(
    "/password-reset/confirm",
    dependencies=[Depends(RateLimiter(times=2, minutes=10, identifier=get_identifier))]
)

async def confirm_password_reset(
    request: Request,
    data: PasswordResetConfirm, 
    db: AsyncSession = Depends(get_db)
):
    return await verify_password_reset(request=request, data=data, db=db)




# create refresh token endpoint
@router.post("/refresh_token")
async def refresh_token(request: Request, response: Response):
    return await refresh_session_token(request=request, response=response)




# create all_device logout endpoint
@router.post("/logout-all")
async def logout_all_devices(request: Request, response: Response):
    return await signout_all_devices(request=request, response=response)
   



# # create endpoint for single-session logout 
# @router.post("/logout")
# async def single_session_logout(request: Request, response: Response):
#     refresh_token = extract_refresh_token(request)
#     if refresh_token:
#         await redis_client.delete(f"refresh:{refresh_token}")

#     # Clear cookies
#     clear_auth_cookies(response)
#     return {"message": "Logged out succesfully"}