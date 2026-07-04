# import dependencies
from fastapi import APIRouter, Depends, status, BackgroundTasks, Response, Request
from app.schemas.platform.users import EmailRequest, UserRead, UserCreate, UserUpdateRead, UserUpdate, UserPasswordUpdate, EmailUpdate, DeleteUserRequest, PasswordResetConfirm, MessageResponse
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.models import User
from app.rate_limit.dependencies import attach_email
from app.rate_limit.limiter import limiter
from app.rate_limit.policy import AUTH_LIMITS
from app.rate_limit.keys import email_key_func, user_key_func
from app.services.platform.user import initiate_registration, finalize_registration, change_password, initiate_email_update, finalize_email_update, delete_user_account, update_user_info, demand_password_reset, verify_password_reset, signout_all_devices, request_delete_user_otp
from app.utility.platform.user import get_current_user, get_current_active_user
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
 



# initialize router
router = APIRouter(prefix="/v1/users", tags=["users"])  



# create endpoint to start user registration by verifying email
@router.post("/start_registration", dependencies=[Depends(attach_email)])

@limiter.limit(AUTH_LIMITS["ip"])      
@limiter.limit(AUTH_LIMITS["register"], key_func=email_key_func)
async def start_registration(
    request: Request,
    user_data: EmailRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    return await initiate_registration(user_data=user_data, background_tasks=background_tasks, db=db) 

    

 
# create endpoint to complete user registration
@router.post("/complete_registration", dependencies=[Depends(attach_email)], response_model=UserRead)

@limiter.limit(AUTH_LIMITS["ip"])  
@limiter.limit(AUTH_LIMITS["register"], key_func=email_key_func)
async def complete_registration(
    request: Request, 
    user: UserCreate,
    otp_code: str,
    db: AsyncSession = Depends(get_db)
):
    return await finalize_registration(user=user, otp_code=otp_code, db=db)




# create endpoint to retrieve username
@router.get("/get_username")
async def get_username(current_user: User = Depends(get_current_user)):
    return f"Hello {current_user.username}"  

  
  
  
# create endpoint to retrieve user info...
@router.get("/read_user", response_model=UserRead) 
async def read_user(current_user: User  = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return current_user 
  
  
  
  
# create user update endpoint
@router.patch("/update_user", response_model=UserUpdateRead)

@limiter.limit(AUTH_LIMITS["update_user"], key_func=user_key_func)
async def update_user(
    request: Request,
    user_data: UserUpdate, 
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db), 
):
    return await update_user_info(user_data=user_data, current_user=current_user, db=db)




# create endpoint to change user password
@router.patch("/update_password", status_code=status.HTTP_200_OK)

@limiter.limit(AUTH_LIMITS["forgot_password"], key_func=user_key_func)
async def update_password(
    request: Request,
    payload: UserPasswordUpdate, 
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    return await change_password(user=current_user, payload=payload, db=db, request=request) 
    
    
    
    
# endpoint to initiate email update
@router.patch("/update_email", status_code=status.HTTP_200_OK)

@limiter.limit(AUTH_LIMITS["update_email"], key_func=user_key_func)
async def update_email(
    request: Request,
    payload: EmailUpdate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    return await initiate_email_update(
        payload=payload,
        background_tasks=background_tasks,
        user=current_user,
        db=db
    )




# endpoint to complete email update
@router.post("/complete_email_update", status_code=status.HTTP_200_OK)


@limiter.limit(AUTH_LIMITS["update_email"], key_func=user_key_func)
async def complete_email_update(
    request: Request,
    otp_code: str, 
    current_user: User = Depends(get_current_user),
    db: AsyncSession=Depends(get_db)
): 
   return await finalize_email_update(otp_code=otp_code, request=request, user=current_user, db=db)
   
   
   

# endpoint for reset password
@router.post("/password-reset/request", dependencies=[Depends(attach_email)])

@limiter.limit(AUTH_LIMITS["ip"])  
@limiter.limit(AUTH_LIMITS["reset_password"], key_func=email_key_func)
async def request_password_reset(
    request: Request,
    user_data: EmailRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    return await demand_password_reset(email=user_data.email, background_tasks=background_tasks, db=db)
    



# confirm reset password endpoint
@router.post("/password-reset/confirm", dependencies=[Depends(attach_email)])

@limiter.limit(AUTH_LIMITS["ip"])  
@limiter.limit(AUTH_LIMITS["reset_password"], key_func=email_key_func)
async def confirm_password_reset(
    request: Request,
    data: PasswordResetConfirm, 
    db: AsyncSession = Depends(get_db)
):
    return await verify_password_reset(request=request, data=data, db=db)




# create all_device logout endpoint
@router.post("/logout-all")
async def logout_all_devices(request: Request, response: Response):
    return await signout_all_devices(request=request, response=response)
   



# endpoint to request deletion OTP
@router.patch("/delete_user", status_code=status.HTTP_200_OK)

@limiter.limit(AUTH_LIMITS["ip"])  
@limiter.limit(AUTH_LIMITS["delete_user"], key_func=user_key_func)
@router.post("/me/delete/request", status_code=status.HTTP_200_OK, response_model=MessageResponse)
async def request_delete_user_otp_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user)
):
    return await request_delete_user_otp(
        background_tasks=background_tasks,
        current_user=current_user
    )





# endpoint to delete user account(soft-delete)
@router.patch("/me", status_code=status.HTTP_200_OK, response_model=MessageResponse)

@limiter.limit(AUTH_LIMITS["ip"])  
@limiter.limit(AUTH_LIMITS["delete_user"], key_func=user_key_func)
async def delete_user_account_endpoint(
    request: Request,
    data: DeleteUserRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    return await delete_user_account(
        request=request,
        data=data,
        current_user=current_user,
        db=db
    )







# # create endpoint for single-session logout 
# @router.post("/logout")
# async def single_session_logout(request: Request, response: Response):
#     refresh_token = extract_refresh_token(request)
#     if refresh_token:
#         await redis_client.delete(f"refresh:{refresh_token}")

#     # Clear cookies
#     clear_auth_cookies(response)
#     return {"message": "Logged out succesfully"}
