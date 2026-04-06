# import dependencies
from fastapi import APIRouter, Depends, status, BackgroundTasks, Response, Request
from fastapi_limiter.depends import RateLimiter
from app.schemas.users import EmailRequest, UserRead, UserCreate, UserUpdateRead, UserUpdate, UserPasswordUpdate, EmailUpdate, DeleteUserRequest, PasswordResetConfirm
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.database import get_db
from app.models import User
from app.utility.security import get_identifier_factory, get_identifier
from app.services.user import initiate_registration, finalize_registration, change_password, initiate_email_update, finalize_email_update, delete_user_account, update_user_info, demand_password_reset, verify_password_reset, signout_all_devices 
from app.utility.user import get_current_user, get_current_active_user
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
 



# initialize router
router = APIRouter(tags=["users"])  



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




# create endpoint to retrieve username
@router.get("/get_username")
async def get_username(current_user: User = Depends(get_current_user)):
    return f"Hello {current_user.username}"  

  
  
  
# create endpoint to retrieve user info...
@router.get("/read_user", response_model=UserRead) 
async def read_user(current_user: User  = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return current_user 
  
  
  
  
# create user update endpoint
@router.patch(
    "/update_user", 
    dependencies=[Depends(RateLimiter(times=3, minutes=5, identifier=get_identifier_factory("update_user")))],
    response_model=UserUpdateRead
)

async def update_user(
    user_data: UserUpdate, 
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db), 
):
    return await update_user_info(user_data=user_data, current_user=current_user, db=db)




# create endpoint to change user password
@router.patch(
    "/update_password", 
    dependencies=[
        Depends(
            RateLimiter(times=3, minutes=5, identifier=get_identifier_factory("update_password"))
        )
    ],
    status_code=status.HTTP_200_OK
)

async def update_password(
    payload: UserPasswordUpdate, 
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    return await change_password(user=current_user, payload=payload, db=db, request=request) 
    
    
    
    
# endpoint to initiate email update
@router.patch( 
    "/update_email", 
    dependencies=[Depends(RateLimiter(times=3, minutes=5, identifier=get_identifier_factory("update_email")))],
    status_code=status.HTTP_200_OK
)

async def update_email(
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

async def complete_email_update(
    otp_code: str, 
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession=Depends(get_db)
): 
   return await finalize_email_update(otp_code=otp_code, user=current_user, db=db, request=request)
   
   
   

# endpoint for reset password
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
    



# confirm reset password endpoint
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




# create all_device logout endpoint
@router.post("/logout-all")
async def logout_all_devices(request: Request, response: Response):
    return await signout_all_devices(request=request, response=response)
   



# create endpoint to delete user account(soft-delete)
@router.patch(
    "/delete_user", 
    dependencies=[Depends(RateLimiter(times=2, minutes=15, identifier=get_identifier_factory("delete_user")))],
    status_code=status.HTTP_200_OK
)

async def delete_user(
    data: DeleteUserRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
   return await delete_user_account(data=data, current_user=current_user, db=db, request=request)





# # create endpoint for single-session logout 
# @router.post("/logout")
# async def single_session_logout(request: Request, response: Response):
#     refresh_token = extract_refresh_token(request)
#     if refresh_token:
#         await redis_client.delete(f"refresh:{refresh_token}")

#     # Clear cookies
#     clear_auth_cookies(response)
#     return {"message": "Logged out succesfully"}