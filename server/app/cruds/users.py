# import dependencies
from fastapi import APIRouter, Depends, status, BackgroundTasks, Response, Request
from app.utility.logging import get_logger
from fastapi_limiter.depends import RateLimiter
from app.schemas.users import EmailRequest, UserRead, UserUpdateRead, UserUpdate, UserPasswordUpdate, EmailUpdate, DeleteUserRequest
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.database import get_db
from app.models import User
from app.utility.security import get_identifier_factory
from app.utility.user_service import get_current_user, get_current_active_user, change_password, initiate_email_update, finalize_email_update, delete_user_account, update_user_info
from sqlalchemy.exc import IntegrityError, SQLAlchemyError




logger = get_logger("auth")

# initialize router
router = APIRouter(tags=["users"]) 

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




# complete email update endpoint
@router.post("/complete_email_update", status_code=status.HTTP_200_OK)

async def complete_email_update(
    otp_code: str, 
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession=Depends(get_db)
): 
   return await finalize_email_update(otp_code=otp_code, user=current_user, db=db, request=request)
   
   
   
   
# create endpoint to delete user account
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