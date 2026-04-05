# import dependencies
from app.cores.logging import get_logger
from fastapi import BackgroundTasks, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.user import get_user_by_identifier, validate_user_credentials, get_user_by_email, validate_2fa_user
from app.utility.security import validate_password, build_audit_context, create_auth_audit_log_bg, verify_email_otp
from app.utility.auth import is_trusted_device, handle_trusted_device_login, handle_2fa_challenge, handle_remember_device, set_auth_cookies, generate_auth_tokens, extract_refresh_token, rotate_refresh_token, get_refresh_token_payload, create_access_token
from app.schemas.users import TwoFAVerify





# initialize get logger
logger = get_logger(__name__)




# login function
async def authenticate_users(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    form_data: OAuth2PasswordRequestForm,
    db: AsyncSession 
):
    # OAuth2PasswordRequestForm uses "username" for both email and username  
    login_identifier = form_data.username.lower().strip()
    password = form_data.password

    # fetch user
    user = await get_user_by_identifier(db, login_identifier)

    # validate user
    validate_user_credentials(user)

    # validate password
    await validate_password(password, user.password_hash)

    # check trusted device (2FA bypass)
    trusted_device = request.cookies.get("trusted_device")

    if trusted_device and await is_trusted_device(user.user_id, trusted_device):
        # extract context metas
        context = build_audit_context(request)
        
        # audit-log success (bypass 2FA)
        background_tasks.add_task(
            create_auth_audit_log_bg,        
            action="LOGIN_SUCCESS",
            user_id=user.user_id,
            metadata={"method": "trusted_device"},
            context=context
        )
        return await handle_trusted_device_login(user, response)

    # handle 2FA challenge
    return await handle_2fa_challenge(
        user=user,
        background_tasks=background_tasks
    )
    
    


# function to verify 2fa authentiction 
async def confirm_2fa(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    data: TwoFAVerify,
    db: AsyncSession
):
    # verify OTP → returns email
    email = await verify_email_otp(otp_code=data.otp, scope="2FA")

    # fetch user
    user = await get_user_by_email(db, email)

    # validate user
    validate_2fa_user(user)

    # generate tokens
    tokens = await generate_auth_tokens(user)

    # set cookies
    set_auth_cookies(response, tokens["access_token"], tokens["refresh_token"], tokens["csrf_token"])

    # remember device 
    if data.remember_device:
        await handle_remember_device(user, response)
    
    # extract context metas
    context = build_audit_context(request)
        
    # audit-log success
    background_tasks.add_task(
        create_auth_audit_log_bg,        
        action="2FA_SUCCESS",
        user_id=user.user_id,
        metadata={"remember_device": data.remember_device},
        context=context
    )

    # log success
    logger.info("2fa_success", extra={"user_id": user.user_id})

    return {
        "access_token": tokens["access_token"],
        "token_type": "bearer"
    }
    
    
    

# function to refresh token
async def refresh_session_token(request: Request, response: Response):
    # extract refresh token from cookies
    old_refresh_token = extract_refresh_token(request)

    # rotate refresh token
    new_refresh_token = await rotate_refresh_token(old_refresh_token, request)

    # get token payload from Redis
    payload = await get_refresh_token_payload(new_refresh_token, request)

    # generate new access token
    access_token = create_access_token(user_id=payload.get("user_id"))

    # set cookies
    set_auth_cookies(response, access_token, new_refresh_token)

    return {"detail": "Token refreshed"} 