# import dependencies
from authlib.integrations.starlette_client import OAuth
from app.cores.logging import get_logger
import re, os
from fastapi import HTTPException, status, Request
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.user import slugify
from app.utility.tenant.tenant_router import get_personal_tenant
from app.utility.platform.auth import generate_auth_tokens
from app.utility.platform.auth import create_access_token, create_refresh_token
from app.models import User, Tenant
from app.utility.platform.security import run_background_task, create_auth_audit_log_bg, create_auth_audit_log_safe, build_audit_context





# initialize oauth
oauth = OAuth()




# register google
oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"}
)





# register github
oauth.register(
    name="github",
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com",
    client_kwargs={"scope": "user.email"}   
)





# initialize logging
logger = get_logger(__name__)




ALLOWED_PROVIDERS = {
    "google",
    "github"
}




# extract username
async def generate_unique_username(base: str, db: AsyncSession) -> str:
    # create unique username
    base = re.sub(r"[^a-zA-Z0-9_]", "", base)
    base = base[:40] if len(base) > 40 else base
    base = base or "user"

    statement = (
        select(User.username)
        .where(User.username.like(f"{base}%"))
    )

    result = await db.exec(statement)

    taken_usernames = set(result.all())

    if base not in taken_usernames:
        return base

    counter = 1

    while f"{base}{counter}" in taken_usernames:
        counter += 1

    return f"{base}{counter}"





# function for social login
async def handle_social_login(
    request: Request,
    email: str,
    name: str,
    provider: str,
    provider_id: str,
    db: AsyncSession
) -> tuple[dict, User]:
    
    logger.info(
        "Social login initiated",
        extra={"provider": provider, "email": email}
    )

    # Validate provider
    provider = provider.lower()
    
    if provider not in ALLOWED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported provider."
        )

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not returned by provider."
        )
    
    # get role id
    role_id = os.getenv("USERS_ROLE_ID")
    
    if not role_id:
        logger.error(
            "USERS_ROLE_ID environment variable missing"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User role configuration missing."
        )

    is_new_user = False

    try:
        # Find user by provider
        statement = select(User).where(User.provider == provider, User.provider_id == provider_id)
        result = await db.exec(statement)
        user = result.first()

        # Existing social account
        if user:
            logger.info(
                "Existing social account found",
                extra={"user_id": user.user_id, "provider": provider}
            )

        else:
            # Find user by email
            email_statement = select(User).where(User.email == email)
            email_result = await db.exec(email_statement)
            existing_email = email_result.first()

            # Link provider to existing account
            if existing_email:
                try:
                    existing_email.provider = provider
                    existing_email.provider_id = provider_id

                    db.add(existing_email)

                    await db.commit()
                    await db.refresh(existing_email)

                    user = existing_email

                    logger.info(
                        "Social provider linked",
                        extra={"user_id": user.user_id, "provider": provider}
                    )
                    
                except Exception:
                    await db.rollback()
                    logger.exception("Failed linking social provider")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Unable to link social account."
                    )

            # Create brand new user
            else:
                logger.info(
                    "Creating new social user",
                    extra={"provider": provider, "email": email}
                )

                username = await generate_unique_username(name.replace(" ", "_").lower(), db)
                
                slug = slugify(username) + "-workspace"

                try:
                    async with db.begin():  
                        new_user = User(
                            username=username,
                            email=email,
                            password_hash="",
                            provider=provider,
                            provider_id=provider_id,
                            country="Unknown",
                            city="Unknown",
                            role_id=role_id
                        )

                        db.add(new_user)
                        await db.flush()

                        # Create Personal Workspace
                        personal_tenant = Tenant(
                            name="private",
                            slug=slug,
                            owner_id=new_user.user_id
                        )

                        db.add(personal_tenant)
                        await db.flush()

                    await db.refresh(new_user)
                    await db.refresh(personal_tenant)

                    user = new_user
                    
                    is_new_user = True

                    logger.info(
                        "New social user created",
                        extra={
                            "user_id": new_user.user_id,
                            "tenant_id": str(personal_tenant.tenant_id),
                            "provider": provider
                        },
                    )

                except Exception:
                    await db.rollback()
                    logger.exception("Failed creating social user")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Unable to create account."
                    )

        # Fetch Personal Workspace
        tenant = await get_personal_tenant(user.user_id, db)

        if not tenant:
            logger.error(
                "Personal workspace not found",
                extra={"user_id": user.user_id}
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Personal workspace not found."
            )

        logger.info(
            "Social login successful",
            extra={"user_id": user.user_id, "provider": provider}
        )
        
        # generate token
        tokens = await generate_auth_tokens(user)
        
        # build audit-context
        audit_context = build_audit_context(request)
        
        # audit-log
        if audit_context is not None:
            run_background_task(
                create_auth_audit_log_safe(
                    create_auth_audit_log_bg,
                    action="social_login",
                    user_id=user.user_id,
                    metadata={"provider": provider, "is_new_user": is_new_user},
                    context=audit_context
                )
            )

        return {
            "user_id": user.user_id,
            "email": user.email,
            "tenant_id": tenant.tenant_id,
            "tenant_name": tenant.name,
            "tenant_type": tenant.type,
            "tokens": tokens,
            "is_new_user": is_new_user,
            "provider": provider
        }
        
    except HTTPException:
        raise

    except Exception:
        await db.rollback()
        logger.exception("Unexpected social login error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred."
        )