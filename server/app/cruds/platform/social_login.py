# import dependencies
from fastapi import APIRouter, Depends, HTTPException, Request, status
import os
from fastapi.responses import RedirectResponse, JSONResponse
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.services.platform.oauth import oauth, handle_social_login
from app.utility.platform.auth import set_auth_cookies





router = APIRouter(prefix="/v1/social_login/", tags=["Social_login"])




local_host=os.getenv("LOCAL_HOST")


# # shared helpers
# def build_redirect_url(result: dict) -> str:
#     return (
#         f"{settings.frontend_url}/auth/callback"
#         f"?is_new_user={str(result['is_new_user']).lower()}"
#         f"&track=b2c"
#     )





# function to normalize google user
def normalize_google_user(token: dict):
    user_info = token.get("userinfo")

    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google user info missing."
        )

    email = user_info.get("email")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google email scope missing."
        )

    name = user_info.get("name") or email.split("@")[0]
    provider_id = user_info.get("sub")

    return email, name, provider_id





# function to normalize github user
def normalize_github_user(profile: dict, emails: list):
    email = profile.get("email")

    if not email:
        for e in emails:
            if e.get("primary") and e.get("verified"):
                email = e.get("email")
                break

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub verified email not found."
        )

    name = profile.get("name") or profile.get("login", "")
    provider_id = str(profile.get("id"))

    return email, name, provider_id




# sign-up with google endpoint
@router.get("/google")
async def google_login(request: Request):
    redirect_uri = f"{local_host}/b2c/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)




@router.get("/google/callback")
async def google_callback(request: Request, db: AsyncSession = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)

        email, name, provider_id = normalize_google_user(token)

        result = await handle_social_login(
            email=email,
            name=name,
            provider="google",
            provider_id=provider_id,
            db=db
        )

        # response = RedirectResponse(url=build_redirect_url(result))
        
        response = JSONResponse(
            content={
                "message": "Authentication successful",
                "is_new_user": result["is_new_user"],
                "tenant_id": result["tenant_id"]
            }
        )
        
        set_auth_cookies(
            response=response,
            access_token=result["tokens"]["access_token"],
            refresh_token=result["tokens"]["refresh_token"]
        )

        return response

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google authentication failed."
        )





# sign-up with github endpoint
@router.get("/github")
async def github_login(request: Request):
    redirect_uri = f"{local_host}/v1/auth/github/callback"
    return await oauth.github.authorize_redirect(request, redirect_uri)




@router.get("/github/callback")
async def github_callback(request: Request, db: AsyncSession = Depends(get_db)):
    try:
        token = await oauth.github.authorize_access_token(request)

        profile_resp = await oauth.github.get("user", token=token)
        profile = profile_resp.json()

        emails_resp = await oauth.github.get("user/emails", token=token)
        emails = emails_resp.json()

        email, name, provider_id = normalize_github_user(profile, emails)

        result = await handle_social_login(
            email=email,
            name=name,
            provider="github",
            provider_id=provider_id,
            db=db
        )

        # response = RedirectResponse(url=build_redirect_url(result))
        
        response = JSONResponse(
            content={
                "message": "Authentication successful",
                "is_new_user": result["is_new_user"],
                "tenant_id": result["tenant_id"]
            }
        )

        
        set_auth_cookies(
            response=response,
            access_token=result["tokens"]["access_token"],
            refresh_token=result["tokens"]["refresh_token"]
        )

        return response

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub authentication failed."
        )





# api versions/google(mobile/spa)
@router.get("/google/callback/api")
async def google_callback_api(request: Request, db: AsyncSession = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)

        email, name, provider_id = normalize_google_user(token)

        return await handle_social_login(
            email=email,
            name=name,
            provider="google",
            provider_id=provider_id,
            db=db
        )

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google authentication failed."
        )





# api versions/github(mobile/spa)
@router.get("/github/callback/api")
async def github_callback_api(request: Request, db: AsyncSession = Depends(get_db)):
    try:
        token = await oauth.github.authorize_access_token(request)

        profile_resp = await oauth.github.get("user", token=token)
        profile = profile_resp.json()

        emails_resp = await oauth.github.get("user/emails", token=token)
        emails = emails_resp.json()

        email, name, provider_id = normalize_github_user(profile, emails)

        return await handle_social_login(
            email=email,
            name=name,
            provider="github",
            provider_id=provider_id,
            db=db
        )

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub authentication failed."
        )
