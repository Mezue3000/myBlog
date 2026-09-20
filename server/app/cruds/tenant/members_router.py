# import dependencies
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from app.rate_limit.limiter import limiter
from app.rate_limit.policy import AUTH_LIMITS
from app.rate_limit.keys import user_key_func
from app.schemas.tenant.admin_router import AcceptInvitationRequest
from app.models import User
from app.utility.platform.user import get_current_active_user 
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.services.tenant.members_router import accept_invitation_service, register_invited_member
from app.schemas.platform.users import UserCreate




# initialize router
router = APIRouter(prefix="/tenant-members",  tags=["Tenant Members"])




# endpoint to accept iv
@router.post("/invitations/accept", summary="Accept Invitation")

@limiter.limit(AUTH_LIMITS["ip"])
@limiter.limit(AUTH_LIMITS["accept_iv"], key_func=user_key_func)
async def accept_invitation(
    request: Request,
    response: Response,
    data: AcceptInvitationRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    return await accept_invitation_service(
        token=data.token,
        current_user=current_user,
        db=db
    )




# endpoint to register invited member
@router.post("/register/invited", summary="Register Invited User")

@limiter.limit(AUTH_LIMITS["ip"])
@limiter.limit(AUTH_LIMITS["register"], key_func=user_key_func)
async def register_invited_user(
    request: Request,
    response: Response,
    user: UserCreate,
    token: str,
    db: AsyncSession = Depends(get_db)
):
    return await register_invited_member(
        user=user,
        token=token,
        db=db
    )
