# import dependencies
from fastapi import APIRouter, Depends, HTTPException
from app.schemas.tenant.admin_router import AcceptInvitationRequest
from app.models import User
from app.utility.platform.user import get_current_active_user 
from sqlmodel.ext.asyncio.session import AsyncSession
from app.utility.platform.database import get_db
from app.services.tenant.admin_router import accept_invitation_service, register_invited_member
from app.schemas.platform.users import UserCreate








# initialize router
router = APIRouter(prefix="/v1/register-Membership",  tags=["tenant-members"])




# endpoint to accept iv
@router.post("/invitations/accept")
async def accept_invitation(
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
@router.post("/auth/register/invited")
async def register_invited_user(
    user: UserCreate,
    token: str,
    db: AsyncSession = Depends(get_db)
):
    return await register_invited_member(
        user=user,
        token=token,
        db=db
    )