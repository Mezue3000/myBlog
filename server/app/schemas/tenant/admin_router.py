# import dependencies
from sqlmodel import SQLModel
from pydantic import EmailStr



# create invite schema
class InviteMembersRequest(SQLModel):
    emails: list[EmailStr]




# create accept iv schema
class AcceptInvitationRequest(SQLModel):
    token: str