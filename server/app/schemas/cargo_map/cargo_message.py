# import dependencies
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, Literal
from uuid import UUID
from datetime import datetime





# cargo message create schema
class CargoMessageCreate(BaseModel):

    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=10000)
    idempotency_key: Optional[str] = Field(default=None, max_length=100)





# cargo message read schema
class CargoMessageRead(BaseModel):

    model_config = ConfigDict(from_attributes=True)
    
    message_id: int
    request_id: UUID
    role: Literal["user", "assistant"]
    content: str
    sequence_number: int
    message_metadata: Optional[dict] = None
    created_at: datetime





# cargo message update schema
class CargoMessageUpdate(BaseModel):

    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=4000)
