# import dependencies
from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field





# booking create schema
class CargoBookingCreate(BaseModel):

    model_config = ConfigDict(extra="forbid")

    request_id: UUID
    selected_option_id: int
    human_choice: int = Field(default=0, ge=0, le=3)
    
    
    
    

# booking read schema
class CargoBookingRead(BaseModel):

    model_config = ConfigDict(from_attributes=True)

    booking_id: int
    request_id: UUID
    tenant_id: UUID
    selected_option_id: int
    awb: str
    status: str
    human_choice: int
    created_at: datetime
