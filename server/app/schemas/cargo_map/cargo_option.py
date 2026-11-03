# import dependencies
from datetime import date, datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict





# flight option create schema
class FlightOptionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rank: int = Field(gt=0)
    airline: str
    flight_no: str
    departure: str
    aircraft: str
    transit_hours: float = Field(ge=0)
    base_price_usd: float = Field(ge=0)
    est_price_usd: float = Field(ge=0)
    source: str = "cache"





# flight option read schema
class FlightOptionRead(FlightOptionCreate):
    model_config = ConfigDict(from_attributes=True)

    option_id: int
    request_id: UUID
    tenant_id: UUID
    status: str
    expires_at: datetime
