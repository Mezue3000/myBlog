# import dependencies
from datetime import datetime
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict





# cache create schema
class FlightCacheCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cache_id: int
    route: str
    data: List[dict] = Field(default_factory=list)
    expires_at: datetime





# cache read schema
class FlightCacheRead(FlightCacheCreate):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: UUID 
    created_at: datetime