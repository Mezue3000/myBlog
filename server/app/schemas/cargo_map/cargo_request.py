# import dependencies
from datetime import datetime, date
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict





# cargo request read schema
class CargoRequestRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    request_id: UUID
    tenant_id: UUID 

    origin: Optional[str] = None
    dest: Optional[str] = None

    actual_weight: Optional[float] = None
    pieces: Optional[int] = None

    length: Optional[float] = None
    width: Optional[float] = None
    height: Optional[float] = None

    commodity: Optional[str] = None

    flight_date: Optional[date] = None

    volumetric_weight: Optional[float] = None
    chargeable_weight: Optional[float] = None

    has_dims: bool
    is_volumetric_estimated: bool
    needs_dims_confirmation: bool

    status: str

    created_at: datetime