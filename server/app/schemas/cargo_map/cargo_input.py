# import dependencies
from datetime import date
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict





# cargo input schema
class CargoIntakeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # route information
    origin: Optional[str] = Field(default=None, max_length=100)
    dest: Optional[str] = Field(default=None, max_length=100)

    # cargo information
    actual_weight: Optional[float] = Field(default=None, gt=0)
    pieces: Optional[int] = Field(default=None, gt=0)

    # dimensions(cm)
    length: Optional[float] = Field(default=None, gt=0)
    width: Optional[float] = Field(default=None, gt=0)
    height: Optional[float] = Field(default=None, gt=0)

    # commodity classification
    commodity: Optional[str] = Field(default=None, max_length=50)

    # flight date
    flight_date: Optional[date] = None
