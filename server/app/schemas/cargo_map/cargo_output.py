# import schema
from pydantic import BaseModel, ConfigDict, Field, model_validator
from app.schemas.cargo_map.cargo_input import CargoIntakeInput
from datetime import date, datetime
from typing import List, Literal, Optional
from uuid import UUID





# cargo ouput schema
class CargoIntakeOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cargo: CargoIntakeInput

    # weight information
    volumetric_weight: Optional[float] = Field(default=None, ge=0)

    # intake flags
    has_dims: bool = False
    is_volumetric_estimated: bool = False
    needs_dims_confirmation: bool = False

    # intake workflow
    ready_for_validation: bool = False
    missing_fields: List[str] = Field(default_factory=list)
    next_question: Optional[str] = None

    @model_validator(mode="after")
    def validate_intake(self):
        dimensions = [
            self.cargo.length,
            self.cargo.width,
            self.cargo.height
        ]

        supplied_dimensions = sum(
            value is not None
            for value in dimensions
        )

        # dimensions must be complete
        if supplied_dimensions not in (0, 3):
            raise ValueError(
                "Length, width and height must be "
                "provided together."
            )

        # dimension flag must match extracted dimensions
        if self.has_dims != (supplied_dimensions == 3):
            raise ValueError(
                "has_dims does not match the supplied dimensions."
            )

        # cannot have actual and estimated dimensions simultaneously
        if self.is_volumetric_estimated and self.has_dims:
            raise ValueError(
                "Estimated dimensions cannot be marked "
                "as actual dimensions."
            )

        if (
            self.is_volumetric_estimated
            and not self.needs_dims_confirmation
        ):
            raise ValueError(
                "Estimated dimensions require confirmation."
            )

        # readiness requirements from ALGO 1
        required_fields_present = all([
            self.cargo.origin,
            self.cargo.dest,
            self.cargo.actual_weight is not None,
            self.cargo.commodity
        ])

        if self.ready_for_validation != required_fields_present:
            raise ValueError(
                "ready_for_validation must reflect "
                "the required intake fields."
            )

        return self












