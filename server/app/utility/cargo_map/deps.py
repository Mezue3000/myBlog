from dataclasses import dataclass
from uuid import UUID
from typing import Any




# define agent dependency
@dataclass
class AgentDeps:

    request_id: UUID
    cargo_snapshot: dict[str, Any]

    required_fields: tuple[str, ...] = (
        "origin",
        "dest",
        "actual_weight",
        "commodity"
    )

    optional_fields: tuple[str, ...] = (
        "pieces",
        "dimensions",
        "flight_date"
    )
