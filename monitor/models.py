from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any


class ThreatLevel(Enum):

    LOW = "LOW"

    MEDIUM = "MEDIUM"

    HIGH = "HIGH"

    CRITICAL = "CRITICAL"


# =========================================================
# Legacy Event Log
# =========================================================

@dataclass
class EventLog:

    event_type: str

    severity: ThreatLevel

    details: str

    timestamp: str = field(
        default_factory=lambda: (
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )
    )


# =========================================================
# Security Event Model
# =========================================================

@dataclass
class SecurityEvent:

    event_type: str

    severity: ThreatLevel

    path: str = ""

    payload: Dict[str, Any] = field(
        default_factory=dict
    )

    created_at: float = 0

    processed_at: float = 0

    alerted_at: float = 0