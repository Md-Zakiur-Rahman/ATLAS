from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any
from dataclasses import dataclass, field
import time

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

    path: str = ""

    timestamp: float = field(default_factory=time.time)

    payload: dict = field(default_factory=dict)

    severity: str = "LOW"

    created_at: float = field(default_factory=time.time)

    processed_at: float = 0.0
    