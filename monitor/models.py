from enum import Enum
from dataclasses import dataclass
from datetime import datetime


class ThreatLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class EventLog:
    event_type: str
    severity: ThreatLevel
    details: str
    timestamp: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")