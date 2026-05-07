"""
ATLAS Threat Engine
Adaptive Threat Level Assessment & Security System

Member B - Detection & Monitoring Layer

Features:
- Ransomware behavior detection
- Mass rename detection
- Mass modification detection
- Mass deletion detection
- Suspicious extension detection
- Threat severity classification
- Event window analysis
"""

import time
import logging
from collections import deque, Counter
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional
from monitor.rules import THREAT_RULES
# =========================================================
# Logging Configuration
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("ATLAS-ThreatEngine")


# =========================================================
# Threat Severity Levels
# =========================================================

class ThreatLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# =========================================================
# Event Data Model
# =========================================================

@dataclass
class FileEvent:
    event_type: str
    path: str
    timestamp: float


# =========================================================
# Threat Engine Configuration
# =========================================================




# =========================================================
# Threat Engine Class
# =========================================================

class ThreatEngine:

    def __init__(self):
        self.last_alert_time = {}
        self.failed_login_attempts = deque()
        self.recent_events = deque()

        logger.info("Threat Engine Initialized")

    # =====================================================
    # Public Event Entry Point
    # =====================================================

    def process_event(self, event: Dict):

        try:

            validated_event = self._validate_event(event)

            if not validated_event:
                return

            self.recent_events.append(validated_event)

            self._cleanup_old_events()

            self._analyze_events()

        except Exception as error:
            logger.error(f"Threat Engine Error: {error}")

    # =====================================================
    # Event Validation
    # =====================================================

    def _validate_event(self, event: Dict) -> Optional[FileEvent]:

        required_keys = ["type", "path"]

        for key in required_keys:
            if key not in event:
                logger.warning(f"Invalid Event Missing Key: {key}")
                return None

        return FileEvent(
            event_type=event["type"],
            path=event["path"],
            timestamp=time.time()
        )

    # =====================================================
    # Remove Expired Events
    # =====================================================

    def _cleanup_old_events(self):

        current_time = time.time()

        while self.recent_events:

            oldest_event = self.recent_events[0]

            if (
                current_time - oldest_event.timestamp
                > THREAT_RULES["time_window_seconds"]
            ):
                self.recent_events.popleft()

            else:
                break

    # =====================================================
    # Main Threat Analysis
    # =====================================================

    def _analyze_events(self):

        event_counter = Counter()

        suspicious_extension_detected = False

        for event in self.recent_events:

            event_counter[event.event_type] += 1

            # Detect ransomware-like extensions
            if event.event_type == "FILE_RENAMED":

                for ext in THREAT_RULES["critical_extensions"]:

                    if event.path.lower().endswith(ext):
                        suspicious_extension_detected = True

        rename_count = event_counter["FILE_RENAMED"]
        modify_count = event_counter["FILE_MODIFIED"]
        delete_count = event_counter["FILE_DELETED"]

        # =================================================
        # Detection Rules
        # =================================================

        # Rule 1 - Mass Rename Detection
        if rename_count >= THREAT_RULES["mass_rename_threshold"]:

            current_time = time.time()

            last_time = self.last_alert_time.get(
            "mass_rename",
            0
            )

    # 10 second cooldown
            if current_time - last_time > 10:

                self.last_alert_time["mass_rename"] = current_time

                self._trigger_alert(
                    severity=ThreatLevel.HIGH,
                    title="Mass Rename Activity Detected",
                    details=(
                    f"{rename_count} file rename operations "
                    f"detected within monitoring window"
                    )
                )

        # Rule 2 - Suspicious Extension Detection
        if suspicious_extension_detected:

            self._trigger_alert(
                severity=ThreatLevel.CRITICAL,
                title="Suspicious Encryption Extension Detected",
                details=(
                    "Possible ransomware encryption pattern "
                    "identified"
                )
            )

        # Rule 3 - Mass Modification Detection
        if modify_count >= THREAT_RULES["mass_modify_threshold"]:

            self._trigger_alert(
                severity=ThreatLevel.HIGH,
                title="Mass File Modification Detected",
                details=(
                    f"{modify_count} file modifications "
                    f"detected within monitoring window"
                )
            )

        # Rule 4 - Mass Deletion Detection
        if delete_count >= THREAT_RULES["mass_delete_threshold"]:

            self._trigger_alert(
                severity=ThreatLevel.HIGH,
                title="Mass File Deletion Detected",
                details=(
                    f"{delete_count} file deletions "
                    f"detected within monitoring window"
                )
            )

    # =====================================================
    # Alert Dispatcher
    # =====================================================

    def _trigger_alert(
        self,
        severity: ThreatLevel,
        title: str,
        details: str
    ):

        logger.warning(
            f"[{severity.value}] {title} | {details}"
        )

        print("\n" + "=" * 60)
        print(f"ATLAS SECURITY ALERT [{severity.value}]")
        print("-" * 60)
        print(f"Threat : {title}")
        print(f"Details: {details}")
        print("=" * 60 + "\n")

        # Future Integration:
        # - event_bus.publish()
        # - database logging
        # - GUI notifications
        # - vault lock trigger
        # - sound alerts
# =====================================================
# Brute Force Login Detection
# =====================================================

    def process_failed_login(
    self,
    username: str,
    source: str = "LOCAL"
    ):

        current_time = time.time()

        self.failed_login_attempts.append({
        "username": username,
        "source": source,
        "timestamp": current_time
        })

    # Remove old attempts
        while self.failed_login_attempts:

            oldest_attempt = self.failed_login_attempts[0]

            if (
            current_time - oldest_attempt["timestamp"]
            > THREAT_RULES["failed_login_window"]
            ):
                self.failed_login_attempts.popleft()

            else:
                break

        recent_attempts = len(self.failed_login_attempts)

    # Trigger brute-force detection
        if (
        recent_attempts
        >= THREAT_RULES["failed_login_threshold"]
        ):

            self._trigger_alert(
                severity=ThreatLevel.HIGH,
                title="Possible Brute-Force Attack Detected",
                details=(
                    f"{recent_attempts} failed login attempts "
                    f"detected within "
                    f"{THREAT_RULES['failed_login_window']} seconds"
                )
            )

# =========================================================
# Event Bus Integration
# =========================================================

from monitor.event_bus import event_bus




# =========================================================
# Standalone Test Mode
# =========================================================

if __name__ == "__main__":

    engine = ThreatEngine()

    print("ATLAS Threat Engine Test Started...\n")

"""
# Simulated ransomware attack
    for i in range(20):

        simulated_event = {
        "type": "FILE_RENAMED",
        "path": f"victim_file_{i}.encrypted"
        }

        engine.process_event(simulated_event)

        time.sleep(0.2)

# Simulate failed logins
    for i in range(6):

        engine.process_failed_login(
        username="admin"
        )

        time.sleep(1)
"""