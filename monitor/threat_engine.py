"""
ATLAS threat engine.

Consumes events from the event bus, applies configurable rules from
monitor.rules, and dispatches alerts through AlertManager.
"""

import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional

from monitor import rules
from monitor.alert_manager import AlertManager
from monitor.models import ThreatLevel


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("ATLAS-ThreatEngine")


@dataclass
class SecurityEvent:
    event_type: str
    path: str
    timestamp: float
    payload: Dict


class ThreatEngine:
    """Rule-based detection engine for file, login, and process activity."""

    def __init__(self, alert_manager: Optional[AlertManager] = None):
        self.alert_manager = alert_manager or AlertManager()
        self.last_alert_time: Dict[str, float] = {}
        self.failed_login_attempts: Deque[Dict] = deque()
        self.recent_events: Deque[SecurityEvent] = deque()
        logger.info("Threat Engine Initialized")

    def process_event(self, event: Dict) -> None:
        """Validate and analyze a single event bus payload."""

        try:
            validated_event = self._validate_event(event)
            if not validated_event:
                return

            if validated_event.event_type in rules.PROCESS_EVENT_TYPES:
                self._analyze_process_event(validated_event)
                return

            self.recent_events.append(validated_event)
            self._cleanup_old_events()
            self._analyze_file_events()

        except Exception as error:
            logger.exception("Threat Engine Error: %s", error)

    def process_failed_login(self, username: str, source: str = "LOCAL") -> None:
        """Record and analyze failed login activity."""

        current_time = time.time()
        self.failed_login_attempts.append(
            {
                "username": username,
                "source": source,
                "timestamp": current_time,
            }
        )

        while self.failed_login_attempts:
            oldest_attempt = self.failed_login_attempts[0]
            if (
                current_time - oldest_attempt["timestamp"]
                > rules.FAILED_LOGIN_WINDOW_SECONDS
            ):
                self.failed_login_attempts.popleft()
            else:
                break

        recent_attempts = len(self.failed_login_attempts)
        if recent_attempts >= rules.FAILED_LOGIN_THRESHOLD:
            self._trigger_alert(
                rule_key="brute_force",
                cooldown_seconds=rules.BRUTE_FORCE_COOLDOWN_SECONDS,
                severity=ThreatLevel.HIGH,
                title="Possible Brute-Force Attack Detected",
                details=(
                    f"{recent_attempts} failed login attempts detected within "
                    f"{rules.FAILED_LOGIN_WINDOW_SECONDS} seconds"
                ),
            )

    def _validate_event(self, event: Dict) -> Optional[SecurityEvent]:
        if "type" not in event:
            logger.warning("Invalid Event Missing Key: type")
            return None

        event_type = event["type"]
        path = event.get("path") or event.get("process_name") or "UNKNOWN"
        timestamp = event.get("timestamp", time.time())

        return SecurityEvent(
            event_type=event_type,
            path=path,
            timestamp=timestamp,
            payload=event,
        )

    def _cleanup_old_events(self) -> None:
        current_time = time.time()
        max_window = max(
            rules.RENAME_TIME_WINDOW_SECONDS,
            rules.MODIFY_TIME_WINDOW_SECONDS,
            rules.DELETE_TIME_WINDOW_SECONDS,
        )

        while self.recent_events:
            oldest_event = self.recent_events[0]
            if current_time - oldest_event.timestamp > max_window:
                self.recent_events.popleft()
            else:
                break

    def _analyze_file_events(self) -> None:
        rename_count = self._count_events(
            event_type="FILE_RENAMED",
            window_seconds=rules.RENAME_TIME_WINDOW_SECONDS,
        )
        modify_count = self._count_events(
            event_type="FILE_MODIFIED",
            window_seconds=rules.MODIFY_TIME_WINDOW_SECONDS,
        )
        delete_count = self._count_events(
            event_type="FILE_DELETED",
            window_seconds=rules.DELETE_TIME_WINDOW_SECONDS,
        )

        if rename_count >= rules.MASS_RENAME_THRESHOLD:
            self._trigger_alert(
                rule_key="mass_rename",
                cooldown_seconds=rules.MASS_RENAME_COOLDOWN_SECONDS,
                severity=ThreatLevel.HIGH,
                title="Mass Rename Activity Detected",
                details=(
                    f"{rename_count} file rename operations detected within "
                    f"{rules.RENAME_TIME_WINDOW_SECONDS} seconds"
                ),
            )

        if modify_count >= rules.MASS_MODIFY_THRESHOLD:
            self._trigger_alert(
                rule_key="mass_modify",
                cooldown_seconds=rules.MASS_MODIFY_COOLDOWN_SECONDS,
                severity=ThreatLevel.HIGH,
                title="Mass File Modification Detected",
                details=(
                    f"{modify_count} file modifications detected within "
                    f"{rules.MODIFY_TIME_WINDOW_SECONDS} seconds"
                ),
            )

        if delete_count >= rules.MASS_DELETE_THRESHOLD:
            self._trigger_alert(
                rule_key="mass_delete",
                cooldown_seconds=rules.MASS_DELETE_COOLDOWN_SECONDS,
                severity=ThreatLevel.HIGH,
                title="Mass File Deletion Detected",
                details=(
                    f"{delete_count} file deletions detected within "
                    f"{rules.DELETE_TIME_WINDOW_SECONDS} seconds"
                ),
            )

        suspicious_event = self._latest_suspicious_extension_event()
        if suspicious_event:
            extension = self._matching_suspicious_extension(suspicious_event.path)
            self._trigger_alert(
                rule_key="suspicious_extension",
                cooldown_seconds=rules.SUSPICIOUS_EXTENSION_COOLDOWN_SECONDS,
                severity=ThreatLevel.CRITICAL,
                title="Suspicious Encryption Extension Detected",
                details=(
                    f"Possible ransomware encryption pattern identified: "
                    f"{suspicious_event.path}"
                ),
            )

    def _analyze_process_event(self, event: SecurityEvent) -> None:
        process_name = event.payload.get("process_name", event.path)
        normalized_name = process_name.lower()

        if normalized_name in rules.SAFE_PROCESSES:
            logger.debug("Safe process ignored: %s", process_name)
            return

        severity = rules.BLOCKED_PROCESSES.get(normalized_name)
        if not severity:
            logger.debug("Process observed without alert: %s", process_name)
            return

        pid = event.payload.get("pid", "UNKNOWN")
        self._trigger_alert(
            rule_key=f"blocked_process:{normalized_name}",
            cooldown_seconds=rules.PROCESS_ALERT_COOLDOWN_SECONDS,
            severity=severity,
            title="Blocked Process Detected",
            details=f"{process_name} detected with PID {pid}",
        )

    def _count_events(self, event_type: str, window_seconds: int) -> int:
        current_time = time.time()
        return sum(
            1
            for event in self.recent_events
            if event.event_type == event_type
            and current_time - event.timestamp <= window_seconds
        )

    def _latest_suspicious_extension_event(self) -> Optional[SecurityEvent]:
        for event in reversed(self.recent_events):
            if event.event_type == "FILE_RENAMED" and self._matching_suspicious_extension(
                event.path
            ):
                return event

        return None

    def _matching_suspicious_extension(self, path: str) -> Optional[str]:
        lowered_path = path.lower()
        for extension in rules.SUSPICIOUS_EXTENSIONS:
            if lowered_path.endswith(extension):
                return extension

        return None

    def _trigger_alert(
        self,
        rule_key: str,
        cooldown_seconds: int,
        severity: ThreatLevel,
        title: str,
        details: str,
    ) -> None:
        current_time = time.time()
        last_time = self.last_alert_time.get(rule_key, 0)

        if current_time - last_time < cooldown_seconds:
            logger.debug("Alert suppressed by cooldown: %s", rule_key)
            return

        self.last_alert_time[rule_key] = current_time
        logger.warning("[%s] %s | %s", severity.value, title, details)
        self.alert_manager.dispatch_alert(severity, title, details)


if __name__ == "__main__":
    engine = ThreatEngine()
    print("ATLAS Threat Engine Test Started...")

    for i in range(rules.MASS_RENAME_THRESHOLD):
        engine.process_event(
            {
                "type": "FILE_RENAMED",
                "path": f"victim_file_{i}.encrypted",
                "timestamp": time.time(),
            }
        )
