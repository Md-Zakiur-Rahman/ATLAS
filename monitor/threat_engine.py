"""
ATLAS threat engine.

Consumes events from the event bus, applies configurable rules from
monitor.rules, and dispatches alerts through AlertManager.
"""
import os
import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional

from monitor import rules
from monitor.alert_manager import AlertManager
from monitor.models import ThreatLevel
from datetime import datetime
from monitor.event_bus import event_bus

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
        self.false_positive_counter = 0

        self.total_alerts = 0
        self.file_event_tracker = {}
        self.max_tracker_size = 5000
        self.threat_score = 0
        self.current_threat_level = "LOW"
        self.alert_manager = alert_manager or AlertManager()
        self.last_alert_time: Dict[str, float] = {}
        self.failed_login_attempts: Deque[Dict] = deque()
        self.recent_events: Deque[SecurityEvent] = deque(
    maxlen=1000
)
        logger.info("Threat Engine Initialized")

    def process_event(self,event: Dict) -> None:
    
    #Validate and analyze a single event bus payload.
    

        try:

            validated_event = (
                self._validate_event(event)
            )

            if not validated_event:
                return

            validated_event.processed_at = (
                time.time()
            )

            latency = (
                self._calculate_detection_latency(
                    validated_event
                )
            )

            logger.info(
                "Detection Latency: %.4f sec",
                latency
            )

            if self._is_duplicate_event(
                validated_event
            ):
                return

            if validated_event.event_type in (
                *rules.PROCESS_EVENT_TYPES,
                "USB_DEVICE_CONNECTED"
            ):

                self._analyze_system_event(
                    validated_event
                )

                return

            self.recent_events.append(
                validated_event
            )

            self._cleanup_old_events()

            self._analyze_file_events()

        except Exception as error:

            logger.exception(
                "Threat Engine Error: %s",
                error
            )

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
            self._update_threat_score("BRUTE_FORCE")
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

    def _validate_event(
        self,
        event: Dict
    ) -> Optional[SecurityEvent]:

        if "type" not in event:

            logger.warning(
                "Invalid Event Missing Key: type"
            )

            return None

        event_type = event["type"]

        path = (
            event.get("path")
            or event.get("process_name")
            or "UNKNOWN"
        )

        created_at = event.get(
            "created_at",
            time.time()
        )

        return SecurityEvent(
            event_type=event_type,
            severity=ThreatLevel.LOW,
            path=path,
            payload=event,
            created_at=created_at,
        )
    def _is_duplicate_event(
    self,
    event: SecurityEvent
) -> bool:
        """
    Prevent duplicate filesystem spam events.
    """

        if not rules.EVENT_DEDUPLICATION_ENABLED:
            return False

        key = (
        event.event_type,
        event.path
        )

        current_time = time.time()

        last_seen = self.file_event_tracker.get(
        key,
        0
        )

        if (
        current_time - last_seen
        < rules.DUPLICATE_EVENT_WINDOW_SECONDS
        ):
            return True
        if len(self.file_event_tracker) > self.max_tracker_size:

            oldest_key = next(
            iter(self.file_event_tracker)
            )

            del self.file_event_tracker[
            oldest_key
            ]
        self.file_event_tracker[key] = current_time

        return False

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
        
        filename = os.path.basename(
            event.path
        ).lower()

        sensitive_keywords_detected = any(
            keyword in filename
            for keyword in rules.HONEYPOT_KEYWORDS
        )

        if sensitive_keywords_detected:

            self._update_threat_score(
                "OFF_HOURS_ACTIVITY"
            )

            self._trigger_alert(
                rule_key="honeypot_behavior",
                cooldown_seconds=15,
                severity=ThreatLevel.HIGH,
                title="Sensitive File Targeting Detected",
                details=(
                    f"Suspicious interaction with "
                    f"sensitive-looking file: {filename}"
                ),
            )
        if self._is_off_hours_activity():

            self._update_threat_score(
            "OFF_HOURS_ACTIVITY"
            )

            self._trigger_alert(
            rule_key="off_hours_activity",
            cooldown_seconds=(
                rules.OFF_HOURS_ALERT_COOLDOWN_SECONDS
                ),
            severity=ThreatLevel.MEDIUM,
            title="Suspicious Off-Hours Activity",
            details=(
            "Unusual filesystem activity detected "
            "during off-hours"
            ),
        )
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
            self._update_threat_score("MASS_RENAME")
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
            self._update_threat_score("MASS_MODIFY")
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
            self._update_threat_score("MASS_DELETE")
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
            self._update_threat_score("SUSPICIOUS_EXTENSION")
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

    def _analyze_system_event(self, event: SecurityEvent) -> None:
        if event.event_type == "USB_DEVICE_CONNECTED":

            device = event.payload.get(
            "device",
            "UNKNOWN"
            )

            self._update_threat_score(
            "USB_DEVICE"
            )

            self._trigger_alert(
            rule_key="usb_device",
            cooldown_seconds=rules.USB_ALERT_COOLDOWN_SECONDS,
            severity=ThreatLevel.MEDIUM,
            title="USB / External Device Connected",
            details=f"New external device detected: {device}"
            )

            return
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
        self._update_threat_score("BLOCKED_PROCESS")
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

    def _is_duplicate_event(self, event: SecurityEvent) -> bool:
        """
        Simple duplicate suppression: return True when a recent identical event
        (same type and path) exists within a short time window.
        """

        now = time.time()
        # 1 second window for duplicate suppression
        dup_window = 1.0

        for recent in reversed(self.recent_events):
            if recent.event_type == event.event_type and recent.path == event.path:
                if abs(now - recent.timestamp) <= dup_window:
                    logger.debug(
                        "Duplicate event suppressed: %s %s",
                        event.event_type,
                        event.path,
                    )
                    return True

        return False

    def _matching_suspicious_extension(self, path: str) -> Optional[str]:
        lowered_path = path.lower()
        for extension in rules.SUSPICIOUS_EXTENSIONS:
            if lowered_path.endswith(extension):
                return extension

        return None
    def _update_threat_score(self, threat_type: str) -> None:
        """
    Increase global threat score based on detected threat type.
    """

        score = rules.THREAT_SCORES.get(
        threat_type,
        0
        )

        self.threat_score += score
        self.threat_score = min(
        self.threat_score,
        100
        )

        self.current_threat_level = (
        self._calculate_threat_level()
        )

        logger.warning(
        "Threat Score Updated: %s | Level: %s",
        self.threat_score,
        self.current_threat_level
        )
        event_bus.publish(
        {
        "type": "DASHBOARD_UPDATE",
        "threat_score": self.threat_score,
        "threat_level": self.current_threat_level,
        "timestamp": time.time(),
        }
)


    def _calculate_threat_level(self) -> str:
        """
    Determine overall threat level from score.
    """

        thresholds = rules.THREAT_LEVEL_THRESHOLDS

        if self.threat_score >= thresholds["CRITICAL"]:
            return "CRITICAL"

        if self.threat_score >= thresholds["HIGH"]:
            return "HIGH"

        if self.threat_score >= thresholds["MEDIUM"]:
            return "MEDIUM"

        return "LOW"
    
    def _calculate_detection_latency(
        self,
        event: SecurityEvent
    ) -> float:
            """
        Calculate event processing latency.
        """

            return (
            event.processed_at
            - event.created_at
        )
    
    def _verify_false_positive(self,threat_score: int) -> bool:
        """
    Determine whether activity
    is likely a false positive.
    """

        if (
        threat_score
        < rules.FALSE_POSITIVE_SCORE_THRESHOLD
        ):

            self.false_positive_counter += 1

            logger.warning(
            "Potential False Positive Detected"
            )

            return True

        return False

    def _is_off_hours_activity(self) -> bool:
        """
    Detect suspicious activity during off-hours.
    """

        current_hour = datetime.now().hour

        return (
        rules.OFF_HOURS_START
        <= current_hour
        < rules.OFF_HOURS_END
        )


    def _trigger_alert(
        self,
        rule_key: str,
        cooldown_seconds: int,
        severity: ThreatLevel,
        title: str,
        details: str,
    ) -> None:

        current_time = time.time()

        last_time = self.last_alert_time.get(
            rule_key,
            0
        )

        if (
            current_time - last_time
            < cooldown_seconds
        ):

            logger.debug(
                "Alert suppressed by cooldown: %s",
                rule_key
            )

            return

        self.last_alert_time[
            rule_key
        ] = current_time

        self.total_alerts += 1

        self._verify_false_positive(
            self.threat_score
        )

        logger.warning(
            "[%s] %s | %s",
            severity.value,
            title,
            details
        )

        self.alert_manager.dispatch_alert(
            severity,
            title,
            details
        )


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
