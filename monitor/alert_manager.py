"""
ATLAS alert dispatch and response layer.
"""

from dataclasses import dataclass
from datetime import datetime

from config.logging_config import get_logger
from monitor.models import ThreatLevel

logger = get_logger("alerts")


@dataclass
class Alert:
    severity: ThreatLevel
    title: str
    details: str
    timestamp: str


class AlertManager:
    """Routes alerts by severity and owns user-facing alert output."""

    def __init__(self):
        logger.info("Alert Manager Initialized")

    def dispatch_alert(
        self,
        severity: ThreatLevel,
        title: str,
        details: str,
    ) -> None:
        alert = Alert(
            severity=severity,
            title=title,
            details=details,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        match severity:
            case ThreatLevel.LOW:
                self._handle_low(alert)
            case ThreatLevel.MEDIUM:
                self._handle_medium(alert)
            case ThreatLevel.HIGH:
                self._handle_high(alert)
            case ThreatLevel.CRITICAL:
                self._handle_critical(alert)

    def _handle_low(self, alert: Alert) -> None:
        logger.info("[LOW] %s | %s", alert.title, alert.details)

    def _handle_medium(self, alert: Alert) -> None:
        logger.warning("[MEDIUM] %s | %s", alert.title, alert.details)
        self._display_console_alert(alert)

    def _handle_high(self, alert: Alert) -> None:
        logger.error("[HIGH] %s | %s", alert.title, alert.details)
        self._display_console_alert(alert)

    def _handle_critical(self, alert: Alert) -> None:
        logger.critical("[CRITICAL] %s | %s", alert.title, alert.details)
        self._display_console_alert(alert)
        print("EMERGENCY RESPONSE ACTIVATED")

    def _display_console_alert(self, alert: Alert) -> None:
        print("\n" + "=" * 70)
        print(f"ATLAS SECURITY ALERT [{alert.severity.value}]")
        print("-" * 70)
        print(f"Time    : {alert.timestamp}")
        print(f"Threat  : {alert.title}")
        print(f"Details : {alert.details}")
        print("=" * 70 + "\n")


if __name__ == "__main__":
    manager = AlertManager()
    manager.dispatch_alert(
        severity=ThreatLevel.HIGH,
        title="Mass Rename Activity Detected",
        details="25 files renamed within 10 seconds",
    )
    manager.dispatch_alert(
        severity=ThreatLevel.CRITICAL,
        title="Ransomware Extension Detected",
        details=".encrypted extension identified",
    )
