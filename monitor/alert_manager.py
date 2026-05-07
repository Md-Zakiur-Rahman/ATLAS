"""
ATLAS Alert Manager
Adaptive Threat Level Assessment & Security System

Member B - Alert Dispatch & Response Layer
"""

import logging
from datetime import datetime
from enum import Enum
from dataclasses import dataclass


# =========================================================
# Logging Configuration
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("ATLAS-AlertManager")


# =========================================================
# Threat Severity Levels
# =========================================================

class ThreatLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# =========================================================
# Alert Data Model
# =========================================================

@dataclass
class Alert:

    severity: ThreatLevel
    title: str
    details: str
    timestamp: str


# =========================================================
# Alert Manager Class
# =========================================================

class AlertManager:

    def __init__(self):

        logger.info("Alert Manager Initialized")

    # =====================================================
    # Main Alert Dispatcher
    # =====================================================

    def dispatch_alert(
        self,
        severity: ThreatLevel,
        title: str,
        details: str
    ):

        alert = Alert(
            severity=severity,
            title=title,
            details=details,
            timestamp=datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        # Route alerts by severity
        match severity:

            case ThreatLevel.LOW:
                self._handle_low(alert)

            case ThreatLevel.MEDIUM:
                self._handle_medium(alert)

            case ThreatLevel.HIGH:
                self._handle_high(alert)

            case ThreatLevel.CRITICAL:
                self._handle_critical(alert)

    # =====================================================
    # LOW Severity Handler
    # =====================================================

    def _handle_low(self, alert: Alert):

        logger.info(
            f"[LOW] {alert.title} | {alert.details}"
        )

    # =====================================================
    # MEDIUM Severity Handler
    # =====================================================

    def _handle_medium(self, alert: Alert):

        logger.warning(
            f"[MEDIUM] {alert.title} | {alert.details}"
        )

        self._display_console_alert(alert)

    # =====================================================
    # HIGH Severity Handler
    # =====================================================

    def _handle_high(self, alert: Alert):

        logger.error(
            f"[HIGH] {alert.title} | {alert.details}"
        )

        self._display_console_alert(alert)

        # Future integrations:
        # self._send_to_dashboard(alert)
        # self._log_to_database(alert)

    # =====================================================
    # CRITICAL Severity Handler
    # =====================================================

    def _handle_critical(self, alert: Alert):

        logger.critical(
            f"[CRITICAL] {alert.title} | {alert.details}"
        )

        self._display_console_alert(alert)

        print("EMERGENCY RESPONSE ACTIVATED")

        # Future integrations:
        # self._lock_vault()
        # self._kill_suspicious_process()
        # self._trigger_alarm()

    # =====================================================
    # Console Alert Display
    # =====================================================

    def _display_console_alert(self, alert: Alert):

        print("\n" + "=" * 70)

        print(
            f"ATLAS SECURITY ALERT "
            f"[{alert.severity.value}]"
        )

        print("-" * 70)

        print(f"Time    : {alert.timestamp}")
        print(f"Threat  : {alert.title}")
        print(f"Details : {alert.details}")

        print("=" * 70 + "\n")


# =========================================================
# Standalone Test Mode
# =========================================================

if __name__ == "__main__":

    manager = AlertManager()

    manager.dispatch_alert(
        severity=ThreatLevel.HIGH,
        title="Mass Rename Activity Detected",
        details="25 files renamed within 10 seconds"
    )

    manager.dispatch_alert(
        severity=ThreatLevel.CRITICAL,
        title="Ransomware Extension Detected",
        details=".encrypted extension identified"
    )