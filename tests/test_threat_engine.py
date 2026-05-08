import time
import unittest

from monitor import rules
from monitor.models import ThreatLevel
from monitor.threat_engine import ThreatEngine


class FakeAlertManager:
    def __init__(self):
        self.alerts = []

    def dispatch_alert(self, severity, title, details):
        self.alerts.append(
            {
                "severity": severity,
                "title": title,
                "details": details,
            }
        )


class ThreatEngineTests(unittest.TestCase):
    def make_engine(self):
        alert_manager = FakeAlertManager()
        return ThreatEngine(alert_manager=alert_manager), alert_manager

    def test_mass_delete_detection_uses_configured_threshold(self):
        engine, alert_manager = self.make_engine()

        for index in range(rules.MASS_DELETE_THRESHOLD):
            engine.process_event(
                {
                    "type": "FILE_DELETED",
                    "path": f"D:/ATLAS_TEST/file_{index}.txt",
                    "timestamp": time.time(),
                }
            )

        self.assertTrue(
            any(
                alert["title"] == "Mass File Deletion Detected"
                and alert["severity"] == ThreatLevel.HIGH
                for alert in alert_manager.alerts
            )
        )

    def test_mass_delete_alert_is_cooled_down(self):
        engine, alert_manager = self.make_engine()

        for index in range(rules.MASS_DELETE_THRESHOLD + 3):
            engine.process_event(
                {
                    "type": "FILE_DELETED",
                    "path": f"D:/ATLAS_TEST/file_{index}.txt",
                    "timestamp": time.time(),
                }
            )

        matching_alerts = [
            alert
            for alert in alert_manager.alerts
            if alert["title"] == "Mass File Deletion Detected"
        ]
        self.assertEqual(len(matching_alerts), 1)

    def test_blocked_process_generates_configured_severity(self):
        engine, alert_manager = self.make_engine()

        engine.process_event(
            {
                "type": "PROCESS_DETECTED",
                "process_name": "mimikatz.exe",
                "pid": 1234,
                "timestamp": time.time(),
            }
        )

        self.assertEqual(
            alert_manager.alerts,
            [
                {
                    "severity": ThreatLevel.CRITICAL,
                    "title": "Blocked Process Detected",
                    "details": "mimikatz.exe detected with PID 1234",
                }
            ],
        )

    def test_safe_process_is_ignored(self):
        engine, alert_manager = self.make_engine()

        engine.process_event(
            {
                "type": "PROCESS_DETECTED",
                "process_name": "chrome.exe",
                "pid": 1234,
                "timestamp": time.time(),
            }
        )

        self.assertEqual(alert_manager.alerts, [])


if __name__ == "__main__":
    unittest.main()
