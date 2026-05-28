"""
Event bus -> runtime state synchronizer.
"""

from __future__ import annotations

import time
from typing import Any, Dict

from core.runtime_state import runtime_state
from monitor.event_bus import event_bus
from monitor.rename_log import rename_log


class RuntimeSync:
    def __init__(self) -> None:
        event_bus.subscribe(self.process_event)

    def process_event(self, event: Dict[str, Any]) -> None:
        event_type = event.get("event_type", "UNKNOWN")
        runtime_state.increment_total_events()

        severity = event.get("severity")
        if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            runtime_state.update(current_threat_level=severity)

        if event_type == "ML_ANOMALY":
            runtime_state.update(
                latest_anomaly_score=event.get("score"),
            )
            runtime_state.set_nested("ml_status", {"last_severity": event.get("severity", "LOW")})
            runtime_state.add_alert(
                {
                    "type": event_type,
                    "severity": event.get("severity", "LOW"), # This 'type' is for the alert dictionary, not the event bus.
                    "score": event.get("score"),
                    "timestamp": event.get("timestamp", time.time()),
                }
            )
            return

        if event_type == "ML_STATUS":
            runtime_state.set_nested(
                "ml_status",
                {
                    "trained": bool(event.get("trained")),
                    "partial_model": bool(event.get("partial")),
                    "initial_training_complete": bool(event.get("trained")),
                },
            )
            return

        if event_type == "DASHBOARD_UPDATE":
            runtime_state.update(
                current_threat_level=event.get("threat_level", "LOW"),
                soc_state=event.get("soc_state", "NORMAL"),
                threat_score=event.get("threat_score", 0),
            )
            return

        if event_type == "NETWORK_CONNECTION":
            runtime_state.add_network_event(
                {
                    "ip": event.get("remote_ip"),
                    "port": event.get("remote_port"),
                    "process": event.get("process_name"),
                    "suspicious": bool(event.get("suspicious")),
                    "city": event.get("city"),
                    "country": event.get("country"),
                    "timestamp": event.get("timestamp", time.time()),
                }
            )
            return

        if event_type == "USB_DEVICE_CONNECTED":
            snapshot = runtime_state.snapshot()
            devices = set(snapshot.get("connected_devices", []))
            device = event.get("device")
            if device:
                devices.add(device)
                runtime_state.set_devices(sorted(devices))
            return

        if event_type == "VAULT_LOCKED":
            runtime_state.update(vault_locked=True)
            runtime_state.add_alert(
                {
                    "type": "VAULT_LOCKED", # This 'type' is for the alert dictionary, not the event bus.
                    "severity": event.get("severity", "CRITICAL"),
                    "reason": event.get("reason"),
                    "timestamp": event.get("timestamp", time.time()),
                }
            )
            return

        if event_type == "VAULT_UNLOCKED":
            runtime_state.update(vault_locked=False)
            runtime_state.add_alert(
                {
                    "type": "VAULT_UNLOCKED", # This 'type' is for the alert dictionary, not the event bus.
                    "severity": event.get("severity", "LOW"),
                    "reason": event.get("reason"),
                    "timestamp": event.get("timestamp", time.time()),
                }
            )
            return

        if event_type == "AUTH_SUCCESS":
            email = event.get("email")
            runtime_state.update(
                current_user=email,
                current_email=email,
                authenticated=True,
                auth_method=event.get("auth_method", "otp"),
                failed_otp_attempts=0,
                failed_biometric_attempts=0,
                vault_locked=False,
            )
            return

        if event_type == "AUTH_FAIL":
            snapshot = runtime_state.snapshot()
            runtime_state.update(
                failed_otp_attempts=snapshot.get("failed_otp_attempts", 0) + 1
            )
            return

        if event_type == "AUTH_BRUTE_FORCE":
            runtime_state.update(vault_locked=True)
            return

        if event_type == "SESSION_CREATED":
            email = event.get("email")
            runtime_state.update(current_user=email, current_email=email)
            return

        if event_type == "SESSION_DESTROYED":
            runtime_state.update(
                current_user=None,
                current_email=None,
                authenticated=False,
                auth_method=None,
            )
            return

        if event_type in {"CRITICAL_NETWORK", "ML_HIGH_ALERT", "RATE_LIMIT_EXCEEDED"}:
            runtime_state.add_alert(
                {
                    "type": event_type,
                    "severity": event.get("severity", "HIGH"), # This 'type' is for the alert dictionary, not the event bus.
                    "timestamp": event.get("timestamp", time.time()),
                    "details": event,
                }
            )
            return

        if event_type == "ROLLBACK_COMPLETED":
            runtime_state.set_nested(
                "rollback_status",
                {
                    "last_rollback_count": rename_log.last_rollback_count,
                    "last_rollback_time": time.time(),
                },
            )
            return

        if event_type == "TARGETED_CONTAINMENT":
            runtime_state.set_nested(
                "containment_state",
                {
                    "active": True,
                    "state": "CONTAINED",
                    "attacked_folder": event.get("attacked_folder"),
                    "attacking_process": event.get("attacking_process"),
                    "attacker_pid": event.get("attacker_pid"),
                    "forensic_log": event.get("forensic_log"),
                    "cooldown_ends_at": event.get("cooldown_ends_at"),
                },
            )
            runtime_state.add_alert(
                {
                    "type": event_type,
                    "severity": event.get("severity", "CRITICAL"),
                    "timestamp": event.get("timestamp", time.time()),
                    "details": event,
                }
            )
            return

        if event_type == "CONTAINMENT_RECOVERED":
            runtime_state.set_nested(
                "containment_state",
                {
                    "active": False,
                    "state": "RECOVERED",
                    "attacked_folder": event.get("attacked_folder"),
                },
            )


runtime_sync = RuntimeSync()
