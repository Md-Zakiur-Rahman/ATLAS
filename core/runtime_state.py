"""
Centralized runtime state for ATLAS.

All major subsystems should update/read this singleton to keep backend,
auth, API, dashboard, ML, and response automation synchronized.
"""

from __future__ import annotations

import threading
import time
from copy import deepcopy
from typing import Any, Dict

from core.training_state import load_training_state


class RuntimeState:
    def __init__(self) -> None:
        training = load_training_state()
        self._lock = threading.RLock()
        self._state: Dict[str, Any] = {
            "current_user": None,
            "current_email": None,
            "authenticated": False,
            "auth_method": None,
            "last_auth_time": None,
            "vault_locked": False,
            "vault_state": {
                "last_folder": None,
                "keyfile_path": "vault.keyfile",
            },
            "current_threat_level": "LOW",
            "soc_state": "NORMAL",
            "threat_score": 0,
            "latest_anomaly_score": None,
            "monitor_states": {
                "file_monitor": False,
                "process_monitor": False,
                "usb_monitor": False,
                "feature_extractor": False,
                "network_monitor": False,
            },
            "api_status": "offline",
            "dashboard_status": "offline",
            "scheduler_status": "offline",
            "ml_status": {
                "trained": bool(training.get("is_initial_training_complete", False)),
                "initial_training_complete": bool(training.get("is_initial_training_complete", False)),
                "partial_model": False,
                "last_severity": "LOW",
                "critical_threshold": training.get("critical_threshold"),
                "high_threshold": training.get("high_threshold"),
                "medium_threshold": training.get("medium_threshold"),
            },
            "rollback_status": {
                "last_rollback_count": 0,
                "last_rollback_time": None,
            },
            "containment_state": {
                "active": False,
                "state": "IDLE",
                "attacked_folder": None,
                "attacking_process": None,
                "attacker_pid": None,
                "forensic_log": None,
                "backup_snapshot": None,
                "cooldown_ends_at": None,
                "recovery_options": None,
            },
            "active_alerts": [],
            "live_network_activity": [],
            "encryption_history": [],
            "connected_devices": [],
            "supabase_status": "unknown",
            "response_engine_subscribed": False,
            "failed_otp_attempts": 0,
            "failed_biometric_attempts": 0,
            "biometric_state": {
                "trusted_device": False,
                "pairing_state": "idle",
                "session_token": None,
                "expires_at": None,
            },
            "total_events": 0,
            "last_updated": time.time(),
        }

    def update(self, **fields: Any) -> None:
        with self._lock:
            self._state.update(fields)
            self._state["last_updated"] = time.time()

    def set_nested(self, key: str, value: Dict[str, Any]) -> None:
        with self._lock:
            current = self._state.get(key, {})
            if not isinstance(current, dict):
                current = {}
            current.update(value)
            self._state[key] = current
            self._state["last_updated"] = time.time()

    def add_alert(self, alert: Dict[str, Any], max_items: int = 50) -> None:
        with self._lock:
            alerts = self._state.get("active_alerts", [])
            alerts.insert(0, alert)
            self._state["active_alerts"] = alerts[:max_items]
            self._state["last_updated"] = time.time()

    def add_network_event(self, event: Dict[str, Any], max_items: int = 100) -> None:
        with self._lock:
            events = self._state.get("live_network_activity", [])
            events.insert(0, event)
            self._state["live_network_activity"] = events[:max_items]
            self._state["last_updated"] = time.time()

    def add_encryption_event(self, event: Dict[str, Any], max_items: int = 200) -> None:
        with self._lock:
            events = self._state.get("encryption_history", [])
            events.insert(0, event)
            self._state["encryption_history"] = events[:max_items]
            self._state["last_updated"] = time.time()

    def set_devices(self, devices: list[str]) -> None:
        with self._lock:
            self._state["connected_devices"] = list(devices)
            self._state["last_updated"] = time.time()

    def increment_total_events(self) -> None:
        with self._lock:
            self._state["total_events"] += 1
            self._state["last_updated"] = time.time()

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return deepcopy(self._state)


runtime_state = RuntimeState()
