"""
Stub for alert_manager integration.
Member B will replace the actual dispatch once alert_manager.py is complete.
Your code imports from here — swap the implementation on Day 4/5.
"""
import time

_alert_log = []

def dispatch_alert(alert: dict) -> None:
    """
    Accepts an alert dict with keys: type, severity, message, timestamp.
    Logs it locally until Member B's alert_manager is wired in.
    """
    _alert_log.append(alert)
    severity = alert.get("severity", "UNKNOWN")
    message = alert.get("message", "No message")
    print(f"[ALERT][{severity}] {message}")

    # When Member B is ready, replace the line above with:
    # from monitor.alert_manager import dispatch as real_dispatch
    # real_dispatch(alert)

def get_alert_log() -> list:
    return list(_alert_log)

def clear_log() -> None:
    _alert_log.clear()