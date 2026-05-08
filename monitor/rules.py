"""
Central ATLAS detection and monitoring configuration.

Threat detection modules should import values from this file instead of
embedding thresholds, cooldowns, extensions, process names, or intervals.
"""

from monitor.models import ThreatLevel


# =========================================================
# Monitor Runtime
# =========================================================

DEFAULT_MONITOR_PATH = "D:/ATLAS_TEST"
FILE_MONITOR_RECURSIVE = True
FILE_MONITOR_STARTUP_DELAY_SECONDS = 1

PROCESS_SCAN_INTERVAL_SECONDS = 5


# =========================================================
# File Activity Windows
# =========================================================

RENAME_TIME_WINDOW_SECONDS = 10
MODIFY_TIME_WINDOW_SECONDS = 10
DELETE_TIME_WINDOW_SECONDS = 10


# =========================================================
# File Activity Thresholds
# =========================================================

MASS_RENAME_THRESHOLD = 15
MASS_MODIFY_THRESHOLD = 20
MASS_DELETE_THRESHOLD = 10


# =========================================================
# Brute Force Login Detection
# =========================================================

FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_SECONDS = 60


# =========================================================
# Alert Cooldowns
# =========================================================

MASS_RENAME_COOLDOWN_SECONDS = 10
MASS_MODIFY_COOLDOWN_SECONDS = 10
MASS_DELETE_COOLDOWN_SECONDS = 10
SUSPICIOUS_EXTENSION_COOLDOWN_SECONDS = 15
BRUTE_FORCE_COOLDOWN_SECONDS = 30
PROCESS_ALERT_COOLDOWN_SECONDS = 60


# =========================================================
# Suspicious Extensions
# =========================================================

SUSPICIOUS_EXTENSIONS = (
    ".encrypted",
    ".locked",
    ".crypt",
    ".enc",
    ".vault",
)


# =========================================================
# Process Rules
# =========================================================

SAFE_PROCESSES = (
    "chrome.exe",
    "code.exe",
    "explorer.exe",
)

BLOCKED_PROCESSES = {
    "mimikatz.exe": ThreatLevel.CRITICAL,
    "nc.exe": ThreatLevel.HIGH,
    "netcat.exe": ThreatLevel.HIGH,
    "powershell.exe": ThreatLevel.HIGH,
}

PROCESS_EVENT_TYPES = ("PROCESS_DETECTED",)


# =========================================================
# Backwards-Compatible Rules Mapping
# =========================================================

THREAT_RULES = {
    "time_window_seconds": max(
        RENAME_TIME_WINDOW_SECONDS,
        MODIFY_TIME_WINDOW_SECONDS,
        DELETE_TIME_WINDOW_SECONDS,
    ),
    "mass_rename_threshold": MASS_RENAME_THRESHOLD,
    "mass_modify_threshold": MASS_MODIFY_THRESHOLD,
    "mass_delete_threshold": MASS_DELETE_THRESHOLD,
    "failed_login_threshold": FAILED_LOGIN_THRESHOLD,
    "failed_login_window": FAILED_LOGIN_WINDOW_SECONDS,
    "critical_extensions": list(SUSPICIOUS_EXTENSIONS),
    "safe_processes": list(SAFE_PROCESSES),
    "blocked_processes": list(BLOCKED_PROCESSES.keys()),
    "process_scan_interval_seconds": PROCESS_SCAN_INTERVAL_SECONDS,
}
