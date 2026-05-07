"""
ATLAS Threat Rules Configuration
"""

THREAT_RULES = {

    # =========================================
    # General Monitoring
    # =========================================

    "time_window_seconds": 10,

    # =========================================
    # Ransomware Detection
    # =========================================

    "mass_rename_threshold": 15,
    "mass_modify_threshold": 20,
    "mass_delete_threshold": 10,

    # =========================================
    # Brute Force Detection
    # =========================================

    "failed_login_threshold": 5,
    "failed_login_window": 60,

    # =========================================
    # Suspicious Extensions
    # =========================================

    "critical_extensions": [
        ".encrypted",
        ".locked",
        ".crypt",
        ".enc",
        ".vault"
    ]
}