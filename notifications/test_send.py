"""
ATLAS Notification Test Sender

Usage:
    python notifications/test_send.py --email zakiurrahman540@gmail.com
"""

import argparse
import time
import sys
from pathlib import Path

from config.logging_config import get_logger

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.session import session
from monitor.event_bus import event_bus
from monitor.response_engine import response_engine
from notifications import notification_manager

logger = get_logger("test")


def publish_test_events(email: str) -> None:
    # Ensure both managers are loaded and subscribed.
    _ = response_engine
    _ = notification_manager

    session.set_user(email)
    logger.info("Session set for notification test: %s", email)

    events = [
        {
            "event_type": "OTP_SENT", # Changed 'type' to 'event_type'
            "email": email,
            "timestamp": time.time(),
        },
        {
            "event_type": "AUTH_SUCCESS", # Changed 'type' to 'event_type'
            "email": email,
            "timestamp": time.time(),
        },
        {
            "event_type": "AUTH_FAIL", # Changed 'type' to 'event_type'
            "email": email,
            "reason": "TEST_INVALID_OTP",
            "timestamp": time.time(),
        },
        {
            "event_type": "AUTH_BRUTE_FORCE", # Changed 'type' to 'event_type'
            "email": email,
            "reason": "TEST_BRUTE_FORCE",
            "severity": "CRITICAL",
            "timestamp": time.time(),
        },
        {
            "event_type": "ML_ANOMALY", # Changed 'type' to 'event_type'
            "email": email,
            "score": -0.82,
            "severity": "HIGH",
            "feature_vector": [0.0] * 8,
            "prediction": -1,
            "timestamp": time.time(),
        },
        {
            "event_type": "ML_ANOMALY", # Changed 'type' to 'event_type'
            "email": email,
            "score": -0.95,
            "severity": "CRITICAL",
            "feature_vector": [0.0] * 8,
            "prediction": -1,
            "attacker_ip": "203.0.113.10",
            "timestamp": time.time(),
        },
    ]

    for index, event in enumerate(events, start=1):
        logger.info("Publishing test event %d/%d: %s", index, len(events), event["event_type"])
        event_bus.publish(event)
        time.sleep(1)

    logger.info("Notification security test flow completed.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--email",
        required=True,
        help="Recipient email used for session-bound alert tests",
    )
    args = parser.parse_args()

    publish_test_events(args.email)


if __name__ == "__main__":
    main()
