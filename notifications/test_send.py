"""
ATLAS Notification Test Sender

Usage:
    python notifications/test_send.py --email zakiurrahman540@gmail.com
"""

import argparse
import logging
import time
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.session import session
from monitor.event_bus import event_bus
from monitor.response_engine import response_engine
from notifications import notification_manager


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("ATLAS-NotificationTest")


def publish_test_events(email: str) -> None:
    # Ensure both managers are loaded and subscribed.
    _ = response_engine
    _ = notification_manager

    session.set_user(email)
    logger.info("Session set for notification test: %s", email)

    events = [
        {
            "type": "OTP_SENT",
            "email": email,
            "timestamp": time.time(),
        },
        {
            "type": "AUTH_SUCCESS",
            "email": email,
            "timestamp": time.time(),
        },
        {
            "type": "AUTH_FAIL",
            "email": email,
            "reason": "TEST_INVALID_OTP",
            "timestamp": time.time(),
        },
        {
            "type": "AUTH_BRUTE_FORCE",
            "email": email,
            "reason": "TEST_BRUTE_FORCE",
            "severity": "CRITICAL",
            "timestamp": time.time(),
        },
        {
            "type": "ML_ANOMALY",
            "email": email,
            "score": -0.82,
            "severity": "HIGH",
            "feature_vector": [0.0] * 8,
            "prediction": -1,
            "timestamp": time.time(),
        },
        {
            "type": "ML_ANOMALY",
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
        logger.info("Publishing test event %d/%d: %s", index, len(events), event["type"])
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
