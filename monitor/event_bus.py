"""
ATLAS Event Bus
Adaptive Threat Level Assessment & Security System

Member B - Thread-Safe Event Communication Layer
"""

import logging
from queue import Queue
from threading import Lock
from typing import Callable, Dict, List


# =========================================================
# Logging Configuration
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("ATLAS-EventBus")


# =========================================================
# Event Bus Class
# =========================================================

class EventBus:

    def __init__(self):

        # Thread-safe event queue
        self.event_queue = Queue()

        # Registered listeners/subscribers
        self.subscribers: List[Callable] = []

        # Thread lock for subscriber safety
        self.lock = Lock()

        logger.info("Event Bus Initialized")

    # =====================================================
    # Subscribe Method
    # =====================================================

    def subscribe(self, callback: Callable):

        with self.lock:

            self.subscribers.append(callback)

            logger.info(
                f"Subscriber Registered: "
                f"{callback.__name__}"
            )

    # =====================================================
    # Publish Event
    # =====================================================

    def publish(self, event: Dict):

        self.event_queue.put(event)

        logger.info(
            f"Event Published: "
            f"{event.get('type', 'UNKNOWN')}"
        )

        self._notify_subscribers(event)

    # =====================================================
    # Notify All Subscribers
    # =====================================================

    def _notify_subscribers(self, event: Dict):

        with self.lock:

            for subscriber in self.subscribers:

                try:
                    subscriber(event)

                except Exception as error:

                    logger.error(
                        f"Subscriber Error "
                        f"({subscriber.__name__}): {error}"
                    )

    # =====================================================
    # Retrieve Event From Queue
    # =====================================================

    def get_event(self):

        if not self.event_queue.empty():

            return self.event_queue.get()

        return None


# =========================================================
# Global Shared Event Bus Instance
# =========================================================

event_bus = EventBus()


# =========================================================
# Standalone Testing
# =========================================================

if __name__ == "__main__":

    # Test Subscriber
    def test_listener(event):

        print(
            f"Received Event -> {event}"
        )

    # Subscribe listener
    event_bus.subscribe(test_listener)

    # Publish sample event
    sample_event = {
        "type": "FILE_MODIFIED",
        "path": "D:/test/sample.txt"
    }

    event_bus.publish(sample_event)