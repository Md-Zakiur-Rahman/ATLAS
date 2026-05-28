"""
Thread-safe ATLAS event bus.

The bus provides synchronous fan-out to subscribers while also retaining a
queue of published events for future consumers such as GUI listeners, database
logging, response engines, and ML detectors.
"""
from queue import Empty, Queue
from threading import Lock, RLock
from typing import Callable, Dict, List

from config.logging_config import get_logger

logger = get_logger("events")


class EventBus:
    """Thread-safe publisher/subscriber event bus."""

    def __init__(self):
        self.event_queue = Queue()
        self._subscribers: List[Callable[[Dict], None]] = []
        self._subscriber_lock = Lock()
        self._publish_lock = RLock()
        logger.info("Event Bus Initialized")

    def subscribe(self, callback: Callable[[Dict], None]) -> None:
        """Register a callback without racing other publishers/subscribers."""

        with self._subscriber_lock:
            if callback in self._subscribers:
                logger.debug("Subscriber already registered: %s", callback.__name__)
                return

            self._subscribers.append(callback)

        logger.info("Subscriber Registered: %s", callback.__name__)

    def unsubscribe(self, callback: Callable[[Dict], None]) -> None:
        """Remove a callback if it is currently registered."""

        with self._subscriber_lock:
            if callback not in self._subscribers:
                return

            self._subscribers.remove(callback)

        logger.info("Subscriber Removed: %s", callback.__name__)

    def publish(self, event: Dict) -> None:
        """Publish an event and notify a stable subscriber snapshot."""

        self.event_queue.put(event)
        event_type = event.get("event_type", "UNKNOWN")
        if event_type == "PROCESS_DETECTED":
            logger.debug("Event Published: %s", event_type)
        else:
            logger.info("Event Published: %s", event_type)

        with self._publish_lock:
            with self._subscriber_lock:
                subscribers_snapshot = tuple(self._subscribers)

            for subscriber in subscribers_snapshot:
                try:
                    subscriber(event)
                except Exception as error:
                    logger.exception(
                        "Subscriber Error (%s): %s",
                        getattr(subscriber, "__name__", repr(subscriber)),
                        error,
                    )

    def get_event(self):
        """Return the next queued event, or None when the queue is empty."""

        try:
            return self.event_queue.get_nowait()
        except Empty:
            return None


event_bus = EventBus()


if __name__ == "__main__":
    def test_listener(event):
        print(f"Received Event -> {event}")

    event_bus.subscribe(test_listener)
    event_bus.publish(
        {
            "event_type": "FILE_MODIFIED",
            "path": "D:/test/sample.txt",
        }
    )
