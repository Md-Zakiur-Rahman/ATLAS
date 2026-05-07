from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from time import sleep
import time
import logging

from monitor.event_bus import event_bus
from monitor.models import EventLog, ThreatLevel


# =========================================================
# Logging Configuration
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("ATLAS-FileMonitor")


# =========================================================
# File Monitor Event Handler
# =========================================================

class FileMonitorHandler(FileSystemEventHandler):

    # -----------------------------------------------------
    # File Created
    # -----------------------------------------------------

    def on_created(self, event):

        if event.is_directory:
            return

        log = EventLog(
            event_type="FILE_CREATED",
            severity=ThreatLevel.LOW,
            details=event.src_path
        )

        event_data = {
            "type": "FILE_CREATED",
            "path": event.src_path,
            "timestamp": time.time()
        }

        event_bus.publish(event_data)

        logger.info(
            f"File Created: {event.src_path}"
        )

    # -----------------------------------------------------
    # File Deleted
    # -----------------------------------------------------

    def on_deleted(self, event):

        if event.is_directory:
            return

        log = EventLog(
            event_type="FILE_DELETED",
            severity=ThreatLevel.MEDIUM,
            details=event.src_path
        )

        event_data = {
            "type": "FILE_DELETED",
            "path": event.src_path,
            "timestamp": time.time()
        }

        event_bus.publish(event_data)

        logger.warning(
            f"File Deleted: {event.src_path}"
        )

    # -----------------------------------------------------
    # File Modified
    # -----------------------------------------------------

    def on_modified(self, event):

        if event.is_directory:
            return

        log = EventLog(
            event_type="FILE_MODIFIED",
            severity=ThreatLevel.LOW,
            details=event.src_path
        )

        event_data = {
            "type": "FILE_MODIFIED",
            "path": event.src_path,
            "timestamp": time.time()
        }

        event_bus.publish(event_data)

        logger.info(
            f"File Modified: {event.src_path}"
        )

    # -----------------------------------------------------
    # File Renamed / Moved
    # -----------------------------------------------------

    def on_moved(self, event):

        if event.is_directory:
            return

        log = EventLog(
            event_type="FILE_RENAMED",
            severity=ThreatLevel.HIGH,
            details=(
                f"{event.src_path} -> "
                f"{event.dest_path}"
            )
        )

        event_data = {
            "type": "FILE_RENAMED",
            "path": event.dest_path,
            "old_path": event.src_path,
            "timestamp": time.time()
        }

        event_bus.publish(event_data)

        logger.warning(
            f"File Renamed: "
            f"{event.src_path} -> {event.dest_path}"
        )


# =========================================================
# File Monitor Startup
# =========================================================

observer = Observer()

def start_monitor(path_to_watch="D:/ATLAS_TEST"):

    global observer

    handler = FileMonitorHandler()

    observer.schedule(
        handler,
        path=path_to_watch,
        recursive=True
    )

    observer.start()

    logger.info(
        f"Monitoring Started On: {path_to_watch}"
    )


def stop_monitor():

    global observer

    observer.stop()

    observer.join()

    logger.info("Monitoring Stopped")


# =========================================================
# Standalone Execution
# =========================================================

if __name__ == "__main__":

    start_monitor()

    try:

        while True:
            sleep(1)

    except KeyboardInterrupt:

        stop_monitor()