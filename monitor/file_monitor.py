from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path
from time import sleep
import time
import os
import math
import psutil
from config.logging_config import get_logger
from monitor import rules
from monitor.event_bus import event_bus
from monitor.models import EventLog, ThreatLevel


# =========================================================
# Logging Configuration
# =========================================================
logger = get_logger("monitor")

HONEYPOT_PATH = os.getenv("HONEYPOT_PATH")
if HONEYPOT_PATH:
    HONEYPOT_PATH = os.path.abspath(HONEYPOT_PATH)
    logger.info(f"Honeypot monitoring enabled for: {HONEYPOT_PATH}")

def is_honeypot_access(path: str) -> bool:
    """Check if a file path is within the configured honeypot directory."""
    if not HONEYPOT_PATH:
        return False
    try:
        # Check if the file's absolute path starts with the honeypot path
        return os.path.abspath(path).startswith(HONEYPOT_PATH)
    except (OSError, TypeError):
        return False


def _path_entropy(path: str) -> float:
    try:
        with open(path, "rb") as handle:
            data = handle.read(4096)
        if not data:
            return 0.0
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        size = len(data)
        return -sum((count / size) * math.log2(count / size) for count in freq.values())
    except Exception:
        return 0.0


def _find_writer_process(path: str) -> tuple[int | None, str | None]:
    norm = str(path).lower()
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            for opened in proc.open_files() or []:
                if str(opened.path).lower() == norm:
                    return proc.info.get("pid"), proc.info.get("name")
        except Exception:
            continue
    return None, None


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

        # Honeypot check is authoritative and triggers immediate critical alert
        if is_honeypot_access(event.src_path):
            logger.critical("HONEYPOT ACCESS DETECTED (CREATE): %s", event.src_path)
            event_bus.publish({
                "event_type": "HONEYPOT_DIRECTORY_ACCESS",
                "path": event.src_path,
                "action": "create",
                "severity": "CRITICAL",
                "timestamp": time.time(),
            })
            return

        log = EventLog(
            event_type="FILE_CREATED",
            severity=ThreatLevel.LOW,
            details=event.src_path
        )

        pid, process_name = _find_writer_process(event.src_path)
        event_data = {
            "event_type": "FILE_MODIFIED",
            "path": event.src_path,
            "folder": str(Path(event.src_path).parent),
            "pid": pid,
            "process_name": process_name,
            "entropy": _path_entropy(event.src_path),
            "timestamp": time.time()
        }

        event_bus.publish(event_data)

        logger.debug("File Created: %s", event.src_path)

    # -----------------------------------------------------
    # File Deleted
    # -----------------------------------------------------

    def on_deleted(self, event):

        if event.is_directory:
            return

        if is_honeypot_access(event.src_path):
            logger.critical("HONEYPOT ACCESS DETECTED (DELETE): %s", event.src_path)
            event_bus.publish({
                "event_type": "HONEYPOT_DIRECTORY_ACCESS", # Changed 'type' to 'event_type'
                "path": event.src_path,
                "action": "delete",
                "severity": "CRITICAL",
                "timestamp": time.time(),
            })
            return

        log = EventLog(
            event_type="FILE_DELETED",
            severity=ThreatLevel.MEDIUM,
            details=event.src_path
        )

        event_data = {
            "event_type": "FILE_DELETED",
            "path": event.src_path,
            "folder": str(Path(event.src_path).parent),
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

        if is_honeypot_access(event.src_path):
            logger.critical("HONEYPOT ACCESS DETECTED (MODIFY): %s", event.src_path)
            event_bus.publish({
                "event_type": "HONEYPOT_DIRECTORY_ACCESS",
                "path": event.src_path,
                "action": "modify",
                "severity": "CRITICAL",
                "timestamp": time.time(),
            })
            return

        log = EventLog(
            event_type="FILE_MODIFIED",
            severity=ThreatLevel.LOW,
            details=event.src_path
        )

        pid, process_name = _find_writer_process(event.src_path)
        event_data = { # Changed 'type' to 'event_type'
            "event_type": "FILE_MODIFIED",
            "path": event.src_path,
            "folder": str(Path(event.src_path).parent),
            "pid": pid,
            "process_name": process_name,
            "entropy": _path_entropy(event.src_path),
            "timestamp": time.time()
        }

        event_bus.publish(event_data)

        logger.debug("File Modified: %s", event.src_path)

    # -----------------------------------------------------
    # File Renamed / Moved
    # -----------------------------------------------------

    def on_moved(self, event):

        if event.is_directory:
            return

        # Check both source and destination for honeypot access
        if is_honeypot_access(event.src_path) or is_honeypot_access(event.dest_path):
            logger.critical("HONEYPOT ACCESS DETECTED (MOVE/RENAME): %s -> %s", event.src_path, event.dest_path)
            event_bus.publish({
                "event_type": "HONEYPOT_DIRECTORY_ACCESS",
                "path": event.dest_path,
                "action": "move",
                "severity": "CRITICAL",
                "timestamp": time.time(),
            })
            return

        log = EventLog(
            event_type="FILE_RENAMED",
            severity=ThreatLevel.HIGH,
            details=(
                f"{event.src_path} -> "
                f"{event.dest_path}"
            )
        )

        pid, process_name = _find_writer_process(event.dest_path)
        event_data = { # Changed 'type' to 'event_type'
            "event_type": "FILE_RENAMED",
            "path": event.dest_path,
            "old_path": event.src_path,
            "folder": str(Path(event.dest_path).parent),
            "pid": pid,
            "process_name": process_name,
            "entropy": _path_entropy(event.dest_path),
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

def start_monitor(path_to_watch=rules.DEFAULT_MONITOR_PATH):

    global observer

    Path(path_to_watch).mkdir(parents=True, exist_ok=True)

    handler = FileMonitorHandler()

    observer.schedule(
        handler,
        path=path_to_watch,
        recursive=rules.FILE_MONITOR_RECURSIVE
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
