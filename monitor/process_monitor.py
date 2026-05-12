"""
ATLAS process monitor.

Periodically scans running processes with psutil and publishes PROCESS_DETECTED
events for the threat engine. Safe and blocked process decisions remain in the
engine so all threat rules are evaluated in one place.
"""

import logging
import threading
import time
from typing import Dict, Optional, Set, Tuple
from monitor.models import ThreatLevel
import psutil

from monitor import rules
from monitor.event_bus import event_bus


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("ATLAS-ProcessMonitor")


class ProcessMonitor:
    """Background process scanner that publishes process detection events."""

    def __init__(self, interval_seconds: Optional[int] = None):
        self.interval_seconds = interval_seconds or rules.PROCESS_SCAN_INTERVAL_SECONDS
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen_processes: Set[Tuple[int, str]] = set()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            logger.debug("Process Monitor already running")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._scan_loop,
            name="ATLAS-ProcessMonitor",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Process Monitor Started (interval=%ss)",
            self.interval_seconds,
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self.interval_seconds + 1)

        logger.info("Process Monitor Stopped")

    def _scan_loop(self) -> None:
        while not self._stop_event.is_set():
            self.scan_once()
            self._stop_event.wait(self.interval_seconds)

    def scan_once(self) -> None:
        for process_info in self._iter_processes():
            process_key = (
                process_info["pid"],
                process_info["process_name"].lower(),
            )
            if process_key in self._seen_processes:
                continue

            self._seen_processes.add(process_key)
            normalized_name = (
                process_info["process_name"]
                .lower()
            )

            if normalized_name in rules.BLOCKED_PROCESSES:

                self._terminate_blocked_process(
                    process_name=process_info["process_name"],
                    pid=process_info["pid"]
                )
            event_bus.publish(
                {
                    "type": "PROCESS_DETECTED",
                    "process_name": process_info["process_name"],
                    "pid": process_info["pid"],
                    "exe": process_info.get("exe"),
                    "username": process_info.get("username"),
                    "timestamp": time.time(),
                }
            )

    def _terminate_blocked_process(
        self,
        process_name: str,
        pid: int
    ) -> None:
        """
        Terminate blocked malicious processes.
        """

        if not rules.AUTO_TERMINATE_BLOCKED_PROCESSES:
            return

        try:

            process = psutil.Process(pid)

            process.terminate()

            logger.warning(
                "Blocked process terminated: %s (PID %s)",
                process_name,
                pid
            )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):

            logger.warning(
                "Failed to terminate process: %s",
                process_name
            )

        except Exception as error:

            logger.exception(
                "Process termination error: %s",
                error
            )

    def _iter_processes(self):
        for process in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                process_info: Dict = process.info
                process_name = process_info.get("name")
                if not process_name:
                    continue

                yield {
                    "pid": process_info.get("pid"),
                    "process_name": process_name,
                    "exe": process_info.get("exe"),
                    "username": process_info.get("username"),
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as error:
                logger.debug("Process scan skipped one process: %s", error)


process_monitor = ProcessMonitor()


def start_process_monitor() -> None:
    process_monitor.start()


def stop_process_monitor() -> None:
    process_monitor.stop()


if __name__ == "__main__":
    monitor = ProcessMonitor(interval_seconds=rules.PROCESS_SCAN_INTERVAL_SECONDS)
    monitor.scan_once()
