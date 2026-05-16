"""
ATLAS Network Monitor

Monitors active network connections,
suspicious ports, and outbound traffic.
"""

import logging
import threading
import time
from typing import Set, Tuple

import psutil

from monitor.event_bus import (
    event_bus
)


logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"
    )
)

logger = logging.getLogger(
    "ATLAS-NetworkMonitor"
)


SUSPICIOUS_PORTS = {

    4444,   # Metasploit
    1337,   # Common backdoor
    5555,   # Android debug / shells
    6666,
    31337,
}


BLOCKED_PROCESSES = {

    "nc.exe",
    "netcat.exe",
    "ncat.exe",
    "powershell.exe",
}


class NetworkMonitor:

    def __init__(self):

        self.seen_connections: Set[
            Tuple
        ] = set()

        self._stop_event = (
            threading.Event()
        )

    def start(self) -> None:

        logger.info(
            "Network Monitor Started"
        )

        while not self._stop_event.is_set():

            self.scan_connections()

            time.sleep(5)

    def stop(self) -> None:

        self._stop_event.set()

        logger.info(
            "Network Monitor Stopped"
        )

    def scan_connections(
        self
    ) -> None:

        try:

            connections = (
                psutil.net_connections(
                    kind="inet"
                )
            )

            for connection in connections:

                try:

                    if not connection.raddr:
                        continue

                    remote_ip = (
                        connection.raddr.ip
                    )

                    remote_port = (
                        connection.raddr.port
                    )

                    pid = connection.pid

                    process_name = (
                        "UNKNOWN"
                    )

                    if pid:

                        try:

                            process_name = (
                                psutil.Process(
                                    pid
                                ).name()
                            )

                        except Exception:
                            pass

                    connection_key = (

                        remote_ip,
                        remote_port,
                        process_name,
                    )

                    if (
                        connection_key
                        in self.seen_connections
                    ):
                        continue

                    self.seen_connections.add(
                        connection_key
                    )

                    suspicious = False

                    if (
                        remote_port
                        in SUSPICIOUS_PORTS
                    ):
                        suspicious = True

                    if (
                        process_name.lower()
                        in BLOCKED_PROCESSES
                    ):
                        suspicious = True

                    event_bus.publish(
                        {
                            "type": (
                                "NETWORK_CONNECTION"
                            ),
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "process_name": process_name,
                            "pid": pid,
                            "suspicious": suspicious,
                            "severity": (
                                    "HIGH"
                                    if suspicious
                                    else "LOW"
                                ),
                            "timestamp": time.time(),
                            "created_at": time.time(),
                        }
                    )

                    if suspicious:

                        logger.warning(
                            "Suspicious Network "
                            "Connection: "
                            "%s:%s | %s",
                            remote_ip,
                            remote_port,
                            process_name,
                        )

                    else:

                        logger.debug(
                            "Network Connection: "
                            "%s:%s",
                            remote_ip,
                            remote_port,
                        )

                except Exception as error:

                    logger.debug(
                        "Connection Parse Error: %s",
                        error
                    )

        except Exception as error:

            logger.exception(
                "Network Monitor Error: %s",
                error
            )


network_monitor = (
    NetworkMonitor()
)