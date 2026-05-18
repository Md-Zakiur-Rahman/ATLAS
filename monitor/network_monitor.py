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

        self.ip_blacklist: Set[str] = set()

    def get_ip_geo(self, ip: str) -> dict:
        try:
            import requests

            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=3
            )
            data = response.json()
            if data.get("status") == "success":
                return {
                    "city": data.get("city", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                }
        except Exception as error:
            logger.debug("Geo-lookup failed for %s: %s", ip, error)

        return {
            "city": "Unknown",
            "country": "Unknown",
            "region": "Unknown",
            "isp": "Unknown",
            "lat": None,
            "lon": None,
        }

    def blacklist_ip(self, ip: str) -> None:
        self.ip_blacklist.add(ip)
        logger.warning("IP blacklisted: %s", ip)

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

                    if remote_ip in self.ip_blacklist:
                        logger.warning(
                            "Blocked blacklisted IP connection: %s",
                            remote_ip,
                        )
                        continue

                    if suspicious:
                        geo = self.get_ip_geo(remote_ip)

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
                                "city": geo.get("city"),
                                "country": geo.get("country"),
                                "region": geo.get("region"),
                                "isp": geo.get("isp"),
                                "timestamp": time.time(),
                                "created_at": time.time(),
                            }
                        )

                    else:

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
                                "city": None,
                                "country": None,
                                "region": None,
                                "isp": None,
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
