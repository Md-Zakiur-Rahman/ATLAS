"""
ATLAS Network Monitor

Monitors active network connections,
suspicious ports, and outbound traffic.
"""

import threading
from collections import deque
import time
from typing import Deque, Dict, Set, Tuple
import subprocess

import psutil
from config.logging_config import get_logger
from monitor.event_bus import (
    event_bus
)
logger = get_logger("monitor")


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

TRUSTED_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "code.exe",
    "explorer.exe",
    "winword.exe",
    "onedrive.exe",
}

LOLBINS = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "bitsadmin.exe",
    "certutil.exe",
}


class NetworkMonitor:

    def __init__(self):

        self._stop_event = (
            threading.Event()
        )

        self.last_connection_time: Dict[Tuple, float] = {}
        self.ip_blacklist: Set[str] = set()
        self.connection_bursts: Dict[str, Deque[float]] = {}
        self.process_destinations: Dict[str, Deque[Tuple[float, str, int]]] = {}
        self.seen_connections: Set[Tuple] = set()
        self.unsigned_cache: Dict[str, bool] = {}
        self.known_malicious_ip_reputation: Set[str] = set()

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

    def add_malicious_ip_reputation(self, ip: str) -> None:
        self.known_malicious_ip_reputation.add(ip)
        logger.warning("IP marked malicious by reputation feed: %s", ip)

    def _is_unsigned_binary(self, pid: int) -> bool:
        if not pid:
            return False
        try:
            exe_path = psutil.Process(pid).exe()
        except Exception:
            return False
        if not exe_path:
            return False
        cache_key = exe_path.lower()
        if cache_key in self.unsigned_cache:
            return self.unsigned_cache[cache_key]
        try:
            safe_path = exe_path.replace('"', '`"')
            command = [
                "powershell",
                "-NoProfile",
                "-Command",
                f'(Get-AuthenticodeSignature -LiteralPath "{safe_path}").Status',
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=2)
            status = (result.stdout or "").strip().lower()
            unsigned = status not in {"valid"}
        except Exception:
            unsigned = False
        self.unsigned_cache[cache_key] = unsigned
        return unsigned

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

                    risk_reasons = []
                    geo = self.get_ip_geo(remote_ip)
                    normalized_process = process_name.lower()
                    is_trusted_process = normalized_process in TRUSTED_PROCESSES

                    if remote_ip in self.ip_blacklist:
                        risk_reasons.append("blacklisted_ip")
                    if remote_ip in self.known_malicious_ip_reputation:
                        risk_reasons.append("known_malicious_ip_reputation")

                    unusual_port = remote_port in SUSPICIOUS_PORTS
                    suspicious_process = normalized_process in BLOCKED_PROCESSES
                    if unusual_port or suspicious_process:
                        risk_reasons.append("abnormal_process_behavior")

                    if normalized_process in LOLBINS:
                        risk_reasons.append("lolbin_process")
                    if self._is_unsigned_binary(pid):
                        risk_reasons.append("unsigned_binary")

                    now = time.time()
                    burst = self.connection_bursts.setdefault(remote_ip, deque(maxlen=40))
                    burst.append(now)
                    burst_count = sum(1 for ts in burst if now - ts <= 10)
                    if burst_count >= 12:
                        risk_reasons.append("high_frequency_outbound_connections")

                    proc_key = f"{normalized_process}:{pid or 0}"
                    recent = self.process_destinations.setdefault(proc_key, deque(maxlen=120))
                    recent.append((now, remote_ip, remote_port))
                    short = [entry for entry in recent if now - entry[0] <= 120]
                    if len(short) >= 6:
                        intervals = [short[i][0] - short[i - 1][0] for i in range(1, len(short))]
                        if intervals:
                            avg_gap = sum(intervals) / len(intervals)
                            jitter = sum(abs(x - avg_gap) for x in intervals) / len(intervals)
                            if avg_gap <= 25 and jitter <= 2.5:
                                risk_reasons.append("beaconing_behavior")

                    # Require stronger evidence to reduce false positives.
                    unique_reasons = sorted(set(risk_reasons))
                    hard_reasons = {"blacklisted_ip", "known_malicious_ip_reputation"}
                    behavioral_reasons = {
                        "unsigned_binary",
                        "lolbin_process",
                        "beaconing_behavior",
                        "high_frequency_outbound_connections",
                        "abnormal_process_behavior",
                    }
                    hard_hit = any(reason in hard_reasons for reason in unique_reasons)
                    behavior_hits = sum(1 for reason in unique_reasons if reason in behavioral_reasons)
                    suspicious = hard_hit or behavior_hits >= 2

                    if is_trusted_process and not hard_hit and behavior_hits < 2:
                        suspicious = False

                    event_bus.publish(
                        {
                            "event_type": "NETWORK_CONNECTION",
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "process_name": process_name,
                            "pid": pid,
                            "suspicious": suspicious,
                            "risk_reasons": unique_reasons if suspicious else [],
                            "severity": "MEDIUM" if suspicious else "LOW",
                            "city": geo.get("city"),
                            "country": geo.get("country"),
                            "region": geo.get("region"),
                            "isp": geo.get("isp"),
                            "trusted_process": is_trusted_process,
                            "timestamp": now,
                            "created_at": now,
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
