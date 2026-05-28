"""
ATLAS Remote Attack Simulator

Simulates a 5-phase attack against a configurable remote target.
Reads settings from simulator/sim_config.json.
Run from ATLAS root: py -3.10 simulator/attack_remote.py
"""
import json
import logging
import os
import random
import requests
import shutil
import socket
import string
import threading
import time
import sys
from pathlib import Path
from config.logging_config import get_logger

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


with open("simulator/sim_config.json") as f:
    CONFIG = json.load(f)


logger = get_logger("simulator")
containment_handler = logging.FileHandler(os.path.join("D:\\logs", "containment.log"), mode="a", encoding="utf-8")
containment_handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
logger.addHandler(containment_handler)


def phase_1_port_scan() -> None:
    logger.info("Starting remote port scan phase")
    target_ip = CONFIG["target_ip"]
    for port in CONFIG["port_scan_ports"]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                logger.info("Open port found on %s: %s", target_ip, port)
            else:
                logger.info("Port closed or filtered on %s: %s", target_ip, port)
        except Exception as error:
            logger.warning("Port scan error on %s:%s | %s", target_ip, port, error)
        finally:
            sock.close()


def phase_2_brute_force() -> None:
    logger.info("Starting remote brute-force simulation phase")
    target_url = f"http://{CONFIG['target_ip']}:{CONFIG['target_port']}/auth-verify"
    attempts = CONFIG["brute_force_attempts"]
    for i in range(attempts):
        payload = {
            "email": "victim@atlas.com",
            "password": f"wrongpassword{i}",
        }
        try:
            response = requests.post(target_url, json=payload, timeout=2)
            logger.info(
                "Brute-force attempt %s/%s | status=%s",
                i + 1,
                attempts,
                response.status_code,
            )
        except Exception as error:
            logger.warning(
                "Brute-force attempt %s/%s failed | %s",
                i + 1,
                attempts,
                error,
            )


def phase_3_file_exfiltration() -> None:
    logger.info("Starting remote file exfiltration phase")
    target_url = f"http://{CONFIG['target_ip']}:{CONFIG['target_port']}/files"
    try:
        response = requests.get(target_url, timeout=2)
        logger.info(
            "Remote files endpoint response | status=%s | bytes=%s",
            response.status_code,
            len(response.content),
        )
    except Exception as error:
        logger.warning(
            "Target has no exposed file endpoint - simulating network probe instead | %s",
            error,
        )
        target_ip = CONFIG["target_ip"]
        additional_ports = [21, 25, 53, 110, 8080]
        for port in additional_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    logger.info("Additional probe found open port on %s: %s", target_ip, port)
                else:
                    logger.info("Additional probe no service on %s: %s", target_ip, port)
            except Exception as probe_error:
                logger.warning(
                    "Additional probe error on %s:%s | %s",
                    target_ip,
                    port,
                    probe_error,
                )
            finally:
                sock.close()


def phase_4_ransomware() -> None:
    if CONFIG.get("safe_mode"):
        logger.warning("safe_mode is True - skipping destructive remote phase")
        return

    logger.warning("REMOTE MODE - no revert. Target files remain renamed.")
    attack_folder = Path(CONFIG["attack_folder"])
    attack_folder.mkdir(parents=True, exist_ok=True)

    file_count = CONFIG["file_count"]
    for i in range(file_count):
        original_path = attack_folder / f"target_{i}.txt"
        original_path.write_text(
            "".join(random.choices(string.ascii_letters, k=1024)),
            encoding="utf-8",
        )

    for i in range(file_count):
        original_path = attack_folder / f"target_{i}.txt"
        renamed_path = attack_folder / f"target_{i}.atlas_locked"
        if original_path.exists():
            original_path.rename(renamed_path)
            logger.info("Renamed file: %s -> %s", original_path.name, renamed_path.name)
            time.sleep(0.2)


def phase_5_c2_connection() -> None:
    logger.info("Starting remote C2 connection simulation phase")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((CONFIG["target_ip"], CONFIG["c2_port"]))
        logger.info(
            "C2 connection established to %s:%s",
            CONFIG["target_ip"],
            CONFIG["c2_port"],
        )
    except Exception as error:
        logger.warning(
            "C2 connection attempt failed to %s:%s | %s",
            CONFIG["target_ip"],
            CONFIG["c2_port"],
            error,
        )
    finally:
        sock.close()


def _print_phase_header(n: int, name: str) -> None:
    print(f"\n{'=' * 50}")
    print(f"PHASE {n}: {name}")
    print(f"{'=' * 50}")


def main() -> None:
    logger.info("EVENT=ATTACK_SIM_START | TYPE=REMOTE | SAFE_MODE=%s", CONFIG.get("safe_mode"))
    if CONFIG.get("safe_mode"):
        logger.warning(
            "safe_mode is True in sim_config.json. "
            "Phase 4 (ransomware) will be skipped. "
            "Set safe_mode to false to run full remote attack."
        )

    phases = [
        ("Port Scan", phase_1_port_scan),
        ("Brute Force", phase_2_brute_force),
        ("File Exfiltration", phase_3_file_exfiltration),
        ("Ransomware Rename Burst", phase_4_ransomware),
        ("C2 Connection", phase_5_c2_connection),
    ]

    for index, (name, phase_fn) in enumerate(phases, start=1):
        _print_phase_header(index, name)
        phase_fn()
        time.sleep(CONFIG["phase_delay_seconds"])
    logger.info("EVENT=ATTACK_SIM_END | TYPE=REMOTE")


if __name__ == "__main__":
    main()