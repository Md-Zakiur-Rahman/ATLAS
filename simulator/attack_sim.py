"""
ATLAS Local Attack Simulator

Simulates a 5-phase attack locally in safe_mode.
All file changes revert automatically after revert_delay_seconds.
Run from ATLAS root: py -3.10 simulator/attack_sim.py
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
    logger.info("Starting local port scan phase")
    for port in CONFIG["port_scan_ports"]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex(("127.0.0.1", port))
            if result == 0:
                logger.info("Open port found on localhost: %s", port)
            else:
                logger.info("Port closed or filtered on localhost: %s", port)
        except Exception as error:
            logger.warning("Port scan error on localhost:%s | %s", port, error)
        finally:
            sock.close()


def phase_2_brute_force() -> None:
    logger.info("Starting brute-force simulation phase")
    endpoint = CONFIG["auth_endpoint"]
    attempts = CONFIG["brute_force_attempts"]
    for i in range(attempts):
        payload = {
            "email": "victim@atlas.com",
            "password": f"wrongpassword{i}",
        }
        try:
            response = requests.post(endpoint, json=payload, timeout=2)
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
    logger.info("Starting file exfiltration simulation phase")
    attack_folder = Path(CONFIG["attack_folder"])
    attack_folder.mkdir(parents=True, exist_ok=True)

    for i in range(5):
        file_path = attack_folder / f"sensitive_data_{i}.txt"
        file_path.write_text(
            "".join(random.choices(string.ascii_letters, k=1024)),
            encoding="utf-8",
        )

    for file_path in attack_folder.glob("sensitive_data_*.txt"):
        with file_path.open("r", encoding="utf-8") as handle:
            _ = handle.read()
        logger.info("Exfiltration read simulated: %s", file_path)


def _revert_ransomware(renamed_pairs: list[tuple[Path, Path]], delay_seconds: int) -> None:
    time.sleep(delay_seconds)
    for renamed_path, original_path in renamed_pairs:
        if renamed_path.exists():
            renamed_path.rename(original_path)
            logger.info("Reverted file: %s -> %s", renamed_path.name, original_path.name)
    logger.info("Ransomware simulation revert completed")


def phase_4_ransomware() -> None:
    logger.info("Starting ransomware simulation phase")
    attack_folder = Path(CONFIG["attack_folder"])
    attack_folder.mkdir(parents=True, exist_ok=True)

    file_count = CONFIG["file_count"]
    renamed_pairs: list[tuple[Path, Path]] = []

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
            renamed_pairs.append((renamed_path, original_path))
            logger.info("Renamed file: %s -> %s", original_path.name, renamed_path.name)
            time.sleep(0.2)

    revert_thread = threading.Thread(
        target=_revert_ransomware,
        args=(renamed_pairs, CONFIG["revert_delay_seconds"]),
        daemon=True,
    )
    revert_thread.start()


def phase_5_c2_connection() -> None:
    logger.info("Starting C2 connection simulation phase")
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
    logger.info("EVENT=ATTACK_SIM_START | TYPE=LOCAL | SAFE_MODE=%s", CONFIG.get("safe_mode"))
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
    logger.info("EVENT=ATTACK_SIM_END | TYPE=LOCAL")


if __name__ == "__main__":
    main()