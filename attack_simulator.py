"""
ATLAS attack simulator.

Safe file-activity simulator for validating:
simulator -> file monitor -> event bus -> threat engine -> alert manager.
"""

import argparse
import logging
import random
import time
from pathlib import Path

from monitor import rules


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("ATLAS-AttackSimulator")


INTENSITY_PROFILES = {
    "low": {
        "file_count": 12,
        "operation_delay": 0.20,
        "delete_count": rules.MASS_DELETE_THRESHOLD,
    },
    "medium": {
        "file_count": 25,
        "operation_delay": 0.08,
        "delete_count": rules.MASS_DELETE_THRESHOLD + 5,
    },
    "high": {
        "file_count": 45,
        "operation_delay": 0.03,
        "delete_count": rules.MASS_DELETE_THRESHOLD + 15,
    },
}


def create_test_files(test_folder: Path, file_count: int) -> None:
    test_folder.mkdir(parents=True, exist_ok=True)
    print(f"[+] Creating {file_count} test files in {test_folder}")

    for index in range(file_count):
        file_path = test_folder / f"document_{index}.txt"
        file_path.write_text(f"ATLAS Test File {index}\n", encoding="utf-8")

    print("[+] Test files ready")


def simulate_modification(test_folder: Path, operation_delay: float) -> None:
    print("[!] Simulating rapid file modification")

    for file_path in sorted(test_folder.iterdir()):
        if not file_path.is_file():
            continue

        try:
            with file_path.open("a", encoding="utf-8") as file:
                file.write("MODIFIED BY ATLAS TEST\n")
            print(f"[MODIFIED] {file_path.name}")
        except OSError as error:
            logger.warning("Modification failed for %s: %s", file_path, error)

        time.sleep(operation_delay)


def simulate_mass_rename(test_folder: Path, operation_delay: float) -> None:
    print("[!] Simulating ransomware-style rename activity")

    for file_path in sorted(test_folder.iterdir()):
        if not file_path.is_file():
            continue

        if any(file_path.name.lower().endswith(ext) for ext in rules.SUSPICIOUS_EXTENSIONS):
            continue

        new_path = file_path.with_name(
            f"{file_path.name}{random.choice(rules.SUSPICIOUS_EXTENSIONS)}"
        )

        try:
            file_path.rename(new_path)
            print(f"[RENAME] {file_path.name} -> {new_path.name}")
        except OSError as error:
            logger.warning("Rename failed for %s: %s", file_path, error)

        time.sleep(operation_delay)


def simulate_mass_delete(
    test_folder: Path,
    delete_count: int,
    operation_delay: float,
) -> None:
    print(f"[!] Simulating deletion spike ({delete_count} deletes)")

    files = [path for path in sorted(test_folder.iterdir()) if path.is_file()]
    for file_path in files[:delete_count]:
        try:
            file_path.unlink()
            print(f"[DELETED] {file_path.name}")
        except OSError as error:
            logger.warning("Delete failed for %s: %s", file_path, error)

        time.sleep(operation_delay)


def simulate_suspicious_process_event() -> None:
    """
    Publish a synthetic event for in-process demos.

    This does not reach an already-running main.py process because the event bus
    is in memory. Real process monitoring is handled by monitor/process_monitor.py.
    """

    from monitor.event_bus import event_bus

    event_bus.publish(
        {
            "type": "PROCESS_DETECTED",
            "process_name": "mimikatz.exe",
            "pid": 99999,
            "timestamp": time.time(),
        }
    )
    print("[PROCESS] Published synthetic mimikatz.exe event for local bus demos")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run safe ATLAS attack simulation")
    parser.add_argument(
        "--path",
        default=rules.DEFAULT_MONITOR_PATH,
        help="Folder watched by ATLAS file monitor",
    )
    parser.add_argument(
        "--intensity",
        choices=sorted(INTENSITY_PROFILES),
        default="medium",
        help="Attack simulation intensity",
    )
    parser.add_argument(
        "--skip-modify",
        action="store_true",
        help="Skip modification activity",
    )
    parser.add_argument(
        "--skip-rename",
        action="store_true",
        help="Skip ransomware rename activity",
    )
    parser.add_argument(
        "--skip-delete",
        action="store_true",
        help="Skip deletion spike activity",
    )
    parser.add_argument(
        "--process-event",
        action="store_true",
        help="Publish one synthetic process event to this simulator process's bus",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    profile = INTENSITY_PROFILES[args.intensity]
    test_folder = Path(args.path)

    print("\n========== ATLAS ATTACK SIMULATOR ==========")
    print(f"Target    : {test_folder}")
    print(f"Intensity : {args.intensity}")
    print("Start main.py first so Watchdog can observe these file operations.\n")

    create_test_files(test_folder, profile["file_count"])
    time.sleep(rules.FILE_MONITOR_STARTUP_DELAY_SECONDS)

    if not args.skip_modify:
        simulate_modification(test_folder, profile["operation_delay"])
        time.sleep(1)

    if not args.skip_rename:
        simulate_mass_rename(test_folder, profile["operation_delay"])
        time.sleep(1)

    if not args.skip_delete:
        simulate_mass_delete(
            test_folder,
            profile["delete_count"],
            profile["operation_delay"],
        )

    if args.process_event:
        simulate_suspicious_process_event()

    print("\n[+] Simulation complete. Check the ATLAS console for alerts.\n")


if __name__ == "__main__":
    main()
