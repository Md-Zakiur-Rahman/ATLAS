"""
ATLAS Dynamic Attack Simulator

Behavioral adversarial emulation engine for:
- ransomware behavior
- reconnaissance activity
- honeypot interaction
- mass deletion
- suspicious process simulation

This simulator intentionally avoids directly triggering alerts.
ATLAS must detect malicious behavior dynamically.
"""

import argparse
import logging
import os
import random
import string
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
        "file_count": 15,
        "delay_min": 0.15,
        "delay_max": 0.30,
    },
    "medium": {
        "file_count": 30,
        "delay_min": 0.05,
        "delay_max": 0.15,
    },
    "high": {
        "file_count": 60,
        "delay_min": 0.01,
        "delay_max": 0.05,
    },
}


class AttackSimulator:

    def __init__(self, target_path: str, intensity: str):

        self.target_path = Path(target_path)

        self.profile = INTENSITY_PROFILES[intensity]

        self.file_count = self.profile["file_count"]

        self.delay_min = self.profile["delay_min"]

        self.delay_max = self.profile["delay_max"]

        self.generated_files = []

    # =====================================================
    # Utility
    # =====================================================

    def random_delay(self):

        time.sleep(
            random.uniform(
                self.delay_min,
                self.delay_max
            )
        )

    def random_filename(self):

        keyword = random.choice(
            rules.HONEYPOT_KEYWORDS
        )

        suffix = ''.join(
            random.choices(
                string.digits,
                k=4
            )
        )

        extension = random.choice(
            rules.HONEYPOT_ALLOWED_EXTENSIONS
        )

        return (
            f"{keyword}_{suffix}"
            f"{extension}"
        )

    # =====================================================
    # Environment Generation
    # =====================================================

    def generate_environment(self):

        self.target_path.mkdir(
            parents=True,
            exist_ok=True
        )

        logger.info(
            "Generating realistic file environment"
        )

        for _ in range(self.file_count):

            filename = self.random_filename()

            filepath = self.target_path / filename

            try:

                with open(filepath, "w") as file:

                    file.write(
                        "Sensitive corporate data\n"
                    )

                self.generated_files.append(
                    filepath
                )

            except Exception as error:

                logger.warning(
                    "Environment generation failed: %s",
                    error
                )

        logger.info(
            "Environment ready (%s files)",
            len(self.generated_files)
        )

    # =====================================================
    # Reconnaissance Simulation
    # =====================================================

    def simulate_recon_activity(self):

        logger.warning(
            "Phase 1: Reconnaissance Activity"
        )

        files = random.sample(
            self.generated_files,
            min(10, len(self.generated_files))
        )

        for file_path in files:

            try:

                with open(file_path, "r") as file:
                    file.read()

                logger.info(
                    "[RECON] Accessed %s",
                    file_path.name
                )

            except Exception:
                pass

            self.random_delay()

    # =====================================================
    # Honeypot Interaction
    # =====================================================

    def simulate_honeypot_access(self):

        logger.warning(
            "Phase 2: Sensitive File Targeting"
        )

        candidate_files = []

        for file_path in self.generated_files:

            filename = file_path.name.lower()

            if any(
                keyword in filename
                for keyword in rules.HONEYPOT_KEYWORDS
            ):
                candidate_files.append(
                    file_path
                )

        random.shuffle(candidate_files)

        for file_path in candidate_files[:8]:

            try:

                with open(file_path, "a") as file:

                    file.write(
                        "\nUNAUTHORIZED ACCESS\n"
                    )

                logger.info(
                    "[HONEYPOT] Modified %s",
                    file_path.name
                )

            except Exception:
                pass

            self.random_delay()

    # =====================================================
    # Ransomware Simulation
    # =====================================================

    def simulate_ransomware_behavior(self):

        logger.warning(
            "Phase 3: Ransomware Behavior"
        )

        targets = random.sample(
            self.generated_files,
            min(25, len(self.generated_files))
        )

        for file_path in targets:

            if not file_path.exists():
                continue

            extension = random.choice(
                rules.SUSPICIOUS_EXTENSIONS
            )

            encrypted_path = file_path.with_name(
                f"{file_path.name}{extension}"
            )

            try:

                with open(file_path, "a") as file:

                    file.write(
                        "\nENCRYPTED_PAYLOAD\n"
                    )

                file_path.rename(
                    encrypted_path
                )

                logger.info(
                    "[ENCRYPTED] %s",
                    encrypted_path.name
                )

            except Exception as error:

                logger.warning(
                    "Encryption simulation failed: %s",
                    error
                )

            self.random_delay()

    # =====================================================
    # Mass Deletion Simulation
    # =====================================================

    def simulate_mass_deletion(self):

        logger.warning(
            "Phase 4: Mass Deletion Activity"
        )

        files = list(
            self.target_path.glob("*")
        )

        random.shuffle(files)

        delete_count = min(
            rules.MASS_DELETE_THRESHOLD + 5,
            len(files)
        )

        for file_path in files[:delete_count]:

            try:

                os.remove(file_path)

                logger.info(
                    "[DELETED] %s",
                    file_path.name
                )

            except Exception:
                pass

            self.random_delay()

    # =====================================================
    # Suspicious Process Simulation
    # =====================================================

    def simulate_suspicious_process(self):

        logger.warning(
            "Phase 5: Suspicious Process Activity"
        )

        logger.info(
            "[PROCESS] Simulated credential dumping behavior"
        )

    # =====================================================
    # Full Attack Chain
    # =====================================================

    def run(self):

        print(
            "\n========== "
            "ATLAS DYNAMIC ATTACK SIMULATION "
            "==========\n"
        )

        self.generate_environment()

        time.sleep(1)

        attack_chain = [
            self.simulate_recon_activity,
            self.simulate_honeypot_access,
            self.simulate_ransomware_behavior,
            self.simulate_mass_deletion,
            self.simulate_suspicious_process,
        ]

        random.shuffle(
            attack_chain
        )

        for phase in attack_chain:

            phase()

            time.sleep(
                random.uniform(1, 3)
            )

        print(
            "\n[+] Dynamic attack simulation completed.\n"
        )


# =========================================================
# CLI
# =========================================================

def parse_args():

    parser = argparse.ArgumentParser(
        description="ATLAS Dynamic Attack Simulator"
    )

    parser.add_argument(
        "--path",
        default=rules.DEFAULT_MONITOR_PATH,
    )

    parser.add_argument(
        "--intensity",
        choices=["low", "medium", "high"],
        default="medium",
    )

    return parser.parse_args()


def main():

    args = parse_args()

    simulator = AttackSimulator(
        target_path=args.path,
        intensity=args.intensity,
    )

    simulator.run()


if __name__ == "__main__":
    main()