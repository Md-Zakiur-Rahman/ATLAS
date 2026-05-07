"""
ATLAS Attack Simulator
SAFE ransomware behavior simulator for testing ONLY

What this does:
- Creates dummy files
- Rapidly renames files
- Modifies files
- Deletes some files

Used to test:
- file_monitor.py
- threat_engine.py
- alert_manager.py
"""

import os
import time
import random
from pathlib import Path


# =========================================================
# Configuration
# =========================================================

TEST_FOLDER = "D:/ATLAS_TEST"

FILE_COUNT = 25

EXTENSIONS = [
    ".encrypted",
    ".locked",
    ".crypt"
]


# =========================================================
# Create Test Files
# =========================================================

def create_test_files():

    os.makedirs(TEST_FOLDER, exist_ok=True)

    print("\n[+] Creating test files...\n")

    for i in range(FILE_COUNT):

        file_path = os.path.join(
            TEST_FOLDER,
            f"document_{i}.txt"
        )

        with open(file_path, "w") as file:

            file.write(
                f"ATLAS Test File {i}\n"
            )

    print(f"[+] {FILE_COUNT} test files created.\n")


# =========================================================
# Simulate Mass Rename Attack
# =========================================================

def simulate_mass_rename():

    print("[!] Simulating ransomware rename attack...\n")

    files = os.listdir(TEST_FOLDER)

    for file_name in files:

        old_path = os.path.join(
            TEST_FOLDER,
            file_name
        )

        # Skip already encrypted files
        if any(
            file_name.endswith(ext)
            for ext in EXTENSIONS
        ):
            continue

        random_ext = random.choice(
            EXTENSIONS
        )

        new_path = os.path.join(
            TEST_FOLDER,
            file_name + random_ext
        )

        try:

            os.rename(old_path, new_path)

            print(
                f"[RENAME] "
                f"{file_name} -> "
                f"{os.path.basename(new_path)}"
            )

        except Exception as error:

            print(
                f"[ERROR] Rename Failed: "
                f"{error}"
            )

        time.sleep(0.1)


# =========================================================
# Simulate Mass Modification
# =========================================================

def simulate_modification():

    print("\n[!] Simulating file modification...\n")

    files = os.listdir(TEST_FOLDER)

    for file_name in files:

        file_path = os.path.join(
            TEST_FOLDER,
            file_name
        )

        try:

            with open(file_path, "a") as file:

                file.write(
                    "\nMODIFIED BY ATLAS TEST\n"
                )

            print(
                f"[MODIFIED] {file_name}"
            )

        except Exception as error:

            print(
                f"[ERROR] Modification Failed: "
                f"{error}"
            )

        time.sleep(0.05)


# =========================================================
# Simulate Mass Deletion
# =========================================================

def simulate_mass_delete():

    print("\n[!] Simulating mass deletion...\n")

    files = os.listdir(TEST_FOLDER)

    for file_name in files[:10]:

        file_path = os.path.join(
            TEST_FOLDER,
            file_name
        )

        try:

            os.remove(file_path)

            print(
                f"[DELETED] {file_name}"
            )

        except Exception as error:

            print(
                f"[ERROR] Delete Failed: "
                f"{error}"
            )

        time.sleep(0.05)


# =========================================================
# Main
# =========================================================

if __name__ == "__main__":

    print("\n========== ATLAS ATTACK SIMULATOR ==========\n")

    create_test_files()

    time.sleep(2)

    simulate_modification()

    time.sleep(2)

    simulate_mass_rename()

    time.sleep(2)

    simulate_mass_delete()

    print(
        "\n[+] Simulation Complete.\n"
    )