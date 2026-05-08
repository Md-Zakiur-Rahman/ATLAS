import os

HONEYPOT_NAMES = [
    "passwords.txt",
    "bank_data.xlsx",
    "credit_cards.csv",
    "private_keys.pem",
    "backup_codes.txt",
    "employee_salaries.xlsx",
]

HONEYPOT_TAG = ".honeypot_registry"

def create_honeypots(folder: str) -> list:
    os.makedirs(folder, exist_ok=True)
    created = []
    registry = []

    for name in HONEYPOT_NAMES:
        path = os.path.join(folder, name)
        with open(path, 'w') as f:
            f.write(f"[DECOY] This file is monitored. Access has been logged.\n")
        created.append(path)
        registry.append(path)

    with open(HONEYPOT_TAG, 'w') as f:
        f.write('\n'.join(registry))

    print(f"[HONEYPOT] Created {len(created)} decoy files in '{folder}'")
    return created

def get_honeypot_paths() -> list:
    if not os.path.exists(HONEYPOT_TAG):
        return []
    with open(HONEYPOT_TAG, 'r') as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def is_honeypot(path: str) -> bool:
    return path in get_honeypot_paths()