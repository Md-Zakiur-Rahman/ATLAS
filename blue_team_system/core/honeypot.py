import os
import time

HONEYPOT_TAG = ".honeypot_registry"

HONEYPOT_FILES = {
    "passwords.txt": "admin:password123\nroot:toor\nguest:guest\n",
    "bank_data.xlsx": "DECOY_BINARY_PLACEHOLDER",
    "credit_cards.csv": "name,number,cvv,expiry\nJohn Doe,4111111111111111,123,12/26\n",
    "private_keys.pem": "-----BEGIN RSA PRIVATE KEY-----\nDECOY_KEY_DATA\n-----END RSA PRIVATE KEY-----\n",
    "backup_codes.txt": "BACKUP-1234-ABCD\nBACKUP-5678-EFGH\nBACKUP-9012-IJKL\n",
    "employee_salaries.xlsx": "DECOY_BINARY_PLACEHOLDER",
}

def create_honeypots(folder: str) -> list:
    os.makedirs(folder, exist_ok=True)
    created = []

    for name, content in HONEYPOT_FILES.items():
        path = os.path.join(folder, name)
        with open(path, 'w') as f:
            f.write(content)
        created.append(os.path.abspath(path))

    with open(HONEYPOT_TAG, 'w') as f:
        f.write('\n'.join(created))

    print(f"[HONEYPOT] Created {len(created)} decoy files in '{folder}'")
    return created

def get_honeypot_paths() -> list:
    if not os.path.exists(HONEYPOT_TAG):
        return []
    with open(HONEYPOT_TAG, 'r') as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def is_honeypot(path: str) -> bool:
    abs_path = os.path.abspath(path)
    return abs_path in get_honeypot_paths()

def check_honeypot_access(path: str) -> dict | None:
    """
    Call this when a file access event is detected.
    Returns an alert dict if it's a honeypot, None otherwise.
    """
    if is_honeypot(path):
        alert = {
            "type": "HONEYPOT_ACCESS",
            "severity": "CRITICAL",
            "path": path,
            "timestamp": time.time(),
            "message": f"Honeypot file accessed: {os.path.basename(path)}"
        }
        print(f"[HONEYPOT ALERT] {alert['message']}")
        return alert
    return None