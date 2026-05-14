import os
from core.encryptor import encrypt_folder, decrypt_folder
from core.key_manager import get_or_create_key, rotate_key
from core.alert_manager_stub import dispatch_alert
import time

VAULT_FLAG = "vault.locked"
KEYFILE_PATH = "vault.keyfile"

def lock_vault(folder: str, password: str, reason: str = "Manual lock") -> None:
    key, _ = get_or_create_key(password, KEYFILE_PATH)
    count = encrypt_folder(folder, key)
    with open(VAULT_FLAG, 'w') as f:
        f.write(reason)
    dispatch_alert({
        "type": "VAULT_LOCKED",
        "severity": "HIGH",
        "timestamp": time.time(),
        "message": f"Vault locked. Reason: {reason} | Files encrypted: {count}"
    })
    print(f"[VAULT LOCKED] Reason: {reason} | Files encrypted: {count}")

def unlock_vault(folder: str, master_password: str) -> bool:
    if not os.path.exists(VAULT_FLAG):
        print("[VAULT] Not locked.")
        return False
    try:
        key, _ = get_or_create_key(master_password, KEYFILE_PATH)
        count = decrypt_folder(folder, key)
        os.remove(VAULT_FLAG)
        dispatch_alert({
            "type": "VAULT_UNLOCKED",
            "severity": "LOW",
            "timestamp": time.time(),
            "message": f"Vault unlocked. Files restored: {count}"
        })
        print(f"[VAULT UNLOCKED] Files restored: {count}")
        return True
    except Exception as e:
        print(f"[VAULT ERROR] {e}")
        return False

def emergency_reencrypt(folder: str, old_password: str, new_password: str) -> bool:
    try:
        old_key, new_key = rotate_key(old_password, new_password, KEYFILE_PATH)
        decrypt_folder(folder, old_key)
        count = encrypt_folder(folder, new_key)
        with open(VAULT_FLAG, 'w') as f:
            f.write("Emergency re-encryption triggered")
        dispatch_alert({
            "type": "EMERGENCY_REENCRYPT",
            "severity": "CRITICAL",
            "timestamp": time.time(),
            "message": f"Emergency re-encryption complete. Files secured: {count}"
        })
        print(f"[EMERGENCY RE-ENCRYPT] Complete. Files secured: {count}")
        return True
    except Exception as e:
        print(f"[EMERGENCY ERROR] {e}")
        return False

def is_locked() -> bool:
    return os.path.exists(VAULT_FLAG)