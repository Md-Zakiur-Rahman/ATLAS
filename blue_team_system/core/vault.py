import os
import time
from core.encryptor import encrypt_folder, decrypt_folder
from core.key_manager import get_or_create_key, rotate_key
from core.alert_manager_stub import dispatch_alert

VAULT_FLAG = "vault.locked"
KEYFILE_PATH = "vault.keyfile"
NGROK_URL_FILE = ".ngrok_url"  # written by main.py after ngrok starts

def _get_ngrok_url() -> str:
    if os.path.exists(NGROK_URL_FILE):
        with open(NGROK_URL_FILE, 'r') as f:
            return f.read().strip()
    return ""

def _build_remote_lock_alert(reason: str) -> dict:
    alert = {
        "type": "VAULT_LOCKED",
        "severity": "CRITICAL",
        "timestamp": time.time(),
        "message": f"Vault locked. Reason: {reason}"
    }
    try:
        from core.biometric_auth import get_remote_lock_url
        base_url = _get_ngrok_url()
        if base_url:
            lock_url, token = get_remote_lock_url(base_url)
            alert["remote_lock_url"] = lock_url
            alert["remote_lock_token"] = token
            alert["message"] += f" | Remote lock: {lock_url}"
    except Exception as e:
        print(f"[VAULT] Remote lock URL generation failed: {e}")
    return alert

def lock(reason: str = "Manual lock", password: str = None, folder: str = None) -> None:
    with open(VAULT_FLAG, 'w') as f:
        f.write(reason)
    alert = _build_remote_lock_alert(reason)
    dispatch_alert(alert)
    print(f"[VAULT] Locked. Reason: {reason}")
    if folder and password:
        key, _ = get_or_create_key(password, KEYFILE_PATH)
        count = encrypt_folder(folder, key)
        print(f"[VAULT] Encrypted {count} files.")

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