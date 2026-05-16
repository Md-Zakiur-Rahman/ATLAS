import os
import json
import time
import hashlib
from core.auth import hash_password, generate_device_fingerprint

REGISTER_FILE = "registered_user.json"

def is_registered() -> bool:
    return os.path.exists(REGISTER_FILE)

def register_user(name: str, email: str, password: str,
                  phone: str, telegram_id: str = "") -> bool:
    """
    One-time registration. Stores bcrypt hash, device fingerprint,
    phone last 5 digits, and Telegram ID.
    """
    try:
        if is_registered():
            print("[REGISTER] User already registered.")
            return False

        pw_hash = hash_password(password).decode('utf-8')
        fingerprint = generate_device_fingerprint()
        fp_hash = hashlib.sha256(fingerprint.encode()).hexdigest()
        phone_tail = phone[-5:] if len(phone) >= 5 else phone

        data = {
            "name": name,
            "email": email,
            "password_hash": pw_hash,
            "phone_tail": phone_tail,
            "telegram_id": telegram_id,
            "fingerprint_hash": fp_hash,
            "registered_at": time.time(),
            "whitelist_processes": ["chrome.exe", "code.exe", "python.exe"],
            "whitelist_ips": ["127.0.0.1"],
        }

        with open(REGISTER_FILE, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[REGISTER] User '{name}' registered successfully.")
        return True
    except Exception as e:
        print(f"[REGISTER ERROR] {e}")
        return False

def load_user() -> dict | None:
    if not is_registered():
        return None
    with open(REGISTER_FILE, 'r') as f:
        return json.load(f)

def update_telegram_id(telegram_id: str) -> bool:
    user = load_user()
    if not user:
        return False
    user["telegram_id"] = telegram_id
    with open(REGISTER_FILE, 'w') as f:
        json.dump(user, f, indent=2)
    print(f"[REGISTER] Telegram ID updated.")
    return True

def get_whitelist() -> dict:
    user = load_user()
    if not user:
        return {"processes": [], "ips": []}
    return {
        "processes": user.get("whitelist_processes", []),
        "ips": user.get("whitelist_ips", [])
    }

def add_to_whitelist(category: str, value: str) -> bool:
    """category: 'whitelist_processes' or 'whitelist_ips'"""
    user = load_user()
    if not user:
        return False
    if value not in user.get(category, []):
        user.setdefault(category, []).append(value)
        with open(REGISTER_FILE, 'w') as f:
            json.dump(user, f, indent=2)
    return True