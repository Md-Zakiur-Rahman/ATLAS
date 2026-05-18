import os
import json
import time
import hashlib
from core.auth import hash_password, generate_device_fingerprint

REGISTER_FILE = "registered_user.json"

DEFAULT_WHITELIST_PROCESSES = [
    "chrome.exe", "code.exe", "python.exe",
    "explorer.exe", "svchost.exe", "notepad.exe"
]

DEFAULT_WHITELIST_IPS = [
    "127.0.0.1", "192.168.1.1"
]

def is_registered() -> bool:
    return os.path.exists(REGISTER_FILE)

def register_user(name: str, email: str, password: str,
                  phone: str, telegram_id: str = "") -> bool:
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
            "whitelist_processes": DEFAULT_WHITELIST_PROCESSES.copy(),
            "whitelist_ips": DEFAULT_WHITELIST_IPS.copy(),
            "whitelist_paths": [],
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
        return {"processes": [], "ips": [], "paths": []}
    return {
        "processes": user.get("whitelist_processes", []),
        "ips": user.get("whitelist_ips", []),
        "paths": user.get("whitelist_paths", []),
    }

def add_to_whitelist(category: str, value: str) -> bool:
    user = load_user()
    if not user:
        return False
    if value not in user.get(category, []):
        user.setdefault(category, []).append(value)
        with open(REGISTER_FILE, 'w') as f:
            json.dump(user, f, indent=2)
    return True

def remove_from_whitelist(category: str, value: str) -> bool:
    user = load_user()
    if not user:
        return False
    if value in user.get(category, []):
        user[category].remove(value)
        with open(REGISTER_FILE, 'w') as f:
            json.dump(user, f, indent=2)
    return True

def seed_demo_whitelist() -> None:
    """
    Call this during demo machine setup to pre-populate
    the whitelist with safe processes and IPs.
    """
    add_to_whitelist("whitelist_processes", "chrome.exe")
    add_to_whitelist("whitelist_processes", "code.exe")
    add_to_whitelist("whitelist_processes", "python.exe")
    add_to_whitelist("whitelist_ips", "127.0.0.1")
    add_to_whitelist("whitelist_ips", "192.168.1.1")
    print("[REGISTER] Demo whitelist seeded.")
    
def sync_user_to_supabase() -> bool:
    """
    Syncs the locally registered user to Supabase.
    Call this after register_user() succeeds.
    """
    user = load_user()
    if not user:
        print("[SUPABASE] No local user to sync.")
        return False
    try:
        from core.supabase_client import get_client, load_env
        load_env()
        sb = get_client()
        # Store everything except the password hash for safety
        data = {
            "name": user["name"],
            "email": user["email"],
            "phone_tail": user["phone_tail"],
            "telegram_id": user.get("telegram_id", ""),
            "fingerprint_hash": user["fingerprint_hash"],
            "registered_at": user["registered_at"],
            "whitelist_processes": user.get("whitelist_processes", []),
            "whitelist_ips": user.get("whitelist_ips", []),
        }
        sb.table("users").upsert(data).execute()
        print(f"[SUPABASE] User '{user['name']}' synced.")
        return True
    except Exception as e:
        print(f"[SUPABASE] Sync failed (running offline): {e}")
        return False

def fetch_user_from_supabase(email: str) -> dict | None:
    """
    Fetches user record from Supabase by email.
    Falls back to local file if offline.
    """
    try:
        from core.supabase_client import get_client, load_env
        load_env()
        sb = get_client()
        result = sb.table("users").select("*").eq("email", email).execute()
        if result.data:
            return result.data[0]
        return None
    except Exception as e:
        print(f"[SUPABASE] Fetch failed (running offline): {e}")
        return load_user()