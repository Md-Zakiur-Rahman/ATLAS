import os
import json
import time
from core.auth import hash_password, verify_password, generate_device_fingerprint
import hashlib

PROFILES_FILE = "auth_profiles.json"

def _load_profiles() -> dict:
    if not os.path.exists(PROFILES_FILE):
        return {}
    with open(PROFILES_FILE, 'r') as f:
        return json.load(f)

def _save_profiles(profiles: dict) -> None:
    with open(PROFILES_FILE, 'w') as f:
        json.dump(profiles, f, indent=2)

def create_profile(username: str, password: str, role: str = "user") -> bool:
    """
    Roles: 'admin' or 'user'.
    Admin can lock/unlock vault. User can only encrypt/decrypt files.
    """
    profiles = _load_profiles()
    if username in profiles:
        print(f"[PROFILES] User '{username}' already exists.")
        return False

    pw_hash = hash_password(password).decode('utf-8')
    fp = generate_device_fingerprint()
    fp_hash = hashlib.sha256(fp.encode()).hexdigest()

    profiles[username] = {
        "password_hash": pw_hash,
        "fingerprint_hash": fp_hash,
        "role": role,
        "created_at": time.time(),
        "failed_attempts": 0,
        "locked": False
    }
    _save_profiles(profiles)
    print(f"[PROFILES] Created profile: {username} ({role})")
    return True

def verify_profile(username: str, password: str, dev_mode: bool = False) -> tuple[bool, str | None]:
    """
    Returns (success, role) or (False, None) on failure.
    Locks account after 5 failed attempts.
    """
    profiles = _load_profiles()
    if username not in profiles:
        print(f"[PROFILES] User '{username}' not found.")
        return False, None

    profile = profiles[username]

    if profile["locked"]:
        print(f"[PROFILES] Account '{username}' is locked.")
        return False, None

    pw_hash = profile["password_hash"].encode('utf-8')
    if not verify_password(password, pw_hash):
        profile["failed_attempts"] += 1
        if profile["failed_attempts"] >= 5:
            profile["locked"] = True
            print(f"[PROFILES] Account '{username}' locked after 5 failed attempts.")
        _save_profiles(profiles)
        return False, None

    if not dev_mode:
        current_fp = generate_device_fingerprint()
        current_fp_hash = hashlib.sha256(current_fp.encode()).hexdigest()
        if current_fp_hash != profile["fingerprint_hash"]:
            print(f"[PROFILES] Device mismatch for '{username}'.")
            profile["failed_attempts"] += 1
            _save_profiles(profiles)
            return False, None

    profile["failed_attempts"] = 0
    _save_profiles(profiles)
    return True, profile["role"]

def unlock_profile(username: str) -> bool:
    profiles = _load_profiles()
    if username not in profiles:
        return False
    profiles[username]["locked"] = False
    profiles[username]["failed_attempts"] = 0
    _save_profiles(profiles)
    print(f"[PROFILES] Account '{username}' unlocked.")
    return True

def delete_profile(username: str) -> bool:
    profiles = _load_profiles()
    if username not in profiles:
        return False
    del profiles[username]
    _save_profiles(profiles)
    print(f"[PROFILES] Deleted profile: {username}")
    return True

def list_profiles() -> list:
    return list(_load_profiles().keys())