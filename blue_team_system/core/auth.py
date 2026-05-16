import uuid
import socket
import platform
import hashlib
import os
import time
import bcrypt

FAILED_ATTEMPTS: dict = {}  # username/session → count
MAX_ATTEMPTS = 5

def _publish_auth_event(event_type: str, severity: str, message: str) -> None:
    """
    Publishes auth events to event_bus if available.
    Falls back to alert_manager_stub if event_bus not yet wired.
    """
    try:
        from monitor.event_bus import publish
        publish(event_type, severity, {"message": message, "timestamp": time.time()})
    except Exception:
        try:
            from core.alert_manager_stub import dispatch_alert
            dispatch_alert({"type": event_type, "severity": severity,
                            "message": message, "timestamp": time.time()})
        except Exception:
            print(f"[AUTH EVENT] {severity} | {event_type} | {message}")

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def generate_device_fingerprint() -> str:
    mac = str(uuid.getnode())
    hostname = socket.gethostname()
    system = platform.system() + platform.release()
    raw = f"{mac}:{hostname}:{system}"
    return hashlib.sha256(raw.encode()).hexdigest()

def save_auth(password: str, filepath: str = "auth.dat") -> str:
    pw_hash = hash_password(password)
    fingerprint = generate_device_fingerprint()
    fp_hash = hashlib.sha256(fingerprint.encode()).hexdigest()
    with open(filepath, 'wb') as f:
        f.write(pw_hash + b'\n' + fp_hash.encode())
    return fingerprint

def verify_auth(password: str, filepath: str = "auth.dat",
                dev_mode: bool = False, session_id: str = "default") -> tuple[bool, dict | None]:
    """
    Returns (success, alert | None).
    Tracks failed attempts per session. Publishes AUTH_FAIL to event_bus.
    Locks vault after MAX_ATTEMPTS failures.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError("Auth file not found. Run save_auth() first.")

    with open(filepath, 'rb') as f:
        lines = f.read().split(b'\n')

    pw_hash = lines[0]
    saved_fp_hash = lines[1].decode()

    if not verify_password(password, pw_hash):
        FAILED_ATTEMPTS[session_id] = FAILED_ATTEMPTS.get(session_id, 0) + 1
        count = FAILED_ATTEMPTS[session_id]
        _publish_auth_event("AUTH_FAIL", "HIGH",
                            f"Failed login attempt {count}/{MAX_ATTEMPTS} for session '{session_id}'")
        if count >= MAX_ATTEMPTS:
            _publish_auth_event("AUTH_BRUTE_FORCE", "CRITICAL",
                                f"Max failed attempts reached for session '{session_id}'. Locking vault.")
            try:
                from core.vault import lock
                lock(reason=f"Brute force detected on session '{session_id}'")
            except Exception as e:
                print(f"[AUTH] Vault lock failed: {e}")
        return False, None

    if dev_mode:
        FAILED_ATTEMPTS[session_id] = 0
        _publish_auth_event("AUTH_SUCCESS", "LOW",
                            f"Successful login (dev_mode) for session '{session_id}'")
        return True, None

    current_fp = generate_device_fingerprint()
    current_fp_hash = hashlib.sha256(current_fp.encode()).hexdigest()

    if current_fp_hash != saved_fp_hash:
        alert = {
            "type": "DEVICE_MISMATCH",
            "severity": "HIGH",
            "timestamp": time.time(),
            "message": "Login attempted from unrecognized device. Access denied."
        }
        _publish_auth_event("DEVICE_MISMATCH", "HIGH", alert["message"])
        return False, alert

    FAILED_ATTEMPTS[session_id] = 0
    _publish_auth_event("AUTH_SUCCESS", "LOW",
                        f"Successful login for session '{session_id}'")
    return True, None

def reset_attempts(session_id: str = "default") -> None:
    FAILED_ATTEMPTS[session_id] = 0