import pyotp
import time
import hashlib

OTP_EXPIRY = 60       # seconds
MAX_OTP_ATTEMPTS = 3

_active_otps: dict = {}   # session_id → {otp, expires_at, attempts}

def _get_totp_secret(seed: str) -> str:
    """Derives a consistent base32 secret from a seed string."""
    raw = hashlib.sha256(seed.encode()).digest()
    import base64
    return base64.b32encode(raw).decode('utf-8')

def generate_otp(session_id: str, seed: str = "blueteam_default") -> str:
    """
    Generates a 6-digit OTP for a session.
    Seed should be the user's email or phone tail in production.
    """
    totp = pyotp.TOTP(_get_totp_secret(seed), interval=OTP_EXPIRY)
    code = totp.now()
    _active_otps[session_id] = {
        "code": code,
        "expires_at": time.time() + OTP_EXPIRY,
        "attempts": 0,
        "seed": seed
    }
    print(f"[OTP] Generated for session '{session_id}' (expires in {OTP_EXPIRY}s)")
    return code

def verify_otp(session_id: str, entered_code: str) -> tuple[bool, str]:
    """
    Returns (success, reason).
    Reasons: 'ok', 'expired', 'wrong', 'max_attempts', 'no_session'
    """
    if session_id not in _active_otps:
        return False, "no_session"

    record = _active_otps[session_id]

    if time.time() > record["expires_at"]:
        del _active_otps[session_id]
        return False, "expired"

    if record["attempts"] >= MAX_OTP_ATTEMPTS:
        del _active_otps[session_id]
        return False, "max_attempts"

    if entered_code.strip() == record["code"]:
        del _active_otps[session_id]
        return True, "ok"

    record["attempts"] += 1
    remaining = MAX_OTP_ATTEMPTS - record["attempts"]
    print(f"[OTP] Wrong code for session '{session_id}'. {remaining} attempt(s) left.")
    return False, "wrong"

def validate_phone_tail(entered_tail: str, registered_tail: str) -> bool:
    """
    Validates last 5 digits of phone before sending OTP.
    Never reveals what was wrong to the caller.
    """
    return entered_tail.strip()[-5:] == registered_tail[-5:]

def invalidate_otp(session_id: str) -> None:
    if session_id in _active_otps:
        del _active_otps[session_id]