import pyotp
import time
import hashlib

OTP_EXPIRY = 60
MAX_OTP_ATTEMPTS = 3

_active_otps: dict = {}

def _get_totp_secret(seed: str) -> str:
    raw = hashlib.sha256(seed.encode()).digest()
    import base64
    return base64.b32encode(raw).decode('utf-8')

def generate_otp(session_id: str, seed: str = "blueteam_default") -> str:
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

def send_otp_via_email(session_id: str, email: str,
                        seed: str = "blueteam_default") -> bool:
    """
    Generates OTP and sends it via email_sender (Member B).
    Falls back to printing the code if email_sender not yet wired.
    """
    code = generate_otp(session_id, seed)
    try:
        from notifications.email_sender import send_otp_email
        send_otp_email(email, code)
        print(f"[OTP] Sent to {email}")
        return True
    except Exception as e:
        print(f"[OTP] Email send failed (email_sender not wired yet): {e}")
        print(f"[OTP] Code for testing: {code}")
        return False

def verify_otp(session_id: str, entered_code: str) -> tuple[bool, str]:
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
    return entered_tail.strip()[-5:] == registered_tail[-5:]

def invalidate_otp(session_id: str) -> None:
    if session_id in _active_otps:
        del _active_otps[session_id]
        
def send_otp_via_supabase(email: str, session_id: str) -> bool:
    """
    Generates OTP locally and sends it via Supabase email edge function
    or falls back to email_sender stub.
    """
    code = generate_otp(session_id, seed=email)
    try:
        from core.supabase_client import get_client, load_env
        load_env()
        sb = get_client()
        # Call a Supabase edge function or use the email_sender
        # This triggers Member B's email_sender wired to Supabase
        from notifications.email_sender import send_otp_email
        send_otp_email(email, code)
        print(f"[OTP] Sent via Supabase to {email}")
        return True
    except Exception as e:
        print(f"[OTP] Supabase send failed: {e}")
        print(f"[OTP] Code for testing: {code}")
        return False