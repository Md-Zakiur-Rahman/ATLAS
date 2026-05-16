import os
import sys
import time
import threading
import hashlib
import secrets
from flask import Flask, request, jsonify

# --- Token store for remote lock ---
_remote_tokens: dict = {}   # token → expires_at
TOKEN_EXPIRY = 300          # 5 minutes

flask_app = Flask(__name__)

# ──────────────────────────────────────────
# DEVICE DETECTION
# ──────────────────────────────────────────

def has_laptop_sensor() -> bool:
    """Checks for Windows Hello / fprintd fingerprint sensor."""
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBioDB"
            )
            winreg.CloseKey(key)
            return True
        except Exception:
            return False
    elif sys.platform.startswith("linux"):
        return os.path.exists("/usr/bin/fprintd-verify")
    return False

def has_usb_phone() -> bool:
    """Checks if an Android device is connected via ADB."""
    try:
        from core.adb_bridge import get_connected_devices
        return len(get_connected_devices()) > 0
    except Exception:
        return False

# ──────────────────────────────────────────
# BIOMETRIC METHODS
# ──────────────────────────────────────────

def authenticate_laptop_sensor() -> bool:
    """Triggers Windows Hello or fprintd scan."""
    if sys.platform == "win32":
        try:
            import ctypes
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", "powershell",
                "-Command \"[Windows.Security.Credentials.UI.UserConsentVerifier,"
                "Windows.Security.Credentials.UI,ContentType=WindowsRuntime]"
                "::RequestVerificationAsync('Blue Team Auth') | Out-Null\"",
                None, 0
            )
            return result > 32
        except Exception as e:
            print(f"[BIOMETRIC] Windows Hello error: {e}")
            return False
    elif sys.platform.startswith("linux"):
        result = os.system("fprintd-verify")
        return result == 0
    return False

def authenticate_usb_phone() -> bool:
    """Sends fingerprint prompt to connected Android via ADB."""
    try:
        from core.adb_bridge import (get_connected_devices, send_fingerprint_prompt,
                                      wait_for_fingerprint_result)
        devices = get_connected_devices()
        if not devices:
            return False
        serial = devices[0]
        send_fingerprint_prompt(serial)
        result = wait_for_fingerprint_result(timeout=30)
        return result is True
    except Exception as e:
        print(f"[BIOMETRIC] USB phone error: {e}")
        return False

def generate_qr_fallback(session_id: str) -> str:
    """
    Generates a TOTP QR code for WiFi phone scan fallback.
    Returns the path to the saved QR image.
    """
    try:
        import pyotp
        import qrcode
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name="BlueTeam", issuer_name="BlueTeamSystem")
        img = qrcode.make(uri)
        path = f"qr_{session_id}.png"
        img.save(path)
        print(f"[BIOMETRIC] QR code saved: {path}")
        return path
    except Exception as e:
        print(f"[BIOMETRIC] QR generation error: {e}")
        return ""

def authenticate_totp_offline(entered_code: str, secret: str) -> bool:
    """Last resort: TOTP offline fallback."""
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.verify(entered_code)
    except Exception:
        return False

# ──────────────────────────────────────────
# BIOMETRIC CHAIN
# ──────────────────────────────────────────

def run_biometric_chain(session_id: str = "default",
                         totp_secret: str = None,
                         entered_totp: str = None) -> tuple[bool, str]:
    """
    Runs the full biometric fallback chain:
    1. Laptop sensor
    2. USB phone (ADB)
    3. QR code (WiFi TOTP)
    4. TOTP offline fallback

    Returns (success, method_used)
    """
    print("[BIOMETRIC] Starting fallback chain...")

    if has_laptop_sensor():
        print("[BIOMETRIC] Step 1: Laptop sensor detected. Scanning...")
        if authenticate_laptop_sensor():
            return True, "laptop_sensor"
        print("[BIOMETRIC] Laptop sensor failed. Trying next...")

    if has_usb_phone():
        print("[BIOMETRIC] Step 2: USB phone detected. Sending prompt...")
        if authenticate_usb_phone():
            return True, "usb_phone"
        print("[BIOMETRIC] USB phone failed. Trying next...")

    print("[BIOMETRIC] Step 3: No hardware available. Generating QR...")
    qr_path = generate_qr_fallback(session_id)
    if qr_path:
        print(f"[BIOMETRIC] Scan QR with phone: {qr_path}")

    if totp_secret and entered_totp:
        print("[BIOMETRIC] Step 4: TOTP offline fallback...")
        if authenticate_totp_offline(entered_totp, totp_secret):
            return True, "totp_offline"

    return False, "all_failed"

# ──────────────────────────────────────────
# REMOTE LOCK — FLASK ENDPOINT
# ──────────────────────────────────────────

def generate_remote_token() -> str:
    token = secrets.token_urlsafe(32)
    _remote_tokens[token] = time.time() + TOKEN_EXPIRY
    return token

def _cleanup_expired_tokens() -> None:
    now = time.time()
    expired = [t for t, exp in _remote_tokens.items() if exp < now]
    for t in expired:
        del _remote_tokens[t]

@flask_app.route("/remote-lock", methods=["POST"])
def remote_lock():
    _cleanup_expired_tokens()
    token = request.json.get("token", "")
    if token not in _remote_tokens:
        return jsonify({"error": "Invalid or expired token"}), 403
    del _remote_tokens[token]
    try:
        from core.vault import lock
        lock(reason="Remote lock via phone")
        return jsonify({"status": "locked", "message": "Vault locked successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@flask_app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

def start_flask_server(port: int = 5000) -> None:
    """Runs Flask in a background thread. Call this from main.py."""
    def run():
        flask_app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    print(f"[FLASK] Remote lock server running on port {port}")