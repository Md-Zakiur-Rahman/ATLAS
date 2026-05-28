import os
import sys
from typing import Optional, Tuple


def has_laptop_sensor() -> bool:
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBioDB",
            )
            winreg.CloseKey(key)
            return True
        except Exception:
            return False
    return False


def has_usb_phone() -> bool:
    try:
        from core.adb_bridge import get_connected_devices
        return len(get_connected_devices()) > 0
    except Exception:
        return False


def authenticate_usb_phone() -> bool:
    try:
        from core.adb_bridge import get_connected_devices, send_fingerprint_prompt, wait_for_fingerprint_result
        devices = get_connected_devices()
        if not devices:
            return False
        serial = devices[0]
        if not send_fingerprint_prompt(serial):
            return False
        result = wait_for_fingerprint_result(timeout=30)
        return result is True
    except Exception:
        return False


def generate_qr_fallback(session_id: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        import pyotp
        import qrcode
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=session_id, issuer_name="BlueTeamSystem")
        img = qrcode.make(uri)
        os.makedirs("assets", exist_ok=True)
        path = os.path.join("assets", f"qr_{session_id.replace('@', '_')}.png")
        img.save(path)
        return path, secret
    except Exception:
        return None, None


def verify_qr_totp(code: str, secret: str) -> bool:
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.verify(code.strip(), valid_window=1)
    except Exception:
        return False

