import sys
import os

APP_NAME = "BlueTeamSystem"

def _get_exe_path() -> str:
    """Returns the path to the current executable or script."""
    if getattr(sys, 'frozen', False):
        return sys.executable  # PyInstaller bundle
    return os.path.abspath(sys.argv[0])

def enable_autostart_windows(minimized: bool = True) -> bool:
    try:
        import winreg
        exe_path = _get_exe_path()
        args = f'"{exe_path}" --minimized' if minimized else f'"{exe_path}"'
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, args)
        winreg.CloseKey(key)
        print(f"[AUTOSTART] Windows autostart enabled: {args}")
        return True
    except Exception as e:
        print(f"[AUTOSTART] Windows error: {e}")
        return False

def disable_autostart_windows() -> bool:
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        )
        winreg.DeleteValue(key, APP_NAME)
        winreg.CloseKey(key)
        print("[AUTOSTART] Windows autostart disabled.")
        return True
    except FileNotFoundError:
        print("[AUTOSTART] No autostart entry found.")
        return False
    except Exception as e:
        print(f"[AUTOSTART] Windows disable error: {e}")
        return False

def enable_autostart_linux(minimized: bool = True) -> bool:
    try:
        autostart_dir = os.path.expanduser("~/.config/autostart")
        os.makedirs(autostart_dir, exist_ok=True)
        exe_path = _get_exe_path()
        args = f"{exe_path} --minimized" if minimized else exe_path
        desktop_entry = f"""[Desktop Entry]
Type=Application
Name={APP_NAME}
Exec={args}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""
        path = os.path.join(autostart_dir, "blueteam.desktop")
        with open(path, 'w') as f:
            f.write(desktop_entry)
        print(f"[AUTOSTART] Linux autostart enabled: {path}")
        return True
    except Exception as e:
        print(f"[AUTOSTART] Linux error: {e}")
        return False

def disable_autostart_linux() -> bool:
    try:
        path = os.path.expanduser("~/.config/autostart/blueteam.desktop")
        if os.path.exists(path):
            os.remove(path)
            print("[AUTOSTART] Linux autostart disabled.")
            return True
        print("[AUTOSTART] No autostart entry found.")
        return False
    except Exception as e:
        print(f"[AUTOSTART] Linux disable error: {e}")
        return False

def enable_autostart(minimized: bool = True) -> bool:
    if sys.platform == "win32":
        return enable_autostart_windows(minimized)
    elif sys.platform.startswith("linux"):
        return enable_autostart_linux(minimized)
    else:
        print(f"[AUTOSTART] Unsupported platform: {sys.platform}")
        return False

def disable_autostart() -> bool:
    if sys.platform == "win32":
        return disable_autostart_windows()
    elif sys.platform.startswith("linux"):
        return disable_autostart_linux()
    else:
        print(f"[AUTOSTART] Unsupported platform: {sys.platform}")
        return False

def is_autostart_enabled() -> bool:
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_READ
            )
            winreg.QueryValueEx(key, APP_NAME)
            winreg.CloseKey(key)
            return True
        except Exception:
            return False
    elif sys.platform.startswith("linux"):
        return os.path.exists(
            os.path.expanduser("~/.config/autostart/blueteam.desktop")
        )
    return False