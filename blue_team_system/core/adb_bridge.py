import subprocess
import time

ADB_TIMEOUT = 5  # seconds

def _run(cmd: list) -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=ADB_TIMEOUT
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except FileNotFoundError:
        return "", "adb not found in PATH", 1
    except subprocess.TimeoutExpired:
        return "", "adb command timed out", 1

def is_adb_available() -> bool:
    _, _, code = _run(["adb", "version"])
    return code == 0

def get_connected_devices() -> list:
    stdout, _, code = _run(["adb", "devices"])
    if code != 0:
        return []
    lines = stdout.splitlines()[1:]  # skip header
    devices = []
    for line in lines:
        if "\tdevice" in line:
            serial = line.split("\t")[0]
            devices.append(serial)
    return devices

def register_device(serial: str) -> bool:
    devices = get_connected_devices()
    if serial not in devices:
        print(f"[ADB] Device '{serial}' not found.")
        return False
    print(f"[ADB] Device '{serial}' registered.")
    return True

def forward_port(local_port: int = 5001, remote_port: int = 5001,
                 serial: str = None) -> bool:
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += ["forward", f"tcp:{local_port}", f"tcp:{remote_port}"]
    _, err, code = _run(cmd)
    if code != 0:
        print(f"[ADB] Port forward failed: {err}")
        return False
    print(f"[ADB] Forwarding localhost:{local_port} → device:{remote_port}")
    return True

def send_fingerprint_prompt(serial: str = None) -> bool:
    """
    Sends a broadcast to the companion app to show fingerprint prompt.
    App must be installed and running on device.
    """
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += [
        "shell", "am", "broadcast",
        "-a", "com.blueteam.FINGERPRINT_REQUEST",
        "--receiver-foreground"
    ]
    _, err, code = _run(cmd)
    if code != 0:
        print(f"[ADB] Broadcast failed: {err}")
        return False
    print("[ADB] Fingerprint prompt sent to phone.")
    return True

def wait_for_fingerprint_result(timeout: int = 30) -> bool | None:
    """
    Polls adb logcat for companion app result tag.
    Returns True (success), False (fail), or None (timeout).
    """
    deadline = time.time() + timeout
    try:
        proc = subprocess.Popen(
            ["adb", "logcat", "-s", "BlueteamAuth:D"],
            stdout=subprocess.PIPE, text=True
        )
        while time.time() < deadline:
            line = proc.stdout.readline()
            if "FINGERPRINT_OK" in line:
                proc.terminate()
                return True
            if "FINGERPRINT_FAIL" in line:
                proc.terminate()
                return False
        proc.terminate()
        return None
    except Exception as e:
        print(f"[ADB] Logcat error: {e}")
        return None