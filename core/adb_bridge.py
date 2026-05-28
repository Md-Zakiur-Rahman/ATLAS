import subprocess
import time

ADB_TIMEOUT = 5


def _run(cmd: list) -> tuple[str, str, int]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=ADB_TIMEOUT)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception:
        return "", "adb command failed", 1


def is_adb_available() -> bool:
    _, _, code = _run(["adb", "version"])
    return code == 0


def get_connected_devices() -> list[str]:
    stdout, _, code = _run(["adb", "devices"])
    if code != 0:
        return []
    lines = stdout.splitlines()[1:]
    devices = []
    for line in lines:
        if "\tdevice" in line:
            devices.append(line.split("\t")[0])
    return devices


def send_fingerprint_prompt(serial: str | None = None) -> bool:
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += ["shell", "am", "broadcast", "-a", "com.blueteam.FINGERPRINT_REQUEST", "--receiver-foreground"]
    _, _, code = _run(cmd)
    return code == 0


def wait_for_fingerprint_result(timeout: int = 30) -> bool | None:
    deadline = time.time() + timeout
    try:
        proc = subprocess.Popen(["adb", "logcat", "-s", "BlueteamAuth:D"], stdout=subprocess.PIPE, text=True)
        while time.time() < deadline:
            line = proc.stdout.readline()
            if "FINGERPRINT_OK" in line:
                proc.terminate()
                return True
            if "FINGERPRINT_FAIL" in line:
                proc.terminate()
                return False
        proc.terminate()
    except Exception:
        return None
    return None

