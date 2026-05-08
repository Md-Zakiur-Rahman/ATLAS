import uuid
import socket
import platform
import hashlib
import bcrypt

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
        # store: pw_hash (60 bytes) + newline + fp_hash
        f.write(pw_hash + b'\n' + fp_hash.encode())
    return fingerprint

def verify_auth(password: str, filepath: str = "auth.dat", dev_mode: bool = False) -> bool:
    if not __import__('os').path.exists(filepath):
        raise FileNotFoundError("Auth file not found. Run save_auth() first.")
    with open(filepath, 'rb') as f:
        lines = f.read().split(b'\n')
    pw_hash = lines[0]
    saved_fp_hash = lines[1].decode()

    if not verify_password(password, pw_hash):
        return False
    if dev_mode:
        return True

    current_fp = generate_device_fingerprint()
    current_fp_hash = hashlib.sha256(current_fp.encode()).hexdigest()
    return current_fp_hash == saved_fp_hash