import os
import hashlib

KEY_SIZE = 32       # 256 bits
SALT_SIZE = 16
ITERATIONS = 100_000

def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password.encode('utf-8'),
        salt=salt,
        iterations=ITERATIONS,
        dklen=KEY_SIZE
    )

def save_keyfile(salt: bytes, filepath: str = "vault.keyfile") -> None:
    with open(filepath, 'wb') as f:
        f.write(salt)

def load_keyfile(filepath: str = "vault.keyfile") -> bytes:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Key file not found: {filepath}")
    with open(filepath, 'rb') as f:
        return f.read()

def get_or_create_key(password: str, keyfile_path: str = "vault.keyfile"):
    if os.path.exists(keyfile_path):
        salt = load_keyfile(keyfile_path)
    else:
        salt = generate_salt()
        save_keyfile(salt, keyfile_path)
    key = derive_key(password, salt)
    return key, salt