import os
import hashlib

KEY_SIZE = 32
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

def rotate_key(old_password: str, new_password: str, keyfile_path: str = "vault.keyfile"):
    """
    Generates a new salt and derives a new key from new_password.
    Returns (old_key, new_key) so the caller can re-encrypt files.
    """
    old_key, _ = get_or_create_key(old_password, keyfile_path)
    new_salt = generate_salt()
    new_key = derive_key(new_password, new_salt)
    save_keyfile(new_salt, keyfile_path)
    print("[KEY ROTATION] New key derived and keyfile updated.")
    return old_key, new_key

def rotate_key_for_folder(old_password: str, new_password: str, folder: str, keyfile_path: str = "vault.keyfile") -> bool:
    """
    Full key rotation: decrypts folder with old key, re-encrypts with new key.
    Safe: only deletes old keyfile after successful re-encryption.
    """
    from core.encryptor import decrypt_folder, encrypt_folder
    try:
        old_key, _ = get_or_create_key(old_password, keyfile_path)
        decrypted = decrypt_folder(folder, old_key)
        print(f"[KEY ROTATION] Decrypted {decrypted} files with old key.")

        new_salt = generate_salt()
        new_key = derive_key(new_password, new_salt)
        save_keyfile(new_salt, keyfile_path)

        encrypted = encrypt_folder(folder, new_key)
        print(f"[KEY ROTATION] Re-encrypted {encrypted} files with new key.")
        return True
    except Exception as e:
        print(f"[KEY ROTATION ERROR] {e}")
        return False