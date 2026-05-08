import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # 96 bits, standard for AES-GCM

def encrypt_file(path: str, key: bytes) -> bool:
    try:
        with open(path, 'rb') as f:
            plaintext = f.read()

        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        tmp_path = path + ".tmp"
        with open(tmp_path, 'wb') as f:
            f.write(nonce + ciphertext)  # prepend nonce

        os.replace(tmp_path, path + ".enc")
        os.remove(path)
        return True
    except Exception as e:
        print(f"[ENCRYPT ERROR] {e}")
        return False

def decrypt_file(path: str, key: bytes) -> bool:
    try:
        with open(path, 'rb') as f:
            data = f.read()

        nonce = data[:NONCE_SIZE]
        ciphertext = data[NONCE_SIZE:]

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        original_path = path.replace(".enc", "")
        tmp_path = original_path + ".tmp"
        with open(tmp_path, 'wb') as f:
            f.write(plaintext)

        os.replace(tmp_path, original_path)
        os.remove(path)
        return True
    except Exception as e:
        print(f"[DECRYPT ERROR] {e}")
        return False

def encrypt_folder(folder: str, key: bytes) -> int:
    count = 0
    for root, _, files in os.walk(folder):
        for filename in files:
            if filename.endswith(".enc") or filename.endswith(".keyfile"):
                continue
            full_path = os.path.join(root, filename)
            if encrypt_file(full_path, key):
                count += 1
    return count