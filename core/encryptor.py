"""
Authoritative encryption engine migrated from legacy Blue Team subsystem.

Supports secure file/folder encryption and decryption with AES-GCM.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12


def encrypt_file(path: str, key: bytes) -> bool:
    try:
        target = Path(path)
        plaintext = target.read_bytes()

        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        tmp_path = str(target) + ".tmp"
        Path(tmp_path).write_bytes(nonce + ciphertext)

        enc_path = str(target) + ".enc"
        os.replace(tmp_path, enc_path)
        os.remove(str(target))
        return True
    except Exception:
        return False


def decrypt_file(path: str, key: bytes) -> bool:
    try:
        target = Path(path)
        data = target.read_bytes()

        nonce = data[:NONCE_SIZE]
        ciphertext = data[NONCE_SIZE:]

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        original_path = str(target).replace(".enc", "")
        tmp_path = original_path + ".tmp"
        Path(tmp_path).write_bytes(plaintext)

        os.replace(tmp_path, original_path)
        os.remove(str(target))
        return True
    except Exception:
        return False


def encrypt_folder(folder: str, key: bytes) -> int:
    count = 0
    for root, _, files in os.walk(folder):
        for filename in files:
            if filename.endswith(".enc") or filename.endswith(".keyfile") or filename.endswith(".tmp"):
                continue
            full_path = os.path.join(root, filename)
            if encrypt_file(full_path, key):
                count += 1
    return count


def decrypt_folder(folder: str, key: bytes) -> int:
    count = 0
    for root, _, files in os.walk(folder):
        for filename in files:
            if filename.endswith(".enc"):
                full_path = os.path.join(root, filename)
                if decrypt_file(full_path, key):
                    count += 1
    return count

