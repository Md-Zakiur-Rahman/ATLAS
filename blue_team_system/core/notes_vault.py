import os
import json
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NOTES_FILE = "notes.vault"
NONCE_SIZE = 12

def _encrypt_data(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    return nonce + aesgcm.encrypt(nonce, data, None)

def _decrypt_data(data: bytes, key: bytes) -> bytes:
    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def save_note(title: str, content: str, key: bytes) -> bool:
    try:
        notes = load_all_notes(key) or {}
        notes[title] = {
            "content": content,
            "updated_at": time.time()
        }
        raw = json.dumps(notes).encode('utf-8')
        encrypted = _encrypt_data(raw, key)
        with open(NOTES_FILE, 'wb') as f:
            f.write(encrypted)
        print(f"[NOTES] Saved note: '{title}'")
        return True
    except Exception as e:
        print(f"[NOTES ERROR] {e}")
        return False

def load_all_notes(key: bytes) -> dict | None:
    if not os.path.exists(NOTES_FILE):
        return {}
    try:
        with open(NOTES_FILE, 'rb') as f:
            encrypted = f.read()
        raw = _decrypt_data(encrypted, key)
        return json.loads(raw.decode('utf-8'))
    except Exception as e:
        print(f"[NOTES ERROR] Could not decrypt notes: {e}")
        return None

def get_note(title: str, key: bytes) -> str | None:
    notes = load_all_notes(key)
    if notes and title in notes:
        return notes[title]["content"]
    return None

def delete_note(title: str, key: bytes) -> bool:
    notes = load_all_notes(key)
    if not notes or title not in notes:
        return False
    del notes[title]
    raw = json.dumps(notes).encode('utf-8')
    encrypted = _encrypt_data(raw, key)
    with open(NOTES_FILE, 'wb') as f:
        f.write(encrypted)
    print(f"[NOTES] Deleted note: '{title}'")
    return True