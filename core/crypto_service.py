"""
Unified crypto integration layer.

This service now delegates encryption/vault semantics to the authoritative
vault/encryptor/key_manager stack integrated from legacy Blue Team logic.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Optional, Tuple

from core.encryptor import decrypt_file as _legacy_decrypt_file
from core.encryptor import encrypt_file as _legacy_encrypt_file
from core.key_manager import get_or_create_key
from core.runtime_state import runtime_state
from core.vault import emergency_reencrypt, is_locked, lock as vault_lock, unlock as vault_unlock
from database.db_manager import log_event

STORAGE_ROOT = Path("storage")
ENCRYPTED_DIR = STORAGE_ROOT / "encrypted"
DECRYPTED_DIR = STORAGE_ROOT / "decrypted"
DEFAULT_KEYFILE_PATH = "vault.keyfile"


def _ensure_dirs() -> None:
    ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)
    DECRYPTED_DIR.mkdir(parents=True, exist_ok=True)


def _record(operation: str, filename: str, user: str, success: bool, detail: str, vault_state: Optional[str] = None) -> None:
    event = {
        "filename": filename,
        "operation": operation,
        "timestamp": time.time(),
        "user": user,
        "success": success,
        "detail": detail,
        "vault_state": vault_state or ("locked" if is_locked() else "unlocked"),
    }
    runtime_state.add_encryption_event(event)
    log_event(
        event_type=f"FILE_{operation.upper()}",
        severity="LOW" if success else "HIGH",
        details=event,
        category="ENCRYPTION",
    )


def encrypt_file(source_path: str, user: str, password: str, output_path: Optional[str] = None) -> Tuple[bool, str]:
    _ensure_dirs()
    src = Path(source_path)
    target = Path(output_path) if output_path else ENCRYPTED_DIR / f"{src.name}.enc"

    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_plain = Path(tmp_dir) / src.name
            shutil.copy2(src, tmp_plain)
            key, _ = get_or_create_key(password, DEFAULT_KEYFILE_PATH)
            ok = _legacy_encrypt_file(str(tmp_plain), key)
            if not ok:
                raise RuntimeError("legacy encrypt_file failed")
            tmp_enc = Path(str(tmp_plain) + ".enc")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(tmp_enc), str(target))
        _record("encrypt", src.name, user, True, str(target))
        return True, str(target)
    except Exception as error:
        _record("encrypt", src.name, user, False, str(error))
        return False, str(error)


def decrypt_file(source_path: str, user: str, password: str, output_path: Optional[str] = None) -> Tuple[bool, str]:
    _ensure_dirs()
    src = Path(source_path)
    default_name = src.name[:-4] if src.name.endswith(".enc") else src.name
    target = Path(output_path) if output_path else DECRYPTED_DIR / default_name

    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_enc = Path(tmp_dir) / src.name
            shutil.copy2(src, tmp_enc)
            key, _ = get_or_create_key(password, DEFAULT_KEYFILE_PATH)
            ok = _legacy_decrypt_file(str(tmp_enc), key)
            if not ok:
                raise RuntimeError("legacy decrypt_file failed")
            tmp_dec = Path(str(tmp_enc).replace(".enc", ""))
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(tmp_dec), str(target))
        _record("decrypt", src.name, user, True, str(target))
        return True, str(target)
    except Exception as error:
        _record("decrypt", src.name, user, False, str(error))
        return False, str(error)


def lock_vault(folder: str, password: str, user: str, reason: str = "Manual lock") -> Tuple[bool, int]:
    try:
        files = vault_lock(reason=reason, password=password, folder=folder)
        _record("vault_lock", os.path.basename(folder.rstrip("\\/")), user, True, f"encrypted={files}", vault_state="locked")
        return True, files
    except Exception as error:
        _record("vault_lock", os.path.basename(folder.rstrip("\\/")), user, False, str(error), vault_state="unlocked")
        return False, 0


def unlock_vault(folder: str, password: str, user: str) -> Tuple[bool, int]:
    try:
        files = vault_unlock(folder=folder, password=password)
        _record("vault_unlock", os.path.basename(folder.rstrip("\\/")), user, True, f"restored={files}", vault_state="unlocked")
        return True, files
    except Exception as error:
        _record("vault_unlock", os.path.basename(folder.rstrip("\\/")), user, False, str(error), vault_state="locked")
        return False, 0


def emergency_reencrypt_vault(folder: str, old_password: str, new_password: str, user: str) -> Tuple[bool, int]:
    try:
        files = emergency_reencrypt(folder, old_password, new_password)
        _record("vault_reencrypt", os.path.basename(folder.rstrip("\\/")), user, True, f"secured={files}", vault_state="locked")
        return True, files
    except Exception as error:
        _record("vault_reencrypt", os.path.basename(folder.rstrip("\\/")), user, False, str(error), vault_state="locked")
        return False, 0


def activate_vault_lock(reason: str) -> None:
    # Response-engine lock path. Performs real vault state activation even
    # when folder/password context is not available.
    vault_lock(reason=reason)
