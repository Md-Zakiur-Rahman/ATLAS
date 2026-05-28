"""
Authoritative vault lifecycle (lock/unlock/emergency re-encrypt).
Integrated from legacy Blue Team vault semantics.
"""

from __future__ import annotations

import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.encryptor import decrypt_folder, encrypt_folder
from core.key_manager import get_or_create_key, rotate_key
from core.runtime_state import runtime_state
from database.db_manager import log_event
from monitor.event_bus import event_bus

VAULT_FLAG = "vault.locked"
KEYFILE_PATH = "vault.keyfile"
VAULT_ROOT = Path("vault")
VAULT_PROTECTED = VAULT_ROOT / "protected"
VAULT_QUARANTINE = VAULT_ROOT / "quarantine"
VAULT_BACKUPS = VAULT_ROOT / "backups"
VAULT_FORENSIC_LOGS = VAULT_ROOT / "forensic_logs"


def ensure_vault_structure() -> None:
    for folder in (VAULT_PROTECTED, VAULT_QUARANTINE, VAULT_BACKUPS, VAULT_FORENSIC_LOGS):
        folder.mkdir(parents=True, exist_ok=True)


def _set_readonly(path: Path, readonly: bool) -> None:
    try:
        mode = path.stat().st_mode
        if readonly:
            path.chmod(mode & ~0o222)
        else:
            path.chmod(mode | 0o200)
    except Exception:
        return


def isolate_folder(folder: str) -> dict:
    ensure_vault_structure()
    target = Path(folder).resolve()
    impacted = 0
    if target.exists():
        _set_readonly(target, True)
        for child in target.rglob("*"):
            _set_readonly(child, True)
            impacted += 1
    marker = VAULT_QUARANTINE / f"{target.name}_{int(time.time())}.marker"
    marker.write_text(f"isolated={target}\ntime={datetime.utcnow().isoformat()}\n", encoding="utf-8")
    return {"folder": str(target), "impacted_items": impacted, "marker": str(marker)}


def release_folder(folder: str) -> dict:
    target = Path(folder).resolve()
    restored = 0
    if target.exists():
        _set_readonly(target, False)
        for child in target.rglob("*"):
            _set_readonly(child, False)
            restored += 1
    return {"folder": str(target), "restored_items": restored}


def backup_folder_snapshot(folder: str) -> Optional[str]:
    ensure_vault_structure()
    target = Path(folder).resolve()
    if not target.exists() or not target.is_dir():
        return None
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_target = VAULT_BACKUPS / f"{target.name}_{stamp}"
    try:
        shutil.copytree(target, backup_target, dirs_exist_ok=True)
        return str(backup_target)
    except Exception:
        return None


ensure_vault_structure()


def is_locked() -> bool:
    return os.path.exists(VAULT_FLAG)


def _set_lock_state(locked: bool, reason: str, severity: str) -> None:
    runtime_state.update(vault_locked=locked)
    event_type = "VAULT_LOCKED" if locked else "VAULT_UNLOCKED"
    event_bus.publish(
        {
            "event_type": event_type,
            "reason": reason,
            "severity": severity,
            "timestamp": time.time(),
        }
    )
    log_event(
        event_type=event_type,
        severity=severity,
        details={"reason": reason},
        category="CONTAINMENT",
    )


def lock(reason: str = "Manual lock", password: Optional[str] = None, folder: Optional[str] = None) -> int:
    files_encrypted = 0
    if folder and password:
        key, _ = get_or_create_key(password, KEYFILE_PATH)
        files_encrypted = encrypt_folder(folder, key)

    with open(VAULT_FLAG, "w", encoding="utf-8") as handle:
        handle.write(reason)

    runtime_state.set_nested("vault_state", {"last_folder": folder, "keyfile_path": KEYFILE_PATH})
    _set_lock_state(True, reason, "CRITICAL")
    return files_encrypted


def unlock(folder: str, password: str) -> int:
    if not is_locked():
        return 0

    key, _ = get_or_create_key(password, KEYFILE_PATH)
    restored = decrypt_folder(folder, key)
    os.remove(VAULT_FLAG)
    _set_lock_state(False, "Vault unlocked", "LOW")
    return restored


def emergency_reencrypt(folder: str, old_password: str, new_password: str) -> int:
    old_key, new_key = rotate_key(old_password, new_password, KEYFILE_PATH)
    decrypt_folder(folder, old_key)
    count = encrypt_folder(folder, new_key)
    with open(VAULT_FLAG, "w", encoding="utf-8") as handle:
        handle.write("Emergency re-encryption triggered")
    _set_lock_state(True, "Emergency re-encryption triggered", "CRITICAL")
    log_event(
        event_type="EMERGENCY_REENCRYPT",
        severity="CRITICAL",
        details={"files_secured": count},
        category="CONTAINMENT",
    )
    return count
