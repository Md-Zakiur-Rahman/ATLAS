import os
from core.encryptor import encrypt_folder, decrypt_file
from core.key_manager import get_or_create_key

VAULT_FLAG = "vault.locked"

def lock_vault(folder: str, password: str, reason: str = "Manual lock") -> None:
    key, _ = get_or_create_key(password)
    count = encrypt_folder(folder, key)
    with open(VAULT_FLAG, 'w') as f:
        f.write(reason)
    print(f"[VAULT LOCKED] Reason: {reason} | Files encrypted: {count}")

def unlock_vault(folder: str, master_password: str) -> bool:
    if not os.path.exists(VAULT_FLAG):
        print("[VAULT] Not locked.")
        return False
    try:
        key, _ = get_or_create_key(master_password)
        for root, _, files in os.walk(folder):
            for filename in files:
                if filename.endswith(".enc"):
                    decrypt_file(os.path.join(root, filename), key)
        os.remove(VAULT_FLAG)
        print("[VAULT UNLOCKED] All files restored.")
        return True
    except Exception as e:
        print(f"[VAULT ERROR] {e}")
        return False

def is_locked() -> bool:
    return os.path.exists(VAULT_FLAG)