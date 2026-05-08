import os
import random

OVERWRITE_PASSES = 3

def shred_file(path: str, passes: int = OVERWRITE_PASSES) -> bool:
    """
    Overwrites file content multiple times before deleting.
    Prevents simple file recovery from disk.
    """
    try:
        if not os.path.exists(path):
            print(f"[SHREDDER] File not found: {path}")
            return False

        file_size = os.path.getsize(path)

        with open(path, 'r+b') as f:
            for p in range(passes):
                f.seek(0)
                if p % 2 == 0:
                    f.write(os.urandom(file_size))   # random pass
                else:
                    f.write(b'\x00' * file_size)     # zero pass
                f.flush()
                os.fsync(f.fileno())

        os.remove(path)
        print(f"[SHREDDER] Securely deleted: {path} ({passes} passes)")
        return True
    except Exception as e:
        print(f"[SHREDDER ERROR] {e}")
        return False

def shred_folder(folder: str, passes: int = OVERWRITE_PASSES) -> int:
    """
    Shreds all files in a folder recursively. Does not delete the folder itself.
    """
    count = 0
    for root, _, files in os.walk(folder):
        for filename in files:
            full_path = os.path.join(root, filename)
            if shred_file(full_path, passes):
                count += 1
    print(f"[SHREDDER] Shredded {count} files in '{folder}'")
    return count