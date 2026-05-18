import os
import pytest
from core.auth import hash_password, verify_password, save_auth, verify_auth, reset_attempts

AUTH_FILE = "test_auth.dat"

def teardown_function():
    if os.path.exists(AUTH_FILE):
        os.remove(AUTH_FILE)
    reset_attempts("test_session")

def test_password_hash_and_verify():
    hashed = hash_password("mypassword")
    assert verify_password("mypassword", hashed) is True
    assert verify_password("wrongpassword", hashed) is False

def test_save_and_verify_auth_dev_mode():
    save_auth("securepass", filepath=AUTH_FILE)
    success, alert = verify_auth("securepass", filepath=AUTH_FILE,
                                 dev_mode=True, session_id="test_session")
    assert success is True
    assert alert is None

def test_wrong_password_fails():
    save_auth("securepass", filepath=AUTH_FILE)
    success, alert = verify_auth("wrongpass", filepath=AUTH_FILE,
                                 dev_mode=True, session_id="test_session")
    assert success is False
    assert alert is None

def test_failed_attempts_tracked():
    save_auth("securepass", filepath=AUTH_FILE)
    for _ in range(3):
        verify_auth("wrong", filepath=AUTH_FILE,
                    dev_mode=True, session_id="test_session")
    from core.auth import FAILED_ATTEMPTS
    assert FAILED_ATTEMPTS.get("test_session", 0) == 3

def test_vault_locks_after_max_attempts():
    save_auth("securepass", filepath=AUTH_FILE)
    for _ in range(5):
        verify_auth("wrong", filepath=AUTH_FILE,
                    dev_mode=True, session_id="test_session")
    assert os.path.exists("vault.locked")
    os.remove("vault.locked")