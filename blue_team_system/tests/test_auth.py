import os
import pytest
from core.auth import hash_password, verify_password, save_auth, verify_auth

AUTH_FILE = "test_auth.dat"

def teardown_function():
    if os.path.exists(AUTH_FILE):
        os.remove(AUTH_FILE)

def test_password_hash_and_verify():
    hashed = hash_password("mypassword")
    assert verify_password("mypassword", hashed) is True
    assert verify_password("wrongpassword", hashed) is False

def test_save_and_verify_auth_dev_mode():
    save_auth("securepass", filepath=AUTH_FILE)
    assert verify_auth("securepass", filepath=AUTH_FILE, dev_mode=True) is True

def test_wrong_password_fails():
    save_auth("securepass", filepath=AUTH_FILE)
    assert verify_auth("wrongpass", filepath=AUTH_FILE, dev_mode=True) is False