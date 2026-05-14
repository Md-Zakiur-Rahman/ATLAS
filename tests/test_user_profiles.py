import os
import pytest
from core.user_profiles import create_profile, verify_profile, unlock_profile, delete_profile, list_profiles

PROFILES_FILE = "auth_profiles.json"

def teardown_function():
    if os.path.exists(PROFILES_FILE):
        os.remove(PROFILES_FILE)

def test_create_and_verify_profile():
    create_profile("alice", "password123", role="admin")
    success, role = verify_profile("alice", "password123", dev_mode=True)
    assert success is True
    assert role == "admin"

def test_wrong_password_fails():
    create_profile("bob", "correctpass", role="user")
    success, role = verify_profile("bob", "wrongpass", dev_mode=True)
    assert success is False
    assert role is None

def test_duplicate_profile_rejected():
    create_profile("charlie", "pass1")
    result = create_profile("charlie", "pass2")
    assert result is False

def test_account_locks_after_5_failures():
    create_profile("dave", "realpass", role="user")
    for _ in range(5):
        verify_profile("dave", "wrongpass", dev_mode=True)
    success, role = verify_profile("dave", "realpass", dev_mode=True)
    assert success is False

def test_unlock_profile():
    create_profile("eve", "mypass", role="user")
    for _ in range(5):
        verify_profile("eve", "wrongpass", dev_mode=True)
    unlock_profile("eve")
    success, role = verify_profile("eve", "mypass", dev_mode=True)
    assert success is True

def test_delete_profile():
    create_profile("frank", "pass", role="user")
    delete_profile("frank")
    assert "frank" not in list_profiles()