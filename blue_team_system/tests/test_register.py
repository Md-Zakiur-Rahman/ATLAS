import os
import json
import pytest
from core.register import register_user, load_user, is_registered, update_telegram_id, get_whitelist, add_to_whitelist

REG_FILE = "registered_user.json"

def teardown_function():
    if os.path.exists(REG_FILE):
        os.remove(REG_FILE)

def test_register_user():
    assert register_user("Alice", "alice@test.com", "pass123", "0501234567") is True
    assert is_registered() is True

def test_register_duplicate_rejected():
    register_user("Alice", "alice@test.com", "pass123", "0501234567")
    assert register_user("Bob", "bob@test.com", "pass456", "0509876543") is False

def test_load_user_data():
    register_user("Alice", "alice@test.com", "pass123", "0501234567")
    user = load_user()
    assert user["name"] == "Alice"
    assert user["email"] == "alice@test.com"
    assert user["phone_tail"] == "34567"
    assert "password_hash" in user

def test_password_not_stored_plaintext():
    register_user("Alice", "alice@test.com", "plaintext_pass", "0501234567")
    user = load_user()
    assert "plaintext_pass" not in json.dumps(user)

def test_update_telegram_id():
    register_user("Alice", "alice@test.com", "pass123", "0501234567")
    assert update_telegram_id("123456789") is True
    assert load_user()["telegram_id"] == "123456789"

def test_whitelist_defaults():
    register_user("Alice", "alice@test.com", "pass123", "0501234567")
    wl = get_whitelist()
    assert "chrome.exe" in wl["processes"]
    assert "127.0.0.1" in wl["ips"]

def test_add_to_whitelist():
    register_user("Alice", "alice@test.com", "pass123", "0501234567")
    add_to_whitelist("whitelist_processes", "notepad.exe")
    wl = get_whitelist()
    assert "notepad.exe" in wl["processes"]