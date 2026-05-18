import os
import pytest
from core.register import (register_user, get_whitelist, add_to_whitelist,
                            remove_from_whitelist, seed_demo_whitelist,
                            DEFAULT_WHITELIST_PROCESSES, DEFAULT_WHITELIST_IPS)

REG_FILE = "registered_user.json"

def teardown_function():
    if os.path.exists(REG_FILE):
        os.remove(REG_FILE)

def test_default_whitelist_on_register():
    register_user("Alice", "alice@test.com", "pass123", "0501234567")
    wl = get_whitelist()
    assert "chrome.exe" in wl["processes"]
    assert "127.0.0.1" in wl["ips"]

def test_add_process_to_whitelist():
    register_user("Alice", "alice@test.com", "pass123", "0501234567")
    add_to_whitelist("whitelist_processes", "notepad.exe")
    assert "notepad.exe" in get_whitelist()["processes"]

def test_add_ip_to_whitelist():
    register_user("Alice", "alice@test.com", "pass123", "0501234567")
    add_to_whitelist("whitelist_ips", "10.0.0.5")
    assert "10.0.0.5" in get_whitelist()["ips"]

def test_remove_from_whitelist():
    register_user("Alice", "alice@test.com", "pass123", "0501234567")
    remove_from_whitelist("whitelist_processes", "chrome.exe")
    assert "chrome.exe" not in get_whitelist()["processes"]

def test_no_duplicate_entries():
    register_user("Alice", "alice@test.com", "pass123", "0501234567")
    add_to_whitelist("whitelist_processes", "chrome.exe")
    add_to_whitelist("whitelist_processes", "chrome.exe")
    count = get_whitelist()["processes"].count("chrome.exe")
    assert count == 1

def test_seed_demo_whitelist():
    register_user("Alice", "alice@test.com", "pass123", "0501234567")
    seed_demo_whitelist()
    wl = get_whitelist()
    assert "chrome.exe" in wl["processes"]
    assert "127.0.0.1" in wl["ips"]