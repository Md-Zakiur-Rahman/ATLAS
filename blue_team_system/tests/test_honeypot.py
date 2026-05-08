import os
import shutil
import pytest
from core.honeypot import create_honeypots, is_honeypot, check_honeypot_access, get_honeypot_paths

HONEYPOT_FOLDER = "test_honeypots"
REGISTRY = ".honeypot_registry"

def teardown_function():
    if os.path.exists(HONEYPOT_FOLDER):
        shutil.rmtree(HONEYPOT_FOLDER)
    if os.path.exists(REGISTRY):
        os.remove(REGISTRY)

def test_create_honeypots():
    files = create_honeypots(HONEYPOT_FOLDER)
    assert len(files) == 6
    for path in files:
        assert os.path.exists(path)

def test_is_honeypot_true():
    files = create_honeypots(HONEYPOT_FOLDER)
    assert is_honeypot(files[0]) is True

def test_is_honeypot_false():
    create_honeypots(HONEYPOT_FOLDER)
    assert is_honeypot("some_random_file.txt") is False

def test_check_honeypot_access_returns_alert():
    files = create_honeypots(HONEYPOT_FOLDER)
    alert = check_honeypot_access(files[0])
    assert alert is not None
    assert alert["severity"] == "CRITICAL"
    assert alert["type"] == "HONEYPOT_ACCESS"

def test_check_honeypot_access_returns_none_for_normal_file():
    alert = check_honeypot_access("normal_file.txt")
    assert alert is None