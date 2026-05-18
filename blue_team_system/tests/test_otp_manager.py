import time
import pytest
from core.otp_manager import generate_otp, verify_otp, validate_phone_tail, invalidate_otp

SESSION = "test_session"

def teardown_function():
    invalidate_otp(SESSION)

def test_generate_and_verify_otp():
    code = generate_otp(SESSION)
    success, reason = verify_otp(SESSION, code)
    assert success is True
    assert reason == "ok"

def test_wrong_otp_fails():
    generate_otp(SESSION)
    success, reason = verify_otp(SESSION, "000000")
    assert success is False
    assert reason == "wrong"

def test_no_session_fails():
    success, reason = verify_otp("nonexistent_session", "123456")
    assert success is False
    assert reason == "no_session"

def test_max_attempts_locks_otp():
    generate_otp(SESSION)
    for _ in range(3):
        verify_otp(SESSION, "000000")
    success, reason = verify_otp(SESSION, "000000")
    assert reason == "max_attempts"

def test_invalidate_otp():
    generate_otp(SESSION)
    invalidate_otp(SESSION)
    success, reason = verify_otp(SESSION, "123456")
    assert reason == "no_session"

def test_phone_tail_validation():
    assert validate_phone_tail("34567", "0501234567") is True
    assert validate_phone_tail("99999", "0501234567") is False

def test_phone_tail_with_exact_5_digits():
    assert validate_phone_tail("12345", "12345") is True