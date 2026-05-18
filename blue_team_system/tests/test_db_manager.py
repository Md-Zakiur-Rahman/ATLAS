import os
import pytest
from database.db_manager import init_db, log_event, get_all_events, verify_chain, clear_db

def setup_function():
    init_db()
    clear_db()

def teardown_function():
    clear_db()

def test_log_and_retrieve_event():
    log_event("TEST_EVENT", "LOW", "test details")
    events = get_all_events()
    assert len(events) == 1
    assert events[0]["event_type"] == "TEST_EVENT"

def test_hash_chain_valid():
    log_event("EVENT_1", "LOW", "details 1")
    log_event("EVENT_2", "MEDIUM", "details 2")
    log_event("EVENT_3", "HIGH", "details 3")
    valid, msg = verify_chain()
    assert valid is True
    assert "3" in msg

def test_hash_chain_detects_tamper():
    log_event("EVENT_1", "LOW", "details 1")
    log_event("EVENT_2", "LOW", "details 2")

    from database.db_manager import get_connection, get_all_events
    events = get_all_events()
    first_id = events[0]["id"]

    conn = get_connection()
    conn.execute(f"UPDATE events SET raw='TAMPERED' WHERE id={first_id}")
    conn.commit()
    conn.close()

    valid, msg = verify_chain()
    assert valid is False
    assert "Tamper" in msg

def test_empty_chain_is_valid():
    valid, msg = verify_chain()
    assert valid is True

def test_multiple_events_chained():
    for i in range(10):
        log_event(f"EVENT_{i}", "LOW", f"details {i}")
    valid, msg = verify_chain()
    assert valid is True
    assert "10" in msg