import os
import pytest
from core.key_manager import derive_key, generate_salt
from core.notes_vault import save_note, load_all_notes, get_note, delete_note

NOTES_FILE = "notes.vault"

def get_key():
    return derive_key("testpassword", generate_salt())

def teardown_function():
    if os.path.exists(NOTES_FILE):
        os.remove(NOTES_FILE)

def test_save_and_get_note():
    key = get_key()
    assert save_note("todo", "Buy milk", key) is True
    assert get_note("todo", key) == "Buy milk"

def test_multiple_notes():
    key = get_key()
    save_note("note1", "Content 1", key)
    save_note("note2", "Content 2", key)
    notes = load_all_notes(key)
    assert "note1" in notes
    assert "note2" in notes

def test_delete_note():
    key = get_key()
    save_note("temp", "Temporary", key)
    assert delete_note("temp", key) is True
    assert get_note("temp", key) is None

def test_wrong_key_returns_none():
    key1 = get_key()
    key2 = get_key()
    save_note("secret", "classified", key1)
    result = load_all_notes(key2)
    assert result is None