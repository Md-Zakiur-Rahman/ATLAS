import os
import pytest
from core.key_manager import derive_key, generate_salt
from core.encryptor import encrypt_file, decrypt_file

TEST_FILE = "test_sample.txt"
TEST_CONTENT = b"Sensitive test data 1234"

def setup_function():
    with open(TEST_FILE, 'wb') as f:
        f.write(TEST_CONTENT)

def teardown_function():
    for f in [TEST_FILE, TEST_FILE + ".enc"]:
        if os.path.exists(f):
            os.remove(f)

def get_key():
    return derive_key("testpassword", generate_salt())

def test_encrypt_creates_enc_file():
    key = get_key()
    assert encrypt_file(TEST_FILE, key) is True
    assert os.path.exists(TEST_FILE + ".enc")
    assert not os.path.exists(TEST_FILE)

def test_decrypt_restores_file():
    key = get_key()
    encrypt_file(TEST_FILE, key)
    assert decrypt_file(TEST_FILE + ".enc", key) is True
    assert os.path.exists(TEST_FILE)
    with open(TEST_FILE, 'rb') as f:
        assert f.read() == TEST_CONTENT

def test_wrong_key_fails_decryption():
    key1 = get_key()
    key2 = get_key()  # different salt = different key
    encrypt_file(TEST_FILE, key1)
    assert decrypt_file(TEST_FILE + ".enc", key2) is False