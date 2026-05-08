import os
import shutil
import pytest
from core.key_manager import derive_key, generate_salt
from core.encryptor import encrypt_file, decrypt_file, encrypt_folder, decrypt_folder

TEST_FILE = "test_sample.txt"
TEST_CONTENT = b"Sensitive test data 1234"
TEST_FOLDER = "test_vault_folder"

def get_key():
    return derive_key("testpassword", generate_salt())

def setup_function():
    with open(TEST_FILE, 'wb') as f:
        f.write(TEST_CONTENT)

def teardown_function():
    for f in [TEST_FILE, TEST_FILE + ".enc"]:
        if os.path.exists(f):
            os.remove(f)
    if os.path.exists(TEST_FOLDER):
        shutil.rmtree(TEST_FOLDER)

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
    key2 = get_key()
    encrypt_file(TEST_FILE, key1)
    assert decrypt_file(TEST_FILE + ".enc", key2) is False

def test_encrypt_folder():
    os.makedirs(TEST_FOLDER, exist_ok=True)
    for i in range(3):
        with open(os.path.join(TEST_FOLDER, f"file{i}.txt"), 'wb') as f:
            f.write(b"data " + str(i).encode())
    key = get_key()
    count = encrypt_folder(TEST_FOLDER, key)
    assert count == 3
    enc_files = [f for f in os.listdir(TEST_FOLDER) if f.endswith(".enc")]
    assert len(enc_files) == 3

def test_decrypt_folder():
    os.makedirs(TEST_FOLDER, exist_ok=True)
    contents = {}
    for i in range(3):
        path = os.path.join(TEST_FOLDER, f"file{i}.txt")
        data = b"data " + str(i).encode()
        contents[f"file{i}.txt"] = data
        with open(path, 'wb') as f:
            f.write(data)
    key = get_key()
    encrypt_folder(TEST_FOLDER, key)
    decrypt_folder(TEST_FOLDER, key)
    for name, data in contents.items():
        path = os.path.join(TEST_FOLDER, name)
        assert os.path.exists(path)
        with open(path, 'rb') as f:
            assert f.read() == data