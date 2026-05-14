import os
import pytest
from core.key_manager import derive_key, generate_salt, save_keyfile, load_keyfile
from core.auth import hash_password, save_auth
from core.encryptor import encrypt_file

KEYFILE = "audit_test.keyfile"
AUTH_FILE = "audit_test.dat"
TEST_FILE = "audit_sample.txt"

def teardown_function():
    for f in [KEYFILE, AUTH_FILE, TEST_FILE, TEST_FILE + ".enc"]:
        if os.path.exists(f):
            os.remove(f)

def test_keyfile_does_not_contain_plaintext_password():
    salt = generate_salt()
    save_keyfile(salt, KEYFILE)
    with open(KEYFILE, 'rb') as f:
        content = f.read()
    assert b"password" not in content
    assert b"secret" not in content
    assert len(content) == 16  # only the salt

def test_derived_key_not_stored_anywhere():
    salt = generate_salt()
    key = derive_key("supersecret", salt)
    save_keyfile(salt, KEYFILE)
    with open(KEYFILE, 'rb') as f:
        content = f.read()
    assert key not in content

def test_auth_file_does_not_store_plaintext_password():
    save_auth("plaintextpassword", filepath=AUTH_FILE)
    with open(AUTH_FILE, 'rb') as f:
        content = f.read()
    assert b"plaintextpassword" not in content

def test_encrypted_file_does_not_contain_plaintext():
    secret = b"top secret classified data"
    with open(TEST_FILE, 'wb') as f:
        f.write(secret)
    key = derive_key("password", generate_salt())
    encrypt_file(TEST_FILE, key)
    with open(TEST_FILE + ".enc", 'rb') as f:
        enc_content = f.read()
    assert secret not in enc_content

def test_enc_file_nonce_is_unique_per_encryption():
    nonces = set()
    for _ in range(5):
        with open(TEST_FILE, 'wb') as f:
            f.write(b"same content every time")
        key = derive_key("password", generate_salt())
        encrypt_file(TEST_FILE, key)
        with open(TEST_FILE + ".enc", 'rb') as f:
            nonce = f.read(12)
        nonces.add(nonce)
        os.remove(TEST_FILE + ".enc")
    assert len(nonces) == 5  # all nonces must be unique

def test_salt_is_random_each_time():
    salts = {generate_salt() for _ in range(10)}
    assert len(salts) == 10  # no two salts should be equal