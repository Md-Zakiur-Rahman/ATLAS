import os
import shutil
import pytest
from core.shredder import shred_file, shred_folder

TEST_FILE = "test_shred.txt"
TEST_FOLDER = "test_shred_folder"

def setup_function():
    with open(TEST_FILE, 'w') as f:
        f.write("sensitive data that must be destroyed")

def teardown_function():
    if os.path.exists(TEST_FILE):
        os.remove(TEST_FILE)
    if os.path.exists(TEST_FOLDER):
        shutil.rmtree(TEST_FOLDER)

def test_shred_file_deletes_file():
    assert shred_file(TEST_FILE) is True
    assert not os.path.exists(TEST_FILE)

def test_shred_nonexistent_file():
    assert shred_file("nonexistent_file.txt") is False

def test_shred_folder():
    os.makedirs(TEST_FOLDER)
    for i in range(4):
        with open(os.path.join(TEST_FOLDER, f"secret{i}.txt"), 'w') as f:
            f.write(f"secret data {i}")
    count = shred_folder(TEST_FOLDER)
    assert count == 4
    remaining = os.listdir(TEST_FOLDER)
    assert len(remaining) == 0