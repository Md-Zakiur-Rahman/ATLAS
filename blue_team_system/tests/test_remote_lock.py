import os
import json
import time
import pytest
import threading
from core.biometric_auth import (
    flask_app, generate_remote_token,
    get_remote_lock_url, _remote_tokens
)

@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c

def teardown_function():
    if os.path.exists("vault.locked"):
        os.remove("vault.locked")
    _remote_tokens.clear()

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "ok"

def test_remote_lock_valid_token(client):
    token = generate_remote_token()
    response = client.post(
        "/remote-lock",
        json={"token": token},
        content_type="application/json"
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "locked"

def test_remote_lock_invalid_token(client):
    response = client.post(
        "/remote-lock",
        json={"token": "invalid_token_xyz"},
        content_type="application/json"
    )
    assert response.status_code == 403

def test_remote_lock_expired_token(client):
    token = generate_remote_token()
    _remote_tokens[token] = time.time() - 1  # expired
    response = client.post(
        "/remote-lock",
        json={"token": token},
        content_type="application/json"
    )
    assert response.status_code == 403

def test_token_single_use(client):
    token = generate_remote_token()
    client.post("/remote-lock", json={"token": token},
                content_type="application/json")
    # second use should fail
    response = client.post("/remote-lock", json={"token": token},
                           content_type="application/json")
    assert response.status_code == 403

def test_get_remote_lock_url():
    url, token = get_remote_lock_url("https://test.ngrok.io")
    assert url == "https://test.ngrok.io/remote-lock"
    assert len(token) > 10
    assert token in _remote_tokens