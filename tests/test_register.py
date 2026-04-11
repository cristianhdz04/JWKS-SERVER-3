import sqlite3
import uuid
from fastapi.testclient import TestClient
from app.main import app
from app.keys import DB_FILE

# Create test client
client = TestClient(app)


def _unique_user():
    tag = uuid.uuid4().hex[:8]
    return {"username": f"user_{tag}", "email": f"{tag}@test.com"}


def test_register_returns_password():
    user = _unique_user()
    res = client.post("/register", json=user)
    assert res.status_code == 201
    body = res.json()
    assert "password" in body
    # Verify it looks like a UUID
    uuid.UUID(body["password"], version=4)


def test_register_stores_user():
    user = _unique_user()
    client.post("/register", json=user)

    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute(
            "SELECT username, email FROM users WHERE username = ?",
            (user["username"],),
        ).fetchone()

    assert row is not None
    assert row[0] == user["username"]
    assert row[1] == user["email"]


def test_register_hashes_password():
    user = _unique_user()
    res = client.post("/register", json=user)
    password = res.json()["password"]

    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (user["username"],),
        ).fetchone()

    # The hash should NOT equal the raw password
    assert row[0] != password
    # Argon2 hashes start with $argon2
    assert row[0].startswith("$argon2")


def test_register_duplicate_username():
    user = _unique_user()
    res1 = client.post("/register", json=user)
    assert res1.status_code == 201

    # Same username, different email
    user["email"] = f"other_{uuid.uuid4().hex[:6]}@test.com"
    res2 = client.post("/register", json=user)
    assert res2.status_code == 400