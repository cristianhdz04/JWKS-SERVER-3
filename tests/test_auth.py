import jwt
import time
import uuid
import sqlite3
from fastapi.testclient import TestClient
from app.main import app
from app.keys import DB_FILE, get_good_key, get_old_key

# create test client
client = TestClient(app)


# test normal login
def test_login_works():

    # send post request
    res = client.post("/auth")

    # check status is ok
    assert res.status_code == 200

    # get token from response
    token = res.json()["token"]

    # get valid key
    key = get_good_key()

    # decode the token
    decoded = jwt.decode(token, key.public, algorithms=["RS256"])

    # check user id
    assert decoded["sub"] == "user123"


# test expired login
def test_expired_login():

    # request expired token
    res = client.post("/auth?expired=true")
    assert res.status_code == 200
    token = res.json()["token"]

    # get expired key
    key = get_old_key()

    # decode without checking expiration
    decoded = jwt.decode(
        token, key.public, algorithms=["RS256"], options={"verify_exp": False}
    )

    # check expiration is in past
    assert decoded["exp"] < int(time.time())


# test wrong http method
def test_wrong_method():

    res = client.get("/auth")

    # should return method not allowed
    assert res.status_code == 405


def test_auth_request_is_logged():
    with sqlite3.connect(DB_FILE) as conn:
        before = conn.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]

    client.post("/auth")

    with sqlite3.connect(DB_FILE) as conn:
        after = conn.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]

    assert after == before + 1


def test_auth_logs_user_id():
    # Register a user first
    tag = uuid.uuid4().hex[:8]
    username = f"logtest_{tag}"
    reg_res = client.post(
        "/register", json={"username": username, "email": f"{tag}@test.com"}
    )
    assert reg_res.status_code == 201

    # Look up user id
    with sqlite3.connect(DB_FILE) as conn:
        user_id = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()[0]

    # Auth with that username in the body
    client.post("/auth", json={"username": username, "password": "anything"})

    # Check the most recent log has the correct user_id
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute(
            "SELECT user_id FROM auth_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()

    assert row[0] == user_id


def test_rate_limiter():
    # Clear auth_logs so previous test runs don't interfere
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM auth_logs")

    # Send 10 requests (should all succeed)
    for _ in range(10):
        res = client.post("/auth")
        assert res.status_code == 200

    # 11th request should be rate-limited
    res = client.post("/auth")
    assert res.status_code == 429

    # Clean up so other tests aren't affected
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM auth_logs")