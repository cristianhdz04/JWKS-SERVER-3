import sqlite3
import time
import uuid
import jwt
from argon2 import PasswordHasher
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from app.keys import DB_FILE, get_good_key, get_old_key, get_good_public_keys
from app.utils import make_jwk

# create fastapi app
app = FastAPI()

# Argon2 password hasher
ph = PasswordHasher(
    time_cost=2, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16
)

RATE_LIMIT = 10   # max requests allowed
RATE_WINDOW = 1   # per this many seconds


def _is_rate_limited(ip):
    now = time.time()
    cutoff = now - RATE_WINDOW
    with sqlite3.connect(DB_FILE) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM auth_logs WHERE request_ip = ? "
            "AND request_timestamp >= datetime(?, 'unixepoch')",
            (ip, cutoff),
        ).fetchone()[0]
    return count >= RATE_LIMIT

class RegisterRequest(BaseModel):
    """Body for the POST /register endpoint."""
    username: str
    email: str

@app.get("/.well-known/jwks.json")
def get_jwks():
    # get valid keys
    keys = get_good_public_keys()
    result = [make_jwk(k) for k in keys]
    # return jwks
    return {"keys": result}


@app.post("/register", status_code=201)
def register(body: RegisterRequest):

    password = str(uuid.uuid4())
    password_hash = ph.hash(password)

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users(username, password_hash, email) VALUES (?, ?, ?)",
                (body.username, password_hash, body.email),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=400, detail="Username or email already exists"
            )

    return {"password": password}


@app.post("/auth")
async def login(request: Request):
    client_ip = request.client.host if request.client else "unknown"

    # Rate limiter check (based on DB logs)
    if _is_rate_limited(client_ip):
        raise HTTPException(status_code=429, detail="Too Many Requests")

    # Try to read username from request body for logging
    user_id = None
    try:
        body = await request.json()
        username = body.get("username")
        if username:
            user_id = _lookup_user_id(username)
    except Exception:
        pass  # no body or invalid JSON is fine

    # check if expired was requested
    expired = request.query_params.get("expired")

    # use expired key if parameter exists
    if expired:
        key = get_old_key()
    # otherwise use valid key
    else:
        key = get_good_key()
    exp_time = key.exp

    # jwt payload
    data = {
        "sub": "user123",  # fake user
        "iat": int(time.time()),  # issued time
        "exp": exp_time,  # expiration time
    }

    # create jwt token
    token = jwt.encode(
        data, key.private, algorithm="RS256", headers={"kid": key.id}
    )

    # Log the authentication request
    _log_auth_request(client_ip, user_id=user_id)

    # return token
    return {"token": token}


# @app.get here means this runs if someone uses get on /auth
# we use this to return error because only post is allowed
@app.get("/auth")
def wrong():

    raise HTTPException(status_code=405, detail="Not allowed")

def _lookup_user_id(username):
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row[0] if row else None


def _log_auth_request(ip, user_id):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO auth_logs(request_ip, user_id) VALUES (?, ?)",
            (ip, user_id),
        )