# JWKS Server – Project 3

Cristian Hernandez  
EUID: ch0928  
CSCE 3550 – Spring 2026

## Overview

This project extends the JWKS server from Project 1/2 using Python and FastAPI. The server now encrypts private keys at rest using **AES-256**, supports **user registration** with Argon2 password hashing, logs all authentication requests to the database, and includes a **rate limiter** on the auth endpoint.

The encryption key is read from the `NOT_MY_KEY` environment variable and is never committed to the repository.

SQLite is used to store keys, users, and auth logs. All database queries use **parameterized queries** to prevent SQL injection.

Database file used:

```
totally_not_my_privateKeys.db
```

Database schema:

```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
```

## Setup Instructions
Create virtual environment:

```bash
python3 -m venv venv
```

Activate virtual environment:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run Server

Start the server:

```bash
export NOT_MY_KEY="my_super_secret_key"
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Server runs at: http://localhost:8080

## Test Endpoints

Open a second terminal.

Register a user:

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "email": "test@example.com"}'
```

Valid JWT:

```bash
curl -X POST http://localhost:8080/auth
```

JWKS endpoint:

```bash
curl http://localhost:8080/.well-known/jwks.json
```

Expired JWT:

```bash
curl -X POST "http://localhost:8080/auth?expired=true"
```

## Run Tests

```bash
export NOT_MY_KEY="your-secret-key-here"
python -m pytest --cov=app --cov-report=term-missing
```

Coverage should be over **80%**.

## Blackbox Testing

```bash
./gradebot project-3 --run "uvicorn app.main:app --host 0.0.0.0 --port 8080"
```

This tests the server automatically and verifies:

* AES encryption of private keys
* User registration
* JWT authentication
* JWKS endpoint
* Authentication request logging
* Rate limiting

## Project Structure

```
JWKS-Server/
|- app/
|   |-- __init__.py
|   |-- keys.py
|   |-- main.py
|   |-- utils.py
|- tests/
|   |-- __init__.py
|   |-- test_auth.py
|   |-- test_jwks.py
|   |-- test_register.py
|- screenshots/
|   |-- BLACKBOX_TEST_CH0928.png
|   |-- PYTEST_RESULTS_CH0928.png
|- totally_not_my_privateKeys.db
|-- gradebot
|-- requirements.txt
|-- README.md
|-- .gitignore
```

## Linting

Code has been formatted with `black` and linted with `pylint`.
Check code quality:

```bash
pylint app/
black --check app/
```
