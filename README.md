# JWKS Server – Project 2

Cristian Hernandez
EUID: ch0928
CSCE 3550 – Spring 2026

## Overview

This project extends the JWKS server from Project 1 using Python and FastAPI. The server now stores RSA private keys in a **SQLite database** so that keys persist even if the server restarts.

The server generates RSA keys, assigns a **kid** and expiration time to each key, serves public keys at a JWKS endpoint, and creates JWT tokens. The server can also return expired JWT tokens when requested for testing.

SQLite is used to securely store keys and all database queries use **parameterized queries** to prevent SQL injection.

Database file used:

```
totally_not_my_privateKeys.db
```

Database schema:

```
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
```

## Setup Instructions
Create virtual environment:

```powershell
python -m venv venv
```

Activate virtual environment (Windows):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
venv\Scripts\activate
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

## Run Server

Start the server:

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Server runs at:
http://localhost:8080

## Test Endpoints

Open a second terminal.

Valid JWT:

```powershell
curl.exe -X POST http://localhost:8080/auth
```

JWKS endpoint:

```powershell
curl.exe http://localhost:8080/.well-known/jwks.json
```

Expired JWT:

```powershell
curl.exe -X POST "http://localhost:8080/auth?expired=true"
```

## Run Tests

```powershell
python -m pytest --cov=app --cov-report=term-missing
```

Coverage should be over **80%**.

## Blackbox Testing

```powershell
./gradebot project-2 --run "uvicorn app.main:app --host 0.0.0.0 --port 8080"
```

This tests the server automatically and verifies:

* JWT authentication
* JWKS endpoint
* SQLite database usage
* Secure database queries

## Project Structure

```
JWKS-Server/
|- app/
|   |-- keys.py
|   |-- main.py
|   |-- utils.py
|- tests/
|   |-- test_auth.py
|   |-- test_jwks.py
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
```powershell
pylint app/
black --check app/
```
