import os
import sqlite3
import time
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# SQLite DB file
DB_FILE = "totally_not_my_privateKeys.db"


def _get_aes_key():
    env_key = os.environ.get("NOT_MY_KEY")
    if not env_key:
        raise RuntimeError("NOT_MY_KEY environment variable is not set")
    # Ensure the key is exactly 32 bytes (AES-256) by padding/truncating
    key_bytes = env_key.encode("utf-8")
    if len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b"\0")
    return key_bytes[:32]


def _encrypt_pem(pem_bytes) :
    key = _get_aes_key()
    # Pad plaintext to AES block size (16 bytes)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(pem_bytes) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _decrypt_pem(encrypted_bytes):
    key = _get_aes_key()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# class to create and store rsa keys
class MyKey:
    def __init__(self, is_expired=False, kid=None, private_pem=None, exp=None):
        if private_pem:  # load key from DB
            self.private = serialization.load_pem_private_key(
                private_pem, password=None, backend=default_backend()
            )
            self.public = self.private.public_key()
            self.id = str(kid)  # convert to string for JWT header
            self.exp = exp
        else:  # generate new key
            self.id = None  # let SQLite auto-assign INTEGER PK
            self.private = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            self.public = self.private.public_key()
            now = int(time.time())
            self.exp = now - 3600 if is_expired else now + 3600

    def serialize(self):
        return self.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def serialize_encrypted(self) -> bytes:
        return _encrypt_pem(self.serialize())

# Initialize DB and table
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)

        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)

        # Auth logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)


def save_key_to_db(key: MyKey):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        encrypted = key.serialize_encrypted()
        if key.id is None:
            cursor.execute(
                "INSERT INTO keys(key, exp) VALUES (?, ?)",
                (encrypted, key.exp),
            )
            key.id = str(cursor.lastrowid)
        else:
            cursor.execute(
                "INSERT OR REPLACE INTO keys(kid, key, exp) VALUES (?, ?, ?)",
                (key.id, encrypted, key.exp),
            )


# Load keys from DB
def load_keys(expired=False):
    now = int(time.time())
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        if expired:
            cursor.execute("SELECT kid, key, exp FROM keys WHERE exp <= ?", (now,))
        else:
            cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (now,))
        rows = cursor.fetchall()

    keys = []
    for kid, encrypted_blob, exp in rows:
        pem_bytes = _decrypt_pem(encrypted_blob)
        keys.append(MyKey(kid=kid, private_pem=pem_bytes, exp=exp))
    return keys

# Interface functions
def get_good_key():
    keys = load_keys(expired=False)
    return keys[0] if keys else None

# return expired key
def get_old_key():
    keys = load_keys(expired=True)
    return keys[0] if keys else None

# return only keys that are still valid
def get_good_public_keys():
    return load_keys(expired=False)


# Initialize DB and ensure at least one valid and one expired key
init_db()
if not get_good_key():
    save_key_to_db(MyKey(is_expired=False))
if not get_old_key():
    save_key_to_db(MyKey(is_expired=True))