import sqlite3
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# SQLite DB file
DB_FILE = "totally_not_my_privateKeys.db"

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
        """Return PEM bytes to store in DB"""
        return self.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


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


# Save a key to the DB
def save_key_to_db(key: MyKey):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        if key.id is None:  # new key, let SQLite assign id
            cursor.execute(
                "INSERT INTO keys(key, exp) VALUES (?, ?)",
                (key.serialize(), key.exp)
            )
            key.id = str(cursor.lastrowid)  # convert to string
        else:
            cursor.execute(
                "INSERT OR REPLACE INTO keys(kid, key, exp) VALUES (?, ?, ?)",
                (key.id, key.serialize(), key.exp)
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
    return [MyKey(kid=row[0], private_pem=row[1], exp=row[2]) for row in rows]


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