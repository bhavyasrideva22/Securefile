"""
Authentication Module - SQLite3 User Management

Provides user registration, login, and logout with password hashing.
Uses a local SQLite3 database for credential storage.
Passwords are stored as SHA-256 hashes with a salt.
"""

import os
import sqlite3
import hashlib
import secrets


DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")


def _get_connection() -> sqlite3.Connection:
    """Get a connection to the auth database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    """Create the users table if it doesn't exist."""
    conn = _get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def _hash_password(password: str, salt: str) -> str:
    """Hash a password with a salt using SHA-256."""
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


# Initialize the database on module import
_init_db()


def register(username: str, password: str) -> dict:
    """
    Register a new user.

    Args:
        username: Desired username.
        password: Desired password.

    Returns:
        dict with 'success' and 'message' keys.
    """
    if not username or not password:
        return {"success": False, "message": "Username and password are required"}

    if len(username) < 3:
        return {"success": False, "message": "Username must be at least 3 characters"}

    if len(password) < 6:
        return {"success": False, "message": "Password must be at least 6 characters"}

    salt = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt)

    try:
        conn = _get_connection()
        conn.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, pw_hash, salt),
        )
        conn.commit()
        conn.close()
        return {"success": True, "message": f"User '{username}' registered successfully"}
    except sqlite3.IntegrityError:
        return {"success": False, "message": f"Username '{username}' already exists"}
    except Exception as e:
        return {"success": False, "message": f"Registration failed: {str(e)}"}


def login(username: str, password: str) -> dict:
    """
    Authenticate a user.

    Args:
        username: Username.
        password: Password.

    Returns:
        dict with 'success', 'message', and 'user_id' keys.
    """
    if not username or not password:
        return {"success": False, "message": "Username and password are required"}

    try:
        conn = _get_connection()
        row = conn.execute(
            "SELECT id, password_hash, salt FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()

        if row is None:
            return {"success": False, "message": "Invalid username or password"}

        stored_hash = row["password_hash"]
        salt = row["salt"]
        input_hash = _hash_password(password, salt)

        if input_hash == stored_hash:
            return {"success": True, "message": f"Welcome, {username}!", "user_id": row["id"]}
        else:
            return {"success": False, "message": "Invalid username or password"}
    except Exception as e:
        return {"success": False, "message": f"Login failed: {str(e)}"}


def get_all_users() -> list[dict]:
    """Return a list of all registered usernames (for admin purposes)."""
    try:
        conn = _get_connection()
        rows = conn.execute("SELECT id, username, created_at FROM users").fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []
