"""
Database connection manager for MySQL.
Reads credentials from environment variables or a .env file.

Required environment variables:
    DB_HOST     – MySQL host (default: localhost)
    DB_PORT     – MySQL port (default: 3306)
    DB_USER     – MySQL username
    DB_PASSWORD – MySQL password
    DB_NAME     – Database name (default: spam_detection)
"""

from dotenv import load_dotenv
load_dotenv()   # đọc file .env tự động

import os
import contextlib
from typing import Optional

try:
    import mysql.connector
    from mysql.connector import Error as MySQLError
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def _get_db_config() -> dict:
    """Build connection config from env variables."""
    return {
        "host":     os.environ.get("DB_HOST", "localhost"),
        "port":     int(os.environ.get("DB_PORT", 3306)),
        "user":     os.environ.get("DB_USER", "root"),
        "password": os.environ.get("DB_PASSWORD", ""),
        "database": os.environ.get("DB_NAME", "spam_detection"),
        "charset":  "utf8mb4",
        "collation": "utf8mb4_unicode_ci",
        "autocommit": False,
    }


# ---------------------------------------------------------------------------
# Connection context manager
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def get_connection():
    """
    Yield a MySQL connection.  Commits on success, rolls back on error.

    Usage:
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(...)
    """
    if not MYSQL_AVAILABLE:
        raise RuntimeError(
            "mysql-connector-python is not installed. "
            "Run: pip install mysql-connector-python"
        )

    conn = None
    try:
        conn = mysql.connector.connect(**_get_db_config())
        yield conn
        conn.commit()
    except MySQLError as exc:
        if conn:
            conn.rollback()
        raise exc
    finally:
        if conn and conn.is_connected():
            conn.close()


# ---------------------------------------------------------------------------
# Convenience query helpers
# ---------------------------------------------------------------------------

def fetchone(query: str, params: tuple = ()) -> Optional[dict]:
    """Return a single row as a dict, or None."""
    with get_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        return cursor.fetchone()


def fetchall(query: str, params: tuple = ()) -> list:
    """Return all rows as a list of dicts."""
    with get_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        return cursor.fetchall()


def execute(query: str, params: tuple = ()) -> int:
    """
    Execute an INSERT / UPDATE / DELETE.
    Returns lastrowid for INSERT, rowcount otherwise.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.lastrowid if cursor.lastrowid else cursor.rowcount


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def ping() -> bool:
    """Return True if the database is reachable."""
    try:
        with get_connection() as conn:
            return conn.is_connected()
    except Exception:
        return False
