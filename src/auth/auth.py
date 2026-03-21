"""
Authentication helpers: register, login, and prediction-history saving.

Password hashing uses bcrypt via the `bcrypt` package.
If bcrypt is unavailable, falls back to SHA-256 (for development only).
"""

import hashlib
import os
from datetime import datetime
from typing import Optional

from src.database.db import fetchone, execute

# ---------------------------------------------------------------------------
# Password utilities
# ---------------------------------------------------------------------------

try:
    import bcrypt as _bcrypt
    _BCRYPT_AVAILABLE = True
except ImportError:
    _BCRYPT_AVAILABLE = False


def _hash_password(plain: str) -> str:
    """Return a hashed version of *plain*."""
    if _BCRYPT_AVAILABLE:
        return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt()).decode()
    # Fallback: SHA-256 with a static salt prefix (NOT for production)
    return hashlib.sha256(("__dev_salt__" + plain).encode()).hexdigest()


def _verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches *hashed*."""
    if _BCRYPT_AVAILABLE:
        try:
            return _bcrypt.checkpw(plain.encode(), hashed.encode())
        except Exception:
            return False
    return hashlib.sha256(("__dev_salt__" + plain).encode()).hexdigest() == hashed


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------

class AuthError(Exception):
    """Raised for expected authentication failures."""


def register_user(username: str, password: str) -> dict:
    """
    Create a new user account.

    Returns:
        dict with keys ``id``, ``username``, ``created_at``.

    Raises:
        AuthError: if username is already taken or inputs are invalid.
    """
    username = username.strip()
    if not username or not password:
        raise AuthError("Tên đăng nhập và mật khẩu không được để trống.")

    if len(username) > 12:
        raise AuthError("Tên đăng nhập tối đa 12 ký tự.")

    if len(password) > 12:
        raise AuthError("Mật khẩu tối đa 12 ký tự.")

    # Check uniqueness
    existing = fetchone(
        "SELECT id FROM User WHERE username = %s",
        (username,)
    )
    if existing:
        raise AuthError(f"Tên đăng nhập '{username}' đã tồn tại.")

    hashed = _hash_password(password)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    user_id = execute(
        "INSERT INTO User (username, password, created_at) VALUES (%s, %s, %s)",
        (username, hashed, now)
    )

    return {"id": user_id, "username": username, "created_at": now}


def login_user(username: str, password: str) -> dict:
    """
    Verify credentials and return user info.

    Returns:
        dict with keys ``id``, ``username``, ``created_at``.

    Raises:
        AuthError: if credentials are wrong.
    """
    username = username.strip()
    row = fetchone(
        "SELECT id, username, password, created_at FROM User WHERE username = %s",
        (username,)
    )
    if not row or not _verify_password(password, row["password"]):
        raise AuthError("Tên đăng nhập hoặc mật khẩu không đúng.")

    return {
        "id":         row["id"],
        "username":   row["username"],
        "created_at": str(row["created_at"]),
    }


# ---------------------------------------------------------------------------
# Prediction history
# ---------------------------------------------------------------------------

def save_single_prediction(
    user_id: int,
    email_content: str,
    prediction: str,
    confidence: Optional[float],
) -> int:
    """
    Persist a single-email prediction result.
    Returns the new record ID.
    """
    pred_value = "SPAM" if prediction.lower() == "spam" else "HAM"
    conf_value = round(float(confidence), 2) if confidence is not None else 0.0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return execute(
        """INSERT INTO Single_Prediction_History
               (user_id, email_content, prediction, confidence, created_at)
           VALUES (%s, %s, %s, %s, %s)""",
        (user_id, email_content[:65535], pred_value, conf_value, now)
    )


def save_batch_prediction(
    user_id: int,
    file_name: str,
    total_emails: int,
    spam_count: int,
    ham_count: int,
) -> int:
    """
    Persist a batch-processing summary.
    Returns the new record ID.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return execute(
        """INSERT INTO Batch_Prediction_History
               (user_id, file_name, total_emails, spam_count, ham_count, created_at)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (user_id, file_name[:50], total_emails, spam_count, ham_count, now)
    )


# ---------------------------------------------------------------------------
# History retrieval
# ---------------------------------------------------------------------------

def get_single_history(user_id: int, limit: int = 20) -> list:
    """Return the most recent single-email predictions for a user."""
    from src.database.db import fetchall
    return fetchall(
        """SELECT id, prediction, confidence, created_at,
                  LEFT(email_content, 120) AS preview
           FROM Single_Prediction_History
           WHERE user_id = %s
           ORDER BY created_at DESC
           LIMIT %s""",
        (user_id, limit)
    )


def get_batch_history(user_id: int, limit: int = 20) -> list:
    """Return the most recent batch-processing records for a user."""
    from src.database.db import fetchall
    return fetchall(
        """SELECT id, file_name, total_emails, spam_count, ham_count, created_at
           FROM Batch_Prediction_History
           WHERE user_id = %s
           ORDER BY created_at DESC
           LIMIT %s""",
        (user_id, limit)
    )
