"""
Authentication helpers: register, login, and prediction-history saving.

Password hashing uses bcrypt via the `bcrypt` package.
If bcrypt is unavailable, falls back to SHA-256 (for development only).
"""

import hashlib
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from src.database.db import fetchall, fetchone, execute

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
    threat_metadata: Optional[Dict[str, object]] = None,
) -> int:
    """
    Persist a single-email prediction result.
    Returns the new record ID.
    """
    pred_value = "SPAM" if prediction.lower() == "spam" else "HAM"
    conf_value = round(float(confidence), 2) if confidence is not None else 0.0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    prediction_id = execute(
        """INSERT INTO Single_Prediction_History
               (user_id, email_content, prediction, confidence, created_at)
           VALUES (%s, %s, %s, %s, %s)""",
        (user_id, email_content[:65535], pred_value, conf_value, now)
    )
    if threat_metadata:
        save_prediction_threat_metadata(prediction_id, threat_metadata)
        save_extracted_indicators(
            prediction_id=prediction_id,
            indicators=threat_metadata.get("indicators", {}),
            risk_score=int(threat_metadata.get("risk_score", 0) or 0),
        )
        maybe_create_review_queue_item(prediction_id, prediction, confidence, threat_metadata)
    return prediction_id


def save_prediction_threat_metadata(prediction_id: int, metadata: Dict[str, object]) -> Optional[int]:
    """Persist extended threat metadata. Silently skips if migration is not installed."""
    try:
        return execute(
            """INSERT INTO Prediction_Threat_Metadata
                   (prediction_id, threat_label, risk_score, risk_level, verdict,
                    component_scores, indicators, reasons, recommended_actions, campaign_id)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                prediction_id,
                str(metadata.get("threat_label") or metadata.get("primary_threat_label") or "Safe"),
                int(metadata.get("risk_score", 0) or 0),
                str(metadata.get("risk_level") or "Low"),
                str(metadata.get("verdict") or "LOW_RISK_EMAIL"),
                _json(metadata.get("components") or metadata.get("component_scores") or {}),
                _json(metadata.get("indicators") or {}),
                _json(metadata.get("reasons") or []),
                _json(metadata.get("recommended_actions") or []),
                metadata.get("campaign_id"),
            )
        )
    except Exception:
        return None


def save_extracted_indicators(
    prediction_id: Optional[int],
    indicators: Dict[str, object],
    risk_score: int = 0,
    source: str = "email",
) -> int:
    saved = 0
    rows = []
    for indicator_type in ("domains", "urls", "brands", "qr_payloads", "risky_files", "keywords"):
        for value in indicators.get(indicator_type, []) or []:
            rows.append((indicator_type, str(value)))
    for field in ("sender_domain", "reply_to_domain"):
        value = indicators.get(field)
        if value:
            rows.append((field, str(value)))

    for indicator_type, value in rows:
        try:
            execute(
                """INSERT INTO Extracted_Indicator
                       (prediction_id, indicator_type, indicator_value, risk_score, source)
                   VALUES (%s, %s, %s, %s, %s)""",
                (prediction_id, indicator_type, value, risk_score, source),
            )
            saved += 1
        except Exception:
            continue
    return saved


def save_campaign_summaries(campaigns: List[Dict[str, object]], report_markdowns: Optional[Dict[str, str]] = None) -> int:
    saved = 0
    report_markdowns = report_markdowns or {}
    for campaign in campaigns:
        try:
            execute(
                """INSERT INTO Threat_Campaign
                       (campaign_id, primary_threat_label, risk_level, risk_score,
                        email_count, first_seen, last_seen, top_domains, top_brands,
                        representative_reasons, report_markdown)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON DUPLICATE KEY UPDATE
                        primary_threat_label = VALUES(primary_threat_label),
                        risk_level = VALUES(risk_level),
                        risk_score = VALUES(risk_score),
                        email_count = VALUES(email_count),
                        first_seen = VALUES(first_seen),
                        last_seen = VALUES(last_seen),
                        top_domains = VALUES(top_domains),
                        top_brands = VALUES(top_brands),
                        representative_reasons = VALUES(representative_reasons),
                        report_markdown = VALUES(report_markdown)""",
                (
                    campaign.get("campaign_id"),
                    campaign.get("primary_threat_label", "Unknown"),
                    campaign.get("risk_level", "Low"),
                    int(campaign.get("risk_score", 0) or 0),
                    int(campaign.get("email_count", 0) or 0),
                    campaign.get("first_seen"),
                    campaign.get("last_seen"),
                    _json(campaign.get("top_domains", [])),
                    _json(campaign.get("top_brands", [])),
                    _json(campaign.get("representative_reasons", [])),
                    report_markdowns.get(str(campaign.get("campaign_id")), ""),
                ),
            )
            saved += 1
        except Exception:
            continue
    return saved


def maybe_create_review_queue_item(
    prediction_id: int,
    prediction: str,
    confidence: Optional[float],
    metadata: Dict[str, object],
) -> Optional[int]:
    risk_score = int(metadata.get("risk_score", 0) or 0)
    reason = None
    if confidence is not None and float(confidence) < 60:
        reason = "low_confidence"
    if prediction.lower() == "ham" and risk_score >= 60:
        reason = "high_risk_ham_conflict"
    if reason is None:
        return None
    return create_review_queue_item(
        prediction_id=prediction_id,
        reason=reason,
        model_label=prediction,
        risk_score=risk_score,
        evidence=metadata,
        priority="high" if risk_score >= 80 else "medium",
    )


def create_review_queue_item(
    prediction_id: Optional[int],
    reason: str,
    model_label: Optional[str],
    risk_score: int,
    evidence: Optional[Dict[str, object]] = None,
    feedback_id: Optional[int] = None,
    priority: str = "medium",
) -> Optional[int]:
    try:
        return execute(
            """INSERT INTO Review_Queue
                   (prediction_id, feedback_id, reason, priority, model_label, risk_score, evidence)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (prediction_id, feedback_id, reason, priority, model_label, risk_score, _json(evidence or {})),
        )
    except Exception:
        return None


def save_prediction_feedback(
    user_id: int,
    prediction_id: Optional[int],
    feedback: str,
    corrected_label: Optional[str] = None,
    note: Optional[str] = None,
) -> Optional[int]:
    feedback = feedback.lower().strip()
    if feedback not in {"correct", "incorrect"}:
        raise AuthError("Feedback must be 'correct' or 'incorrect'.")
    try:
        feedback_id = execute(
            """INSERT INTO Prediction_Feedback
                   (user_id, prediction_id, feedback, corrected_label, note)
               VALUES (%s, %s, %s, %s, %s)""",
            (user_id, prediction_id, feedback, corrected_label, note),
        )
        if feedback == "incorrect":
            create_review_queue_item(
                prediction_id=prediction_id,
                feedback_id=feedback_id,
                reason="user_corrected_prediction",
                model_label=None,
                risk_score=0,
                evidence={"corrected_label": corrected_label, "note": note},
                priority="high",
            )
        return feedback_id
    except Exception:
        return None


def get_review_queue(limit: int = 30) -> List[dict]:
    try:
        return fetchall(
            """SELECT id, prediction_id, feedback_id, reason, priority, model_label,
                      risk_score, status, approved_label, created_at
               FROM Review_Queue
               ORDER BY FIELD(priority, 'high', 'medium', 'low'), created_at DESC
               LIMIT %s""",
            (limit,),
        )
    except Exception:
        return []


def update_review_queue_item(
    review_id: int,
    status: str,
    approved_label: Optional[str] = None,
    reviewer: Optional[str] = None,
) -> bool:
    if status not in {"pending", "approved", "rejected"}:
        raise AuthError("Review status must be pending, approved, or rejected.")
    try:
        execute(
            """UPDATE Review_Queue
               SET status = %s, approved_label = %s, reviewer = %s, reviewed_at = %s
               WHERE id = %s""",
            (status, approved_label, reviewer, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), review_id),
        )
        return True
    except Exception:
        return False


def export_retraining_data() -> List[dict]:
    try:
        return fetchall(
            """SELECT rq.id AS review_id,
                      rq.approved_label AS threat_label,
                      sph.prediction AS binary_label,
                      sph.email_content AS normalized_text,
                      ptm.indicators AS indicators,
                      rq.reviewed_at
               FROM Review_Queue rq
               JOIN Single_Prediction_History sph ON sph.ID = rq.prediction_id
               LEFT JOIN Prediction_Threat_Metadata ptm ON ptm.prediction_id = sph.ID
               WHERE rq.status = 'approved' AND rq.approved_label IS NOT NULL
               ORDER BY rq.reviewed_at DESC"""
        )
    except Exception:
        return []


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
    try:
        return fetchall(
            """SELECT sph.id, sph.prediction, sph.confidence, sph.created_at,
                      LEFT(sph.email_content, 120) AS preview,
                      ptm.threat_label, ptm.risk_score, ptm.risk_level, ptm.verdict,
                      ptm.campaign_id
               FROM Single_Prediction_History sph
               LEFT JOIN Prediction_Threat_Metadata ptm ON ptm.prediction_id = sph.ID
               WHERE sph.user_id = %s
               ORDER BY sph.created_at DESC
               LIMIT %s""",
            (user_id, limit)
        )
    except Exception:
        return fetchall(
            """SELECT id, prediction, confidence, created_at,
                      LEFT(email_content, 120) AS preview
               FROM Single_Prediction_History
               WHERE user_id = %s
               ORDER BY created_at DESC
               LIMIT %s""",
            (user_id, limit)
        )


def get_history_campaign_candidates(user_id: int, limit: int = 200) -> List[dict]:
    try:
        return fetchall(
            """SELECT sph.id, sph.created_at AS Time, sph.email_content AS Body,
                      LEFT(sph.email_content, 120) AS Subject,
                      ptm.threat_label AS `Threat Label`,
                      ptm.risk_score AS `Risk Score`,
                      ptm.risk_level AS `Risk Level`,
                      ptm.verdict AS Verdict,
                      ptm.indicators AS Indicators,
                      ptm.reasons AS Reasons
               FROM Single_Prediction_History sph
               LEFT JOIN Prediction_Threat_Metadata ptm ON ptm.prediction_id = sph.ID
               WHERE sph.user_id = %s
               ORDER BY sph.created_at DESC
               LIMIT %s""",
            (user_id, limit),
        )
    except Exception:
        return []


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


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)
