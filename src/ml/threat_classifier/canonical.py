from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import pandas as pd

from src.ml.threat_classifier.cleaning import (
    clean_email_text,
    extract_urls,
    message_hash,
    near_duplicate_hash,
    normalize_json_list,
    normalize_string,
)
from src.ml.threat_classifier.labels import normalize_threat_label, risk_level_from_label
from src.ml.threat_classifier.legacy import normalize_url_label
from src.ml.threat_classifier.schema import (
    EMAIL_CANONICAL_COLUMNS,
    THREAT_LABELS,
    URL_CANONICAL_COLUMNS,
    URL_LABELS,
)


def normalize_email_records(
    records: Iterable[Dict[str, object]],
    dataset_version: str,
    default_source: str = "external",
) -> pd.DataFrame:
    rows = []
    now = datetime.utcnow().isoformat(timespec="seconds")
    for record in records:
        subject = normalize_string(record.get("subject") or record.get("Subject"))
        body = clean_email_text(record.get("body") or record.get("text") or record.get("Message") or "")
        text = clean_email_text(record.get("text") or body)
        sender = normalize_string(record.get("sender") or record.get("From"))
        reply_to = normalize_string(record.get("reply_to") or record.get("Reply-To"))
        urls = record.get("urls") or extract_urls(subject, body, text)
        attachments = record.get("attachments") or record.get("attachment") or record.get("File") or []
        label = normalize_threat_label(record.get("threat_label") or record.get("label") or record.get("type"))
        source = normalize_string(record.get("source")) or default_source
        label_source = normalize_string(record.get("label_source")) or "external"
        is_weak = _truthy(record.get("is_weak_label")) or label_source.lower() in {
            "weak",
            "generated",
            "synthetic",
            "bootstrap",
            "inferred",
        }
        content_hash = message_hash(subject, body, sender, reply_to)
        rows.append({
            "message_id": normalize_string(record.get("message_id")) or content_hash,
            "subject": subject,
            "body": body,
            "text": text,
            "sender": sender,
            "reply_to": reply_to,
            "urls": normalize_json_list(urls),
            "attachments": normalize_json_list(attachments),
            "threat_label": label,
            "risk_level": normalize_string(record.get("risk_level")) or risk_level_from_label(label),
            "source": source,
            "source_split": normalize_string(record.get("source_split")),
            "label_source": label_source,
            "is_weak_label": bool(is_weak),
            "review_status": normalize_string(record.get("review_status")) or "external",
            "created_at": normalize_string(record.get("created_at")) or now,
            "dataset_version": dataset_version,
            "raw_path": normalize_string(record.get("raw_path")),
            "content_hash": content_hash,
            "near_duplicate_hash": near_duplicate_hash(subject, body),
        })
    return pd.DataFrame(rows, columns=EMAIL_CANONICAL_COLUMNS)


def normalize_url_records(
    records: Iterable[Dict[str, object]],
    dataset_version: str,
    default_source: str = "external",
) -> pd.DataFrame:
    rows = []
    now = datetime.utcnow().isoformat(timespec="seconds")
    for record in records:
        url = normalize_string(record.get("url") or record.get("URL"))
        label = normalize_url_label(record.get("label") or record.get("target") or record.get("threat_label"))
        source = normalize_string(record.get("source")) or default_source
        label_source = normalize_string(record.get("label_source")) or "external"
        content_hash = message_hash(url, label, source)
        rows.append({
            "url": url,
            "label": label,
            "risk_level": normalize_string(record.get("risk_level")),
            "source": source,
            "source_split": normalize_string(record.get("source_split")),
            "label_source": label_source,
            "is_weak_label": _truthy(record.get("is_weak_label")),
            "created_at": normalize_string(record.get("created_at")) or now,
            "dataset_version": dataset_version,
            "raw_path": normalize_string(record.get("raw_path")),
            "content_hash": content_hash,
        })
    return pd.DataFrame(rows, columns=URL_CANONICAL_COLUMNS)


def validate_email_dataset(frame: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    valid = []
    invalid = []
    for _, row in frame.iterrows():
        errors: List[str] = []
        if not str(row.get("text") or row.get("body") or "").strip():
            errors.append("missing_text")
        if row.get("threat_label") not in THREAT_LABELS:
            errors.append("unsupported_threat_label")
        if errors:
            invalid.append({**row.to_dict(), "validation_errors": "|".join(errors)})
        else:
            valid.append(row.to_dict())
    return pd.DataFrame(valid, columns=EMAIL_CANONICAL_COLUMNS), pd.DataFrame(invalid)


def validate_url_dataset(frame: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    valid = []
    invalid = []
    for _, row in frame.iterrows():
        errors: List[str] = []
        if not str(row.get("url") or "").strip():
            errors.append("missing_url")
        if row.get("label") not in URL_LABELS:
            errors.append("unsupported_url_label")
        if errors:
            invalid.append({**row.to_dict(), "validation_errors": "|".join(errors)})
        else:
            valid.append(row.to_dict())
    return pd.DataFrame(valid, columns=URL_CANONICAL_COLUMNS), pd.DataFrame(invalid)


def dedupe_email_dataset(frame: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, int]]:
    before = len(frame)
    deduped = frame.drop_duplicates(subset=["content_hash"]).drop_duplicates(subset=["near_duplicate_hash"])
    return deduped.reset_index(drop=True), {
        "input_rows": int(before),
        "deduped_rows": int(len(deduped)),
        "duplicate_rows": int(before - len(deduped)),
    }


def dedupe_url_dataset(frame: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, int]]:
    before = len(frame)
    deduped = frame.drop_duplicates(subset=["content_hash"])
    return deduped.reset_index(drop=True), {
        "input_rows": int(before),
        "deduped_rows": int(len(deduped)),
        "duplicate_rows": int(before - len(deduped)),
    }


def save_canonical_outputs(
    email_frame: pd.DataFrame,
    url_frame: pd.DataFrame,
    output_dir: Path,
    manifest_dir: Path,
    dataset_version: str,
) -> Dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_dir.mkdir(parents=True, exist_ok=True)
    email_valid, email_invalid = validate_email_dataset(email_frame)
    url_valid, url_invalid = validate_url_dataset(url_frame)
    email_valid, email_dedupe = dedupe_email_dataset(email_valid)
    url_valid, url_dedupe = dedupe_url_dataset(url_valid)

    email_path = output_dir / "email_threat_canonical.csv"
    url_path = output_dir / "url_threat_canonical.csv"
    email_invalid_path = output_dir / "email_threat_rejected.csv"
    url_invalid_path = output_dir / "url_threat_rejected.csv"
    report_path = manifest_dir / f"{dataset_version}_validation_report.json"

    email_valid.to_csv(email_path, index=False)
    url_valid.to_csv(url_path, index=False)
    email_invalid.to_csv(email_invalid_path, index=False)
    url_invalid.to_csv(url_invalid_path, index=False)
    report = {
        "dataset_version": dataset_version,
        "email": {
            "accepted_rows": int(len(email_valid)),
            "rejected_rows": int(len(email_invalid)),
            "source_counts": email_valid.get("source", pd.Series(dtype=str)).value_counts().to_dict(),
            "label_counts": email_valid.get("threat_label", pd.Series(dtype=str)).value_counts().to_dict(),
            "dedupe": email_dedupe,
        },
        "url": {
            "accepted_rows": int(len(url_valid)),
            "rejected_rows": int(len(url_invalid)),
            "source_counts": url_valid.get("source", pd.Series(dtype=str)).value_counts().to_dict(),
            "label_counts": url_valid.get("label", pd.Series(dtype=str)).value_counts().to_dict(),
            "dedupe": url_dedupe,
        },
    }
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return {
        "email_dataset_path": str(email_path),
        "url_dataset_path": str(url_path),
        "email_rejected_path": str(email_invalid_path),
        "url_rejected_path": str(url_invalid_path),
        "validation_report_path": str(report_path),
    }


def to_legacy_email_training_frame(frame: pd.DataFrame) -> pd.DataFrame:
    result = frame.copy()
    result["text"] = result.get("text", result.get("body", "")).fillna("").astype(str)
    for column in ["subject", "sender", "reply_to", "threat_label", "risk_level", "source", "label_source", "is_weak_label", "review_status"]:
        if column not in result.columns:
            result[column] = ""
    return result[["text", "subject", "sender", "reply_to", "threat_label", "risk_level", "source", "label_source", "is_weak_label", "review_status"]]


def to_legacy_url_training_frame(frame: pd.DataFrame) -> pd.DataFrame:
    result = frame.copy()
    for column in ["url", "label", "risk_level", "source", "label_source", "is_weak_label"]:
        if column not in result.columns:
            result[column] = ""
    return result[["url", "label", "risk_level", "source", "label_source", "is_weak_label"]]


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}
