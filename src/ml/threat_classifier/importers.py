from __future__ import annotations

import csv
import hashlib
import json
import mailbox
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import pandas as pd

from src.ml.threat_classifier.cleaning import extract_urls, message_to_record, parse_email_bytes


def file_manifest(source_name: str, input_path: str, row_count: int, label_mapping: Optional[Dict[str, str]] = None, notes: str = "") -> Dict[str, object]:
    path = Path(input_path)
    return {
        "source_name": source_name,
        "input_path": str(path),
        "file_size": int(path.stat().st_size) if path.exists() and path.is_file() else 0,
        "checksum_sha256": _checksum(path) if path.exists() and path.is_file() else "",
        "imported_row_count": int(row_count),
        "label_mapping": label_mapping or {},
        "imported_at": datetime.utcnow().isoformat(timespec="seconds"),
        "operator_notes": notes,
    }


def write_source_manifest(manifests: Iterable[Dict[str, object]], output_path: str) -> None:
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(list(manifests), indent=2, ensure_ascii=False), encoding="utf-8")


def import_phishfuzzer_json(path: str) -> List[Dict[str, object]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    items = payload if isinstance(payload, list) else payload.get("emails") or payload.get("data") or []
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        label = item.get("type") or item.get("label") or item.get("class") or item.get("threat_label")
        rows.append({
            "message_id": item.get("id") or item.get("message_id"),
            "subject": item.get("subject") or item.get("Subject"),
            "body": item.get("body") or item.get("Body") or item.get("message") or item.get("text"),
            "text": item.get("text") or item.get("body") or item.get("message"),
            "sender": item.get("sender") or item.get("from") or item.get("From"),
            "reply_to": item.get("reply_to") or item.get("Reply-To"),
            "urls": item.get("urls") or item.get("url") or item.get("URL"),
            "attachments": item.get("attachments") or item.get("file") or item.get("File"),
            "threat_label": label,
            "source": "phishfuzzer",
            "source_split": item.get("split") or item.get("variant") or "",
            "label_source": "external",
            "is_weak_label": False,
            "review_status": "external",
            "raw_path": path,
            "motivation": item.get("motivation") or item.get("Motivation"),
        })
    return rows


def import_mbox_corpus(path: str, source: str = "nazario", threat_label: str = "Phishing") -> List[Dict[str, object]]:
    rows = []
    box = mailbox.mbox(path)
    try:
        for message in box:
            rows.append(message_to_record(message, source=source, threat_label=threat_label, raw_path=path))
    finally:
        box.close()
    return rows


def import_spamassassin_path(path: str) -> List[Dict[str, object]]:
    root = Path(path)
    rows = []
    label = "Spam" if "spam" in root.name.lower() else "Safe"
    files = [root] if root.is_file() else [item for item in root.rglob("*") if item.is_file()]
    for file_path in files:
        try:
            row = parse_email_bytes(file_path.read_bytes(), source="spamassassin", threat_label=label, raw_path=str(file_path))
            row["source_split"] = root.name
            rows.append(row)
        except Exception:
            continue
    return rows


def import_enron_maildir(path: str) -> List[Dict[str, object]]:
    root = Path(path)
    rows = []
    files = [root] if root.is_file() else [item for item in root.rglob("*") if item.is_file()]
    for file_path in files:
        try:
            row = parse_email_bytes(file_path.read_bytes(), source="enron", threat_label="Safe", raw_path=str(file_path))
            row["source_split"] = file_path.parent.name
            rows.append(row)
        except Exception:
            continue
    return rows


def import_phishtank_urls(path: str) -> List[Dict[str, object]]:
    rows = []
    for item in _read_csv_or_json(path):
        url = item.get("url") or item.get("phish_detail_url") or item.get("URL")
        if not url:
            continue
        rows.append({
            "url": url,
            "label": "phishing",
            "risk_level": "High",
            "source": "phishtank",
            "source_split": item.get("verified") or "",
            "label_source": "external",
            "is_weak_label": False,
            "raw_path": path,
        })
    return rows


def import_urlhaus_urls(path: str) -> List[Dict[str, object]]:
    rows = []
    for item in _read_csv_or_json(path):
        url = item.get("url") or item.get("URL")
        if not url:
            continue
        rows.append({
            "url": url,
            "label": "suspicious",
            "risk_level": "High",
            "source": "urlhaus",
            "source_split": item.get("threat") or item.get("tags") or "",
            "label_source": "external",
            "is_weak_label": False,
            "raw_path": path,
        })
    return rows


def url_records_to_email_enrichment(records: Iterable[Dict[str, object]], threat_label: str = "Phishing") -> List[Dict[str, object]]:
    rows = []
    for record in records:
        url = record.get("url")
        if not url:
            continue
        rows.append({
            "subject": "URL threat intelligence indicator",
            "body": f"Security intelligence source reported suspicious URL {url}",
            "text": f"Security intelligence source reported suspicious URL {url}",
            "urls": [url],
            "attachments": [],
            "sender": "",
            "reply_to": "",
            "threat_label": threat_label,
            "source": f"{record.get('source', 'url_intel')}_email_enrichment",
            "label_source": "weak",
            "is_weak_label": True,
            "review_status": "weak_label",
            "raw_path": record.get("raw_path", ""),
        })
    return rows


def reviewed_feedback_rows_to_canonical(rows: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    canonical = []
    for row in rows:
        status = str(row.get("review_status") or row.get("status") or "approved").lower()
        label = row.get("threat_label") or row.get("approved_label")
        text = row.get("normalized_text") or row.get("text") or row.get("email_content")
        if status not in {"approved", "reviewed"} or not label or not text:
            continue
        canonical.append({
            "message_id": row.get("review_id") or row.get("id"),
            "subject": row.get("subject", ""),
            "body": text,
            "text": text,
            "sender": row.get("sender", ""),
            "reply_to": row.get("reply_to", ""),
            "urls": extract_urls(text),
            "attachments": [],
            "threat_label": label,
            "source": "reviewed_feedback",
            "source_split": row.get("reviewer", ""),
            "label_source": "reviewed_feedback",
            "is_weak_label": False,
            "review_status": "approved",
            "created_at": row.get("reviewed_at", ""),
            "raw_path": row.get("raw_path", ""),
        })
    return canonical


def read_feedback_export(path: str) -> List[Dict[str, object]]:
    return reviewed_feedback_rows_to_canonical(_read_csv_or_json(path))


def _read_csv_or_json(path: str) -> List[Dict[str, object]]:
    file_path = Path(path)
    if file_path.suffix.lower() == ".json":
        payload = json.loads(file_path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            for key in ("data", "rows", "items"):
                if isinstance(payload.get(key), list):
                    return [item for item in payload[key] if isinstance(item, dict)]
            return [payload]
    if file_path.suffix.lower() in {".csv", ".txt"}:
        try:
            return pd.read_csv(file_path, comment="#").fillna("").to_dict(orient="records")
        except Exception:
            rows = []
            with file_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                for line in handle:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        rows.append({"url": line})
            return rows
    with file_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        return list(csv.DictReader(handle))


def _checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
