from __future__ import annotations

import email
import hashlib
import html
import json
import re
from email.message import Message
from typing import Iterable, List

from bs4 import BeautifulSoup


URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s<>'\"]*)?")


def clean_email_text(value: object) -> str:
    text = "" if value is None else str(value)
    text = html.unescape(text)
    if "<" in text and ">" in text:
        text = BeautifulSoup(text, "html.parser").get_text(" ")
    text = re.sub(r"(?im)^>.*$", " ", text)
    text = re.sub(r"(?im)^On .+ wrote:$", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def normalize_string(value: object) -> str:
    return re.sub(r"\s+", " ", "" if value is None else str(value)).strip()


def normalize_json_list(value: object) -> str:
    if value is None or value == "":
        return "[]"
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                return json.dumps(json.loads(stripped), ensure_ascii=False)
            except Exception:
                pass
        items = [item.strip() for item in re.split(r"[,|]", stripped) if item.strip()]
        return json.dumps(items, ensure_ascii=False)
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        return json.dumps([str(item).strip() for item in value if str(item).strip()], ensure_ascii=False)
    return json.dumps([str(value).strip()], ensure_ascii=False)


def extract_urls(*values: object) -> List[str]:
    seen = []
    for value in values:
        for match in URL_PATTERN.findall("" if value is None else str(value)):
            item = match.rstrip(").,;]")
            if item and item not in seen:
                seen.append(item)
    return seen


def message_hash(*values: object) -> str:
    payload = "\n".join("" if value is None else str(value) for value in values)
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()


def near_duplicate_hash(*values: object) -> str:
    payload = " ".join(clean_email_text(value).lower() for value in values)
    payload = re.sub(r"https?://\S+", " URL ", payload)
    payload = re.sub(r"\d+", "0", payload)
    payload = re.sub(r"[^a-z0-9]+", " ", payload)
    return hashlib.sha1(payload.strip().encode("utf-8", errors="ignore")).hexdigest()


def message_to_record(message: Message, source: str, threat_label: str, raw_path: str = "") -> dict:
    subject = normalize_string(message.get("Subject", ""))
    sender = normalize_string(message.get("From", ""))
    reply_to = normalize_string(message.get("Reply-To", ""))
    body_parts: List[str] = []
    attachments: List[str] = []

    if message.is_multipart():
        for part in message.walk():
            disposition = str(part.get("Content-Disposition", "")).lower()
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
            if "attachment" in disposition:
                continue
            content_type = part.get_content_type()
            if content_type not in {"text/plain", "text/html"}:
                continue
            body_parts.append(_payload_to_text(part))
    else:
        body_parts.append(_payload_to_text(message))

    body = clean_email_text(" ".join(body_parts))
    urls = extract_urls(subject, body)
    return {
        "message_id": normalize_string(message.get("Message-ID", "")) or message_hash(subject, sender, body),
        "subject": subject,
        "body": body,
        "text": body,
        "sender": sender,
        "reply_to": reply_to,
        "urls": urls,
        "attachments": attachments,
        "threat_label": threat_label,
        "source": source,
        "source_split": "",
        "label_source": "external",
        "is_weak_label": False,
        "review_status": "external",
        "raw_path": raw_path,
    }


def parse_email_bytes(payload: bytes, source: str, threat_label: str, raw_path: str = "") -> dict:
    message = email.message_from_bytes(payload)
    return message_to_record(message, source=source, threat_label=threat_label, raw_path=raw_path)


def _payload_to_text(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return clean_email_text(raw)
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")
