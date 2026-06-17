from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.message import Message
from typing import Dict, List, Optional
from urllib.parse import urlparse

from src.utils.email_utils import all_recipients, clean_text, extract_body

from .url_risk_model import URLRiskModel


SUSPICIOUS_KEYWORDS = {
    "urgent",
    "verify",
    "password",
    "otp",
    "login",
    "invoice",
    "payment",
    "refund",
    "bank",
    "wallet",
    "qr",
    "macro",
}


@dataclass
class EmailFeatureRecord:
    body: str
    subject: str = ""
    sender: str = ""
    sender_domain: str = ""
    recipients: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    timestamp: str = ""
    direction: str = ""
    category: str = ""
    urls: List[Dict[str, object]] = field(default_factory=list)
    qr_payloads: List[Dict[str, object]] = field(default_factory=list)
    risky_files: List[str] = field(default_factory=list)
    suspicious_keywords: List[str] = field(default_factory=list)
    indicators: Dict[str, object] = field(default_factory=dict)
    missing_fields: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "body": self.body,
            "subject": self.subject,
            "sender": self.sender,
            "sender_domain": self.sender_domain,
            "recipients": self.recipients,
            "reply_to": self.reply_to,
            "reply_to_domain": self.reply_to_domain,
            "timestamp": self.timestamp,
            "direction": self.direction,
            "category": self.category,
            "urls": self.urls,
            "qr_payloads": self.qr_payloads,
            "risky_files": self.risky_files,
            "suspicious_keywords": self.suspicious_keywords,
            "indicators": self.indicators,
            "missing_fields": self.missing_fields,
        }


class EmailFeatureExtractor:
    """Create structured security-event features from pasted text or MBOX messages."""

    def __init__(self) -> None:
        self.url_model = URLRiskModel()

    def from_text(
        self,
        email_text: str,
        subject: str = "",
        sender: str = "",
        recipients: str = "",
        reply_to: str = "",
        timestamp: str = "",
        qr_payloads: Optional[List[str]] = None,
    ) -> EmailFeatureRecord:
        body = clean_text(email_text or "")
        urls = self._extract_urls(email_text or "")
        url_results = [self.url_model.analyze(value).to_dict() for value in urls]
        qr_results = [self.url_model.analyze(value).to_dict() for value in (qr_payloads or [])]
        sender_domain = self._domain_from_email(sender)
        reply_to_domain = self._domain_from_email(reply_to)
        keywords = self._keyword_hits(" ".join([subject, body]))

        record = EmailFeatureRecord(
            body=body,
            subject=clean_text(subject or ""),
            sender=sender or "",
            sender_domain=sender_domain,
            recipients=recipients or "",
            reply_to=reply_to or "",
            reply_to_domain=reply_to_domain,
            timestamp=timestamp or "",
            urls=url_results,
            qr_payloads=qr_results,
            risky_files=self._risky_filenames(email_text or ""),
            suspicious_keywords=keywords,
        )
        record.missing_fields = self._missing_fields(record)
        record.indicators = self._indicators(record)
        return record

    def from_message(self, message: Message) -> EmailFeatureRecord:
        labels = (message.get("X-Gmail-Labels") or "").lower()
        category = (
            "Spam" if "spam" in labels else
            "Promotions" if "category_promotions" in labels else
            "Social" if "category_social" in labels else
            "Updates" if "category_updates" in labels else
            "Inbox"
        )
        direction = "Sent" if "sent" in labels else "Received"

        record = self.from_text(
            email_text=extract_body(message),
            subject=message.get("Subject", ""),
            sender=message.get("From", ""),
            recipients=all_recipients(message),
            reply_to=message.get("Reply-To", ""),
            timestamp=message.get("Date", ""),
        )
        record.category = category
        record.direction = direction
        record.indicators = self._indicators(record)
        return record

    def _indicators(self, record: EmailFeatureRecord) -> Dict[str, object]:
        domains = sorted(
            {
                str(item.get("domain", "")).lower()
                for item in record.urls
                if item.get("domain")
            }
        )
        brands = sorted(
            {
                item.get("features", {}).get("brand_impersonation", {}).get("brand")
                for item in record.urls
                if item.get("features", {}).get("brand_impersonation")
            }
        )
        qr_payloads = [str(item.get("url", "")) for item in record.qr_payloads if item.get("url")]

        return {
            "sender": record.sender,
            "sender_domain": record.sender_domain,
            "reply_to_domain": record.reply_to_domain,
            "domains": domains,
            "urls": [str(item.get("final_url") or item.get("url")) for item in record.urls],
            "brands": brands,
            "qr_payloads": qr_payloads,
            "risky_files": record.risky_files,
            "keywords": record.suspicious_keywords,
            "timestamp": record.timestamp,
        }

    def _domain_from_email(self, value: str) -> str:
        match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", value or "")
        if match:
            return match.group(1).lower().strip(".")
        parsed = urlparse(value or "")
        return (parsed.hostname or "").lower().strip(".")

    def _keyword_hits(self, text: str) -> List[str]:
        normalized = (text or "").lower()
        return sorted({keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in normalized})

    def _extract_urls(self, text: str) -> List[str]:
        return re.findall(r"https?://[^\s<>'\"]+|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s<>'\"]*)?", text or "")

    def _risky_filenames(self, text: str) -> List[str]:
        return re.findall(
            r"\b[\w.-]+\.(?:exe|scr|bat|cmd|js|vbs|msi|apk|jar|zip|rar|7z)\b",
            text or "",
            flags=re.IGNORECASE,
        )

    def _missing_fields(self, record: EmailFeatureRecord) -> List[str]:
        missing = []
        for field_name in ("sender", "reply_to", "timestamp"):
            if not getattr(record, field_name):
                missing.append(field_name)
        if not record.qr_payloads:
            missing.append("qr_payloads")
        return missing
