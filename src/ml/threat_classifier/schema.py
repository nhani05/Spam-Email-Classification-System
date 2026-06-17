from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


ARTIFACT_SCHEMA_VERSION = "email-threat-lifecycle-v1"
FIXTURE_SOURCE_PREFIXES = {"local_seed", "fixture", "smoke_fixture"}
TRUSTED_LABEL_SOURCES = {"external", "curated", "reviewed_feedback", "manual"}
WEAK_LABEL_SOURCES = {"weak", "generated", "synthetic", "bootstrap", "inferred"}

THREAT_LABELS = [
    "Safe",
    "Spam",
    "Phishing",
    "Malware Risk",
    "Credential Theft",
    "Payment Scam",
    "Quishing",
    "Business Email Compromise",
]

URL_LABELS = ["benign", "suspicious", "phishing"]

EMAIL_CANONICAL_COLUMNS = [
    "message_id",
    "subject",
    "body",
    "text",
    "sender",
    "reply_to",
    "urls",
    "attachments",
    "threat_label",
    "risk_level",
    "source",
    "source_split",
    "label_source",
    "is_weak_label",
    "review_status",
    "created_at",
    "dataset_version",
    "raw_path",
    "content_hash",
    "near_duplicate_hash",
]

URL_CANONICAL_COLUMNS = [
    "url",
    "label",
    "risk_level",
    "source",
    "source_split",
    "label_source",
    "is_weak_label",
    "created_at",
    "dataset_version",
    "raw_path",
    "content_hash",
]


@dataclass(frozen=True)
class ThreatDataLayout:
    base_dir: Path = Path("data/ai_threat")
    raw_dir: Path = Path("data/ai_threat/raw")
    interim_dir: Path = Path("data/ai_threat/interim")
    canonical_dir: Path = Path("data/ai_threat/canonical")
    manifest_dir: Path = Path("data/ai_threat/manifests")
    feedback_dir: Path = Path("data/ai_threat/feedback")
    fixture_dir: Path = Path("data/ai_threat/fixtures")

    @classmethod
    def from_base(cls, base_dir: str = "data/ai_threat") -> "ThreatDataLayout":
        base = Path(base_dir)
        return cls(
            base_dir=base,
            raw_dir=base / "raw",
            interim_dir=base / "interim",
            canonical_dir=base / "canonical",
            manifest_dir=base / "manifests",
            feedback_dir=base / "feedback",
            fixture_dir=base / "fixtures",
        )

    def ensure(self) -> None:
        for directory in [
            self.base_dir,
            self.raw_dir,
            self.interim_dir,
            self.canonical_dir,
            self.manifest_dir,
            self.feedback_dir,
            self.fixture_dir,
        ]:
            directory.mkdir(parents=True, exist_ok=True)


@dataclass
class DatasetSourceConfig:
    phishfuzzer_json_paths: List[str] = field(default_factory=list)
    nazario_mbox_paths: List[str] = field(default_factory=list)
    spamassassin_paths: List[str] = field(default_factory=list)
    enron_maildir_paths: List[str] = field(default_factory=list)
    phishtank_paths: List[str] = field(default_factory=list)
    urlhaus_paths: List[str] = field(default_factory=list)
    reviewed_feedback_paths: List[str] = field(default_factory=list)

    def has_external_email_sources(self) -> bool:
        return bool(
            self.phishfuzzer_json_paths
            or self.nazario_mbox_paths
            or self.spamassassin_paths
            or self.enron_maildir_paths
            or self.reviewed_feedback_paths
        )

    def has_url_sources(self) -> bool:
        return bool(self.phishtank_paths or self.urlhaus_paths)


@dataclass
class PublishGateConfig:
    min_total_rows: int = 40
    min_per_class: int = 2
    min_macro_f1: float = 0.35
    min_required_recall: float = 0.20
    required_labels: List[str] = field(default_factory=lambda: ["Safe", "Spam", "Phishing"])
    allow_publish_from_fixture: bool = False


def default_dataset_source_notes() -> Dict[str, Dict[str, str]]:
    return {
        "phishfuzzer": {
            "mode": "local-file",
            "notes": "Download JSON files from DataPhish/PhishFuzzer and pass local paths.",
        },
        "nazario": {
            "mode": "local-file",
            "notes": "Download mbox files from the Nazario phishing corpus and pass local paths.",
        },
        "spamassassin": {
            "mode": "local-file",
            "notes": "Download/extract SpamAssassin public corpus tarballs before import.",
        },
        "enron": {
            "mode": "local-file",
            "notes": "Download/extract the Enron maildir dataset before import.",
        },
        "phishtank": {
            "mode": "local-file-or-optional-download",
            "notes": "Use local CSV/JSON exports; API-key downloads are intentionally optional.",
        },
        "urlhaus": {
            "mode": "local-file-or-optional-download",
            "notes": "Use local CSV exports; authenticated downloads are intentionally optional.",
        },
        "reviewed_feedback": {
            "mode": "local-file",
            "notes": "Use approved feedback exports produced by the application review workflow.",
        },
    }
