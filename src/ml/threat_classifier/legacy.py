from __future__ import annotations

import json
import pickle
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from src.ml.model_lab import dataset_identity, evaluate_predictions, threshold_report
from src.utils.logger import get_logger
from src.security.url_risk_model import BRAND_DOMAINS, HIGH_RISK_TLDS, SHORTENER_DOMAINS, SENSITIVE_KEYWORDS

logger = get_logger(__name__)


EMAIL_THREAT_COLUMNS = [
    "text",
    "subject",
    "sender",
    "reply_to",
    "threat_label",
    "risk_level",
    "source",
    "label_source",
    "is_weak_label",
    "review_status",
]

URL_THREAT_COLUMNS = [
    "url",
    "label",
    "risk_level",
    "source",
    "label_source",
    "is_weak_label",
]

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

MALICIOUS_LABELS = {
    "Spam",
    "Phishing",
    "Malware Risk",
    "Credential Theft",
    "Payment Scam",
    "Quishing",
    "Business Email Compromise",
}

RISK_LEVEL_TO_SCORE = {
    "Low": 15,
    "Medium": 45,
    "High": 70,
    "Critical": 90,
}

THRESHOLDS = {
    "balanced": {"medium": 35, "high": 60, "critical": 80},
    "high_sensitivity_phishing": {"medium": 25, "high": 50, "critical": 75},
}


class EmailTextSelector(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        frame = _as_frame(X)
        subject = frame.get("subject", pd.Series([""] * len(frame))).fillna("")
        text = frame.get("text", pd.Series([""] * len(frame))).fillna("")
        sender = frame.get("sender", pd.Series([""] * len(frame))).fillna("")
        reply_to = frame.get("reply_to", pd.Series([""] * len(frame))).fillna("")
        return (subject.astype(str) + " " + text.astype(str) + " " + sender.astype(str) + " " + reply_to.astype(str)).tolist()


class EmailThreatNumericTransformer(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        frame = _as_frame(X)
        rows = []
        for record in frame.to_dict(orient="records"):
            text = str(record.get("text") or "")
            subject = str(record.get("subject") or "")
            sender = str(record.get("sender") or "")
            reply_to = str(record.get("reply_to") or "")
            full_text = f"{subject} {text}"
            lower = full_text.lower()
            urls = _extract_urls(full_text)
            risky_files = _risky_filenames(full_text)
            rows.append([
                len(full_text),
                sum(ch.isdigit() for ch in full_text),
                len(urls),
                lower.count("!"),
                int(any(token in lower for token in ("urgent", "immediately", "verify", "account locked", "suspended"))),
                int(any(token in lower for token in ("password", "otp", "login", "2fa", "security code"))),
                int(any(token in lower for token in ("invoice", "payment", "bank", "refund", "$", "transfer"))),
                int(bool(risky_files)),
                int(bool(sender and reply_to and _domain_from_email(sender) != _domain_from_email(reply_to))),
                int(any(_url_has_brand_impersonation(url) for url in urls)),
            ])
        return csr_matrix(np.asarray(rows, dtype=float))


class URLFeatureTransformer(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        values = _url_values(X)
        rows = []
        for url in values:
            features = extract_url_features(str(url))
            rows.append([
                int(features["uses_https"]),
                int(features["uses_ip_address"]),
                int(features["is_shortened"]),
                int(features["has_nested_redirect"]),
                int(features["has_at_symbol"]),
                int(features["has_encoded_chars"]),
                int(features["has_many_subdomains"]),
                int(features["suspicious_tld"]),
                int(bool(features["keyword_hits"])),
                int(bool(features["brand_impersonation"])),
                int(features["url_length"]),
                int(features["domain_length"]),
                int(features["digit_count"]),
                int(features["hyphen_count"]),
                int(features["encoded_char_count"]),
            ])
        return np.asarray(rows, dtype=float)


@dataclass
class AIModelPrediction:
    available: bool
    source: str
    label: str
    risk_score: int
    risk_level: str
    verdict: str
    class_scores: Dict[str, float] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    provenance: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "available": self.available,
            "source": self.source,
            "label": self.label,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "verdict": self.verdict,
            "class_scores": self.class_scores,
            "reasons": self.reasons,
            "provenance": self.provenance,
        }


class AIThreatModelService:
    def __init__(self, email_model_path: str = "", url_model_path: str = "") -> None:
        self.email_model_path = email_model_path
        self.url_model_path = url_model_path
        self.email_bundle: Optional[Dict[str, object]] = None
        self.url_bundle: Optional[Dict[str, object]] = None
        self.email_load_error: Optional[str] = None
        self.url_load_error: Optional[str] = None
        self.load_artifacts()

    @property
    def email_available(self) -> bool:
        return self.email_bundle is not None

    @property
    def url_available(self) -> bool:
        return self.url_bundle is not None

    def load_artifacts(self) -> None:
        self.email_bundle = self._load_bundle(self.email_model_path, "email")
        self.url_bundle = self._load_bundle(self.url_model_path, "url")
        logger.info(
            "AI threat artifacts status | email=%s | url=%s | email_path=%s | url_path=%s",
            "loaded" if self.email_bundle else "model_unavailable",
            "loaded" if self.url_bundle else "model_unavailable",
            self.email_model_path or "not configured",
            self.url_model_path or "not configured",
        )

    def predict_email(self, text: str, subject: str = "", sender: str = "", reply_to: str = "") -> AIModelPrediction:
        if not self.email_bundle:
            logger.info("AI email threat model unavailable; runtime risk scoring suppressed. reason=%s", self.email_load_error)
            return AIModelPrediction(
                available=False,
                source="model_unavailable",
                label="Model Unavailable",
                risk_score=0,
                risk_level="Unavailable",
                verdict="AI_MODEL_UNAVAILABLE",
                reasons=[
                    "AI email threat model artifacts are unavailable.",
                    "Train the AI threat model and configure ai_threat_model_path before using runtime risk scoring.",
                ],
                provenance={
                    "model_available": False,
                    "load_error": self.email_load_error,
                    "source": "model_unavailable",
                    "risk_source": "model_unavailable",
                },
            )

        frame = pd.DataFrame([{
            "text": text or "",
            "subject": subject or "",
            "sender": sender or "",
            "reply_to": reply_to or "",
        }])
        model = self.email_bundle["model"]
        features = self.email_bundle["features"]
        labels = list(self.email_bundle.get("labels", []))
        try:
            matrix = features.transform(frame)
            label = str(model.predict(matrix)[0])
            class_scores = _class_scores(model, matrix, labels)
        except Exception as exc:
            logger.exception("AI email threat model prediction failed; runtime risk scoring suppressed")
            return AIModelPrediction(
                available=False,
                source="model_unavailable",
                label="Model Unavailable",
                risk_score=0,
                risk_level="Unavailable",
                verdict="AI_MODEL_UNAVAILABLE",
                reasons=[
                    "AI email threat model artifact is incompatible with the current feature pipeline.",
                    "Retrain the AI threat model and update ai_threat_model_path.",
                ],
                provenance={
                    "model_available": False,
                    "load_error": str(exc),
                    "source": "model_unavailable",
                    "risk_source": "model_unavailable",
                    "artifact_path": self.email_model_path,
                },
            )
        risk_score = _risk_from_class_scores(label, class_scores)
        risk_level = risk_level_from_score(risk_score)
        result = AIModelPrediction(
            available=True,
            source="ai_model",
            label=label,
            risk_score=risk_score,
            risk_level=risk_level,
            verdict=email_verdict(label, risk_score),
            class_scores=class_scores,
            reasons=[
                f"AI email threat model selected `{label}` from supervised multi-class features.",
                f"Model-driven risk score is {risk_score}/100 using calibrated class probabilities when available.",
            ],
            provenance={
                "model_available": True,
                "model_type": "email_threat_classifier",
                "artifact_path": self.email_model_path,
                "run_id": self.email_bundle.get("metadata", {}).get("run_id"),
                "source": "ai_model",
                "risk_source": "ai_model",
            },
        )
        logger.info(
            "AI email prediction | label=%s | risk=%s | level=%s | source=ai_model | run_id=%s",
            result.label,
            result.risk_score,
            result.risk_level,
            result.provenance.get("run_id"),
        )
        return result

    def predict_url(self, url: str) -> Dict[str, object]:
        if not self.url_bundle:
            logger.info("AI URL model unavailable; URL risk scoring suppressed. reason=%s", self.url_load_error)
            return {
                "model_available": False,
                "model_source": "model_unavailable",
                "model_label": "Model Unavailable",
                "model_probability": None,
                "class_scores": {},
                "risk_score": 0,
                "risk_level": "Unavailable",
                "verdict": "AI_URL_MODEL_UNAVAILABLE",
                "features": extract_url_features(url),
                "reasons": [
                    "AI URL phishing model artifacts are unavailable.",
                    "Train the AI URL model and configure ai_url_model_path before using URL risk scoring.",
                ],
                "provenance": {
                    "model_type": "url_phishing_classifier",
                    "artifact_path": self.url_model_path,
                    "source": "model_unavailable",
                    "risk_source": "model_unavailable",
                    "model_available": False,
                    "load_error": self.url_load_error,
                },
            }

        model = self.url_bundle["model"]
        features = self.url_bundle["features"]
        labels = list(self.url_bundle.get("labels", []))
        try:
            matrix = features.transform(pd.DataFrame([{"url": url}]))
            label = str(model.predict(matrix)[0])
            scores = _class_scores(model, matrix, labels)
        except Exception as exc:
            logger.exception("AI URL model prediction failed; URL risk scoring suppressed")
            return {
                "model_available": False,
                "model_source": "model_unavailable",
                "model_label": "Model Unavailable",
                "model_probability": None,
                "class_scores": {},
                "risk_score": 0,
                "risk_level": "Unavailable",
                "verdict": "AI_URL_MODEL_UNAVAILABLE",
                "features": extract_url_features(url),
                "reasons": [
                    "AI URL model artifact is incompatible with the current feature pipeline.",
                    "Retrain the AI URL model and update ai_url_model_path.",
                ],
                "provenance": {
                    "model_type": "url_phishing_classifier",
                    "artifact_path": self.url_model_path,
                    "source": "model_unavailable",
                    "risk_source": "model_unavailable",
                    "model_available": False,
                    "load_error": str(exc),
                },
            }
        phishing_probability = max(
            float(scores.get("phishing", 0.0)),
            float(scores.get("suspicious", 0.0)) * 0.75,
            100.0 if label == "phishing" else 0.0,
        )
        risk_score = int(round(min(100.0, phishing_probability)))
        risk_level = risk_level_from_score(risk_score)
        url_features = extract_url_features(url)
        result = {
            "model_available": True,
            "model_source": "ai_model",
            "model_label": label,
            "model_probability": round(phishing_probability, 2),
            "class_scores": scores,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "verdict": url_verdict(risk_score),
            "features": url_features,
            "reasons": [
                f"AI URL phishing model predicted `{label}`.",
                f"Model phishing probability is {phishing_probability:.1f}%.",
            ],
            "provenance": {
                "model_type": "url_phishing_classifier",
                "artifact_path": self.url_model_path,
                "run_id": self.url_bundle.get("metadata", {}).get("run_id"),
                "source": "ai_model",
                "risk_source": "ai_model",
                "model_available": True,
            },
        }
        logger.info(
            "AI URL prediction | label=%s | probability=%.2f | risk=%s | url=%s",
            result["model_label"],
            float(result["model_probability"]),
            result["risk_score"],
            url,
        )
        return result

    def _load_bundle(self, path: str, kind: str) -> Optional[Dict[str, object]]:
        if not path:
            return None
        file_path = Path(path)
        if not file_path.exists():
            if kind == "email":
                self.email_load_error = f"{path}:missing"
            else:
                self.url_load_error = f"{path}:missing"
            return None
        try:
            with open(file_path, "rb") as f:
                bundle = pickle.load(f)
            return bundle
        except Exception as exc:
            if kind == "email":
                self.email_load_error = str(exc)
            else:
                self.url_load_error = str(exc)
            return None


def _as_frame(X) -> pd.DataFrame:
    if isinstance(X, pd.DataFrame):
        return X.copy()
    if isinstance(X, list):
        if not X:
            return pd.DataFrame(columns=EMAIL_THREAT_COLUMNS)
        if isinstance(X[0], dict):
            return pd.DataFrame(X)
        return pd.DataFrame({"text": [str(item) for item in X]})
    return pd.DataFrame(X)


def _url_values(X) -> List[str]:
    if isinstance(X, pd.DataFrame):
        return X.get("url", pd.Series([""] * len(X))).fillna("").astype(str).tolist()
    if isinstance(X, list):
        if X and isinstance(X[0], dict):
            return [str(item.get("url", "")) for item in X]
        return [str(item) for item in X]
    return [str(item) for item in X]


def _domain_from_email(value: str) -> str:
    match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", value or "")
    return match.group(1).lower().strip(".") if match else ""


def build_email_feature_pipeline() -> FeatureUnion:
    return FeatureUnion([
        ("word_tfidf", Pipeline([
            ("selector", EmailTextSelector()),
            ("tfidf", TfidfVectorizer(lowercase=True, stop_words="english", ngram_range=(1, 2), max_features=12000)),
        ])),
        ("char_tfidf", Pipeline([
            ("selector", EmailTextSelector()),
            ("tfidf", TfidfVectorizer(lowercase=True, analyzer="char_wb", ngram_range=(3, 5), max_features=8000)),
        ])),
        ("security_numeric", EmailThreatNumericTransformer()),
    ])


def build_url_feature_pipeline() -> URLFeatureTransformer:
    return URLFeatureTransformer()


def normalize_email_dataset(data: pd.DataFrame) -> pd.DataFrame:
    frame = data.copy()
    aliases = {
        "Message": "text",
        "message": "text",
        "email": "text",
        "body": "text",
        "Subject": "subject",
        "From": "sender",
        "label": "threat_label",
        "Category": "threat_label",
    }
    frame = frame.rename(columns={old: new for old, new in aliases.items() if old in frame.columns})
    for column in EMAIL_THREAT_COLUMNS:
        if column not in frame.columns:
            frame[column] = ""
    frame["text"] = frame["text"].fillna("").astype(str)
    frame["subject"] = frame["subject"].fillna("").astype(str)
    frame["sender"] = frame["sender"].fillna("").astype(str)
    frame["reply_to"] = frame["reply_to"].fillna("").astype(str)
    frame["threat_label"] = frame["threat_label"].map(normalize_threat_label)
    frame["risk_level"] = frame["risk_level"].fillna("").replace("", None)
    frame["risk_level"] = frame.apply(
        lambda row: row["risk_level"] or risk_level_from_label(row["threat_label"]),
        axis=1,
    )
    frame["source"] = frame["source"].replace("", "local").fillna("local")
    frame["label_source"] = frame["label_source"].replace("", "curated").fillna("curated")
    frame["is_weak_label"] = frame["is_weak_label"].apply(_truthy)
    frame["review_status"] = frame["review_status"].replace("", "seed").fillna("seed")
    return frame[EMAIL_THREAT_COLUMNS]


def normalize_url_dataset(data: pd.DataFrame) -> pd.DataFrame:
    frame = data.copy()
    aliases = {"URL": "url", "target": "label", "threat_label": "label"}
    frame = frame.rename(columns={old: new for old, new in aliases.items() if old in frame.columns})
    for column in URL_THREAT_COLUMNS:
        if column not in frame.columns:
            frame[column] = ""
    frame["url"] = frame["url"].fillna("").astype(str)
    frame["label"] = frame["label"].map(normalize_url_label)
    frame["risk_level"] = frame["risk_level"].fillna("").replace("", None)
    frame["risk_level"] = frame.apply(lambda row: row["risk_level"] or ("High" if row["label"] == "phishing" else "Low"), axis=1)
    frame["source"] = frame["source"].replace("", "local").fillna("local")
    frame["label_source"] = frame["label_source"].replace("", "curated").fillna("curated")
    frame["is_weak_label"] = frame["is_weak_label"].apply(_truthy)
    return frame[URL_THREAT_COLUMNS]


def load_email_threat_dataset(paths: Iterable[str]) -> pd.DataFrame:
    frames = []
    for path in paths:
        if path and Path(path).exists():
            frames.append(pd.read_csv(path))
    if not frames:
        raise FileNotFoundError("No email threat dataset files were found.")
    return normalize_email_dataset(pd.concat(frames, ignore_index=True))


def load_url_threat_dataset(paths: Iterable[str]) -> pd.DataFrame:
    frames = []
    for path in paths:
        if path and Path(path).exists():
            frames.append(pd.read_csv(path))
    if not frames:
        raise FileNotFoundError("No URL threat dataset files were found.")
    return normalize_url_dataset(pd.concat(frames, ignore_index=True))


def reviewed_feedback_rows_to_email_examples(rows: Iterable[Dict[str, object]]) -> pd.DataFrame:
    examples = []
    for row in rows:
        examples.append({
            "text": row.get("normalized_text", ""),
            "subject": "",
            "sender": "",
            "reply_to": "",
            "threat_label": row.get("threat_label") or row.get("approved_label") or "Safe",
            "risk_level": risk_level_from_label(str(row.get("threat_label") or "Safe")),
            "source": "review_queue",
            "label_source": "reviewed_feedback",
            "is_weak_label": False,
            "review_status": "approved",
        })
    if not examples:
        return pd.DataFrame(columns=EMAIL_THREAT_COLUMNS)
    return normalize_email_dataset(pd.DataFrame(examples))


def dataset_provenance(frame: pd.DataFrame, path: str = "") -> Dict[str, object]:
    return {
        "dataset_identity": dataset_identity(path) if path else "in_memory",
        "row_count": int(len(frame)),
        "source_counts": frame.get("source", pd.Series(dtype=str)).value_counts(dropna=False).to_dict(),
        "label_source_counts": frame.get("label_source", pd.Series(dtype=str)).value_counts(dropna=False).to_dict(),
        "weak_label_count": int(frame.get("is_weak_label", pd.Series(dtype=bool)).astype(bool).sum()),
        "label_counts": frame.iloc[:, 0:0].to_dict() if "threat_label" not in frame.columns else frame["threat_label"].value_counts().to_dict(),
    }


def train_ai_threat_models(
    email_dataset_path: str,
    url_dataset_path: str,
    output_base_dir: str = "outputs",
    extra_email_dataset_paths: Optional[Iterable[str]] = None,
) -> Dict[str, object]:
    logger.info("AI threat training started | email_dataset=%s | url_dataset=%s", email_dataset_path, url_dataset_path)
    email_paths = [email_dataset_path, *(extra_email_dataset_paths or [])]
    email_data = load_email_threat_dataset(email_paths)
    url_data = load_url_threat_dataset([url_dataset_path])

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_ai-threat")
    output_dir = Path(output_base_dir) / timestamp
    models_dir = output_dir / "models"
    observations_dir = output_dir / "observations"
    models_dir.mkdir(parents=True, exist_ok=True)
    observations_dir.mkdir(parents=True, exist_ok=True)

    email_result = _train_email_model(email_data)
    url_result = _train_url_model(url_data)

    email_bundle = {
        "model": email_result["model"],
        "features": email_result["features"],
        "labels": email_result["labels"],
        "thresholds": THRESHOLDS,
        "metadata": {
            "run_id": timestamp,
            "model_type": "email_threat_classifier",
            "dataset": dataset_provenance(email_data, email_dataset_path),
            "feature_config": email_feature_config(),
        },
    }
    url_bundle = {
        "model": url_result["model"],
        "features": url_result["features"],
        "labels": url_result["labels"],
        "thresholds": THRESHOLDS,
        "metadata": {
            "run_id": timestamp,
            "model_type": "url_phishing_classifier",
            "dataset": {
                **dataset_provenance(url_data.rename(columns={"label": "threat_label"}), url_dataset_path),
                "label_counts": url_data["label"].value_counts().to_dict(),
            },
            "feature_config": url_feature_config(),
        },
    }

    email_model_path = models_dir / "email_threat_model.pkl"
    url_model_path = models_dir / "url_phishing_model.pkl"
    with open(email_model_path, "wb") as f:
        pickle.dump(email_bundle, f)
    with open(url_model_path, "wb") as f:
        pickle.dump(url_bundle, f)

    _write_json(observations_dir / "email_threat_metrics.json", email_result["metrics"])
    _write_json(observations_dir / "url_phishing_metrics.json", url_result["metrics"])
    _write_json(observations_dir / "email_error_analysis.json", email_result["errors"])
    _write_json(observations_dir / "url_error_analysis.json", url_result["errors"])
    pd.DataFrame(url_result["thresholds"]).to_csv(observations_dir / "url_threshold_analysis.csv", index=False)

    metadata = {
        "run_id": timestamp,
        "best_model_name": "AIThreatRiskModel",
        "dataset_identity": {
            "email": dataset_identity(email_dataset_path),
            "url": dataset_identity(url_dataset_path),
        },
        "feature_config": {
            "email": email_feature_config(),
            "url": url_feature_config(),
        },
        "taxonomy": THREAT_LABELS,
        "best_metrics": {
            "email_macro_f1": email_result["metrics"].get("macro_f1"),
            "email_weighted_f1": email_result["metrics"].get("weighted_f1"),
            "url_macro_f1": url_result["metrics"].get("macro_f1"),
            "url_weighted_f1": url_result["metrics"].get("weighted_f1"),
        },
        "thresholds": THRESHOLDS,
        "baselines": {
            "binary_spam_ham": "preserved_existing_pipeline",
            "rule_only": "historical_report_only_not_runtime_scoring",
        },
        "artifact_paths": {
            "output_dir": str(output_dir),
            "email_model_path": str(email_model_path),
            "url_model_path": str(url_model_path),
            "observations_dir": str(observations_dir),
        },
        "label_quality": {
            "email": dataset_provenance(email_data, email_dataset_path),
            "url": dataset_provenance(url_data.rename(columns={"label": "threat_label"}), url_dataset_path),
        },
    }
    _write_json(observations_dir / "model_lab_metadata.json", metadata)
    pd.DataFrame([{
        "run_id": timestamp,
        "email_model_path": str(email_model_path),
        "url_model_path": str(url_model_path),
        "email_macro_f1": email_result["metrics"].get("macro_f1"),
        "url_macro_f1": url_result["metrics"].get("macro_f1"),
    }]).to_csv(observations_dir / "ai_threat_model_summary.csv", index=False)

    logger.info(
        "AI threat training completed | run_id=%s | email_macro_f1=%s | url_macro_f1=%s | output=%s",
        timestamp,
        metadata["best_metrics"]["email_macro_f1"],
        metadata["best_metrics"]["url_macro_f1"],
        output_dir,
    )
    return metadata


def _train_email_model(data: pd.DataFrame) -> Dict[str, object]:
    X = data[["text", "subject", "sender", "reply_to"]]
    y = data["threat_label"]
    stratify = y if y.value_counts().min() >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.35, random_state=42, stratify=stratify)
    features = build_email_feature_pipeline()
    X_train_matrix = features.fit_transform(X_train)
    X_test_matrix = features.transform(X_test)
    model = LogisticRegression(max_iter=1000, class_weight="balanced", solver="liblinear")
    model.fit(X_train_matrix, y_train)
    y_pred = model.predict(X_test_matrix)
    scores = _positive_scores(model, X_test_matrix, MALICIOUS_LABELS)
    metrics = _string_label_metrics(y_test, y_pred, scores)
    errors = _text_error_rows(X_test, y_test, y_pred, model, X_test_matrix)
    return {
        "model": model,
        "features": features,
        "labels": sorted(set(y)),
        "metrics": metrics,
        "errors": errors,
    }


def _train_url_model(data: pd.DataFrame) -> Dict[str, object]:
    X = data[["url"]]
    y = data["label"]
    stratify = y if y.value_counts().min() >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.35, random_state=42, stratify=stratify)
    features = build_url_feature_pipeline()
    X_train_matrix = features.fit_transform(X_train)
    X_test_matrix = features.transform(X_test)
    model = RandomForestClassifier(n_estimators=80, random_state=42, class_weight="balanced")
    model.fit(X_train_matrix, y_train)
    y_pred = model.predict(X_test_matrix)
    scores = _positive_scores(model, X_test_matrix, {"phishing", "suspicious"})
    metrics = _string_label_metrics(y_test, y_pred, scores)
    thresholds = threshold_report([1 if item in {"phishing", "suspicious"} else 0 for item in y_test], scores)
    errors = _url_error_rows(X_test, y_test, y_pred, model, X_test_matrix)
    return {
        "model": model,
        "features": features,
        "labels": sorted(set(y)),
        "metrics": metrics,
        "thresholds": thresholds,
        "errors": errors,
    }


def extract_url_features(url: str) -> Dict[str, object]:
    normalized = _normalize_url(url)
    parsed = urlparse(normalized)
    final_url = _extract_nested_url(normalized)
    final_parsed = urlparse(final_url)
    domain = (final_parsed.hostname or parsed.hostname or "").lower().strip(".")
    domain_parts = domain.split(".") if domain else []
    tld = domain_parts[-1] if domain_parts else ""
    path_query = f"{final_parsed.path}?{final_parsed.query}".lower()
    encoded_char_count = final_url.count("%")
    return {
        "is_url": _looks_like_url(url),
        "uses_https": final_parsed.scheme == "https",
        "uses_ip_address": _is_ip_address(domain),
        "is_shortened": domain in SHORTENER_DOMAINS,
        "has_nested_redirect": final_url != normalized,
        "has_at_symbol": "@" in final_url,
        "has_encoded_chars": encoded_char_count > 0,
        "has_many_subdomains": max(len(domain_parts) - 2, 0) >= 3,
        "url_length": len(final_url),
        "domain_length": len(domain),
        "digit_count": sum(ch.isdigit() for ch in domain),
        "hyphen_count": domain.count("-"),
        "encoded_char_count": encoded_char_count,
        "suspicious_tld": tld in HIGH_RISK_TLDS,
        "keyword_hits": sorted({kw for kw in SENSITIVE_KEYWORDS if kw in path_query or kw in domain}),
        "brand_impersonation": _detect_brand_impersonation(domain),
        "domain": domain,
        "final_url": final_url,
    }


def normalize_threat_label(value: object) -> str:
    raw = str(value or "").strip().lower()
    mapping = {
        "ham": "Safe",
        "safe": "Safe",
        "benign": "Safe",
        "normal": "Safe",
        "spam": "Spam",
        "phishing": "Phishing",
        "malware": "Malware Risk",
        "malware risk": "Malware Risk",
        "credential": "Credential Theft",
        "credential theft": "Credential Theft",
        "payment": "Payment Scam",
        "payment scam": "Payment Scam",
        "quishing": "Quishing",
        "bec": "Business Email Compromise",
        "business email compromise": "Business Email Compromise",
    }
    return mapping.get(raw, str(value or "Safe").strip() or "Safe")


def normalize_url_label(value: object) -> str:
    raw = str(value or "").strip().lower()
    if raw in {"1", "phishing", "malicious", "bad", "high"}:
        return "phishing"
    if raw in {"suspicious", "medium"}:
        return "suspicious"
    return "benign"


def risk_level_from_score(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def risk_level_from_label(label: str) -> str:
    if label in {"Malware Risk", "Credential Theft", "Payment Scam", "Quishing", "Business Email Compromise"}:
        return "High"
    if label in {"Spam", "Phishing"}:
        return "Medium"
    return "Low"


def email_verdict(label: str, score: int) -> str:
    mapping = {
        "Safe": "LOW_RISK_EMAIL",
        "Spam": "SPAM_EMAIL",
        "Phishing": "PHISHING_EMAIL",
        "Malware Risk": "MALWARE_RISK_EMAIL",
        "Credential Theft": "CREDENTIAL_THEFT_EMAIL",
        "Payment Scam": "PAYMENT_SCAM_EMAIL",
        "Quishing": "QUISHING_EMAIL",
        "Business Email Compromise": "BUSINESS_EMAIL_COMPROMISE",
    }
    if score >= 80 and label != "Safe":
        return "CRITICAL_EMAIL_THREAT"
    return mapping.get(label, "SUSPICIOUS_EMAIL")


def url_verdict(score: int) -> str:
    if score >= 80:
        return "PHISHING_URL"
    if score >= 60:
        return "HIGH_RISK_URL"
    if score >= 35:
        return "SUSPICIOUS_URL"
    return "LOW_RISK_URL"


def email_feature_config() -> Dict[str, object]:
    return {
        "word_tfidf": {"ngram_range": [1, 2], "max_features": 12000, "stop_words": "english"},
        "char_tfidf": {"analyzer": "char_wb", "ngram_range": [3, 5], "max_features": 8000},
        "numeric": [
            "length",
            "digit_count",
            "url_count",
            "exclamation_count",
            "urgency_flag",
            "credential_flag",
            "payment_flag",
            "risky_file_flag",
            "sender_reply_to_mismatch",
            "brand_impersonation_flag",
        ],
    }


def url_feature_config() -> Dict[str, object]:
    return {
        "numeric": [
            "uses_https",
            "uses_ip_address",
            "is_shortened",
            "has_nested_redirect",
            "has_at_symbol",
            "has_encoded_chars",
            "has_many_subdomains",
            "suspicious_tld",
            "keyword_hits",
            "brand_impersonation",
            "url_length",
            "domain_length",
            "digit_count",
            "hyphen_count",
            "encoded_char_count",
        ],
    }


def _class_scores(model, matrix, labels: List[str]) -> Dict[str, float]:
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(matrix)[0]
        model_labels = [str(item) for item in model.classes_]
        return {label: round(float(probabilities[model_labels.index(label)]) * 100, 2) for label in model_labels}
    label = str(model.predict(matrix)[0])
    return {item: 100.0 if item == label else 0.0 for item in labels}


def _risk_from_class_scores(label: str, scores: Dict[str, float]) -> int:
    if label == "Safe":
        return int(round(max(0.0, 100.0 - float(scores.get("Safe", 100.0)))))
    malicious_score = max(float(scores.get(item, 0.0)) for item in MALICIOUS_LABELS)
    return int(round(max(RISK_LEVEL_TO_SCORE.get(risk_level_from_label(label), 35), malicious_score)))


def _positive_scores(model, matrix, positive_labels: Iterable[str]) -> List[float]:
    positive_labels = {str(item) for item in positive_labels}
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(matrix)
        labels = [str(item) for item in model.classes_]
        positive_indexes = [index for index, label in enumerate(labels) if label in positive_labels]
        if positive_indexes:
            return probabilities[:, positive_indexes].sum(axis=1).tolist()
    predictions = [str(item) for item in model.predict(matrix)]
    return [1.0 if item in positive_labels else 0.0 for item in predictions]


def _string_label_metrics(y_true, y_pred, positive_scores: Optional[Iterable[float]] = None) -> Dict[str, object]:
    labels = sorted(set(str(item) for item in list(y_true) + list(y_pred)))
    precision, recall, f1, support = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    metrics = {
        "labels": labels,
        "per_class": {
            str(label): {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
            }
            for index, label in enumerate(labels)
        },
        "macro_f1": float(report.get("macro avg", {}).get("f1-score", 0.0)),
        "weighted_f1": float(report.get("weighted avg", {}).get("f1-score", 0.0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
    }
    if positive_scores is not None:
        binary_true = [1 if str(item) in MALICIOUS_LABELS or str(item) in {"phishing", "suspicious"} else 0 for item in y_true]
        binary_pred = [1 if str(item) in MALICIOUS_LABELS or str(item) in {"phishing", "suspicious"} else 0 for item in y_pred]
        metrics["binary_security_view"] = evaluate_predictions(binary_true, binary_pred, positive_scores)
    return metrics


def _text_error_rows(X_test, y_true, y_pred, model, matrix) -> Dict[str, List[Dict[str, object]]]:
    confidences = []
    if hasattr(model, "predict_proba"):
        confidences = (model.predict_proba(matrix).max(axis=1) * 100).tolist()
    else:
        confidences = [None] * len(y_pred)
    result = {"false_positives": [], "false_negatives": [], "low_confidence": []}
    for index, (_, row) in enumerate(X_test.reset_index(drop=True).iterrows()):
        truth = str(list(y_true)[index])
        pred = str(list(y_pred)[index])
        item = {
            "index": index,
            "preview": f"{row.get('subject', '')} {row.get('text', '')}"[:180],
            "expected_label": truth,
            "predicted_label": pred,
            "confidence": confidences[index],
        }
        if truth == "Safe" and pred != "Safe":
            result["false_positives"].append(item)
        if truth != "Safe" and pred == "Safe":
            result["false_negatives"].append(item)
        if confidences[index] is not None and float(confidences[index]) < 60:
            result["low_confidence"].append(item)
    return result


def _url_error_rows(X_test, y_true, y_pred, model, matrix) -> Dict[str, List[Dict[str, object]]]:
    confidences = []
    if hasattr(model, "predict_proba"):
        confidences = (model.predict_proba(matrix).max(axis=1) * 100).tolist()
    else:
        confidences = [None] * len(y_pred)
    result = {"false_positives": [], "false_negatives": [], "low_confidence": []}
    for index, (_, row) in enumerate(X_test.reset_index(drop=True).iterrows()):
        truth = str(list(y_true)[index])
        pred = str(list(y_pred)[index])
        item = {
            "index": index,
            "url": row.get("url", ""),
            "expected_label": truth,
            "predicted_label": pred,
            "confidence": confidences[index],
        }
        if truth == "benign" and pred != "benign":
            result["false_positives"].append(item)
        if truth != "benign" and pred == "benign":
            result["false_negatives"].append(item)
        if confidences[index] is not None and float(confidences[index]) < 60:
            result["low_confidence"].append(item)
    return result


def _normalize_url(url: str) -> str:
    url = str(url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        return f"http://{url}"
    return url


def _extract_urls(text: str) -> List[str]:
    return re.findall(r"https?://[^\s<>'\"]+|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s<>'\"]*)?", text or "")


def _risky_filenames(text: str) -> List[str]:
    return re.findall(
        r"\b[\w.-]+\.(?:exe|scr|bat|cmd|js|vbs|msi|apk|jar|zip|rar|7z)\b",
        text or "",
        flags=re.IGNORECASE,
    )


def _url_has_brand_impersonation(url: str) -> bool:
    return bool(extract_url_features(url).get("brand_impersonation"))


def _looks_like_url(value: str) -> bool:
    value = str(value or "").strip()
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        return True
    return bool(re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/|$)", value))


def _extract_nested_url(url: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    for key in ("url", "u", "target", "redirect", "redirect_url", "to", "link"):
        values = query.get(key)
        if values:
            nested = unquote(values[0])
            if nested.startswith(("http://", "https://")):
                return nested
    return url


def _is_ip_address(value: str) -> bool:
    try:
        import ipaddress

        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _detect_brand_impersonation(domain: str) -> Optional[Dict[str, str]]:
    from difflib import SequenceMatcher

    compact_domain = domain.replace("-", "").replace(".", "")
    for brand, official_domain in BRAND_DOMAINS.items():
        if domain == official_domain or domain.endswith(f".{official_domain}"):
            continue
        if brand in compact_domain:
            return {"brand": brand, "official_domain": official_domain}
        ratio = SequenceMatcher(None, brand, compact_domain[: len(brand) + 4]).ratio()
        if ratio >= 0.82:
            return {"brand": brand, "official_domain": official_domain}
    return None


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _write_json(path: Path, data: Dict[str, object]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
