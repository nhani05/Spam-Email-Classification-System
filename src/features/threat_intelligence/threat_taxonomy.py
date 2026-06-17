from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional


THREAT_LABELS = [
    "Safe",
    "Spam",
    "Phishing",
    "Malware Risk",
    "Business Email Compromise",
    "Quishing",
    "Credential Theft",
    "Payment Scam",
]


@dataclass
class ThreatClassification:
    label: str
    confidence: Optional[float]
    class_scores: Dict[str, float]
    reasons: List[str]

    def to_dict(self) -> Dict[str, object]:
        return {
            "label": self.label,
            "confidence": self.confidence,
            "class_scores": self.class_scores,
            "reasons": self.reasons,
        }


class ThreatTaxonomyClassifier:
    """Map ML and security signals into a defensible email-threat taxonomy."""

    def classify(
        self,
        prediction: str,
        confidence: Optional[float],
        threat_result: object,
        qr_results: Optional[Iterable[Dict[str, object]]] = None,
    ) -> ThreatClassification:
        threat_data = self._as_dict(threat_result)
        qr_results = list(qr_results or [])

        phishing = int(threat_data.get("phishing_score", 0) or 0)
        malware = int(threat_data.get("malware_score", 0) or 0)
        fake_link = int(threat_data.get("fake_link_score", 0) or 0)
        risk = int(threat_data.get("risk_score", 0) or 0)
        urls = list(threat_data.get("urls", []) or [])

        scores = {label: 0.0 for label in THREAT_LABELS}
        scores["Safe"] = max(0.0, 100.0 - max(risk, self._spam_probability(prediction, confidence)))
        scores["Spam"] = self._spam_probability(prediction, confidence)
        scores["Phishing"] = float(max(phishing, fake_link))
        scores["Malware Risk"] = float(malware)

        credential_hits = self._credential_signal(threat_data)
        scores["Credential Theft"] = float(max(phishing, fake_link, credential_hits))

        payment_signal = self._payment_signal(threat_data, qr_results)
        scores["Payment Scam"] = float(payment_signal)

        quishing_signal = self._quishing_signal(qr_results)
        scores["Quishing"] = float(quishing_signal)

        if self._bec_signal(threat_data):
            scores["Business Email Compromise"] = max(scores["Business Email Compromise"], 55.0)

        if urls and risk >= 35:
            scores["Phishing"] = max(scores["Phishing"], float(risk))

        label = max(scores, key=scores.get)
        if scores[label] < 35 and (prediction or "").lower() == "spam":
            label = "Spam"
        elif scores[label] < 35:
            label = "Safe"

        confidence_value = min(100.0, max(0.0, scores[label]))
        reasons = self._reasons(label, threat_data, qr_results)

        return ThreatClassification(
            label=label,
            confidence=confidence_value,
            class_scores={key: round(value, 2) for key, value in scores.items()},
            reasons=reasons,
        )

    def _spam_probability(self, prediction: str, confidence: Optional[float]) -> float:
        if (prediction or "").lower() != "spam":
            return 100.0 - float(confidence or 95.0) if confidence is not None else 15.0
        return float(confidence or 70.0)

    def _credential_signal(self, threat_data: Dict[str, object]) -> int:
        reasons = " ".join(str(item).lower() for item in threat_data.get("reasons", []) or [])
        if any(token in reasons for token in ("password", "otp", "credential", "login", "verify")):
            return max(60, int(threat_data.get("phishing_score", 0) or 0))
        return 0

    def _payment_signal(self, threat_data: Dict[str, object], qr_results: List[Dict[str, object]]) -> int:
        reasons = " ".join(str(item).lower() for item in threat_data.get("reasons", []) or [])
        score = 0
        if any(token in reasons for token in ("payment", "invoice", "bank-transfer", "refund", "transfer")):
            score = max(score, 45)
        for result in qr_results:
            if result.get("verdict") == "PAYMENT_QR_REVIEW" or result.get("features", {}).get("is_payment_payload"):
                score = max(score, int(result.get("risk_score", 40) or 40), 60)
        return score

    def _quishing_signal(self, qr_results: List[Dict[str, object]]) -> int:
        if not qr_results:
            return 0
        return max(int(result.get("risk_score", 0) or 0) for result in qr_results)

    def _bec_signal(self, threat_data: Dict[str, object]) -> bool:
        reasons = " ".join(str(item).lower() for item in threat_data.get("reasons", []) or [])
        return "payment" in reasons and "urgent" in reasons

    def _reasons(
        self,
        label: str,
        threat_data: Dict[str, object],
        qr_results: List[Dict[str, object]],
    ) -> List[str]:
        reasons = [f"Threat taxonomy selected `{label}` from ML, URL, QR, and rule signals."]
        for reason in list(threat_data.get("reasons", []) or [])[:3]:
            reasons.append(str(reason))
        if qr_results:
            reasons.append("QR payload analysis contributed to the threat taxonomy decision.")
        return self._dedupe(reasons)

    def _as_dict(self, value: object) -> Dict[str, object]:
        if hasattr(value, "to_dict"):
            return value.to_dict()
        if isinstance(value, dict):
            return value
        return {}

    def _dedupe(self, values: List[str]) -> List[str]:
        seen = set()
        result = []
        for value in values:
            if value and value not in seen:
                seen.add(value)
                result.append(value)
        return result
