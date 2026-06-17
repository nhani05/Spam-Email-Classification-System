from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class RiskAnalysisResult:
    prediction: str
    confidence: Optional[float]
    risk_score: int
    risk_level: str
    verdict: str
    threat_label: str = "Safe"
    reasons: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    components: Dict[str, object] = field(default_factory=dict)
    urls: List[Dict[str, object]] = field(default_factory=list)
    class_scores: Dict[str, float] = field(default_factory=dict)
    campaign: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "prediction": self.prediction,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "verdict": self.verdict,
            "threat_label": self.threat_label,
            "reasons": self.reasons,
            "recommended_actions": self.recommended_actions,
            "components": self.components,
            "urls": self.urls,
            "class_scores": self.class_scores,
            "campaign": self.campaign,
        }


class RiskAggregator:
    """Combine ML spam prediction with explainable rule-based threat signals."""

    def aggregate_email(
        self,
        prediction: str,
        confidence: Optional[float],
        threat_result: object,
        threat_classification: object = None,
        campaign_result: Optional[Dict[str, object]] = None,
    ) -> RiskAnalysisResult:
        threat_data = self._as_dict(threat_result)
        classification_data = self._as_dict(threat_classification)
        campaign_result = campaign_result or {}
        ml_score, ml_reasons = self._score_ml_prediction(prediction, confidence)
        threat_score = int(threat_data.get("risk_score", 0) or 0)
        campaign_score = int(campaign_result.get("risk_score", 0) or 0)

        combined_score = max(ml_score, threat_score, campaign_score)
        if ml_score >= 35 and threat_score >= 35:
            combined_score += 12
        if prediction.lower() == "ham" and threat_score >= 60:
            combined_score += 8
        if campaign_score >= 60:
            combined_score += 8
        risk_score = min(100, combined_score)

        reasons = self._dedupe(
            ml_reasons
            + list(threat_data.get("reasons", []))
            + list(classification_data.get("reasons", []))
            + self._campaign_reasons(campaign_result)
            + self._conflict_reasons(prediction, threat_score)
        )
        if not reasons:
            reasons = ["No strong spam, phishing, fake-link, or malware indicator found."]

        result = RiskAnalysisResult(
            prediction=prediction,
            confidence=confidence,
            risk_score=risk_score,
            risk_level=self._risk_level(risk_score),
            verdict=self._verdict(risk_score, prediction, threat_data, classification_data),
            threat_label=str(classification_data.get("label") or self._threat_label_from_scores(prediction, threat_data)),
            reasons=reasons,
            recommended_actions=self._recommended_actions(risk_score, threat_data),
            components={
                "ml_spam_score": ml_score,
                "threat_score": threat_score,
                "campaign_score": campaign_score,
                "phishing_score": int(threat_data.get("phishing_score", 0) or 0),
                "fake_link_score": int(threat_data.get("fake_link_score", 0) or 0),
                "malware_score": int(threat_data.get("malware_score", 0) or 0),
                "threat_verdict": threat_data.get("verdict", "UNKNOWN"),
            },
            urls=list(threat_data.get("urls", [])),
            class_scores=dict(classification_data.get("class_scores", {}) or {}),
            campaign=campaign_result,
        )
        return result

    def _score_ml_prediction(self, prediction: str, confidence: Optional[float]) -> tuple[int, List[str]]:
        normalized_prediction = (prediction or "").strip().lower()
        confidence_value = self._bounded_confidence(confidence)

        if normalized_prediction == "spam":
            if confidence_value is None:
                return 60, ["ML classifier predicts Spam."]
            score = min(85, 30 + round(confidence_value * 0.55))
            return score, [f"ML classifier predicts Spam with {confidence_value:.1f}% confidence."]

        if confidence_value is None:
            return 10, ["ML classifier predicts Ham, but confidence was unavailable."]

        if confidence_value < 60:
            return 25, [f"ML classifier predicts Ham, but confidence is low ({confidence_value:.1f}%)."]

        return 5, [f"ML classifier predicts Ham with {confidence_value:.1f}% confidence."]

    def _conflict_reasons(self, prediction: str, threat_score: int) -> List[str]:
        if prediction.lower() == "ham" and threat_score >= 60:
            return ["Rule-based threat analysis found high-risk signals even though the ML label is Ham."]
        if prediction.lower() == "spam" and threat_score < 35:
            return ["ML spam signal is the main risk indicator; rule-based threat signals are low."]
        return []

    def _recommended_actions(self, risk_score: int, threat_data: Dict[str, object]) -> List[str]:
        actions: List[str] = []

        if risk_score >= 80:
            actions.append("Do not click links, scan QR codes, download files, or reply to this email.")
            actions.append("Report or delete the message after preserving evidence if needed.")
        elif risk_score >= 60:
            actions.append("Treat this email as dangerous until verified through a trusted channel.")
            actions.append("Do not provide passwords, OTP codes, payment details, or personal information.")
        elif risk_score >= 35:
            actions.append("Review the sender, links, and attachments carefully before taking action.")
            actions.append("Open the official website directly instead of using links in the email.")
        else:
            actions.append("No urgent action is required, but keep normal email safety checks in mind.")

        if threat_data.get("urls"):
            actions.append("Verify detected domains before opening any link.")
        if threat_data.get("risky_files"):
            actions.append("Do not open mentioned attachments or downloads unless you trust the sender.")

        return self._dedupe(actions)

    def _campaign_reasons(self, campaign_result: Dict[str, object]) -> List[str]:
        if not campaign_result:
            return []
        campaign_id = campaign_result.get("campaign_id")
        if not campaign_id:
            return []
        return [f"Email is linked to campaign {campaign_id} ({campaign_result.get('risk_level', 'Unknown')} risk)."]

    def _threat_label_from_scores(self, prediction: str, threat_data: Dict[str, object]) -> str:
        if int(threat_data.get("malware_score", 0) or 0) >= 60:
            return "Malware Risk"
        if int(threat_data.get("fake_link_score", 0) or 0) >= 35 or int(threat_data.get("phishing_score", 0) or 0) >= 60:
            return "Phishing"
        if prediction.lower() == "spam":
            return "Spam"
        return "Safe"

    def _verdict(
        self,
        score: int,
        prediction: str,
        threat_data: Dict[str, object],
        classification_data: Optional[Dict[str, object]] = None,
    ) -> str:
        label = str((classification_data or {}).get("label") or "")
        if label == "Quishing":
            return "QUISHING_EMAIL"
        if label == "Payment Scam":
            return "PAYMENT_SCAM_EMAIL"
        if label == "Credential Theft":
            return "CREDENTIAL_THEFT_EMAIL"
        threat_verdict = str(threat_data.get("verdict", ""))
        malware_score = int(threat_data.get("malware_score", 0) or 0)
        fake_link_score = int(threat_data.get("fake_link_score", 0) or 0)

        if score >= 80:
            return "CRITICAL_EMAIL_THREAT"
        if malware_score >= 60:
            return "MALWARE_RISK_EMAIL"
        if fake_link_score >= 60:
            return "FAKE_LINK_PHISHING"
        if score >= 60:
            return "HIGH_RISK_EMAIL"
        if score >= 35:
            return threat_verdict if threat_verdict and threat_verdict != "LOW_RISK_EMAIL" else "SUSPICIOUS_EMAIL"
        if prediction.lower() == "spam":
            return "SPAM_LOW_THREAT"
        return "LOW_RISK_EMAIL"

    def _risk_level(self, score: int) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 35:
            return "Medium"
        return "Low"

    def _as_dict(self, value: object) -> Dict[str, object]:
        if hasattr(value, "to_dict"):
            return value.to_dict()
        if isinstance(value, dict):
            return value
        return {}

    def _bounded_confidence(self, confidence: Optional[float]) -> Optional[float]:
        if confidence is None:
            return None
        return max(0.0, min(100.0, float(confidence)))

    def _dedupe(self, values: List[str]) -> List[str]:
        seen = set()
        result = []
        for value in values:
            if value and value not in seen:
                seen.add(value)
                result.append(value)
        return result
