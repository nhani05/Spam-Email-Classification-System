import ipaddress
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Dict, List
from urllib.parse import parse_qs, unquote, urlparse

from src.utils.logger import get_logger

logger = get_logger(__name__)


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "s.id",
}

HIGH_RISK_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "xyz",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "work",
    "support",
}

SENSITIVE_KEYWORDS = {
    "login",
    "verify",
    "password",
    "passwd",
    "account",
    "bank",
    "wallet",
    "invoice",
    "payment",
    "secure",
    "security",
    "confirm",
    "update",
    "reset",
    "otp",
    "auth",
}

BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "facebook": "facebook.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "vnpay": "vnpay.vn",
    "momo": "momo.vn",
    "vietcombank": "vietcombank.com.vn",
    "mbbank": "mbbank.com.vn",
    "techcombank": "techcombank.com",
}


@dataclass
class URLRiskResult:
    url: str
    final_url: str
    domain: str
    risk_score: int
    risk_level: str
    verdict: str
    features: Dict[str, object] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "domain": self.domain,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "verdict": self.verdict,
            "features": self.features,
            "reasons": self.reasons,
        }


class URLRiskModel:
    """Explainable phishing risk model for URLs from email text and QR payloads."""

    def __init__(self, ai_service=None) -> None:
        self.ai_service = ai_service
        if self.ai_service is None:
            try:
                from src.config.config import Config
                from src.ml.threat_classifier.service import AIThreatModelService

                config = Config()
                self.ai_service = AIThreatModelService(url_model_path=config.ai_url_model_path)
            except Exception:
                self.ai_service = None

    def analyze(self, url: str) -> URLRiskResult:
        logger.info("URL analysis started | url=%s", url)
        if not self._looks_like_url(url):
            return self._analyze_non_url_qr(url)

        normalized_url = self._normalize_url(url)
        parsed = urlparse(normalized_url)
        domain = parsed.hostname or ""
        domain = domain.lower().strip(".")
        final_url = self._extract_nested_url(normalized_url)
        final_parsed = urlparse(final_url)
        final_domain = (final_parsed.hostname or domain).lower().strip(".")

        features = self._extract_features(normalized_url, final_url, final_domain)
        score = 0
        risk_level = "Unavailable"
        verdict = "AI_URL_MODEL_UNAVAILABLE"
        reasons = [
            "AI URL phishing model artifacts are unavailable.",
            "Train the AI URL model and configure ai_url_model_path before using URL risk scoring.",
        ]
        if self.ai_service is not None:
            ai_result = self.ai_service.predict_url(url)
            if ai_result and ai_result.get("model_available"):
                score = int(ai_result["risk_score"])
                risk_level = str(ai_result["risk_level"])
                verdict = str(ai_result["verdict"])
                features = {
                    **features,
                    "ai_model": {
                        "model_label": ai_result.get("model_label"),
                        "model_probability": ai_result.get("model_probability"),
                        "class_scores": ai_result.get("class_scores", {}),
                        "provenance": ai_result.get("provenance", {}),
                    },
                }
                reasons = list(ai_result.get("reasons", []))
                logger.info(
                    "URL analysis using AI model | domain=%s | risk=%s | verdict=%s",
                    final_domain,
                    score,
                    verdict,
                )
            else:
                if ai_result:
                    features = {
                        **features,
                        "ai_model": {
                            "model_label": ai_result.get("model_label"),
                            "model_probability": ai_result.get("model_probability"),
                            "class_scores": ai_result.get("class_scores", {}),
                            "provenance": ai_result.get("provenance", {}),
                        },
                    }
                    reasons = list(ai_result.get("reasons", reasons))
                logger.info(
                    "URL analysis model unavailable | domain=%s | risk_source=model_unavailable",
                    final_domain,
                )
        else:
            logger.info(
                "URL analysis model unavailable | domain=%s | risk_source=model_unavailable",
                final_domain,
            )

        return URLRiskResult(
            url=url,
            final_url=final_url,
            domain=final_domain,
            risk_score=score,
            risk_level=risk_level,
            verdict=verdict,
            features=features,
            reasons=reasons,
        )

    def _looks_like_url(self, value: str) -> bool:
        value = value.strip()
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
            return True
        return bool(re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/|$)", value))

    def _analyze_non_url_qr(self, value: str) -> URLRiskResult:
        compact = re.sub(r"\s+", "", value)
        is_payment_payload = compact.startswith("000201") or "A000000727" in compact

        if is_payment_payload:
            return URLRiskResult(
                url=value,
                final_url=value,
                domain="",
                risk_score=0,
                risk_level="Unavailable",
                verdict="NON_URL_QR_UNSCORED",
                features={
                    "is_url": False,
                    "is_payment_payload": True,
                    "payload_length": len(compact),
                },
                reasons=[
                    "QR code contains a payment payload, not a web URL.",
                    "AI URL model scoring applies only to decoded URLs; this payload is retained as evidence without a rule-derived risk verdict.",
                ],
            )

        return URLRiskResult(
            url=value,
            final_url=value,
            domain="",
            risk_score=0,
            risk_level="Unavailable",
            verdict="NON_URL_QR_UNSCORED",
            features={
                "is_url": False,
                "is_payment_payload": False,
                "payload_length": len(compact),
            },
            reasons=["QR code was decoded, but it does not contain a web URL; no rule-derived risk verdict was assigned."],
        )

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
            return f"http://{url}"
        return url

    def _extract_nested_url(self, url: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        candidate_keys = ("url", "u", "target", "redirect", "redirect_url", "to", "link")

        for key in candidate_keys:
            values = query.get(key)
            if not values:
                continue
            nested = unquote(values[0])
            if nested.startswith(("http://", "https://")):
                return nested
        return url

    def _extract_features(self, url: str, final_url: str, domain: str) -> Dict[str, object]:
        parsed = urlparse(final_url)
        path_query = f"{parsed.path}?{parsed.query}".lower()
        domain_parts = domain.split(".")
        tld = domain_parts[-1] if domain_parts else ""
        encoded_char_count = final_url.count("%")

        return {
            "uses_https": parsed.scheme == "https",
            "uses_ip_address": self._is_ip_address(domain),
            "is_shortened": domain in SHORTENER_DOMAINS,
            "has_nested_redirect": final_url != url,
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
            "brand_impersonation": self._detect_brand_impersonation(domain),
        }

    def _score(self, features: Dict[str, object], domain: str, url: str) -> tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []

        checks = [
            (not features["uses_https"], 12, "URL does not use HTTPS."),
            (features["uses_ip_address"], 25, "URL uses a raw IP address instead of a domain."),
            (features["is_shortened"], 18, "URL points to a shortened URL."),
            (features["has_nested_redirect"], 18, "URL contains a nested redirect parameter."),
            (features["has_at_symbol"], 20, "URL contains '@', which can hide the real destination."),
            (features["has_encoded_chars"], 8, "URL contains encoded characters such as '%', which can hide text."),
            (features["has_many_subdomains"], 12, "Domain has an unusual number of subdomains."),
            (features["url_length"] > 120, 12, "URL is unusually long."),
            (features["domain_length"] > 35, 10, "Domain name is unusually long."),
            (features["digit_count"] >= 4, 10, "Domain contains many digits."),
            (features["hyphen_count"] >= 2, 10, "Domain contains many hyphens."),
            (features["suspicious_tld"], 12, "Domain uses a high-risk top-level domain."),
        ]

        for matched, weight, reason in checks:
            if matched:
                score += weight
                reasons.append(reason)

        keyword_hits = features["keyword_hits"]
        if keyword_hits:
            score += min(22, 6 * len(keyword_hits))
            reasons.append(f"URL contains sensitive phishing keywords: {', '.join(keyword_hits)}.")

        brand = features["brand_impersonation"]
        if brand:
            score += 28
            reasons.append(
                f"Domain resembles {brand['brand']} but is not the official domain {brand['official_domain']}."
            )

        if re.search(r"\.(exe|scr|bat|cmd|js|vbs|msi|apk|jar)(\?|$)", url.lower()):
            score += 25
            reasons.append("URL appears to point to a risky executable file.")

        return min(score, 100), reasons

    def _risk_level(self, score: int) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 35:
            return "Medium"
        return "Low"

    def _verdict(self, score: int, features: Dict[str, object]) -> str:
        if score >= 80:
            return "PHISHING_URL"
        if score >= 60:
            return "HIGH_RISK_URL"
        if score >= 35:
            return "SUSPICIOUS_URL"
        if features["is_shortened"]:
            return "UNKNOWN_SHORT_LINK"
        return "LOW_RISK_URL"

    def _is_ip_address(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _detect_brand_impersonation(self, domain: str) -> Dict[str, str] | None:
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
