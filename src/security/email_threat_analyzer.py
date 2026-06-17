import os
import re
from dataclasses import dataclass, field
from html import unescape
from typing import Dict, List

from bs4 import BeautifulSoup

from .url_risk_model import URLRiskModel

try:
    import torch
    from transformers import pipeline
except ImportError:
    torch = None
    pipeline = None


URL_PATTERN = re.compile(
    r"(?i)\b((?:https?://|www\.)[^\s<>'\"]+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>'\"]*)?)"
)

RISKY_FILE_EXTENSIONS = {
    "exe",
    "scr",
    "bat",
    "cmd",
    "js",
    "jse",
    "vbs",
    "vbe",
    "wsf",
    "ps1",
    "msi",
    "apk",
    "jar",
    "com",
    "lnk",
}

ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "iso", "gz"}
DOCUMENT_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "png", "mp4"}

URGENT_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bwithin\s+24\s+hours\b",
    r"\baccount\s+(?:locked|suspended|disabled)\b",
    r"\bverify\s+(?:your\s+)?account\b",
    r"\bconfirm\s+(?:your\s+)?identity\b",
    r"\breset\s+(?:your\s+)?password\b",
    r"\bunauthorized\s+(?:login|transaction|access)\b",
    r"\bpayment\s+(?:failed|overdue|required)\b",
    r"\bscan\s+(?:the\s+)?qr\b",
    r"\bclick\s+(?:here|the\s+link)\b",
    r"\bclaim\s+(?:your\s+)?(?:reward|prize|gift)\b",
    r"t[aà]i kho[aả]n.*(?:kh[oó]a|t[aạ]m ng[uư]ng|x[aá]c minh)",
    r"x[aá]c minh.*(?:m[aậ]t kh[aẩ]u|otp|t[aà]i kho[aả]n)",
    r"chuy[eể]n ti[eề]n|thanh to[aá]n g[aấ]p|qu[eé]t mã|qu[eé]t qr",
]

CREDENTIAL_PATTERNS = [
    r"\bpassword\b",
    r"\bpasscode\b",
    r"\botp\b",
    r"\b2fa\b",
    r"\bsecurity\s+code\b",
    r"\blogin\b",
    r"\bsign\s+in\b",
    r"m[aậ]t kh[aẩ]u",
    r"m[aã]\s+otp",
    r"[dđ][aă]ng nh[aậ]p",
]

MONEY_PATTERNS = [
    r"\binvoice\b",
    r"\bpayment\b",
    r"\bbank\s+transfer\b",
    r"\brefund\b",
    r"\boverdue\b",
    r"h[oó]a [dđ][oơ]n",
    r"chuy[eể]n kho[aả]n",
    r"ho[aà]n ti[eề]n",
    r"ph[ií]",
]


@dataclass
class EmailThreatResult:
    verdict: str
    risk_level: str
    risk_score: int
    phishing_score: int
    malware_score: int
    fake_link_score: int
    urls: List[Dict[str, object]] = field(default_factory=list)
    risky_files: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "verdict": self.verdict,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "phishing_score": self.phishing_score,
            "malware_score": self.malware_score,
            "fake_link_score": self.fake_link_score,
            "urls": self.urls,
            "risky_files": self.risky_files,
            "reasons": self.reasons,
        }


class EmailThreatAnalyzer:
    """Hybrid analyzer for phishing, fake links, and malware indicators."""

    def __init__(self) -> None:
        self.url_model = URLRiskModel()
        self.ai_phishing_detector = None
        
        if pipeline is not None and torch is not None:
            try:
                device = "cuda" if torch.cuda.is_available() else "cpu"
                model_path = "outputs/phishing_detector_vi"
                # Nếu chưa tự train, sẽ lấy mô hình trực tiếp từ Hugging Face
                if not os.path.exists(model_path):
                    model_path = "nxtcute/xlm-r-phishing-and-social-engineering-detector-vi"
                self.ai_phishing_detector = pipeline(
                    "text-classification", model=model_path, tokenizer=model_path, device=device
                )
            except Exception as e:
                print(f"Warning: Không thể tải AI Phishing Model: {e}")

    def analyze(self, email_text: str) -> EmailThreatResult:
        normalized_text = self._normalize_text(email_text)
        urls = [self.url_model.analyze(url).to_dict() for url in self._extract_urls(email_text)]
        risky_files = self._extract_risky_files(normalized_text)

        phishing_score, phishing_reasons = self._score_phishing_text(normalized_text)
        malware_score, malware_reasons = self._score_malware(normalized_text, risky_files, urls)
        fake_link_score, fake_link_reasons = self._score_fake_links(urls)

        risk_score = min(100, max(phishing_score, malware_score, fake_link_score) + self._combo_bonus(
            phishing_score, malware_score, fake_link_score
        ))
        verdict = self._verdict(risk_score, phishing_score, malware_score, fake_link_score)
        risk_level = self._risk_level(risk_score)
        reasons = self._dedupe(phishing_reasons + malware_reasons + fake_link_reasons)

        if not reasons:
            reasons = ["No strong phishing, fake link, or malware indicator found."]

        return EmailThreatResult(
            verdict=verdict,
            risk_level=risk_level,
            risk_score=risk_score,
            phishing_score=phishing_score,
            malware_score=malware_score,
            fake_link_score=fake_link_score,
            urls=urls,
            risky_files=risky_files,
            reasons=reasons,
        )

    def _normalize_text(self, email_text: str) -> str:
        text = unescape(email_text or "")
        if "<" in text and ">" in text:
            text = BeautifulSoup(text, "html.parser").get_text(" ")
        text = re.sub(r"\s+", " ", text)
        return text.strip().lower()

    def _extract_urls(self, email_text: str) -> List[str]:
        text = unescape(email_text or "")
        urls = []

        if "<" in text and ">" in text:
            soup = BeautifulSoup(text, "html.parser")
            for tag in soup.find_all("a"):
                href = tag.get("href")
                if href:
                    urls.append(href.strip())

        for match in URL_PATTERN.findall(text):
            urls.append(match.rstrip(".,);]}>\"'"))

        return self._dedupe(urls)

    def _extract_risky_files(self, text: str) -> List[str]:
        file_pattern = re.compile(r"\b[\w.-]+\.(?:[a-z0-9]{2,5})(?:\.[a-z0-9]{2,5})?\b", re.IGNORECASE)
        risky = []

        for filename in file_pattern.findall(text):
            parts = filename.lower().split(".")
            if len(parts) < 2:
                continue

            extension = parts[-1]
            previous_extension = parts[-2] if len(parts) >= 3 else ""
            is_double_extension = previous_extension in DOCUMENT_EXTENSIONS and extension in RISKY_FILE_EXTENSIONS

            if extension in RISKY_FILE_EXTENSIONS or extension in ARCHIVE_EXTENSIONS or is_double_extension:
                risky.append(filename)

        return self._dedupe(risky)

    def _score_phishing_text(self, text: str) -> tuple[int, List[str]]:
        reasons = []

        # 1. Phân tích bằng AI Model (Mới)
        ai_score = 0
        if self.ai_phishing_detector is not None and text.strip():
            try:
                # XLM-R giới hạn 512 token, cắt bớt text đầu/cuối để tránh lỗi
                result = self.ai_phishing_detector(text[:2000], truncation=True, max_length=512)[0]
                label = result['label'].upper()
                ai_conf = result['score']
                
                if label == 'LABEL_1' or 'PHISH' in label or 'SCAM' in label or 'SOCIAL' in label:
                    ai_score = int(ai_conf * 100)
                    reasons.append(f"AI Model detected phishing/social engineering with {ai_score}% confidence.")
            except Exception:
                pass

        # 2. Phân tích bằng Luật (Rule-based) như cũ
        urgent_hits = self._pattern_hits(text, URGENT_PATTERNS)
        credential_hits = self._pattern_hits(text, CREDENTIAL_PATTERNS)
        money_hits = self._pattern_hits(text, MONEY_PATTERNS)

        rule_score = 0
        if urgent_hits:
            rule_score += min(35, 8 * len(urgent_hits))
            reasons.append("Email uses urgent or pressure language commonly seen in phishing.")
        if credential_hits:
            rule_score += min(35, 10 * len(credential_hits))
            reasons.append("Email asks for or references credentials such as password, OTP, or login.")
        if money_hits:
            rule_score += min(25, 7 * len(money_hits))
            reasons.append("Email contains payment, invoice, refund, or bank-transfer language.")
        if urgent_hits and credential_hits:
            rule_score += 15
            reasons.append("Urgency is combined with credential-related wording.")
        if urgent_hits and money_hits:
            rule_score += 10
            reasons.append("Urgency is combined with payment-related wording.")

        # Hợp nhất: Lấy điểm cao nhất giữa AI dự đoán và Luật
        final_score = max(rule_score, ai_score)
        return min(final_score, 100), reasons

    def _score_malware(
        self,
        text: str,
        risky_files: List[str],
        urls: List[Dict[str, object]],
    ) -> tuple[int, List[str]]:
        score = 0
        reasons = []

        if risky_files:
            score += min(55, 20 * len(risky_files))
            reasons.append(f"Email mentions risky attachment or download names: {', '.join(risky_files)}.")

        if any(self._url_points_to_risky_file(url["final_url"]) for url in urls):
            score += 35
            reasons.append("At least one link appears to download an executable or script file.")

        if re.search(r"\b(enable macros|enable content|disable antivirus|turn off antivirus)\b", text):
            score += 35
            reasons.append("Email asks the user to enable macros/content or disable protection.")

        if re.search(r"b[aậ]t macro|t[aắ]t antivirus|t[aắ]t ph[aầ]n m[eề]m di[eệ]t virus", text):
            score += 35
            reasons.append("Email asks the user to enable macros or disable antivirus in Vietnamese.")

        return min(score, 100), reasons

    def _score_fake_links(self, urls: List[Dict[str, object]]) -> tuple[int, List[str]]:
        if not urls:
            return 0, []

        max_url_score = max(int(url["risk_score"]) for url in urls)
        reasons = []

        suspicious_urls = [url for url in urls if int(url["risk_score"]) >= 35]
        if suspicious_urls:
            reasons.append(f"Detected {len(suspicious_urls)} suspicious link(s) in the email.")

        for url in suspicious_urls[:3]:
            for reason in url["reasons"][:2]:
                reasons.append(f"Link `{url['domain'] or url['url']}`: {reason}")

        return min(100, max_url_score), reasons

    def _combo_bonus(self, phishing_score: int, malware_score: int, fake_link_score: int) -> int:
        active = sum(score >= 35 for score in (phishing_score, malware_score, fake_link_score))
        if active >= 3:
            return 20
        if active == 2:
            return 12
        return 0

    def _verdict(self, risk_score: int, phishing_score: int, malware_score: int, fake_link_score: int) -> str:
        if risk_score < 35:
            return "LOW_RISK_EMAIL"
        if malware_score >= max(phishing_score, fake_link_score) and malware_score >= 60:
            return "MALWARE_RISK_EMAIL"
        if fake_link_score >= max(phishing_score, malware_score) and fake_link_score >= 60:
            return "FAKE_LINK_PHISHING"
        if phishing_score >= 60:
            return "PHISHING_EMAIL"
        return "SUSPICIOUS_EMAIL"

    def _risk_level(self, score: int) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 35:
            return "Medium"
        return "Low"

    def _pattern_hits(self, text: str, patterns: List[str]) -> List[str]:
        return [pattern for pattern in patterns if re.search(pattern, text, re.IGNORECASE)]

    def _url_points_to_risky_file(self, url: str) -> bool:
        return bool(re.search(r"\.(exe|scr|bat|cmd|js|vbs|msi|apk|jar|ps1|lnk)(\?|#|$)", url.lower()))

    def _dedupe(self, values: List[str]) -> List[str]:
        seen = set()
        result = []
        for value in values:
            if value not in seen:
                seen.add(value)
                result.append(value)
        return result
