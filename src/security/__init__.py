"""Security analysis modules for email threat detection."""

__all__ = [
    "CampaignIntelligenceEngine",
    "AIThreatModelService",
    "EmailFeatureExtractor",
    "EmailFeatureRecord",
    "EmailThreatAnalyzer",
    "QRImageAnalyzer",
    "URLRiskModel",
]


def __getattr__(name: str):
    if name == "AIThreatModelService":
        from .ai_threat_model import AIThreatModelService

        return AIThreatModelService
    if name == "EmailThreatAnalyzer":
        from .email_threat_analyzer import EmailThreatAnalyzer

        return EmailThreatAnalyzer
    if name in {"EmailFeatureExtractor", "EmailFeatureRecord"}:
        from .feature_extractor import EmailFeatureExtractor, EmailFeatureRecord

        return {"EmailFeatureExtractor": EmailFeatureExtractor, "EmailFeatureRecord": EmailFeatureRecord}[name]
    if name == "CampaignIntelligenceEngine":
        from .campaign_intelligence import CampaignIntelligenceEngine

        return CampaignIntelligenceEngine
    if name == "QRImageAnalyzer":
        from .qr_image_analyzer import QRImageAnalyzer

        return QRImageAnalyzer
    if name == "URLRiskModel":
        from .url_risk_model import URLRiskModel

        return URLRiskModel
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
