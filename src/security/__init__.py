"""Security analysis modules for email threat detection."""

__all__ = [
    "EmailThreatAnalyzer",
    "QRImageAnalyzer",
    "RiskAggregator",
    "RiskAnalysisResult",
    "URLRiskModel",
]


def __getattr__(name: str):
    if name == "EmailThreatAnalyzer":
        from .email_threat_analyzer import EmailThreatAnalyzer

        return EmailThreatAnalyzer
    if name in {"RiskAggregator", "RiskAnalysisResult"}:
        from .risk_aggregator import RiskAggregator, RiskAnalysisResult

        return {"RiskAggregator": RiskAggregator, "RiskAnalysisResult": RiskAnalysisResult}[name]
    if name == "QRImageAnalyzer":
        from .qr_image_analyzer import QRImageAnalyzer

        return QRImageAnalyzer
    if name == "URLRiskModel":
        from .url_risk_model import URLRiskModel

        return URLRiskModel
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
