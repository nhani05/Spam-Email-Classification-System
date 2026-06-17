import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.pipeline.prediction_pipeline import PredictionPipeline
from src.security.campaign_intelligence import CampaignIntelligenceEngine, CampaignSummary
from src.security.feature_extractor import EmailFeatureExtractor


def main() -> None:
    extractor = EmailFeatureExtractor()
    feature_record = extractor.from_text(
        "URGENT verify your account at http://fake-bank-login.xyz/reset and open invoice.pdf.exe",
        subject="Bank verification",
        sender="Security <alerts@fake-bank-login.xyz>",
        reply_to="help@fake-bank-login.xyz",
        timestamp="Mon, 01 Jan 2024 10:00:00 +0000",
        qr_payloads=["000201010212A000000727"],
    )
    assert feature_record.urls, "URL indicators should be extracted"
    assert feature_record.risky_files, "Risky attachment indicators should be extracted"
    assert feature_record.qr_payloads, "QR payload features should be attached"

    pipeline = PredictionPipeline()
    single = pipeline.predict_single_email(
        "URGENT verify your PayPal password at http://paypa1-login.xyz/reset"
    )
    for key in ("prediction", "confidence", "risk_score", "risk_level", "verdict"):
        assert key in single, f"missing legacy field: {key}"
    for key in ("threat_label", "class_scores", "indicators", "feature_record"):
        assert key in single, f"missing adaptive field: {key}"

    rows = [
        {
            "Body": "URGENT verify account http://fake-bank-login.xyz/a",
            "Subject": "Verify bank",
            "Time": "Mon, 01 Jan 2024 10:00:00 +0000",
        },
        {
            "Body": "Please verify account http://fake-bank-login.xyz/b",
            "Subject": "Bank verify",
            "Time": "Mon, 01 Jan 2024 11:00:00 +0000",
        },
        {
            "Body": "Team meeting tomorrow",
            "Subject": "Meeting",
            "Time": "Mon, 01 Jan 2024 12:00:00 +0000",
        },
    ]
    batch = pipeline.run_prediction(rows)
    assert batch[0]["Campaign ID"] == batch[1]["Campaign ID"], "related phishing emails should share a campaign"
    assert pipeline.last_campaigns, "campaign summaries should be generated"

    engine = CampaignIntelligenceEngine()
    campaign = CampaignSummary(**pipeline.last_campaigns[0])
    graph = engine.graph_for_campaign(campaign, batch)
    report = engine.markdown_report(campaign, batch)
    assert graph["nodes"], "campaign graph should contain nodes"
    assert "Threat Intelligence Report" in report
    print("adaptive threat intelligence smoke passed")


if __name__ == "__main__":
    main()
