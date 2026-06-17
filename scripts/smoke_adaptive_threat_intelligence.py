import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.pipeline.prediction_pipeline import PredictionPipeline
from src.config.config import Config
from src.security.ai_threat_model import AIThreatModelService, train_ai_threat_models
from src.security.campaign_intelligence import CampaignIntelligenceEngine, CampaignSummary
from src.security.feature_extractor import EmailFeatureExtractor


def main() -> None:
    config = Config()
    metadata = train_ai_threat_models(
        email_dataset_path=config.ai_threat_email_data_path,
        url_dataset_path=config.ai_threat_url_data_path,
        output_base_dir=config.OUTPUT_BASE_DIR,
    )
    service = AIThreatModelService(
        email_model_path=metadata["artifact_paths"]["email_model_path"],
        url_model_path=metadata["artifact_paths"]["url_model_path"],
    )

    extractor = EmailFeatureExtractor()
    extractor.url_model.ai_service = service
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
    pipeline.ai_threat_service = service
    pipeline.feature_extractor.url_model.ai_service = service
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
