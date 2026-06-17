import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config.config import Config
from src.ml.threat_classifier import AIThreatModelService, train_ai_threat_models
from src.workflows.prediction import PredictionPipeline
from src.security.url_risk_model import URLRiskModel


def main() -> None:
    config = Config()
    metadata = train_ai_threat_models(
        email_dataset_path=config.ai_threat_email_fixture_path,
        url_dataset_path=config.ai_threat_url_fixture_path,
        output_base_dir=config.OUTPUT_BASE_DIR,
        fixture_mode=True,
    )
    service = AIThreatModelService(
        email_model_path=metadata["artifact_paths"]["email_model_path"],
        url_model_path=metadata["artifact_paths"]["url_model_path"],
    )

    email_result = service.predict_email(
        "URGENT verify your PayPal password at http://paypa1-login.xyz/reset",
        subject="Account verification",
        sender="alerts@paypal-security.example",
        reply_to="help@paypa1-login.xyz",
    )
    assert email_result.available, "email AI model should load"
    assert email_result.label != "Safe", f"expected a malicious threat label, got {email_result.label}"
    assert email_result.risk_score >= 35, "email AI model should produce elevated risk"

    url_result = service.predict_url("http://paypa1-login.xyz/verify")
    assert url_result is not None, "URL AI model should load"
    assert url_result["risk_score"] >= 35, "URL AI model should produce elevated risk"

    unavailable_pipeline = PredictionPipeline(load_models=False)
    unavailable_pipeline.ai_threat_service = AIThreatModelService()
    unavailable = unavailable_pipeline.predict_single_email(
        "URGENT verify your bank password at http://secure-bank-login.xyz/reset"
    )
    assert unavailable["model_provenance"]["risk_source"] == "model_unavailable"
    assert unavailable["verdict"] == "AI_MODEL_UNAVAILABLE"
    assert unavailable["risk_score"] == 0

    unavailable_url = URLRiskModel(ai_service=AIThreatModelService()).analyze("http://paypa1-login.xyz/verify")
    assert unavailable_url.verdict == "AI_URL_MODEL_UNAVAILABLE"
    assert unavailable_url.risk_level == "Unavailable"
    assert unavailable_url.risk_score == 0

    ai_pipeline = PredictionPipeline(load_models=False)
    ai_pipeline.ai_threat_service = service
    ai_result = ai_pipeline.predict_single_email(
        "URGENT verify your bank password at http://secure-bank-login.xyz/reset"
    )
    assert ai_result["model_provenance"]["risk_source"] == "ai_model"
    print("ai threat model smoke passed")


if __name__ == "__main__":
    main()
