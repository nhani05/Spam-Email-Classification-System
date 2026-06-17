import importlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


MODULES = [
    "app",
    "src.app",
    "src.auth.auth",
    "src.components.dashboard",
    "src.components.data_ingestion",
    "src.components.data_transformation",
    "src.components.model_lab",
    "src.components.model_training",
    "src.config.config",
    "src.core",
    "src.data",
    "src.database.db",
    "src.ml",
    "src.ml.model_lab",
    "src.ml.spam_classifier",
    "src.ml.threat_classifier",
    "src.ml.url_classifier",
    "src.persistence",
    "src.pipeline.prediction_pipeline",
    "src.pipeline.training_pipeline",
    "src.security",
    "src.security.ai_threat_model",
    "src.security.campaign_intelligence",
    "src.security.feature_extractor",
    "src.security.qr_image_analyzer",
    "src.security.url_risk_model",
    "src.utils.email_utils",
    "src.utils.logger",
    "src.workflows",
]


def main() -> None:
    failures = []
    for module_name in MODULES:
        try:
            importlib.import_module(module_name)
            print(f"ok {module_name}")
        except Exception as exc:
            failures.append((module_name, exc))
            print(f"fail {module_name}: {exc}")

    if failures:
        details = ", ".join(name for name, _ in failures)
        raise SystemExit(f"Import smoke failed for: {details}")


if __name__ == "__main__":
    main()
