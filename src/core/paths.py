from dataclasses import dataclass
from pathlib import Path

from src.core.config import Config


@dataclass(frozen=True)
class ArtifactLayout:
    bundled_baseline_dir: Path
    current_runtime_dir: Path
    historical_runs_dir: Path
    spam_model_path: Path
    spam_feature_path: Path
    email_threat_model_path: Path
    url_phishing_model_path: Path


def artifact_layout(config: Config | None = None) -> ArtifactLayout:
    config = config or Config()
    return ArtifactLayout(
        bundled_baseline_dir=Path("data/models/v1"),
        current_runtime_dir=Path("outputs/ai-threat-current"),
        historical_runs_dir=Path(config.OUTPUT_BASE_DIR),
        spam_model_path=Path(config.model_path),
        spam_feature_path=Path(config.feature_path),
        email_threat_model_path=Path(config.ai_threat_model_path),
        url_phishing_model_path=Path(config.ai_url_model_path),
    )
