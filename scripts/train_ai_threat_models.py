import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config.config import Config
from src.security.ai_threat_model import train_ai_threat_models


def main() -> None:
    config = Config()
    metadata = train_ai_threat_models(
        email_dataset_path=config.ai_threat_email_data_path,
        url_dataset_path=config.ai_threat_url_data_path,
        output_base_dir=config.OUTPUT_BASE_DIR,
    )
    print("ai threat model training complete")
    print(f"run_id={metadata['run_id']}")
    print(f"email_model_path={metadata['artifact_paths']['email_model_path']}")
    print(f"url_model_path={metadata['artifact_paths']['url_model_path']}")


if __name__ == "__main__":
    main()
