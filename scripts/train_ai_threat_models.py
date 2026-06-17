import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config.config import Config
from src.ml.threat_classifier.schema import DatasetSourceConfig, PublishGateConfig, ThreatDataLayout
from src.ml.threat_classifier.training import build_canonical_datasets, train_ai_threat_models


def main() -> None:
    parser = argparse.ArgumentParser(description="Build, train, evaluate, and optionally publish AI threat models.")
    parser.add_argument("--force", action="store_true", help="Retrain even when configured model artifacts already exist.")
    parser.add_argument("--stage", choices=["import", "train", "all"], default="train")
    parser.add_argument("--fixture-mode", action="store_true", help="Allow tiny seed/fixture CSVs for smoke checks. Never publishes by default.")
    parser.add_argument("--publish", action="store_true", help="Publish passing artifacts to configured current runtime paths.")
    parser.add_argument("--include-weak-labels", action="store_true", help="Include weak/generated/synthetic labels in primary training and evaluation.")
    parser.add_argument("--email-dataset", default="", help="Canonical email dataset CSV. Defaults to Config.ai_threat_email_data_path.")
    parser.add_argument("--url-dataset", default="", help="Canonical URL dataset CSV. Defaults to Config.ai_threat_url_data_path.")
    parser.add_argument("--extra-email-dataset", action="append", default=[], help="Additional canonical/reviewed email CSV to merge.")
    parser.add_argument("--reviewed-feedback", action="append", default=[], help="Approved feedback export CSV/JSON to merge into retraining.")
    parser.add_argument("--phishfuzzer-json", action="append", default=[], help="Local PhishFuzzer JSON file.")
    parser.add_argument("--nazario-mbox", action="append", default=[], help="Local Nazario phishing mbox file.")
    parser.add_argument("--spamassassin-path", action="append", default=[], help="Local SpamAssassin corpus file/folder.")
    parser.add_argument("--enron-maildir", action="append", default=[], help="Local Enron maildir file/folder.")
    parser.add_argument("--phishtank-path", action="append", default=[], help="Local PhishTank CSV/JSON export.")
    parser.add_argument("--urlhaus-path", action="append", default=[], help="Local URLhaus CSV/TXT export.")
    args = parser.parse_args()

    config = Config()
    email_model = Path(config.ai_threat_model_path)
    url_model = Path(config.ai_url_model_path)
    if args.stage == "train" and email_model.exists() and url_model.exists() and not args.force and not args.publish:
        print("ai threat model artifacts already exist; skipping training")
        print(f"email_model_path={email_model}")
        print(f"url_model_path={url_model}")
        print("Use --force to retrain and replace the configured artifacts.")
        return

    layout = ThreatDataLayout.from_base(config.ai_threat_data_base_dir)
    source_config = DatasetSourceConfig(
        phishfuzzer_json_paths=args.phishfuzzer_json,
        nazario_mbox_paths=args.nazario_mbox,
        spamassassin_paths=args.spamassassin_path,
        enron_maildir_paths=args.enron_maildir,
        phishtank_paths=args.phishtank_path,
        urlhaus_paths=args.urlhaus_path,
        reviewed_feedback_paths=args.reviewed_feedback,
    )
    if args.stage in {"import", "all"}:
        outputs = build_canonical_datasets(source_config, layout)
        print("canonical dataset build complete")
        print(f"dataset_version={outputs['dataset_version']}")
        print(f"email_dataset_path={outputs['email_dataset_path']}")
        print(f"url_dataset_path={outputs['url_dataset_path']}")
        print(f"source_manifest_path={outputs['source_manifest_path']}")
        if args.stage == "import":
            return

    email_dataset_path = args.email_dataset or (config.ai_threat_email_fixture_path if args.fixture_mode else config.ai_threat_email_data_path)
    url_dataset_path = args.url_dataset or (config.ai_threat_url_fixture_path if args.fixture_mode else config.ai_threat_url_data_path)
    metadata = train_ai_threat_models(
        email_dataset_path=email_dataset_path,
        url_dataset_path=url_dataset_path,
        output_base_dir=config.OUTPUT_BASE_DIR,
        extra_email_dataset_paths=args.extra_email_dataset,
        reviewed_feedback_paths=args.reviewed_feedback,
        fixture_mode=args.fixture_mode,
        publish=args.publish and not args.fixture_mode,
        publish_email_model_path=config.ai_threat_model_path,
        publish_url_model_path=config.ai_url_model_path,
        publish_marker_path=config.ai_threat_published_run_path,
        include_weak_labels=args.include_weak_labels,
        publish_gate=PublishGateConfig(
            min_total_rows=config.ai_threat_publish_min_total_rows,
            min_per_class=config.ai_threat_publish_min_per_class,
            min_macro_f1=config.ai_threat_publish_min_macro_f1,
            min_required_recall=config.ai_threat_publish_min_required_recall,
        ),
    )
    if args.fixture_mode:
        print("fixture-mode training complete; artifacts were not published as production-current models")
    elif args.publish:
        print(f"publish_gate={metadata.get('publish_gate')}")
    else:
        print("training complete; use --publish to copy passing artifacts to current runtime paths")
    print("ai threat model training complete")
    print(f"run_id={metadata['run_id']}")
    print(f"email_model_path={email_model}")
    print(f"url_model_path={url_model}")
    print(f"archived_email_model_path={metadata['artifact_paths']['email_model_path']}")
    print(f"archived_url_model_path={metadata['artifact_paths']['url_model_path']}")


if __name__ == "__main__":
    main()
