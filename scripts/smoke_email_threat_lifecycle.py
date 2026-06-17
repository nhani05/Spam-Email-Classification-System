import json
import mailbox
import sys
import tempfile
from email.message import EmailMessage
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config.config import Config
from src.ml.threat_classifier import AIThreatModelService, train_ai_threat_models
from src.ml.threat_classifier.artifacts import publish_gates_pass
from src.ml.threat_classifier.lifecycle import build_canonical_datasets
from src.ml.threat_classifier.schema import DatasetSourceConfig, PublishGateConfig, ThreatDataLayout


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        phishfuzzer_path = root / "phishfuzzer.json"
        phishfuzzer_path.write_text(
            json.dumps([
                {
                    "subject": "Verify account",
                    "body": "Verify your password at http://paypa1-login.xyz/reset",
                    "sender": "alerts@paypa1-login.xyz",
                    "type": "Phishing",
                    "url": "http://paypa1-login.xyz/reset",
                    "File": "",
                    "Motivation": "credential theft",
                },
                {
                    "subject": "Team meeting",
                    "body": "The project meeting is at 10 AM.",
                    "sender": "manager@example.com",
                    "type": "Safe",
                },
            ]),
            encoding="utf-8",
        )

        mbox_path = root / "nazario.mbox"
        box = mailbox.mbox(mbox_path)
        msg = EmailMessage()
        msg["Subject"] = "Password reset required"
        msg["From"] = "security@fake-bank.example"
        msg.set_content("Reset password at http://fake-bank-login.xyz")
        box.add(msg)
        box.flush()
        box.close()

        spam_dir = root / "spam"
        spam_dir.mkdir()
        spam_msg = EmailMessage()
        spam_msg["Subject"] = "Cheap meds"
        spam_msg["From"] = "sales@spam.example"
        spam_msg.set_content("Buy cheap meds now")
        (spam_dir / "spam.eml").write_bytes(spam_msg.as_bytes())

        phishtank_path = root / "phishtank.csv"
        pd.DataFrame([{"url": "http://fake-bank-login.xyz"}]).to_csv(phishtank_path, index=False)
        feedback_path = root / "feedback.csv"
        pd.DataFrame([{
            "review_id": 1,
            "status": "approved",
            "approved_label": "Credential Theft",
            "normalized_text": "Your OTP is required at http://otp-login.example",
            "reviewed_at": "2026-01-01 00:00:00",
        }]).to_csv(feedback_path, index=False)

        layout = ThreatDataLayout.from_base(str(root / "ai_threat"))
        outputs = build_canonical_datasets(
            DatasetSourceConfig(
                phishfuzzer_json_paths=[str(phishfuzzer_path)],
                nazario_mbox_paths=[str(mbox_path)],
                spamassassin_paths=[str(spam_dir)],
                phishtank_paths=[str(phishtank_path)],
                reviewed_feedback_paths=[str(feedback_path)],
            ),
            layout,
        )
        email_df = pd.read_csv(outputs["email_dataset_path"])
        url_df = pd.read_csv(outputs["url_dataset_path"])
        assert not email_df.empty, "canonical email dataset should have rows"
        assert not url_df.empty, "canonical URL dataset should have rows"
        assert "reviewed_feedback" in set(email_df["source"]), "reviewed feedback should be merged"

        config = Config()
        try:
            train_ai_threat_models(
                email_dataset_path=config.ai_threat_email_fixture_path,
                url_dataset_path=config.ai_threat_url_fixture_path,
                output_base_dir=str(root / "outputs"),
            )
            raise AssertionError("seed-only production training should be rejected")
        except ValueError as exc:
            assert "Seed/fixture-only" in str(exc)

        metadata = train_ai_threat_models(
            email_dataset_path=config.ai_threat_email_fixture_path,
            url_dataset_path=config.ai_threat_url_fixture_path,
            output_base_dir=str(root / "outputs"),
            fixture_mode=True,
        )
        service = AIThreatModelService(
            email_model_path=metadata["artifact_paths"]["email_model_path"],
            url_model_path=metadata["artifact_paths"]["url_model_path"],
        )
        assert service.email_available, "fixture artifact should load after schema stamping"
        assert service.predict_email("Verify password at http://fake-login.example").available
        gate = publish_gates_pass(metadata, PublishGateConfig())
        assert not gate["passed"], "fixture artifacts should not pass production publish gates"
        assert "seed_only_dataset" in gate["failures"]

    print("email threat lifecycle smoke passed")


if __name__ == "__main__":
    main()
