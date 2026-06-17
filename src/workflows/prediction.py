import mailbox
import pickle
import time
import pandas as pd
from typing import Dict, List, Optional
from pathlib import Path

from src.utils.state import PredictionState
from src.utils.logger import get_logger
from src.config.config import Config
from src.utils.email_utils import extract_body, all_recipients, clean_text
from src.security.feature_extractor import EmailFeatureExtractor
from src.security.campaign_intelligence import CampaignIntelligenceEngine
from src.ml.threat_classifier.service import AIModelPrediction, AIThreatModelService

logger = get_logger(__name__)

class PredictionPipeline:
    def __init__(self, load_models: bool = True):
        self.config = Config()
        self.mailbox = None
        self.feature_transformer = None
        self.model = None
        self.feature_extractor = EmailFeatureExtractor()
        self.campaign_engine = CampaignIntelligenceEngine()
        self.ai_threat_service = AIThreatModelService(
            email_model_path=self.config.ai_threat_model_path,
            url_model_path=self.config.ai_url_model_path,
        )
        self.last_campaigns = []
        
        if load_models:
            self._load_models()
    
    def _load_models(self) -> None:

        logger.info("Loading binary spam/ham model | model=%s | vectorizer=%s", self.config.model_path, self.config.feature_path)
        self.feature_transformer = pickle.load(open(self.config.feature_path, "rb"))
        self.model = pickle.load(open(self.config.model_path, "rb"))
        logger.info("Binary spam/ham model loaded successfully")
    
    def predict_single_email(self, email_body: str) -> Dict:
        if self.model is None or self.feature_transformer is None:
            self._load_models()

        logger.info("Single email analysis started | chars=%s", len(email_body or ""))
        cleaned_body = clean_text(email_body)
        features = self.feature_transformer.transform([cleaned_body])
        prediction = self.model.predict(features)
        prediction_label = "Spam" if str(prediction[0]) == "0" else "Ham"
        
        try:
            prediction_proba = self.model.predict_proba(features)
            confidence = float(max(prediction_proba[0])) * 100
        except:
            confidence = None
        
        feature_record = self.feature_extractor.from_text(email_body)
        ai_prediction = self.ai_threat_service.predict_email(email_body)
        risk_payload = self._risk_payload_from_ai_prediction(ai_prediction, feature_record, confidence)
        model_provenance = self._model_provenance(ai_prediction)

        logger.info(
            "Single email analysis completed | binary=%s | confidence=%s | threat_label=%s | risk=%s | level=%s | source=%s",
            prediction_label,
            f"{confidence:.1f}" if confidence is not None else "unavailable",
            risk_payload["threat_label"],
            risk_payload["risk_score"],
            risk_payload["risk_level"],
            risk_payload["components"].get("risk_source", "model_unavailable"),
        )

        return {
            'prediction': prediction_label,
            'confidence': confidence,
            'raw_prediction': int(prediction[0]),
            'threat_label': risk_payload["threat_label"],
            'class_scores': risk_payload.get("class_scores", {}),
            'risk_score': risk_payload["risk_score"],
            'risk_level': risk_payload["risk_level"],
            'verdict': risk_payload["verdict"],
            'reasons': risk_payload["reasons"],
            'recommended_actions': risk_payload["recommended_actions"],
            'urls': risk_payload["urls"],
            'indicators': feature_record.indicators,
            'feature_record': feature_record.to_dict(),
            'threat_analysis': self._feature_evidence(feature_record),
            'threat_classification': {
                "threat_label": ai_prediction.label,
                "source": ai_prediction.source,
                "model_available": ai_prediction.available,
            },
            'risk_analysis': risk_payload,
            'ai_threat_analysis': ai_prediction.to_dict(),
            'model_provenance': model_provenance,
        }

    def _risk_payload_from_ai_prediction(
        self,
        ai_prediction: AIModelPrediction,
        feature_record,
        confidence: Optional[float],
    ) -> Dict:
        risk_source = "ai_model" if ai_prediction.available else "model_unavailable"
        return {
            "risk_score": ai_prediction.risk_score,
            "risk_level": ai_prediction.risk_level,
            "verdict": ai_prediction.verdict,
            "threat_label": ai_prediction.label,
            "class_scores": ai_prediction.class_scores,
            "reasons": list(ai_prediction.reasons),
            "recommended_actions": self._recommended_actions(ai_prediction),
            "urls": self._feature_value(feature_record, "urls", []),
            "components": {
                "ml_spam_score": round(float(confidence), 2) if confidence is not None else None,
                "ai_model_score": ai_prediction.risk_score if ai_prediction.available else None,
                "ai_model_label": ai_prediction.label if ai_prediction.available else None,
                "model_available": ai_prediction.available,
                "risk_source": risk_source,
            },
        }

    def _recommended_actions(self, ai_prediction: AIModelPrediction) -> List[str]:
        if not ai_prediction.available:
            return [
                "Train the AI threat model with scripts/train_ai_threat_models.py.",
                "Configure ai_threat_model_path and ai_url_model_path before demoing risk scoring.",
            ]
        if ai_prediction.risk_score >= 80:
            return ["Quarantine this email and review the model evidence before user interaction."]
        if ai_prediction.risk_score >= 35:
            return ["Review this email carefully before opening links or attachments."]
        return ["No high-risk AI threat signal was detected by the trained model."]

    def _model_provenance(self, ai_prediction: AIModelPrediction) -> Dict:
        risk_source = "ai_model" if ai_prediction.available else "model_unavailable"
        return {
            **ai_prediction.provenance,
            "model_available": ai_prediction.available,
            "risk_source": risk_source,
        }

    def _feature_evidence(self, feature_record) -> Dict:
        return {
            "urls": self._feature_value(feature_record, "urls", []),
            "risky_files": self._feature_value(feature_record, "risky_files", []),
            "suspicious_keywords": self._feature_value(feature_record, "suspicious_keywords", []),
            "indicators": self._feature_value(feature_record, "indicators", {}),
            "missing_fields": self._feature_value(feature_record, "missing_fields", []),
        }

    def _feature_value(self, feature_record, key: str, default):
        if isinstance(feature_record, dict):
            return feature_record.get(key, default)
        return getattr(feature_record, key, default)

    def load_mailbox(self, mailbox_path: str) -> None:
        """Load MBOX file"""

        logger.info(f"Loading mailbox from {mailbox_path}")
        self.mailbox = mailbox.mbox(mailbox_path)
        logger.info(f"Loaded mailbox from {mailbox_path}")

    def process_mailbox(self, mailbox_path: Optional[str] = None) -> List[Dict]:
        if mailbox_path:
            self.load_mailbox(mailbox_path)
        
        if self.mailbox is None:
            raise ValueError("No mailbox loaded. Call load_mailbox() first.")
        
        logger.info("Processing mailbox")
        data = []
        
        for message in self.mailbox:
            labels = (message.get("X-Gmail-Labels") or "").lower()
            category = (
                "Spam" if "spam" in labels else
                "Promotions" if "category_promotions" in labels else
                "Social" if "category_social" in labels else
                "Updates" if "category_updates" in labels else
                "Inbox"
            )
            time_str = message.get("Date", "")
            feature_record = self.feature_extractor.from_message(message)
            recipients = clean_text(feature_record.recipients)
            subject = feature_record.subject
            body = feature_record.body
            direction = feature_record.direction
            
            data.append({
                "Time": time_str,
                "Sender": feature_record.sender,
                "Sender Domain": feature_record.sender_domain,
                "Reply-To": feature_record.reply_to,
                "Reply-To Domain": feature_record.reply_to_domain,
                "Recipients": recipients,
                "Subject": subject,
                "Body": body,
                "Category": category,
                "Direction": direction,
                "Indicators": feature_record.indicators,
                "Feature Record": feature_record.to_dict(),
            })
        
        logger.info(f"Processed {len(data)} emails from mailbox")
        self.mailbox.close()
        
        return data
    
    def run_prediction(self, mail_data: List[Dict]) -> List[Dict]:
        if self.model is None or self.feature_transformer is None:
            self._load_models()
        
        start_time = time.time()
        logger.info("Running batch predictions | emails=%s", len(mail_data))
        
        for mail in mail_data:
            body_text = mail.get('Body', '')
            features = self.feature_transformer.transform([body_text])
            prediction = self.model.predict(features)
            prediction_label = "Spam" if str(prediction[0]) == "0" else "Ham"

            try:
                prediction_proba = self.model.predict_proba(features)
                confidence = float(max(prediction_proba[0])) * 100
            except:
                confidence = None

            feature_record = mail.get("Feature Record") or self.feature_extractor.from_text(
                email_text=body_text,
                subject=mail.get("Subject", ""),
                sender=mail.get("Sender", ""),
                recipients=mail.get("Recipients", ""),
                reply_to=mail.get("Reply-To", ""),
                timestamp=mail.get("Time", ""),
            ).to_dict()
            ai_prediction = self.ai_threat_service.predict_email(
                body_text,
                subject=mail.get("Subject", ""),
                sender=mail.get("Sender", ""),
                reply_to=mail.get("Reply-To", ""),
            )
            risk_payload = self._risk_payload_from_ai_prediction(
                ai_prediction,
                feature_record,
                confidence,
            )

            mail["Prediction"] = prediction_label
            mail["Confidence"] = confidence
            mail["Threat Label"] = risk_payload["threat_label"]
            mail["Class Scores"] = risk_payload.get("class_scores", {})
            mail["Risk Score"] = risk_payload["risk_score"]
            mail["Risk Level"] = risk_payload["risk_level"]
            mail["Verdict"] = risk_payload["verdict"]
            mail["Reasons"] = " | ".join(risk_payload["reasons"])
            mail["Recommended Actions"] = " | ".join(risk_payload["recommended_actions"])
            mail["URLs"] = risk_payload["urls"]
            mail["Indicators"] = feature_record.get("indicators", mail.get("Indicators", {}))
            mail["Risk Source"] = risk_payload["components"].get("risk_source", "model_unavailable")
            mail["Model Provenance"] = self._model_provenance(ai_prediction)
            logger.info(
                "Batch email scored | subject=%s | binary=%s | threat_label=%s | risk=%s | source=%s",
                str(mail.get("Subject", ""))[:60],
                prediction_label,
                mail["Threat Label"],
                mail["Risk Score"],
                mail["Risk Source"],
            )
        
        campaigns = self.campaign_engine.cluster(mail_data)
        self.campaign_engine.assign_campaign_ids(mail_data, campaigns)
        for mail in mail_data:
            mail.setdefault("Campaign ID", "")
            mail.setdefault("Campaign Risk", "")
        self.last_campaigns = [campaign.to_dict() for campaign in campaigns]

        end_time = time.time()
        logger.info(
            "Batch prediction completed | emails=%s | campaigns=%s | elapsed=%.2fs",
            len(mail_data),
            len(self.last_campaigns),
            end_time - start_time,
        )
        
        return mail_data
    
    def predict_mbox_file(self, mailbox_path: str, output_path: Optional[str] = None) -> pd.DataFrame:
        mail_data = self.process_mailbox(mailbox_path)
        mail_data = self.run_prediction(mail_data)
        df = pd.DataFrame(mail_data)
        df.attrs["campaigns"] = self.last_campaigns
        if output_path:
            df.to_csv(output_path, index=False)
            logger.info(f"Predictions saved to {output_path}")
        return df


def run_legacy_pipeline(state: PredictionState) -> None:
    pipeline = PredictionPipeline(load_models=False)
    pipeline.load_mailbox(state.mailbox_path)
    mail_data = pipeline.process_mailbox()
    state.mail_data = mail_data
    state.mail_data = pipeline.run_prediction(state.mail_data)
    df = pd.DataFrame(state.mail_data)
    df.to_csv("data/predictions.csv", index=False)
