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
from src.security.email_threat_analyzer import EmailThreatAnalyzer
from src.security.risk_aggregator import RiskAggregator
from src.security.feature_extractor import EmailFeatureExtractor
from src.security.threat_taxonomy import ThreatTaxonomyClassifier
from src.security.campaign_intelligence import CampaignIntelligenceEngine

logger = get_logger(__name__)

class PredictionPipeline:
    def __init__(self, load_models: bool = True):
        self.config = Config()
        self.mailbox = None
        self.feature_transformer = None
        self.model = None
        self.threat_analyzer = EmailThreatAnalyzer()
        self.risk_aggregator = RiskAggregator()
        self.feature_extractor = EmailFeatureExtractor()
        self.taxonomy = ThreatTaxonomyClassifier()
        self.campaign_engine = CampaignIntelligenceEngine()
        self.last_campaigns = []
        
        if load_models:
            self._load_models()
    
    def _load_models(self) -> None:

        logger.info("Loading models...")
        self.feature_transformer = pickle.load(open(self.config.feature_path, "rb"))
        self.model = pickle.load(open(self.config.model_path, "rb"))
        logger.info("Models loaded successfully")
    
    def predict_single_email(self, email_body: str) -> Dict:
        if self.model is None or self.feature_transformer is None:
            self._load_models()

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
        threat_result = self.threat_analyzer.analyze(email_body)
        threat_classification = self.taxonomy.classify(
            prediction=prediction_label,
            confidence=confidence,
            threat_result=threat_result,
            qr_results=feature_record.qr_payloads,
        )
        risk_result = self.risk_aggregator.aggregate_email(
            prediction=prediction_label,
            confidence=confidence,
            threat_result=threat_result,
            threat_classification=threat_classification,
        )

        return {
            'prediction': prediction_label,
            'confidence': confidence,
            'raw_prediction': int(prediction[0]),
            'threat_label': risk_result.threat_label,
            'class_scores': risk_result.class_scores,
            'risk_score': risk_result.risk_score,
            'risk_level': risk_result.risk_level,
            'verdict': risk_result.verdict,
            'reasons': risk_result.reasons,
            'recommended_actions': risk_result.recommended_actions,
            'urls': risk_result.urls,
            'indicators': feature_record.indicators,
            'feature_record': feature_record.to_dict(),
            'threat_analysis': threat_result.to_dict(),
            'threat_classification': threat_classification.to_dict(),
            'risk_analysis': risk_result.to_dict(),
        }

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
        logger.info("Running predictions")
        
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

            threat_result = self.threat_analyzer.analyze(body_text)
            feature_record = mail.get("Feature Record") or self.feature_extractor.from_text(
                email_text=body_text,
                subject=mail.get("Subject", ""),
                sender=mail.get("Sender", ""),
                recipients=mail.get("Recipients", ""),
                reply_to=mail.get("Reply-To", ""),
                timestamp=mail.get("Time", ""),
            ).to_dict()
            threat_classification = self.taxonomy.classify(
                prediction=prediction_label,
                confidence=confidence,
                threat_result=threat_result,
                qr_results=feature_record.get("qr_payloads", []),
            )
            risk_result = self.risk_aggregator.aggregate_email(
                prediction=prediction_label,
                confidence=confidence,
                threat_result=threat_result,
                threat_classification=threat_classification,
            )

            mail["Prediction"] = prediction_label
            mail["Confidence"] = confidence
            mail["Threat Label"] = risk_result.threat_label
            mail["Class Scores"] = risk_result.class_scores
            mail["Risk Score"] = risk_result.risk_score
            mail["Risk Level"] = risk_result.risk_level
            mail["Verdict"] = risk_result.verdict
            mail["Reasons"] = " | ".join(risk_result.reasons)
            mail["Recommended Actions"] = " | ".join(risk_result.recommended_actions)
            mail["URLs"] = risk_result.urls
            mail["Indicators"] = feature_record.get("indicators", mail.get("Indicators", {}))
        
        campaigns = self.campaign_engine.cluster(mail_data)
        self.campaign_engine.assign_campaign_ids(mail_data, campaigns)
        for mail in mail_data:
            mail.setdefault("Campaign ID", "")
            mail.setdefault("Campaign Risk", "")
        self.last_campaigns = [campaign.to_dict() for campaign in campaigns]

        end_time = time.time()
        logger.info(f"Prediction completed in {end_time - start_time:.2f} seconds")
        
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
