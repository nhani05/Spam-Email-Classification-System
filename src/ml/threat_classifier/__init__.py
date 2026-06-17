"""Email threat classifier training and inference modules."""

from src.ml.threat_classifier.service import AIModelPrediction, AIThreatModelService
from src.ml.threat_classifier.training import build_canonical_datasets, train_ai_threat_models
from src.ml.threat_classifier.schema import ARTIFACT_SCHEMA_VERSION

__all__ = [
    "AIModelPrediction",
    "AIThreatModelService",
    "ARTIFACT_SCHEMA_VERSION",
    "build_canonical_datasets",
    "train_ai_threat_models",
]
