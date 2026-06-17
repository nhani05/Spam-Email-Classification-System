"""Application workflow orchestration for prediction and training."""

from src.workflows.prediction import PredictionPipeline, run_legacy_pipeline
from src.workflows.training import TrainingPipeline

__all__ = ["PredictionPipeline", "TrainingPipeline", "run_legacy_pipeline"]
