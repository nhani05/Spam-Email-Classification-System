from src.persistence.legacy import (
    create_review_queue_item,
    export_retraining_data,
    get_review_queue,
    maybe_create_review_queue_item,
    save_prediction_feedback,
    update_review_queue_item,
)
from src.ml.threat_classifier.importers import reviewed_feedback_rows_to_canonical


def export_retraining_data_canonical() -> list:
    return reviewed_feedback_rows_to_canonical(export_retraining_data())

__all__ = [
    "create_review_queue_item",
    "export_retraining_data",
    "export_retraining_data_canonical",
    "get_review_queue",
    "maybe_create_review_queue_item",
    "save_prediction_feedback",
    "update_review_queue_item",
]
