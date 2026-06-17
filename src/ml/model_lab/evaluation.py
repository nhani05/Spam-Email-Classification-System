from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)


@dataclass
class ModelLabSummary:
    run_id: str
    model_name: str
    dataset_identity: str
    feature_config: str
    metrics: Dict[str, object]
    artifact_paths: Dict[str, str]

    def to_dict(self) -> Dict[str, object]:
        return {
            "run_id": self.run_id,
            "model_name": self.model_name,
            "dataset_identity": self.dataset_identity,
            "feature_config": self.feature_config,
            "metrics": self.metrics,
            "artifact_paths": self.artifact_paths,
        }


def dataset_identity(path: str) -> str:
    file_path = Path(path)
    if not file_path.exists():
        return f"{path}:missing"
    stat = file_path.stat()
    return f"{file_path.as_posix()}|size={stat.st_size}|mtime={int(stat.st_mtime)}"


def evaluate_predictions(
    y_true: Iterable[int],
    y_pred: Iterable[int],
    y_score: Optional[Iterable[float]] = None,
) -> Dict[str, object]:
    y_true = list(y_true)
    y_pred = list(y_pred)
    labels = sorted(set(y_true) | set(y_pred))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        zero_division=0,
    )
    report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    metrics: Dict[str, object] = {
        "labels": labels,
        "per_class": {
            str(label): {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
            }
            for index, label in enumerate(labels)
        },
        "macro_f1": float(report.get("macro avg", {}).get("f1-score", 0.0)),
        "weighted_f1": float(report.get("weighted avg", {}).get("f1-score", 0.0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "roc_auc": "unavailable",
        "pr_auc": "unavailable",
    }
    if y_score is not None and len(labels) == 2:
        scores = list(y_score)
        try:
            metrics["roc_auc"] = float(roc_auc_score(y_true, scores))
        except Exception:
            metrics["roc_auc"] = "unavailable"
        try:
            metrics["pr_auc"] = float(average_precision_score(y_true, scores))
        except Exception:
            metrics["pr_auc"] = "unavailable"
    return metrics


def threshold_report(
    y_true: Iterable[int],
    positive_scores: Iterable[float],
    thresholds: Iterable[float] = (0.35, 0.5, 0.65, 0.8),
) -> List[Dict[str, object]]:
    y_true = list(y_true)
    scores = list(positive_scores)
    rows = []
    for threshold in thresholds:
        predictions = [1 if score >= threshold else 0 for score in scores]
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true,
            predictions,
            average="binary",
            zero_division=0,
        )
        false_positive = sum(1 for truth, pred in zip(y_true, predictions) if truth == 0 and pred == 1)
        false_negative = sum(1 for truth, pred in zip(y_true, predictions) if truth == 1 and pred == 0)
        rows.append({
            "threshold": threshold,
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "false_positives": false_positive,
            "false_negatives": false_negative,
        })
    return rows


def error_analysis(
    texts: Iterable[str],
    y_true: Iterable[int],
    y_pred: Iterable[int],
    confidences: Optional[Iterable[float]] = None,
    indicators: Optional[Iterable[Dict[str, object]]] = None,
) -> Dict[str, List[Dict[str, object]]]:
    texts = list(texts)
    y_true = list(y_true)
    y_pred = list(y_pred)
    confidences = list(confidences or [None] * len(texts))
    indicators = list(indicators or [{} for _ in texts])
    result = {"false_positives": [], "false_negatives": [], "low_confidence": []}
    for index, text in enumerate(texts):
        row = {
            "index": index,
            "preview": str(text)[:180],
            "expected_label": y_true[index],
            "predicted_label": y_pred[index],
            "confidence": confidences[index],
            "indicators": indicators[index],
        }
        if y_true[index] == 0 and y_pred[index] == 1:
            result["false_positives"].append(row)
        if y_true[index] == 1 and y_pred[index] == 0:
            result["false_negatives"].append(row)
        if confidences[index] is not None and float(confidences[index]) < 60:
            result["low_confidence"].append(row)
    return result


def save_model_lab_artifacts(output_dir: str, metadata: Dict[str, object]) -> None:
    observations_dir = Path(output_dir) / "observations"
    observations_dir.mkdir(parents=True, exist_ok=True)
    with open(observations_dir / "model_lab_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False, default=str)


def discover_model_runs(outputs_dir: str = "outputs") -> pd.DataFrame:
    rows = []
    root = Path(outputs_dir)
    if not root.exists():
        return pd.DataFrame()
    for metadata_path in root.glob("*/observations/model_lab_metadata.json"):
        try:
            data = json.loads(metadata_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        rows.append({
            "run_id": metadata_path.parents[1].name,
            "model_name": data.get("best_model_name", ""),
            "dataset_identity": data.get("dataset_identity", ""),
            "feature_config": data.get("feature_config", ""),
            "macro_f1": data.get("best_metrics", {}).get("macro_f1", ""),
            "weighted_f1": data.get("best_metrics", {}).get("weighted_f1", ""),
            "path": str(metadata_path.parents[1]),
        })
    return pd.DataFrame(rows)
