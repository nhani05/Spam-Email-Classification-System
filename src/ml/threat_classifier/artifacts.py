from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable

import pandas as pd

from src.ml.threat_classifier.schema import ARTIFACT_SCHEMA_VERSION, FIXTURE_SOURCE_PREFIXES, PublishGateConfig


def is_seed_only_dataset(frame: pd.DataFrame) -> bool:
    if frame.empty or "source" not in frame.columns:
        return True
    sources = {str(item).strip().lower() for item in frame["source"].dropna().unique()}
    return bool(sources) and all(_is_fixture_source(source) for source in sources)


def assert_not_seed_only(frame: pd.DataFrame, fixture_mode: bool = False) -> None:
    if fixture_mode:
        return
    if is_seed_only_dataset(frame):
        raise ValueError(
            "Production AI threat training requires external or reviewed data. "
            "Seed/fixture-only datasets are allowed only with explicit fixture mode."
        )


def stamp_bundle_metadata(bundle: Dict[str, object], metadata: Dict[str, object]) -> Dict[str, object]:
    model_metadata = dict(bundle.get("metadata", {}))
    model_metadata.update(metadata)
    model_metadata.setdefault("artifact_schema_version", ARTIFACT_SCHEMA_VERSION)
    bundle["metadata"] = model_metadata
    return bundle


def validate_model_bundle(bundle: Dict[str, object]) -> None:
    metadata = bundle.get("metadata", {}) if isinstance(bundle, dict) else {}
    schema_version = metadata.get("artifact_schema_version")
    if schema_version != ARTIFACT_SCHEMA_VERSION:
        raise ValueError(f"incompatible artifact schema version: {schema_version or 'missing'}")
    for key in ("model", "features", "labels", "metadata"):
        if key not in bundle:
            raise ValueError(f"missing artifact key: {key}")


def publish_gates_pass(metadata: Dict[str, object], gate: PublishGateConfig) -> Dict[str, object]:
    label_quality = metadata.get("label_quality", {}).get("email", {})
    label_counts = label_quality.get("label_counts", {})
    best_metrics = metadata.get("best_metrics", {})
    email_metrics = metadata.get("evaluation", {}).get("email", {})
    per_class = email_metrics.get("per_class", {}) if isinstance(email_metrics, dict) else {}
    source_counts = label_quality.get("source_counts", {})
    seed_only = all(_is_fixture_source(str(source).lower()) for source in source_counts) if source_counts else True
    failures = []
    if sum(int(value) for value in label_counts.values()) < gate.min_total_rows:
        failures.append("min_total_rows")
    for label in gate.required_labels:
        if int(label_counts.get(label, 0)) < gate.min_per_class:
            failures.append(f"min_per_class:{label}")
    if float(best_metrics.get("email_macro_f1") or 0.0) < gate.min_macro_f1:
        failures.append("min_macro_f1")
    for label in gate.required_labels:
        recall = per_class.get(label, {}).get("recall") if isinstance(per_class.get(label, {}), dict) else None
        if recall is not None and float(recall) < gate.min_required_recall:
            failures.append(f"min_required_recall:{label}")
    if seed_only and not gate.allow_publish_from_fixture:
        failures.append("seed_only_dataset")
    return {"passed": not failures, "failures": failures}


def publish_artifacts(metadata: Dict[str, object], email_target: str, url_target: str, marker_path: str, gate: PublishGateConfig) -> Dict[str, object]:
    gate_result = publish_gates_pass(metadata, gate)
    if not gate_result["passed"]:
        return {"published": False, **gate_result}

    email_target_path = Path(email_target)
    url_target_path = Path(url_target)
    email_target_path.parent.mkdir(parents=True, exist_ok=True)
    url_target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(metadata["artifact_paths"]["email_model_path"], email_target_path)
    shutil.copy2(metadata["artifact_paths"]["url_model_path"], url_target_path)
    marker = {
        "published": True,
        "published_at": datetime.utcnow().isoformat(timespec="seconds"),
        "run_id": metadata.get("run_id"),
        "dataset_identity": metadata.get("dataset_identity", {}),
        "artifact_paths": {
            "email_model_path": str(email_target_path),
            "url_model_path": str(url_target_path),
            "source_email_model_path": metadata["artifact_paths"]["email_model_path"],
            "source_url_model_path": metadata["artifact_paths"]["url_model_path"],
        },
        "gate": gate_result,
    }
    marker_file = Path(marker_path)
    marker_file.parent.mkdir(parents=True, exist_ok=True)
    marker_file.write_text(json.dumps(marker, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"published": True, **gate_result, "marker_path": str(marker_file)}


def source_counts(frame: pd.DataFrame) -> Dict[str, int]:
    if "source" not in frame.columns:
        return {}
    return {str(key): int(value) for key, value in frame["source"].value_counts().to_dict().items()}


def weak_label_count(frame: pd.DataFrame) -> int:
    if "is_weak_label" not in frame.columns:
        return 0
    return int(frame["is_weak_label"].astype(bool).sum())


def _is_fixture_source(source: str) -> bool:
    return (
        any(source.startswith(prefix) for prefix in FIXTURE_SOURCE_PREFIXES)
        or "seed" in source
        or "fixture" in source
        or source.startswith("synthetic")
    )
