from __future__ import annotations

import json
import pickle
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import pandas as pd

from src.ml.threat_classifier.artifacts import assert_not_seed_only, publish_artifacts, stamp_bundle_metadata
from src.ml.threat_classifier.canonical import (
    normalize_email_records,
    normalize_url_records,
    save_canonical_outputs,
    to_legacy_email_training_frame,
    to_legacy_url_training_frame,
)
from src.ml.threat_classifier.importers import (
    file_manifest,
    import_enron_maildir,
    import_mbox_corpus,
    import_phishfuzzer_json,
    import_phishtank_urls,
    import_spamassassin_path,
    import_urlhaus_urls,
    read_feedback_export,
    reviewed_feedback_rows_to_canonical,
    url_records_to_email_enrichment,
    write_source_manifest,
)
from src.ml.threat_classifier.legacy import train_ai_threat_models as _legacy_train_ai_threat_models
from src.ml.threat_classifier.schema import ARTIFACT_SCHEMA_VERSION, DatasetSourceConfig, PublishGateConfig, ThreatDataLayout


def build_canonical_datasets(
    sources: DatasetSourceConfig,
    layout: ThreatDataLayout,
    dataset_version: Optional[str] = None,
    enrich_email_from_url_sources: bool = True,
) -> Dict[str, object]:
    layout.ensure()
    dataset_version = dataset_version or datetime.utcnow().strftime("%Y%m%d%H%M%S")
    email_records: List[Dict[str, object]] = []
    url_records: List[Dict[str, object]] = []
    manifests: List[Dict[str, object]] = []

    for path in sources.phishfuzzer_json_paths:
        rows = import_phishfuzzer_json(path)
        email_records.extend(rows)
        manifests.append(file_manifest("phishfuzzer", path, len(rows), {"Valid": "Safe", "Spam": "Spam", "Phishing": "Phishing"}))

    for path in sources.nazario_mbox_paths:
        rows = import_mbox_corpus(path, source="nazario", threat_label="Phishing")
        email_records.extend(rows)
        manifests.append(file_manifest("nazario", path, len(rows), {"corpus": "Phishing"}))

    for path in sources.spamassassin_paths:
        rows = import_spamassassin_path(path)
        email_records.extend(rows)
        manifests.append(file_manifest("spamassassin", path, len(rows), {"spam": "Spam", "ham": "Safe"}))

    for path in sources.enron_maildir_paths:
        rows = import_enron_maildir(path)
        email_records.extend(rows)
        manifests.append(file_manifest("enron", path, len(rows), {"maildir": "Safe"}))

    for path in sources.phishtank_paths:
        rows = import_phishtank_urls(path)
        url_records.extend(rows)
        if enrich_email_from_url_sources:
            email_records.extend(url_records_to_email_enrichment(rows, threat_label="Phishing"))
        manifests.append(file_manifest("phishtank", path, len(rows), {"verified_online": "phishing"}))

    for path in sources.urlhaus_paths:
        rows = import_urlhaus_urls(path)
        url_records.extend(rows)
        if enrich_email_from_url_sources:
            email_records.extend(url_records_to_email_enrichment(rows, threat_label="Malware Risk"))
        manifests.append(file_manifest("urlhaus", path, len(rows), {"malware_url": "suspicious"}))

    for path in sources.reviewed_feedback_paths:
        rows = read_feedback_export(path)
        email_records.extend(rows)
        manifests.append(file_manifest("reviewed_feedback", path, len(rows), {"approved_label": "threat_label"}))

    email_frame = normalize_email_records(email_records, dataset_version=dataset_version)
    url_frame = normalize_url_records(url_records, dataset_version=dataset_version)
    outputs = save_canonical_outputs(email_frame, url_frame, layout.canonical_dir, layout.manifest_dir, dataset_version)
    source_manifest_path = layout.manifest_dir / f"{dataset_version}_sources.json"
    write_source_manifest(manifests, str(source_manifest_path))
    return {
        **outputs,
        "dataset_version": dataset_version,
        "source_manifest_path": str(source_manifest_path),
        "source_count": len(manifests),
    }


def train_ai_threat_models(
    email_dataset_path: str,
    url_dataset_path: str,
    output_base_dir: str = "outputs",
    extra_email_dataset_paths: Optional[Iterable[str]] = None,
    fixture_mode: bool = False,
    reviewed_feedback_rows: Optional[Iterable[Dict[str, object]]] = None,
    reviewed_feedback_paths: Optional[Iterable[str]] = None,
    publish_email_model_path: str = "",
    publish_url_model_path: str = "",
    publish_marker_path: str = "outputs/ai-threat-current/published_run.json",
    publish: bool = False,
    publish_gate: Optional[PublishGateConfig] = None,
    include_weak_labels: bool = False,
) -> Dict[str, object]:
    email_paths = [email_dataset_path, *(extra_email_dataset_paths or [])]
    email_frames = [_load_email_frame(path) for path in email_paths if path]
    if reviewed_feedback_rows:
        feedback_frame = normalize_email_records(
            reviewed_feedback_rows_to_canonical(reviewed_feedback_rows),
            dataset_version=_dataset_version(),
            default_source="reviewed_feedback",
        )
        email_frames.append(feedback_frame)
    for path in reviewed_feedback_paths or []:
        feedback_frame = normalize_email_records(read_feedback_export(path), dataset_version=_dataset_version(), default_source="reviewed_feedback")
        email_frames.append(feedback_frame)

    email_frame = pd.concat(email_frames, ignore_index=True) if email_frames else pd.DataFrame()
    url_frame = _load_url_frame(url_dataset_path)
    assert_not_seed_only(email_frame, fixture_mode=fixture_mode)
    assert_not_seed_only(url_frame.rename(columns={"label": "threat_label"}), fixture_mode=fixture_mode)
    training_email_frame = _filter_weak_labels(email_frame, include_weak_labels)
    training_url_frame = _filter_weak_labels(url_frame, include_weak_labels)

    staging_dir = Path(output_base_dir) / "_ai_threat_training_inputs"
    staging_dir.mkdir(parents=True, exist_ok=True)
    email_training_path = staging_dir / "email_threat_training.csv"
    url_training_path = staging_dir / "url_threat_training.csv"
    to_legacy_email_training_frame(training_email_frame).to_csv(email_training_path, index=False)
    to_legacy_url_training_frame(training_url_frame).to_csv(url_training_path, index=False)

    metadata = _legacy_train_ai_threat_models(
        email_dataset_path=str(email_training_path),
        url_dataset_path=str(url_training_path),
        output_base_dir=output_base_dir,
    )
    lifecycle_metadata = _lifecycle_metadata(email_frame, url_frame, fixture_mode)
    lifecycle_metadata["include_weak_labels_in_primary_training"] = bool(include_weak_labels)
    lifecycle_metadata["primary_training"] = {
        "email_rows": int(len(training_email_frame)),
        "url_rows": int(len(training_url_frame)),
        "excluded_weak_email_rows": int(len(email_frame) - len(training_email_frame)),
        "excluded_weak_url_rows": int(len(url_frame) - len(training_url_frame)),
    }
    metadata["artifact_schema_version"] = ARTIFACT_SCHEMA_VERSION
    metadata["dataset_lifecycle"] = lifecycle_metadata
    metadata["evaluation"] = _load_evaluation_reports(metadata)
    metadata["label_quality"] = {
        **metadata.get("label_quality", {}),
        "email": {**metadata.get("label_quality", {}).get("email", {}), **lifecycle_metadata["email"]},
        "url": {**metadata.get("label_quality", {}).get("url", {}), **lifecycle_metadata["url"]},
    }
    metadata["publish_gate"] = {}

    _stamp_saved_bundle(metadata["artifact_paths"]["email_model_path"], lifecycle_metadata, "email_threat_classifier")
    _stamp_saved_bundle(metadata["artifact_paths"]["url_model_path"], lifecycle_metadata, "url_phishing_classifier")
    _write_lifecycle_reports(metadata, lifecycle_metadata)

    if publish:
        gate = publish_gate or PublishGateConfig()
        metadata["publish_gate"] = publish_artifacts(
            metadata,
            publish_email_model_path,
            publish_url_model_path,
            publish_marker_path,
            gate,
        )
    return metadata


def _load_email_frame(path: str) -> pd.DataFrame:
    raw = pd.read_csv(path).fillna("")
    if "body" in raw.columns or "message_id" in raw.columns:
        return normalize_email_records(raw.to_dict(orient="records"), dataset_version=_dataset_version())
    return normalize_email_records(raw.to_dict(orient="records"), dataset_version=_dataset_version())


def _load_url_frame(path: str) -> pd.DataFrame:
    raw = pd.read_csv(path).fillna("")
    return normalize_url_records(raw.to_dict(orient="records"), dataset_version=_dataset_version())


def _dataset_version() -> str:
    return datetime.utcnow().strftime("%Y%m%d")


def _lifecycle_metadata(email_frame: pd.DataFrame, url_frame: pd.DataFrame, fixture_mode: bool) -> Dict[str, object]:
    return {
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "fixture_mode": bool(fixture_mode),
        "trained_from_seed_only": False if not fixture_mode else True,
        "email": {
            "row_count": int(len(email_frame)),
            "source_counts": _counts(email_frame, "source"),
            "label_counts": _counts(email_frame, "threat_label"),
            "label_source_counts": _counts(email_frame, "label_source"),
            "weak_label_count": int(email_frame.get("is_weak_label", pd.Series(dtype=bool)).astype(bool).sum()) if not email_frame.empty else 0,
        },
        "url": {
            "row_count": int(len(url_frame)),
            "source_counts": _counts(url_frame, "source"),
            "label_counts": _counts(url_frame, "label"),
            "label_source_counts": _counts(url_frame, "label_source"),
            "weak_label_count": int(url_frame.get("is_weak_label", pd.Series(dtype=bool)).astype(bool).sum()) if not url_frame.empty else 0,
        },
    }


def _counts(frame: pd.DataFrame, column: str) -> Dict[str, int]:
    if frame.empty or column not in frame.columns:
        return {}
    return {str(key): int(value) for key, value in frame[column].value_counts().to_dict().items()}


def _filter_weak_labels(frame: pd.DataFrame, include_weak_labels: bool) -> pd.DataFrame:
    if include_weak_labels or frame.empty or "is_weak_label" not in frame.columns:
        return frame
    return frame[~frame["is_weak_label"].astype(bool)].reset_index(drop=True)


def _stamp_saved_bundle(path: str, lifecycle_metadata: Dict[str, object], model_type: str) -> None:
    with open(path, "rb") as handle:
        bundle = pickle.load(handle)
    stamp_bundle_metadata(
        bundle,
        {
            "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
            "model_type": model_type,
            "dataset_lifecycle": lifecycle_metadata,
        },
    )
    with open(path, "wb") as handle:
        pickle.dump(bundle, handle)


def _write_lifecycle_reports(metadata: Dict[str, object], lifecycle_metadata: Dict[str, object]) -> None:
    observations = Path(metadata["artifact_paths"]["observations_dir"])
    observations.mkdir(parents=True, exist_ok=True)
    (observations / "dataset_lifecycle.json").write_text(
        json.dumps(lifecycle_metadata, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    metadata_path = observations / "model_lab_metadata.json"
    if metadata_path.exists():
        current = json.loads(metadata_path.read_text(encoding="utf-8"))
        current["artifact_schema_version"] = ARTIFACT_SCHEMA_VERSION
        current["dataset_lifecycle"] = lifecycle_metadata
        current["evaluation"] = metadata.get("evaluation", {})
        current["label_quality"] = metadata.get("label_quality", current.get("label_quality", {}))
        metadata_path.write_text(json.dumps(current, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def _load_evaluation_reports(metadata: Dict[str, object]) -> Dict[str, object]:
    observations = Path(metadata["artifact_paths"]["observations_dir"])
    reports = {}
    for key, filename in {
        "email": "email_threat_metrics.json",
        "url": "url_phishing_metrics.json",
        "email_errors": "email_error_analysis.json",
        "url_errors": "url_error_analysis.json",
    }.items():
        path = observations / filename
        if path.exists():
            reports[key] = json.loads(path.read_text(encoding="utf-8"))
    return reports
