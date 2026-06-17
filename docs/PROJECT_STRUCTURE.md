# Project Structure Map

This map records the target ownership boundaries for the project-structure refactor. Compatibility modules stay in place during migration so existing scripts, pickled artifacts, and Streamlit imports continue to work.

## Target Packages

| Target package | Owns | Compatibility notes |
| --- | --- | --- |
| `src.app` | Streamlit views, page handlers, rendering and translation helpers | `app.py` remains the Streamlit entrypoint. |
| `src.core` | Configuration, path helpers, logging | `src.config.config` and `src.utils.logger` continue to import or delegate here. |
| `src.data` | Email parsing, dataset loading, schema helpers | `src.utils.email_utils` remains import-compatible. |
| `src.ml.spam_classifier` | Baseline spam/ham ingestion, transformation, training, inference helpers | `src.components.data_ingestion`, `src.components.data_transformation`, and `src.components.model_training` remain import-compatible. |
| `src.ml.threat_classifier` | Email threat model service, training, features, datasets, labels, evaluation | `src.security.ai_threat_model` remains import-compatible for runtime and training APIs. |
| `src.ml.url_classifier` | URL classifier features and label/verdict helpers | Existing URL analysis imports remain available through `src.security`. |
| `src.ml.model_lab` | Model metrics, threshold reports, error analysis, run discovery | `src.components.model_lab` remains import-compatible. |
| `src.security` | URL analysis, QR analysis, email indicators, campaign intelligence | Supervised model training moves out of this package. |
| `src.workflows` | Prediction and training orchestration used by UI/scripts | `src.pipeline.prediction_pipeline` and `src.pipeline.training_pipeline` remain import-compatible. |
| `src.persistence` | Users, predictions/history, feedback/review queue, campaigns | `src.auth.auth` remains import-compatible while delegating persistence concerns. |

## Artifact Categories

| Category | Current location | Meaning |
| --- | --- | --- |
| Bundled baseline artifacts | `data/models/v1/` | Checked-in spam/ham fallback artifacts. |
| Current runtime artifacts | Configured paths such as `outputs/ai-threat-current/models/` | Artifacts loaded by prediction workflows. |
| Historical training runs | `outputs/<run-id>/` | Timestamped generated models, observations, and metadata. |

## Migration Rule

Move ownership in small steps, keep compatibility shims thin, and run import/smoke checks after each package boundary changes.
