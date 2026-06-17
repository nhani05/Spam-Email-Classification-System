## Why

The current security-risk layer still relies mainly on deterministic rules for phishing, malware, URL, QR, and final risk scoring, while the trained ML model only performs binary spam/ham classification. This weakens the academic AI/ML story because the most security-relevant verdicts are produced by hand-written scoring rather than a trained threat model.

This change introduces a trained AI/ML threat-risk model so phishing, malware risk, credential theft, payment scam, and URL phishing signals are learned from labeled data. Deterministic rules must no longer produce final risk scores, labels, verdicts, or fallback results.

## What Changes

- Add a supervised threat-risk modeling workflow that trains an ML model for multi-class email threat labels and risk levels.
- Add a supervised URL phishing classifier that predicts URL risk from lexical/domain features instead of fixed URL score weights.
- Add dataset preparation support for labeled threat examples, including imported CSV data, reviewed feedback exports, and optional weak labels that are clearly marked as bootstrap data and are not generated from runtime rule scores.
- Update prediction flow so trained AI/ML outputs are the only source for `threat_label`, `class_scores`, `risk_score`, `risk_level`, and final `verdict`.
- Remove rule-based fallback behavior from email, URL, QR, and batch risk scoring. If model artifacts are unavailable, return a model-unavailable state instead of a rule-derived risk result.
- Allow deterministic extractors only as non-decision feature builders or UI evidence helpers when they do not assign final risk, labels, or verdicts.
- Extend model lab outputs to evaluate binary spam/ham baseline, AI threat classifier, and URL phishing classifier using defensible metrics; rule-only baselines may be documented historically but must not be part of runtime scoring.
- Preserve existing Streamlit workflows and return fields for single email, URL/QR analysis, MBOX batch analysis, history, dashboard, and feedback.

## Capabilities

### New Capabilities

- `ai-threat-risk-model`: Trained ML models produce email threat labels, URL phishing predictions, risk levels, probabilities, evaluation metrics, and model artifacts for the risk-analysis layer.

### Modified Capabilities

- None.

## Impact

- Affected code: `src/components/data_ingestion.py`, `src/components/data_transformation.py`, `src/components/model_training.py`, `src/components/model_lab.py`, `src/pipeline/prediction_pipeline.py`, `src/security/`, `src/config/config.py`, `app.py`, and dashboard/history integration points.
- Affected data/artifacts: threat-labeled CSV datasets under `data/`, model artifacts under `outputs/<timestamp>/models/`, evaluation reports under `outputs/<timestamp>/observations/`, and optional reviewed feedback export files.
- Affected documentation: README/demo docs should explain that risk analysis is model-only at runtime, and deterministic rules are not used as a fallback scoring engine.
- Dependencies: Prefer existing sklearn/pandas stack for MVP. Optional NLP or external datasets can be added later only if they do not make local Streamlit execution fragile.
