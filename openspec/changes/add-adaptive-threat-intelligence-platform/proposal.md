## Why

The current project is still centered on binary spam/ham classification with a small imbalanced dataset and a classic TF-IDF classifier, while the product layer already hints at broader email security through URL, QR, and rule-based risk analysis. This change turns the project into a harder, more defensible adaptive email threat intelligence platform that can classify threat types, explain risk, detect phishing campaigns, and improve through feedback.

## What Changes

- Add a hybrid threat modeling capability that combines text, URL, QR, attachment, sender/header, and rule-derived features instead of relying only on message-body TF-IDF.
- Add a model lab for repeatable benchmark experiments, threshold tuning, calibration, error analysis, and model registry metadata.
- Add campaign intelligence that groups related dangerous emails into phishing or scam campaigns using similarity signals across content, domains, senders, brands, QR payloads, and time windows.
- Add threat graph analysis to connect emails, URLs, domains, senders, brands, QR payloads, and campaigns for investigation workflows.
- Add feedback and active-learning workflows so uncertain, conflicting, or user-corrected predictions can be reviewed and used for future retraining.
- Extend dashboard and report outputs from spam/ham counts into security-oriented threat intelligence views.
- No breaking changes are intended for existing single-email, URL, QR, MBOX, history, or dashboard workflows; existing flows should be enhanced rather than removed.

## Capabilities

### New Capabilities

- `hybrid-threat-modeling`: Covers multi-source feature extraction, multi-class threat prediction, calibrated scoring, and explainable fusion of ML and rule-based signals.
- `model-evaluation-lab`: Covers repeatable model experiments, metrics beyond accuracy, threshold selection, error analysis, and model version metadata.
- `campaign-threat-intelligence`: Covers IoC extraction, email similarity scoring, phishing campaign clustering, campaign summaries, threat graph relationships, and exportable investigation reports.
- `adaptive-feedback-learning`: Covers user feedback capture, analyst review queues, active-learning sample selection, and retraining dataset preparation.

### Modified Capabilities

- None.

## Impact

- Affected ML pipeline modules: `src/components/data_ingestion.py`, `src/components/data_transformation.py`, `src/components/model_training.py`, `src/pipeline/training_pipeline.py`, and `src/pipeline/prediction_pipeline.py`.
- Affected security modules: `src/security/email_threat_analyzer.py`, `src/security/url_risk_model.py`, `src/security/qr_image_analyzer.py`, and `src/security/risk_aggregator.py`.
- Affected UI and reporting modules: `app.py`, `src/components/dashboard.py`, history views, batch MBOX output, and export/download flows.
- Affected persistence: database schema for model runs, feedback, review queues, extracted indicators, campaign records, campaign-email links, and report metadata.
- Likely dependency additions: graph/similarity tooling such as `networkx`, optional visualization support, and possibly extra sklearn utilities for calibration, imbalance handling, and metrics.
- Data impact: current `data/dataset/dataset.csv` remains usable as a baseline, but the platform should support richer labeled datasets with threat taxonomy labels and feature snapshots.
