## 1. Data Model and Storage

- [x] 1.1 Review current MySQL schema and history save/read paths for compatibility with new threat fields.
- [x] 1.2 Add migration SQL for model runs, prediction threat metadata, extracted indicators, campaigns, campaign-email links, feedback, and review queue items.
- [x] 1.3 Add database helper functions for saving and reading threat metadata without breaking existing history functions.
- [x] 1.4 Add lightweight seed or fixture data for campaign, indicator, and feedback workflows.

## 2. Hybrid Feature Extraction

- [x] 2.1 Create a structured email feature record model for text, metadata, URL, QR, attachment, sender/header, and rule-derived signals.
- [x] 2.2 Extend email parsing to preserve subject, sender, recipients, reply-to, date, body, and available headers from MBOX messages.
- [x] 2.3 Add URL and domain feature extraction outputs that can be reused by both rule scoring and ML features.
- [x] 2.4 Add QR payload feature extraction outputs that can be attached to email/image analysis results.
- [x] 2.5 Add attachment and suspicious filename feature extraction for pasted email text and parsed MBOX messages.
- [x] 2.6 Add tests or smoke checks for feature extraction with normal email, phishing URL email, risky attachment email, and QR payload examples.

## 3. Hybrid Threat Modeling

- [x] 3.1 Extend data transformation to support word TF-IDF, character n-gram TF-IDF, numeric security features, and combined feature matrices.
- [x] 3.2 Add support for multi-class threat labels while preserving binary spam/ham compatibility.
- [x] 3.3 Train baseline hybrid sklearn models and compare them against the current TF-IDF-only baseline.
- [x] 3.4 Update prediction pipeline output to include threat label, calibrated scores when available, component scores, reasons, and recommended actions.
- [x] 3.5 Update risk aggregation to fuse ML output, rule-based threat evidence, and future campaign evidence while explaining model-rule conflicts.
- [x] 3.6 Add regression checks that existing single-email and MBOX workflows still return their previous core fields.

## 4. Model Evaluation Lab

- [x] 4.1 Add model run metadata capture for dataset identity, feature config, model config, timestamp, selected model, artifact paths, and taxonomy.
- [x] 4.2 Add per-class precision, recall, F1, macro F1, weighted F1, confusion matrix, ROC-AUC when supported, and PR-AUC when supported.
- [x] 4.3 Add threshold analysis for high-sensitivity phishing/spam detection profiles.
- [x] 4.4 Add calibration metadata and calibrated confidence output for models that support calibration.
- [x] 4.5 Add error analysis outputs for false positives, false negatives, low-confidence cases, and model-rule conflicts.
- [x] 4.6 Add a Streamlit model lab view or report section for comparing model runs and reviewing error analysis.

## 5. Campaign Threat Intelligence

- [x] 5.1 Implement indicator extraction for senders, domains, URLs, QR payloads, brands, suspicious files, keywords, timestamps, and threat labels.
- [x] 5.2 Implement deterministic campaign similarity scoring across text, domains, URLs, senders, brands, QR payloads, labels, and time windows.
- [x] 5.3 Implement campaign clustering for suspicious MBOX and persisted-history analysis scopes.
- [x] 5.4 Create campaign summary records with id, primary threat label, risk level, email count, first seen, last seen, top domains, top brands, and representative reasons.
- [x] 5.5 Add isolated-high-risk handling for suspicious emails that do not meet campaign grouping thresholds.
- [x] 5.6 Add campaign detection smoke checks with related phishing emails and unrelated benign emails.

## 6. Threat Graph and Reports

- [x] 6.1 Add graph-ready node and edge generation for campaigns, emails, senders, URLs, domains, QR payloads, brands, labels, and users.
- [x] 6.2 Add graph size limiting and prioritization for high-risk or high-frequency indicators.
- [x] 6.3 Add campaign detail dashboard with summary metrics, indicators, related emails, and graph view.
- [x] 6.4 Add campaign report export in at least one structured format such as Markdown, JSON, or CSV.
- [x] 6.5 Add no-campaign empty states for dashboard and export workflows.

## 7. Feedback and Active Learning

- [x] 7.1 Add authenticated-user feedback capture for correct, incorrect, corrected label, and optional note.
- [x] 7.2 Add review queue creation for low-confidence predictions, model-rule conflicts, high-risk ham predictions, and user-corrected predictions.
- [x] 7.3 Add review status handling for pending, approved, and rejected feedback items.
- [x] 7.4 Add retraining dataset export for approved review items with normalized text, threat label, optional binary label, indicators, and metadata.
- [x] 7.5 Add safeguards so rejected or unreviewed feedback cannot enter retraining exports.

## 8. UI Integration

- [x] 8.1 Update single-email results to display primary threat label, risk fusion evidence, component scores, and review/feedback controls.
- [x] 8.2 Update batch MBOX results to display threat labels, campaign ids, campaign summaries, and campaign report downloads.
- [x] 8.3 Update dashboard to show threat taxonomy distribution, high-risk trend, top risky domains, top impersonated brands, campaign count, and recent review queue items.
- [x] 8.4 Preserve guest-mode behavior for single email, URL, and QR analysis while keeping persistence-only features behind authentication.

## 9. Documentation and Verification

- [x] 9.1 Update README and project roadmap to describe the adaptive threat intelligence platform, model lab, campaign detection, graph, and feedback loop.
- [x] 9.2 Document new database migrations and model artifact/versioning behavior.
- [x] 9.3 Add demo scenarios for safe email, phishing URL, quishing/payment QR, risky attachment, MBOX campaign detection, and feedback review.
- [x] 9.4 Run available lint, compile, training smoke, prediction smoke, and Streamlit smoke checks.
- [x] 9.5 Record final implementation notes, known limitations, and follow-up improvements.
