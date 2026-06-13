# Adaptive Threat Intelligence Platform

## Overview

This upgrade turns the project from a binary spam/ham classifier into a local email threat intelligence platform. The system now treats every email as a structured security event with text, URL, QR, attachment, sender/header, risk, campaign, and feedback signals.

## Architecture

```text
Email / MBOX / QR
        |
        v
EmailFeatureExtractor
        |
        +--> Text features
        +--> URL/domain features
        +--> QR payload features
        +--> Attachment indicators
        +--> Sender/header metadata
        +--> Rule-based threat scores
        |
        v
Hybrid ML + Threat Taxonomy + Risk Aggregator
        |
        v
CampaignIntelligenceEngine
        |
        +--> Campaign summaries
        +--> Threat graph nodes/edges
        +--> Markdown/JSON reports
        |
        v
Dashboard + Feedback + Review Queue + Retraining Export
```

## Model Lab

Training now records richer experiment metadata:

- Dataset identity.
- Feature configuration.
- Threat taxonomy mapping.
- Per-class precision, recall, F1.
- Macro F1 and weighted F1.
- Confusion matrix.
- ROC-AUC and PR-AUC when supported.
- Threshold analysis.
- Calibration metadata.
- Error analysis for false positives, false negatives, low-confidence cases, and model-rule conflicts.

Model-lab metadata is stored in:

```text
outputs/<timestamp>/observations/model_lab_metadata.json
outputs/<timestamp>/observations/threshold_analysis.csv
outputs/<timestamp>/observations/error_analysis.json
```

## Database Migration

Run `db/db.sql` on a fresh MySQL database or copy the adaptive extension tables into an existing schema. New tables:

- `Model_Run`
- `Prediction_Threat_Metadata`
- `Extracted_Indicator`
- `Threat_Campaign`
- `Campaign_Email`
- `Prediction_Feedback`
- `Review_Queue`

Existing `Single_Prediction_History` and `Batch_Prediction_History` remain compatible.

## Demo Scenarios

1. Safe email: short work message without links.
2. Phishing URL: urgent login/password email with a fake brand domain.
3. Quishing/payment QR: QR payload that contains a payment payload or suspicious URL.
4. Risky attachment: message mentioning `invoice.pdf.exe` or macro enabling.
5. MBOX campaign: multiple phishing messages sharing a domain or similar subject/body.
6. Feedback review: mark a prediction incorrect and export approved review items for retraining.

## Verification

Run:

```bash
python -m compileall src app.py
python scripts/smoke_adaptive_threat_intelligence.py
```

## Known Limitations

- Header authentication checks such as SPF, DKIM, and DMARC are represented as optional metadata, not live DNS verification.
- Transformer-based language models are intentionally out of scope for the first implementation.
- Campaign clustering is deterministic and explainable, but thresholds may need tuning on larger mailboxes.
- Feedback is stored for review before retraining to reduce poisoning risk.
