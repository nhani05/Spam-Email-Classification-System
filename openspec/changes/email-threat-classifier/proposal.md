## Why

The current AI threat model workflow still depends on small local seed CSVs and legacy-compatible wrappers, so retraining is not yet a defensible end-to-end ML lifecycle. This change refactors the email threat classifier around a standard model creation loop: external data acquisition, cleaning, feature engineering, training, evaluation, artifact publishing, app integration, feedback capture, and retraining.

## What Changes

- Replace seed-based threat training inputs with importable external dataset sources such as PhishFuzzer, Nazario phishing corpus, SpamAssassin, Enron, PhishTank, and URLhaus-derived URL labels.
- Add dataset acquisition and normalization steps that produce canonical, provenance-tracked training tables instead of relying on manually seeded CSVs as the primary training source.
- Refactor email threat classifier modules away from compatibility-only wrappers into explicit dataset, cleaning, feature, training, evaluation, artifact, service, and retraining boundaries.
- Train a new supervised multi-class email threat model from refreshed data and publish versioned artifacts for runtime use.
- Evaluate the new model with per-class metrics, macro/weighted F1, confusion matrix, data-source breakdowns, label-quality breakdowns, and error analysis.
- Integrate the retrained model into the Streamlit prediction flow while preserving the current AI-only runtime contract: no rule-based fallback verdicts.
- Extend the feedback loop so reviewed user corrections can be exported, validated, merged into the training corpus, and used in the next retraining run.
- Mark any synthetic, generated, weak, or bootstrap labels separately and exclude them from primary evaluation unless explicitly selected.
- **BREAKING**: `data/ai_threat/*_seed.csv` must no longer be treated as the authoritative training source for the production email threat classifier.

## Capabilities

### New Capabilities
- `email-threat-classifier-lifecycle`: Defines the complete lifecycle for creating, retraining, evaluating, publishing, and using the email threat classifier from external/provenance-tracked data rather than seed data.

### Modified Capabilities
- None.

## Impact

- Affected code: `src/ml/threat_classifier/`, `src/ml/url_classifier/`, `src/workflows/training.py`, `src/pipeline/prediction_pipeline.py`, `src/config/config.py`, `scripts/train_ai_threat_models.py`, Streamlit model lab and prediction pages, and smoke scripts.
- Affected data: new raw/imported dataset directories, normalized canonical datasets, reviewed feedback exports, dataset manifests, and label provenance metadata.
- Affected artifacts: retrained model bundles under `outputs/<run-id>/models/`, current published artifacts under `outputs/ai-threat-current/models/`, evaluation reports under `outputs/<run-id>/observations/`, and dataset manifests/checksums.
- Affected docs: README, adaptive threat intelligence docs, demo guide, and retraining instructions must describe the external-data lifecycle and no-seed production training policy.
- Dependencies: continue using the existing Python/sklearn/pandas stack for the first implementation; dataset download/import commands may require optional network access and should support offline local-file inputs.
