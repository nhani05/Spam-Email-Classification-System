## 1. AI-only Runtime Contract

- [x] 1.1 Define a `model_unavailable` response shape for email, URL, QR, and batch flows that preserves existing UI-safe keys without returning rule-derived final risk.
- [x] 1.2 Replace runtime risk source values so final scoring can only be `ai_model` or `model_unavailable`.
- [x] 1.3 Remove `fallback_rules`, `hybrid_conflict_review`, and model-rule conflict states from final prediction outputs.
- [x] 1.4 Ensure missing or incompatible model artifacts produce operator-facing train/configure guidance instead of a rule-derived verdict.

## 2. Email and Batch Prediction Refactor

- [x] 2.1 Update single-email prediction so `threat_label`, `class_scores`, `risk_score`, `risk_level`, and `verdict` are populated only from trained AI threat artifacts.
- [x] 2.2 Remove calls to deterministic threat taxonomy and risk aggregation from final single-email scoring.
- [x] 2.3 Keep binary spam/ham prediction separate from threat-risk scoring and prevent it from becoming a fallback risk verdict.
- [x] 2.4 Update MBOX batch processing so each row either has AI-model risk fields or a model-unavailable state.
- [x] 2.5 Remove model-rule conflict review routing that depends on runtime rule scores.

## 3. URL and QR Prediction Refactor

- [x] 3.1 Update URL analysis so final URL risk, verdict, probability, and level are produced only by the trained URL phishing model.
- [x] 3.2 Remove deterministic URL score fallback from direct URL analysis.
- [x] 3.3 Update QR/quishing analysis so decoded URL scoring uses only the trained URL model.
- [x] 3.4 Preserve URL/QR parsing and evidence display only where those helpers do not assign final risk values.

## 4. Feature and Evidence Boundaries

- [x] 4.1 Audit deterministic analyzer modules and classify each retained function as parsing, feature extraction, evidence formatting, offline evaluation, or deprecated runtime scoring.
- [x] 4.2 Remove or bypass retained runtime scoring functions from production prediction paths.
- [x] 4.3 Ensure AI model features do not include final rule scores that would make the model imitate the removed rule engine.
- [x] 4.4 Keep explainability output tied to model probabilities, model features, artifact metadata, and non-decision evidence.

## 5. UI and Documentation

- [x] 5.1 Update Streamlit single-email UI to show AI-model scoring or model-unavailable state only.
- [x] 5.2 Update URL/QR UI to remove fallback rule labels and show model training/configuration guidance when artifacts are missing.
- [x] 5.3 Update batch CSV columns and preview labels to remove rule fallback/conflict terminology.
- [x] 5.4 Update README and demo docs to state that runtime risk scoring requires trained AI artifacts and does not fall back to deterministic rules.

## 6. Verification

- [x] 6.1 Run `python -m compileall src app.py scripts`.
- [x] 6.2 Run AI threat model smoke checks with configured artifacts and verify risk source is `ai_model`.
- [x] 6.3 Run prediction smoke checks with missing artifacts and verify outputs are `model_unavailable`, not rule-derived verdicts.
- [x] 6.4 Run URL/QR smoke checks with missing URL artifacts and verify no deterministic URL risk fallback is returned.
- [x] 6.5 Inspect terminal logs to confirm demo output clearly distinguishes `ai_model` from `model_unavailable`.
