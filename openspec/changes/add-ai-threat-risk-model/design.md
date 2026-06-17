## Context

The application already supports spam/ham prediction, URL analysis, QR/quishing checks, MBOX batch processing, dashboard views, history, feedback, and model lab outputs. The current trained model is still primarily a binary spam/ham classifier. Security-risk decisions for phishing, malware, fake links, URL risk, QR/payment scam, taxonomy, and final verdict are largely produced by deterministic rules.

For an academic AI/ML evaluation, this creates a weak story: the most important security-risk behavior is programmed directly instead of learned from labeled data. The next design step is to make the threat-risk layer AI-only at runtime: trained models produce the final threat labels, risk scores, risk levels, and verdicts.

## Goals / Non-Goals

**Goals:**

- Train and load supervised ML models for email threat classification and URL phishing classification.
- Produce model-only `threat_label`, `class_scores`, `risk_score`, `risk_level`, and `verdict` for single-email, URL/QR, and MBOX flows.
- Remove deterministic rule fallback from runtime risk scoring. When required model artifacts are missing or incompatible, return a clear model-unavailable result and ask the operator to train/configure artifacts.
- Keep deterministic helper code only where it acts as non-decision feature extraction or evidence formatting, and only if it cannot assign final labels, risk levels, scores, or verdicts.
- Support realistic evaluation: per-class metrics, macro/weighted F1, confusion matrix, PR-AUC/ROC-AUC when available, threshold analysis, and historical comparison against old rule-only scoring when useful for reports.
- Make dataset provenance clear, including imported labeled data, reviewed feedback exports, and any weak/pseudo-labeled bootstrap examples that do not come from runtime rule scoring.
- Preserve existing return keys and UI workflows so current app behavior remains usable.

**Non-Goals:**

- Training a large transformer or requiring GPU support in the first implementation.
- Guaranteeing production-grade malware detection from binary/file content. The MVP operates on email text, headers/metadata when available, URL features, QR payload metadata, and attachment filename indicators.
- Building external threat-intelligence API integrations.
- Building a real-time mailbox ingestion system.

## Decisions

### Decision 1: Use sklearn-first supervised models for the MVP

The first implementation will train sklearn-compatible models such as Logistic Regression, Linear SVM, Random Forest, Gradient Boosting, or calibrated ensembles. This fits the current codebase, existing dependencies, Streamlit runtime, and model lab infrastructure.

Alternatives considered:

- Transformer model first: more impressive in wording, but heavier, harder to run locally, and risky for project deadlines.
- Keep only rule scoring: simple but does not solve the academic evaluation concern.

### Decision 2: Split email threat model and URL phishing model

Email threat classification and URL phishing classification should be trained as separate models:

- Email threat model predicts labels such as Safe, Spam, Phishing, Malware Risk, Credential Theft, Payment Scam, Quishing, and Business Email Compromise when enough labeled samples exist.
- URL phishing model predicts benign/suspicious/phishing or phishing probability from URL lexical/domain features.

Rationale: URL datasets and email datasets usually have different schemas and signal types. Splitting models makes training, evaluation, and explanation clearer.

Alternatives considered:

- One model for everything: simpler integration, but weak for URL-only analysis and harder to evaluate.
- Separate model for every threat class: too much data needed for the current project.

### Decision 3: Rules are removed from runtime decision-making

Existing modules such as `EmailThreatAnalyzer`, `URLRiskModel`, `ThreatTaxonomyClassifier`, and `RiskAggregator` must no longer produce final runtime risk decisions. The implementation should either remove those calls from final scoring paths or constrain them to non-decision roles:

- Numeric features such as URL count, risky filename count, keyword hits, old rule scores, domain features, and QR/payment payload markers.
- Human-readable evidence for UI explanations.
- Offline comparison for model-lab reports.

Alternatives considered:

- Remove rule analyzers entirely: cleanest runtime story, but may require replacing useful parsers and feature extractors.
- Keep rule score as fallback: rejected because it weakens the academic claim and lets the product behave like a rule system when models are missing.
- Keep rule score as final verdict: rejected because it fails the goal of AI-only risk analysis.

### Decision 4: Track dataset source and label quality

Training data should include provenance fields such as `source`, `label_source`, `is_weak_label`, and optional `review_status`. Examples:

- External labeled phishing/spam datasets.
- Local curated examples for phishing, malware-risk wording, payment scam, and safe email.
- Reviewed feedback exports from the application.
- Weak labels from trusted dataset metadata or manual triage, clearly marked as bootstrap data and reported separately.

Rationale: evaluation is more defensible when the report can distinguish real labels from generated labels.

Alternatives considered:

- Train on rule-generated labels: rejected because the model would imitate fixed rules and remain easy to criticize.
- Require a perfect dataset before implementation: unrealistic for the project timeline.

### Decision 5: Convert model output into risk through calibrated probabilities and thresholds

The final risk score must derive from model probabilities and selected thresholds:

- `risk_score` can map the highest malicious probability to `0-100`.
- `risk_level` maps calibrated score to Low/Medium/High/Critical.
- Threshold profiles can favor phishing recall for safer demos.
- Deterministic evidence cannot adjust the score, override the model, or create a fallback verdict.

Alternatives considered:

- Direct regression to `0-100`: attractive but needs reliable numeric labels.
- Keep handcrafted score weights: easy but remains rule-based.

### Decision 6: Keep return fields stable while adding model provenance and unavailable states

Prediction outputs should keep existing keys such as `prediction`, `confidence`, `threat_label`, `risk_score`, `risk_level`, `verdict`, `reasons`, `recommended_actions`, and `class_scores`. New metadata should identify:

- model type and artifact paths,
- model version/run id,
- whether the required model was available,
- source of risk score: `ai_model` or `model_unavailable`.

Rationale: this lets the UI and database continue working while making the AI/ML story explicit and preventing silent rule-based scoring.

## Risks / Trade-offs

- Small or imbalanced threat dataset -> Use macro F1, per-class recall, class weights, stratified splits, and document dataset provenance.
- Weak labels may reduce model credibility -> Mark weak labels separately, prefer reviewed/external labels for metrics, and avoid claiming weak-label metrics as final truth.
- Model may under-detect rare malware or quishing classes -> Allow class merging for MVP, such as Malware Risk and Payment Scam, until enough examples exist.
- Model artifacts may be missing on first run -> Return `model_available = false`, suppress final risk scoring, and show a train/configure action in the UI.
- Probability calibration can be unreliable for some estimators -> Use calibrated classifiers when feasible and record calibration method.
- Adding new models can complicate configuration -> Add explicit config paths for threat model, URL model, vectorizers, and metadata.

## Migration Plan

1. Add dataset schema and sample dataset files for threat-labeled email and URL examples.
2. Add model training path for email threat classifier and URL phishing classifier, reusing existing model lab patterns.
3. Save artifacts under versioned `outputs/<timestamp>/models/` with metadata describing labels, features, thresholds, and dataset provenance.
4. Add config paths for current threat model and URL model artifacts.
5. Update prediction pipeline to load AI threat artifacts and use them as primary risk source.
6. Remove rule-only fallback when artifacts are missing or incompatible; return a model-unavailable result.
7. Update UI/docs to clearly state that runtime risk scoring requires trained AI artifacts.
8. Roll back by disabling AI-only risk features and showing model-unavailable states; do not re-enable rule-based runtime scoring under this change.

## Open Questions

- Which external labeled datasets are acceptable for the final report and demo?
- Should the first MVP merge some labels into fewer classes, such as Safe, Spam, Phishing, Malware Risk, Payment Scam, and Credential Theft?
- Should URL classifier output binary phishing probability or three classes: Benign, Suspicious, Phishing?
- How many reviewed local examples are needed before claiming the multi-class threat model is reliable?
- Should model training expose a Streamlit button, remain CLI-only, or support both?
