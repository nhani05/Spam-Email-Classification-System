## Context

The current application already has a working Streamlit experience for single-email prediction, MBOX batch processing, URL phishing analysis, QR/quishing analysis, user history, and dashboard views. The ML core is still a classic binary spam/ham pipeline using `data/dataset/dataset.csv`, TF-IDF features, and sklearn classifiers. Security risk is handled separately through rule-based URL, QR, email-threat, and risk-aggregation modules.

This change evolves the project into an adaptive email threat intelligence platform. The main architectural shift is to treat each email as a structured security event rather than just raw text. The platform should extract indicators, classify threat type, explain risk, group related messages into campaigns, and capture feedback for later retraining.

## Goals / Non-Goals

**Goals:**

- Preserve existing single-email, URL, QR, MBOX, history, and dashboard workflows while enriching their outputs.
- Build a hybrid detection layer that combines message text, URL, QR, attachment, sender/header, and rule-derived features.
- Support multi-class threat labels such as Safe, Spam, Phishing, Malware Risk, Business Email Compromise, Quishing, Credential Theft, and Payment Scam.
- Add a repeatable model evaluation lab with threshold tuning, calibration, imbalance-aware metrics, error analysis, and model run metadata.
- Detect related phishing/scam campaigns across batch email inputs and stored history.
- Represent investigation relationships through a threat graph and export campaign reports.
- Capture user feedback and route uncertain or conflicting predictions into a review queue for active learning.

**Non-Goals:**

- Real-time mailbox ingestion from Gmail, Outlook, or IMAP is out of scope for the initial change.
- External threat-intelligence APIs are optional integrations, not required for MVP completion.
- Deep transformer training is not required for the first implementation because it adds dependency and runtime risk; the first target is a strong hybrid sklearn pipeline.
- Automated production deployment, SOC alerting, and multi-tenant admin operations are out of scope unless added by later changes.

## Decisions

### Decision 1: Use a hybrid feature pipeline before adding transformer models

The first implementation should improve the current sklearn pipeline with richer features: word TF-IDF, character n-gram TF-IDF, URL lexical features, QR-derived features, sender/header features, attachment indicators, and rule scores from existing security analyzers.

Rationale: this reuses the current codebase, remains explainable, runs locally in Streamlit, and is easier to defend in an academic demo. Transformer models can be added later as an optional benchmark once the platform has stronger data and evaluation infrastructure.

Alternatives considered:

- Replace the model with a transformer immediately. This may look advanced but risks slow setup, larger dependencies, and weaker explainability.
- Keep only TF-IDF text classification. This is simpler but does not justify the new threat-intelligence direction.

### Decision 2: Keep ML prediction and risk fusion as separate layers

The ML model should produce labels, probabilities, and model explanations. The risk aggregator should combine those outputs with rule-based threat signals and campaign signals into final risk score, verdict, reasons, and recommended actions.

Rationale: separating prediction from risk fusion lets the system handle cases where the model says Ham but URL/header/campaign evidence is dangerous. It also makes explanations easier to inspect and test.

Alternatives considered:

- Put every signal directly into one model. This can work later but makes early explanations and debugging harder.
- Keep risk rules completely independent from model output. This misses useful confidence and taxonomy signals from ML.

### Decision 3: Store model runs and feature snapshots

Each training run should persist metadata such as dataset path or hash, label taxonomy, feature configuration, selected model, metrics, calibration summary, threshold configuration, and artifact paths.

Rationale: current outputs save basic CSV metrics, but a model lab needs reproducibility and comparison across runs.

Alternatives considered:

- Only overwrite `model.pkl` and `feature.pkl`. This is fast but loses experiment history.
- Use a heavyweight tracking server. This is unnecessary for the project scale.

### Decision 4: Campaign detection should start with deterministic similarity scoring

Campaign clustering should initially use deterministic signals: normalized text similarity, domain overlap, URL overlap, sender-domain similarity, brand impersonation overlap, QR payload overlap, and time-window proximity.

Rationale: deterministic scoring is explainable and demo-friendly. It also works with small datasets and MBOX batches.

Alternatives considered:

- Use unsupervised embeddings from the start. This can be added later, but it is harder to explain and tune.
- Manually group by domain only. This misses campaigns that rotate domains or reuse content.

### Decision 5: Threat graph is an investigation view over stored entities

The graph should model relationships among emails, senders, URLs, domains, QR payloads, brands, campaigns, and users. It should be generated from extracted indicators and campaign membership rather than maintained as a separate source of truth.

Rationale: this avoids graph/database synchronization complexity while still enabling a strong dashboard and report experience.

Alternatives considered:

- Introduce a graph database. This is too heavy for the current project.
- Render only tables. Tables are useful but do not clearly show campaign relationships during demo.

### Decision 6: Feedback should feed a review queue before retraining

User feedback should not immediately retrain models. It should be stored, validated, and routed into a review queue together with model-rule conflicts and low-confidence cases.

Rationale: direct retraining from unchecked feedback can poison the model. A review queue is more realistic and safer.

Alternatives considered:

- Retrain immediately after each feedback item. This is unstable and hard to validate.
- Store feedback only as history. This does not support adaptive learning.

## Risks / Trade-offs

- Feature scope grows too large -> Implement in phases and keep the first MVP focused on hybrid features, model lab, and campaign summaries.
- Dataset is too small or not representative of real email threats -> Keep the existing dataset as baseline, add synthetic phishing/quishing examples, support external labeled CSV imports, and track dataset provenance.
- Multi-class labels are unavailable in current data -> Use binary baseline plus rule-derived pseudo-labels initially, then allow corrected labels through feedback.
- Header analysis may be weak for pasted email text -> Treat full header parsing as optional and degrade gracefully when headers are missing.
- Campaign clustering may produce false groups -> Show similarity evidence and allow threshold tuning or manual review.
- Graph visualization may become noisy -> Limit graph views to selected campaigns and cap nodes by risk or relationship strength.
- Feedback can be malicious or wrong -> Store feedback separately, require review before training-set promotion, and keep audit metadata.

## Migration Plan

1. Add new database tables without dropping existing user, single prediction, or batch history tables.
2. Add new pipeline modules while keeping existing `PredictionPipeline.predict_single_email` return keys compatible.
3. Extend saved prediction records with optional risk, threat label, indicator, campaign, and feedback metadata.
4. Add model lab outputs under versioned output directories and keep existing model path configuration usable.
5. Add campaign and graph views as new dashboard sections, not replacements for existing views.
6. Rollback by disabling new UI sections and continuing to load the previous binary model/vectorizer artifacts.

## Open Questions

- Which threat labels should be required for the first grading demo: Spam, Phishing, Quishing, Malware Risk, Payment Scam, and Safe may be enough.
- Should campaign detection run only on uploaded MBOX batches first, or also across persisted user history?
- Should the first graph view use `networkx` plus Streamlit tables, or add a dedicated visualization package?
- How much synthetic phishing/quishing data is acceptable for the academic report versus externally sourced datasets?
