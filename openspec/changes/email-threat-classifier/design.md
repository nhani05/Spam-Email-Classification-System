## Context

The repository already has an AI-only runtime contract for email and URL threat scoring. The current implementation exposes `src/ml/threat_classifier/` modules, `scripts/train_ai_threat_models.py`, config paths for current model artifacts, and model-unavailable behavior when artifacts are missing. However, the training side still points at `data/ai_threat/email_threat_seed.csv` and `data/ai_threat/url_threat_seed.csv`, and several modules are compatibility wrappers around a large legacy implementation.

The refactor should turn the email threat classifier into a repeatable ML lifecycle. The production training source must be assembled from external datasets and reviewed feedback, not from hard-coded seed rows. Seed files may remain only as tiny smoke-test fixtures or examples, never as authoritative production training data.

## Goals / Non-Goals

**Goals:**

- Build an explicit data-to-model lifecycle: acquire external data, normalize, clean, engineer features, train, evaluate, save artifacts, publish current artifacts, integrate with app runtime, capture feedback, and retrain.
- Support local-file imports first, with optional downloader helpers for public sources when network access is available.
- Produce canonical datasets with schema validation, source manifests, checksums, label provenance, and weak-label flags.
- Retrain the email threat classifier from refreshed data and publish versioned artifacts to the existing runtime paths.
- Preserve AI-only runtime behavior: missing models produce model-unavailable states, not rule-derived fallbacks.
- Refactor `src/ml/threat_classifier/` into clear modules rather than compatibility wrappers around `legacy.py`.
- Make evaluation defensible for imbalanced security labels using per-class metrics, macro/weighted F1, confusion matrices, source breakdowns, weak-label separation, and error analysis.
- Let reviewed user feedback enter retraining only after validation and provenance tagging.

**Non-Goals:**

- Building a GPU/transformer-first training stack.
- Guaranteeing high-quality malware or BEC detection without enough labeled examples.
- Shipping API keys or automatically downloading restricted datasets without user configuration.
- Using runtime deterministic rule scores as labels, final verdicts, or fallback risk decisions.
- Replacing the existing binary spam/ham baseline unless needed for comparison reports.

## Decisions

### Decision 1: Treat dataset acquisition as a first-class pipeline stage

Add dataset source definitions and importers for public/local sources such as PhishFuzzer JSON, Nazario mbox phishing corpora, SpamAssassin ham/spam archives, Enron ham maildir, PhishTank URL exports, and URLhaus URL exports. Each importer writes raw files under a raw data area and normalized rows under a canonical area.

Alternatives considered:

- Keep editing `email_threat_seed.csv`: simple, but it does not satisfy the no-seed retraining requirement.
- Download directly during training: convenient, but fragile and hard to reproduce.

### Decision 2: Canonical schema separates raw content, labels, and provenance

Use a canonical email dataset with fields such as `message_id`, `subject`, `body`, `sender`, `reply_to`, `urls`, `attachments`, `threat_label`, `source`, `source_split`, `label_source`, `is_weak_label`, `review_status`, `created_at`, and `dataset_version`. URL datasets use `url`, `label`, `source`, `label_source`, `is_weak_label`, and timestamp/provenance fields.

Alternatives considered:

- Train directly from each source schema: faster initially, but creates repeated parsing and inconsistent labels.
- Store only `text,label`: easier for sklearn, but loses auditability and source-specific evaluation.

### Decision 3: No-seed production policy with smoke-test exceptions

Production training commands must reject seed-only datasets unless an explicit smoke-test flag is used. Tiny fixtures may stay in the repo for tests, but release artifacts must record that they were trained from external/reviewed data.

Alternatives considered:

- Delete all seed files immediately: cleaner, but may break smoke tests and demos.
- Allow seed fallback silently: rejected because it violates the requested refactor.

### Decision 4: Keep sklearn-first model training but make it replaceable

The first retrained classifier should keep the existing sklearn-compatible stack: TF-IDF word/char features plus numeric security features and calibrated/logistic classifiers. The module boundaries should make a transformer implementation possible later without rewriting acquisition, cleaning, evaluation, artifact publishing, or app integration.

Alternatives considered:

- Fine-tune a transformer first: stronger NLP potential, but heavier and riskier for local Streamlit use.
- Keep all logic inside `legacy.py`: fastest path but blocks maintainable lifecycle work.

### Decision 5: Evaluation must separate trusted and weak labels

Primary metrics are computed on external/reviewed labels. Weak, synthetic, generated, or bootstrap labels are reported separately and can help training only when explicitly enabled. Reports include source-level and label-quality breakdowns so model quality claims are defensible.

Alternatives considered:

- Mix all data and report one score: easy, but hides label quality problems.
- Ban weak labels entirely: conservative, but may limit coverage for rare classes.

### Decision 6: Feedback enters retraining through review and export

User feedback must be reviewed, normalized, deduplicated, and exported before it can become training data. The retraining pipeline records feedback counts, review status, and label-source metadata.

Alternatives considered:

- Train directly on every feedback row: faster, but vulnerable to noisy labels and poisoning.
- Ignore feedback for now: misses the requested feedback -> retrain loop.

## Risks / Trade-offs

- Public datasets are old or imbalanced -> Use multiple sources, source-level metrics, class weights, and per-class recall targets.
- Dataset licenses or availability change -> Support local-file import paths and record source URLs/version notes in manifests.
- Some classes lack enough examples -> Allow label merging or mark low-support classes as experimental in metadata.
- Downloading data may fail in restricted environments -> Separate optional download from required import/normalize steps.
- Weak labels can inflate metrics -> Exclude weak labels from primary evaluation and show separate weak-label metrics.
- Refactoring wrappers can break pickle compatibility -> Preserve compatibility import paths or provide migration shims until old artifacts are replaced.
- New artifacts may be incompatible with current runtime -> Add artifact schema version and smoke checks before publishing to `outputs/ai-threat-current/`.

## Migration Plan

1. Add dataset source config and raw/canonical directory layout.
2. Implement importers for local PhishFuzzer JSON, Nazario mbox, SpamAssassin archives, Enron maildir, PhishTank CSV/JSON, and URLhaus CSV inputs.
3. Add cleaning, normalization, deduplication, label mapping, and manifest generation.
4. Refactor `src/ml/threat_classifier/legacy.py` into focused modules while preserving public imports needed by existing scripts and artifacts.
5. Update the training script to run acquire/import -> clean -> feature -> train -> evaluate -> save -> publish.
6. Train a new model from external/reviewed data and publish it to configured current artifact paths only after smoke checks pass.
7. Update Streamlit/model-lab UI and docs to expose dataset provenance, model version, and retraining workflow.
8. Add reviewed-feedback export and merge it into the next training run with provenance metadata.
9. Roll back by restoring previous configured model artifact paths; do not restore rule-based fallback scoring.

## Open Questions

- Which external sources are available locally for the first training run, and which require manual download by the operator?
- Should low-support labels such as Quishing or Business Email Compromise be merged for the first retrained model or kept as experimental classes?
- What minimum per-class support should block publishing a production artifact?
- Should URL model retraining remain part of the same command or split into a separate lifecycle after email refactor is complete?
