## 1. Data Source Layout and Configuration

- [x] 1.1 Define raw, interim, canonical, manifest, and feedback data directories for email threat classifier training.
- [x] 1.2 Add dataset source configuration for PhishFuzzer JSON, Nazario mbox, SpamAssassin archives, Enron maildir, PhishTank exports, URLhaus exports, and reviewed feedback exports.
- [x] 1.3 Add config fields for canonical email dataset path, canonical URL dataset path, dataset manifest path, publish gate settings, and smoke-test fixture mode.
- [x] 1.4 Document which dataset sources are local-file only and which optional helpers may download public data when network access is available.
- [x] 1.5 Mark existing `data/ai_threat/*_seed.csv` files as fixture/smoke data rather than production training data.

## 2. External Dataset Importers

- [x] 2.1 Implement a PhishFuzzer importer that reads original and rephrased JSON files into canonical email rows with subject, body, sender, URL, attachment, type, motivation, and provenance fields.
- [x] 2.2 Implement a Nazario mbox importer that parses phishing messages, extracts subject/body/sender/reply-to/URLs/attachments, and maps rows to phishing-derived labels.
- [x] 2.3 Implement a SpamAssassin importer that reads ham/spam archives or extracted folders and maps rows to Safe or Spam labels with source metadata.
- [x] 2.4 Implement an Enron importer that reads maildir-style messages and maps rows to Safe labels with privacy/provenance metadata.
- [x] 2.5 Implement PhishTank export import for URL labels and optional email URL feature enrichment.
- [x] 2.6 Implement URLhaus export import for malware/suspicious URL labels and optional email URL feature enrichment.
- [x] 2.7 Add source manifest generation with source name, input path, file size, checksum, imported row count, label mapping, import timestamp, and operator notes.
- [x] 2.8 Add CLI entry points or script arguments to import each source independently without running model training.

## 3. Canonical Cleaning and Normalization

- [x] 3.1 Create canonical email and URL schema definitions with required columns, optional columns, accepted labels, and validation rules.
- [x] 3.2 Implement MIME, HTML, malformed encoding, duplicate whitespace, and quoted-reply cleaning for email body text.
- [x] 3.3 Normalize sender, reply-to, URL list, attachment list, subject, and body fields into stable string/list representations.
- [x] 3.4 Map source-specific labels into the project taxonomy: Safe, Spam, Phishing, Malware Risk, Credential Theft, Payment Scam, Quishing, and Business Email Compromise.
- [x] 3.5 Add weak-label and label-source tagging for generated, synthetic, bootstrap, inferred, external, curated, and reviewed labels.
- [x] 3.6 Add deduplication by message hash and near-duplicate text hash before train/test split.
- [x] 3.7 Quarantine invalid rows with missing text, missing labels, unsupported labels, invalid URLs, or schema errors.
- [x] 3.8 Save canonical datasets and validation reports showing accepted rows, rejected rows, duplicate counts, source counts, and label counts.

## 4. Threat Classifier Module Refactor

- [x] 4.1 Split `src/ml/threat_classifier/legacy.py` into focused modules for schema, importers, cleaning, datasets, features, training, evaluation, artifact publishing, and service loading.
- [x] 4.2 Keep compatibility exports in existing module paths so current scripts and old imports continue to run during migration.
- [x] 4.3 Remove production training dependencies on seed CSV paths from default threat classifier workflow.
- [x] 4.4 Add explicit errors when production training is attempted with seed-only or fixture-only data.
- [x] 4.5 Add artifact schema version constants and validation helpers for saved model bundles.
- [x] 4.6 Ensure deterministic analyzer outputs can be used only as non-decision features/evidence and cannot become labels or fallback verdicts.

## 5. Feature Engineering

- [x] 5.1 Build reproducible word TF-IDF and character n-gram feature pipelines over subject, body, sender, and reply-to fields.
- [x] 5.2 Build numeric security metadata features for URL count, suspicious attachment names, sender/reply-to mismatch, credential terms, payment terms, urgency terms, brand/domain indicators, and message length.
- [x] 5.3 Ensure feature extraction does not include final rule scores, rule verdicts, or runtime fallback labels.
- [x] 5.4 Save fitted feature artifacts with feature configuration, feature version, and training run metadata.
- [x] 5.5 Add unit or smoke checks for feature extraction on safe, spam, phishing, malware-risk, payment-scam, and credential-theft examples.

## 6. Training Workflow

- [x] 6.1 Refactor `scripts/train_ai_threat_models.py` so it can run import, clean, feature, train, evaluate, save, publish, and feedback-merge stages separately or end-to-end.
- [x] 6.2 Add a production retraining command that uses canonical external/reviewed data and rejects seed-only inputs.
- [x] 6.3 Add an explicit fixture/smoke command that can train on tiny fixture data without publishing production artifacts.
- [x] 6.4 Train candidate sklearn-compatible classifiers with class weighting and stratified splitting when class counts allow it.
- [x] 6.5 Select the best model using configured primary metric such as macro F1 with per-class recall guardrails.
- [x] 6.6 Save versioned model bundles under `outputs/<run-id>/models/` with model, features, labels, thresholds, schema version, dataset manifest, and run metadata.
- [x] 6.7 Preserve URL classifier training or split it into a clearly named stage so email retraining can run independently when needed.

## 7. Evaluation and Publish Gates

- [x] 7.1 Save per-class precision, recall, F1, support, macro F1, weighted F1, and confusion matrix for the email threat classifier.
- [x] 7.2 Save metrics broken down by data source, source split, label source, weak-label flag, and reviewed feedback source.
- [x] 7.3 Save error analysis for false positives, false negatives, low-confidence predictions, and high-risk misses.
- [x] 7.4 Exclude weak, generated, synthetic, or bootstrap labels from primary evaluation unless an explicit option includes them.
- [x] 7.5 Add publish gates for minimum dataset size, minimum per-class support, macro F1 threshold, required class recall threshold, and successful smoke predictions.
- [x] 7.6 Copy artifacts to `outputs/ai-threat-current/models/` only after publish gates pass.
- [x] 7.7 Save a published-run marker that records current run id, source dataset version, artifact paths, and publish timestamp.

## 8. Runtime App Integration

- [x] 8.1 Update config loading to point runtime email threat scoring at the published current artifact paths.
- [x] 8.2 Update prediction service loading to validate artifact schema version and return model-unavailable for missing or incompatible artifacts.
- [x] 8.3 Verify single-email analysis returns model-derived threat label, class scores, risk score, risk level, verdict, reasons, and provenance metadata.
- [x] 8.4 Verify MBOX batch analysis returns model-derived threat fields or model-unavailable states for every row.
- [x] 8.5 Ensure no Streamlit page, pipeline, URL/QR path, dashboard, or history flow reintroduces rule-based final threat fallback.
- [x] 8.6 Show model run id, dataset version, source counts, label counts, and evaluation summary in model lab or admin-facing UI.

## 9. Feedback to Retraining Loop

- [x] 9.1 Add or update feedback export logic so approved corrections are written in the canonical email training schema.
- [x] 9.2 Exclude unreviewed, rejected, or malformed feedback rows from retraining and record exclusion counts.
- [x] 9.3 Add deduplication between feedback examples and external datasets before training.
- [x] 9.4 Record feedback examples with `source=reviewed_feedback`, reviewer status, label source, timestamp, and optional original prediction metadata.
- [x] 9.5 Add retraining command options to merge reviewed feedback exports with external canonical datasets.
- [x] 9.6 Add smoke checks proving reviewed feedback can change a subsequent canonical dataset version without directly poisoning current artifacts.

## 10. Documentation and Operator Workflow

- [x] 10.1 Update README with the full AI model lifecycle: Data, Cleaning, Feature, Train, Evaluate, Save model, App integration, Feedback, and Retrain.
- [x] 10.2 Add dataset source setup instructions for PhishFuzzer, Nazario, SpamAssassin, Enron, PhishTank, and URLhaus local imports.
- [x] 10.3 Document the no-seed production training policy and the difference between fixture/smoke data and production data.
- [x] 10.4 Update adaptive threat intelligence docs to reflect the refactored lifecycle and AI-only runtime contract.
- [x] 10.5 Update demo docs with a retraining narrative and expected model provenance outputs.

## 11. Verification

- [x] 11.1 Run `python -m compileall src app.py scripts`.
- [x] 11.2 Run importer smoke checks against small local fixtures for PhishFuzzer, mbox, ham/spam, and URL exports.
- [x] 11.3 Run canonical validation smoke checks and confirm invalid rows are quarantined.
- [x] 11.4 Run fixture-mode training and confirm artifacts are not published as production-current models.
- [x] 11.5 Run production-mode training against external/reviewed canonical data and confirm seed-only input is rejected.
- [x] 11.6 Run model evaluation and confirm reports include per-class, source-level, label-quality, and error-analysis outputs.
- [x] 11.7 Run publish-gate checks and confirm only passing artifacts are copied to current runtime paths.
- [x] 11.8 Run single-email prediction smoke checks and verify `risk_source=ai_model` with valid artifacts.
- [x] 11.9 Run missing-artifact smoke checks and verify `model_unavailable` without rule-derived verdicts.
- [x] 11.10 Run MBOX batch smoke checks and verify every row uses model-derived fields or model-unavailable states.
- [x] 11.11 Run feedback export and retraining merge smoke checks.
- [x] 11.12 Inspect `git diff` to confirm no unrelated user changes were reverted.


