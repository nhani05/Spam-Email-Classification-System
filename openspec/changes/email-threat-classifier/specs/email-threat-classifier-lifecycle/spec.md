## ADDED Requirements

### Requirement: External dataset acquisition
The system SHALL support building email threat training data from external or reviewed data sources rather than seed-only CSV files.

#### Scenario: Import PhishFuzzer dataset
- **WHEN** the operator provides a local PhishFuzzer JSON dataset path
- **THEN** the system imports subject, body, sender, URL, attachment, class label, motivation, source, and provenance fields into the canonical email dataset

#### Scenario: Import phishing mbox corpus
- **WHEN** the operator provides a Nazario phishing mbox or equivalent phishing email corpus
- **THEN** the system parses each message into canonical email rows labeled as phishing-derived threat examples with source metadata

#### Scenario: Import ham and spam corpora
- **WHEN** the operator provides SpamAssassin or Enron corpus files
- **THEN** the system imports them as spam or safe examples according to the selected source mapping and records the source mapping in the dataset manifest

#### Scenario: Use offline source files
- **WHEN** network access is unavailable but local source files are present
- **THEN** the system can build the canonical dataset without attempting a network download

### Requirement: No seed-only production training
The system SHALL NOT train or publish production email threat classifier artifacts from seed-only datasets.

#### Scenario: Reject seed-only production run
- **WHEN** the production training workflow receives only `data/ai_threat/*_seed.csv` or fixture data
- **THEN** the system aborts before training and reports that external or reviewed training data is required

#### Scenario: Allow explicit smoke-test fixture run
- **WHEN** the operator runs a smoke-test command with an explicit fixture or smoke flag
- **THEN** the system may train against small fixture data without publishing those artifacts as production-current models

#### Scenario: Record non-seed artifact provenance
- **WHEN** the system saves a production model artifact
- **THEN** the artifact metadata records external and reviewed data source counts and confirms that the run was not seed-only

### Requirement: Canonical dataset normalization
The system SHALL normalize imported email and URL data into canonical schemas before feature extraction or training.

#### Scenario: Normalize email fields
- **WHEN** imported rows contain source-specific column names or message formats
- **THEN** the system maps them into canonical fields including subject, body, sender, reply-to, URLs, attachments, threat label, source, label source, weak-label flag, review status, and dataset version

#### Scenario: Clean message content
- **WHEN** imported messages contain HTML, MIME noise, malformed encoding, quoted replies, or duplicate whitespace
- **THEN** the system produces cleaned text suitable for feature extraction while preserving raw-source provenance

#### Scenario: Deduplicate examples
- **WHEN** multiple sources contain identical or near-identical messages
- **THEN** the system removes or marks duplicates before splitting train/test data and records duplicate counts in the manifest

#### Scenario: Validate required labels
- **WHEN** normalized rows are missing labels or contain unsupported labels
- **THEN** the system rejects or quarantines those rows and records validation errors

### Requirement: Feature engineering pipeline
The system SHALL build model features from canonical datasets using reproducible feature configuration.

#### Scenario: Build text features
- **WHEN** the training workflow receives normalized email examples
- **THEN** the system builds word and character n-gram text features from subject, body, sender, and reply-to fields

#### Scenario: Build security metadata features
- **WHEN** canonical rows include URLs, attachments, sender fields, or message metadata
- **THEN** the system builds numeric security features without using deterministic final rule scores as model labels or fallback verdicts

#### Scenario: Save feature configuration
- **WHEN** feature extraction completes for a training run
- **THEN** the system saves feature configuration and fitted feature artifacts with the model bundle

### Requirement: Model training lifecycle
The system SHALL train a supervised multi-class email threat classifier from canonical, provenance-tracked data.

#### Scenario: Train refreshed email threat model
- **WHEN** the operator runs the retraining workflow with valid canonical data
- **THEN** the system splits data reproducibly, trains candidate classifiers, selects the configured best model, and saves a versioned model bundle

#### Scenario: Handle class imbalance
- **WHEN** the training dataset has imbalanced threat labels
- **THEN** the system applies configured class weighting, stratified splitting when possible, and reports per-class support

#### Scenario: Store artifact schema version
- **WHEN** the model bundle is saved
- **THEN** the system includes artifact schema version, run id, dataset version, source counts, label counts, feature configuration, thresholds, and model type metadata

### Requirement: Model evaluation and publish gate
The system SHALL evaluate retrained artifacts before publishing them as current runtime models.

#### Scenario: Save evaluation reports
- **WHEN** a training run completes
- **THEN** the system saves per-class precision, recall, F1, macro F1, weighted F1, confusion matrix, source-level metrics, label-quality metrics, threshold analysis when available, and representative error cases

#### Scenario: Separate weak-label metrics
- **WHEN** weak, generated, synthetic, or bootstrap labels are included in a run
- **THEN** the system reports primary metrics on trusted labels separately from weak-label metrics

#### Scenario: Block publish on failed gate
- **WHEN** required evaluation gates fail or smoke checks fail
- **THEN** the system keeps the versioned run artifacts but does not copy them to `outputs/ai-threat-current/models/`

#### Scenario: Publish current artifacts
- **WHEN** evaluation gates and smoke checks pass
- **THEN** the system publishes the selected model and feature bundle to the configured current artifact paths and records the published run id

### Requirement: App integration contract
The system SHALL integrate the retrained email threat classifier into existing app flows without reintroducing rule-based fallback scoring.

#### Scenario: Single email prediction uses published model
- **WHEN** a user analyzes a single email and published artifacts are available
- **THEN** the app returns model-derived threat label, class scores, risk score, risk level, verdict, reasons, and provenance metadata

#### Scenario: Batch prediction uses published model
- **WHEN** the app processes an MBOX batch and published artifacts are available
- **THEN** each row includes model-derived threat fields and model provenance metadata

#### Scenario: Missing artifacts remain unavailable
- **WHEN** published artifacts are missing or incompatible
- **THEN** the app returns model-unavailable state and does not emit rule-derived final threat labels, risk scores, risk levels, or verdicts

### Requirement: Feedback retraining loop
The system SHALL support a reviewed feedback loop that can contribute corrected examples to future retraining runs.

#### Scenario: Export reviewed feedback
- **WHEN** users submit prediction feedback and reviewers approve corrected labels
- **THEN** the system exports reviewed feedback rows into the canonical training schema with feedback provenance

#### Scenario: Reject unreviewed feedback from training
- **WHEN** feedback rows are unreviewed or invalid
- **THEN** the retraining workflow excludes them from training and records exclusion counts

#### Scenario: Retrain with reviewed feedback
- **WHEN** reviewed feedback export is supplied to the retraining workflow
- **THEN** the system merges it with external data, deduplicates examples, records feedback source counts, and trains a new versioned model

### Requirement: Documentation and operator workflow
The system SHALL document and expose the full retraining workflow for local operators.

#### Scenario: Document data-to-model flow
- **WHEN** the change is implemented
- **THEN** README or project docs describe Data, Cleaning, Feature, Train, Evaluate, Save model, App integration, Feedback, and Retrain steps

#### Scenario: Show model and dataset provenance
- **WHEN** the app or model lab displays a trained model
- **THEN** it shows run id, dataset version, source counts, label counts, evaluation summary, and whether the model was trained from external/reviewed data
