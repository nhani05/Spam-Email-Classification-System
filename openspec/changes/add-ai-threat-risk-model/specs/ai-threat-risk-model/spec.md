## ADDED Requirements

### Requirement: AI-only email threat classification
The system SHALL train and use a supervised ML model as the only runtime source for email threat labels, risk scores, risk levels, and verdicts.

#### Scenario: Train email threat classifier
- **WHEN** the training workflow receives a dataset with email text and threat labels
- **THEN** the system trains an email threat classifier, saves model artifacts, saves feature artifacts, and records label taxonomy metadata

#### Scenario: Predict email threat label
- **WHEN** a user analyzes a single email and AI threat artifacts are available
- **THEN** the system returns an AI-model threat label, class scores, risk score, risk level, verdict, and model provenance metadata
- **AND** deterministic rule scores do not override, adjust, or replace those values

#### Scenario: Process MBOX with AI threat model
- **WHEN** the system processes an MBOX file and AI threat artifacts are available
- **THEN** each output row includes the AI-model threat label, class scores, risk score, risk level, verdict, and model provenance metadata
- **AND** no row receives a fallback rule-derived threat label, risk score, risk level, or verdict

### Requirement: AI-only URL phishing classification
The system SHALL train and use a supervised URL phishing classifier as the only runtime source for URL risk prediction.

#### Scenario: Train URL classifier
- **WHEN** the training workflow receives a URL dataset with labels
- **THEN** the system extracts URL lexical and domain features, trains a URL phishing classifier, saves artifacts, and records evaluation metrics

#### Scenario: Analyze URL with model
- **WHEN** a user submits a URL and URL model artifacts are available
- **THEN** the system returns AI-model phishing probability, URL risk level, URL verdict, and supporting feature evidence
- **AND** deterministic URL rules do not override, adjust, or replace the model result

#### Scenario: Analyze QR URL with model
- **WHEN** a decoded QR payload contains a URL and URL model artifacts are available
- **THEN** the system scores the decoded URL with the URL phishing classifier and includes the result in QR/quishing analysis

### Requirement: No rule-based runtime fallback
The system SHALL NOT use deterministic analyzers as runtime fallback scoring engines for email, URL, QR, or batch risk decisions.

#### Scenario: AI artifacts are available
- **WHEN** AI threat model artifacts load successfully
- **THEN** final threat labels, risk scores, risk levels, and verdicts are derived only from model predictions and calibrated probabilities

#### Scenario: AI artifacts are unavailable
- **WHEN** required AI threat model artifacts cannot be loaded
- **THEN** the system returns a model-unavailable state with model provenance metadata
- **AND** the system does not emit a rule-derived final threat label, risk score, risk level, or verdict

#### Scenario: Deterministic helpers are used
- **WHEN** deterministic helper code is retained for parsing, feature extraction, or evidence display
- **THEN** helper outputs are treated as non-decision inputs
- **AND** helper outputs cannot assign final labels, scores, levels, or verdicts

### Requirement: Threat dataset provenance tracking
The system SHALL record dataset identity and label provenance for threat-model training examples.

#### Scenario: Train with mixed data sources
- **WHEN** the training dataset contains imported, reviewed, and weak-labeled examples
- **THEN** the model metadata records source counts, label-source counts, weak-label counts, and dataset identity

#### Scenario: Evaluate weak labels separately
- **WHEN** evaluation data includes weak-labeled examples
- **THEN** the evaluation report distinguishes metrics computed on reviewed or external labels from metrics computed on weak labels

### Requirement: AI threat model evaluation
The system SHALL evaluate AI threat and URL models with metrics suitable for imbalanced security data.

#### Scenario: Evaluate multi-class threat model
- **WHEN** the threat classifier finishes training
- **THEN** the system saves per-class precision, per-class recall, per-class F1, macro F1, weighted F1, confusion matrix, and representative error cases

#### Scenario: Evaluate URL phishing model
- **WHEN** the URL phishing classifier finishes training
- **THEN** the system saves precision, recall, F1, ROC-AUC or PR-AUC when supported, confusion matrix, and threshold analysis

#### Scenario: Compare against baselines
- **WHEN** model lab outputs are generated
- **THEN** the system compares AI model performance against the existing binary spam/ham baseline and the rule-only risk baseline when baseline outputs are available

### Requirement: Stable prediction contract with AI-only provenance
The system SHALL preserve existing prediction response fields while adding provenance fields that identify AI-model scoring or model-unavailable states.

#### Scenario: Preserve existing response keys
- **WHEN** existing UI or history code reads prediction output
- **THEN** fields such as prediction, confidence, threat_label, risk_score, risk_level, verdict, reasons, recommended_actions, and class_scores remain available

#### Scenario: Expose provenance
- **WHEN** a prediction is produced
- **THEN** the response includes whether AI model mode or model-unavailable mode was used, plus model run id or artifact metadata when available
- **AND** provenance never reports rule-based fallback as the final risk source
