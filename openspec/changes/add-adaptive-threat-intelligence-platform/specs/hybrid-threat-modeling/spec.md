## ADDED Requirements

### Requirement: Multi-source email feature extraction
The system SHALL transform each email analysis request into a structured feature record that includes text, URL, QR, attachment, sender/header, and rule-derived security signals when those inputs are available.

#### Scenario: Analyze pasted email with URL
- **WHEN** a user submits a single email that contains text and at least one URL
- **THEN** the system produces a feature record containing normalized text features, URL features, rule-based threat scores, extracted indicators, and missing-value markers for unavailable QR or header fields

#### Scenario: Analyze MBOX email with headers
- **WHEN** the system processes an MBOX message with sender, recipients, subject, date, labels, and body
- **THEN** the system includes available metadata and header-derived signals in the feature record without discarding the current batch output columns

### Requirement: Multi-class threat taxonomy
The system SHALL support threat taxonomy labels beyond binary spam/ham, including Safe, Spam, Phishing, Malware Risk, Business Email Compromise, Quishing, Credential Theft, and Payment Scam.

#### Scenario: Phishing URL detected in ham-like text
- **WHEN** the text classifier predicts a low-spam message but URL and credential signals are high risk
- **THEN** the final threat label includes a phishing-oriented verdict instead of reporting only Ham

#### Scenario: QR payment payload detected
- **WHEN** a QR payload contains payment information from an unexpected email image
- **THEN** the system classifies the case as Payment Scam or Quishing risk when other risk signals meet configured thresholds

### Requirement: Calibrated hybrid prediction output
The system SHALL return a calibrated prediction package containing model label, model confidence, per-class scores when available, risk score, risk level, final verdict, reasons, recommended actions, and component scores.

#### Scenario: Single email prediction response
- **WHEN** a single email is analyzed
- **THEN** the result includes the existing prediction and confidence fields plus calibrated threat classification fields and explainable component scores

#### Scenario: Batch prediction response
- **WHEN** an MBOX file is processed
- **THEN** each output row includes prediction, confidence, risk score, risk level, verdict, primary threat label, reasons, and recommended actions

### Requirement: Explainable fusion of ML and rules
The system SHALL combine ML outputs with rule-based security signals through an explicit risk fusion layer that preserves evidence from each component.

#### Scenario: Model-rule conflict
- **WHEN** the ML model predicts Ham with high confidence but rule-based URL, QR, or malware indicators are high risk
- **THEN** the final risk score is elevated and the reasons list explains the conflict

#### Scenario: Low risk agreement
- **WHEN** both the ML model and rule-based analyzers produce low-risk signals
- **THEN** the final verdict remains low risk and the reasons list states that no strong threat indicators were found
