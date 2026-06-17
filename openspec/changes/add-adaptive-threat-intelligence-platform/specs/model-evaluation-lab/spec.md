## ADDED Requirements

### Requirement: Repeatable model experiment runs
The system SHALL provide a model evaluation workflow that records dataset identity, feature configuration, model configuration, training timestamp, selected model, artifact paths, and metric outputs for each run.

#### Scenario: Train new benchmark run
- **WHEN** the training pipeline completes a benchmark run
- **THEN** the system saves model artifacts, feature artifacts, metrics, and run metadata in a versioned output directory

#### Scenario: Compare previous runs
- **WHEN** model lab data contains multiple completed runs
- **THEN** the system can display or export a comparison of runs by model name, dataset identity, feature configuration, and selected metrics

### Requirement: Imbalance-aware metrics
The system SHALL report metrics that are suitable for imbalanced spam and threat data, including per-class precision, per-class recall, per-class F1, macro F1, weighted F1, confusion matrix, ROC-AUC when supported, and PR-AUC when supported.

#### Scenario: Evaluate imbalanced dataset
- **WHEN** the dataset has substantially more safe or ham examples than malicious examples
- **THEN** the evaluation report includes per-class and macro metrics rather than relying only on accuracy

#### Scenario: Unsupported probability metrics
- **WHEN** a trained model cannot produce probability or decision scores needed for ROC-AUC or PR-AUC
- **THEN** the system marks those metrics as unavailable instead of failing the entire evaluation run

### Requirement: Threshold tuning and calibration
The system SHALL support threshold analysis for spam and threat classes and record selected thresholds used for final verdict decisions.

#### Scenario: Tune threshold for phishing recall
- **WHEN** the user selects a higher-sensitivity profile for phishing detection
- **THEN** the model lab reports the resulting precision, recall, F1, false positives, and false negatives for that threshold

#### Scenario: Persist calibrated model metadata
- **WHEN** a model is calibrated or threshold-tuned
- **THEN** the selected calibration method and threshold values are stored with the model run metadata

### Requirement: Error analysis report
The system SHALL generate an error analysis view that summarizes false positives, false negatives, low-confidence predictions, and model-rule conflicts.

#### Scenario: Review false negatives
- **WHEN** evaluation results contain malicious samples predicted as safe or ham
- **THEN** the report lists representative false negatives with text preview, expected label, predicted label, confidence, and detected indicators

#### Scenario: Review conflict cases
- **WHEN** ML prediction and rule-based threat analysis disagree during evaluation
- **THEN** the report groups those cases separately for analyst review
