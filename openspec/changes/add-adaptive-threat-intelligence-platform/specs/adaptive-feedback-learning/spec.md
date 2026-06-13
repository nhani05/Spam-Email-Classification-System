## ADDED Requirements

### Requirement: Prediction feedback capture
The system SHALL allow authenticated users to provide feedback on prediction results, including whether the result is correct, an optional corrected label, and an optional note.

#### Scenario: User marks prediction incorrect
- **WHEN** an authenticated user marks a prediction as incorrect and selects a corrected label
- **THEN** the system stores the feedback linked to the original prediction result and user

#### Scenario: Guest user feedback
- **WHEN** a guest user views a prediction result
- **THEN** the system does not persist feedback unless the user authenticates or the application explicitly supports anonymous feedback

### Requirement: Active-learning review queue
The system SHALL route low-confidence predictions, model-rule conflicts, high-risk ham predictions, and user-corrected predictions into a review queue.

#### Scenario: Low confidence case
- **WHEN** a prediction confidence falls below the configured review threshold
- **THEN** the system creates or updates a review queue item with the prediction, risk evidence, and reason for review

#### Scenario: High-risk ham conflict
- **WHEN** the ML model predicts Ham but the final risk score is High or Critical
- **THEN** the system adds the case to the review queue as a model-rule conflict

### Requirement: Feedback validation before retraining
The system SHALL keep feedback and reviewed labels separate from the training dataset until they are approved for retraining.

#### Scenario: Approved feedback item
- **WHEN** a reviewer approves a feedback item for retraining
- **THEN** the system marks the item as training-ready and records the approved label, reviewer, and timestamp

#### Scenario: Rejected feedback item
- **WHEN** a reviewer rejects a feedback item
- **THEN** the system keeps the original prediction history unchanged and excludes the item from retraining exports

### Requirement: Retraining dataset export
The system SHALL export approved feedback and reviewed samples into a retraining dataset format compatible with the model training pipeline.

#### Scenario: Export approved samples
- **WHEN** approved review items exist
- **THEN** the system exports their normalized text, threat label, optional binary spam label, indicators, and metadata needed for retraining

#### Scenario: No approved samples
- **WHEN** no reviewed samples are approved for retraining
- **THEN** the system reports that there is no adaptive learning data to export
