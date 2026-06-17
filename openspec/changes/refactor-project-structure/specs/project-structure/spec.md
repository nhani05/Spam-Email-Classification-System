## ADDED Requirements

### Requirement: Source packages have clear ownership
The system SHALL organize source modules by primary responsibility so that application UI, workflow orchestration, ML training/inference, security analysis, persistence, data helpers, and core configuration/logging each have a clear package boundary.

#### Scenario: Developer locates ML training code
- **WHEN** a developer needs to update model training, feature engineering, label normalization, dataset normalization, or model evaluation code
- **THEN** the relevant implementation is located under an ML-owned package rather than under generic UI components or security analyzer modules

#### Scenario: Developer locates security analyzers
- **WHEN** a developer needs to update URL, QR, email indicator, or campaign investigation logic
- **THEN** the relevant implementation is located under a security-owned package that does not own supervised model training workflows

### Requirement: Refactor preserves public workflow behavior
The system SHALL preserve existing user-facing workflows, script entrypoints, prediction result keys, URL analysis result shape, QR analysis result shape, and database interactions during the project-structure refactor.

#### Scenario: Existing prediction flow after refactor
- **WHEN** the application analyzes a single email with the same configured artifacts
- **THEN** the result includes the existing public keys such as `prediction`, `confidence`, `threat_label`, `class_scores`, `risk_score`, `risk_level`, `verdict`, `reasons`, `recommended_actions`, `ai_threat_analysis`, and `model_provenance`

#### Scenario: Existing scripts after refactor
- **WHEN** a developer runs the existing training and smoke scripts from `scripts/`
- **THEN** the scripts continue to import the required APIs and exercise the same workflow responsibilities

### Requirement: Compatibility imports remain available during migration
The system SHALL keep compatibility imports available for previously public modules until all runtime code, scripts, and pickled model artifact compatibility concerns have been addressed.

#### Scenario: Legacy AI threat import
- **WHEN** code imports `AIThreatModelService` or `train_ai_threat_models` from the previous AI threat module path
- **THEN** the import resolves to the refactored implementation or a compatibility delegation without changing caller behavior

#### Scenario: Legacy component import
- **WHEN** code imports existing model-lab, data transformation, model training, dashboard, pipeline, or auth functions from their previous module paths
- **THEN** the import continues to work or fails with an intentional migration error documented by the refactor tasks

### Requirement: Artifact ownership is explicit
The system SHALL distinguish bundled baseline model artifacts, current runtime model artifacts, and historical training-run artifacts through configuration names, docs, or path helper APIs.

#### Scenario: Runtime artifact path lookup
- **WHEN** prediction code loads spam, email threat, or URL phishing artifacts
- **THEN** the loaded paths are resolved through explicit configuration or path helpers rather than hard-coded ad hoc locations in workflow code

#### Scenario: Historical training output
- **WHEN** training code writes a new model run
- **THEN** generated models, observations, and metadata are written under a historical run directory without deleting bundled baseline or current runtime artifacts

### Requirement: Refactor includes validation coverage
The system SHALL include smoke or import validation covering the affected package boundaries before the refactor is considered complete.

#### Scenario: Validation after module moves
- **WHEN** module files are moved or compatibility shims are introduced
- **THEN** validation confirms that core imports, single-email prediction setup, URL analysis, QR analysis, AI threat service loading, and training script imports still work

#### Scenario: Missing artifact behavior after refactor
- **WHEN** configured AI model artifacts are missing or unavailable
- **THEN** the system preserves the existing model-unavailable behavior instead of falling back to rule-derived final risk scoring
