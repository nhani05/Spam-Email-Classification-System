## 1. Package Skeleton And Compatibility Plan

- [x] 1.1 Create target package skeletons for `src/app`, `src/core`, `src/data`, `src/ml`, `src/workflows`, and `src/persistence` with package initializers.
- [x] 1.2 Add a short internal module map documenting old module ownership, target module ownership, and compatibility shim expectations.
- [x] 1.3 Add import smoke coverage that verifies the existing public module paths still import before deeper moves begin.

## 2. Core And Data Helpers

- [x] 2.1 Move logging/config/path helper ownership into `src/core` while preserving existing `src.config.config` and `src.utils.logger` imports.
- [x] 2.2 Move email parsing and dataset helper ownership into `src/data` while preserving existing `src.utils.email_utils` imports.
- [x] 2.3 Centralize artifact path terminology for bundled baseline artifacts, current runtime artifacts, and historical training runs without changing configured runtime paths.

## 3. ML And Model Lab Refactor

- [x] 3.1 Move model-lab evaluation and run-discovery utilities from `src.components.model_lab` into an ML-owned package with compatibility exports.
- [x] 3.2 Move baseline spam training data ingestion, transformation, and model training modules from `src.components` into ML-owned packages with compatibility exports.
- [x] 3.3 Split AI threat model runtime service and prediction dataclasses into `src.ml.threat_classifier.service` while preserving `src.security.ai_threat_model` imports.
- [x] 3.4 Split AI threat model training, datasets, feature transformers, labels, URL helpers, and evaluation code into ML-owned modules.
- [x] 3.5 Verify existing pickled artifacts still load or keep required compatibility classes available for old artifact module paths.

## 4. Workflow And Security Boundaries

- [x] 4.1 Move prediction orchestration into `src.workflows` while preserving `src.pipeline.prediction_pipeline` imports and return payloads.
- [x] 4.2 Move training orchestration into `src.workflows` while preserving `src.pipeline.training_pipeline` imports and CLI behavior.
- [x] 4.3 Keep `src.security` focused on URL analysis, QR analysis, email indicators, and campaign intelligence after ML code is extracted.

## 5. Persistence And Auth Boundaries

- [x] 5.1 Split user authentication persistence into `src.persistence.users` while preserving existing auth APIs.
- [x] 5.2 Split prediction history and metadata persistence into `src.persistence.predictions` while preserving existing auth module exports.
- [x] 5.3 Split feedback, review queue, retraining export, and campaign persistence into focused persistence modules with compatibility exports.

## 6. Streamlit App Structure

- [x] 6.1 Move reusable translation/rendering helpers from `app.py` into `src.app` modules without changing UI labels or payload formatting.
- [x] 6.2 Move tab/page handlers for single email, URL, QR, batch, history, and dashboard views into `src.app` modules while keeping `app.py` as the Streamlit entrypoint.
- [x] 6.3 Keep dashboard rendering import-compatible or update the app entrypoint to the new dashboard module path.

## 7. Documentation And Validation

- [x] 7.1 Update README/demo/docs references for the new source ownership and artifact terminology.
- [x] 7.2 Run import smoke checks for old and new module paths.
- [x] 7.3 Run existing AI threat model smoke checks and adaptive threat intelligence smoke checks.
- [x] 7.4 Run a lightweight Streamlit import/startup check or equivalent app-level smoke check.
- [x] 7.5 Review `git status` and confirm no historical outputs or unrelated user changes were removed or overwritten.
