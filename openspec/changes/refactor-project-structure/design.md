## Context

The current repository has a working Streamlit application for single-email analysis, URL phishing analysis, QR/quishing checks, batch MBOX processing, history, dashboards, AI threat scoring, model training, and smoke scripts. The source layout no longer communicates those responsibilities clearly:

- `src/components` mixes training pipeline steps, model-lab utilities, and dashboard UI.
- `src/security` mixes rule/security analyzers with AI model training, dataset normalization, feature transformers, runtime inference, labels, metrics, and artifact writing.
- `src/auth/auth.py` handles authentication plus prediction history, feedback, review queue, and campaign persistence.
- `app.py` contains Streamlit routing and most view logic in one file.
- Model artifacts live under both `data/models/v1` and multiple `outputs/.../models` directories, while current runtime AI artifacts use `outputs/ai-threat-current`.

The refactor must respect existing user-facing behavior and the recent AI-only runtime scoring decision. It should make ownership clearer without changing prediction payloads, training commands, database behavior, or demo workflows.

## Goals / Non-Goals

**Goals:**

- Establish package boundaries that make source ownership obvious.
- Move ML-specific code out of generic `components` and security analyzer modules.
- Keep security analyzers focused on evidence extraction, URL/QR analysis, and campaign intelligence.
- Split persistence code by concern while preserving current database interactions.
- Keep scripts and public imports working through compatibility shims during migration.
- Standardize artifact terminology for bundled baseline models, current runtime artifacts, and historical training runs.
- Add smoke validation so refactor regressions are caught quickly.

**Non-Goals:**

- Change model algorithms, risk thresholds, labels, or AI-only scoring behavior.
- Redesign the Streamlit UI visually.
- Change database schema or migrate stored data.
- Delete historical output runs.
- Introduce new framework dependencies or package managers.
- Archive previous completed OpenSpec changes.

## Decisions

### Decision 1: Refactor by ownership layers, not by feature tabs

Target package ownership:

```text
src/
  app/              Streamlit page/view helpers
  core/             config, paths, logging
  data/             email parsing, dataset loading, schema helpers
  ml/               model training, inference, features, labels, evaluation
  security/         URL/QR/email indicator analyzers and campaign intelligence
  workflows/        user-facing orchestration for predictions, analysis, training
  persistence/      database access by domain concern
```

Rationale: feature-tab organization would duplicate shared ML/security/persistence logic. Ownership layers make it clearer where a new model, analyzer, or persistence function belongs.

Alternative considered: keep the current folders and only rename files. This would reduce import churn but would not solve the mixed responsibilities.

### Decision 2: Preserve old imports with shims during the first migration

Existing modules such as `src.security.ai_threat_model`, `src.components.model_lab`, `src.components.data_transformation`, `src.components.model_training`, and `src.auth.auth` should initially re-export or delegate to new modules where practical.

Rationale: the app, scripts, notebooks, docs, and smoke checks rely on these imports. Compatibility shims let the refactor proceed in smaller steps and make behavior preservation easier to test.

Alternative considered: update every import at once and remove old modules. This is cleaner long-term but creates a larger breakage surface.

### Decision 3: Move AI threat model code into ML subpackages

The current `src/security/ai_threat_model.py` should be decomposed into:

```text
src/ml/threat_classifier/
  service.py        AIThreatModelService and runtime prediction dataclasses
  training.py       train_ai_threat_models and artifact writing
  features.py       email feature pipeline and transformers
  datasets.py       dataset loading and normalization
  labels.py         label normalization and risk/verdict mapping
  evaluation.py     metrics, error rows, threshold helpers

src/ml/url_classifier/
  features.py       URL lexical/domain feature extraction
  labels.py         URL label normalization and verdict helpers
```

Rationale: the security package should not own model training or dataset normalization. ML packages can still reuse security constants and parsing helpers when they are non-decision evidence.

Alternative considered: create one `src/models` package. The name is too broad and can be confused with binary artifact files.

### Decision 4: Treat artifacts as a runtime contract

Keep existing configured paths working, but document and gradually normalize artifact categories:

- Bundled baseline artifacts: checked-in fallback artifacts, currently `data/models/v1`.
- Current runtime artifacts: paths loaded by config, currently including `outputs/ai-threat-current`.
- Historical run artifacts: timestamped training outputs under `outputs/<run-id>/`.

Rationale: changing physical artifact locations immediately risks breaking demos and user-local paths. The first refactor should centralize path naming/configuration before moving or deleting artifact files.

Alternative considered: move all artifacts immediately into a new `artifacts/` directory. This is clearer but unsafe while config and docs still reference `outputs/`.

### Decision 5: Separate persistence concerns without schema migration

Split functions from `src/auth/auth.py` into persistence modules by concern:

```text
src/persistence/
  users.py
  predictions.py
  feedback.py
  campaigns.py
```

The original auth module can continue to export the same functions while delegating to the new modules.

Rationale: auth should not be the main interface for history, feedback, and campaign data. Avoiding schema changes keeps the refactor focused.

Alternative considered: redesign the persistence layer with repositories and models. That is heavier than needed for this change.

## Risks / Trade-offs

- Import cycles after moving modules -> Move leaf utilities first, keep compatibility shims thin, and run import/smoke checks after each phase.
- Pickled sklearn artifacts may reference old module paths -> Keep old classes importable through shims until artifacts are retrained or migration compatibility is verified.
- Refactor could silently alter prediction payloads -> Add smoke checks for single email, URL analysis, QR analysis, batch prediction, and AI model service availability states.
- Documentation may drift from actual paths -> Update README/demo docs in the same task group that changes config/path terminology.
- User-local generated outputs may differ from tracked files -> Do not delete historical `outputs/` runs; only standardize code and config expectations.

## Migration Plan

1. Add new package skeletons and compatibility exports without moving behavior.
2. Extract model-lab and baseline spam training modules out of `src/components`.
3. Decompose AI threat model code into `src/ml/threat_classifier` and URL feature/label helpers.
4. Move prediction/training orchestration into `src/workflows` while keeping `src/pipeline` imports working.
5. Split persistence functions out of `src/auth/auth.py` while keeping old exports.
6. Move Streamlit view helpers into `src/app` and keep `app.py` as the entrypoint.
7. Centralize path/config naming and update docs.
8. Run smoke scripts and import checks; only then remove or deprecate redundant compatibility code in a later change.

Rollback strategy: because the first migration keeps compatibility modules, rollback can be done by pointing imports back to the old modules or reverting the compatibility delegation without changing persisted data or artifacts.

## Open Questions

- Should the physical artifact root remain `outputs/` permanently, or should a later change introduce `artifacts/` after docs and config are stable?
- Should compatibility shims be removed in this change or explicitly left for a follow-up cleanup after retraining pickled artifacts?
- Should the Streamlit page split happen in this change, or should this change focus on backend/model/persistence structure first?
