## Why

The project structure has grown around individual features instead of clear ownership boundaries, making model code, security analyzers, UI, persistence, and generated artifacts hard to locate and reason about. This refactor is needed now because recent AI threat-model and adaptive intelligence work added large cross-cutting modules that make future feature work and debugging slower.

## What Changes

- Reorganize source modules around stable responsibilities: application UI, workflows, ML training/inference, security analysis, persistence, data helpers, and core configuration/logging.
- Split overloaded modules, especially the AI threat model implementation, into smaller files for service/runtime inference, training, feature engineering, dataset normalization, labels, and evaluation helpers.
- Move training-oriented components out of the generic `components` package and keep Streamlit/dashboard UI code separate from ML/model-lab code.
- Separate authentication from prediction history, feedback, review queue, and campaign persistence concerns.
- Standardize model/data artifact ownership so bundled baseline models, current runtime models, and historical training runs have explicit locations and config names.
- Preserve existing user-facing workflows, public return keys, scripts, and smoke-test behavior during the refactor.
- Add compatibility shims where needed so existing imports continue to work during migration.

## Capabilities

### New Capabilities
- `project-structure`: Defines the target package boundaries, artifact layout, compatibility expectations, and validation requirements for project organization.

### Modified Capabilities
None.

## Impact

- Affected source areas: `app.py`, `src/components`, `src/pipeline`, `src/security`, `src/auth`, `src/database`, `src/utils`, `src/config`, and scripts under `scripts/`.
- Affected artifacts: model paths in `src/config/config.py`, bundled model files under `data/models/v1`, generated runs under `outputs/`, and current AI threat artifacts under `outputs/ai-threat-current`.
- Affected documentation: README/demo/setup notes that mention model paths, source folders, training scripts, or generated output locations.
- No new third-party runtime dependencies are expected.
- The refactor must not intentionally change prediction labels, risk payload keys, URL/QR analysis outputs, database schema behavior, or training CLI behavior.
