---
name: mailguard-fix
description: Debug and fix MailGuard AI defects. Use when Codex needs to investigate errors, broken Streamlit behavior, model loading failures, DB/auth bugs, MBOX processing issues, QR/security analyzer failures, encoding problems, or failing smoke checks in this repository.
---

# MailGuard Fix

## Mission

Find the smallest correct fix for a real defect, then verify the affected path.

## Triage Order

1. Reproduce or inspect the failing path.
2. Read the files closest to the error.
3. Identify whether the issue is configuration, dependency, data shape, model artifact, DB schema, or code logic.
4. Patch only the relevant surface.
5. Run a targeted check and report residual risk.

## Frequent Failure Points

- `Config.model_path` or `Config.feature_path` points to missing `outputs/...` artifacts.
- Pickled model and vectorizer come from different training runs.
- MySQL is unavailable, but guest mode should still work.
- `User.password VARCHAR(12)` is too short for hashed passwords.
- MBOX DataFrame columns changed but `app.py` still expects `Time`, `Subject`, `Prediction`.
- SVM may lack `predict_proba`, so `confidence` must stay optional.
- Streamlit cache can hide load-time changes until restart/cache clear.

## Safe Fix Rules

- Preserve guest access to single email and QR checks.
- Preserve parameterized SQL.
- Do not reverse the spam/ham label mapping accidentally.
- Do not fetch or open suspicious URLs as part of a fix.
- Do not overwrite user changes outside the failing area.

## Verification Examples

```powershell
python -c "from src.database.db import ping; print(ping())"
```

```powershell
python -c "from src.pipeline.prediction_pipeline import PredictionPipeline; p=PredictionPipeline(load_models=False); print('ok')"
```

```powershell
python -c "from src.security.url_risk_model import URLRiskModel; print(URLRiskModel().analyze('http://paypa1-login.xyz/reset').to_dict())"
```
