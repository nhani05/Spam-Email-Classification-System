---
name: mailguard-cook
description: Implement complete MailGuard AI features end to end. Use when Codex needs to build or modify Streamlit UI, ML prediction flows, threat aggregation, QR/email analysis, dashboard features, feedback capture, exports, or cohesive cross-module product functionality in this repository.
---

# MailGuard Cook

## Mission

Turn a feature request into working code while respecting the current Streamlit, scikit-learn, MySQL, and security-analyzer architecture.

## Implementation Loop

1. Inspect the relevant files with `rg --files` and targeted `Get-Content`.
2. Identify the contract that must stay stable:
   - `PredictionPipeline.predict_single_email`
   - threat analyzer result dataclasses
   - Streamlit session keys
   - DB helper functions
3. Make small, connected edits.
4. Add or update verification where risk justifies it.
5. Run the narrowest useful smoke check.

## Repository Contracts

- Guest mode must keep single email and QR analysis usable even when DB is unavailable.
- Authenticated-only features include dashboard, MBOX processing, saved history, and user-specific views.
- Model label mapping is `spam -> 0 -> Spam`, `ham -> 1 -> Ham`.
- Threat scoring should remain explainable through `reasons`.
- Do not open suspicious URLs or execute attachments during analysis.

## Common Feature Areas

- UI: `app.py`
- Prediction: `src/pipeline/prediction_pipeline.py`
- Training: `src/pipeline/training_pipeline.py`, `src/components/`
- Threats: `src/security/`
- Auth/history: `src/auth/auth.py`, `src/database/db.py`, `db/db.sql`
- Dashboard: `src/components/dashboard.py`

## Verification

Prefer direct checks before a full app run:

```powershell
python -c "from src.pipeline.prediction_pipeline import PredictionPipeline; print('ok')"
```

```powershell
python -c "from src.security.email_threat_analyzer import EmailThreatAnalyzer; print(EmailThreatAnalyzer().analyze('URGENT verify password at http://paypa1-login.xyz').to_dict())"
```

Run `streamlit run app.py` for UI behavior when feasible.
