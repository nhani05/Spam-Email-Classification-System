---
name: mailguard-scout
description: Explore and map MailGuard AI repository context. Use when Codex needs to understand unfamiliar code, locate relevant files, summarize architecture, inspect data/model/auth/security flows, or gather evidence before planning or editing the Spam Email Classification System.
---

# MailGuard Scout

## Mission

Gather just enough repository context to act accurately.

## First Commands

```powershell
rg --files
```

```powershell
git status --short
```

Then read targeted files based on the request.

## Repository Map

- `app.py`: Streamlit app and UI flow.
- `src/config/config.py`: dataset and model artifact paths.
- `src/pipeline/`: training and prediction pipelines.
- `src/components/`: ingestion, transformation, model training, dashboard.
- `src/security/`: email, URL, QR, and risk analysis.
- `src/auth/auth.py`: auth and prediction history.
- `src/database/db.py`: MySQL connection helpers.
- `db/db.sql`: schema and seed data.
- `data/`: dataset and existing model artifacts.
- `docs/`: project docs and assignments.

## What To Report

When scouting, summarize:

- Relevant files found.
- Current behavior inferred from code.
- Important contracts or risks.
- What should be read next if implementation continues.

Avoid proposing broad rewrites unless the evidence points there.
