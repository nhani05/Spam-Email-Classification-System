---
name: mailguard-docs
description: Create or update MailGuard AI documentation. Use when Codex needs to write README content, project reports, feature specs, setup guides, demo scripts, Vietnamese docs, architecture notes, schema notes, or assignment documents for the Spam Email Classification System.
---

# MailGuard Docs

## Mission

Keep project documentation accurate, demo-ready, and aligned with the implemented code.

## Style

- Prefer Vietnamese without accents when the surrounding file is already written that way.
- Use concise sections and concrete commands.
- Document current behavior, not aspirational behavior, unless the file is explicitly a roadmap.
- Mention limitations clearly, especially DB setup, model paths, and password schema constraints.

## Documentation Sources

Inspect before editing:

- `README.md`
- `docs/`
- `app.py`
- `src/config/config.py`
- `src/pipeline/`
- `src/security/`
- `db/db.sql`

## Common Updates

- Setup and run instructions.
- `.env` database configuration.
- Model artifact path guidance.
- Training pipeline explanation.
- Feature list for spam/ham, URL, QR, MBOX, dashboard, history.
- Demo script: input examples, expected screenshots, talking points.
- Team assignment or milestone docs.

## Accuracy Checklist

Before finishing docs:

1. Confirm commands match the repo.
2. Confirm model paths exist or explain fallback paths.
3. Confirm DB schema matches code expectations.
4. Confirm feature claims exist in code.
5. Keep generated docs scoped to the requested file.
