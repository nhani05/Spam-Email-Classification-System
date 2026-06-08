---
name: mailguard-plan
description: Plan MailGuard AI work before implementation. Use when Codex needs to break down a feature, migration, refactor, demo roadmap, model-training update, security enhancement, or database change into ordered implementation steps for this repository.
---

# MailGuard Plan

## Mission

Create clear, implementation-ready plans for MailGuard AI changes.

## Planning Inputs

Read only the context needed for the plan:

- Request details from the user.
- `README.md` and `docs/` for project intent.
- Relevant code modules for feasibility.
- Current `git status --short` when edits may follow.

## Plan Shape

Use short ordered phases:

1. Discovery.
2. Implementation.
3. Data/schema/config updates if needed.
4. Verification.
5. Handoff notes.

For each phase, name likely files and risk points.

## Decision Rules

- Prefer existing architecture over new frameworks.
- Keep DB-dependent features graceful when MySQL is unavailable.
- Keep ML model changes paired with vectorizer/config updates.
- Keep analyzer changes explainable.
- Split large work into safe increments.

## Output

Return a plan that Codex can execute directly, with no vague "improve system" steps.
