---
name: mailguard-brainstorm
description: Brainstorm product and technical ideas for MailGuard AI. Use when Codex needs to propose feature ideas, risk-scoring improvements, UI concepts, demo narratives, research directions, or alternative implementation approaches for the Spam Email Classification System without editing code immediately.
---

# MailGuard Brainstorm

## Mission

Generate practical ideas for MailGuard AI as an email threat detection product, not only a spam/ham classifier.

Use this framing:

```text
Is this email dangerous, why is it dangerous, and what should the user do next?
```

## Workflow

1. Read the relevant project context before proposing ideas:
   - `README.md`
   - `docs/` when present
   - `app.py`
   - `src/security/`
   - `src/pipeline/`
2. Separate ideas into near-term, medium-term, and later enhancements.
3. Prefer features that reuse existing modules before suggesting new services.
4. Include implementation impact: files likely touched, data needed, and validation method.
5. Keep suggestions concrete enough for Codex to implement in a follow-up turn.

## Product Priorities

Prefer ideas around:

- Explainable risk score `0-100`.
- Phishing URL and brand impersonation detection.
- QR phishing, also called quishing.
- Malware attachment and risky filename indicators.
- Security dashboard and high-risk history.
- User feedback loop for correcting predictions.
- Model evaluation tab with metrics and confusion matrix.
- Admin blacklist/whitelist management.

## Output Shape

When asked for brainstorming, return:

- Best 3-5 ideas.
- Why each matters.
- Where it fits in the current repo.
- First implementation step.
- Validation plan.
