---
name: mailguard-loop
description: Run iterative build-test-improve loops for MailGuard AI. Use when Codex needs to repeatedly implement, smoke test, inspect output, refine UI/logic/docs, or drive a feature from rough behavior to verified behavior in this repository.
---

# MailGuard Loop

## Mission

Use a tight loop to move from uncertain behavior to verified behavior.

## Loop

1. Define the target behavior in one sentence.
2. Pick the smallest observable check.
3. Make one focused change.
4. Run the check.
5. Inspect errors or output.
6. Repeat until the behavior is handled or a real blocker is found.

## Good Checks

- Import-level smoke checks for Python modules.
- Direct analyzer calls for threat logic.
- Direct `PredictionPipeline` calls for model loading and prediction.
- `streamlit run app.py` for UI flow.
- DB `ping()` and auth helper imports for database-adjacent work.

## Stop Conditions

Stop the loop only when:

- The requested behavior is implemented and verified.
- A dependency or external system blocks verification.
- More user input is genuinely required.

Report the last check run and what it proved.
