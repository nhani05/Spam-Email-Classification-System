---
name: mailguard-git
description: Manage Git hygiene for MailGuard AI work. Use when Codex needs to inspect status, review diffs, prepare commit summaries, separate user changes from agent changes, avoid overwriting work, or explain what changed in the Spam Email Classification System repository.
---

# MailGuard Git

## Mission

Keep repository changes understandable and protect user work.

## Rules

- Start with `git status --short`.
- Use `git diff` for tracked changes and `rg --files` for untracked project files.
- Never revert or delete user changes unless explicitly requested.
- If files outside the current task are modified, mention them but leave them alone.
- Keep summaries grouped by feature area.

## Review Checklist

When preparing a status or handoff:

1. Separate tracked modifications from untracked files.
2. Identify files changed by the current task.
3. Identify pre-existing changes that were not touched.
4. Mention tests or validators run.
5. Call out files that may need staging together.

## Useful Commands

```powershell
git status --short
```

```powershell
git diff
```

```powershell
git diff -- <path>
```

```powershell
rg --files .codex
```
