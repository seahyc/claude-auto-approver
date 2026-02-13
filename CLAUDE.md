# Claude Auto-Approver

A PreToolUse hook for Claude Code that auto-approves tool calls based on keyword rules.

## How it works

Registered as a `PreToolUse` hook in `~/.claude/settings.json`. Every tool call goes through `approver.py`, which checks the command against keyword rules in `config.toml` and logs every decision to `logs/YYYY-MM-DD.jsonl`.

**Priority:** deny keywords > ask keywords > allow keywords > per-tool default > global default

## Files

- `approver.py` — hook script (receives JSON on stdin, outputs decision)
- `config.toml` — keyword rules and defaults
- `viewer.py` — CLI log viewer
- `logs/` — JSONL audit logs (one file per day)

## Config (`config.toml`)

- `rules.default_action` — `approve`, `deny`, or `ask` (default: `approve`)
- `rules.deny.keywords` — commands matching these are denied
- `rules.ask.keywords` — commands matching these prompt the user (e.g. `rm `, `mv `, `kubectl`, `rancher`)
- `rules.allow.keywords` — commands matching these are approved
- `tools.<ToolName>.default_action` — per-tool override

Non-dangerous tools (`ExitPlanMode`, `EnterPlanMode`, `TaskCreate`, etc.) skip keyword matching entirely.

## Log Viewer

```sh
python3 viewer.py                     # today's logs
python3 viewer.py --date 2026-02-12   # specific date
python3 viewer.py --action ask         # only prompts
python3 viewer.py --grep kubectl       # search commands
python3 viewer.py --session 5a12       # specific session
python3 viewer.py --tail               # live follow
python3 viewer.py --stats              # summary counts
```

## Turn off

Remove the `PreToolUse` block from `~/.claude/settings.json`.
