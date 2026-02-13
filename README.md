# Claude Auto-Approver

A lightweight [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that auto-approves tool calls based on configurable keyword rules. No more clicking "yes" hundreds of times per session.

## Why?

Claude Code asks for permission before every tool call (Bash commands, file edits, MCP tools, etc.). This is safe but slow. This hook auto-approves everything by default, while still prompting you for destructive commands like `rm`, `kubectl`, or `git push --force`.

## How it works

```
Claude calls a tool
    → PreToolUse hook fires
    → approver.py checks command against config.toml rules
    → Returns allow/deny/ask decision
    → Logs everything to logs/YYYY-MM-DD.jsonl
```

**Priority:** deny > ask > allow > per-tool default > global default

## Setup

1. Clone this repo:
```bash
git clone https://github.com/yingcong-wu/claude-auto-approver.git
```

2. Add the hook to `~/.claude/settings.json`:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/claude-auto-approver/approver.py"
          }
        ]
      }
    ]
  }
}
```

Empty `matcher` = matches ALL tools. Takes effect immediately for all sessions (no restart needed).

3. That's it. Every Claude Code session on your machine now uses the hook.

## Config (`config.toml`)

```toml
[rules]
default_action = "approve"  # approve | deny | ask

[rules.deny]
keywords = []

[rules.ask]
keywords = [
    "rm ",
    "mv ",
    "kubectl",
    "git reset --hard",
    "push --force",
    # ... see config.toml for full list
]

[rules.allow]
keywords = []

# Per-tool overrides
[tools.Write]
default_action = "approve"
```

Edit `config.toml` to customize. Changes take effect on the next tool call.

## Log Viewer

```bash
python3 viewer.py                     # today's logs
python3 viewer.py --date 2025-02-12   # specific date
python3 viewer.py --action ask         # only prompts
python3 viewer.py --grep kubectl       # search commands
python3 viewer.py --session 5a12       # specific session
python3 viewer.py --tail               # live follow
python3 viewer.py --stats              # summary counts
```

Example output:
```
10:18:56  ASK    [launch_video] [Bash] rm -rf /tmp/old-cache
                 session:0ac231ca  reason: Matched ask keyword: rm
10:19:29  ASK    [launch_video] [Bash] docker system prune -a --volumes -f
                 session:0ac231ca  reason: Matched ask keyword: docker system prune
10:19:48  ALLOW  [api] [Bash] git log --oneline -5
                 session:4b710699  reason: Global default action
```

Shows project name, session ID, tool, command, and reason for each decision.

## Turn off

Remove the `PreToolUse` block from `~/.claude/settings.json`.

## Requirements

- Python 3.11+ (uses `tomllib` from stdlib)
- Claude Code with hooks support

## License

MIT
