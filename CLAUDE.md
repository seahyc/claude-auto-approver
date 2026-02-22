# Claude Auto-Approver

A PreToolUse hook for Claude Code that auto-approves tool calls based on keyword rules.

## How it works

Registered as a `PreToolUse` hook in `~/.claude/settings.json`. Every tool call goes through `approver.py`, which checks the command against keyword rules in `config.toml` and logs every decision to `logs/YYYY-MM-DD.jsonl`.

**Priority:** deny keywords > scoped rules (path-checked allow) > docker scoped rules (literal-target allow) > ask keywords > allow keywords > per-tool default > global default

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
- `rules.scoped.keywords` — commands matching these are auto-approved **only if** all file path arguments resolve within the project directory (git root) or `allowed_dirs`
- `rules.scoped.allow_project_dir` — auto-detect project root from cwd (default: `true`)
- `rules.scoped.allowed_dirs` — additional static directories where scoped commands are allowed
- `rules.docker_scoped.keywords` — docker commands (e.g. `docker rm`, `docker rmi`) auto-approved when targeting specific containers/images by name, but fall through to `ask` when using shell expansion (`$(...)`, `$VAR`, backticks)
- `tools.<ToolName>.default_action` — per-tool override

Non-dangerous tools (`ExitPlanMode`, `EnterPlanMode`, `TaskCreate`, etc.) skip keyword matching entirely.

### Scoped rules

Scoped rules allow dangerous commands (like `rm`) to auto-approve when all their file path arguments stay within the project directory. Uses `bashlex` to parse compound commands (`&&`, `||`, `;`, `|`) into an AST — redirections are naturally excluded, and each simple command is analyzed independently. If paths can't be safely parsed (command substitution, `$VAR`) or any path escapes the project boundary, the command falls through to the normal `ask` behavior. Commands prefixed with `sudo`/`doas` are never scoped-approved.

**Glob support:** Paths with globs (e.g. `build/*.o`, `transfers/*.parquet`) are handled by checking the *directory* containing the glob is within the project. The glob can only expand to files inside that directory.

**cd tracking:** When `cd <dir>` precedes a dangerous command in a chain (e.g. `cd subdir && rm file`), the cd target is resolved and verified to be within the project. If it is, the subsequent command's paths are resolved relative to the new directory. If the cd target is outside the project or can't be determined, the command falls through to `ask`.

### Docker scoped rules

Docker scoped rules auto-approve `docker rm`/`docker rmi` when all arguments are literal container or image names (e.g. `docker rm my-container`). When shell expansion is detected (`docker rm $(docker ps -aq)`), the command falls through to `ask` — preventing one agent from shotgun-removing another agent's containers. Also rejects if other uncovered ask keywords appear in the same compound command. `sudo docker ...` is never auto-approved.

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
