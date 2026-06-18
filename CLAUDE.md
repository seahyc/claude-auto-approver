# Claude Auto-Approver

A PreToolUse hook for Claude Code that auto-approves tool calls based on keyword rules.

## How it works

Registered as a `PreToolUse` hook in `~/.claude/settings.json`. Every tool call goes through `approver.py`, which checks the command against keyword rules in `config.toml` and logs every decision to `logs/YYYY-MM-DD.jsonl`.

**Priority:** deny keywords > kubectl/helm/helmfile scoped rules (context-aware) > scoped rules (path-checked allow) > docker scoped rules (literal-target allow) > psql scoped rules (host-aware) > ask keywords > allow keywords > per-tool default > global default

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
- `rules.psql_scoped.enabled` — host-aware psql gating (default in repo: `true`)
- `rules.psql_scoped.local_hosts` — hostnames treated as the local DB (auto-approve); `localhost`/`127.0.0.1`/`::1`/no-host are always local
- `rules.psql_scoped.remote_wrappers` — command words (`ssh`, `kubectl`, `rancher`) that mean psql runs on another machine, forcing `ask` even for `-h localhost`
- `rules.psql_scoped.trusted_remote_hosts` — ssh destinations (e.g. `oracle.seahyingcong.com`) treated as trusted dev VMs: `ssh <host> … psql` against that VM's own local DB auto-approves; using the VM as a proxy to another host still prompts
- `tools.<ToolName>.default_action` — per-tool override

Keyword matching only applies to `Bash` tool calls (the `KEYWORD_MATCH_TOOLS` set). All other tools (WebSearch, Read, Grep, ToolSearch, etc.) skip keyword checks and use per-tool or global defaults - this prevents false positives like "form" matching "rm " in search queries.

### Scoped rules

Scoped rules allow dangerous commands (like `rm`) to auto-approve when all their file path arguments stay within the project directory. Uses `bashlex` to parse compound commands (`&&`, `||`, `;`, `|`) into an AST — redirections are naturally excluded, and each simple command is analyzed independently. If paths can't be safely parsed (command substitution, `$VAR`) or any path escapes the project boundary, the command falls through to the normal `ask` behavior. Commands prefixed with `sudo`/`doas` are never scoped-approved.

**Glob support:** Paths with globs (e.g. `build/*.o`, `transfers/*.parquet`) are handled by checking the *directory* containing the glob is within the project. The glob can only expand to files inside that directory.

**cd tracking:** When `cd <dir>` precedes a dangerous command in a chain (e.g. `cd subdir && rm file`), the cd target is resolved and verified to be within the project. If it is, the subsequent command's paths are resolved relative to the new directory. If the cd target is outside the project or can't be determined, the command falls through to `ask`.

### Docker scoped rules

Docker scoped rules auto-approve `docker rm`/`docker rmi` when all arguments are literal container or image names (e.g. `docker rm my-container`). When shell expansion is detected (`docker rm $(docker ps -aq)`), the command falls through to `ask` — preventing one agent from shotgun-removing another agent's containers. Also rejects if other uncovered ask keywords appear in the same compound command. `sudo docker ...` is never auto-approved.

### psql scoped rules

Auto-approves `psql` commands (including destructive SQL like `DELETE`/`DROP`) when they target the **local** machine's database, and prompts (`ask`) for any **non-local** psql — read or write alike (a remote `SELECT` is still surfaced). A connection is local when the host is `localhost`/`127.0.0.1`/`::1` (or a configured `local_hosts` entry), is a unix-socket path, or no host is given. It is remote — forcing `ask` — when:

- the parsed host is non-local. Hosts are read from `-h <host>` / `-h<host>` (no space), `--host`/`--host=`, a `postgres://` URI, a `host=` conninfo key (even when quote-prefixed), or an inline `PGHOST=` env assignment — wherever they appear in the command (e.g. `-h` after `-c`);
- a connection **service** is used (`service=` / `PGSERVICE=`) — the host lives in an unreadable `pg_service.conf`, so we can't prove it's local; **or**
- psql is wrapped by a `remote_wrappers` command (`ssh`, `kubectl`, `rancher`) appearing at a command position — even `-h localhost` then refers to the *remote* box's localhost. **Exception:** an `ssh` into a `trusted_remote_hosts` VM is exempt (see below).

**Trusted dev VMs (`trusted_remote_hosts`):** when psql is wrapped in `ssh <trusted-host>` and connects to that VM's **own** local DB (`-h localhost`/`127.0.0.1`/`::1`, unix socket, or no host), it auto-approves — destructive SQL included — treating the VM like a local dev box. The exemption only relaxes the `ssh` wrapper, never `kubectl`/`rancher`. The VM-as-a-proxy case still prompts: if the inner psql targets a different host (`ssh oracle 'psql -h prod-db …'`), the normal non-local host check catches it → `ask`. The ssh destination is matched against the configured list as bare host or `user@host` (`ubuntu@oracle…` matches `oracle…`), skipping ssh option flags like `-i <key>`/`-p <port>` when locating it. With an empty/absent `trusted_remote_hosts`, ssh-wrapped psql prompts as before. Caveat: nested ssh (`ssh oracle 'ssh otherbox psql …'`) isn't reliably detected as a second hop because of quote-splitting, but an inner `psql -h <otherhost>` is caught regardless.

A bare `docker exec … psql` (not under a remote wrapper) is treated as a local dev container → allow. If a local-psql line also contains an uncovered ask keyword (`rm`/`mv`/…), the check defers so that risk still prompts. Host parsing runs against the raw command, so an unquoted `host=` substring inside SQL may cause a (safe-direction) extra prompt; a quoted SQL value like `host='x'` is not misread. Regression tests for every local/remote/bypass form live in `test_scoped.py::TestCheckPsqlScoped`.

Note on precedence: settings.json `ask` rules win over a hook `allow`, and settings.json `allow` rules win over a hook `ask`. So this gating only works while `psql`/`PGPASSWORD=` are **absent** from `~/.claude/settings.json` `permissions` — otherwise a native rule overrides the hook.

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
