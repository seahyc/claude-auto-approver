#!/usr/bin/env python3
"""Claude Code PreToolUse hook: auto-approve/deny tool calls based on keyword rules."""

import json
import sys
import os
import re
import datetime

import bashlex

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.toml")
LOGS_DIR = os.path.join(SCRIPT_DIR, "logs")


def load_config():
    with open(CONFIG_PATH, "rb") as f:
        return tomllib.load(f)


def extract_command(tool_name, tool_input):
    """Extract the actionable string from tool_input."""
    if isinstance(tool_input, dict):
        for key in ("command", "file_path", "query", "pattern", "url", "content", "old_string", "new_string"):
            if key in tool_input:
                return str(tool_input[key])
        return json.dumps(tool_input)
    return str(tool_input)


SKIP_KEYWORD_CHECK = {"ExitPlanMode", "EnterPlanMode", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "AskUserQuestion"}

# Privilege-escalation prefixes — never auto-approve these via scoped rules.
UNSAFE_PREFIXES = {"sudo", "doas"}

# Sentinel: cd appeared but target can't be determined (no args, $VAR, etc.)
_UNKNOWN_CD = object()

# Characters indicating shell globs — the exact filenames can't be resolved
# statically, but the *directory* containing the glob can still be checked.
GLOB_CHARS = set("*?[]{}")


def find_git_root(cwd):
    """Walk up from cwd to find the nearest .git directory (project root)."""
    current = os.path.realpath(cwd)
    while True:
        if os.path.exists(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def _strip_quoted_contents(text):
    """Replace contents of quoted strings with empty markers.

    Prevents keywords inside commit messages, echo strings, etc. from
    triggering false positives.  The actual command tokens outside quotes
    are preserved.
    """
    text = re.sub(r'"[^"]*"', '""', text)
    text = re.sub(r"'[^']*'", "''", text)
    return text


def _strip_comments(text):
    """Remove bash comment content (``# ...`` to end of line).

    Must be called **after** ``_strip_quoted_contents`` so that ``#``
    characters inside quoted strings (already replaced with empty markers)
    don't get misidentified as comment starts.
    """
    return re.sub(r"#[^\n]*", "", text)


def _glob_dir_prefix(path):
    """Extract the directory containing a glob pattern.

    We can't resolve the exact files a glob matches at parse time, but we
    *can* verify that the directory they'd live in is within the project.

    Examples::

        build/*.o            → build
        *.txt                → .
        /tmp/*.txt           → /tmp
        a/b/c*.txt           → a/b
        build/**/*.o         → build
        transfers/t_*.pq     → transfers
    """
    for i, c in enumerate(path):
        if c in GLOB_CHARS:
            prefix = path[:i]
            last_sep = prefix.rfind("/")
            if last_sep > 0:
                return prefix[:last_sep]
            if last_sep == 0:
                return "/"
            return "."
    return path


def _word_is_unsafe(word_node):
    """Check if a bashlex word node contains unsafe expansions.

    Unsafe expansions (``$VAR``, ``$(cmd)``, `` `cmd` ``) mean the actual
    value is determined at runtime — we can't statically verify paths.
    ``tilde`` expansion (``~/...``) is safe because we handle it ourselves
    via ``os.path.expanduser()``.
    """
    for child in word_node.parts:
        if child.kind in ("commandsubstitution", "parameter", "processsubstitution"):
            return True
    return False


def _parse_commands(command_str):
    """Parse a bash command string into a list of simple command descriptors.

    Uses bashlex to build an AST, then walks it to extract each simple
    command with its arguments, safety flags, and position in the chain.

    Returns a list of dicts (one per simple command), or ``None`` if
    bashlex cannot parse the input (triggering a safe fall-through to ask).

    Each dict contains::

        name:           Command name (first word, e.g. 'rm')
        path_args:      Non-flag arguments (potential file paths), or None
        is_unsafe:      True if command has globs, expansions, etc.
        cd_target:      None if no cd preceded this command, a path string if
                        cd had a resolvable target, or _UNKNOWN_CD if cd was
                        present but target can't be determined
        is_privileged:  True if first word is sudo/doas
        raw_words:      All word values including flags (for sudo inspection)
    """
    try:
        parts = bashlex.parse(command_str)
    except Exception:
        return None

    commands = []
    cd_target = [None]  # mutable for closure — tracks effective cwd changes

    def _analyze_command(node):
        """Extract structured info from a single bashlex command node."""
        words = []
        is_unsafe = False

        for part in node.parts:
            if part.kind == "word":
                if _word_is_unsafe(part):
                    is_unsafe = True
                words.append(part.word)
            elif part.kind == "redirect":
                # Redirections are naturally separated — skip them.
                # They don't affect which files rm/mv operate on.
                pass
            else:
                # Any other node type (compound, etc.) → can't be sure
                is_unsafe = True

        if not words:
            return None

        name = words[0]
        is_privileged = name.lower() in UNSAFE_PREFIXES

        # Extract path args: skip flags, handle --
        path_args = []
        past_double_dash = False
        for w in words[1:]:
            if not past_double_dash and w == "--":
                past_double_dash = True
                continue
            if not past_double_dash and w.startswith("-"):
                continue
            if GLOB_CHARS.intersection(w):
                # Can't resolve exact files, but can verify the containing
                # directory is within the project boundary.
                path_args.append(_glob_dir_prefix(w))
            else:
                path_args.append(w)

        return {
            "name": name,
            "path_args": path_args if path_args else None,
            "is_unsafe": is_unsafe,
            "cd_target": cd_target[0],
            "is_privileged": is_privileged,
            "raw_words": words,
        }

    def visit(nodes):
        for node in nodes:
            if node.kind == "list":
                visit(node.parts)
            elif node.kind == "pipeline":
                visit(node.parts)
            elif node.kind == "command":
                info = _analyze_command(node)
                if info is not None:
                    commands.append(info)
                    cmd_lower = info["name"].lower()
                    if cmd_lower in ("cd", "pushd"):
                        args = info["path_args"]
                        if args and len(args) == 1 and not info["is_unsafe"]:
                            new = args[0]
                            prev = cd_target[0]
                            if prev is None or prev is _UNKNOWN_CD:
                                cd_target[0] = new if prev is None else _UNKNOWN_CD
                            else:
                                expanded = os.path.expanduser(new)
                                if os.path.isabs(expanded):
                                    cd_target[0] = new
                                else:
                                    cd_target[0] = os.path.join(prev, new)
                        else:
                            cd_target[0] = _UNKNOWN_CD
                    elif cmd_lower == "popd":
                        # Can't track the directory stack — mark unknown
                        cd_target[0] = _UNKNOWN_CD
            # operator, pipe nodes are skipped

    visit(parts)
    return commands


def extract_path_args(command, keyword):
    """Extract path arguments from a shell command using bashlex AST parsing.

    Parses the full command into an AST, finds the simple command whose name
    matches the keyword, and returns its path arguments if the command is
    safe to auto-approve.

    Returns a list of path strings, or ``None`` if the command cannot be
    reliably parsed (triggering a fall-through to ``ask``).
    """
    commands = _parse_commands(command)
    if commands is None:
        return None

    target = keyword.strip().lower()

    # First pass: reject if any privileged (sudo/doas) command wraps our target.
    # e.g. "sudo rm file" → command name is "sudo", but "rm" is in raw_words.
    for cmd in commands:
        if cmd["is_privileged"]:
            if target in (w.lower() for w in cmd["raw_words"]):
                return None

    # Second pass: find the first command whose name matches our keyword.
    for cmd in commands:
        if cmd["name"].lower() != target:
            continue

        if cmd["is_unsafe"] or cmd["cd_target"] is not None:
            return None

        return cmd["path_args"]

    return None


def resolve_and_check_paths(paths, cwd, allowed_dirs):
    """Check if every path resolves (via realpath) within at least one allowed dir.

    Returns (True, reason) if all paths are contained, (False, reason) otherwise.
    """
    if not allowed_dirs:
        return False, "No allowed directories configured"

    for raw_path in paths:
        expanded = os.path.expanduser(raw_path)
        if not os.path.isabs(expanded):
            expanded = os.path.join(cwd, expanded)
        resolved = os.path.realpath(expanded)

        contained = False
        for allowed in allowed_dirs:
            allowed_real = os.path.realpath(allowed)
            # Strict subdirectory check — the path must be *inside* the dir,
            # not equal to it (prevents deleting the project root itself).
            if resolved.startswith(allowed_real + os.sep):
                contained = True
                break

        if not contained:
            return False, f"Path escapes allowed dirs: {raw_path} -> {resolved}"

    return True, "All paths within allowed directories"


def build_allowed_dirs(cwd, scoped_config):
    """Assemble allowed directories from static config + git-root detection."""
    dirs = []
    for d in scoped_config.get("allowed_dirs", []):
        real = os.path.realpath(d)
        if os.path.isdir(real):
            dirs.append(real)
    if scoped_config.get("allow_project_dir", False):
        git_root = find_git_root(cwd)
        if git_root:
            dirs.append(git_root)
    return dirs


def check_scoped_rules(command, cwd, config):
    """Check if a Bash command matches scoped rules and all paths are within bounds.

    Auto-approves only when **every** dangerous command in the chain is
    accounted for.  Specifically:

    1. ALL scoped keywords that match must have paths inside the project.
    2. No ask-only keywords (those in ask but not in scoped) may appear
       anywhere in the chain — we can't verify those commands.
    3. No privileged (sudo/doas) command may wrap a scoped keyword.

    Returns ("allow", reason) if auto-approved, or None to fall through.
    """
    rules = config.get("rules", {})
    scoped = rules.get("scoped", {})
    scoped_keywords = scoped.get("keywords", [])
    if not scoped_keywords:
        return None

    # Apply safe_substring stripping, quote stripping, and comment stripping
    # (consistent with decide)
    normalized = command
    for safe in rules.get("safe_substrings", []):
        normalized = normalized.replace(safe, "")
    normalized = _strip_quoted_contents(normalized)
    normalized = _strip_comments(normalized)
    norm_lower = normalized.lower()

    # Check if ANY scoped keyword matches
    matched_scoped = [kw for kw in scoped_keywords if kw.lower() in norm_lower]
    if not matched_scoped:
        return None

    # Reject if ask-only keywords (not in scoped) also appear in the command.
    # We can't verify those commands, so the whole chain must go to ask.
    ask_keywords = rules.get("ask", {}).get("keywords", [])
    scoped_set = {kw.lower() for kw in scoped_keywords}
    for kw in ask_keywords:
        if kw.lower() not in scoped_set and kw.lower() in norm_lower:
            return None

    allowed_dirs = build_allowed_dirs(cwd, scoped)
    if not allowed_dirs:
        return None

    # Parse command AST directly so we can handle cd targets
    commands = _parse_commands(command)
    if commands is None:
        return None

    # Reject if any privileged command wraps a scoped keyword
    scoped_names = {kw.strip().lower() for kw in scoped_keywords}
    for cmd in commands:
        if cmd["is_privileged"]:
            if scoped_names.intersection(w.lower() for w in cmd["raw_words"]):
                return None

    # Verify EVERY command that matches a scoped keyword
    verified_names = []
    for cmd in commands:
        cmd_name = cmd["name"].lower()
        if cmd_name not in scoped_names:
            continue

        if cmd["is_unsafe"]:
            return None

        path_args = cmd["path_args"]
        if path_args is None:
            return None

        # Determine effective cwd — handle cd preceding the command
        effective_cwd = cwd
        cd = cmd["cd_target"]
        if cd is _UNKNOWN_CD:
            return None
        if cd is not None:
            expanded = os.path.expanduser(cd)
            if not os.path.isabs(expanded):
                expanded = os.path.join(cwd, expanded)
            cd_resolved = os.path.realpath(expanded)
            cd_ok = any(
                cd_resolved.startswith(d + os.sep) or cd_resolved == d
                for d in allowed_dirs
            )
            if not cd_ok:
                return None
            effective_cwd = cd_resolved

        ok, reason = resolve_and_check_paths(path_args, effective_cwd, allowed_dirs)
        if not ok:
            return None
        verified_names.append(cmd_name)

    if not verified_names:
        return None

    names = ", ".join(sorted(set(verified_names)))
    return "allow", f"Scoped approve: {names} with all paths in project"


def check_docker_scoped(command, config):
    """Auto-approve docker rm/rmi when targeting specific containers by name.

    Falls through to ask when shell expansion (``$(...)``, ``$VAR``,
    backticks) is detected — prevents ``docker rm $(docker ps -aq)`` style
    shotgun removal that could nuke another agent's containers.

    Verifies ALL docker commands in a compound chain.  If any uses shell
    expansion, the whole command falls through to ask.  Also rejects if
    other unrelated ask keywords appear in the chain.
    """
    rules = config.get("rules", {})
    docker_scoped = rules.get("docker_scoped", {})
    docker_keywords = docker_scoped.get("keywords", [])
    if not docker_keywords:
        return None

    # Normalize same as decide()
    normalized = command
    for safe in rules.get("safe_substrings", []):
        normalized = normalized.replace(safe, "")
    normalized = _strip_quoted_contents(normalized)
    normalized = _strip_comments(normalized)
    norm_lower = normalized.lower()

    matched = [kw for kw in docker_keywords if kw.lower() in norm_lower]
    if not matched:
        return None

    commands = _parse_commands(command)
    if commands is None:
        return None

    # Extract subcommand names from matched keywords (e.g. "docker rm" → "rm")
    matched_subs = set()
    for kw in matched:
        parts = kw.strip().lower().split()
        if len(parts) >= 2:
            matched_subs.add(parts[1])

    # Reject if any command in the chain matches ask keywords not covered
    # by docker_scoped.  Uses AST-level check so "rm " inside "docker rm"
    # doesn't false-positive, but standalone "rm file" or uncovered docker
    # commands like "docker system prune" are caught.
    ask_keywords = rules.get("ask", {}).get("keywords", [])
    docker_kw_lower = {kw.lower() for kw in docker_keywords}
    for cmd in commands:
        if cmd["is_privileged"]:
            continue
        raw_lower = " ".join(w.lower() for w in cmd["raw_words"])
        is_docker = cmd["name"].lower() == "docker"
        for kw in ask_keywords:
            kw_lower = kw.lower()
            if kw_lower in docker_kw_lower:
                continue  # Handled by this docker_scoped check
            # For docker commands, only match docker-prefixed ask keywords
            # (e.g. "docker system prune"), skip bare ones like "rm " that
            # would false-positive on the docker subcommand name.
            if is_docker and not kw_lower.startswith("docker "):
                continue
            if kw_lower in raw_lower:
                return None

    # Verify ALL docker commands with matching subcommands are safe
    found_any = False
    for cmd in commands:
        # sudo/doas docker ... → never auto-approve
        if cmd["is_privileged"]:
            if "docker" in (w.lower() for w in cmd["raw_words"]):
                return None
            continue

        if cmd["name"].lower() != "docker":
            continue

        raw_lower = [w.lower() for w in cmd["raw_words"]]
        has_matched_sub = any(sub in raw_lower for sub in matched_subs)
        if not has_matched_sub:
            continue

        found_any = True

        if cmd["is_unsafe"]:
            return None

    if not found_any:
        return None

    kw_str = ", ".join(sorted(matched_subs))
    return "allow", f"Docker scoped approve: docker {kw_str} with literal targets"


def decide(tool_name, command, config, cwd=""):
    rules = config.get("rules", {})
    default = rules.get("default_action", "approve")

    # Skip keyword matching for non-dangerous tools (includes plan mode)
    if tool_name in SKIP_KEYWORD_CHECK or "Plan" in tool_name:
        return normalize(default), f"Skipped keyword check for {tool_name}"

    # Strip safe substrings before keyword matching so they don't
    # false-positive on dangerous keywords (e.g. "--rm" triggering "rm ")
    normalized = command
    for safe in rules.get("safe_substrings", []):
        normalized = normalized.replace(safe, "")

    # Strip quoted string contents so keywords inside commit messages,
    # echo strings, etc. don't trigger false positives.
    normalized = _strip_quoted_contents(normalized)

    # Strip bash comments (# to end of line) so keywords inside comments
    # don't trigger false positives.  Must run after quote stripping.
    normalized = _strip_comments(normalized)

    # Deny keywords (highest priority)
    for kw in rules.get("deny", {}).get("keywords", []):
        if kw.lower() in normalized.lower():
            return "deny", f"Matched deny keyword: {kw}"

    # Scoped rules: auto-approve dangerous commands when all paths are in-project
    if cwd:
        scoped_result = check_scoped_rules(command, cwd, config)
        if scoped_result is not None:
            return scoped_result

    # Docker scoped rules: auto-approve docker rm/rmi with literal targets
    docker_result = check_docker_scoped(command, config)
    if docker_result is not None:
        return docker_result

    # Ask keywords (second priority — also catches failed scoped checks)
    for kw in rules.get("ask", {}).get("keywords", []):
        if kw.lower() in normalized.lower():
            return "ask", f"Matched ask keyword: {kw}"

    # Allow keywords
    for kw in rules.get("allow", {}).get("keywords", []):
        if kw.lower() in command.lower():
            return "allow", f"Matched allow keyword: {kw}"

    # Per-tool override
    tool_cfg = config.get("tools", {}).get(tool_name, {})
    if "default_action" in tool_cfg:
        action = tool_cfg["default_action"]
        return normalize(action), f"Tool default for {tool_name}"

    return normalize(default), "Global default action"


def normalize(action):
    return "allow" if action in ("approve", "allow") else action


def log_event(session, cwd, tool, command, action, reason):
    os.makedirs(LOGS_DIR, exist_ok=True)
    today = datetime.date.today().isoformat()
    path = os.path.join(LOGS_DIR, f"{today}.jsonl")
    entry = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "session": session,
        "cwd": cwd,
        "tool": tool,
        "command": command[:500],
        "action": action,
        "reason": reason,
    }
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        return

    data = json.loads(raw)
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    session_id = data.get("session_id", "")
    cwd = data.get("cwd", "")

    config = load_config()
    command = extract_command(tool_name, tool_input)
    action, reason = decide(tool_name, command, config, cwd=cwd)

    # Skip logging noise commands
    if not re.match(r"^sleep\s+\d+", command.strip()):
        log_event(session_id, cwd, tool_name, command, action, reason)

    decision = normalize(action)
    # Map to Claude Code's expected values
    perm = {"allow": "allow", "deny": "deny", "ask": "ask"}.get(decision, "ask")

    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": perm,
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(output))


if __name__ == "__main__":
    main()
