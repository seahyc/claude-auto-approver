#!/usr/bin/env python3
"""Claude Code PreToolUse hook: auto-approve/deny tool calls based on keyword rules."""

import json
import sys
import os
import re
import shlex
import datetime

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

# Characters that make shell command parsing unreliable — if any appear in a
# single command segment, we cannot trust shlex to give us the actual paths.
# Note: command-chaining chars (& | ;) are handled by segment splitting instead.
SEGMENT_UNSAFE_CHARS = set("$`*?[]{}!><()")

# Privilege-escalation prefixes — never auto-approve these via scoped rules.
UNSAFE_PREFIXES = {"sudo", "doas"}


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


def _find_keyword_segment(command, keyword):
    """Split a compound command on ``&&  ||  ;  |`` and return the segment
    containing *keyword*.

    Returns ``None`` if:
    - the keyword isn't found in any segment, or
    - a prior segment contains ``cd`` (meaning cwd may have changed).
    """
    segments = re.split(r"\s*(?:&&|\|\||;|\|)\s*", command)

    for i, seg in enumerate(segments):
        if keyword.lower() in seg.lower():
            # Bail if any earlier segment changes directory
            for prev in segments[:i]:
                if re.search(r"(?:^|\s)cd(?:\s|$)", prev):
                    return None
            return seg

    return None


def _strip_redirections(segment):
    """Remove shell redirections from a command segment.

    Strips patterns like ``2>&1``, ``2>/dev/null``, ``>/dev/null``,
    ``2>>file``, ``< input``.  These don't affect which files a command
    like ``rm`` or ``mv`` operates on.
    """
    # 2>&1, 1>&2, >&2, etc.
    segment = re.sub(r"\s+\d*>&\d+", "", segment)
    # 2>/dev/null, 2>>file, >/dev/null, >>file, etc.
    segment = re.sub(r"\s+\d*>+\s*\S+", "", segment)
    # <file (input redirect)
    segment = re.sub(r"\s+<\s*\S+", "", segment)
    return segment.strip()


def extract_path_args(command, keyword):
    """Extract path arguments from a shell command using the matched keyword position.

    For compound commands (``rm file && yarn build``), only the segment that
    contains the keyword is analysed.  Dangerous metacharacters are checked
    within that segment only — command-chaining operators like ``&&`` are
    handled by segment splitting.

    Returns a list of path strings, or ``None`` if the command cannot be
    reliably parsed (triggering a fall-through to ``ask``).
    """
    # Isolate the segment that contains the keyword
    segment = _find_keyword_segment(command, keyword)
    if segment is None:
        return None

    # Reject privilege-escalation prefixes within the segment
    first_word = segment.strip().split()[0] if segment.strip() else ""
    if first_word.lower() in UNSAFE_PREFIXES:
        return None

    # Strip harmless redirections (2>&1, >/dev/null, etc.) before checking
    # for dangerous metacharacters — redirections don't affect which files
    # rm/mv operate on.
    segment = _strip_redirections(segment)

    # Reject segments with metacharacters that make path parsing unreliable
    if SEGMENT_UNSAFE_CHARS.intersection(segment):
        return None

    # Locate the keyword within the segment
    idx = segment.lower().find(keyword.lower())
    if idx == -1:
        return None

    from_keyword = segment[idx:]

    try:
        tokens = shlex.split(from_keyword)
    except ValueError:
        return None

    if not tokens:
        return None

    # First token is the command itself (rm, mv, etc.) — skip it
    args = tokens[1:]

    paths = []
    past_double_dash = False

    for token in args:
        if not past_double_dash and token == "--":
            past_double_dash = True
            continue
        if not past_double_dash and token.startswith("-"):
            continue
        paths.append(token)

    return paths if paths else None


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

    Returns ("allow", reason) if auto-approved, or None to fall through.
    """
    scoped = config.get("rules", {}).get("scoped", {})
    keywords = scoped.get("keywords", [])
    if not keywords:
        return None

    # Apply safe_substring stripping (consistent with the rest of decide)
    normalized = command
    for safe in config.get("rules", {}).get("safe_substrings", []):
        normalized = normalized.replace(safe, "")

    # Find a matching scoped keyword
    matched_keyword = None
    for kw in keywords:
        if kw.lower() in normalized.lower():
            matched_keyword = kw
            break
    if matched_keyword is None:
        return None

    allowed_dirs = build_allowed_dirs(cwd, scoped)
    if not allowed_dirs:
        return None

    path_args = extract_path_args(command, matched_keyword)
    if path_args is None:
        return None

    ok, reason = resolve_and_check_paths(path_args, cwd, allowed_dirs)
    if ok:
        kw_name = matched_keyword.strip()
        return "allow", f"Scoped approve: {kw_name} with all paths in project"

    return None


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

    # Deny keywords (highest priority)
    for kw in rules.get("deny", {}).get("keywords", []):
        if kw.lower() in normalized.lower():
            return "deny", f"Matched deny keyword: {kw}"

    # Scoped rules: auto-approve dangerous commands when all paths are in-project
    if cwd:
        scoped_result = check_scoped_rules(command, cwd, config)
        if scoped_result is not None:
            return scoped_result

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
