#!/usr/bin/env python3
"""Claude Code PreToolUse hook: auto-approve/deny tool calls based on keyword rules."""

import json
import sys
import os
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


def decide(tool_name, command, config):
    rules = config.get("rules", {})
    default = rules.get("default_action", "approve")

    # Skip keyword matching for non-dangerous tools (includes plan mode)
    if tool_name in SKIP_KEYWORD_CHECK or "Plan" in tool_name:
        return normalize(default), f"Skipped keyword check for {tool_name}"

    # Deny keywords (highest priority)
    for kw in rules.get("deny", {}).get("keywords", []):
        if kw.lower() in command.lower():
            return "deny", f"Matched deny keyword: {kw}"

    # Ask keywords (second priority)
    for kw in rules.get("ask", {}).get("keywords", []):
        if kw.lower() in command.lower():
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
    action, reason = decide(tool_name, command, config)

    # Skip logging noise commands
    import re
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
