#!/usr/bin/env python3
"""Active permission prompt scanner for Claude Code.

Monitors terminal sessions for Claude Code's built-in permission prompts
(which bypass the PreToolUse hook) and auto-approves them based on the
same config.toml rules used by approver.py.

Usage:
    python3 scanner.py                # auto-detect backend
    python3 scanner.py --backend iterm2
    python3 scanner.py --backend tmux
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from approver import decide, load_config, normalize, LOGS_DIR


# ---------------------------------------------------------------------------
# Terminal backends
# ---------------------------------------------------------------------------

class Backend:
    """Abstract interface for terminal multiplexer backends."""

    def list_sessions(self):
        """Return list of dicts: [{id, tty, name}]."""
        raise NotImplementedError

    def read_content(self, session):
        """Return visible screen text for the given session."""
        raise NotImplementedError

    def send_input(self, session, text):
        """Inject text input into the given session."""
        raise NotImplementedError


class ITermBackend(Backend):
    """iTerm2 backend using AppleScript."""

    def _osascript(self, script):
        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def list_sessions(self):
        # Get all sessions with their tty and name
        script = '''
tell application "iTerm2"
    set output to ""
    repeat with w in windows
        repeat with t in tabs of w
            repeat with s in sessions of t
                set sessionTTY to tty of s
                set sessionID to id of s
                set sessionName to name of s
                set output to output & sessionID & "|||" & sessionTTY & "|||" & sessionName & linefeed
            end repeat
        end repeat
    end repeat
    return output
end tell
'''
        raw = self._osascript(script)
        sessions = []
        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = line.split("|||")
            if len(parts) >= 3:
                sessions.append({
                    "id": parts[0].strip(),
                    "tty": parts[1].strip(),
                    "name": parts[2].strip(),
                })
        return sessions

    def read_content(self, session):
        script = f'''
tell application "iTerm2"
    repeat with w in windows
        repeat with t in tabs of w
            repeat with s in sessions of t
                if id of s is "{session['id']}" then
                    return contents of s
                end if
            end repeat
        end repeat
    end repeat
end tell
'''
        return self._osascript(script)

    def send_input(self, session, text):
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        script = f'''
tell application "iTerm2"
    repeat with w in windows
        repeat with t in tabs of w
            repeat with s in sessions of t
                if id of s is "{session['id']}" then
                    write text "{escaped}" to s
                end if
            end repeat
        end repeat
    end repeat
end tell
'''
        self._osascript(script)


class TmuxBackend(Backend):
    """tmux backend using tmux CLI."""

    def list_sessions(self):
        try:
            result = subprocess.run(
                ["tmux", "list-panes", "-a", "-F",
                 "#{pane_id}|||#{pane_tty}|||#{pane_current_command}"],
                capture_output=True, text=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        sessions = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = line.split("|||")
            if len(parts) >= 3:
                sessions.append({
                    "id": parts[0].strip(),
                    "tty": parts[1].strip(),
                    "name": parts[2].strip(),
                })
        return sessions

    def read_content(self, session):
        try:
            result = subprocess.run(
                ["tmux", "capture-pane", "-t", session["id"], "-p"],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def send_input(self, session, text):
        try:
            subprocess.run(
                ["tmux", "send-keys", "-t", session["id"], text, "Enter"],
                capture_output=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

def detect_backend():
    """Auto-detect the appropriate backend."""
    # Check if iTerm2 is running (macOS)
    try:
        result = subprocess.run(
            ["pgrep", "-x", "iTerm2"],
            capture_output=True, timeout=3,
        )
        if result.returncode == 0:
            return ITermBackend()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Check if inside tmux
    if os.environ.get("TMUX"):
        return TmuxBackend()

    # Check if tmux is available and has sessions
    try:
        result = subprocess.run(
            ["tmux", "list-sessions"],
            capture_output=True, timeout=3,
        )
        if result.returncode == 0:
            return TmuxBackend()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return None


# ---------------------------------------------------------------------------
# Prompt parsing
# ---------------------------------------------------------------------------

def strip_ansi(text):
    """Remove ANSI escape sequences from terminal output."""
    return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)


def is_claude_session(session):
    """Check if a session is likely running Claude Code."""
    name = session.get("name", "").lower()
    return "claude" in name


# Regex to find the "Do you want to proceed?" prompt
PROCEED_RE = re.compile(r"Do you want to proceed\?", re.IGNORECASE)

# Regex to confirm cursor is on option 1 (Yes)
CURSOR_ON_YES_RE = re.compile(r"[❯>]\s*1\.\s*Yes")

# Tool header patterns - matches "Bash command" or "Bash(command)" style
TOOL_HEADER_RE = re.compile(
    r"^\s*(?:[│|]\s*)?(\w+(?:\s+\w+)?)\s*$",
    re.MULTILINE,
)


def _looks_like_description(line):
    """Heuristic: return True if a line looks like a natural-language description.

    Claude Code shows a description string below the command. These are
    typically: capitalized, no shell metacharacters, and read as prose.
    """
    # Must start with a letter (commands start with lowercase or paths/env vars)
    if not line or not line[0].isalpha():
        return False
    # Contains shell metacharacters - probably a command
    if any(c in line for c in "|;&$`<>(){}"):
        return False
    # Starts with an uppercase word and has multiple words - likely description
    if line[0].isupper() and " " in line:
        return True
    return False


def parse_prompt(content):
    """Parse terminal content for a Claude Code permission prompt.

    Returns a dict with {tool, command} if a prompt is found, or None.
    """
    text = strip_ansi(content)
    lines = text.split("\n")

    # Find "Do you want to proceed?" - should be near the bottom
    proceed_idx = None
    for i in range(len(lines) - 1, -1, -1):
        if PROCEED_RE.search(lines[i]):
            proceed_idx = i
            break

    if proceed_idx is None:
        return None

    # Check that cursor is on option 1 (Yes) - safety measure
    tail = "\n".join(lines[proceed_idx:])
    if not CURSOR_ON_YES_RE.search(tail):
        return None

    # Look backwards from the prompt for the tool header
    # The prompt format is:
    #   <tool header>         (e.g. "Bash command" or "Read file_path")
    #   <blank or border>
    #   <command text>        (indented, possibly multi-line)
    #   <description>         (optional)
    #   <blank or border>
    #   "Command contains..." (optional warning)
    #   "Do you want to proceed?"
    #   "> 1. Yes"

    # Strategy: scan backwards from proceed_idx to find the tool header,
    # then extract the command between header and proceed line.

    tool_name = None
    header_idx = None

    # Known tool headers that appear in permission prompts
    tool_headers = {
        "bash command": "Bash",
        "bash": "Bash",
        "read file_path": "Read",
        "read": "Read",
        "write file_path": "Write",
        "write": "Write",
        "edit file_path": "Edit",
        "edit": "Edit",
        "glob pattern": "Glob",
        "glob": "Glob",
        "grep pattern": "Grep",
        "grep": "Grep",
    }

    for i in range(proceed_idx - 1, max(proceed_idx - 30, -1), -1):
        stripped = lines[i].strip().strip("│| ")
        if stripped.lower() in tool_headers:
            tool_name = tool_headers[stripped.lower()]
            header_idx = i
            break

    if tool_name is None or header_idx is None:
        return None

    # Extract command text between header and prompt.
    # Claude Code shows: command line(s), then a description line (plain English).
    # We collect indented lines as command text, stopping at blank lines or
    # lines that look like natural-language descriptions (no shell metacharacters,
    # starts with a capital letter and reads like prose).
    cmd_lines = []
    in_command = False

    for i in range(header_idx + 1, proceed_idx):
        line = lines[i]
        stripped = line.strip().strip("│| ")

        if not stripped:
            if in_command:
                break  # blank line after command = end of command block
            continue

        # Skip known non-command lines
        if stripped.startswith("Command contains"):
            break

        leading = len(line) - len(line.lstrip())
        if leading >= 3 or in_command:
            # Heuristic: if we already have command line(s) and this line
            # looks like a plain English description, stop collecting.
            if in_command and _looks_like_description(stripped):
                break
            cmd_lines.append(stripped)
            in_command = True

    if not cmd_lines:
        return None

    command = "\n".join(cmd_lines)
    return {"tool": tool_name, "command": command}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log_event(source, tty, tool, command, action, reason):
    """Log scanner decisions to the same JSONL log files as approver.py."""
    os.makedirs(LOGS_DIR, exist_ok=True)
    today = datetime.date.today().isoformat()
    path = os.path.join(LOGS_DIR, f"{today}.jsonl")
    entry = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": source,
        "tty": tty,
        "tool": tool,
        "command": command[:500],
        "action": action,
        "reason": reason,
    }
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def cmd_hash(command):
    return hashlib.md5(command.encode()).hexdigest()[:12]


def clear_seen_for_tty(seen, tty):
    """Remove all seen entries for a given tty (prompt was resolved)."""
    keys_to_remove = [k for k in seen if k[0] == tty]
    for k in keys_to_remove:
        del seen[k]


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def get_own_tty():
    """Get the tty of the current process to avoid scanning ourselves."""
    try:
        return os.ttyname(sys.stdin.fileno())
    except (OSError, AttributeError):
        return None


def main():
    parser = argparse.ArgumentParser(description="Claude Code permission prompt scanner")
    parser.add_argument(
        "--backend", choices=["iterm2", "tmux"],
        help="Terminal backend (auto-detected if not specified)",
    )
    parser.add_argument(
        "--interval", type=float, default=1.5,
        help="Scan interval in seconds (default: 1.5)",
    )
    args = parser.parse_args()

    if args.backend == "iterm2":
        backend = ITermBackend()
    elif args.backend == "tmux":
        backend = TmuxBackend()
    else:
        backend = detect_backend()

    if backend is None:
        print("No supported terminal backend found (iTerm2 or tmux required)", file=sys.stderr)
        sys.exit(1)

    backend_name = type(backend).__name__.replace("Backend", "")
    print(f"Scanner started with {backend_name} backend, interval={args.interval}s")

    own_tty = get_own_tty()
    seen = {}  # (tty, cmd_hash) -> timestamp
    debounce_secs = 5

    while True:
        try:
            config = load_config()
            sessions = backend.list_sessions()

            for session in sessions:
                tty = session.get("tty", "")

                # Never send input to our own session
                if own_tty and tty == own_tty:
                    continue

                # Only scan sessions that look like Claude Code
                if not is_claude_session(session):
                    continue

                content = backend.read_content(session)
                if not content:
                    continue

                prompt = parse_prompt(content)

                if prompt is None:
                    # Prompt resolved or not present - clear seen entries
                    clear_seen_for_tty(seen, tty)
                    continue

                h = cmd_hash(prompt["command"])
                key = (tty, h)

                # Debounce: skip if we've seen this exact prompt recently
                if key in seen:
                    if time.time() - seen[key] < debounce_secs:
                        continue

                # Only evaluate Bash commands - we can't assess other tools
                if prompt["tool"] != "Bash":
                    seen[key] = time.time()
                    log_event(
                        source="scanner", tty=tty,
                        tool=prompt["tool"], command=prompt["command"],
                        action="skip", reason=f"Non-Bash tool: {prompt['tool']}",
                    )
                    continue

                action, reason = decide("Bash", prompt["command"], config, cwd="")
                action = normalize(action)

                log_event(
                    source="scanner", tty=tty,
                    tool=prompt["tool"], command=prompt["command"],
                    action=action, reason=reason,
                )

                if action == "allow":
                    print(f"[{datetime.datetime.now():%H:%M:%S}] APPROVE {tty}: {prompt['command'][:80]}")
                    backend.send_input(session, "1")
                else:
                    print(f"[{datetime.datetime.now():%H:%M:%S}] SKIP({action}) {tty}: {prompt['command'][:80]}")

                seen[key] = time.time()

        except KeyboardInterrupt:
            print("\nScanner stopped")
            break
        except Exception as e:
            print(f"Error in scan loop: {e}", file=sys.stderr)

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
