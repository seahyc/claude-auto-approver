#!/usr/bin/env python3
"""Claude Code PreToolUse hook: auto-approve/deny tool calls based on keyword rules."""

import json
import sys
import os
import re
import datetime

try:
    import bashlex
    HAS_BASHLEX = True
except ImportError:
    bashlex = None
    HAS_BASHLEX = False

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


# Tools where keyword matching actually applies (i.e. tools that execute
# commands).  All other tools skip keyword checks and use per-tool or global
# defaults — prevents false positives like "form" matching "rm " in WebSearch.
KEYWORD_MATCH_TOOLS = {"Bash"}

# Legacy skip set kept for backward-compat in case anything references it.
SKIP_KEYWORD_CHECK = {"ExitPlanMode", "EnterPlanMode", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "AskUserQuestion"}

# Privilege-escalation prefixes — never auto-approve these via scoped rules.
UNSAFE_PREFIXES = {"sudo", "doas"}

# Sentinel: cd appeared but target can't be determined (no args, $VAR, etc.)
_UNKNOWN_CD = object()

# Characters indicating shell globs — the exact filenames can't be resolved
# statically, but the *directory* containing the glob can still be checked.
GLOB_CHARS = set("*?[]{}")


class GlobDir(str):
    """A path that is the *directory* containing a glob pattern.

    Behaves exactly like a ``str`` everywhere, but carries a flag so the
    containment check knows this represents files *inside* the directory
    (e.g. ``/tmp/x*`` → ``/tmp``).  Unlike a literal path, a glob's
    directory is allowed to *equal* an allowed dir — the glob can only ever
    match files within it, never the directory itself.
    """

    is_glob_dir = True


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


def _strip_heredoc_contents(text):
    """Replace heredoc bodies with empty markers.

    Matches ``<<EOF...EOF``, ``<<'EOF'...EOF``, ``<<"EOF"...EOF`` and
    common variants (HEREDOC, END, MSG, etc.).  The delimiter and body
    are replaced so keywords inside commit messages, PR descriptions,
    etc. don't trigger false positives.
    """
    return re.sub(
        r"<<-?\s*['\"]?(\w+)['\"]?\s*\n.*?\n\s*\1",
        "<<STRIPPED_HEREDOC",
        text,
        flags=re.DOTALL,
    )


def _strip_quoted_contents(text):
    """Replace contents of quoted strings with empty markers.

    Prevents keywords inside commit messages, echo strings, etc. from
    triggering false positives.  The actual command tokens outside quotes
    are preserved.
    """
    text = _strip_heredoc_contents(text)
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


def _keyword_match(keyword, text):
    """Check if keyword appears in text at a word boundary.

    Uses ``(?<!\\w)`` (not preceded by a word character) so that ``rm ``
    matches standalone ``rm -f`` but not ``JobRequiredForm -name``.
    The trailing content of the keyword is matched literally.
    """
    pattern = r"(?<!\w)" + re.escape(keyword)
    return re.search(pattern, text, re.IGNORECASE) is not None


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
                return GlobDir(prefix[:last_sep])
            if last_sep == 0:
                return GlobDir("/")
            return GlobDir(".")
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
    if not HAS_BASHLEX:
        return None
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

        # A glob's directory prefix represents files *inside* that directory,
        # so it may equal an allowed dir.  A literal path must be strictly
        # inside (equality would mean deleting the dir itself → ask).
        is_glob_dir = getattr(raw_path, "is_glob_dir", False)

        contained = False
        for allowed in allowed_dirs:
            allowed_real = os.path.realpath(allowed)
            if resolved.startswith(allowed_real + os.sep) or (
                is_glob_dir and resolved == allowed_real
            ):
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
    matched_scoped = [kw for kw in scoped_keywords if _keyword_match(kw, normalized)]
    if not matched_scoped:
        return None

    # Reject if ask-only keywords (not in scoped) also appear in the command.
    # We can't verify those commands, so the whole chain must go to ask.
    ask_keywords = rules.get("ask", {}).get("keywords", [])
    scoped_set = {kw.lower() for kw in scoped_keywords}
    for kw in ask_keywords:
        if kw.lower() not in scoped_set and _keyword_match(kw, normalized):
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

        # A preceding cd only affects how *relative* paths resolve.  If every
        # path arg is absolute, the cd target is irrelevant to this command
        # (e.g. "cd ~/elsewhere && rm /tmp/x") — don't reject on it.
        all_absolute = all(
            os.path.isabs(os.path.expanduser(p)) for p in path_args
        )

        # Determine effective cwd — handle cd preceding the command
        effective_cwd = cwd
        cd = cmd["cd_target"]
        if not all_absolute:
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

    matched = [kw for kw in docker_keywords if _keyword_match(kw, normalized)]
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


# Hostnames that mean "the local machine's postgres" — safe to auto-approve.
# Empty string covers the no-host case (psql connects via local unix socket).
PSQL_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", ""}

# Command words that, when they wrap a psql invocation, mean psql runs on a
# *different* machine — so even `-h localhost` refers to the remote box.
# Their presence forces a prompt regardless of the parsed host.
PSQL_REMOTE_WRAPPERS = ("ssh", "kubectl", "rancher")

# Patterns that surface the target host of a psql connection.  Run against the
# raw command (hosts usually sit outside quotes, e.g. `-h localhost`, and conn
# strings may be quoted so we must see inside them).  `-h\s*` covers both
# `-h host` and the no-space `-hhost` form; the `host=` key tolerates a leading
# quote (`"host=prod ..."`) but stops at the next quote/space so quoted SQL
# values like `host='x'` don't match.
_PSQL_HOST_RES = [
    re.compile(r"(?:^|\s)-h\s*([^\s]+)"),
    re.compile(r"(?:^|\s)--host(?:=|\s+)(\S+)"),
    re.compile(r"postgres(?:ql)?://(?:[^@/\s]*@)?([^:/\s]+)", re.IGNORECASE),
    re.compile(r"(?<![\w-])host=([^\s\"']+)"),
    re.compile(r"(?:^|\s)PGHOST=(\S+)"),
]

# A connection *service* (pg_service.conf) or PGSERVICE resolves the host from
# an external file we can't read statically — so we can't prove it's local.
# Treat its presence as remote → prompt.
_PSQL_SERVICE_RE = re.compile(r"(?<![\w-])(?:service=|PGSERVICE=)", re.IGNORECASE)


def _clean_psql_host(h):
    """Strip surrounding quotes/escapes from a captured host token."""
    return h.strip().strip("'\"").strip("\\").strip("'\"").strip()


def check_psql_scoped(command, config):
    """Host-aware psql access control.

    Auto-approves psql commands that target the **local** machine's database
    (``-h localhost``/``127.0.0.1``/``::1``, a unix socket, or no host at all),
    and prompts (``ask``) when psql targets a remote host or runs on another
    machine via a remote wrapper (ssh/kubectl/rancher).

    Returns ("allow"|"ask", reason) or None to fall through.  A ``docker exec``
    that is *not* itself under a remote wrapper is treated as local (a local
    dev container).  Returns None (defer) when a local psql line also contains
    an uncovered ask keyword (rm/mv/...), so that command's risk is still
    surfaced by the normal ask-keyword pass.
    """
    rules = config.get("rules", {})
    psql_cfg = rules.get("psql_scoped", {})
    if not psql_cfg.get("enabled", False):
        return None

    # Only engage when psql actually appears as a command word.
    if not re.search(r"(?<!\w)psql(?!\w)", command, re.IGNORECASE):
        return None

    local_hosts = {h.lower() for h in psql_cfg.get("local_hosts", [])} | PSQL_LOCAL_HOSTS
    wrappers = tuple(psql_cfg.get("remote_wrappers", PSQL_REMOTE_WRAPPERS))

    # A remote wrapper means psql executes on another machine — even
    # `-h localhost` is that machine's localhost.  Always prompt.
    tokens = command.split()
    for i, t in enumerate(tokens):
        if t in wrappers and _is_command_position(tokens, i):
            return "ask", f"Remote psql via {t} — prompt"

    # A connection service resolves the host from an external file we can't
    # read — we can't prove it's local, so prompt.
    if _PSQL_SERVICE_RE.search(command):
        return "ask", "psql uses a connection service (host not statically verifiable) — prompt"

    # Collect every host the command targets.
    hosts = []
    for rx in _PSQL_HOST_RES:
        for m in rx.finditer(command):
            hosts.append(_clean_psql_host(m.group(1)))

    remote = [
        h for h in hosts
        if h.lower() not in local_hosts and not h.startswith("/")
    ]
    if remote:
        uniq = ", ".join(sorted(set(remote)))
        return "ask", f"psql targets non-local host(s): {uniq}"

    # Local psql (explicit local host or no host = unix socket).  Before
    # auto-approving, make sure no *other* ask keyword (rm/mv/...) rides along
    # in the same line — if it does, defer so that risk still prompts.
    normalized = command
    for safe in rules.get("safe_substrings", []):
        normalized = normalized.replace(safe, "")
    normalized = _strip_quoted_contents(normalized)
    normalized = _strip_comments(normalized)
    for kw in rules.get("ask", {}).get("keywords", []):
        if _keyword_match(kw, normalized):
            return None

    return "allow", "Local psql — auto-approved"


# Tokens that separate one simple command from the next in a chain.
_CMD_SEPARATORS = {"&&", "||", ";", "|", "&", "(", ")"}

# Flags (other than the context flag) that take a value argument, so the
# following token must be skipped when hunting for the subcommand.  Includes
# helmfile's -e/--environment — without it, "helmfile -e production apply"
# mistakes "production" for the subcommand.
_VALUE_FLAGS = {
    "--namespace", "-n", "--kubeconfig", "--server", "-s",
    "--token", "--user", "--cluster", "--certificate-authority",
    "--client-certificate", "--client-key", "-o", "--output",
    "-l", "--selector", "-f", "--filename", "--timeout",
    "--sort-by", "--field-selector", "-e", "--environment",
}


def _kubectl_current_context():
    """Best-effort `kubectl config current-context`, or None."""
    try:
        import shutil
        import subprocess
        kubectl = shutil.which("kubectl") or "/usr/local/bin/kubectl"
        result = subprocess.run(
            [kubectl, "config", "current-context"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip() or None
    except Exception:
        pass
    return None


def _is_command_position(tokens, i):
    """True if tokens[i] starts a new simple command.

    Covers the start of the line, the token after a shell separator, after
    ``xargs``, and after env-assignment prefixes (``FOO=bar kubectl ...``).
    """
    if i == 0:
        return True
    prev = tokens[i - 1]
    if prev in _CMD_SEPARATORS or prev == "xargs":
        return True
    # Env-assignment prefix (FOO=bar) immediately before the command.
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", prev):
        return True
    return False


def check_kubectl_scoped(command, config):
    """Context-aware kubectl/helm/helmfile access control.

    Auto-approves write operations on non-production contexts, prompts for
    production writes.  Read operations return None (fall through to native
    permissions which auto-approve them).

    The tool is detected at *any* command position in a chain — not just the
    first token — so env-prefixed (``FOO=bar kubectl``), chained
    (``... && kubectl delete``), and ``xargs kubectl`` invocations are all
    covered.  A ``kubectl config use-context <ctx>`` earlier in the same chain
    sets the effective context for later writes.  Each write invocation is
    evaluated; the most restrictive outcome wins (ask > allow).
    """
    rules = config.get("rules", {})
    kubectl_scoped = rules.get("kubectl_scoped", {})
    if not kubectl_scoped:
        return None

    prod_contexts = set(kubectl_scoped.get("production_contexts", []))
    writes_by_tool = {
        "kubectl": set(kubectl_scoped.get("kubectl_write_subcommands", [])),
        "rancher kubectl": set(kubectl_scoped.get("kubectl_write_subcommands", [])),
        "helm": set(kubectl_scoped.get("helm_write_subcommands", [])),
        "helmfile": set(kubectl_scoped.get("helmfile_write_subcommands", [])),
    }
    # helmfile environments are orthogonal to kube contexts, so we never fall
    # back to `kubectl current-context` for it — an unconfirmed helmfile write
    # context stays unknown (→ ask).
    context_flag_by_tool = {
        "kubectl": "--context",
        "rancher kubectl": "--context",
        "helm": "--kube-context",
        "helmfile": "--kube-context",
    }
    uses_kube_fallback = {"kubectl", "rancher kubectl", "helm"}

    tokens = command.split()
    if not tokens:
        return None

    # Locate every tool invocation and the token range of its segment.
    invocations = []  # (tool, start_idx, end_idx)
    i = 0
    n = len(tokens)
    while i < n:
        if not _is_command_position(tokens, i):
            i += 1
            continue
        tool = None
        start = i
        if tokens[i] == "rancher" and i + 1 < n and tokens[i + 1] == "kubectl":
            tool = "rancher kubectl"
        elif tokens[i] in ("kubectl", "helm", "helmfile"):
            tool = tokens[i]
        if tool is None:
            i += 1
            continue
        # Segment runs until the next separator.
        end = i + 1
        while end < n and tokens[end] not in _CMD_SEPARATORS:
            end += 1
        invocations.append((tool, start, end))
        i = end

    if not invocations:
        return None

    # A `kubectl config use-context <ctx>` anywhere in the chain sets the
    # effective context for writes that don't name one explicitly.
    chain_context = None
    for tool, start, end in invocations:
        seg = tokens[start:end]
        head = 2 if tool == "rancher kubectl" else 1
        rest = seg[head:]
        if len(rest) >= 3 and rest[0] == "config" and rest[1] == "use-context":
            chain_context = rest[2]

    def _parse_segment(tool, seg):
        """Return (subcommand, explicit_context) for one tool segment."""
        head = 2 if tool == "rancher kubectl" else 1
        context_flag = context_flag_by_tool[tool]
        subcommand = None
        context = None
        skip_next = False
        for t in seg[head:]:
            if skip_next:
                skip_next = False
                continue
            if t == context_flag:
                skip_next = True
                continue
            if t.startswith(context_flag + "="):
                context = t.split("=", 1)[1]
                continue
            if t in _VALUE_FLAGS:
                skip_next = True
                continue
            if t.startswith("-"):
                continue
            if subcommand is None:
                subcommand = t
        # Re-scan for the context flag's value (separate pass keeps the
        # subcommand logic simple).
        for j, t in enumerate(seg[head:]):
            if t == context_flag and head + j + 1 < len(seg):
                context = seg[head + j + 1]
        return subcommand, context

    results = []
    for tool, start, end in invocations:
        seg = tokens[start:end]
        subcommand, context = _parse_segment(tool, seg)
        if subcommand is None or subcommand not in writes_by_tool[tool]:
            continue  # read / non-write / use-context itself

        if context is None:
            context = chain_context
        if context is None and tool in uses_kube_fallback:
            context = _kubectl_current_context()

        if context is None:
            results.append(("ask", f"Write operation ({tool} {subcommand}) but context unknown"))
        elif context in prod_contexts:
            results.append(("ask", f"Write operation on PRODUCTION: {tool} {subcommand} (context: {context})"))
        else:
            results.append(("allow", f"Write on non-production context: {tool} {subcommand} (context: {context})"))

    if not results:
        return None
    # Most restrictive wins: any ask → ask.
    for action, reason in results:
        if action == "ask":
            return action, reason
    return results[0]


def _decide_single(command, config, cwd=""):
    """Evaluate a single logical command line through the full rule pipeline.

    Returns (action, reason) tuple.  This is the core keyword-matching logic
    extracted from decide() so it can be applied per-line for multiline inputs.
    """
    rules = config.get("rules", {})

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
        if _keyword_match(kw, normalized):
            return "deny", f"Matched deny keyword: {kw}"

    # kubectl/helm/helmfile context-aware scoped rules (before generic ask keywords)
    kubectl_result = check_kubectl_scoped(command, config)
    if kubectl_result is not None:
        return kubectl_result

    # Scoped rules: auto-approve dangerous commands when all paths are in-project
    if cwd:
        scoped_result = check_scoped_rules(command, cwd, config)
        if scoped_result is not None:
            return scoped_result

    # Docker scoped rules: auto-approve docker rm/rmi with literal targets
    docker_result = check_docker_scoped(command, config)
    if docker_result is not None:
        return docker_result

    # psql host-scoped rules: auto-approve local psql, prompt for remote psql
    psql_result = check_psql_scoped(command, config)
    if psql_result is not None:
        return psql_result

    # Ask keywords (second priority - also catches failed scoped checks)
    for kw in rules.get("ask", {}).get("keywords", []):
        if _keyword_match(kw, normalized):
            return "ask", f"Matched ask keyword: {kw}"

    # Allow keywords
    for kw in rules.get("allow", {}).get("keywords", []):
        if _keyword_match(kw, command):
            return "allow", f"Matched allow keyword: {kw}"

    return None, None


# Priority ranking for combining per-line results (higher = more restrictive)
_ACTION_PRIORITY = {"allow": 0, "ask": 1, "deny": 2}


def _split_multiline(command):
    """Split a multiline command into individual logical lines.

    Joins line continuations (backslash + newline) first, then splits on
    remaining newlines that are **outside** quoted strings.  A newline inside
    a quoted string (e.g. a multi-line ``git commit -m "..."`` message) is
    kept on the same logical line so later quote-stripping can remove its
    contents — otherwise keywords inside the message leak out per-line.
    Skips blank lines and comment-only lines.
    """
    # Join line continuations into single logical lines
    joined = command.replace("\\\n", "")

    lines = []
    cur = []
    in_single = False
    in_double = False
    for ch in joined:
        if ch == "'" and not in_double:
            in_single = not in_single
            cur.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            cur.append(ch)
        elif ch == "\n" and not in_single and not in_double:
            lines.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    lines.append("".join(cur))

    result = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        result.append(stripped)
    return result


def decide(tool_name, command, config, cwd=""):
    rules = config.get("rules", {})
    default = rules.get("default_action", "approve")

    # Only run keyword matching on tools that actually execute commands.
    # Other tools (WebSearch, Read, Grep, ToolSearch, etc.) skip to per-tool
    # or global default — prevents "form" matching "rm " and similar noise.
    if tool_name not in KEYWORD_MATCH_TOOLS:
        tool_cfg = config.get("tools", {}).get(tool_name, {})
        if "default_action" in tool_cfg:
            return normalize(tool_cfg["default_action"]), f"Tool default for {tool_name}"
        return normalize(default), f"Skipped keyword check for {tool_name}"

    # Strip heredoc bodies before any line splitting so keywords inside
    # commit messages, PR descriptions, etc. don't leak into per-line checks.
    command_stripped = _strip_heredoc_contents(command)

    # Check if command is multiline (after joining continuations)
    joined = command_stripped.replace("\\\n", "")
    if "\n" not in joined:
        # Single-line: evaluate directly (existing behavior, zero overhead)
        action, reason = _decide_single(command_stripped, config, cwd=cwd)
        if action is not None:
            return action, reason
    else:
        # Multiline: split into logical lines, evaluate each independently,
        # return the most restrictive result (deny > ask > allow)
        lines = _split_multiline(command_stripped)
        if not lines:
            # All lines were blank/comments - fall through to defaults
            pass
        else:
            worst_action = None
            worst_reason = None
            worst_priority = -1
            for line in lines:
                action, reason = _decide_single(line, config, cwd=cwd)
                if action is not None:
                    p = _ACTION_PRIORITY.get(action, 1)
                    if p > worst_priority:
                        worst_priority = p
                        worst_action = action
                        worst_reason = reason
                    if action == "deny":
                        return worst_action, worst_reason
            if worst_action is not None:
                return worst_action, worst_reason

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
