#!/usr/bin/env python3
"""CLI viewer for claude-auto-approver logs."""

import argparse
import json
import os
import sys
import time
import datetime

LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")


def load_log(date_str):
    path = os.path.join(LOGS_DIR, f"{date_str}.jsonl")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def print_entry(e):
    ts = e["ts"][:19].replace("T", " ")
    action = e["action"].upper()
    color = {"allow": "\033[32m", "deny": "\033[31m", "ask": "\033[33m"}.get(e["action"], "")
    dim = "\033[2m"
    reset = "\033[0m"
    cmd = e["command"][:120]
    project = os.path.basename(e.get("cwd", "")) or "?"
    session = e.get("session", "")[:8]
    print(f"{ts}  {color}{action:5s}{reset}  {dim}[{project}]{reset} [{e['tool']}] {cmd}")
    print(f"           {dim}session:{session}  reason: {e['reason']}{reset}")


def tail_log(date_str):
    path = os.path.join(LOGS_DIR, f"{date_str}.jsonl")
    if not os.path.exists(path):
        print(f"Waiting for {path}...")
    while not os.path.exists(path):
        time.sleep(1)
    with open(path) as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line.strip():
                print_entry(json.loads(line))
            else:
                time.sleep(0.5)


def print_stats(entries):
    from collections import Counter
    actions = Counter(e["action"] for e in entries)
    tools = Counter(e["tool"] for e in entries)
    total = len(entries)
    print(f"Total: {total}")
    for a in ("allow", "deny", "ask"):
        print(f"  {a}: {actions.get(a, 0)}")
    print(f"\nBy tool:")
    for tool, count in tools.most_common():
        print(f"  {tool}: {count}")


def main():
    p = argparse.ArgumentParser(
        description="View claude-auto-approver logs",
        epilog="Examples:\n"
               "  python3 viewer.py                     # today's logs\n"
               "  python3 viewer.py --date 2026-02-12   # specific date\n"
               "  python3 viewer.py --action ask         # only prompts\n"
               "  python3 viewer.py --grep kubectl       # search commands\n"
               "  python3 viewer.py --session 5a12       # specific session\n"
               "  python3 viewer.py --tail               # live follow\n"
               "  python3 viewer.py --stats              # summary counts\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--date", default=datetime.date.today().isoformat(), help="log date (default: today, format: YYYY-MM-DD)")
    p.add_argument("--action", choices=["allow", "deny", "ask"], help="filter by decision")
    p.add_argument("--session", help="filter by session ID (prefix match)")
    p.add_argument("--grep", help="search within commands")
    p.add_argument("--tail", action="store_true", help="live tail (follow mode)")
    p.add_argument("--stats", action="store_true", help="show summary counts")
    args = p.parse_args()

    if args.tail:
        tail_log(args.date)
        return

    entries = load_log(args.date)
    if args.action:
        entries = [e for e in entries if e["action"] == args.action]
    if args.session:
        entries = [e for e in entries if args.session in e.get("session", "")]
    if args.grep:
        entries = [e for e in entries if args.grep.lower() in e.get("command", "").lower()]

    if args.stats:
        print_stats(entries)
    else:
        for e in entries:
            print_entry(e)
        if not entries:
            print("No log entries found.")


if __name__ == "__main__":
    main()
