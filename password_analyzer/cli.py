"""Command line interface.

    python -m password_analyzer              open the window
    python -m password_analyzer check        analyze a password typed at a hidden prompt
    python -m password_analyzer generate     print strong passwords
    python -m password_analyzer history      show or clear the password history

Passwords are read from a hidden prompt or from standard input, never from the
command line arguments, because arguments end up in the shell history.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from .analyzer import analyze
from .generator import suggestions
from .history import PasswordHistory


def read_password(from_stdin: bool) -> str:
    if from_stdin or not sys.stdin.isatty():
        # some shells put an invisible byte order mark in front of piped text
        return sys.stdin.readline().rstrip("\r\n").removeprefix("﻿")
    return getpass.getpass("Password: ")


def command_check(args) -> int:
    password = read_password(args.stdin)
    history = None if args.no_history else PasswordHistory(args.db)
    reuse = history.check(args.account, password) if history else None
    analysis = analyze(password, args.personal, reuse)

    if args.save and history and password:
        history.add(args.account, password)

    if args.json:
        output = analysis.to_dict()
        output["alternatives"] = [vars(s) for s in suggestions()] if analysis.score < 3 else []
        print(json.dumps(output, indent=2))
        return 0 if analysis.score >= 3 else 1

    print(f"Strength: {analysis.label} ({analysis.score}/4, about {analysis.bits:.0f} bits)")
    print(f"Time to crack: {analysis.offline_time} offline, {analysis.online_time} online")
    print("\nChecks")
    for check in analysis.checks:
        print(f"  [{'ok' if check.passed else '!!'}] {check.name}: {check.message}")
    if analysis.suggestions:
        print("\nHow to improve")
        for suggestion in analysis.suggestions:
            print(f"  - {suggestion}")
    if analysis.score < 3:
        print("\nStronger alternatives")
        for suggestion in suggestions():
            print(f"  {suggestion.kind:14} {suggestion.password}   ({suggestion.bits:.0f} bits)")
    if args.save and history and password:
        print(f"\nRemembered as used for account '{args.account}'.")
    return 0 if analysis.score >= 3 else 1


def command_generate(args) -> int:
    for _ in range(args.count):
        for suggestion in suggestions():
            print(f"{suggestion.kind:14} {suggestion.password}   ({suggestion.bits:.0f} bits, {suggestion.label.lower()})")
    return 0


def command_history(args) -> int:
    history = PasswordHistory(args.db)
    if args.clear:
        removed = history.clear(args.account)
        print(f"Removed {removed} remembered password(s) for account '{args.account}'.")
        return 0
    dates = history.dates(args.account)
    print(f"Account '{args.account}': {len(dates)} remembered password(s). Only salted hashes are stored.")
    for date in dates:
        print(f"  added {date}")
    return 0


def command_gui(args) -> int:
    from .gui import run

    run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="password_analyzer", description="Password Strength Analyzer")
    parser.set_defaults(run=command_gui)
    commands = parser.add_subparsers(dest="command")

    check = commands.add_parser("check", help="analyze a password")
    check.add_argument("--account", default="default", help="whose password history to check against")
    check.add_argument("--personal", default="", help="your name, username or email, to check the password avoids them")
    check.add_argument("--save", action="store_true", help="remember this password as used")
    check.add_argument("--no-history", action="store_true", help="do not use the password history")
    check.add_argument("--stdin", action="store_true", help="read the password from standard input")
    check.add_argument("--json", action="store_true", help="print the result as JSON")
    check.add_argument("--db", help="path of the history database")
    check.set_defaults(run=command_check)

    generate = commands.add_parser("generate", help="print strong passwords")
    generate.add_argument("--count", type=int, default=1, help="how many sets to print")
    generate.set_defaults(run=command_generate)

    history = commands.add_parser("history", help="show or clear the password history")
    history.add_argument("--account", default="default")
    history.add_argument("--clear", action="store_true", help="forget the account's remembered passwords")
    history.add_argument("--db", help="path of the history database")
    history.set_defaults(run=command_history)

    gui = commands.add_parser("gui", help="open the window")
    gui.set_defaults(run=command_gui)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.run(args)
