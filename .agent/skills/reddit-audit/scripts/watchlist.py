#!/usr/bin/env python3
"""Manage confirmed bot/swarm/benign watchlist entries in data/reddit_graph.db."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import audit_thread as core  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage confirmed verdicts in the Reddit audit SQLite watchlist."
    )
    parser.add_argument(
        "--db",
        default=str(core.DEFAULT_DB_PATH),
        help=f"SQLite DB path (default: {core.DEFAULT_DB_PATH}).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="Add or update a watchlist verdict.")
    p_add.add_argument("author", help="Reddit username (with or without u/).")
    p_add.add_argument(
        "--verdict",
        required=True,
        choices=sorted(core.WATCHLIST_VALID_VERDICTS),
        help="Verdict classification.",
    )
    p_add.add_argument(
        "--confidence",
        type=int,
        default=85,
        help="Confidence score 0-100 (default: 85).",
    )
    p_add.add_argument(
        "--notes",
        default="",
        help="Short evidence note (truncated to 240 chars).",
    )

    p_rm = sub.add_parser("remove", help="Remove an author from the watchlist.")
    p_rm.add_argument("author", help="Reddit username to remove.")

    p_ls = sub.add_parser("list", help="List watchlist entries.")
    p_ls.add_argument(
        "--verdict",
        default=None,
        choices=sorted(core.WATCHLIST_VALID_VERDICTS),
        help="Optional verdict filter.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    db = core.RedditGraphDB(Path(args.db))
    try:
        if args.command == "add":
            try:
                entry = db.upsert_watchlist(
                    author=args.author,
                    verdict=args.verdict,
                    confidence=args.confidence,
                    notes=args.notes,
                )
            except ValueError as exc:
                return core.emit_error("invalid_watchlist_entry", str(exc))
            out = {"status": "ok", "action": "added", "entry": entry}
        elif args.command == "remove":
            removed = db.remove_watchlist(args.author)
            out = {
                "status": "ok",
                "action": "removed" if removed else "not_found",
                "author": args.author.lstrip("/").removeprefix("u/"),
            }
        else:
            entries = db.list_watchlist(verdict_filter=args.verdict)
            out = {"status": "ok", "count": len(entries), "entries": entries}
    finally:
        db.close()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
