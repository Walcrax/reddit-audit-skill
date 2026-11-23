#!/usr/bin/env python3
"""Batch subreddit scanner & SQLite graph seeder (Python stdlib only).

Fetches recent threads from r/<subreddit> (spaced >= 2s apart) and runs the
local audit_thread pipeline incrementally into data/reddit_graph.db so
cross-thread swarm clusters and >60% power-user calibration work accurately.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import audit_thread as core  # noqa: E402


def normalize_subreddit(raw: str) -> str:
    """Accept 'SaaS', 'r/SaaS', '/r/SaaS', or a reddit.com/r/SaaS URL."""
    s = (raw or "").strip()
    if "reddit.com/" in s.lower():
        parsed = urllib.parse.urlparse(s if "://" in s else "https://" + s)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) >= 2 and parts[0].lower() == "r":
            s = parts[1]
    s = s.lstrip("/")
    if s.lower().startswith("r/"):
        s = s[2:]
    s = s.split("/")[0].split("?")[0]
    return core.sanitize_identifier(s, "")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Seed data/reddit_graph.db and audit recent threads in a subreddit."
    )
    parser.add_argument(
        "subreddit",
        nargs="?",
        help="Subreddit name (e.g. SaaS, r/SaaS) or subreddit URL.",
    )
    parser.add_argument(
        "--mock",
        dest="mock_path",
        default=None,
        help="Offline JSON file containing a list of Reddit thread payloads for batch testing.",
    )
    parser.add_argument(
        "--sort",
        choices=["new", "hot", "top"],
        default="new",
        help="Subreddit listing sort order (default: new).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of threads to scan (1-25, default: 10).",
    )
    parser.add_argument(
        "--max-comments",
        type=int,
        default=30,
        help="Max non-ignored comments per thread (default: 30).",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=4,
        help="Comment tree depth per thread (default: 4).",
    )
    parser.add_argument(
        "--include-stickied",
        action="store_true",
        help="Include stickied/pinned moderator announcements.",
    )
    parser.add_argument(
        "--with-profile-fetch",
        action="store_true",
        help="Enable stage-2 profile fetches during batch scan (off by default for speed/rate-limits).",
    )
    parser.add_argument(
        "--ignore-users",
        action="append",
        default=[],
        help="Comma-separated usernames to ignore (repeatable).",
    )
    parser.add_argument(
        "--window-sec",
        type=float,
        default=300.0,
        help="Co-occurrence time window in seconds (default: 300).",
    )
    parser.add_argument(
        "--db",
        default=str(core.DEFAULT_DB_PATH),
        help=f"SQLite graph DB path (default: {core.DEFAULT_DB_PATH}).",
    )
    parser.add_argument(
        "--user-agent",
        default=core.DEFAULT_USER_AGENT,
        help="Custom HTTP User-Agent header.",
    )
    parser.add_argument(
        "--no-oauth",
        action="store_true",
        help="Disable Reddit OAuth2 even if REDDIT_CLIENT_ID/SECRET are configured.",
    )
    parser.add_argument(
        "--source",
        choices=["auto", "reddit", "arctic-shift"],
        default="auto",
        help="Data backend: auto (Reddit OAuth/public with Arctic Shift 403 fallback), reddit, or arctic-shift.",
    )
    parser.add_argument(
        "--min-age-hours",
        type=float,
        default=6.0,
        help="Arctic Shift lookback in hours so scanned posts have indexed comments (default: 6.0; 0 disables).",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.mock_path and not args.subreddit:
        return core.emit_error(
            "invalid_arguments",
            "Provide a subreddit name/URL (e.g. r/SaaS) or --mock <batch_threads.json>.",
        )

    limit = max(1, min(25, args.limit))
    ignored_authors = set(core.DEFAULT_IGNORED_AUTHORS)
    for entry in args.ignore_users:
        for item in entry.split(","):
            u = item.strip().lower().lstrip("/")
            if u.startswith("u/"):
                u = u[2:]
            if u:
                ignored_authors.add(u)

    fetcher = core.RateLimitedFetcher(
        user_agent=args.user_agent,
        delay_sec=core.REQUEST_DELAY_SEC,
        use_oauth=not args.no_oauth,
        source=args.source,
    )
    warnings: list[str] = []
    partial = False
    mock_mode = bool(args.mock_path)

    thread_payloads: list[tuple[str, Any]] = []
    subreddit_name = "unknown"

    if mock_mode:
        mock_file = core.resolve_local_file(args.mock_path)
        if mock_file is None:
            return core.emit_error(
                "mock_file_not_found",
                f"Could not find mock batch file at '{args.mock_path}'.",
            )
        try:
            raw_batch = json.loads(mock_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return core.emit_error("mock_parse_error", f"Failed to read mock batch file: {exc}")
        if not isinstance(raw_batch, list):
            return core.emit_error(
                "mock_parse_error",
                "Mock batch file must be a JSON array of native Reddit thread payloads.",
            )
        for idx, item in enumerate(raw_batch[:limit]):
            thread_payloads.append((f"mock_{idx}", item))
    else:
        subreddit_name = normalize_subreddit(args.subreddit)
        if not subreddit_name:
            return core.emit_error("invalid_subreddit", "Could not parse a valid subreddit name.")

        posts, err, sub_notes = fetcher.fetch_subreddit_posts(
            subreddit_name,
            sort=args.sort,
            limit=limit,
            include_stickied=args.include_stickied,
            min_age_hours=max(0.0, args.min_age_hours),
        )
        warnings.extend(sub_notes)
        if err is not None:
            return core.emit_error(
                str(err.get("type", "fetch_error")),
                str(err.get("message", "Failed to fetch subreddit listing.")),
                code=err.get("code"),
            )

        for post in posts or []:
            tid = core.sanitize_identifier(post.get("id"), "")
            if not tid:
                continue
            if fetcher.active_source == "arctic_shift":
                payload, t_err, t_notes = fetcher.fetch_thread_arctic(
                    tid, max_comments=max(1, args.max_comments), post_override=post
                )
                warnings.extend(t_notes)
            else:
                permalink = str(post.get("permalink") or f"/comments/{tid}/")
                t_url = f"https://www.reddit.com{permalink}"
                payload, t_err, t_notes = fetcher.fetch_thread(
                    t_url, max_comments=max(1, args.max_comments), depth=max(1, args.depth)
                )
                warnings.extend(t_notes)

            if t_err is not None:
                warnings.append(f"Thread {tid}: {t_err['message']}")
                if t_err.get("code") == 429:
                    partial = True
                    break
                continue
            thread_payloads.append((tid, payload))

    # Run incremental audits on all fetched threads
    db = core.RedditGraphDB(Path(args.db))
    thread_summaries: list[dict[str, Any]] = []
    account_agg: dict[str, dict[str, Any]] = {}
    all_clusters: dict[tuple[str, ...], dict[str, Any]] = {}
    all_power_users: set[str] = set()
    all_role_patterns: dict[str, dict[str, Any]] = {}
    all_watchlist_hits: dict[str, dict[str, Any]] = {}
    all_watchlist_assoc: list[dict[str, Any]] = []

    try:
        for label, payload in thread_payloads:
            try:
                res = core.audit_thread_payload(
                    payload=payload,
                    db=db,
                    fetcher=fetcher,
                    ignored_authors=ignored_authors,
                    max_comments=args.max_comments,
                    top_n=5,
                    window_sec=args.window_sec,
                    no_profile_fetch=not args.with_profile_fetch,
                    mock_mode=mock_mode,
                    mock_profiles=None,
                )
            except ValueError as exc:
                warnings.append(f"Parse error on {label}: {exc}")
                continue

            op = res["op_analysis"]
            subreddit_name = op["subreddit"]
            meta = res["audit_meta"]
            anomalies = res["top_anomalies"]
            max_comment_score = max((a["anomaly_score"] for a in anomalies), default=0)

            thread_summaries.append(
                {
                    "thread_id": op["thread_id"],
                    "op_author": op["author"],
                    "op_score": op["anomaly_score"],
                    "max_comment_score": max_comment_score,
                    "comments_analyzed": meta["comments_analyzed"],
                    "comments_flagged": meta["comments_flagged"],
                    "untrusted_content": core.neutralize_untrusted_text(
                        op["untrusted_content"].split("\nBODY:")[0], 140
                    ),
                }
            )

            # Aggregate flagged accounts (OP + anomalous commenters)
            def record_account(author: str, score: int, flags: list[str], tid: str) -> None:
                if score <= 0:
                    return
                if author not in account_agg:
                    account_agg[author] = {
                        "author": author,
                        "max_score": score,
                        "threads": {tid},
                        "flags": set(flags),
                    }
                else:
                    rec = account_agg[author]
                    rec["max_score"] = max(rec["max_score"], score)
                    rec["threads"].add(tid)
                    rec["flags"].update(flags)

            if op["flagged"]:
                record_account(op["author"], op["anomaly_score"], op["flags"], op["thread_id"])
            for a in anomalies:
                record_account(a["author"], a["anomaly_score"], a["flags"], op["thread_id"])

            for cl in res["graph_clusters"]:
                key = tuple(cl["authors"])
                if key not in all_clusters or cl["max_distinct_threads"] > all_clusters[key]["max_distinct_threads"]:
                    all_clusters[key] = cl

            all_power_users.update(meta.get("power_users_flagged", []))
            for rp in meta.get("repeating_role_patterns", []):
                all_role_patterns[rp["pattern"]] = rp
            for wh in meta.get("watchlist_hits", []):
                all_watchlist_hits[wh["author"]] = wh
            all_watchlist_assoc.extend(meta.get("watchlist_associations", []))

        db_stats = db.get_db_stats(subreddit_name)
    finally:
        db.close()

    ranked_accounts = sorted(
        [
            {
                "author": rec["author"],
                "max_score": rec["max_score"],
                "threads_flagged": len(rec["threads"]),
                "flags": sorted(rec["flags"])[:6],
            }
            for rec in account_agg.values()
        ],
        key=lambda x: (-x["max_score"], -x["threads_flagged"], x["author"]),
    )

    ranked_threads = sorted(
        thread_summaries,
        key=lambda x: (-max(x["op_score"], x["max_comment_score"]), -x["comments_flagged"]),
    )

    recommended_deep_checks = [
        a["author"] for a in ranked_accounts if a["max_score"] >= 60
    ][:5]

    report: dict[str, Any] = {
        "status": "ok",
        "mode": "mock" if mock_mode else "live",
        "data_source": "mock" if mock_mode else fetcher.active_source,
        "auth_mode": "mock" if mock_mode else fetcher.auth_mode,
        "subreddit": subreddit_name,
        "sort": args.sort,
        "partial": partial,
        "threads_scanned": len(thread_summaries),
        "db_stats": db_stats,
        "top_flagged_accounts": ranked_accounts[:8],
        "recommended_deep_checks": recommended_deep_checks,
        "flagged_threads": ranked_threads[:8],
        "graph_clusters": list(all_clusters.values())[:6],
        "repeating_role_patterns": list(all_role_patterns.values())[:6],
        "power_users_flagged": sorted(all_power_users),
        "watchlist_hits": list(all_watchlist_hits.values()),
        "watchlist_associations": all_watchlist_assoc[:8],
        "warnings": warnings[:10],
    }

    output_json = core.serialize_within_budget(report, max_bytes=core.MAX_OUTPUT_BYTES)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(output_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
