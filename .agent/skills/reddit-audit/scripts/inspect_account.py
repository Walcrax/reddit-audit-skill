#!/usr/bin/env python3
"""Deep deterministic account confirmation inspector for flagged Reddit users.

Stdlib-only. Fetches /about.json, /comments.json?limit=50, and /submitted.json?limit=25
(spaced >= 2s apart) or reads an offline --mock fixture, updates SQLite baselines,
and evaluates circadian sleep gaps, cron periodicity, dormancy + topic pivot,
stylometric shift, 3-gram self-duplication, domain concentration, and stealth edits.
"""

from __future__ import annotations

import argparse
import collections
import html
import json
import statistics
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import audit_thread as core  # noqa: E402


def normalize_username(raw: str) -> str:
    """Accept 'name', 'u/name', '/u/name', or a reddit.com/user/name URL."""
    s = (raw or "").strip()
    if "reddit.com/" in s.lower():
        parsed = urllib.parse.urlparse(s if "://" in s else "https://" + s)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) >= 2 and parts[0].lower() in ("u", "user"):
            s = parts[1]
    s = s.lstrip("/")
    if s.lower().startswith("u/"):
        s = s[2:]
    elif s.lower().startswith("user/"):
        s = s[5:]
    s = s.split("/")[0].split("?")[0]
    return core.sanitize_identifier(s, "")


def compute_longest_quiet_hours(active_hours: dict[int, int]) -> int:
    """Return longest contiguous run of inactive UTC hours on the 24h ring."""
    if not active_hours:
        return 24
    ring = [1 if active_hours.get(h, 0) > 0 else 0 for h in range(24)]
    if all(ring):
        return 0
    doubled = ring + ring
    best = 0
    cur = 0
    for val in doubled:
        if val == 0:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return min(24, best)


def tokenize_3grams(text: str) -> set[tuple[str, str, str]]:
    """Build normalized word 3-gram set for lightweight self-duplication checks."""
    words = [w.lower() for w in core.RE_WORD_TOKEN.findall(text or "") if len(w) >= 2]
    if len(words) < 8:
        return set()
    return {(words[i], words[i + 1], words[i + 2]) for i in range(len(words) - 2)}


def compute_self_duplication(texts: list[str]) -> tuple[float, int, int]:
    """Return (duplicate_item_ratio, duplicate_pairs_count, eligible_count)."""
    shingles = [tokenize_3grams(t) for t in texts]
    eligible_idx = [i for i, sg in enumerate(shingles) if sg]
    if len(eligible_idx) < 3:
        return 0.0, 0, len(eligible_idx)

    dup_items: set[int] = set()
    dup_pairs = 0
    for pos_a in range(len(eligible_idx)):
        i = eligible_idx[pos_a]
        sa = shingles[i]
        for pos_b in range(pos_a + 1, len(eligible_idx)):
            j = eligible_idx[pos_b]
            sb = shingles[j]
            inter = len(sa & sb)
            if inter == 0:
                continue
            union = len(sa | sb)
            if (inter / union) >= 0.45:
                dup_pairs += 1
                dup_items.add(i)
                dup_items.add(j)

    ratio = round(len(dup_items) / len(eligible_idx), 3)
    return ratio, dup_pairs, len(eligible_idx)


def parse_listing_items(payload: Any, kind: str) -> list[dict[str, Any]]:
    """Parse comments ('t1') or submissions ('t3') from a Reddit user listing."""
    if not isinstance(payload, dict):
        return []
    children = payload.get("data", {}).get("children", [])
    items: list[dict[str, Any]] = []
    for ch in children:
        if not isinstance(ch, dict) or ch.get("kind") != kind:
            continue
        d = ch.get("data", {})
        created_utc = float(d.get("created_utc") or 0.0)
        if created_utc <= 0:
            continue
        subreddit = core.sanitize_identifier(d.get("subreddit"), "unknown")
        if kind == "t1":
            raw_text = html.unescape(str(d.get("body") or ""))
            url_text = raw_text
        else:
            title = html.unescape(str(d.get("title") or ""))
            selftext = html.unescape(str(d.get("selftext") or ""))
            ext_url = "" if d.get("is_self", True) else str(d.get("url") or "")
            raw_text = f"{title}\n{selftext}".strip()
            url_text = f"{raw_text}\n{ext_url}"

        edited_utc, edit_delay = core.parse_edited_utc(d.get("edited"), created_utc)
        _, domains, has_short, has_track, has_funnel = core.extract_urls_and_domains(url_text)
        items.append(
            {
                "kind": kind,
                "id": core.sanitize_identifier(d.get("id"), ""),
                "subreddit": subreddit,
                "created_utc": created_utc,
                "edited_utc": edited_utc,
                "edit_delay_sec": edit_delay,
                "raw_text": raw_text,
                "char_len": len(raw_text),
                "domains": domains,
                "has_shortener": has_short,
                "has_tracking": has_track,
                "has_funnel": has_funnel,
            }
        )
    return items


def inspect_account_data(
    author: str,
    about_payload: Optional[dict[str, Any]],
    comments_payload: Optional[dict[str, Any]],
    submitted_payload: Optional[dict[str, Any]],
    db: core.RedditGraphDB,
    warnings: list[str],
    mode: str,
) -> dict[str, Any]:
    """Compute deep deterministic confirmation metrics and update SQLite baselines."""
    now_utc = time.time()
    about_data = (
        about_payload.get("data", {})
        if isinstance(about_payload, dict) and isinstance(about_payload.get("data"), dict)
        else {}
    )
    created_utc_acct = about_data.get("created_utc")
    account_age_days: Optional[float] = (
        round(max(0.0, (now_utc - float(created_utc_acct)) / 86400.0), 1)
        if isinstance(created_utc_acct, (int, float)) and created_utc_acct > 0
        else None
    )

    comments = parse_listing_items(comments_payload, "t1")
    posts = parse_listing_items(submitted_payload, "t3")
    all_items = sorted(comments + posts, key=lambda x: x["created_utc"])

    # Update author_baselines in SQLite from comment history
    if comments:
        comment_ts = sorted(c["created_utc"] for c in comments)
        comment_lens = [c["char_len"] for c in comments]
        c_intervals = [
            comment_ts[i + 1] - comment_ts[i]
            for i in range(len(comment_ts) - 1)
            if comment_ts[i + 1] >= comment_ts[i]
        ]
        c_hours = dict(collections.Counter(core.utc_hour_from_ts(ts) for ts in comment_ts))
        c_style = core.aggregate_stylometry([c["raw_text"] for c in comments])
        db.upsert_author_baseline(
            author=author,
            account_age_days=account_age_days,
            median_len=round(float(statistics.median(comment_lens)), 1),
            median_interval_sec=(
                round(float(statistics.median(c_intervals)), 1) if c_intervals else None
            ),
            sample_size=len(comments),
            last_checked_utc=now_utc,
            active_hours=c_hours,
            stylometry=c_style,
        )

    score = 0
    flags: list[str] = []

    # 1. Temporal analysis: sleep gap, cron periodicity, dormancy cliff
    all_ts = [x["created_utc"] for x in all_items]
    hour_counts: dict[int, int] = dict(
        collections.Counter(core.utc_hour_from_ts(ts) for ts in all_ts)
    )
    hours_active = len(hour_counts)
    max_quiet_hours = compute_longest_quiet_hours(hour_counts)

    intervals = [
        all_ts[i + 1] - all_ts[i]
        for i in range(len(all_ts) - 1)
        if all_ts[i + 1] >= all_ts[i]
    ]
    median_interval_sec = round(float(statistics.median(intervals)), 1) if intervals else None
    max_dormancy_days = round(max(intervals) / 86400.0, 1) if intervals else 0.0

    # Active-session intervals (60s..7200s) for robotic spacing check
    session_intervals = [iv for iv in intervals if 60.0 <= iv <= 7200.0]
    interval_cv: Optional[float] = None
    if len(session_intervals) >= 6:
        mean_iv = statistics.mean(session_intervals)
        if mean_iv > 0:
            interval_cv = round(statistics.pstdev(session_intervals) / mean_iv, 3)
            if interval_cv <= 0.15:
                score += 28
                flags.append("robotic_fixed_cadence")

    # Cron clock alignment (within +/-15s of exact 15m/30m/60m boundaries)
    cron_aligned_ratio = 0.0
    if len(all_ts) >= 10:
        aligned = sum(
            1
            for ts in all_ts
            if min(ts % 900.0, 900.0 - (ts % 900.0)) <= 15.0
        )
        cron_aligned_ratio = round(aligned / len(all_ts), 3)
        if cron_aligned_ratio >= 0.60:
            score += 22
            flags.append("cron_clock_alignment")

    if len(all_items) >= 24 and hours_active >= 21 and max_quiet_hours <= 2:
        score += 26
        flags.append("no_human_sleep_window")
    elif len(all_items) >= 20 and hours_active >= 19 and max_quiet_hours <= 3:
        score += 14
        flags.append("narrow_sleep_window")

    # 2. Subreddit/topic pivot & historical stylometric shift (older half vs newer half)
    older_top_subs: list[str] = []
    newer_top_subs: list[str] = []
    subreddit_overlap: Optional[float] = None
    older_style: dict[str, float] = {}
    newer_style: dict[str, float] = {}
    older_median_len: Optional[float] = None
    newer_median_len: Optional[float] = None

    if len(all_items) >= 10:
        # Split at largest dormancy gap if >= 30 days, otherwise midpoint
        split_idx = len(all_items) // 2
        if intervals:
            max_gap = max(intervals)
            gap_idx = intervals.index(max_gap) + 1
            if max_gap >= 30 * 86400 and 3 <= gap_idx <= len(all_items) - 3:
                split_idx = gap_idx

        older = all_items[:split_idx]
        newer = all_items[split_idx:]
        older_subs = collections.Counter(x["subreddit"] for x in older)
        newer_subs = collections.Counter(x["subreddit"] for x in newer)
        older_top_subs = [s for s, _ in older_subs.most_common(4)]
        newer_top_subs = [s for s, _ in newer_subs.most_common(4)]

        o_set, n_set = set(older_subs.keys()), set(newer_subs.keys())
        subreddit_overlap = round(len(o_set & n_set) / max(len(o_set | n_set), 1), 3)

        if max_dormancy_days >= 90.0 and subreddit_overlap == 0.0:
            score += 32
            flags.append("dormancy_then_subreddit_pivot")
        elif max_dormancy_days >= 60.0 and subreddit_overlap <= 0.15:
            score += 20
            flags.append("inactivity_and_topic_shift")

        older_style = core.aggregate_stylometry([x["raw_text"] for x in older])
        newer_style = core.aggregate_stylometry([x["raw_text"] for x in newer])
        older_median_len = round(float(statistics.median(x["char_len"] for x in older)), 1)
        newer_median_len = round(float(statistics.median(x["char_len"] for x in newer)), 1)

        len_jump = (
            (newer_median_len / max(older_median_len, 1.0))
            if older_median_len and newer_median_len
            else 1.0
        )
        style_jump = (
            older_style.get("casual_rate", 0.0) >= 0.60
            and older_style.get("markdown_rate", 0.0) <= 0.15
            and newer_style.get("casual_rate", 1.0) <= 0.30
            and (
                newer_style.get("markdown_rate", 0.0) >= 0.40
                or len_jump >= 3.0
                or newer_style.get("em_dash_per_1k", 0.0) >= older_style.get("em_dash_per_1k", 0.0) + 2.5
            )
        )
        if style_jump:
            score += 24
            flags.append("historical_style_takeover_shift")

    # 3. Self-duplication (word 3-gram Jaccard across account's own texts & post-pivot window)
    dup_ratio, dup_pairs, eligible_dup = compute_self_duplication(
        [x["raw_text"] for x in all_items]
    )
    if len(all_items) >= 10:
        newer_dup_ratio, newer_dup_pairs, _ = compute_self_duplication(
            [x["raw_text"] for x in newer]
        )
        effective_dup_ratio = max(dup_ratio, newer_dup_ratio)
        effective_dup_pairs = max(dup_pairs, newer_dup_pairs)
    else:
        effective_dup_ratio = dup_ratio
        effective_dup_pairs = dup_pairs

    if (effective_dup_ratio >= 0.35 and effective_dup_pairs >= 2) or effective_dup_pairs >= 5:
        score += 30
        flags.append("template_or_copy_paste_loop")
    elif effective_dup_ratio >= 0.20 and effective_dup_pairs >= 1:
        score += 18
        flags.append("repeated_phrasing_pattern")

    # 4. External domain concentration, affiliate links, stealth edits, leaked artifacts
    domain_counter: collections.Counter[str] = collections.Counter()
    linked_items = 0
    affiliate_or_shortener_count = 0
    stealth_edit_link_count = 0
    artifact_hits = 0

    for item in all_items:
        txt = item["raw_text"]
        if item["domains"]:
            linked_items += 1
            for d in item["domains"]:
                domain_counter[d] += 1
        if item["has_shortener"] or item["has_tracking"] or item["has_funnel"]:
            affiliate_or_shortener_count += 1
        if (
            item["edit_delay_sec"] is not None
            and item["edit_delay_sec"] >= 300.0
            and core.has_suspicious_edit_link(
                item["domains"],
                item["has_shortener"],
                item["has_tracking"],
                item["has_funnel"],
            )
        ):
            stealth_edit_link_count += 1
        if (
            core.RE_TOOL_CALL_TAGS.search(txt)
            or core.RE_LEAKED_JSON_AGENT.search(txt)
            or core.RE_PROMPT_INJECTION.search(txt)
        ):
            artifact_hits += 1

    top_domains = [{"domain": d, "count": c} for d, c in domain_counter.most_common(4)]
    top_domain_share = (
        round(top_domains[0]["count"] / max(linked_items, 1), 3) if top_domains else 0.0
    )

    if linked_items >= 4 and top_domain_share >= 0.65:
        score += 24
        flags.append("single_domain_shill_concentration")
    if affiliate_or_shortener_count >= 3:
        score += 18
        flags.append("repeated_affiliate_or_shortener_links")
    if stealth_edit_link_count >= 2:
        score += 28
        flags.append("repeated_stealth_edit_links")
    elif stealth_edit_link_count == 1:
        score += 14
        flags.append("stealth_edit_link_detected")
    if artifact_hits >= 1:
        score += 45
        flags.append("historical_agentic_artifact_leak")

    # 5. SQLite graph & watchlist context
    graph_ctx = db.query_author_graph_summary(author)
    wl_entry = graph_ctx.get("watchlist_entry")
    if wl_entry and wl_entry["verdict"].lower() in core.WATCHLIST_BAD_VERDICTS:
        score = max(score, 75)
        flags.append(f"watchlisted_{wl_entry['verdict'].lower()}")
    if graph_ctx.get("watchlisted_associations"):
        score += 20
        flags.append("cooccurs_with_watchlisted")

    final_score = min(100, int(round(score)))
    if final_score >= 80:
        band = "very_high"
    elif final_score >= 60:
        band = "high"
    elif final_score >= 30:
        band = "moderate"
    else:
        band = "low"

    # Build up to 3 neutralized samples (oldest + newest + artifact/stealth if any)
    samples: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    def add_sample(label: str, item: dict[str, Any]) -> None:
        if item["id"] in seen_ids or len(samples) >= 3:
            return
        seen_ids.add(item["id"])
        samples.append(
            {
                "label": label,
                "kind": item["kind"],
                "subreddit": item["subreddit"],
                "created_utc": item["created_utc"],
                "char_len": item["char_len"],
                "edit_delay_sec": item["edit_delay_sec"],
                "untrusted_content": core.neutralize_untrusted_text(
                    item["raw_text"], 300, preserve_tail_artifact=True
                ),
            }
        )

    if all_items:
        for it in reversed(all_items):
            if core.RE_TOOL_CALL_TAGS.search(it["raw_text"]) or (
                it["edit_delay_sec"] and it["edit_delay_sec"] >= 300.0 and it["domains"]
            ):
                add_sample("flagged_recent", it)
                break
        add_sample("newest", all_items[-1])
        if len(all_items) >= 4:
            add_sample("oldest", all_items[0])

    return {
        "status": "ok",
        "mode": mode,
        "account_meta": {
            "author": author,
            "account_age_days": account_age_days,
            "link_karma": about_data.get("link_karma"),
            "comment_karma": about_data.get("comment_karma"),
            "is_mod": about_data.get("is_mod"),
            "is_suspended": bool(about_data.get("is_suspended", False)),
            "comments_analyzed": len(comments),
            "posts_analyzed": len(posts),
        },
        "scripted_likelihood_score": final_score,
        "assessment_band": band,
        "flags": sorted(set(flags)),
        "temporal_analysis": {
            "hours_active_of_24": hours_active,
            "max_quiet_hours": max_quiet_hours,
            "median_interval_sec": median_interval_sec,
            "interval_cv": interval_cv,
            "cron_aligned_ratio": cron_aligned_ratio,
            "max_dormancy_days": max_dormancy_days,
        },
        "topic_and_style_shift": {
            "older_top_subreddits": older_top_subs,
            "newer_top_subreddits": newer_top_subs,
            "subreddit_overlap": subreddit_overlap,
            "older_median_len": older_median_len,
            "newer_median_len": newer_median_len,
            "older_stylometry": older_style,
            "newer_stylometry": newer_style,
        },
        "content_patterns": {
            "duplicate_item_ratio": dup_ratio,
            "duplicate_pairs_count": dup_pairs,
            "eligible_items_for_dup": eligible_dup,
            "linked_items": linked_items,
            "top_domains": top_domains,
            "top_domain_share": top_domain_share,
            "affiliate_or_shortener_count": affiliate_or_shortener_count,
            "stealth_edit_link_count": stealth_edit_link_count,
            "artifact_hits": artifact_hits,
        },
        "graph_context": graph_ctx,
        "untrusted_samples": samples,
        "warnings": warnings,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Deep confirmation inspection for a flagged Reddit account."
    )
    parser.add_argument(
        "author",
        nargs="?",
        help="Reddit username (with or without u/) or profile URL.",
    )
    parser.add_argument(
        "--mock",
        dest="mock_path",
        default=None,
        help="Offline JSON bundle with {'about': ..., 'comments': ..., 'submitted': ...}.",
    )
    parser.add_argument(
        "--comments-limit",
        type=int,
        default=50,
        help="Recent comments to inspect (default: 50).",
    )
    parser.add_argument(
        "--posts-limit",
        type=int,
        default=25,
        help="Recent submissions to inspect (default: 25).",
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
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    warnings: list[str] = []

    if args.mock_path:
        mock_file = core.resolve_local_file(args.mock_path)
        if mock_file is None:
            return core.emit_error(
                "mock_file_not_found",
                f"Could not find mock account JSON at '{args.mock_path}'.",
            )
        try:
            bundle = json.loads(mock_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return core.emit_error("mock_parse_error", f"Failed to read mock file: {exc}")

        about_payload = bundle.get("about")
        comments_payload = bundle.get("comments")
        submitted_payload = bundle.get("submitted")
        author = normalize_username(
            args.author or (about_payload or {}).get("data", {}).get("name", "mock_user")
        )
        mode = "mock"
        auth_mode = "mock"
        data_source = "mock"
    else:
        if not args.author:
            return core.emit_error(
                "invalid_arguments",
                "Provide a Reddit username (e.g. u/example) or --mock <path>.",
            )
        author = normalize_username(args.author)
        if not author:
            return core.emit_error("invalid_username", "Could not parse a valid Reddit username.")

        fetcher = core.RateLimitedFetcher(
            user_agent=args.user_agent,
            delay_sec=core.REQUEST_DELAY_SEC,
            use_oauth=not args.no_oauth,
            source=args.source,
        )

        about_payload, err_about, about_notes = fetcher.fetch_user_about(author)
        warnings.extend(about_notes)
        if err_about:
            if err_about.get("code") in (401, 403, 404, 429) or err_about.get("type") == "oauth_auth_failed":
                return core.emit_error(
                    str(err_about.get("type", "fetch_error")),
                    f"u/{author} about: {err_about['message']}",
                    code=err_about.get("code"),
                )
            warnings.append(f"about: {err_about['message']}")

        comments_payload, err_c = fetcher.fetch_user_comments(
            author, limit=max(1, min(100, args.comments_limit))
        )
        if err_c:
            warnings.append(f"comments: {err_c['message']}")
            if err_c.get("code") == 429:
                submitted_payload = None
            else:
                submitted_payload, err_s = fetcher.fetch_user_posts(
                    author, limit=max(1, min(100, args.posts_limit))
                )
                if err_s:
                    warnings.append(f"submitted: {err_s['message']}")
        else:
            submitted_payload, err_s = fetcher.fetch_user_posts(
                author, limit=max(1, min(100, args.posts_limit))
            )
            if err_s:
                warnings.append(f"submitted: {err_s['message']}")
        mode = "live"
        auth_mode = fetcher.auth_mode
        data_source = fetcher.active_source

    db = core.RedditGraphDB(Path(args.db))
    try:
        report = inspect_account_data(
            author=author,
            about_payload=about_payload,
            comments_payload=comments_payload,
            submitted_payload=submitted_payload,
            db=db,
            warnings=warnings,
            mode=mode,
        )
        report["auth_mode"] = auth_mode
        report["data_source"] = data_source
    finally:
        db.close()

    output_json = core.serialize_within_budget(report, max_bytes=core.MAX_OUTPUT_BYTES)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(output_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
