#!/usr/bin/env python3
"""Deterministic local Reddit thread auditor for agentic activity, takeovers, and swarms.

Zero third-party dependencies (Python standard library only).
Persists incremental cross-thread signals into SQLite (`data/reddit_graph.db`)
and emits a compact, prompt-injection-neutralized JSON report to stdout.
"""

from __future__ import annotations

import argparse
import base64
import collections
import datetime
import html
import json
import os
import re
import sqlite3
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Constants & Defaults
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
DEFAULT_DB_PATH = SKILL_DIR / "data" / "reddit_graph.db"
DEFAULT_USER_AGENT = "windows:reddit-agentic-audit:1.1.0 (local deterministic analyzer)"
DEFAULT_IGNORED_AUTHORS = {"automoderator", "[deleted]", "[removed]"}
REDDIT_OAUTH_TOKEN_URL = "https://www.reddit.com/api/v1/access_token"
ARCTIC_SHIFT_BASE = "https://arctic-shift.photon-reddit.com/api"

REQUEST_DELAY_SEC = 2.0
HTTP_TIMEOUT_SEC = 20.0
PROFILE_CACHE_TTL_SEC = 86400  # 24 hours
PROFILE_COMMENTS_LIMIT = 15

OP_CONTENT_MAX_CHARS = 600
COMMENT_CONTENT_MAX_CHARS = 500
DB_EXCERPT_MAX_CHARS = 240
MAX_OUTPUT_BYTES = 7800  # Hard cap under 8 KB

REDDIT_SELF_DOMAINS = {
    "reddit.com",
    "old.reddit.com",
    "www.reddit.com",
    "np.reddit.com",
    "m.reddit.com",
    "redd.it",
    "i.redd.it",
    "v.redd.it",
    "preview.redd.it",
    "redditstatic.com",
    "redditmedia.com",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "rb.gy",
    "cutt.ly",
    "goo.gl",
    "shorturl.at",
    "linktr.ee",
    "ow.ly",
    "is.gd",
    "rebrand.ly",
    "tiny.cc",
    "buff.ly",
}

FUNNEL_DOMAINS = {
    "t.me",
    "telegram.me",
    "discord.gg",
    "wa.me",
    "chat.whatsapp.com",
}

TRACKING_QUERY_KEYS = {
    "ref",
    "aff",
    "affiliate",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "partner",
    "promo",
    "referral",
    "via",
}

REFERENCE_DOMAINS = {
    "wikipedia.org",
    "wikimedia.org",
    "arxiv.org",
    "github.com",
    "gist.github.com",
    "stackoverflow.com",
    "youtube.com",
    "youtu.be",
    "imgur.com",
    "i.imgur.com",
    "bbc.com",
    "bbc.co.uk",
    "reuters.com",
    "npr.org",
    "developer.mozilla.org",
    "docs.python.org",
}

WATCHLIST_BAD_VERDICTS = {
    "confirmed_bot",
    "confirmed_swarm",
    "confirmed_takeover",
    "confirmed_shill",
    "suspicious",
}
WATCHLIST_VALID_VERDICTS = WATCHLIST_BAD_VERDICTS | {"benign"}

RE_SENTENCE_SPLIT = re.compile(r"[.!?\n]+")
RE_WORD_TOKEN = re.compile(r"[A-Za-z0-9']+")
RE_MD_STRUCT = re.compile(r"(?m)(?:^\s*(?:[-*+]|\d+\.)\s+\S|\*\*[^*\n]{2,60}\*\*|^#{1,4}\s+\S)")

# ---------------------------------------------------------------------------
# Compiled Heuristic Regexes (Class 3)
# ---------------------------------------------------------------------------

RE_URL = re.compile(r"https?://[^\s<>()\[\]\"']+", re.IGNORECASE)

RE_TOOL_CALL_TAGS = re.compile(
    r"(?is)"
    r"(?:<\s*/?\s*(?:tool_call|tool_response|function_call|function_response|"
    r"tool_use|tool_result|antml:invoke|invoke|scratchpad|thinking|thought)\b"
    r"|\bfunction_call\s*[:=\(\{]"
    r"|\"(?:tool_calls|function_call|tool_name)\"\s*:)"
)

RE_LEAKED_JSON_AGENT = re.compile(
    r"(?is)"
    r"(?:\{\s*\"(?:action|action_input|tool|tool_name|arguments|parameters|"
    r"final_answer|thought|scratchpad)\"\s*:"
    r"|\{\s*\"name\"\s*:\s*\"[^\"]{1,60}\"\s*,\s*\"(?:arguments|parameters|input)\"\s*:"
    r"|\"role\"\s*:\s*\"(?:system|assistant|tool)\""
    r"|\"(?:arguments|parameters)\"\s*:\s*\{[^\}]{0,200}$)"
)

RE_LLM_BOILERPLATE = re.compile(
    r"(?i)"
    r"(?:\bas an ai (?:language model|assistant)\b"
    r"|\bi(?:'m| am) sorry,?\s*(?:but )?as an ai\b"
    r"|\bi cannot (?:fulfill|comply with|assist with) (?:this|that) request\b"
    r"|\bhere(?:'s| is) a (?:polite|helpful|concise|detailed|reddit) "
    r"(?:reply|response|comment|breakdown)\b"
    r"|\bcertainly!\s*here(?:'s| is)\b"
    r"|\bmy (?:knowledge cutoff|training data|programming prevents)\b"
    r"|\bi hope this (?:helps|clarifies)!?\s*let me know if you(?:'d| would) like\b)"
)

RE_PROMPT_INJECTION = re.compile(
    r"(?is)"
    r"(?:\bignore (?:all )?(?:previous|prior|above|preceding) "
    r"(?:instructions|prompts|rules|directions|directives)\b"
    r"|\bdisregard (?:all )?(?:previous|prior|system) "
    r"(?:instructions|prompts|rules|directives)\b"
    r"|\bforget (?:everything|all previous instructions)\b"
    r"|\b(?:override|replace|update|reveal|print|dump) (?:the |your )?"
    r"(?:system prompt|hidden instructions|initial prompt|system instructions)\b"
    r"|\byou are now (?:in )?(?:developer mode|dan|jailbreak|an unrestricted)\b"
    r"|<\s*/?\s*(?:system|system_prompt|instructions|override|prompt_injection|"
    r"untrusted_content|user_request)\b"
    r"|\[\s*/?\s*(?:SYSTEM|INST|ADMIN|OVERRIDE|DEVELOPER)\s*\]"
    r"|<\|\s*(?:im_start|im_end|system|assistant|endoftext)\s*\|>)"
)

RE_BOLD_BULLET = re.compile(
    r"(?m)^\s*(?:[-*+]|\d+\.)\s+\*\*[^*\n]{2,60}(?:[:—-]\*\*|\*\*\s*[:—-])"
)
RE_MD_HEADER = re.compile(r"(?m)^#{1,4}\s+\S")
RE_LLM_STYLE_PHRASES = re.compile(
    r"(?i)\b(?:it(?:'s| is) worth noting|in conclusion|let(?:'s| us) dive in|"
    r"delve into|key takeaways|game[- ]changer|furthermore|moreover)\b"
)

RE_OP_TEMPLATED_TITLE = re.compile(
    r"(?i)(?:so you don(?:'t|’t) have to|here(?:'s| is) (?:my|what) "
    r"(?:honest |i )?(?:review|breakdown|learned)|i tested \d+|"
    r"after \d+ (?:days|hours|months) of|ultimate guide to)"
)

RE_OP_CTA = re.compile(
    r"(?i)(?:drop a comment|comment ['\"a-z0-9 ]{1,20} and i(?:'ll| will) dm|"
    r"dm me for|link in (?:bio|profile|comments)|use code\s+\w+|"
    r"free trial|limited spots|check out my (?:tool|app|saas|newsletter)|"
    r"sign up (?:here|now|today)|join (?:our|my) (?:discord|telegram|waitlist))"
)

# Neutralization regexes (defang prompt boundaries in untrusted Reddit text)
RE_CTRL_AND_BIDI = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]"
)
RE_SPECIAL_PIPE_TOKEN = re.compile(r"<\|([^|]{1,64})\|>")
RE_XML_LIKE_TAG = re.compile(
    r"<\s*(/?\s*[a-zA-Z_][\w:.-]{0,60}(?:\s+[^<>]{0,120})?)\s*>"
)
RE_UNCLOSED_BOUNDARY_TAG = re.compile(
    r"(?i)<\s*(/?\s*(?:untrusted_content|system|system_prompt|user|assistant|"
    r"tool_call|tool_response|instructions|override|user_request|prompt)\b)"
)
RE_BRACKET_DIRECTIVE = re.compile(
    r"(?i)\[\s*(/?\s*(?:SYSTEM|INST|ASSISTANT|USER|ADMIN|OVERRIDE|PROMPT|"
    r"DEVELOPER|TOOL_CALL|FUNCTION_CALL)[^\]]{0,40})\]"
)
RE_HEADING_BOUNDARY = re.compile(
    r"(?im)^(?:#{1,6}\s*|---+\s*|===+\s*)"
    r"(SYSTEM|INSTRUCTIONS?|OVERRIDE|ASSISTANT|DEVELOPER|USER|PROMPT)\b"
)
RE_ROLE_PREFIX = re.compile(
    r"(?im)^(SYSTEM|ASSISTANT|USER|DEVELOPER|INSTRUCTION)\s*:"
)
RE_MULTI_SPACE = re.compile(r"[ \t]{2,}")
RE_MULTI_NEWLINE = re.compile(r"\n{2,}")


# ---------------------------------------------------------------------------
# Sanitization & Utility Helpers
# ---------------------------------------------------------------------------

def neutralize_untrusted_text(
    text: str,
    max_chars: int,
    preserve_tail_artifact: bool = False,
) -> str:
    """Neutralize prompt-boundary strings and truncate untrusted Reddit text."""
    cleaned = html.unescape(text or "")
    cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = RE_CTRL_AND_BIDI.sub("", cleaned)

    # Defang special tokens, XML tags, bracket directives, fences, and role headers
    cleaned = RE_SPECIAL_PIPE_TOKEN.sub(r"(|token:\1|)", cleaned)
    cleaned = RE_XML_LIKE_TAG.sub(r"(tag:\1)", cleaned)
    cleaned = RE_UNCLOSED_BOUNDARY_TAG.sub(r"(tag_fragment:\1)", cleaned)
    cleaned = RE_BRACKET_DIRECTIVE.sub(r"(directive:\1)", cleaned)
    cleaned = cleaned.replace("```", "'''")
    cleaned = RE_HEADING_BOUNDARY.sub(r"[boundary:\1]", cleaned)
    cleaned = RE_ROLE_PREFIX.sub(r"[role:\1]:", cleaned)

    cleaned = RE_MULTI_SPACE.sub(" ", cleaned)
    cleaned = RE_MULTI_NEWLINE.sub("\n", cleaned)
    cleaned = cleaned.strip()

    if len(cleaned) > max_chars:
        if max_chars <= 3:
            return cleaned[:max_chars]
        if preserve_tail_artifact and max_chars >= 120:
            marker = " [...] "
            avail = max_chars - len(marker)
            head_len = int(avail * 0.52)
            tail_len = avail - head_len
            return cleaned[:head_len].rstrip() + marker + cleaned[-tail_len:].lstrip()
        return cleaned[: max_chars - 3].rstrip() + "..."
    return cleaned


def sanitize_identifier(value: Any, fallback: str = "unknown") -> str:
    """Sanitize short Reddit metadata identifiers (author, subreddit, IDs)."""
    if not isinstance(value, str):
        return fallback
    cleaned = RE_CTRL_AND_BIDI.sub("", value).strip()
    if not cleaned:
        return fallback
    # Allow standard Reddit identifier characters plus brackets for [deleted]
    cleaned = re.sub(r"[^A-Za-z0-9_\-\[\].]", "_", cleaned)
    return cleaned[:64]


def extract_urls_and_domains(text: str) -> tuple[list[str], list[str], bool, bool, bool]:
    """Return (urls, external_domains, has_shortener, has_tracking, has_funnel)."""
    urls = RE_URL.findall(text or "")
    domains: list[str] = []
    seen: set[str] = set()
    has_shortener = False
    has_tracking = False
    has_funnel = False

    for raw_url in urls:
        url = raw_url.rstrip(".,;:!?)")
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        if host.startswith("www."):
            norm_host = host[4:]
        else:
            norm_host = host

        if not norm_host:
            continue

        if norm_host in URL_SHORTENERS or host in URL_SHORTENERS:
            has_shortener = True
        if norm_host in FUNNEL_DOMAINS or (
            norm_host == "discord.com" and "/invite" in (parsed.path or "").lower()
        ):
            has_funnel = True

        qs = urllib.parse.parse_qs(parsed.query)
        if any(k.lower() in TRACKING_QUERY_KEYS for k in qs):
            has_tracking = True

        if host not in REDDIT_SELF_DOMAINS and norm_host not in REDDIT_SELF_DOMAINS:
            if norm_host not in seen:
                seen.add(norm_host)
                domains.append(norm_host)

    return urls, domains, has_shortener, has_tracking, has_funnel


def is_reference_domain(domain: str) -> bool:
    """Return True for benign citation/reference domains (Wikipedia, YouTube, GitHub, etc.)."""
    d = (domain or "").lower().removeprefix("www.")
    if not d:
        return False
    if d in REFERENCE_DOMAINS:
        return True
    if (
        d.endswith(".wikipedia.org")
        or d.endswith(".wikimedia.org")
        or d.endswith(".gov")
        or d.endswith(".edu")
        or d.startswith("docs.")
    ):
        return True
    return False


def has_suspicious_edit_link(
    domains: list[str], has_shortener: bool, has_tracking: bool, has_funnel: bool
) -> bool:
    """True when an edited post/comment carries a non-reference URL or tracking/shortener/funnel."""
    if not domains:
        return False
    if has_shortener or has_tracking or has_funnel:
        return True
    return any(not is_reference_domain(d) for d in domains)


def utc_hour_from_ts(ts: float) -> int:
    """Return UTC hour (0-23) for a Unix timestamp."""
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).hour


def circular_hour_distance(h1: int, h2: int) -> int:
    """Shortest distance in hours on a 24-hour clock (0-12)."""
    diff = abs(h1 - h2) % 24
    return min(diff, 24 - diff)


def combine_class_scores(c1: int, c2: int, c3: int) -> int:
    """Max-dominant score with corroboration bonus across the 3 classes (0-100)."""
    ordered = sorted([max(0, c1), max(0, c2), max(0, c3)], reverse=True)
    score = ordered[0] + 0.25 * ordered[1] + 0.15 * ordered[2]
    return int(min(100, round(score)))


def parse_edited_utc(raw_edited: Any, created_utc: float) -> tuple[Optional[float], Optional[float]]:
    """Parse Reddit's `edited` field (`false` or Unix timestamp) into (edited_utc, delay_sec)."""
    if isinstance(raw_edited, (int, float)) and not isinstance(raw_edited, bool) and raw_edited > 0:
        edited_utc = float(raw_edited)
        delay = round(edited_utc - created_utc, 2) if edited_utc > created_utc else 0.0
        return edited_utc, delay
    return None, None


def compute_text_stylometry(text: str) -> dict[str, float]:
    """Ultra-lightweight O(n) formatting & stylometric fingerprint (no NLP libs)."""
    stripped = (text or "").strip()
    char_len = len(stripped)
    if char_len == 0:
        return {
            "avg_sentence_words": 0.0,
            "is_casual": 0.0,
            "has_markdown": 0.0,
            "em_dash_count": 0.0,
            "em_dash_per_1k": 0.0,
        }

    # Remove URLs before sentence/punctuation checks so dots in domains don't skew metrics
    no_url = RE_URL.sub("", stripped).strip()
    sentences = [s.strip() for s in RE_SENTENCE_SPLIT.split(no_url) if s.strip()]
    word_counts = [len(RE_WORD_TOKEN.findall(s)) for s in sentences]
    word_counts = [wc for wc in word_counts if wc > 0]
    avg_sentence_words = (
        round(sum(word_counts) / len(word_counts), 2) if word_counts else 0.0
    )

    first_alpha = next((ch for ch in no_url if ch.isalpha()), "")
    starts_lower = bool(first_alpha) and first_alpha.islower()
    ends_punct = bool(no_url) and no_url[-1] in ".!?:)"
    is_casual = 1.0 if (starts_lower or (not ends_punct and len(no_url) < 160)) else 0.0
    has_markdown = 1.0 if RE_MD_STRUCT.search(stripped) else 0.0
    em_dash_count = float(stripped.count("—") + stripped.count(" -- ") + stripped.count(" – "))
    em_dash_per_1k = round(em_dash_count * 1000.0 / max(char_len, 1), 2)

    return {
        "avg_sentence_words": avg_sentence_words,
        "is_casual": is_casual,
        "has_markdown": has_markdown,
        "em_dash_count": em_dash_count,
        "em_dash_per_1k": em_dash_per_1k,
    }


def aggregate_stylometry(texts: list[str]) -> dict[str, float]:
    """Aggregate stylometric baseline across a list of historical comments."""
    valid = [t for t in texts if (t or "").strip()]
    if not valid:
        return {}
    metrics = [compute_text_stylometry(t) for t in valid]
    n = len(metrics)
    return {
        "avg_sentence_words": round(
            sum(m["avg_sentence_words"] for m in metrics) / n, 2
        ),
        "casual_rate": round(sum(m["is_casual"] for m in metrics) / n, 3),
        "markdown_rate": round(sum(m["has_markdown"] for m in metrics) / n, 3),
        "em_dash_per_1k": round(sum(m["em_dash_per_1k"] for m in metrics) / n, 2),
    }


# ---------------------------------------------------------------------------
# URL Normalization & Rate-Limited HTTP Client
# ---------------------------------------------------------------------------

def normalize_thread_url(url: str, max_comments: int = 50, depth: int = 4) -> str:
    """Convert a Reddit thread URL to its canonical `.json?limit=..&depth=..` URL."""
    raw = (url or "").strip()
    if not raw:
        raise ValueError("Empty Reddit thread URL.")
    if "://" not in raw:
        raw = "https://" + raw

    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")

    host = (parsed.hostname or "").lower()
    if host == "redd.it":
        thread_slug = parsed.path.strip("/").split("/")[0]
        if not thread_slug:
            raise ValueError("Could not extract thread ID from redd.it URL.")
        path = f"/comments/{thread_slug}.json"
    elif host == "reddit.com" or host.endswith(".reddit.com"):
        path = parsed.path.rstrip("/")
        if not path or "/comments/" not in path:
            raise ValueError("URL does not look like a Reddit thread (/comments/...).")
        if not path.endswith(".json"):
            path = f"{path}.json"
    else:
        raise ValueError(f"URL host '{host}' is not a Reddit domain.")

    query = urllib.parse.urlencode({"limit": max_comments, "depth": depth})
    return f"https://www.reddit.com{path}?{query}"


def _parse_dotenv_file(path: Path) -> dict[str, str]:
    """Minimal stdlib .env parser (KEY=VALUE, ignoring comments/blank lines)."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                val = val[1:-1]
            if key:
                values[key] = val
    except OSError:
        return {}
    return values


def load_reddit_oauth_config() -> dict[str, Optional[str]]:
    """Load Reddit OAuth2 settings from env vars first, then skill/workspace .env."""
    dotenv_vals: dict[str, str] = {}
    for candidate in (Path.cwd() / ".env", SKILL_DIR / ".env"):
        dotenv_vals.update(_parse_dotenv_file(candidate))

    placeholder_vals = {
        "your_client_id_here",
        "your_client_secret_here",
        "your_reddit_username_here",
        "changeme",
        "placeholder",
    }

    def get_val(name: str) -> Optional[str]:
        v = os.environ.get(name) or dotenv_vals.get(name)
        if not v or not v.strip():
            return None
        cleaned = v.strip()
        if cleaned.lower() in placeholder_vals:
            return None
        return cleaned

    return {
        "client_id": get_val("REDDIT_CLIENT_ID"),
        "client_secret": get_val("REDDIT_CLIENT_SECRET"),
        "username": get_val("REDDIT_USERNAME"),
    }


def resolve_user_agent(cli_user_agent: Optional[str]) -> str:
    """Build a compliant Reddit User-Agent (incorporating REDDIT_USERNAME when available)."""
    if cli_user_agent and cli_user_agent != DEFAULT_USER_AGENT:
        return cli_user_agent
    cfg = load_reddit_oauth_config()
    if cfg.get("username"):
        uname = sanitize_identifier(
            cfg["username"].lstrip("/").removeprefix("u/"), ""
        )
        if uname:
            return f"windows:reddit-agentic-audit:1.1.0 (by /u/{uname})"
    return DEFAULT_USER_AGENT


def rewrite_to_oauth_url(url: str) -> str:
    """Rewrite a www.reddit.com `.json` URL to canonical `oauth.reddit.com` endpoint."""
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if host != "reddit.com" and not host.endswith(".reddit.com"):
        return url
    path = parsed.path or "/"
    if path.endswith(".json"):
        path = path[:-5] or "/"
    return urllib.parse.urlunparse(
        ("https", "oauth.reddit.com", path, parsed.params, parsed.query, "")
    )


def extract_thread_id_from_url(url: str) -> Optional[str]:
    """Extract the base36 Reddit submission ID from a Reddit thread or redd.it URL."""
    raw = (url or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    host = (parsed.hostname or "").lower()
    parts = [p for p in (parsed.path or "").split("/") if p]
    if host == "redd.it" and parts:
        return sanitize_identifier(parts[0].removesuffix(".json"), "") or None
    if host == "reddit.com" or host.endswith(".reddit.com"):
        for idx, seg in enumerate(parts):
            if seg.lower() == "comments" and idx + 1 < len(parts):
                return sanitize_identifier(parts[idx + 1].removesuffix(".json"), "") or None
    return None


def arctic_shift_wrap_listing(items: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    """Wrap Arctic Shift flat item dicts into a native Reddit Listing object."""
    children = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cid = str(item.get("id") or "")
        wrapped = dict(item)
        if cid and not wrapped.get("name"):
            wrapped["name"] = f"{kind}_{cid}"
        children.append({"kind": kind, "data": wrapped})
    return {"kind": "Listing", "data": {"children": children}}


def arctic_shift_build_thread_payload(
    post: dict[str, Any], comments: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Convert Arctic Shift post + flat comments into native Reddit [post_listing, comment_listing]."""
    tid = str(post.get("id") or "")
    post_wrapped = dict(post)
    if tid and not post_wrapped.get("name"):
        post_wrapped["name"] = f"t3_{tid}"
    post_listing = {
        "kind": "Listing",
        "data": {"children": [{"kind": "t3", "data": post_wrapped}]},
    }

    node_by_fullname: dict[str, dict[str, Any]] = {}
    ordered_nodes: list[tuple[str, dict[str, Any], str]] = []
    for c in comments:
        if not isinstance(c, dict):
            continue
        cid = str(c.get("id") or "")
        if not cid:
            continue
        fullname = f"t1_{cid}"
        parent_id = str(c.get("parent_id") or f"t3_{tid}")
        node_data = dict(c)
        node_data["name"] = fullname
        node_data["replies"] = {"kind": "Listing", "data": {"children": []}}
        node = {"kind": "t1", "data": node_data}
        node_by_fullname[fullname] = node
        ordered_nodes.append((fullname, node, parent_id))

    roots: list[dict[str, Any]] = []
    for _, node, parent_id in ordered_nodes:
        parent_node = node_by_fullname.get(parent_id)
        if parent_node is not None:
            parent_node["data"]["replies"]["data"]["children"].append(node)
        else:
            roots.append(node)

    comment_listing = {"kind": "Listing", "data": {"children": roots}}
    return [post_listing, comment_listing]


class RateLimitedFetcher:
    """Stdlib HTTP JSON fetcher with >= 2s spacing, Reddit OAuth2, and Arctic Shift fallback."""

    def __init__(
        self,
        user_agent: Optional[str] = None,
        delay_sec: float = REQUEST_DELAY_SEC,
        use_oauth: bool = True,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        source: str = "auto",
    ) -> None:
        cfg = load_reddit_oauth_config() if (use_oauth and (not client_id or not client_secret)) else {}
        self._client_id = client_id or cfg.get("client_id")
        self._client_secret = client_secret or cfg.get("client_secret")
        self.oauth_enabled = bool(use_oauth and self._client_id and self._client_secret)
        self.user_agent = resolve_user_agent(user_agent)
        self.delay_sec = delay_sec
        self.source_mode = source if source in ("auto", "reddit", "arctic-shift") else "auto"
        if self.source_mode == "arctic-shift":
            self.active_source = "arctic_shift"
        elif self.oauth_enabled:
            self.active_source = "reddit_oauth"
        else:
            self.active_source = "reddit_public"
        self._last_request_mono: Optional[float] = None
        self._access_token: Optional[str] = None
        self._token_expires_mono: float = 0.0

    @property
    def auth_mode(self) -> str:
        if self.active_source == "arctic_shift":
            return "arctic_shift_public"
        return "oauth" if self.oauth_enabled else "public_json"

    def _respect_delay(self) -> None:
        if self._last_request_mono is not None:
            elapsed = time.monotonic() - self._last_request_mono
            remaining = self.delay_sec - elapsed
            if remaining > 0:
                time.sleep(remaining)

    def _ensure_oauth_token(
        self, force_refresh: bool = False
    ) -> tuple[Optional[str], Optional[dict[str, Any]]]:
        """Acquire or return a cached app-only OAuth2 Bearer token via client_credentials."""
        if (
            not force_refresh
            and self._access_token
            and time.monotonic() < (self._token_expires_mono - 60.0)
        ):
            return self._access_token, None

        self._respect_delay()
        creds = f"{self._client_id}:{self._client_secret}".encode("utf-8")
        basic_b64 = base64.b64encode(creds).decode("ascii")
        body = urllib.parse.urlencode({"grant_type": "client_credentials"}).encode("ascii")
        req = urllib.request.Request(
            REDDIT_OAUTH_TOKEN_URL,
            data=body,
            headers={
                "Authorization": f"Basic {basic_b64}",
                "User-Agent": self.user_agent,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
                self._last_request_mono = time.monotonic()
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            self._last_request_mono = time.monotonic()
            return None, {
                "code": exc.code,
                "type": "oauth_auth_failed",
                "message": (
                    f"Reddit OAuth2 token exchange failed with HTTP {exc.code}. "
                    "Verify REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET belong to a "
                    "'script' app at https://www.reddit.com/prefs/apps."
                ),
            }
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            self._last_request_mono = time.monotonic()
            return None, {
                "code": None,
                "type": "oauth_network_error",
                "message": f"Failed to reach Reddit OAuth2 token endpoint: {exc}",
            }

        token = data.get("access_token") if isinstance(data, dict) else None
        if not token:
            err_detail = data.get("error") if isinstance(data, dict) else "missing_access_token"
            return None, {
                "code": None,
                "type": "oauth_auth_failed",
                "message": f"Reddit OAuth2 did not return an access_token ({err_detail}).",
            }
        expires_in = float(data.get("expires_in") or 3600.0)
        self._access_token = str(token)
        self._token_expires_mono = time.monotonic() + max(120.0, expires_in)
        return self._access_token, None

    def fetch_json(
        self, url: str, _retried_401: bool = False
    ) -> tuple[Optional[Any], Optional[dict[str, Any]]]:
        """Fetch and decode JSON from URL (applying Reddit OAuth2 only to reddit.com hosts)."""
        target_url = url
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }
        parsed_host = (urllib.parse.urlparse(url).hostname or "").lower()
        is_reddit_host = parsed_host == "reddit.com" or parsed_host.endswith(".reddit.com")

        if self.oauth_enabled and is_reddit_host:
            token, tok_err = self._ensure_oauth_token(force_refresh=_retried_401)
            if tok_err is not None:
                return None, tok_err
            target_url = rewrite_to_oauth_url(url)
            headers["Authorization"] = f"Bearer {token}"

        self._respect_delay()
        req = urllib.request.Request(target_url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
                self._last_request_mono = time.monotonic()
                raw_bytes = resp.read()
                text = raw_bytes.decode("utf-8", errors="replace")
                return json.loads(text), None
        except urllib.error.HTTPError as exc:
            self._last_request_mono = time.monotonic()
            if exc.code == 401 and self.oauth_enabled and is_reddit_host and not _retried_401:
                self._access_token = None
                return self.fetch_json(url, _retried_401=True)
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            if exc.code == 429:
                hint = f" Retry-After={retry_after}s." if retry_after else ""
                return None, {
                    "code": 429,
                    "type": "rate_limited",
                    "message": (
                        "Endpoint returned HTTP 429 Too Many Requests."
                        f"{hint} Wait briefly or re-run with --no-profile-fetch."
                    ),
                }
            if exc.code == 403:
                if is_reddit_host and not self.oauth_enabled:
                    msg = (
                        "Reddit returned HTTP 403 Forbidden on the unauthenticated .json endpoint. "
                        "Use --source auto (Arctic Shift public API fallback), configure Reddit OAuth2, "
                        "or pass a locally saved JSON via --mock."
                    )
                else:
                    msg = (
                        "Endpoint returned HTTP 403 Forbidden. The thread/subreddit "
                        "may be private, quarantined, or restricting access."
                    )
                return None, {
                    "code": 403,
                    "type": "forbidden",
                    "message": msg,
                }
            return None, {
                "code": exc.code,
                "type": "http_error",
                "message": f"HTTP {exc.code}: {exc.reason}",
            }
        except urllib.error.URLError as exc:
            self._last_request_mono = time.monotonic()
            return None, {
                "code": None,
                "type": "network_error",
                "message": f"Network error reaching endpoint: {exc.reason}",
            }
        except TimeoutError:
            self._last_request_mono = time.monotonic()
            return None, {
                "code": None,
                "type": "timeout",
                "message": f"Request timed out after {HTTP_TIMEOUT_SEC:.0f}s.",
            }
        except json.JSONDecodeError as exc:
            return None, {
                "code": None,
                "type": "invalid_json",
                "message": f"Failed to parse JSON response: {exc}",
            }

    # -- High-level fetchers with seamless 403 -> Arctic Shift fallback ------

    def _should_fallback_to_arctic(self, err: Optional[dict[str, Any]]) -> bool:
        if not err or self.source_mode != "auto" or self.active_source == "arctic_shift":
            return False
        if err.get("code") == 403 and self.active_source == "reddit_public":
            return True
        if err.get("type") == "oauth_auth_failed":
            return True
        return False

    def fetch_thread_arctic(
        self, thread_id: str, max_comments: int = 50, post_override: Optional[dict[str, Any]] = None
    ) -> tuple[Optional[Any], Optional[dict[str, Any]], list[str]]:
        """Fetch submission + comments from Arctic Shift public research API."""
        notes: list[str] = []
        post = post_override
        if post is None:
            p_url = f"{ARCTIC_SHIFT_BASE}/posts/ids?ids={urllib.parse.quote(thread_id, safe='')}"
            p_data, p_err = self.fetch_json(p_url)
            if p_err is not None:
                return None, p_err, notes
            items = p_data.get("data", []) if isinstance(p_data, dict) else []
            if not items:
                return None, {
                    "code": 404,
                    "type": "not_found_arctic_shift",
                    "message": (
                        f"Thread '{thread_id}' is not indexed in Arctic Shift yet "
                        "(very new or private thread)."
                    ),
                }, notes
            post = items[0]

        lim = max(1, min(100, max_comments))
        c_url = (
            f"{ARCTIC_SHIFT_BASE}/comments/search?"
            f"{urllib.parse.urlencode({'link_id': f't3_{thread_id}', 'limit': lim, 'sort': 'asc'})}"
        )
        c_data, c_err = self.fetch_json(c_url)
        comments_list: list[dict[str, Any]] = []
        if c_err is not None:
            notes.append(f"Arctic Shift comments fetch error: {c_err['message']}")
        elif isinstance(c_data, dict):
            comments_list = c_data.get("data") or []

        expected_comments = int(post.get("num_comments") or 0)
        if expected_comments > 0 and len(comments_list) == 0:
            notes.append(
                f"Arctic Shift archive lag: thread reports {expected_comments} comments on Reddit "
                "but 0 are indexed yet (very recent threads typically appear within 1-4 hours)."
            )

        return arctic_shift_build_thread_payload(post, comments_list), None, notes

    def fetch_thread(
        self, url: str, max_comments: int = 50, depth: int = 4
    ) -> tuple[Optional[Any], Optional[dict[str, Any]], list[str]]:
        """Fetch a Reddit thread via OAuth/public .json, falling back to Arctic Shift on 403."""
        notes: list[str] = []
        thread_id = extract_thread_id_from_url(url)
        endpoint_url = normalize_thread_url(
            url, max_comments=max(1, max_comments), depth=max(1, depth)
        )

        if self.active_source != "arctic_shift":
            payload, err = self.fetch_json(endpoint_url)
            if err is None:
                return payload, None, notes
            if not self._should_fallback_to_arctic(err) or not thread_id:
                return None, err, notes
            reason = (
                "Reddit OAuth2 failed (check .env credentials)"
                if err.get("type") == "oauth_auth_failed"
                else "Reddit public .json returned 403"
            )
            self.active_source = "arctic_shift"
            notes.append(
                f"{reason}; automatically switched to Arctic Shift public API."
            )

        if not thread_id:
            return None, {
                "code": None,
                "type": "invalid_url",
                "message": "Could not extract thread ID for Arctic Shift lookup.",
            }, notes
        payload, err, arctic_notes = self.fetch_thread_arctic(thread_id, max_comments=max_comments)
        return payload, err, notes + arctic_notes

    def fetch_user_comments(
        self, author: str, limit: int = PROFILE_COMMENTS_LIMIT
    ) -> tuple[Optional[Any], Optional[dict[str, Any]]]:
        """Fetch recent comments for an author (auto-fallback to Arctic Shift on 403)."""
        lim = max(1, min(100, limit))
        if self.active_source != "arctic_shift":
            encoded = urllib.parse.quote(author, safe="")
            url = f"https://www.reddit.com/user/{encoded}/comments.json?limit={lim}"
            payload, err = self.fetch_json(url)
            if err is None:
                return payload, None
            if not self._should_fallback_to_arctic(err):
                return None, err
            self.active_source = "arctic_shift"

        q = urllib.parse.urlencode({"author": author, "limit": lim, "sort": "desc"})
        data, err = self.fetch_json(f"{ARCTIC_SHIFT_BASE}/comments/search?{q}")
        if err is not None:
            return None, err
        items = data.get("data", []) if isinstance(data, dict) else []
        return arctic_shift_wrap_listing(items, "t1"), None

    def fetch_user_posts(
        self, author: str, limit: int = 25
    ) -> tuple[Optional[Any], Optional[dict[str, Any]]]:
        """Fetch recent submissions for an author (auto-fallback to Arctic Shift on 403)."""
        lim = max(1, min(100, limit))
        if self.active_source != "arctic_shift":
            encoded = urllib.parse.quote(author, safe="")
            url = f"https://www.reddit.com/user/{encoded}/submitted.json?limit={lim}"
            payload, err = self.fetch_json(url)
            if err is None:
                return payload, None
            if not self._should_fallback_to_arctic(err):
                return None, err
            self.active_source = "arctic_shift"

        q = urllib.parse.urlencode({"author": author, "limit": lim, "sort": "desc"})
        data, err = self.fetch_json(f"{ARCTIC_SHIFT_BASE}/posts/search?{q}")
        if err is not None:
            return None, err
        items = data.get("data", []) if isinstance(data, dict) else []
        return arctic_shift_wrap_listing(items, "t3"), None

    def fetch_user_about(
        self, author: str
    ) -> tuple[Optional[Any], Optional[dict[str, Any]], list[str]]:
        """Fetch user profile metadata (returns None gracefully when using Arctic Shift)."""
        notes: list[str] = []
        if self.active_source != "arctic_shift":
            encoded = urllib.parse.quote(author, safe="")
            url = f"https://www.reddit.com/user/{encoded}/about.json"
            payload, err = self.fetch_json(url)
            if err is None:
                return payload, None, notes
            if not self._should_fallback_to_arctic(err):
                return None, err, notes
            self.active_source = "arctic_shift"
            notes.append(
                "Reddit public .json returned 403; switched to Arctic Shift public API "
                "(karma/account_age unavailable without Reddit OAuth, behavioral history intact)."
            )
        return None, None, notes

    def fetch_subreddit_posts(
        self,
        subreddit: str,
        sort: str = "new",
        limit: int = 10,
        include_stickied: bool = False,
        min_age_hours: float = 6.0,
    ) -> tuple[Optional[list[dict[str, Any]]], Optional[dict[str, Any]], list[str]]:
        """Fetch recent subreddit post dicts (auto-fallback to Arctic Shift on 403)."""
        notes: list[str] = []
        lim = max(1, min(25, limit))
        if self.active_source != "arctic_shift":
            url = (
                f"https://www.reddit.com/r/{urllib.parse.quote(subreddit, safe='')}"
                f"/{sort}.json?limit={min(50, lim + 5)}"
            )
            data, err = self.fetch_json(url)
            if err is None:
                children = data.get("data", {}).get("children", []) if isinstance(data, dict) else []
                posts = []
                for ch in children:
                    if not isinstance(ch, dict) or ch.get("kind") != "t3":
                        continue
                    d = ch.get("data", {})
                    if d.get("stickied") and not include_stickied:
                        continue
                    posts.append(d)
                    if len(posts) >= lim:
                        break
                return posts, None, notes
            if not self._should_fallback_to_arctic(err):
                return None, err, notes
            self.active_source = "arctic_shift"
            notes.append(
                "Reddit public .json returned 403; automatically switched to Arctic Shift public API."
            )

        # Fetch a slightly wider window on Arctic Shift using lookback so comment trees are indexed
        fetch_lim = min(100, max(lim * 3, 25))
        params: dict[str, Any] = {"subreddit": subreddit, "limit": fetch_lim, "sort": "desc"}
        if min_age_hours > 0:
            params["before"] = int(time.time() - (min_age_hours * 3600.0))
            notes.append(
                f"Arctic Shift lookback: scanning threads >= {min_age_hours:g}h old so comment trees are indexed."
            )
        q = urllib.parse.urlencode(params)
        data, err = self.fetch_json(f"{ARCTIC_SHIFT_BASE}/posts/search?{q}")
        if err is not None:
            return None, err, notes
        raw_posts = [p for p in (data.get("data") or []) if isinstance(p, dict)]
        if not include_stickied:
            raw_posts = [p for p in raw_posts if not p.get("stickied")]

        # Prefer posts with comments (skipping brand-new <1h 0-comment stubs when enough exist)
        with_comments = [p for p in raw_posts if int(p.get("num_comments") or 0) > 0]
        selected = with_comments[:lim] if len(with_comments) >= lim else (with_comments + [p for p in raw_posts if p not in with_comments])[:lim]
        return selected, None, notes


# ---------------------------------------------------------------------------
# Reddit Payload Parsing
# ---------------------------------------------------------------------------

def parse_reddit_thread(
    payload: Any,
    ignored_authors: set[str],
    max_comments: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], int]:
    """Parse native Reddit `.json` thread payload into (op_dict, comments_list, ignored_count)."""
    if not isinstance(payload, list) or len(payload) < 2:
        raise ValueError(
            "Expected Reddit thread JSON to be a 2-element list [post_listing, comment_listing]."
        )

    post_children = (
        payload[0].get("data", {}).get("children", [])
        if isinstance(payload[0], dict)
        else []
    )
    if not post_children or not isinstance(post_children[0], dict):
        raise ValueError("Missing OP submission object in Reddit JSON payload.")

    post_data = post_children[0].get("data", {})
    thread_id = sanitize_identifier(post_data.get("id"), "unknown_thread")
    op_fullname = sanitize_identifier(post_data.get("name"), f"t3_{thread_id}")
    op_author = sanitize_identifier(post_data.get("author"), "[deleted]")
    subreddit = sanitize_identifier(post_data.get("subreddit"), "unknown")
    op_created = float(post_data.get("created_utc") or 0.0)
    raw_title = html.unescape(str(post_data.get("title") or ""))
    raw_selftext = html.unescape(str(post_data.get("selftext") or ""))
    post_url = str(post_data.get("url") or "")
    is_self = bool(post_data.get("is_self", True))
    op_edited_utc, op_edit_delay = parse_edited_utc(post_data.get("edited"), op_created)

    combined_op_url_text = f"{raw_title}\n{raw_selftext}\n{'' if is_self else post_url}"
    op_urls, op_domains, op_shortener, op_tracking, op_funnel = extract_urls_and_domains(
        combined_op_url_text
    )

    op_info: dict[str, Any] = {
        "thread_id": thread_id,
        "fullname": op_fullname,
        "subreddit": subreddit,
        "author": op_author,
        "author_ignored": op_author.lower() in ignored_authors,
        "created_utc": op_created,
        "edited_utc": op_edited_utc,
        "edit_delay_sec": op_edit_delay,
        "raw_title": raw_title,
        "raw_selftext": raw_selftext,
        "post_url": post_url,
        "is_self": is_self,
        "urls": op_urls,
        "domains": op_domains,
        "has_shortener": op_shortener,
        "has_tracking": op_tracking,
        "has_funnel": op_funnel,
    }

    # BFS traversal so parents are always seen before children and max_comments stays balanced
    timestamp_map: dict[str, float] = {op_fullname: op_created}
    parent_author_map: dict[str, str] = {}
    if not op_info["author_ignored"]:
        parent_author_map[op_fullname] = op_author

    root_children = (
        payload[1].get("data", {}).get("children", [])
        if isinstance(payload[1], dict)
        else []
    )

    queue: collections.deque[tuple[dict[str, Any], int, Optional[str]]] = collections.deque()
    for child in root_children:
        if isinstance(child, dict):
            queue.append((child, 0, None))

    comments: list[dict[str, Any]] = []
    ignored_count = 0

    while queue and len(comments) < max_comments:
        node, depth, root_branch = queue.popleft()
        if node.get("kind") != "t1":
            continue
        data = node.get("data")
        if not isinstance(data, dict):
            continue

        cid = sanitize_identifier(data.get("id"), f"c_{len(comments)}")
        fullname = sanitize_identifier(data.get("name"), f"t1_{cid}")
        parent_id = sanitize_identifier(data.get("parent_id"), op_fullname)
        author = sanitize_identifier(data.get("author"), "[deleted]")
        raw_body = html.unescape(str(data.get("body") or ""))
        created_utc = float(data.get("created_utc") or 0.0)
        branch_id = root_branch or cid

        # Always record timestamp for child latency calculation even if this comment is ignored
        timestamp_map[fullname] = created_utc

        # Enqueue replies regardless of whether this node is ignored/deleted
        replies = data.get("replies")
        if isinstance(replies, dict):
            rep_children = replies.get("data", {}).get("children", [])
            for rep in rep_children:
                if isinstance(rep, dict):
                    queue.append((rep, depth + 1, branch_id))

        body_stripped = raw_body.strip().lower()
        is_ignored = (
            author.lower() in ignored_authors
            or body_stripped in ("[deleted]", "[removed]")
            or not raw_body.strip()
        )
        if is_ignored:
            ignored_count += 1
            continue

        parent_author_map[fullname] = author
        parent_ts = timestamp_map.get(parent_id)
        latency_sec = (
            round(max(0.0, created_utc - parent_ts), 2)
            if parent_ts is not None
            else None
        )
        urls, domains, has_shortener, has_tracking, has_funnel = extract_urls_and_domains(
            raw_body
        )
        edited_utc, edit_delay_sec = parse_edited_utc(data.get("edited"), created_utc)

        comments.append(
            {
                "comment_id": cid,
                "fullname": fullname,
                "thread_id": thread_id,
                "parent_id": parent_id,
                "parent_author": parent_author_map.get(parent_id),
                "root_branch_id": branch_id,
                "author": author,
                "created_utc": created_utc,
                "edited_utc": edited_utc,
                "edit_delay_sec": edit_delay_sec,
                "depth": depth,
                "raw_body": raw_body,
                "char_len": len(raw_body),
                "latency_sec": latency_sec,
                "urls": urls,
                "domains": domains,
                "has_shortener": has_shortener,
                "has_tracking": has_tracking,
                "has_funnel": has_funnel,
            }
        )

    return op_info, comments, ignored_count


# ---------------------------------------------------------------------------
# SQLite Graph Store
# ---------------------------------------------------------------------------

class RedditGraphDB:
    """Incremental SQLite persistence for threads, comments, baselines, and edges."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        self.conn.close()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS threads (
                thread_id TEXT PRIMARY KEY,
                subreddit TEXT NOT NULL,
                author TEXT NOT NULL,
                title TEXT NOT NULL,
                created_utc REAL NOT NULL,
                scraped_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS comments (
                comment_id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL,
                parent_id TEXT NOT NULL,
                author TEXT NOT NULL,
                created_utc REAL NOT NULL,
                char_len INTEGER NOT NULL,
                latency_sec REAL,
                body_excerpt TEXT NOT NULL,
                anomaly_score REAL NOT NULL DEFAULT 0.0,
                edited_utc REAL
            );

            CREATE TABLE IF NOT EXISTS author_baselines (
                author TEXT PRIMARY KEY,
                account_age_days REAL,
                median_len REAL,
                median_interval_sec REAL,
                sample_size INTEGER NOT NULL DEFAULT 0,
                last_checked_utc REAL NOT NULL,
                active_hours_json TEXT,
                stylometry_json TEXT
            );

            CREATE TABLE IF NOT EXISTS co_occurrences (
                author_a TEXT NOT NULL,
                author_b TEXT NOT NULL,
                thread_id TEXT NOT NULL,
                time_delta_sec REAL NOT NULL,
                same_branch INTEGER NOT NULL DEFAULT 0,
                shared_domain TEXT,
                PRIMARY KEY (author_a, author_b, thread_id)
            );

            CREATE TABLE IF NOT EXISTS watchlist (
                author TEXT PRIMARY KEY COLLATE NOCASE,
                verdict TEXT NOT NULL,
                confidence INTEGER NOT NULL DEFAULT 80,
                notes TEXT NOT NULL DEFAULT '',
                updated_utc REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_threads_subreddit ON threads(subreddit);
            CREATE INDEX IF NOT EXISTS idx_comments_thread ON comments(thread_id);
            CREATE INDEX IF NOT EXISTS idx_comments_author ON comments(author);
            CREATE INDEX IF NOT EXISTS idx_comments_parent ON comments(parent_id);
            CREATE INDEX IF NOT EXISTS idx_co_occ_pair ON co_occurrences(author_a, author_b);
            CREATE INDEX IF NOT EXISTS idx_co_occ_thread ON co_occurrences(thread_id);
            CREATE INDEX IF NOT EXISTS idx_watchlist_verdict ON watchlist(verdict);
            """
        )
        # Forward-compatible column migrations for existing DBs
        baseline_cols = {
            row["name"]
            for row in cur.execute("PRAGMA table_info(author_baselines)").fetchall()
        }
        if "active_hours_json" not in baseline_cols:
            cur.execute("ALTER TABLE author_baselines ADD COLUMN active_hours_json TEXT")
        if "stylometry_json" not in baseline_cols:
            cur.execute("ALTER TABLE author_baselines ADD COLUMN stylometry_json TEXT")

        comment_cols = {
            row["name"]
            for row in cur.execute("PRAGMA table_info(comments)").fetchall()
        }
        if "edited_utc" not in comment_cols:
            cur.execute("ALTER TABLE comments ADD COLUMN edited_utc REAL")
        self.conn.commit()

    def upsert_thread(self, op_info: dict[str, Any], scraped_at_iso: str) -> None:
        safe_title = neutralize_untrusted_text(op_info["raw_title"], DB_EXCERPT_MAX_CHARS)
        self.conn.execute(
            """
            INSERT INTO threads (thread_id, subreddit, author, title, created_utc, scraped_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(thread_id) DO UPDATE SET
                subreddit = excluded.subreddit,
                author = excluded.author,
                title = excluded.title,
                created_utc = excluded.created_utc,
                scraped_at = excluded.scraped_at
            """,
            (
                op_info["thread_id"],
                op_info["subreddit"],
                op_info["author"],
                safe_title,
                op_info["created_utc"],
                scraped_at_iso,
            ),
        )
        self.conn.commit()

    def upsert_comments(self, comments: list[dict[str, Any]]) -> None:
        rows = [
            (
                c["comment_id"],
                c["thread_id"],
                c["parent_id"],
                c["author"],
                c["created_utc"],
                c["char_len"],
                c["latency_sec"],
                neutralize_untrusted_text(c["raw_body"], DB_EXCERPT_MAX_CHARS),
                float(c.get("anomaly_score", 0.0)),
                c.get("edited_utc"),
            )
            for c in comments
        ]
        self.conn.executemany(
            """
            INSERT INTO comments (
                comment_id, thread_id, parent_id, author, created_utc,
                char_len, latency_sec, body_excerpt, anomaly_score, edited_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(comment_id) DO UPDATE SET
                parent_id = excluded.parent_id,
                author = excluded.author,
                created_utc = excluded.created_utc,
                char_len = excluded.char_len,
                latency_sec = excluded.latency_sec,
                body_excerpt = excluded.body_excerpt,
                anomaly_score = excluded.anomaly_score,
                edited_utc = COALESCE(excluded.edited_utc, comments.edited_utc)
            """,
            rows,
        )
        self.conn.commit()

    def upsert_co_occurrences(self, edges: list[dict[str, Any]]) -> None:
        if not edges:
            return
        rows = [
            (
                e["author_a"],
                e["author_b"],
                e["thread_id"],
                float(e["time_delta_sec"]),
                1 if e["same_branch"] else 0,
                e["shared_domain"],
            )
            for e in edges
        ]
        self.conn.executemany(
            """
            INSERT INTO co_occurrences (
                author_a, author_b, thread_id, time_delta_sec, same_branch, shared_domain
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(author_a, author_b, thread_id) DO UPDATE SET
                time_delta_sec = MIN(co_occurrences.time_delta_sec, excluded.time_delta_sec),
                same_branch = MAX(co_occurrences.same_branch, excluded.same_branch),
                shared_domain = COALESCE(excluded.shared_domain, co_occurrences.shared_domain)
            """,
            rows,
        )
        self.conn.commit()

    def get_author_baseline(self, author: str) -> Optional[dict[str, Any]]:
        row = self.conn.execute(
            """
            SELECT author, account_age_days, median_len, median_interval_sec,
                   sample_size, last_checked_utc, active_hours_json, stylometry_json
            FROM author_baselines
            WHERE author = ?
            """,
            (author,),
        ).fetchone()
        if not row:
            return None
        hours_data: dict[int, int] = {}
        if row["active_hours_json"]:
            try:
                parsed = json.loads(row["active_hours_json"])
                if isinstance(parsed, dict):
                    hours_data = {int(k): int(v) for k, v in parsed.items()}
            except (ValueError, TypeError):
                hours_data = {}
        stylometry_data: dict[str, float] = {}
        if row["stylometry_json"]:
            try:
                parsed_st = json.loads(row["stylometry_json"])
                if isinstance(parsed_st, dict):
                    stylometry_data = {str(k): float(v) for k, v in parsed_st.items()}
            except (ValueError, TypeError):
                stylometry_data = {}
        return {
            "author": row["author"],
            "account_age_days": row["account_age_days"],
            "median_len": row["median_len"],
            "median_interval_sec": row["median_interval_sec"],
            "sample_size": row["sample_size"],
            "last_checked_utc": row["last_checked_utc"],
            "active_hours": hours_data,
            "stylometry": stylometry_data,
        }

    def upsert_author_baseline(
        self,
        author: str,
        account_age_days: Optional[float],
        median_len: Optional[float],
        median_interval_sec: Optional[float],
        sample_size: int,
        last_checked_utc: float,
        active_hours: dict[int, int],
        stylometry: Optional[dict[str, float]] = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO author_baselines (
                author, account_age_days, median_len, median_interval_sec,
                sample_size, last_checked_utc, active_hours_json, stylometry_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(author) DO UPDATE SET
                account_age_days = COALESCE(excluded.account_age_days, author_baselines.account_age_days),
                median_len = excluded.median_len,
                median_interval_sec = excluded.median_interval_sec,
                sample_size = excluded.sample_size,
                last_checked_utc = excluded.last_checked_utc,
                active_hours_json = excluded.active_hours_json,
                stylometry_json = COALESCE(excluded.stylometry_json, author_baselines.stylometry_json)
            """,
            (
                author,
                account_age_days,
                median_len,
                median_interval_sec,
                sample_size,
                last_checked_utc,
                json.dumps(active_hours, separators=(",", ":")),
                json.dumps(stylometry or {}, separators=(",", ":")),
            ),
        )
        self.conn.commit()

    # -- Watchlist CRUD & Propagation Queries --------------------------------

    def upsert_watchlist(
        self,
        author: str,
        verdict: str,
        confidence: int = 80,
        notes: str = "",
        updated_utc: Optional[float] = None,
    ) -> dict[str, Any]:
        clean_author = sanitize_identifier(author.lstrip("/").removeprefix("u/"), "")
        if not clean_author:
            raise ValueError("Invalid author username for watchlist.")
        verdict_norm = verdict.strip().lower()
        if verdict_norm not in WATCHLIST_VALID_VERDICTS:
            raise ValueError(
                f"Invalid verdict '{verdict}'. Valid: {sorted(WATCHLIST_VALID_VERDICTS)}"
            )
        conf = max(0, min(100, int(confidence)))
        ts = float(updated_utc if updated_utc is not None else time.time())
        safe_notes = neutralize_untrusted_text(notes, 240)
        self.conn.execute(
            """
            INSERT INTO watchlist (author, verdict, confidence, notes, updated_utc)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(author) DO UPDATE SET
                verdict = excluded.verdict,
                confidence = excluded.confidence,
                notes = excluded.notes,
                updated_utc = excluded.updated_utc
            """,
            (clean_author, verdict_norm, conf, safe_notes, ts),
        )
        self.conn.commit()
        return {
            "author": clean_author,
            "verdict": verdict_norm,
            "confidence": conf,
            "notes": safe_notes,
            "updated_utc": ts,
        }

    def remove_watchlist(self, author: str) -> bool:
        clean_author = sanitize_identifier(author.lstrip("/").removeprefix("u/"), "")
        cur = self.conn.execute(
            "DELETE FROM watchlist WHERE LOWER(author) = LOWER(?)", (clean_author,)
        )
        self.conn.commit()
        return cur.rowcount > 0

    def list_watchlist(self, verdict_filter: Optional[str] = None) -> list[dict[str, Any]]:
        if verdict_filter:
            rows = self.conn.execute(
                """
                SELECT author, verdict, confidence, notes, updated_utc
                FROM watchlist
                WHERE LOWER(verdict) = LOWER(?)
                ORDER BY updated_utc DESC
                """,
                (verdict_filter,),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT author, verdict, confidence, notes, updated_utc
                FROM watchlist
                ORDER BY updated_utc DESC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def get_watchlist_map(self, authors: set[str]) -> dict[str, dict[str, Any]]:
        if not authors:
            return {}
        lower_to_orig = {a.lower(): a for a in authors}
        placeholders = ",".join("?" for _ in lower_to_orig)
        rows = self.conn.execute(
            f"""
            SELECT author, verdict, confidence, notes, updated_utc
            FROM watchlist
            WHERE LOWER(author) IN ({placeholders})
            """,
            list(lower_to_orig.keys()),
        ).fetchall()
        out: dict[str, dict[str, Any]] = {}
        for r in rows:
            orig = lower_to_orig.get(r["author"].lower(), r["author"])
            out[orig] = dict(r)
        return out

    def query_watchlisted_co_occurrences(
        self, authors: set[str], window_sec: float
    ) -> dict[str, list[dict[str, Any]]]:
        """Find links between `authors` and any known-bad watchlisted accounts in SQLite."""
        if not authors:
            return {}
        bad_rows = self.conn.execute(
            f"""
            SELECT author, verdict, confidence
            FROM watchlist
            WHERE LOWER(verdict) IN ({",".join("?" for _ in WATCHLIST_BAD_VERDICTS)})
            """,
            sorted(WATCHLIST_BAD_VERDICTS),
        ).fetchall()
        if not bad_rows:
            return {}

        bad_meta = {r["author"].lower(): dict(r) for r in bad_rows}
        bad_lowers = list(bad_meta.keys())
        author_lowers = {a.lower(): a for a in authors}
        a_ph = ",".join("?" for _ in author_lowers)
        b_ph = ",".join("?" for _ in bad_lowers)

        rows = self.conn.execute(
            f"""
            SELECT
                author_a,
                author_b,
                COUNT(DISTINCT thread_id) AS total_threads,
                COUNT(DISTINCT CASE WHEN time_delta_sec <= ? THEN thread_id END) AS rapid_threads,
                MIN(time_delta_sec) AS min_delta_sec,
                GROUP_CONCAT(DISTINCT shared_domain) AS all_shared_domains
            FROM co_occurrences
            WHERE (LOWER(author_a) IN ({a_ph}) AND LOWER(author_b) IN ({b_ph}))
               OR (LOWER(author_b) IN ({a_ph}) AND LOWER(author_a) IN ({b_ph}))
            GROUP BY author_a, author_b
            """,
            [window_sec, *author_lowers.keys(), *bad_lowers, *author_lowers.keys(), *bad_lowers],
        ).fetchall()

        assoc: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
        for r in rows:
            a_low = r["author_a"].lower()
            b_low = r["author_b"].lower()
            domains = sorted(
                {d.strip() for d in (r["all_shared_domains"] or "").split(",") if d.strip()}
            )
            pairs_to_check: list[tuple[str, str]] = []
            if a_low in author_lowers and b_low in bad_meta and a_low != b_low:
                pairs_to_check.append((author_lowers[a_low], b_low))
            if b_low in author_lowers and a_low in bad_meta and a_low != b_low:
                pairs_to_check.append((author_lowers[b_low], a_low))

            for target_author, watched_low in pairs_to_check:
                if int(r["rapid_threads"]) == 0 and not domains:
                    continue
                wm = bad_meta[watched_low]
                assoc[target_author].append(
                    {
                        "watched_author": wm["author"],
                        "watched_verdict": wm["verdict"],
                        "distinct_threads": int(r["total_threads"]),
                        "rapid_threads": int(r["rapid_threads"]),
                        "min_delta_sec": round(float(r["min_delta_sec"]), 2),
                        "shared_domains": domains,
                    }
                )
        return dict(assoc)

    def query_author_graph_summary(self, author: str) -> dict[str, Any]:
        """Return historical graph stats for a single author (used by inspect_account.py)."""
        threads_seen = int(
            self.conn.execute(
                """
                SELECT COUNT(DISTINCT thread_id) FROM (
                    SELECT thread_id FROM comments WHERE LOWER(author) = LOWER(?)
                    UNION
                    SELECT thread_id FROM threads WHERE LOWER(author) = LOWER(?)
                )
                """,
                (author, author),
            ).fetchone()[0]
        )
        comment_stats = self.conn.execute(
            """
            SELECT COUNT(*) AS cnt, MAX(anomaly_score) AS max_score, AVG(anomaly_score) AS avg_score
            FROM comments WHERE LOWER(author) = LOWER(?)
            """,
            (author,),
        ).fetchone()
        co_rows = self.conn.execute(
            """
            SELECT
                CASE WHEN LOWER(author_a) = LOWER(?) THEN author_b ELSE author_a END AS peer,
                COUNT(DISTINCT thread_id) AS distinct_threads,
                MIN(time_delta_sec) AS min_delta_sec,
                GROUP_CONCAT(DISTINCT shared_domain) AS domains
            FROM co_occurrences
            WHERE LOWER(author_a) = LOWER(?) OR LOWER(author_b) = LOWER(?)
            GROUP BY peer
            ORDER BY distinct_threads DESC, min_delta_sec ASC
            LIMIT 8
            """,
            (author, author, author),
        ).fetchall()
        top_peers = [
            {
                "peer": r["peer"],
                "distinct_threads": int(r["distinct_threads"]),
                "min_delta_sec": round(float(r["min_delta_sec"]), 2),
                "shared_domains": sorted(
                    {d.strip() for d in (r["domains"] or "").split(",") if d.strip()}
                ),
            }
            for r in co_rows
        ]
        wl = self.get_watchlist_map({author}).get(author)
        wl_assoc = self.query_watchlisted_co_occurrences({author}, window_sec=300.0).get(author, [])
        return {
            "threads_in_db": threads_seen,
            "comments_in_db": int(comment_stats["cnt"] or 0),
            "max_recorded_score": round(float(comment_stats["max_score"] or 0.0), 1),
            "top_co_occurring_peers": top_peers,
            "watchlist_entry": wl,
            "watchlisted_associations": wl_assoc,
        }

    def query_pair_history(
        self, authors: set[str], window_sec: float
    ) -> list[dict[str, Any]]:
        """Query co-occurrence history for pairs where both authors are in `authors`."""
        if len(authors) < 2:
            return []
        placeholders = ",".join("?" for _ in authors)
        author_list = sorted(authors)
        sql = f"""
            SELECT
                author_a,
                author_b,
                COUNT(DISTINCT thread_id) AS total_threads,
                COUNT(DISTINCT CASE WHEN time_delta_sec <= ? THEN thread_id END) AS rapid_threads,
                MIN(time_delta_sec) AS min_delta_sec,
                MAX(same_branch) AS any_same_branch,
                GROUP_CONCAT(DISTINCT shared_domain) AS all_shared_domains
            FROM co_occurrences
            WHERE author_a IN ({placeholders})
              AND author_b IN ({placeholders})
            GROUP BY author_a, author_b
        """
        rows = self.conn.execute(sql, [window_sec, *author_list, *author_list]).fetchall()
        results: list[dict[str, Any]] = []
        for r in rows:
            domains = sorted(
                {
                    d.strip()
                    for d in (r["all_shared_domains"] or "").split(",")
                    if d.strip()
                }
            )
            results.append(
                {
                    "author_a": r["author_a"],
                    "author_b": r["author_b"],
                    "total_threads": int(r["total_threads"]),
                    "rapid_threads": int(r["rapid_threads"]),
                    "min_delta_sec": round(float(r["min_delta_sec"]), 2),
                    "any_same_branch": bool(r["any_same_branch"]),
                    "shared_domains": domains,
                }
            )
        return results

    def query_subreddit_power_users(
        self, subreddit: str, authors: set[str]
    ) -> tuple[int, dict[str, dict[str, Any]]]:
        """Detect accounts appearing in >60% of stored threads for this subreddit."""
        total_row = self.conn.execute(
            "SELECT COUNT(DISTINCT thread_id) AS cnt FROM threads WHERE LOWER(subreddit) = LOWER(?)",
            (subreddit,),
        ).fetchone()
        total_threads = int(total_row["cnt"]) if total_row else 0
        power_users: dict[str, dict[str, Any]] = {}

        if total_threads < 3 or not authors:
            return total_threads, power_users

        placeholders = ",".join("?" for _ in authors)
        author_list = sorted(authors)
        sql = f"""
            SELECT author, COUNT(DISTINCT thread_id) AS appeared_threads
            FROM (
                SELECT c.author AS author, c.thread_id AS thread_id
                FROM comments c
                JOIN threads t ON c.thread_id = t.thread_id
                WHERE LOWER(t.subreddit) = LOWER(?)
                  AND c.author IN ({placeholders})
                UNION
                SELECT t.author AS author, t.thread_id AS thread_id
                FROM threads t
                WHERE LOWER(t.subreddit) = LOWER(?)
                  AND t.author IN ({placeholders})
            )
            GROUP BY author
        """
        rows = self.conn.execute(
            sql, [subreddit, *author_list, subreddit, *author_list]
        ).fetchall()
        for r in rows:
            ratio = r["appeared_threads"] / total_threads
            if ratio > 0.60:
                power_users[r["author"]] = {
                    "threads_seen": int(r["appeared_threads"]),
                    "subreddit_threads": total_threads,
                    "presence_ratio": round(ratio, 3),
                }
        return total_threads, power_users

    def query_repeating_role_patterns(
        self, current_authors: set[str], window_sec: float
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Find directed reply pairs (A->B) and chains (A->B->C) repeating across >=2 threads."""
        if len(current_authors) < 2:
            return [], []

        placeholders = ",".join("?" for _ in current_authors)
        author_list = sorted(current_authors)
        thread_rows = self.conn.execute(
            f"""
            SELECT DISTINCT thread_id FROM (
                SELECT thread_id FROM comments WHERE author IN ({placeholders})
                UNION
                SELECT thread_id FROM threads WHERE author IN ({placeholders})
            )
            """,
            [*author_list, *author_list],
        ).fetchall()
        thread_ids = [r["thread_id"] for r in thread_rows]
        if len(thread_ids) < 2:
            return [], []

        t_placeholders = ",".join("?" for _ in thread_ids)
        thread_ops = {
            r["thread_id"]: (r["author"], float(r["created_utc"]))
            for r in self.conn.execute(
                f"SELECT thread_id, author, created_utc FROM threads WHERE thread_id IN ({t_placeholders})",
                thread_ids,
            ).fetchall()
        }
        comment_rows = self.conn.execute(
            f"""
            SELECT comment_id, thread_id, parent_id, author, created_utc
            FROM comments
            WHERE thread_id IN ({t_placeholders})
            ORDER BY thread_id, created_utc ASC
            """,
            thread_ids,
        ).fetchall()

        by_thread: dict[str, list[sqlite3.Row]] = collections.defaultdict(list)
        for r in comment_rows:
            by_thread[r["thread_id"]].append(r)

        pair_threads: dict[tuple[str, str], set[str]] = collections.defaultdict(set)
        triple_threads: dict[tuple[str, str, str], set[str]] = collections.defaultdict(set)

        for tid, rows in by_thread.items():
            node_info: dict[str, tuple[str, float, Optional[str]]] = {}
            if tid in thread_ops:
                op_author, op_ts = thread_ops[tid]
                node_info[f"t3_{tid}"] = (op_author, op_ts, None)

            for r in rows:
                fullname = f"t1_{r['comment_id']}"
                node_info[fullname] = (r["author"], float(r["created_utc"]), r["parent_id"])

            # Direct reply pairs A -> B and reply triples A -> B -> C within window_sec
            for r in rows:
                b_author = r["author"]
                b_ts = float(r["created_utc"])
                parent_key = r["parent_id"]
                if parent_key not in node_info:
                    continue
                a_author, a_ts, grand_key = node_info[parent_key]
                if a_author != b_author and 0 <= (b_ts - a_ts) <= window_sec:
                    if a_author in current_authors and b_author in current_authors:
                        pair_threads[(a_author, b_author)].add(tid)

                if grand_key and grand_key in node_info:
                    g_author, g_ts, _ = node_info[grand_key]
                    if (
                        len({g_author, a_author, b_author}) == 3
                        and 0 <= (a_ts - g_ts) <= window_sec
                        and 0 <= (b_ts - a_ts) <= window_sec
                        and g_author in current_authors
                        and a_author in current_authors
                        and b_author in current_authors
                    ):
                        triple_threads[(g_author, a_author, b_author)].add(tid)

            # Rapid sequential triples in same thread within window_sec
            for i in range(len(rows)):
                a_auth, a_ts = rows[i]["author"], float(rows[i]["created_utc"])
                if a_auth not in current_authors:
                    continue
                for j in range(i + 1, len(rows)):
                    b_auth, b_ts = rows[j]["author"], float(rows[j]["created_utc"])
                    if b_ts - a_ts > window_sec:
                        break
                    if b_auth == a_auth or b_auth not in current_authors:
                        continue
                    for k in range(j + 1, len(rows)):
                        c_auth, c_ts = rows[k]["author"], float(rows[k]["created_utc"])
                        if c_ts - b_ts > window_sec:
                            break
                        if c_auth in (a_auth, b_auth) or c_auth not in current_authors:
                            continue
                        triple_threads[(a_auth, b_auth, c_auth)].add(tid)

        repeating_triples = [
            {
                "pattern": f"{a} -> {b} -> {c}",
                "authors": [a, b, c],
                "distinct_threads": len(tids),
            }
            for (a, b, c), tids in sorted(
                triple_threads.items(), key=lambda kv: len(kv[1]), reverse=True
            )
            if len(tids) >= 2
        ]
        repeating_pairs = [
            {
                "pattern": f"{a} -> {b}",
                "authors": [a, b],
                "distinct_threads": len(tids),
            }
            for (a, b), tids in sorted(
                pair_threads.items(), key=lambda kv: len(kv[1]), reverse=True
            )
            if len(tids) >= 2
        ]
        return repeating_pairs[:10], repeating_triples[:10]

    def get_db_stats(self, subreddit: str) -> dict[str, int]:
        threads_cnt = int(
            self.conn.execute("SELECT COUNT(*) FROM threads").fetchone()[0]
        )
        comments_cnt = int(
            self.conn.execute("SELECT COUNT(*) FROM comments").fetchone()[0]
        )
        authors_cnt = int(
            self.conn.execute(
                """
                SELECT COUNT(DISTINCT author) FROM (
                    SELECT author FROM threads
                    UNION
                    SELECT author FROM comments
                    UNION
                    SELECT author FROM author_baselines
                )
                WHERE LOWER(author) NOT IN ('[deleted]', '[removed]', 'automoderator')
                """
            ).fetchone()[0]
        )
        edges_cnt = int(
            self.conn.execute("SELECT COUNT(*) FROM co_occurrences").fetchone()[0]
        )
        sub_threads_cnt = int(
            self.conn.execute(
                "SELECT COUNT(*) FROM threads WHERE LOWER(subreddit) = LOWER(?)",
                (subreddit,),
            ).fetchone()[0]
        )
        watchlist_cnt = int(
            self.conn.execute(
                f"SELECT COUNT(*) FROM watchlist WHERE LOWER(verdict) IN ({','.join('?' for _ in WATCHLIST_BAD_VERDICTS)})",
                sorted(WATCHLIST_BAD_VERDICTS),
            ).fetchone()[0]
        )
        return {
            "total_threads": threads_cnt,
            "total_authors": authors_cnt,
            "total_comments": comments_cnt,
            "total_co_occurrences": edges_cnt,
            "subreddit_threads": sub_threads_cnt,
            "watchlist_count": watchlist_cnt,
        }


# ---------------------------------------------------------------------------
# Class 3 Heuristics — Spilled Agent & OP Post
# ---------------------------------------------------------------------------

def score_comment_class3(comment: dict[str, Any]) -> tuple[int, list[str], dict[str, Any]]:
    """Score a single comment for Class 3 (Spilled Agent / LLM artifacts / injection)."""
    body = comment["raw_body"]
    char_len = comment["char_len"]
    latency_sec = comment["latency_sec"]

    score = 0
    flags: list[str] = []

    chars_per_sec: Optional[float] = None
    if latency_sec is not None:
        chars_per_sec = round(char_len / max(latency_sec, 1.0), 2)

    bold_bullets = len(RE_BOLD_BULLET.findall(body))
    md_headers = len(RE_MD_HEADER.findall(body))
    style_hits = len(RE_LLM_STYLE_PHRASES.findall(body))
    is_structured = bold_bullets >= 2 or md_headers >= 2

    # 1. Response velocity vs. length / complexity
    if latency_sec is not None:
        if char_len >= 800 and latency_sec <= 25:
            score += 45
            flags.append("ultra_fast_long_reply")
        elif (char_len >= 400 and latency_sec <= 20) or (
            chars_per_sec is not None and chars_per_sec >= 25.0 and char_len >= 250
        ):
            score += 28
            flags.append("superhuman_typing_velocity")
        elif chars_per_sec is not None and chars_per_sec >= 15.0 and char_len >= 200:
            score += 14
            flags.append("elevated_typing_velocity")

        if is_structured and latency_sec <= 45 and char_len >= 300:
            score += 12
            flags.append("structured_fast_response")

    # 2. Leaked agentic / LLM artifacts
    if RE_TOOL_CALL_TAGS.search(body):
        score += 50
        flags.append("leaked_tool_call_artifact")

    if RE_LEAKED_JSON_AGENT.search(body):
        score += 25
        flags.append("leaked_json_fragment")

    if RE_LLM_BOILERPLATE.search(body):
        score += 25
        flags.append("llm_boilerplate_refusal")

    # 3. Prompt injection patterns
    inj_matches = RE_PROMPT_INJECTION.findall(body)
    if inj_matches:
        score += 55 + (15 if len(inj_matches) >= 2 else 0)
        flags.append("prompt_injection_pattern")

    # 4. Supporting formatting / promotional signals
    if (bold_bullets >= 3 or style_hits >= 2) and char_len >= 350:
        score += 8
        flags.append("llm_style_markers")

    if comment["has_shortener"]:
        score += 10
        flags.append("url_shortener_link")
    if comment["has_tracking"]:
        score += 8
        flags.append("tracking_or_affiliate_link")
    if comment["has_funnel"]:
        score += 12
        flags.append("external_funnel_link")

    # 5. Stealth-edit link injection (edited >= 5 min after posting with non-reference/tracked URL)
    edit_delay_sec = comment.get("edit_delay_sec")
    if (
        edit_delay_sec is not None
        and edit_delay_sec >= 300.0
        and has_suspicious_edit_link(
            comment["domains"],
            comment["has_shortener"],
            comment["has_tracking"],
            comment["has_funnel"],
        )
    ):
        score += 42 if (
            comment["has_shortener"] or comment["has_tracking"] or comment["has_funnel"]
        ) else 32
        flags.append("stealth_edit_link_injection")

    features: dict[str, Any] = {
        "char_len": char_len,
        "latency_sec": latency_sec,
        "chars_per_sec": chars_per_sec,
        "bold_bullets": bold_bullets,
        "domains": comment["domains"][:5],
    }
    if edit_delay_sec is not None:
        features["edit_delay_sec"] = edit_delay_sec
    return min(100, score), flags, features


def score_op_class3(op_info: dict[str, Any]) -> tuple[int, list[str]]:
    """Evaluate OP post for templated structure, suspicious links/CTAs, and agent artifacts."""
    combined = f"{op_info['raw_title']}\n{op_info['raw_selftext']}"
    score = 0
    flags: list[str] = []

    if RE_TOOL_CALL_TAGS.search(combined):
        score += 50
        flags.append("leaked_tool_call_artifact")
    if RE_LEAKED_JSON_AGENT.search(combined):
        score += 25
        flags.append("leaked_json_fragment")
    if RE_LLM_BOILERPLATE.search(combined):
        score += 25
        flags.append("llm_boilerplate_refusal")
    if RE_PROMPT_INJECTION.search(combined):
        score += 55
        flags.append("prompt_injection_pattern")

    bold_bullets = len(RE_BOLD_BULLET.findall(op_info["raw_selftext"]))
    md_headers = len(RE_MD_HEADER.findall(op_info["raw_selftext"]))
    templated_title = bool(RE_OP_TEMPLATED_TITLE.search(op_info["raw_title"]))

    if templated_title:
        score += 18
        flags.append("op_templated_title")
    if bold_bullets >= 3 or (bold_bullets >= 2 and md_headers >= 2):
        score += 16
        flags.append("op_templated_structure")
    if RE_OP_CTA.search(combined):
        score += 22
        flags.append("op_engagement_bait_cta")

    if op_info["has_shortener"]:
        score += 18
        flags.append("op_url_shortener")
    if op_info["has_tracking"]:
        score += 12
        flags.append("op_tracking_params")
    if op_info["has_funnel"]:
        score += 18
        flags.append("op_external_funnel_link")

    op_edit_delay = op_info.get("edit_delay_sec")
    if (
        op_edit_delay is not None
        and op_edit_delay >= 300.0
        and has_suspicious_edit_link(
            op_info["domains"],
            op_info["has_shortener"],
            op_info["has_tracking"],
            op_info["has_funnel"],
        )
    ):
        score += 22
        flags.append("op_stealth_edit_link")

    return min(100, score), flags


# ---------------------------------------------------------------------------
# Class 2 Heuristics — Coordination Graph (Swarm)
# ---------------------------------------------------------------------------

def build_current_co_occurrences(
    op_info: dict[str, Any],
    comments: list[dict[str, Any]],
    window_sec: float,
) -> list[dict[str, Any]]:
    """Extract current-thread co-occurrence edges (within window_sec OR direct reply)."""
    thread_id = op_info["thread_id"]
    edges_map: dict[tuple[str, str], dict[str, Any]] = {}

    def record_edge(
        u1: str,
        u2: str,
        delta: float,
        same_branch: bool,
        shared_domains: set[str],
    ) -> None:
        if not u1 or not u2 or u1 == u2:
            return
        a, b = sorted((u1, u2))
        domain_str = ",".join(sorted(shared_domains)) if shared_domains else None
        key = (a, b)
        if key not in edges_map:
            edges_map[key] = {
                "author_a": a,
                "author_b": b,
                "thread_id": thread_id,
                "time_delta_sec": round(delta, 2),
                "same_branch": same_branch,
                "shared_domain": domain_str,
            }
        else:
            existing = edges_map[key]
            existing["time_delta_sec"] = round(min(existing["time_delta_sec"], delta), 2)
            existing["same_branch"] = bool(existing["same_branch"] or same_branch)
            if domain_str:
                merged = set(
                    d for d in (existing["shared_domain"] or "").split(",") if d
                ) | set(domain_str.split(","))
                existing["shared_domain"] = ",".join(sorted(merged))

    # 1. Comment-to-comment pairs (within window_sec OR direct reply)
    n = len(comments)
    for i in range(n):
        c1 = comments[i]
        d1 = set(c1["domains"])
        for j in range(i + 1, n):
            c2 = comments[j]
            if c1["author"] == c2["author"]:
                continue
            delta = abs(c1["created_utc"] - c2["created_utc"])
            is_direct_reply = (
                c2["parent_id"] == c1["fullname"] or c1["parent_id"] == c2["fullname"]
            )
            shared = d1 & set(c2["domains"])
            if delta <= window_sec or is_direct_reply or bool(shared):
                same_branch = is_direct_reply or (
                    c1["root_branch_id"] == c2["root_branch_id"]
                )
                record_edge(c1["author"], c2["author"], delta, same_branch, shared)

    # 2. OP-to-comment pairs (within window_sec OR sharing an external domain)
    if not op_info["author_ignored"]:
        op_domains = set(op_info["domains"])
        for c in comments:
            if c["author"] == op_info["author"]:
                continue
            delta = abs(c["created_utc"] - op_info["created_utc"])
            shared = op_domains & set(c["domains"])
            if delta <= window_sec or bool(shared):
                is_direct = c["parent_id"] == op_info["fullname"]
                record_edge(op_info["author"], c["author"], delta, is_direct, shared)

    return list(edges_map.values())


def evaluate_coordination_graph(
    db: RedditGraphDB,
    op_info: dict[str, Any],
    comments: list[dict[str, Any]],
    current_edges: list[dict[str, Any]],
    window_sec: float,
) -> tuple[dict[str, int], dict[str, list[str]], list[dict[str, Any]], dict[str, Any]]:
    """Compute Class 2 swarm scores, per-author flags, and cluster summaries."""
    current_authors: set[str] = {c["author"] for c in comments}
    if not op_info["author_ignored"]:
        current_authors.add(op_info["author"])

    pair_history = db.query_pair_history(current_authors, window_sec)
    sub_thread_count, power_users = db.query_subreddit_power_users(
        op_info["subreddit"], current_authors
    )
    repeating_pairs, repeating_triples = db.query_repeating_role_patterns(
        current_authors, window_sec
    )
    watchlist_map = db.get_watchlist_map(current_authors)
    wl_associations = db.query_watchlisted_co_occurrences(current_authors, window_sec)

    current_edge_by_pair: dict[tuple[str, str], dict[str, Any]] = {
        (e["author_a"], e["author_b"]): e for e in current_edges
    }

    author_scores: dict[str, float] = collections.defaultdict(float)
    author_flags: dict[str, set[str]] = collections.defaultdict(set)
    flagged_edges: list[dict[str, Any]] = []
    watchlist_hits: list[dict[str, Any]] = []
    watchlist_assoc_out: list[dict[str, Any]] = []

    # Direct watchlist hits & guilt-by-association propagation
    for author, wl in watchlist_map.items():
        verdict = wl["verdict"].lower()
        if verdict in WATCHLIST_BAD_VERDICTS:
            base_boost = 70.0 if verdict.startswith("confirmed_") else 45.0
            author_scores[author] = max(author_scores[author], base_boost)
            author_flags[author].add(f"watchlisted_{verdict}")
            watchlist_hits.append(
                {
                    "author": author,
                    "verdict": verdict,
                    "confidence": wl["confidence"],
                }
            )
        elif verdict == "benign":
            author_flags[author].add("watchlisted_benign")

    for author, links in wl_associations.items():
        wl_self = watchlist_map.get(author)
        if wl_self and wl_self["verdict"].lower() == "benign":
            continue
        for lnk in links:
            strong_assoc = (
                lnk["distinct_threads"] >= 2
                or bool(lnk["shared_domains"])
                or lnk["min_delta_sec"] <= 60.0
            )
            pts = 45.0 if strong_assoc else 28.0
            if author in power_users and not lnk["shared_domains"]:
                pts *= 0.5
            author_scores[author] = max(author_scores[author], pts)
            author_flags[author].add("cooccurs_with_watchlisted")
            watchlist_assoc_out.append(
                {
                    "author": author,
                    "watched_author": lnk["watched_author"],
                    "watched_verdict": lnk["watched_verdict"],
                    "distinct_threads": lnk["distinct_threads"],
                    "min_delta_sec": lnk["min_delta_sec"],
                    "shared_domains": lnk["shared_domains"],
                }
            )
            a, b = sorted((author, lnk["watched_author"]))
            flagged_edges.append(
                {
                    "author_a": a,
                    "author_b": b,
                    "distinct_threads": lnk["distinct_threads"],
                    "rapid_threads": lnk["rapid_threads"],
                    "current_delta_sec": lnk["min_delta_sec"],
                    "same_branch": False,
                    "shared_domains": lnk["shared_domains"],
                    "signals": ["cooccurs_with_watchlisted"],
                }
            )

    for hist in pair_history:
        a, b = hist["author_a"], hist["author_b"]
        cur_edge = current_edge_by_pair.get((a, b))
        cur_delta = cur_edge["time_delta_sec"] if cur_edge else hist["min_delta_sec"]
        cur_same_branch = cur_edge["same_branch"] if cur_edge else hist["any_same_branch"]
        cur_shared = (
            [d for d in (cur_edge["shared_domain"] or "").split(",") if d]
            if cur_edge
            else hist["shared_domains"]
        )
        all_shared = sorted(set(hist["shared_domains"]) | set(cur_shared))

        edge_score = 0.0
        edge_signals: list[str] = []

        # Cross-thread rapid co-occurrence (>=2 distinct threads within window_sec)
        if hist["rapid_threads"] >= 2:
            pts = min(70.0, 45.0 + 10.0 * (hist["rapid_threads"] - 2))
            edge_score += pts
            edge_signals.append("cross_thread_rapid_cooccurrence")

        # Same-thread / historical shared external domain signals
        if all_shared:
            if cur_delta <= 60.0:
                edge_score += 48.0
                edge_signals.append("rapid_shared_domain_pair")
            elif cur_delta <= window_sec:
                edge_score += 32.0
                edge_signals.append("shared_domain_cooccurrence")
            else:
                edge_score += 18.0
                edge_signals.append("shared_external_domain")

        # Tight same-branch burst without shared domain (mild corroborator)
        if cur_same_branch and cur_delta <= 45.0:
            edge_score += 12.0
            edge_signals.append("rapid_same_branch_pair")

        if edge_score <= 0:
            continue

        # Power-user dampening for pure timing co-occurrence (keep domain sharing intact)
        both_or_either_power = (a in power_users) or (b in power_users)
        if both_or_either_power and not all_shared:
            edge_score *= 0.4
            edge_signals.append("power_user_dampened")

        # Only promote genuinely noteworthy links into clusters (avoid noise)
        is_significant = (
            hist["rapid_threads"] >= 2
            or bool(all_shared)
            or edge_score >= 25.0
        )
        if is_significant:
            for user in (a, b):
                author_scores[user] = max(author_scores[user], edge_score)
                author_flags[user].update(edge_signals)
                if user in power_users:
                    author_flags[user].add("power_user")
            flagged_edges.append(
                {
                    "author_a": a,
                    "author_b": b,
                    "distinct_threads": hist["total_threads"],
                    "rapid_threads": hist["rapid_threads"],
                    "current_delta_sec": cur_delta,
                    "same_branch": bool(cur_same_branch),
                    "shared_domains": all_shared,
                    "signals": edge_signals,
                }
            )

    # Apply repeating role-pattern bonuses (A -> B and A -> B -> C across >=2 threads)
    for rp in repeating_pairs:
        a, b = rp["authors"]
        bonus = 35.0
        if (a in power_users or b in power_users):
            bonus *= 0.5
        for u in (a, b):
            author_scores[u] = max(author_scores[u], bonus)
            author_flags[u].add("repeating_role_pair")

    for rt in repeating_triples:
        bonus = 50.0
        if any(u in power_users for u in rt["authors"]):
            bonus *= 0.6
        for u in rt["authors"]:
            author_scores[u] = max(author_scores[u], bonus)
            author_flags[u].add("repeating_role_triple")

    # Zero out Class 2 swarm scores for explicitly verified benign accounts
    for author, wl in watchlist_map.items():
        if wl["verdict"].lower() == "benign":
            author_scores[author] = 0.0

    # Deduplicate flagged_edges by canonical (author_a, author_b)
    dedup_edges: dict[tuple[str, str], dict[str, Any]] = {}
    for e in flagged_edges:
        pair_key = (e["author_a"], e["author_b"])
        if pair_key not in dedup_edges:
            dedup_edges[pair_key] = dict(e)
        else:
            ex = dedup_edges[pair_key]
            ex["distinct_threads"] = max(ex["distinct_threads"], e["distinct_threads"])
            ex["rapid_threads"] = max(ex["rapid_threads"], e["rapid_threads"])
            ex["current_delta_sec"] = min(ex["current_delta_sec"], e["current_delta_sec"])
            ex["same_branch"] = bool(ex["same_branch"] or e["same_branch"])
            ex["shared_domains"] = sorted(set(ex["shared_domains"]) | set(e["shared_domains"]))
            ex["signals"] = sorted(set(ex["signals"]) | set(e["signals"]))
    flagged_edges = list(dedup_edges.values())

    # Group flagged_edges into connected clusters
    adj: dict[str, set[str]] = collections.defaultdict(set)
    for e in flagged_edges:
        adj[e["author_a"]].add(e["author_b"])
        adj[e["author_b"]].add(e["author_a"])

    visited: set[str] = set()
    clusters: list[dict[str, Any]] = []
    cluster_idx = 0

    for node in sorted(adj.keys()):
        if node in visited:
            continue
        comp: set[str] = set()
        stack = [node]
        while stack:
            curr = stack.pop()
            if curr in visited:
                continue
            visited.add(curr)
            comp.add(curr)
            stack.extend(adj[curr] - visited)

        comp_edges = [
            e for e in flagged_edges if e["author_a"] in comp and e["author_b"] in comp
        ]
        cluster_idx += 1
        signals = sorted({s for e in comp_edges for s in e["signals"]})
        domains = sorted({d for e in comp_edges for d in e["shared_domains"]})
        min_delta = min(e["current_delta_sec"] for e in comp_edges)
        max_threads = max(e["distinct_threads"] for e in comp_edges)
        comp_power_users = sorted(u for u in comp if u in power_users)

        clusters.append(
            {
                "cluster_id": f"cluster_{cluster_idx}",
                "authors": sorted(comp),
                "edge_count": len(comp_edges),
                "max_distinct_threads": max_threads,
                "min_time_delta_sec": min_delta,
                "shared_domains": domains[:5],
                "signals": signals,
                "power_users_in_cluster": comp_power_users,
                "edges": comp_edges[:8],
            }
        )

    final_scores = {u: min(100, int(round(s))) for u, s in author_scores.items()}
    final_flags = {u: sorted(fl) for u, fl in author_flags.items()}
    graph_meta = {
        "subreddit_threads_in_db": sub_thread_count,
        "power_users_flagged": power_users,
        "repeating_role_patterns": repeating_triples + repeating_pairs,
        "watchlist_map": watchlist_map,
        "watchlist_hits": watchlist_hits,
        "watchlist_associations": watchlist_assoc_out[:10],
    }
    return final_scores, final_flags, clusters, graph_meta


# ---------------------------------------------------------------------------
# Class 1 Heuristics — Account Takeover (Two-Stage Fetch + Drift)
# ---------------------------------------------------------------------------

def parse_user_comments_history(
    payload: Any, exclude_thread_id: str
) -> list[dict[str, Any]]:
    """Extract historical comments from Reddit `/user/{author}/comments.json`."""
    if not isinstance(payload, dict):
        return []
    children = payload.get("data", {}).get("children", [])
    history: list[dict[str, Any]] = []
    for child in children:
        if not isinstance(child, dict) or child.get("kind") != "t1":
            continue
        d = child.get("data", {})
        link_id = str(d.get("link_id") or "")
        if link_id == f"t3_{exclude_thread_id}":
            continue
        body = html.unescape(str(d.get("body") or ""))
        created_utc = float(d.get("created_utc") or 0.0)
        if created_utc <= 0:
            continue
        history.append(
            {
                "body": body,
                "char_len": len(body),
                "created_utc": created_utc,
                "author_created_utc": d.get("author_created_utc"),
            }
        )
    return history


def compute_baseline_from_history(
    history: list[dict[str, Any]], now_utc: float
) -> dict[str, Any]:
    """Compute historical median length, cadence interval, active hours, stylometry, and age."""
    sample_size = len(history)
    if sample_size == 0:
        return {
            "account_age_days": None,
            "median_len": None,
            "median_interval_sec": None,
            "sample_size": 0,
            "active_hours": {},
            "stylometry": {},
            "latest_hist_utc": None,
        }

    lengths = [h["char_len"] for h in history]
    timestamps = sorted(h["created_utc"] for h in history)
    intervals = [
        timestamps[i + 1] - timestamps[i]
        for i in range(len(timestamps) - 1)
        if timestamps[i + 1] >= timestamps[i]
    ]

    hour_counts: dict[int, int] = collections.Counter(
        utc_hour_from_ts(ts) for ts in timestamps
    )
    stylometry = aggregate_stylometry([str(h.get("body") or "") for h in history])

    account_age_days: Optional[float] = None
    for h in history:
        ac = h.get("author_created_utc")
        if isinstance(ac, (int, float)) and ac > 0:
            account_age_days = round(max(0.0, (now_utc - float(ac)) / 86400.0), 1)
            break

    return {
        "account_age_days": account_age_days,
        "median_len": round(float(statistics.median(lengths)), 1),
        "median_interval_sec": (
            round(float(statistics.median(intervals)), 1) if intervals else None
        ),
        "sample_size": sample_size,
        "active_hours": dict(hour_counts),
        "stylometry": stylometry,
        "latest_hist_utc": timestamps[-1],
    }


def score_profile_drift(
    baseline: dict[str, Any],
    current_char_len: int,
    current_created_utc: float,
    latest_hist_utc: Optional[float] = None,
    current_text: Optional[str] = None,
) -> tuple[int, dict[str, Any]]:
    """Compute Class 1 Account Takeover drift score (0-100) and diagnostic dict."""
    sample_size = int(baseline.get("sample_size") or 0)
    median_len = baseline.get("median_len")
    active_hours: dict[int, int] = baseline.get("active_hours") or {}
    hist_style: dict[str, float] = baseline.get("stylometry") or {}
    current_hour = utc_hour_from_ts(current_created_utc)

    score = 0
    drift_flags: list[str] = []

    len_ratio: Optional[float] = None
    if sample_size < 3:
        if current_char_len >= 600:
            score += 10
            drift_flags.append("sparse_history_long_post")
    else:
        # 1. Text length drift
        if median_len is not None and median_len > 0:
            len_ratio = round(current_char_len / median_len, 2)
            if len_ratio >= 4.0 and current_char_len >= 300:
                score += 38
                drift_flags.append("length_drift_spike")
            elif len_ratio >= 2.5 and current_char_len >= 200:
                score += 22
                drift_flags.append("length_drift_moderate")
            elif median_len >= 400 and len_ratio <= 0.15:
                score += 10
                drift_flags.append("length_drift_drop")

        # 2. Active UTC hours drift
        if active_hours:
            total_obs = sum(active_hours.values())
            near_obs = sum(
                cnt
                for hr, cnt in active_hours.items()
                if circular_hour_distance(int(hr), current_hour) <= 2
            )
            min_dist = min(
                circular_hour_distance(int(hr), current_hour) for hr in active_hours
            )
            near_frac = near_obs / max(total_obs, 1)

            if sample_size >= 5 and near_obs == 0 and min_dist >= 4:
                score += 32
                drift_flags.append("active_hours_shift_strong")
            elif near_frac < 0.10 and min_dist >= 3:
                score += 18
                drift_flags.append("active_hours_shift_moderate")

        # 3. Lightweight stylometric baseline drift (casual -> formal/structured shift)
        if sample_size >= 5 and hist_style and current_text:
            cur_style = compute_text_stylometry(current_text)
            hist_casual = hist_style.get("casual_rate", 0.0)
            hist_md = hist_style.get("markdown_rate", 0.0)
            hist_sent = hist_style.get("avg_sentence_words", 0.0)
            hist_em = hist_style.get("em_dash_per_1k", 0.0)

            if (
                hist_casual >= 0.60
                and hist_md <= 0.15
                and current_char_len >= 220
                and cur_style["is_casual"] == 0.0
                and (
                    cur_style["has_markdown"] == 1.0
                    or (hist_sent > 0 and hist_sent <= 12.0 and cur_style["avg_sentence_words"] >= 18.0)
                )
            ):
                score += 22
                drift_flags.append("stylometric_formality_jump")

            if (
                hist_em < 1.5
                and cur_style["em_dash_count"] >= 2.0
                and current_char_len >= 200
            ):
                score += 15
                drift_flags.append("stylometric_punctuation_shift")

    # 4. Dormancy wake-up (if latest historical timestamp available)
    dormancy_days: Optional[float] = None
    if latest_hist_utc is not None and current_created_utc > latest_hist_utc:
        dormancy_days = round((current_created_utc - latest_hist_utc) / 86400.0, 1)
        if dormancy_days >= 90.0:
            score += 30
            drift_flags.append("dormant_account_reactivation")
        elif dormancy_days >= 30.0:
            score += 15
            drift_flags.append("extended_inactivity_gap")

    top_hours = [
        hr
        for hr, _ in sorted(
            active_hours.items(), key=lambda kv: (-kv[1], kv[0])
        )[:4]
    ]

    drift_info: dict[str, Any] = {
        "sample_size": sample_size,
        "median_len": median_len,
        "len_ratio": len_ratio,
        "current_hour_utc": current_hour,
        "typical_hours_utc": top_hours,
        "dormancy_days": dormancy_days,
        "drift_flags": drift_flags,
    }
    if hist_style:
        drift_info["baseline_stylometry"] = hist_style
    return min(100, score), drift_info


def run_stage2_profile_checks(
    db: RedditGraphDB,
    fetcher: RateLimitedFetcher,
    op_info: dict[str, Any],
    comments: list[dict[str, Any]],
    op_prelim_score: int,
    no_profile_fetch: bool,
    mock_mode: bool,
    mock_profiles: Optional[dict[str, Any]],
    warnings: list[str],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Stage-2 fetch ONLY for top 3 comment authors (+ flagged OP) not checked in 24h."""
    # Rank unique comment authors by their highest preliminary score
    best_by_author: dict[str, int] = {}
    for c in comments:
        a = c["author"]
        sc = c["prelim_score"]
        if a not in best_by_author or sc > best_by_author[a]:
            best_by_author[a] = sc

    ranked_comment_authors = [
        a
        for a, sc in sorted(best_by_author.items(), key=lambda kv: (-kv[1], kv[0]))
        if sc > 0
    ][:3]

    candidates = list(ranked_comment_authors)
    op_flagged = op_prelim_score >= 35 and not op_info["author_ignored"]
    if op_flagged and op_info["author"] not in candidates:
        candidates.append(op_info["author"])

    now_utc = time.time()
    baselines_out: dict[str, dict[str, Any]] = {}
    rate_limited_abort = False

    for author in candidates:
        cached = db.get_author_baseline(author)
        if cached and (now_utc - cached["last_checked_utc"]) < PROFILE_CACHE_TTL_SEC:
            cached["fetch_status"] = "cached_24h"
            cached["latest_hist_utc"] = None
            baselines_out[author] = cached
            continue

        if no_profile_fetch:
            baselines_out[author] = {"fetch_status": "disabled_by_flag"}
            continue

        if mock_mode and mock_profiles is None:
            baselines_out[author] = {"fetch_status": "skipped_offline_mock"}
            continue

        if rate_limited_abort:
            baselines_out[author] = {"fetch_status": "skipped_rate_limited"}
            continue

        if mock_profiles is not None:
            payload = mock_profiles.get(author)
            err = None if payload is not None else {"message": "Not in mock_profiles."}
        else:
            payload, err = fetcher.fetch_user_comments(
                author, limit=PROFILE_COMMENTS_LIMIT
            )

        if err is not None:
            status = f"fetch_error_{err.get('code') or err.get('type', 'unknown')}"
            baselines_out[author] = {"fetch_status": status}
            warnings.append(f"Profile fetch for u/{author}: {err['message']}")
            if err.get("code") == 429:
                rate_limited_abort = True
            continue

        history = parse_user_comments_history(payload, op_info["thread_id"])
        computed = compute_baseline_from_history(history, now_utc)
        db.upsert_author_baseline(
            author=author,
            account_age_days=computed["account_age_days"],
            median_len=computed["median_len"],
            median_interval_sec=computed["median_interval_sec"],
            sample_size=computed["sample_size"],
            last_checked_utc=now_utc,
            active_hours=computed["active_hours"],
            stylometry=computed["stylometry"],
        )
        computed["fetch_status"] = "fetched_live" if mock_profiles is None else "fetched_mock"
        baselines_out[author] = computed

    return baselines_out, candidates


# ---------------------------------------------------------------------------
# Output Serialization with Token / Byte Budget Guard
# ---------------------------------------------------------------------------

def serialize_within_budget(report: dict[str, Any], max_bytes: int = MAX_OUTPUT_BYTES) -> str:
    """Serialize report to JSON strictly within max_bytes (~6-8 KB)."""
    # Try readable indented JSON first
    pretty = json.dumps(report, ensure_ascii=False, indent=2)
    if len(pretty.encode("utf-8")) <= max_bytes:
        return pretty

    # Fall back to compact JSON
    compact = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    if len(compact.encode("utf-8")) <= max_bytes:
        return compact

    # Progressively trim untrusted snippets and cluster edges while preserving structure
    trimmed = json.loads(compact)
    trimmed.setdefault("audit_meta", {})["output_trimmed_for_budget"] = True

    for op_cap, c_cap, edge_cap in [(350, 260, 4), (200, 150, 2), (120, 90, 1)]:
        op_txt = trimmed.get("op_analysis", {}).get("untrusted_content", "")
        if len(op_txt) > op_cap:
            trimmed["op_analysis"]["untrusted_content"] = op_txt[: op_cap - 3] + "..."

        for item in trimmed.get("top_anomalies", []):
            txt = item.get("untrusted_content", "")
            if len(txt) > c_cap:
                item["untrusted_content"] = txt[: c_cap - 3] + "..."

        for cl in trimmed.get("graph_clusters", []):
            if "edges" in cl and len(cl["edges"]) > edge_cap:
                cl["edges"] = cl["edges"][:edge_cap]

        candidate = json.dumps(trimmed, ensure_ascii=False, separators=(",", ":"))
        if len(candidate.encode("utf-8")) <= max_bytes:
            return candidate

    # Final fallback: drop excess anomalies/clusters until strictly under cap
    while len(json.dumps(trimmed, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > max_bytes:
        if len(trimmed.get("top_anomalies", [])) > 1:
            trimmed["top_anomalies"].pop()
        elif len(trimmed.get("graph_clusters", [])) > 1:
            trimmed["graph_clusters"].pop()
        else:
            break

    return json.dumps(trimmed, ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Main Pipeline
# ---------------------------------------------------------------------------

def resolve_local_file(path_arg: str) -> Optional[Path]:
    """Resolve a path relative to CWD first, then relative to the skill root."""
    p = Path(path_arg)
    if p.is_file():
        return p.resolve()
    alt = SKILL_DIR / path_arg
    if alt.is_file():
        return alt.resolve()
    return None


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit a Reddit thread for agentic artifacts, takeovers, and swarm coordination."
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="Reddit thread URL (omitted when using --mock).",
    )
    parser.add_argument(
        "--mock",
        "--file",
        dest="mock_path",
        default=None,
        help="Path to a local Reddit-format JSON file for offline testing or browser-saved threads.",
    )
    parser.add_argument(
        "--mock-profiles",
        dest="mock_profiles_path",
        default=None,
        help="Optional JSON map of {author: reddit_user_comments_json} for offline Class 1 testing.",
    )
    parser.add_argument(
        "--max-comments",
        type=int,
        default=50,
        help="Maximum non-ignored comments to fetch/analyze (default: 50).",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=4,
        help="Comment tree depth parameter for Reddit .json endpoint (default: 4).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Maximum anomalous comments to include in stdout report (default: 5).",
    )
    parser.add_argument(
        "--ignore-users",
        action="append",
        default=[],
        help="Comma-separated usernames to ignore (repeatable).",
    )
    parser.add_argument(
        "--no-profile-fetch",
        action="store_true",
        help="Disable stage-2 /user/{author}/comments.json fetches.",
    )
    parser.add_argument(
        "--window-sec",
        type=float,
        default=300.0,
        help="Co-occurrence time window in seconds (default: 300).",
    )
    parser.add_argument(
        "--db",
        dest="db_path",
        default=str(DEFAULT_DB_PATH),
        help=f"SQLite graph DB path (default: {DEFAULT_DB_PATH}).",
    )
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="Custom HTTP User-Agent header for Reddit requests.",
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
        "--format",
        dest="output_format",
        choices=["json", "md"],
        default="json",
        help="Output format: json (compact machine-readable, default) or md (human-readable Markdown).",
    )
    return parser


def format_report_markdown(report: dict[str, Any]) -> str:
    """Render an audit report as a compact, scannable Markdown summary for terminal use."""
    meta = report["audit_meta"]
    db = report["db_stats"]
    op = report["op_analysis"]
    anomalies = report["top_anomalies"]
    clusters = report["graph_clusters"]

    high_cnt = sum(1 for a in anomalies if a["anomaly_score"] >= 60)
    mod_cnt = sum(1 for a in anomalies if 30 <= a["anomaly_score"] < 60)
    max_score = max([op["anomaly_score"], *(a["anomaly_score"] for a in anomalies)], default=0)

    if max_score >= 60 or clusters or meta.get("watchlist_hits"):
        verdict = "HIGH-RISK ACTIVITY"
    elif max_score >= 30:
        verdict = "MIXED / NEEDS REVIEW"
    else:
        verdict = "ORGANIC"

    lines = [
        f"### Verdict: {verdict} ({high_cnt} high · {mod_cnt} moderate · {meta['comments_clean']} clean)",
        (
            f"r/{op['subreddit']} ({op['thread_id']}) · "
            f"{meta['comments_analyzed']} comments · "
            f"DB: {db['total_threads']} threads ({db['subreddit_threads']} in sub) · "
            f"Source: {meta['data_source']}"
        ),
        "",
        (
            f"- **OP:** u/{op['author']} — **{op['anomaly_score']}/100** "
            f"(C1:{op['sub_scores']['class1_takeover']} / C2:{op['sub_scores']['class2_swarm']} / "
            f"C3:{op['sub_scores']['class3_agentic']})"
            + (f" — flags: `{', '.join(op['flags'])}`" if op["flags"] else " — clean")
        ),
    ]

    if anomalies:
        lines.append("")
        lines.append("| Account | Score (C1/C2/C3) | Signals |")
        lines.append("| :--- | :---: | :--- |")
        for a in anomalies:
            sub = a["sub_scores"]
            sig = ", ".join(a["flags"]) if a["flags"] else "—"
            lines.append(
                f"| u/{a['author']} | **{a['anomaly_score']}** "
                f"({sub['class1_takeover']}/{sub['class2_swarm']}/{sub['class3_agentic']}) | `{sig}` |"
            )

    if clusters:
        lines.append("")
        lines.append("**Graph Clusters:**")
        for cl in clusters:
            dom = f" · domains: {', '.join(cl['shared_domains'])}" if cl["shared_domains"] else ""
            lines.append(
                f"- `{cl['cluster_id']}`: {', '.join('u/' + u for u in cl['authors'])} "
                f"(min delta {cl['min_time_delta_sec']}s, threads: {cl['max_distinct_threads']}{dom})"
            )
    else:
        lines.append("")
        lines.append("**Clusters / Watchlist:** None")

    if meta.get("warnings"):
        lines.append("")
        lines.append("**Notes:** " + " | ".join(meta["warnings"][:3]))

    return "\n".join(lines)


def emit_error(error_type: str, message: str, code: Optional[int] = None) -> int:
    payload: dict[str, Any] = {
        "status": "error",
        "error_type": error_type,
        "message": message,
    }
    if code is not None:
        payload["http_code"] = code
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 1


def audit_thread_payload(
    payload: Any,
    db: RedditGraphDB,
    fetcher: RateLimitedFetcher,
    ignored_authors: set[str],
    max_comments: int = 50,
    top_n: int = 5,
    window_sec: float = 300.0,
    no_profile_fetch: bool = False,
    mock_mode: bool = False,
    mock_profiles: Optional[dict[str, Any]] = None,
    extra_warnings: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Run the full 3-class audit pipeline on a parsed Reddit thread JSON payload."""
    warnings: list[str] = list(extra_warnings or [])
    op_info, comments, ignored_count = parse_reddit_thread(
        payload, ignored_authors=ignored_authors, max_comments=max(1, max_comments)
    )

    # Stage 1A: Class 3 heuristics (local, deterministic)
    op_c3, op_c3_flags = score_op_class3(op_info)
    for c in comments:
        c3_score, c3_flags, c3_features = score_comment_class3(c)
        c["class3_score"] = c3_score
        c["class3_flags"] = c3_flags
        c["features"] = c3_features

    # Persist thread, comments, and current-thread co-occurrences into SQLite
    scraped_at_iso = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
    db.upsert_thread(op_info, scraped_at_iso)
    db.upsert_comments(comments)

    current_edges = build_current_co_occurrences(
        op_info, comments, window_sec=window_sec
    )
    db.upsert_co_occurrences(current_edges)

    # Stage 1B: Class 2 Coordination Graph + Watchlist queries
    c2_scores, c2_flags, graph_clusters, graph_meta = evaluate_coordination_graph(
        db=db,
        op_info=op_info,
        comments=comments,
        current_edges=current_edges,
        window_sec=window_sec,
    )
    watchlist_map: dict[str, dict[str, Any]] = graph_meta.get("watchlist_map") or {}

    def is_benign_watched(user: str) -> bool:
        entry = watchlist_map.get(user)
        return bool(entry and entry["verdict"].lower() == "benign")

    hard_artifact_flags = {"leaked_tool_call_artifact", "prompt_injection_pattern"}

    op_c2 = c2_scores.get(op_info["author"], 0)
    op_c2_flags = c2_flags.get(op_info["author"], [])
    if is_benign_watched(op_info["author"]) and not (set(op_c3_flags) & hard_artifact_flags):
        op_c3 = int(round(op_c3 * 0.25))
    op_prelim_score = combine_class_scores(0, op_c2, op_c3)

    for c in comments:
        c["class2_score"] = c2_scores.get(c["author"], 0)
        c["class2_flags"] = c2_flags.get(c["author"], [])
        if is_benign_watched(c["author"]) and not (set(c["class3_flags"]) & hard_artifact_flags):
            c["class3_score"] = int(round(c["class3_score"] * 0.25))
        c["prelim_score"] = combine_class_scores(
            0, c["class2_score"], c["class3_score"]
        )

    # Stage 2: Class 1 Account Takeover (Top 3 authors + flagged OP, 24h cache)
    baselines_by_author, stage2_candidates = run_stage2_profile_checks(
        db=db,
        fetcher=fetcher,
        op_info=op_info,
        comments=comments,
        op_prelim_score=op_prelim_score,
        no_profile_fetch=no_profile_fetch,
        mock_mode=mock_mode,
        mock_profiles=mock_profiles,
        warnings=warnings,
    )

    # Apply Class 1 drift scoring (including lightweight stylometric drift)
    op_c1 = 0
    op_profile_drift: Optional[dict[str, Any]] = None
    if op_info["author"] in baselines_by_author:
        b = baselines_by_author[op_info["author"]]
        if b.get("sample_size") is not None and b.get("fetch_status") in (
            "fetched_live",
            "fetched_mock",
            "cached_24h",
        ):
            op_c1, op_drift = score_profile_drift(
                baseline=b,
                current_char_len=len(op_info["raw_selftext"]) + len(op_info["raw_title"]),
                current_created_utc=op_info["created_utc"],
                latest_hist_utc=b.get("latest_hist_utc"),
                current_text=op_info["raw_selftext"] or op_info["raw_title"],
            )
            op_drift["status"] = b["fetch_status"]
            op_profile_drift = op_drift
        else:
            op_profile_drift = {"status": b.get("fetch_status", "skipped")}

    op_final_score = combine_class_scores(op_c1, op_c2, op_c3)

    for c in comments:
        c1_score = 0
        drift_out: Optional[dict[str, Any]] = None
        if c["author"] in baselines_by_author:
            b = baselines_by_author[c["author"]]
            if b.get("sample_size") is not None and b.get("fetch_status") in (
                "fetched_live",
                "fetched_mock",
                "cached_24h",
            ):
                c1_score, drift_dict = score_profile_drift(
                    baseline=b,
                    current_char_len=c["char_len"],
                    current_created_utc=c["created_utc"],
                    latest_hist_utc=b.get("latest_hist_utc"),
                    current_text=c["raw_body"],
                )
                drift_dict["status"] = b["fetch_status"]
                drift_out = drift_dict
            else:
                drift_out = {"status": b.get("fetch_status", "skipped")}

        c["class1_score"] = c1_score
        c["profile_drift"] = drift_out
        c["anomaly_score"] = combine_class_scores(
            c1_score, c["class2_score"], c["class3_score"]
        )

    # Persist updated final anomaly_scores into SQLite
    db.upsert_comments(comments)
    db_stats = db.get_db_stats(op_info["subreddit"])

    # Build top anomalies (up to top_n, only comments with score > 0)
    ranked_comments = sorted(
        comments,
        key=lambda x: (
            -x["anomaly_score"],
            -x["class3_score"],
            -x["class2_score"],
            -x["char_len"],
        ),
    )
    anomalous_comments = [c for c in ranked_comments if c["anomaly_score"] > 0]
    top_anomalies: list[dict[str, Any]] = []

    for c in anomalous_comments[: max(0, top_n)]:
        all_flags = list(
            dict.fromkeys(
                c["class3_flags"]
                + c["class2_flags"]
                + (
                    c["profile_drift"].get("drift_flags", [])
                    if isinstance(c["profile_drift"], dict)
                    else []
                )
            )
        )
        has_tail_artifact = any(
            f in c["class3_flags"]
            for f in (
                "leaked_tool_call_artifact",
                "leaked_json_fragment",
                "prompt_injection_pattern",
            )
        )
        entry: dict[str, Any] = {
            "comment_id": c["comment_id"],
            "parent_id": c["parent_id"],
            "author": c["author"],
            "depth": c["depth"],
            "created_utc": c["created_utc"],
            "anomaly_score": c["anomaly_score"],
            "sub_scores": {
                "class1_takeover": c["class1_score"],
                "class2_swarm": c["class2_score"],
                "class3_agentic": c["class3_score"],
            },
            "flags": all_flags,
            "features": c["features"],
            "untrusted_content": neutralize_untrusted_text(
                c["raw_body"],
                COMMENT_CONTENT_MAX_CHARS,
                preserve_tail_artifact=has_tail_artifact,
            ),
        }
        if c["profile_drift"] is not None:
            entry["profile_drift"] = c["profile_drift"]
        top_anomalies.append(entry)

    # Wrap BOTH OP title and body inside neutralized untrusted_content (<= 600 chars)
    op_raw_combined = f"TITLE: {op_info['raw_title']}\nBODY: {op_info['raw_selftext']}"
    op_all_flags = list(
        dict.fromkeys(
            op_c3_flags
            + op_c2_flags
            + (
                op_profile_drift.get("drift_flags", [])
                if isinstance(op_profile_drift, dict)
                else []
            )
        )
    )
    op_analysis: dict[str, Any] = {
        "thread_id": op_info["thread_id"],
        "subreddit": op_info["subreddit"],
        "author": op_info["author"],
        "created_utc": op_info["created_utc"],
        "is_self": op_info["is_self"],
        "domains": op_info["domains"][:5],
        "anomaly_score": op_final_score,
        "sub_scores": {
            "class1_takeover": op_c1,
            "class2_swarm": op_c2,
            "class3_agentic": op_c3,
        },
        "flagged": op_final_score >= 35,
        "flags": op_all_flags,
        "untrusted_content": neutralize_untrusted_text(
            op_raw_combined, OP_CONTENT_MAX_CHARS
        ),
    }
    if op_profile_drift is not None:
        op_analysis["profile_drift"] = op_profile_drift

    audit_meta: dict[str, Any] = {
        "mode": "mock" if mock_mode else "live",
        "data_source": "mock" if mock_mode else fetcher.active_source,
        "auth_mode": "mock" if mock_mode else fetcher.auth_mode,
        "comments_analyzed": len(comments),
        "comments_flagged": len(anomalous_comments),
        "comments_clean": len(comments) - len(anomalous_comments),
        "ignored_filtered": ignored_count,
        "stage2_candidates": stage2_candidates,
        "power_users_flagged": sorted(graph_meta["power_users_flagged"].keys()),
        "repeating_role_patterns": graph_meta["repeating_role_patterns"],
        "watchlist_hits": graph_meta["watchlist_hits"],
        "watchlist_associations": graph_meta["watchlist_associations"],
        "warnings": warnings,
    }

    return {
        "status": "ok",
        "audit_meta": audit_meta,
        "db_stats": db_stats,
        "op_analysis": op_analysis,
        "top_anomalies": top_anomalies,
        "graph_clusters": graph_clusters,
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.mock_path and not args.url:
        return emit_error(
            "invalid_arguments",
            "Provide either a Reddit thread URL or --mock <path/to/mock_thread.json>.",
        )

    # Build ignore list
    ignored_authors = set(DEFAULT_IGNORED_AUTHORS)
    for entry in args.ignore_users:
        for item in entry.split(","):
            u = item.strip().lower()
            if u.startswith("/u/"):
                u = u[3:]
            elif u.startswith("u/"):
                u = u[2:]
            if u:
                ignored_authors.add(u)

    fetcher = RateLimitedFetcher(
        user_agent=args.user_agent,
        delay_sec=REQUEST_DELAY_SEC,
        use_oauth=not args.no_oauth,
        source=args.source,
    )
    mock_mode = bool(args.mock_path)
    mock_profiles: Optional[dict[str, Any]] = None
    fetch_warnings: list[str] = []

    # Load thread payload (offline mock OR live Reddit/Arctic Shift)
    if mock_mode:
        mock_file = resolve_local_file(args.mock_path)
        if mock_file is None:
            return emit_error(
                "mock_file_not_found",
                f"Could not find mock thread JSON at '{args.mock_path}'.",
            )
        try:
            payload = json.loads(mock_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return emit_error("mock_parse_error", f"Failed to read mock file: {exc}")

        if args.mock_profiles_path:
            mp_file = resolve_local_file(args.mock_profiles_path)
            if mp_file is None:
                return emit_error(
                    "mock_profiles_not_found",
                    f"Could not find mock profiles JSON at '{args.mock_profiles_path}'.",
                )
            try:
                mock_profiles = json.loads(mp_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                return emit_error(
                    "mock_profiles_parse_error",
                    f"Failed to parse mock profiles file: {exc}",
                )
    else:
        try:
            payload, err, fetch_warnings = fetcher.fetch_thread(
                args.url, max_comments=max(1, args.max_comments), depth=max(1, args.depth)
            )
        except ValueError as exc:
            return emit_error("invalid_url", str(exc))

        if err is not None:
            return emit_error(
                str(err.get("type", "fetch_error")),
                str(err.get("message", "Failed to fetch thread.")),
                code=err.get("code"),
            )

    db = RedditGraphDB(Path(args.db_path))
    try:
        report = audit_thread_payload(
            payload=payload,
            db=db,
            fetcher=fetcher,
            ignored_authors=ignored_authors,
            max_comments=args.max_comments,
            top_n=args.top,
            window_sec=args.window_sec,
            no_profile_fetch=args.no_profile_fetch,
            mock_mode=mock_mode,
            mock_profiles=mock_profiles,
            extra_warnings=fetch_warnings,
        )
    except ValueError as exc:
        return emit_error("parse_error", str(exc))
    finally:
        db.close()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.output_format == "md":
        print(format_report_markdown(report))
    else:
        output_json = serialize_within_budget(report, max_bytes=MAX_OUTPUT_BYTES)
        print(output_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
