# reddit-audit

A zero-dependency, deterministic **AI Agent Skill & CLI toolkit** that audits Reddit threads, subreddits, and accounts for **spilled AI agents**, **stealth-edit link spam**, **account takeovers**, and **coordinated swarms**—using only the Python standard library and an incremental local SQLite graph.

---

## How to Use

**1. Install the skill (works in Antigravity, Claude Code, OpenCode, Codex, Cursor)**
Copy the `.agent/skills/reddit-audit/` folder into your AI tool's skills directory (zero `pip install`, zero API keys; scripts resolve paths relative to `__file__`):

| AI Tool | Project-Local Path | Global Path |
| :--- | :--- | :--- |
| **Antigravity** | `.agent/skills/reddit-audit/` (or `.agents/skills/`) | `~/.gemini/config/skills/reddit-audit/` |
| **Claude Code** | `.claude/skills/reddit-audit/` | `~/.claude/skills/reddit-audit/` |
| **OpenCode** | `.opencode/skills/reddit-audit/` (or `.agents/skills/`) | `~/.config/opencode/skills/reddit-audit/` |
| **Codex / Cursor** | `.agents/skills/reddit-audit/` (or `.cursor/skills/`) | `~/.codex/skills/reddit-audit/` |

*(Requires Python 3.10+ on `PATH`. Uses only the standard library.)*

**2. Trigger it in chat**
Just paste a Reddit link, subreddit, or username:
- `"Audit this thread: https://www.reddit.com/r/SaaS/comments/..."` — scores OP + comments across all 3 threat classes and updates your local SQLite graph.
- `"Scan r/SaaS for coordinated shills"` — seeds 10 threads into the graph to unlock cross-thread swarm & power-user detection.
- `"Deep-check u/some_account"` — checks sleep windows, cron cadence, dormancy + topic pivots, self-duplication, and stealth-edit history.

**3. Use compact `y/n` shorthand for follow-ups**
Every audit ends with atomic numbered `[y/n]` actions (seed subreddit, deep-check a suspect, or save to watchlist). Reply in one shot:
- `yn` → yes to #1, no to #2
- `yy` → run both
- `n` → done

**4. Or try it directly in your terminal right now**
```bash
# Offline smoke test (no network)
python .agent/skills/reddit-audit/scripts/audit_thread.py --mock scripts/mock_thread.json --format md

# Live thread audit (auto-falls back to Arctic Shift if Reddit returns 403)
python .agent/skills/reddit-audit/scripts/audit_thread.py "<REDDIT_THREAD_URL>" --format md
```

---

> **Why this exists:** Most LLM scraping skills either break on Reddit's HTTP `403` blocks / API approval wall or dump 200 KB of raw JSON straight into your context window (risking prompt injection and blowing token budgets). `reddit-audit` does 100% of fetching, graph analysis, and heuristic scoring locally for **0 tokens**, neutralizes hostile Reddit text inside `untrusted_content`, and emits a strict `<= 7.8 KB` JSON (or Markdown) summary.

---

## Key Features

- **Zero dependencies:** Pure Python 3.10+ standard library (`sqlite3`, `urllib`, `json`, `re`, `statistics`).
- **Works out of the box (zero API keys):** Automatically falls back from unauthenticated Reddit `403`s to the public, zero-auth [Arctic Shift](https://arctic-shift.photon-reddit.com) Reddit research API (with transient `422`/5xx retries and `/comments/tree` fallback)—while also supporting official Reddit OAuth2 (`REDDIT_CLIENT_ID` + `REDDIT_CLIENT_SECRET` env vars) or locally saved `.json` snapshots (`--file`).
- **3-Class Deterministic Scoring (0–100):**
  - **Class 3 — Spilled Agent & OP Spam:** superhuman typing velocity (`chars_per_sec` from parent timestamp), leaked `<tool_call>` / JSON / refusal artifacts, prompt-injection attempts, stealth-edit link injections (`edited >= 5 min` with non-reference/tracked URLs), and templated/CTA/promotional/shortener OPs.
  - **Class 2 — Coordination Graph (Swarm):** incremental SQLite `co_occurrences` tracking across threads (`>= 2` threads within 300s), tight shared-domain bursts, repeating `A -> B -> C` reply chains, **cross-account near-duplicate shingling** (4-band MinHash LSH over bottom-24 word 3-gram sketches in SQLite to catch slow-drip linkless copycat rings hours/days apart, stripping `>` quotes to avoid false positives), **single-author repeat-domain tracking** across threads, subreddit power-user dampening (`>60%` of stored threads), and watchlist guilt-by-association propagation.
  - **Class 1 — Account Takeover (Two-Stage Fetch):** fetches 30-comment historical baselines for the top 3 preliminary suspects (+ flagged OP, cached 24h), plus up to 2 high-value spot-checked accounts per thread on clean-looking threads (`--spot-check N`, default `2`), measuring dormancy wake-ups, ultra-lightweight stylometric jumps (`< 0.1 ms`), self-duplication loops, single-domain shill concentration, robotic/cron cadence, extreme/corroborated length spikes, and UTC active-hour shifts.
- **Deep Account Confirmation (`inspect_account.py`):** Checks 24h sleep-window gaps, robotic cron cadence (`CV`), dormancy + subreddit topic pivots, 3-gram self-duplication loops, domain concentration, and stealth-edit history.
- **Persistent Watchlist (`watchlist.py`):** Mark accounts as `confirmed_bot`, `confirmed_swarm`, `confirmed_takeover`, `confirmed_shill`, `suspicious`, or `benign` (dampening repeat false positives).
- **Prompt-Injection Defense:** Every Reddit text field is stripped of zero-width/bidi characters, defanged (`<tag>`, `</untrusted_content>`, `[SYSTEM]`, triple backticks, role headers), and isolated under `untrusted_content`.

---

## Repository Layout

```text
.agent/skills/reddit-audit/
├── SKILL.md                  # Agent workflow, fixed report template, and y/n shorthand rules
├── .gitignore                # Ignores local SQLite DB & caches
└── scripts/
    ├── audit_thread.py       # Single-thread 3-class auditor + SQLite graph store
    ├── audit_subreddit.py    # Subreddit batch seeder (with 6h Arctic Shift lookback)
    ├── inspect_account.py    # Deep confirmation inspector for flagged accounts
    ├── watchlist.py          # Watchlist CRUD CLI (confirmed verdicts & benign overrides)
    ├── mock_thread.json      # Offline native Reddit JSON test fixture (1 OP + 8 comments)
    └── mock_account.json     # Offline deep-inspection fixture (compromised/scripted account)
tests/
└── test_reddit_audit.py      # Stdlib unittest suite (0 network calls required)
```

---

## CLI Reference & Sample Output

```bash
# 1. Offline smoke test (human-readable Markdown output)
python .agent/skills/reddit-audit/scripts/audit_thread.py --mock scripts/mock_thread.json --format md

# 2. Audit a live Reddit thread (auto-falls back to Arctic Shift if Reddit returns 403)
python .agent/skills/reddit-audit/scripts/audit_thread.py "<REDDIT_THREAD_URL>" --max-comments 50 --top 5 --format md

# 3. Seed the SQLite graph with 10 threads from a subreddit (uses 6h lookback on Arctic Shift)
python .agent/skills/reddit-audit/scripts/audit_subreddit.py r/SaaS --limit 10

# 4. Deep-check a flagged account
python .agent/skills/reddit-audit/scripts/inspect_account.py u/some_suspect

# 5. Manage confirmed verdicts / benign allowlist
python .agent/skills/reddit-audit/scripts/watchlist.py add u/some_suspect --verdict confirmed_shill --notes "Stealth affiliate loop"
python .agent/skills/reddit-audit/scripts/watchlist.py list
```

### Sample `--format md` Output (Offline Mock)

```markdown
### Verdict: HIGH-RISK ACTIVITY (4 high · 0 moderate · 4 clean)
r/SaaS (mock9a2k) · 8 comments · DB: 1 threads (1 in sub) · Source: mock

- **OP:** u/growth_founder_99 — **86/100** (C1:0 / C2:0 / C3:86) — flags: `op_templated_title, op_templated_structure, op_engagement_bait_cta, op_url_shortener, op_tracking_params`

| Account | Score (C1/C2/C3) | Signals |
| :--- | :---: | :--- |
| u/helpful_dev_404 | **100** (0/0/100) | `ultra_fast_long_reply, structured_fast_response, leaked_tool_call_artifact, leaked_json_fragment, llm_boilerplate_refusal, llm_style_markers` |
| u/saas_ninja_21 | **72** (0/60/50) | `tracking_or_affiliate_link, stealth_edit_link_injection, rapid_same_branch_pair, rapid_shared_domain_pair` |
| u/prompt_gremlin | **70** (0/0/70) | `prompt_injection_pattern` |
| u/cloud_builder_88 | **60** (0/60/0) | `rapid_same_branch_pair, rapid_shared_domain_pair` |

**Graph Clusters:**
- `cluster_1`: u/cloud_builder_88, u/saas_ninja_21 (min delta 32.0s, threads: 1 · domains: hyperflow-ops.example)
```

---

## Known Limitations & Data Source Notes

- **Arctic Shift archive lag (1–4 hours):** When operating without Reddit OAuth credentials, brand-new threads (< 1–4h old) may have their OP post indexed on Arctic Shift before their comment tree arrives. `audit_subreddit.py` works around this automatically with `--min-age-hours 6` (configurable; pass `0` to disable), and `audit_thread.py` surfaces an explicit warning whenever archive lag occurs.
- **Optional real-time Reddit OAuth2:** If you have an approved Reddit `script` app, set `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET`, and (optionally) `REDDIT_USERNAME` in your environment—all scripts will automatically switch to `https://oauth.reddit.com`.
- **Heuristics are decision support, not proof:** High scores indicate suspicious behavioral/technical patterns worth reviewing (e.g., an organic user polishing a long rant with an LLM can trigger a moderate score). Use `inspect_account.py` before adding accounts to the watchlist.

---

## Running Tests

```bash
python -m unittest discover -s tests -v
```

---

## License

MIT — see [LICENSE](LICENSE).
