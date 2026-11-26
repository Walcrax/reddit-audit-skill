"""Offline stdlib unittest suite for the reddit-audit skill."""
from __future__ import annotations

import base64
import importlib.util
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / ".agent" / "skills" / "reddit-audit" / "scripts"
AUDIT_THREAD = SCRIPTS_DIR / "audit_thread.py"
INSPECT_ACCOUNT = SCRIPTS_DIR / "inspect_account.py"
AUDIT_SUBREDDIT = SCRIPTS_DIR / "audit_subreddit.py"
WATCHLIST = SCRIPTS_DIR / "watchlist.py"
MOCK_THREAD = SCRIPTS_DIR / "mock_thread.json"
MOCK_ACCOUNT = SCRIPTS_DIR / "mock_account.json"

_spec = importlib.util.spec_from_file_location("audit_thread", AUDIT_THREAD)
core = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader is not None
_spec.loader.exec_module(core)


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def run_cli(script: Path, *args: str, parse_json: bool = True):
    proc = subprocess.run(
        [sys.executable, str(script), *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if proc.stderr:
        raise AssertionError(f"Unexpected stderr from {script.name}: {proc.stderr}")
    byte_len = len(proc.stdout.encode("utf-8"))
    if parse_json:
        return proc.returncode, json.loads(proc.stdout), byte_len
    return proc.returncode, proc.stdout, byte_len


def make_thread(tid: str, sub: str, op: str, t0: float, comments: list[dict]) -> list:
    return [
        {
            "kind": "Listing",
            "data": {
                "children": [
                    {
                        "kind": "t3",
                        "data": {
                            "id": tid,
                            "name": f"t3_{tid}",
                            "subreddit": sub,
                            "author": op,
                            "title": f"Thread {tid}",
                            "selftext": "Normal discussion.",
                            "created_utc": t0,
                            "edited": False,
                            "is_self": True,
                            "url": f"https://www.reddit.com/r/{sub}/comments/{tid}/",
                        },
                    }
                ]
            },
        },
        {"kind": "Listing", "data": {"children": comments}},
    ]


def cnode(
    cid: str,
    tid: str,
    parent: str,
    author: str,
    body: str,
    ts: float,
    edited=False,
    replies=None,
) -> dict:
    rep_obj = "" if not replies else {"kind": "Listing", "data": {"children": replies}}
    return {
        "kind": "t1",
        "data": {
            "id": cid,
            "name": f"t1_{cid}",
            "link_id": f"t3_{tid}",
            "parent_id": parent,
            "subreddit": "testsub",
            "author": author,
            "body": body,
            "created_utc": ts,
            "edited": edited,
            "replies": rep_obj,
        },
    }


class TestRedditAuditSkill(unittest.TestCase):
    def test_url_normalization_and_host_validation(self):
        self.assertEqual(
            core.normalize_thread_url("https://old.reddit.com/r/SaaS/comments/abc123/my_post/?utm_source=x"),
            "https://www.reddit.com/r/SaaS/comments/abc123/my_post.json?limit=50&depth=4",
        )
        self.assertEqual(
            core.normalize_thread_url("https://redd.it/abc123", max_comments=30, depth=3),
            "https://www.reddit.com/comments/abc123.json?limit=30&depth=3",
        )
        with self.assertRaises(ValueError):
            core.normalize_thread_url("https://example.com/r/SaaS/comments/abc123")

    def test_http_429_403_and_rate_limit(self):
        fetcher = core.RateLimitedFetcher("test-agent", delay_sec=0.12, use_oauth=False, source="reddit")
        for code, expected_type in [(429, "rate_limited"), (403, "forbidden")]:
            err = urllib.error.HTTPError("https://www.reddit.com/test.json", code, "Err", {"Retry-After": "12"}, None)
            with mock.patch("urllib.request.urlopen", side_effect=err):
                t0 = time.monotonic()
                data, res_err = fetcher.fetch_json("https://www.reddit.com/test.json")
                self.assertIsNone(data)
                self.assertEqual(res_err["code"], code)
                self.assertEqual(res_err["type"], expected_type)
                if code == 403:
                    self.assertGreaterEqual(time.monotonic() - t0, 0.08)

    def test_oauth2_rewrite_token_refresh_and_secret_safety(self):
        self.assertEqual(
            core.rewrite_to_oauth_url("https://www.reddit.com/r/Polska/comments/abc/slug.json?limit=50&depth=4"),
            "https://oauth.reddit.com/r/Polska/comments/abc/slug?limit=50&depth=4",
        )
        calls = []

        def fake_urlopen(req, timeout=20.0):
            calls.append((req.full_url, dict(req.header_items())))
            if req.full_url == core.REDDIT_OAUTH_TOKEN_URL:
                n = len([c for c in calls if c[0] == core.REDDIT_OAUTH_TOKEN_URL])
                return FakeResp(json.dumps({"access_token": f"tok_{n}", "expires_in": 3600}).encode())
            api_calls = [c for c in calls if c[0] != core.REDDIT_OAUTH_TOKEN_URL]
            if len(api_calls) == 2:
                raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)
            return FakeResp(json.dumps({"ok": True}).encode())

        fetcher = core.RateLimitedFetcher(
            user_agent="windows:test:1.0", delay_sec=0.0, use_oauth=True, client_id="cid", client_secret="sec"
        )
        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            d1, e1 = fetcher.fetch_json("https://www.reddit.com/r/Polska/comments/abc.json")
            d2, e2 = fetcher.fetch_json("https://www.reddit.com/user/alice/comments.json")
        self.assertIsNone(e1)
        self.assertIsNone(e2)
        self.assertEqual(d1, {"ok": True})
        self.assertEqual(d2, {"ok": True})
        expected_basic = "Basic " + base64.b64encode(b"cid:sec").decode("ascii")
        self.assertEqual(calls[0][1]["Authorization"], expected_basic)
        self.assertEqual(calls[-1][1]["Authorization"], "Bearer tok_2")

        # Auth failure must never echo the secret
        secret = "TOP_SECRET_DO_NOT_LEAK"
        bad_fetcher = core.RateLimitedFetcher(delay_sec=0.0, use_oauth=True, client_id="bad", client_secret=secret)
        err401 = urllib.error.HTTPError(core.REDDIT_OAUTH_TOKEN_URL, 401, "Unauthorized", {}, None)
        with mock.patch("urllib.request.urlopen", side_effect=err401):
            _, err_obj = bad_fetcher.fetch_json("https://www.reddit.com/r/Polska/comments/abc.json")
        self.assertNotIn(secret, json.dumps(err_obj))

    def test_arctic_shift_lookback_and_tree_reconstruction(self):
        seen_urls = []

        def fake_fetch(url):
            seen_urls.append(url)
            return {"data": [{"id": "p1", "subreddit": "SaaS", "num_comments": 5}]}, None

        fetcher = core.RateLimitedFetcher(delay_sec=0.0, use_oauth=False, source="arctic-shift")
        with mock.patch.object(fetcher, "fetch_json", side_effect=fake_fetch):
            posts, err, notes = fetcher.fetch_subreddit_posts("SaaS", limit=5, min_age_hours=6.0)
        self.assertIsNone(err)
        self.assertEqual(len(posts), 1)
        self.assertIn("before=", seen_urls[0])
        self.assertTrue(any("6h old" in n for n in notes))

        payload = core.arctic_shift_build_thread_payload(
            {"id": "t1", "subreddit": "SaaS", "author": "op", "title": "Hi", "selftext": "", "created_utc": 100.0},
            [
                {"id": "c1", "parent_id": "t3_t1", "author": "u1", "body": "parent", "created_utc": 120.0},
                {"id": "c2", "parent_id": "t1_c1", "author": "u2", "body": "child", "created_utc": 135.0},
            ],
        )
        _, comments, _ = core.parse_reddit_thread(payload, set(), max_comments=10)
        self.assertEqual(len(comments), 2)
        c2 = next(c for c in comments if c["comment_id"] == "c2")
        self.assertEqual(c2["latency_sec"], 15.0)
        self.assertEqual(c2["depth"], 1)

    def test_reference_domain_stealth_edit_exemption(self):
        # Benign Wikipedia/YouTube citation added on late edit -> NOT stealth-edit spam
        self.assertTrue(core.is_reference_domain("en.wikipedia.org"))
        self.assertTrue(core.is_reference_domain("youtu.be"))
        self.assertFalse(core.has_suspicious_edit_link(["en.wikipedia.org", "youtu.be"], False, False, False))
        # Tracked YouTube URL or non-reference promotional domain -> flagged
        self.assertTrue(core.has_suspicious_edit_link(["youtu.be"], False, True, False))
        self.assertTrue(core.has_suspicious_edit_link(["hyperflow-ops.example"], False, False, False))

    def test_mock_thread_json_and_markdown_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "g.db"
            rc, out, byte_len = run_cli(AUDIT_THREAD, "--mock", str(MOCK_THREAD), "--db", str(db))
            self.assertEqual(rc, 0)
            self.assertLessEqual(byte_len, 7800)
            self.assertEqual(out["audit_meta"]["comments_flagged"], 4)
            self.assertEqual(out["audit_meta"]["comments_clean"], 4)
            swm = next(a for a in out["top_anomalies"] if a["author"] == "saas_ninja_21")
            self.assertIn("stealth_edit_link_injection", swm["flags"])
            inj = next(a for a in out["top_anomalies"] if a["author"] == "prompt_gremlin")
            self.assertNotIn("<system>", inj["untrusted_content"])
            self.assertNotIn("</untrusted_content>", inj["untrusted_content"])

            rc_md, md_out, _ = run_cli(
                AUDIT_THREAD, "--mock", str(MOCK_THREAD), "--db", str(db), "--format", "md", parse_json=False
            )
            self.assertEqual(rc_md, 0)
            self.assertIn("### Verdict: HIGH-RISK ACTIVITY", md_out)
            self.assertIn("u/helpful_dev_404", md_out)

    def test_cross_thread_swarm_power_users_and_deleted_parent_latency(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db = tmp_path / "swarm.db"
            for idx in range(1, 4):
                ts = 1795400000.0 + idx * 10000
                th = make_thread(
                    f"th0{idx}", "SubAlpha", f"op{idx}", ts,
                    [
                        cnode(f"am{idx}", f"th0{idx}", f"t3_th0{idx}", "AutoModerator", "Rules", ts + 2),
                        cnode(
                            f"del{idx}", f"th0{idx}", f"t3_th0{idx}", "[deleted]", "[deleted]", ts + 100,
                            replies=[
                                cnode(
                                    f"sa{idx}", f"th0{idx}", f"t1_del{idx}", "swarm_a", "Point A", ts + 120,
                                    replies=[
                                        cnode(
                                            f"sb{idx}", f"th0{idx}", f"t1_sa{idx}", "swarm_b", "Point B", ts + 150,
                                            replies=[
                                                cnode(f"sc{idx}", f"th0{idx}", f"t1_sb{idx}", "swarm_c", "Point C", ts + 180)
                                            ],
                                        )
                                    ],
                                )
                            ],
                        ),
                        cnode(f"reg{idx}", f"th0{idx}", f"t3_th0{idx}", "sub_regular", "Hello", ts + 140),
                    ],
                )
                pf = tmp_path / f"t{idx}.json"
                pf.write_text(json.dumps(th), encoding="utf-8")
                rc, out, _ = run_cli(AUDIT_THREAD, "--mock", str(pf), "--db", str(db))
                self.assertEqual(rc, 0)

            self.assertIn("sub_regular", out["audit_meta"]["power_users_flagged"])
            patterns = [p["pattern"] for p in out["audit_meta"]["repeating_role_patterns"]]
            self.assertIn("swarm_a -> swarm_b -> swarm_c", patterns)

            conn = sqlite3.connect(db)
            lat = conn.execute("SELECT latency_sec FROM comments WHERE comment_id='sa1'").fetchone()[0]
            conn.close()
            self.assertEqual(lat, 20.0)

    def test_stage2_stylometry_drift_and_24h_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db = tmp_path / "drift.db"
            base_old = 1795460834.0 - 120 * 86400
            day_start = base_old - (base_old % 86400) + 3 * 3600
            hist = [
                {
                    "kind": "t1",
                    "data": {
                        "link_id": f"t3_old{i}",
                        "body": "lol yeah totally agree man",
                        "created_utc": day_start - i * 86400,
                    },
                }
                for i in range(8)
            ]
            mp = tmp_path / "mp.json"
            mp.write_text(
                json.dumps({"helpful_dev_404": {"kind": "Listing", "data": {"children": hist}}}),
                encoding="utf-8",
            )
            rc1, out1, _ = run_cli(
                AUDIT_THREAD, "--mock", str(MOCK_THREAD), "--mock-profiles", str(mp), "--db", str(db)
            )
            self.assertEqual(rc1, 0)
            bot = next(a for a in out1["top_anomalies"] if a["author"] == "helpful_dev_404")
            flags = set(bot["profile_drift"]["drift_flags"])
            self.assertTrue(
                {"length_drift_spike", "active_hours_shift_strong", "stylometric_formality_jump", "dormant_account_reactivation"}.issubset(flags),
                flags,
            )

            # Second run reuses 24h cache
            rc2, out2, _ = run_cli(AUDIT_THREAD, "--mock", str(MOCK_THREAD), "--db", str(db))
            self.assertEqual(rc2, 0)
            bot2 = next(a for a in out2["top_anomalies"] if a["author"] == "helpful_dev_404")
            self.assertEqual(bot2["profile_drift"]["status"], "cached_24h")

    def test_watchlist_propagation_and_benign_dampening(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "wl.db"
            run_cli(AUDIT_THREAD, "--mock", str(MOCK_THREAD), "--db", str(db))
            rc_a, _, _ = run_cli(
                WATCHLIST, "--db", str(db), "add", "u/saas_ninja_21",
                "--verdict", "confirmed_shill", "--confidence", "95",
            )
            rc_b, _, _ = run_cli(
                WATCHLIST, "--db", str(db), "add", "growth_founder_99", "--verdict", "benign"
            )
            self.assertEqual(rc_a, 0)
            self.assertEqual(rc_b, 0)

            rc2, out2, _ = run_cli(AUDIT_THREAD, "--mock", str(MOCK_THREAD), "--db", str(db))
            self.assertEqual(rc2, 0)
            cb = next(a for a in out2["top_anomalies"] if a["author"] == "cloud_builder_88")
            self.assertIn("cooccurs_with_watchlisted", cb["flags"])
            self.assertIn("watchlisted_benign", out2["op_analysis"]["flags"])
            self.assertLess(out2["op_analysis"]["anomaly_score"], 35)

    def test_inspect_account_and_audit_subreddit_mocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db = tmp_path / "full.db"
            run_cli(AUDIT_THREAD, "--mock", str(MOCK_THREAD), "--db", str(db))

            rc, out, b = run_cli(INSPECT_ACCOUNT, "--mock", str(MOCK_ACCOUNT), "--db", str(db))
            self.assertEqual(rc, 0)
            self.assertLessEqual(b, 7800)
            self.assertEqual(out["scripted_likelihood_score"], 100)
            self.assertTrue(
                {
                    "robotic_fixed_cadence",
                    "cron_clock_alignment",
                    "dormancy_then_subreddit_pivot",
                    "historical_style_takeover_shift",
                    "template_or_copy_paste_loop",
                    "single_domain_shill_concentration",
                    "repeated_stealth_edit_links",
                }.issubset(set(out["flags"]))
            )

            batch = [
                make_thread(
                    f"b{i}", "SaaS", f"op_{i}", 1795400000.0 + i * 9000,
                    [
                        cnode(f"r{i}", f"b{i}", f"t3_b{i}", "loyal_reg", "Nice", 1795400050.0 + i * 9000),
                        cnode(
                            f"a{i}", f"b{i}", f"t3_b{i}", "shill_1",
                            "Try https://promo.example/x?ref=1", 1795400100.0 + i * 9000,
                            edited=1795400700.0 + i * 9000,
                            replies=[
                                cnode(f"c{i}", f"b{i}", f"t1_a{i}", "shill_2", "https://promo.example/y", 1795400130.0 + i * 9000)
                            ],
                        ),
                    ],
                )
                for i in range(1, 4)
            ]
            bf = tmp_path / "batch.json"
            bf.write_text(json.dumps(batch), encoding="utf-8")
            rc_s, out_s, b_s = run_cli(AUDIT_SUBREDDIT, "--mock", str(bf), "--db", str(tmp_path / "sub.db"))
            self.assertEqual(rc_s, 0)
            self.assertLessEqual(b_s, 7800)
            self.assertEqual(out_s["threads_scanned"], 3)
            self.assertIn("loyal_reg", out_s["power_users_flagged"])
            self.assertIn("shill_1", out_s["recommended_deep_checks"])

    def test_cross_account_near_duplicate_shingling_and_quote_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db = tmp_path / "shingle.db"

            # Thread 1 at T0: slow-drip linkless pitch + human quoting OP
            t0 = 1795400000.0
            quoted_block = (
                "> Over the past month we migrated our entire ops stack across twelve "
                "automation platforms to measure cold start latency and webhook retries under load."
            )
            th1 = make_thread(
                "sh_t1", "SaaS", "op_one", t0,
                [
                    cnode(
                        "d1", "sh_t1", "t3_sh_t1", "drip_bot_alpha",
                        "We switched our internal team over to AcmeFlow last quarter after getting "
                        "burned by unpredictable per step webhook billing and silent retry storms "
                        "and honestly our engineering ops spend dropped in half overnight.",
                        t0 + 600,
                    ),
                    cnode(
                        "q1", "sh_t1", "t3_sh_t1", "human_reader_1",
                        f"{quoted_block}\n\nYeah totally agree, cold starts are rough.",
                        t0 + 900,
                    ),
                    cnode(
                        "s1", "sh_t1", "t3_sh_t1", "human_short_1",
                        "Thanks for sharing this, super helpful!",
                        t0 + 1200,
                    ),
                ],
            )
            p1 = tmp_path / "sh_t1.json"
            p1.write_text(json.dumps(th1), encoding="utf-8")
            rc1, out1, _ = run_cli(AUDIT_THREAD, "--mock", str(p1), "--db", str(db))
            self.assertEqual(rc1, 0)
            self.assertGreaterEqual(out1["db_stats"]["indexed_shingles"], 1)

            # Thread 2 SIX HOURS LATER (21,600s >> 300s window), NO links, slightly paraphrased copycat
            t2 = t0 + 21600.0
            th2 = make_thread(
                "sh_t2", "Entrepreneur", "op_two", t2,
                [
                    cnode(
                        "d2", "sh_t2", "t3_sh_t2", "drip_bot_beta",
                        "We switched our internal team over to AcmeFlow last month after getting "
                        "burned by unpredictable per step webhook billing and silent retry storms "
                        "and honestly our engineering ops spend dropped in half almost overnight.",
                        t2 + 700,
                    ),
                    cnode(
                        "q2", "sh_t2", "t3_sh_t2", "human_reader_2",
                        f"{quoted_block}\n\nInteresting benchmark, did you test dead letter queues?",
                        t2 + 1000,
                    ),
                    cnode(
                        "s2", "sh_t2", "t3_sh_t2", "human_short_2",
                        "Thanks for sharing this, super helpful!",
                        t2 + 1300,
                    ),
                ],
            )
            p2 = tmp_path / "sh_t2.json"
            p2.write_text(json.dumps(th2), encoding="utf-8")
            rc2, out2, b2 = run_cli(AUDIT_THREAD, "--mock", str(p2), "--db", str(db))
            self.assertEqual(rc2, 0)
            self.assertLessEqual(b2, 7800)

            # drip_bot_beta must be flagged across threads (6h apart, zero links!)
            flagged_authors = {a["author"]: a for a in out2["top_anomalies"]}
            self.assertIn("drip_bot_beta", flagged_authors)
            self.assertNotIn("human_reader_2", flagged_authors)
            self.assertNotIn("human_short_2", flagged_authors)

            beta = flagged_authors["drip_bot_beta"]
            self.assertGreaterEqual(beta["sub_scores"]["class2_swarm"], 54)
            self.assertTrue(
                "cross_account_copycat_shingle" in beta["flags"]
                or "cross_account_near_duplicate" in beta["flags"],
                beta["flags"],
            )
            self.assertIn("cross_thread_shingle_match", beta["flags"])
            self.assertTrue(len(out2["audit_meta"]["near_duplicate_links"]) >= 1)
            self.assertTrue(
                any(
                    set(cl["authors"]) == {"drip_bot_alpha", "drip_bot_beta"}
                    for cl in out2["graph_clusters"]
                ),
                out2["graph_clusters"],
            )

            # Deep account inspection on drip_bot_beta must surface cross_account_duplicate_peers
            acct_bundle = {
                "about": {"kind": "t2", "data": {"name": "drip_bot_beta", "created_utc": t0 - 86400 * 90}},
                "comments": {"kind": "Listing", "data": {"children": []}},
                "submitted": {"kind": "Listing", "data": {"children": []}},
            }
            acct_file = tmp_path / "drip_beta_acct.json"
            acct_file.write_text(json.dumps(acct_bundle), encoding="utf-8")
            rc_a, out_a, _ = run_cli(INSPECT_ACCOUNT, "--mock", str(acct_file), "--db", str(db))
            self.assertEqual(rc_a, 0)
            self.assertIn("cross_account_near_duplicate", out_a["flags"])
            peers = [p["peer"] for p in out_a["graph_context"]["cross_account_duplicate_peers"]]
            self.assertIn("drip_bot_alpha", peers)

    def test_stage2_spot_check_on_clean_thread(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db = tmp_path / "spot.db"
            t0 = 1795460834.0
            long_polished = (
                "This is a carefully structured reflection on the broader trade-offs — "
                "looking closely at reliability, **operational overhead**, and team velocity across "
                "several quarters of real production usage. When teams underestimate maintenance "
                "costs early on, the hidden tax compounds quietly until every minor release feels "
                "riskier than it should be, even when individual benchmarks look great on paper."
            )
            long_benign = (
                "From a completely different angle, gardening in raised cedar beds during late "
                "autumn requires balancing compost moisture, mulching depth, and drainage layers "
                "before the first hard frost arrives. Neighbors often swap heirloom garlic cloves "
                "and cover crop seeds right after harvest because perennial herbs establish stronger "
                "root networks through mild winter weeks when soil temperatures stay steady."
            )
            th = make_thread(
                "spot1",
                "testsub",
                "plain_op",
                t0,
                [
                    cnode("c1", "spot1", "t3_spot1", "sleeper_ai", long_polished, t0 + 1800),
                    cnode("c2", "spot1", "t3_spot1", "casual_user_1", "nice post", t0 + 2000),
                    cnode("c3", "spot1", "t3_spot1", "benign_long", long_benign, t0 + 2200),
                ],
            )
            tf = tmp_path / "thread.json"
            tf.write_text(json.dumps(th), encoding="utf-8")

            base_old = t0 - 120 * 86400
            day_start = base_old - (base_old % 86400) + 3 * 3600
            hist_sleeper = [
                {
                    "kind": "t1",
                    "data": {
                        "link_id": f"t3_old{i}",
                        "body": "lol yeah totally agree man",
                        "created_utc": day_start - i * 86400,
                    },
                }
                for i in range(8)
            ]
            hist_casual = [
                {
                    "kind": "t1",
                    "data": {
                        "link_id": f"t3_c_old{i}",
                        "body": "nice post lol",
                        "created_utc": t0 - (i + 1) * 3600,
                    },
                }
                for i in range(6)
            ]
            mp = tmp_path / "mp.json"
            mp.write_text(
                json.dumps(
                    {
                        "sleeper_ai": {"kind": "Listing", "data": {"children": hist_sleeper}},
                        "casual_user_1": {"kind": "Listing", "data": {"children": hist_casual}},
                        "benign_long": {"kind": "Listing", "data": {"children": hist_sleeper}},
                    }
                ),
                encoding="utf-8",
            )

            # Mark benign_long as benign on watchlist before running
            rc_w, _, _ = run_cli(WATCHLIST, "--db", str(db), "add", "benign_long", "--verdict", "benign")
            self.assertEqual(rc_w, 0)

            # 1. Default --spot-check 2 catches sleeper_ai and skips benign_long
            rc1, out1, _ = run_cli(
                AUDIT_THREAD, "--mock", str(tf), "--mock-profiles", str(mp), "--db", str(db)
            )
            self.assertEqual(rc1, 0)
            self.assertIn("sleeper_ai", out1["audit_meta"]["stage2_spot_checked"])
            self.assertNotIn("benign_long", out1["audit_meta"]["stage2_spot_checked"])
            sleeper = next(a for a in out1["top_anomalies"] if a["author"] == "sleeper_ai")
            self.assertGreater(sleeper["sub_scores"]["class1_takeover"], 0)
            self.assertEqual(sleeper["sub_scores"]["class2_swarm"], 0)
            self.assertEqual(sleeper["sub_scores"]["class3_agentic"], 0)
            self.assertTrue(
                {
                    "length_drift_spike",
                    "dormant_account_reactivation",
                    "stylometric_formality_jump",
                }.issubset(set(sleeper["flags"])),
                sleeper["flags"],
            )

            # 2. --spot-check 0 disables spot-checking on fresh DB
            db0 = tmp_path / "spot0.db"
            rc2, out2, _ = run_cli(
                AUDIT_THREAD, "--mock", str(tf), "--mock-profiles", str(mp), "--spot-check", "0", "--db", str(db0)
            )
            self.assertEqual(rc2, 0)
            self.assertEqual(out2["audit_meta"]["stage2_candidates"], [])
            self.assertEqual(out2["audit_meta"]["stage2_spot_checked"], [])
            self.assertEqual(out2["audit_meta"]["comments_flagged"], 0)

            # 3. --no-profile-fetch disables spot-checking on fresh DB
            db_nopf = tmp_path / "spot_nopf.db"
            rc3, out3, _ = run_cli(
                AUDIT_THREAD, "--mock", str(tf), "--mock-profiles", str(mp), "--no-profile-fetch", "--db", str(db_nopf)
            )
            self.assertEqual(rc3, 0)
            self.assertEqual(out3["audit_meta"]["stage2_spot_checked"], [])
            self.assertEqual(out3["audit_meta"]["comments_flagged"], 0)

    def test_class1_noise_reduction_and_op_promo_signals(self):
        # 1. Verbose author posting a short reply must NOT trigger length_drift_drop
        ts_base = 1795460834.0
        cur_hr = core.utc_hour_from_ts(ts_base)
        baseline_verbose = {
            "sample_size": 10,
            "median_len": 800.0,
            "active_hours": {cur_hr: 5, (cur_hr + 4) % 24: 5},
            "stylometry": {"avg_sentence_words": 14.0, "casual_rate": 0.1, "markdown_rate": 0.0, "em_dash_per_1k": 0.0},
        }
        sc_short, dr_short = core.score_profile_drift(
            baseline_verbose, current_char_len=7, current_created_utc=ts_base, current_text="Thanks!"
        )
        self.assertEqual(sc_short, 0)
        self.assertEqual(dr_short["drift_flags"], [])

        # 2. Small sample_size (4) or 4h gap on n=15 must NOT fire active_hours_shift_*
        sc_small_n, dr_small_n = core.score_profile_drift(
            {"sample_size": 4, "median_len": 100.0, "active_hours": {(cur_hr + 8) % 24: 4}, "stylometry": {}},
            current_char_len=120,
            current_created_utc=ts_base,
            current_text="normal reply here",
        )
        self.assertEqual(sc_small_n, 0)
        self.assertEqual(dr_small_n["drift_flags"], [])

        sc_4h_gap, dr_4h_gap = core.score_profile_drift(
            {"sample_size": 15, "median_len": 100.0, "active_hours": {(cur_hr + 4) % 24: 15}, "stylometry": {}},
            current_char_len=250,
            current_created_utc=ts_base,
            current_text="A normal moderately longer human reply in a discussion.",
        )
        self.assertEqual(sc_4h_gap, 0)
        self.assertEqual(dr_4h_gap["drift_flags"], [])

        # Uncorroborated 6h active-hours gap stays green (< 30)
        sc_6h_uncorr, dr_6h_uncorr = core.score_profile_drift(
            {"sample_size": 10, "median_len": 100.0, "active_hours": {(cur_hr + 6) % 24: 10}, "stylometry": {}},
            current_char_len=120,
            current_created_utc=ts_base,
            current_text="normal reply",
        )
        self.assertEqual(sc_6h_uncorr, 16)
        self.assertEqual(dr_6h_uncorr["drift_flags"], ["active_hours_shift_strong"])

        # 3. Uncorroborated 6x/600-char stays green (14); extreme >=12x/>=1000 triggers spike (30);
        # corroborated >=4x/>=300 + dormancy triggers spike
        base_len = {"sample_size": 10, "median_len": 100.0, "active_hours": {cur_hr: 10}, "stylometry": {}}
        sc_mod, dr_mod = core.score_profile_drift(
            base_len, current_char_len=600, current_created_utc=ts_base, current_text="plain text " * 50
        )
        self.assertEqual(sc_mod, 14)
        self.assertEqual(dr_mod["drift_flags"], ["length_drift_moderate"])

        sc_ext, dr_ext = core.score_profile_drift(
            base_len, current_char_len=1300, current_created_utc=ts_base, current_text="plain text " * 110
        )
        self.assertEqual(sc_ext, 30)
        self.assertEqual(dr_ext["drift_flags"], ["length_drift_spike"])

        sc_corr, dr_corr = core.score_profile_drift(
            base_len,
            current_char_len=450,
            current_created_utc=ts_base,
            latest_hist_utc=ts_base - 40 * 86400,
            current_text="plain text " * 40,
        )
        self.assertGreaterEqual(sc_corr, 49)
        self.assertIn("length_drift_spike", dr_corr["drift_flags"])
        self.assertIn("extended_inactivity_gap", dr_corr["drift_flags"])

        # 4. OP promotional pitch & multi-domain self-promo vs benign image/news posts
        promo_op = {
            "raw_title": "CoinGecko alternative that focuses on custom date-range performance",
            "raw_selftext": ("We built a tracking tool with live metrics across exchanges. " * 14).strip(),
            "is_self": True,
            "domains": ["cointrends.xyz", "cointrends-blog.example"],
            "has_shortener": False,
            "has_tracking": False,
            "has_funnel": False,
            "edit_delay_sec": None,
        }
        op_sc, op_fl = core.score_op_class3(promo_op)
        self.assertEqual(op_sc, 32)
        self.assertEqual(set(op_fl), {"op_promotional_pitch", "op_multi_domain_self_promo"})

        img_op = {
            "raw_title": "Funny meme comparison",
            "raw_selftext": ("Normal personal story text here without promo links. " * 14).strip(),
            "is_self": True,
            "domains": ["ibb.co"],
            "has_shortener": False,
            "has_tracking": False,
            "has_funnel": False,
            "edit_delay_sec": None,
        }
        self.assertEqual(core.score_op_class3(img_op), (0, []))
        self.assertTrue(core.is_reference_domain("ibb.co"))
        self.assertTrue(core.is_reference_domain("coinmarketcap.com"))
        self.assertTrue(core.is_reference_domain("coingecko.com"))

    def test_arctic_shift_422_retry_and_tree_fallback(self):
        # 1. Transient HTTP 422 twice then 200 on Arctic Shift retries cleanly
        calls = []

        def fake_retry_urlopen(req, timeout=20.0):
            calls.append(req.full_url)
            if len(calls) <= 2:
                raise urllib.error.HTTPError(
                    req.full_url, 422, "Unprocessable Entity", {}, io.BytesIO(b"busy")
                )
            return FakeResp(json.dumps({"data": [{"id": "c1"}]}).encode())

        f_retry = core.RateLimitedFetcher(delay_sec=0.0, use_oauth=False, source="arctic-shift")
        with mock.patch("urllib.request.urlopen", side_effect=fake_retry_urlopen):
            data, err = f_retry.fetch_json(
                "https://arctic-shift.photon-reddit.com/api/comments/search?author=alice&limit=30"
            )
        self.assertIsNone(err)
        self.assertEqual(len(calls), 3)
        self.assertEqual(data, {"data": [{"id": "c1"}]})

        # 2. Persistent 422 on /comments/search falls back to /comments/tree without bogus lag warning
        f_tree = core.RateLimitedFetcher(delay_sec=0.0, use_oauth=False, source="arctic-shift")
        tree_node = cnode("c1", "t99", "t3_t99", "alice", "Recovered via tree", 1795400100.0)

        def fake_fetch_json(url):
            if "/posts/ids" in url:
                return {
                    "data": [
                        {
                            "id": "t99",
                            "subreddit": "altcoin",
                            "author": "op_user",
                            "title": "Test",
                            "selftext": "",
                            "created_utc": 1795400000.0,
                            "num_comments": 1,
                        }
                    ]
                }, None
            if "/comments/search" in url:
                return None, {"code": 422, "type": "http_error", "message": "HTTP 422: Unprocessable Entity"}
            if "/comments/tree" in url:
                return {"data": [tree_node]}, None
            raise AssertionError(f"Unexpected URL: {url}")

        with mock.patch.object(f_tree, "fetch_json", side_effect=fake_fetch_json):
            payload, t_err, notes = f_tree.fetch_thread_arctic("t99", max_comments=50)
        self.assertIsNone(t_err)
        self.assertEqual(notes, [])
        _, comments, _ = core.parse_reddit_thread(payload, set(), max_comments=50)
        self.assertEqual(len(comments), 1)
        self.assertEqual(comments[0]["raw_body"], "Recovered via tree")

    def test_op_promo_non_self_and_single_author_repeat_promoter(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db = tmp_path / "promo.db"
            t0 = 1795400000.0

            for idx in range(1, 4):
                th = make_thread(
                    f"pr{idx}",
                    "altcoin",
                    "solo_shill",
                    t0 + idx * 3600,
                    [cnode(f"pc{idx}", f"pr{idx}", f"t3_pr{idx}", f"reader_{idx}", "Interesting", t0 + idx * 3600 + 200)],
                )
                post_data = th[0]["data"]["children"][0]["data"]
                post_data["is_self"] = False
                post_data["url"] = "https://i.redd.it/example.png"
                post_data["title"] = f"Project update #{idx}: revenue-funded buyback model is worth discussing"
                post_data["selftext"] = (
                    "Most projects promise adoption while this one operates globally with real payments "
                    "and transparent metrics on https://pesabase.example/docs and https://medium.example/post. "
                    * 5
                ).strip()
                pf = tmp_path / f"pr{idx}.json"
                pf.write_text(json.dumps(th), encoding="utf-8")
                rc, out, _ = run_cli(AUDIT_THREAD, "--mock", str(pf), "--db", str(db))
                self.assertEqual(rc, 0)
                op = out["op_analysis"]
                self.assertIn("op_promotional_pitch", op["flags"])
                self.assertIn("op_multi_domain_self_promo", op["flags"])
                if idx == 1:
                    self.assertEqual(op["sub_scores"]["class2_swarm"], 0)
                elif idx == 2:
                    self.assertEqual(op["sub_scores"]["class2_swarm"], 26)
                    self.assertIn("repeat_domain_promoter", op["flags"])
                else:
                    self.assertEqual(op["sub_scores"]["class2_swarm"], 48)
                    self.assertIn("repeat_domain_promoter", op["flags"])
                    self.assertGreaterEqual(op["anomaly_score"], 56)

    def test_stage2_self_duplication_and_domain_concentration(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db = tmp_path / "stage2_beh.db"
            t0 = 1795460834.0
            th = make_thread(
                "s2b",
                "SaaS",
                "plain_op",
                t0,
                [
                    cnode(
                        "c1",
                        "s2b",
                        "t3_s2b",
                        "stealth_loop_shill",
                        "Check out https://acme-ops.example/trial for our workflow tool today!",
                        t0 + 1800,
                    )
                ],
            )
            tf = tmp_path / "thread.json"
            tf.write_text(json.dumps(th), encoding="utf-8")

            hist = []
            for i in range(10):
                body = (
                    f"We switched our engineering team to AcmeOps last quarter and cut webhook failures "
                    f"in half immediately, full details at https://acme-ops.example/case-{i % 2}"
                    if i < 6
                    else f"Totally agree, reliable queues save hours every week #{i}."
                )
                hist.append(
                    {
                        "kind": "t1",
                        "data": {
                            "link_id": f"t3_hist{i}",
                            "body": body,
                            "created_utc": t0 - (i + 1) * 3600,
                        },
                    }
                )
            mp = tmp_path / "mp.json"
            mp.write_text(
                json.dumps({"stealth_loop_shill": {"kind": "Listing", "data": {"children": hist}}}),
                encoding="utf-8",
            )

            rc1, out1, _ = run_cli(
                AUDIT_THREAD, "--mock", str(tf), "--mock-profiles", str(mp), "--db", str(db)
            )
            self.assertEqual(rc1, 0)
            shill = next(a for a in out1["top_anomalies"] if a["author"] == "stealth_loop_shill")
            self.assertIn("stage2_self_duplication_loop", shill["flags"])
            self.assertIn("stage2_domain_concentration", shill["flags"])
            self.assertGreaterEqual(shill["sub_scores"]["class1_takeover"], 52)

            # Cached 24h run retains Stage-2 behavioral flags
            rc2, out2, _ = run_cli(AUDIT_THREAD, "--mock", str(tf), "--db", str(db))
            self.assertEqual(rc2, 0)
            shill2 = next(a for a in out2["top_anomalies"] if a["author"] == "stealth_loop_shill")
            self.assertEqual(shill2["profile_drift"]["status"], "cached_24h")
            self.assertIn("stage2_self_duplication_loop", shill2["flags"])
            self.assertIn("stage2_domain_concentration", shill2["flags"])

    def test_stage2_robotic_cron_cadence_and_per_host_delay(self):
        # 1. Stage-2 robotic + cron cadence detection (0 extra HTTP calls, persists on 24h cache)
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db = tmp_path / "cadence.db"
            t0 = 1795460400.0  # Exact 900s boundary
            th = make_thread(
                "cad1",
                "SaaS",
                "plain_op",
                t0,
                [cnode("c1", "cad1", "t3_cad1", "cron_bot", "Clean looking comment.", t0 + 900)],
            )
            tf = tmp_path / "thread.json"
            tf.write_text(json.dumps(th), encoding="utf-8")

            hist = [
                {
                    "kind": "t1",
                    "data": {
                        "link_id": f"t3_h{i}",
                        "body": f"Distinct short update number {i} on topic {i}.",
                        "created_utc": t0 - (i + 1) * 900.0,
                    },
                }
                for i in range(12)
            ]
            mp = tmp_path / "mp.json"
            mp.write_text(
                json.dumps({"cron_bot": {"kind": "Listing", "data": {"children": hist}}}),
                encoding="utf-8",
            )

            rc1, out1, _ = run_cli(
                AUDIT_THREAD, "--mock", str(tf), "--mock-profiles", str(mp), "--db", str(db)
            )
            self.assertEqual(rc1, 0)
            bot = next(a for a in out1["top_anomalies"] if a["author"] == "cron_bot")
            self.assertIn("stage2_robotic_cadence", bot["flags"])
            self.assertIn("stage2_cron_cadence", bot["flags"])
            self.assertGreaterEqual(bot["sub_scores"]["class1_takeover"], 44)

            rc2, out2, _ = run_cli(AUDIT_THREAD, "--mock", str(tf), "--db", str(db))
            self.assertEqual(rc2, 0)
            bot2 = next(a for a in out2["top_anomalies"] if a["author"] == "cron_bot")
            self.assertEqual(bot2["profile_drift"]["status"], "cached_24h")
            self.assertIn("stage2_robotic_cadence", bot2["flags"])
            self.assertIn("stage2_cron_cadence", bot2["flags"])

        # 2. Per-host rate-limit delay: sleeps for same host, skips sleep when switching hosts
        fetcher = core.RateLimitedFetcher("test-agent", delay_sec=0.15, use_oauth=False)
        with mock.patch("urllib.request.urlopen", return_value=FakeResp(b'{"ok":true}')):
            fetcher.fetch_json("https://www.reddit.com/r/test.json")
            t_switch0 = time.monotonic()
            fetcher.fetch_json("https://arctic-shift.photon-reddit.com/api/posts/ids?ids=abc")
            switch_elapsed = time.monotonic() - t_switch0
            self.assertLess(switch_elapsed, 0.08)

            t_same0 = time.monotonic()
            fetcher.fetch_json("https://arctic-shift.photon-reddit.com/api/comments/search?link_id=t3_abc")
            same_elapsed = time.monotonic() - t_same0
            self.assertGreaterEqual(same_elapsed, 0.10)


if __name__ == "__main__":
    unittest.main()
