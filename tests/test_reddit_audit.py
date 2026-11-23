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


if __name__ == "__main__":
    unittest.main()
