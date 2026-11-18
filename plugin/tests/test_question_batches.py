"""Offline regression checks for opt-in question batching (run as a script)."""
import copy
from contextvars import ContextVar
import importlib.util
import io
import json
from pathlib import Path
from typing import Any
import urllib.error
from email.message import Message
import threading
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("jev_batches", Path(__file__).resolve().parents[1] / "__init__.py")
assert spec is not None and spec.loader is not None
jev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jev)
ANSWERS = {
    "verdict": {"choice": "APPROVE", "confidence": 0.9},
    "blast_radius": {"score": 0.1}, "self_advocating": {"noul": 0.01},
    "policy_allows": {"noul": 0.02}, "reads_secrets": {"noul": 0.01},
    "sends_outbound": {"noul": 0.01},
}
BODY = {"state": {"command": "echo safe"}, "model": "test", "questions": jev.QUESTIONS}


def response(body):
    return {"answers": {k: copy.deepcopy(ANSWERS[k]) for k in body["questions"]},
            "model": "test", "provider": "fixture", "usage": {"input_tokens": 10, "output_tokens": 2},
            jev._TRANSPORT_KEY: {"attempts": 1, "http_status": 200, "request_id": next(iter(body["questions"]))}}


def ask(command="echo safe"):
    return jev.JevClient(base_url="https://example.com/decide").chat.completions.create(
        model="test", messages=[{"role": "user", "content": f"<command>{command}</command>"}])


class Batches(unittest.TestCase):
    def setUp(self):
        self.records = []
        self.settings: dict[str, Any] = {"max_questions_per_request": 1}
        self.patches = [patch.object(jev, "_record", self.records.append),
                        patch.object(jev, "_setting", lambda k, default=None: self.settings.get(k, default))]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        for row in self.records:
            self.assertEqual(set(row), set(jev._audit_row()))

    def test_terminal_error_survives_pending_sibling_deadline(self):
        release = threading.Event()
        failed = threading.Event()
        def post(url, body, timeout, deadline=None):
            if "verdict" in body["questions"]:
                failed.set()
                raise jev._tag_error(RuntimeError("fixture authentication failed"),
                                     attempts=1, status_code=401,
                                     request_id="auth-failure", error_class="http_401")
            release.wait(2)
            return response(body)
        try:
            with patch.object(jev, "_post", post), patch.object(jev, "_deadline_for", lambda t: time.monotonic() + 0.1):
                with self.assertRaisesRegex(RuntimeError, "authentication"):
                    ask()
            self.assertTrue(failed.is_set())
            row = self.records[-1]
            self.assertEqual(row["http_status"], 401)
            self.assertEqual(row["error_class"], "http_401")
            self.assertEqual(row["request_id"], "auth-failure")
            self.assertFalse(row["ok"])
        finally:
            release.set()

    def test_unset_and_large_limit_keep_one_request(self):
        for limit in (None, 6, 100):
            self.settings["max_questions_per_request"] = limit
            with patch.object(jev, "_post", side_effect=lambda u, b, t, deadline=None: response(b)) as post:
                self.assertEqual(ask().choices[0].message.content, "APPROVE")
                self.assertEqual(post.call_count, 1)
                self.assertEqual(post.call_args.args[1]["questions"], jev.QUESTIONS)

    def test_invalid_setting_never_sends(self):
        for limit in (False, True, 0, -1, 1.5, "1", [], {}):
            self.settings["max_questions_per_request"] = limit
            with patch.object(jev, "_post") as post, self.assertRaises(ValueError):
                ask()
            post.assert_not_called()
            self.assertFalse(self.records[-1]["ok"])

    def test_concurrent_exact_partition_context_and_usage(self):
        profile = ContextVar("test_profile", default="wrong")
        token = profile.set("origin")
        self.addCleanup(profile.reset, token)
        for limit, count in ((1, 6), (3, 2), (4, 2)):
            self.settings["max_questions_per_request"] = limit
            barrier, calls = threading.Barrier(count), []
            def post(url, body, timeout, deadline=None):
                self.assertEqual(profile.get(), "origin")
                calls.append((body, deadline))
                barrier.wait(timeout=2)
                return response(body)
            with patch.object(jev, "_post", post):
                result = ask("echo --password=secret-value")
            self.assertEqual(result.choices[0].message.content, "APPROVE")
            self.assertEqual(result.usage.prompt_tokens, 10 * count)
            self.assertEqual(result.usage.completion_tokens, 2 * count)
            self.assertEqual(len(calls), count)
            self.assertEqual(len({d for _, d in calls}), 1)
            self.assertEqual({k: v for b, _ in calls for k, v in b["questions"].items()}, jev.QUESTIONS)
            self.assertTrue(all(len(b["questions"]) <= limit for b, _ in calls))
            self.assertTrue(all("secret-value" not in b["state"]["command"] for b, _ in calls))
            self.assertEqual(self.records[-1]["attempts"], count)
            self.assertEqual(len(self.records[-1]["request_ids"]), count)

    def test_partial_malformed_or_extra_answers_never_approve(self):
        def missing(data):
            data["answers"].clear()
        def extra(data):
            data["answers"]["unexpected"] = {"noul": 0}
        def malformed(data):
            data["answers"][next(iter(data["answers"]))] = None
        def bad_value(data):
            data["answers"]["reads_secrets"] = {"noul": "not-a-number"}
        for mutate in (missing, extra, malformed, bad_value):
            def post(url, body, timeout, deadline=None):
                data = response(body)
                if "reads_secrets" in body["questions"]:
                    mutate(data)
                return data
            with patch.object(jev, "_post", post), self.assertRaises(RuntimeError):
                ask()
            self.assertFalse(self.records[-1]["ok"])
            self.assertEqual(self.records[-1]["attempts"], 6)

    def test_http_failure_wins_over_context_retry(self):
        def post(url, body, timeout, deadline=None):
            key = next(iter(body["questions"]))
            if key in ("verdict", "reads_secrets"):
                kind = "http_401" if key == "reads_secrets" else "max_tokens_exceeded"
                raise jev._tag_error(RuntimeError(kind), attempts=2, error_class=kind)
            return response(body)
        with patch.object(jev, "_post", post), self.assertRaisesRegex(RuntimeError, "http_401"):
            ask()
        self.assertEqual(self.records[-1]["attempts"], 8)

    def test_context_retry_resends_entire_rubric_under_same_deadline(self):
        self.settings["max_questions_per_request"] = 3
        calls = []
        def post(url, body, timeout, deadline=None):
            calls.append((body, deadline))
            if len(body["state"]["command"]) > 40000 and "verdict" in body["questions"]:
                raise jev._tag_error(RuntimeError("too big"), attempts=1, error_class="max_tokens_exceeded")
            return response(body)
        with patch.object(jev, "_post", post):
            result = ask("x" * 50000)
        self.assertEqual(result.choices[0].message.content, "ESCALATE")
        self.assertEqual(len(calls), 4)
        self.assertEqual(len({d for _, d in calls}), 1)
        self.assertEqual(self.records[-1]["attempts"], 4)

    def test_shared_deadline_returns_without_late_approval(self):
        release = threading.Event()
        def post(url, body, timeout, deadline=None):
            release.wait(2)
            return response(body)
        try:
            with patch.object(jev, "_post", post), patch.object(jev, "_deadline_for", lambda t: time.monotonic() + 0.05):
                started = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, "deadline"):
                    ask()
                self.assertLess(time.monotonic() - started, 1)
                self.assertFalse(self.records[-1]["ok"])
        finally:
            release.set()

    def test_transport_auth_and_transient_retry_are_reused(self):
        calls, lock = [], threading.Lock()
        profile = ContextVar("transport_profile", default="wrong")
        token = profile.set("origin")
        self.addCleanup(profile.reset, token)
        def key(base_url):
            self.assertEqual(profile.get(), "origin")
            return "synthetic-test-key"
        def urlopen(req, timeout):
            self.assertEqual(req.full_url, "https://example.com/decide")
            self.assertEqual(req.get_header("Authorization"), "Bearer synthetic-test-key")
            body = json.loads(req.data)
            with lock:
                calls.append(body)
                first = len(calls) == 1
            if first:
                raise urllib.error.HTTPError(req.full_url, 429, "fixture", Message(), io.BytesIO())
            return io.StringIO(json.dumps(response(body)))
        with patch.object(jev, "_api_key", key), patch.object(jev, "_urlopen", urlopen), patch.object(jev.time, "sleep"):
            self.assertEqual(ask().choices[0].message.content, "APPROVE")
        self.assertEqual(len(calls), 7)
        self.assertEqual(self.records[-1]["attempts"], 7)

    def test_security_signal_still_prevents_approval(self):
        def post(url, body, timeout, deadline=None):
            data = response(body)
            if "self_advocating" in body["questions"]:
                data["answers"]["self_advocating"]["noul"] = 0.99
            return data
        with patch.object(jev, "_post", post):
            self.assertNotEqual(ask().choices[0].message.content, "APPROVE")

    def test_expired_deadline_sends_nothing(self):
        with patch.object(jev, "_post") as post, self.assertRaisesRegex(RuntimeError, "deadline"):
            jev._post_questions("https://example.com", BODY, 5, time.monotonic() - 1, 1)
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
