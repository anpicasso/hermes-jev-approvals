#!/usr/bin/env python3
"""Offline fork-derived credential-scope and exact-cap regressions (fake keys only)."""
import importlib.util
import os
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

from agent.secret_scope import (
    UnscopedSecretError, reset_multiplex_context, reset_secret_scope,
    set_multiplex_context, set_secret_scope,
)

spec = importlib.util.spec_from_file_location("jev_fork_regressions", Path(__file__).parents[1] / "__init__.py")
assert spec is not None and spec.loader is not None
jev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jev)


class ForkRegressions(unittest.TestCase):
    def setUp(self):
        self.mx = set_multiplex_context(True)
        self.scope = set_secret_scope(None)
        self.env = patch.dict(os.environ, {
            "TYPESAFE_API_KEY": "ambient-typesafe", "OPENROUTER_API_KEY": "ambient-router",
            "CUSTOM_JEV_KEY": "ambient-custom",
        })
        self.env.start()
        self.pool = patch.object(jev, "_key_from_runtime_provider", return_value="")
        self.pool_mock = self.pool.start()
        self.dotenv = patch.object(jev, "_key_from_dotenv", return_value="")
        self.dotenv.start()
        self.settings = patch.object(jev, "_setting", side_effect=lambda k, default=None: default)
        self.settings.start()

    def tearDown(self):
        self.settings.stop()
        self.dotenv.stop()
        self.pool.stop()
        self.env.stop()
        reset_secret_scope(self.scope)
        reset_multiplex_context(self.mx)

    def test_missing_scope_fails_before_resolver_or_http(self):
        with patch.object(jev, "_setting", return_value="CUSTOM_JEV_KEY"), patch.object(jev, "_urlopen") as http:
            for url in (jev.DEFAULT_BASE_URL, "https://openrouter.ai/api/v1", "https://example.com/decide"):
                with self.subTest(url=url), self.assertRaises(UnscopedSecretError):
                    jev._post(url, {}, 1)
            http.assert_not_called()
            self.pool_mock.assert_not_called()

    def test_two_profiles_and_no_ambient_fallback(self):
        for label in ("a", "b", "a"):
            token = set_secret_scope({"TYPESAFE_API_KEY": label, "OPENROUTER_API_KEY": label, "CUSTOM_JEV_KEY": label})
            try:
                self.assertEqual(jev._api_key(), label)
                self.assertEqual(jev._api_key("https://openrouter.ai/api/v1"), label)
                with patch.object(jev, "_setting", return_value="CUSTOM_JEV_KEY"):
                    self.assertEqual(jev._api_key("https://example.com/decide"), label)
            finally:
                reset_secret_scope(token)
        token = set_secret_scope({})
        try:
            for url in (jev.DEFAULT_BASE_URL, "https://openrouter.ai/api/v1"):
                with self.assertRaises(RuntimeError):
                    jev._api_key(url)
            with patch.object(jev, "_setting", return_value="CUSTOM_JEV_KEY"):
                self.assertEqual(jev._api_key("https://example.com/decide"), "")
        finally:
            reset_secret_scope(token)

    def test_pool_still_wins_over_scoped_fallback(self):
        token = set_secret_scope({"OPENROUTER_API_KEY": "scoped-fallback"})
        try:
            self.pool_mock.return_value = "pool-key"
            self.assertEqual(jev._api_key("https://openrouter.ai/api/v1"), "pool-key")
            self.pool_mock.assert_called_once_with("openrouter")
        finally:
            reset_secret_scope(token)

    def test_anonymous_custom_and_constructor_do_not_read_ambient_key(self):
        self.assertEqual(jev._api_key("https://example.com/decide"), "")
        self.assertEqual(jev.JevClient().api_key, "")
        self.assertEqual(jev.JevClient(api_key="dispatch-only").api_key, "dispatch-only")

    def test_legacy_host_compatibility(self):
        with patch.dict(sys.modules, {"agent.secret_scope": None}):
            self.assertEqual(jev._secret_env("TYPESAFE_API_KEY"), "ambient-typesafe")

    def test_exact_cap_head_tail_and_marker(self):
        for limit in (1000, 16000, 64000):
            for extra in (1, 9, 99, 999, 100000):
                text = "HEAD" + "界" * (limit + extra) + "TAIL"
                cut, truncated = jev._truncate(text, limit)
                self.assertTrue(truncated)
                self.assertEqual(len(cut), limit)
                self.assertTrue(cut.startswith("HEAD") and cut.endswith("TAIL"))
                marker = re.search(r"…\[(\d+) chars elided\]", cut)
                assert marker is not None
                self.assertEqual(int(marker[1]), len(text) - (len(cut) - len(marker[0])))
            self.assertEqual(jev._truncate("x" * limit, limit), ("x" * limit, False))

    def test_tiny_caps_and_zero_tail(self):
        for limit in range(40):
            cut, truncated = jev._truncate("x" * 100, limit)
            self.assertEqual(len(cut), limit)
            self.assertTrue(truncated)
        with self.assertRaises(ValueError):
            jev._truncate("x", -1)


if __name__ == "__main__":
    unittest.main()
