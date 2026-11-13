#!/usr/bin/env python3
"""Offline: a custom route gets a dispatch placeholder; TypeSafe direct still needs its key.

Hermes' api_key branch refuses to construct the provider without a credential, before the
plugin can resolve the route's real key (or anonymous access). `resolve_api_key_secret` is the
documented provider-owned seam that supplies the dispatch value; it must never be the value
sent upstream.
"""
import importlib.util
import os
import pathlib
import tempfile

_HERE = pathlib.Path(__file__).resolve().parent
os.environ["JEV_APPROVAL_LOG"] = str(pathlib.Path(tempfile.mkdtemp()) / "decisions.jsonl")
spec = importlib.util.spec_from_file_location("jev_dispatch_auth", _HERE.parent / "__init__.py")
jev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jev)

profile = jev._build_profile()
original_base_url = jev._configured_approval_base_url
original_setting = jev._setting


def with_base_url(value):
    jev._configured_approval_base_url = lambda: value


try:
    with_base_url("https://opencode.ai/zen/v1/systemone")
    assert profile.resolve_api_key_secret() == (
        "plugin-dispatch-placeholder", "plugin-dispatch")

    with_base_url("https://openrouter.ai/api/alpha")
    assert profile.resolve_api_key_secret() == (
        "plugin-dispatch-placeholder", "plugin-dispatch")

    # TypeSafe direct and an unset base_url keep core's normal real-key requirement.
    for value in ("https://api.typesafe.ai/v1", ""):
        with_base_url(value)
        assert profile.resolve_api_key_secret() is None, value

    # The dispatch placeholder is never what the request sends: a custom route with no
    # key_env resolves to an anonymous request.
    jev._setting = lambda key, default=None: default
    assert jev._api_key("https://opencode.ai/zen/v1/systemone") == ""
finally:
    jev._configured_approval_base_url = original_base_url
    jev._setting = original_setting

print("1. custom/aggregator route gets a dispatch placeholder             ok")
print("2. TypeSafe direct keeps the real-key requirement                   ok")
print("3. placeholder is never the upstream credential                     ok")
