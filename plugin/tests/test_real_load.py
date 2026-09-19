#!/usr/bin/env python3
"""Do BOTH halves load through the real plugin manager?

`plugins doctor` cannot answer this: it calls `register(ctx)` itself. The real manager does
not, for `kind: model-provider` — that kind is placeholdered
(hermes_cli/plugins_discovery.py::gate_manifest) and never receives a ctx, so a hook
registered in `register(ctx)` would be dead code in a real gateway while doctor reported it
as present. This asserts the manifest kind that actually works.

Needs the host on sys.path and the plugin enabled:
    hermes plugins enable jev-approval-provider
"""
import os
import sys

for _candidate in (os.environ.get("HERMES_AGENT_DIR"),
                   os.path.expanduser("~/.hermes/hermes-agent")):
    if _candidate and os.path.isdir(_candidate):
        sys.path.insert(0, _candidate)
        break

try:
    from hermes_cli.plugins import discover_plugins, get_plugin_manager
except ImportError as exc:
    print(f"SKIP: Hermes core not importable ({exc}). "
          f"Set HERMES_AGENT_DIR to the hermes-agent checkout.")
    raise SystemExit(0)

PLUGIN_ID = "jev-approval-provider"

discover_plugins(force=True)   # the entry point both the CLI and the gateway call
mgr = get_plugin_manager()

plugin = mgr._plugins.get(PLUGIN_ID)
assert plugin is not None, f"{PLUGIN_ID} was not discovered at all"
print(f"kind={plugin.manifest.kind}  enabled={plugin.enabled}  error={plugin.error}")

# The kind is load-bearing. model-provider => placeholdered => register(ctx) never called.
assert plugin.manifest.kind == "standalone", (
    f"kind is {plugin.manifest.kind!r}; only 'standalone' gets a register(ctx) call, so any "
    f"other kind silently drops the pre_tool_call hook (doctor will NOT catch this)")
assert plugin.enabled, (
    f"not enabled ({plugin.error}) — a standalone plugin needs "
    f"`hermes plugins enable {PLUGIN_ID}`")
assert not plugin.error, f"load error: {plugin.error}"

# 1. the hook is in the manager's own registry, not merely callable
hooks = mgr._hooks.get("pre_tool_call") or []
names = [getattr(h, "__qualname__", str(h)) for h in hooks]
assert any("_pre_tool_call" in n for n in names), (
    f"pre_tool_call hook missing from the real manager (registered: {names})")
print(f"hook registered: {[n for n in names if '_pre_tool_call' in n]}")

# 2. the provider self-registered from register(ctx), since providers/ never imports us now
from providers import get_provider_profile  # noqa: E402

profile = get_provider_profile("jev-approval")
assert profile is not None, "provider did not self-register from register(ctx)"
assert profile.name == "jev-approval"
print(f"provider registered: {type(profile).__name__}")

# 3. the dispatch path a real tool call takes reaches the hook and leaves benign work alone
from hermes_cli.plugins import _dispatch_pre_tool_call_hooks  # noqa: E402

block, _ = _dispatch_pre_tool_call_hooks("terminal", {"command": "echo hello"})
assert block is None, f"a benign command was blocked: {block}"
print("benign command through the real dispatch path: not blocked")

print("\nboth halves load through the real plugin manager")
