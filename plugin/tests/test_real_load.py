#!/usr/bin/env python3
"""Is the provider reachable the way core reaches it? TWO registries must both have it.

`plugins doctor` proves neither: it calls `register(ctx)` itself and only inspects the
plugin manager. Two silent failure modes this catches:

  1. `providers` registry missing -> get_provider_profile() returns None, no client built.
  2. `hermes_cli.auth.PROVIDER_REGISTRY` missing -> resolve_provider_client logs
     "unknown provider" and returns (None, None); auxiliary.approval falls back with no
     visible error.

(2) is the one that actually broke. PROVIDER_REGISTRY is built at hermes_cli.auth IMPORT
time by walking list_providers(), so a provider that registers later — e.g. from
register(ctx) under `kind: standalone` — never lands in it. `kind: model-provider` is
required precisely because providers/ discovery imports the module during that walk.

Needs the host on sys.path; no API key required.
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
    print(f"SKIP: Hermes core not importable ({exc}). Set HERMES_AGENT_DIR.")
    raise SystemExit(0)

# The PLUGIN id (manifest name / directory) and the PROVIDER name are independent: discovery
# only checks `kind: model-provider` and imports the directory, and the profile decides the
# provider name. So the plugin stays `jev-approvals` (what it does) while the provider is
# `typesafe-jev` (what you type in auxiliary.approval.provider).
PLUGIN_ID = "jev-approvals"
PROVIDER = "typesafe-jev"
ALIASES = ("jev",)

# Import order mirrors core's: auth first (building PROVIDER_REGISTRY), then discovery.
from hermes_cli.auth import PROVIDER_REGISTRY  # noqa: E402

discover_plugins(force=True)
mgr = get_plugin_manager()

plugin = mgr._plugins.get(PLUGIN_ID)
assert plugin is not None, f"{PLUGIN_ID} was not discovered at all"
print(f"kind={plugin.manifest.kind}  enabled={plugin.enabled}  error={plugin.error}")
assert plugin.manifest.kind == "model-provider", (
    f"kind is {plugin.manifest.kind!r}; only 'model-provider' is imported by providers/ "
    f"discovery, which is what puts the name into PROVIDER_REGISTRY")

# 1. the providers registry — what actually builds the client
from providers import get_provider_profile  # noqa: E402

profile = get_provider_profile(PROVIDER)
assert profile is not None, f"{PROVIDER} did not self-register at import"
assert profile.name == PROVIDER, f"profile name is {profile.name!r}"
assert tuple(profile.aliases) == ALIASES, (
    f"aliases are {tuple(profile.aliases)!r}, expected {ALIASES!r} — every registered name "
    f"is one more entry in the auxiliary auto-fallback chain, where Jev cannot serve")
print(f"providers registry: {type(profile).__name__} name={profile.name} "
      f"aliases={tuple(profile.aliases)}")

# 2. PROVIDER_REGISTRY — what resolve_provider_client validates the name against
assert PROVIDER in PROVIDER_REGISTRY, (
    f"{PROVIDER!r} is NOT in PROVIDER_REGISTRY — resolve_provider_client rejects it as "
    f"'unknown provider' and auxiliary.approval silently falls back")
for alias in ALIASES:
    assert alias in PROVIDER_REGISTRY, f"alias {alias!r} missing from PROVIDER_REGISTRY"
print(f"PROVIDER_REGISTRY: {PROVIDER} + {list(ALIASES)} present")

# 3. the route core actually takes, for both endpoints
from agent.auxiliary_client import resolve_provider_client  # noqa: E402

for label, base_url, model in (
    ("typesafe direct", "", "jev-latest"),
    ("openrouter", "https://openrouter.ai/api/alpha", "~typesafe/jev-latest"),
):
    client, final_model = resolve_provider_client(
        PROVIDER, model=model,
        explicit_base_url=base_url or None, explicit_api_key="test-key-not-used",
    )
    assert client is not None, f"{label}: resolve_provider_client returned no client"
    assert type(client).__name__ == "JevClient", (
        f"{label}: core built {type(client).__name__}, not our client — a base_url may have "
        f"collapsed the route to the generic OpenAI path")
    print(f"{label:<16} -> JevClient  model={final_model!r}  "
          f"route_default={client._default_model()!r}")

# 4. the host -> endpoint mapping, including that an unknown host is not the alpha route
import importlib.util  # noqa: E402
import pathlib  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "tsj_probe", pathlib.Path(__file__).resolve().parent.parent / "__init__.py")
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

assert mod._route_for("")[0] == "/systemone"
assert mod._route_for("https://api.typesafe.ai/v1")[0] == "/systemone"
assert mod._route_for("https://openrouter.ai/api/alpha")[0] == "/decisions"
assert mod._route_for("https://OPENROUTER.AI/api/alpha")[0] == "/decisions"
assert mod._route_for("https://example.com/v1")[0] == "/systemone"
# the OpenRouter model list must carry the filter, or it pulls the whole 447-model catalogue
assert "output_modalities=decisions" in mod._route_for("https://openrouter.ai/api/alpha")[1]
print("route_for: typesafe -> /systemone, openrouter -> /decisions, unknown -> /systemone")

print("\nboth registries have the provider, and both routes build our client")
