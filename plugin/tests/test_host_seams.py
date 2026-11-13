#!/usr/bin/env python3
"""Every core seam this provider imports must still exist in the RUNNING Hermes.

`test_real_load.py` proves the same thing through discovery, but needs the plugin installed;
this runs offline (no install, no credential, no network) so a moved helper fails fast.
It is the check that would have caught `_is_auth_error` leaving `agent.auxiliary_client`.
"""
import importlib
import inspect

from _host import ensure_host

ensure_host()

# The module under test, loaded by path exactly as the doctor/bench harnesses load it.
import importlib.util
import pathlib

_PLUGIN = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("tsj_seams", _PLUGIN / "__init__.py")
assert _spec and _spec.loader
plugin = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plugin)

# (module, attribute) pairs the provider calls at runtime.
SEAMS = [
    ("hermes_cli.config", "load_config_readonly"),
    ("hermes_cli.config", "get_env_value_prefer_dotenv"),
    ("hermes_cli.runtime_provider", "resolve_runtime_provider"),
    ("providers", "register_provider"),
    ("providers", "get_provider_profile"),
    ("providers.base", "ProviderProfile"),
    ("agent.redact", "redact_sensitive_text"),
    ("agent.error_classifier", "classify_api_error"),
    ("agent.auxiliary_client", "_resolve_task_provider_model"),
    ("agent.auxiliary_client", "call_llm"),
    ("agent.auxiliary_client", "_get_task_timeout"),
]
for module_name, attribute in SEAMS:
    module = importlib.import_module(module_name)
    assert hasattr(module, attribute), f"{module_name}.{attribute} is gone"

# The two optional kwargs the redaction boundary depends on.
signature = inspect.signature(importlib.import_module("agent.redact").redact_sensitive_text)
assert "redact_url_credentials" in signature.parameters, "redact_sensitive_text lost the URL opt-in"
assert signature.parameters["force"].default is False

# Profile fields the plugin sets by keyword, and the two client opt-out flags core honors.
from providers.base import ProviderProfile  # noqa: E402

FIELDS = ("name", "aliases", "display_name", "description", "signup_url", "env_vars",
          "base_url", "auth_type", "supports_health_check", "supports_model_listing",
          "supports_vision", "fallback_models")
missing = [field for field in FIELDS if field not in ProviderProfile.__dataclass_fields__]
assert not missing, f"ProviderProfile no longer declares {missing}"

profile = plugin._build_profile()
assert profile.name == plugin.PROVIDER_NAME
assert profile.create_client(timeout=5) is not None

print(f"host seams present: {len(SEAMS)} module attributes, {len(FIELDS)} profile fields")
print("redaction boundary: force + redact_url_credentials")
print("seam check done")
