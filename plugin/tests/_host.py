"""Resolve the Hermes install the way core does: whatever is importable in this process.

A hardcoded checkout prepended to ``sys.path`` shadows the running install: with a legacy
``~/.hermes/hermes-agent`` present, these scripts validated old core while the gateway ran
new core. Import first; only fall back to a directory hint when core is genuinely absent.
"""
from __future__ import annotations

import os
import sys


def ensure_host() -> None:
    try:
        import hermes_cli  # noqa: F401
        return
    except ImportError:
        pass
    for candidate in (os.environ.get("HERMES_AGENT_DIR"),
                      os.path.expanduser("~/.hermes/hermes-agent")):
        if candidate and os.path.isdir(candidate):
            sys.path.insert(0, candidate)
            return
