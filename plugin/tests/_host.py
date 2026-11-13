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
    except ImportError:
        pass
    else:
        # An editable install can make `hermes_cli` importable through a finder that
        # maps packages only, leaving the install root (hermes_yaml, utils, ...) off
        # sys.path. Core's launcher inserts that root; a test run directly under the
        # venv interpreter must do the same or `hermes_cli.config` fails on import.
        module_file = getattr(hermes_cli, "__file__", None)
        if module_file:
            root = os.path.dirname(os.path.dirname(os.path.abspath(module_file)))
            if root not in sys.path:
                sys.path.insert(0, root)
        return
    for candidate in (os.environ.get("HERMES_AGENT_DIR"),
                      os.path.expanduser("~/.hermes/hermes-agent")):
        if candidate and os.path.isdir(candidate):
            sys.path.insert(0, candidate)
            return
