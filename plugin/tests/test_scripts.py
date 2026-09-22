"""Pytest adapter for the repository's executable assertion scripts."""

import os
from pathlib import Path
import subprocess
import sys

import pytest


TESTS = Path(__file__).resolve().parent
PLUGIN = TESTS.parent
OFFLINE = (
    "test_audit.py",
    "test_boundary.py",
    "test_hardening.py",
    "test_policy_contract.py",
)
INTEGRATION = {
    "test_real_load.py": "requires Hermes core and an installed plugin",
    "test_routes.py": "requires live provider credentials and network access",
    "test_provider.py": "requires Hermes core, provider credentials, and network access",
}


def test_script_inventory_is_explicit():
    scripts = {path.name for path in TESTS.glob("test_*.py")}
    assert scripts == set(OFFLINE) | set(INTEGRATION) | {"test_scripts.py"}


@pytest.mark.parametrize("script", OFFLINE)
def test_offline_script(script, tmp_path):
    env = os.environ.copy()
    env["JEV_APPROVAL_LOG"] = str(tmp_path / f"{script}.jsonl")
    completed = subprocess.run(
        [sys.executable, str(TESTS / script)],
        cwd=PLUGIN,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout


@pytest.mark.parametrize("script,reason", INTEGRATION.items())
def test_integration_script_is_explicit(script, reason):
    pytest.skip(f"{script} is a direct integration check: {reason}; run it with python3")
