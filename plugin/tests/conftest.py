"""Keep executable test scripts out of pytest's import-time collector.

The scripts predate pytest and intentionally run assertions at module scope.  Importing all
of them in one pytest process makes their environment/module stubs leak between files, while
Hermes-dependent scripts cannot be collected on machines without Hermes core.  The pytest
suite runs the offline scripts in isolated subprocesses instead (test_scripts.py).
"""

collect_ignore = [
    "test_audit.py",
    "test_boundary.py",
    "test_hardening.py",
    "test_policy_contract.py",
    "test_provider.py",
    "test_real_load.py",
    "test_routes.py",
]
