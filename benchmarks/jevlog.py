#!/usr/bin/env python3
"""Read and validate both generations of the structured decision log."""
import argparse
import json
import os
import tempfile
from pathlib import Path

LOG_NAME = "jev-approval-decisions.jsonl"
SCHEMA = (
    "ts", "ok", "verdict", "raw_verdict", "rule", "reason", "model", "model_requested",
    "provider", "route", "latency_ms", "attempts", "http_status", "request_id",
    "error_class", "error", "policy_version", "policy_fp", "has_policy", "questions_fp",
    "confidence", "blast_radius", "self_advocating", "policy_allows", "reads_secrets",
    "sends_outbound", "truncated", "flagged_as", "command", "redacted", "usage",
)


def default_path():
    override = os.environ.get("JEV_APPROVAL_LOG", "").strip()
    if override:
        return Path(os.path.expanduser(override))
    try:
        from hermes_constants import get_hermes_home
        home = Path(get_hermes_home())
    except Exception:
        home = Path(os.path.expanduser(os.environ.get("HERMES_HOME", "~/.hermes")))
    return home / LOG_NAME


def generations(path=None):
    live = Path(path) if path else default_path()
    return (("rotated", live.with_suffix(live.suffix + ".1")), ("live", live))


def read_rows(path=None):
    """Return exact-schema rows and diagnostics; missing generations are fine."""
    rows, errors = [], []
    wanted = set(SCHEMA)
    for source, candidate in generations(path):
        if not candidate.is_file():
            continue
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            errors.append(f"{candidate}: {exc}")
            continue
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"{candidate}:{number}: invalid JSON ({exc.msg})")
                continue
            if not isinstance(row, dict) or set(row) != wanted:
                got = set(row) if isinstance(row, dict) else set()
                errors.append(f"{candidate}:{number}: schema drift "
                              f"missing={sorted(wanted-got)} extra={sorted(got-wanted)}")
                continue
            rows.append((source, row))
    return rows, errors


def _self_check():
    row = {key: None for key in SCHEMA}
    row.update(ok=True, verdict="APPROVE", raw_verdict="APPROVE", rule="model_verdict")
    with tempfile.TemporaryDirectory(prefix="jevlog-") as tmp:
        live = Path(tmp) / LOG_NAME
        live.write_text(json.dumps(row) + "\n{}\nnot json\n")
        live.with_suffix(live.suffix + ".1").write_text(json.dumps(row) + "\n")
        rows, errors = read_rows(live)
        assert len(rows) == 2 and {source for source, _ in rows} == {"live", "rotated"}
        assert len(errors) == 2
    print("jevlog self-check: ok")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)
    if args.self_check:
        return _self_check()
    rows, errors = read_rows(args.path)
    print(f"log={Path(args.path) if args.path else default_path()} rows={len(rows)} errors={len(errors)}")
    for error in errors[:20]:
        print(f"error: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
