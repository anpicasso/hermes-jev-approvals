#!/usr/bin/env python3
"""Counterfactual threshold sweeps over decision logs; stdout only, never applied."""
import argparse
import collections
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "plugin"))
import jev_policy  # noqa: E402
from jevlog import read_rows  # noqa: E402
from logstats import _inputs  # noqa: E402

CANDIDATES = {
    "confidence": (0.45, 0.50, 0.55, 0.60, 0.65),
    "blast_radius": (1.4, 1.6, 1.8),
    "blast_allow": (1.8, 2.0),
    "policy_allows": (0.6, 0.7, 0.8),
    "secrets": (0.6, 0.7, 0.8),
    "self_advocating": (0.5, 0.6, 0.7),
}


def sweep(rows, field, values):
    playable = [(row, _inputs(row)) for row in rows]
    playable = [(row, inputs) for row, inputs in playable if inputs]
    baseline = [(row, jev_policy.apply_policy(**inputs)[:2]) for row, inputs in playable]
    results = []
    for value in values:
        thresholds = jev_policy.DEFAULT_THRESHOLDS._replace(**{field: float(value)})
        changes = collections.Counter()
        rule_changes = 0
        for (row, inputs), (_, old) in zip(playable, baseline):
            new = jev_policy.apply_policy(**inputs, thresholds=thresholds)[:2]
            if new[0] != old[0]:
                changes[f"{old[0]}->{new[0]}"] += 1
            rule_changes += new[1] != old[1]
        results.append((float(value), sum(changes.values()), rule_changes, dict(changes)))
    return len(playable), results


def _self_check():
    row = dict(ok=True, raw_verdict="APPROVE", verdict="ESCALATE", rule="low_confidence",
               confidence=0.50, blast_radius=0.1, self_advocating=0.01,
               policy_allows=0.01, reads_secrets=0.01, sends_outbound=0.01,
               has_policy=False, truncated=False)
    n, results = sweep([row], "confidence", (0.45, 0.55))
    assert n == 1 and results[0][3] == {"ESCALATE->APPROVE": 1} and results[1][1] == 0
    print("sweep self-check: ok")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path")
    parser.add_argument("--field", choices=tuple(CANDIDATES) + ("all",), default="all")
    parser.add_argument("--values", help="comma-separated values; requires one --field")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)
    if args.self_check:
        return _self_check()
    if args.values and args.field == "all":
        parser.error("--values requires one --field")
    loaded, errors = read_rows(args.path)
    rows = [row for _, row in loaded]
    fields = CANDIDATES if args.field == "all" else (args.field,)
    for field in fields:
        values = ([float(value) for value in args.values.split(",")]
                  if args.values else CANDIDATES[field])
        count, results = sweep(rows, field, values)
        print(f"{field} replayable={count}")
        for value, changed, rule_changes, directions in results:
            marker = " *" if value == getattr(jev_policy.DEFAULT_THRESHOLDS, field) else ""
            print(f"  {value:g}{marker}: verdict_changes={changed} rule_changes={rule_changes} "
                  f"directions={directions}")
    if errors:
        print(f"schema_errors={len(errors)}", file=sys.stderr)
    print("read-only: no threshold was applied")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
