#!/usr/bin/env python3
"""Summarize structured decision logs and verify policy replay."""
import argparse
import collections
import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN = HERE.parent / "plugin"
sys.path.insert(0, str(PLUGIN))
import jev_policy  # noqa: E402
from jevlog import read_rows  # noqa: E402


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _percentile(values, percent):
    if not values:
        return None
    values = sorted(values)
    return values[max(0, math.ceil(len(values) * percent / 100) - 1)]


def _inputs(row):
    required = ("confidence", "blast_radius", "self_advocating", "policy_allows",
                "reads_secrets", "sends_outbound")
    if row.get("ok") is not True or row.get("raw_verdict") not in jev_policy.VERDICTS:
        return None
    if not all(_number(row.get(key)) for key in required):
        return None
    return dict(verdict=row["raw_verdict"], confidence=row["confidence"],
                blast_radius=row["blast_radius"], self_advocating=row["self_advocating"],
                policy_allows=row["policy_allows"], reads_secrets=row["reads_secrets"],
                sends_outbound=row["sends_outbound"], has_policy=bool(row["has_policy"]),
                truncated=bool(row["truncated"]))


def summarize(rows, near=0.1):
    counters = {key: collections.Counter() for key in
                ("verdict", "raw_verdict", "rule", "error_class", "policy_version",
                 "questions_fp", "route", "model")}
    latencies, input_tokens, output_tokens, cost = [], 0, 0, 0.0
    replayed = verdict_matches = rule_matches = 0
    t = jev_policy.DEFAULT_THRESHOLDS
    cuts = {"self_advocating": t.self_advocating, "reads_secrets": t.secrets,
            "sends_outbound": t.secrets, "policy_allows": t.policy_allows,
            "confidence": t.confidence, "blast_radius": t.blast_radius}
    near_counts = collections.Counter()
    for row in rows:
        for key, counter in counters.items():
            value = row.get(key)
            if value is not None:
                counter[str(value)] += 1
        if _number(row.get("latency_ms")):
            latencies.append(float(row["latency_ms"]))
        usage = row.get("usage") or {}
        ins = usage.get("input_tokens", usage.get("prompt_tokens", 0))
        outs = usage.get("output_tokens", usage.get("completion_tokens", 0))
        input_tokens += int(ins) if _number(ins) else 0
        output_tokens += int(outs) if _number(outs) else 0
        cost += float(usage["cost"]) if _number(usage.get("cost")) else (
            (float(ins) if _number(ins) else 0.0) * 0.042 / 1_000_000)
        for field, cut in cuts.items():
            if _number(row.get(field)) and abs(float(row[field]) - cut) <= near:
                near_counts[field] += 1
        inputs = _inputs(row)
        if inputs:
            verdict, rule, _ = jev_policy.apply_policy(**inputs)
            replayed += 1
            verdict_matches += verdict == row.get("verdict")
            rule_matches += rule == row.get("rule")
    return {
        "rows": len(rows), "counts": {key: dict(value) for key, value in counters.items()},
        "tokens": {"input": input_tokens, "output": output_tokens, "cost_usd": cost},
        "latency_ms": {"p50": _percentile(latencies, 50),
                       "p95": _percentile(latencies, 95)},
        "near_threshold": dict(near_counts),
        "replay": {"rows": replayed, "verdict_matches": verdict_matches,
                   "rule_matches": rule_matches},
    }


def _self_check():
    base = {key: None for key in __import__("jevlog").SCHEMA}
    base.update(ok=True, verdict="APPROVE", raw_verdict="APPROVE", rule="model_verdict",
                confidence=0.9, blast_radius=0.1, self_advocating=0.01,
                policy_allows=0.02, reads_secrets=0.01, sends_outbound=0.01,
                has_policy=False, truncated=False, latency_ms=100,
                usage={"input_tokens": 100, "output_tokens": 0})
    report = summarize([base, dict(base, latency_ms=300)])
    assert report["latency_ms"] == {"p50": 100.0, "p95": 300.0}
    assert report["replay"] == {"rows": 2, "verdict_matches": 2, "rule_matches": 2}
    print("logstats self-check: ok")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path")
    parser.add_argument("--near", type=float, default=0.1)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)
    if args.self_check:
        return _self_check()
    loaded, errors = read_rows(args.path)
    print(json.dumps(summarize([row for _, row in loaded], args.near), indent=2, sort_keys=True))
    for error in errors:
        print(f"schema error: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
