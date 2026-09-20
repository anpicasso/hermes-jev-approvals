# Evaluation

All evaluation tools are stdlib-only, offline, and read-only. They never change runtime
thresholds, register hooks, or cache approvals.

## Decision-log analysis

```bash
python3 benchmarks/jevlog.py
python3 benchmarks/logstats.py
python3 benchmarks/sweep.py
```

The plugin records one uniform JSONL row for every successful or failed decision under the
active profile's `$HERMES_HOME`. The file is mode `0600`, rotates once at 4 MB, and can be
moved with `JEV_APPROVAL_LOG` or disabled with `JEV_APPROVAL_LOG_MAX_BYTES=0`.

- `jevlog.py` reads the live and `.1` generations and rejects schema drift.
- `logstats.py` reports outcomes, rules, errors, token/cost totals, p50/p95 latency,
  near-threshold counts, policy/question versions, and replay agreement.
- `sweep.py` replays candidate thresholds through `plugin/jev_policy.py` and prints what
  **would** change. It never writes or applies a value.

The decision log is evidence from your traffic, but only for commands Hermes core routed to
the approval provider. It is not a sample of all commands or all users.

## Frozen regression set

```bash
python3 benchmarks/check_holdout.py
python3 benchmarks/check_pairs.py
```

`benchmarks/fixtures/approval_holdout.jsonl` contains 24 synthetic commands, human labels,
and frozen Jev-style answers. Its provenance file pins SHA-256, byte count, case count,
policy version, and question fingerprint before scoring. Curation is drop-never-relabel.

`check_holdout.py` reports false allows separately and fails on any false allow. Friction
(false escalations/denials) is reported but never averaged against that safety bar.
`check_pairs.py` checks ordering for literal-vs-executed text, encoded execution,
destructive tails, `--force-with-lease` vs `--force`, secret read vs exfiltration, and
operator policy vs self-advocacy.

This fixture tests policy composition, not live model quality. Threshold changes require a
separate reviewed change supported by both real-log analysis and regression evidence.

## Live evidence

[`METRICS.md`](./METRICS.md) documents live provider benchmarks and the independent
live-sandbox study. Those numbers include provider behavior; the frozen checks above do not.
