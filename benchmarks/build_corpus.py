#!/usr/bin/env python3
"""Merge per-profile mined commands into one pool, redacted, with metrics.

The raw commands contain live secrets (a working bot token appeared verbatim in one
of them), so nothing raw may reach a public repo. This produces:
  - pool.json      : redacted commands, for local benchmarking only (gitignored)
  - corpus.md      : aggregate metrics only, safe to publish

Redaction is conservative: anything resembling a token, key, password or long
base64/hex blob is replaced before the command is written anywhere.
"""
import json, pathlib, re, sys
from collections import Counter

HERE = pathlib.Path(__file__).resolve().parent
OUT_POOL = HERE / "pool.json"
OUT_MD = HERE / "corpus.md"

SECRET_PATTERNS = [
    # assignments: KEY=value / "key": "value"
    (re.compile(r"((?:[A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|COOKIE|SESSION)[A-Z0-9_]*)\s*[=:]\s*)"
                r"['\"]?[^\s'\"&|;]{6,}", re.I), r"\1<redacted>"),
    # bearer / basic headers
    (re.compile(r"(Bearer|Basic)\s+[A-Za-z0-9._\-+/=]{10,}", re.I), r"\1 <redacted>"),
    # dotted-triple tokens (JWT and similar)
    (re.compile(r"\b[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{20,}\b"), "<redacted-token>"),
    # long opaque blobs
    (re.compile(r"\b(?:sk|pk|ghp|gho|xox[abps]|AIza|AKIA)[A-Za-z0-9_\-]{12,}\b"), "<redacted-key>"),
    (re.compile(r"\b[A-Fa-f0-9]{40,}\b"), "<redacted-hex>"),
]


def redact(text: str) -> str:
    for rx, repl in SECRET_PATTERNS:
        text = rx.sub(repl, text)
    return text


def load():
    """Merge the per-profile mines, keeping each row's own profile label.

    ponytail: do NOT relabel by file name. real_commands.json came from the combined
    miner, which walks every profile and stamps each row with the profile it came from;
    overwriting that with "default" produced per-profile counts that were simply wrong
    (one profile vanished entirely once its rows deduped against the combined file).
    Per-profile files carry the same field, so trusting the row is correct for both.
    """
    rows, sources = [], []
    for path in sorted(HERE.glob("real_*.json")):
        data = json.loads(path.read_text())
        rows += data
        sources.append(f"{path.stem.removeprefix('real_')}={len(data)}")
    return rows, sources


if __name__ == "__main__":
    rows, sources = load()
    seen, pool = set(), []
    for r in rows:
        cmd = redact(r["command"])
        key = cmd[:300]
        if key in seen:
            continue
        seen.add(key)
        pool.append({**r, "command": cmd})

    OUT_POOL.write_text(json.dumps(pool, indent=1))

    n = len(pool)
    hard = [r for r in pool if r["hardline"]]
    dang = [r for r in pool if r["dangerous"] and not r["hardline"]]
    clean = [r for r in pool if not r["dangerous"] and not r["hardline"]]
    by_prof = Counter(r["profile"] for r in pool)
    by_tool = Counter(r["tool"] for r in pool)
    descs = Counter(r["description"] for r in pool if r["description"])

    lines = [
        "# Real-command corpus",
        "",
        "Mined from this machine's own Hermes session dumps across three profiles. Commands",
        "are what the agent actually ran, not invented test cases. **Aggregate metrics only:**",
        "the raw commands stay local because they contain live credentials.",
        "",
        f"- unique payloads: **{n}** ({', '.join(sources)})",
        f"- by tool: {dict(by_tool)}",
        f"- by profile: {dict(by_prof)}",
        "",
        "Labels come from Hermes' own detectors (`tools/approval_detection.py`), not from",
        "hand-labelling — `detect_hardline_command` and `detect_dangerous_command` on the exact",
        "string the approval gate sees (`execute_code` payloads wrapped as the gate wraps them).",
        "",
        f"| bucket | count | share |",
        f"|---|---|---|",
        f"| hardline (auto-blocked) | {len(hard)} | {len(hard)/n:.1%} |",
        f"| dangerous (approval prompt) | {len(dang)} | {len(dang)/n:.1%} |",
        f"| clean (runs freely) | {len(clean)} | {len(clean)/n:.1%} |",
        "",
        "## What actually gets flagged",
        "",
        "| count | detector description |",
        "|---|---|",
    ]
    for desc, c in descs.most_common(20):
        lines.append(f"| {c} | {desc[:76]} |")
    lines += [
        "",
        f"So on real traffic **{len(dang)+len(hard)} of {n} ({(len(dang)+len(hard))/n:.1%})** commands",
        "reach the approval gate at all. That ratio is the cost multiplier for any approval",
        "judgment: everything else never triggers a call.",
        "",
    ]
    OUT_MD.write_text("\n".join(lines))
    print("\n".join(lines[:26]))
    print(f"\n-> {OUT_POOL} (local only), {OUT_MD} (publishable)")
    # secrets must not survive into the pool
    # A credential must not survive redaction. Generic on purpose: the original assert
    # named one specific platform's token, which leaked what this machine is used for.
    assert not re.search(r"(?i)(TOKEN|SECRET|PASSWORD|APIKEY)\s*=\s*[A-Za-z0-9_\-]{12,}",
                         json.dumps(pool)), "a credential survived redaction"
    print("redaction self-check passed")
