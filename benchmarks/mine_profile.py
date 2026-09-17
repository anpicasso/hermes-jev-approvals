#!/usr/bin/env python3
"""Mine one profile's sessions. Run per-profile so an OOM cannot lose the others.

The combined run died silently at 400 files on a 7GB box: session dumps reach
hundreds of MB and json.loads of a whole file plus the nested re-parse of every
embedded JSON string blows the heap. Fix: per-profile invocation, a hard RSS
ceiling, and append-per-file output.

Usage: mine_profile.py <profile-name> [max_mb]
"""
import json, os, pathlib, resource, sys, time
from collections import Counter

import os
import pathlib

# Resolve Hermes' install and home from the environment so this runs on any machine.
HERMES_HOME = pathlib.Path(os.environ.get("HERMES_HOME") or (pathlib.Path.home() / ".hermes"))
HERMES_SRC = pathlib.Path(os.environ.get("HERMES_SRC") or (HERMES_HOME / "hermes-agent"))

sys.path.insert(0, str(HERMES_SRC))
from tools.approval_detection import detect_dangerous_command, detect_hardline_command

def profile_home(name: str) -> pathlib.Path:
    """`default` is $HERMES_HOME itself; every other profile lives under profiles/."""
    return HERMES_HOME if name == "default" else HERMES_HOME / "profiles" / name
TOOLS = ("terminal", "execute_code")
# ponytail: hard RSS ceiling instead of clever streaming. A killed worker on one
# oversized dump is fine; losing 900 files of progress is not.
RSS_LIMIT_MB = 2200
MAX_FILE_MB = 40


def walk(obj, depth=0):
    if depth > 40:
        return
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from walk(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v, depth + 1)
    elif isinstance(obj, str) and 2 < len(obj) < 2_000_000 and obj[0] in "{[":
        try:
            yield from walk(json.loads(obj), depth + 1)
        except Exception:
            return


def calls_from(path):
    try:
        data = json.loads(path.read_text(errors="replace"))
    except Exception:
        return
    for d in walk(data):
        fn = d.get("function") if isinstance(d.get("function"), dict) else None
        name = (fn or d).get("name")
        if name not in TOOLS:
            continue
        args = (fn or d).get("arguments", (fn or d).get("input"))
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                continue
        if not isinstance(args, dict):
            continue
        payload = args.get("command") if name == "terminal" else args.get("code")
        if isinstance(payload, str) and payload.strip():
            yield name, payload.strip()


if __name__ == "__main__":
    prof = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else RSS_LIMIT_MB
    resource.setrlimit(resource.RLIMIT_AS, (limit * 1024 * 1024, limit * 1024 * 1024))

    out = pathlib.Path(__file__).resolve().parent / f"real_{prof}.json"
    sess = profile_home(prof) / "sessions"
    seen, rows = set(), []
    files = skipped = errors = 0
    t0 = time.time()
    for path in sorted(sess.glob("*.json")):
        files += 1
        if path.stat().st_size > MAX_FILE_MB * 1024 * 1024:
            skipped += 1
            continue
        try:
            for tool, payload in calls_from(path):
                key = payload[:300]
                if key in seen:
                    continue
                seen.add(key)
                probe = payload if tool == "terminal" else f"execute_code <<'PY'\n{payload}\nPY"
                hard, hd = detect_hardline_command(probe)[:2]
                dang, dd = detect_dangerous_command(probe)[:2]
                rows.append({"command": payload[:4000], "tool": tool, "profile": prof,
                             "hardline": bool(hard), "dangerous": bool(dang),
                             "description": (hd if hard else dd) or ""})
        except MemoryError:
            errors += 1
        if files % 100 == 0:
            out.write_text(json.dumps(rows, indent=1))
            print(f"  {files} files, {len(rows)} unique, {time.time()-t0:.0f}s", flush=True)

    out.write_text(json.dumps(rows, indent=1))
    print(f"{prof}: {files} files ({skipped} oversized, {errors} OOM), "
          f"{len(rows)} unique payloads in {time.time()-t0:.0f}s")
    print(f"  tools: {dict(Counter(r['tool'] for r in rows))}")
    print(f"  hardline {sum(r['hardline'] for r in rows)}, "
          f"dangerous {sum(r['dangerous'] and not r['hardline'] for r in rows)}, "
          f"clean {sum(not r['dangerous'] and not r['hardline'] for r in rows)}")
    print(f"-> {out}")
