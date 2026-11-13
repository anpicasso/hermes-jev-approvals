#!/usr/bin/env python3
"""Offline: the command cap is sized to Jev's context and shrinks on max_tokens_exceeded.

No API key, no network. Jev 1.13/1.14: 64k tokens per request, 32k per question
(docs.typesafe.ai/models#context-length).
"""
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import urllib.error

_HERE = pathlib.Path(__file__).resolve().parent
os.environ["JEV_APPROVAL_LOG"] = str(pathlib.Path(tempfile.mkdtemp()) / "decisions.jsonl")
spec = importlib.util.spec_from_file_location("jev_context_cap", _HERE.parent / "__init__.py")
jev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jev)

FULL = {"verdict": {"choice": "APPROVE", "confidence": 0.9},
        "blast_radius": {"score": 0.1}, "self_advocating": {"noul": 0.01},
        "policy_allows": {"noul": 0.02}, "reads_secrets": {"noul": 0.01},
        "sends_outbound": {"noul": 0.01}}


def ask(command):
    msgs = [{"role": "system", "content": "You are a security reviewer for an AI coding agent."},
            {"role": "user", "content": f"The following command was flagged as: probe\n\n"
                                        f"<command>\n{command}\n</command>\n\nOne word."}]
    r = jev.JevClient(api_key="x").chat.completions.create(model="jev-latest", messages=msgs)
    return r.choices[0].message.content


# 1. A ~20k-char script — five times the old 4000 cap — goes out whole and can be APPROVEd.
sent = []
def ok_post(base_url, body, timeout, deadline=None):
    sent.append(len(body["state"]["command"]))
    return {"answers": FULL, "model": "jev-1.13.0", "usage": {}}
jev._post = ok_post
script = "python - <<'PY'\n" + "print('audit step')\n" * 1000 + "PY"
assert len(script) > 16000
assert ask(script) == "APPROVE", "a mid-size script was escalated for truncation"
assert sent == [len(script)], sent
print("1. 20k-char script judged whole and APPROVEd                     ok")

# 2. The real 400 body is classified as max_tokens_exceeded, and not retried by _post.
calls = {"n": 0}
def opener(req, timeout=None):
    calls["n"] += 1
    raise urllib.error.HTTPError(req.full_url, 400, "Bad Request", {},
                                 io.BytesIO(b'{"detail":{"error_type":"max_tokens_exceeded"}}'))
real_post = None  # jev2 below is a fresh load, so its _post is the unpatched one
spec2 = importlib.util.spec_from_file_location("jev_context_cap2", _HERE.parent / "__init__.py")
jev2 = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(jev2)
jev2._urlopen = opener
jev2._api_key = lambda base_url="": "test-key"
try:
    jev2._post("https://api.typesafe.ai/v1", {"state": {}}, 30.0)
    raise AssertionError("400 must raise")
except RuntimeError as exc:
    assert exc.error_class == "max_tokens_exceeded", exc.error_class
assert calls["n"] == 1, f"400 was retried {calls['n']} times"
print("2. 400 max_tokens_exceeded classified, not retried               ok")

# 3. Over context: halve and resend, and a cut command still can never be APPROVEd.
sizes = []
def shrinking_post(base_url, body, timeout, deadline=None):
    n = len(body["state"]["command"])
    sizes.append(n)
    if n > 20000:
        err = RuntimeError("Jev: HTTP 400 (state over Jev context)")
        jev._tag_error(err, attempts=1, status_code=400, error_class="max_tokens_exceeded")
        raise err
    return {"answers": FULL, "model": "jev-1.13.0", "usage": {}}
jev._post = shrinking_post
huge = "echo " + "\u4e00" * 100000 + " && rm -rf /tmp/x"
assert ask(huge) == "ESCALATE", "a command cut to fit context was APPROVEd"
assert len(sizes) == 3 and sizes[0] > sizes[1] > sizes[2] <= 20000, sizes
row = json.loads(pathlib.Path(os.environ["JEV_APPROVAL_LOG"]).read_text().splitlines()[-1])
assert row["truncated"] is True and row["rule"] == "truncated", row
print(f"3. over-context command shrunk {sizes} -> ESCALATE         ok")

# 4. At the floor, a further max_tokens_exceeded raises (core escalates) — no infinite loop.
sizes.clear()
def always_too_big(base_url, body, timeout, deadline=None):
    sizes.append(len(body["state"]["command"]))
    err = RuntimeError("Jev: HTTP 400 (state over Jev context)")
    jev._tag_error(err, attempts=1, status_code=400, error_class="max_tokens_exceeded")
    raise err
jev._post = always_too_big
try:
    ask(huge)
    raise AssertionError("must raise at the floor")
except RuntimeError:
    pass
assert len(sizes) == 3, sizes
print("4. floor reached -> raises, core escalates                       ok")

# 5. Cap reductions share ONE deadline and the audit row counts every HTTP attempt.
timeouts, budget = [], []
def slow_shrinking_post(base_url, body, timeout, deadline=None):
    timeouts.append(timeout)
    budget.append(deadline)
    n = len(body["state"]["command"])
    if n > 20000:
        err = RuntimeError("Jev: HTTP 400 (state over Jev context)")
        jev._tag_error(err, attempts=2, status_code=400, error_class="max_tokens_exceeded")
        raise err
    return {"answers": FULL, "model": "jev-1.13.0", "usage": {},
            jev._TRANSPORT_KEY: {"attempts": 1, "http_status": 200, "request_id": "r"}}
jev._post = slow_shrinking_post
assert ask(huge) == "ESCALATE"
assert len(budget) == 3 and budget[0] is not None and len(set(budget)) == 1, budget
row = json.loads(pathlib.Path(os.environ["JEV_APPROVAL_LOG"]).read_text().splitlines()[-1])
assert row["attempts"] == 5, row["attempts"]
print("5. one deadline across cap reductions, attempts summed (5)          ok")

# 6. Failure rows also count every attempt across reductions.
def always_too_big2(base_url, body, timeout, deadline=None):
    err = RuntimeError("Jev: HTTP 400 (state over Jev context)")
    jev._tag_error(err, attempts=1, status_code=400, error_class="max_tokens_exceeded")
    raise err
jev._post = always_too_big2
try:
    ask(huge)
    raise AssertionError("must raise at the floor")
except RuntimeError:
    pass
row = json.loads(pathlib.Path(os.environ["JEV_APPROVAL_LOG"]).read_text().splitlines()[-1])
assert row["ok"] is False and row["attempts"] == 3, row
print("6. failure row counts all 3 attempts                             ok")

# 7. _post honours a shared deadline that has already passed: no request is sent.
calls["n"] = 0
jev2._urlopen = opener
try:
    jev2._post("https://api.typesafe.ai/v1", {"state": {}}, 30.0, deadline=jev2.time.monotonic() - 1)
    raise AssertionError("expired deadline must raise")
except RuntimeError:
    pass
assert calls["n"] == 0, calls
print("7. expired shared deadline -> no request                         ok")
