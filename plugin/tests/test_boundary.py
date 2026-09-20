#!/usr/bin/env python3
"""The provider's egress boundary: where the command text and the API key may go.

Offline except for three loopback sockets in check 3: no credentials, no third party.
Every case here is a shape that leaked (or an ordinary command that would have been
mangled) before the fix, so each assert is a regression test:

  1. endpoint validation — https only; custom hosts allow optional key_env authentication
  2. host matching — an exact host or a real subdomain, never a raw suffix
  3. redirects — `Authorization` does not follow a cross-origin redirect
  4. redaction — URL/query credentials, `Cookie:`, `curl -u`, and the commands that
     must come out untouched
  5. the Jev Choice/Score contract — invalid data escalates, and never approves
"""
import http.server
import importlib.util
import io
import json
import os
import pathlib
import threading
import urllib.error
import urllib.request

os.environ["JEV_APPROVAL_LOG_MAX_BYTES"] = "0"

_HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("jev_boundary_probe", _HERE.parent / "__init__.py")
assert spec and spec.loader
jev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jev)

PROVIDER = "typesafe-jev"
_real_key, _real_open = jev._api_key, jev._urlopen
_stubs = (jev._key_from_runtime_provider, jev._key_from_dotenv, jev._setting, jev._core_redact)
# Do not let this machine's plugin settings decide the negative test cases.
jev._setting = lambda key, default=None: default


# --- 1. the endpoint is a credential boundary ----------------------------------------
ACCEPTED = ("", "  https://api.typesafe.ai/v1  ", "https://api.typesafe.ai",
            "https://openrouter.ai/api/alpha", "https://OPENROUTER.AI/api/alpha",
            "https://api.openrouter.ai/v1", "https://openrouter.ai:443/api/alpha",
            "https://openrouter.ai/api/alpha/", "https://notopenrouter.ai/api/alpha",
            "https://openrouter.ai.evil.example/api/alpha", "https://example.com/v1/systemone")
for candidate in ACCEPTED:
    assert jev._validated_base_url(candidate) == (candidate or jev.DEFAULT_BASE_URL).strip(), candidate

REFUSED = {
    "http://openrouter.ai/api/alpha": "https",                 # the key in cleartext
    "openrouter.ai/api/alpha": "https",                        # no scheme at all
    "ftp://openrouter.ai/x": "https",
    "//openrouter.ai/api/alpha": "https",

    "https://user:hunter2@openrouter.ai/api/alpha": "URL credentials",
    "https://openrouter.ai/api/alpha?api_key=AKIAdeadbeef": "query string",
    "https://openrouter.ai/api/alpha#frag": "fragment",
    "https://openrouter.ai:8443/api/alpha": "port",
    "https://openrouter.ai:99999/x": "invalid port",           # urlparse.port raises
}
for candidate, expected in REFUSED.items():
    try:
        jev._validated_base_url(candidate)
        raise AssertionError(f"{candidate!r} was accepted")
    except RuntimeError as exc:
        text = str(exc)
        assert PROVIDER in text and expected in text, (candidate, text)
        # a rejected endpoint can itself carry a credential: never echo it back
        for secret in ("hunter2", "AKIAdeadbeef"):
            assert secret not in text, (candidate, text)


# The refusal lands before anything is resolved or opened: no key, no socket.
def _no_key(base_url=""):
    raise AssertionError("the API key was resolved before the endpoint was validated")


def _no_socket(req, timeout=None):
    raise AssertionError("a socket was opened before the endpoint was validated")


try:
    jev._api_key, jev._urlopen = _no_key, _no_socket
    for candidate in ("http://evil.example/systemone", "https:///decisions"):
        try:
            jev._post(candidate, {"state": {}}, 5.0)
            raise AssertionError(f"_post accepted {candidate!r}")
        except RuntimeError:
            pass
finally:
    jev._api_key, jev._urlopen = _real_key, _real_open

assert jev.fetch_decision_models("http://evil.example") == []
assert jev.fetch_decision_models("https://notopenrouter.ai/api/alpha") == []

# A custom HTTPS endpoint may be anonymous or use an explicit plugin-level key_env.
_setting_before_custom = jev._setting
_open_before_custom = jev._urlopen
try:
    jev._setting = lambda key, default=None: "NEW_JEV_KEY" if key == "key_env" else default
    for hostless in ("https:", "https://", "https:///systemone"):
        try:
            jev._validated_base_url(hostless)
            raise AssertionError(f"host-less endpoint {hostless!r} was accepted")
        except RuntimeError as exc:
            assert "host" in str(exc), (hostless, exc)
    custom = "https://jev.example/v1/systemone"
    assert jev._validated_base_url(custom) == custom
    assert jev._route_for(custom) == ("", "", "")
    assert jev.fetch_decision_models(custom) == []
    requests = []

    def _custom_open(req, timeout=None):
        requests.append(
            (
                req.full_url,
                req.get_header("Authorization"),
                req.get_header("Accept"),
                req.get_header("User-agent"),
            )
        )
        response = io.BytesIO(b"{}")
        response.status, response.headers = 200, {}
        return response

    jev._urlopen = _custom_open
    jev._setting = lambda key, default=None: default
    assert jev._api_key(custom) == ""
    assert isinstance(jev._post(custom, {"state": {}}, 5.0), dict)
    assert requests == [(custom, None, "application/json", "hermes-jev-approvals/0.3")], requests

    requests.clear()
    jev._setting = lambda key, default=None: "NEW_JEV_KEY" if key == "key_env" else default
    os.environ["NEW_JEV_KEY"] = "fake-custom-key"
    assert isinstance(jev._post(custom, {"state": {}}, 5.0), dict)
    assert requests == [
        (custom, "Bearer fake-custom-key", "application/json", "hermes-jev-approvals/0.3")
    ], requests
finally:
    jev._setting = _setting_before_custom
    jev._urlopen = _open_before_custom
    os.environ.pop("NEW_JEV_KEY", None)
print("1. https boundary; custom hosts support anonymous or explicit-key use ok")

# --- 2. exact host or a real subdomain, never a raw suffix ----------------------------
for host, expected in (("openrouter.ai", True), ("api.openrouter.ai", True),
                       ("OPENROUTER.AI", True), ("openrouter.ai.", False),
                       ("notopenrouter.ai", False), ("xopenrouter.ai", False),
                       ("openrouter.ai.evil.example", False), ("", False)):
    assert jev._host_matches(host, "openrouter.ai") is expected, host

# A lookalike must not reach the decisions route or inherit the aggregator's credential.
assert jev._route_for("https://notopenrouter.ai/api/alpha")[0] == ""
assert jev._route_for("https://openrouter.ai/api/alpha")[0] == "/decisions"
assert jev._aggregator_for("notopenrouter.ai") is None
assert jev._aggregator_for("xopenrouter.ai") is None
assert jev._aggregator_for("api.openrouter.ai") == ("openrouter", "OPENROUTER_API_KEY")

try:
    asked = []
    jev._key_from_runtime_provider = lambda requested: asked.append(requested) or ""
    jev._key_from_dotenv = lambda: ""
    jev._setting = lambda key, default=None: default
    os.environ["TYPESAFE_API_KEY"] = "fake-typesafe-key"
    assert jev._api_key("https://notopenrouter.ai/api/alpha") == ""
    assert asked == [], asked               # never the OpenRouter or TypeSafe pool
    os.environ["NEW_JEV_KEY"] = "fake-custom-key"
    jev._setting = lambda key, default=None: "NEW_JEV_KEY" if key == "key_env" else default
    assert jev._api_key("https://notopenrouter.ai/api/alpha") == "fake-custom-key"
    # A real aggregator host with no aggregator credential stored raises rather than
    # falling back to TypeSafe's key: the two credentials are not interchangeable.
    jev._setting = lambda key, default=None: default
    try:
        jev._api_key("https://openrouter.ai/api/alpha")
        raise AssertionError("the openrouter route fell back to the TypeSafe key")
    except RuntimeError as exc:
        assert "openrouter" in str(exc), exc

finally:
    jev._key_from_runtime_provider, jev._key_from_dotenv = _stubs[:2]
    jev._setting = lambda key, default=None: default
    os.environ.pop("TYPESAFE_API_KEY", None)
    os.environ.pop("NEW_JEV_KEY", None)
print("2. exact matching; custom hosts use only their configured key         ok")

# --- 3. a cross-origin redirect must not carry the credential -------------------------
sink_hits, redirector_hits = [], []


def _handler(record=None):
    """A server whose scripted answers are replaced through `RequestHandlerClass.responses`."""

    class Handler(http.server.BaseHTTPRequestHandler):
        responses = []

        def _respond(self):
            if record is not None:
                record.append({"method": self.command, "path": self.path,
                               "auth": self.headers.get("Authorization")})
            scripted = type(self).responses
            body, code, location = scripted.pop(0) if scripted else (b"{}", 200, None)
            self.send_response(code)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = _respond

        def log_message(self, *args):
            pass

    return Handler


redirector = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(redirector_hits))
sink = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(sink_hits))
same_origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler())
for server in (redirector, sink, same_origin):
    threading.Thread(target=server.serve_forever, daemon=True).start()

_auth = {"Authorization": "Bearer sk-fake-local-key", "Content-Type": "application/json"}

# two ports are two origins: the POST must not arrive at the second one
redirector.RequestHandlerClass.responses = [
    (b"", 302, f"http://127.0.0.1:{sink.server_address[1]}/decisions")]
request = urllib.request.Request(f"http://127.0.0.1:{redirector.server_address[1]}/systemone",
                                 data=b'{"x": 1}', headers=_auth)
try:
    jev._urlopen(request, 5)
    raise AssertionError("a cross-origin redirect was followed")
except urllib.error.HTTPError as exc:
    assert exc.code == 302, exc
assert [hit["path"] for hit in redirector_hits] == ["/systemone"], redirector_hits
assert not sink_hits, f"the credential followed the redirect: {sink_hits}"

# same-origin: still followed, so a host that moves its own path keeps working
same_origin.RequestHandlerClass.responses = [(b"", 302, "/moved"), (b'{"ok": true}', 200, None)]
request = urllib.request.Request(f"http://127.0.0.1:{same_origin.server_address[1]}/a",
                                 data=b'{"x": 1}', headers=_auth)
with jev._urlopen(request, 5) as response:
    assert response.status == 200 and json.load(response) == {"ok": True}

# and _post treats a refused redirect as final: one attempt, no retry
attempts = []


def _refuse_redirect(req, timeout=None):
    attempts.append(req.full_url)
    raise urllib.error.HTTPError(req.full_url, 302, "refused", {}, None)


try:
    jev._api_key, jev._urlopen = lambda base_url="": "fake-key", _refuse_redirect
    try:
        jev._post("https://api.typesafe.ai/v1", {"state": {}}, 5.0)
        raise AssertionError("a refused redirect did not raise")
    except RuntimeError as exc:
        assert getattr(exc, "status_code", None) == 302, exc
        assert "redirect" in str(exc), exc
finally:
    jev._api_key, jev._urlopen = _real_key, _real_open
assert len(attempts) == 1, f"a refused redirect was retried {len(attempts)} times"
for server in (redirector, sink, same_origin):
    server.shutdown()
print("3. cross-origin redirects refused, same-origin still followed         ok")

# --- 4. redaction: the credential shapes, and the false positives ---------------------
# Literal FAKE material throughout, so a secret scanner has nothing to find.
FAKE_GH = "ghp_" + "FAKEFAKEFAKEFAKEFAKEFAKEFAKE"
LEAKS = [
    "curl -u admin:hunter2 https://api.example.com/v1/data",
    "curl --user=admin:hunter2 https://api.example.com",
    "curl -uadmin:hunter2 https://api.example.com",
    "curl -u 'admin:hunter2' https://api.example.com",
    "curl --user :hunter2 https://api.example.com",
    "curl -H 'Cookie: session=abc123deadbeef; csrf=csrfvalue' https://api.example.com",
    "curl --cookie 'session=abc123deadbeef' https://api.example.com",
    "curl -b session=abc123deadbeef https://api.example.com",
    "curl 'https://user:s3cretpw@api.example.com/v1'",
    f"git remote set-url origin https://{FAKE_GH}@github.com/x/y.git",
    "curl 'https://api.example.com/v1?api_key=AKIAdeadbeef&page=2'",
    "curl 'https://api.example.com/v1?token=tokvalue&signature=sigvalue'",
    "wget 'https://api.example.com/x?access_token=accvalue'",
]
SECRETS = ("hunter2", "s3cretpw", "abc123deadbeef", "csrfvalue", "sigvalue",
           "tokvalue", "accvalue", FAKE_GH)
# Ordinary commands carrying the same letters: nothing here is a credential.
UNTOUCHED = [
    "sudo -u www-data systemctl restart nginx",
    "sort -u /tmp/words.txt",
    "uniq -u report.txt",
    "python3 -u -m http.server 8080",
    "grep -b -n 'pattern' src/app.py",
    "curl -b cookies.txt https://api.example.com/",
    "curl --cookie-jar jar.txt https://api.example.com/",
    "docker exec -u 1000:1000 web sh -c 'ls'",
    "docker run -p 8080:80 -d nginx",
    "psql --host=x --no-password --dbname=postgres --command='SELECT 1'",
    "ssh -i key.pem git@github.com",
    "git clone git@github.com:org/repo.git",
]


def _no_core(text):
    raise ImportError("simulated: core redactor not importable")


_real_core = jev._core_redact
for label, fake_core in (("core + shell passes", None), ("local fallback", _no_core)):
    jev._core_redact = _real_core if fake_core is None else fake_core
    try:
        for text in LEAKS:
            out = jev._redact(text)
            leaked = [s for s in SECRETS if s in out]
            assert not leaked, f"{label}: {leaked} survived {text!r} -> {out!r}"
        for text in UNTOUCHED:
            out = jev._redact(text)
            assert out == text, f"{label}: false positive on {text!r} -> {out!r}"
        # the passes are idempotent: a second pass over their own output is a no-op
        for text in LEAKS:
            once = jev._redact(text)
            assert jev._redact(once) == once, (label, text, once)
    finally:
        jev._core_redact = _real_core
print("4. url/query credentials, Cookie, curl -u masked; ordinary input intact  ok")

# --- 5. the full Jev Choice/Score contract -------------------------------------------
CRITERIA = jev.QUESTIONS["blast_radius"]["criteria"]
# Verbatim answer shape captured from a live /v1/systemone response.
LIVE = {"verdict": {"type": "choice", "choice": "APPROVE", "confidence": 0.99,
                    "probabilities": {"APPROVE": 1.0, "DENY": 0.0, "ESCALATE": 0.0}},
        "policy_allows": {"type": "noul", "noul": 0.11},
        "blast_radius": {"type": "score", "score": 0.0, "confidence": 0.99,
                         "legend": {str(i): c for i, c in enumerate(CRITERIA)},
                         "probabilities": {"0": 1.0, "1": 0.0, "2": 0.0}},
        "self_advocating": {"type": "noul", "noul": 0.03},
        "reads_secrets": {"type": "noul", "noul": 0.12},
        "sends_outbound": {"type": "noul", "noul": 0.07}}


def guardian(command="ls -la"):
    return [{"role": "system", "content": "You are a security reviewer for an AI coding agent."},
            {"role": "user", "content": (f"The following command was flagged as: inspection\n\n"
                                         f"<command>\n{command}\n</command>\n\n"
                                         "Respond with exactly one word.")}]


def verdict_for(answers, command="ls -la"):
    jev._post = lambda base_url, body, timeout: {"answers": answers, "model": "jev-1.13.0",
                                                 "usage": {"input_tokens": 1, "output_tokens": 1}}
    return jev.JevClient(api_key="x").chat.completions.create(
        model="jev-latest", messages=guardian(command)).choices[0].message.content


CASES = [
    # (label, answers, expected verdict, or "raise:<text the message must name>")
    ("live payload", LIVE, "APPROVE"),
    ("choice case is normalized",
     dict(LIVE, verdict=dict(LIVE["verdict"], choice="approve")), "APPROVE"),
    ("choice without probabilities",
     dict(LIVE, verdict={"choice": "DENY", "confidence": 0.9}), "DENY"),
    ("absent choice escalates", dict(LIVE, verdict={"confidence": 0.99}), "ESCALATE"),
    ("absent verdict escalates", {k: v for k, v in LIVE.items() if k != "verdict"}, "ESCALATE"),
    ("absent confidence cannot approve", dict(LIVE, verdict={"choice": "APPROVE"}), "ESCALATE"),
    ("a tie for the top option is allowed",
     dict(LIVE, verdict={"choice": "APPROVE", "confidence": 0.99,
                         "probabilities": {"APPROVE": 0.5, "DENY": 0.5, "ESCALATE": 0.0}}),
     "APPROVE"),
    ("choice outside the option set",
     dict(LIVE, verdict={"choice": "ALLOW", "confidence": 0.99}), "raise:verdict.choice"),
    ("choice is not a string", dict(LIVE, verdict={"choice": 3, "confidence": 0.99}),
     "raise:verdict.choice"),
    ("verdict is not an object", dict(LIVE, verdict="APPROVE"), "raise:verdict is not"),
    ("confidence is not a number",
     dict(LIVE, verdict={"choice": "APPROVE", "confidence": "high"}), "raise:confidence"),
    ("confidence above 1", dict(LIVE, verdict={"choice": "APPROVE", "confidence": 5.0}),
     "raise:confidence"),
    ("confidence is a bool", dict(LIVE, verdict={"choice": "APPROVE", "confidence": True}),
     "raise:confidence"),
    ("confidence is NaN", dict(LIVE, verdict={"choice": "APPROVE", "confidence": float("nan")}),
     "raise:confidence"),
    ("probabilities miss an option",
     dict(LIVE, verdict={"choice": "APPROVE", "confidence": 0.99,
                         "probabilities": {"APPROVE": 0.9, "DENY": 0.1}}),
     "raise:probabilities"),
    ("probabilities carry an unknown option",
     dict(LIVE, verdict={"choice": "APPROVE", "confidence": 0.99,
                         "probabilities": {"APPROVE": 0.9, "DENY": 0.1, "MAYBE": 0.0}}),
     "raise:probabilities"),
    ("probabilities do not sum to 1",
     dict(LIVE, verdict={"choice": "APPROVE", "confidence": 0.99,
                         "probabilities": {"APPROVE": 0.5, "DENY": 0.1, "ESCALATE": 0.1}}),
     "raise:sum"),
    ("probabilities contradict the choice",
     dict(LIVE, verdict={"choice": "APPROVE", "confidence": 0.99,
                         "probabilities": {"APPROVE": 0.1, "DENY": 0.9, "ESCALATE": 0.0}}),
     "raise:argmax"),
    ("probability outside [0,1]",
     dict(LIVE, verdict={"choice": "APPROVE", "confidence": 0.99,
                         "probabilities": {"APPROVE": 1.5, "DENY": 0.0, "ESCALATE": 0.0}}),
     "raise:probabilities[APPROVE]"),
    ("score just over the top level", dict(LIVE, blast_radius={"score": 2.0001}),
     "raise:rubric"),
    ("score far out of range", dict(LIVE, blast_radius={"score": 9.9}), "raise:rubric"),
    ("score is a bool", dict(LIVE, blast_radius={"score": True}), "raise:blast_radius"),
    ("score is a string", dict(LIVE, blast_radius={"score": "1.0"}), "raise:blast_radius"),
    ("score missing", dict(LIVE, blast_radius={"confidence": 0.9}), "raise:blast_radius"),
    ("score answer missing", {k: v for k, v in LIVE.items() if k != "blast_radius"},
     "raise:blast_radius"),
    ("score confidence out of range",
     dict(LIVE, blast_radius={"score": 1.0, "confidence": 1.4}), "raise:blast_radius.conf"),
    ("score probabilities miss a level",
     dict(LIVE, blast_radius={"score": 1.0, "probabilities": {"0": 0.1, "1": 0.9}}),
     "raise:probabilities"),
    ("score probabilities do not sum to 1",
     dict(LIVE, blast_radius={"score": 1.0, "probabilities": {"0": 0.1, "1": 0.1, "2": 0.1}}),
     "raise:sum"),
    ("score just under the top level", dict(LIVE, blast_radius={"score": 1.5}), "APPROVE"),
    ("real fractional score is in range", dict(LIVE, blast_radius={"score": 1.74}), "ESCALATE"),
    ("noul out of range", dict(LIVE, reads_secrets={"noul": 1.4}), "raise:reads_secrets"),
]
for label, answers, expected in CASES:
    try:
        got = verdict_for(answers)
    except RuntimeError as exc:
        assert expected.startswith("raise:"), f"{label}: raised unexpectedly ({exc})"
        assert expected.split(":", 1)[1] in str(exc), f"{label}: wrong reason ({exc})"
    else:
        assert got == expected, f"{label}: got {got}, wanted {expected}"

# An envelope that is not an answers object at all is a failure, not a verdict.
for label, payload in (("answers is a list", {"answers": []}),
                       ("answers is missing", {"model": "jev-1.13.0"}),
                       ("response is a list", None)):
    jev._post = ((lambda base_url, body, timeout: []) if payload is None
                 else (lambda base_url, body, timeout, p=payload: dict(p, model="jev-1.13.0")))
    try:
        jev.JevClient(api_key="x").chat.completions.create(model="jev-latest",
                                                           messages=guardian())
        raise AssertionError(f"{label} was accepted")
    except RuntimeError:
        pass
print("5. Choice option set, confidence, distribution and Score range all checked  ok")

print("\nall 5 boundary checks pass")
