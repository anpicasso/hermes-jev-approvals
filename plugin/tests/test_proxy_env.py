#!/usr/bin/env python3
"""Offline check: the provider honours a proxy set in the environment AFTER import.

Hermes discovers plugins before it loads ~/.hermes/.env, so HTTPS_PROXY often appears only
after this module is imported. A urllib opener built at import time snapshots the proxy
environment and then bypasses the proxy for good. No API key, no network: a local socket
plays the proxy and records the CONNECT it receives.
"""
import importlib.util
import os
import pathlib
import socket
import tempfile
import threading
import urllib.request

_HERE = pathlib.Path(__file__).resolve().parent
os.environ["JEV_APPROVAL_LOG"] = str(pathlib.Path(tempfile.mkdtemp()) / "decisions.jsonl")
for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
             "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
    os.environ.pop(name, None)

# 1. import with no proxy configured, as at Hermes plugin discovery
spec = importlib.util.spec_from_file_location("jev_proxy_probe", _HERE.parent / "__init__.py")
assert spec and spec.loader
jev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jev)

# 2. a fake proxy that records the first request line, then refuses the tunnel
seen = []
server = socket.socket()
server.bind(("127.0.0.1", 0))
server.listen(1)


def serve():
    conn, _ = server.accept()
    with conn:
        seen.append(conn.recv(4096).split(b"\r\n", 1)[0].decode())
        conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")


threading.Thread(target=serve, daemon=True).start()

# 3. the proxy appears only now, as when Hermes loads .env after plugin discovery
os.environ["HTTPS_PROXY"] = f"http://127.0.0.1:{server.getsockname()[1]}"
req = urllib.request.Request("https://openrouter.ai/api/alpha/decisions", data=b"{}")
try:
    jev._urlopen(req, 5)
except Exception:
    pass  # the fake proxy refuses the tunnel; only the CONNECT matters

assert seen and seen[0].startswith("CONNECT openrouter.ai:443"), (
    f"request bypassed an HTTPS_PROXY set after import (proxy saw {seen!r})")
print("1. HTTPS_PROXY set after import is honoured                           ok")

# 4. the model-list path (provider discovery) must use the same per-call opener, not the
#    stdlib global one, which also snapshots the proxy environment on first use.
for name in ("HTTPS_PROXY", "https_proxy"):
    os.environ.pop(name, None)
try:
    urllib.request.urlopen("https://127.0.0.1:9/", timeout=1)  # installs the global opener, no proxy
except Exception:
    pass
seen.clear()
server2 = socket.socket()
server2.bind(("127.0.0.1", 0))
server2.listen(1)


def serve2():
    conn, _ = server2.accept()
    with conn:
        seen.append(conn.recv(4096).split(b"\r\n", 1)[0].decode())
        conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")


threading.Thread(target=serve2, daemon=True).start()
os.environ["HTTPS_PROXY"] = f"http://127.0.0.1:{server2.getsockname()[1]}"
assert jev.fetch_decision_models("https://openrouter.ai/api/alpha") == []  # never raises
assert seen and seen[0].startswith("CONNECT openrouter.ai:443"), (
    f"model list bypassed an HTTPS_PROXY set after import (proxy saw {seen!r})")
print("2. model-list fetch honours HTTPS_PROXY set after import             ok")
print("\nall 2 proxy-env checks pass")
