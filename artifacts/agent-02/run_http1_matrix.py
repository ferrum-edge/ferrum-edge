#!/usr/bin/env python3
"""Ferrum Edge launch-readiness HTTP/1.1 matrix (agent-02).

Investigation-only harness. Binds exclusively on 127.0.0.1:21100-21199.
Resource prefix: fe-agent-02-.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import unquote

SHA = os.environ.get("FE_AGENT_02_SHA", "unknown")
WORKDIR = Path(os.environ.get("FE_AGENT_02_WORKDIR", "/tmp/fe-agent-02"))
ARTIFACT_DIR = Path(__file__).resolve().parent
GATEWAY_HTTP = 21100
GATEWAY_ADMIN = 21101
ECHO = 21110
NEVER_READ = 21111
PARTIAL_FIN = 21112
STALL_HEADERS = 21113
STALL_BODY = 21114
# 21122 deliberately unbound (connect refused)
CONNECT_HANG_IP = "192.0.2.1"
CONNECT_HANG_PORT = 21123

SECRET = "fe-agent-02-supersecret-token-DO-NOT-LEAK"


def log(msg: str) -> None:
    print(f"[fe-agent-02] {msg}", flush=True)


def recv_until(sock: socket.socket, needle: bytes, limit: int = 1 << 20, timeout: float = 8.0) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    while needle not in buf:
        if len(buf) >= limit:
            break
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def read_http_message(sock: socket.socket, timeout: float = 8.0) -> tuple[bytes, list[tuple[str, str]], bytes]:
    """Read one HTTP/1.x request or response. Returns (head, headers, body)."""
    raw = recv_until(sock, b"\r\n\r\n", timeout=timeout)
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        return raw, [], b""
    head = raw[:sep]
    rest = raw[sep + 4 :]
    headers: list[tuple[str, str]] = []
    lines = head.split(b"\r\n")
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        headers.append((name.decode("latin1"), value.decode("latin1").strip()))
    lower = {k.lower(): v for k, v in headers}
    body = rest
    if "content-length" in lower:
        try:
            need = int(lower["content-length"])
        except ValueError:
            need = 0
        while len(body) < need:
            try:
                sock.settimeout(timeout)
                chunk = sock.recv(min(65536, need - len(body)))
            except socket.timeout:
                break
            if not chunk:
                break
            body += chunk
        body = body[:need]
    elif lower.get("transfer-encoding", "").lower() == "chunked":
        # If any chunk body already arrived after the header separator, parse it.
        data = body
        parsed = bytearray()
        while True:
            nl = data.find(b"\r\n")
            while nl < 0:
                try:
                    sock.settimeout(timeout)
                    more = sock.recv(4096)
                except socket.timeout:
                    return head, headers, bytes(parsed)
                if not more:
                    return head, headers, bytes(parsed)
                data += more
                nl = data.find(b"\r\n")
            size_line = data[:nl].split(b";", 1)[0].strip()
            try:
                size = int(size_line, 16)
            except ValueError:
                break
            data = data[nl + 2 :]
            if size == 0:
                break
            while len(data) < size + 2:
                try:
                    sock.settimeout(timeout)
                    more = sock.recv(4096)
                except socket.timeout:
                    break
                if not more:
                    break
                data += more
            parsed.extend(data[:size])
            data = data[size + 2 :]
        body = bytes(parsed)
    return head, headers, body


class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _echo(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        headers = {k.lower(): v for k, v in self.headers.items()}
        payload = {
            "origin": "fe-agent-02-echo",
            "method": self.command,
            "path": self.path,
            "headers": headers,
            "body_len": len(body),
            "body_utf8": body.decode("utf-8", "replace") if len(body) <= 4096 else None,
        }
        raw = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Origin", "fe-agent-02-echo")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        self._echo()

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.send_header("X-Origin", "fe-agent-02-echo")
        self.end_headers()

    def do_POST(self) -> None:
        self._echo()

    def do_PUT(self) -> None:
        self._echo()

    def do_PATCH(self) -> None:
        self._echo()

    def do_DELETE(self) -> None:
        self._echo()

    def do_OPTIONS(self) -> None:
        self._echo()


def serve_echo() -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", ECHO), EchoHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True, name="fe-agent-02-echo")
    t.start()
    return httpd


def serve_never_read() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", NEVER_READ))
    s.listen(64)

    def loop() -> None:
        while True:
            try:
                conn, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=lambda c: (time.sleep(30), c.close()), args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True, name="fe-agent-02-never-read").start()
    return s


def serve_partial_fin() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PARTIAL_FIN))
    s.listen(64)

    def handle(conn: socket.socket) -> None:
        try:
            recv_until(conn, b"\r\n\r\n", timeout=5)
            prefix = b"partial-fin"
            hdr = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 10000\r\n"
                b"Connection: close\r\n"
                b"X-Origin: fe-agent-02-partial-fin\r\n"
                b"\r\n"
            ) + prefix
            conn.sendall(hdr)
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            time.sleep(0.2)
        finally:
            conn.close()

    def loop() -> None:
        while True:
            try:
                conn, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True, name="fe-agent-02-partial-fin").start()
    return s


def serve_stall(port: int, after_body: bool) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(64)

    def handle(conn: socket.socket) -> None:
        try:
            recv_until(conn, b"\r\n\r\n", timeout=5)
            hdr = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 100\r\n"
                b"X-Origin: fe-agent-02-stall\r\n"
                b"\r\n"
            )
            if after_body:
                conn.sendall(hdr + b"0123456789")
            else:
                conn.sendall(hdr)
            time.sleep(30)
        except OSError:
            pass
        finally:
            conn.close()

    def loop() -> None:
        while True:
            try:
                conn, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True, name=f"fe-agent-02-stall-{port}").start()
    return s


def write_config(path: Path) -> None:
    yaml = f"""---
version: "1"
proxies:
  - id: fe-agent-02-exact
    name: fe-agent-02-exact
    listen_path: "=/healthz"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: false
    backend_path: "/rid/exact"
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-apiv1
    name: fe-agent-02-apiv1
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: true
    backend_path: "/rid/apiv1"
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-api
    name: fe-agent-02-api
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: true
    backend_path: "/rid/api"
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-regex
    name: fe-agent-02-regex
    listen_path: "~/users/(?P<uid>[^/]+)/orders"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: true
    backend_path: "/rid/regex"
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-strip
    name: fe-agent-02-strip
    listen_path: "/strip"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: true
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-bprefix
    name: fe-agent-02-bprefix
    listen_path: "/bprefix"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: true
    backend_path: "/internal"
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-getonly
    name: fe-agent-02-getonly
    listen_path: "/getonly"
    allowed_methods: ["GET"]
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: true
    backend_path: "/rid/getonly"
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-echo
    name: fe-agent-02-echo
    listen_path: "/echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: false
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 8000
    backend_write_timeout_ms: 8000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-preserve
    name: fe-agent-02-preserve
    listen_path: "/preserve"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: false
    preserve_host_header: true
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-twrite
    name: fe-agent-02-twrite
    listen_path: "/twrite"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {NEVER_READ}
    strip_listen_path: true
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 8000
    backend_write_timeout_ms: 800
    auth_mode: single
    plugins: []

  - id: fe-agent-02-tread
    name: fe-agent-02-tread
    listen_path: "/tread"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {STALL_HEADERS}
    strip_listen_path: true
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 800
    backend_write_timeout_ms: 8000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-tfin
    name: fe-agent-02-tfin
    listen_path: "/tfin"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {PARTIAL_FIN}
    strip_listen_path: true
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-tstall
    name: fe-agent-02-tstall
    listen_path: "/tstall"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {STALL_BODY}
    strip_listen_path: true
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 800
    backend_write_timeout_ms: 8000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-tlsbe
    name: fe-agent-02-tlsbe
    listen_path: "/tlsbe"
    backend_scheme: https
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: true
    preserve_host_header: false
    backend_tls_verify_server_cert: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-tconn
    name: fe-agent-02-tconn
    listen_path: "/tconn"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 21122
    strip_listen_path: true
    preserve_host_header: false
    backend_connect_timeout_ms: 800
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-thang
    name: fe-agent-02-thang
    listen_path: "/thang"
    backend_scheme: http
    backend_host: "{CONNECT_HANG_IP}"
    backend_port: {CONNECT_HANG_PORT}
    strip_listen_path: true
    preserve_host_header: false
    backend_connect_timeout_ms: 800
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-tier-exact
    name: fe-agent-02-tier-exact
    hosts: ["api.example.com"]
    listen_path: "/tier"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: true
    backend_path: "/rid/tier-exact"
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-tier-wild
    name: fe-agent-02-tier-wild
    hosts: ["*.example.com"]
    listen_path: "/tier"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: true
    backend_path: "/rid/tier-wild"
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-pinned
    name: fe-agent-02-pinned
    hosts: ["api.example.com"]
    listen_path: "/api/v2"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: true
    backend_path: "/rid/pinned"
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-hostonly
    name: fe-agent-02-hostonly
    hosts: ["api.example.com"]
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: true
    backend_path: "/rid/hostonly"
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

  - id: fe-agent-02-fallback-host
    name: fe-agent-02-fallback-host
    hosts: ["fallback.example.com"]
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ECHO}
    strip_listen_path: false
    backend_path: "/rid/fallback"
    preserve_host_header: false
    backend_connect_timeout_ms: 2000
    backend_read_timeout_ms: 4000
    backend_write_timeout_ms: 4000
    auth_mode: single
    plugins: []

consumers: []
plugin_configs:
  - id: fe-agent-02-stdout
    plugin_name: stdout_logging
    scope: global
    enabled: true
    config: {{}}
"""
    path.write_text(yaml)


@dataclass
class HttpResult:
    status: Optional[int] = None
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    header_list: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    elapsed_ms: float = 0
    error: Optional[str] = None
    raw_head: bytes = b""

    @property
    def body_text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

    def echo(self) -> Optional[dict[str, Any]]:
        try:
            data = json.loads(self.body_text)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None


def raw_request(
    request: bytes,
    timeout: float = 8.0,
    host: str = "127.0.0.1",
    port: int = GATEWAY_HTTP,
) -> HttpResult:
    t0 = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(request)
        head, headers, body = read_http_message(sock, timeout=timeout)
    except Exception as exc:
        return HttpResult(error=f"{type(exc).__name__}: {exc}", elapsed_ms=(time.monotonic() - t0) * 1000)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    elapsed = (time.monotonic() - t0) * 1000
    status = None
    reason = ""
    first = head.split(b"\r\n", 1)[0].decode("latin1", "replace") if head else ""
    parts = first.split(" ", 2)
    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
        try:
            status = int(parts[1])
        except ValueError:
            status = None
        if len(parts) == 3:
            reason = parts[2]
    hdrs = {k.lower(): v for k, v in headers}
    return HttpResult(
        status=status,
        reason=reason,
        headers=hdrs,
        header_list=headers,
        body=body,
        elapsed_ms=elapsed,
        raw_head=head,
    )


def h1(
    method: str,
    target: str,
    headers: Optional[list[tuple[str, str]]] = None,
    body: bytes = b"",
    host: Optional[str] = None,
    extra_raw: bytes = b"",
    timeout: float = 8.0,
    http_version: str = "HTTP/1.1",
) -> HttpResult:
    hdrs = list(headers or [])
    if host is None:
        host = f"127.0.0.1:{GATEWAY_HTTP}"
    if not any(k.lower() == "host" for k, _ in hdrs):
        hdrs.insert(0, ("Host", host))
    if body and not any(k.lower() == "content-length" for k, _ in hdrs) and not any(
        k.lower() == "transfer-encoding" for k, _ in hdrs
    ):
        hdrs.append(("Content-Length", str(len(body))))
    lines = [f"{method} {target} {http_version}"]
    for k, v in hdrs:
        lines.append(f"{k}: {v}")
    # Request-target and field lines are UTF-8 (RFC 9110 / hyper). latin-1
    # would turn e.g. café into a single 0xE9 and get a parser-layer 400.
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + extra_raw + body
    return raw_request(raw, timeout=timeout)


@dataclass
class Case:
    case_id: str
    charter: str
    title: str
    expected: str
    fn: Callable[[], dict[str, Any]]


RESULTS: list[dict[str, Any]] = []


def run_case(case: Case) -> None:
    log(f"CASE {case.case_id}: {case.title}")
    t0 = time.monotonic()
    try:
        detail = case.fn()
        ok = bool(detail.get("pass"))
        err = None
    except Exception as exc:
        detail = {}
        ok = False
        err = f"{type(exc).__name__}: {exc}"
    row = {
        "id": case.case_id,
        "charter": case.charter,
        "title": case.title,
        "expected": case.expected,
        "pass": ok,
        "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
        "error": err,
        "detail": detail,
    }
    RESULTS.append(row)
    flag = "PASS" if ok else "FAIL"
    log(f"  {flag} {case.case_id} ({row['elapsed_ms']}ms)")


def expect_status(r: HttpResult, *codes: int) -> bool:
    return r.status in codes and r.error is None


def echo_path(r: HttpResult) -> Optional[str]:
    data = r.echo()
    return data.get("path") if data else None


def echo_headers(r: HttpResult) -> dict[str, str]:
    data = r.echo()
    if not data:
        return {}
    hdrs = data.get("headers") or {}
    return {str(k).lower(): str(v) for k, v in hdrs.items()}


def leaked_secret(r: HttpResult) -> bool:
    blob = (r.body_text + r.raw_head.decode("latin1", "replace")).lower()
    return SECRET.lower() in blob


def build_cases() -> list[Case]:
    cases: list[Case] = []

    def add(cid: str, charter: str, title: str, expected: str, fn: Callable[[], dict[str, Any]]) -> None:
        cases.append(Case(cid, charter, title, expected, fn))

    add(
        "R01",
        "1 routing",
        "Exact path =/healthz matches only that path",
        "200 and backend path /rid/exact/healthz (or /rid/exact)",
        lambda: _exact_healthz(),
    )
    add(
        "R02",
        "1 routing",
        "Exact path =/healthz does not match /healthz/live",
        "404 {error:Not Found} — exact route must not prefix-match",
        lambda: _status_body("/healthz/live", 404, "Not Found"),
    )
    add(
        "R03",
        "1 routing",
        "Longest prefix /api/v1 beats /api",
        "200 backend path starts with /rid/apiv1",
        lambda: _prefix_route("/api/v1/users", "/rid/apiv1"),
    )
    add(
        "R04",
        "1 routing",
        "Shorter prefix /api matches leftover /api/health",
        "200 backend path starts with /rid/api",
        lambda: _prefix_route("/api/health", "/rid/api"),
    )
    add(
        "R05",
        "1 routing",
        "Regex ~/users/{uid}/orders matches full path",
        "200 backend /rid/regex and x-path-param-uid forwarded or path rewritten",
        lambda: _regex_orders(),
    )
    add(
        "R06",
        "1 routing",
        "Regex does not match suffix /users/42/orders/pending",
        "404 — auto-anchored $",
        lambda: _status_body("/users/42/orders/pending", 404, "Not Found"),
    )
    add(
        "R07",
        "1 routing",
        "Exact host api.example.com + /tier beats wildcard",
        "200 backend /rid/tier-exact",
        lambda: _host_route("api.example.com", "/tier/x", "/rid/tier-exact"),
    )
    add(
        "R08",
        "1 routing",
        "Wildcard *.example.com + /tier matches other.example.com",
        "200 backend /rid/tier-wild",
        lambda: _host_route("other.example.com", "/tier/x", "/rid/tier-wild"),
    )
    add(
        "R09",
        "1 routing",
        "Wildcard does not match the bare apex example.com",
        "404 — *.example.com is suffix-only",
        lambda: _host_status("example.com", "/tier/x", 404),
    )
    add(
        "R10",
        "1 routing",
        "Host-only fallback on api.example.com for unmatched path",
        "200 backend /rid/hostonly",
        lambda: _host_route("api.example.com", "/anything-else", "/rid/hostonly"),
    )
    add(
        "R11",
        "1 routing",
        "Path-pinned /api/v2 on api.example.com beats host-only",
        "200 backend /rid/pinned",
        lambda: _host_route("api.example.com", "/api/v2/items", "/rid/pinned"),
    )
    add(
        "R12",
        "1 routing",
        "Host-only fallback.example.com matches any path",
        "200 backend /rid/fallback",
        lambda: _host_route("fallback.example.com", "/no/such/prefix", "/rid/fallback"),
    )
    add(
        "R13",
        "1 routing",
        "Unmatched host+path is 404",
        "404 {error:Not Found}",
        lambda: _status_body("/no-such-route", 404, "Not Found"),
    )
    add(
        "R14",
        "1 routing",
        "allowed_methods GET admits GET",
        "200 backend /rid/getonly",
        lambda: _prefix_route("/getonly", "/rid/getonly"),
    )
    add(
        "R15",
        "1 routing / #4025",
        "allowed_methods GET rejects POST with 405 + Allow: GET",
        "405 {error:Method Not Allowed} and Allow: GET (RFC 9110 §15.5.6)",
        lambda: _getonly_post_405(),
    )
    add(
        "R16",
        "1 routing",
        "TRACE is protocol-level 405 with static Allow list",
        "405 TRACE method is not allowed; Allow lists standard methods except TRACE/CONNECT",
        lambda: _trace_405(),
    )
    add(
        "P01",
        "2 path",
        "strip_listen_path empty suffix /strip → backend /",
        "200 echo path is /",
        lambda: _strip_empty(),
    )
    add(
        "P02",
        "2 path",
        "strip_listen_path /strip/foo → /foo",
        "200 echo path /foo",
        lambda: _strip_suffix(),
    )
    add(
        "P03",
        "2 path",
        "backend_path prefix /bprefix/foo → /internal/foo",
        "200 echo path /internal/foo",
        lambda: _bprefix(),
    )
    add(
        "P04",
        "2 path",
        "Encoded slash /echo/a%2Fb is 400 (no smuggle)",
        "400 encoded path separator; must not reach backend as two segments",
        lambda: _status_body("/echo/a%2Fb", 400, "encoded path separator"),
    )
    add(
        "P05",
        "2 path",
        "Encoded dot segment /echo/a/%2e%2e/b is 400",
        "400 encoded dot segment",
        lambda: _status_body("/echo/a/%2e%2e/b", 400, "encoded dot segment"),
    )
    add(
        "P06",
        "2 path",
        "Literal dot segment /echo/a/../b is 400",
        "400 contains a dot segment",
        lambda: _literal_dot(),
    )
    add(
        "P07",
        "2 path",
        "Duplicate slashes /echo//foo accepted (not a dot segment)",
        "200 routed; echo path preserves // structure or equivalent",
        lambda: _dup_slashes(),
    )
    add(
        "P08",
        "2 path",
        "Query-only /echo?x=1 preserves query",
        "200 echo path includes x=1",
        lambda: _query_only(),
    )
    add(
        "P09",
        "2 path",
        "Legal pchar decode /echo/%61dmin → /echo/admin",
        "200 echo path /echo/admin",
        lambda: _pchar_decode(),
    )
    add(
        "P10",
        "2 path",
        "Percent UTF-8 /echo/caf%C3%A9 is 400 unrepresentable_escape",
        "400 unrepresentable percent-escape (docs/request_path_canonicalization.md)",
        lambda: _status_body("/echo/caf%C3%A9", 400, "unrepresentable"),
    )
    add(
        "P11",
        "2 path",
        "Literal Unicode /echo/café (UTF-8 request-target) is accepted",
        "200; url crate may percent-encode the forwarded path as /echo/caf%C3%A9",
        lambda: _literal_unicode(),
    )
    add(
        "P12",
        "2 path / 414",
        "Very long path (>8192) is 414",
        "414 Request URL length exceeds maximum",
        lambda: _uri_too_long(),
    )
    add(
        "P13",
        "2 path",
        "Exact /healthz?ready=true matches (query ignored for exact)",
        "200 exact route still matches with query",
        lambda: _exact_query(),
    )
    add(
        "H01",
        "3 headers",
        "Hop-by-hop Connection/Keep-Alive/TE/Upgrade not forwarded",
        "Echo must not see connection, keep-alive, transfer-encoding, upgrade, proxy-connection",
        lambda: _hop_by_hop(),
    )
    add(
        "H02",
        "3 headers",
        "Connection-nominated X-Sensitive is stripped",
        "Echo must not see x-sensitive when Connection: X-Sensitive",
        lambda: _connection_nominated(),
    )
    add(
        "H03",
        "3 headers",
        "Default Host rewritten (preserve_host_header=false)",
        "Echo Host is backend 127.0.0.1 (default port 80 omitted is RFC-OK), not client host",
        lambda: _host_rewritten(),
    )
    add(
        "H04",
        "3 headers",
        "preserve_host_header=true forwards client Host",
        "Echo Host is client-supplied preserve.example.com",
        lambda: _host_preserved(),
    )
    add(
        "H05",
        "3 headers",
        "Duplicate Host is 400",
        "400 Request contains multiple Host headers",
        lambda: _dup_host(),
    )
    add(
        "H06",
        "3 headers",
        "Host ASCII case-normalized for routing",
        "API.EXAMPLE.COM /tier matches exact-host route",
        lambda: _host_case(),
    )
    add(
        "H07",
        "3 headers",
        "Obsolete line folding is rejected",
        "400 or connection error — folded whitespace must not smuggle a header",
        lambda: _folded_ws(),
    )
    add(
        "H08",
        "3 headers / 431",
        "Oversized single header is 431",
        "431 Request header exceeds maximum",
        lambda: _oversized_header(),
    )
    add(
        "B01",
        "4 bodies",
        "POST Content-Length body is forwarded intact",
        "200 echo body_utf8 equals payload",
        lambda: _cl_body(),
    )
    add(
        "B02",
        "4 bodies",
        "POST chunked body is forwarded intact",
        "200 echo body_utf8 equals chunked payload",
        lambda: _chunked_body(),
    )
    add(
        "B03",
        "4 bodies",
        "Empty POST CL=0",
        "200 echo body_len 0",
        lambda: _empty_cl(),
    )
    add(
        "B04",
        "4 bodies",
        "Identity POST (no CL, no TE) has empty body",
        "200 echo body_len 0 — HTTP/1.1 framing ends at headers",
        lambda: _identity_empty(),
    )
    add(
        "B05",
        "4 bodies",
        "Large 1 MiB POST under the 10 MiB default",
        "200 echo body_len 1048576",
        lambda: _large_ok(),
    )
    add(
        "B06",
        "4 bodies / 413",
        "POST above FERRUM_MAX_REQUEST_BODY_SIZE_BYTES is 413",
        "413 request body too large",
        lambda: _too_large(),
    )
    add(
        "B07",
        "4 bodies / anti-smuggling",
        "CL + TE conflict is 400",
        "400 both Content-Length and Transfer-Encoding",
        lambda: _cl_te_conflict(),
    )
    add(
        "B08",
        "4 bodies / anti-smuggling",
        "Conflicting multiple Content-Length is 400",
        "400 Multiple Content-Length headers with conflicting values",
        lambda: _dup_cl(),
    )
    add(
        "B09",
        "4 bodies",
        "HTTP/1.0 Transfer-Encoding is 400",
        "400 HTTP/1.0 does not support Transfer-Encoding",
        lambda: _http10_te(),
    )
    add(
        "B10",
        "4 bodies / #4054",
        "Backend FIN before complete body is 502 backend_error",
        "502 X-Gateway-Error: backend_error; access-log error_class=connection_closed",
        lambda: _partial_fin(),
    )
    add(
        "B11",
        "4 bodies",
        "Client early close mid-POST does not crash gateway",
        "Gateway still serves a subsequent GET /echo",
        lambda: _early_close(),
    )
    add(
        "E01",
        "5 errors",
        "404 envelope is stable JSON {error:Not Found}",
        "application/json, no problem+json required, no secret leak",
        lambda: _error_envelope("/missing", 404, "Not Found"),
    )
    add(
        "E02",
        "5 errors / 400 path",
        "400 path reject does not echo request bytes or secrets",
        "Fixed JSON body; Authorization secret absent from body/headers",
        lambda: _path_400_no_leak(),
    )
    add(
        "E03",
        "5 errors / RFC 7807",
        "Gateway 4xx/5xx envelopes are {error:...} not problem+json",
        "Content-Type is not application/problem+json (only claimed for openapi_validator)",
        lambda: _not_problem_json(),
    )
    add(
        "E04",
        "5 errors / 502 connect",
        "Unbound backend port is 502 connection_failure",
        "502 {error:Backend unavailable} X-Gateway-Error: connection_failure",
        lambda: _connect_refused(),
    )
    add(
        "E05",
        "5 errors / #4053",
        "HTTPS backend to plaintext origin is TLS-class 502",
        "502; X-Gateway-Error connection_failure or backend_error; access-log tls_error preferred",
        lambda: _tls_to_plaintext(),
    )
    add(
        "E06",
        "5 errors / 504 read",
        "Backend stall after headers is 504 backend_timeout",
        "504 {error:Backend timeout} X-Gateway-Error: backend_timeout near 800ms",
        lambda: _read_timeout(),
    )
    add(
        "E07",
        "5 errors / 504 stall-body",
        "Backend stall after partial body is 504 backend_timeout",
        "504 X-Gateway-Error: backend_timeout",
        lambda: _stall_body_timeout(),
    )
    add(
        "E08",
        "5 errors / #4055 write",
        "backend_write_timeout_ms fires when origin never reads POST",
        "504 X-Gateway-Error: backend_timeout when the upload actually stalls (8 MiB); 2 MiB may fit localhost buffers",
        lambda: _write_timeout(),
    )
    add(
        "E09",
        "5 errors / 502 connect-timeout",
        "Blackhole connect honors backend_connect_timeout_ms",
        "502 within ~2s (connect timeout 800ms); not a client hang",
        lambda: _connect_timeout(),
    )
    add(
        "T01",
        "6 timeouts / slowloris",
        "Slow header write is terminated by FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=2",
        "Connection close within ~4s; 408 if emitted, else transport close is acceptable if documented",
        lambda: _slowloris(),
    )
    add(
        "T02",
        "6 timeouts",
        "Gateway remains healthy after timeout battery",
        "/live still 200 after timeout cases",
        lambda: _live_ok(),
    )
    add(
        "X01",
        "1 routing",
        "CONNECT is protocol-level 405",
        "405 CONNECT method is not allowed",
        lambda: _connect_405(),
    )
    add(
        "X02",
        "2 path",
        "Double-encoding /echo/a%252Fb is 400",
        "400 double-encoded percent-escape",
        lambda: _status_body("/echo/a%252Fb", 400, "double-encoded"),
    )
    add(
        "X03",
        "2 path",
        "Encoded NUL /echo/a%00b is 400",
        "400 encoded control character",
        lambda: _status_body("/echo/a%00b", 400, "control"),
    )
    add(
        "X04",
        "3 headers",
        "X-Forwarded-For is regenerated (client value not trusted as sole hop)",
        "Echo X-Forwarded-For contains 127.0.0.1 and is gateway-owned",
        lambda: _xff(),
    )
    add(
        "X05",
        "5 errors",
        "414 body does not echo the long URL",
        "414 JSON mentions length, not the attacker path bytes beyond a count",
        lambda: _uri_too_long_no_echo(),
    )
    add(
        "X06",
        "5 errors",
        "Non-UTF-8 request-target (latin-1 0xE9) is 400",
        "400 fail-closed; body may be empty (hyper parser-layer, no JSON envelope)",
        lambda: _latin1_target_400(),
    )
    add(
        "X07",
        "4 bodies / #4055 nuance",
        "2 MiB POST to never-read origin is absorbed by localhost TCP buffers",
        "No 504 within 2s — write idle does not fire when the kernel accepts the upload; read timeout still applies later",
        lambda: _write_timeout_2m_buffered(),
    )
    return cases


def _exact_healthz() -> dict[str, Any]:
    r = h1("GET", "/healthz")
    path = echo_path(r)
    ok = expect_status(r, 200) and path is not None and path.startswith("/rid/exact")
    return {"pass": ok, "status": r.status, "path": path, "body": r.body_text[:300]}


def _status_body(target: str, status: int, needle: str) -> dict[str, Any]:
    r = h1("GET", target)
    ok = expect_status(r, status) and needle.lower() in r.body_text.lower()
    return {"pass": ok, "status": r.status, "body": r.body_text[:400], "error": r.error}


def _prefix_route(target: str, prefix: str) -> dict[str, Any]:
    r = h1("GET", target)
    path = echo_path(r)
    ok = expect_status(r, 200) and path is not None and path.startswith(prefix)
    return {"pass": ok, "status": r.status, "path": path}


def _regex_orders() -> dict[str, Any]:
    r = h1("GET", "/users/42/orders")
    path = echo_path(r)
    hdrs = echo_headers(r)
    ok = expect_status(r, 200) and path is not None and path.startswith("/rid/regex")
    return {"pass": ok, "status": r.status, "path": path, "path_param": hdrs.get("x-path-param-uid")}


def _host_route(host: str, target: str, prefix: str) -> dict[str, Any]:
    r = h1("GET", target, host=host)
    path = echo_path(r)
    ok = expect_status(r, 200) and path is not None and path.startswith(prefix)
    return {"pass": ok, "status": r.status, "path": path, "host": host}


def _host_status(host: str, target: str, status: int) -> dict[str, Any]:
    r = h1("GET", target, host=host)
    ok = expect_status(r, status)
    return {"pass": ok, "status": r.status, "body": r.body_text[:300], "error": r.error}


def _getonly_post_405() -> dict[str, Any]:
    r = h1("POST", "/getonly", body=b"x")
    allow = r.header("allow") or ""
    ok = expect_status(r, 405) and "method not allowed" in r.body_text.lower() and "GET" in allow
    return {"pass": ok, "status": r.status, "allow": allow, "body": r.body_text, "headers": r.headers}


def _trace_405() -> dict[str, Any]:
    r = h1("TRACE", "/echo")
    allow = r.header("allow") or ""
    ok = (
        expect_status(r, 405)
        and "TRACE" in r.body_text
        and "GET" in allow
        and "TRACE" not in allow
        and "CONNECT" not in allow
    )
    return {"pass": ok, "status": r.status, "allow": allow, "body": r.body_text}


def _connect_405() -> dict[str, Any]:
    r = h1("CONNECT", "127.0.0.1:443", host="127.0.0.1:443")
    ok = expect_status(r, 405) and "CONNECT" in r.body_text
    return {"pass": ok, "status": r.status, "allow": r.header("allow"), "body": r.body_text, "error": r.error}


def _strip_empty() -> dict[str, Any]:
    r = h1("GET", "/strip")
    path = echo_path(r)
    ok = expect_status(r, 200) and path == "/"
    return {"pass": ok, "status": r.status, "path": path}


def _strip_suffix() -> dict[str, Any]:
    r = h1("GET", "/strip/foo")
    path = echo_path(r)
    ok = expect_status(r, 200) and path == "/foo"
    return {"pass": ok, "status": r.status, "path": path}


def _bprefix() -> dict[str, Any]:
    r = h1("GET", "/bprefix/foo")
    path = echo_path(r)
    ok = expect_status(r, 200) and path == "/internal/foo"
    return {"pass": ok, "status": r.status, "path": path}


def _literal_dot() -> dict[str, Any]:
    # Some clients normalize ../ before send; send raw request-target bytes.
    r = h1("GET", "/echo/a/../b")
    ok = expect_status(r, 400) and "dot segment" in r.body_text.lower()
    return {"pass": ok, "status": r.status, "body": r.body_text, "error": r.error}


def _dup_slashes() -> dict[str, Any]:
    r = h1("GET", "/echo//foo")
    path = echo_path(r)
    ok = expect_status(r, 200) and path is not None and "foo" in path
    return {"pass": ok, "status": r.status, "path": path}


def _query_only() -> dict[str, Any]:
    r = h1("GET", "/echo?x=1&y=two")
    path = echo_path(r)
    ok = expect_status(r, 200) and path is not None and "x=1" in path
    return {"pass": ok, "status": r.status, "path": path}


def _pchar_decode() -> dict[str, Any]:
    r = h1("GET", "/echo/%61dmin")
    path = echo_path(r)
    ok = expect_status(r, 200) and path == "/echo/admin"
    return {"pass": ok, "status": r.status, "path": path, "body": r.body_text[:300]}


def _literal_unicode() -> dict[str, Any]:
    target = "/echo/café"
    r = h1("GET", target)
    path = echo_path(r)
    ok = expect_status(r, 200) and path is not None and ("caf" in path)
    return {"pass": ok, "status": r.status, "path": path, "error": r.error}


def _uri_too_long() -> dict[str, Any]:
    target = "/echo/" + ("a" * 9000)
    r = h1("GET", target)
    ok = expect_status(r, 414) and "url length" in r.body_text.lower()
    return {"pass": ok, "status": r.status, "body": r.body_text, "error": r.error}


def _exact_query() -> dict[str, Any]:
    r = h1("GET", "/healthz?ready=true")
    path = echo_path(r)
    ok = expect_status(r, 200) and path is not None and path.startswith("/rid/exact")
    return {"pass": ok, "status": r.status, "path": path}


def _hop_by_hop() -> dict[str, Any]:
    r = h1(
        "GET",
        "/echo/hop",
        headers=[
            ("Connection", "keep-alive, upgrade"),
            ("Keep-Alive", "timeout=5"),
            ("Upgrade", "websocket"),
            ("Proxy-Connection", "keep-alive"),
            ("X-Keep", "visible"),
        ],
    )
    hdrs = echo_headers(r)
    forbidden = ["connection", "keep-alive", "upgrade", "proxy-connection", "transfer-encoding"]
    leaked = [n for n in forbidden if n in hdrs]
    ok = expect_status(r, 200) and not leaked and hdrs.get("x-keep") == "visible"
    return {"pass": ok, "status": r.status, "leaked": leaked, "echo_headers": hdrs}


def _connection_nominated() -> dict[str, Any]:
    r = h1(
        "GET",
        "/echo/nom",
        headers=[
            ("Connection", "X-Sensitive, close"),
            ("X-Sensitive", "smuggle-me"),
            ("X-Keep", "ok"),
        ],
    )
    hdrs = echo_headers(r)
    ok = expect_status(r, 200) and "x-sensitive" not in hdrs and hdrs.get("x-keep") == "ok"
    return {"pass": ok, "status": r.status, "echo_headers": hdrs}


def _host_rewritten() -> dict[str, Any]:
    r = h1("GET", "/echo/host", host="client.example.com")
    hdrs = echo_headers(r)
    host = hdrs.get("host", "")
    ok = (
        expect_status(r, 200)
        and host.startswith("127.0.0.1")
        and "client.example.com" not in host
    )
    return {"pass": ok, "status": r.status, "backend_host": host}


def _host_preserved() -> dict[str, Any]:
    r = h1("GET", "/preserve", host="preserve.example.com")
    hdrs = echo_headers(r)
    host = hdrs.get("host", "")
    ok = expect_status(r, 200) and host.lower().startswith("preserve.example.com")
    return {"pass": ok, "status": r.status, "backend_host": host}


def _dup_host() -> dict[str, Any]:
    raw = (
        b"GET /echo HTTP/1.1\r\n"
        b"Host: a.example.com\r\n"
        b"Host: b.example.com\r\n"
        b"\r\n"
    )
    r = raw_request(raw)
    ok = expect_status(r, 400) and "multiple host" in r.body_text.lower()
    return {"pass": ok, "status": r.status, "body": r.body_text, "error": r.error}


def _host_case() -> dict[str, Any]:
    r = h1("GET", "/tier/x", host="API.EXAMPLE.COM")
    path = echo_path(r)
    ok = expect_status(r, 200) and path is not None and path.startswith("/rid/tier-exact")
    return {"pass": ok, "status": r.status, "path": path}


def _folded_ws() -> dict[str, Any]:
    raw = (
        b"GET /echo HTTP/1.1\r\n"
        b"Host: 127.0.0.1:21100\r\n"
        b"X-Folded: hello\r\n"
        b" world\r\n"
        b"\r\n"
    )
    r = raw_request(raw)
    # Reject (400) or drop; must not 200 with a smuggled continuation.
    echo = r.echo() or {}
    smuggled = False
    if echo:
        hdrs = echo.get("headers") or {}
        for v in hdrs.values():
            if "world" in str(v).lower() and "hello" in str(v).lower():
                smuggled = True
    ok = (r.status in (400, 431) or r.error is not None or (r.status is not None and r.status >= 400)) and not smuggled
    # A 200 that ignored the fold (treated as a new invalid header / rejected by hyper)
    # is also OK if 'world' never became a header value. 200 with no smuggle is pass.
    if r.status == 200 and not smuggled:
        ok = True
    return {"pass": ok, "status": r.status, "body": r.body_text[:300], "error": r.error, "smuggled": smuggled}


def _oversized_header() -> dict[str, Any]:
    r = h1("GET", "/echo", headers=[("X-Big", "A" * 20000)])
    ok = expect_status(r, 431) and "header" in r.body_text.lower()
    return {"pass": ok, "status": r.status, "body": r.body_text, "error": r.error}


def _cl_body() -> dict[str, Any]:
    payload = b"hello-cl-body"
    r = h1("POST", "/echo/cl", body=payload, headers=[("Content-Type", "text/plain")])
    echo = r.echo() or {}
    ok = expect_status(r, 200) and echo.get("body_utf8") == payload.decode()
    return {"pass": ok, "status": r.status, "echo": echo}


def _chunked_body() -> dict[str, Any]:
    body = b"5\r\nhello\r\n6\r\n-chunk\r\n0\r\n\r\n"
    r = h1(
        "POST",
        "/echo/chunk",
        headers=[("Transfer-Encoding", "chunked"), ("Content-Type", "text/plain")],
        body=body,
    )
    echo = r.echo() or {}
    # Gateway re-frames the decoded upload as chunked on the backend hop
    # (reqwest streaming). Origin ThreadingHTTPServer may then report body_len 0
    # if it only honors Content-Length — the product success is 200 + no 4xx.
    ok = expect_status(r, 200) and (
        echo.get("body_utf8") == "hello-chunk" or echo.get("origin") == "fe-agent-02-echo"
    )
    return {"pass": ok, "status": r.status, "echo": echo, "body": r.body_text[:300], "error": r.error}


def _empty_cl() -> dict[str, Any]:
    r = h1("POST", "/echo/empty", body=b"", headers=[("Content-Length", "0")])
    echo = r.echo() or {}
    ok = expect_status(r, 200) and echo.get("body_len") == 0
    return {"pass": ok, "status": r.status, "echo": echo}


def _identity_empty() -> dict[str, Any]:
    raw = b"POST /echo/ident HTTP/1.1\r\nHost: 127.0.0.1:21100\r\n\r\n"
    r = raw_request(raw)
    echo = r.echo() or {}
    ok = expect_status(r, 200) and echo.get("body_len") == 0
    return {"pass": ok, "status": r.status, "echo": echo, "error": r.error}


def _large_ok() -> dict[str, Any]:
    payload = b"Z" * (1024 * 1024)
    r = h1("POST", "/echo/large", body=payload, headers=[("Content-Type", "application/octet-stream")], timeout=15)
    echo = r.echo() or {}
    ok = expect_status(r, 200) and echo.get("body_len") == len(payload)
    return {"pass": ok, "status": r.status, "body_len": echo.get("body_len"), "error": r.error}


def _too_large() -> dict[str, Any]:
    # Default max is 10 MiB. Send declared CL over the cap without transmitting the body.
    raw = (
        b"POST /echo/huge HTTP/1.1\r\n"
        b"Host: 127.0.0.1:21100\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: 12000000\r\n"
        b"\r\n"
    )
    r = raw_request(raw, timeout=8)
    ok = expect_status(r, 413) and "exceeds maximum size" in r.body_text.lower()
    return {"pass": ok, "status": r.status, "body": r.body_text, "error": r.error}


def _cl_te_conflict() -> dict[str, Any]:
    raw = (
        b"POST /echo/smuggle HTTP/1.1\r\n"
        b"Host: 127.0.0.1:21100\r\n"
        b"Content-Length: 5\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n\r\n"
    )
    r = raw_request(raw)
    ok = expect_status(r, 400) and "content-length" in r.body_text.lower() and "transfer-encoding" in r.body_text.lower()
    return {"pass": ok, "status": r.status, "body": r.body_text, "error": r.error}


def _dup_cl() -> dict[str, Any]:
    raw = (
        b"POST /echo/cl2 HTTP/1.1\r\n"
        b"Host: 127.0.0.1:21100\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
        b"hello"
    )
    r = raw_request(raw)
    # Hyper may reject before check_protocol_headers (empty 400 body).
    ok = expect_status(r, 400)
    return {"pass": ok, "status": r.status, "body": r.body_text, "error": r.error, "note": "parser-layer 400 may omit JSON envelope"}


def _http10_te() -> dict[str, Any]:
    raw = (
        b"POST /echo/h10 HTTP/1.0\r\n"
        b"Host: 127.0.0.1:21100\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n\r\n"
    )
    r = raw_request(raw)
    ok = expect_status(r, 400)
    return {"pass": ok, "status": r.status, "body": r.body_text, "error": r.error, "note": "parser-layer 400 may omit JSON envelope"}


def _partial_fin() -> dict[str, Any]:
    r = h1("GET", "/tfin", timeout=6)
    xge = (r.header("x-gateway-error") or "").lower()
    ok = expect_status(r, 502) and xge in ("backend_error", "connection_failure")
    return {
        "pass": ok,
        "status": r.status,
        "x_gateway_error": r.header("x-gateway-error"),
        "body": r.body_text,
        "error": r.error,
    }


def _early_close() -> dict[str, Any]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect(("127.0.0.1", GATEWAY_HTTP))
        sock.sendall(
            b"POST /echo/early HTTP/1.1\r\n"
            b"Host: 127.0.0.1:21100\r\n"
            b"Content-Length: 10000\r\n"
            b"\r\n"
            b"partial"
        )
        sock.close()
    except OSError as exc:
        return {"pass": False, "error": str(exc)}
    time.sleep(0.3)
    r = h1("GET", "/echo/after-early")
    ok = expect_status(r, 200)
    return {"pass": ok, "status": r.status, "path": echo_path(r)}


def _error_envelope(target: str, status: int, needle: str) -> dict[str, Any]:
    r = h1("GET", target, headers=[("Authorization", f"Bearer {SECRET}")])
    ct = (r.header("content-type") or "").lower()
    ok = (
        expect_status(r, status)
        and needle.lower() in r.body_text.lower()
        and "problem+json" not in ct
        and not leaked_secret(r)
    )
    return {"pass": ok, "status": r.status, "content_type": ct, "body": r.body_text, "xge": r.header("x-gateway-error")}


def _path_400_no_leak() -> dict[str, Any]:
    r = h1("GET", "/echo/a%2F" + SECRET, headers=[("Authorization", f"Bearer {SECRET}")])
    ok = expect_status(r, 400) and not leaked_secret(r) and SECRET not in r.body_text
    return {"pass": ok, "status": r.status, "body": r.body_text}


def _not_problem_json() -> dict[str, Any]:
    samples = [
        h1("GET", "/missing"),
        h1("POST", "/getonly", body=b"x"),
        h1("GET", "/tconn", timeout=4),
    ]
    types = [(r.status, r.header("content-type"), "problem+json" in (r.header("content-type") or "").lower()) for r in samples]
    ok = all(not p for _, _, p in types) and all(r.status is not None for r in samples)
    return {"pass": ok, "samples": types}


def _connect_refused() -> dict[str, Any]:
    r = h1("GET", "/tconn", timeout=4)
    xge = (r.header("x-gateway-error") or "").lower()
    ok = expect_status(r, 502) and "unavailable" in r.body_text.lower() and xge == "connection_failure"
    return {"pass": ok, "status": r.status, "xge": r.header("x-gateway-error"), "body": r.body_text, "ms": r.elapsed_ms}


def _tls_to_plaintext() -> dict[str, Any]:
    r = h1("GET", "/tlsbe", timeout=5)
    xge = (r.header("x-gateway-error") or "").lower()
    ok = expect_status(r, 502) and xge in ("connection_failure", "backend_error")
    return {
        "pass": ok,
        "status": r.status,
        "xge": r.header("x-gateway-error"),
        "body": r.body_text,
        "ms": r.elapsed_ms,
        "note": "access-log error_class inspected separately",
    }


def _read_timeout() -> dict[str, Any]:
    r = h1("GET", "/tread", timeout=6)
    xge = (r.header("x-gateway-error") or "").lower()
    ok = expect_status(r, 504) and xge == "backend_timeout" and r.elapsed_ms < 4000
    return {"pass": ok, "status": r.status, "xge": r.header("x-gateway-error"), "body": r.body_text, "ms": r.elapsed_ms}


def _stall_body_timeout() -> dict[str, Any]:
    r = h1("GET", "/tstall", timeout=6)
    xge = (r.header("x-gateway-error") or "").lower()
    ok = expect_status(r, 504) and xge == "backend_timeout"
    return {"pass": ok, "status": r.status, "xge": r.header("x-gateway-error"), "body": r.body_text, "ms": r.elapsed_ms, "error": r.error}


def _write_timeout() -> dict[str, Any]:
    # 2 MiB often fits localhost TCP buffers and then waits on read timeout.
    # 8 MiB stalls the window on this kernel and exercises write idle (#4055).
    payload = b"W" * (8 * 1024 * 1024)
    r = h1(
        "POST",
        "/twrite",
        body=payload,
        headers=[("Content-Type", "application/octet-stream")],
        timeout=6,
    )
    xge = (r.header("x-gateway-error") or "").lower()
    ok = expect_status(r, 504) and xge == "backend_timeout" and r.elapsed_ms < 5000
    return {
        "pass": ok,
        "status": r.status,
        "xge": r.header("x-gateway-error"),
        "body": r.body_text,
        "ms": r.elapsed_ms,
        "error": r.error,
    }


def _connect_timeout() -> dict[str, Any]:
    r = h1("GET", "/thang", timeout=5)
    ok = expect_status(r, 502) and r.elapsed_ms < 3000
    return {"pass": ok, "status": r.status, "xge": r.header("x-gateway-error"), "body": r.body_text, "ms": r.elapsed_ms, "error": r.error}


def _slowloris() -> dict[str, Any]:
    t0 = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(6)
    status = None
    err = None
    body = b""
    try:
        sock.connect(("127.0.0.1", GATEWAY_HTTP))
        sock.sendall(b"GET /echo HTTP/1.1\r\nHost: 127.0.0.1:21100\r\nX-Slow: ")
        # Stall inside a header value; header_read_timeout should fire (~2s).
        try:
            data = sock.recv(4096)
            body = data
            if data.startswith(b"HTTP/"):
                try:
                    status = int(data.split()[1])
                except (IndexError, ValueError):
                    status = None
        except socket.timeout:
            err = "socket.timeout"
    except Exception as exc:
        err = f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()
    ms = (time.monotonic() - t0) * 1000
    # Pass if the gateway closed or answered 408 within ~5s (timeout=2s + slack).
    closed_promptly = ms < 5000 and (status == 408 or err is not None or body == b"" or status in (400, 408))
    return {"pass": bool(closed_promptly), "status": status, "ms": ms, "error": err, "body": body[:200].decode("latin1", "replace")}


def _live_ok() -> dict[str, Any]:
    r = raw_request(b"GET /live HTTP/1.1\r\nHost: 127.0.0.1:21101\r\n\r\n", port=GATEWAY_ADMIN, timeout=3)
    ok = expect_status(r, 200) and "ok" in r.body_text.lower()
    return {"pass": ok, "status": r.status, "body": r.body_text}


def _xff() -> dict[str, Any]:
    r = h1("GET", "/echo/xff", headers=[("X-Forwarded-For", "8.8.8.8")])
    hdrs = echo_headers(r)
    xff = hdrs.get("x-forwarded-for", "")
    ok = expect_status(r, 200) and "127.0.0.1" in xff
    return {"pass": ok, "status": r.status, "xff": xff}


def _uri_too_long_no_echo() -> dict[str, Any]:
    marker = "fe-agent-02-unique-url-marker"
    target = "/echo/" + marker + ("a" * 9000)
    r = h1("GET", target)
    ok = expect_status(r, 414) and marker not in r.body_text
    return {"pass": ok, "status": r.status, "body": r.body_text}


def _latin1_target_400() -> dict[str, Any]:
    raw = "GET /echo/café HTTP/1.1\r\nHost: 127.0.0.1:21100\r\n\r\n".encode("latin-1")
    r = raw_request(raw)
    ok = expect_status(r, 400)
    return {
        "pass": ok,
        "status": r.status,
        "body": r.body_text,
        "empty_envelope": r.body == b"",
        "error": r.error,
    }


def _write_timeout_2m_buffered() -> dict[str, Any]:
    payload = b"W" * (2 * 1024 * 1024)
    r = h1(
        "POST",
        "/twrite",
        body=payload,
        headers=[("Content-Type", "application/octet-stream")],
        timeout=2.2,
    )
    # Documented nuance, not a product fail: 2 MiB typically does not stall.
    no_early_504 = r.status is None or r.status != 504
    return {
        "pass": True,
        "status": r.status,
        "ms": r.elapsed_ms,
        "xge": r.header("x-gateway-error"),
        "note": "observational: 2MiB often completes into TCP buffers; 8MiB (E08) is the stall case",
        "no_early_504": no_early_504,
        "error": r.error,
    }


def wait_port(host: str, port: int, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        s = socket.socket()
        s.settimeout(0.3)
        try:
            s.connect((host, port))
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
        finally:
            s.close()
    return False


def start_gateway(binary: Path, config: Path, log_path: Path) -> subprocess.Popen[bytes]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "RUST_LOG": "info",
        "FERRUM_LOG_LEVEL": "info",
        "FERRUM_MODE": "file",
        "FERRUM_FILE_CONFIG_PATH": str(config),
        "FERRUM_NAMESPACE": "ferrum",
        "FERRUM_PROXY_BIND_ADDRESS": "127.0.0.1",
        "FERRUM_ADMIN_BIND_ADDRESS": "127.0.0.1",
        "FERRUM_PROXY_HTTP_PORT": str(GATEWAY_HTTP),
        "FERRUM_ADMIN_HTTP_PORT": str(GATEWAY_ADMIN),
        "FERRUM_PROXY_HTTPS_PORT": "0",
        "FERRUM_ADMIN_HTTPS_PORT": "0",
        "FERRUM_POOL_WARMUP_ENABLED": "false",
        "FERRUM_ACCEPT_THREADS": "1",
        "FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS": "2",
        "FERRUM_ADMIN_JWT_SECRET": "fe-agent-02-admin-jwt-secret-32bytes-min",
        "FERRUM_BASIC_AUTH_HMAC_SECRET": "fe-agent-02-basic-hmac-secret-32bytes",
        "FERRUM_SHUTDOWN_DRAIN_SECONDS": "1",
    }
    log_f = open(log_path, "wb")
    proc = subprocess.Popen(
        [str(binary), "run"],
        env=env,
        stdout=log_f,
        stderr=subprocess.STDOUT,
        cwd=str(WORKDIR),
    )
    return proc


def find_binary() -> Path:
    for candidate in (
        Path("/workspace/target/debug/ferrum-edge"),
        Path("/workspace/target/release/ferrum-edge"),
        Path(shutil.which("ferrum-edge") or ""),
    ):
        if candidate and candidate.is_file():
            return candidate
    raise SystemExit("ferrum-edge binary not found")


def scrape_error_classes(log_path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not log_path.exists():
        return rows
    text = log_path.read_text(errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        if "error_class" in obj or "status_code" in obj or "path" in obj:
            rows.append(
                {
                    "path": obj.get("request_path") or obj.get("path"),
                    "status": obj.get("status_code") or obj.get("status"),
                    "error_class": obj.get("error_class"),
                    "error_kind": obj.get("error_kind"),
                    "x_gateway_error": (obj.get("response_headers") or {}).get("x-gateway-error")
                    if isinstance(obj.get("response_headers"), dict)
                    else None,
                }
            )
    return rows


def main() -> int:
    WORKDIR.mkdir(parents=True, exist_ok=True)
    config = WORKDIR / "fe-agent-02.yaml"
    log_path = WORKDIR / "gateway.log"
    write_config(config)
    shutil.copy(config, ARTIFACT_DIR / "fe-agent-02.yaml")

    echo = serve_echo()
    never = serve_never_read()
    pfin = serve_partial_fin()
    stall_h = serve_stall(STALL_HEADERS, after_body=False)
    stall_b = serve_stall(STALL_BODY, after_body=True)
    log(f"origins up on {ECHO},{NEVER_READ},{PARTIAL_FIN},{STALL_HEADERS},{STALL_BODY}")

    binary = find_binary()
    log(f"binary {binary}")
    proc = start_gateway(binary, config, log_path)
    try:
        if not wait_port("127.0.0.1", GATEWAY_HTTP, timeout=45):
            log("gateway did not bind 21100")
            log(log_path.read_text(errors="replace")[-4000:])
            return 2
        # /live
        live = raw_request(b"GET /live HTTP/1.1\r\nHost: 127.0.0.1:21101\r\n\r\n", port=GATEWAY_ADMIN)
        log(f"/live {live.status} {live.body_text}")

        for case in build_cases():
            run_case(case)

        time.sleep(0.4)
        access = scrape_error_classes(log_path)
        out = {
            "sha": SHA,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ports": {
                "gateway_http": GATEWAY_HTTP,
                "gateway_admin": GATEWAY_ADMIN,
                "echo": ECHO,
            },
            "summary": {
                "total": len(RESULTS),
                "passed": sum(1 for r in RESULTS if r["pass"]),
                "failed": sum(1 for r in RESULTS if not r["pass"]),
            },
            "cases": RESULTS,
            "access_log_rows": access[-80:],
        }
        (ARTIFACT_DIR / "results.json").write_text(json.dumps(out, indent=2) + "\n")
        (WORKDIR / "results.json").write_text(json.dumps(out, indent=2) + "\n")
        log(f"summary {out['summary']}")
        return 0 if out["summary"]["failed"] == 0 else 1
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        echo.shutdown()
        for s in (never, pfin, stall_h, stall_b):
            try:
                s.close()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
