#!/usr/bin/env python3
"""HTTP-message-level launch-readiness probes. No exploit payloads."""

from __future__ import annotations

import json
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def raw_http(port: int, payload: bytes, timeout: float = 2.0) -> tuple[int | None, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(("127.0.0.1", port))
        sock.sendall(payload)
        data = b""
        while True:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        text = data.decode("latin1", errors="replace")
        status = None
        if text.startswith("HTTP/"):
            try:
                status = int(text.split(" ", 2)[1])
            except (IndexError, ValueError):
                status = None
        return status, text
    except OSError as exc:
        return None, f"connect-error: {exc}"
    finally:
        try:
            sock.close()
        except OSError:
            pass


def http_get(url: str, headers: dict[str, str] | None = None) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except Exception as exc:
        return 0, str(exc)


def main() -> int:
    proxy = int(sys.argv[1]) if len(sys.argv) > 1 else 22800
    admin = int(sys.argv[2]) if len(sys.argv) > 2 else 22801
    out_path = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("artifacts/agent-19/live-results.json")

    cases: list[dict[str, object]] = []

    def record(name: str, payload: bytes, note: str) -> None:
        status, body = raw_http(proxy, payload)
        snippet = body[:400].replace("\r", "\\r").replace("\n", "\\n")
        cases.append(
            {
                "name": name,
                "status": status,
                "note": note,
                "body_snippet": snippet,
            }
        )
        print(f"{name}: status={status} {note}")

    record(
        "h11_clean",
        b"GET / HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\n\r\n",
        "baseline with Host",
    )
    record(
        "h11_cl_te",
        b"POST / HTTP/1.1\r\nHost: app.example\r\nContent-Length: 6\r\n"
        b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
        "CL.TE smuggling shape",
    )
    record(
        "h11_te_cl",
        b"POST / HTTP/1.1\r\nHost: app.example\r\nTransfer-Encoding: chunked\r\n"
        b"Content-Length: 6\r\nConnection: close\r\n\r\n0\r\n\r\n",
        "TE.CL smuggling shape",
    )
    record(
        "h11_dup_cl_conflict",
        b"POST / HTTP/1.1\r\nHost: app.example\r\nContent-Length: 1\r\n"
        b"Content-Length: 2\r\nConnection: close\r\n\r\nx",
        "duplicate conflicting Content-Length",
    )
    record(
        "h11_dup_host",
        b"GET / HTTP/1.1\r\nHost: app.example\r\nHost: evil.example\r\n"
        b"Connection: close\r\n\r\n",
        "duplicate Host",
    )
    record(
        "h11_missing_host",
        b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 origin-form without Host (RFC 9112 MUST 400)",
    )
    record(
        "h11_missing_host_catchall_path",
        b"GET /catchall HTTP/1.1\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 without Host against catch-all path",
    )
    record(
        "h11_absolute_form_mismatch",
        b"GET http://evil.example/ HTTP/1.1\r\nHost: app.example\r\n"
        b"Connection: close\r\n\r\n",
        "absolute-form authority disagrees with Host",
    )
    record(
        "h11_absolute_form_no_host",
        b"GET http://app.example/ HTTP/1.1\r\nConnection: close\r\n\r\n",
        "absolute-form without Host",
    )
    record(
        "h11_obs_fold",
        b"GET / HTTP/1.1\r\nHost: app.example\r\nX-Fold: one\r\n two\r\n"
        b"Connection: close\r\n\r\n",
        "obsolete line folding",
    )
    record(
        "h11_connection_nominated",
        b"GET / HTTP/1.1\r\nHost: app.example\r\nConnection: x-internal-token\r\n"
        b"X-Internal-Token: redacted-probe\r\nConnection: close\r\n\r\n",
        "Connection-nominated header should be stripped before backend",
    )
    record(
        "h11_te_only_chunked",
        b"POST / HTTP/1.1\r\nHost: app.example\r\nTransfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n0\r\n\r\n",
        "TE-only chunked is valid HTTP/1.1",
    )
    record(
        "h10_with_te",
        b"POST / HTTP/1.0\r\nHost: app.example\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.0 + TE",
    )
    record(
        "h11_control_byte_header",
        b"GET / HTTP/1.1\r\nHost: app.example\r\nX-Bad: val\x01ue\r\n"
        b"Connection: close\r\n\r\n",
        "control byte in header value",
    )

    live = http_get(f"http://127.0.0.1:{admin}/live")
    health = http_get(f"http://127.0.0.1:{admin}/health")
    status = http_get(f"http://127.0.0.1:{admin}/status")
    overload = http_get(f"http://127.0.0.1:{admin}/overload")
    metrics = http_get(f"http://127.0.0.1:{admin}/metrics")

    admin_cases = {
        "live": {"status": live[0], "body": live[1][:300]},
        "health": {"status": health[0], "body": health[1][:300]},
        "status": {"status": status[0], "body": status[1][:300]},
        "overload": {"status": overload[0], "body": overload[1][:300]},
        "metrics": {"status": metrics[0], "body": metrics[1][:300]},
    }
    for name, result in admin_cases.items():
        print(f"admin_{name}: status={result['status']} body={result['body']}")

    out = {
        "proxy_port": proxy,
        "admin_port": admin,
        "ts": time.time(),
        "http1_cases": cases,
        "admin_cases": admin_cases,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
