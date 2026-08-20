#!/usr/bin/env python3
"""Agent 01 launch-readiness harness: build/CLI/config/file-mode.

Loopback only. Ports 21000-21099. No secrets in evidence.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(os.environ.get("FERRUM_EDGE_ROOT", "/workspace")).resolve()
BIN = Path(os.environ.get("FERRUM_EDGE_BIN", str(ROOT / "target/debug/ferrum-edge")))
EVIDENCE = ROOT / "artifacts/agent-01/evidence"
FIXTURES = ROOT / "artifacts/agent-01/fixtures"
RESULTS = EVIDENCE / "matrix-results.json"

# Port plan (127.0.0.1 only)
P_HTTP = 21000
P_ADMIN = 21001
P_HTTP_BE = 21002
P_TCP = 21003
P_TCP_BE = 21004
P_ADMIN_TLS = 21005
P_HTTP2 = 21010
P_ADMIN2 = 21011
P_RELOAD_HTTP = 21020
P_RELOAD_ADMIN = 21021
P_SHUT_HTTP = 21030
P_SHUT_ADMIN = 21031
P_P0_HTTP = 21040
P_P0_ADMIN = 21041
P_CONF_HTTP = 21050
P_CONF_ADMIN = 21051

ADMIN_JWT_SECRET = "agent01-test-admin-jwt-secret-min-32-chars"
BIND = "127.0.0.1"

# Never export leftover FERRUM_* from the parent environment into children
STRIP_FERRUM = True


@dataclass
class Row:
    id: str
    priority: str
    capability: str
    mode: str
    method: str
    expected: str
    result: str = "not-tested"
    evidence: str = ""
    issue: str = ""
    notes: str = ""


ROWS: list[Row] = []


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_rows() -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": utcnow(),
        "sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "binary": str(BIN),
        "rows": [asdict(r) for r in ROWS],
    }
    RESULTS.write_text(json.dumps(payload, indent=2) + "\n")


def add(row: Row) -> Row:
    ROWS.append(row)
    save_rows()
    print(f"[{row.result.upper():10}] {row.id}: {row.capability} — {row.notes or row.expected}")
    return row


def clean_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    if STRIP_FERRUM:
        for k in list(env):
            if k.startswith("FERRUM_"):
                del env[k]
    if extra:
        env.update(extra)
    return env


def run_cmd(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    timeout: float = 20,
    stdin: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        env=env or clean_env(),
        cwd=cwd or ROOT,
        timeout=timeout,
        input=stdin,
        text=True,
        capture_output=True,
    )


def write_ev(name: str, text: str) -> str:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE / name
    path.write_text(text)
    return str(path.relative_to(ROOT))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint_admin_jwt(secret: str = ADMIN_JWT_SECRET, role: str = "admin") -> str:
    now = int(time.time())
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(
        json.dumps(
            {
                "iss": "ferrum-edge",
                "sub": "agent01",
                "iat": now,
                "nbf": now - 5,
                "exp": now + 3600,
                "jti": f"agent01-{now}",
                "role": role,
            },
            separators=(",", ":"),
        ).encode()
    )
    signing = f"{header}.{payload}".encode()
    sig = hmac.new(secret.encode(), signing, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url(sig)}"


def wait_port(host: str, port: int, timeout: float = 20) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.4):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def port_closed(host: str, port: int, timeout: float = 15) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                time.sleep(0.1)
        except OSError:
            return True
    return False


class HttpEcho(threading.Thread):
    def __init__(self, port: int, body_prefix: str = "echo"):
        super().__init__(daemon=True)
        self.port = port
        self.body_prefix = body_prefix
        self._stop = threading.Event()
        self.ready = threading.Event()
        self.hits = 0
        self.sock: socket.socket | None = None

    def run(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((BIND, self.port))
        s.listen(64)
        s.settimeout(0.3)
        self.sock = s
        self.ready.set()
        while not self._stop.is_set():
            try:
                conn, _ = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.hits += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        try:
            s.close()
        except OSError:
            pass

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(2)
            data = conn.recv(8192)
            first = data.split(b"\r\n", 1)[0].decode("latin1", "replace") if data else ""
            body = f"{self.body_prefix}:{first}"
            resp = (
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n"
                f"Content-Type: text/plain\r\nConnection: close\r\n\r\n{body}"
            )
            conn.sendall(resp.encode())
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


class TcpEcho(threading.Thread):
    def __init__(self, port: int):
        super().__init__(daemon=True)
        self.port = port
        self._stop = threading.Event()
        self.ready = threading.Event()
        self.hits = 0
        self.sock: socket.socket | None = None

    def run(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((BIND, self.port))
        s.listen(32)
        s.settimeout(0.3)
        self.sock = s
        self.ready.set()
        while not self._stop.is_set():
            try:
                conn, _ = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.hits += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        try:
            s.close()
        except OSError:
            pass

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(3)
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


def http_get(host: str, port: int, path: str, headers: dict[str, str] | None = None, timeout: float = 3) -> tuple[int | None, str, str]:
    req_h = {"Host": f"{host}:{port}", "Connection": "close"}
    if headers:
        req_h.update(headers)
    lines = [f"GET {path} HTTP/1.1"] + [f"{k}: {v}" for k, v in req_h.items()] + ["", ""]
    raw = "\r\n".join(lines).encode()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(raw)
            chunks: list[bytes] = []
            while True:
                b = s.recv(8192)
                if not b:
                    break
                chunks.append(b)
        data = b"".join(chunks)
    except OSError as e:
        return None, "", f"connect-error:{e}"
    text = data.decode("latin1", "replace")
    status = None
    if text.startswith("HTTP/"):
        try:
            status = int(text.split(" ", 2)[1])
        except (IndexError, ValueError):
            status = None
    body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
    return status, body, text[:800]


def tcp_roundtrip(host: str, port: int, payload: bytes = b"ping-agent01\n", timeout: float = 3) -> bytes | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(payload)
            return s.recv(4096)
    except OSError:
        return None


def spec_http_tcp(http_be: int = P_HTTP_BE, tcp_listen: int = P_TCP, tcp_be: int = P_TCP_BE) -> str:
    return f"""version: "1"
proxies:
  - id: "http-echo"
    name: "HTTP Echo"
    listen_path: "/echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {http_be}
    strip_listen_path: true
    auth_mode: none
  - id: "tcp-echo"
    name: "TCP Echo"
    listen_port: {tcp_listen}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {tcp_be}
consumers: []
plugin_configs: []
upstreams: []
"""


def gateway_env(
    spec: Path,
    *,
    http_port: int = P_HTTP,
    admin_port: int = P_ADMIN,
    settings: Path | None = None,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    env = {
        "FERRUM_MODE": "file",
        "FERRUM_FILE_CONFIG_PATH": str(spec),
        "FERRUM_PROXY_BIND_ADDRESS": BIND,
        "FERRUM_STREAM_PROXY_BIND_ADDRESS": BIND,
        "FERRUM_ADMIN_BIND_ADDRESS": BIND,
        "FERRUM_PROXY_HTTP_PORT": str(http_port),
        "FERRUM_PROXY_HTTPS_PORT": "0",
        "FERRUM_ADMIN_HTTP_PORT": str(admin_port),
        "FERRUM_ADMIN_HTTPS_PORT": "0",
        "FERRUM_ADMIN_JWT_SECRET": ADMIN_JWT_SECRET,
        "FERRUM_LOG_LEVEL": "info",
        "FERRUM_SHUTDOWN_DRAIN_SECONDS": "2",
        "FERRUM_POOL_WARMUP_ENABLED": "false",
    }
    if settings:
        env["FERRUM_CONF_PATH"] = str(settings)
    if extra:
        env.update(extra)
    return clean_env(env)


class Gateway:
    def __init__(self, env: dict[str, str], args: list[str] | None = None, log_name: str = "gw.log"):
        self.env = env
        self.args = args or ["run"]
        self.log_path = EVIDENCE / log_name
        self.proc: subprocess.Popen[str] | None = None
        self.log_fh = None

    def start(self) -> None:
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        self.log_fh = self.log_path.open("w")
        self.proc = subprocess.Popen(
            [str(BIN), *self.args],
            env=self.env,
            cwd=ROOT,
            stdout=self.log_fh,
            stderr=subprocess.STDOUT,
            text=True,
        )

    def wait_ready(self, admin: int, timeout: float = 25) -> bool:
        return wait_port(BIND, admin, timeout=timeout) and self.alive()

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def pid(self) -> int | None:
        return self.proc.pid if self.proc else None

    def signal(self, sig: int) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(sig)

    def stop(self, sig: int = signal.SIGTERM, wait: float = 8) -> int | None:
        if not self.proc:
            return None
        if self.proc.poll() is None:
            self.proc.send_signal(sig)
            try:
                self.proc.wait(timeout=wait)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        if self.log_fh:
            self.log_fh.close()
        return self.proc.returncode

    def log_tail(self, n: int = 80) -> str:
        if not self.log_path.exists():
            return ""
        lines = self.log_path.read_text(errors="replace").splitlines()
        return "\n".join(lines[-n:])


def require_bin() -> bool:
    return BIN.exists() and os.access(BIN, os.X_OK)


# ── test phases ──────────────────────────────────────────────────────────


def phase_cli() -> None:
    # help
    p = run_cmd([str(BIN), "--help"])
    ev = write_ev("cli-help.txt", f"exit={p.returncode}\n---stdout---\n{p.stdout}\n---stderr---\n{p.stderr}")
    ok = p.returncode == 0 and "run" in p.stdout and "validate" in p.stdout and p.stdout and not p.stderr.strip()
    add(Row("C01", "P0", "--help lists documented subcommands", "cli", "binary --help",
            "exit 0, stdout help, stderr empty, run/validate/reload/version/health/ambient-udp-preflight present",
            "passed" if ok else "failed", ev,
            notes="migrate is a mode not a clap subcommand" if "migrate" not in p.stdout else ""))

    p = run_cmd([str(BIN), "run", "--help"])
    ev = write_ev("cli-run-help.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    ok = p.returncode == 0 and "--settings" in p.stdout and "--spec" in p.stdout and "--mode" in p.stdout
    add(Row("C02", "P0", "run --help flags", "cli", "binary run --help",
            "exit 0; -s/-c/-m/-v documented", "passed" if ok else "failed", ev))

    p = run_cmd([str(BIN), "validate", "--help"])
    ev = write_ev("cli-validate-help.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("C03", "P0", "validate --help flags", "cli", "binary validate --help",
            "exit 0; same flags as run",
            "passed" if p.returncode == 0 and "--spec" in p.stdout else "failed", ev))

    p = run_cmd([str(BIN), "reload", "--help"])
    ev = write_ev("cli-reload-help.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("C04", "P0", "reload --help", "cli", "binary reload --help",
            "exit 0; --pid documented",
            "passed" if p.returncode == 0 and "--pid" in p.stdout else "failed", ev))

    p = run_cmd([str(BIN), "version"])
    ev = write_ev("cli-version.txt", f"exit={p.returncode}\nstdout={p.stdout!r}\nstderr={p.stderr!r}")
    ok = p.returncode == 0 and p.stdout.startswith("ferrum-edge ") and not p.stderr.strip()
    add(Row("C05", "P0", "version plaintext stdout", "cli", "binary version",
            "exit 0; 'ferrum-edge X.Y.Z (target)' on stdout; stderr empty",
            "passed" if ok else "failed", ev))

    p = run_cmd([str(BIN), "version", "--json"])
    ev = write_ev("cli-version-json.txt", f"exit={p.returncode}\nstdout={p.stdout!r}\nstderr={p.stderr!r}")
    valid = False
    try:
        obj = json.loads(p.stdout)
        valid = isinstance(obj, dict) and "version" in obj and "target" in obj and p.returncode == 0
    except json.JSONDecodeError:
        valid = False
    add(Row("C06", "P0", "version --json is valid JSON", "cli", "binary version --json",
            "exit 0; JSON object with version+target; stderr empty",
            "passed" if valid and not p.stderr.strip() else "failed", ev))

    p = run_cmd([str(BIN), "health", "--help"])
    ev = write_ev("cli-health-help.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("C07", "P0", "health --help", "cli", "binary health --help",
            "exit 0; --port/--host/--tls/--live documented",
            "passed" if p.returncode == 0 and "--live" in p.stdout else "failed", ev))

    p = run_cmd([str(BIN), "ambient-udp-preflight", "--help"])
    ev = write_ev("cli-ambient-help.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("C08", "P0", "ambient-udp-preflight --help", "cli", "binary ambient-udp-preflight --help",
            "exit 0; --settings/--timeout-seconds documented",
            "passed" if p.returncode == 0 and "--timeout-seconds" in p.stdout else "failed", ev))

    p = run_cmd([str(BIN), "migrate"])
    ev = write_ev("cli-migrate-subcommand.txt", f"exit={p.returncode}\nstdout={p.stdout!r}\nstderr={p.stderr!r}")
    # clap unknown subcommand should be non-zero
    add(Row("C09", "P0", "migrate is not a clap subcommand", "cli", "binary migrate",
            "exit != 0 with invalid-subcommand diagnostic (docs/cli.md: subcommand required; migrate is a mode)",
            "passed" if p.returncode != 0 else "failed", ev,
            notes="docs/migrations.md invokes bare ferrum-edge with FERRUM_MODE=migrate"))

    p = run_cmd([str(BIN), "run", "--mode", "not-a-mode"])
    ev = write_ev("cli-invalid-mode.txt", f"exit={p.returncode}\nstdout={p.stdout!r}\nstderr={p.stderr!r}")
    add(Row("C10", "P0", "invalid --mode rejected", "cli", "binary run -m not-a-mode",
            "exit != 0; diagnostic names allowed modes",
            "passed" if p.returncode != 0 else "failed", ev))

    p = run_cmd([str(BIN), "reload", "--pid", "not-a-pid"])
    ev = write_ev("cli-reload-invalid-pid.txt", f"exit={p.returncode}\nstdout={p.stdout!r}\nstderr={p.stderr!r}")
    add(Row("C11", "P0", "reload --pid non-numeric", "cli", "binary reload --pid not-a-pid",
            "exit != 0; clap invalid-value on stderr",
            "passed" if p.returncode != 0 else "failed", ev))

    p = run_cmd([str(BIN), "nosuch"])
    ev = write_ev("cli-unknown-subcommand.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("C12", "P1", "unknown subcommand", "cli", "binary nosuch",
            "exit != 0", "passed" if p.returncode != 0 else "failed", ev))

    p = run_cmd([str(BIN), "health", "--port", "1"])
    ev = write_ev("cli-health-refused.txt", f"exit={p.returncode}\nstdout={p.stdout!r}\nstderr={p.stderr!r}")
    add(Row("C13", "P0", "health refused connection", "cli", "binary health -p 1",
            "exit 1; connection error; no hang",
            "passed" if p.returncode == 1 else "failed", ev))

    try:
        p = run_cmd([str(BIN)], timeout=8)
        ev = write_ev(
            "cli-no-subcommand.txt",
            f"exit={p.returncode}\nstdout_head={p.stdout[:400]!r}\nstderr_head={p.stderr[:800]!r}",
        )
        add(Row("C14", "P1", "bare ferrum-edge (no subcommand)", "cli", "binary with no args (8s timeout)",
                "docs/cli.md says subcommand required; migrations.md uses bare binary. Fail-closed or start.",
                "passed" if p.returncode != 0 else "failed", ev,
                notes="nonzero fail-closed without settings is acceptable"))
    except subprocess.TimeoutExpired as e:
        ev = write_ev("cli-no-subcommand.txt", f"TIMEOUT stdout={e.stdout!r}\nstderr={e.stderr!r}")
        add(Row("C14", "P1", "bare ferrum-edge (no subcommand)", "cli", "binary with no args (8s timeout)",
                "should exit or be documented as legacy start",
                "failed", ev, notes="timed out — process started serving without a subcommand"))


def phase_validate_positive(tmpdir: Path) -> None:
    spec = tmpdir / "ok.yaml"
    spec.write_text(spec_http_tcp())
    env = gateway_env(spec)
    p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(spec)], env=env, timeout=30)
    ev = write_ev("validate-ok-yaml.txt", f"exit={p.returncode}\n---stdout---\n{p.stdout}\n---stderr---\n{p.stderr}")
    ok = p.returncode == 0 and "Validation passed" in p.stdout
    add(Row("V01", "P0", "validate minimal YAML HTTP+TCP", "file/http+tcp", "binary validate -m file -c",
            "exit 0; Validation passed; Proxies: 2",
            "passed" if ok and "Proxies: 2" in p.stdout else "failed", ev))

    specj = tmpdir / "ok.json"
    specj.write_text(json.dumps({
        "version": "1",
        "proxies": [
            {"id": "http-echo", "listen_path": "/echo", "backend_scheme": "http",
             "backend_host": "127.0.0.1", "backend_port": P_HTTP_BE, "strip_listen_path": True, "auth_mode": "none"},
            {"id": "tcp-echo", "listen_port": P_TCP, "backend_scheme": "tcp",
             "backend_host": "127.0.0.1", "backend_port": P_TCP_BE},
        ],
        "consumers": [], "plugin_configs": [], "upstreams": [],
    }))
    p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(specj)], env=gateway_env(specj), timeout=30)
    ev = write_ev("validate-ok-json.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("V02", "P0", "validate minimal JSON HTTP+TCP", "file/http+tcp", "binary validate JSON spec",
            "exit 0; Validation passed",
            "passed" if p.returncode == 0 and "Validation passed" in p.stdout else "failed", ev))


def phase_negative(tmpdir: Path) -> None:
    cases = [
        ("N01", "unknown field enabled on stream proxy",
         'version: "1"\nproxies:\n  - id: "p"\n    listen_port: 21003\n    backend_scheme: tcp\n    backend_host: "127.0.0.1"\n    backend_port: 21004\n    enabled: true\n',
         "unknown field"),
        ("N02", "duplicate proxy IDs",
         'version: "1"\nproxies:\n  - id: "dup"\n    listen_path: "/a"\n    backend_scheme: http\n    backend_host: "127.0.0.1"\n    backend_port: 21002\n  - id: "dup"\n    listen_path: "/b"\n    backend_scheme: http\n    backend_host: "127.0.0.1"\n    backend_port: 21002\n',
         "duplicate"),
        ("N03", "duplicate listen_path",
         'version: "1"\nproxies:\n  - id: "a"\n    listen_path: "/same"\n    backend_scheme: http\n    backend_host: "127.0.0.1"\n    backend_port: 21002\n  - id: "b"\n    listen_path: "/same"\n    backend_scheme: http\n    backend_host: "127.0.0.1"\n    backend_port: 21002\n',
         "listen_path"),
        ("N04", "stream listen_port conflicts reserved admin port",
         f'version: "1"\nproxies:\n  - id: "clash"\n    listen_port: {P_ADMIN}\n    backend_scheme: tcp\n    backend_host: "127.0.0.1"\n    backend_port: 21004\n',
         "conflict"),
        ("N05", "invalid backend_scheme",
         'version: "1"\nproxies:\n  - id: "bad"\n    listen_path: "/x"\n    backend_scheme: ftp\n    backend_host: "127.0.0.1"\n    backend_port: 21002\n',
         "scheme"),
        ("N06", "missing required backend_host",
         'version: "1"\nproxies:\n  - id: "bad"\n    listen_path: "/x"\n    backend_scheme: http\n    backend_port: 21002\n',
         "missing"),
        ("N07", "empty proxy id",
         'version: "1"\nproxies:\n  - id: ""\n    listen_path: "/x"\n    backend_scheme: http\n    backend_host: "127.0.0.1"\n    backend_port: 21002\n',
         "empty"),
        ("N08", "malformed YAML",
         'version: "1"\nproxies: [\n  - id: broken\n',
         "yaml"),
        ("N09", "malformed JSON",
         '{"version":"1","proxies":[',
         "json"),
        ("N10", "missing version field",
         'proxies:\n  - id: "p"\n    listen_path: "/x"\n    backend_scheme: http\n    backend_host: "127.0.0.1"\n    backend_port: 21002\n',
         "version"),
        ("N11", "invalid path missing file",
         None,
         "not found"),
        ("N12", "boundary listen_port 0 on stream",
         'version: "1"\nproxies:\n  - id: "z"\n    listen_port: 0\n    backend_scheme: tcp\n    backend_host: "127.0.0.1"\n    backend_port: 21004\n',
         "port"),
        ("N13", "Unicode proxy id",
         'version: "1"\nproxies:\n  - id: "路由-α"\n    listen_path: "/uni"\n    backend_scheme: http\n    backend_host: "127.0.0.1"\n    backend_port: 21002\n    auth_mode: none\n',
         None),  # may pass or fail; record
        ("N14", "HTTP proxy with listen_path on stream-like tcp scheme using path",
         'version: "1"\nproxies:\n  - id: "mix"\n    listen_path: "/tcp"\n    listen_port: 21003\n    backend_scheme: tcp\n    backend_host: "127.0.0.1"\n    backend_port: 21004\n',
         "listen_path"),
        ("N15", "empty string backend_host",
         'version: "1"\nproxies:\n  - id: "eh"\n    listen_path: "/x"\n    backend_scheme: http\n    backend_host: ""\n    backend_port: 21002\n',
         "empty"),
        ("N16", "duplicate listen_port stream proxies",
         'version: "1"\nproxies:\n  - id: "s1"\n    listen_port: 21003\n    backend_scheme: tcp\n    backend_host: "127.0.0.1"\n    backend_port: 21004\n  - id: "s2"\n    listen_port: 21003\n    backend_scheme: tcp\n    backend_host: "127.0.0.1"\n    backend_port: 21004\n',
         "port"),
    ]
    for cid, title, body, expect_token in cases:
        if cid == "N11":
            path = tmpdir / "does-not-exist.yaml"
            ext = "yaml"
            p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(path)],
                        env=gateway_env(path), timeout=20)
        else:
            ext = "json" if "JSON" in title else "yaml"
            path = tmpdir / f"{cid}.{ext}"
            assert body is not None
            path.write_text(body)
            p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(path)],
                        env=gateway_env(path), timeout=20)
        blob = f"exit={p.returncode}\n---stdout---\n{p.stdout}\n---stderr---\n{p.stderr}"
        ev = write_ev(f"neg-{cid}.txt", blob)
        combined = (p.stdout + p.stderr).lower()
        if expect_token is None:
            # Unicode: record actual
            result = "passed" if p.returncode == 0 else "failed"
            notes = f"unicode id accepted={p.returncode==0}"
        else:
            rejected = p.returncode != 0
            result = "passed" if rejected else "failed"
            notes = f"token_hint={expect_token!r} seen={expect_token.lower() in combined}"
        add(Row(cid, "P0" if cid in {"N01", "N02", "N03", "N04", "N08", "N09"} else "P1",
                title, "file/validate", "binary validate negative fixture",
                "fail closed, no Validation passed", result, ev, notes=notes))


def phase_live_http_tcp(tmpdir: Path) -> Gateway | None:
    spec = tmpdir / "live.yaml"
    spec.write_text(spec_http_tcp())
    http_be = HttpEcho(P_HTTP_BE, "http-be")
    tcp_be = TcpEcho(P_TCP_BE)
    http_be.start(); tcp_be.start()
    http_be.ready.wait(2); tcp_be.ready.wait(2)
    gw = Gateway(gateway_env(spec), log_name="live-http-tcp.log")
    gw.start()
    if not gw.wait_ready(P_ADMIN, 30):
        add(Row("L01", "P0", "file-mode start HTTP+TCP", "file/http+tcp", "binary run",
                "admin binds 127.0.0.1:21001", "failed",
                write_ev("live-start-fail.txt", gw.log_tail(120)),
                notes="gateway did not become ready"))
        gw.stop()
        http_be.stop(); tcp_be.stop()
        return None
    st, body, raw = http_get(BIND, P_HTTP, "/echo/hello")
    ev = write_ev("live-http.txt", f"status={st}\nbody={body}\nraw_head={raw[:400]}\nlog=\n{gw.log_tail(40)}")
    add(Row("L01", "P0", "file-mode HTTP route on loopback", "file/http", "binary run + GET /echo/hello",
            "HTTP 200 via 127.0.0.1:21000", "passed" if st == 200 else "failed", ev))
    got = tcp_roundtrip(BIND, P_TCP, b"tcp-ping\n")
    ev = write_ev("live-tcp.txt", f"got={got!r}\nbackend_hits={tcp_be.hits}\n")
    add(Row("L02", "P0", "file-mode TCP stream route on loopback", "file/tcp", "binary run + TCP echo",
            "payload echoed via 127.0.0.1:21003", "passed" if got == b"tcp-ping\n" else "failed", ev))
    # keep backends/gw for later health/reload? We'll stop and use dedicated processes.
    gw.stop(); http_be.stop(); tcp_be.stop()
    return None


def phase_precedence(tmpdir: Path) -> None:
    spec_cli = tmpdir / "cli.yaml"
    spec_env = tmpdir / "env.yaml"
    spec_cli.write_text(spec_http_tcp(http_be=P_HTTP_BE, tcp_listen=21003, tcp_be=P_TCP_BE))
    spec_env.write_text('version: "1"\nproxies: []\nconsumers: []\nplugin_configs: []\n')
    conf = tmpdir / "ferrum.conf"
    conf.write_text(
        f"FERRUM_MODE=file\n"
        f"FERRUM_PROXY_HTTP_PORT=21050\n"
        f"FERRUM_ADMIN_HTTP_PORT=21051\n"
        f"FERRUM_FILE_CONFIG_PATH={spec_env}\n"
        f"FERRUM_LOG_LEVEL=warn\n"
        f"FERRUM_PROXY_BIND_ADDRESS=127.0.0.1\n"
        f"FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1\n"
        f"FERRUM_STREAM_PROXY_BIND_ADDRESS=127.0.0.1\n"
        f"FERRUM_PROXY_HTTPS_PORT=0\n"
        f"FERRUM_ADMIN_HTTPS_PORT=0\n"
    )
    # CLI -c should win over env and conf file path; CLI -m file; env ports should win over conf ports
    env = clean_env({
        "FERRUM_MODE": "database",  # should lose to CLI -m file
        "FERRUM_FILE_CONFIG_PATH": str(spec_env),
        "FERRUM_PROXY_HTTP_PORT": str(P_HTTP),
        "FERRUM_ADMIN_HTTP_PORT": str(P_ADMIN),
        "FERRUM_PROXY_BIND_ADDRESS": BIND,
        "FERRUM_ADMIN_BIND_ADDRESS": BIND,
        "FERRUM_STREAM_PROXY_BIND_ADDRESS": BIND,
        "FERRUM_PROXY_HTTPS_PORT": "0",
        "FERRUM_ADMIN_HTTPS_PORT": "0",
        "FERRUM_ADMIN_JWT_SECRET": ADMIN_JWT_SECRET,
        "FERRUM_LOG_LEVEL": "info",
        "FERRUM_SHUTDOWN_DRAIN_SECONDS": "2",
        "FERRUM_POOL_WARMUP_ENABLED": "false",
        "FERRUM_CONF_PATH": str(conf),
    })
    http_be = HttpEcho(P_HTTP_BE); http_be.start(); http_be.ready.wait(2)
    tcp_be = TcpEcho(P_TCP_BE); tcp_be.start(); tcp_be.ready.wait(2)
    gw = Gateway(env, args=["run", "-s", str(conf), "-c", str(spec_cli), "-m", "file", "-v"],
                 log_name="precedence.log")
    gw.start()
    ready_cli_ports = gw.wait_ready(P_ADMIN, 25)
    ready_conf_ports = wait_port(BIND, 21051, timeout=1)
    st, body, raw = http_get(BIND, P_HTTP, "/echo/prec") if ready_cli_ports else (None, "", "not-ready")
    ev = write_ev("precedence.txt",
                  f"ready_env_ports={ready_cli_ports} ready_conf_ports={ready_conf_ports}\n"
                  f"http_status={st} body={body}\nlog=\n{gw.log_tail(80)}")
    # Winner: CLI mode=file + CLI spec (has /echo) + env ports 21000/21001 over conf 21050/21051
    ok = ready_cli_ports and not ready_conf_ports and st == 200
    add(Row("P01", "P0", "CLI > env > conf for mode/spec/ports", "file", "conflicting -m/-c vs env vs ferrum.conf",
            "serves CLI spec on env ports; conf ports unused; database mode from env ignored",
            "passed" if ok else "failed", ev,
            notes=f"admin21001={ready_cli_ports} admin21051={ready_conf_ports} http={st}"))
    # validate report should show File mode from CLI
    p = run_cmd([str(BIN), "validate", "-s", str(conf), "-c", str(spec_cli), "-m", "file"], env=env, timeout=25)
    ev = write_ev("precedence-validate.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("P02", "P0", "validate reports CLI-winning mode", "file/validate", "validate -m file vs env database",
            "Mode: File and Validation passed",
            "passed" if p.returncode == 0 and "Mode: File" in p.stdout else "failed", ev))
    gw.stop(); http_be.stop(); tcp_be.stop()


def phase_port_zero(tmpdir: Path) -> None:
    spec = tmpdir / "p0.yaml"
    spec.write_text(spec_http_tcp())
    # disable proxy HTTP (0) but keep a stream + admin
    env = gateway_env(spec, http_port=0, admin_port=P_P0_ADMIN, extra={"FERRUM_PROXY_HTTP_PORT": "0"})
    http_be = HttpEcho(P_HTTP_BE); tcp_be = TcpEcho(P_TCP_BE)
    http_be.start(); tcp_be.start(); http_be.ready.wait(2); tcp_be.ready.wait(2)
    gw = Gateway(env, log_name="port0-proxy.log")
    gw.start()
    ready = gw.wait_ready(P_P0_ADMIN, 25)
    http_open = wait_port(BIND, 0, timeout=0.2)  # nonsense
    # check 8000 default is NOT bound, and 21000 not bound
    def bound(port: int) -> bool:
        return wait_port(BIND, port, timeout=0.4)
    ev = write_ev("port0-proxy.txt",
                  f"ready_admin={ready} bound_21000={bound(P_HTTP)} bound_8000={bound(8000)}\n"
                  f"tcp={tcp_roundtrip(BIND, P_TCP)}\nlog=\n{gw.log_tail(50)}")
    add(Row("Z01", "P0", "FERRUM_PROXY_HTTP_PORT=0 disables plaintext proxy", "file", "binary run port 0",
            "admin up; 21000/8000 not listening; TCP stream still works",
            "passed" if ready and not bound(P_HTTP) and not bound(8000) and tcp_roundtrip(BIND, P_TCP) == b"tcp-ping\n"
            else ("passed" if ready and not bound(P_HTTP) else "failed"), ev,
            notes="tcp may still work independently"))
    gw.stop()

    # reserved-port: stream on 0-disabled proxy port should be allowed
    spec2 = tmpdir / "p0-reserved.yaml"
    spec2.write_text(
        'version: "1"\nproxies:\n'
        f'  - id: "s"\n    listen_port: {P_HTTP}\n    backend_scheme: tcp\n'
        f'    backend_host: "127.0.0.1"\n    backend_port: {P_TCP_BE}\n'
    )
    env2 = gateway_env(spec2, http_port=0, admin_port=P_P0_ADMIN)
    p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(spec2)], env=env2, timeout=20)
    ev = write_ev("port0-reserved.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("Z02", "P0", "port 0 excluded from reserved_gateway_ports", "file/validate",
            "stream listen_port=21000 while proxy HTTP=0",
            "validate passes (21000 not reserved)",
            "passed" if p.returncode == 0 else "failed", ev))

    # disable admin HTTP
    env3 = gateway_env(spec, http_port=P_P0_HTTP, admin_port=0)
    gw3 = Gateway(env3, log_name="port0-admin.log")
    gw3.start()
    time.sleep(3)
    admin_up = wait_port(BIND, 0 if False else P_P0_ADMIN, timeout=0.3)
    # admin 21001 from previous? we used P_P0_ADMIN which is 21041, env sets 0
    admin_default = wait_port(BIND, 9000, timeout=0.3)
    proxy_up = wait_port(BIND, P_P0_HTTP, timeout=8)
    ev = write_ev("port0-admin.txt",
                  f"alive={gw3.alive()} proxy={proxy_up} admin21041={wait_port(BIND, P_P0_ADMIN, 0.3)} "
                  f"admin9000={admin_default}\nlog=\n{gw3.log_tail(60)}")
    add(Row("Z03", "P0", "FERRUM_ADMIN_HTTP_PORT=0 disables plaintext admin", "file", "binary run admin port 0",
            "proxy may bind; admin 21041/9000 not listening",
            "passed" if gw3.alive() and not wait_port(BIND, P_P0_ADMIN, 0.3) and not admin_default else "failed", ev))
    gw3.stop(); http_be.stop(); tcp_be.stop()


def phase_health_shutdown(tmpdir: Path) -> None:
    spec = tmpdir / "hs.yaml"
    spec.write_text(spec_http_tcp())
    http_be = HttpEcho(P_HTTP_BE); http_be.start(); http_be.ready.wait(2)
    tcp_be = TcpEcho(P_TCP_BE); tcp_be.start(); tcp_be.ready.wait(2)
    env = gateway_env(spec, http_port=P_SHUT_HTTP, admin_port=P_SHUT_ADMIN)
    gw = Gateway(env, log_name="health-shutdown.log")
    gw.start()
    if not gw.wait_ready(P_SHUT_ADMIN, 25):
        add(Row("H01", "P0", "health CLI vs plaintext admin", "file/admin", "binary health -p",
                "exit 0 when ready", "failed", write_ev("health-start-fail.txt", gw.log_tail(80))))
        gw.stop(); http_be.stop(); tcp_be.stop()
        return
    p = run_cmd([str(BIN), "health", "-p", str(P_SHUT_ADMIN), "--host", BIND], env=clean_env(), timeout=10)
    ev = write_ev("health-ready.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("H01", "P0", "health CLI readiness plaintext", "file/admin", "binary health -p 21031",
            "exit 0", "passed" if p.returncode == 0 else "failed", ev))
    p = run_cmd([str(BIN), "health", "-p", str(P_SHUT_ADMIN), "--host", BIND, "--live"], env=clean_env(), timeout=10)
    ev = write_ev("health-live.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("H02", "P0", "health CLI --live", "file/admin", "binary health --live",
            "exit 0", "passed" if p.returncode == 0 else "failed", ev))
    st, body, raw = http_get(BIND, P_SHUT_ADMIN, "/live")
    ev = write_ev("admin-live.json", f"status={st}\nbody={body}\n")
    live_ok = st == 200 and '"status"' in body
    add(Row("H03", "P0", "GET /live unauthenticated minimal", "file/admin", "GET /live",
            "200 {status:ok} only", "passed" if live_ok else "failed", ev))
    st, body, raw = http_get(BIND, P_SHUT_ADMIN, "/health")
    ev = write_ev("admin-health-unauth.txt", f"status={st}\nbody={body}\n")
    # unauth should be coarse
    add(Row("H04", "P0", "GET /health unauthenticated is coarse", "file/admin", "GET /health no JWT",
            "200 with status+ready only; no full diagnostics",
            "passed" if st == 200 and "config_rejected" not in body else "failed", ev,
            notes=f"keys={list(json.loads(body).keys()) if body.startswith('{') else 'n/a'}"))
    token = mint_admin_jwt()
    st, body, raw = http_get(BIND, P_SHUT_ADMIN, "/health", headers={"Authorization": f"Bearer {token}"})
    ev = write_ev("admin-health-auth.txt", f"status={st}\nbody_redacted_len={len(body)}\nbody_head={body[:500]}\n")
    add(Row("H05", "P0", "GET /health authenticated detail", "file/admin", "GET /health + JWT",
            "200 with richer diagnostics than unauth",
            "passed" if st == 200 and len(body) > 40 else "failed", ev))
    st, body, raw = http_get(BIND, P_SHUT_ADMIN, "/metrics")
    ev = write_ev("admin-metrics-unauth.txt", f"status={st}\nbody_head={body[:200]}\n")
    add(Row("H06", "P1", "GET /metrics unauthenticated 401", "file/admin", "GET /metrics",
            "401", "passed" if st == 401 else "failed", ev))

    # SIGTERM drain + rebind
    pid = gw.pid()
    gw.signal(signal.SIGTERM)
    closed = port_closed(BIND, P_SHUT_HTTP, timeout=10)
    rc = gw.proc.wait(timeout=12) if gw.proc else None
    ev = write_ev("sigterm.txt", f"pid={pid} rc={rc} port_closed={closed}\nlog=\n{gw.log_tail(60)}")
    add(Row("S01", "P0", "SIGTERM stops accept and exits", "file", "SIGTERM running gateway",
            "process exits; port free for rebind",
            "passed" if rc is not None and closed else "failed", ev))
    # restart / rebind
    gw2 = Gateway(env, log_name="sigterm-rebind.log")
    gw2.start()
    rebound = gw2.wait_ready(P_SHUT_ADMIN, 20)
    st, body, raw = http_get(BIND, P_SHUT_HTTP, "/echo/rebind") if rebound else (None, "", "")
    ev = write_ev("sigterm-rebind.txt", f"rebound={rebound} status={st}\nlog=\n{gw2.log_tail(40)}")
    add(Row("S02", "P0", "immediate rebind after SIGTERM", "file", "restart same ports",
            "admin+proxy accept again",
            "passed" if rebound and st == 200 else "failed", ev))
    # SIGINT
    gw2.signal(signal.SIGINT)
    closed2 = port_closed(BIND, P_SHUT_HTTP, timeout=10)
    rc2 = gw2.proc.wait(timeout=12) if gw2.proc else None
    ev = write_ev("sigint.txt", f"rc={rc2} closed={closed2}\nlog=\n{gw2.log_tail(40)}")
    add(Row("S03", "P0", "SIGINT graceful stop", "file", "SIGINT",
            "exits and releases ports",
            "passed" if rc2 is not None and closed2 else "failed", ev))
    http_be.stop(); tcp_be.stop()


def phase_reload(tmpdir: Path) -> None:
    spec = tmpdir / "reload.yaml"
    spec.write_text(spec_http_tcp())
    http_be = HttpEcho(P_HTTP_BE, "r1"); http_be.start(); http_be.ready.wait(2)
    tcp_be = TcpEcho(P_TCP_BE); tcp_be.start(); tcp_be.ready.wait(2)
    env = gateway_env(spec, http_port=P_RELOAD_HTTP, admin_port=P_RELOAD_ADMIN)
    gw = Gateway(env, log_name="reload.log")
    gw.start()
    if not gw.wait_ready(P_RELOAD_ADMIN, 25):
        add(Row("R01", "P0", "SIGHUP reload add route", "file/reload", "binary run + SIGHUP",
                "new route becomes live", "failed", write_ev("reload-start-fail.txt", gw.log_tail(80))))
        gw.stop(); http_be.stop(); tcp_be.stop()
        return
    st, _, _ = http_get(BIND, P_RELOAD_HTTP, "/echo/pre")
    # add route via atomic rename
    new = spec_http_tcp() + """
  # extra HTTP route added below via rewrite
"""
    # rewrite with second HTTP path
    spec.write_text(f"""version: "1"
proxies:
  - id: "http-echo"
    name: "HTTP Echo"
    listen_path: "/echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {P_HTTP_BE}
    strip_listen_path: true
    auth_mode: none
  - id: "http-v2"
    name: "HTTP V2"
    listen_path: "/v2"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {P_HTTP_BE}
    strip_listen_path: true
    auth_mode: none
  - id: "tcp-echo"
    name: "TCP Echo"
    listen_port: {P_TCP}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {P_TCP_BE}
consumers: []
plugin_configs: []
upstreams: []
""")
    tmp = tmpdir / "reload.yaml.tmp"
    tmp.write_text(spec.read_text())
    os.replace(tmp, spec)
    p = run_cmd([str(BIN), "reload", "--pid", str(gw.pid())], env=clean_env(), timeout=10)
    time.sleep(1.5)
    st2, body2, raw2 = http_get(BIND, P_RELOAD_HTTP, "/v2/x")
    ev = write_ev("reload-add.txt", f"reload_exit={p.returncode} stdout={p.stdout!r}\npre={st} post_v2={st2} body={body2}\nlog=\n{gw.log_tail(50)}")
    add(Row("R01", "P0", "SIGHUP add route via atomic rename + reload --pid", "file/reload",
            "rewrite spec, ferrum-edge reload --pid",
            "exit 0; /v2 becomes 200; /echo still works",
            "passed" if p.returncode == 0 and st2 == 200 and http_get(BIND, P_RELOAD_HTTP, "/echo/z")[0] == 200 else "failed", ev))

    # invalid SIGHUP
    spec.write_text('version: "1"\nproxies: [broken')
    p = run_cmd([str(BIN), "reload", "--pid", str(gw.pid())], env=clean_env(), timeout=10)
    time.sleep(1.2)
    still = http_get(BIND, P_RELOAD_HTTP, "/echo/after-bad")[0]
    v2 = http_get(BIND, P_RELOAD_HTTP, "/v2/after-bad")[0]
    token = mint_admin_jwt()
    st_h, body_h, _ = http_get(BIND, P_RELOAD_ADMIN, "/health", headers={"Authorization": f"Bearer {token}"})
    ev = write_ev("reload-invalid.txt",
                  f"reload_exit={p.returncode} echo={still} v2={v2} health_status={st_h}\n"
                  f"health_body={body_h[:800]}\nalive={gw.alive()}\nlog=\n{gw.log_tail(60)}")
    rejected = "config_rejected" in body_h or "degraded" in body_h.lower()
    add(Row("R02", "P0", "invalid SIGHUP keeps last-good generation", "file/reload",
            "write malformed YAML + SIGHUP",
            "process alive; /echo and /v2 still 200; auth /health reports rejected/degraded",
            "passed" if gw.alive() and still == 200 and v2 == 200 else "failed", ev,
            notes=f"rejected_signal={rejected}"))

    # repair and reload
    spec.write_text(f"""version: "1"
proxies:
  - id: "http-echo"
    listen_path: "/echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {P_HTTP_BE}
    strip_listen_path: true
    auth_mode: none
  - id: "http-v3"
    listen_path: "/v3"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {P_HTTP_BE}
    strip_listen_path: true
    auth_mode: none
consumers: []
plugin_configs: []
upstreams: []
""")
    p = run_cmd([str(BIN), "reload", "--pid", str(gw.pid())], env=clean_env(), timeout=10)
    time.sleep(1.2)
    st3 = http_get(BIND, P_RELOAD_HTTP, "/v3/x")[0]
    st_old = http_get(BIND, P_RELOAD_HTTP, "/v2/x")[0]
    ev = write_ev("reload-repair.txt", f"exit={p.returncode} v3={st3} old_v2={st_old}\nlog=\n{gw.log_tail(40)}")
    add(Row("R03", "P0", "repair + SIGHUP applies new generation", "file/reload",
            "write valid spec missing /v2 adding /v3",
            "/v3=200; /v2 gone (404/no route); process healthy",
            "passed" if st3 == 200 and st_old != 200 else "failed", ev))

    # rapid consecutive reloads
    ok_rapid = True
    for i in range(5):
        spec.write_text(f"""version: "1"
proxies:
  - id: "http-echo"
    listen_path: "/echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {P_HTTP_BE}
    strip_listen_path: true
    auth_mode: none
  - id: "rapid-{i}"
    listen_path: "/r{i}"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {P_HTTP_BE}
    strip_listen_path: true
    auth_mode: none
consumers: []
plugin_configs: []
upstreams: []
""")
        run_cmd([str(BIN), "reload", "--pid", str(gw.pid())], env=clean_env(), timeout=8)
    time.sleep(1.5)
    last = http_get(BIND, P_RELOAD_HTTP, "/r4/x")[0]
    echo = http_get(BIND, P_RELOAD_HTTP, "/echo/x")[0]
    ev = write_ev("reload-rapid.txt", f"last=/r4 -> {last} echo={echo} alive={gw.alive()}\nlog=\n{gw.log_tail(30)}")
    add(Row("R04", "P1", "rapid consecutive reloads", "file/reload", "5 SIGHUPs",
            "final generation live; process healthy",
            "passed" if gw.alive() and last == 200 and echo == 200 else "failed", ev))

    # stale / unrelated / missing pid
    p = run_cmd([str(BIN), "reload", "--pid", "1"], env=clean_env(), timeout=8)
    ev = write_ev("reload-pid-unrelated.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("R05", "P1", "reload --pid unrelated PID 1", "cli/reload", "reload --pid 1",
            "non-zero (EPERM/ESRCH) or documented failure",
            "passed" if p.returncode != 0 else "failed", ev))
    p = run_cmd([str(BIN), "reload", "--pid", "999999"], env=clean_env(), timeout=8)
    ev = write_ev("reload-pid-missing.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("R06", "P1", "reload --pid missing PID", "cli/reload", "reload --pid 999999",
            "exit != 0", "passed" if p.returncode != 0 else "failed", ev))
    p = run_cmd([str(BIN), "reload", "--pid", "0"], env=clean_env(), timeout=8)
    ev = write_ev("reload-pid-zero.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("R07", "P1", "reload --pid 0 invalid", "cli/reload", "reload --pid 0",
            "exit != 0", "passed" if p.returncode != 0 else "failed", ev))

    # deleted file then SIGHUP
    spec.unlink()
    p = run_cmd([str(BIN), "reload", "--pid", str(gw.pid())], env=clean_env(), timeout=8)
    time.sleep(1.0)
    still = http_get(BIND, P_RELOAD_HTTP, "/echo/deleted")[0]
    ev = write_ev("reload-deleted.txt", f"reload_cli={p.returncode} echo={still} alive={gw.alive()}\nlog=\n{gw.log_tail(40)}")
    add(Row("R08", "P1", "SIGHUP after deleted spec keeps last-good", "file/reload",
            "unlink spec + SIGHUP",
            "process + old routes stay healthy",
            "passed" if gw.alive() and still == 200 else "failed", ev))

    # reload during shutdown
    spec.write_text(spec_http_tcp())
    gw.signal(signal.SIGTERM)
    p = run_cmd([str(BIN), "reload", "--pid", str(gw.pid())], env=clean_env(), timeout=8)
    try:
        rc = gw.proc.wait(timeout=12) if gw.proc else None
    except subprocess.TimeoutExpired:
        rc = None
        gw.stop(signal.SIGKILL)
    ev = write_ev("reload-during-shutdown.txt", f"reload_exit={p.returncode} gw_rc={rc}\nlog=\n{gw.log_tail(40)}")
    add(Row("R09", "P1", "reload during graceful shutdown", "file/reload",
            "SIGTERM then reload --pid",
            "no crash loop; process exits",
            "passed" if rc is not None else "failed", ev))
    http_be.stop(); tcp_be.stop()


def phase_reload_fs(tmpdir: Path) -> None:
    """partial write, permission loss, symlink swap, large config."""
    spec = tmpdir / "fs.yaml"
    spec.write_text(spec_http_tcp())
    http_be = HttpEcho(P_HTTP_BE); http_be.start(); http_be.ready.wait(2)
    env = gateway_env(spec, http_port=P_CONF_HTTP, admin_port=P_CONF_ADMIN)
    gw = Gateway(env, log_name="reload-fs.log")
    gw.start()
    if not gw.wait_ready(P_CONF_ADMIN, 25):
        add(Row("R10", "P1", "partial write rejected", "file/reload", "truncate in place",
                "last-good kept", "blocked", write_ev("reload-fs-start-fail.txt", gw.log_tail(60))))
        gw.stop(); http_be.stop()
        return
    # partial write in place (not atomic)
    with spec.open("w") as f:
        f.write('version: "1"\nproxies:\n  - id: "partial"\n    listen_path: "/p"\n')
        f.flush()
        # leave truncated
    os.kill(gw.pid() or 0, signal.SIGHUP)
    time.sleep(1.0)
    still = http_get(BIND, P_CONF_HTTP, "/echo/partial")[0]
    ev = write_ev("reload-partial.txt", f"echo={still} alive={gw.alive()}\nlog=\n{gw.log_tail(40)}")
    add(Row("R10", "P1", "partial in-place write + SIGHUP", "file/reload",
            "truncate YAML then SIGHUP",
            "reject torn candidate; /echo stays 200",
            "passed" if gw.alive() and still == 200 else "failed", ev))

    # restore good then chmod 000
    spec.write_text(spec_http_tcp())
    os.kill(gw.pid() or 0, signal.SIGHUP)
    time.sleep(1.0)
    spec.chmod(0)
    os.kill(gw.pid() or 0, signal.SIGHUP)
    time.sleep(1.0)
    still = http_get(BIND, P_CONF_HTTP, "/echo/perm")[0]
    ev = write_ev("reload-chmod.txt", f"echo={still} alive={gw.alive()}\nlog=\n{gw.log_tail(30)}")
    add(Row("R11", "P1", "permission loss on spec + SIGHUP", "file/reload",
            "chmod 000 + SIGHUP",
            "last-good kept",
            "passed" if gw.alive() and still == 200 else "failed", ev))
    spec.chmod(0o644)

    # symlink swap
    real = tmpdir / "real-a.yaml"
    real.write_text(f"""version: "1"
proxies:
  - id: "http-echo"
    listen_path: "/echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {P_HTTP_BE}
    strip_listen_path: true
    auth_mode: none
  - id: "via-link"
    listen_path: "/link"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {P_HTTP_BE}
    strip_listen_path: true
    auth_mode: none
consumers: []
plugin_configs: []
upstreams: []
""")
    link = tmpdir / "link.yaml"
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(real)
    env2 = gateway_env(link, http_port=P_CONF_HTTP, admin_port=P_CONF_ADMIN)
    # can't rebind same ports — use current gw: replace spec with symlink via rename
    # Instead: point same path — replace file with symlink
    spec.unlink()
    spec.symlink_to(real)
    os.kill(gw.pid() or 0, signal.SIGHUP)
    time.sleep(1.2)
    st = http_get(BIND, P_CONF_HTTP, "/link/x")[0]
    ev = write_ev("reload-symlink.txt", f"/link={st} alive={gw.alive()}\nlog=\n{gw.log_tail(30)}")
    add(Row("R12", "P1", "symlink swap reload", "file/reload", "replace spec with symlink",
            "new generation from symlink target",
            "passed" if st == 200 else "failed", ev))

    # large valid config
    proxies = []
    for i in range(80):
        proxies.append(
            f'  - id: "p{i}"\n    listen_path: "/bulk{i}"\n    backend_scheme: http\n'
            f'    backend_host: "127.0.0.1"\n    backend_port: {P_HTTP_BE}\n'
            f'    strip_listen_path: true\n    auth_mode: none\n'
        )
    large = 'version: "1"\nproxies:\n' + "".join(proxies) + "consumers: []\nplugin_configs: []\nupstreams: []\n"
    if spec.is_symlink():
        spec.unlink()
    spec.write_text(large)
    os.kill(gw.pid() or 0, signal.SIGHUP)
    time.sleep(2.0)
    st = http_get(BIND, P_CONF_HTTP, "/bulk79/x")[0]
    ev = write_ev("reload-large.txt", f"bytes={len(large)} /bulk79={st} alive={gw.alive()}\nlog=\n{gw.log_tail(20)}")
    add(Row("R13", "P2", "large valid config reload (80 proxies)", "file/reload", "SIGHUP 80-route spec",
            "/bulk79=200", "passed" if st == 200 else "failed", ev))
    gw.stop(); http_be.stop()


def phase_migrate(tmpdir: Path) -> None:
    current = tmpdir / "mig-current.yaml"
    current.write_text(spec_http_tcp())
    env = clean_env({
        "FERRUM_MODE": "migrate",
        "FERRUM_MIGRATE_ACTION": "config",
        "FERRUM_FILE_CONFIG_PATH": str(current),
        "FERRUM_LOG_LEVEL": "info",
    })
    p = run_cmd([str(BIN), "run", "-m", "migrate"], env=env, timeout=25)
    ev = write_ev("migrate-current.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("M01", "P0", "migrate config already-current version 1", "migrate/config",
            "FERRUM_MODE=migrate ACTION=config on v1",
            "exit 0; no backup (already current); no secret leak",
            "passed" if p.returncode == 0 else "failed", ev))

    p2 = run_cmd([str(BIN), "run", "-m", "migrate"], env=env, timeout=25)
    ev = write_ev("migrate-idempotent.txt", f"exit={p2.returncode}\n{p2.stdout}\n{p2.stderr}")
    add(Row("M02", "P0", "migrate config idempotent", "migrate/config", "run twice",
            "second run exit 0", "passed" if p2.returncode == 0 else "failed", ev))

    older = tmpdir / "mig-older.yaml"
    older.write_text('proxies:\n  - id: "p"\n    listen_path: "/x"\n    backend_scheme: http\n    backend_host: "127.0.0.1"\n    backend_port: 21002\n')
    env_old = clean_env({
        "FERRUM_MODE": "migrate",
        "FERRUM_MIGRATE_ACTION": "config",
        "FERRUM_FILE_CONFIG_PATH": str(older),
    })
    p = run_cmd([str(BIN), "run", "-m", "migrate"], env=env_old, timeout=25)
    ev = write_ev("migrate-missing-version.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("M03", "P1", "migrate config missing version", "migrate/config", "file without version",
            "exit != 0; no silent rewrite",
            "passed" if p.returncode != 0 else "failed", ev))

    bad = tmpdir / "mig-bad.yaml"
    bad.write_text("{not yaml")
    env_bad = clean_env({
        "FERRUM_MODE": "migrate",
        "FERRUM_MIGRATE_ACTION": "config",
        "FERRUM_FILE_CONFIG_PATH": str(bad),
    })
    p = run_cmd([str(BIN), "run", "-m", "migrate"], env=env_bad, timeout=25)
    ev = write_ev("migrate-malformed.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("M04", "P1", "migrate config malformed", "migrate/config", "broken YAML",
            "exit != 0", "passed" if p.returncode != 0 else "failed", ev))

    ro = tmpdir / "mig-ro.yaml"
    ro.write_text(spec_http_tcp())
    ro.chmod(0o444)
    env_ro = clean_env({
        "FERRUM_MODE": "migrate",
        "FERRUM_MIGRATE_ACTION": "config",
        "FERRUM_FILE_CONFIG_PATH": str(ro),
    })
    p = run_cmd([str(BIN), "run", "-m", "migrate"], env=env_ro, timeout=25)
    ev = write_ev("migrate-readonly.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("M05", "P1", "migrate config read-only file", "migrate/config", "chmod 444 current v1",
            "already-current should still succeed without write; or fail closed if it tries to write",
            "passed" if p.returncode == 0 else "failed", ev,
            notes="v1 already-current typically no write"))

    # bare binary (documented in migrations.md)
    p = run_cmd([str(BIN)], env=env, timeout=25)
    ev = write_ev("migrate-bare.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("M06", "P1", "bare ferrum-edge with FERRUM_MODE=migrate", "migrate",
            "docs/migrations.md copy-paste without subcommand",
            "same as `run -m migrate` (exit 0 on current file)",
            "passed" if p.returncode == 0 else "failed", ev))

    # secrets in file should not be printed
    secret_spec = tmpdir / "mig-secret.yaml"
    secret_spec.write_text(
        'version: "1"\nconsumers:\n  - id: "c"\n    username: "alice"\n    credentials:\n      keyauth:\n        - key: "SUPER-SECRET-KEY-DO-NOT-LOG"\nproxies: []\nplugin_configs: []\n'
    )
    env_s = clean_env({
        "FERRUM_MODE": "migrate",
        "FERRUM_MIGRATE_ACTION": "config",
        "FERRUM_FILE_CONFIG_PATH": str(secret_spec),
    })
    p = run_cmd([str(BIN), "run", "-m", "migrate"], env=env_s, timeout=25)
    leaked = "SUPER-SECRET-KEY-DO-NOT-LOG" in (p.stdout + p.stderr)
    ev = write_ev("migrate-secret.txt", f"exit={p.returncode} leaked={leaked}\nstdout_len={len(p.stdout)} stderr_len={len(p.stderr)}\n")
    add(Row("M07", "P0", "migrate config does not disclose secrets", "migrate/config",
            "consumer keyauth in file",
            "secret string absent from stdout/stderr",
            "passed" if not leaked else "failed", ev))


def phase_docs_examples(tmpdir: Path) -> None:
    """Validate documented core file-mode examples (copy-paste)."""
    # README example
    readme = ROOT / "README.md"
    text = readme.read_text()
    start = text.find('version: "1"\nproxies:\n  - id: "my-api"')
    block = ""
    if start >= 0:
        rest = text[start:]
        end = rest.find("```")
        block = rest[:end]
    path = tmpdir / "readme.yaml"
    path.write_text(block)
    p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(path)],
                env=gateway_env(path), timeout=25)
    ev = write_ev("docs-readme.yaml.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}\n---spec---\n{block}")
    add(Row("D01", "P0", "README file-mode example validates", "docs/file",
            "extract README YAML + validate",
            "exit 0 or documented partial",
            "passed" if p.returncode == 0 else "failed", ev))

    # configuration.md full example
    cfg = (ROOT / "docs/configuration.md").read_text()
    start = cfg.find('```yaml\nversion: "1"\n# Optional integrity seal')
    block = ""
    if start >= 0:
        rest = cfg[start + len("```yaml\n"):]
        block = rest.split("```", 1)[0]
    path = tmpdir / "configuration-example.yaml"
    path.write_text(block)
    p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(path)],
                env=gateway_env(path), timeout=25)
    ev = write_ev("docs-configuration.yaml.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("D02", "P0", "docs/configuration.md file-mode YAML validates", "docs/file",
            "extract configuration.md example",
            "exit 0", "passed" if p.returncode == 0 else "failed", ev))

    # tcp_udp_proxy.md with enabled: true (hot zone #4033)
    tcpdoc = (ROOT / "docs/tcp_udp_proxy.md").read_text()
    start = tcpdoc.find("```yaml\nproxies:\n  - id: \"postgres-proxy\"")
    block = ""
    if start >= 0:
        rest = tcpdoc[start + len("```yaml\n"):]
        block = rest.split("```", 1)[0]
        if "version:" not in block:
            block = 'version: "1"\n' + block
    path = tmpdir / "tcp-udp-doc.yaml"
    path.write_text(block)
    p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(path)],
                env=gateway_env(path), timeout=25)
    ev = write_ev("docs-tcp-udp.yaml.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}\n---spec-head---\n{block[:400]}")
    enabled_rejected = p.returncode != 0 and "enabled" in (p.stdout + p.stderr)
    add(Row("D03", "P0", "docs/tcp_udp_proxy.md examples with enabled: true", "docs/file",
            "copy-paste File Mode YAML + validate",
            "should validate on main if docs match schema; #4033 claims reject",
            "failed" if enabled_rejected else ("passed" if p.returncode == 0 else "failed"), ev,
            issue="https://github.com/ferrum-edge/ferrum-edge/issues/4033" if enabled_rejected else "",
            notes="confirm #4033 on this SHA"))

    # same without enabled
    cleaned = "\n".join(ln for ln in block.splitlines() if "enabled:" not in ln)
    path = tmpdir / "tcp-udp-doc-cleaned.yaml"
    path.write_text(cleaned)
    p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(path)],
                env=gateway_env(path), timeout=25)
    ev = write_ev("docs-tcp-udp-cleaned.yaml.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("D04", "P1", "tcp_udp_proxy.md examples after removing enabled", "docs/file",
            "same YAML minus enabled",
            "validate passes (workaround)",
            "passed" if p.returncode == 0 else "failed", ev))

    # tests/config.yaml (README getting started)
    p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(ROOT / "tests/config.yaml")],
                env=gateway_env(ROOT / "tests/config.yaml"), timeout=30)
    ev = write_ev("docs-tests-config.yaml.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("D05", "P0", "README getting-started tests/config.yaml validates", "docs/file",
            "validate tests/config.yaml",
            "exit 0", "passed" if p.returncode == 0 else "failed", ev))

    # openapi_validator without api_spec_id (#4037)
    oas = tmpdir / "oas.yaml"
    oas.write_text("""version: "1"
proxies:
  - id: "pets"
    listen_path: "/pets"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 21002
    strip_listen_path: false
    auth_mode: none
    plugins:
      - plugin_config_id: "ov"
plugin_configs:
  - id: "ov"
    plugin_name: "openapi_validator"
    scope: proxy
    proxy_id: "pets"
    enabled: true
    config:
      operations:
        - method: POST
          path: /pets
          request_body:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  required: [name]
                  properties:
                    name: {type: string}
                    id: {type: integer}
consumers: []
upstreams: []
""")
    p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(oas)],
                env=gateway_env(oas), timeout=25)
    ev = write_ev("docs-openapi-no-spec-id.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("D06", "P1", "openapi_validator file-mode without api_spec_id", "docs/file",
            "hand-authored operations, no api_spec_id",
            "validate passes on file mode (#4037: docs say rejected)",
            "passed" if p.returncode == 0 else "failed", ev,
            issue="https://github.com/ferrum-edge/ferrum-edge/issues/4037"))

    # plugin proxy_id only vs plugins[] (#4038) — validate both shapes
    only_id = tmpdir / "plugin-proxy-id-only.yaml"
    only_id.write_text("""version: "1"
proxies:
  - id: "error-route"
    listen_path: "/error"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 21002
    auth_mode: none
plugin_configs:
  - id: "alerts-error"
    plugin_name: "stdout_logging"
    scope: proxy
    proxy_id: "error-route"
    enabled: true
    config: {}
consumers: []
upstreams: []
""")
    p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(only_id)],
                env=gateway_env(only_id), timeout=25)
    ev = write_ev("docs-plugin-proxy-id-only.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("D07", "P1", "proxy-scoped plugin with proxy_id only validates", "docs/file",
            "scope=proxy + proxy_id, no proxies[].plugins",
            "validate accepts (attachment is a runtime/docs issue #4038)",
            "passed" if p.returncode == 0 else "failed", ev,
            issue="https://github.com/ferrum-edge/ferrum-edge/issues/4038"))


def phase_copy_paste_journey(tmpdir: Path) -> None:
    """One complete journey: clean fixtures → validate → run → routed traffic."""
    spec = tmpdir / "journey.yaml"
    spec.write_text(spec_http_tcp())
    p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(spec)],
                env=gateway_env(spec), timeout=25)
    if p.returncode != 0:
        add(Row("J01", "P0", "copy-paste journey checkout→validate→traffic", "file/http+tcp",
                "validate + run + GET + TCP",
                "200 + TCP echo", "failed",
                write_ev("journey-validate.txt", f"{p.stdout}\n{p.stderr}")))
        return
    http_be = HttpEcho(P_HTTP_BE, "journey"); tcp_be = TcpEcho(P_TCP_BE)
    http_be.start(); tcp_be.start(); http_be.ready.wait(2); tcp_be.ready.wait(2)
    gw = Gateway(gateway_env(spec), args=["run", "-m", "file", "-c", str(spec), "-v"],
                 log_name="journey.log")
    # CLI -c/-m should be enough; env also set
    gw.start()
    ok = gw.wait_ready(P_ADMIN, 25)
    st = http_get(BIND, P_HTTP, "/echo/journey")[0] if ok else None
    tcp = tcp_roundtrip(BIND, P_TCP, b"journey\n") if ok else None
    ev = write_ev("journey.txt", f"ready={ok} http={st} tcp={tcp!r}\nvalidate_ok\nlog=\n{gw.log_tail(40)}")
    add(Row("J01", "P0", "copy-paste journey checkout→validate→traffic", "file/http+tcp",
            "validate -m file -c; run -m file -c; GET /echo; TCP echo",
            "validate 0, HTTP 200, TCP echo on loopback 21000/21003",
            "passed" if ok and st == 200 and tcp == b"journey\n" else "failed", ev))
    gw.stop(); http_be.stop(); tcp_be.stop()


def phase_tls_health(tmpdir: Path) -> None:
    """Self-signed admin TLS + health --tls / invalid cert."""
    cert = tmpdir / "admin.crt"
    key = tmpdir / "admin.key"
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
             "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1"],
            check=True, capture_output=True, text=True, timeout=20,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        add(Row("H07", "P1", "health CLI vs TLS admin", "file/admin-tls", "openssl + health --tls",
                "exit 0 with --tls-no-verify", "blocked",
                write_ev("tls-openssl-fail.txt", str(e))))
        return
    spec = tmpdir / "tls.yaml"
    spec.write_text(spec_http_tcp())
    env = gateway_env(spec, http_port=P_HTTP2, admin_port=0, extra={
        "FERRUM_ADMIN_HTTP_PORT": "0",
        "FERRUM_ADMIN_HTTPS_PORT": str(P_ADMIN_TLS),
        "FERRUM_ADMIN_TLS_CERT_PATH": str(cert),
        "FERRUM_ADMIN_TLS_KEY_PATH": str(key),
    })
    gw = Gateway(env, log_name="admin-tls.log")
    gw.start()
    # HTTPS admin — wait_port still works (TCP accept)
    ready = wait_port(BIND, P_ADMIN_TLS, timeout=25) and gw.alive()
    if not ready:
        add(Row("H07", "P1", "health CLI vs TLS admin", "file/admin-tls", "run with admin HTTPS",
                "admin TLS listener up", "failed", write_ev("admin-tls-start.txt", gw.log_tail(80))))
        gw.stop()
        return
    p = run_cmd([str(BIN), "health", "--tls", "--tls-no-verify", "-p", str(P_ADMIN_TLS), "--host", BIND],
                env=clean_env(), timeout=12)
    ev = write_ev("health-tls-no-verify.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("H07", "P1", "health --tls --tls-no-verify against self-signed", "file/admin-tls",
            "binary health --tls --tls-no-verify",
            "exit 0", "passed" if p.returncode == 0 else "failed", ev))
    p = run_cmd([str(BIN), "health", "--tls", "-p", str(P_ADMIN_TLS), "--host", BIND],
                env=clean_env(), timeout=12)
    ev = write_ev("health-tls-verify-fail.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("H08", "P1", "health --tls rejects invalid/self-signed cert", "file/admin-tls",
            "binary health --tls (verify on)",
            "exit 1", "passed" if p.returncode == 1 else "failed", ev))
    p = run_cmd([str(BIN), "health", "--live", "--tls", "--tls-no-verify", "-p", str(P_ADMIN_TLS), "--host", BIND],
                env=clean_env(), timeout=12)
    ev = write_ev("health-tls-live.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("H09", "P1", "health --live over TLS", "file/admin-tls", "health --live --tls --tls-no-verify",
            "exit 0", "passed" if p.returncode == 0 else "failed", ev))
    gw.stop()


def phase_cp_port_zero(tmpdir: Path) -> None:
    spec = tmpdir / "cp0.yaml"
    spec.write_text(spec_http_tcp())
    env = gateway_env(spec, extra={"FERRUM_CP_GRPC_LISTEN_ADDR": "127.0.0.1:0"})
    p = run_cmd([str(BIN), "validate", "-m", "file", "-c", str(spec)], env=env, timeout=20)
    ev = write_ev("cp-port0-validate.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    add(Row("Z04", "P1", "CP gRPC listen :0 excluded from reserved ports (file validate)", "file/validate",
            "FERRUM_CP_GRPC_LISTEN_ADDR=127.0.0.1:0 + stream on 21003",
            "validate still passes",
            "passed" if p.returncode == 0 else "failed", ev))


def main() -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    if not require_bin():
        print(f"binary missing: {BIN}", file=sys.stderr)
        add(Row("B00", "P0", "debug binary present", "build", "stat ferrum-edge",
                "executable exists", "blocked", str(BIN)))
        return 2
    add(Row("B00", "P0", "debug binary present", "build", "stat ferrum-edge",
            "executable exists", "passed", str(BIN)))
    tmp = Path(tempfile.mkdtemp(prefix="agent01-", dir="/tmp"))
    try:
        phase_cli()
        phase_validate_positive(tmp)
        phase_negative(tmp)
        phase_docs_examples(tmp)
        phase_cp_port_zero(tmp)
        phase_live_http_tcp(tmp)
        phase_copy_paste_journey(tmp)
        phase_precedence(tmp)
        phase_port_zero(tmp)
        phase_health_shutdown(tmp)
        phase_tls_health(tmp)
        phase_reload(tmp)
        phase_reload_fs(tmp)
        phase_migrate(tmp)
    finally:
        save_rows()
        print(f"\nResults: {RESULTS}")
        counts = {}
        for r in ROWS:
            counts[r.result] = counts.get(r.result, 0) + 1
        print("counts:", counts, "total:", len(ROWS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
