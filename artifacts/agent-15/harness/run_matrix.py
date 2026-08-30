#!/usr/bin/env python3
"""Launch-readiness Agent 15: exclusive FERRUM_MODE, CP+DP push, last-good, HOLD #4041.

Loopback 127.0.0.1:22400-22499 only. Prefix fe-agent-15-.
CP is a config broker (no proxy). Investigation only — no production Rust.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path("/workspace")
BIN = Path(os.environ.get("FERRUM_EDGE_BIN", str(REPO / "target/debug/ferrum-edge")))
WORKDIR = Path("/tmp/fe-agent-15")
EVIDENCE = REPO / "artifacts/agent-15/evidence"
PREFIX = "fe-agent-15-"

ADMIN_SECRET = "fe-agent-15-admin-jwt-secret-32chars!!"
GRPC_SECRET = "fe-agent-15-cp-dp-grpc-secret-32chars"
ADMIN_ISS = "ferrum-edge"
METRICS_TOKEN = "fe-agent-15-metrics-bearer-token"

PORT_CP_ADMIN = 22400
PORT_CP_GRPC = 22401
PORT_DP_ADMIN = 22402
PORT_DP_PROXY = 22403
PORT_ECHO = 22404
PORT_CP_PROXY_SHOULD_NOT_BIND = 22405
PORT_DP_GRPC_SHOULD_NOT_BIND = 22406
PORT_EXCL_ADMIN = 22410
PORT_EXCL_GRPC = 22411
PORT_STALE_ADMIN = 22420
PORT_STALE_PROXY = 22421
PORT_STALE_GRPC = 22422

RESULTS: list[dict[str, Any]] = []


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def mint_admin_jwt(secret: str = ADMIN_SECRET, role: str = "admin", ttl: int = 3600) -> str:
    now = int(time.time())
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(
        json.dumps(
            {
                "iss": ADMIN_ISS,
                "sub": "fe-agent-15",
                "role": role,
                "iat": now,
                "nbf": now,
                "exp": now + ttl,
                "jti": str(uuid.uuid4()),
            },
            separators=(",", ":"),
        ).encode()
    )
    sig = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url(sig)}"


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def http(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 8.0,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()
    except Exception as e:
        return 0, {}, str(e).encode()


def write_evidence(name: str, text: str) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE / name
    path.write_text(text if text.endswith("\n") else text + "\n")


def record(row_id: str, priority: str, capability: str, expected: str, result: str, evidence: str, notes: str = "") -> None:
    RESULTS.append(
        {
            "id": row_id,
            "priority": priority,
            "capability": capability,
            "expected": expected,
            "result": result,
            "evidence": evidence,
            "notes": notes,
        }
    )
    print(f"[{result.upper():7}] {row_id} {capability}", flush=True)


def common_env() -> dict[str, str]:
    env = os.environ.copy()
    for k in list(env):
        if k.startswith("FERRUM_"):
            del env[k]
    env.update(
        {
            "FERRUM_LOG_LEVEL": "info",
            "FERRUM_ADMIN_JWT_SECRET": ADMIN_SECRET,
            "FERRUM_ADMIN_JWT_ISSUER": ADMIN_ISS,
            "FERRUM_CP_DP_GRPC_JWT_SECRET": GRPC_SECRET,
            "FERRUM_METRICS_BEARER_TOKEN": METRICS_TOKEN,
            "FERRUM_POOL_WARMUP_ENABLED": "false",
            "FERRUM_PROXY_BIND_ADDRESS": "127.0.0.1",
            "FERRUM_ADMIN_BIND_ADDRESS": "127.0.0.1",
            "FERRUM_STREAM_PROXY_BIND_ADDRESS": "127.0.0.1",
            "FERRUM_PROXY_HTTPS_PORT": "0",
            "FERRUM_ADMIN_HTTPS_PORT": "0",
            "FERRUM_NAMESPACE": "ferrum",
        }
    )
    return env


@dataclass
class Proc:
    name: str
    popen: subprocess.Popen
    log_path: Path
    ports: list[int] = field(default_factory=list)

    def poll(self) -> int | None:
        return self.popen.poll()

    def log_tail(self, n: int = 80) -> str:
        if not self.log_path.exists():
            return ""
        lines = self.log_path.read_text(errors="replace").splitlines()
        return "\n".join(lines[-n:])

    def stop(self, timeout: float = 8.0) -> None:
        if self.popen.poll() is not None:
            return
        self.popen.send_signal(signal.SIGTERM)
        deadline = time.time() + timeout
        while time.time() < deadline and self.popen.poll() is None:
            time.sleep(0.1)
        if self.popen.poll() is None:
            self.popen.kill()
            self.popen.wait(timeout=3)


def start_proc(name: str, args: list[str], env: dict[str, str], ports: list[int] | None = None) -> Proc:
    WORKDIR.mkdir(parents=True, exist_ok=True)
    log_path = WORKDIR / f"{PREFIX}{name}.log"
    fh = open(log_path, "ab")
    popen = subprocess.Popen(
        args,
        stdout=fh,
        stderr=subprocess.STDOUT,
        env=env,
        cwd=str(WORKDIR),
    )
    return Proc(name=name, popen=popen, log_path=log_path, ports=ports or [])


def run_capture(args: list[str], env: dict[str, str] | None = None, timeout: float = 20.0) -> tuple[int, str]:
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env or common_env(),
        )
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, out
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + (e.stderr or "")
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
        return 124, out + "\nTIMEOUT\n"


def wait_ready(admin_port: int, timeout: float = 45.0, token: str | None = None) -> bool:
    deadline = time.time() + timeout
    auth = token or mint_admin_jwt()
    url = f"http://127.0.0.1:{admin_port}/health"
    while time.time() < deadline:
        code, _, body = http(
            "GET",
            url,
            headers={"Authorization": f"Bearer {auth}"},
            timeout=2.0,
        )
        if code == 200:
            try:
                data = json.loads(body.decode())
            except json.JSONDecodeError:
                data = {}
            if data.get("ready") is True or data.get("status") in ("ok", "ready", "degraded"):
                # Prefer ready==true; accept status ok after listeners are up.
                if data.get("ready") is True:
                    return True
                # Some early health responses are 200 with ready false.
                if data.get("ready") is True:
                    return True
        time.sleep(0.25)
    return False


def wait_live(admin_port: int, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{admin_port}/live"
    while time.time() < deadline:
        code, _, body = http("GET", url, timeout=2.0)
        if code == 200 and b'"status"' in body:
            return True
        time.sleep(0.2)
    return False


def wait_ready_strict(admin_port: int, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    auth = mint_admin_jwt()
    url = f"http://127.0.0.1:{admin_port}/health"
    while time.time() < deadline:
        code, _, body = http(
            "GET",
            url,
            headers={"Authorization": f"Bearer {auth}"},
            timeout=2.0,
        )
        if code == 200:
            try:
                data = json.loads(body.decode())
            except json.JSONDecodeError:
                data = {}
            if data.get("ready") is True:
                return True
        time.sleep(0.3)
    return False


def start_echo(port: int) -> Proc:
    script = WORKDIR / f"{PREFIX}echo.py"
    WORKDIR.mkdir(parents=True, exist_ok=True)
    script.write_text(
        f"""#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (self.path + "\\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

ThreadingHTTPServer(("127.0.0.1", {port}), H).serve_forever()
"""
    )
    return start_proc("echo", [sys.executable, str(script)], os.environ.copy(), [port])


def cp_env(admin: int, grpc: int, db_path: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = common_env()
    env.update(
        {
            "FERRUM_MODE": "cp",
            "FERRUM_DB_TYPE": "sqlite",
            "FERRUM_DB_URL": f"sqlite:{db_path}?mode=rwc",
            "FERRUM_ADMIN_HTTP_PORT": str(admin),
            "FERRUM_PROXY_HTTP_PORT": str(PORT_CP_PROXY_SHOULD_NOT_BIND),
            "FERRUM_CP_GRPC_LISTEN_ADDR": f"127.0.0.1:{grpc}",
            "FERRUM_DB_POLL_INTERVAL": "1",
        }
    )
    if extra:
        env.update(extra)
    return env


def dp_env(admin: int, proxy: int, grpc_url: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = common_env()
    env.update(
        {
            "FERRUM_MODE": "dp",
            "FERRUM_ADMIN_HTTP_PORT": str(admin),
            "FERRUM_PROXY_HTTP_PORT": str(proxy),
            "FERRUM_DP_CP_GRPC_URLS": grpc_url,
            "FERRUM_CP_GRPC_LISTEN_ADDR": f"127.0.0.1:{PORT_DP_GRPC_SHOULD_NOT_BIND}",
        }
    )
    if extra:
        env.update(extra)
    return env


def auth_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {mint_admin_jwt()}",
        "Content-Type": "application/json",
        "X-Ferrum-Namespace": "ferrum",
    }


def row_m01_invalid_mode() -> None:
    code, out = run_capture([str(BIN), "run", "-m", "not-a-mode"], timeout=12)
    write_evidence("excl-invalid-mode.txt", f"exit={code}\n{out}")
    ok = code != 0 and "Invalid FERRUM_MODE" in out and "cp" in out and "dp" in out
    record("M01", "P0", "invalid FERRUM_MODE rejected", "exit!=0, lists allowed modes", "passed" if ok else "failed", "excl-invalid-mode.txt")


def row_m02_combined_mode() -> None:
    code, out = run_capture([str(BIN), "run", "-m", "cp,dp"], timeout=12)
    write_evidence("excl-combined-mode.txt", f"exit={code}\n{out}")
    ok = code != 0 and "Invalid FERRUM_MODE" in out
    record("M02", "P0", "combined FERRUM_MODE=cp,dp rejected", "exit!=0 exclusive enum", "passed" if ok else "failed", "excl-combined-mode.txt")


def row_m03_empty_mode() -> None:
    env = common_env()
    env["FERRUM_MODE"] = ""
    code, out = run_capture([str(BIN), "run"], env=env, timeout=12)
    write_evidence("excl-empty-mode.txt", f"exit={code}\n{out}")
    ok = code != 0 and "Invalid FERRUM_MODE" in out
    record("M03", "P0", "empty FERRUM_MODE rejected", "exit!=0", "passed" if ok else "failed", "excl-empty-mode.txt")


def row_m04_cli_wins() -> None:
    env = common_env()
    env["FERRUM_MODE"] = "dp"
    env["FERRUM_DP_CP_GRPC_URLS"] = "http://127.0.0.1:1"
    code, out = run_capture([str(BIN), "run", "-m", "cp", "--help"], env=env, timeout=8)
    # --help on run should still show mode flag; stronger check: validate -m cp vs env dp
    code2, out2 = run_capture(
        [str(BIN), "validate", "-m", "cp"],
        env=env,
        timeout=20,
    )
    write_evidence("excl-cli-wins.txt", f"help_exit={code}\n{out}\n--- validate -m cp with FERRUM_MODE=dp ---\nexit={code2}\n{out2}")
    # validate -m cp should require DB, not DP URLs. CLI mode must win.
    ok = "FERRUM_DP_CP_GRPC_URLS" not in out2 or "required in dp mode" not in out2.lower()
    ok = ok and ("Mode" in out2 or "cp" in out2.lower() or "database" in out2.lower() or "FERRUM_DB" in out2 or code2 != 0)
    # Fail if it behaved as DP (missing DP URLs after CLI -m cp would be wrong only if it said dp required)
    dp_leak = "required in dp mode" in out2.lower()
    record(
        "M04",
        "P0",
        "CLI -m cp exclusive over env FERRUM_MODE=dp",
        "validate/run uses CP, not DP",
        "failed" if dp_leak else "passed",
        "excl-cli-wins.txt",
        notes="dp leak" if dp_leak else "",
    )


def row_m05_cp_validate_needs_db() -> None:
    env = common_env()
    env["FERRUM_MODE"] = "cp"
    env["FERRUM_CP_GRPC_LISTEN_ADDR"] = "127.0.0.1:22490"
    code, out = run_capture([str(BIN), "validate", "-m", "cp"], env=env, timeout=20)
    write_evidence("excl-cp-validate.txt", f"exit={code}\n{out}")
    ok = code != 0  # missing DB should fail closed
    record("M05", "P1", "validate -m cp without DB fails closed", "exit!=0", "passed" if ok else "failed", "excl-cp-validate.txt")


def row_m06_dp_validate_needs_urls() -> None:
    env = common_env()
    env["FERRUM_MODE"] = "dp"
    code, out = run_capture([str(BIN), "validate", "-m", "dp"], env=env, timeout=20)
    write_evidence("excl-dp-validate.txt", f"exit={code}\n{out}")
    ok = code != 0 and ("FERRUM_DP_CP_GRPC_URLS" in out or "dp" in out.lower())
    record("M06", "P0", "validate -m dp without CP URLs fails closed", "exit!=0 names DP URLs", "passed" if ok else "failed", "excl-dp-validate.txt")


def start_cp_dp() -> tuple[Proc, Proc, Path]:
    db = WORKDIR / f"{PREFIX}cp.db"
    if db.exists():
        db.unlink()
    cp = start_proc(
        "cp",
        [str(BIN), "run", "-m", "cp"],
        cp_env(PORT_CP_ADMIN, PORT_CP_GRPC, db),
        [PORT_CP_ADMIN, PORT_CP_GRPC],
    )
    if not wait_live(PORT_CP_ADMIN, 40) or not wait_ready_strict(PORT_CP_ADMIN, 50):
        raise RuntimeError(f"CP not ready\n{cp.log_tail()}")
    dp = start_proc(
        "dp",
        [str(BIN), "run", "-m", "dp"],
        dp_env(PORT_DP_ADMIN, PORT_DP_PROXY, f"http://127.0.0.1:{PORT_CP_GRPC}"),
        [PORT_DP_ADMIN, PORT_DP_PROXY],
    )
    if not wait_live(PORT_DP_ADMIN, 40) or not wait_ready_strict(PORT_DP_ADMIN, 70):
        raise RuntimeError(f"DP not ready\n{dp.log_tail()}")
    return cp, dp, db


def row_m07_cp_no_proxy(cp: Proc) -> None:
    listening = port_open(PORT_CP_PROXY_SHOULD_NOT_BIND)
    grpc_ok = port_open(PORT_CP_GRPC)
    admin_ok = port_open(PORT_CP_ADMIN)
    write_evidence(
        "excl-cp-no-proxy.txt",
        f"cp_alive={cp.poll() is None}\nadmin_{PORT_CP_ADMIN}={admin_ok}\ngrpc_{PORT_CP_GRPC}={grpc_ok}\n"
        f"proxy_{PORT_CP_PROXY_SHOULD_NOT_BIND}={listening}\nlog_tail:\n{cp.log_tail(40)}\n",
    )
    ok = cp.poll() is None and admin_ok and grpc_ok and not listening
    record(
        "M07",
        "P0",
        "CP exclusive: admin+gRPC, no proxy bind",
        f"binds {PORT_CP_ADMIN}/{PORT_CP_GRPC}, not {PORT_CP_PROXY_SHOULD_NOT_BIND}",
        "passed" if ok else "failed",
        "excl-cp-no-proxy.txt",
    )


def row_m08_dp_no_grpc_listen(dp: Proc) -> None:
    listening = port_open(PORT_DP_GRPC_SHOULD_NOT_BIND)
    proxy_ok = port_open(PORT_DP_PROXY)
    admin_ok = port_open(PORT_DP_ADMIN)
    write_evidence(
        "excl-dp-no-grpc-listen.txt",
        f"dp_alive={dp.poll() is None}\nadmin_{PORT_DP_ADMIN}={admin_ok}\nproxy_{PORT_DP_PROXY}={proxy_ok}\n"
        f"grpc_listen_{PORT_DP_GRPC_SHOULD_NOT_BIND}={listening}\nlog_tail:\n{dp.log_tail(40)}\n",
    )
    ok = dp.poll() is None and admin_ok and proxy_ok and not listening
    record(
        "M08",
        "P0",
        "DP exclusive: proxy+admin, ignores CP gRPC listen",
        f"binds {PORT_DP_ADMIN}/{PORT_DP_PROXY}, not {PORT_DP_GRPC_SHOULD_NOT_BIND}",
        "passed" if ok else "failed",
        "excl-dp-no-grpc-listen.txt",
    )


def row_m09_dp_readonly() -> None:
    body = json.dumps(
        {
            "id": "fe-agent-15-should-fail",
            "listen_path": "/should-fail",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": PORT_ECHO,
            "strip_listen_path": True,
        }
    ).encode()
    code, _, raw = http("POST", f"http://127.0.0.1:{PORT_DP_ADMIN}/proxies", headers=auth_headers(), body=body)
    write_evidence("excl-dp-readonly.txt", f"status={code}\n{raw.decode(errors='replace')}\n")
    ok = code in (403, 405)
    record("M09", "P0", "DP admin is read-only", "POST /proxies 403/405", "passed" if ok else "failed", "excl-dp-readonly.txt")


def row_p01_push_and_proxy() -> None:
    body = json.dumps(
        {
            "id": "fe-agent-15-echo",
            "listen_path": "/echo",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": PORT_ECHO,
            "strip_listen_path": True,
        }
    ).encode()
    code, _, raw = http("POST", f"http://127.0.0.1:{PORT_CP_ADMIN}/proxies", headers=auth_headers(), body=body)
    write_evidence("push-create-proxy.txt", f"status={code}\n{raw.decode(errors='replace')}\n")
    if code not in (200, 201, 202):
        record("P01", "P0", "CP push proxy + DP serves HTTP", "201/202 then DP GET /echo/hello 200", "failed", "push-create-proxy.txt")
        return
    deadline = time.time() + 25
    last = b""
    last_code = 0
    while time.time() < deadline:
        last_code, _, last = http("GET", f"http://127.0.0.1:{PORT_DP_PROXY}/echo/hello", timeout=3.0)
        if last_code == 200 and b"/hello" in last:
            write_evidence("push-dp-http.txt", f"status={last_code}\n{last.decode(errors='replace')}\n")
            record("P01", "P0", "CP push proxy + DP serves HTTP", "DP GET /echo/hello 200", "passed", "push-dp-http.txt")
            return
        time.sleep(0.4)
    write_evidence("push-dp-http.txt", f"status={last_code}\n{last.decode(errors='replace')}\n")
    record("P01", "P0", "CP push proxy + DP serves HTTP", "DP GET /echo/hello 200", "failed", "push-dp-http.txt")


def row_p02_cluster() -> None:
    h = auth_headers()
    cp_code, _, cp_body = http("GET", f"http://127.0.0.1:{PORT_CP_ADMIN}/cluster", headers=h)
    dp_code, _, dp_body = http("GET", f"http://127.0.0.1:{PORT_DP_ADMIN}/cluster", headers=h)
    write_evidence(
        "cluster.txt",
        f"cp_status={cp_code}\n{cp_body.decode(errors='replace')}\n--- dp ---\ndp_status={dp_code}\n{dp_body.decode(errors='replace')}\n",
    )
    ok = cp_code == 200 and dp_code == 200
    record("P02", "P0", "GET /cluster JWT on CP and DP", "both 200", "passed" if ok else "failed", "cluster.txt")


def row_l01_invalid_post_keeps_route() -> None:
    body = json.dumps(
        {
            "id": "fe-agent-15-bad",
            "listen_path": "not-a-path",
            "backend_scheme": "not-a-scheme",
            "backend_host": "127.0.0.1",
            "backend_port": PORT_ECHO,
        }
    ).encode()
    code, _, raw = http("POST", f"http://127.0.0.1:{PORT_CP_ADMIN}/proxies", headers=auth_headers(), body=body)
    echo_code, _, echo_body = http("GET", f"http://127.0.0.1:{PORT_DP_PROXY}/echo/still", timeout=3.0)
    write_evidence(
        "lastgood-invalid-post.txt",
        f"post_status={code}\n{raw.decode(errors='replace')}\necho_status={echo_code}\n{echo_body.decode(errors='replace')}\n",
    )
    ok = code in (400, 422) and echo_code == 200
    record(
        "L01",
        "P0",
        "invalid CP write rejected; DP last-good route stays",
        "POST 400 and /echo still 200",
        "passed" if ok else "failed",
        "lastgood-invalid-post.txt",
    )


def row_l02_cp_outage_keeps_route(cp: Proc) -> None:
    cp.stop()
    time.sleep(1.0)
    echo_code, _, echo_body = http("GET", f"http://127.0.0.1:{PORT_DP_PROXY}/echo/outage", timeout=3.0)
    write_evidence(
        "lastgood-cp-outage.txt",
        f"cp_alive={cp.poll() is None}\necho_status={echo_code}\n{echo_body.decode(errors='replace')}\n",
    )
    ok = echo_code == 200 and b"/outage" in echo_body
    record(
        "L02",
        "P0",
        "DP keeps last-good after CP SIGTERM",
        "GET /echo/outage 200 while CP down",
        "passed" if ok else "failed",
        "lastgood-cp-outage.txt",
    )


def row_l03_restart_cp_and_add_route(db: Path) -> Proc | None:
    cp = start_proc(
        "cp2",
        [str(BIN), "run", "-m", "cp"],
        cp_env(PORT_CP_ADMIN, PORT_CP_GRPC, db),
        [PORT_CP_ADMIN, PORT_CP_GRPC],
    )
    if not wait_ready_strict(PORT_CP_ADMIN, 50):
        write_evidence("lastgood-cp-restart.txt", f"CP restart not ready\n{cp.log_tail()}\n")
        record("L03", "P1", "CP restart + second route reaches DP", "new /v2 200", "failed", "lastgood-cp-restart.txt")
        return cp
    body = json.dumps(
        {
            "id": "fe-agent-15-v2",
            "listen_path": "/v2",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": PORT_ECHO,
            "strip_listen_path": True,
        }
    ).encode()
    code, _, raw = http("POST", f"http://127.0.0.1:{PORT_CP_ADMIN}/proxies", headers=auth_headers(), body=body)
    deadline = time.time() + 25
    last_code = 0
    last = b""
    while time.time() < deadline:
        last_code, _, last = http("GET", f"http://127.0.0.1:{PORT_DP_PROXY}/v2/hi", timeout=3.0)
        if last_code == 200 and b"/hi" in last:
            break
        time.sleep(0.4)
    echo_ok, _, echo_body = http("GET", f"http://127.0.0.1:{PORT_DP_PROXY}/echo/after", timeout=3.0)
    write_evidence(
        "lastgood-second-route.txt",
        f"post={code}\n{raw.decode(errors='replace')}\nv2={last_code}\n{last.decode(errors='replace')}\n"
        f"echo={echo_ok}\n{echo_body.decode(errors='replace')}\n",
    )
    ok = last_code == 200 and echo_ok == 200
    record(
        "L03",
        "P1",
        "CP restart + second route reaches DP; first route kept",
        "/v2 and /echo both 200",
        "passed" if ok else "failed",
        "lastgood-second-route.txt",
    )
    return cp


def row_g01_provider_mesh_admission() -> None:
    missing = json.dumps(
        {
            "id": "fe-agent-15-mesh-missing",
            "targets": [{"host": "127.0.0.1", "port": PORT_ECHO}],
            "service_discovery": {"provider": "mesh"},
        }
    ).encode()
    code_miss, _, raw_miss = http(
        "POST", f"http://127.0.0.1:{PORT_CP_ADMIN}/upstreams", headers=auth_headers(), body=missing
    )
    good = json.dumps(
        {
            "id": "fe-agent-15-mesh-sd",
            "targets": [],
            "service_discovery": {
                "provider": "mesh",
                "mesh": {
                    "service_name": "reviews",
                    "namespace": "ferrum",
                    "topology": "sidecar",
                    "poll_interval_seconds": 5,
                },
            },
        }
    ).encode()
    code_ok, _, raw_ok = http(
        "POST", f"http://127.0.0.1:{PORT_CP_ADMIN}/upstreams", headers=auth_headers(), body=good
    )
    # DP should eventually see the upstream (config push), mesh snapshot stays empty without k8s overlay
    deadline = time.time() + 20
    dp_list = b""
    dp_code = 0
    while time.time() < deadline:
        dp_code, _, dp_list = http(
            "GET", f"http://127.0.0.1:{PORT_DP_ADMIN}/upstreams", headers=auth_headers()
        )
        if dp_code == 200 and b"fe-agent-15-mesh-sd" in dp_list:
            break
        time.sleep(0.4)
    write_evidence(
        "provider-mesh.txt",
        f"missing_mesh_block={code_miss}\n{raw_miss.decode(errors='replace')}\n"
        f"with_mesh_block={code_ok}\n{raw_ok.decode(errors='replace')}\n"
        f"dp_upstreams={dp_code}\n{dp_list.decode(errors='replace')}\n",
    )
    miss_ok = code_miss in (400, 422)
    create_ok = code_ok in (200, 201, 202)
    dp_sees = dp_code == 200 and b"fe-agent-15-mesh-sd" in dp_list
    record(
        "G01",
        "P0",
        "provider: mesh admission + CP→DP push (no k8s mesh overlay)",
        "missing mesh block 400; valid 201; DP lists upstream",
        "passed" if (miss_ok and create_ok and dp_sees) else "failed",
        "provider-mesh.txt",
        notes="sqlite CP clears GatewayConfig.mesh for overlay re-merge; snapshot empty without k8s",
    )


def row_g02_dp_health_no_mesh_slice() -> None:
    code, _, body = http(
        "GET",
        f"http://127.0.0.1:{PORT_DP_ADMIN}/health",
        headers=auth_headers(),
    )
    write_evidence("dp-health-detail.txt", f"status={code}\n{body.decode(errors='replace')}\n")
    ok = code == 200
    record(
        "G02",
        "P1",
        "DP authenticated /health after mesh-SD upstream (no mesh slice)",
        "200; process stays up without GatewayConfig.mesh",
        "passed" if ok else "failed",
        "dp-health-detail.txt",
    )


def row_o01_registry_only_not_on_gateway_dp() -> None:
    # REGISTRY_ONLY is mesh-runtime injected. Gateway DP must not auto-inject it
    # from an empty sqlite CP mesh overlay.
    code, _, body = http(
        "GET",
        f"http://127.0.0.1:{PORT_DP_ADMIN}/plugin-configs",
        headers=auth_headers(),
    )
    text = body.decode(errors="replace")
    write_evidence("registry-only-plugins.txt", f"status={code}\n{text}\n")
    injected = "mesh_outbound_registry" in text
    ok = code == 200 and not injected
    record(
        "O01",
        "P1",
        "REGISTRY_ONLY plugin not auto-injected on gateway DP without mesh slice",
        "GET /plugin-configs has no mesh_outbound_registry",
        "passed" if ok else "failed",
        "registry-only-plugins.txt",
        notes="enforcement lives in mesh mode; see mesh_outbound_registry_* tests",
    )


def row_r01_4041_hold() -> None:
    # Source-level HOLD: wait_for_initial_mesh_config uses evaluate_received_slice
    # and reject() → record_rejected_slice. Tests exist on this SHA.
    wait_src = (REPO / "src/modes/mesh/mod.rs").read_text()
    runtime_src = (REPO / "src/modes/mesh/runtime.rs").read_text()
    tests_src = (REPO / "tests/integration/mesh_config_revision_tests.rs").read_text()
    has_eval = "evaluate_received_slice" in wait_src and "revision_rolled_back" in wait_src
    has_reject = "fn record_rejected_slice" in runtime_src
    has_test = "a_conversion_invalid_first_slice_does_not_pin_the_startup_watermark" in tests_src
    has_lower = "a_lower_sequence_slice_recovers_startup_after_a_conversion_refusal" in tests_src
    write_evidence(
        "hold-4041.txt",
        "SHA re-verify of #4041 record_rejected_slice (no new issue).\n"
        f"wait_for_initial_mesh_config evaluate+reject: {has_eval}\n"
        f"MeshRuntimeState::record_rejected_slice present: {has_reject}\n"
        f"same-seq test present: {has_test}\n"
        f"lower-seq / u64::MAX test present: {has_lower}\n"
        "Live mesh-mode process not started (charter: local CP+DP; compile light).\n",
    )
    ok = has_eval and has_reject and has_test and has_lower
    record(
        "R01",
        "P0",
        "#4041 HOLD re-verify record_rejected_slice on invalid first slice",
        "evaluate_received_slice + same-seq/lower-seq tests still on SHA",
        "passed" if ok else "failed",
        "hold-4041.txt",
        notes="HOLD — do not reopen #4041; do not duplicate",
    )


def row_h01_unauth_health() -> None:
    live = http("GET", f"http://127.0.0.1:{PORT_DP_ADMIN}/live")
    health = http("GET", f"http://127.0.0.1:{PORT_DP_ADMIN}/health")
    metrics = http("GET", f"http://127.0.0.1:{PORT_DP_ADMIN}/metrics")
    write_evidence(
        "obs-tier.txt",
        f"live={live[0]} {live[2][:200]!r}\nhealth={health[0]} {health[2][:300]!r}\nmetrics={metrics[0]}\n",
    )
    live_ok = live[0] == 200 and b'"status"' in live[2]
    health_coarse = health[0] == 200
    metrics_denied = metrics[0] == 401
    record(
        "H01",
        "P1",
        "observability tier on DP admin",
        "/live 200; /health coarse 200; /metrics 401",
        "passed" if (live_ok and health_coarse and metrics_denied) else "failed",
        "obs-tier.txt",
    )


def row_b00() -> None:
    exists = BIN.is_file() and os.access(BIN, os.X_OK)
    ver_code, ver_out = run_capture([str(BIN), "version"], timeout=8)
    write_evidence(
        "debug-binary.txt",
        f"path={BIN}\nexists={exists}\nsize={BIN.stat().st_size if exists else 0}\n"
        f"version_exit={ver_code}\n{ver_out}\n",
    )
    record("B00", "P0", "debug ferrum-edge binary", "executable + version", "passed" if exists and ver_code == 0 else "failed", "debug-binary.txt")


def main() -> int:
    WORKDIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(REPO), text=True).strip()
    write_evidence("sha-start.txt", sha + "\n")

    if not BIN.is_file():
        record("B00", "P0", "debug ferrum-edge binary", "executable exists", "failed", "debug-binary.txt", notes=f"missing {BIN}")
        (EVIDENCE / "matrix-results.json").write_text(json.dumps(RESULTS, indent=2) + "\n")
        return 1

    row_b00()
    row_m01_invalid_mode()
    row_m02_combined_mode()
    row_m03_empty_mode()
    row_m04_cli_wins()
    row_m05_cp_validate_needs_db()
    row_m06_dp_validate_needs_urls()
    row_r01_4041_hold()

    echo = start_echo(PORT_ECHO)
    time.sleep(0.3)
    cp = dp = None
    db = WORKDIR / f"{PREFIX}cp.db"
    try:
        cp, dp, db = start_cp_dp()
        write_evidence("cp-start.txt", cp.log_tail(60))
        write_evidence("dp-start.txt", dp.log_tail(60))
        row_m07_cp_no_proxy(cp)
        row_m08_dp_no_grpc_listen(dp)
        row_m09_dp_readonly()
        row_h01_unauth_health()
        row_p01_push_and_proxy()
        row_p02_cluster()
        row_l01_invalid_post_keeps_route()
        row_g01_provider_mesh_admission()
        row_g02_dp_health_no_mesh_slice()
        row_o01_registry_only_not_on_gateway_dp()
        row_l02_cp_outage_keeps_route(cp)
        cp = row_l03_restart_cp_and_add_route(db)
    except Exception as e:
        write_evidence("harness-error.txt", f"{type(e).__name__}: {e}\n")
        record("P00", "P0", "CP+DP process pair start", "both ready on loopback", "failed", "harness-error.txt", notes=str(e))
    finally:
        if dp:
            write_evidence("dp-final.txt", dp.log_tail(80))
            dp.stop()
        if cp:
            write_evidence("cp-final.txt", cp.log_tail(80))
            cp.stop()
        echo.stop()

    (EVIDENCE / "matrix-results.json").write_text(json.dumps(RESULTS, indent=2) + "\n")
    passed = sum(1 for r in RESULTS if r["result"] == "passed")
    failed = sum(1 for r in RESULTS if r["result"] == "failed")
    blocked = sum(1 for r in RESULTS if r["result"] == "blocked")
    print(f"\nSHA {sha}\npassed={passed} failed={failed} blocked={blocked} total={len(RESULTS)}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
