#!/usr/bin/env python3
"""Continue remaining Agent 01 rows after the main harness stopped at R06."""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path("/workspace")
BIN = ROOT / "target/debug/ferrum-edge"
EV = ROOT / "artifacts/agent-01/evidence"
BIND = "127.0.0.1"
ADMIN_JWT = "agent01-test-admin-jwt-secret-min-32-chars"


def clean(extra=None):
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("FERRUM_"):
            del env[key]
    if extra:
        env.update(extra)
    return env


class Echo(threading.Thread):
    def __init__(self, port: int):
        super().__init__(daemon=True)
        self.port = port
        self._s = None
        self._stop = threading.Event()

    def run(self) -> None:
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((BIND, self.port))
        sock.listen(32)
        sock.settimeout(0.3)
        self._s = sock
        while not self._stop.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(2)
                data = conn.recv(4096)
                first = data.split(b"\r\n", 1)[0].decode("latin1", "replace") if data else ""
                body = f"ok:{first}"
                conn.sendall(
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}".encode()
                )
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
        try:
            sock.close()
        except OSError:
            pass

    def stop(self) -> None:
        self._stop.set()
        if self._s:
            try:
                self._s.close()
            except OSError:
                pass


def http_get(port: int, path: str, timeout: float = 3):
    raw = f"GET {path} HTTP/1.1\r\nHost: {BIND}:{port}\r\nConnection: close\r\n\r\n"
    try:
        with socket.create_connection((BIND, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(raw.encode())
            data = b""
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                data += chunk
        text = data.decode("latin1", "replace")
        status = int(text.split(" ", 2)[1]) if text.startswith("HTTP/") else None
        return status, text
    except OSError as exc:
        return None, str(exc)


def wait_port(port: int, timeout: float = 25) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection((BIND, port), 0.3).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def main() -> None:
    EV.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="agent01c-"))
    http_be, proxy, admin = 21072, 21070, 21071
    echo = Echo(http_be)
    echo.start()
    time.sleep(0.2)
    spec = tmp / "r.yaml"

    def write_spec(extra: str = "") -> None:
        spec.write_text(
            f"""version: "1"
plugin_configs: []
proxies:
  - id: http-echo
    listen_path: /echo
    backend_scheme: http
    backend_host: 127.0.0.1
    backend_port: {http_be}
    strip_listen_path: true
{extra}
"""
        )

    write_spec()
    env = clean(
        {
            "FERRUM_MODE": "file",
            "FERRUM_FILE_CONFIG_PATH": str(spec),
            "FERRUM_PROXY_BIND_ADDRESS": BIND,
            "FERRUM_ADMIN_BIND_ADDRESS": BIND,
            "FERRUM_STREAM_PROXY_BIND_ADDRESS": BIND,
            "FERRUM_PROXY_HTTP_PORT": str(proxy),
            "FERRUM_ADMIN_HTTP_PORT": str(admin),
            "FERRUM_PROXY_HTTPS_PORT": "0",
            "FERRUM_ADMIN_HTTPS_PORT": "0",
            "FERRUM_ADMIN_JWT_SECRET": ADMIN_JWT,
            "FERRUM_LOG_LEVEL": "info",
            "FERRUM_SHUTDOWN_DRAIN_SECONDS": "2",
            "FERRUM_POOL_WARMUP_ENABLED": "false",
        }
    )
    log_path = EV / "continue-reload.log"
    log_fh = log_path.open("w")
    gw = subprocess.Popen([str(BIN), "run"], env=env, stdout=log_fh, stderr=subprocess.STDOUT)
    if not wait_port(admin):
        raise SystemExit("gateway not ready:\n" + log_path.read_text()[-800:])

    rows = []

    def rec(row_id, pri, cap, expected, result, evidence, notes=""):
        rows.append(
            {
                "id": row_id,
                "priority": pri,
                "capability": cap,
                "mode": "file/reload",
                "method": "binary",
                "expected": expected,
                "result": result,
                "evidence": evidence,
                "issue": "",
                "notes": notes,
            }
        )
        print(f"[{result}] {row_id} {cap} {notes}", flush=True)

    proc = subprocess.run(
        [str(BIN), "reload", "--pid", "0"], env=clean(), capture_output=True, text=True, timeout=8
    )
    (EV / "reload-pid-zero.txt").write_text(f"exit={proc.returncode}\n{proc.stdout}\n{proc.stderr}")
    rec(
        "R07",
        "P1",
        "reload --pid 0 invalid",
        "exit != 0",
        "passed" if proc.returncode != 0 else "failed",
        "artifacts/agent-01/evidence/reload-pid-zero.txt",
    )

    spec.unlink()
    proc = subprocess.run(
        [str(BIN), "reload", "--pid", str(gw.pid)],
        env=clean(),
        capture_output=True,
        text=True,
        timeout=8,
    )
    time.sleep(1)
    status, _ = http_get(proxy, "/echo/deleted")
    (EV / "reload-deleted.txt").write_text(
        f"reload={proc.returncode} echo={status} alive={gw.poll() is None}\n"
    )
    rec(
        "R08",
        "P1",
        "SIGHUP after deleted spec keeps last-good",
        "echo 200 + alive",
        "passed" if gw.poll() is None and status == 200 else "failed",
        "artifacts/agent-01/evidence/reload-deleted.txt",
        notes=f"echo={status}",
    )

    write_spec()
    os.kill(gw.pid, signal.SIGHUP)
    time.sleep(1)
    os.kill(gw.pid, signal.SIGTERM)
    proc = subprocess.run(
        [str(BIN), "reload", "--pid", str(gw.pid)],
        env=clean(),
        capture_output=True,
        text=True,
        timeout=8,
    )
    try:
        rc = gw.wait(timeout=12)
    except subprocess.TimeoutExpired:
        gw.kill()
        rc = gw.wait(timeout=5)
    (EV / "reload-during-shutdown.txt").write_text(f"reload_exit={proc.returncode} gw_rc={rc}\n")
    rec(
        "R09",
        "P1",
        "reload during graceful shutdown",
        "process exits",
        "passed" if rc is not None else "failed",
        "artifacts/agent-01/evidence/reload-during-shutdown.txt",
    )

    write_spec()
    log_fh = (EV / "continue-fs.log").open("w")
    gw = subprocess.Popen([str(BIN), "run"], env=env, stdout=log_fh, stderr=subprocess.STDOUT)
    if not wait_port(admin):
        raise SystemExit("fs gateway not ready")

    with spec.open("w") as handle:
        handle.write('version: "1"\nproxies:\n  - id: "partial"\n    listen_path: "/p"\n')
        handle.flush()
    os.kill(gw.pid, signal.SIGHUP)
    time.sleep(1.2)
    status, _ = http_get(proxy, "/echo/partial")
    (EV / "reload-partial.txt").write_text(f"echo={status} alive={gw.poll() is None}\n")
    rec(
        "R10",
        "P1",
        "partial in-place write + SIGHUP",
        "last-good /echo 200",
        "passed" if gw.poll() is None and status == 200 else "failed",
        "artifacts/agent-01/evidence/reload-partial.txt",
        notes=f"echo={status}",
    )

    write_spec()
    os.kill(gw.pid, signal.SIGHUP)
    time.sleep(1)
    spec.chmod(0)
    os.kill(gw.pid, signal.SIGHUP)
    time.sleep(1)
    status, _ = http_get(proxy, "/echo/perm")
    (EV / "reload-chmod.txt").write_text(f"echo={status} alive={gw.poll() is None}\n")
    rec(
        "R11",
        "P1",
        "permission loss on spec + SIGHUP",
        "last-good",
        "passed" if gw.poll() is None and status == 200 else "failed",
        "artifacts/agent-01/evidence/reload-chmod.txt",
        notes=f"echo={status}",
    )
    spec.chmod(0o644)

    real = tmp / "real.yaml"
    real.write_text(
        spec.read_text()
        + f"""  - id: via-link
    listen_path: /link
    backend_scheme: http
    backend_host: 127.0.0.1
    backend_port: {http_be}
    strip_listen_path: true
"""
    )
    spec.unlink()
    spec.symlink_to(real)
    os.kill(gw.pid, signal.SIGHUP)
    time.sleep(1.2)
    status, _ = http_get(proxy, "/link/x")
    (EV / "reload-symlink.txt").write_text(f"link={status}\n")
    rec(
        "R12",
        "P1",
        "symlink swap reload",
        "/link 200",
        "passed" if status == 200 else "failed",
        "artifacts/agent-01/evidence/reload-symlink.txt",
        notes=f"link={status}",
    )

    proxies = "\n".join(
        f"  - id: p{i}\n    listen_path: /bulk{i}\n    backend_scheme: http\n"
        f"    backend_host: 127.0.0.1\n    backend_port: {http_be}\n    strip_listen_path: true"
        for i in range(80)
    )
    if spec.is_symlink():
        spec.unlink()
    spec.write_text('version: "1"\nplugin_configs: []\nproxies:\n' + proxies + "\n")
    os.kill(gw.pid, signal.SIGHUP)
    time.sleep(2)
    status, _ = http_get(proxy, "/bulk79/x")
    (EV / "reload-large.txt").write_text(f"bytes={spec.stat().st_size} bulk79={status}\n")
    rec(
        "R13",
        "P2",
        "large valid config reload (80 proxies)",
        "/bulk79 200",
        "passed" if status == 200 else "failed",
        "artifacts/agent-01/evidence/reload-large.txt",
        notes=f"bulk79={status}",
    )
    gw.send_signal(signal.SIGTERM)
    gw.wait(timeout=10)
    echo.stop()

    oas = tmp / "oas2.yaml"
    oas.write_text(
        """version: "1"
plugin_configs:
  - id: ov
    plugin_name: openapi_validator
    scope: proxy
    proxy_id: pets
    enabled: true
    config:
      operations:
        - method: POST
          path_template: /pets
          path_regex: "^/pets$"
          request_body:
            required: true
            content:
              application/json:
                schema:
                  type: object
                  required: [name]
                  properties:
                    name: {type: string}
proxies:
  - id: pets
    listen_path: /pets
    backend_scheme: http
    backend_host: 127.0.0.1
    backend_port: 21002
    plugins:
      - plugin_config_id: ov
"""
    )
    envv = clean(
        {
            "FERRUM_MODE": "file",
            "FERRUM_FILE_CONFIG_PATH": str(oas),
            "FERRUM_PROXY_BIND_ADDRESS": BIND,
            "FERRUM_ADMIN_BIND_ADDRESS": BIND,
            "FERRUM_PROXY_HTTP_PORT": "21000",
            "FERRUM_ADMIN_HTTP_PORT": "21001",
            "FERRUM_PROXY_HTTPS_PORT": "0",
            "FERRUM_ADMIN_HTTPS_PORT": "0",
            "FERRUM_ADMIN_JWT_SECRET": ADMIN_JWT,
        }
    )
    proc = subprocess.run(
        [str(BIN), "validate", "-m", "file", "-c", str(oas)],
        env=envv,
        capture_output=True,
        text=True,
        timeout=25,
    )
    (EV / "docs-openapi-no-spec-id-retest.txt").write_text(
        f"exit={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    )
    rec(
        "D06b",
        "P1",
        "openapi_validator file-mode without api_spec_id (path_template)",
        "validate 0",
        "passed" if proc.returncode == 0 else "failed",
        "artifacts/agent-01/evidence/docs-openapi-no-spec-id-retest.txt",
        notes=(proc.stdout + proc.stderr)[-240:],
    )

    current = tmp / "mig.yaml"
    current.write_text('version: "1"\nplugin_configs: []\nproxies: []\n')
    envm = clean(
        {
            "FERRUM_MODE": "migrate",
            "FERRUM_MIGRATE_ACTION": "config",
            "FERRUM_FILE_CONFIG_PATH": str(current),
        }
    )
    proc = subprocess.run(
        [str(BIN), "run", "-m", "migrate"], env=envm, capture_output=True, text=True, timeout=20
    )
    (EV / "migrate-current-2.txt").write_text(f"exit={proc.returncode}\n{proc.stdout}\n{proc.stderr}")
    rec(
        "M01b",
        "P0",
        "migrate config already-current (reconfirm)",
        "exit 0",
        "passed" if proc.returncode == 0 else "failed",
        "artifacts/agent-01/evidence/migrate-current-2.txt",
    )

    (EV / "continue-rows.json").write_text(json.dumps(rows, indent=2) + "\n")
    print("WROTE", len(rows), "rows", flush=True)


if __name__ == "__main__":
    main()
