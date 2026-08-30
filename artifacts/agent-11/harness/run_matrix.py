#!/usr/bin/env python3
"""fe-agent-11- plugin-lifecycle file-mode matrix. Loopback only. No cargo test."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIX = ROOT / "artifacts" / "agent-11" / "fixtures"
EVIDENCE = ROOT / "artifacts" / "agent-11" / "evidence"
BIN = Path(os.environ.get("FERRUM_BIN", ROOT / "target" / "debug" / "ferrum-edge"))
PROXY_PORT = int(os.environ.get("FE_AGENT11_PROXY_PORT", "22000"))
ADMIN_PORT = int(os.environ.get("FE_AGENT11_ADMIN_PORT", "22001"))
BACKEND_PORT = int(os.environ.get("FE_AGENT11_BACKEND_PORT", "22002"))
PREFIX = "fe-agent-11-"


def atomic_copy(src: Path, dest: Path) -> None:
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    shutil.copy2(src, tmp)
    tmp.replace(dest)


def run_validate(fixture: Path) -> dict:
    env = os.environ.copy()
    env["FERRUM_MODE"] = "file"
    env["FERRUM_FILE_CONFIG_PATH"] = str(fixture)
    env["FERRUM_PROXY_HTTP_PORT"] = str(PROXY_PORT)
    env["FERRUM_PROXY_HTTPS_PORT"] = "0"
    env["FERRUM_ADMIN_HTTP_PORT"] = str(ADMIN_PORT)
    env["FERRUM_ADMIN_HTTPS_PORT"] = "0"
    env["FERRUM_PROXY_BIND_ADDRESS"] = "127.0.0.1"
    env["FERRUM_ADMIN_BIND_ADDRESS"] = "127.0.0.1"
    env["FERRUM_LOG_LEVEL"] = "warn"
    proc = subprocess.run(
        [str(BIN), "validate", "-m", "file", "-c", str(fixture)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return {
        "fixture": fixture.name,
        "exit": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-8000:],
    }


def http_get(url: str, timeout: float = 3.0) -> tuple[int, str, dict[str, str]]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body, headers
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        headers = {k.lower(): v for k, v in exc.headers.items()}
        return exc.code, body, headers


def wait_live(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/live"
    while time.time() < deadline:
        try:
            status, body, _ = http_get(url, timeout=1.0)
            if status == 200 and "ok" in body:
                return True
        except Exception:
            time.sleep(0.2)
    return False


def start_backend(port: int) -> subprocess.Popen:
    script = r"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = {
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
        }
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def log_message(self, fmt, *args):
        return

ThreadingHTTPServer(("127.0.0.1", %d), H).serve_forever()
""" % port
    return subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def start_gateway(config_path: Path, workdir: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env.update(
        {
            "FERRUM_MODE": "file",
            "FERRUM_FILE_CONFIG_PATH": str(config_path),
            "FERRUM_PROXY_HTTP_PORT": str(PROXY_PORT),
            "FERRUM_PROXY_HTTPS_PORT": "0",
            "FERRUM_ADMIN_HTTP_PORT": str(ADMIN_PORT),
            "FERRUM_ADMIN_HTTPS_PORT": "0",
            "FERRUM_PROXY_BIND_ADDRESS": "127.0.0.1",
            "FERRUM_ADMIN_BIND_ADDRESS": "127.0.0.1",
            "FERRUM_LOG_LEVEL": "info",
        }
    )
    log = open(workdir / "gateway.log", "w")
    return subprocess.Popen(
        [str(BIN), "run", "-m", "file", "-c", str(config_path)],
        cwd=str(ROOT),
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def main() -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    if not BIN.is_file():
        print(f"missing binary: {BIN}", file=sys.stderr)
        return 2

    validate_cases = [
        ("base-good", "base-good.yaml", 0),
        ("proxy-id-only-4038", "proxy-id-only.yaml", 0),
        ("unknown-plugin-name", "unknown-plugin-name.yaml", 1),
        ("unknown-envelope-field", "unknown-envelope-field.yaml", 1),
        ("jwt-unknown-key", "jwt-unknown-key.yaml", 1),
        ("cors-unknown-key", "cors-unknown-key.yaml", 1),
        ("rsl-unknown-key", "rsl-unknown-key.yaml", None),
        ("wsmsl-unknown-key", "wsmsl-unknown-key.yaml", None),
        ("http-logging-unknown-key", "http-logging-unknown-key.yaml", None),
        ("prom-unknown-key", "prom-unknown-key.yaml", None),
        ("stdout-unknown-key", "stdout-unknown-key.yaml", 0),
        ("removed-oauth2-auth", "removed-oauth2-auth.yaml", 1),
        ("a2a-unknown-key", "a2a-unknown-key.yaml", None),
        ("ws-logging-unknown-key", "ws-logging-unknown-key.yaml", None),
        ("disabled-unknown-name", "disabled-unknown-name.yaml", 0),
        ("ordering", "ordering.yaml", 0),
        ("reload-start", "reload-start.yaml", 0),
        ("reload-add-terminate", "reload-add-terminate.yaml", 0),
        ("reload-fail-closed", "reload-fail-closed.yaml", 1),
    ]

    rows = []
    for name, filename, expected in validate_cases:
        result = run_validate(FIX / filename)
        result["name"] = name
        result["expected_exit"] = expected
        if expected is None:
            result["verdict"] = "OBSERVE"
        elif result["exit"] == expected:
            result["verdict"] = "PASS"
        else:
            result["verdict"] = "FAIL"
        warn = "unknown" in result["stderr"].lower() or "unknown" in result["stdout"].lower()
        result["mentions_unknown"] = warn
        result["passed_phrase"] = "Validation passed" in result["stdout"] or "Validation passed" in result["stderr"]
        rows.append(result)
        print(f"VALIDATE {name}: exit={result['exit']} expected={expected} verdict={result['verdict']}")

    runtime = {}
    backend = start_backend(BACKEND_PORT)
    time.sleep(0.3)
    try:
        with tempfile.TemporaryDirectory(prefix=PREFIX) as td:
            work = Path(td)
            live = work / "live.yaml"
            atomic_copy(FIX / "proxy-id-only.yaml", live)
            gw = start_gateway(live, work)
            try:
                ready = wait_live(ADMIN_PORT, timeout=25)
                runtime["live_ready"] = ready
                if ready:
                    status, body, _ = http_get(f"http://127.0.0.1:{PROXY_PORT}/error")
                    runtime["proxy_id_only_status"] = status
                    runtime["proxy_id_only_body"] = body[:500]
                    runtime["proxy_id_only_is_418"] = status == 418

                    atomic_copy(FIX / "base-good.yaml", live)
                    os.kill(gw.pid, signal.SIGHUP)
                    time.sleep(1.5)
                    status, body, _ = http_get(f"http://127.0.0.1:{PROXY_PORT}/error")
                    runtime["associated_after_hup_status"] = status
                    runtime["associated_after_hup_body"] = body[:500]
                    runtime["associated_is_418"] = status == 418

                    atomic_copy(FIX / "reload-fail-closed.yaml", live)
                    os.kill(gw.pid, signal.SIGHUP)
                    time.sleep(1.5)
                    status, body, _ = http_get(f"http://127.0.0.1:{PROXY_PORT}/error")
                    runtime["after_failclosed_hup_status"] = status
                    runtime["after_failclosed_kept_418"] = status == 418
                    log = (work / "gateway.log").read_text(errors="replace")
                    runtime["log_kept_previous"] = "keeping previous" in log.lower() or "reload rejected" in log.lower()
                    runtime["log_tail"] = log[-3000:]
                else:
                    runtime["error"] = "gateway /live not ready"
                    runtime["log_tail"] = (work / "gateway.log").read_text(errors="replace")[-3000:]
            finally:
                try:
                    os.killpg(gw.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    gw.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    os.killpg(gw.pid, signal.SIGKILL)
                    gw.wait(timeout=3)

        with tempfile.TemporaryDirectory(prefix=PREFIX + "ord-") as td:
            work = Path(td)
            live = work / "live.yaml"
            atomic_copy(FIX / "ordering.yaml", live)
            gw = start_gateway(live, work)
            try:
                ready = wait_live(ADMIN_PORT, timeout=25)
                runtime["ordering_ready"] = ready
                if ready:
                    status, body, _ = http_get(f"http://127.0.0.1:{PROXY_PORT}/echo")
                    runtime["ordering_status"] = status
                    runtime["ordering_body"] = body[:800]
                    try:
                        payload = json.loads(body)
                        hdrs = payload.get("headers", {})
                        runtime["ordering_saw_early"] = hdrs.get("x-fe-early") == "early"
                        runtime["ordering_saw_late"] = hdrs.get("x-fe-late") == "late"
                    except json.JSONDecodeError:
                        runtime["ordering_json"] = False
                else:
                    runtime["ordering_log"] = (work / "gateway.log").read_text(errors="replace")[-2000:]
            finally:
                try:
                    os.killpg(gw.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    gw.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    os.killpg(gw.pid, signal.SIGKILL)
                    gw.wait(timeout=3)
    finally:
        backend.terminate()
        try:
            backend.wait(timeout=3)
        except subprocess.TimeoutExpired:
            backend.kill()

    report = {
        "sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(ROOT), text=True).strip(),
        "binary": str(BIN),
        "ports": {"proxy": PROXY_PORT, "admin": ADMIN_PORT, "backend": BACKEND_PORT},
        "validate": rows,
        "runtime": runtime,
    }
    (EVIDENCE / "matrix.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"validate_verdicts": {r["name"]: r["verdict"] for r in rows}, "runtime_keys": list(runtime)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
