#!/usr/bin/env python3
"""Launch-readiness Admin API live probe (agent 13). Investigation only."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

WORKDIR = Path("/tmp/fe-agent-13")
WORKDIR.mkdir(parents=True, exist_ok=True)
BIN = os.environ.get("FERRUM_BIN", "/workspace/target/debug/ferrum-edge")
SECRET = "fe-agent-13-admin-jwt-secret-32chars!!"
RESULTS: list[dict[str, Any]] = []
PROCS: list[subprocess.Popen] = []


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def mint_jwt(
    secret: str = SECRET,
    role: str | None = "admin",
    iss: str = "ferrum-edge",
    alg: str = "HS256",
    extra: dict[str, Any] | None = None,
    exp_offset: int = 1800,
    nbf_offset: int = 0,
    iat_offset: int = 0,
    include_role: bool = True,
) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": iss,
        "sub": "fe-agent-13",
        "iat": now + iat_offset,
        "nbf": now + nbf_offset,
        "exp": now + exp_offset,
        "jti": str(uuid.uuid4()),
    }
    if include_role and role is not None:
        payload["role"] = role
    if extra:
        payload.update(extra)
    header = {"alg": alg, "typ": "JWT"}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing = f"{h}.{p}".encode()
    if alg == "none":
        sig = ""
    else:
        sig = b64url(hmac.new(secret.encode(), signing, hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def http(
    method: str,
    url: str,
    token: str | None = None,
    body: Any = None,
    headers: dict[str, str] | None = None,
    timeout: float = 8.0,
) -> tuple[int, dict[str, str], Any]:
    data = None
    req_headers = {"Accept": "application/json"}
    if token is not None:
        req_headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode()
        req_headers["Content-Type"] = "application/json"
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            parsed: Any
            if raw:
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    parsed = raw.decode("utf-8", "replace")
            else:
                parsed = None
            return resp.status, hdrs, parsed
    except urllib.error.HTTPError as e:
        raw = e.read()
        hdrs = {k.lower(): v for k, v in e.headers.items()}
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = raw.decode("utf-8", "replace")
        return e.code, hdrs, parsed
    except Exception as e:
        return 0, {}, {"error": str(e)}


def record(name: str, ok: bool, detail: Any, expected: str = "", observed: str = "") -> None:
    RESULTS.append(
        {
            "name": name,
            "ok": ok,
            "expected": expected,
            "observed": observed,
            "detail": detail,
        }
    )
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}: {observed or detail}")


def expect_status(
    name: str,
    status: int,
    want: int | set[int],
    body: Any,
    extra_ok: bool = True,
    expected: str = "",
) -> bool:
    wanted = want if isinstance(want, set) else {want}
    ok = status in wanted and extra_ok
    record(
        name,
        ok,
        body,
        expected or f"HTTP {sorted(wanted)}",
        f"HTTP {status} {body if isinstance(body, (str, int)) else json.dumps(body, default=str)[:240]}",
    )
    return ok


def wait_live(base: str, timeout: float = 45.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status, _, body = http("GET", f"{base}/live", token=None, timeout=2.0)
        if status == 200 and isinstance(body, dict) and body.get("status") == "ok":
            return True
        time.sleep(0.25)
    return False


def start_gateway(name: str, env: dict[str, str], log_path: Path) -> subprocess.Popen:
    full_env = os.environ.copy()
    # Avoid leaking parent ferrum config.
    for key in list(full_env):
        if key.startswith("FERRUM_"):
            del full_env[key]
    full_env.update(env)
    log = log_path.open("w")
    proc = subprocess.Popen(
        [BIN, "run"],
        env=full_env,
        stdout=log,
        stderr=subprocess.STDOUT,
        cwd="/workspace",
    )
    PROCS.append(proc)
    return proc


def stop_all() -> None:
    for proc in PROCS:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
    deadline = time.time() + 8
    for proc in PROCS:
        while proc.poll() is None and time.time() < deadline:
            time.sleep(0.1)
        if proc.poll() is None:
            proc.kill()


def common_env(admin_port: int, proxy_port: int) -> dict[str, str]:
    return {
        "FERRUM_ADMIN_HTTP_PORT": str(admin_port),
        "FERRUM_ADMIN_HTTPS_PORT": "0",
        "FERRUM_PROXY_HTTP_PORT": str(proxy_port),
        "FERRUM_PROXY_HTTPS_PORT": "0",
        "FERRUM_ADMIN_BIND_ADDRESS": "127.0.0.1",
        "FERRUM_BIND_ADDRESS": "127.0.0.1",
        "FERRUM_ADMIN_JWT_SECRET": SECRET,
        "FERRUM_ADMIN_JWT_ISSUER": "ferrum-edge",
        "FERRUM_LOG_LEVEL": "warn",
        "FERRUM_POOL_WARMUP_ENABLED": "false",
        "FERRUM_SHUTDOWN_DRAIN_SECONDS": "1",
        "FERRUM_BASIC_AUTH_HMAC_SECRET": "fe-agent-13-basic-hmac-secret-32chars",
    }


def probe_unauth_and_jwt(base: str) -> None:
    admin = mint_jwt(role="admin")
    operator = mint_jwt(role="operator")
    viewer = mint_jwt(role="viewer")

    status, _, body = http("GET", f"{base}/live")
    expect_status("unauth GET /live", status, 200, body, extra_ok=isinstance(body, dict) and body == {"status": "ok"})

    status, _, body = http("GET", f"{base}/health")
    coarse_ok = (
        status in {200, 503}
        and isinstance(body, dict)
        and set(body.keys()) <= {"status", "ready"}
        and "mode" not in body
    )
    expect_status(
        "unauth GET /health coarse",
        status,
        {200, 503},
        body,
        extra_ok=coarse_ok,
        expected="200/503 with only status+ready",
    )

    status, _, body = http("GET", f"{base}/proxies")
    expect_status("missing JWT GET /proxies", status, 401, body)

    status, _, body = http("GET", f"{base}/proxies", headers={"Authorization": "Bearer not-a-jwt"})
    expect_status("malformed JWT GET /proxies", status, 401, body)

    status, _, body = http("GET", f"{base}/proxies", token=mint_jwt(secret="wrong-secret-fe-agent-13-xxxxxxxxxx"))
    expect_status("wrong secret GET /proxies", status, 401, body)

    status, _, body = http("GET", f"{base}/proxies", token=mint_jwt(alg="none"))
    expect_status("alg=none GET /proxies", status, 401, body)

    status, _, body = http("GET", f"{base}/proxies", token=mint_jwt(alg="HS384"))
    expect_status("alg=HS384 GET /proxies", status, 401, body)

    status, _, body = http("GET", f"{base}/proxies", token=mint_jwt(exp_offset=-30, iat_offset=-120))
    expect_status("expired JWT GET /proxies", status, 401, body)

    status, _, body = http("GET", f"{base}/proxies", token=mint_jwt(nbf_offset=120, exp_offset=400))
    expect_status("future nbf GET /proxies", status, 401, body)

    status, _, body = http("GET", f"{base}/proxies", token=mint_jwt(iss="not-ferrum"))
    expect_status("wrong iss GET /proxies", status, 401, body)

    status, _, body = http("GET", f"{base}/proxies", token=mint_jwt(include_role=False))
    expect_status("missing role GET /proxies", status, 401, body)

    status, _, body = http("GET", f"{base}/proxies", token=mint_jwt(extra={"aud": "other-service"}))
    expect_status("unexpected aud GET /proxies", status, 401, body)

    status, _, body = http("GET", f"{base}/proxies", token=viewer)
    expect_status("viewer GET /proxies", status, 200, body)

    status, _, body = http("POST", f"{base}/proxies", token=viewer, body={"listen_path": "/nope", "backend_host": "127.0.0.1", "backend_port": 9, "backend_scheme": "http"})
    expect_status("viewer POST /proxies", status, 403, body)

    status, _, body = http("POST", f"{base}/consumers", token=operator, body={"username": "op-cannot"})
    expect_status("operator POST /consumers", status, 403, body)

    status, _, body = http("GET", f"{base}/audit", token=operator)
    expect_status("operator GET /audit", status, 403, body)

    status, _, body = http("GET", f"{base}/backup", token=viewer)
    expect_status("viewer GET /backup", status, 403, body, expected="403 admin-only unredacted export")

    status, _, body = http("GET", f"{base}/health", token=admin)
    detailed_ok = isinstance(body, dict) and "mode" in body
    expect_status("admin GET /health detailed", status, {200, 503}, body, extra_ok=detailed_ok)

    status, _, body = http("GET", f"{base}/namespaces", token=admin)
    expect_status("admin GET /namespaces", status, 200, body)


def probe_file_mode(base: str) -> None:
    admin = mint_jwt()
    status, _, body = http(
        "POST",
        f"{base}/proxies",
        token=admin,
        body={"id": "fe-agent-13-file-write", "listen_path": "/x", "backend_host": "127.0.0.1", "backend_port": 9, "backend_scheme": "http"},
    )
    expect_status(
        "file-mode POST /proxies",
        status,
        403,
        body,
        extra_ok=isinstance(body, dict) and body.get("error") == "Admin API is in read-only mode",
        expected="403 Admin API is in read-only mode",
    )

    status, _, body = http("POST", f"{base}/batch", token=admin, body={"proxies": []})
    expect_status(
        "file-mode POST /batch",
        status,
        403,
        body,
        extra_ok=isinstance(body, dict) and body.get("error") == "Admin API is in read-only mode",
    )

    status, _, body = http("GET", f"{base}/backup", token=admin)
    expect_status("file-mode GET /backup", status, 200, body)

    status, _, body = http("POST", f"{base}/restore?confirm=true", token=admin, body={"proxies": []})
    expect_status(
        "file-mode POST /restore",
        status,
        503,
        body,
        extra_ok=isinstance(body, dict) and body.get("error") == "No database",
        expected="503 {error: No database} (docs/admin_backup_restore.md; closed #4027)",
    )

    status, _, body = http(
        "POST",
        f"{base}/api-specs",
        token=admin,
        body={"openapi": "3.1.0", "info": {"title": "x", "version": "1"}, "x-ferrum-proxy": {"listen_path": "/s", "backend_host": "127.0.0.1", "backend_port": 9}},
        headers={"Content-Type": "application/json"},
    )
    expect_status(
        "file-mode POST /api-specs",
        status,
        403,
        body,
        extra_ok=isinstance(body, dict) and "read-only" in str(body.get("error", "")).lower(),
        expected="403 read-only (docs/admin_api.md mode table)",
    )

    status, _, body = http("GET", f"{base}/api-specs", token=admin)
    expect_status(
        "file-mode GET /api-specs",
        status,
        503,
        body,
        extra_ok=isinstance(body, dict) and "database" in str(body.get("error", "")).lower(),
        expected="503 no database",
    )

    status, _, body = http("GET", f"{base}/proxies", token=admin)
    expect_status("file-mode GET /proxies", status, 200, body)

    status, _, body = http("POST", f"{base}/namespaces", token=admin, body={"name": "fe-agent-13-empty"})
    expect_status(
        "file-mode POST /namespaces",
        status,
        403,
        body,
        extra_ok=isinstance(body, dict) and "read-only" in str(body.get("error", "")).lower(),
    )


def probe_database_crud(base: str) -> None:
    admin = mint_jwt()
    operator = mint_jwt(role="operator")
    ns = {"X-Ferrum-Namespace": "fe-agent-13-tenant"}

    status, _, body = http("POST", f"{base}/namespaces", token=admin, body={"name": "fe-agent-13-tenant", "description": "agent 13"})
    expect_status("POST /namespaces empty tenant", status, {201, 409}, body)

    status, hdrs, body = http(
        "POST",
        f"{base}/upstreams",
        token=operator,
        headers=ns,
        body={
            "id": "fe-agent-13-up",
            "name": "fe-agent-13-up",
            "targets": [{"host": "127.0.0.1", "port": 9, "weight": 1}],
            "algorithm": "round_robin",
        },
    )
    other_ns_cursor = hdrs.get("x-ferrum-config-cursor")
    expect_status(
        "POST /upstreams other-namespace (no local live-apply cursor)",
        status,
        201,
        {"body": body, "cursor": other_ns_cursor},
        extra_ok=other_ns_cursor is None,
        expected="201 without cursor when this process does not serve the namespace (docs/admin_api.md)",
    )

    # Default served namespace should capture a covering cursor on 201.
    status, hdrs, body = http(
        "POST",
        f"{base}/upstreams",
        token=operator,
        body={
            "id": "fe-agent-13-up-ferrum",
            "targets": [{"host": "127.0.0.1", "port": 9, "weight": 1}],
            "algorithm": "round_robin",
        },
    )
    cursor = hdrs.get("x-ferrum-config-cursor")
    expect_status(
        "POST /upstreams served-namespace 201 + cursor header",
        status,
        201,
        {"body": body, "cursor": cursor, "headers": {k: v for k, v in hdrs.items() if k.startswith("x-")}},
        extra_ok=bool(cursor),
        expected="201 with X-Ferrum-Config-Cursor on served namespace (runtime; OpenAPI only documents 202 — #4287)",
    )

    status, _, body = http(
        "POST",
        f"{base}/proxies",
        token=operator,
        headers=ns,
        body={
            "id": "fe-agent-13-px-up",
            "listen_path": "/fe-agent-13-via-up",
            "backend_scheme": "http",
            "upstream_id": "fe-agent-13-up",
        },
    )
    expect_status(
        "POST /proxies with upstream_id omits host/port",
        status,
        201,
        body,
        expected="201 (closed #4029)",
    )

    status, _, body = http("DELETE", f"{base}/upstreams/fe-agent-13-up", token=operator, headers=ns)
    expect_status(
        "DELETE referenced upstream",
        status,
        409,
        body,
        extra_ok=isinstance(body, dict) and "referenced" in str(body.get("error", "")).lower(),
        expected="409 referenced by proxies (closed #4044)",
    )

    status, _, body = http(
        "POST",
        f"{base}/consumers",
        token=admin,
        headers=ns,
        body={"id": "fe-agent-13-cs", "username": "feagent13user", "credentials": {"keyauth": [{"key": "fe-agent-13-key"}]}},
    )
    expect_status("POST /consumers", status, 201, body)

    if isinstance(body, dict):
        creds = body.get("credentials") or {}
        key = ((creds.get("keyauth") or [{}])[0] or {}).get("key")
        expect_status(
            "consumer keyauth redacted",
            200 if key == "[REDACTED]" else 500,
            200,
            {"key": key},
            expected="ordinary GET/POST response redacts keyauth.key",
        )

    status, _, body = http(
        "POST",
        f"{base}/plugins/config",
        token=operator,
        headers=ns,
        body={
            "id": "fe-agent-13-acl",
            "plugin_name": "access_control",
            "enabled": True,
            "scope": "proxy",
            "proxy_id": "fe-agent-13-px-up",
            "config": {"allowed_consumers": ["feagent13user"]},
        },
    )
    expect_status("POST /plugins/config access_control", status, 201, body)

    status, _, body = http(
        "POST",
        f"{base}/plugins/config",
        token=operator,
        headers=ns,
        body={"name": "stdout_logging", "enabled": True, "scope": "global", "config": {}},
    )
    expect_status(
        "POST /plugins/config with name not plugin_name",
        status,
        400,
        body,
        extra_ok=isinstance(body, dict) and "plugin_name" in str(body.get("error", "")),
        expected="400 unknown field name (closed #4031)",
    )

    status, _, body = http("DELETE", f"{base}/consumers/fe-agent-13-cs", token=admin, headers=ns)
    expect_status(
        "DELETE consumer referenced by access_control",
        status,
        409,
        body,
        extra_ok=isinstance(body, dict) and "access_control" in str(body.get("error", "")).lower(),
        expected="409 (closed #4045)",
    )

    status, _, body = http(
        "POST",
        f"{base}/batch",
        token=admin,
        headers=ns,
        body={
            "updates": {"proxies": [{"id": "fe-agent-13-px-up", "listen_path": "/nope"}]},
            "deletes": {"proxies": ["fe-agent-13-px-up"]},
            "dry_run": True,
            "proxies": [
                {
                    "id": "fe-agent-13-px-unk",
                    "listen_path": "/fe-agent-13-unk",
                    "backend_scheme": "http",
                    "backend_host": "127.0.0.1",
                    "backend_port": 9,
                }
            ],
        },
    )
    expect_status(
        "POST /batch unknown envelope keys updates/deletes/dry_run",
        status,
        400,
        body,
        expected="400 deny unknown top-level keys (closed #4042)",
    )

    status, _, body = http(
        "POST",
        f"{base}/batch",
        token=admin,
        headers=ns,
        body={
            "consumers": [{"id": "fe-agent-13-batch-cs", "username": "batchuser13", "credentials": {"keyauth": [{"key": "k13"}]}}],
            "proxies": [
                {
                    "id": "fe-agent-13-batch-px",
                    "listen_path": "/fe-agent-13-batch",
                    "backend_scheme": "http",
                    "backend_host": "127.0.0.1",
                    "backend_port": 9,
                }
            ],
            "plugin_configs": [
                {
                    "id": "fe-agent-13-batch-pc",
                    "plugin_name": "stdout_logging",
                    "enabled": True,
                    "scope": "proxy",
                    "proxy_id": "fe-agent-13-batch-px",
                    "config": {},
                }
            ],
        },
    )
    expect_status("POST /batch valid create", status, 201, body)

    status, _, body = http("GET", f"{base}/proxies/fe-agent-13-batch-px", token=admin, headers=ns)
    expect_status("GET batch-created proxy", status, 200, body)

    other = {"X-Ferrum-Namespace": "fe-agent-13-other"}
    status, _, body = http("GET", f"{base}/proxies/fe-agent-13-batch-px", token=admin, headers=other)
    expect_status(
        "cross-namespace GET proxy isolated",
        status,
        404,
        body,
        expected="404 in a different X-Ferrum-Namespace",
    )

    status, _, body = http(
        "POST",
        f"{base}/proxies",
        token=admin,
        headers=other,
        body={
            "id": "fe-agent-13-other-px",
            "listen_path": "/fe-agent-13-other",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 9,
        },
    )
    expect_status("POST proxy in other namespace", status, 201, body)

    status, _, body = http("DELETE", f"{base}/proxies/fe-agent-13-px-up", token=operator, headers=ns)
    expect_status("DELETE last proxy referencing hand-owned upstream (default cleanup)", status, 204, body)

    status, _, body = http("GET", f"{base}/upstreams/fe-agent-13-up", token=operator, headers=ns)
    expect_status(
        "GET hand-owned upstream after last proxy delete (default orphan-clean)",
        status,
        404,
        body,
        expected="404 default cleanup (closed #4046/#4064; opt-out exists)",
    )

    # Recreate upstream + two proxies to test opt-out flag.
    status, _, body = http(
        "POST",
        f"{base}/upstreams",
        token=operator,
        headers=ns,
        body={
            "id": "fe-agent-13-up-keep",
            "targets": [{"host": "127.0.0.1", "port": 9, "weight": 1}],
            "algorithm": "round_robin",
        },
    )
    expect_status("recreate upstream for opt-out", status, 201, body)
    status, _, _ = http(
        "POST",
        f"{base}/proxies",
        token=operator,
        headers=ns,
        body={
            "id": "fe-agent-13-px-keep",
            "listen_path": "/fe-agent-13-keep",
            "backend_scheme": "http",
            "upstream_id": "fe-agent-13-up-keep",
        },
    )
    status, _, body = http(
        "DELETE",
        f"{base}/proxies/fe-agent-13-px-keep?cleanup_orphaned_upstream=false",
        token=operator,
        headers=ns,
    )
    expect_status("DELETE proxy with cleanup_orphaned_upstream=false", status, 204, body)
    status, _, body = http("GET", f"{base}/upstreams/fe-agent-13-up-keep", token=operator, headers=ns)
    expect_status(
        "hand-owned upstream survives when cleanup opted out",
        status,
        200,
        body,
        expected="200 (closed #4064)",
    )

    # API spec importer (database)
    spec = {
        "openapi": "3.1.0",
        "info": {"title": "fe-agent-13", "version": "1.0.0"},
        "x-ferrum-proxy": {
            "id": "fe-agent-13-spec-px",
            "listen_path": "/fe-agent-13-spec",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 9,
        },
    }
    status, _, body = http(
        "POST",
        f"{base}/api-specs",
        token=admin,
        headers={**ns, "Content-Type": "application/json"},
        body=spec,
    )
    expect_status("POST /api-specs database mode", status, 201, body)
    spec_id = None
    if isinstance(body, dict):
        spec_id = body.get("id") or (body.get("spec") or {}).get("id")
    if not spec_id:
        status, _, listed = http("GET", f"{base}/api-specs", token=admin, headers=ns)
        if isinstance(listed, dict):
            for item in listed.get("data") or []:
                if item.get("proxy_id") == "fe-agent-13-spec-px":
                    spec_id = item.get("id")
                    break
    status, _, body = http("GET", f"{base}/proxies/fe-agent-13-spec-px", token=admin, headers=ns)
    expect_status("spec-extracted proxy exists", status, 200, body)

    viewer = mint_jwt(role="viewer")
    status, _, body = http("GET", f"{base}/api-specs", token=viewer, headers=ns)
    expect_status("viewer GET /api-specs list", status, 200, body)
    if spec_id:
        status, _, body = http("GET", f"{base}/api-specs/{spec_id}", token=viewer, headers=ns)
        expect_status("viewer GET /api-specs/{id} raw document", status, 403, body)

    # Invalid namespace header
    status, _, body = http("GET", f"{base}/proxies", token=admin, headers={"X-Ferrum-Namespace": "../evil"})
    expect_status("invalid X-Ferrum-Namespace", status, 400, body)

    # Implicit namespace (no registry POST) still isolates
    implicit = {"X-Ferrum-Namespace": "fe-agent-13-implicit"}
    status, _, body = http(
        "POST",
        f"{base}/proxies",
        token=admin,
        headers=implicit,
        body={
            "id": "fe-agent-13-implicit-px",
            "listen_path": "/fe-agent-13-implicit",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 9,
        },
    )
    expect_status("implicit namespace via header without registry POST", status, 201, body)
    status, _, body = http("GET", f"{base}/namespaces", token=admin)
    names = body.get("data") if isinstance(body, dict) else None
    expect_status(
        "GET /namespaces includes implicit derived name",
        200 if isinstance(names, list) and "fe-agent-13-implicit" in names else 500,
        200,
        names,
        expected="derived name appears without registry row",
    )


def probe_namespace_claim(base: str) -> None:
    scoped = mint_jwt(extra={"ns": "fe-agent-13-claim-a"})
    other = mint_jwt(extra={"ns": "fe-agent-13-claim-b"})
    missing = mint_jwt()
    admin_global_create = mint_jwt(extra={"ns": ["fe-agent-13-claim-a", "fe-agent-13-claim-b"]})

    status, _, body = http("POST", f"{base}/namespaces", token=admin_global_create, body={"name": "fe-agent-13-claim-a"})
    expect_status("ns-claim POST /namespaces a", status, {201, 409, 403}, body)
    status, _, body = http("POST", f"{base}/namespaces", token=admin_global_create, body={"name": "fe-agent-13-claim-b"})
    expect_status("ns-claim POST /namespaces b", status, {201, 409, 403}, body)

    status, _, body = http(
        "POST",
        f"{base}/proxies",
        token=scoped,
        headers={"X-Ferrum-Namespace": "fe-agent-13-claim-a"},
        body={
            "id": "fe-agent-13-claim-px",
            "listen_path": "/fe-agent-13-claim",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 9,
        },
    )
    expect_status("ns-claim matching header POST /proxies", status, 201, body)

    status, _, body = http(
        "GET",
        f"{base}/proxies",
        token=scoped,
        headers={"X-Ferrum-Namespace": "fe-agent-13-claim-b"},
    )
    expect_status(
        "ns-claim mismatch GET /proxies",
        status,
        403,
        body,
        extra_ok=isinstance(body, dict) and "ns" in str(body.get("error", "")),
        expected="403 JWT ns claim does not authorize",
    )

    status, _, body = http("GET", f"{base}/proxies", token=missing)
    expect_status(
        "ns-claim missing ns on scoped route",
        status,
        403,
        body,
        expected="403 require-namespace-claim with no ns",
    )

    status, _, body = http("GET", f"{base}/namespaces", token=scoped)
    names = body.get("data") if isinstance(body, dict) else None
    filtered = isinstance(names, list) and "fe-agent-13-claim-b" not in names
    expect_status(
        "ns-claim GET /namespaces filtered",
        status,
        200,
        names,
        extra_ok=filtered,
        expected="200 filtered to token ns; no 403",
    )

    status, _, body = http("GET", f"{base}/cluster", token=scoped)
    expect_status(
        "ns-claim GET /cluster global surface still allowed",
        status,
        200,
        body,
        expected="global surface not gated by ns claim",
    )

    status, _, body = http("GET", f"{base}/namespaces/fe-agent-13-claim-b", token=scoped)
    expect_status(
        "ns-claim GET /namespaces/{other}",
        status,
        403,
        body,
        expected="403 on registry get for unauthorized name",
    )


def main() -> int:
    if not Path(BIN).exists():
        print(f"binary missing: {BIN}", file=sys.stderr)
        return 2

    file_cfg = WORKDIR / "file-config.yaml"
    file_cfg.write_text(
        """version: "1"
proxies:
  - id: fe-agent-13-file-px
    listen_path: /fe-agent-13-file
    backend_scheme: http
    backend_host: 127.0.0.1
    backend_port: 9
    strip_listen_path: true
consumers: []
plugin_configs: []
upstreams: []
"""
    )

    # --- file mode ---
    file_admin, file_proxy = 22200, 22201
    env = common_env(file_admin, file_proxy)
    env.update(
        {
            "FERRUM_MODE": "file",
            "FERRUM_FILE_CONFIG_PATH": str(file_cfg),
        }
    )
    start_gateway("file", env, WORKDIR / "file.log")
    file_base = f"http://127.0.0.1:{file_admin}"
    if not wait_live(file_base):
        record("file-mode startup", False, (WORKDIR / "file.log").read_text()[-2000:], "process live", "did not become live")
    else:
        record("file-mode startup", True, "live", "200 /live", "200")
        probe_unauth_and_jwt(file_base)
        probe_file_mode(file_base)
    stop_all()
    PROCS.clear()

    # --- database mode ---
    db_path = WORKDIR / "edge.db"
    if db_path.exists():
        db_path.unlink()
    db_admin, db_proxy = 22210, 22211
    env = common_env(db_admin, db_proxy)
    env.update(
        {
            "FERRUM_MODE": "database",
            "FERRUM_DB_TYPE": "sqlite",
            "FERRUM_DB_URL": f"sqlite:{db_path}?mode=rwc",
            "FERRUM_NAMESPACE": "ferrum",
        }
    )
    start_gateway("db", env, WORKDIR / "db.log")
    db_base = f"http://127.0.0.1:{db_admin}"
    if not wait_live(db_base, timeout=60):
        record("database-mode startup", False, (WORKDIR / "db.log").read_text()[-2000:], "process live", "did not become live")
    else:
        record("database-mode startup", True, "live", "200 /live", "200")
        probe_unauth_and_jwt(db_base)
        probe_database_crud(db_base)
    stop_all()
    PROCS.clear()

    # --- database + namespace claim ---
    db2 = WORKDIR / "edge-ns.db"
    if db2.exists():
        db2.unlink()
    ns_admin, ns_proxy = 22220, 22221
    env = common_env(ns_admin, ns_proxy)
    env.update(
        {
            "FERRUM_MODE": "database",
            "FERRUM_DB_TYPE": "sqlite",
            "FERRUM_DB_URL": f"sqlite:{db2}?mode=rwc",
            "FERRUM_NAMESPACE": "ferrum",
            "FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM": "true",
        }
    )
    start_gateway("nsclaim", env, WORKDIR / "nsclaim.log")
    ns_base = f"http://127.0.0.1:{ns_admin}"
    if not wait_live(ns_base, timeout=60):
        record("ns-claim startup", False, (WORKDIR / "nsclaim.log").read_text()[-2000:], "process live", "did not become live")
    else:
        record("ns-claim startup", True, "live", "200 /live", "200")
        probe_namespace_claim(ns_base)
    stop_all()

    out = WORKDIR / "probe-results.json"
    payload = {
        "sha_hint": "bf05855f8429e466511610f9072f666b45cd309a",
        "pass": sum(1 for r in RESULTS if r["ok"]),
        "fail": sum(1 for r in RESULTS if not r["ok"]),
        "results": RESULTS,
    }
    out.write_text(json.dumps(payload, indent=2))
    print(f"\nWrote {out} pass={payload['pass']} fail={payload['fail']}")
    return 0 if payload["fail"] == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        stop_all()
