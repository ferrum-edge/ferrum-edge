#!/usr/bin/env python3
"""Re-run only the first-pass failed rows with isolated backend ports."""
from __future__ import annotations

import json
import os
import signal
import tempfile
import time
from pathlib import Path

import run_matrix as m

ROOT = m.ROOT
BIN = m.BIN
EV = m.EVIDENCE


def upsert(row: m.Row) -> None:
    existing = [r for r in m.ROWS if r.id != row.id]
    m.ROWS.clear()
    m.ROWS.extend(existing)
    m.add(row)


def load_prior() -> None:
    results = EV / "matrix-results.json"
    if not results.exists():
        return
    payload = json.loads(results.read_text())
    for raw in payload.get("rows", []):
        m.ROWS.append(m.Row(**raw))


def retry_d06(tmpdir: Path) -> None:
    oas = tmpdir / "oas.yaml"
    oas.write_text(
        """version: "1"
proxies:
  - id: "pets"
    listen_path: "/pets"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 21062
    strip_listen_path: false
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
          path_template: /pets
          path_regex: ^/pets$
          request_required: true
          request_body:
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
"""
    )
    p = m.run_cmd(
        [str(BIN), "validate", "-m", "file", "-c", str(oas)],
        env=m.gateway_env(oas),
        timeout=25,
    )
    ev = m.write_ev("docs-openapi-no-spec-id.txt", f"exit={p.returncode}\n{p.stdout}\n{p.stderr}")
    upsert(
        m.Row(
            "D06",
            "P1",
            "openapi_validator file-mode without api_spec_id",
            "docs/file",
            "hand-authored operations (path_template+path_regex), no api_spec_id",
            "validate passes; docs distinguish Admin vs file-mode (#4037 hold after #4066)",
            "passed" if p.returncode == 0 else "failed",
            ev,
            issue="https://github.com/ferrum-edge/ferrum-edge/issues/4037",
            notes=f"retry exit={p.returncode}",
        )
    )


def retry_p01_s02_r10(tmpdir: Path) -> None:
    # Isolated ports for this retry only.
    http_be_p = 21070
    tcp_be_p = 21071
    http_p = 21072
    admin_p = 21073
    spec_cli = tmpdir / "cli.yaml"
    spec_env = tmpdir / "env.yaml"
    spec_cli.write_text(m.spec_http_tcp(http_be=http_be_p, tcp_listen=21074, tcp_be=tcp_be_p))
    spec_env.write_text('version: "1"\nproxies: []\nconsumers: []\nplugin_configs: []\n')
    conf = tmpdir / "ferrum.conf"
    conf.write_text(
        "FERRUM_MODE=file\n"
        "FERRUM_PROXY_HTTP_PORT=21050\n"
        "FERRUM_ADMIN_HTTP_PORT=21051\n"
        f"FERRUM_FILE_CONFIG_PATH={spec_env}\n"
        "FERRUM_LOG_LEVEL=warn\n"
        "FERRUM_PROXY_BIND_ADDRESS=127.0.0.1\n"
        "FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1\n"
        "FERRUM_STREAM_PROXY_BIND_ADDRESS=127.0.0.1\n"
        "FERRUM_PROXY_HTTPS_PORT=0\n"
        "FERRUM_ADMIN_HTTPS_PORT=0\n"
    )
    env = m.clean_env(
        {
            "FERRUM_MODE": "database",
            "FERRUM_FILE_CONFIG_PATH": str(spec_env),
            "FERRUM_PROXY_HTTP_PORT": str(http_p),
            "FERRUM_ADMIN_HTTP_PORT": str(admin_p),
            "FERRUM_PROXY_BIND_ADDRESS": m.BIND,
            "FERRUM_ADMIN_BIND_ADDRESS": m.BIND,
            "FERRUM_STREAM_PROXY_BIND_ADDRESS": m.BIND,
            "FERRUM_PROXY_HTTPS_PORT": "0",
            "FERRUM_ADMIN_HTTPS_PORT": "0",
            "FERRUM_ADMIN_JWT_SECRET": m.ADMIN_JWT_SECRET,
            "FERRUM_LOG_LEVEL": "info",
            "FERRUM_SHUTDOWN_DRAIN_SECONDS": "2",
            "FERRUM_POOL_WARMUP_ENABLED": "false",
            "FERRUM_CONF_PATH": str(conf),
        }
    )
    http_be = m.HttpEcho(http_be_p)
    tcp_be = m.TcpEcho(tcp_be_p)
    http_be.start()
    tcp_be.start()
    http_be.ready.wait(3)
    tcp_be.ready.wait(3)
    gw = m.Gateway(
        env,
        args=["run", "-s", str(conf), "-c", str(spec_cli), "-m", "file", "-v"],
        log_name="precedence-retry.log",
    )
    gw.start()
    ready_cli = gw.wait_ready(admin_p, 25)
    ready_conf = m.wait_port(m.BIND, 21051, timeout=0.5)
    st = m.http_get(m.BIND, http_p, "/echo/prec")[0] if ready_cli else None
    ev = m.write_ev(
        "precedence.txt",
        f"retry=1 ready_env_ports={ready_cli} ready_conf_ports={ready_conf} "
        f"http={st} be_ready={http_be.ready.is_set()}\nlog=\n{gw.log_tail(50)}",
    )
    ok = ready_cli and not ready_conf and st == 200
    upsert(
        m.Row(
            "P01",
            "P0",
            "CLI > env > conf for mode/spec/ports",
            "file",
            "conflicting -m/-c vs env vs ferrum.conf",
            "serves CLI spec on env ports; conf ports unused; database mode from env ignored",
            "passed" if ok else "failed",
            ev,
            notes=f"retry admin={ready_cli} conf={ready_conf} http={st}",
        )
    )
    gw.stop()
    http_be.stop()
    tcp_be.stop()
    time.sleep(0.4)

    # S02 rebind on isolated ports
    spec = tmpdir / "hs.yaml"
    spec.write_text(m.spec_http_tcp(http_be=http_be_p, tcp_listen=21075, tcp_be=tcp_be_p))
    http_be = m.HttpEcho(http_be_p)
    tcp_be = m.TcpEcho(tcp_be_p)
    http_be.start()
    tcp_be.start()
    http_be.ready.wait(3)
    tcp_be.ready.wait(3)
    env2 = m.gateway_env(spec, http_port=21076, admin_port=21077)
    gw = m.Gateway(env2, log_name="sigterm-retry.log")
    gw.start()
    if not gw.wait_ready(21077, 25):
        upsert(
            m.Row(
                "S02",
                "P0",
                "immediate rebind after SIGTERM",
                "file",
                "restart same ports",
                "admin+proxy accept again",
                "failed",
                m.write_ev("sigterm-rebind.txt", gw.log_tail(80)),
            )
        )
        gw.stop()
        http_be.stop()
        tcp_be.stop()
        return
    gw.send(signal.SIGTERM)
    m.port_closed(m.BIND, 21076, timeout=10)
    if gw.proc:
        try:
            gw.proc.wait(timeout=12)
        except Exception:
            gw.stop(signal.SIGKILL)
    time.sleep(0.3)
    gw2 = m.Gateway(env2, log_name="sigterm-rebind.log")
    gw2.start()
    rebound = gw2.wait_ready(21077, 20)
    st = m.http_get(m.BIND, 21076, "/echo/rebind")[0] if rebound else None
    ev = m.write_ev(
        "sigterm-rebind.txt",
        f"retry=1 rebound={rebound} status={st}\nlog=\n{gw2.log_tail(40)}",
    )
    upsert(
        m.Row(
            "S02",
            "P0",
            "immediate rebind after SIGTERM",
            "file",
            "restart same ports",
            "admin+proxy accept again",
            "passed" if rebound and st == 200 else "failed",
            ev,
            notes=f"retry rebound={rebound} http={st}",
        )
    )
    gw2.stop()
    http_be.stop()
    tcp_be.stop()


def retry_reload_fs(tmpdir: Path) -> None:
    spec = tmpdir / "fs.yaml"
    spec.write_text(m.spec_http_tcp(http_be=21080, tcp_listen=21081, tcp_be=21082))
    http_be = m.HttpEcho(21080)
    http_be.start()
    http_be.ready.wait(3)
    if not http_be.ready.is_set():
        upsert(
            m.Row(
                "R10",
                "P1",
                "partial in-place write + SIGHUP",
                "file/reload",
                "truncate YAML then SIGHUP",
                "reject torn candidate; /echo stays 200",
                "blocked",
                m.write_ev("reload-partial.txt", "backend bind failed on retry"),
            )
        )
        return
    env = m.gateway_env(spec, http_port=21083, admin_port=21084)
    gw = m.Gateway(env, log_name="reload-fs-retry.log")
    gw.start()
    if not gw.wait_ready(21084, 25):
        upsert(
            m.Row(
                "R10",
                "P1",
                "partial in-place write + SIGHUP",
                "file/reload",
                "truncate YAML then SIGHUP",
                "reject torn candidate; /echo stays 200",
                "failed",
                m.write_ev("reload-partial.txt", gw.log_tail(80)),
            )
        )
        gw.stop()
        http_be.stop()
        return
    with spec.open("w") as f:
        f.write('version: "1"\nproxies:\n  - id: "partial"\n    listen_path: "/p"\n')
        f.flush()
    os.kill(gw.pid() or 0, signal.SIGHUP)
    time.sleep(1.2)
    still = m.http_get(m.BIND, 21083, "/echo/partial")[0]
    ev = m.write_ev(
        "reload-partial.txt",
        f"retry=1 echo={still} alive={gw.alive()}\nlog=\n{gw.log_tail(40)}",
    )
    upsert(
        m.Row(
            "R10",
            "P1",
            "partial in-place write + SIGHUP",
            "file/reload",
            "truncate YAML then SIGHUP",
            "reject torn candidate; /echo stays 200",
            "passed" if gw.alive() and still == 200 else "failed",
            ev,
            notes=f"retry echo={still}",
        )
    )

    spec.write_text(m.spec_http_tcp(http_be=21080, tcp_listen=21081, tcp_be=21082))
    os.kill(gw.pid() or 0, signal.SIGHUP)
    time.sleep(1.2)
    spec.chmod(0)
    os.kill(gw.pid() or 0, signal.SIGHUP)
    time.sleep(1.2)
    still = m.http_get(m.BIND, 21083, "/echo/perm")[0]
    ev = m.write_ev("reload-chmod.txt", f"retry=1 echo={still} alive={gw.alive()}\nlog=\n{gw.log_tail(30)}")
    upsert(
        m.Row(
            "R11",
            "P1",
            "permission loss on spec + SIGHUP",
            "file/reload",
            "chmod 000 + SIGHUP",
            "last-good kept",
            "passed" if gw.alive() and still == 200 else "failed",
            ev,
            notes=f"retry echo={still}",
        )
    )
    spec.chmod(0o644)

    real = tmpdir / "real-a.yaml"
    real.write_text(
        f"""version: "1"
proxies:
  - id: "http-echo"
    listen_path: "/echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 21080
    strip_listen_path: true
  - id: "via-link"
    listen_path: "/link"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 21080
    strip_listen_path: true
consumers: []
plugin_configs: []
upstreams: []
"""
    )
    if spec.exists() or spec.is_symlink():
        spec.unlink()
    spec.symlink_to(real)
    os.kill(gw.pid() or 0, signal.SIGHUP)
    time.sleep(1.4)
    st = m.http_get(m.BIND, 21083, "/link/x")[0]
    ev = m.write_ev("reload-symlink.txt", f"retry=1 /link={st} alive={gw.alive()}\nlog=\n{gw.log_tail(30)}")
    upsert(
        m.Row(
            "R12",
            "P1",
            "symlink swap reload",
            "file/reload",
            "replace spec with symlink",
            "new generation from symlink target",
            "passed" if st == 200 else "failed",
            ev,
            notes=f"retry /link={st}",
        )
    )

    proxies = []
    for i in range(80):
        proxies.append(
            f'  - id: "p{i}"\n    listen_path: "/bulk{i}"\n    backend_scheme: http\n'
            f'    backend_host: "127.0.0.1"\n    backend_port: 21080\n'
            f"    strip_listen_path: true\n"
        )
    large = 'version: "1"\nproxies:\n' + "".join(proxies) + "consumers: []\nplugin_configs: []\nupstreams: []\n"
    if spec.is_symlink():
        spec.unlink()
    spec.write_text(large)
    os.kill(gw.pid() or 0, signal.SIGHUP)
    time.sleep(2.0)
    st = m.http_get(m.BIND, 21083, "/bulk79/x")[0]
    ev = m.write_ev(
        "reload-large.txt",
        f"retry=1 bytes={len(large)} /bulk79={st} alive={gw.alive()}\nlog=\n{gw.log_tail(20)}",
    )
    upsert(
        m.Row(
            "R13",
            "P2",
            "large valid config reload (80 proxies)",
            "file/reload",
            "SIGHUP 80-route spec",
            "/bulk79=200",
            "passed" if st == 200 else "failed",
            ev,
            notes=f"retry /bulk79={st}",
        )
    )
    gw.stop()
    http_be.stop()


def main() -> int:
    if not m.require_bin():
        print(f"binary missing: {BIN}")
        return 2
    load_prior()
    tmp = Path(tempfile.mkdtemp(prefix="agent01-retry-", dir="/tmp"))
    try:
        retry_d06(tmp)
        retry_p01_s02_r10(tmp)
        retry_reload_fs(tmp)
    finally:
        m.save_rows()
        counts: dict[str, int] = {}
        for r in m.ROWS:
            counts[r.result] = counts.get(r.result, 0) + 1
        print("counts:", counts, "total:", len(m.ROWS))
        print("failed:", [r.id for r in m.ROWS if r.result == "failed"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
