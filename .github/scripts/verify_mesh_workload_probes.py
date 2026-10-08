#!/usr/bin/env python3
"""Hosted CI checks for mesh workload startup/liveness/readiness probes (#2450).

Kept out of `.github/workflows/ci.yml` shell so the trusted ARM64 build-policy
gate can compare unprotected workflow surfaces without freezing routine
probe-shape assertions into the workflow. Process launches (`helm template`)
stay in the trusted workflow shell; this script only statically parses captured
results and the declarative expectations fixture beside it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXPECTATIONS = Path(__file__).with_name(
    "mesh_workload_probes_expectations.json"
)

PROBE_KEYS = ("startupProbe", "livenessProbe", "readinessProbe")


def fail(title: str, detail: str) -> None:
    print(f"::error title={title}::{detail}")
    raise SystemExit(1)


def load_expectations(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail("Mesh probe expectations unreadable", f"{path}: {exc}")
    if not isinstance(data, dict):
        fail("Mesh probe expectations invalid", f"{path} must be a JSON object")
    return data


def require_capture(results_dir: Path, relative: str) -> Path:
    path = results_dir / relative
    if not path.is_file():
        fail(
            "Missing mesh probe capture",
            f"workflow must write {relative} under {results_dir} before this script",
        )
    return path


def split_documents(rendered: str) -> list[str]:
    return [doc for doc in re.split(r"(?m)^---\s*$", rendered) if doc.strip()]


def resource_document(rendered: str, name: str, kind: str) -> str:
    for doc in split_documents(rendered):
        if not re.search(rf"(?m)^kind:\s*{re.escape(kind)}\s*$", doc):
            continue
        if re.search(rf"(?m)^  name:\s*{re.escape(name)}\s*$", doc):
            return doc
    fail(
        "Mesh workload missing from render",
        f"{kind}/{name} must appear in the captured Helm render",
    )
    raise AssertionError("unreachable")


def extract_probe(resource: str, probe_key: str) -> str | None:
    """Return the indented probe block for probe_key, or None if absent."""

    match = re.search(
        rf"(?m)^(?P<indent>[ \t]+){re.escape(probe_key)}:\s*(?P<body>.*)$",
        resource,
    )
    if match is None:
        return None
    indent = match.group("indent")
    indent_len = len(indent)
    lines = [match.group(0) + "\n"]
    rest = resource[match.end() :]
    if rest.startswith("\n"):
        rest = rest[1:]
    # Inline body on the same line is uncommon for probes but keep it.
    for line in rest.splitlines(keepends=True):
        if not line.strip():
            lines.append(line)
            continue
        current_indent = len(line) - len(line.lstrip(" \t"))
        if current_indent <= indent_len:
            break
        lines.append(line)
    return "".join(lines)


def require_probe(resource: str, name: str, probe_key: str) -> str:
    block = extract_probe(resource, probe_key)
    if block is None:
        fail(
            "Mesh probe missing",
            f"{name} must render {probe_key} by default",
        )
    return block


def assert_admin_health_pair(name: str, live: str, ready: str) -> None:
    if "health" not in live or "--live" not in live:
        fail(
            "Admin liveness not process-only",
            f"{name} startup/liveness must run ferrum-edge health --live",
        )
    if "health" not in ready:
        fail(
            "Admin readiness missing health",
            f"{name} readiness must run ferrum-edge health",
        )
    if "--live" in ready:
        fail(
            "Admin readiness coupled to liveness",
            f"{name} readiness must probe /health without --live",
        )


def assert_tcp_port(name: str, block: str, port: str) -> None:
    if "tcpSocket:" not in block or not re.search(
        rf"(?m)^\s+port:\s*{re.escape(port)}\s*$", block
    ):
        fail(
            "TCP probe port mismatch",
            f"{name} must default to tcpSocket on {port}",
        )


def validate_defaults(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(results_dir, captures["default"]).read_text(
        encoding="utf-8"
    )
    for workload in expectations["workloads"]:
        name = workload["name"]
        resource = resource_document(rendered, name, workload["kind"])
        startup = require_probe(resource, name, "startupProbe")
        liveness = require_probe(resource, name, "livenessProbe")
        readiness = require_probe(resource, name, "readinessProbe")
        handler = workload["handler"]
        if handler == "admin_health":
            assert_admin_health_pair(name, startup, readiness)
            assert_admin_health_pair(name, liveness, readiness)
        elif handler == "tcp":
            port = workload["tcp_port"]
            assert_tcp_port(name, startup, port)
            assert_tcp_port(name, liveness, port)
            assert_tcp_port(name, readiness, port)
        else:
            fail("Unknown probe handler kind", f"{name}: {handler!r}")
    print("mesh probe defaults ok")


def validate_disabled(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(results_dir, captures["disabled"]).read_text(
        encoding="utf-8"
    )
    for probe_key in PROBE_KEYS:
        if re.search(rf"(?m)^\s*{re.escape(probe_key)}:\s*$", rendered):
            fail(
                "Disabled mesh probes still rendered",
                f"enabled=false must omit {probe_key} for every first-class workload",
            )
    print("mesh probe disabled ok")


def validate_override(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(results_dir, captures["override"]).read_text(
        encoding="utf-8"
    )
    resource = resource_document(
        rendered, "ferrum-mesh-control-plane", "Deployment"
    )
    liveness = require_probe(resource, "ferrum-mesh-control-plane", "livenessProbe")
    readiness = require_probe(resource, "ferrum-mesh-control-plane", "readinessProbe")
    startup = require_probe(resource, "ferrum-mesh-control-plane", "startupProbe")
    if "httpGet:" not in liveness or not re.search(
        r"(?m)^\s+path:\s*/live\s*$", liveness
    ):
        fail(
            "Per-probe liveness override missing",
            "controlPlane.probes.liveness.override must replace the liveness handler",
        )
    # Startup shares the liveness handler, so the override reaches startup too.
    if "httpGet:" not in startup or not re.search(
        r"(?m)^\s+path:\s*/live\s*$", startup
    ):
        fail(
            "Startup did not inherit liveness override",
            "startupProbe must use the overridden liveness handler",
        )
    if "httpGet:" in readiness or re.search(r"(?m)^\s+path:\s*/live\s*$", readiness):
        fail(
            "Per-probe override leaked into readiness",
            "liveness.override must not replace the readiness handler",
        )
    if "health" not in readiness or "--live" in readiness:
        fail(
            "Readiness drifted after liveness override",
            "control-plane readiness must remain health without --live",
        )
    print("mesh probe override ok")


def validate_coupled_rejected(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    err_path = require_capture(results_dir, captures["coupled_err"])
    err_text = err_path.read_text(encoding="utf-8")
    if not err_text.strip():
        fail(
            "Coupled mesh probe override accepted",
            "controlPlane.probes.override must fail schema validation",
        )
    # Helm JSON schema wording varies slightly; require a property/additional hint.
    if not re.search(
        r"override|additional propert|Additional propert",
        err_text,
        re.IGNORECASE,
    ):
        fail(
            "Coupled override rejection message drift",
            "stderr must mention the rejected shared probes.override shape",
        )
    print("mesh probe coupled override rejected ok")


def validate_node_agent_port0(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(results_dir, captures["node_agent_port0"]).read_text(
        encoding="utf-8"
    )
    resource = resource_document(
        rendered, "ferrum-mesh-node-agent", "DaemonSet"
    )
    if extract_probe(resource, "readinessProbe") is not None:
        fail(
            "Node-agent port 0 still ready",
            "admin port 0 must omit readinessProbe",
        )
    print("mesh probe node-agent port 0 ok")


def validate_node_agent_https_only(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(results_dir, captures["node_agent_https_only"]).read_text(
        encoding="utf-8"
    )
    resource = resource_document(rendered, "ferrum-mesh-node-agent", "DaemonSet")
    readiness = require_probe(resource, "ferrum-mesh-node-agent", "readinessProbe")
    liveness = require_probe(resource, "ferrum-mesh-node-agent", "livenessProbe")
    if "--tls" not in readiness or "--tls-no-verify" not in readiness:
        fail(
            "Node-agent HTTPS-only probes missing TLS",
            "HTTPS-only admin must render health --tls --tls-no-verify",
        )
    if not re.search(r'(?m)^\s+-\s+"19443"\s*$', readiness):
        fail(
            "Node-agent HTTPS-only probe port mismatch",
            "HTTPS-only probes must dial httpsPort 19443, not the disabled HTTP port",
        )
    if "19090" in readiness:
        fail(
            "Node-agent HTTPS-only still probes HTTP",
            "disabled plaintext port must not remain in HTTPS-only probes",
        )
    if "--tls" not in liveness or "--live" not in liveness:
        fail(
            "Node-agent HTTPS-only liveness regress",
            "liveness must keep --live with --tls",
        )
    if "FERRUM_ADMIN_TLS_CERT_PATH" not in resource:
        fail(
            "Node-agent HTTPS-only missing TLS env",
            "Secret-backed admin TLS PATH env must be rendered",
        )
    if "node-agent-admin-tls" not in resource:
        fail(
            "Node-agent HTTPS-only missing TLS volume",
            "admin TLS Secret mount must be rendered",
        )
    print("mesh probe node-agent HTTPS-only ok")


def validate_node_agent_integer_port0_preserves_https_only(
    results_dir: Path, expectations: dict
) -> None:
    """Integer `--set nodeAgent.admin.port=0` must not re-enable plaintext 19090."""

    captures = expectations["captures"]
    rendered = require_capture(
        results_dir, captures["node_agent_https_only_int_port0"]
    ).read_text(encoding="utf-8")
    resource = resource_document(rendered, "ferrum-mesh-node-agent", "DaemonSet")
    if not re.search(
        r'(?m)^\s+- name: FERRUM_ADMIN_HTTP_PORT\s*\n\s+value: "0"\s*$',
        resource,
    ):
        fail(
            "Integer admin.port=0 re-enabled plaintext",
            "Helm --set nodeAgent.admin.port=0 must render FERRUM_ADMIN_HTTP_PORT=0",
        )
    if re.search(
        r'(?m)^\s+- name: FERRUM_ADMIN_HTTP_PORT\s*\n\s+value: "19090"\s*$',
        resource,
    ):
        fail(
            "Integer admin.port=0 fell back to 19090",
            "Sprig default must not treat integer 0 as empty for admin.port",
        )
    readiness = require_probe(resource, "ferrum-mesh-node-agent", "readinessProbe")
    if "--tls" not in readiness or not re.search(r'(?m)^\s+-\s+"19443"\s*$', readiness):
        fail(
            "Integer port=0 HTTPS-only probe regress",
            "integer port=0 HTTPS-only must keep TLS probes on httpsPort",
        )
    err_text = require_capture(
        results_dir, captures["node_agent_https_mtls_int_port0_err"]
    ).read_text(encoding="utf-8")
    if not err_text.strip():
        fail(
            "Integer port=0 bypassed HTTPS-only mTLS guard",
            "--set nodeAgent.admin.port=0 must keep HTTPS-only mTLS fail-closed",
        )
    if "client certificate" not in err_text and "clientCaKey" not in err_text:
        fail(
            "Integer port=0 mTLS rejection drift",
            "stderr must mention client certificate / clientCaKey guidance",
        )
    print("mesh probe node-agent integer port=0 HTTPS-only/mTLS ok")


def validate_node_agent_dual(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(results_dir, captures["node_agent_dual"]).read_text(
        encoding="utf-8"
    )
    resource = resource_document(rendered, "ferrum-mesh-node-agent", "DaemonSet")
    readiness = require_probe(resource, "ferrum-mesh-node-agent", "readinessProbe")
    # Dual keeps plaintext probes on HTTP while still mounting HTTPS TLS.
    if "--tls" in readiness:
        fail(
            "Node-agent dual probes unexpectedly TLS",
            "dual listeners with HTTP enabled should keep plaintext probe scheme",
        )
    if not re.search(r'(?m)^\s+-\s+"19090"\s*$', readiness):
        fail(
            "Node-agent dual probe port mismatch",
            "dual listeners must probe the HTTP admin port when it is enabled",
        )
    if "FERRUM_ADMIN_HTTPS_PORT" not in resource or "19443" not in resource:
        fail(
            "Node-agent dual missing HTTPS port env",
            "dual listeners must render FERRUM_ADMIN_HTTPS_PORT",
        )
    if "FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH" not in resource:
        fail(
            "Node-agent dual missing client CA mount env",
            "optional mTLS clientCaKey must render CLIENT_CA_BUNDLE_PATH",
        )
    # Dual HTTP + mTLS HTTPS: simple Prometheus annotations cannot present a
    # client certificate, so advertise the active plaintext HTTP listener.
    if 'prometheus.io/scheme: "https"' in resource:
        fail(
            "Node-agent dual mTLS scrape prefers unusable HTTPS",
            "dual listeners with clientCaKey must advertise http scheme/port",
        )
    if 'prometheus.io/scheme: "http"' not in resource:
        fail(
            "Node-agent dual mTLS scrape scheme missing",
            "dual mTLS metricsScrape must advertise http",
        )
    if 'prometheus.io/port: "19090"' not in resource:
        fail(
            "Node-agent dual mTLS scrape port mismatch",
            "dual mTLS metricsScrape must advertise the HTTP admin port",
        )
    if 'prometheus.io/port: "19443"' in resource:
        fail(
            "Node-agent dual mTLS scrape still advertises HTTPS port",
            "mTLS HTTPS must not be advertised via simple prometheus.io annotations",
        )
    print("mesh probe node-agent dual ok")


def validate_node_agent_https_no_tls_rejected(
    results_dir: Path, expectations: dict
) -> None:
    captures = expectations["captures"]
    err_path = require_capture(results_dir, captures["node_agent_https_no_tls_err"])
    err_text = err_path.read_text(encoding="utf-8")
    if not err_text.strip():
        fail(
            "Node-agent HTTPS without TLS accepted",
            "httpsPort without complete admin.tls must fail at render",
        )
    if "httpsPort" not in err_text and "TLS" not in err_text:
        fail(
            "Node-agent HTTPS-without-TLS rejection drift",
            "stderr must mention httpsPort/TLS fail-closed guidance",
        )
    print("mesh probe node-agent HTTPS without TLS rejected ok")


def validate_node_agent_https_mtls_probe_policy(
    results_dir: Path, expectations: dict
) -> None:
    captures = expectations["captures"]
    disabled = require_capture(
        results_dir, captures["node_agent_https_mtls_disabled"]
    ).read_text(encoding="utf-8")
    if "ferrum-mesh-node-agent" not in disabled:
        fail(
            "Node-agent HTTPS-only mTLS with disabled probes missing",
            "disabling all computed probes must permit HTTPS-only mTLS",
        )
    if any(
        probe in disabled
        for probe in ("startupProbe:", "livenessProbe:", "readinessProbe:")
    ):
        fail(
            "Node-agent HTTPS-only mTLS disabled probes still rendered",
            "disabled probes must omit computed handlers",
        )
    overridden = require_capture(
        results_dir, captures["node_agent_https_mtls_override"]
    ).read_text(encoding="utf-8")
    if overridden.count("/bin/true") < 3:
        fail(
            "Node-agent HTTPS-only mTLS override missing",
            "safe override must replace every enabled probe (startup/liveness/readiness)",
        )
    if re.search(r"ferrum-edge\"?\s*\n\s*-\s*\"health\"", overridden) and "--tls" in overridden:
        fail(
            "Node-agent HTTPS-only mTLS override still uses computed TLS health",
            "overrides must replace computed exec probes",
        )
    err_text = require_capture(
        results_dir, captures["node_agent_https_mtls_unsafe_err"]
    ).read_text(encoding="utf-8")
    if not err_text.strip():
        fail(
            "Node-agent HTTPS-only mTLS unsafe probes accepted",
            "enabled computed probes under HTTPS-only mTLS must fail closed",
        )
    if "client certificate" not in err_text and "clientCaKey" not in err_text:
        fail(
            "Node-agent HTTPS-only mTLS unsafe rejection drift",
            "stderr must mention client certificate / clientCaKey guidance",
        )
    asymmetric = require_capture(
        results_dir, captures["node_agent_https_mtls_asymmetric_err"]
    ).read_text(encoding="utf-8")
    if not asymmetric.strip():
        fail(
            "Node-agent HTTPS-only mTLS asymmetric override accepted",
            "startup staying computed while liveness/readiness are overridden must fail closed",
        )
    if "client certificate" not in asymmetric and "clientCaKey" not in asymmetric:
        fail(
            "Node-agent HTTPS-only mTLS asymmetric rejection drift",
            "stderr must mention client certificate / clientCaKey guidance",
        )
    scrape_err = require_capture(
        results_dir, captures["node_agent_https_mtls_scrape_err"]
    ).read_text(encoding="utf-8")
    if not scrape_err.strip():
        fail(
            "Node-agent HTTPS-only mTLS scrape annotations accepted",
            "metricsScrape.enabled with HTTPS-only mTLS must fail closed",
        )
    if "metricsScrape" not in scrape_err and "client certificate" not in scrape_err:
        fail(
            "Node-agent HTTPS-only mTLS scrape rejection drift",
            "stderr must mention metricsScrape / client certificate guidance",
        )
    print("mesh probe node-agent HTTPS-only mTLS probe policy ok")


def validate_node_agent_https_collision_policy(
    results_dir: Path, expectations: dict
) -> None:
    captures = expectations["captures"]
    allowed = require_capture(
        results_dir, captures["node_agent_https_no_ambient_collision"]
    ).read_text(encoding="utf-8")
    if "FERRUM_ADMIN_HTTPS_PORT" not in allowed or "9443" not in allowed:
        fail(
            "Node-agent HTTPS without ambient TLS missing",
            "inherited ambient HTTPS default must not block node-agent HTTPS",
        )
    err_text = require_capture(
        results_dir, captures["node_agent_https_collision_err"]
    ).read_text(encoding="utf-8")
    if not err_text.strip():
        fail(
            "Ambient/node-agent HTTPS collision accepted",
            "active ambient and node-agent HTTPS on the same port must fail",
        )
    if "FERRUM_ADMIN_HTTPS_PORT" not in err_text:
        fail(
            "Ambient/node-agent HTTPS collision rejection drift",
            "stderr must mention FERRUM_ADMIN_HTTPS_PORT",
        )
    http_https = require_capture(
        results_dir, captures["node_agent_http_https_collision_err"]
    ).read_text(encoding="utf-8")
    if not http_https.strip():
        fail(
            "Node-agent HTTP/HTTPS collision accepted",
            "same-port node-agent HTTP+HTTPS must fail closed",
        )
    if "httpsPort" not in http_https and "admin.port" not in http_https:
        fail(
            "Node-agent HTTP/HTTPS collision rejection drift",
            "stderr must mention admin.port / httpsPort",
        )
    ambient_http = require_capture(
        results_dir, captures["ambient_http_node_https_collision_err"]
    ).read_text(encoding="utf-8")
    if not ambient_http.strip():
        fail(
            "Ambient HTTP / node-agent HTTPS collision accepted",
            "cross-protocol hostNetwork collision must fail closed",
        )
    if "hostNetwork" not in ambient_http and "httpsPort" not in ambient_http:
        fail(
            "Ambient HTTP / node-agent HTTPS collision rejection drift",
            "stderr must mention the cross-protocol collision",
        )
    ambient_https = require_capture(
        results_dir, captures["ambient_https_node_http_collision_err"]
    ).read_text(encoding="utf-8")
    if not ambient_https.strip():
        fail(
            "Ambient HTTPS / node-agent HTTP collision accepted",
            "cross-protocol hostNetwork collision must fail closed",
        )
    if "hostNetwork" not in ambient_https and "admin.port" not in ambient_https:
        fail(
            "Ambient HTTPS / node-agent HTTP collision rejection drift",
            "stderr must mention the cross-protocol collision",
        )
    noncollision = require_capture(
        results_dir, captures["admin_port_noncollision"]
    ).read_text(encoding="utf-8")
    if "ferrum-mesh-node-agent" not in noncollision or "ferrum-mesh-ambient" not in noncollision:
        fail(
            "Admin port noncollision control missing workloads",
            "distinct active admin ports must still render ambient and node-agent",
        )
    print("mesh probe node-agent HTTPS collision policy ok")


def validate_node_waypoint_ambient(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(results_dir, captures["node_waypoint"]).read_text(
        encoding="utf-8"
    )
    ambient = expectations["node_waypoint_ambient"]
    resource = resource_document(rendered, ambient["name"], ambient["kind"])
    readiness = require_probe(resource, ambient["name"], "readinessProbe")
    liveness = require_probe(resource, ambient["name"], "livenessProbe")
    port = ambient["admin_port"]
    if not re.search(rf'(?m)^\s+-\s+"{re.escape(port)}"\s*$', readiness):
        fail(
            "NodeWaypoint ambient readiness regress",
            f"ambient readiness must dial admin port {port}",
        )
    if "health" not in readiness or "--live" in readiness:
        fail(
            "NodeWaypoint ambient readiness regress",
            "ambient readiness must keep admin /health without --live",
        )
    if "health" not in liveness or "--live" not in liveness:
        fail(
            "Ambient liveness not process-only",
            "ambient livenessProbe must run health --live",
        )
    print("mesh probe NodeWaypoint ambient ok")


def validate_startup_overrides(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(results_dir, captures["startup_overrides"]).read_text(
        encoding="utf-8"
    )
    expected = (
        ("ferrum-mesh-control-plane", "Deployment", "/bin/startup-cp"),
        ("ferrum-mesh-ca", "Deployment", "/bin/startup-ca"),
        ("ferrum-mesh-east-west", "Deployment", "/bin/startup-ew"),
        ("ferrum-mesh-ambient", "DaemonSet", "/bin/startup-amb"),
        ("ferrum-mesh-injector", "Deployment", "/bin/startup-inj"),
    )
    for name, kind, needle in expected:
        resource = resource_document(rendered, name, kind)
        startup = require_probe(resource, name, "startupProbe")
        liveness = require_probe(resource, name, "livenessProbe")
        if needle not in startup:
            fail(
                "Startup override missing",
                f"{name} startupProbe must use {needle}",
            )
        if needle in liveness:
            fail(
                "Startup override leaked into liveness",
                f"{name} livenessProbe must keep the computed/fallback handler",
            )
        if name == "ferrum-mesh-injector":
            if "tcpSocket:" not in liveness:
                fail(
                    "Injector liveness lost TCP default",
                    "injector must keep tcpSocket on webhook when only startup is overridden",
                )
        elif "--live" not in liveness:
            fail(
                "Liveness lost computed handler after startup override",
                f"{name} livenessProbe must remain health --live",
            )
    validate_service_account_isolation(rendered)
    print("mesh probe startup overrides ok")


def validate_service_account_isolation(rendered: str) -> None:
    expected_accounts = {
        "ferrum-mesh-control-plane": "ferrum-mesh-control-plane",
        "ferrum-mesh-ambient": "ferrum-mesh-ambient",
        "ferrum-mesh-east-west": "ferrum-mesh-east-west",
        "ferrum-mesh-injector": "ferrum-mesh-injector",
        "ferrum-mesh-ca": "ferrum-mesh-ca",
    }
    workloads = {
        "ferrum-mesh-control-plane": ("Deployment", "ferrum-mesh-control-plane"),
        "ferrum-mesh-ambient": ("DaemonSet", "ferrum-mesh-ambient"),
        "ferrum-mesh-east-west": ("Deployment", "ferrum-mesh-east-west"),
        "ferrum-mesh-injector": ("Deployment", "ferrum-mesh-injector"),
        "ferrum-mesh-ca": ("Deployment", "ferrum-mesh-ca"),
    }
    for component, account in expected_accounts.items():
        kind, workload_name = workloads[component]
        workload = resource_document(rendered, workload_name, kind)
        pod_spec = re.search(r"(?ms)^    spec:\n(?P<body>.*?)(?=^  [^ ]|\Z)", workload)
        if pod_spec is None or not re.search(
            rf"(?m)^      serviceAccountName:\s*{re.escape(account)}\s*$",
            pod_spec.group("body"),
        ):
            fail(
                "Mesh workload ServiceAccount is shared",
                f"{workload_name} must use {account}",
            )
        service_account = resource_document(rendered, account, "ServiceAccount")
        if account != "ferrum-mesh-control-plane" and not re.search(
            r"(?m)^automountServiceAccountToken:\s*false\s*$", service_account
        ):
            fail(
                "Mesh workload token automount enabled",
                f"{account} must disable automatic token mounting",
            )

    resource_document(rendered, "ferrum-mesh-control-plane-ferrum", "ClusterRoleBinding")
    validate_secret_grants(rendered, ambient_secret_refs={})


CONTROL_PLANE_ACCOUNT = "ferrum-mesh-control-plane"
AMBIENT_ACCOUNT = "ferrum-mesh-ambient"
AMBIENT_TLS_SECRET_ROLE = "ferrum-mesh-ambient-tls-secrets-ferrum"
SECRET_READ_VERBS = {"get", "list", "watch", "*"}


def document_field(doc: str, path: str) -> str | None:
    """Return a scalar `child` from a top-level `parent` mapping block."""

    parent, child = path.split(".")
    match = re.search(rf"(?m)^{re.escape(parent)}:\n(?P<body>(?:^[ ]+.*\n?)*)", doc)
    if match is None:
        return None
    field = re.search(
        rf"(?m)^  {re.escape(child)}:\s*(?P<value>\S+)\s*$", match.group("body")
    )
    return field.group("value").strip("\"'") if field else None


def yaml_list_field(block: str, key: str) -> list[str] | None:
    """Read a flow (`key: [a, b]`) or block-sequence string list for `key`."""

    flow = re.search(
        rf"(?m)^(?P<indent>[ ]*)(?:- )?{re.escape(key)}:\s*\[(?P<items>[^\]]*)\]\s*$",
        block,
    )
    if flow is not None:
        return [
            item.strip().strip("\"'")
            for item in flow.group("items").split(",")
            if item.strip()
        ]
    header = re.search(
        rf"(?m)^(?P<prefix>[ ]*(?:- )?){re.escape(key)}:\s*$", block
    )
    if header is None:
        return None
    column = len(header.group("prefix"))
    items: list[str] = []
    for line in block[header.end() :].splitlines()[1:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= column and not stripped.startswith("- "):
            break
        if not stripped.startswith("- ") or indent < column:
            break
        items.append(stripped[2:].strip().strip("\"'"))
    return items


def rbac_rules(doc: str) -> list[str]:
    match = re.search(r"(?m)^rules:\n(?P<body>(?:^[ ]+.*\n?|^\n)*)", doc)
    if match is None:
        return []
    return [
        "  - " + rule
        for rule in re.split(r"(?m)^  - ", match.group("body"))[1:]
        if rule.strip()
    ]


def binding_subjects(doc: str) -> list[tuple[str, str]]:
    match = re.search(r"(?m)^subjects:\n(?P<body>(?:^[ ]+.*\n?)*)", doc)
    if match is None:
        return []
    subjects = []
    for entry in re.split(r"(?m)^  - ", match.group("body"))[1:]:
        kind = re.search(r"(?m)^(?:kind:|    kind:)\s*(\S+)", entry)
        name = re.search(r"(?m)^(?:name:|    name:)\s*(\S+)", entry)
        subjects.append(
            (kind.group(1) if kind else "", name.group(1) if name else "")
        )
    return subjects


def secret_read_rules(doc: str) -> list[list[str] | None]:
    """Return the `resourceNames` of every rule that can read core Secrets.

    `None` marks a rule with no `resourceNames`, which reads every Secret in
    its scope (the namespace for a Role, the cluster for a ClusterRole).
    """

    grants: list[list[str] | None] = []
    for rule in rbac_rules(doc):
        groups = yaml_list_field(rule, "apiGroups") or []
        resources = yaml_list_field(rule, "resources") or []
        verbs = yaml_list_field(rule, "verbs") or []
        if not ({"", "*"} & set(groups)):
            continue
        if not ({"secrets", "*"} & set(resources)):
            continue
        if not (SECRET_READ_VERBS & set(verbs)):
            continue
        grants.append(yaml_list_field(rule, "resourceNames"))
    return grants


def validate_secret_grants(
    rendered: str, ambient_secret_refs: dict[str, list[str]]
) -> None:
    """No data-plane identity may read Secrets beyond explicit resourceNames.

    Only the control plane may hold namespace- or cluster-wide Secret reads.
    Ambient may read exactly the `ambient.tlsSecretRefs` Secrets, through
    namespaced Roles with `resourceNames`, and nothing by default.
    """

    documents = split_documents(rendered)
    roles: dict[tuple[str, str, str], list[list[str] | None]] = {}
    for doc in documents:
        kind = re.search(r"(?m)^kind:\s*(\S+)\s*$", doc)
        if kind is None or kind.group(1) not in {"Role", "ClusterRole"}:
            continue
        name = document_field(doc, "metadata.name") or ""
        namespace = (
            document_field(doc, "metadata.namespace") or ""
            if kind.group(1) == "Role"
            else ""
        )
        roles[(kind.group(1), name, namespace)] = secret_read_rules(doc)

    ambient_grants: dict[str, set[str]] = {}
    for doc in documents:
        kind = re.search(r"(?m)^kind:\s*(\S+)\s*$", doc)
        if kind is None or kind.group(1) not in {"RoleBinding", "ClusterRoleBinding"}:
            continue
        binding = document_field(doc, "metadata.name") or ""
        binding_namespace = (
            document_field(doc, "metadata.namespace") or ""
            if kind.group(1) == "RoleBinding"
            else ""
        )
        role_kind = document_field(doc, "roleRef.kind") or ""
        role_name = document_field(doc, "roleRef.name") or ""
        role_namespace = binding_namespace if role_kind == "Role" else ""
        grants = roles.get((role_kind, role_name, role_namespace), [])
        subjects = binding_subjects(doc)
        if binding == "ferrum-mesh-control-plane-ferrum" and subjects != [
            ("ServiceAccount", CONTROL_PLANE_ACCOUNT)
        ]:
            fail(
                "Control-plane permissions bound to wrong identity",
                "the cluster-wide controller role must target only the control-plane account",
            )
        if not grants:
            continue
        for subject_kind, subject_name in subjects:
            if subject_kind == "ServiceAccount" and subject_name == CONTROL_PLANE_ACCOUNT:
                continue
            if any(names is None or not names for names in grants):
                scope = (
                    "cluster-wide"
                    if kind.group(1) == "ClusterRoleBinding"
                    else f"namespace-wide in {binding_namespace}"
                )
                fail(
                    "Data-plane identity can read Secrets broadly",
                    f"{subject_kind}/{subject_name} reads Secrets {scope} via {binding}",
                )
            if subject_kind != "ServiceAccount" or subject_name != AMBIENT_ACCOUNT:
                fail(
                    "Unexpected Secret access",
                    f"{subject_kind}/{subject_name} must not read Secrets ({binding})",
                )
            if kind.group(1) != "RoleBinding":
                fail(
                    "Ambient Secret access not namespaced",
                    f"{binding} must be a RoleBinding restricted by resourceNames",
                )
            granted = ambient_grants.setdefault(binding_namespace, set())
            for names in grants:
                granted.update(names or [])

    expected = {
        namespace: set(names) for namespace, names in ambient_secret_refs.items()
    }
    if ambient_grants != expected:
        fail(
            "Ambient Secret access does not match ambient.tlsSecretRefs",
            f"rendered {sorted((ns, sorted(n)) for ns, n in ambient_grants.items())}, "
            f"expected {sorted((ns, sorted(n)) for ns, n in expected.items())}",
        )
    for doc in documents:
        if not re.search(r"(?m)^kind:\s*Role\s*$", doc):
            continue
        if document_field(doc, "metadata.name") != AMBIENT_TLS_SECRET_ROLE:
            continue
        namespace = document_field(doc, "metadata.namespace")
        for rule in rbac_rules(doc):
            names = yaml_list_field(rule, "resourceNames")
            if sorted(yaml_list_field(rule, "verbs") or []) != ["get", "list", "watch"]:
                fail(
                    "Ambient Secret verbs drifted",
                    f"{AMBIENT_TLS_SECRET_ROLE} in {namespace} must grant exactly "
                    "get/list/watch",
                )
            if not names or sorted(names) != sorted(expected.get(namespace or "", set())):
                fail(
                    "Ambient Secret access not restricted by resourceNames",
                    f"{AMBIENT_TLS_SECRET_ROLE} in {namespace} must list exactly the "
                    "ambient.tlsSecretRefs Secrets of that namespace",
                )


def validate_ambient_tls_secret_refs(results_dir: Path, expectations: dict) -> None:
    captures = expectations["captures"]
    rendered = require_capture(
        results_dir, captures["ambient_tls_secret_refs"]
    ).read_text(encoding="utf-8")
    validate_secret_grants(
        rendered,
        ambient_secret_refs={
            "edge": ["edge-frontend", "edge-frontend-ca"],
            "ferrum": ["mesh-dtls"],
        },
    )
    print("mesh ambient TLS Secret refs ok")


def validate_node_waypoint_service_account_trust() -> None:
    source = (REPO_ROOT / "src/config_sources/k8s/core.rs").read_text(encoding="utf-8")
    constant = re.search(
        r'(?m)^const NODE_WAYPOINT_SERVICE_ACCOUNT: &str = "(?P<name>[^"]+)";$', source
    )
    if constant is None or constant.group("name") != AMBIENT_ACCOUNT:
        fail(
            "NodeWaypoint discovery trusts a different identity",
            f"NODE_WAYPOINT_SERVICE_ACCOUNT must equal the chart's {AMBIENT_ACCOUNT}",
        )
    daemonset = (REPO_ROOT / "charts/ferrum-mesh/templates/ambient-daemonset.yaml").read_text(
        encoding="utf-8"
    )
    if not re.search(
        rf"(?m)^      serviceAccountName: {re.escape(AMBIENT_ACCOUNT)}$", daemonset
    ):
        fail(
            "NodeWaypoint discovery trusts a different identity",
            f"the Ambient DaemonSet must run as {AMBIENT_ACCOUNT}",
        )


def validate_host_veth_source_usage() -> None:
    veth = (REPO_ROOT / "src/ebpf/veth.rs").read_text(encoding="utf-8")
    for removed in (
        "discover_veth_for_pod(",
        "discover_veth_for_pod_ip(",
        "discover_veth_for_pod_ip6(",
    ):
        if removed in veth:
            fail(
                "Shared or pod-visible veth resolver reintroduced",
                f"src/ebpf/veth.rs must not define {removed.rstrip('(')}",
            )
    sources = {
        REPO_ROOT / "src/proxy/node_waypoint_udp_identity.rs": "discover_dedicated_veth_for_pod_ip",
        REPO_ROOT / "src/proxy/host_udp_capture.rs": "discover_dedicated_veth_for_pod_ip",
        REPO_ROOT / "src/modes/node_agent.rs": "discover_dedicated_veth_for_pod(",
    }
    for path, resolver in sources.items():
        source = path.read_text(encoding="utf-8")
        if resolver not in source:
            fail(
                "Host route ownership lookup missing",
                f"{path.relative_to(REPO_ROOT)} must resolve from a dedicated pod host route",
            )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root (defaults to the checkout containing this script)",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        required=True,
        help="Directory with helm template stdout/stderr captures from the workflow",
    )
    parser.add_argument(
        "--expectations",
        type=Path,
        default=DEFAULT_EXPECTATIONS,
        help="Declarative JSON fixture of workload/probe expectations",
    )
    args = parser.parse_args(argv)
    _ = args.root.resolve()
    results_dir = args.results_dir.resolve()
    expectations = load_expectations(args.expectations.resolve())

    validate_defaults(results_dir, expectations)
    validate_disabled(results_dir, expectations)
    validate_override(results_dir, expectations)
    validate_coupled_rejected(results_dir, expectations)
    validate_node_agent_port0(results_dir, expectations)
    validate_node_agent_https_only(results_dir, expectations)
    validate_node_agent_integer_port0_preserves_https_only(results_dir, expectations)
    validate_node_agent_dual(results_dir, expectations)
    validate_node_agent_https_no_tls_rejected(results_dir, expectations)
    validate_node_agent_https_mtls_probe_policy(results_dir, expectations)
    validate_node_agent_https_collision_policy(results_dir, expectations)
    validate_node_waypoint_ambient(results_dir, expectations)
    validate_startup_overrides(results_dir, expectations)
    validate_ambient_tls_secret_refs(results_dir, expectations)
    validate_node_waypoint_service_account_trust()
    validate_host_veth_source_usage()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
