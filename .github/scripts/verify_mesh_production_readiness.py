#!/usr/bin/env python3
"""Hosted CI checks for ferrum-mesh production-readiness (#4266, #4267, #4288).

Process launches (`helm template`) stay in `.github/workflows/ci.yml`. This
script only parses captured renders and expected-failure stderr.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SERVING = (
    ("ferrum-mesh-control-plane", "Deployment"),
    ("ferrum-mesh-ca", "Deployment"),
    ("ferrum-mesh-east-west", "Deployment"),
    ("ferrum-mesh-ambient", "DaemonSet"),
)

RESTRICTED = (
    "ferrum-mesh-control-plane",
    "ferrum-mesh-ca",
    "ferrum-mesh-east-west",
)

# Every workload that runs a Ferrum image and therefore needs the chart-level
# image.pullSecrets on a private registry (#4510). Both CNI uninstall-hook pods
# are included on purpose: they run the Ferrum image, so a missing pull secret
# hangs `helm uninstall` behind an ImagePullBackOff on the node whose CNI chain
# is being removed.
PULL_SECRET_WORKLOADS = (
    ("ferrum-mesh-control-plane", "Deployment"),
    ("ferrum-mesh-ca", "Deployment"),
    ("ferrum-mesh-east-west", "Deployment"),
    ("ferrum-mesh-injector", "Deployment"),
    ("ferrum-mesh-ambient", "DaemonSet"),
    ("ferrum-mesh-node-agent", "DaemonSet"),
    ("ferrum-mesh-cni-cleanup", "DaemonSet"),
    ("ferrum-mesh-cni-cleanup-wait", "Job"),
)


def fail(title: str, detail: str) -> None:
    print(f"::error title={title}::{detail}")
    raise SystemExit(1)


def require_capture(results_dir: Path, relative: str) -> Path:
    path = results_dir / relative
    if not path.is_file():
        fail(
            "Missing mesh production-readiness capture",
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


def require_text(doc: str, needle: str, title: str, detail: str) -> None:
    if needle not in doc:
        fail(title, detail)


def require_scalar(
    doc: str, key: str, expected: str, title: str, detail: str
) -> None:
    value = re.escape(expected)
    if not re.search(
        rf"(?m)^\s*{re.escape(key)}:\s*(?:{value}|'{value}'|\"{value}\")\s*$",
        doc,
    ):
        fail(title, detail)


def forbid_text(doc: str, needle: str, title: str, detail: str) -> None:
    if needle in doc:
        fail(title, detail)


def env_value(doc: str, name: str) -> str | None:
    match = re.search(
        rf"(?m)^\s+- name:\s*{re.escape(name)}\s*\n\s+value:\s*(\S+)",
        doc,
    )
    if match is None:
        return None
    return match.group(1).strip().strip('"').strip("'")


def env_occurrences(doc: str, name: str) -> int:
    return len(
        re.findall(rf"(?m)^\s+- name:\s*{re.escape(name)}\s*$", doc)
    )


ADMIN_ENV_KEYS = (
    "FERRUM_ADMIN_HTTP_PORT",
    "FERRUM_ADMIN_BIND_ADDRESS",
    "FERRUM_ALLOW_INSECURE_ADMIN_HTTP",
    "FERRUM_ADMIN_ALLOWED_CIDRS",
)


def validate_admin_env_override(results_dir: Path) -> None:
    """`<workload>.env.FERRUM_ADMIN_*` must reach the container exactly once.

    `ferrum-mesh.adminEnv` is the sole renderer of these four keys and every
    workload env loop filters them out, so a resolver that deferred to the loop
    for an env-supplied value would drop it from the PodSpec while the container
    port and the computed exec probes still used it — a pod that never becomes
    ready, or a non-loopback plaintext admin listener with no allowlist.
    """
    rendered = require_capture(
        results_dir, "mesh-prod-admin-env-override.yaml"
    ).read_text(encoding="utf-8")
    cp = resource_document(rendered, "ferrum-mesh-control-plane", "Deployment")
    for name, expected in (
        ("FERRUM_ADMIN_HTTP_PORT", "19000"),
        ("FERRUM_ADMIN_BIND_ADDRESS", "0.0.0.0"),
        ("FERRUM_ALLOW_INSECURE_ADMIN_HTTP", "true"),
        ("FERRUM_ADMIN_ALLOWED_CIDRS", "127.0.0.0/8"),
    ):
        actual = env_value(cp, name)
        if actual != expected:
            fail(
                "Admin env override dropped",
                f"controlPlane.env.{name} must render as {expected!r}, got {actual!r}",
            )
        count = env_occurrences(cp, name)
        if count != 1:
            fail(
                "Admin env override duplicated",
                f"{name} must appear exactly once on the control plane, found {count}",
            )
    if not re.search(r"(?m)^\s+containerPort:\s*19000\s*$", cp):
        fail(
            "Admin container port not resolved from env",
            "controlPlane.env.FERRUM_ADMIN_HTTP_PORT must drive the admin-http containerPort",
        )
    print("mesh admin env override ok")


def validate_serving_podspecs(results_dir: Path) -> None:
    rendered = require_capture(results_dir, "mesh-probes-default.yaml").read_text(
        encoding="utf-8"
    )
    for name, kind in SERVING:
        doc = resource_document(rendered, name, kind)
        if not re.search(r"(?m)^\s+terminationGracePeriodSeconds:\s*110\s*$", doc):
            fail(
                "Serving grace period missing",
                f"{name} must render terminationGracePeriodSeconds: 110 "
                "(preStop 30 + full 78s post-SIGTERM budget, plus headroom)",
            )
        require_text(
            doc,
            "preStop:",
            "Serving preStop missing",
            f"{name} must render lifecycle.preStop (SleepAction) by default",
        )
        prestop = re.search(
            r"(?ms)^\s+preStop:\s*\n(?:\s+.*\n){0,6}",
            doc,
        )
        if prestop is None or "sleep:" not in prestop.group(0):
            fail(
                "preStop is not a SleepAction",
                f"{name}: distroless has no shell; preStop must use sleep",
            )
        if not re.search(r"seconds:\s*30", prestop.group(0)):
            fail(
                "preStop seconds missing",
                f"{name} must render shutdownPreStopSeconds (30)",
            )
        drain = env_value(doc, "FERRUM_SHUTDOWN_DRAIN_SECONDS")
        if drain != "30":
            fail(
                "Drain env missing",
                f"{name} must render FERRUM_SHUTDOWN_DRAIN_SECONDS=30, got {drain!r}",
            )
        if env_value(doc, "FERRUM_SHUTDOWN_PREDRAIN_SECONDS") != "0":
            fail(
                "Pre-drain env missing",
                f"{name} must render FERRUM_SHUTDOWN_PREDRAIN_SECONDS=0 by default",
            )
        if not re.search(r"(?m)^\s+cpu:\s*\S+", doc) or not re.search(
            r"(?m)^\s+memory:\s*\S+", doc
        ):
            fail(
                "Serving resources missing",
                f"{name} must render non-empty resources.requests.cpu and memory",
            )
        require_text(
            doc,
            "drop:",
            "capabilities.drop missing",
            f"{name} must drop ALL capabilities first",
        )
        require_text(
            doc,
            "- ALL",
            "capabilities.drop ALL missing",
            f"{name} must drop ALL capabilities",
        )
        if not re.search(r"(?m)^\s+failureThreshold:\s*3\s*$", doc):
            fail(
                "Readiness failureThreshold implicit",
                f"{name} must render readiness failureThreshold: 3 (endpoint-removal budget)",
            )

    for name in RESTRICTED:
        doc = resource_document(rendered, name, "Deployment")
        require_text(
            doc,
            "runAsNonRoot: true",
            "Restricted runAsNonRoot missing",
            f"{name} must run as non-root for PodSecurity restricted",
        )
        require_text(
            doc,
            "runAsUser: 65532",
            "Restricted runAsUser missing",
            f"{name} must use distroless nonroot uid 65532",
        )
        require_text(
            doc,
            "allowPrivilegeEscalation: false",
            "Restricted allowPrivilegeEscalation missing",
            f"{name} must set allowPrivilegeEscalation: false",
        )
        require_text(
            doc,
            "readOnlyRootFilesystem: true",
            "Restricted readOnlyRootFilesystem missing",
            f"{name} must set readOnlyRootFilesystem: true",
        )
        require_text(
            doc,
            "type: RuntimeDefault",
            "Restricted seccomp missing",
            f"{name} must set seccompProfile.type: RuntimeDefault",
        )
        forbid_text(
            doc,
            "priorityClassName:",
            "Deployment node-critical default",
            f"{name} must omit priorityClassName by default (empty string)",
        )
        forbid_text(
            doc,
            "NET_ADMIN",
            "Restricted cap regression",
            f"{name} must not add NET_ADMIN",
        )

    ambient = resource_document(rendered, "ferrum-mesh-ambient", "DaemonSet")
    require_text(
        ambient,
        "- NET_ADMIN",
        "Ambient NET_ADMIN missing",
        "ambient must retain unquoted NET_ADMIN for datapath capture",
    )
    require_text(
        ambient,
        "- NET_RAW",
        "Ambient NET_RAW missing",
        "ambient must retain unquoted NET_RAW for datapath capture",
    )
    require_text(
        ambient,
        "- ALL",
        "Ambient capabilities.drop ALL missing",
        "ambient must drop unquoted ALL so the add list is the complete privilege surface",
    )
    require_text(
        ambient,
        "allowPrivilegeEscalation: false",
        "Ambient Restricted allowPrivilegeEscalation missing",
        "the steady-state ambient proxy must set allowPrivilegeEscalation: false (Restricted); omitting it lets Kubernetes default permissively",
    )
    forbid_text(
        ambient,
        '- "NET_ADMIN"',
        "Ambient NET_ADMIN quoted",
        "quoting datapath capabilities breaks NodeWaypoint eBPF live and Helm Chart greps",
    )
    require_scalar(
        ambient,
        "priorityClassName",
        "system-node-critical",
        "Ambient priorityClass missing",
        "ambient must default to system-node-critical",
    )
    require_text(
        ambient,
        "hostNetwork: true",
        "Ambient hostNetwork missing",
        "ambient must keep hostNetwork",
    )

    node_agent = resource_document(rendered, "ferrum-mesh-node-agent", "DaemonSet")
    require_scalar(
        node_agent,
        "priorityClassName",
        "system-node-critical",
        "Node-agent priorityClass missing",
        "nodeAgent must default to system-node-critical",
    )
    forbid_text(
        node_agent,
        "FERRUM_SHUTDOWN_DRAIN_SECONDS",
        "Node-agent serving drain",
        "node-agent is not a serving mode and must not receive the drain contract",
    )
    forbid_text(
        node_agent,
        "preStop:",
        "Node-agent preStop",
        "node-agent must not render serving preStop",
    )

    # The injector DOES take the drain contract (issue #4512): FERRUM_MODE=injector
    # reads FERRUM_SHUTDOWN_DRAIN_SECONDS and waits that long for in-flight
    # admission connections, and its failurePolicy=Fail webhook needs the
    # preStop endpoint-propagation window. Its positive shape (grace period,
    # SleepAction preStop, drain env rendered exactly once) is asserted by
    # validate_injector_shutdown; only node-agent stays drain-free above.
    resource_document(rendered, "ferrum-mesh-injector", "Deployment")
    print("mesh serving podspecs ok")


def validate_cni_no_drain(results_dir: Path) -> None:
    hook = require_capture(results_dir, "cni-uninstall-hook.yaml").read_text(
        encoding="utf-8"
    )
    forbid_text(
        hook,
        "FERRUM_SHUTDOWN_DRAIN_SECONDS",
        "CNI hook serving drain",
        "one-shot CNI uninstall hooks must not receive the serving drain contract",
    )
    forbid_text(
        hook,
        "preStop:",
        "CNI hook preStop",
        "one-shot CNI uninstall hooks must not render serving preStop",
    )
    print("mesh cni hook no serving drain ok")


def validate_refusals(results_dir: Path) -> None:
    low = require_capture(results_dir, "mesh-prod-low-grace.err").read_text(
        encoding="utf-8"
    )
    if "terminationGracePeriodSeconds" not in low or "preStop 30s" not in low:
        fail(
            "Low grace refusal missing",
            "under-budget terminationGracePeriodSeconds must fail with the additive preStop budget",
        )
    kube = require_capture(results_dir, "mesh-prod-kube-1.28.err").read_text(
        encoding="utf-8"
    )
    if "SleepAction" not in kube or "1.29" not in kube:
        fail(
            "Old Kubernetes SleepAction guard missing",
            "--kube-version 1.28.0 must refuse SleepAction and tell operators to set shutdownPreStopSeconds=0 and raise shutdownPreDrainSeconds",
        )
    if "shutdownPreStopSeconds=0" not in kube or "shutdownPreDrainSeconds" not in kube:
        fail(
            "SleepAction remediation missing",
            "the <1.29 guard must name shutdownPreStopSeconds=0 and shutdownPreDrainSeconds",
        )
    empty = require_capture(results_dir, "mesh-prod-empty-resources.err").read_text(
        encoding="utf-8"
    )
    if "resources.requests.cpu" not in empty or "BestEffort" not in empty:
        fail(
            "Empty resources refusal missing",
            "empty serving requests.cpu/memory must fail closed (BestEffort QoS)",
        )
    print("mesh shutdown/resource refusals ok")


def validate_zero_drain(results_dir: Path) -> None:
    rendered = require_capture(results_dir, "mesh-prod-zero-drain.yaml").read_text(
        encoding="utf-8"
    )
    doc = resource_document(rendered, "ferrum-mesh-control-plane", "Deployment")
    if env_value(doc, "FERRUM_SHUTDOWN_DRAIN_SECONDS") != "0":
        fail(
            "Zero drain dropped",
            "shutdownDrainSeconds=0 must render FERRUM_SHUTDOWN_DRAIN_SECONDS=0",
        )
    forbid_text(
        doc,
        "preStop:",
        "preStop rendered at zero",
        "shutdownPreStopSeconds=0 must omit lifecycle.preStop entirely",
    )
    print("mesh zero-drain render ok")


def validate_injector_shutdown(results_dir: Path) -> None:
    rendered = require_capture(results_dir, "mesh-prod-injector.yaml").read_text(
        encoding="utf-8"
    )
    injector = resource_document(rendered, "ferrum-mesh-injector", "Deployment")
    require_scalar(
        injector,
        "terminationGracePeriodSeconds",
        "65",
        "Injector grace period missing",
        "ferrum-mesh-injector must render terminationGracePeriodSeconds: 65 "
        "(preStop 30 + drain 30 + 5s process-exit slack); it is a "
        "failurePolicy=Fail webhook, so a terminating replica rejects pod CREATE",
    )
    require_text(
        injector,
        "preStop:",
        "Injector preStop missing",
        "ferrum-mesh-injector must render lifecycle.preStop (SleepAction) so "
        "kube-proxy endpoint removal finishes before the listener closes",
    )
    prestop = re.search(r"(?ms)^\s+preStop:\s*\n(?:\s+.*\n){0,6}", injector)
    if prestop is None or "sleep:" not in prestop.group(0):
        fail(
            "Injector preStop is not a SleepAction",
            "distroless has no shell; the injector preStop must use sleep",
        )
    if not re.search(r"seconds:\s*30", prestop.group(0)):
        fail(
            "Injector preStop seconds missing",
            "ferrum-mesh-injector must render injector.shutdownPreStopSeconds (30)",
        )
    drain = env_value(injector, "FERRUM_SHUTDOWN_DRAIN_SECONDS")
    if drain != "30":
        fail(
            "Injector drain env missing",
            f"ferrum-mesh-injector must render FERRUM_SHUTDOWN_DRAIN_SECONDS=30, got {drain!r}",
        )
    occurrences = env_occurrences(injector, "FERRUM_SHUTDOWN_DRAIN_SECONDS")
    if occurrences != 1:
        fail(
            "Injector drain env duplicated",
            "FERRUM_SHUTDOWN_DRAIN_SECONDS must render exactly once "
            f"(got {occurrences}); injector.env overrides are rejected at render",
        )
    node_agent = resource_document(rendered, "ferrum-mesh-node-agent", "DaemonSet")
    require_scalar(
        node_agent,
        "terminationGracePeriodSeconds",
        "30",
        "Node-agent grace period missing",
        "ferrum-mesh-node-agent must render terminationGracePeriodSeconds: 30 "
        "(the Kubernetes default, made explicit and validated)",
    )
    forbid_text(
        node_agent,
        "preStop:",
        "Node-agent preStop rendered",
        "node_agent mode has no drain stage and sits behind no Service; a "
        "preStop sleep would only delay node drains",
    )
    forbid_text(
        node_agent,
        "FERRUM_SHUTDOWN_DRAIN_SECONDS",
        "Node-agent drain env rendered",
        "node_agent mode never reads FERRUM_SHUTDOWN_DRAIN_SECONDS",
    )
    sentinel = require_capture(
        results_dir, "mesh-prod-injector-no-kube-version.yaml"
    ).read_text(encoding="utf-8")
    resource_document(sentinel, "ferrum-mesh-injector", "Deployment")
    kube = require_capture(
        results_dir, "mesh-prod-injector-kube-1.27.err"
    ).read_text(encoding="utf-8")
    if "1.29" not in kube or "SidecarContainers" not in kube:
        fail(
            "Native-sidecar Kubernetes guard missing",
            "--kube-version 1.27.0 with injector.enabled=true must refuse render "
            "and name Kubernetes 1.29 plus the 1.28 SidecarContainers feature gate",
        )
    if "injector.enabled=false" not in kube:
        fail(
            "Native-sidecar remediation missing",
            "the <1.29 injector guard must name injector.enabled=false as the "
            "only option on an older cluster (there is no container fallback)",
        )
    low = require_capture(
        results_dir, "mesh-prod-injector-low-grace.err"
    ).read_text(encoding="utf-8")
    if "injector.terminationGracePeriodSeconds" not in low:
        fail(
            "Injector low-grace refusal missing",
            "an under-budget injector grace period must fail render and name "
            "injector.terminationGracePeriodSeconds",
        )
    if "preStop 30s" not in low or "drain 30s" not in low:
        fail(
            "Injector budget arithmetic missing",
            "the injector refusal must spell out preStop + drain + process-exit slack",
        )
    print("mesh injector/node-agent shutdown ok")


def validate_optional_crds_off(results_dir: Path) -> None:
    rendered = require_capture(results_dir, "default-rendered.yaml").read_text(
        encoding="utf-8"
    )
    for kind in ("ServiceMonitor", "PodMonitor", "PrometheusRule"):
        if re.search(rf"(?m)^kind:\s*{re.escape(kind)}\s*$", rendered):
            fail(
                "Optional observability CRD rendered",
                f"{kind} must stay gated on observability.enabled (default false)",
            )
    if "FERRUM_METRICS_ALLOWED_CIDRS" in rendered or "FERRUM_METRICS_BEARER_TOKEN" in rendered:
        fail(
            "Metrics env rendered while observability is off",
            "FERRUM_METRICS_* must render only when observability.enabled=true",
        )
    print("mesh optional CRDs gated ok")


def validate_observability(results_dir: Path) -> None:
    no_cred = require_capture(results_dir, "mesh-prod-obs-no-cred.err").read_text(
        encoding="utf-8"
    )
    if "scrape credential" not in no_cred:
        fail(
            "Missing-credential refusal missing",
            "observability.alerts/monitors without bearer or allowedCidrs must fail closed",
        )
    inline = require_capture(results_dir, "mesh-prod-obs-inline-bearer.err").read_text(
        encoding="utf-8"
    )
    if "existingSecret.name" not in inline or "inline" not in inline.lower():
        fail(
            "Inline bearer monitor refusal missing",
            "ServiceMonitor without allowedCidrs requires bearerToken.existingSecret.name",
        )
    rendered = require_capture(results_dir, "mesh-prod-obs.yaml").read_text(
        encoding="utf-8"
    )
    sm = resource_document(rendered, "ferrum-mesh-metrics", "ServiceMonitor")
    require_text(
        sm,
        "app.kubernetes.io/component: mesh-metrics",
        "ServiceMonitor selector missing",
        "ServiceMonitor must select mesh-metrics Services",
    )
    require_text(
        sm,
        "port: admin-http",
        "ServiceMonitor port missing",
        "ServiceMonitor must scrape named port admin-http",
    )
    require_text(
        sm,
        "path: /metrics",
        "ServiceMonitor path missing",
        "ServiceMonitor must scrape /metrics",
    )
    for svc_name in (
        "ferrum-mesh-control-plane-metrics",
        "ferrum-mesh-ca-metrics",
        "ferrum-mesh-east-west-metrics",
    ):
        svc = resource_document(rendered, svc_name, "Service")
        require_text(
            svc,
            "targetPort: admin-http",
            "Metrics Service port missing",
            f"{svc_name} must target container port admin-http",
        )
        require_text(
            svc,
            "app.kubernetes.io/component: mesh-metrics",
            "Metrics Service label missing",
            f"{svc_name} must carry mesh-metrics for ServiceMonitor selection",
        )
    cp_svc = resource_document(rendered, "ferrum-mesh-control-plane", "Service")
    forbid_text(
        cp_svc,
        "admin-http",
        "Admin published on CP Service",
        "control-plane Service must stay gRPC-only; scrape via the dedicated metrics Service",
    )
    ew_svc = resource_document(rendered, "ferrum-mesh-east-west", "Service")
    forbid_text(
        ew_svc,
        "admin-http",
        "Admin published on east-west Service",
        "east-west Service must stay tls-passthru only; scrape via the dedicated metrics Service",
    )
    ambient_pm = resource_document(
        rendered, "ferrum-mesh-ambient-metrics", "PodMonitor"
    )
    require_text(
        ambient_pm,
        "app.kubernetes.io/name: ferrum-mesh-ambient",
        "Ambient PodMonitor selector missing",
        "ambient PodMonitor must select ferrum-mesh-ambient pods",
    )
    na_pm = resource_document(
        rendered, "ferrum-mesh-node-agent-metrics", "PodMonitor"
    )
    require_text(
        na_pm,
        "app.kubernetes.io/name: ferrum-mesh-node-agent",
        "Node-agent PodMonitor selector missing",
        "node-agent PodMonitor must select ferrum-mesh-node-agent pods",
    )
    cp = resource_document(rendered, "ferrum-mesh-control-plane", "Deployment")
    if env_value(cp, "FERRUM_METRICS_ALLOWED_CIDRS") is None:
        fail(
            "Metrics CIDR env missing",
            "observability.enabled must render FERRUM_METRICS_ALLOWED_CIDRS on serving pods",
        )
    if "value: " in cp and "change-me" in cp:
        fail(
            "Placeholder metrics token rendered",
            "do not render a default metrics bearer token value",
        )
    rule = resource_document(rendered, "ferrum-mesh-alerts", "PrometheusRule")
    for match in re.finditer(r"(?m)^\s+expr:\s*(.+)$", rule):
        if "absent(" in match.group(1):
            fail(
                "Impossible absent() alert",
                "shipped alert exprs must not use absent() for optional mesh emitters",
            )
    require_text(
        rule,
        "ferrum_mesh_config_last_received_timestamp_seconds",
        "Stale-config alert metric missing",
        "FerrumMeshControlPlaneConfigStale must still reference the freshness timestamp",
    )
    validate_metrics_bearer_https(results_dir)
    print("mesh observability scrape path ok")


def validate_metrics_bearer_https(results_dir: Path) -> None:
    """A metrics bearer credential is only ever attached to a verified HTTPS scrape.

    FERRUM_METRICS_BEARER_TOKEN is not scrape-only: a match also unlocks full
    /health, /status and /overload detail, and both mesh DaemonSets run on the
    host network, so a plaintext scrape puts the credential on the node network
    on every interval (issue #4509, the ferrum-gateway rule from #4316).
    """
    rendered = require_capture(
        results_dir, "mesh-prod-obs-bearer-https.yaml"
    ).read_text(encoding="utf-8")
    sm = resource_document(rendered, "ferrum-mesh-metrics", "ServiceMonitor")
    for needle in ("port: admin-https", "scheme: https", "type: Bearer"):
        require_text(
            sm,
            needle,
            "Credentialed ServiceMonitor is not HTTPS",
            f"a bearer ServiceMonitor scrape must carry {needle}",
        )
    forbid_text(
        sm,
        "port: admin-http\n",
        "Credentialed ServiceMonitor scrapes plaintext",
        "a bearer scrape must never select the plaintext admin port",
    )
    for svc_name in (
        "ferrum-mesh-control-plane-metrics",
        "ferrum-mesh-ca-metrics",
        "ferrum-mesh-east-west-metrics",
    ):
        svc = resource_document(rendered, svc_name, "Service")
        require_text(
            svc,
            "targetPort: admin-https",
            "Metrics Service missing HTTPS port",
            f"{svc_name} must publish admin-https for a credentialed scrape",
        )
    for pm_name in (
        "ferrum-mesh-ambient-metrics",
        "ferrum-mesh-node-agent-metrics",
    ):
        pm = resource_document(rendered, pm_name, "PodMonitor")
        for needle in ("port: admin-https", "scheme: https", "type: Bearer"):
            require_text(
                pm,
                needle,
                "Credentialed PodMonitor is not HTTPS",
                f"{pm_name} must carry {needle}",
            )
        forbid_text(
            pm,
            "port: admin-http\n",
            "Credentialed PodMonitor scrapes plaintext",
            f"{pm_name} must never select the plaintext admin port",
        )
    require_stderr(
        results_dir,
        "mesh-prod-obs-bearer-plaintext.err",
        ("bearer", "admin HTTPS", "plaintext"),
        "Bearer over plaintext admin accepted",
    )
    require_stderr(
        results_dir,
        "mesh-prod-obs-bearer-insecure.err",
        ("insecureSkipVerify",),
        "insecureSkipVerify accepted with a bearer scrape",
    )
    require_stderr(
        results_dir,
        "mesh-prod-obs-bearer-no-tlsconfig.err",
        ("tlsConfig is empty",),
        "Empty tlsConfig accepted for an HTTPS scrape",
    )
    print("mesh metrics bearer HTTPS-only scrape policy ok")


def require_stderr(results_dir: Path, relative: str, needles: tuple[str, ...], title: str) -> None:
    text = require_capture(results_dir, relative).read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in text]
    if missing:
        fail(title, f"{relative} must explain the refusal; missing {missing!r}")


def validate_strict_admin_validation(results_dir: Path) -> None:
    """Issue #4267: the mesh chart must reach the runtime's accept/reject line.

    Every capture below renders cleanly under a permissive approximation and
    then either CrashLoops the pod (`CidrSet::parse_strict`, the CP plaintext
    admin guard, `EnvConfig::validate`'s IP-literal bind requirement) or has the
    admin TCP accept loop silently drop the in-pod exec probes.
    """
    require_stderr(
        results_dir,
        "mesh-prod-bad-admin-bool.err",
        (
            "controlPlane.env.FERRUM_ALLOW_INSECURE_ADMIN_HTTP",
            "true, false, 1, or 0",
        ),
        "Invalid admin insecure-http boolean refusal missing",
    )
    bad_bool = require_capture(
        results_dir, "mesh-prod-bad-admin-bool.err"
    ).read_text(encoding="utf-8")
    if "not-a-bool" in bad_bool:
        fail(
            "Invalid admin bool echoed value",
            "mesh-prod-bad-admin-bool.err must not echo the operator-supplied value",
        )
    require_stderr(
        results_dir,
        "mesh-prod-bad-cidr.err",
        ("controlPlane.admin.allowedCidrs", "not a valid IP address or CIDR"),
        "Malformed admin CIDR refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-catchall-cidr.err",
        ("permits every address in an IP family", "allowInsecureHttp"),
        "Catch-all admin allowlist refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-hostname-bind.err",
        ("controlPlane.admin.bindAddress", "IP literal"),
        "Hostname admin bind refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-probe-family.err",
        ("::1/128", "computed exec probes"),
        "Probe-source family refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-bad-metrics-cidr.err",
        ("observability.metrics.allowedCidrs", "not a valid IP address or CIDR"),
        "Malformed metrics CIDR refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-missing-ready-handler.err",
        ("eastWest.probes.readiness", "drain-aware readiness"),
        "Handler-less readiness refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-ambient-drop.err",
        ("ambient.securityContext.capabilities.drop",),
        "Narrowed ambient capability drop refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-ambient-drop-empty.err",
        ("empty list", "ALL"),
        "Empty ambient capability drop must fail closed instead of becoming [ALL]",
    )
    require_stderr(
        results_dir,
        "mesh-prod-ambient-add-malformed.err",
        ("not a Linux capability name",),
        "Malformed ambient capability add refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-ambient-add-all.err",
        ("values don't meet the specifications of the schema", "add"),
        "Ambient capabilities.add ALL must fail schema validation",
    )
    require_stderr(
        results_dir,
        "mesh-prod-ambient-add-cap-all.err",
        ("must not include ALL", "CAP_ALL"),
        "Ambient capabilities.add CAP_ALL must fail the template guard when schema validation is skipped",
    )
    require_stderr(
        results_dir,
        "mesh-prod-ambient-unknown-sc.err",
        ("runAsUser",),
        "Unsupported ambient securityContext key refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-mapped-catchall.err",
        ("permits every address in an IP family", "IPv4-mapped"),
        "Mapped IPv6 /96 catch-all allowlist refusal missing",
    )
    require_stderr(
        results_dir,
        "mesh-prod-mapped-loopback-probe.err",
        ("127.0.0.1/32", "source 127.0.0.1"),
        "Mapped IPv4 loopback probe-source refusal missing",
    )
    for component in ("controlPlane", "ca"):
        require_stderr(
            results_dir,
            f"mesh-prod-{component}-mapped-bind.err",
            ("non-loopback plaintext listener", "allowInsecureHttp"),
            f"{component} mapped IPv4 loopback bind refusal missing",
        )
    require_stderr(
        results_dir,
        "mesh-prod-ambient-admin-port0.err",
        ("ambient.probes", "no handler can be computed"),
        "Ambient admin-port-zero enabled probes must fail closed",
    )
    print("mesh strict admin/metrics validation ok")


def validate_narrow_ipv6_render(results_dir: Path) -> None:
    """A valid narrow IPv6 allowlist, the <1.29 pre-drain remediation, and an
    ambient capability merge must all still render."""
    rendered = require_capture(results_dir, "mesh-prod-narrow-ipv6.yaml").read_text(
        encoding="utf-8"
    )
    cp = resource_document(rendered, "ferrum-mesh-control-plane", "Deployment")
    cidrs = env_value(cp, "FERRUM_ADMIN_ALLOWED_CIDRS")
    if cidrs != "fd00::/8,::1/128":
        fail(
            "Narrow IPv6 allowlist dropped",
            f"controlPlane.admin.allowedCidrs must render verbatim, got {cidrs!r}",
        )
    if env_value(cp, "FERRUM_ADMIN_BIND_ADDRESS") != "::":
        fail(
            "IPv6 wildcard bind dropped",
            "controlPlane.admin.bindAddress=:: must render as a bare IPv6 literal",
        )
    require_text(
        cp,
        '"::1"',
        "IPv6 probe host missing",
        "the computed exec probes must dial ::1 for an IPv6 wildcard bind",
    )
    # Issue #4266: the <1.29 remediation the SleepAction guard recommends must be
    # a real runtime contract. `cp` mode honors FERRUM_SHUTDOWN_PREDRAIN_SECONDS
    # (EnvConfig::effective_shutdown_predrain_seconds), so the chart may budget it.
    if env_value(cp, "FERRUM_SHUTDOWN_PREDRAIN_SECONDS") != "30":
        fail(
            "Pre-drain remediation not rendered",
            "shutdownPreDrainSeconds=30 must render FERRUM_SHUTDOWN_PREDRAIN_SECONDS=30 on the cp-mode control plane",
        )
    forbid_text(
        cp,
        "preStop:",
        "preStop rendered with the pre-drain remediation",
        "shutdownPreStopSeconds=0 must omit lifecycle.preStop entirely",
    )
    ambient = resource_document(rendered, "ferrum-mesh-ambient", "DaemonSet")
    for cap in ("- NET_ADMIN", "- NET_RAW", "- SYS_RESOURCE"):
        require_text(
            ambient,
            cap,
            "Ambient capability merge broken",
            f"ambient.securityContext.capabilities.add must merge on top of the datapath minimum ({cap})",
        )
    require_text(
        ambient,
        "- ALL",
        "Ambient capability drop missing",
        "ambient must keep dropping unquoted ALL even when extra capabilities are added",
    )
    print("mesh narrow-IPv6 / pre-drain / capability-merge render ok")


def validate_mapped_admin_and_probe_source(results_dir: Path) -> None:
    """Bare mapped IPv6 is /32 IPv4; mapped loopback probes from 127.0.0.1."""

    bare = require_capture(
        results_dir, "mesh-prod-mapped-bare.yaml"
    ).read_text(encoding="utf-8")
    cp = resource_document(bare, "ferrum-mesh-control-plane", "Deployment")
    if env_value(cp, "FERRUM_ADMIN_ALLOWED_CIDRS") != "::ffff:127.0.0.1":
        fail(
            "Bare mapped allowlist dropped",
            "controlPlane.admin.allowedCidrs=::ffff:127.0.0.1 must render and not be treated as permit-all",
        )
    cidr = require_capture(
        results_dir, "mesh-prod-mapped-cidr-host.yaml"
    ).read_text(encoding="utf-8")
    cp_cidr = resource_document(cidr, "ferrum-mesh-control-plane", "Deployment")
    if env_value(cp_cidr, "FERRUM_ADMIN_ALLOWED_CIDRS") != "::ffff:127.0.0.1/128":
        fail(
            "Mapped host CIDR dropped",
            "controlPlane.admin.allowedCidrs=::ffff:127.0.0.1/128 must render as IPv4 /32, not permit-all",
        )
    loopback = require_capture(
        results_dir, "mesh-prod-mapped-loopback-probe-ok.yaml"
    ).read_text(encoding="utf-8")
    cp_lb = resource_document(loopback, "ferrum-mesh-control-plane", "Deployment")
    if env_value(cp_lb, "FERRUM_ADMIN_BIND_ADDRESS") != "::ffff:127.0.0.2":
        fail(
            "Mapped loopback bind dropped",
            "bindAddress=::ffff:127.0.0.2 must render; probe source is 127.0.0.1",
        )
    if env_value(cp_lb, "FERRUM_ADMIN_ALLOWED_CIDRS") != "127.0.0.1/32":
        fail(
            "Mapped loopback probe allowlist dropped",
            "allowlist 127.0.0.1/32 must cover the canonicalized mapped loopback probe source",
        )
    disabled = require_capture(
        results_dir, "mesh-prod-ambient-admin-port0-disabled.yaml"
    ).read_text(encoding="utf-8")
    ambient = resource_document(disabled, "ferrum-mesh-ambient", "DaemonSet")
    if any(
        probe in ambient
        for probe in ("startupProbe:", "livenessProbe:", "readinessProbe:")
    ):
        fail(
            "Disabled ambient probes still rendered",
            "ambient admin httpPort 0 with probes.enabled=false must omit computed probes",
        )
    print("mesh mapped-admin / ambient-port0-disabled render ok")


def _unquoted_cap(doc: str, cap: str, workload: str) -> None:
    require_text(
        doc,
        f"- {cap}",
        f"{workload} {cap} missing",
        f"{workload} must render unquoted - {cap}",
    )
    forbid_text(
        doc,
        f'- "{cap}"',
        f"{workload} {cap} quoted",
        f"quoting {cap} breaks NodeWaypoint eBPF live and Helm Chart greps",
    )


def validate_node_waypoint_ebpf_caps(results_dir: Path) -> None:
    rendered = require_capture(results_dir, "mesh-probes-node-waypoint.yaml").read_text(
        encoding="utf-8"
    )
    ambient = resource_document(rendered, "ferrum-mesh-ambient", "DaemonSet")
    node_agent = resource_document(rendered, "ferrum-mesh-node-agent", "DaemonSet")
    for name, doc in (("ambient", ambient), ("node-agent", node_agent)):
        for cap in ("BPF", "PERFMON", "SYS_ADMIN"):
            _unquoted_cap(doc, cap, name)
    _unquoted_cap(ambient, "SYS_PTRACE", "ambient")
    # This capture sets ambient.env.FERRUM_ADMIN_HTTP_PORT, so it also proves
    # the steady-state env loop does not re-emit what ferrum-mesh.adminEnv
    # rendered. Scoped past `containers:` so the one-shot preflight init
    # container (which renders the raw env map) cannot mask a real duplicate.
    marker = "\n      containers:\n"
    if marker not in ambient:
        fail(
            "Ambient containers section missing",
            "the ambient DaemonSet render must contain a pod-level containers list",
        )
    proxy = ambient.split(marker, 1)[1]
    for name in ADMIN_ENV_KEYS:
        count = env_occurrences(proxy, name)
        if count > 1:
            fail(
                "Ambient admin env duplicated",
                f"{name} must appear exactly once on the ambient proxy, found {count}",
            )
    if env_value(proxy, "FERRUM_ADMIN_HTTP_PORT") != "19091":
        fail(
            "Ambient admin env override dropped",
            "ambient.env.FERRUM_ADMIN_HTTP_PORT must reach the proxy container as 19091",
        )
    require_text(
        ambient,
        "allowPrivilegeEscalation: false",
        "NodeWaypoint Restricted allowPrivilegeEscalation missing",
        "the NodeWaypoint proxy must set allowPrivilegeEscalation: false (Restricted); omitting it lets Kubernetes default permissively",
    )
    print("mesh node-waypoint eBPF capabilities ok")


def validate_udp_cleanup_upgrade(results_dir: Path) -> None:
    rendered = require_capture(
        results_dir, "udp-placement-pod-host-cleanup.yaml"
    ).read_text(encoding="utf-8")
    require_text(
        rendered,
        "- SYS_ADMIN",
        "UDP cleanup SYS_ADMIN missing",
        "pre-contract Ambient UDP cleanup must keep unquoted SYS_ADMIN for setns predecessor retirement",
    )
    require_text(
        rendered,
        "- SYS_PTRACE",
        "UDP cleanup SYS_PTRACE missing",
        "pre-contract Ambient UDP cleanup must keep unquoted SYS_PTRACE for setns predecessor retirement",
    )
    if 'phase: "cleanup"' not in rendered and "phase: cleanup" not in rendered:
        fail(
            "UDP cleanup contract phase missing",
            "the positive --is-upgrade cleanup fixture must stamp phase=cleanup",
        )
    print("mesh UDP cleanup upgrade capabilities ok")


def validate_image_pull_secrets(results_dir: Path) -> None:
    """Chart-level image.pullSecrets must reach every Ferrum pod spec.

    The value is a list of Secret NAMES (strings), matching the gateway chart
    and values.schema.json. The chart default is [], so this render is the only
    thing that exercises either surface; a workload that quietly dropped the
    block would ImagePullBackOff on the first private-registry install.
    """
    rendered = require_capture(
        results_dir, "mesh-image-pull-secrets.yaml"
    ).read_text(encoding="utf-8")
    for name, kind in PULL_SECRET_WORKLOADS:
        doc = resource_document(rendered, name, kind)
        require_text(
            doc,
            "      imagePullSecrets:\n        - name: regcred\n",
            "Mesh workload missing imagePullSecrets",
            f"{kind}/{name} must render image.pullSecrets as `- name: regcred`",
        )
        entries = len(re.findall(r"(?m)^\s*- name: regcred\s*$", doc))
        if entries != 1:
            fail(
                "Mesh workload imagePullSecrets count wrong",
                f"{kind}/{name} rendered regcred {entries} times; expected exactly 1",
            )
        forbid_text(
            doc,
            "map[name:",
            "Mesh imagePullSecrets rendered a Go map",
            f"{kind}/{name} stringified an object entry; items are Secret names",
        )
    print("mesh image pull secrets ok")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results-dir",
        type=Path,
        required=True,
        help="Directory of helm template captures written by ci.yml",
    )
    args = parser.parse_args()
    results_dir = args.results_dir
    if not results_dir.is_dir():
        fail("Results dir missing", f"{results_dir} is not a directory")
    validate_serving_podspecs(results_dir)
    validate_cni_no_drain(results_dir)
    validate_refusals(results_dir)
    validate_zero_drain(results_dir)
    validate_injector_shutdown(results_dir)
    validate_optional_crds_off(results_dir)
    validate_observability(results_dir)
    validate_strict_admin_validation(results_dir)
    validate_narrow_ipv6_render(results_dir)
    validate_mapped_admin_and_probe_source(results_dir)
    validate_admin_env_override(results_dir)
    validate_node_waypoint_ebpf_caps(results_dir)
    validate_udp_cleanup_upgrade(results_dir)
    validate_image_pull_secrets(results_dir)
    print("mesh production-readiness ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
