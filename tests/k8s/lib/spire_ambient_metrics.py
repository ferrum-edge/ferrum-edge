#!/usr/bin/env python3
"""Fail-closed SPIRE Agent ambient metric proof for NodeWaypoint live gates.

The production mesh SPIRE path publishes identity telemetry with
`source=\"spire_agent\"` / `ca_type=\"spire_agent\"` (issue #3608). The live
harness must prove the exact per-node SPIFFE ID, SPIRE-agent source, positive
certificate expiry, healthy CA, and a trust-bundle observation — never mere
metric-name presence, and never the historical generic `workload_api` label.
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Iterable

CERT_EXPIRY_RE = re.compile(
    r'^ferrum_mesh_cert_expiry_seconds\{(?P<labels>[^}]*)\}\s+(?P<value>-?\d+(?:\.\d+)?)\s*$'
)
CA_HEALTH_RE = re.compile(
    r'^ferrum_mesh_ca_health\{(?P<labels>[^}]*)\}\s+(?P<value>-?\d+(?:\.\d+)?)\s*$'
)
TRUST_BUNDLE_RE = re.compile(
    r'^ferrum_mesh_trust_bundle_version\{(?P<labels>[^}]*)\}\s+(?P<value>-?\d+(?:\.\d+)?)\s*$'
)
LABEL_RE = re.compile(
    r'\s*([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\[\\"n]|[^"\\])*)"\s*'
)


def _unescape_label_value(raw: str) -> str:
    value: list[str] = []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char != "\\":
            value.append(char)
            index += 1
            continue

        escaped = raw[index + 1]
        value.append({"\\": "\\", '"': '"', "n": "\n"}[escaped])
        index += 2
    return "".join(value)


def parse_labels(raw: str) -> dict[str, str] | None:
    labels: dict[str, str] = {}
    position = 0
    while position < len(raw):
        match = LABEL_RE.match(raw, position)
        if match is None:
            return None
        name = match.group(1)
        if name in labels:
            return None
        labels[name] = _unescape_label_value(match.group(2))
        position = match.end()
        if position == len(raw):
            break
        if raw[position] != ",":
            return None
        position += 1
        if position == len(raw):
            return None
    return labels


def prove_spire_agent_identity(
    metrics_text: str,
    *,
    expected_spiffe: str,
    trust_domain: str,
) -> list[str]:
    """Return human-readable errors; empty list means the scrape proves identity."""
    errors: list[str] = []
    lines = [line.strip() for line in metrics_text.splitlines() if line.strip()]

    expiry_ok = False
    for line in lines:
        match = CERT_EXPIRY_RE.match(line)
        if match is None:
            continue
        labels = parse_labels(match.group("labels"))
        if labels is None:
            continue
        if labels.get("spiffe_id") != expected_spiffe:
            continue
        if labels.get("source") != "spire_agent":
            continue
        value = float(match.group("value"))
        if value <= 0:
            errors.append(
                f"cert expiry for {expected_spiffe} with source=spire_agent must be > 0, got {value}"
            )
            continue
        expiry_ok = True
        break
    if not expiry_ok and not any(
        err.startswith("cert expiry for ") for err in errors
    ):
        # Distinguish the exact hosted regression: presence under the wrong source
        # label must not satisfy the gate.
        wrong_source = False
        for line in lines:
            match = CERT_EXPIRY_RE.match(line)
            if match is None:
                continue
            labels = parse_labels(match.group("labels"))
            if labels is None:
                continue
            if (
                labels.get("spiffe_id") == expected_spiffe
                and labels.get("source") == "workload_api"
            ):
                wrong_source = True
                break
        if wrong_source:
            errors.append(
                f"found cert expiry for {expected_spiffe} with source=workload_api; "
                "production SPIRE mesh path must publish source=spire_agent"
            )
        else:
            errors.append(
                "missing ferrum_mesh_cert_expiry_seconds with "
                f'spiffe_id="{expected_spiffe}",source="spire_agent" and value > 0'
            )

    ca_ok = False
    for line in lines:
        match = CA_HEALTH_RE.match(line)
        if match is None:
            continue
        labels = parse_labels(match.group("labels"))
        if labels is None:
            continue
        if labels.get("ca_type") != "spire_agent":
            continue
        value = float(match.group("value"))
        if value != 1.0:
            errors.append(
                f'ferrum_mesh_ca_health{{ca_type="spire_agent"}} must be 1, got {value}'
            )
            continue
        ca_ok = True
        break
    if not ca_ok and not any("ca_health" in err for err in errors):
        errors.append('missing ferrum_mesh_ca_health{ca_type="spire_agent"} 1')

    bundle_ok = False
    for line in lines:
        match = TRUST_BUNDLE_RE.match(line)
        if match is None:
            continue
        labels = parse_labels(match.group("labels"))
        if labels is None:
            continue
        if labels.get("trust_domain") != trust_domain:
            continue
        if labels.get("source") != "spire_agent":
            continue
        value = float(match.group("value"))
        if value < 1:
            errors.append(
                "trust bundle version for "
                f'trust_domain="{trust_domain}",source="spire_agent" must be >= 1, got {value}'
            )
            continue
        bundle_ok = True
        break
    if not bundle_ok and not any("trust bundle" in err for err in errors):
        errors.append(
            "missing ferrum_mesh_trust_bundle_version with "
            f'trust_domain="{trust_domain}",source="spire_agent" and value >= 1'
        )

    return errors


def _assert_errors(actual: Iterable[str], expected_substrings: list[str], label: str) -> None:
    actual_list = list(actual)
    if not expected_substrings:
        if actual_list:
            raise AssertionError(f"{label}: expected success, got errors {actual_list!r}")
        return
    joined = "\n".join(actual_list)
    for needle in expected_substrings:
        if needle not in joined:
            raise AssertionError(
                f"{label}: expected error containing {needle!r}, got {actual_list!r}"
            )


def self_test() -> None:
    expected_spiffe = (
        "spiffe://cluster.local/ns/ferrum/sa/ferrum-mesh-ambient/node/ferrum-ebpf-live-worker2"
    )
    trust_domain = "cluster.local"

    # Exact hosted failure scrape shape from workflow run 31253986050: the
    # series are present under source=spire_agent, but the old harness grepped
    # for source=workload_api and rejected a valid proof.
    hosted_present = """
# HELP ferrum_mesh_cert_expiry_seconds Seconds until mesh X.509-SVID expiry.
# TYPE ferrum_mesh_cert_expiry_seconds gauge
ferrum_mesh_cert_expiry_seconds{spiffe_id="spiffe://cluster.local/ns/ferrum/sa/ferrum-mesh-ambient/node/ferrum-ebpf-live-worker2",source="spire_agent"} 3569
# HELP ferrum_mesh_ca_health Mesh CA backend health, 1 healthy and 0 unhealthy.
# TYPE ferrum_mesh_ca_health gauge
ferrum_mesh_ca_health{ca_type="spire_agent"} 1
# HELP ferrum_mesh_trust_bundle_version Monotonic version of observed mesh trust bundles.
# TYPE ferrum_mesh_trust_bundle_version gauge
ferrum_mesh_trust_bundle_version{trust_domain="cluster.local",source="spire_agent"} 1
"""
    _assert_errors(
        prove_spire_agent_identity(
            hosted_present,
            expected_spiffe=expected_spiffe,
            trust_domain=trust_domain,
        ),
        [],
        "hosted-present-spire-agent",
    )

    wrong_source_only = """
ferrum_mesh_cert_expiry_seconds{spiffe_id="spiffe://cluster.local/ns/ferrum/sa/ferrum-mesh-ambient/node/ferrum-ebpf-live-worker2",source="workload_api"} 3569
ferrum_mesh_ca_health{ca_type="spire_agent"} 1
ferrum_mesh_trust_bundle_version{trust_domain="cluster.local",source="spire_agent"} 1
"""
    _assert_errors(
        prove_spire_agent_identity(
            wrong_source_only,
            expected_spiffe=expected_spiffe,
            trust_domain=trust_domain,
        ),
        ["source=workload_api", "source=spire_agent"],
        "reject-workload-api-source",
    )

    name_only = """
ferrum_mesh_cert_expiry_seconds 3569
ferrum_mesh_ca_health 1
ferrum_mesh_trust_bundle_version 1
"""
    _assert_errors(
        prove_spire_agent_identity(
            name_only,
            expected_spiffe=expected_spiffe,
            trust_domain=trust_domain,
        ),
        [
            'spiffe_id="spiffe://cluster.local/ns/ferrum/sa/ferrum-mesh-ambient/node/ferrum-ebpf-live-worker2"',
            'ca_type="spire_agent"',
            'trust_domain="cluster.local"',
        ],
        "reject-metric-name-only",
    )

    zero_expiry = """
ferrum_mesh_cert_expiry_seconds{spiffe_id="spiffe://cluster.local/ns/ferrum/sa/ferrum-mesh-ambient/node/ferrum-ebpf-live-worker2",source="spire_agent"} 0
ferrum_mesh_ca_health{ca_type="spire_agent"} 1
ferrum_mesh_trust_bundle_version{trust_domain="cluster.local",source="spire_agent"} 1
"""
    _assert_errors(
        prove_spire_agent_identity(
            zero_expiry,
            expected_spiffe=expected_spiffe,
            trust_domain=trust_domain,
        ),
        ["must be > 0"],
        "reject-non-positive-expiry",
    )

    unhealthy_ca = """
ferrum_mesh_cert_expiry_seconds{spiffe_id="spiffe://cluster.local/ns/ferrum/sa/ferrum-mesh-ambient/node/ferrum-ebpf-live-worker2",source="spire_agent"} 3569
ferrum_mesh_ca_health{ca_type="spire_agent"} 0
ferrum_mesh_trust_bundle_version{trust_domain="cluster.local",source="spire_agent"} 1
"""
    _assert_errors(
        prove_spire_agent_identity(
            unhealthy_ca,
            expected_spiffe=expected_spiffe,
            trust_domain=trust_domain,
        ),
        ["must be 1"],
        "reject-unhealthy-ca",
    )

    missing_bundle = """
ferrum_mesh_cert_expiry_seconds{spiffe_id="spiffe://cluster.local/ns/ferrum/sa/ferrum-mesh-ambient/node/ferrum-ebpf-live-worker2",source="spire_agent"} 3569
ferrum_mesh_ca_health{ca_type="spire_agent"} 1
"""
    _assert_errors(
        prove_spire_agent_identity(
            missing_bundle,
            expected_spiffe=expected_spiffe,
            trust_domain=trust_domain,
        ),
        ["trust_bundle_version"],
        "reject-missing-trust-bundle",
    )

    malformed_labels = """
ferrum_mesh_cert_expiry_seconds{spiffe_id="spiffe://cluster.local/ns/ferrum/sa/ferrum-mesh-ambient/node/ferrum-ebpf-live-worker2",source="spire_agent",broken} 3569
ferrum_mesh_ca_health{ca_type="spire_agent",ca_type="other"} 1
ferrum_mesh_trust_bundle_version{trust_domain="cluster.local",source="spire_agent",bad="\\t"} 1
"""
    _assert_errors(
        prove_spire_agent_identity(
            malformed_labels,
            expected_spiffe=expected_spiffe,
            trust_domain=trust_domain,
        ),
        [
            "ferrum_mesh_cert_expiry_seconds",
            'ca_type="spire_agent"',
            "ferrum_mesh_trust_bundle_version",
        ],
        "reject-malformed-or-duplicate-labels",
    )

    print("spire_ambient_metrics.py --self-test: ok")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--metrics-file")
    parser.add_argument("--expected-spiffe")
    parser.add_argument("--trust-domain")
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    missing = [
        name
        for name, value in (
            ("--metrics-file", args.metrics_file),
            ("--expected-spiffe", args.expected_spiffe),
            ("--trust-domain", args.trust_domain),
        )
        if not value
    ]
    if missing:
        parser.error(f"{', '.join(missing)} required unless --self-test is used")

    with open(args.metrics_file, encoding="utf-8") as fh:
        metrics_text = fh.read()
    errors = prove_spire_agent_identity(
        metrics_text,
        expected_spiffe=args.expected_spiffe,
        trust_domain=args.trust_domain,
    )
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
