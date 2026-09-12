#!/usr/bin/env python3
"""Pure data helpers for the multicluster poller-partition fixture."""

from __future__ import annotations

import base64
import binascii
import decimal
import hashlib
import hmac
import json
import re
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


TOXIPROXY_ACCEPTED_CLIENT_FIELDS = frozenset(
    {"level", "caller", "time", "name", "listen", "upstream", "client", "message"}
)
MAX_FIXTURE_COUNT = 999_999_999_999_999_999


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def init(path: Path, commit: str, platform_profile: str) -> None:
    payload = {
        "schema_version": 1,
        "suite": "multicluster-poller-partition",
        "commit": commit,
        "platform_profile": platform_profile,
        "created_at": timestamp(),
        "assertions": [],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def record(
    path: Path,
    assertion_id: str,
    status: str,
    outcome: str,
    diagnostics_csv: str,
) -> None:
    if status not in {"pass", "fail", "skip"}:
        raise SystemExit(
            f"invalid live assertion status for {assertion_id}: {status}"
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.setdefault("assertions", []).append(
        {
            "id": assertion_id,
            "status": status,
            "source_workload": "mesh-dp",
            "destination_workload": "mesh-dp",
            "observed_outcome": outcome or None,
            "observed_source_spiffe_id": None,
            "observed_destination_spiffe_id": None,
            "configuration_generation": None,
            "timestamp": timestamp(),
            "diagnostic_artifact_paths": [
                item for item in diagnostics_csv.split(",") if item
            ],
        }
    )
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def require(path: Path, required: list[str]) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    observed = {entry.get("id"): entry for entry in payload.get("assertions", [])}
    missing = [assertion_id for assertion_id in required if assertion_id not in observed]
    failed = [
        assertion_id
        for assertion_id in required
        if assertion_id in observed and observed[assertion_id].get("status") != "pass"
    ]
    if missing:
        print("missing live assertions: " + ", ".join(missing), file=sys.stderr)
    if failed:
        print("non-passing live assertions: " + ", ".join(failed), file=sys.stderr)
    if missing or failed:
        raise SystemExit(1)


def read_stdin_json() -> object:
    return json.load(sys.stdin)


def running_spire_nodes() -> None:
    nodes: set[str] = set()
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 2:
            raise SystemExit("malformed SPIRE agent pod row")
        phase, node = fields
        if phase == "Running":
            nodes.add(node)
    for node in sorted(nodes):
        print(node)


def bundle_b64der() -> None:
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    authorities: list[str] = []
    encoded: list[str] | None = None
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        if line == begin:
            if encoded is not None:
                raise SystemExit("nested certificate in SPIRE bundle")
            encoded = []
        elif line == end:
            if not encoded:
                raise SystemExit("empty certificate in SPIRE bundle")
            try:
                der = base64.b64decode("".join(encoded), validate=True)
            except (ValueError, binascii.Error) as error:
                raise SystemExit("invalid certificate encoding in SPIRE bundle") from error
            if not der:
                raise SystemExit("empty DER certificate in SPIRE bundle")
            authorities.append(base64.b64encode(der).decode())
            encoded = None
        elif encoded is None:
            raise SystemExit("unexpected content outside SPIRE certificate")
        elif re.fullmatch(r"[A-Za-z0-9+/=]+", line) is None:
            raise SystemExit("invalid certificate line in SPIRE bundle")
        else:
            encoded.append(line)
    if encoded is not None:
        raise SystemExit("unterminated certificate in SPIRE bundle")
    if not authorities:
        raise SystemExit("SPIRE bundle contains no certificates")
    print(*authorities, sep="\n")


def prometheus_uint(value: str, label: str) -> int:
    try:
        parsed = decimal.Decimal(value)
    except decimal.InvalidOperation as error:
        raise SystemExit(f"invalid Prometheus value for {label}") from error
    if not parsed.is_finite() or parsed < 0 or parsed != parsed.to_integral_value():
        raise SystemExit(f"non-integer Prometheus value for {label}")
    return int(parsed)


def prometheus_samples(metric: str, selectors: tuple[str, ...]) -> list[int]:
    values: list[int] = []
    prefix = metric + "{"
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line.startswith(prefix) or not all(
            selector in line for selector in selectors
        ):
            continue
        fields = line.rsplit(None, 1)
        if len(fields) != 2:
            raise SystemExit(f"malformed Prometheus sample for {metric}")
        values.append(prometheus_uint(fields[1], metric))
    return values


def prometheus_value(metric: str, selector: str) -> None:
    values = prometheus_samples(metric, (selector,))
    if len(values) > 1:
        raise SystemExit(f"duplicate Prometheus samples for {metric}")
    print(values[0] if values else 0)


def toxiproxy_accepted_client_count(proxy: str) -> None:
    if re.fullmatch(r"[a-z0-9-]{1,64}", proxy) is None:
        raise SystemExit("invalid Toxiproxy fixture proxy name")

    count = 0
    for line_number, raw_line in enumerate(sys.stdin, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise SystemExit(
                f"malformed Toxiproxy JSON log record at line {line_number}"
            ) from error
        if not isinstance(record, dict):
            raise SystemExit(
                f"non-object Toxiproxy JSON log record at line {line_number}"
            )
        for required in ("level", "caller", "time", "message"):
            if not isinstance(record.get(required), str) or not record[required]:
                raise SystemExit(
                    f"malformed Toxiproxy log envelope at line {line_number}"
                )
        if record["message"] != "Accepted client":
            continue
        if set(record) != TOXIPROXY_ACCEPTED_CLIENT_FIELDS:
            raise SystemExit(
                f"unexpected accepted-client log structure at line {line_number}"
            )
        if record["level"] != "info" or any(
            not isinstance(record.get(field), str) or not record[field]
            for field in ("name", "listen", "upstream", "client")
        ):
            raise SystemExit(
                f"malformed accepted-client log record at line {line_number}"
            )
        if record["name"] == proxy:
            if count == MAX_FIXTURE_COUNT:
                raise SystemExit("Toxiproxy accepted-client count exceeds fixture bound")
            count += 1
    print(count)


def mint_admin_jwt(secret: str) -> None:
    now = int(time.time())

    def encode(value: object) -> str:
        encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode()

    header = encode({"alg": "HS256", "typ": "JWT"})
    claims = encode(
        {
            "iss": "ferrum-edge",
            "sub": "poller-live",
            "iat": now,
            "nbf": now - 1,
            "exp": now + 3600,
            "jti": str(uuid.uuid4()),
            "role": "admin",
        }
    )
    payload = f"{header}.{claims}"
    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    ).rstrip(b"=")
    print(f"{payload}.{signature.decode()}")


def state_matches(
    peer: str,
    discovered: str,
    trust_source: str,
    outbound: str,
    inbound: str,
) -> None:
    payload = read_stdin_json()
    if not isinstance(payload, dict):
        raise SystemExit(1)
    configured = payload.get("configured")
    if not isinstance(configured, list):
        raise SystemExit(1)
    rows = [row for row in configured if row.get("cluster_name") == peer]
    if discovered not in {"true", "false", "any"}:
        raise SystemExit(1)
    expected = {
        "trust_source": trust_source,
        "outbound_trust_active": outbound == "true",
        "inbound_trust_active": inbound == "true",
    }
    if discovered != "any":
        expected["discovered"] = discovered == "true"
    if len(rows) != 1 or any(
        rows[0].get(key) != value for key, value in expected.items()
    ):
        raise SystemExit(1)


def no_configured_state() -> None:
    payload = read_stdin_json()
    if (
        not isinstance(payload, dict)
        or payload.get("configured") != []
        or payload.get("discovered") != []
    ):
        raise SystemExit(1)


def remote_ages(peer: str) -> tuple[int, int]:
    payload = read_stdin_json()
    if not isinstance(payload, dict):
        raise SystemExit(1)
    configured_rows = payload.get("configured")
    discovered_rows = payload.get("discovered")
    if not isinstance(configured_rows, list) or not isinstance(
        discovered_rows, list
    ):
        raise SystemExit(1)
    configured = [
        row
        for row in configured_rows
        if isinstance(row, dict) and row.get("cluster_name") == peer
    ]
    discovered = [
        row
        for row in discovered_rows
        if isinstance(row, dict) and row.get("cluster_name") == peer
    ]
    if len(configured) != 1 or len(discovered) != 1:
        raise SystemExit(1)
    try:
        return (
            int(configured[0]["trust_bundle_age_seconds"]),
            int(discovered[0]["age_seconds"]),
        )
    except (KeyError, TypeError, ValueError):
        raise SystemExit(1) from None


def ages_between(peer: str, low: int, high: int) -> None:
    trust_age, endpoint_age = remote_ages(peer)
    if not (low <= trust_age < high and low <= endpoint_age < high):
        raise SystemExit(1)


def metric_value(text: str, name: str, labels: dict[str, str]) -> float:
    for line in text.splitlines():
        if line.startswith(name + "{") and all(
            f'{key}="{value}"' in line for key, value in labels.items()
        ):
            return float(line.rsplit(" ", 1)[1])
    raise SystemExit(f"missing {name}")


PARITY_AGE_TOLERANCE_SECONDS = 2


def remote_cache_ages(payload: object, peer: str) -> tuple[float, float]:
    if not isinstance(payload, dict):
        raise SystemExit(1)
    configured_rows = payload.get("configured")
    discovered_rows = payload.get("discovered")
    if not isinstance(configured_rows, list) or not isinstance(
        discovered_rows, list
    ):
        raise SystemExit(1)
    configured = next(
        row
        for row in configured_rows
        if isinstance(row, dict) and row.get("cluster_name") == peer
    )
    discovered = next(
        row
        for row in discovered_rows
        if isinstance(row, dict) and row.get("cluster_name") == peer
    )
    try:
        return (
            float(configured["trust_bundle_age_seconds"]),
            float(discovered["age_seconds"]),
        )
    except (KeyError, TypeError, ValueError):
        raise SystemExit(1) from None


def metric_age_matches_admin_snapshot(
    metric_age: float, admin_age: float, tolerance: float = PARITY_AGE_TOLERANCE_SECONDS
) -> bool:
    return abs(metric_age - admin_age) <= tolerance


def assert_metric_admin_parity(
    json_before_path: Path,
    metrics_path: Path,
    json_after_path: Path,
    peer: str,
    trust_domain: str,
) -> None:
    before = json.loads(json_before_path.read_text(encoding="utf-8"))
    after = json.loads(json_after_path.read_text(encoding="utf-8"))
    text = metrics_path.read_text(encoding="utf-8")
    trust_before, endpoint_before = remote_cache_ages(before, peer)
    trust_after, endpoint_after = remote_cache_ages(after, peer)
    federation_age = metric_value(
        text,
        "ferrum_mesh_federation_bundle_age_seconds",
        {"trust_domain": trust_domain},
    )
    endpoint_age = metric_value(
        text,
        "ferrum_mesh_remote_discovery_endpoint_age_seconds",
        {"cluster": peer, "trust_domain": trust_domain},
    )
    trust_ok = metric_age_matches_admin_snapshot(
        federation_age, trust_before
    ) or metric_age_matches_admin_snapshot(federation_age, trust_after)
    endpoint_ok = metric_age_matches_admin_snapshot(
        endpoint_age, endpoint_before
    ) or metric_age_matches_admin_snapshot(endpoint_age, endpoint_after)
    if not trust_ok or not endpoint_ok:
        raise SystemExit("admin/metric cache-age parity exceeded 2s")
    if (
        'endpoint="redacted"' not in text
        and "ferrum_mesh_federation_poll_failures_total" in text
    ):
        raise SystemExit("federation endpoint label not redacted")
    if (
        'control_plane="redacted"' not in text
        and "ferrum_mesh_remote_discovery_poll_failures_total" in text
    ):
        raise SystemExit("control-plane label not redacted")
    families = {
        "ferrum_mesh_federation_poll_failures_total": f'trust_domain="{trust_domain}"',
        "ferrum_mesh_federation_bundle_age_seconds": f'trust_domain="{trust_domain}"',
        "ferrum_mesh_remote_discovery_poll_failures_total": f'cluster="{peer}"',
        "ferrum_mesh_remote_discovery_poll_successes_total": f'cluster="{peer}"',
        "ferrum_mesh_remote_discovery_endpoint_age_seconds": f'cluster="{peer}"',
    }
    for family, selector in families.items():
        matches = [
            line
            for line in text.splitlines()
            if line.startswith(family + "{") and selector in line
        ]
        if len(matches) != 1:
            raise SystemExit(
                f"bounded cardinality violated for {family}: {len(matches)}"
            )


def self_test_metric_admin_parity() -> None:
    peer = "cluster-b"
    trust_domain = "cluster-b.example"
    before = {
        "configured": [
            {"cluster_name": peer, "trust_bundle_age_seconds": 5},
        ],
        "discovered": [
            {"cluster_name": peer, "age_seconds": 5},
        ],
    }
    after = {
        "configured": [
            {"cluster_name": peer, "trust_bundle_age_seconds": 0},
        ],
        "discovered": [
            {"cluster_name": peer, "age_seconds": 5},
        ],
    }
    metrics = "\n".join(
        [
            (
                'ferrum_mesh_federation_bundle_age_seconds'
                f'{{trust_domain="{trust_domain}"}} 0'
            ),
            (
                'ferrum_mesh_remote_discovery_endpoint_age_seconds'
                f'{{cluster="{peer}",trust_domain="{trust_domain}"}} 5'
            ),
            'ferrum_mesh_federation_poll_failures_total'
            f'{{trust_domain="{trust_domain}",endpoint="redacted"}} 1',
            'ferrum_mesh_remote_discovery_poll_failures_total'
            f'{{cluster="{peer}",control_plane="redacted"}} 1',
            'ferrum_mesh_remote_discovery_poll_successes_total'
            f'{{cluster="{peer}",trust_domain="{trust_domain}"}} 2',
        ]
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        before_path = root / "before.json"
        after_path = root / "after.json"
        metrics_path = root / "metrics.prom"
        before_path.write_text(json.dumps(before), encoding="utf-8")
        after_path.write_text(json.dumps(after), encoding="utf-8")
        metrics_path.write_text(metrics, encoding="utf-8")
        assert_metric_admin_parity(
            before_path, metrics_path, after_path, peer, trust_domain
        )
        stale_metrics = metrics.replace(" 0\n", " 9\n", 1)
        metrics_path.write_text(stale_metrics, encoding="utf-8")
        try:
            assert_metric_admin_parity(
                before_path, metrics_path, after_path, peer, trust_domain
            )
        except SystemExit as error:
            if str(error) != "admin/metric cache-age parity exceeded 2s":
                raise
        else:
            raise SystemExit("parity self-test expected stale trust age to fail")


def redact_toxiproxy() -> None:
    payload = read_stdin_json()
    if not isinstance(payload, dict):
        raise SystemExit(1)
    for proxy in payload.values():
        if not isinstance(proxy, dict):
            raise SystemExit(1)
        proxy["upstream"] = "redacted"
        proxy["listen"] = "redacted"
    print(json.dumps(payload, indent=2, sort_keys=True))


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        raise SystemExit("fixture helper operation is required")
    operation = argv[1]
    if operation == "running-spire-nodes" and len(argv) == 2:
        running_spire_nodes()
    elif operation == "bundle-b64der" and len(argv) == 2:
        bundle_b64der()
    elif operation == "prometheus-value" and len(argv) == 4:
        prometheus_value(argv[2], argv[3])
    elif operation == "toxiproxy-accepted-client-count" and len(argv) == 3:
        toxiproxy_accepted_client_count(argv[2])
    elif operation == "mint-admin-jwt" and len(argv) == 3:
        mint_admin_jwt(argv[2])
    elif operation == "proxy-count" and len(argv) == 2:
        payload = read_stdin_json()
        if not isinstance(payload, dict):
            raise SystemExit(1)
        print(len(payload))
    elif operation == "bundle-json" and len(argv) == 4:
        print(
            json.dumps(
                {
                    "trust_domain": argv[2],
                    "x509_authorities": argv[3].splitlines(),
                    "jwt_authorities": [],
                }
            )
        )
    elif operation == "state-matches" and len(argv) == 7:
        state_matches(*argv[2:])
    elif operation == "no-configured-state" and len(argv) == 2:
        no_configured_state()
    elif operation == "ages-between" and len(argv) == 5:
        ages_between(argv[2], int(argv[3]), int(argv[4]))
    elif operation == "admin-ages" and len(argv) == 3:
        print(*remote_ages(argv[2]))
    elif operation == "self-test" and len(argv) == 2:
        self_test_metric_admin_parity()
        print("live_assertions self-test passed")
    elif operation == "assert-metric-admin-parity" and len(argv) == 7:
        assert_metric_admin_parity(
            Path(argv[2]), Path(argv[3]), Path(argv[4]), argv[5], argv[6]
        )
    elif operation == "redact-toxiproxy" and len(argv) == 2:
        redact_toxiproxy()
    elif len(argv) < 3:
        raise SystemExit("live assertion operation requires an output path")
    elif operation == "init" and len(argv) == 5:
        path = Path(argv[2])
        init(path, argv[3], argv[4])
    elif operation == "record" and len(argv) == 7:
        path = Path(argv[2])
        record(path, argv[3], argv[4], argv[5], argv[6])
    elif operation == "require" and len(argv) > 3:
        path = Path(argv[2])
        require(path, argv[3:])
    else:
        raise SystemExit(f"invalid live assertion operation or arguments: {operation}")


if __name__ == "__main__":
    main(sys.argv)
