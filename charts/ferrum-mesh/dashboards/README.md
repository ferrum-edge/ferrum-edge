# Ferrum Edge Grafana Dashboards

This directory ships five curated Grafana dashboards covering the Ferrum
Edge gateway and mesh-mode data plane. Every panel reads only metrics that
the gateway emits today; no synthetic or aspirational queries.

## Dashboards

| File | UID | Tags | Use case |
|---|---|---|---|
| `gateway-overview.json` | `ferrum-gateway-overview` | `ferrum`, `gateway` | HTTP RED, status-code distribution, p50/p95/p99 latency, stream connections, client disconnects. |
| `mesh-overview.json` | `ferrum-mesh-overview` | `ferrum`, `mesh` | Mesh RED grouped by source / destination workload, mTLS coverage, mTLS handshake failures, config freshness. |
| `certificate-posture.json` | `ferrum-certificate-posture` | `ferrum`, `mesh` | SVID expiry table sorted ascending, < 7d / < 24h counters, CA health, trust-bundle churn, SPIFFE federation poll health. |
| `egress-scope.json` | `ferrum-egress-scope` | `ferrum`, `mesh` | Admitted vs denied egress destinations from the mesh outbound registry plugin. |
| `policy-deny.json` | `ferrum-policy-deny` | `ferrum`, `mesh` | Mesh policy denies (HTTP 403) grouped by source workload / destination workload / source principal / destination service, plus egress-registry denies. |

Every dashboard exposes a `$datasource` (Prometheus) variable and a set of
scoping selectors (namespace, workload, source / destination, trust domain)
templated against the live metrics.

## Metric coverage

| Dashboard | Metrics consumed |
|---|---|
| gateway-overview | `ferrum_requests_total`, `ferrum_request_duration_ms_bucket`, `ferrum_backend_duration_ms_bucket`, `ferrum_edge_overhead_ms_bucket`, `ferrum_rate_limit_exceeded_total`, `ferrum_client_disconnects_total`, `ferrum_stream_connections_total`, `ferrum_stream_disconnects_total` |
| mesh-overview | `ferrum_mesh_requests_total`, `ferrum_mesh_request_duration_ms_bucket`, `ferrum_mesh_mtls_handshake_failures_total`, `ferrum_mesh_config_last_received_timestamp_seconds`, `ferrum_mesh_node_waypoint_hbone_handshakes_total`, `ferrum_mesh_node_waypoint_asserted_identity_total`, `ferrum_mesh_node_waypoint_destination_policy_rejections_total`, `ferrum_mesh_node_waypoint_missing_destination_metadata_total`, `ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total` |
| certificate-posture | `ferrum_mesh_cert_expiry_seconds`, `ferrum_mesh_cert_rotation_failures_total`, `ferrum_mesh_ca_health`, `ferrum_mesh_trust_bundle_version`, `ferrum_mesh_federation_bundle_age_seconds`, `ferrum_mesh_federation_poll_failures_total` |
| egress-scope | `ferrum_mesh_outbound_registry_decisions_total{decision="admit"\|"deny"}` |
| policy-deny | `ferrum_mesh_requests_total{response_code="403"}`, `ferrum_mesh_outbound_registry_decisions_total{decision="deny"}` |

Names are emitted in `src/plugins/prometheus_metrics.rs`,
`src/plugins/mesh/prometheus_helpers.rs`, and
`src/modes/mesh/node_waypoint_observability.rs`; alert rules built on the
same names live in `charts/ferrum-mesh/templates/alerts-prometheusrule.yaml`.

## Installing via the Helm chart

The bundled `ferrum-mesh` Helm chart ships these dashboards as a templated
`ConfigMap` (default name `ferrum-mesh-dashboards`) carrying the
`grafana_dashboard: "1"` label, which the upstream Grafana sidecar
(`kiwigrid/k8s-sidecar`) and the Grafana Operator both pick up automatically.
The ConfigMap renders only when `observability.enabled=true`
(`observability.dashboards.enabled` then defaults to `true`; set it to `false`
if you manage dashboards out of band). Enabling observability also renders
monitors and alerts, which require a scrape credential
(`observability.metrics.allowedCidrs` or `observability.metrics.bearerToken`),
so render fails without one:

```bash
helm install ferrum-mesh ./charts/ferrum-mesh \
  --set observability.enabled=true \
  --set observability.metrics.allowedCidrs=<prometheus-pod-cidr>
```

If Grafana looks for a non-default label, override it with
`observability.dashboards.sidecarLabel` / `observability.dashboards.sidecarLabelValue`
(for example `--set observability.dashboards.sidecarLabelValue=my-folder`).

## Installing without Helm

Each `.json` file is a standalone Grafana v9+ dashboard. Import them by
either:

1. **Grafana UI** — Dashboards → New → Import → upload the JSON file. Pick
   the Prometheus datasource when prompted.
2. **Dashboard sidecar** — drop the JSON into a `ConfigMap` with the
   `grafana_dashboard: "1"` label in the namespace your sidecar watches.
3. **Provisioning** — copy the JSON files into a Grafana provisioning
   directory under `/etc/grafana/provisioning/dashboards/`.

## Notes on what is and isn't covered

- **Concurrency and pool detail** is not charted. The live gauges
  `ferrum_overload_active_connections` / `ferrum_overload_active_requests` are
  exported on `/metrics` but not on `gateway-overview.json`; fuller pool and
  overload detail is available from authenticated `GET /overload` and the
  JWT-authenticated `GET /metrics/runtime` JSON endpoint.
- **Per-rule mesh authz denies** are surfaced in transaction logs only
  (`mesh_authz.deny_policy` metadata), not as Prometheus labels. The
  `policy-deny.json` dashboard groups denies by source / destination
  workload, source principal, and destination service — the highest
  cardinality the metrics support today.
- **Egress destination cardinality is bounded.** The mesh outbound registry
  plugin reports deny decisions under a single `<denied>` host bucket to
  keep `/metrics` bounded under hostile traffic; admit decisions report the
  real destination. The egress-scope dashboard reflects this asymmetry.
- **NodeWaypoint BPF metrics** (`ferrum_mesh_bpf_*`) are auto-injected only
  when the mesh topology is `NodeWaypoint`. They are not on any of the five
  bundled dashboards yet — pull from
  `src/plugins/mesh/bpf_metrics.rs` if you need a node-waypoint-specific
  view.
