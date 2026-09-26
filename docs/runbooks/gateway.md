# Core Gateway Alert Runbook

First-response procedures for every alert shipped by
[`charts/ferrum-gateway/templates/metrics-prometheusrule.yaml`](../../charts/ferrum-gateway/templates/metrics-prometheusrule.yaml).
Each alert's `runbook_url` annotation points at its section below; the base URL
is `metrics.alerts.runbookBaseUrl` in
[`charts/ferrum-gateway/values.yaml`](../../charts/ferrum-gateway/values.yaml),
so a fork or internal mirror can repoint every link at once.

Sections appear in the order the alerts appear in the PrometheusRule.

## Admin endpoints used by this runbook

Ferrum's observability surfaces are tiered by default (see
[admin_metrics.md](../admin_metrics.md)). "Credentialed" below means a valid
admin JWT, a matching `FERRUM_METRICS_BEARER_TOKEN`, **or** a source IP inside
`FERRUM_METRICS_ALLOWED_CIDRS`.

| Endpoint | Credential | What it gives you |
|----------|-----------|-------------------|
| `GET /live` | none | Liveness only: `{"status":"ok"}`. Proves the process is up and the admin listener is accepting. |
| `GET /health` | none → `status` + `ready` only; credentialed → full diagnostics | Credentialed: DB type/pool stats, `database_polling`, `config_rejected`, mesh state, sanitized listener failures, `jwks_trust`. |
| `GET /status` | same tiering as `/health` | Same coarse/detailed split. |
| `GET /overload` | none → `{level}` only; credentialed → full snapshot | Shedding `actions`, active connections/requests, per-resource `current`/`max` under `pressure`, `red_drop_probability_pct`, `draining`. |
| `GET /metrics` | credentialed (401 otherwise) | Prometheus exposition. Requires one globally scoped `prometheus_metrics` plugin for the request/latency families. |
| `GET /metrics/runtime` | admin JWT | Cached JSON runtime snapshot. |
| `GET /backend-capabilities` | admin JWT | Negotiated upstream protocol capabilities per destination. |
| `GET /cluster` | admin JWT | CP: connected data planes. DP: control-plane connection state. |

Throughout, `$ADMIN` is the admin base URL and `$TOKEN` a metrics bearer token
or admin JWT:

```bash
curl -fsS -H "Authorization: Bearer $TOKEN" "$ADMIN/health" | jq .
```

## FerrumGatewayHigh5xxRate

**Symptom.** `sum(rate(ferrum_requests_total{status_code=~"5.."}[5m]))` exceeds
`metrics.alerts.high5xxRatePerSecond` for 5 minutes. Clients are receiving
server errors.

**First checks.**

1. `GET /metrics` — break the rate down by `proxy_id` and `status_code`:
   `sum by (proxy_id, status_code) (rate(ferrum_requests_total{status_code=~"5.."}[5m]))`.
   One proxy means a single route or upstream; all proxies means a gateway-wide
   cause.
2. `GET /overload` — a non-zero `level` or an active shedding action means the
   5xx are 503s Ferrum is generating deliberately. Go to
   [FerrumGatewayOverloadSheddingActive](#ferrumgatewayoverloadsheddingactive).
3. `GET /health` (credentialed) — `config_rejected: true` means the gateway is
   serving an older configuration than the source of truth.
4. `ferrum_circuit_breakers{state="open"}` and
   `ferrum_upstream_unhealthy_targets` — an open breaker returns 503 without
   contacting the upstream.

**Likely causes.** Upstream outage or upstream 5xx passed through; all
load-balancer targets ejected by health checks; an open circuit breaker;
overload shedding; a plugin returning an error on the request path (auth
provider unreachable, rate-limit backend down); backend TLS/mTLS failure after
a certificate rotation.

**Remediation.** If the errors originate upstream, fix or drain the upstream —
Ferrum is reporting accurately. If Ferrum is generating them, treat the more
specific alert (overload, breaker, upstream health) as the primary and work
that section. If a plugin dependency is the cause, restore that dependency or
temporarily disable the plugin instance through the admin API in `database`/`cp`
mode.

**Escalation.** Page the owning service team when the 5xx are upstream-origin.
Page the gateway on-call when `ferrum_requests_total` shows 5xx with no
corresponding upstream errors and no overload signal.

## FerrumGatewayHighP99Latency

**Symptom.** P99 of `ferrum_request_duration_ms` exceeds
`metrics.alerts.p99LatencyMs` for 5 minutes.

**First checks.**

1. Compare `ferrum_request_duration_ms` (total) against
   `ferrum_backend_duration_ms` (upstream) and `ferrum_edge_overhead_ms`
   (Ferrum's own cost). If backend duration tracks total, the upstream is slow
   and the gateway is fine.
2. `GET /overload` (credentialed) — `pressure.event_loop_latency_us` and the
   per-resource `current`/`max` pairs under `pressure` show whether the runtime
   itself is saturated (metric: `ferrum_overload_event_loop_latency_seconds`).
3. `ferrum_connection_pool_entries` versus
   `ferrum_connection_pool_max_idle_per_host` — pool churn adds a connect
   handshake to requests that should have reused a connection.
4. `GET /backend-capabilities` — an unexpected protocol downgrade (HTTP/2 to
   HTTP/1.1) removes multiplexing and raises tail latency.

**Likely causes.** Slow upstream; connection-pool thrash or an undersized idle
pool; DNS resolution latency on upstream hostnames; event-loop saturation under
overload; a synchronous plugin (external authorization, remote rate limiting)
on the hot path.

**Remediation.** Scale or fix the upstream when backend duration dominates.
When gateway overhead dominates, raise `FERRUM_POOL_MAX_IDLE_PER_HOST` (a
global setting), verify DNS caching, and check for CPU throttling on the pod. If a
remote-dependency plugin dominates, lower its timeout so it fails fast rather
than holding requests.

**Escalation.** Page the upstream owner when `ferrum_backend_duration_ms`
accounts for the regression; otherwise page the gateway on-call.

## FerrumGatewayOverloadSheddingActive

**Symptom.** `ferrum_overload_shedding_active` is `1` for some `action` for 5
minutes. Ferrum is deliberately rejecting or degrading traffic to protect
itself.

**First checks.**

1. `GET /overload` (credentialed) — the full snapshot names the `level`, the
   active `actions`, `draining`, `red_drop_probability_pct`, and every resource
   under `pressure` with its `current` and `max`.
2. `ferrum_overload_resource_current / ferrum_overload_resource_limit` per
   `resource` identifies which budget is exhausted (connections, requests,
   memory, file descriptors, ports).
3. `ferrum_overload_active_connections` and `ferrum_overload_active_requests` —
   compare against configured caps.
4. `ferrum_overload_draining == 1` means this is a graceful shutdown, not an
   overload. Expected during a rolling restart.

**Likely causes.** Genuine traffic surge; a resource limit set too low for the
pod's actual capacity; a connection leak from slow or stuck clients; file
descriptor exhaustion; ephemeral port exhaustion toward a single upstream; a
rolling restart draining connections.

**Remediation.** Confirm `draining` first — if it is `1`, the alert is
expected and will clear. Otherwise scale out replicas, or raise the specific
exhausted limit if the pod has headroom. For port exhaustion, check
`ferrum_overload_port_exhaustion_events_total` and increase connection reuse
(`FERRUM_POOL_MAX_IDLE_PER_HOST`) rather than raising the limit. See
[overload_manager.md](../overload_manager.md) for the full threshold model.

**Escalation.** Page capacity/on-call when shedding persists after scaling out,
or when a single resource repeatedly saturates at a limit the pod should be
able to exceed.

## FerrumGatewayUpstreamMajorityUnhealthy

**Symptom.**
`ferrum_upstream_unhealthy_targets / ferrum_upstream_targets` exceeds
`metrics.alerts.upstreamUnhealthyRatio` for one upstream for 5 minutes. Active
health probes have ejected most of that upstream's targets.

**First checks.**

1. `GET /health` (credentialed) — the health-check block reports per-upstream
   probe state.
2. `ferrum_upstream_targets` — if the denominator dropped rather than the
   numerator rising, targets were removed from configuration or service
   discovery, not ejected.
3. Probe the upstream directly from a gateway pod using the same path, method,
   and expected status the health check is configured with. A health check that
   probes a path the upstream does not serve ejects healthy targets.
4. `GET /backend-capabilities` — a TLS or ALPN failure toward the upstream
   shows up as a capability negotiation failure.

**Likely causes.** Real upstream outage; a health-check path/status/timeout
mismatch after an upstream deployment; backend mTLS certificate expiry or a
rotated CA; DNS returning stale or wrong addresses; a NetworkPolicy or
security-group change blocking probe traffic.

**Remediation.** If the upstream is genuinely down, fail over or drain. If the
probe configuration is wrong, correct the health-check path/expected status —
do not disable health checking to clear the alert. For mTLS, check
`ferrum_tls_cert_expiry_seconds` for the backend surface and see
[backend_mtls.md](../backend_mtls.md).

**Escalation.** Page the upstream owner. Page the gateway on-call if probes
fail from the gateway but the upstream answers identical requests from
elsewhere in the same network.

## FerrumGatewayCircuitBreakerOpen

**Symptom.** `ferrum_circuit_breakers{state="open"} > 0` for one proxy for 5
minutes. Requests to that upstream are being rejected without being sent.

**First checks.**

1. `GET /metrics` — `ferrum_circuit_breakers` by `proxy_id`, `proxy_namespace`,
   and `state` shows which breakers are open, half-open, or closed.
2. Correlate with [FerrumGatewayUpstreamMajorityUnhealthy](#ferrumgatewayupstreammajorityunhealthy):
   a breaker usually opens because the same upstream is failing.
3. `ferrum_backend_duration_ms` — breakers also open on timeouts, not only on
   error responses.
4. `ferrum_circuit_breaker_cache_entries` versus
   `ferrum_circuit_breaker_cache_max_entries` — a saturated cache means breaker
   state is being evicted and re-learned.

**Likely causes.** Sustained upstream errors or timeouts; a breaker threshold
tuned too tightly for a naturally bursty upstream; an upstream deploy causing a
short error spike that opened the breaker and has not yet half-opened.

**Remediation.** Fix the upstream. The breaker closes on its own after the
half-open probe succeeds — do not restart the gateway to "clear" it, which
discards breaker state across every destination. If the threshold is wrong for
this upstream, retune it in the destination configuration.

**Escalation.** Page the upstream owner. Escalate to the gateway on-call only
if breakers open while the upstream demonstrably answers successfully.

## FerrumGatewayFrontendTlsHandshakeErrors

**Symptom.** `ferrum_frontend_tls_handshake_failures_total{reason="error"}`
exceeds `metrics.alerts.frontendTlsHandshakeErrorsPerSecond` for 10 minutes.
This alert renders only when that threshold is non-zero, because `reason=error`
is the catch-all rustls accept failure and is never zero on an internet-facing
listener.

**First checks.**

1. `GET /metrics` — break the failures down by `reason`. `error` is the
   catch-all; other reasons are more specific and more actionable.
2. `ferrum_tls_cert_expiry_seconds` for `surface="frontend"` — an expired or
   not-yet-valid leaf fails every handshake.
3. `ferrum_tls_cert_rotations_total` by `outcome` — a failed rotation can leave
   a listener serving a stale or broken chain.
4. `ferrum_tls_source_fetch_failures_total` — the certificate source (file,
   Kubernetes Secret, HSM, cloud secret) may be unreachable.

**Likely causes.** Plain HTTP sent to a TLS port; scanners and probes; clients
with no overlapping cipher suite or TLS version; an expired or mis-chained
certificate; a failed certificate rotation; SNI that matches no configured
certificate; mutual TLS required but the client sent no certificate.

**Remediation.** Distinguish noise from a real regression by checking whether
the rate coincides with a deploy or rotation. If it does, inspect the served
chain with `openssl s_client -connect host:port -servername name`. If it does
not, and the rate matches background scanning, raise the threshold to a level
abnormal for your exposure. See [frontend_tls.md](../frontend_tls.md).

**Escalation.** Page the gateway on-call when the rate steps up at a deploy or
rotation boundary, or when legitimate clients report handshake failures.

## FerrumGatewayTlsCertExpiringSoon

**Symptom.** `ferrum_tls_cert_expiry_seconds` for some certificate is below
`metrics.alerts.certExpiringSeconds` (default 7 days) for 15 minutes.

**First checks.**

1. `GET /metrics` — the `cert_id`, `surface`, and `source_kind` labels identify
   exactly which certificate and which listener surface.
2. `ferrum_tls_inventory_snapshot_timestamp_seconds` versus
   `ferrum_tls_inventory_snapshot_max_age_seconds` — confirm the inventory is
   fresh, so you are not alerting on a stale snapshot.
3. `ferrum_tls_cert_rotations_total{outcome=...}` and
   `ferrum_tls_source_refresh_total` — check whether automatic rotation has
   been attempting and failing.

**Remediation.** Renew and publish the certificate through its configured
source. Ferrum reloads certificates from watched sources without a restart; a
restart is not the remedy and does not renew anything. Verify the alert clears
after the source is updated — if the gauge does not move, the watcher is not
seeing the new material (check `ferrum_tls_source_fetch_failures_total`).

**Escalation.** Page the PKI/certificate owner immediately when the remaining
lifetime is under 24 hours, or when rotation is failing.

## FerrumGatewayRevocationMaterialExpiringSoon

**Symptom.** `ferrum_tls_revocation_expiry_seconds` for some CRL or stapled
OCSP response is below `metrics.alerts.revocationExpiringSeconds` (default 7
days) for 15 minutes. The gauge counts down to the material's `nextUpdate`;
a negative value means it has already expired.

**Why it pages.** Ferrum refuses expired revocation material at reload **and
at startup**. A gateway that is still serving keeps its last good material,
but any pod that restarts after `nextUpdate` will not come back until fresh
material is published. This alert is the advance notice before that
restart-blocking outage.

**First checks.**

1. `GET /metrics` — the `material_id`, `kind` (`crl` or `ocsp`), and
   `source_kind` labels identify exactly which file or staple is aging out and
   where it is loaded from.
2. `ferrum_tls_inventory_snapshot_timestamp_seconds` versus
   `ferrum_tls_inventory_snapshot_max_age_seconds` — confirm the inventory is
   fresh, so you are not alerting on a stale snapshot.
3. The gateway log — the same condition is logged at startup and on every
   reload once the remaining lifetime is under
   `FERRUM_TLS_CRL_EXPIRY_WARNING_DAYS` (default 30 days). For a stapled OCSP
   response the warning also re-fires on the hourly staple re-check, so it
   recurs without a reload.

**Remediation.** Publish a freshly issued CRL (or a new stapled OCSP
response) through the configured source; Ferrum reloads revocation material
from watched sources without a restart. Note that a stapled OCSP response that
reaches its `nextUpdate` is **dropped** by the hourly re-check — the listener
then serves no staple, which is the safer state but leaves a must-staple
certificate unusable until a fresh response is published. Do **not** restart the gateway as a
remedy — if the material has already expired, the restart is exactly the
outage this alert warns about. Verify the gauge moves after the source is
updated; if it does not, the watcher is not seeing the new material.

**Escalation.** Page the PKI/CRL-issuing owner immediately when the remaining
lifetime is under 24 hours, or when the issuer has stopped publishing.

## FerrumGatewayDatabaseUnavailable

**Symptom.** `ferrum_database_config_source_connected == 0` for 5 minutes in
`database` or `cp` mode. The configuration source is unreachable or unusable.

This alert is **critical** because it is silent from the client's point of
view: the gateway keeps serving the last known-good configuration, so traffic
looks healthy while routing rules, consumer credentials, and plugin
configuration freeze and drift away from the source of truth. Admin writes are
rejected for the duration.

**First checks.**

1. `GET /health` (credentialed) — `database.available` mirrors this gauge
   exactly (they are the same in-process flag), and the block also carries the
   DB type and pool statistics.
2. `ferrum_database_poll_failures_total{reason}` — the reason tells you what
   kind of failure this is:
   - `connectivity` — the backend cannot be reached, or a reload against a
     reachable backend failed for an unclassifiable reason.
   - `validation_rejected` — the backend is **reachable** and served a snapshot
     the runtime-config validation contract rejected. This is a bad
     configuration mutation, not an outage; admin writes stay enabled so it can
     be repaired in band.
   - `migration_gate` — deferred core or custom-plugin migrations are blocking
     recovery, so a loaded configuration cannot be published.
3. `GET /health` `config_rejected` — `true` alongside `validation_rejected`
   confirms the invalid-snapshot reading.
4. `ferrum_database_poll_last_completed_timestamp_seconds` — if this is still
   advancing, the poll task is alive and this is a genuine backend problem, not
   a wedged poller. If it has stopped, work
   [FerrumGatewayDatabasePollStale](#ferrumgatewaydatabasepollstale) as well.
5. Pod logs — every failure path logs a `warn!`/`error!` with the backend error.

**Likely causes.** Database down, failed over, or out of connections; network
policy or security-group change; credential rotation invalidating the
configured `FERRUM_DB_URL`; DNS change on the database hostname with a stale
pool; TLS expiry on the database connection; an invalid configuration mutation
(`validation_rejected`); pending migrations after an offline bootstrap
(`migration_gate`).

**Remediation.** Restore database reachability, then confirm the gauge returns
to `1` and admin writes are accepted again — the poll loop recovers on its own
and needs no gateway restart. For `validation_rejected`, find and repair the
offending resource through the admin API (writes remain enabled precisely for
this). For `migration_gate`, apply the pending migrations (`ferrum-edge run
--mode migrate` with `FERRUM_MIGRATE_ACTION=up`, or
`FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS` for custom plugin schema).

**Do not** restart the gateway to "reconnect": a restart risks losing the
last known-good configuration if the database is still unreachable at startup,
which converts a silent-but-serving outage into a serving outage.

**Escalation.** Page the database owner immediately. Page the gateway on-call
in parallel, because configuration is frozen for the whole fleet reading this
source.

## FerrumGatewayDatabasePollStale

**Symptom.** `time() - ferrum_database_poll_last_completed_timestamp_seconds`
exceeds `metrics.alerts.databasePollStaleSeconds` (default 300) for 10 minutes,
or the series is absent.

**This alert detects poll-task death, not a database outage.** The freshness
gauge advances on every *normally completed* poll tick — success, empty result,
validation rejection, **and handled error** — so a database that is completely
unreachable still advances it every poll interval. Use
[FerrumGatewayDatabaseUnavailable](#ferrumgatewaydatabaseunavailable) for
outages. This alert firing means the supervised poll task itself panicked, was
aborted or cancelled, or is wedged inside a tick.

**First checks.**

1. `GET /health` (credentialed) — `database_polling.last_poll_completed_at` is
   the same timestamp in RFC3339 form. In `cp` mode an unexpected poll-task
   exit also flips sticky `serving_degraded`, so `/health` returns 503 with
   `status: "unavailable"` and `ready: false`.
2. Pod logs — look for a panic backtrace or an abort from the poll task at
   roughly `last_poll_completed_at`.
3. If the series is **absent**, check that the gateway is actually in
   `database` or `cp` mode and that a globally scoped `prometheus_metrics`
   plugin is enabled — the family is conditional on the delta-poll registry
   being installed.
4. `ferrum_database_config_source_connected` — `1` here plus this alert firing
   is the clean "task died while the database is fine" signature.

**Likely causes.** Poll-task panic; a backend call with no timeout wedged
inside a tick; a database driver deadlock; in `database` mode, repeated
respawn-and-die.

**Remediation.** In `database` mode the poll task is respawned after an
unexpected exit while last-known-good configuration continues to serve; check
whether the timestamp resumes advancing. In `cp` mode the process marks itself
degraded and should be restarted (it is no longer distributing fresh
configuration to data planes). Capture the panic backtrace before restarting —
a wedged tick with no panic is a bug worth filing with the backend type and the
last log lines.

**Escalation.** Page the gateway on-call. This is a Ferrum-side fault, not a
database fault.

## FerrumGatewayDpConfigStale

**Symptom.** `ferrum_dp_config_stale == 1` for 5 minutes. A data plane is
serving with a configuration snapshot older than its staleness budget.

**First checks.**

1. `GET /cluster` on the DP (admin JWT) — reports the control-plane connection
   state. On the CP, the same endpoint lists connected data planes; a DP
   missing there confirms the connection is down.
2. `ferrum_dp_config_cp_connected` — `0` means the gRPC stream to the control
   plane is down.
3. `ferrum_dp_config_snapshot_age_seconds` versus
   `ferrum_dp_config_max_stale_seconds` — how far past the budget you are.
4. `ferrum_dp_config_new_traffic_blocked` — `1` means the staleness policy has
   started refusing new traffic, which is a client-visible impact.
5. `ferrum_dp_config_snapshots_rejected_total` and
   `ferrum_dp_config_snapshot_apply_failures_total` — the DP may be *connected*
   and rejecting what the CP sends. If so, go to
   [FerrumGatewayConfigSyncDiverged](#ferrumgatewayconfigsyncdiverged).

**Likely causes.** CP unreachable from the DP (network, DNS, NetworkPolicy);
`FERRUM_CP_DP_GRPC_JWT_SECRET` mismatch or an expired token; CP gRPC TLS
certificate expiry; every configured CP in `FERRUM_DP_CP_GRPC_URLS` down; the
CP itself unable to read its database (check
[FerrumGatewayDatabaseUnavailable](#ferrumgatewaydatabaseunavailable) on the
CP); snapshots arriving but failing to apply.

**Remediation.** Restore CP reachability and confirm
`ferrum_dp_config_snapshot_age_seconds` falls back under the budget. The DP
recovers without a restart once the stream re-establishes and a snapshot
applies. If apply failures are the cause, the CP is publishing a configuration
this DP cannot accept — treat it as a divergence.

**Escalation.** Page the control-plane owner. Page the gateway on-call when
`ferrum_dp_config_new_traffic_blocked` is `1`, because that is client-visible.

## FerrumGatewayConfigSyncDiverged

**Symptom.** `ferrum_configsync_diverged == 1` for 5 minutes. The data plane is
sticky-diverged after rejecting a ConfigSync delta and will not accept further
deltas until a fenced full snapshot reconciles it.

**First checks.**

1. `ferrum_configsync_delta_rejections_total` — how many deltas were rejected
   and when the divergence started.
2. `ferrum_configsync_fenced_full_snapshots_total` — whether the CP has already
   attempted the full-snapshot reconciliation that clears divergence.
3. `ferrum_configsync_divergence_recoveries_total` — whether previous
   divergences recovered on their own.
4. `GET /health` (credentialed) on the DP — `config_rejected` and the cached
   configuration counts show what the DP is actually serving.
5. `GET /cluster` on the CP — confirm the DP is still connected. Divergence
   with a live connection is the expected shape.
6. CP logs around the first rejection — they name the rejected resource
   category and validation category.

**Likely causes.** A configuration mutation that is valid at the CP but invalid
under the DP's local validation (for example a plugin the DP build does not
have, or a TLS reference the DP cannot resolve); a version skew between CP and
DP images; a delta applied against a snapshot the DP had already fenced.

**Remediation.** Divergence is designed to be safe: the DP keeps serving its
last known-good configuration rather than applying a bad delta. Identify the
rejected resource from the CP logs and repair it at the source, then let the CP
issue a fenced full snapshot. If the cause is CP/DP version skew, align the
images — a DP older than the configuration it is being sent will keep
diverging.

**Escalation.** Page the control-plane owner. Escalate to the gateway on-call
if a fenced full snapshot is issued and the DP still refuses it, which points
at a validation bug rather than a bad configuration.

## Related documents

- [prometheus_metrics.md](../prometheus_metrics.md) — the full metric contract,
  including every family referenced above.
- [admin_metrics.md](../admin_metrics.md) — admin endpoint authentication
  tiering and the `/metrics` surface.
- [overload_manager.md](../overload_manager.md) — overload thresholds and
  shedding actions.
- [kubernetes_deployment.md](../kubernetes_deployment.md) — chart values,
  including `metrics.alerts` and `metrics.dashboards`.
- [mesh_multicluster_federation_runbook.md](../mesh_multicluster_federation_runbook.md)
  — the mesh-side counterpart to this document.
