# ferrum-gateway Helm chart

Deploys the Ferrum Edge binary in one of the **core gateway** operating modes.
For the service-mesh components (mesh data plane, injector webhook, ambient
node-agent, mesh CA) use the sibling [`ferrum-mesh`](../ferrum-mesh) chart
instead — the two charts share naming, labelling, secret, and validation
conventions so they feel like one product.

| Mode | `mode` value | Proxy | Admin | Extra config |
|------|--------------|-------|-------|--------------|
| Database | `database` | yes | read/write | `database.*`, `admin.jwtSecret` (>=32) |
| File | `file` | yes | read-only | `file.inlineConfig` or `file.existingConfigMap` |
| Control plane | `cp` | no | read/write | `database.*`, `admin.jwtSecret`, `grpc.jwtSecret` (>=32) or `cp.trustBundlePath` |
| Data plane | `dp` | yes | read-only | `dp.cpGrpcUrls`, `admin.jwtSecret`, `grpc.jwtSecret` (>=32) or `dp.cpGrpcTokenFile` |

### Multi-tenant control planes

`grpc.jwtSecret` is a *fleet* secret: it is distributed to the very data planes
it would authorize, so a compromised tenant can re-sign the JWT `ns` claim and
read another tenant's configuration (advisory GHSA-3f2j-wwqw-grmg). A control
plane serving more than one namespace therefore requires
`cp.trustBundlePath` — a mounted JSON bundle of namespace-bound verification
credentials — and the chart fails render without it. Data planes then present
either an externally issued token (`dp.cpGrpcTokenFile`, no signing key on the
node) or a per-tenant secret selected by `grpc.jwtKeyId`. See
[docs/cp_namespace_tenancy.md](../../docs/cp_namespace_tenancy.md).

The `mode` value is first-class and required. `mesh` / `injector` / `node_agent`
fail at template time with a pointer to [`ferrum-mesh`](../ferrum-mesh).
`migrate` is **not** deployed by either chart — it fails with a pointer to the
external pre-deploy Job examples under
[`examples/migrate-job-*.yaml`](examples/) (see
[docs/kubernetes_deployment.md](../../docs/kubernetes_deployment.md#explicit-migrate-mode-external-job)).
Normal `database` / `cp` startup still auto-applies pending core schema
migrations; use the explicit Job for `status`, dry-run, and operator-controlled
`up` / `config` workflows.

## Security defaults you should know

- **Secrets are never generated or rendered into ConfigMaps.** Admin JWT, DB
  URL, and CP/DP gRPC JWT material come from inline values (dev only) or Secret
  references you own. The chart validates that database, cp, and dp modes have
  a `>=32`-char admin JWT secret, and that cp/dp modes have a `>=32`-char gRPC
  JWT secret, before it will render. Required DB/JWT values may instead come
  from matching `secretFileMounts` entries and Ferrum's `_FILE` resolver.
- **Admin binds to loopback by default.** Probes use the in-pod exec
  `ferrum-edge health` check, which works with the loopback default (a kubelet
  `httpGet` targets the pod IP and would miss a loopback listener). To expose
  admin through a Service set `admin.bindAddress=0.0.0.0` **and**
  `admin.service.enabled=true`. In the write-capable `database`/`cp` modes the
  binary hard-fails on a non-loopback **plaintext** admin bind unless you also
  set one of `admin.allowedCidrs`, admin TLS (`tls.admin` or a complete
  `FERRUM_ADMIN_TLS_{CERT,KEY}_SOURCE` pair, with `ports.adminHttp=0`), or
  `admin.allowInsecureHttp=true` with `networkPolicy.enabled=true`; TLS on 9443 does not protect a still-live
  plaintext listener on 9000. Any allowlist that covers a whole address family
  is rejected as ineffective protection, including `/0`, mapped IPv6 `/96`
  spellings that canonicalize to IPv4 `/0`, and full-coverage CIDR unions.
  Every entry is strictly validated so a typo fails at render instead of
  crash-looping the pod. If computed exec probes are enabled,
  `admin.allowedCidrs` must contain source `127.0.0.1` (for example
  `127.0.0.0/8`, `127.0.0.1/32`, or the bare IP)
  because the admin TCP filter does not special-case loopback. An IPv6 wildcard
  or loopback bind (`::` or `::1`) shifts probes to `--host ::1` and requires an
  entry containing `::1` (such as `::/127`, `::1/128`, or bare `::1`) — an
  unspecified IPv6 bind is not guaranteed to accept v4-mapped `127.0.0.1`.
  A concrete IPv6 bind is dialed directly and its concrete source must be allowed.
  IPv6 allowlist entries use bare address syntax (`fd00::/8`, `::1/128`), not
  URL-style brackets (`[fd00::]/8`), matching the runtime's strict CIDR parser.
  `admin.bindAddress` must be an IP literal — any hostname (`localhost`,
  `admin.internal`, ...) or malformed IPv6 literal is rejected at render (the
  binary requires an IP); use `127.0.0.1` or `::1`.
- **Probes and admin HTTPS.** When `ports.adminHttp=0` the computed exec probes
  auto-switch to `ferrum-edge health --tls` against admin HTTPS (`:9443`), which
  only serves when admin TLS material is configured. The chart therefore requires
  `tls.admin.enabled` + `tls.admin.secretName` or a complete
  `FERRUM_ADMIN_TLS_{CERT,KEY}_SOURCE` pair in that combination (or that you
  override/disable the computed probes). Disabling **both** admin ports
  (`ports.adminHttp=0` and `ports.adminHttps=0`) leaves no admin listener for the
  computed probes and is rejected unless every computed probe is overridden. Admin
  **mTLS** (`tls.admin.clientCaKey` or
  `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_SOURCE`) makes the admin HTTPS listener
  demand a client cert the exec probes cannot present, so with
  `ports.adminHttp=0` the chart requires you to override/disable the computed
  probes or keep a plaintext loopback admin listener.
- **Admin Service needs a publishable port.** With `admin.service.enabled=true`
  the chart fails render if no admin Service port is available — a plaintext admin
  port (`ports.adminHttp>0`) or admin HTTPS (`ports.adminHttps>0` with a
  `tls.admin` Secret or complete admin cert/key SOURCE pair) — rather than ship
  a portless Service the API server rejects.
- **CP/DP gRPC transport.** The binary rejects a non-loopback **plaintext** CP
  gRPC bind (`cp` mode, default `cp.grpcBindAddress=0.0.0.0`) and a non-loopback
  `http://` CP URL (`dp` mode) unless gRPC TLS is configured or you set
  `grpc.allowPlaintext=true` (renders `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT`). The
  chart mirrors that guard at render. CP server TLS may come from `tls.cpGrpc`
  or a complete `FERRUM_CP_GRPC_TLS_{CERT,KEY}_SOURCE` pair. Prefer TLS plus
  `tls.dpGrpc` trust pinning for production; the dev opt-in flows through the
  first-class `grpc.allowPlaintext`.
  IPv6 CP binds are bracketed automatically (`::` → `[::]:50051`). A loopback CP
  Both bare and balanced bracketed IPv6 are accepted; malformed literals and
  mismatched brackets fail at render. A loopback CP bind is unreachable through
  `cp.service`, so the chart requires
  `cp.service.enabled=false` with it; `ports.cpGrpc=0` disables the CP gRPC
  listener (the gRPC container port and CP Service are omitted). `cp.grpcBindAddress`
  must be an IP literal — the runtime parses `FERRUM_CP_GRPC_LISTEN_ADDR` as an
  IP:port socket address and rejects hostnames like `localhost` at boot, so the
  chart rejects non-IP binds at render. DP CP URLs are validated for both scheme
  (http/https/grpc/grpcs) and a non-empty host, so typos and host-less values (e.g.
  `https://`) fail at render, not at boot.
- **Chart-managed env is protected.** Every `FERRUM_*` var the chart renders from
  first-class values (mode, DB, JWTs, ports, bind address, allowlist, TLS paths,
  shutdown drain, DP URLs, gRPC plaintext opt-in, K8s controller/pod-discovery
  switches, ...) is reserved: setting it through `env` or `extraEnv` fails
  render, so the process can never drift from the rendered probes/Services/ports.
  Their external-secret resolver suffixes
  (`_VAULT`/`_AWS`/`_AZURE`/`_GCP`/`_FILE`) are reserved too — a suffixed source
  of a managed base var (e.g. `FERRUM_ADMIN_JWT_SECRET_VAULT`) resolves into that
  base var and would collide with the chart's own source, aborting startup with
  "Multiple secret sources configured". Generated `<name>_FILE` vars from
  `secretFileMounts` are reserved as well, and so are their base names, so
  `env`/`extraEnv` cannot shadow a file source or configure both `<name>` and
  `<name>_FILE` (which Ferrum rejects as conflicting providers). A mount may
  replace a chart-managed base only for the first-class DB/JWT file sources
  (`FERRUM_DB_URL`, `FERRUM_ADMIN_JWT_SECRET`, and
  `FERRUM_CP_DP_GRPC_JWT_SECRET`); other managed names such as `FERRUM_MODE`
  are rejected because the chart renders their direct value too.
- **Kubernetes CRD controller is off.** `k8sController.enabled` defaults to
  `false`. `mode=cp` renders `FERRUM_K8S_CONTROLLER_ENABLED=false` and
  `FERRUM_K8S_POD_DISCOVERY_ENABLED=false` so the in-cluster binary default
  cannot start un-granted core watches (issue #4384). Setting
  `k8sController.enabled=true` fails render; use
  [`ferrum-mesh`](../ferrum-mesh) instead.
- **TLS and `_FILE` Secret mounts are non-root readable.** They default to mode
  `0440` with pod `fsGroup: 65532`, matching the distroless nonroot image. Both
  `secretVolumeDefaultMode` and `podSecurityContext` are overridable for images
  with a different runtime identity.
- **Graceful shutdown** wires `terminationGracePeriodSeconds` to the WHOLE
  termination sequence (enforced at render): `preStop + preDrain + shutdown
  budget`, where the shutdown budget sums in-flight drain, transport pool tail
  (6s), background join (5s), audit flush `clamp(drain, 5, 60)` (database/cp),
  observability delivery (2s default), and 5s finalizer slack. With default
  `shutdownDrainSeconds: 30` that budget is `30 + 6 + 5 + 30 + 2 + 5 = 78s`,
  and the default 30s `preStop` window brings the minimum grace to `108s`; the
  chart defaults to `110s`. See `docs/graceful_shutdown.md`.
  `shutdownDrainSeconds: 0` is a valid "skip draining" value and is rendered
  explicitly; set it to `null` to omit the env and fall back to the binary's
  30s default. A `null` drain is still validated against that 30s default, so
  a grace period below the computed minimum fails render rather than letting
  Kubernetes SIGKILL the pod mid-flush.
- **Rolling upgrades do not refuse new connections.** See
  [Termination and rolling upgrades](#termination-and-rolling-upgrades) below.

## Termination and rolling upgrades

Kubernetes removes a terminating pod from its Service endpoints *concurrently
with* stopping it, and that removal has to propagate through the EndpointSlice
controller to every node's kube-proxy. A gateway that closes its accept loops
the instant SIGTERM lands therefore refuses new connections at a pod that is
still a live Endpoint. The chart closes that window from both sides:

1. `shutdownPreStopSeconds` (default `30`) renders a native
   `lifecycle.preStop.sleep` (`SleepAction`). Kubernetes runs `preStop`
   **before** SIGTERM, so the gateway keeps serving normally for the whole
   window while endpoint removal propagates. `SleepAction` needs no shell, so
   it works on the distroless image; it requires Kubernetes **1.29+** (GA in
   1.30). Set it to `0` on older clusters to omit the hook. With
   `shutdownPreStopSeconds > 0`, `helm template` / `helm install` **fail** on
   clusters older than 1.29 with a remediation message instead of silently
   dropping the unsupported `sleep` field.
2. `shutdownPreDrainSeconds` (default `0`, `FERRUM_SHUTDOWN_PREDRAIN_SECONDS`)
   keeps every listener — proxy **and** admin — accepting for a window *after*
   SIGTERM while readiness already reports `ready:false` / 503 and `/live` still
   returns 200. Redundant with `preStop` on 1.29+, so it is off by default;
   raise it on clusters without `SleepAction` or when an external load balancer
   polls `/health` directly.
3. Readiness is drain-aware in the binary: as soon as termination begins,
   `/health` and `/status` report `{"status":"draining","ready":false}` with
   HTTP 503, while `/live` deliberately keeps returning 200 so kubelet does not
   SIGKILL the pod mid-drain.
4. `probes.readiness.failureThreshold` (default `3`) is rendered explicitly
   rather than inherited, because `failureThreshold x periodSeconds` is the
   probe-driven endpoint-removal latency the `preStop` default is derived from.

### Grace-period arithmetic

`terminationGracePeriodSeconds` is measured from pod deletion, so the `preStop`
sleep is billed to it. The chart fails render unless:

```
terminationGracePeriodSeconds >= shutdownPreStopSeconds
                               + shutdownPreDrainSeconds
                               + post-SIGTERM shutdown budget
```

The post-SIGTERM budget is more than `shutdownDrainSeconds`: after the in-flight
drain the binary still releases transport pools, joins background tasks, flushes
the admin audit spool (`database`/`cp`), drains observability delivery, and
finalizes plugin generations — roughly **78s** at the defaults. See
[docs/graceful_shutdown.md](../../docs/graceful_shutdown.md). The chart default
of `110` covers the full sequence plus the 30s `preStop` window.

## Probes

Liveness and startup run `ferrum-edge health --live` (GET `/live`), which
returns 200 whenever the process and admin listener are up — even during
startup or while serving degraded. Readiness runs `ferrum-edge health` (GET
`/health`), which returns 503 until the gateway is ready. Keeping them distinct
means an alive-but-unready pod (e.g. a `dp` that has lost its `cp`) is dropped
from Service endpoints **without** being restart-looped by liveness — never
point liveness at `/health`. The defaults use the exec `ferrum-edge health`
command and auto-switch to the TLS variant when `ports.adminHttp=0`.

The exec probes dial the admin listener at its configured bind address, because
the runtime binds admin ONLY to `admin.bindAddress`. Wildcard binds probe
loopback (`0.0.0.0`→`127.0.0.1`, `::`→`::1`); a concrete bind is probed as-is
(`::1`, `10.0.0.5`, ...). If you also set `admin.allowedCidrs`, it must cover
the TCP source observed by the listener or the admin allowlist drops the in-pod
checks. That source normally equals the dial address, except Linux connections
to any concrete `127/8` bind (for example `127.0.0.2`) originate from
`127.0.0.1`; use `127.0.0.1/32` or a covering `127.0.0.0/8`. The chart fails
render otherwise.

Liveness and readiness have **separate** override knobs so a custom handler
cannot silently re-couple them. Replace only one probe's computed handler with
`probes.liveness.override` or `probes.readiness.override` (e.g. an `httpGet`
when admin is bound non-loopback); the startup probe reuses the liveness
handler.

## Quickstart per mode

### Database mode (PostgreSQL)

```bash
kubectl -n ferrum create secret generic ferrum-gateway-db \
  --from-literal=url='postgres://ferrum:<percent-encoded-pw>@postgres.ferrum.svc:5432/ferrum'
kubectl -n ferrum create secret generic ferrum-gateway-credentials \
  --from-literal=admin-jwt-secret="$(openssl rand -hex 32)"

helm install ferrum ./charts/ferrum-gateway -n ferrum \
  -f charts/ferrum-gateway/examples/database-values.yaml
```

### File mode (inline config, no Secrets)

```bash
helm install ferrum ./charts/ferrum-gateway -n ferrum \
  -f charts/ferrum-gateway/examples/file-values.yaml
```

File mode generates a random read-only admin JWT secret at startup, so no
credential Secret is required. Kubernetes does not send `SIGHUP` on ConfigMap
change; the chart stamps a config checksum so `helm upgrade` rolls pods, or run
`kubectl rollout restart` after editing config.

The rendered config must define all four `GatewayConfig` top-level lists —
`version`, `proxies`, `consumers`, and `plugin_configs` — because none carry a
serde default and deserialization uses `deny_unknown_fields`. The default
`file.inlineConfig` supplies empty `consumers`/`plugin_configs` lists; keep them
(or an `existingConfigMap` equivalent) or the pod fails to boot.

### Control plane + data plane pair

```bash
# Shared gRPC JWT secret + CP database + admin secret
kubectl -n ferrum create secret generic ferrum-cp-db \
  --from-literal=url='postgres://ferrum:<pw>@postgres.ferrum.svc:5432/ferrum'
kubectl -n ferrum create secret generic ferrum-grpc-credentials \
  --from-literal=admin-jwt-secret="$(openssl rand -hex 32)" \
  --from-literal=cp-dp-grpc-jwt-secret="$(openssl rand -hex 32)"

helm install ferrum-cp ./charts/ferrum-gateway -n ferrum \
  -f charts/ferrum-gateway/examples/cp-values.yaml
helm install ferrum-dp ./charts/ferrum-gateway -n ferrum \
  -f charts/ferrum-gateway/examples/dp-values.yaml
```

The CP example release renders the gRPC Service
`ferrum-cp-ferrum-gateway-grpc:50051`; the paired DP example targets that exact
DNS name. In general the name is `<chart-fullname>-grpc`, truncated as one DNS
label. The quickstart pair explicitly opts into plaintext ClusterIP gRPC for
development. Production control planes should remove that opt-in, serve gRPC
over TLS (`tls.cpGrpc` or a complete CP cert/key SOURCE pair), and have DPs pin
CP trust (`tls.dpGrpc`).

This chart's `mode=cp` is a database-backed config distributor, **not** a
Kubernetes CRD controller. The binary defaults `FERRUM_K8S_CONTROLLER_ENABLED`
to true in-cluster, but `ferrum-gateway` renders no ClusterRole — core watches
would 403-retry for the life of the process. `k8sController.enabled` therefore
defaults to `false` and `mode=cp` emits `FERRUM_K8S_CONTROLLER_ENABLED=false`
plus `FERRUM_K8S_POD_DISCOVERY_ENABLED=false`. Setting `k8sController.enabled=true`
fails render with a pointer to [`ferrum-mesh`](../ferrum-mesh) (`controlPlane.rbac`),
which is the designated controller. Both env names are reserved so `env` /
`extraEnv` cannot re-enable the watches.

## Explicit migrate mode (external Job)

Neither this chart nor `ferrum-mesh` accepts `mode=migrate`. For status,
dry-run, preflight, and operator-controlled schema/config migration, apply one
of the Job manifests under [`examples/`](examples/):

| Action | Example |
|--------|---------|
| Apply pending DB migrations | [`migrate-job-up.yaml`](examples/migrate-job-up.yaml) |
| Migration status (read-only) | [`migrate-job-status.yaml`](examples/migrate-job-status.yaml) |
| Dry-run pending DB migrations | [`migrate-job-up-dry-run.yaml`](examples/migrate-job-up-dry-run.yaml) |
| Persist file-config version migration on a pre-staged writable PVC | [`migrate-job-config.yaml`](examples/migrate-job-config.yaml) |

Reuse the same image tag, DB Secret, ServiceAccount, and security context as the
gateway Deployment so the Job cannot drift from the running release. Do not run
overlapping `up` Jobs against the same database; the binary takes a migration
lock, but one operator-owned Job at a time is the supported workflow.

## Ports and stream listeners

`ports.{proxyHttp,proxyHttps,adminHttp,adminHttps,cpGrpc}` drive both the
container ports and the `FERRUM_*_PORT` env; a value of `0` disables that
listener (e.g. `ports.adminHttp=0` for TLS-only admin). The proxy Service
publishes its HTTPS port when `tls.frontend.enabled=true` with a frontend TLS
Secret, or when a complete `FERRUM_FRONTEND_TLS_{CERT,KEY}_SOURCE` pair is
supplied through `env`/`extraEnv` (file/database modes). Resolver-suffixed and
`valueFrom` source entries count too. In `dp` mode, any nonzero
`ports.proxyHttps` is published because the DP binds HTTPS on the port alone and
hot-swaps CP-delivered Gateway TLS. Default file/database installs therefore do
not advertise an unbound 443.
The admin Service publishes `admin-https` when `tls.admin` is enabled with a
Secret or a complete admin cert/key SOURCE pair is configured. If no proxy port
would be published (all proxy ports `0`, no frontend TLS, no `service: true`
stream port), the proxy Service is skipped entirely rather than rendering an
API-server-rejected empty `ports:` block.

Enabling HTTP/3 through the supported env passthrough (`env.FERRUM_ENABLE_HTTP3:
"true"`) starts a QUIC listener on the same `ports.proxyHttps` port over UDP. The
chart then adds a `proxy-h3-udp` container port and a `https-quic` UDP entry on
the proxy Service next to the TCP `https` port, so kube-proxy forwards the QUIC
datagrams (the UDP port renders only when the HTTPS listener is active — frontend
TLS with a Secret or complete cert/key SOURCE pair, or `dp` mode, and a nonzero
`ports.proxyHttps`). A
`valueFrom`-sourced `FERRUM_ENABLE_HTTP3` can't be read at render, so those
installs must hand-add the UDP port.
Raw TCP/UDP stream proxy listeners are declared under `streamPorts` and, when
`service: true`, are published on the proxy Service:

```yaml
streamPorts:
  - name: postgres-tcp
    containerPort: 15432
    protocol: TCP
    service: true
  - name: dns-udp
    containerPort: 15353
    protocol: UDP
    service: true
```

Gateway API `TCPRoute` / `TLSRoute` / `UDPRoute` listeners materialize Ferrum
stream proxies on the Gateway listener port itself (`TLSRoute` as SNI
passthrough on `protocol: TLS` / `tls.mode: Passthrough`; a `UDPRoute` on a
`protocol: UDP` listener as a UDP datagram relay). `TLSRouteModeTerminate` is
not implemented; non-Passthrough TLS listeners are rejected fail closed. Chart
installs that expose north-south TCP, TLS passthrough, or UDP must publish
matching `streamPorts` with the matching `protocol` (and `service: true` when
the Service should expose them). The Gateway API conformance lab exercises the
TCPRoute and TLSRoute paths with dedicated NodePorts; `UDPRoute` is covered by
CI Unit Tests plus a live UDP data-path integration suite, including the finite
response-amplification default and Ferrum `UDPResponseAmplificationPolicy` —
see [`docs/gateway_api_conformance.md`](../../docs/gateway_api_conformance.md).

Gateway API CRDs are a **cluster prerequisite** for any install that attaches
routes to a `Gateway` (including paired `ferrum-mesh` control-plane +
`ferrum-gateway` data-plane labs). This chart does not install them. Apply the
experimental v1.5.1 bundle before the control plane creates `Gateway` /
`GatewayClass` objects:

```bash
kubectl apply --server-side=true \
  -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/experimental-install.yaml
```

Ferrum requires the experimental channel because L4 routes and
`XBackendTrafficPolicy` are not in `standard-install.yaml` at this pin, and
upstream rejects mixing channels. See
[`docs/kubernetes_deployment.md`](../../docs/kubernetes_deployment.md#gateway-api-crds-required).

Gateway API `GRPCRoute` attaches to HTTP/HTTPS listeners and is release-gated by
the upstream `GATEWAY-GRPC` profile (same doc).

## High availability and disruption

`replicaCount` defaults to **2** so a rolling upgrade or node drain can evict one
gateway pod without dropping the front door to zero. The optional
PodDisruptionBudget (`podDisruptionBudget.enabled`, default **true**,
`minAvailable: 1`) renders only when at least two replicas are configured (or
`autoscaling.minReplicas >= 2` when HPA is enabled).

Single-replica installs (`replicaCount: 1`) are an explicit non-HA choice: the
chart skips the PDB so `minAvailable: 1` cannot block all voluntary evictions
during a drain. Pair multi-replica installs with `topologySpreadConstraints` if
you need hostname spread beyond the PDB alone.

## TLS material

Each surface under `tls.*` (`frontend`, `admin`, `backend`, `cpGrpc`, `dpGrpc`)
mounts a Secret read-only and sets the matching `FERRUM_*_TLS_*_PATH` env vars.
Ferrum's supported TLS `*_SOURCE` siblings may instead be supplied through
`env`/`extraEnv`; frontend cert/key sources participate in Service HTTPS/QUIC
gating. An admin client-CA SOURCE enables mTLS just like `tls.admin.clientCaKey`,
so TLS-only admin requires custom client-certificate-capable probes.
For the external-secret `_FILE` suffix pattern, use `secretFileMounts` to mount
an arbitrary Secret key and expose `<VAR>_FILE` pointing at it. Required sources
are matched by base name, for example `name: FERRUM_ADMIN_JWT_SECRET` renders
`FERRUM_ADMIN_JWT_SECRET_FILE` and satisfies the admin JWT render guard.

See [`values.yaml`](values.yaml) for the fully commented value surface and
[`docs/kubernetes_deployment.md`](../../docs/kubernetes_deployment.md) for the
deployment guide.

## Metrics and Prometheus

`/metrics` is served on the **admin** listener and is **gated by default** — a
scraper must present a valid admin JWT, a matching `FERRUM_METRICS_BEARER_TOKEN`,
or originate from `FERRUM_METRICS_ALLOWED_CIDRS`. The chart's optional `metrics`
subtree (`metrics.enabled`, default `false`) wires those env vars and can render
a Prometheus Operator `ServiceMonitor` plus a `PrometheusRule` with core gateway
alerts. Data-path alerts (overload shedding, upstream health, circuit breakers,
frontend TLS handshake failures) work without the optional `prometheus_metrics`
plugin; traffic alerts (5xx rate, P99 latency) require it. Database poll
freshness alerts render only in `database` and `cp` modes. The frontend TLS
handshake alert renders only when `metrics.alerts.frontendTlsHandshakeErrorsPerSecond`
is set above `0`: `reason="error"` counts every rustls accept failure, including
mid-handshake client disconnects and scanners, so a `0` threshold would fire
permanently on an internet-facing listener. Enabling metrics does **not** change `admin.bindAddress`; you must
explicitly expose admin for cluster scraping:

```yaml
metrics:
  enabled: true
  allowedCidrs: "10.0.0.0/8"   # Prometheus subnet, OR:
  bearerToken:
    existingSecret:
      name: ferrum-metrics
      key: metrics-bearer-token
  serviceMonitor:
    enabled: true
admin:
  bindAddress: "0.0.0.0"
  service:
    enabled: true
  allowedCidrs: "10.0.0.0/8,127.0.0.0/8"   # database/cp: required for plaintext admin
```

Pair a non-loopback admin bind with a `NetworkPolicy` restricting who can reach
the admin port. `metrics.bearerToken.value` wires the pod env for development;
`metrics.bearerToken.existingSecret` is required for ServiceMonitor Bearer
authorization when `metrics.allowedCidrs` is empty.

When the ServiceMonitor uses Bearer authorization, the chart always scrapes the
admin HTTPS port and requires a verifying `metrics.serviceMonitor.tlsConfig`
(for example, `ca.secret` and `serverName`). It refuses plaintext transport and
`insecureSkipVerify: true` so the observability credential is never sent to an
unauthenticated endpoint.

Authenticated `/metrics` always includes core data-path families (overload shedding,
upstream health, circuit breakers, frontend TLS handshake failures, TLS inventory,
and other runtime families) without the plugin. The optional globally scoped
`prometheus_metrics` plugin adds traffic/request families such as
`ferrum_requests_total` and `ferrum_request_duration_ms_bucket`, which the
5xx-rate and P99-latency alerts require. Add it to your gateway config when you
need those traffic metrics or alerts (`file.inlineConfig`, database
`plugin_configs`, or CP-pushed config):

```yaml
plugin_configs:
  - id: prometheus
    plugin_name: prometheus_metrics
    scope: global
    enabled: true
    config: {}
```

See [`docs/admin_metrics.md`](../../docs/admin_metrics.md) and
[`docs/prometheus_metrics.md`](../../docs/prometheus_metrics.md) for the metric
families and bundled alert expressions.
