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
| Control plane | `cp` | no | read/write | `database.*`, `admin.jwtSecret`, `grpc.jwtSecret` (>=32) |
| Data plane | `dp` | yes | read-only | `dp.cpGrpcUrls`, `admin.jwtSecret`, `grpc.jwtSecret` (>=32) |

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
  `admin.allowInsecureHttp=true`; TLS on 9443 does not protect a still-live
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
  shutdown drain, DP URLs, gRPC plaintext opt-in, ...) is reserved: setting it
  through `env` or `extraEnv` fails render, so the process can never drift from
  the rendered probes/Services/ports. Their external-secret resolver suffixes
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
- **TLS and `_FILE` Secret mounts are non-root readable.** They default to mode
  `0440` with pod `fsGroup: 65532`, matching the distroless nonroot image. Both
  `secretVolumeDefaultMode` and `podSecurityContext` are overridable for images
  with a different runtime identity.
- **Graceful shutdown** wires `terminationGracePeriodSeconds` to the
  `FERRUM_SHUTDOWN_DRAIN_SECONDS` drain window (grace must exceed drain + ~5s
  cleanup, enforced at render). `shutdownDrainSeconds: 0` is a valid "skip
  draining" value and is rendered explicitly; set it to `null` to omit the env
  and fall back to the binary's 30s default. A `null` drain is still validated
  against that 30s default, so a grace period below 35s fails render rather than
  letting Kubernetes SIGKILL the pod mid-drain.

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

## Explicit migrate mode (external Job)

Neither this chart nor `ferrum-mesh` accepts `mode=migrate`. For status,
dry-run, preflight, and operator-controlled schema/config migration, apply one
of the Job manifests under [`examples/`](examples/):

| Action | Example |
|--------|---------|
| Apply pending DB migrations | [`migrate-job-up.yaml`](examples/migrate-job-up.yaml) |
| Migration status (read-only) | [`migrate-job-status.yaml`](examples/migrate-job-status.yaml) |
| Dry-run pending DB migrations | [`migrate-job-up-dry-run.yaml`](examples/migrate-job-up-dry-run.yaml) |
| Persist file-config version migration | [`migrate-job-config.yaml`](examples/migrate-job-config.yaml) |

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
