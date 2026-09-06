# Production Hardening Checklist

A surface-by-surface checklist for deploying Ferrum Edge in front of production
traffic. Each row names the control, the setting that carries it, the value to
run, and the authoritative section — this page is an index of decisions, not a
second copy of the [configuration reference](configuration.md).

Companion documents:

- [Threat model](threat_model.md) — trust boundaries, attacker capabilities, and
  the residuals this checklist cannot close.
- [Support policy](support_policy.md) — what a version number promises today.
- [SECURITY.md](../SECURITY.md) — vulnerability reporting and the supply-chain gate.

> **Build-out status.** Ferrum Edge is pre-1.0 (`0.9.0`) and no `v*` release has
> been tagged. Read [support_policy.md](support_policy.md) before treating any
> item here as a stability commitment.

## 1. Admin plane

The admin API is a management plane. It **validates** JWTs and never mints them —
tokens are issued by your own identity tooling.

| Do this | Setting | Secure value | Reference |
|---|---|---|---|
| Keep admin off the network unless you need it | `FERRUM_ADMIN_BIND_ADDRESS` | `127.0.0.1` (the default) | [Admin API](configuration.md#admin-api) |
| Prefer TLS-only admin: no plaintext listener at all | `FERRUM_ADMIN_HTTP_PORT` | `0` | [Admin API](configuration.md#admin-api) |
| Serve admin over TLS | `FERRUM_ADMIN_TLS_CERT_PATH`, `FERRUM_ADMIN_TLS_KEY_PATH` | file or provider-backed material | [Admin API TLS Configuration](frontend_tls.md#admin-api-tls-configuration) |
| Restrict who may reach admin at the transport | `FERRUM_ADMIN_ALLOWED_CIDRS` | the narrowest operator ranges; empty permits all | [Admin API](configuration.md#admin-api) |
| Require client certificates on admin TLS | `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH` | your operator CA bundle | [Admin API TLS Configuration](frontend_tls.md#admin-api-tls-configuration) |
| Use a real admin signing secret | `FERRUM_ADMIN_JWT_SECRET` | >= 32 chars, distinct from `FERRUM_CP_DP_GRPC_JWT_SECRET` | [Admin API](configuration.md#admin-api) |
| Bound externally minted token lifetime | `FERRUM_ADMIN_JWT_MAX_TTL` | the shortest your tooling can mint (default `3600`) | [Admin API](configuration.md#admin-api) |
| Pin the audience so a token for another service cannot be replayed here | `FERRUM_ADMIN_JWT_AUDIENCE` | your admin audience string | [Admin API](configuration.md#admin-api) |
| Enforce tenancy on namespace-scoped routes instead of trusting the header | `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM` | `true` in multi-tenant deployments | [Per-namespace tenancy](admin_api.md#per-namespace-tenancy-ferrum_admin_require_namespace_claim) |
| Bound admin connection concurrency | `FERRUM_ADMIN_MAX_CONNECTIONS` | leave at `1024`; do not set `0` | [Admin API](configuration.md#admin-api) |
| Make gateways that never need writes read-only | `FERRUM_ADMIN_READ_ONLY` | `true` where writes are not required | [Admin read-only mode](admin_read_only_mode.md) |
| Mount writable, persistent audit storage before enabling fail-closed audit | `FERRUM_ADMIN_AUDIT_SPOOL_DIR` plus a volume mount | writable by UID/GID `65532`; default path `/var/lib/ferrum/audit-spool` | [Audit spool deployment](../charts/ferrum-gateway/README.md#audit-spool-with-a-read-only-root) |
| Record configuration mutations | `FERRUM_ADMIN_AUDIT_ENABLED` | `true` | [Admin API](configuration.md#admin-api) |
| Decide what happens when the audit handoff fails | `FERRUM_ADMIN_AUDIT_UNAVAILABLE_POLICY` | `fail_closed` where an unaudited mutation is unacceptable | [Admin API](configuration.md#admin-api) |

`FERRUM_ADMIN_READ_ONLY=true` is **not** a substitute for loopback, TLS, or an
allowlist: the admin API still serves sensitive management-plane reads (for
example unredacted `/backup`), and a plaintext listener still exposes operator
bearer tokens on the wire.

In `database` and `cp` modes the binary **refuses to start** when admin is bound
to a non-loopback address with a live plaintext listener and none of
`FERRUM_ADMIN_ALLOWED_CIDRS`, admin TLS with `FERRUM_ADMIN_HTTP_PORT=0`, or the
dev escape hatch `FERRUM_ALLOW_INSECURE_ADMIN_HTTP` is present. The read-only
modes (`file`, `dp`, `mesh`) warn instead of failing — treat that warning as the
same defect.

## 2. Observability endpoints

Observability is tiered by default; the goal of this section is to keep it that
way and to give scrapers a credential rather than opening the tier.

| Endpoint | Unauthenticated | Authenticated |
|---|---|---|
| `/live` | always available, `{"status":"ok"}` | same |
| `/health`, `/status` | `status` + `ready` only | full diagnostics |
| `/overload` | coarse level only | full snapshot |
| `/metrics` | `401` | full metrics |

"Authenticated" means a valid admin JWT, a matching `FERRUM_METRICS_BEARER_TOKEN`,
or a source IP inside `FERRUM_METRICS_ALLOWED_CIDRS`.

| Do this | Setting | Secure value | Reference |
|---|---|---|---|
| Give Prometheus a credential instead of opening a tier | `FERRUM_METRICS_BEARER_TOKEN` | a dedicated random token | [Admin API](configuration.md#admin-api) |
| If a scraper cannot present a credential, scope it by network | `FERRUM_METRICS_ALLOWED_CIDRS` | the scraper subnet only, never `0.0.0.0/0` | [Admin API](configuration.md#admin-api) |
| Use `/live` for liveness probes and `/health` for readiness | — | probes need no credential at the minimal tier | [Liveness and Health Checks](admin_api.md#liveness-and-health-checks) |

See [admin_metrics.md](admin_metrics.md) and
[prometheus_metrics.md](prometheus_metrics.md) for the metric contract, and
[overload_manager.md](overload_manager.md) for what `/overload` reports.

## 3. Frontend TLS

| Do this | Setting | Secure value | Reference |
|---|---|---|---|
| Terminate TLS at the gateway | `FERRUM_FRONTEND_TLS_CERT_PATH`, `FERRUM_FRONTEND_TLS_KEY_PATH` | file or provider-backed material | [Frontend TLS](frontend_tls.md) |
| Disable the plaintext proxy listener when clients are TLS-only | `FERRUM_PROXY_HTTP_PORT` | `0` | [Deployment Flexibility](frontend_tls.md#deployment-flexibility) |
| Raise the protocol floor where clients allow it | `FERRUM_TLS_MIN_VERSION` | `1.3` (default `1.2`) | [TLS / mTLS](configuration.md#tls--mtls) |
| Require client certificates for zero-trust frontends | `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` | your client CA bundle | [Client Certificate Verification (mTLS)](frontend_tls.md#client-certificate-verification-mtls) |
| Keep a handshake deadline | `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` | leave at `10`; `0` only behind a load balancer with an equivalent deadline | [Handshake Timeout](frontend_tls.md#handshake-timeout) |
| Police revocation for the issuers you own | `FERRUM_TLS_CRL_FILE_PATH` | a CRL bundle refreshed ahead of its own `nextUpdate` | [CRL Policy](frontend_tls.md#crl-policy) |
| Staple OCSP where your CA supports it | `FERRUM_FRONTEND_TLS_OCSP_RESPONSE_SOURCE` | a refreshed DER response source | [TLS Material Sources](configuration.md#tls-material-sources) |
| Rotate certificates without a restart | `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` | `true` with file/provider-backed sources | [Configuration Reference](configuration.md#tls-material-sources) |
| Resolve the real client IP only from peers you trust | `FERRUM_TRUSTED_PROXIES` | your load-balancer CIDRs, never empty-and-trusting | [Client IP resolution](client_ip_resolution.md) |

Frontend/admin TLS live reload is **off by default**; with it off, rotating
frontend material requires a configuration reload or a restart. Inline PEM is
static until config reload regardless of the flag. A CRL whose `nextUpdate`
passes stops authorizing new handshakes on every surface it is installed on —
refresh it on a schedule, not on expiry.

For non-HTTP listeners see
[TCP/UDP stream proxy encryption](tcp_udp_proxy.md#encryption-support); for HTTP/3
see [http3.md](http3.md). UDP amplification and session bounds are covered in
[tcp_udp_proxy.md](tcp_udp_proxy.md) — review that page before exposing a UDP
listener.

## 4. Backend TLS and egress

| Do this | Setting | Secure value | Reference |
|---|---|---|---|
| Verify backend certificates | `FERRUM_TLS_NO_VERIFY` | `false` (the default) | [TLS / mTLS](configuration.md#tls--mtls) |
| Pin backend trust to your own CA when you own the issuer | `FERRUM_TLS_CA_BUNDLE_PATH` | your bundle — note it becomes the **sole** trust anchor | [Custom CA Bundles](backend_mtls.md#custom-ca-bundles) |
| Authenticate the gateway to backends | `FERRUM_BACKEND_TLS_CLIENT_CERT_PATH`, `FERRUM_BACKEND_TLS_CLIENT_KEY_PATH` | per-deployment client identity | [Backend mTLS](backend_mtls.md) |
| Keep the SSRF baseline on | `FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES` | `true` (the default) | [Backend Egress / SSRF Protection](configuration.md#backend-egress--ssrf-protection) |
| Narrow egress further where the deployment allows | `FERRUM_BACKEND_ALLOW_IPS` | `public` for egress-gateway shapes, `private` for internal-only | [Backend Egress / SSRF Protection](configuration.md#backend-egress--ssrf-protection) |
| Deny internal ranges you never dial | `FERRUM_BACKEND_DENY_CIDRS` | the ranges you want unreachable | [Backend Egress / SSRF Protection](configuration.md#backend-egress--ssrf-protection) |
| Use the allow list as a narrow escape hatch only | `FERRUM_BACKEND_ALLOW_CIDRS` | the smallest CIDR that works; it overrides everything below it | [Backend Egress / SSRF Protection](configuration.md#backend-egress--ssrf-protection) |
| Keep backend material rotating | `FERRUM_BACKEND_TLS_LIVE_RELOAD_ENABLED` | `true` (the default) | [Operational Contract for Backend TLS Sources](backend_mtls.md#operational-contract-for-backend-tls-sources) |

The default posture (`both` + baseline on) still reaches loopback and RFC1918/ULA
backends so sidecars and internal upstreams work, while denying cloud-metadata,
link-local, multicast and unspecified addresses. Precedence is first match wins:
`FERRUM_BACKEND_ALLOW_CIDRS`, then `FERRUM_BACKEND_DENY_CIDRS`, then the
dangerous-range baseline, then `FERRUM_BACKEND_ALLOW_IPS`.

`kafka_logging` is admitted **only** under a fully open egress policy, because
librdkafka dials cluster-advertised brokers Ferrum never screens. If you enable
it you have given up backend egress enforcement process-wide — see
[`kafka_logging` requires a fully-open egress policy](configuration.md#kafka_logging-requires-a-fully-open-egress-policy).

Database connections have their own TLS surface: see
[database_tls.md](database_tls.md) and, for MongoDB, [mongodb.md](mongodb.md).

## 5. Control plane / data plane

| Do this | Setting | Secure value | Reference |
|---|---|---|---|
| Never run config sync in plaintext off loopback | `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT` | `false` (the default) | [Control Plane / Data Plane](configuration.md#control-plane--data-plane) |
| Serve CP gRPC over TLS | `FERRUM_CP_GRPC_TLS_CERT_PATH`, `FERRUM_CP_GRPC_TLS_KEY_PATH` | file or provider-backed material | [Transport security](cp_dp_mode.md#transport-security-tlsmtls) |
| Pin the CP's CA on every data plane | `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` | the CP issuing CA | [Transport security](cp_dp_mode.md#transport-security-tlsmtls) |
| Use a distinct plane secret | `FERRUM_CP_DP_GRPC_JWT_SECRET` | >= 32 chars, distinct from `FERRUM_ADMIN_JWT_SECRET` | [Control Plane / Data Plane](configuration.md#control-plane--data-plane) |
| Prefer an externally issued token so no signing key sits on the node | `FERRUM_DP_CP_GRPC_TOKEN_FILE` | a short-lived issued token file | [Control Plane / Data Plane](configuration.md#control-plane--data-plane) |
| Bind namespace authority to the credential in multi-tenant CPs | `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM` | `true` | [JWT tenancy claim](cp_namespace_tenancy.md#jwt-tenancy-claim) |
| Use per-namespace verification credentials rather than one shared secret | `FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH` | a trust-bundle document | [Trust binding](cp_namespace_tenancy.md#trust-binding-ghsa-3f2j-wwqw-grmg) |
| Bound how long an unrevalidatable verifier keeps authorizing | `FERRUM_CP_DP_TRUST_MAX_STALE_SECONDS` | leave at `900` or lower | [Retention of an unrevalidatable verifier is bounded (issue #3813)](cp_namespace_tenancy.md#retention-of-an-unrevalidatable-verifier-is-bounded-issue-3813) |
| Fence a data plane serving stale config | `FERRUM_DP_CONFIG_MAX_STALE_SECONDS`, `FERRUM_DP_CONFIG_STALE_ACTION` | the default bound with `fail_closed` | [Bounded last-known-good configuration age](cp_dp_mode.md#bounded-last-known-good-configuration-age) |
| Keep stream admission budgets bounded | `FERRUM_XDS_ALLOW_UNBOUNDED_STREAM_LIMITS` | `false` (the default) | [Control Plane / Data Plane](configuration.md#control-plane--data-plane) |

## 6. Mesh

| Do this | Setting | Secure value | Reference |
|---|---|---|---|
| Turn on the master mesh guardrail | `FERRUM_MESH_PRODUCTION_MODE` | `true` in every production mesh deployment | [Mesh Runtime](configuration.md#mesh-runtime) |
| Never accept a hard-coded peer identity | `FERRUM_MESH_ALLOW_STATIC_ID` | `false` | [Mesh Runtime](configuration.md#mesh-runtime) |
| Never bootstrap a self-signed root in production | `FERRUM_MESH_CA_BOOTSTRAP_DEV` | `false` | [Mesh Runtime](configuration.md#mesh-runtime) |
| Never run without workload identity | `FERRUM_MESH_ALLOW_NO_CA` | `false` | [Mesh Runtime](configuration.md#mesh-runtime) |
| Supply a stable trust-domain JWT authority | `FERRUM_MESH_JWT_SIGNING_KEY_PEM` | one value shared across replicas, from a secret provider | [Mesh Runtime](configuration.md#mesh-runtime) |
| Never mint a process-local signing key | `FERRUM_MESH_ALLOW_EPHEMERAL_JWT_KEY` | `false` | [Mesh Runtime](configuration.md#mesh-runtime) |
| Keep stock-xDS plaintext off | `FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT` | `false` (the default) | [Mesh Runtime](configuration.md#mesh-runtime) |
| Give each remote cluster its own discovery credential | `FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS` | a per-remote map, >= 32 chars each | [Mesh Runtime](configuration.md#mesh-runtime) |

`FERRUM_MESH_PRODUCTION_MODE=true` unconditionally refuses the four dev opt-ins
above and refuses `FERRUM_TLS_NO_VERIFY` / `FERRUM_ADMIN_TLS_NO_VERIFY` at the
shared validation path used by both `ferrum-edge validate` and startup. Set it
first; it converts several of the rows above from a review item into a startup
failure.

Read [mesh.md](mesh.md), its
[Maturity and Support Status](mesh.md#maturity-and-support-status) matrix, and
[mesh_supported_matrix.md](mesh_supported_matrix.md) before relying on a mesh
topology. Node-agent deployments have their own posture document:
[node_agent_security.md](node_agent_security.md). For SPIFFE issuance see
[spire_deployment.md](spire_deployment.md).

## 7. Plugins

| Do this | Setting or field | Secure value | Reference |
|---|---|---|---|
| Always verify token expiry on JWT auth | plugin `jwt` config | expiry validation is required, never disabled | [Plugin reference](plugins.md) |
| Bound remote signing-key trust | `jwks_auth` `jwks_max_stale_seconds` | shorter than the default hour when revocation must converge fast | [SECURITY.md](../SECURITY.md) |
| Fail closed when the shared rate-limit store is unreachable | `rate_limiting` `redis_failure_policy` | `fail_closed` (the default) | [rate_limiting](plugins.md#rate_limiting) |
| Enforce, do not just monitor, the WAF | WAF plugin mode | enforcement mode; the default rule pack ships monitor-only | [Default rules ship monitor-only](waf.md#default-rules-ship-monitor-only--and-how-to-enforce-them) |
| Bound request bodies | `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` | a real ceiling; `0` is unlimited | [Size limits](size_limits.md) |
| Keep plugin egress inside the backend policy | `FERRUM_BACKEND_ALLOW_IPS` and the CIDR lists | see §4 — plugin endpoints are screened by the same policy | [Backend Egress / SSRF Protection](configuration.md#backend-egress--ssrf-protection) |
| Review credential storage before choosing an auth plugin | consumer credentials | see [plugins.md](plugins.md) | [Plugin reference](plugins.md) |

Plugin ordering is security-relevant: an authentication plugin that runs after a
transform sees different input. See
[plugin_execution_order.md](plugin_execution_order.md).

## 8. Secrets

| Do this | Mechanism | Secure value | Reference |
|---|---|---|---|
| Never put secrets in `ferrum.conf` or a ConfigMap | external secret suffixes | `_FILE`, `_VAULT`, `_AWS`, `_AZURE`, `_GCP` | [TLS Material Sources](configuration.md#tls-material-sources) |
| Refresh provider-backed material | `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` | the shortest interval your provider tolerates | [Core Settings](configuration.md#core-settings) |
| Bound each secret fetch | `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` | leave at `30` | [Core Settings](configuration.md#core-settings) |
| Keep TLS private keys non-extractable where an HSM exists | `pkcs11://` key sources | frontend/admin server keys, backend client keys | [PKCS#11 TLS keys](pkcs11_tls.md) |
| Source Kubernetes TLS material from Secrets, not files baked into images | `k8s://` sources | cert-manager-managed Secrets | [Kubernetes Secret TLS sources](k8s_cert_manager.md) |
| Redact anything sensitive your backends echo into logs | `FERRUM_LOG_REDACT_METADATA_KEYS` | your sensitive metadata keys | [Core Settings](configuration.md#core-settings) |
| Bound the size of any material accepted from a source | `FERRUM_TLS_MAX_MATERIAL_SIZE_BYTES` | leave at the default 4 MiB | [Core Settings](configuration.md#core-settings) |

A provider conflict for one base key (two suffixes on the same variable) is a
startup error, not a silent precedence choice.

## 9. Containers and Helm

| Do this | Chart value or setting | Secure value | Reference |
|---|---|---|---|
| Pin a published image tag | `image.tag` | an immutable published tag, never `latest` | [Security defaults you should know](../charts/ferrum-gateway/README.md#security-defaults-you-should-know) |
| Keep the non-root, read-only-root defaults | `podSecurityContext`, `securityContext` | the chart defaults (`runAsNonRoot`, `readOnlyRootFilesystem`, all capabilities dropped, `RuntimeDefault` seccomp) | [ferrum-gateway chart](../charts/ferrum-gateway/README.md) |
| Never render secrets into ConfigMaps | Secret references or `secretFileMounts` | referenced Secrets you own | [Security defaults you should know](../charts/ferrum-gateway/README.md#security-defaults-you-should-know) |
| Keep admin on loopback and probe in-pod | `admin.bindAddress` | the loopback default with the computed exec probes | [Security defaults you should know](../charts/ferrum-gateway/README.md#security-defaults-you-should-know) |
| Restrict admin and CP gRPC ingress | `networkPolicy.enabled` plus at least one selector | `true` with explicit selectors — an empty selector pair denies all, which is deliberate | [ferrum-gateway chart](../charts/ferrum-gateway/README.md) |
| Give the pod time to drain | `terminationGracePeriodSeconds` | longer than `FERRUM_SHUTDOWN_DRAIN_SECONDS` plus the rest of the shutdown budget | [Graceful shutdown](graceful_shutdown.md#kubernetes) |
| Keep draining on | `FERRUM_SHUTDOWN_DRAIN_SECONDS` | the default `30`, tuned to your load balancer | [Graceful shutdown](graceful_shutdown.md) |

Deployment references: [kubernetes_deployment.md](kubernetes_deployment.md),
[docker.md](docker.md), [multi_region_ha.md](multi_region_ha.md),
[infrastructure_sizing.md](infrastructure_sizing.md). For a FIPS-validated crypto
posture see [fips.md](fips.md).

## Never in production

Each of these is verified against the shipped configuration reference. The first
two are refused or refused-in-context rather than merely discouraged; the rest
are accepted and silently weaken the deployment.

| Setting | Why not |
|---|---|
| `FERRUM_TLS_NO_VERIFY=true` | Disables outbound TLS verification for **all** connections and bypasses backend SAN allow-list enforcement. Any on-path attacker becomes a valid backend. Refused when `FERRUM_MESH_PRODUCTION_MODE=true`. |
| `FERRUM_DP_GRPC_TLS_NO_VERIFY=true` | Not supported: **rejected at startup**. To reach a CP presenting a self-signed certificate, pin its CA with `FERRUM_DP_GRPC_TLS_CA_CERT_PATH`. |
| `FERRUM_ADMIN_TLS_NO_VERIFY=true` | Skips Admin API TLS certificate verification. Refused when `FERRUM_MESH_PRODUCTION_MODE=true`. |
| `FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true` with a non-loopback plaintext admin bind | Downgrades the `database`/`cp` startup refusal to a warning and serves the management plane — and every operator bearer token that reaches it — in cleartext on a network-reachable interface. |
| `FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES=false` | Removes the cloud-metadata / link-local / multicast / unspecified baseline. With `FERRUM_BACKEND_ALLOW_IPS=both` and no deny list this makes the gateway an unrestricted SSRF bridge; the gateway logs a startup warning to that effect. |
| `FERRUM_SHUTDOWN_DRAIN_SECONDS=0` | Skips the in-flight connection drain, so a rolling deploy severs live requests instead of finishing them. |
| `FERRUM_XDS_ALLOW_UNBOUNDED_STREAM_LIMITS=true` | Permits `0` (unbounded) configuration-stream admission budgets, removing the control plane's per-node stream ceiling. |
| `FERRUM_MESH_ALLOW_STATIC_ID=true` | The static attestor returns a hard-coded SPIFFE ID for any peer — zero proof of identity. Refused under `FERRUM_MESH_PRODUCTION_MODE`. |
| `FERRUM_MESH_ALLOW_NO_CA=true` | Runs mesh mode with no workload identity at all. Refused under `FERRUM_MESH_PRODUCTION_MODE`. |
| `FERRUM_MESH_ALLOW_EPHEMERAL_JWT_KEY=true` | Mints a process-local JWT signing key, so tokens stop verifying across replicas and restarts. Refused under `FERRUM_MESH_PRODUCTION_MODE`. |
| `FERRUM_MESH_CA_BOOTSTRAP_DEV=true` | Mints a self-signed root for the internal CA backend. Refused under `FERRUM_MESH_PRODUCTION_MODE`. |
| `FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT=true` | Admits plaintext (h2c) stock ADS endpoints. Development only. |
| `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true` on a networked address | Sends the entire configuration stream, including the plane bearer token, in cleartext. |

UDP amplification and datagram limits are deliberately **not** listed here
because those defaults are being revised; read
[tcp_udp_proxy.md](tcp_udp_proxy.md) for the current values before exposing a UDP
listener.

## Verifying a deployment

```bash
# Fail fast on an unsafe configuration before it reaches a listener.
ferrum-edge validate -s /etc/ferrum/ferrum.conf

# Confirm the admin tiering is what you expect (no credential presented).
curl -s http://127.0.0.1:9000/live
curl -s http://127.0.0.1:9000/metrics -o /dev/null -w '%{http_code}\n'   # expect 401
```

`ferrum-edge validate` runs the same `EnvConfig` validation path as startup, so a
setting refused at runtime is refused here too. See [cli.md](cli.md).
