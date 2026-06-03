# Mesh Mode

Ferrum Edge runs as a service mesh data plane when `FERRUM_MODE=mesh`. In this mode the gateway consumes mesh configuration from a Ferrum Control Plane (native `MeshSubscribe` gRPC) or a standard xDS ADS server, materializes SPIFFE-identity-aware proxies and authorization policies, and serves traffic with automatic mTLS, identity propagation, and Istio-compatible observability. The mesh subsystem deliberately reuses the existing proxy/plugin chain so all 58+ gateway plugins work unchanged in mesh context.

Concepts map directly to the Istio service mesh model: `Workload` corresponds to a pod or VM identity, `MeshPolicy` to `AuthorizationPolicy`, `PeerAuthentication` to per-port mTLS modes, `ServiceEntry` to external service registration, and `MeshRequestAuthentication` to `RequestAuthentication` JWT declarations. The Ferrum mesh layer adds multi-cluster east-west gateways, egress gateway materialization, node-waypoint operation for sidecarless pod capture, service-scoped Ambient waypoints, a transparent DNS proxy for `ServiceEntry` resolution, and a Kubernetes sidecar injector.

## Table of Contents

- [Maturity and Support Status](#maturity-and-support-status)
- [Limitations and Not Supported](#limitations-and-not-supported)
- [Failure-Mode Runbook](#failure-mode-runbook)
- [Observability and Troubleshooting Quick Reference](#observability-and-troubleshooting-quick-reference)
- [Topologies](#topologies)
- [Configuration Consumption](#configuration-consumption)
  - [Native MeshSubscribe (default)](#native-meshsubscribe-default)
  - [xDS ADS](#xds-ads)
  - [Ferrum mesh-slice ECDS carriers (full parity over xDS)](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds)
  - [ECDS DestinationRule carrier (full DR semantics over xDS)](#ecds-destinationrule-carrier-full-dr-semantics-over-xds)
  - [Bootstrap Behavior](#bootstrap-behavior)
- [Mesh Data Model](#mesh-data-model)
- [MeshSlice](#meshslice)
- [Authorization](#authorization)
  - [PolicyScope Filtering](#policyscope-filtering)
  - [Evaluation Semantics](#evaluation-semantics)
  - [Rule Matching](#rule-matching)
  - [SPIFFE Identity](#spiffe-identity)
  - [HBONE Protocol](#hbone-protocol)
  - [Trust Domain Aliasing](#trust-domain-aliasing)
  - [Trusted HBONE Assertors](#trusted-hbone-assertors)
- [RequestAuthentication](#requestauthentication)
- [PeerAuthentication](#peerauthentication)
- [Transparent DNS Proxy](#transparent-dns-proxy)
- [Multi-Cluster](#multi-cluster)
  - [Trust Federation](#trust-federation)
  - [Cross-Cluster Endpoint Discovery](#cross-cluster-endpoint-discovery)
- [Egress Gateway](#egress-gateway)
- [Sidecar Egress Scoping](#sidecar-egress-scoping)
- [Config Drift Introspection](#config-drift-introspection)
- [DestinationRule](#destinationrule)
- [Observability](#observability)
- [Kubernetes Injector](#kubernetes-injector)
- [Control Plane Integration](#control-plane-integration)
- [Gateway-to-Mesh Bridge](#gateway-to-mesh-bridge)
- [Mesh Identity](#mesh-identity)
  - [SPIRE Agent CA](#spire-agent-ca)
  - [Internal Dev CA and Production Guardrails](#internal-dev-ca-and-production-guardrails)
- [Node Agent Mode](#node-agent-mode)
- [VirtualService Translation](#virtualservice-translation)
- [Gateway API Status](#gateway-api-status)
- [Istio CRD Status](#istio-crd-status)
- [Locality-Aware Load Balancing](#locality-aware-load-balancing)
- [xDS ADS Compatibility](#xds-ads-compatibility)
- [Istio Compatibility Gaps](#istio-compatibility-gaps)
- [Environment Variables](#environment-variables)

## Maturity and Support Status

Ferrum's mesh subsystem is in active build-out. The paths below ship in one binary and share the same proxy/plugin chain, but they are at very different maturity levels. Use this matrix to decide what to rely on in production. Labels:

- **Stable** — exercised end-to-end (functional/integration tests against a live data path), production-suitable.
- **Beta** — feature-complete and tested, but with a documented sharp edge or a verification step still owed (see [Limitations](#limitations-and-not-supported)).
- **Experimental** — usable but with a safety-relevant caveat (plaintext, unauthenticated, or partial enforcement); opt-in and not recommended without compensating controls.
- **Dev-only** — gated behind a build feature or an explicit dev opt-in; not present in the published image's default behavior.

> For the one-screen **product contract** (what to rely on, the GA promise, and the explicit non-goals), see [docs/mesh_supported_matrix.md](mesh_supported_matrix.md). The contract's **GA** tier is the maturity bar these tables label **Stable**, and it is machine-enforced *for the features enrolled in the conformance GA contract* — such a feature regressing (or its test being deleted) fails the conformance suite (`tests/conformance/ga_scope.rs`). That contract is populated incrementally as each area is verified, so it does **not** yet enroll every row labeled Stable here (e.g. native `MeshSubscribe`, `Sidecar + native config`, and SPIFFE identity are Stable but not yet GA-gated). The live, auto-generated set of GA-gated features is written to `target/conformance/coverage.md`.

### Config-source maturity

| Capability | Status | Notes |
|---|---|---|
| Native `MeshSubscribe` (Ferrum CP → Ferrum DP) | **Stable** | Default protocol. Full slice (authz, PeerAuth, JWT, ServiceEntry, trust bundles, ProxyConfig, workloads, telemetry, multi-cluster) is pushed directly. The most mature and recommended config path. |
| xDS ADS (Ferrum CP → Ferrum DP) | **Beta** | Functionally equivalent to native via Ferrum-specific ECDS carriers (`ferrum.config.extension.v3.*`). **NOT stock-Envoy / third-party-Istio interop** — a non-Ferrum CP emits only name-only CDS/EDS/LDS/RDS and no carriers, so it cannot drive a protected Ferrum mesh and may be NACKed. `ProxyConfig` is native-only. RTDS layers are authored by the operator's CP (Ferrum's xDS server does not originate Runtime resources). |
| Stock Envoy / third-party Istio xDS interop | **Not supported** | See [Limitations](#limitations-and-not-supported). Use native or a Ferrum CP. |

### Topology maturity

| Topology | Status | Notes |
|---|---|---|
| `Sidecar` + native config | **Stable** | The most mature path: inbound 15006 mTLS + outbound 15001 capture, SPIFFE-verified peers, full authz/JWT/DR enforcement. Recommended for production. |
| `Ambient` (HBONE 15008) | **Beta** | HBONE termination over mTLS is implemented and SPIFFE-trust-domain-verified. Requires eBPF ambient capture (or iptables) to actually intercept traffic — see capture maturity below. |
| `EastWestGateway` (SNI passthrough 15443) | **Beta** | TCP/SNI passthrough for multi-cluster; no TLS termination. Cross-cluster *endpoint* discovery (vs SNI passthrough) is separate and Experimental — see below. |
| `EgressGateway` — HTTP-family (15090 mTLS) | **Beta** | mTLS-terminating egress for `mesh_external` ServiceEntries with `outboundTrafficPolicy` enforcement. |
| `EgressGateway` — stream-family (TCP/UDP) | **Experimental** | Opt-in via `FERRUM_MESH_EGRESS_STREAM_ENABLED=true`. **Per-port stream listeners are plaintext and unauthenticated** (`mesh_authz` cannot verify SPIFFE identity without mTLS). Default-off; enable only with compensating network controls. |
| `ServiceWaypoint` (GAMMA) | **Beta** | Service-scoped Ambient waypoint; CP narrows resources to the named binding. Needs the eBPF/ambient capture caveats of node-waypoint when fronting captured pods. |
| `NodeWaypoint` (sidecarless capture) | **Experimental** | HBONE listener is implemented; the GAP-2M accept-side bridge is implemented in the kernel `sock_ops` program (re-keys the orig-dst record by connection 4-tuple, then re-stamps it under the accept-side cookie), and per-pod identity enrollment is wired (slice apply installs a `workload_spiffe_hash`→SPIFFE index that `resolve_record` hash-joins against the eBPF-stamped `(pod_uid, hash)` to lazily enroll identities) — so socket-cookie identity resolution is complete end-to-end in code, but it is **CI compile/load-tested only, unverified on a live multi-pod datapath** (a tuple/byte-order or enrollment miss fails closed, never misattributes). **IPv4 only:** both `sock_ops` bridge paths guard on `AF_INET` because aya's IPv6 ctx accessors trip the BPF verifier, so IPv6 (and the IPv6 half of dual-stack) accepts get no accept-side cookie record and node-waypoint resolution stays fail-closed there, pending a verifier-safe v6 read. **IPv4 TCP** stream authz scopes per source pod via the resolver when capture is loaded; **UDP/DTLS** stream authz is mesh-wide-only by architectural blocker (eBPF capture is `connect()`-hooked and TCP-only). With scoped policies present, missing scope (UDP, or TCP unresolved) fails closed with 403; with only mesh-wide policies, both fall through to mesh-wide-only evaluation. Requires a `--features ebpf` capture build. |

### Capture / data-path maturity

| Capability | Status | Notes |
|---|---|---|
| iptables capture (injector init container) | **Beta** | Requires `NET_ADMIN`/`NET_RAW`; rules applied at pod admission, restart needed to pick up new annotations. |
| eBPF ambient capture | **Dev-only** | Requires a build with `--features ebpf` (the **default published image uses a no-op mock backend** that attaches nothing and sets `ferrum_mesh_node_topology_degraded`). The aya kernel loader compiles on Linux only. CI now builds the BPF object (`build-ebpf`), compiles the userspace loader (`build-ebpf-userspace`), and **load/attach-tests the programs on a real ≥5.7 kernel** (`ebpf-live`); the **full capture datapath remains unverified on a live multi-pod node**. Inbound TC redirect is deferred; the iptables fallback is node-global and needs a custom runtime image with `/bin/sh` + `iptables`. |
| orig-dst → proxy identity bridge (node-waypoint) | **Experimental** | `src/ebpf/orig_dst_bridge.rs` mirrors socket-cookie records into the resolver (+ installs a synchronous accept-path fallback); the **accept-side cookie bridge (GAP-2M) is implemented** in the kernel `sock_ops` program (re-keys orig-dst by connection 4-tuple, re-stamps under the accept-side cookie), and **per-pod identity enrollment is wired** (hash-join of the slice's `workload_spiffe_hash`→SPIFFE index against the eBPF-stamped `(pod_uid, hash)`), so resolution is complete end-to-end with no further proxy-side change — **IPv4 only**: both bridge paths guard on `AF_INET`, so IPv6 (and dual-stack IPv6) accepts get no accept-side cookie and stay fail-closed. CI compile/load-tests it; end-to-end resolution is **unverified on a live datapath** and fails closed (never misattributes) on a tuple/byte-order/enrollment miss — including a cached pod whose workload a later slice removes, which `resolve_record` re-validates against the current slice index on every resolve. |

### Identity / CA maturity

| Capability | Status | Notes |
|---|---|---|
| SPIRE Agent CA (`spire_agent`) | **Stable** | Recommended production identity path — delegates SVID issuance to a separately operated SPIRE installation over the Workload API. |
| Internal self-signed CA (`internal`) | **Dev-only** | Self-signed root generated by the bootstrap helper; gated behind `FERRUM_MESH_CA_BOOTSTRAP_DEV=true` and refused when `FERRUM_MESH_PRODUCTION_MODE=true`. Lab/test only — see [Internal Dev CA and Production Guardrails](#internal-dev-ca-and-production-guardrails). |
| SPIFFE inbound/HBONE peer trust-domain verification | **Stable** | When gateway SVID material is configured, inbound mTLS/HBONE peers are SPIFFE-trust-domain-verified against the local + federated bundles (not just chain-validated). |
| Trust-bundle federation poller | **Beta** | Fetches `RemoteCluster.federation_endpoint` bundles; outbound-only (a poller-added trust domain is rejected inbound until the CP pushes it). `FERRUM_MESH_FEDERATION_FAIL_OPEN` is inert. |

### Cross-cluster maturity

| Capability | Status | Notes |
|---|---|---|
| East-west SNI passthrough + trust federation | **Beta** | See `EastWestGateway` above and [Trust Federation](#trust-federation). |
| Cross-cluster endpoint discovery (local→remote failover) | **Experimental** | `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS>0` dials each `RemoteCluster.control_plane_url`. Aggregation + locality failover are integration-tested with a mockable source; the **live two-control-plane round trip is not yet verified**. Requires source locality to be set for local-first preference. |

## Limitations and Not Supported

This section consolidates every known residual gap so operators do not have to reconstruct them from the prose. Items are grouped by area; each is enforced or deferred as described against the merged code.

### Not interoperable / not planned

- **Stock Envoy / third-party Istio xDS interop** — Ferrum's `FERRUM_MESH_CONFIG_PROTOCOL=xds` is a **Ferrum-CP-to-Ferrum-DP** path. It follows the Envoy ADS gRPC contract, but CDS/EDS/LDS/RDS are name-only with Ferrum-shaped resource names, and all security/policy fields ride Ferrum-defined ECDS carriers. A stock Envoy/Istio CP does not emit these, so pointing Ferrum's xDS client at a non-Ferrum CP is unsupported and may be NACKed. Use native, or a Ferrum CP over xDS.
- **`EnvoyFilter`** — not planned. Use Ferrum custom plugins (`custom_plugins/`).
- **`WasmPlugin`** — not planned. Use Ferrum custom plugins.
- **Per-node ADS stream ceiling** — `FERRUM_XDS_MAX_STREAMS_PER_NODE` (default `4`, `0`=unbounded) bounds concurrent ADS streams under one node id; excess streams are rejected with gRPC `RESOURCE_EXHAUSTED` and counted by `ferrum_xds_streams_rejected_total`. (Resource warming / make-before-break across types is now implemented — see [xDS ADS Compatibility](#xds-ads-compatibility).)

### Capture / node-waypoint (see also the Maturity matrix)

- **eBPF capture is a build feature** — the published image ships a no-op mock backend; real capture needs `--features ebpf` on Linux. CI now load/attach-tests the programs on a real ≥5.7 kernel (`ebpf-live`), but the full capture datapath is unverified on a live multi-pod node.
- **Node-waypoint identity: GAP-2M bridge implemented (IPv4), runtime-unverified** — the accept-side socket-cookie bridge is implemented in the kernel `sock_ops` program (re-keys orig-dst by connection 4-tuple, re-stamps under the accept-side cookie), so cookie resolution can succeed with `--features ebpf`. **IPv4 only**: aya's IPv6 ctx accessors trip the BPF verifier, so IPv6 node-waypoint resolution stays fail-closed (pre-GAP-2M behavior) pending a verifier-safe v6 read. End-to-end resolution is CI compile/load-tested but unverified on a live datapath; a tuple/byte-order mismatch fails closed (never misattributes).
- **Node-waypoint UDP/DTLS stream authz is mesh-wide-only** — TCP stream connections through a node-waypoint proxy now scope per source pod via `resolve_node_waypoint_stream_scope()` (socket-cookie → pod identity → `PolicyScopeCache`); when the connect-side resolver returns no identity, the connection fails closed with 403 if any namespace/selector-scoped `AuthorizationPolicy` exists in the mesh (else falls through to mesh-wide-only evaluation). **UDP/DTLS** scope is unresolvable by architecture — eBPF capture is `connect()`-hooked and TCP-only, and a UDP proxy demuxes all clients off one shared frontend socket — so UDP node-waypoint authz is always mesh-wide-only; with scoped policies present, UDP fails closed with 403.
- **Inbound TC redirect deferred; iptables fallback is node-global** — and requires a custom runtime image with `/bin/sh` + `iptables` (+ `ip6tables` for IPv6).

### Authorization

- **`ipBlocks` / `remoteIpBlocks` on the stream path collapse to one IP** — on the HTTP request path the two are distinguished (`ipBlocks`/`source.ip` = the immediate downstream socket peer via `direct_client_ip`; `remoteIpBlocks`/`remote.ip` = the gateway-resolved, XFF-aware `client_ip`). On the **TCP/UDP stream path** (`on_stream_connect`) both `source.ip` and `remote.ip` derive from the single gateway-resolved `client_ip` — there is no direct-vs-XFF distinction for streams. IP-block matchers fail closed when the IP they test is absent.
- **DENY rules treat missing HTTP-only attributes as matches** — Istio semantics. Port-scope DENY rules that mention HTTP fields and can see TCP traffic, or they may over-match.

### DestinationRule (parsed but inert / approximated / deferred)

- **`connectionPool.http.maxRequestsPerConnection`** — wire-projected end-to-end but **inert at runtime**: hyper lacks a stable close-after-N-requests builder knob. Activates automatically once hyper grows the knob.
- **`connectionPool.tcp.maxConnections`** — enforced for **stream-family (TCP)** and **HTTP-family WebSocket** (H1/H2/H3) via an RAII guard on `ProxyState.backend_conn_limit`. The pooled multiplexed transports (reqwest H1/H2, direct H2, gRPC, H3, HBONE) do **not** enforce it because their backend-connection lifecycle is pool-internal (reuse, sharding, idle eviction) and a request-keyed counter would measure request concurrency rather than open connections — use `http2MaxRequests` / `h2_max_concurrent_streams` for HTTP/2-family concurrency instead. Full rationale in [DestinationRule `maxConnections` enforcement scope](#destinationrule-maxconnections-enforcement-scope).
- **`connectionPool.http.{http1MaxPendingRequests, maxRetries, h2UpgradePolicy}`** — parsed, warned, and surfaced in `status.ferrum.translation.deferred_fields`; not enforced.
- **Per-subset `connectionPool.tcp.connectTimeout`** — **applied**: it overrides `backend_connect_timeout_ms` for proxies whose `upstream_subset` selects the subset, taking precedence over the DestinationRule's top-level `connectTimeout`. **Per-subset `outlierDetection` thresholds** (consecutive errors, interval, base-ejection time, min-health) — **applied**: resolved into the subset's passive-health overlay and consulted by `passive_health_for_target` ahead of the upstream-level passive health for subset-bound proxies. The one residual is the per-subset `outlierDetection.maxEjectionPercent` **cap**, which is resolved at the upstream level (`LoadBalancerCache`) and is not yet per-subset. Other per-subset `connectionPool` fields beyond `connectTimeout` are still parsed-and-warned.
- **`portLevelSettings[].tls`** — **applied** per-port: resolved over the upstream-level TLS at apply time and projected onto the per-target effective proxy's `resolved_tls` (which is part of the backend pool key, so a distinct per-port TLS posture fragments its own pool). Takes precedence over the upstream-/subset-level `trafficPolicy.tls` for dials to that port.
- **`loadBalancer.simple = PASSTHROUGH`** — approximated as `ROUND_ROBIN` (warns); Ferrum cannot preserve the original destination IP. `MAGLEV` is a hard reject.
- Stream-family (TCP/UDP/DTLS) upstreams use upstream-level LB / passive / locality policy only — per-port `loadBalancer` / `outlierDetection` / `localityLbSetting` apply to HTTP-family / gRPC / WebSocket / HBONE dispatch.

### VirtualService

- **`spec.tcp[]` / `spec.tls[]` L4 routing** — **supported** (materialized into Ferrum stream proxies, reusing the gateway/east-west stream + SNI machinery): `tls[]` → a passthrough TCP proxy keyed by SNI (`sniHosts`, encrypted bytes forwarded with no TLS termination); `tcp[]` → a plain TCP proxy keyed by port. Match predicates the stream layer cannot express (`sourceLabels` / `sourceSubnets` / `destinationSubnets` / `gateways` / `sourceNamespace`) and weighted multi-destination splitting are **rejected fail-closed** (`FerrumAccepted=False`/`Invalid`) rather than mis-routed. (`mirror`, `mirrorPercentage`, `redirect`, and `rewrite` are fully translated.)
- **`http[].corsPolicy`** — translated to a proxy-scoped `cors` plugin when its origins are representable: `allowOrigins[].exact` (or the legacy `allowOrigin` string list), plus `allowMethods`/`allowHeaders`/`exposeHeaders`/`maxAge`/`allowCredentials`. `prefix`/`regex` origin matchers have no `cors` plugin equivalent, so a policy using them is left unprojected (warned, surfaced as a `deferred_fields` entry) rather than silently approximated — configure the `cors` plugin directly for those. Routing on the route is unaffected either way.
- **Per-rule fault percentages are not RTDS-tunable** — the GAP-3E RTDS fault keys apply only to `fault_injection` plugin instances with `runtime_overlay_scope`, not to per-route VS faults.

### mTLS / HBONE operator cautions

- **PERMISSIVE with no client CA degrades to no-auth** — if `PeerAuthentication` resolves to `PERMISSIVE` but neither `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` nor gateway SVID material is configured, client certificates are **not requested or verified** (logged at startup as a `warn!`; resolved through the explicit `PermissiveNoTrustAnchor` decision in `resolve_mesh_inbound_client_auth`). The listener admits unauthenticated peers and no peer SPIFFE identity is recorded. Configure a client CA or SVID material, or use STRICT, when you need PERMISSIVE to actually capture identity.

### Federation / multi-cluster

- **`FERRUM_MESH_FEDERATION_FAIL_OPEN` is inert** — recorded in poll-failure logs only; verifier behavior is always fail-closed (verifies against the last-good cached bundle).
- **Federation-poller bundles are outbound-only** — a poller-added trust domain validates outbound mTLS but is rejected inbound until the CP pushes it in a slice.
- **Live two-CP discovery round trip is verified in-process, not across real clusters** — the gRPC dialer is covered by an in-process loopback round trip against a real `MeshSubscribe` server; a true cross-cluster deployment under network churn/loss is still unverified. See [Cross-Cluster Endpoint Discovery](#cross-cluster-endpoint-discovery).

## Failure-Mode Runbook

Where to look, and what to expect, when the mesh data plane misbehaves. All slice state lives in an `ArcSwap<Option<MeshSlice>>` (lock-free hot-swap); in-flight requests always see a complete old-or-new slice, never a partial one.

| Symptom | What happens | Where to look / what to do |
|---|---|---|
| **CP unreachable at startup** | `wait_for_initial_mesh_config` blocks (via `wait_for_first_slice`) until the first valid slice arrives — the DP does not serve traffic with an empty/unprotected config. The native/xDS client retries with jittered exponential backoff (1s → 30s, ±25%) across all `FERRUM_DP_CP_GRPC_URLS`. | Confirm `FERRUM_DP_CP_GRPC_URLS`, the `FERRUM_CP_DP_GRPC_JWT_SECRET`, and DP↔CP TLS. Startup logs show the connection/backoff attempts. The DP stays NotReady until converged. |
| **CP goes down after startup** | The last-good slice is retained (ArcSwap snapshot keeps serving). No new slices arrive; the client backs off and reconnects. | `GET /mesh/config-drift` shows `slice.last_received_at` / `age_seconds` going stale; alert on `ferrum_mesh_config_last_received_timestamp_seconds`. **SVID interaction:** while disconnected, SVID rotation still proceeds via the CA backend (SPIRE Agent / internal); the federation poller and CP-pushed trust bundles do not update, so a *new* federated trust domain will not appear until the CP returns. Existing identities and bundles remain valid until their own TTLs expire. |
| **Slice rejected (invalid update)** | The update is logged (`Ignoring invalid mesh slice update` / `Ignoring invalid initial mesh slice`) and dropped; the last accepted slice keeps serving. A rejected slice never advances `config-drift` `last_received_at`/fingerprint and never alters inbound trust (staged SPIFFE bundle is dropped on rejection). Over xDS, a malformed mesh-slice carrier causes the DP to NACK the whole ECDS response and retain the previous slice. | Search logs for `Ignoring invalid` and the `mesh_slice_version` + `error`. Compare `slice.fingerprint` across DPs via `GET /mesh/config-drift` to spot split-brain. |
| **eBPF capture unavailable** | The node-agent probes kernel ≥ 5.7 + cgroup v2 + bpffs once at startup. On a miss it sets `ferrum_mesh_node_topology_degraded{reason}` to `1` (reason ∈ `kernel_too_old` / `cgroup_v1` / `bpffs_missing`) and, with the default `FERRUM_NODE_AGENT_FALLBACK_MODE=fail`, refuses to start. `=iptables` falls back to host iptables capture (needs a custom image with `/bin/sh` + `iptables`). On a build without `--features ebpf`, the orig-dst bridge logs once and exits and node-waypoint accept fails closed. | Alert on `ferrum_mesh_node_topology_degraded == 1` and node-agent readiness. See [Node Agent Mode](#node-agent-mode) and [docs/node_agent.md](node_agent.md#kernel-fallback) for the per-reason remediation table. The rest of the data plane (slice apply, `mesh_authz`, `workload_metrics`, HBONE) is unaffected by node-level capture degradation. |
| **Requests denied unexpectedly** | `mesh_authz` evaluated DENY-first then implicit-deny-on-no-ALLOW-match. | `GET /mesh/policy-denies/recent` (JWT) groups recent denies by `(rule, source, destination, reason)`; correlate with `ferrum_mesh_requests_total{response_code="403"}`. Transaction logs carry `mesh_authz.deny_policy` (e.g. `untrusted_assertor`, `trust_domain_mismatch`, `unauthenticated_baggage`) and `mesh_authz.scope_missing` (node-waypoint per-pod scope not yet enrolled). |
| **mTLS / HBONE handshake failures** | Peer cert chain or SPIFFE trust-domain validation failed, or a plaintext peer hit a STRICT listener. | `ferrum_mesh_mtls_handshake_failures_total{reason}` (`timeout` / `error`). Check that gateway SVID material (`FERRUM_GATEWAY_SVID_*`) and the slice trust bundles cover the peer's trust domain; for HBONE baggage rewrites, confirm the assertor is on `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS`. Remember PERMISSIVE-with-no-client-CA admits unauthenticated peers (see [Limitations](#limitations-and-not-supported)). |
| **Cert / CA health** | SVID rotation or CA backend problems. | `ferrum_mesh_cert_expiry_seconds`, `ferrum_mesh_cert_rotation_failures_total`, `ferrum_mesh_ca_health{ca_type}`, `ferrum_mesh_trust_bundle_version`. |

## Observability and Troubleshooting Quick Reference

### Admin introspection endpoints (all JWT-authenticated; 404 outside mesh mode / wrong topology)

| Endpoint | Purpose | Diagnose |
|---|---|---|
| `GET /mesh/config-drift` (`?include_overlay=false`) | Per-DP "where is this DP vs the CP's last push" — `slice.last_received_at`, `version`, per-kind `resources` counts, `fingerprint`, `source_protocol`/`source_cp_url`, RTDS `runtime_overlay`, and (xDS mode) the `convergence` block (per-type versions, missing required types). | Stuck DP (stale `last_received_at`), split-brain (fingerprint divergence), cross-cluster endpoint discovery (workload/service resource counts), RTDS drift, wedged xDS warming (non-empty `convergence.missing_required_types`). |
| `GET /mesh/federation` | Trust-bundle federation snapshot: per-trust-domain `bundle_age_seconds` + authority counts. | Stale / missing federated bundles for cross-cluster mTLS. |
| `GET /mesh/runtime-overlay` | Live RTDS overlay (fault percentages, transformer gates, log level). | RTDS knob propagation. |
| `GET /mesh/service-graph` | Node-local source/destination edge graph from `workload_metrics`. | Who is talking to whom (per DP; aggregate in the backend). |
| `GET /mesh/policy-denies/recent` (`?window=`, `?limit=`) | Aggregated recent `mesh_authz` denies grouped by `(rule, source, destination, reason)`. | Misconfigured `AuthorizationPolicy` / unexpected denies. |
| `GET /mesh/egress-scope` + `POST /mesh/egress-scope/test` | Resolved Sidecar egress scope: admitted/denied services + outbound-registry destinations; dry-run host/port check. | Sidecar egress narrowing before/after enabling enforcement. |
| `GET /node-waypoint/identities` (NodeWaypoint only) | Currently enrolled pod identities. | Node-waypoint enrollment / cookie resolution. |
| `GET /service-waypoint/services` (ServiceWaypoint only) | Services bound to this waypoint in the active slice. | GAMMA waypoint binding resolution. |

There is no dedicated remote-cluster discovery admin endpoint; observe cross-cluster endpoint discovery through `GET /mesh/config-drift` resource counts and the locality-aware LB behavior.

### Key metrics (`/metrics`, unauthenticated — restrict scraper reachability)

- RED: `ferrum_mesh_requests_total`, `ferrum_mesh_request_duration_ms` (carry SPIFFE identity + `connection_security_policy` labels).
- Config freshness: `ferrum_mesh_config_last_received_timestamp_seconds{namespace}`.
- Identity: `ferrum_mesh_cert_expiry_seconds`, `ferrum_mesh_cert_rotation_failures_total`, `ferrum_mesh_ca_health{ca_type}`, `ferrum_mesh_trust_bundle_version`, `ferrum_mesh_mtls_handshake_failures_total{reason}`.
- Federation: `ferrum_mesh_federation_poll_failures_total`, `ferrum_mesh_federation_last_success_timestamp_seconds`, `ferrum_mesh_federation_bundle_age_seconds`.
- Outbound policy: `ferrum_mesh_outbound_registry_decisions_total`, `ferrum_mesh_outbound_registry_stream_decisions_total{protocol, decision}`.
- Node capture: `ferrum_mesh_node_topology_degraded{reason}`, `ferrum_node_agent_pods_enrolled_total`, `ferrum_node_agent_attach_errors_total`; BPF TCP-layer counters via `__mesh_bpf_metrics` (NodeWaypoint only).

## Topologies

Mesh mode supports six topologies selected by `FERRUM_MESH_TOPOLOGY`. Each topology determines which listeners are created and how traffic is handled.

### Sidecar

Per-pod sidecar proxy deployed alongside application containers. This is the default topology.

| Listener | Address | Direction | Kind |
|---|---|---|---|
| Outbound capture | `127.0.0.1:15001` | Outbound | Plaintext capture |
| Inbound mTLS | `0.0.0.0:15006` | Inbound | mTLS termination |

The outbound listener intercepts application-originated traffic (redirected by iptables or eBPF) and routes it to the appropriate upstream. The inbound listener terminates mTLS from peer sidecars and forwards plaintext to the local application.

### Ambient

Ztunnel-style ambient mesh proxy that terminates HBONE (HTTP/2 CONNECT over mTLS) traffic. Does not require a per-pod sidecar.

| Listener | Address | Direction | Kind |
|---|---|---|---|
| Outbound capture | `127.0.0.1:15001` | Outbound | Plaintext capture |
| HBONE | `0.0.0.0:15008` | Inbound | HBONE termination |

The HBONE listener accepts HTTP/2 CONNECT streams over mTLS on port 15008. Source identity is extracted from the mTLS peer certificate and optionally from W3C Baggage headers. See [HBONE Protocol](#hbone-protocol) below.

### Node Waypoint

Node-scoped sidecarless waypoint for pods captured by the node agent. This topology uses the same HBONE listener as ambient mode, but source pod identity is resolved from the node-agent/eBPF socket-cookie record instead of assuming one proxy per workload.

| Listener | Address | Direction | Kind |
|---|---|---|---|
| HBONE | `0.0.0.0:15008` | Inbound | HBONE termination |

At accept time the proxy reads the Linux `SO_COOKIE` value and looks up the corresponding `FERRUM_ORIG_DST4` / `FERRUM_ORIG_DST6` capture record in the `NodeWaypointIdentityResolver`. The record carries the original destination, pod UID, and a stable hash of the workload SPIFFE ID. Those records are populated by the **orig-dst bridge** (`src/ebpf/orig_dst_bridge.rs`): the bridge opens the node-agent-pinned `FERRUM_ORIG_DST4/6` maps by path and mirrors each socket-cookie record into the resolver via `record_orig_dst4`/`record_orig_dst6`. **Accept-side bridge (GAP-2M, IPv4):** these records are keyed by the *source pod's connect-side* socket cookie, but at accept time the proxy resolves by the *accepted server-side* socket's `SO_COOKIE` — a different kernel socket with a different cookie (see the invariant in `src/socket_opts.rs`). The kernel `sock_ops` program bridges them: at active-established it re-keys the IPv4 orig-dst record by `(netns cookie, connection 4-tuple)`, and at passive-established it re-stamps that record under the accept-side cookie, so the resolver's cookie map is reachable from the accept path with no further proxy-side change. **IPv4 only** — both bridge paths guard on `AF_INET` because aya's IPv6 `sock_ops` ctx accessors trip the BPF verifier, so IPv6 (and the IPv6 half of dual-stack) node-waypoint accepts get no accept-side record and stay fail-closed, pending a verifier-safe v6 read. Pod-identity enrollment is wired into the same path with no separate channel: slice apply installs a `workload_spiffe_hash`→SPIFFE index that `resolve_record` hash-joins against the eBPF-stamped `(pod_uid, hash)` to lazily enroll identities (re-validated against the current slice on every resolve). This is CI compile/load-tested but unverified on a live multi-pod datapath. The eBPF `connect4`/`connect6` hooks stamp each record's pod UID and SPIFFE hash from the per-cgroup `FERRUM_WORKLOAD_IDENTITY` map the node-agent writes at enrollment (see [docs/node_agent.md](node_agent.md#ebpf-build-and-capture-what-actually-ships)). Unknown cookies, zero pod UIDs, missing workload hashes, missing pod identities, and SPIFFE-hash mismatches fail closed before TLS/HBONE processing. `/overload.node_waypoint_drops` reports per-reason counters for these fail-closed drops. On a build without `--features ebpf` the bridge logs once and exits and the resolver stays empty, so every node-waypoint accept fails closed.

**In-pod-netns outbound capture listeners.** The eBPF `connect4` hook rewrites a captured pod's outbound connection to `127.0.0.1:15001` — but that is the **pod's** loopback. A single outbound listener bound on `127.0.0.1:15001` in the host/proxy network namespace can never receive a connection on a pod's loopback, so a host-only listener would leave node-waypoint outbound capture non-functional on a real multi-pod node: the rewritten connections would be refused and scoped enforcement never engage. (The GAP-2M `sock_ops` cookie bridge also independently requires the accept socket to share the connecting pod's netns.) So in NodeWaypoint topology the mesh proxy always opens a listener — bound to pod loopback (`127.0.0.1`) on the port from `FERRUM_MESH_OUTBOUND_LISTEN_ADDR` (default port `15001`), so it agrees with the port `connect4` rewrites to; if that port is `0`, capture is disabled and the manager does not start — **inside each enrolled pod's network namespace** (via `setns(CLONE_NEWNET)` on a dedicated thread; one listener per pod netns, deduped by netns inode), so captured pod-loopback connections are accepted in the right namespace and the same-netns cookie bridge resolves the source pod identity. Pod discovery comes from a registry directory the node-agent publishes: `FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR` (default `/run/ferrum/node-waypoint-pods`) holds one file per enrolled pod (file name = pod UID, contents = the pod cgroup path), written on enrollment and removed on teardown; the proxy's `NetnsCaptureManager` polls this directory and reconciles listeners (opening on add, closing on removal). **Fail-closed listener startup:** because pod discovery and in-netns listener binds are asynchronous, a freshly enrolled pod can briefly have `connect4` rewriting to a pod-loopback port before the proxy listener exists. The node-agent still attaches `connect4` during enrollment, before marking the pod enrolled, so IPv4 egress cannot bypass `mesh_authz`; early captured connects may be refused until the listener opens, but they fail closed. `connect6` is also attached up front as a **fail-closed IPv6 denier** — the in-netns listener and sock-ops bridge are IPv4-only, so the `ipv6_outbound_deny` capture-config flag makes `connect6` return `EPERM` for captured IPv6 rather than letting that egress bypass `mesh_authz` (excluded v6 via CIDR/port excludes still flows). The proxy may write a marker `<registry_dir>/.ready/<pod_uid>` once it has opened that pod's in-netns listener; the `.ready` subdir is a dotfile and is ignored by the pod-discovery scan. The inbound `getpeername4`/`getpeername6` programs do not redirect and are still attached at enrollment. This path is Linux-only (`setns`, `/proc/<pid>/ns/net`); on non-Linux it compiles to an unsupported stub. The reconcile/registry logic is unit-tested, but the `setns`/bind path and the full pod-loopback datapath require a live multi-pod node and are **not** CI-verified — treat it as implemented, live-datapath-unverified.

Operators inspect the currently enrolled pod identities via the JWT-authenticated admin endpoint `GET /node-waypoint/identities` — see [docs/admin_api.md](admin_api.md#node-waypoint-identities-mesh-nodewaypoint-topology) for the response shape. The endpoint returns 404 outside `NodeWaypoint` topology so unrelated DPs don't surface an empty stub list.

Per-pod authorization scope is published only after a mesh slice is accepted by the proxy config apply path. Slice apply installs one `NodeWaypointSlice` generation — the `workload_spiffe_hash`→SPIFFE identity gate plus the per-pod-UID scope index (`scopes_by_pod_uid`, a `PolicyScopeCache` per workload `metadata.uid`) — via a single `ArcSwap` store, so a lock-free reader never sees a new gate paired with an old or missing scope. A pod's scope is keyed **strictly** by the exact pod UID the eBPF capture stamps; a captured pod is **never** resolved through a SPIFFE-keyed index, so pods that share a service account — and therefore one SPIFFE — but carry different labels are scoped independently (each against its own labels) instead of collapsed to the label intersection, and a pod whose workload is absent from the live slice **fails closed** (no scope) rather than borrowing a same-SPIFFE workload's labels. Scope is reclaimed by slice updates, not by identity lifecycle. `resolve_*` returns the identity and its scope from a single load. Because the snapshot is stored only after `proxy_state.update_config` accepts the slice, a rejected slice never publishes scopes.

**TCP stream scoping**: raw **TCP** stream connections through a node-waypoint proxy follow the same per-pod scoping wiring as HTTP/HBONE. The TCP stream accept loop resolves each accepted connection's `SO_COOKIE` through the shared `NodeWaypointIdentityResolver`, looks up that pod's `PolicyScopeCache`, and stamps it onto the connection context so namespace-scoped and selector-scoped `AuthorizationPolicy` DENY/ALLOW rules are enforced for the correct source pod. The **same GAP-2M bridge described above for HBONE applies here**, and is likewise **IPv4 only**: the kernel `sock_ops` program re-keys the connect-side orig-dst record under the accept-side cookie, so the resolver (populated by the `orig-dst` bridge) is now reachable from the accept path for IPv4. IPv6 TCP accepts get no accept-side cookie record (the bridge guards on `AF_INET`) and stay fail-closed. This is CI compile/load-tested but unverified on a live datapath; on any tuple/byte-order mismatch (or an IPv6 accept) no accept-side record is written and the stream resolves `None` (fail-closed, never misattributed). When the scope cannot be resolved (a GAP-2M tuple miss, no node-agent enrollment yet, non-Linux, unknown cookie, slice/identity race), `mesh_authz` falls back to its missing-scope behavior: with namespace- or selector-scoped policies configured it **fails closed** and rejects the stream (403); with only mesh-wide policies it evaluates mesh-wide normally. Either way, the transaction records `mesh_authz.scope_missing=true`. With GAP-2M implemented the wiring enforces scoped policies on IPv4 TCP streams without further proxy-side changes (pending live-datapath verification); IPv6 TCP streams remain mesh-wide-only / fail-closed until the bridge supports v6.

**UDP/DTLS limitation**: **UDP and DTLS** stream connections through a node-waypoint proxy cannot be scoped per-pod. Per-pod scoping cannot be wired for UDP without a new capture path: node-waypoint identity is keyed by the per-connection TCP socket cookie that the eBPF `connect4`/`connect6` cgroup hooks stamp with the source pod, there are no UDP capture hooks, and a UDP stream proxy demultiplexes every client off one shared frontend socket that carries a single cookie — so there is no per-source-pod cookie to resolve. Like TCP, when any namespace- or selector-scoped policy is configured mesh_authz **fails closed** on UDP/DTLS streams (403); meshes with only mesh-wide policies evaluate normally. TCP and HTTP/HBONE share the same per-pod scoping wiring (before the GAP-2M bridge they behaved like UDP/DTLS; with it implemented they scope per-pod for **IPv4** — IPv6 stays fail-closed until the bridge supports v6 — pending live-datapath verification).

#### BPF SOCK_OPS observability (GAP-SC3)

The `__mesh_bpf_metrics` plugin is auto-injected on `NodeWaypoint` topology only and surfaces the TCP-layer counters published by the `BPF_PROG_TYPE_SOCK_OPS` program. The userspace consumer (`src/ebpf/event_consumer.rs::SockOpsConsumer`) drains the per-CPU ringbuf and increments a shared `BpfMetricsState` that the plugin reads on each `/metrics` scrape. Metrics emitted (Prometheus text format):

- `ferrum_mesh_bpf_tcp_events_total{event="connect"|"accept_established"|"rst_sent"|"rst_received"|"fin_sent"|"fin_received"}` — per-TCP-event counts. Operators correlate `accept` vs `connect` rates to spot stuck pods or pre-handshake drops.
- `ferrum_mesh_bpf_drops_total{reason="bypass_uid_hit"|"exclude_cidr_hit"|"not_in_include_cidr"|"exclude_port_hit"}` — how often each BPF drop reason fired. Previously invisible.
- `ferrum_mesh_bpf_srtt_microseconds_{sum,count}`, `ferrum_mesh_bpf_syn_to_ack_microseconds_{sum,count}`, `ferrum_mesh_bpf_accept_to_first_byte_microseconds_{sum,count}` — TCP-layer latency aggregates. Operators derive averages from `sum / count`. App-layer latency stays in `workload_metrics`.
- `ferrum_mesh_bpf_ringbuf_overruns_total` + companion `ferrum_mesh_bpf_ringbuf_in_overrun_regime` gauge — ringbuf health. Non-zero overrun count means userspace fell behind and the kernel dropped events; raise `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES` or reduce event rate. The consumer also logs one `warn!` per regime entry and one `info!` on recovery — no per-event spam.

**Process split**: the node-agent owns the BPF program lifecycle — it loads `ferrum_sock_ops` from the ELF, attaches it to the cgroup root, and pins the event ringbuf + per-CPU drop counter at `/sys/fs/bpf/ferrum/sock_ops_events` and `/sys/fs/bpf/ferrum/sock_ops_stats`. The mesh-proxy in `NodeWaypoint` topology opens those pinned maps by path, drives a `tokio::io::unix::AsyncFd` poll loop, and feeds decoded records through `SockOpsConsumer::handle_event` into the shared `Arc<BpfMetricsState>` that `__mesh_bpf_metrics` reads. There is no cross-process pointer sharing — the pinned-path contract is the entire IPC surface.

When the kernel-side program is not pinned (no node-agent on the host, kernel < 5.7, or a build without the `ebpf` feature), the consumer logs one info line at startup and exits; the plugin keeps emitting a stable Prometheus surface populated by zeros so dashboards do not break. The ringbuf size is sized at BPF load time by the node-agent from `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES` (default 4 MiB) — see [docs/configuration.md](configuration.md).

### Service Waypoint

Service-scoped Ambient waypoint for Istio GAMMA traffic. Set `FERRUM_MESH_TOPOLOGY=service_waypoint` and `FERRUM_MESH_WAYPOINT_NAME=<gateway-name>`; the waypoint name is required so the control plane can project only the services bound to this waypoint.

| Listener | Address | Direction | Kind |
|---|---|---|---|
| HBONE | `0.0.0.0:15008` | Inbound | HBONE termination |

The Kubernetes translator records `MeshConfig.waypoint_bindings` from Gateway API `Gateway` resources whose `spec.gatewayClassName` is `istio-waypoint` or `ferrum-waypoint`, plus core `Service` labels. The same keys are accepted as annotations for file/native compatibility, but labels match the standard Istio enrollment shape:

- `istio.io/use-waypoint: <name>` binds a Service to the named waypoint.
- `istio.io/use-waypoint: None` opts that Service out.
- `istio.io/use-waypoint-namespace: <namespace>` points the binding at a waypoint Gateway outside the Service namespace.
- `istio.io/waypoint-for` on the Gateway or Service is stored on the binding as `service`, `workload`, `all`, or `none`; `none` produces an empty admitted set.

With the native `MeshSubscribe` protocol, the DP sends `waypoint_name` to the CP and the CP narrows `services`, `service_entries`, `destination_rules`, and dependent `workloads` to the matching binding in the request namespace. If the named binding is not known yet, the slice intentionally fails open for rollout safety; once the binding exists, an empty binding fails closed to zero services. For xDS deployments, use a control plane that already emits waypoint-scoped resources; the local xDS reconstructor can stamp the waypoint name for operability, but standard ADS does not provide Ferrum's native binding request field.

Operators inspect the currently resolved binding via the JWT-authenticated admin endpoint `GET /service-waypoint/services` — see [docs/admin_api.md](admin_api.md#service-waypoint-services-mesh-servicewaypoint-topology). The endpoint returns 404 outside `ServiceWaypoint` topology or before the first mesh slice is installed.

### East-West Gateway

Multi-cluster SNI-routed passthrough gateway. Does not create listeners directly; instead materializes passthrough TCP proxies from `MultiClusterConfig.east_west_gateways` entries.

All east-west traffic flows through a shared TCP passthrough listener on port 15443 (configurable via `FERRUM_MESH_EAST_WEST_LISTEN_PORT`). Routing is by TLS SNI hostname. The gateway does not terminate TLS -- it passes encrypted bytes directly to the backend cluster.

### Egress Gateway

Controlled egress proxy for mesh-to-external traffic. Materializes HTTP-family proxies (sharing the egress listener at 15090 with mTLS termination) and stream-family TCP proxies (each on its own listener bound to the ServiceEntry's destination port) from `ServiceEntry` resources with `location: mesh_external`. See the "Egress Gateway" section below for materialization rules.

| Listener | Address | Direction | Kind |
|---|---|---|---|
| mTLS inbound | `0.0.0.0:15090` | Inbound | mTLS termination |

Sidecars route external traffic to the egress gateway over mTLS. The gateway terminates mTLS, evaluates authorization policies, and forwards to the external backend. Requires frontend TLS certificates and a client CA for mTLS verification.

## Configuration Consumption

Mesh mode consumes configuration from a Control Plane via one of two protocols, selected by `FERRUM_MESH_CONFIG_PROTOCOL`.

### Native MeshSubscribe (default)

The Ferrum-native protocol uses the `MeshConfigSync.MeshSubscribe` gRPC streaming RPC defined in `proto/ferrum.proto`. The CP pushes complete `MeshSlice` JSON payloads whenever configuration changes. The mesh node sends its identity (node ID, namespace, SPIFFE ID, workload labels) in the subscribe request so the CP can filter resources by scope.

- **Multi-CP failover**: ordered list of CP URLs in `FERRUM_DP_CP_GRPC_URLS`. Jittered exponential backoff (1s initial, 30s max, +/-25% jitter) per URL. Primary retry interval configurable via `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`.
- **Authentication**: JWT HS256 in gRPC `authorization` metadata, using `FERRUM_CP_DP_GRPC_JWT_SECRET`.
- **Transport security**: same TLS configuration as CP/DP mode (see [cp_dp_mode.md](cp_dp_mode.md)).
- **No-op suppression**: `MeshSlice::content_eq()` skips updates that do not change mesh-relevant fields (ignoring the transport version stamp).

### xDS ADS

Aggregated Discovery Service client over the Envoy ADS gRPC service path. Consumes CDS, EDS, LDS, RDS, SDS, ECDS, and RTDS resource types via state-of-the-world mode with incremental version tracking. ECDS is subscribed after the baseline types as a richer-semantics overlay (see the carrier bullets below) and RTDS is subscribed last as a runtime-knob overlay (see the RTDS bullet below); the slice still applies if either overlay returns no resources.

**This is NOT a stock-Envoy / third-party-Istio-interoperable xDS feed.** A Ferrum CP talks to a Ferrum DP. The CDS/EDS/LDS/RDS resources Ferrum exchanges are name-only (service/port discovery) and use Ferrum-shaped names such as `cluster/{namespace}/{service}/{port}`; they carry none of the security- or policy-bearing slice fields. To reach native-config parity, the CP additionally emits the full slice — authorization policies, PeerAuthentication mTLS posture, effective workload labels for selector matching, RequestAuthentication/JWT rules, ServiceEntry shape, SPIFFE trust bundles, ProxyConfig, per-pod workloads, MeshService protocol/workload-ref shape, sidecar egress-scope metadata, and outbound traffic policy — as a set of **Ferrum-specific ECDS carriers** (see [Ferrum mesh-slice ECDS carriers](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds) below). A stock Envoy or Istio control plane neither emits these carriers nor uses Ferrum's name format, so pointing Ferrum's xDS client at a non-Ferrum CP is unsupported and may be NACKed before any fallback slice can be built.

- **Full-parity carriers**: the security- and policy-bearing slice fields plus effective workload labels ride the ECDS stream as Ferrum carriers. A slice built over xDS is **functionally equivalent** to one built over `native` (same authz / mTLS / JWT / trust-bundle / ServiceEntry / ProxyConfig / workload-selector behavior). See [Ferrum mesh-slice ECDS carriers](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds).
- **Resource warming (make-before-break)**: the DP tracks each resource type's `version_info` independently but requires one coherent version across CDS/EDS/LDS/RDS/ECDS before applying. Once every required type has delivered the same version (ECDS included, so the first slice is never the name-only, unprotected view) and the converged set is internally consistent, the DP builds and applies the slice; the previous slice keeps serving through the runtime `ArcSwap` until the replacement is ready, so a partial set never blackholes traffic and a version-skewed set never mixes new routing with stale ECDS policy. Because ECDS carries security-critical policy, a policy/workload-only ECDS update also force-re-sends subscribed required CDS/EDS/LDS/RDS resources with the new snapshot version. See [xDS ADS Compatibility](#xds-ads-compatibility).
- **25ms debounce** on slice application to batch rapid resource updates (a CP that streams a burst of per-type responses for one logical change is collapsed into a single apply, capped at 500ms).
- **Multi-CP failover**: same URL list and backoff as native mode.
- **Node identity**: `FERRUM_MESH_XDS_NODE_CLUSTER` sets the `node.cluster` field in DiscoveryRequest (defaults to `FERRUM_NAMESPACE`).
- **Connect timeout**: `FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS` (default 10).
- **DestinationRule support across xDS**: standard CDS/EDS bakes DR traffic policy (LB algorithm, outlier detection, connection pool, subsets) into the Envoy `Cluster` resource at the CP, so the original DR is not recoverable from CDS/EDS alone. The Ferrum CP ships the full DR via its own ECDS carrier (see [ECDS DestinationRule carrier](#ecds-destinationrule-carrier-full-dr-semantics-over-xds)); native protocol carries it too. Both produce identical DR semantics on the DP.
- **RTDS subscription** (`type.googleapis.com/envoy.service.runtime.v3.Runtime`): subscribed alongside CDS/EDS/LDS/RDS/SDS/ECDS so operators can flip runtime knobs without churning the entire slice. The xDS client decodes every layer through `translate_rtds_layer`, merging top-level fields into a single `MeshRuntimeOverlay` carried on `MeshSlice.runtime_overlay`. Supported value kinds: numeric (`f64`), string, bool, and Envoy `FractionalPercent`-shaped structs (`{numerator, denominator: HUNDRED | TEN_THOUSAND | MILLION}`). Other struct, list, and null values are silently dropped. The overlay is exposed via `GET /mesh/runtime-overlay` for inspection and fans out on every proxy-accepted slice to the consumers documented in the "[xDS ADS Compatibility](#xds-ads-compatibility)" section below (fault injection rates, request/response transformer gates, and the gateway-wide tracing log level).

#### Ferrum mesh-slice ECDS carriers (full parity over xDS)

The name-only CDS/EDS/LDS/RDS resources Ferrum exchanges round-trip service-port discovery only. Every security- and policy-bearing slice field plus the effective workload labels used for selector matching — authorization policies, PeerAuthentication mTLS posture, RequestAuthentication/JWT rules, full ServiceEntry shape, SPIFFE trust bundles, ProxyConfig, per-pod workloads, MeshService protocol/workload-ref shape, telemetry resources, multi-cluster config, sidecar egress-scope metadata, and mesh-wide outbound traffic policy — rides the ECDS stream as a **Ferrum mesh-slice carrier**. Without these, `FERRUM_MESH_CONFIG_PROTOCOL=xds` produced an **unprotected mesh**: the DP rebuilt the slice with every one of those fields emptied or contextless (no authz → implicit allow-all; no PeerAuthentication → Permissive on every port; no trust bundles → no inbound mTLS authority material; no effective labels → selector-scoped policy stops matching).

This is the same mechanism as the [DestinationRule carrier](#ecds-destinationrule-carrier-full-dr-semantics-over-xds): each non-empty slice field group is JSON-serialized and wrapped in a standard `envoy.config.core.v3.TypedExtensionConfig` whose **inner** `type_url` is a Ferrum-specific marker under `type.googleapis.com/ferrum.config.extension.v3.*`. The single source of truth for the markers and their encode/decode is `src/xds/carrier.rs` (`MeshSliceCarrier`); the CP emits them in `translate_mesh_slice_carriers` (`src/xds/translator.rs`) and the DP decodes them in `reverse_translate` (`src/modes/mesh/config_consumer/xds_client.rs`).

| Slice field | Inner `type_url` (suffix after `type.googleapis.com/ferrum.config.extension.v3.`) | ECDS resource name |
| --- | --- | --- |
| `services` (full `MeshService`) | `ServicesCarrier` | `ferrum-mesh-carrier/services` |
| `workloads` (per-pod endpoints) | `WorkloadsCarrier` | `ferrum-mesh-carrier/workloads` |
| `labels` (effective workload labels) | `WorkloadLabelsCarrier` | `ferrum-mesh-carrier/workload-labels` |
| `mesh_policies` (authz) | `MeshPoliciesCarrier` | `ferrum-mesh-carrier/mesh-policies` |
| `peer_authentications` | `PeerAuthenticationsCarrier` | `ferrum-mesh-carrier/peer-authentications` |
| `request_authentications` (JWT) | `RequestAuthenticationsCarrier` | `ferrum-mesh-carrier/request-authentications` |
| `service_entries` (full shape) | `ServiceEntriesCarrier` | `ferrum-mesh-carrier/service-entries` |
| `telemetry_resources` | `TelemetryResourcesCarrier` | `ferrum-mesh-carrier/telemetry-resources` |
| `proxy_configs` | `ProxyConfigsCarrier` | `ferrum-mesh-carrier/proxy-configs` |
| `trust_bundles` (SPIFFE) | `TrustBundlesCarrier` | `ferrum-mesh-carrier/trust-bundles` |
| `outbound_traffic_policy` | `OutboundTrafficPolicyCarrier` | `ferrum-mesh-carrier/outbound-traffic-policy` |
| `multi_cluster` | `MultiClusterCarrier` | `ferrum-mesh-carrier/multi-cluster` |
| `sidecar_egress_scope` | `SidecarEgressScopeCarrier` | `ferrum-mesh-carrier/sidecar-egress-scope` |

**Behavior and fail-closed.** The CP always emits these alongside CDS/EDS (no env var gate), and the DP waits for the initial ECDS response before building a slice so startup cannot briefly apply the name-only, unprotected view. On the DP, a mesh-slice carrier must have both the reserved ECDS resource name and the matching inner `type_url`: a recognized pair overwrites the corresponding slice field; an unrecognized inner type (the DR carrier, or an operator's own extension config) is skipped; a reserved inner type under any other resource name is `warn!`-logged and skipped so operator-defined ECDS configs cannot impersonate security/policy carriers. A recognized carrier whose JSON fails to parse is FAIL-CLOSED: `MeshSliceCarrier::decode` returns `Err`, `recover_slice_carriers` propagates it, and the DP NACKs the entire ECDS response and retains the previous accepted slice — it does NOT skip the malformed carrier and continue with a partially populated slice. CDS/EDS service-port discovery still runs; the DP **prefers** the full `services`/`service_entries` recovered from carriers and falls back to the name-only CDS/EDS reconstruction only when no slice carrier is present at all (e.g. an internal Ferrum-shaped test CP with no carrier support). Empty `Vec`/`None` field groups emit no carrier, so "absent" and "empty" are indistinguishable on the DP — matching native, where an empty list and an absent list are equivalent. Effective workload labels are the exception: the CP emits `WorkloadLabelsCarrier` even when the label map is empty, because empty labels are meaningful selector context and must override any local DP labels during xDS recovery. Operator-defined `MeshExtensionConfig` entries whose names start with `ferrum-mesh-carrier/` or whose inner `type_url` is one of the mesh-slice carrier markers are skipped by the Ferrum CP for the same reason.

**Interop boundary.** A stock Envoy or third-party Istio control plane does not emit these inner type URLs or Ferrum-shaped resource names, so it cannot drive a protected Ferrum mesh over xDS. The carrier format is a Ferrum-to-Ferrum wire convention layered on the standard ECDS transport; it is **not** an interoperable third-party xDS extension. For full DR/policy parity, run a Ferrum CP (either protocol works) or use `FERRUM_MESH_CONFIG_PROTOCOL=native`.

**Test pin.** `xds_round_trip_preserves_protected_slice_fields()` in `src/modes/mesh/config_consumer/xds_client.rs` drives the real CP-encode → ECDS-on-the-wire → DP-decode path for a representative protected slice (authz + PeerAuthentication + ServiceEntry + trust bundle + JWT + ProxyConfig + workloads) and asserts the recovered slice equals the native one field-for-field, including resolved mTLS posture. `tests/conformance/xds_type_urls.rs` pins the carrier type-URL set.

#### ECDS DestinationRule carrier (full DR semantics over xDS)

Standard CDS/EDS bakes a `DestinationRule`'s traffic policy (LB algorithm, outlier detection, connection pool, per-subset TLS, subsets) into the Envoy `Cluster` resource at the CP, which means the original DR is unrecoverable from CDS/EDS alone. The ECDS DestinationRule carrier preserves the original DR JSON inside a standard ECDS `TypedExtensionConfig` resource so the Ferrum DP can rebuild the full `MeshDestinationRule` server-side. This is a Ferrum-specific carrier convention layered on top of the standard ECDS resource type — it uses the standard ECDS transport (`type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig`) but a Ferrum-defined inner type URL, so it coexists with unrelated ECDS consumers on the same ADS stream.

The DP recognizes the carrier by an exact match on the inner `type_url` constant:

```
type.googleapis.com/ferrum.config.extension.v3.DestinationRuleCarrier
```

(defined as `FERRUM_ECDS_DESTINATION_RULE_TYPE_URL` in `src/xds/translator.rs`).

**Envelope shape.** Each DR is one ECDS resource on the wire. The CP wraps an `envoy.config.core.v3.TypedExtensionConfig` message with the carrier marker on its inner `Any`:

```
ECDS resource (Any)
  type_url = "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig"
  value    = encoded TypedExtensionConfig {
    name         = "<dr-name>"               # informational, used in DP logs
    typed_config = Any {
      type_url = "type.googleapis.com/ferrum.config.extension.v3.DestinationRuleCarrier"
      value    = <raw bytes of the original MeshDestinationRule JSON>
    }
  }
```

The inner `value` is the original DR document as UTF-8 JSON bytes — there is no protobuf wire encoding of the DR itself, just `serde_json` over the `MeshDestinationRule` shape consumed by the DP at `src/modes/mesh/config_consumer/xds_client.rs` (see `dr_carrier_resource()` and the recovery loop). The DP iterates ECDS resources, decodes each `TypedExtensionConfig`, and applies one of three behaviors per inner payload:

- Inner `type_url` matches the carrier constant and JSON parses cleanly: the recovered `MeshDestinationRule` is appended to `slice.destination_rules`.
- Inner `type_url` is anything else: silently skipped (belongs to an unrelated ECDS consumer).
- Inner `type_url` matches the carrier constant but JSON fails to parse: the DR is skipped with a `warn!` and the rest of the slice still applies — bad payloads do not fail the whole slice.

**Worked example.** Given this original DestinationRule:

```yaml
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: api-dr
  namespace: default
spec:
  host: api.default.svc.cluster.local
  trafficPolicy:
    loadBalancer:
      simple: ROUND_ROBIN
    outlierDetection:
      consecutive5xxErrors: 5
      interval: 30s
    connectionPool:
      tcp:
        connectTimeout: 2s
    tls:
      mode: ISTIO_MUTUAL
      sni: api.default.svc.cluster.local
  subsets:
    - name: v1
      labels:
        version: v1
```

the CP must emit one ECDS resource whose decoded `TypedExtensionConfig` looks like:

```json
{
  "name": "api-dr",
  "typed_config": {
    "type_url": "type.googleapis.com/ferrum.config.extension.v3.DestinationRuleCarrier",
    "value": "<UTF-8 bytes of the MeshDestinationRule JSON below>"
  }
}
```

with the inner `value` bytes carrying the original DR as `MeshDestinationRule` JSON (note: the inner shape is the Ferrum `MeshDestinationRule` serde representation, not the Istio CRD YAML — Istio's nested `connectionPool.tcp.connectTimeout` flattens to `traffic_policy.connect_timeout_ms` in milliseconds, `outlierDetection.consecutive5xxErrors` → `outlier_detection.consecutive_errors`, `outlierDetection.interval` (a duration string) → `outlier_detection.interval_seconds` (a `u64`), and `tls.mode` values are lowercase `snake_case` (`istio_mutual`, `simple`, `mutual`, `disable`) per `MtlsMode`):

```json
{
  "name": "api-dr",
  "namespace": "default",
  "host": "api.default.svc.cluster.local",
  "traffic_policy": {
    "connect_timeout_ms": 2000,
    "load_balancer": {"simple": "ROUND_ROBIN"},
    "outlier_detection": {"consecutive_errors": 5, "interval_seconds": 30},
    "tls": {"mode": "istio_mutual", "sni": "api.default.svc.cluster.local"}
  },
  "subsets": [{"name": "v1", "labels": {"version": "v1"}}]
}
```

The DP recovers this back into a `MeshDestinationRule` with `traffic_policy.load_balancer = Simple(RoundRobin)`, `outlier_detection` (consecutive-error + interval), `traffic_policy.connect_timeout_ms` projected onto `Proxy.backend_connect_timeout_ms` (and per-port settings onto `Upstream.port_overrides[port].connect_timeout_ms`), the `tls` block, and the `v1` subset all intact — i.e. every field that would have been baked out by a CDS-only path round-trips. Non-carrier ECDS resources sharing the same response are unaffected, so the channel can be shared with unrelated extension consumers.

**Opt-in and the per-slice diagnostic.** Emission is purely CP-side opt-in — the DP always subscribes ECDS, but a CP that only emits CDS/EDS is fully supported. When the DP receives a slice with CDS clusters but zero carrier ECDS resources, it emits a single one-line `debug!` per slice apply listing the fields that cannot be round-tripped from CDS/EDS alone (`connectTimeout`, `loadBalancer`, `outlierDetection`, `subsets`, `tls.sni`, `tls.subjectAltNames`, `tls.mode`); see the `debug!` guarded by `!dr_carrier_seen && !accumulator.resources(CDS_TYPE_URL).is_empty()` in `src/modes/mesh/config_consumer/xds_client.rs`. Emitting any carrier resource silences that log for the slice.

**Other notes.**

- Configuration: no `FERRUM_MESH_*` env var gates the carrier path. The DP recognizes the marker whenever `FERRUM_MESH_CONFIG_PROTOCOL=xds`; turning the path on is a CP-authoring decision.
- Test pin: `ecds_dr_carrier_payload_recovers_destination_rule()` in `src/modes/mesh/config_consumer/xds_client.rs` round-trips the envelope and asserts that `traffic_policy.load_balancer` survives — i.e. fields baked out by a CDS-only path are recovered.

### Bootstrap Behavior

Both protocols share the same startup contract:

1. The mesh data plane waits for an initial valid slice before serving traffic.
2. Valid updates are applied atomically via `ArcSwap`.
3. Invalid updates are logged and ignored; the last accepted configuration continues serving.
4. On config source unavailability, the gateway keeps serving cached configuration (resilience principle).

## Mesh Data Model

The mesh data model lives in `src/modes/mesh/config.rs`. All types carry `namespace` for scope isolation and use `#[serde(default)]` so non-mesh `GatewayConfig` round-trips byte-identical.

### Workload

The unit of identity. Every SPIFFE SVID is issued to one workload.

```yaml
spiffe_id: "spiffe://cluster.local/ns/default/sa/my-service"
selector:
  labels:
    app: my-service
service_name: "my-service"
addresses: ["10.0.1.5"]
ports:
  - port: 8080
    protocol: http
    name: http
trust_domain: "cluster.local"
namespace: "default"
```

### MeshService

Logical service grouping workloads by SPIFFE ID reference.

```yaml
name: "my-service"
namespace: "default"
ports:
  - port: 8080
    protocol: http
workloads:
  - spiffe_id: "spiffe://cluster.local/ns/default/sa/my-service"
```

### MeshPolicy

Identity-based authorization policy (mirrors Istio `AuthorizationPolicy`).

```yaml
name: "deny-unauthenticated"
namespace: "default"
scope:
  kind: namespace
  namespace: "default"
rules:
  - from:
      - spiffe_id_pattern: "spiffe://cluster.local/ns/*/sa/*"
    to:
      - methods: ["GET", "POST"]
        paths: ["/api/*"]
    action: allow
```

### ServiceEntry

External service registration for DNS resolution and egress materialization.

```yaml
name: "external-api"
namespace: "default"
hosts: ["api.external.com"]
endpoints:
  - address: "203.0.113.10"
resolution: static
location: mesh_external
ports:
  - port: 443
    protocol: tls
export_to: ["*"]
```

### PeerAuthentication

Per-workload mTLS mode with optional per-port overrides.

### MeshRequestAuthentication

Declares valid JWTs for a workload scope. Permissive by default (see [RequestAuthentication](#requestauthentication)).

### MeshTelemetryResource

Per-scope telemetry configuration for tracing, metrics, and access logging (see [Observability](#observability)).

### MeshProxyConfig (Istio ProxyConfig)

Maps an Istio `ProxyConfig` (`networking.istio.io/v1beta1`) onto a config-time, read-only data structure consumed by the mesh runtime at slice-apply time. ProxyConfig has **no data-plane request-path impact** — it shapes startup posture (concurrency, image, environment variables) and tracing sampling.

```yaml
name: "api-defaults"
namespace: "default"
scope:                  # resolved from spec.selector + Istio root-namespace rule
  workload_selector:
    selector:
      labels: { app: "api" }
      namespace: "default"  # absent when the resource lives in the Istio root namespace
concurrency: 4          # spec.concurrency (informational; rejected if outside u32 range)
image: "distroless"     # spec.image.imageType (informational)
environment:            # spec.environmentVariables (informational)
  GOMAXPROCS: "4"
tracing_sampling: 42.5  # spec.tracing.sampling — percentage 0-100
```

**Honored fields**:

| Istio field | MeshProxyConfig field | Notes |
|---|---|---|
| `metadata.name` | `name` | |
| `metadata.namespace` | `namespace` | |
| `spec.selector` + root-namespace rule | `scope` ([`PolicyScope`](#policyscope)) | See "Scope resolution" below — same semantics as Telemetry / PeerAuthentication |
| `spec.concurrency` | `concurrency` | Informational; rejected as `InvalidResource` if it does not fit in `u32` |
| `spec.image.imageType` | `image` | Informational; surfaced to operator tooling |
| `spec.environmentVariables` | `environment` | Informational; surfaced to operator tooling |
| `spec.tracing.sampling` | `tracing_sampling` | Percentage 0-100; merged into the injected `workload_metrics` plugin's `sampling_percentage` |

**Scope resolution**: ProxyConfig honors the same Istio root-namespace + selector rules used by `Telemetry`, `RequestAuthentication`, and `PeerAuthentication`. The K8s translator routes through the shared `istio_policy_scope` helper, so [`scope`](../src/modes/mesh/config.rs) ends up as:

- `MeshWide` — resource in the Istio root namespace (`FERRUM_K8S_ISTIO_ROOT_NAMESPACE`, default `istio-system`) with no selector. Applies to every workload in the mesh.
- `WorkloadSelector { namespace: None, labels: ... }` — resource in the Istio root namespace with a selector. Applies to matching workloads across all namespaces.
- `Namespace { namespace }` — resource in any other namespace with no selector. Applies to all workloads in that namespace.
- `WorkloadSelector { namespace: Some(ns), labels: ... }` — resource in any other namespace with a selector. Applies to matching workloads in that namespace.

Within the resolved slice, [`MeshSlice::resolved_proxy_config()`](../src/modes/mesh/slice.rs) returns the most-specific applicable entry:

1. `WorkloadSelector` > `Namespace` > `MeshWide`.
2. Among same-tier matches, the ASCII-smallest `name` wins (deterministic tiebreaker mirroring the accumulator's `(namespace, name)` sort).

**`tracing.sampling` merge with `Telemetry`**: ProxyConfig `tracing_sampling` is applied first as a baseline, then `Telemetry.tracing.randomSamplingPercentage` overrides on the same `sampling_percentage` key when both are present. The more granular Telemetry API wins because it can be per-section scoped; ProxyConfig provides a per-workload-config-level default.

**xDS protocol**: ProxyConfig is config-time and not exposed via standard xDS. Operators relying on ProxyConfig translation must use `FERRUM_MESH_CONFIG_PROTOCOL=native`.

### TrustBundleSet

Local and federated X.509/JWT authority bundles for cross-cluster trust.

### MultiClusterConfig

Multi-cluster settings: local cluster identity, remote clusters, east-west gateways, and SPIFFE federation endpoints.

### MeshDestinationRule

Maps an Istio `DestinationRule` onto Ferrum's existing `Upstream` / `PassiveHealthCheck` / `LoadBalancerAlgorithm` primitives. Applied at slice-apply time in `prepare_normalized_gateway_config_for_mesh()` after upstream materialization.

```yaml
name: "reviews-policy"
namespace: "default"
host: "reviews.default.svc.cluster.local"
traffic_policy:
  connect_timeout_ms: 5000
  outlier_detection:
    consecutive_errors: 5
    interval_seconds: 10
    base_ejection_seconds: 30
    max_ejection_percent: 50
  load_balancer:
    consistent_hash:
      http_header_name: "x-user-id"
subsets:
  - name: "v1"
    labels:
      version: "v1"
```

**Host matching**: the DR `host` is matched against upstream targets, the upstream `name`, and the upstream `id`. Short hostnames are namespace-completed (`reviews` ⇒ `reviews.{namespace}.svc.*`); namespaced (`reviews.ns`) and `.svc`-suffixed forms are also supported. Cross-namespace matches require the FQDN form because slice filtering already restricts DRs to the subscriber's namespace.

**Multiple DRs targeting the same upstream**: applied in deterministic `(namespace, name)` order — the alphabetically last entry wins, last-writer-wins per field. Operators see `debug!` log lines when subsets or proxy `backend_connect_timeout_ms` get overwritten.

**Support matrix** (canonical Istio field → Ferrum target). The auto-generated machine-readable view of this table — plus VirtualService, AuthorizationPolicy, PeerAuthentication, ServiceEntry, and xDS coverage — lives in `target/conformance/coverage.md` after `cargo test --test conformance_tests`. See [CONFORMANCE.md](../CONFORMANCE.md#istio--xds-conformance-suite) for how to run the suite and how the status enum works.

| Istio field | Status | Notes |
|---|---|---|
| `host` | Supported | Required, lowercased at admission, empty/dot-only rejected |
| `trafficPolicy.connectionPool.tcp.connectTimeout` | Supported | Applied to `Proxy.backend_connect_timeout_ms` for every proxy referencing the matching upstream |
| `trafficPolicy.outlierDetection.consecutive5xxErrors` / `consecutiveErrors` | Supported | → `PassiveHealthCheck.unhealthy_threshold` |
| `trafficPolicy.outlierDetection.interval` | Supported | → `PassiveHealthCheck.unhealthy_window_seconds` (zero filtered out, sub-second rounded up) |
| `trafficPolicy.outlierDetection.baseEjectionTime` | Supported | → `PassiveHealthCheck.healthy_after_seconds` |
| `trafficPolicy.outlierDetection.maxEjectionPercent` | Supported | → `PassiveHealthCheck.max_ejection_percent`; values >100 rejected |
| `trafficPolicy.loadBalancer.simple = ROUND_ROBIN` | Supported | → `LoadBalancerAlgorithm::RoundRobin` |
| `trafficPolicy.loadBalancer.simple = LEAST_REQUEST` / `LEAST_CONN` | Supported | → `LoadBalancerAlgorithm::LeastConnections` |
| `trafficPolicy.loadBalancer.simple = RANDOM` | Supported | → `LoadBalancerAlgorithm::Random` |
| `trafficPolicy.loadBalancer.simple = PASSTHROUGH` | Approximated (warns) | → `RoundRobin`; Ferrum cannot preserve the original destination IP |
| `trafficPolicy.loadBalancer.simple = MAGLEV` | Rejected | Hard error at translate time |
| `trafficPolicy.loadBalancer.consistentHash.{httpHeaderName,httpCookie.name,useSourceIp}` | Supported | Exactly one of the three required (rejected otherwise); → `LoadBalancerAlgorithm::ConsistentHashing` + `Upstream.hash_on` |
| `subsets[].name` / `subsets[].labels` | Supported | → `SubsetDefinition` entries on the upstream; second DR overwrites the first |
| `subsets[].trafficPolicy.loadBalancer` | Supported | → `SubsetTrafficPolicy.load_balancer_algorithm` |
| `subsets[].trafficPolicy.tls` | Supported | → `SubsetTrafficPolicy.tls` (nests `MeshTrafficPolicyTls`). Cold-path `resolve_subset_traffic_policy_tls` layers the subset's TLS overlay (mode / SNI / CA / mTLS material / SAN allow-list / `insecureSkipVerify`) onto the upstream-level TLS and stores the result on `Upstream.resolved_subset_tls[subset_name]`. `GatewayConfig::resolve_upstream_tls` then projects that overlay onto `Proxy.resolved_tls` for proxies whose `upstream_subset` selects this subset — so v1 and v2 subsets with different CAs land on different `Proxy.resolved_tls` values and partition the backend pool. `upstream_subset` also enters HTTP / H2 / gRPC / H3 pool keys as a defense-in-depth backstop on top of TLS partitioning. Subsets without `trafficPolicy.tls` fall back to upstream-level TLS, identical to today's behavior. |
| `subsets[].trafficPolicy.connectionPool.tcp.connectTimeout` | Supported | Overrides `backend_connect_timeout_ms` for proxies bound to the subset (precedence over the DR top-level connectTimeout). Other per-subset `connectionPool` fields are still ignored (warns). |
| `subsets[].trafficPolicy.outlierDetection` | Supported (thresholds) | Ejection thresholds (consecutive errors / interval / base-ejection / min-health) applied per-subset, overriding upstream-level passive health for subset-bound proxies (`passive_health_for_target`). The `maxEjectionPercent` cap is still resolved at the upstream level. |
| `trafficPolicy.connectionPool.http.maxRequestsPerConnection` | Supported (wire-projected, runtime pending) | Lands on `Upstream.port_overrides[port].http_max_requests_per_connection` and projects onto `Proxy.pool_max_requests_per_connection` via the per-target effective proxy. Hyper does not yet expose a stable close-after-N-requests builder knob, so the field is admitted, persisted, and routed end-to-end through the dispatch path — but it has no live runtime effect. Tracked as a follow-on (would light up automatically once hyper grows the knob or a request-count wrapper is added). Top-level fan-out applies to every target port; per-port `portLevelSettings` overrides per-port. Zero/negative values rejected at translate time. Because pool keys exclude policy fields, when the field activates the same "first proxy to materialise the pool entry wins" tradeoff documented for `idleTimeout` will apply — proxies needing strict per-proxy isolation should fragment via `dns_override`. |
| `trafficPolicy.connectionPool.http.idleTimeout` | Supported (HTTP-family) | Lands on `Upstream.port_overrides[port].http_idle_timeout_ms` and projects onto `Proxy.pool_idle_timeout_seconds` for the per-target effective proxy, which threads into the reqwest/H2 client pool idle timeout. Sub-second durations are rejected at translate time because `pool_idle_timeout_seconds` is whole-second granular; values above `MAX_POOL_IDLE_TIMEOUT` (1 hour) are also rejected so the K8s surface stays consistent with the admin admit-path validator. Top-level fan-out applies to every target port; per-port `portLevelSettings` overrides per-port. Because pool keys exclude policy fields, two proxies that resolve to the same pool entry but configure different per-port idle timeouts will have the first proxy to materialise the entry win for the shared `reqwest::Client` — same cross-proxy sharing tradeoff documented for `backend_connect_timeout_ms` (operators who need strict isolation fragment via `dns_override`). |
| `trafficPolicy.connectionPool.http.http2MaxRequests` | Supported (HTTP-family) | Lands on `Upstream.port_overrides[port].h2_max_concurrent_streams` and projects onto `Proxy.pool_http2_max_concurrent_streams` via the per-target effective proxy. Threads into the direct H2 (`src/proxy/http2_pool.rs`) and gRPC (`src/proxy/grpc_proxy.rs`) builders as both `http2::Builder::max_concurrent_streams` (peer SETTINGS) and `initial_max_send_streams` (local outbound-stream initial cap). Reqwest's H2 path does not expose the same builder knobs today. Top-level fan-out applies to every target port; per-port `portLevelSettings` overrides per-port. Zero/negative values rejected at translate time. Same first-proxy-wins tradeoff as `idleTimeout`: the direct-H2 / gRPC pool keys exclude policy fields, so two proxies that share `(host, port, TLS)` but configure different per-port H2 caps share the first connection materialised with the first proxy's cap — operators wanting strict per-proxy isolation fragment via `dns_override`. |
| `trafficPolicy.connectionPool.http.http1MaxPendingRequests` / `maxRetries` / `h2UpgradePolicy` | Ignored (warns + status `deferred_fields`) | Deferred T1-C follow-on. The translator parses the rule successfully so operators can keep their CRDs unchanged, emits an operator-visible warning acknowledging the field was seen, and otherwise drops it. When the Istio controller is active these fields are also surfaced in the DestinationRule `status.ferrum.translation.deferred_fields` block (see "Istio CRD Status") so the gap shows up in `kubectl describe`. `http1MaxPendingRequests` needs reqwest-side queue tracking; `maxRetries` overlaps with `Proxy.retry`; `h2UpgradePolicy` is cross-cutting with the backend capability registry. |
| `trafficPolicy.connectionPool.tcp.maxConnections` | Supported (stream-family + HTTP-family WebSocket) | Cap on concurrent open backend connections per target, enforced via a per-`(host, port)` CAS-bumped counter on `Upstream.port_overrides[port].max_connections`. **Stream-family** (TCP / TCP+TLS / TCP-passthrough) enforces it at backend dial; exceeding the cap returns a typed `StreamSetupKind::BackendMaxConnectionsExceeded` (logged as `Backend maxConnections reached`) and the relay retry loop tries another LB target if `RetryConfig.retry_on_connect_failure` is enabled. **HTTP-family WebSocket** (H1/H2 in `src/proxy/mod.rs` and H3 in `src/http3/websocket.rs`) also enforces it: a proxied WebSocket opens one dedicated backend connection whose lifetime equals the session, so an RAII guard (`src/backend_conn_limit.rs::BackendConnectionGuard`) held on `ProxyState.backend_conn_limit` for the session bounds concurrent open connections per destination; exceeding the cap rejects the upgrade with `503` (`rejection_phase=backend_max_connections`) before dialing, and a closed/failed session releases its slot (no leak). The pooled, multiplexed HTTP transports (reqwest H1/H2, direct H2, gRPC, HTTP/3, HBONE) do **not** enforce the field — see the "DestinationRule `maxConnections` enforcement scope" note below for why. Top-level fan-out applies to every target port; per-port `portLevelSettings.connectionPool.tcp.maxConnections` overrides the fan-out for that specific port. `maxConnections <= 0` is rejected at translate time. |
| `trafficPolicy.connectionPool.tcp.tcpKeepalive` (`time` / `interval` / `probes`) | Supported (stream-family only) | Each subfield independently optional. Applied via `setsockopt(SO_KEEPALIVE)` + `TCP_KEEPIDLE` (Linux) / `TCP_KEEPALIVE` (macOS/iOS) for `time`, `TCP_KEEPINTVL` for `interval`, `TCP_KEEPCNT` for `probes`. Set on the backend socket right after `connect()` on TCP / TCP+TLS / TCP-passthrough paths. Best-effort: a `setsockopt` failure logs a `warn!` and continues rather than aborting the connection. Sub-second durations and zero values are rejected at translate time because the underlying socket options are second-granular and require at least one probe. HTTP-family / gRPC / WebSocket / HBONE / H3 dispatch ignores the field — follow-on PR. |
| `trafficPolicy.tls` | Supported | Overrides the `PeerAuthentication`-derived backend posture per matching `Upstream` when set. Mode mapping: `DISABLE` → clears `Upstream.backend_tls_*`; `SIMPLE` → enables server-cert verify + `backend_tls_server_ca_cert_path = caCertificates` (client cert/key cleared); `MUTUAL` → enables server-cert verify + projects `caCertificates`/`clientCertificate`/`privateKey` onto `Upstream.backend_tls_server_ca_cert_path`/`_client_cert_path`/`_client_key_path`; `ISTIO_MUTUAL` → enables server-cert verify + projects the workload SVID paths from `FERRUM_GATEWAY_SVID_CERT_PATH` / `FERRUM_GATEWAY_SVID_KEY_PATH` onto the upstream client cert/key fields, failing slice apply if either path is missing so stale/global client material is not used. Validated reloads of the `FERRUM_GATEWAY_SVID_*` files bump a generation in backend TLS and pool keys so new H2/gRPC/H3/HTTP connections rebuild client identity state without restarting; active HTTP health probes are restarted on each observed revision, and existing connections complete on their original config unless `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS` force-drains old-generation pool entries. `insecureSkipVerify: true` forces `backend_tls_verify_server_cert = false`. `sni` projects to `Upstream.backend_tls_sni`, onto `Proxy.resolved_tls`, into backend H2/gRPC/H3 TLS handshakes, and into the backend pool key so different SNI values never share connections. Plain HTTPS requests with an SNI override use the direct H2 backend pool instead of reqwest because reqwest cannot express per-request backend SNI overrides. `subjectAltNames` projects to `Upstream.backend_tls_san_allow_list`, onto `Proxy.resolved_tls`, into backend TLS verifier enforcement, and into the backend pool key so different allow-lists never share connections. If per-proxy or global no-verify is enabled, SAN allow-lists are not enforced and Ferrum logs a warning. When the field is unset, behavior is identical to today and `PeerAuthentication` continues to drive the default mTLS posture. |
| `trafficPolicy.portLevelSettings[].port.number` + nested `connectionPool.tcp.connectTimeout` | Supported | Top-level policy applies first; per-port `connectTimeout` lands on `Upstream.port_overrides[port].connect_timeout_ms` at apply time, then `GatewayConfig::resolve_dispatch_port_overrides()` projects it onto `Proxy.dispatch_port_overrides` for O(1) hot-path lookup. All four dispatch families consult it: HTTP/H2/H3 via `resolve_effective_proxy_for_target` (`src/proxy/mod.rs`), gRPC via the same helper threaded through `proxy_grpc_request*` (`src/proxy/grpc_proxy.rs`), TCP via `effective_backend_connect_timeout_ms` in `TcpConnParams` (`src/proxy/tcp_proxy.rs`), and HBONE via `effective_connect_timeout_ms` in `connect_backend` (`src/proxy/hbone_proxy.rs`). Ports outside 1-65535 rejected; duplicate port entries rejected; phantom ports (DR entry references a port unused by any `Upstream.target`) skipped with a warning at apply time. The admin API rejects POST/PUT setting `Upstream.port_overrides` directly — express per-port policy as a DestinationRule (SQL/MongoDB schemas don't persist the field) |
| `trafficPolicy.portLevelSettings[].loadBalancer` / `outlierDetection` | Supported for HTTP-family / gRPC / WebSocket / HBONE dispatch | Per-port load-balancer algorithm/hash settings, passive outlier thresholds, and `localityLbSetting` (`distribute` / `failover` / `enabled`) land on `Upstream.port_overrides[port]`; the runtime builds isolated per-port LB counters/hash rings, per-port passive health, and per-port locality LB state. Dispatch on a port with an override consults the per-port locality preference first and falls back to the upstream-level `trafficPolicy.loadBalancer.localityLbSetting` when the per-port entry omits it. TCP/UDP/DTLS stream proxies currently enforce only per-port `connectTimeout` and continue to use the upstream-level LB/passive/locality policy. Phantom ports are skipped with a warning at apply time. Migration note: operators who previously set these fields expecting warning-only behavior should audit them before upgrade because they now affect HTTP-family/gRPC/WebSocket/HBONE routing and ejection decisions. Example: a top-level `ROUND_ROBIN` policy with `portLevelSettings[8080].loadBalancer.simple=RANDOM` keeps non-8080 traffic on round-robin while 8080 dispatch uses its own random counter/ring; a per-port `localityLbSetting.distribute` on 8080 weights only port-8080 traffic and leaves other ports on the upstream-level locality preference. |
| `exportTo` | Ignored | DRs are scoped to their declared namespace at slice-filter time |

Translator warnings surface in the `K8sTranslation.warnings` returned from `translate_k8s_objects`, so operators see them at apply time.

DestinationRule `trafficPolicy.tls.sni` is enforced only on backend paths where Ferrum owns the TLS handshake: direct HTTP/2 for plain HTTPS, gRPC over H2, and native H3. Because reqwest cannot express a per-request backend SNI override, Ferrum rejects SNI-overridden plain HTTPS requests that cannot use the direct H2 backend pool (request-body replay for retries, request-body-buffering plugins, `pool_enable_http2: false`, or an H1-only backend) with `502` and a `gateway-error-reason: backend_tls_sni_requires_direct_h2` header instead of silently dropping the override. H3 frontend requests bridged to a non-H3 backend now fail closed with the same 502/header policy; use an H2/H3-capable backend for those routes until the bridge grows a direct-H2 fallback. Active HTTP/H2/H3/gRPC health probes still use the target host as the TLS server name, so a backend certificate that only matches the override name can be marked unhealthy even though request traffic succeeds. Prefer TCP/passive health checks or a certificate that covers both names until active probes grow the same SNI override path. As a last-resort operational escape hatch, `backend_tls_verify_server_cert=false` avoids the certificate-name check for active probes, but it also disables backend certificate verification for request traffic.

## MeshSlice

`MeshSlice` is the per-node filtered view of mesh configuration, built by `MeshSlice::from_gateway_config()`. The CP computes a slice per subscriber; in native mode the slice is pushed directly, in xDS mode the translated resources are sliced locally.

The slice builder:

1. Filters workloads by namespace.
2. Finds the selected workload (if `workload_spiffe_id` is provided) for effective namespace/labels.
3. Filters `MeshPolicy` entries by `PolicyScope` matching against the proxy's namespace and labels.
4. Filters `PeerAuthentication` entries by workload selector.
5. Filters `ServiceEntry` entries by `export_to` visibility.
6. Filters `MeshRequestAuthentication` entries by scope.
7. Filters `MeshTelemetryResource` entries by scope.
8. Filters `MeshProxyConfig` entries by [`PolicyScope`](#policyscope) — same predicate as `MeshPolicy`, so root-namespace ProxyConfigs apply mesh-wide.

## Authorization

Mesh authorization is evaluated by the auto-injected `mesh_authz` plugin (priority 2075) on every request. In sidecar, ambient, east-west, and egress-gateway topologies, the plugin pre-filters applicable policies at construction time (cold path) so the request hot path evaluates only the relevant subset. In `NodeWaypoint` topology, one proxy instance serves many pods, so policy scope is resolved per pod on the request path from the node-waypoint identity resolver; a pod whose scope is absent (its workload left the live slice generation) **fails closed** when namespace/selector-scoped policies are configured, and falls through to mesh-wide-only when the mesh has only mesh-wide policies.

### PolicyScope Filtering

Every `MeshPolicy` carries a `PolicyScope`:

| Scope | Matches when |
|---|---|
| `MeshWide` | Always |
| `Namespace { namespace }` | `proxy_namespace == policy_namespace` |
| `WorkloadSelector { selector }` | Selector namespace matches (or is unset) AND all selector labels are present on the proxy with matching values (subset match) |

An empty `WorkloadSelector` (`labels: {}`, `namespace: None`) intentionally matches any workload.

The canonical matching helper `policy_scope_applies_to_workload()` is shared between the slice builder and the plugin filter so scope semantics stay byte-identical across both surfaces.

### Evaluation Semantics

`evaluate_mesh_authorization()` processes policies in order:

1. **DENY rules checked first** -- first match returns `Deny`.
2. **ALLOW rules** -- if any ALLOW rule exists in the policy set but none matched, the result is **implicit deny** (Istio semantics).
3. **AUDIT rules** -- matched audit policies are returned for logging.
4. If no DENY or ALLOW rules exist, the result is `Allow`.

**Istio empty-rule semantics**: `ALLOW` with no rules is allow-nothing (emits a `never_matches` rule so the implicit deny applies). `DENY`/`AUDIT` with no rules are no-ops.

### Rule Matching

Each `MeshRule` checks the following dimensions (all must match — a conjunction):

- **Principal matching** (`from`): Istio source-principal patterns (`<trust-domain>/ns/<namespace>/sa/<service-account>`, glob), `serviceAccounts`, namespace patterns (glob), and trust-domain patterns. Full `spiffe://...` patterns are also accepted in direct `MeshPolicy` config. Multiple `from[]` source entries are ORed.
- **Request principal matching**: `request_principals` glob patterns matched against the `{issuer}/{subject}` composite extracted by `jwks_auth`. When `request_principals` is non-empty and no JWT is present, the rule does not match (Istio semantics: anonymous requests fail the principal check). An empty `request_principals` list matches any request including unauthenticated ones.
- **Source negation / IP blocks** (per-source, ANDed with the positive `from`): Istio `notPrincipals`, `notServiceAccounts`, `notNamespaces`, `notTrustDomains`, `notRequestPrincipals`, `ipBlocks`, `notIpBlocks`, `remoteIpBlocks`, `notRemoteIpBlocks`. These are **conjunctive** with the positive matchers. Negative identity matchers fail the rule only when the corresponding source/JWT identity is present and matches an excluded pattern; if the identity is absent, the negative matcher succeeds, so `DENY notPrincipals: ["*"]` and `DENY notRequestPrincipals: ["*"]` catch anonymous traffic. IP block matchers fail closed when the IP they test is absent, so a positive `ipBlocks`/`remoteIpBlocks` constraint with no resolved IP does not match. `ipBlocks`/`notIpBlocks` match the direct connection peer IP (`source.ip`); `remoteIpBlocks`/`notRemoteIpBlocks` match the gateway-resolved client IP (`remote.ip`, XFF-derived when trusted proxies are configured). Unsupported source fields fail the resource closed at translation time (mirroring the `to.operation` side); a malformed CIDR rejects the resource or direct plugin config.
- **Request matching** (`to`): methods, paths (glob), hosts (normalized, case-insensitive), ports (exact + glob patterns), headers (case-insensitive keys, normalized at config load). The negative `to.operation` matchers (`notMethods`/`notPaths`/`notHosts`/`notPorts`) are conjunctive. ALLOW/AUDIT rules fail closed when the corresponding request attribute is absent; DENY rules follow Istio and treat missing HTTP-only operation attributes as matches, so port scoping is recommended for DENY rules that mention HTTP fields and can see TCP traffic.
- **Condition matching** (`when`): attribute-based with `values` (the attribute must be present and equal one of the values) and `not_values` (the attribute must not equal any value; an absent attribute satisfies a `not_values`-only condition, matching Istio's compiled `not_rule` semantics). Conditions are evaluated against attributes sourced from the request: `source.principal` (Istio form without the `spiffe://` scheme), `source.namespace` (from the resolved peer SPIFFE ID), `request.auth.principal`, `request.auth.presenter` (JWT `azp`), `request.auth.audiences`, `request.auth.claims[<name>]` and nested `request.auth.claims[<name>][<nested>]` string or string-list leaf values (from the validated JWT via the mesh `RequestAuthentication` plugin), `request.headers[<name>]`, `destination.port`, `connection.sni` (frontend TLS/QUIC and stream connections when SNI is available), `source.ip`, and `remote.ip`. Unsupported condition keys are rejected at translation/config validation time so DENY conditions cannot silently fail open. DENY conditions treat missing HTTP-only attributes (`request.headers[...]`, `request.auth.*`) as matches; other missing attributes never satisfy a `values` check. Only the attribute keys some loaded policy references are materialized per request, so a policy set with no `when:` conditions adds no hot-path cost.

### SPIFFE Identity

The `spiffe_identity` plugin (priority 940) extracts the peer SPIFFE ID from TLS/DTLS client certificates on every inbound request. This identity feeds into:

- `mesh_authz` principal matching
- Workload metrics labels (`source.principal`, `destination.principal`)
- Transaction summary `auth_method` tracking

For production deployments, Ferrum delegates SVID issuance and trust-bundle
distribution to a separately operated [SPIRE](https://spiffe.io/docs/latest/spire-about/)
installation. See [docs/spire_deployment.md](spire_deployment.md) for the
operator runbook covering trust-domain choice, registration entries, single-
and multi-cluster topologies, SVID rotation cadence, alert wiring, and failure
recovery.

### HBONE Protocol

HBONE (HTTP-Based Overlay Network Environment) is HTTP/2 CONNECT over mTLS, used by the ambient topology on port 15008.

Wire-shape detection by `is_hbone_connect()`:
- Method must be `CONNECT`, version must be HTTP/2.
- Optional marker headers: `x-ferrum-mesh-protocol` or `x-istio-protocol` (value `hbone` or absent).

Shape detection alone does **not** authorize the relay. Before the transparent TCP relay is established, the HBONE handler requires an authenticated, trust-domain-verified peer SPIFFE identity (`ctx.peer_spiffe_id.is_some()`, captured by `is_authenticated_hbone_connect()`). The inbound mTLS/HBONE listener populates `peer_spiffe_id` from the verified peer certificate (via the `spiffe_identity` plugin, or the node-agent/eBPF identity on the NodeWaypoint listener), so a present identity means a verified mesh peer terminated mTLS on this listener. A bare (marker-less) HTTP/2 CONNECT with no authenticated peer — and equally a CONNECT that merely asserts an `x-*-protocol: hbone` marker without a verified peer — is rejected with `403 Forbidden` and never relayed or dialed to a backend; the rejection stamps `mesh_authz.deny_policy=hbone_unauthenticated_peer`. Legitimate Istio ztunnel/waypoint HBONE always presents an authenticated mTLS peer, so interop is unaffected. This is independent of the trust-bundle peer verification performed at TLS time — it ensures the relay itself never opens a tunnel for an unauthenticated peer.

Identity extraction from W3C Baggage headers:
- Source principal keys (with fallback aliases): `source.principal`, `source_principal`, `source.identity`, `source_identity`, `src.identity`, `src_identity`.
- Values are percent-decoded per the Baggage spec.

Gateway DPs can also originate HBONE when they have a gateway SVID loaded and an upstream target is tagged `mesh.hbone=true`. The gateway probes the target's sidecar HBONE port (`15008`, or `mesh.hbone_port`) during backend capability refresh, then sends eligible plain HTTP traffic through HTTP/2 CONNECT over SPIFFE mTLS before trying the ordinary direct backend transports. The HBONE pool honors the proxy's effective `pool_*` overrides, including connection count, idle timeout, TCP keepalive, and HTTP/2 flow-control settings, and coalesces concurrent first connects for the same target/SVID key within the proxy's `backend_connect_timeout_ms` budget. Requests that require replayable retries or request-body buffering continue to use the direct backend transports. The CONNECT request carries `source.principal` baggage derived from the gateway SVID; mesh-side authz still requires the baggage to agree with the authenticated peer identity. The tunneled inner HTTP request strips client-supplied identity baggage (`source.*`, `destination.*`, and aliases) while preserving non-identity baggage, so untrusted client claims cannot reach the mesh backend as application headers.

Gateways with a loaded SVID auto-enable source identity labels for the `workload_metrics` plugin. The runtime injects an internal global `workload_metrics` plugin when none exists, or augments an existing global plugin with `workload_spiffe_id` when the operator has not set one explicitly. Successful HBONE-dispatched transactions are labeled with `mesh.connection_security_policy=mutual_tls` and `mesh.gateway.transport=hbone`; mesh-aware upstream target tags such as `mesh.spiffe_id`, `mesh.namespace`, `mesh.service`, and `mesh.trust_domain` are copied to destination metadata.

Inbound HBONE CONNECT requests run the standard `before_proxy` plugin chain on the outer CONNECT request before the transparent TCP relay is established. This means `mesh_route_dispatch` (and any other `before_proxy` plugin that writes `RequestContext::route_override_*`) can match on the CONNECT request's method, headers, and query parameters, and override the backend `upstream_id`, `backend_host`/`backend_port`, resolved backend TLS materials, backend read timeout, and retry policy on a per-rule basis. The overrides flow into HBONE backend selection through `apply_route_overrides_with_upstreams`, so per-rule `timeout_ms` / `timeout_disabled` and `retry` from a translated `VirtualService` reach the HBONE relay's `backend_read_timeout` / `backend_write_timeout` / circuit-breaker decisions just as they reach the H1/H2/H3 dispatch paths. The relay itself stays a transparent byte-copy after the upgrade — `before_proxy` does not see inner H2 frames, so route decisions are made once per outer CONNECT, mirroring the post-upgrade pinning behavior of WebSocket dispatch.

### Trust Domain Aliasing

`FERRUM_MESH_TRUST_DOMAIN_ALIASES` configures additional trust domains accepted as equivalent to the peer certificate's trust domain when validating HBONE baggage `source.principal`. By default (empty), strict same-trust-domain matching applies. This mirrors Istio's `MeshConfig.trustDomainAliases`.

### Trusted HBONE Assertors

HBONE baggage `source.principal` is rewritten onto the `mesh_authz` principal only when the authenticated peer is on a configurable allow-list of identity-asserting infrastructure components. Authenticated mesh peers that are NOT on this list have their baggage `source.principal` dropped — they authorise under their own peer-cert identity. This prevents a workload-to-workload impersonation bypass where an authenticated peer would otherwise rewrite the authz principal to a different workload via a forged `baggage` header.

The default allow-list matches Istio ambient's `ztunnel` and `waypoint` service accounts:

```
trusted_hbone_assertors = ["ztunnel", "waypoint"]
```

Each entry is matched against the peer's SPIFFE id as follows:

- **Bare service-account name** (e.g., `ztunnel`): matches any peer whose path is `<...>/sa/<name>` per the Istio convention `ns/<ns>/sa/<sa>`. Trust-domain-independent — `spiffe://cluster.local/.../sa/ztunnel` and `spiffe://partner.local/.../sa/ztunnel` both match.
- **Full SPIFFE id** (e.g., `spiffe://cluster.local/ns/istio-system/sa/ztunnel`): exact-identity match including trust domain, namespace, and service account.

Operators with Gateway-managed waypoints often run with SA names like `<gateway-name>-istio` instead of `waypoint`; override the allow-list via `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS` (comma-separated, mix-and-match SA names and full SPIFFE ids):

```
FERRUM_MESH_TRUSTED_HBONE_ASSERTORS="ztunnel,default-waypoint,spiffe://cluster.local/ns/team-a/sa/team-a-waypoint"
```

When the env var is unset or empty, mesh injection uses the defaults. To lock down baggage rewriting entirely (no peer can rewrite the authz principal), configure a `mesh_authz` global plugin override with an explicit empty list (`trusted_hbone_assertors: []`).

`FERRUM_MESH_TRUST_DOMAIN_ALIASES` continues to gate the baggage identity's trust domain — both checks apply to a baggage rewrite.

**Observability**: when baggage is dropped because the peer is not a trusted assertor, transaction logs surface `mesh_authz.ignored_baggage=untrusted_assertor` and `mesh_authz.ignored_baggage.untrusted_assertor=true`. If the resulting authz decision is a DENY, `mesh_authz.deny_policy` is stamped as `untrusted_assertor`. Trust-domain-mismatch diagnostics retain their existing `trust_domain_mismatch` reason.

## RequestAuthentication

`MeshRequestAuthentication` declares which JWTs are valid for a workload scope. When applicable resources with JWT rules exist in the mesh slice, the mesh runtime auto-injects a `jwks_auth` global plugin (`__mesh_request_auth`) configured from the JWT rules.

**Permissive semantics** (matching Istio): RequestAuthentication only declares which JWTs are *valid*, not which are *required*. A request with no JWT passes through. An invalid JWT is rejected. Enforcement (requiring a JWT) comes from `AuthorizationPolicy` ALLOW/DENY rules that check for authenticated identity.

Each `MeshJwtRule` specifies:

| Field | Description |
|---|---|
| `issuer` | Expected JWT issuer (`iss` claim) |
| `audiences` | Accepted audience values (`aud` claim); any configured value may match |
| `jwks_uri` | URL to fetch the JWKS key set |
| `jwks` | Inline JWKS JSON (alternative to `jwks_uri`); keys are loaded from config without a fetch loop |
| `from_headers` | Headers to extract the JWT from (with optional prefix stripping) |
| `from_params` | Query parameters to extract the JWT from |
| `forward_original_token` | Whether to forward the original token to the backend |

Each JWT rule resolves token locations independently. Rules with custom `from_headers` or `from_params` check those locations in declaration order; rules without custom locations continue to use the standard `Authorization: Bearer ...` lookup. When `forward_original_token: false`, the backend-bound request strips the matched rule's configured token headers or query parameters (or `Authorization` for standard lookup).

**`exp` claim requirement**: the injected plugin requires the JWT `exp` claim by default (`FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP=true`), so tokens that omit `exp` are rejected and cannot live forever — this satisfies the gateway's `validate_exp = true` invariant. Some Istio issuers legitimately omit `exp`; set `FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP=false` to accept them. This knob is independent of expiry *validation*: a present-but-expired `exp` is always rejected regardless of the flag.

**Authz attribute emission**: a validated token's `iss/sub` (`request.auth.principal`), audiences (`request.auth.audiences`), and scalar / string-array claims (`request.auth.claims[<name>]`) are surfaced to the `mesh_authz` plugin so `AuthorizationPolicy` `when:` conditions over those attributes are evaluated (see [Rule Matching](#rule-matching)).

## PeerAuthentication

`PeerAuthentication` controls per-workload mTLS behavior with optional per-port overrides.

mTLS modes:

| Mode | Description |
|---|---|
| `strict` | Require mTLS on all connections. Reject plaintext. |
| `permissive` (default) | Accept both mTLS and plaintext. |
| `disable` | Disable mTLS. Accept plaintext only. |

Per-port overrides allow mixed-mode operation on the same workload:

```yaml
name: "mixed-mode"
namespace: "default"
selector:
  labels:
    app: my-service
mtls_mode: strict
port_overrides:
  8081: permissive   # Health check port accepts plaintext
```

Selector-less `PeerAuthentication` applies to all workloads in its namespace (or mesh-wide if namespace-scoped).

### Resolution and listener wiring

The effective mTLS mode for the inbound TLS-terminating listener is resolved at startup from the initial mesh slice via `resolve_effective_mtls_mode()`. Scope precedence (highest wins): `WorkloadSelector` > `Namespace` > `MeshWide`. Among same-tier matches the tie is resolved **fail-secure**: the more-restrictive effective mode for the port wins (`Strict` > `Permissive` > `Disable`). This is both deterministic (so the posture cannot flap across pods or reconciles) and a genuine trust boundary — because the winner is decided by mode rather than by the policy's namespace string or name, a tenant-controlled policy cannot downgrade inbound mTLS below a trusted same-tier policy by choosing a low-sorting namespace or policy name, and a customized `FERRUM_K8S_ISTIO_ROOT_NAMESPACE` that sorts after tenant namespaces is equally safe. Two conflicting same-tier `PeerAuthentication`s are still an operator misconfiguration; only when their effective modes are identical does the resolver fall back to the value-neutral `(namespace, name)` ordering to pick a canonical winner (this differs from the sibling `ProxyConfig` resolver, which has no security posture to protect and tiebreaks by `name`). Port-level overrides within a policy are applied before this comparison, so the fail-secure choice reflects the mode each policy actually yields for the port. Port-level overrides within the winning policy then take precedence over its top-level `mtls_mode`.

The resulting `MeshClientAuth` is plumbed into the inbound TLS acceptor:

- `strict` -> TLS `Required` (client cert mandatory; plaintext rejected).
- `permissive` -> TLS `Optional` (TLS accepted with optional client cert; plaintext can be accepted by the mesh listener).
- `disable` -> TLS `Disabled` (plaintext only; mTLS connections rejected).

**SPIFFE peer trust-domain verification**: when gateway SVID material is configured (all three of `FERRUM_GATEWAY_SVID_CERT_PATH` / `FERRUM_GATEWAY_SVID_KEY_PATH` / `FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH`), the inbound mTLS / HBONE listener verifies each peer certificate's chain **and** that the peer's SPIFFE URI-SAN trust domain matches the gateway SVID's local trust bundle or one of the slice's federated bundles. This closes the gap where a peer cert that merely chained to the configured client CA was admitted regardless of its SPIFFE trust domain. STRICT requires + validates a peer cert; PERMISSIVE still admits peers that present no cert but trust-domain-validates any cert that is offered (so PERMISSIVE records mTLS identity when present). Without gateway SVID material, the listener keeps the prior chain-only verification against `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH`. In PERMISSIVE specifically, the listener requests a client certificate whenever **either** trust anchor exists (the SVID verifier is preferred, otherwise the operator client CA bundle) so an offered cert is verified and its identity recorded; only when **neither** anchor is configured does PERMISSIVE skip the certificate request entirely — and in that fully-degraded case Ferrum emits a single startup warning that inbound peer identity cannot be verified or recorded, rather than silently treating authenticated peers as anonymous. The HBONE baggage `source.principal` trust-gate now rests on this verified peer identity. When `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true`, the lock-free SVID bundle slot is re-published on slice apply so federated trust-domain additions take effect without a listener restart; the SVID's own local roots / cert / key remain file-based startup inputs.

The port used for `port_overrides` lookup follows the topology's TLS-terminating listener (see `MeshRuntimeConfig::listener_plan()`):

| Topology | Resolution port (default) | Override key example |
|---|---|---|
| `Sidecar` | `inbound_listen_addr` (15006) | `port_overrides: {15006: strict}` |
| `Ambient` | `hbone_listen_addr` (15008) | `port_overrides: {15008: strict}` |
| `NodeWaypoint` | `hbone_listen_addr` (15008) | `port_overrides: {15008: strict}` |
| `ServiceWaypoint` | `hbone_listen_addr` (15008) | `port_overrides: {15008: strict}` |
| `EgressGateway` | `egress_listen_addr` (15090) | `port_overrides: {15090: strict}` |
| `EastWestGateway` | n/a (SNI passthrough, no termination) | — |

By default, the resolved mode is captured **once at startup** from the first valid slice. Subsequent `PeerAuthentication` changes pushed via the control plane update the in-memory slice and are honored by other plugin paths (e.g. `mesh_authz`, plugin chains), but the inbound TLS `ServerConfig` is not rebuilt.

Set `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true` to opt in to live reload of the resolved mTLS mode and frontend client CA verifier on mesh slice apply. Coverage includes mesh HTTP/HBONE termination listeners **and** mesh-shared TCP+TLS / UDP+DTLS stream listeners: a slice apply that flips `PeerAuthentication` mode (e.g. `PERMISSIVE` → `STRICT`) or rotates the client CA bundle hot-swaps the shared `rustls::ServerConfig` slot for TCP+TLS listeners (snapshotted per accept) and rebuilds the DTLS `FrontendDtlsConfig` on every active `DtlsServer` (new sessions snapshot the swapped material at handshake; existing handshake-complete sessions keep the material they handshake with until they end — rustls/dimpl consult the config only at handshake time). Failure handling differs by path. A single `rustls::ServerConfig` build backs **both** mesh HTTP/HBONE termination and the shared TCP+TLS stream slot, and it is computed *before* the proxy config is applied; if that build fails — or the client-CA-bundle snapshot cannot be read (e.g. a secrets operator truncating the bundle file mid-write) — Ferrum **rejects the whole slice** and keeps the last good config in its entirety, so no authz/`MeshPolicy`/`RequestAuthentication`/`ServiceEntry`/endpoint update from that slice is applied either, until the rebuild succeeds (fail-closed; the inbound posture is never silently weakened). Only the *post-accept* DTLS `FrontendDtlsConfig` rebuild keeps the previous config **for that path** and logs a warning without rejecting the slice. Topology-disable rejection (see below) likewise keeps the last good config wholesale.

Frontend cert/key paths are independently controlled by `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` (default `false`). When that flag is enabled, the proxy HTTPS / H2 / HTTP/3 and admin HTTPS listeners watch their cert/key files on a poll interval (`FERRUM_FRONTEND_TLS_WATCH_INTERVAL_SECONDS`, default 30s) and atomically swap a rebuilt `ServerConfig` on validated change. The two flags are orthogonal: PeerAuthentication live reload covers the mesh inbound mTLS mode + client CA verifier surface, frontend live reload covers the operator-supplied cert/key material across the proxy and admin HTTPS surfaces. See [docs/configuration.md](configuration.md#proxy-listener) for full semantics.

### Disable-mode topology guard

`PeerAuthentication.mode: disable` resolved against an `Ambient`, `NodeWaypoint`, `ServiceWaypoint`, or `EgressGateway` workload is rejected. Startup fails closed on an invalid initial slice; with `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true`, later invalid slices are rejected and the last good inbound TLS config remains active.

- **Ambient**: HBONE is HTTP/2 CONNECT over mTLS — running the inbound listener plaintext is not a valid HBONE listener. Use `permissive` or `strict`, or move the workload to `Sidecar` topology if plaintext-only inbound is intended.
- **NodeWaypoint**: the shared node listener must resolve pod identity from the node-agent/eBPF socket-cookie record before admitting HBONE traffic. Use `permissive` or `strict`.
- **ServiceWaypoint**: service-scoped Ambient waypoint traffic arrives as HBONE over mTLS. Use `permissive` or `strict`.
- **EgressGateway**: the egress listener must verify sidecar client certificates. Use `permissive` or `strict`.

Invalid startup mode fails closed with or without live reload. With live reload enabled, invalid incoming slices are rejected and the last good config stays active. `Sidecar` and `EastWestGateway` accept any resolved mode (`Disable` on Sidecar produces a plaintext inbound listener; on EastWestGateway the resolved mode is unused because there is no TLS termination).

### NodeWaypoint cgroup-inode lifecycle binding

In NodeWaypoint topology one HBONE listener serves many pods. The node-agent enrolls each pod's identity into the proxy via `NodeWaypointIdentityResolver`. When the agent supplies the pod's cgroup v2 directory at enrollment time (`upsert_identity_with_cgroup`), the resolver captures the directory inode plus a small Unix metadata fingerprint, and a periodic sweep (`FERRUM_MESH_NODE_WAYPOINT_CGROUP_SWEEP_INTERVAL_SECS`, default 30s) re-stats the path:

- Inode/fingerprint unchanged → identity kept.
- Inode or fingerprint changed → pod restarted under the same UID; identity (and its per-pod policy scope) is evicted so a fresh enrollment is required before traffic for the new instance is honoured. The fingerprint prevents missed restarts when the filesystem reuses the old inode number.
- Path gone → pod removed; identity and policy scope are evicted.

The same sweep also reclaims identities enrolled **without** a cgroup path — which is what the production lazy hash-join enrollment produces (it has no cgroup to bind, and nothing calls the explicit removal API for it). For those, the sweep evicts an identity only when its pod UID is no longer referenced by a live cookie record **and** its identity `Arc` has no other holder (`strong_count == 1`): a removed/restarted pod's accept-side cookies age out of the mirrored `FERRUM_ORIG_DST4/6` view within a poll interval, so the orphaned identity (and its per-pod policy scope) is reclaimed instead of accumulating across pod churn. Prompt aging-out depends on the `sock_ops` program **removing the orig-dst record on TCP close** (not just on LRU pressure): without that, a closed connection's cookie would linger in the LRU map on a low-churn node and keep the dead pod's record mirrored indefinitely. The `strong_count` guard protects in-flight connections: the HTTP/HBONE accept path stores the resolved identity `Arc` on the connection for its whole lifetime and re-queries the per-pod scope on every request, so a connection whose cookie the BPF LRU evicted mid-flight still pins its identity (`strong_count > 1`) and keeps its scope until it closes — without the guard the cookie-only signal would wrongly drop the scope and downgrade later streams to mesh-wide. TCP streams resolve their scope once at accept and never re-query, so they are unaffected regardless. An evicted-but-still-live idle pod simply re-enrolls on its next connection. cgroup-bound identities are left to the cgroup-binding pass above and are never touched by this idle pass.

Set the sweep interval to `0` to disable. The sweep is best-effort GC, not a security boundary: the accept-path check on unknown socket cookies remains fail-closed regardless of sweep cadence.

Picking an interval is a tradeoff between eviction lag (worst-case time a stale identity remains after pod removal/restart) and per-sweep stat cost. Each enrolled cgroup-bound identity costs one `stat(2)` per sweep — on the order of tens of microseconds on a warm dentry cache, so even at thousands of pods per node a sweep finishes in a few milliseconds and the work runs on a dedicated background task off the accept path. Shorten the interval to tighten the eviction window on heavy pod churn; lengthen it (or set `0`) if the operator already drives identity removal explicitly from the node-agent and treats the sweep as a defence-in-depth backstop.

## Transparent DNS Proxy

The mesh DNS proxy intercepts DNS queries and resolves mesh-internal hostnames from a pre-built resolution table. Non-mesh queries are forwarded to the upstream system resolver.

### Enablement

The DNS proxy is opt-in because it requires iptables or eBPF redirect to be useful:

```bash
FERRUM_MESH_DNS_PROXY_ENABLED=true
FERRUM_MESH_DNS_LISTEN_ADDR=127.0.0.1:15053    # default
FERRUM_MESH_DNS_UPSTREAM_ADDR=127.0.0.53:53     # default
```

### How It Works

1. The `DnsResolutionTable` is built atomically from the `MeshSlice` on every config update via `ArcSwap` -- no locks on the query hot path.
2. Incoming DNS queries (UDP and TCP) are parsed for hostname and query type (A/AAAA).
3. Exact matches are checked first, then wildcard suffix matches.
4. Mesh-resolved responses are served with configurable TTL (`FERRUM_MESH_DNS_TTL_SECONDS`, default 60).
5. Non-mesh queries are forwarded transparently to the upstream resolver.

### Resolution Sources

**ServiceEntry hosts**: endpoint IP addresses are indexed by hostname.

```
api.external.com -> [203.0.113.10]
```

**MeshService names**: workload addresses are resolved through SPIFFE ID references and registered under both FQDN and short name forms:

```
my-service.default.svc.cluster.local -> [10.0.1.5, 10.0.1.6]
my-service.default                   -> [10.0.1.5, 10.0.1.6]
```

The cluster domain suffix is configurable via `FERRUM_MESH_CLUSTER_DOMAIN` (default `cluster.local`).

### Wildcard Support

Wildcard hosts (`*.example.com`) are supported via bucketed suffix matching. The DNS proxy maintains a suffix index so lookup is bounded rather than linear.

### Protocol Details

- Supports A (IPv4) and AAAA (IPv6) queries.
- EDNS(0) OPT pseudo-records are echoed when they fit.
- UDP responses are clamped to the client's advertised payload size (or 512 bytes without EDNS).
- TCP fallback for large responses.
- Concurrent query limiting via `FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES` (default 1024) using a semaphore.
- Upstream forwarding timeout: 5 seconds.

## Multi-Cluster

Multi-cluster mesh support enables cross-cluster service discovery and traffic routing.

### East-West Gateways

When `FERRUM_MESH_TOPOLOGY=east_west_gateway`, the mesh runtime materializes passthrough TCP proxies from `MultiClusterConfig.east_west_gateways` entries. Each gateway entry specifies:

- `host` / `port`: backend cluster endpoint.
- `sni_hosts`: TLS SNI hostnames routed through this gateway.
- `trust_domain` / `network`: optional cross-cluster identity and network labels.

The materialized proxies use `passthrough: true` (no TLS termination), route by SNI, and share the listener on `FERRUM_MESH_EAST_WEST_LISTEN_PORT` (default 15443). Only entries matching the gateway's namespace are materialized.

In addition to remote-cluster gateways, the east-west topology materializes a TCP passthrough proxy for each local `MeshService` in the mesh slice. The SNI routing host is the service FQDN (e.g., `reviews.default.svc.cluster.local`), enabling cross-cluster clients to reach local services through the east-west gateway without separate per-service configuration.

### Trust Federation

`TrustBundleSet` carries local and federated X.509/JWT authority bundles:

- `local`: the trust bundle for the local cluster's trust domain.
- `federated`: trust bundles from remote clusters, enabling cross-cluster mTLS verification.

X.509 authorities are stored as base64-encoded DER for serialization-friendly persistence. JWT authorities carry `key_id` and `public_key_pem`.

A background poller hits each `RemoteCluster.federation_endpoint` over HTTPS at
`FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS` (default 300; `0` disables) and
overlays the fetched bundle onto `TrustBundleSet.federated` for cross-cluster
mTLS verification. The polled bundle is validated through the same invariants
the slice validator applies before swapping the `ArcSwap`-held snapshot, so a
malformed remote response is rejected and the last-good bundle stays in
service. Per-target failures use jittered exponential backoff (1s → 30s cap,
±25%, matching `src/grpc/dp_client.rs`); successes reset the backoff to the
configured poll interval. The polled bundles win on conflict against any
control-plane-supplied federated entries because the poller signals the
freshest rotation; CP-supplied bundles remain as a fallback for trust domains
the poller has not yet fetched. `FERRUM_MESH_FEDERATION_FAIL_OPEN` is reserved
for future verifier integration — today it is recorded in poll-failure log
lines for operator visibility but does NOT change verifier behavior. Verifier
behavior is fail-closed regardless of the flag (verification only succeeds
against the last-good cached bundle). Endpoints are validated at slice apply
for SSRF (link-local / loopback / cloud metadata IPs are rejected) and must
use `https://`; response bodies are capped at 2 MiB and parsed bundles are
capped at 256 X.509 + 256 JWT authorities. Federation-poller trust bundles are **outbound-only**: a poller-added trust domain validates outbound mTLS but is rejected inbound until the CP pushes it in a slice (inbound trust is governed solely by the CP slice's trust-domain set).

Two on-the-wire formats are accepted:

1. The native Ferrum `TrustBundle` JSON shape (round-trips through
   `serde_json` from the persistence model).
2. The SPIFFE Trust Domain and Bundle JWKS profile
   (`{"keys": [{"use": "x509-svid", "x5c": ["..."]}], "spiffe_refresh_hint":
   60}`). The trust domain is supplied by the surrounding `RemoteCluster`
   entry because SPIFFE bundles do not carry it inline.

The federation snapshot is exposed at `GET /mesh/federation` (JWT-auth), with
per-trust-domain `bundle_age_seconds` and authority counts, and emits these
Prometheus series alongside the existing mesh metrics:

- `ferrum_mesh_federation_poll_failures_total{trust_domain,endpoint}`
- `ferrum_mesh_federation_last_success_timestamp_seconds{trust_domain}`
- `ferrum_mesh_federation_bundle_age_seconds{trust_domain}`

### Remote Clusters

`RemoteCluster` entries identify peer clusters:

```yaml
multi_cluster:
  local_cluster: "us-east-1"
  remote_clusters:
    - name: "eu-west-1"
      trust_domain: "eu-west-1.example.com"
      network: "network-eu"
      control_plane_url: "https://cp.eu-west-1.internal:50051"
      federation_endpoint: "https://cp.eu-west-1.internal/.well-known/spiffe"
```

- `federation_endpoint` feeds the [trust-bundle federation poller](#trust-federation) (cross-cluster mTLS verification material).
- `control_plane_url` feeds **cross-cluster endpoint discovery** (below).

### Cross-Cluster Endpoint Discovery

When `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS > 0` (default `0`, disabled), each currently eligible `RemoteCluster.control_plane_url` is dialed over the native `MeshSubscribe` gRPC stream (reusing the DP↔CP gRPC JWT secret and TLS selected from that remote URL) to fetch that cluster's service endpoints (workloads + services). The discovered endpoints are merged into the local mesh registry at slice apply and become ordinary upstream targets, tagged with a synthetic **remote locality** (`remote-<cluster>` or `remote-<cluster>/<network>`). Because the load balancer is **locality-aware priority-tier** (see [Locality-Aware Load Balancing](#locality-aware-load-balancing)), local endpoints occupy the source region/zone tier and remote endpoints sit in the fallback tier: traffic stays local while local endpoints are healthy and **fails over to the remote cluster's endpoints only when the local tier has no healthy endpoints**.

> **Precondition — source locality required for local-first preference.** The priority-tier LB only prefers local endpoints over remote ones when the local workload's source locality is set (derived from `topology.kubernetes.io/region`+`zone` labels on the mesh slice's SPIFFE-matched workload, or from the label-based heuristic). When source locality is absent (e.g. the labels are missing or the SPIFFE-matched workload has no locality), `target_locality_ranks` is empty and the LB returns local **and** remote endpoints together — traffic can go to the remote cluster even when local endpoints are healthy (fails open, not local-first). Ferrum emits a startup `WARN` when discovery is enabled but no source locality can be resolved from the initial mesh slice. Ensure `topology.kubernetes.io/region` and `topology.kubernetes.io/zone` Node labels are propagated to workload locality metadata (via `FERRUM_K8S_NODE_LOCALITY_ENABLED=true`, or by stamping them directly on the mesh slice's `Workload.locality` field) before enabling discovery.

Discovery is fail-closed on trust: a remote cluster is dialed **only** while a federated trust bundle for its `trust_domain` is present (configure [Trust Federation](#trust-federation) for the peer first). The discovery reconciler watches mesh-slice and federation updates, starts newly eligible clusters, stops removed or no-longer-trusted clusters, and removes their stale endpoints. A poll failure keeps the last-good endpoints and backs off (jittered 1s -> 30s); it never deletes previously fetched endpoints. `control_plane_url` is SSRF-validated (cloud-metadata / link-local hosts rejected; loopback allowed for local/dev/test).

Merge rules: exact duplicate workload endpoints are skipped, but workloads with the same SPIFFE ID and different addresses are retained because the same service account identity can have replicas in multiple clusters. A service the local cluster already advertises keeps its local ports/overrides and unions in the remote workload refs so it resolves both local and remote endpoints; a service that exists only remotely is added wholesale.

**Live-verification status:** the aggregation + failover path is covered by tests with a mockable remote source, and the production `MeshSubscribe` gRPC dialer is covered by an **in-process two-CP round trip** — tests stand up a real `MeshSubscribe` gRPC server on a loopback port and drive the production dialer against it (channel dial, DP↔CP JWT mint + server-side verification, heartbeat skipping, slice decode, endpoint extraction, and a full discovery-loop install). The remaining live-verification step is a **true cross-cluster deployment** (two mesh control planes on separate networks) exercising the dialer under real network churn / loss / latency.

## Egress Gateway

When `FERRUM_MESH_TOPOLOGY=egress_gateway`, the mesh runtime materializes HTTP-family **and** stream-family (TCP) proxies from `ServiceEntry` resources with `location: mesh_external`.

### Materialization Rules

- Only `MeshExternal` entries are materialized (internal entries are skipped).
- HTTP-family protocols (`http`, `http2`, `grpc`, `tls`) materialize **HTTP-family** proxies: host-routed off the shared egress listener (mTLS termination at `egress_listen_addr`, default 15090). One proxy per host across all ports — host-only routing cannot disambiguate multiple ports under the same host.
- Stream-family protocols (`tcp`, `mongo`, `redis`, `mysql`, `postgres`) are **opt-in** via `FERRUM_MESH_EGRESS_STREAM_ENABLED=true` (default `false`). When the flag is off, stream-family ports are skipped with a warning and only HTTP-family egress materializes. When the flag is on, each stream-family port materializes its own TCP proxy (T5-A) on the ServiceEntry's destination port (e.g., `mongo.external.io:27017/TCP` produces a TCP listener on port 27017). Default-off because the per-port stream listener is plaintext (no frontend TLS / DTLS) and `mesh_authz` cannot authenticate connections without TLS client certs — enabling it without alternative auth lets any pod on the mesh network reach the external service through the egress gateway. One proxy per port; same-port collisions across ServiceEntries skip the second entry with a warning. Multi-port stream ServiceEntries bind each port separately. ServiceEntry ports that collide with the egress gateway's own listener port (`egress_listen_addr.port()`, default `15090`) or port `0` are skipped with a warning rather than emitted — letting them through would fail to bind at runtime (`EADDRINUSE`) and reject the entire slice apply.
- Mongo / Redis / MySQL / Postgres are TCP-based at the wire level; the protocol tag is preserved on `Proxy.name` for observability but **no protocol-aware mediation** (e.g., MongoDB wire-format inspection) is performed. Protocol-level mediation is tracked separately.
- DNS-resolution entries use ServiceEntry hosts as backend targets; static-resolution entries use endpoint addresses. Stream-family proxies pin to the first host (DNS) or all endpoints (Static) — a raw L4 listener cannot distinguish hosts (no SNI for plain TCP), so multi-host external services should be split into one SE per host.
- HTTP-family materialized proxies use host-only routing (no `listen_path`), `preserve_host_header: true`, and passive health checks. Stream-family proxies use port routing (no `hosts`), `passthrough: false` (the per-port stream listener is plaintext L4 — the inbound sidecar mTLS boundary is the sibling 15090 mTLS-termination listener for HTTP-family flows, *not* the per-port stream listener itself; this is NOT raw SNI passthrough, that flow lives in the east-west gateway), and passive health checks.
- The egress gateway materialization pairs with the `mesh_outbound_registry` plugin (HTTP-family, request-path 4xx/5xx). T5-A and the sibling T5-B (stream-family outbound enforcement at sidecar capture: connection-level drop / silent UDP datagram drop) close the `outboundTrafficPolicy: REGISTRY_ONLY` gap across both transport families.

### ServiceEntry Visibility

`export_to` controls which namespaces can see a ServiceEntry:

| `export_to` value | Visibility |
|---|---|
| (empty) | Namespace-local (same namespace as the entry) |
| `"*"` | Mesh-wide |
| `"."` | Same namespace as the entry |
| `"namespace-name"` | Exported to that specific namespace |

### Baggage Stripping

`FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS` configures baggage header keys to strip before forwarding to external backends, preventing identity leakage outside the mesh.

## Sidecar Egress Scoping

Istio `Sidecar` resources narrow which mesh service configuration a workload receives for egress. Ferrum translates the egress portion of a `Sidecar` into a `MeshSidecar` record and applies it at slice build time. Ingress listener configuration on `Sidecar` is intentionally not modeled — egress config scoping is the immediate compatibility gap.

### Behavior

When `FERRUM_MESH_SIDECAR_ENFORCED=true`, the `MeshSlice` projection narrows `services`, `service_entries`, and `destination_rules` to the set admitted by the workload's applicable `Sidecar`. When `false` (the default), `Sidecar` resources are still parsed and persisted in `MeshConfig` for future use, but slice narrowing is skipped and behavior is identical to today.

When `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN=true`, Ferrum computes and reports the same admitted/denied egress scope but keeps the slice unchanged. This lets operators verify would-deny behavior before enabling enforcement.

### Resolution Precedence

Most specific wins:

1. **Workload-scoped** Sidecar (`spec.workloadSelector.matchLabels` matches the workload's labels)
2. **Root-namespace workload-scoped** Sidecar (native config with a root-namespace `workloadSelector` whose selector namespace is omitted; Kubernetes `Sidecar` selectors stay namespace-scoped)
3. **Namespace-default** Sidecar (no `workloadSelector`)
4. **Root-namespace default** Sidecar (no `workloadSelector`, in `FERRUM_K8S_ISTIO_ROOT_NAMESPACE`, default `istio-system`)
5. **No Sidecar applies** → no narrowing (existing behavior)

### Host Pattern Syntax

Each `spec.egress[].hosts` entry follows Istio scope-host syntax:

| Pattern | Meaning |
|---|---|
| `*/*` | Allow everything (effective no-op) |
| `*/host` | `host` in any namespace |
| `./host` | `host` in the Sidecar's own namespace |
| `namespace/host` | Exact namespace + host match |
| `namespace/*` | Anything in the specified namespace |
| `~/*` | No namespace; trims all service config from the slice |
| `host` (bare) | Treated as `./host` — current Sidecar's namespace |

The `host` portion may itself be a single-label DNS wildcard (e.g. `*/*.example.com` admits `api.example.com` but not `example.com` nor `a.b.example.com`). This is the same single-label wildcard semantic Ferrum uses elsewhere (`config::types::wildcard_matches`, mesh DNS proxy); operators relying on deeper-than-one-label wildcards should list the additional surfaces explicitly. `MeshService` entries match their short name, `{name}.{namespace}`, `{name}.{namespace}.svc`, and `{name}.{namespace}.svc.{cluster_domain}` aliases. On the control plane this suffix follows `FERRUM_K8S_CLUSTER_DOMAIN`; in local mesh mode it follows `FERRUM_MESH_CLUSTER_DOMAIN`.

When Kubernetes `spec.egress` is omitted, Istio inherits the namespace-default outbound scope; Ferrum preserves that distinction so an ingress-only workload Sidecar does not override a namespace default. If no namespace default exists, Ferrum falls back to the root-namespace default Sidecar when one is present; otherwise omitted egress is treated as no narrowing. If a namespace-default Sidecar exists — even one with omitted egress — Ferrum does **not** fall through to the root-namespace default. This is an intentional divergence from upstream Istio for partial CP snapshots: the namespace-level object is treated as authoritative for that namespace, and an inheriting namespace default leaves the slice unnarrowed rather than guessing which root defaults the CP omitted. An explicit native/file `egress: []` or `~/*` trims all service config from the slice. When an admitted egress host also sets `spec.egress[].port.number`, Ferrum narrows matching `MeshService` and `ServiceEntry` port lists to the union of admitted ports; `DestinationRule` resources remain host-scoped because they do not carry a resource port list in the slice.

When multiple `Sidecar` resources apply at the same scope tier (two namespace-defaults, two root-namespace defaults, or two workload-scoped Sidecars both matching the same workload), the resolver picks the ASCII-smallest `name` as the deterministic tiebreak so reconciles are stable across pods and restarts.

### Workload Identity Narrowing

`FERRUM_MESH_SIDECAR_IDENTITY_NARROWING=true` adds a second, default-off narrowing pass after Sidecar egress scope has admitted services. The slice builder collects `MeshService.workloads[].spiffe_id` references from the admitted services and filters `workloads` to that reachable identity set. The flag only takes effect when `FERRUM_MESH_SIDECAR_ENFORCED=true`; with either flag disabled, workload identity lists keep the legacy namespace-wide behavior.

The local workload identity is still preserved separately on `MeshSlice::workload_spiffe_id`. It is often not listed under any admitted service's `workloads[]`, so it can be absent from the narrowed `slice.workloads` output; operators should treat `workload_spiffe_id` as the canonical local identity field.

Before enabling identity narrowing, confirm admitted `MeshService.workloads[]` lists are populated in a few representative slices. Empty workload refs on admitted services cause the second pass to remove every workload identity from `slice.workloads`; this usually indicates EndpointSlice reconciliation lag in Kubernetes-derived config or a file-mode service typo.

Inbound mTLS peer validation continues to use the trust bundle carried in the slice, not the `workloads` list. HBONE `source.principal` baggage continues to be accepted or rejected by peer-cert trust-domain matching plus `FERRUM_MESH_TRUST_DOMAIN_ALIASES`, not by checking whether the source identity appears in the narrowed workload list.

### Migration Notes

The flag defaults `false` so existing deployments see zero behavior change on upgrade. Operators should:

1. Apply `Sidecar` CRDs and verify the translator parses them without errors.
2. Set `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN=true` and inspect `GET /mesh/egress-scope` on a data plane to confirm the expected narrowing would apply without denying traffic.
3. Use `POST /mesh/egress-scope/test` to dry-run important destinations by host and port.
4. Set `FERRUM_MESH_SIDECAR_ENFORCED=true` on the CP and roll. DPs receive the already-narrowed slice - no DP-side configuration is required.
5. After egress narrowing is trusted, set `FERRUM_MESH_SIDECAR_IDENTITY_NARROWING=true` and roll the CP again to trim `slice.workloads` to reachable service identities.

### Egress Scope Operations

`GET /mesh/egress-scope` is a JWT-authenticated admin endpoint that returns the current workload's resolved egress scope: admitted services, admitted service-entries, known outbound registry destinations, dry-run status, and admitted/denied service counts. It returns 404 when no mesh slice has been installed yet rather than fabricating counts from raw config.

`POST /mesh/egress-scope/test` accepts JSON like `{"host":"ratings.default.svc.cluster.local","port":9080}` and returns whether the destination is currently admitted by the resolved scope. The endpoint is a dry-run check only; it never mutates slice state. It also returns 404 when no mesh slice has been installed.

When dry-run mode computes denied services, the data plane emits one transition warning when would-denies become active and one recovery info line when the next installed slice has no would-denies. It does not log per request. The `/health` response includes `mesh.egress_scope.sidecar_admitted_services` and `mesh.egress_scope.sidecar_denied_services` for readiness dashboards.

The `mesh_outbound_registry` plugin exposes `ferrum_mesh_outbound_registry_decisions_total` with `mesh_namespace`, `host`, and `decision` labels so operators can compare admitted and denied outbound destinations during rollout. To keep label cardinality bounded, the `host` label uses the actual destination only for `admit` decisions (constrained by the configured registry) — `deny` decisions always bucket under `host="<denied>"` since the Host header is attacker-controlled on that path. Operators triaging denied traffic should consult application logs for the requested host; the metric only signals the rate of denied egress per namespace.

Stream-family egress (TCP / UDP / TCP+TLS / UDP+DTLS) is enforced at the connect / first-datagram stage rather than via a plugin: when `outbound_traffic_policy: registry_only` is active and the gateway owns at least one mesh outbound capture listener port, stream proxies bound to those ports consult the same slice-derived registry before dialing the backend. Rejection semantics differ from HTTP:

- **TCP / TCP+TLS**: graceful close of the inbound connection before any backend dial happens. No SYN ever leaves the gateway, so backend circuit breakers, pool entries, and DNS caches stay untouched by hostile traffic. `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS` does not apply — TCP has no "HTTP status" concept.
- **UDP / UDP+DTLS**: the first datagram of a would-be new session is silently dropped (UDP has no RST analogue). Existing sessions are unaffected; the check only runs on session creation. DTLS handshakes are not initiated for unadmitted destinations.

Stream decisions are exported via a sibling counter `ferrum_mesh_outbound_registry_stream_decisions_total` with `mesh_namespace`, `protocol`, and `decision` labels (`protocol` ∈ {`tcp`, `tcp_tls`, `udp`, `udp_dtls`}). Keeping it as a sibling rather than adding a `protocol` label to the HTTP counter preserves Wave-1 dashboard compatibility. Stream rejects do not include a per-host label — the protocol label is the only dimension dashboards need, and TCP closes happen before SNI / Host material is structured. Operators triaging denied stream traffic should consult the gateway's structured `warn!` logs (one per reject) which include `backend_host`, `backend_port`, `listen_port`, and the client IP.

Enforcement is keyed on the runtime's mesh outbound capture listener port set. Stream proxies bound to other ports (inbound, admin, HBONE, east-west gateway, egress gateway) flow through unchanged — outbound policy never gates inbound traffic.

## Config Drift Introspection

`GET /mesh/config-drift` is a JWT-authenticated admin endpoint that surfaces a per-DP "where is this DP relative to the CP's last push?" view. Pair it with `ferrum_mesh_config_last_received_timestamp_seconds` (the gauge the GAP-3E Grafana dashboards already alert on) to triage stuck DPs — the metric tells you when the alert tripped; the endpoint tells you what slice content the DP actually applied.

The response always carries a `slice` block. After the first proxy-accepted slice it carries:

- `last_received_at` / `age_seconds` — wall-clock timestamp + seconds since the most recent proxy-accepted slice. Received-but-rejected updates do not advance this field or the fingerprint. `age_seconds` clamps to zero on backwards clock skew so an alert never fires on a future-stamped slice.
- `version` / `namespace` — the slice's own `version` string and `namespace` field, surfaced for self-describing cross-DP diffs.
- `resources` — counts per resource kind (workloads, services, mesh_policies, peer_authentications, service_entries, request_authentications, destination_rules, mesh_telemetry, mesh_proxy_configs, extension_configs). Always present; defaults to all zeros before the first slice so the shape is stable for dashboards.
- `fingerprint` — `sha256-<64 hex>` over a deterministic JSON encoding of the last proxy-accepted slice with per-DP identity metadata (`node_id`, `workload_spiffe_id`, `waypoint_name`, `labels`), `version`, and `runtime_overlay` stripped. Two DPs in the same namespace expecting the same resources produce the same fingerprint even when the CP re-stamps a no-op publish; divergence flags split-brain. The hash strips the overlay because RTDS-driven knobs (fault percentages, log level, transformer gates — see "xDS ADS Compatibility / RTDS") intentionally hot-swap without a new slice version; drift in the overlay surfaces under `runtime_overlay` instead.
- `source_protocol` / `source_cp_url` — configured source from `FERRUM_MESH_CONFIG_PROTOCOL` and the first entry of `FERRUM_DP_CP_GRPC_URLS`. Populated even before the first slice so dashboards can label DPs by source.

The optional `runtime_overlay` block (default included) summarises the live RTDS overlay as `{ key_count, keys, fingerprint }` where `keys` is the sorted list of overlay keys currently in effect and `fingerprint` hashes the typed overlay values. Pass `?include_overlay=false` to omit the block for high-frequency drift polling that only needs the slice fingerprint.

The optional `convergence` block is present only when `FERRUM_MESH_CONFIG_PROTOCOL=xds` and at least one ADS response has arrived; in native mode it is omitted entirely. It surfaces the xDS [resource-warming](#xds-ads-compatibility) state: `per_type_versions` (received `version_info` per subscribed type, keyed by short name — `cds`/`eds`/`lds`/`rds`/`sds`/`ecds`/`rtds`), `missing_required_types` (required types still awaiting an initial response — empty once the first slice can build), `converged` (every required type has responded **at one coherent `version_info`** — no required type missing and no version skew), and `version_skew` (all required types have responded but their `version_info` strings are **not** all identical). `converged` and `version_skew` are mutually exclusive: a skewed required set is a transient *waiting* state, not an applied one — the DP keeps serving the prior slice via `ArcSwap` and does not build a new one until the required versions reconverge. Because the CP force-refreshes every subscribed required type to one snapshot version on any required-mesh-slice change (including a policy/workload-only ECDS update), skew normally clears within a debounce window; a `version_skew` that persists points at a CP advancing required types independently of the ECDS security carriers and is worth investigating as config drift. This detail is JWT-gated here rather than on the unauthenticated `/metrics` surface because the version strings embed config-change timestamps and content digests; the aggregate `ferrum_xds_warming_partial_applies_total` counter is the safe-to-scrape companion signal.

The endpoint returns 404 outside mesh mode and 200 with `last_received_at` elided / zeroed `resources` when mesh mode is active but no slice has been accepted yet — operators rely on the difference between "404 (wrong mode)" and "200 with no `last_received_at` (mesh mode, not converged yet)".

Operator playbook:

- **Spot a stuck DP**: walk every DP in a deployment, compare `slice.last_received_at`. A significantly older timestamp on one DP flags a missing CP→DP stream. A safe upper bound is `slice.age_seconds > 2 * FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS` (default 600 s with the 300 s primary retry); operators expecting steadier CP push cadence should tighten the threshold to a small multiple of their observed push interval.
- **Spot split brain**: walk every DP, compare `slice.fingerprint`. All DPs in the same namespace expecting the same resources should agree — divergence means at least one DP is on a stale or wrong slice. Operators can recompute the fingerprint offline by (1) serialising the slice JSON with `node_id`, `workload_spiffe_id`, `waypoint_name`, `labels`, `version`, and `runtime_overlay` stripped, (2) recursively sorting object keys (`BTreeMap`-style) while preserving array order, (3) SHA-256 hashing the resulting bytes, and (4) prefixing the lower-case hex digest with `sha256-`.
- **Spot RTDS drift**: compare `runtime_overlay.keys` and `runtime_overlay.fingerprint` across DPs. Missing keys point to subscription or layer merge issues; matching keys with different fingerprints mean a same-key runtime value diverged.
- **Spot a wedged xDS DP**: when `convergence.converged` is `false` with a non-empty `convergence.missing_required_types` on a starting DP, the first slice is blocked waiting on those types — cross-check `ferrum_xds_first_slice_nacks_total` for a malformed required resource (NACK loop) versus a CP that is simply not sending that type (no NACKs, type stays missing).

A CP-side endpoint that reports what slice version the CP last published to each connected DP (so external tooling can diff "what the CP thinks each DP should have" against "what each DP reports here") is future work; this endpoint covers the DP-local half of the drift picture.

## DestinationRule

Istio `DestinationRule` resources are translated into Ferrum upstream and proxy configuration at the Kubernetes translation layer. The following fields are supported:

### Traffic Policy

- **`connectionPool.tcp.connectTimeout`**: mapped to the proxy's `backend_connect_timeout_ms`.
- **`outlierDetection`**: translated to Ferrum passive health checks:
  - `consecutive5xxErrors` -> `passive_health_check.consecutive_failures`
  - `interval` -> `passive_health_check.check_interval_seconds`
  - `baseEjectionTime` -> `passive_health_check.eject_duration_seconds`

### Load Balancer

Simple load balancer algorithms are mapped directly:

| Istio `simple` | Ferrum algorithm |
|---|---|
| `ROUND_ROBIN` | `round_robin` |
| `LEAST_REQUEST` / `LEAST_CONN` | `least_connections` |
| `RANDOM` | `random` |

Consistent hash load balancing (`consistentHash`) is translated to Ferrum's `consistent_hashing` algorithm with the hash key derived from `httpHeaderName`, `httpCookie`, or `useSourceIp`.

### Subsets

DestinationRule `subsets` are preserved as named subsets in the Ferrum upstream. Each subset can carry a `loadBalancer` override that takes precedence over the top-level traffic policy. Subset-level `tls` is also applied per subset: the cold-path apply layers the subset's TLS overlay onto the upstream-level TLS and stores the result on `Upstream.resolved_subset_tls[subset_name]`. `GatewayConfig::resolve_upstream_tls` then projects that overlay onto `Proxy.resolved_tls` for proxies whose `upstream_subset` selects the subset, so two proxies pointed at the same upstream but at different subsets (each carrying distinct `caCertificates` / `clientCertificate` / `privateKey` / `sni` / `subjectAltNames`) land on different resolved TLS values and partition the backend pool. Subset-level `outlierDetection` and `connectionPool` are still parsed by the K8s translator and warned but not applied per subset — top-level `trafficPolicy.outlierDetection` / `trafficPolicy.connectionPool.tcp.connectTimeout` remain the only paths to per-upstream passive health and connect timeout.

### Deferred Fields

Top-level and per-subset DestinationRule TLS settings (`trafficPolicy.tls`, `subsets[].trafficPolicy.tls`) are translated onto the matching Ferrum upstream's `backend_tls_*` fields and `resolved_subset_tls` map at slice-apply time. Backend handshake SNI consumption and SAN allow-list verification are enforced on the backend TLS paths; both settings — plus the selected subset name — are included in backend pool keys so distinct TLS identities never share connections.

Port-level `connectionPool.tcp.connectTimeout`, `loadBalancer`, and `outlierDetection` are **all enforced** for HTTP/H2/H3/gRPC/WebSocket/HBONE dispatch via `Upstream.port_overrides[port]` + `Proxy.dispatch_port_overrides[port]`. TCP, UDP, and DTLS stream proxies enforce only the per-port `connectTimeout` and `maxConnections`/`tcpKeepalive`; load-balancing and outlier-detection for stream-family upstreams use upstream-level settings only. Port-level `connectionPool.tcp.maxConnections` is enforced for stream-family dispatch and for HTTP-family **WebSocket** dispatch (see the scope note below); `tcpKeepalive` remains stream-family only.

Top-level and per-port `connectionPool.http.{idleTimeout, http2MaxRequests}` are projected per port onto the same `Upstream.port_overrides[port]` slot and consumed by HTTP-family / gRPC dispatch via the per-target effective proxy (`Proxy.pool_idle_timeout_seconds`, `Proxy.pool_http2_max_concurrent_streams`). `connectionPool.http.maxRequestsPerConnection` is wire-projected end-to-end onto `Proxy.pool_max_requests_per_connection` but is currently inert at runtime — hyper does not yet expose a stable close-after-N-requests builder knob; once it does (or once a request-count wrapper is introduced) the field will activate without further translator work. The remaining HTTP knobs (`http1MaxPendingRequests`, `maxRetries`, `h2UpgradePolicy`) are deferred T1-C follow-ons and surface as a `debug!` line at translate time so operators see acknowledgement without admission failure.

Pool keys for the reqwest, direct-H2, and gRPC backends intentionally exclude policy fields, so two proxies that share `(host, port, TLS)` but configure different per-port `idleTimeout` / `http2MaxRequests` share a single materialised connection — the first proxy to materialise the pool entry sets the effective idle window and H2 stream cap for everyone reusing it. Operators who need strict per-proxy isolation fragment the pool via `dns_override` (or distinct `upstream_subset` / `backend_tls_*` material). This matches the existing `backend_connect_timeout_ms` cross-proxy sharing tradeoff documented in CLAUDE.md's "Policy cross-proxy sharing" note.

### DestinationRule `maxConnections` enforcement scope

`connectionPool.tcp.maxConnections` caps **concurrent open backend connections per destination** — Envoy's semantics. Keying is per resolved `(host, port)` endpoint, not per logical cluster, so a destination with N endpoint hosts sharing one port has an effective ceiling of N×cap rather than Envoy's per-cluster total (the two are equivalent for the typical single-host mesh destination). Ferrum enforces it everywhere it owns the backend connection's lifecycle and that lifecycle maps onto an open-connection count:

- **Stream-family (TCP / TCP+TLS / TCP-passthrough)**: each accepted stream dials one dedicated backend socket whose lifetime equals the relay session. Enforced at dial with an RAII counter on the shared `BackendConnectionLimiter` (`src/backend_conn_limit.rs`), the same primitive the WebSocket path uses, held on `TcpProxyMetrics.backend_inflight` (`src/proxy/tcp_proxy.rs`).
- **HTTP-family WebSocket (H1/H2/H3)**: a proxied WebSocket opens one dedicated, non-pooled backend TCP/TLS connection whose lifetime equals the session. Enforced at the backend dial with an RAII counter on the shared `ProxyState.backend_conn_limit` (`src/backend_conn_limit.rs`), acquired in the WebSocket connect loop (so a failed/rotated connect attempt frees its slot before retry) and held for the session. Over the cap, the upgrade is rejected with `503` before dialing.

The **pooled, multiplexed HTTP-family transports do not enforce it**, by design, because their backend connection lifecycle is not observable as an open-connection count on the request path:

- **reqwest (plain HTTP/1.1 and reqwest-path HTTP/2)**: `reqwest::Client` fully owns and hides its internal TCP connection pool (`src/connection_pool.rs`). Ferrum never observes a socket open, close, or reuse, so there is no event to count against the cap without forking the reqwest connector. The request path only sees "send a request", not "open a connection".
- **Direct H2, gRPC, HTTP/3, HBONE**: these pools keep one (or `http2_connections_per_host`-sharded) long-lived, multiplexed connection per destination in a `DashMap`, reused across unlimited concurrent requests and reaped only by idle eviction (`src/proxy/http2_pool.rs`, `src/proxy/grpc_proxy.rs`, `src/http3/client.rs`, `src/proxy/hbone_pool.rs`). "Open a new backend connection" is decoupled from the request by pool reuse, sharding, and idle eviction. Counting per request would measure request concurrency — Envoy's `http.maxPendingRequests` / `http2MaxRequests` territory (the latter is already mapped via `h2_max_concurrent_streams`), not open connections — and tying a decrement to the streaming/retry/error exit paths in dispatch would risk leaking a count and wedging the destination. For these multiplexed transports Envoy's own `maxConnections` is largely advisory (typically one connection per upstream host) and `http2MaxRequests` is the meaningful concurrency knob.

This is a deliberate, tested limitation rather than an oversight: a counter keyed to the pooled connection lifecycle would require threading an RAII guard through the shared `GenericPool` insert/evict/replace/destroy paths (`src/pool/mod.rs`) — every one a potential leak site on the hot path — for a control that does not match Envoy's effective behavior on multiplexed transports. Operators who need a hard per-destination concurrent-connection ceiling on a non-WebSocket HTTP route should bound concurrency with `http2MaxRequests` (H2/gRPC) and the global / per-IP request caps instead.

## Observability

### RED Metrics

The auto-injected `workload_metrics` plugin emits Istio/GAMMA-shaped RED (Rate, Errors, Duration) metrics:

- `ferrum_mesh_requests_total` -- request counter.
- `ferrum_mesh_request_duration_ms` -- request duration histogram.

Labels include:

| Label | Description |
|---|---|
| `source_workload` | Source workload name |
| `source_namespace` | Source workload namespace |
| `source_principal` | Source SPIFFE ID |
| `source_app` | Source `app` label |
| `destination_workload` | Destination workload name |
| `destination_namespace` | Destination workload namespace |
| `destination_principal` | Destination SPIFFE ID |
| `destination_service` | Destination service name |
| `destination_app` | Destination `app` label |
| `request_protocol` | Protocol (http, grpc, tcp) |
| `response_code` | HTTP status code |
| `response_flags` | Error flags |
| `connection_security_policy` | `mutual_tls` or `none` |

### Service Graph

`GET /mesh/service-graph` exposes the same mesh identity labels as a node-local service graph. The graph is built by the auto-injected `workload_metrics` plugin at log time and aggregates HTTP-family traffic by `(source_principal, destination_principal)` with request count, error count, total duration, average duration, and last-seen timestamp. The admin endpoint is JWT-authenticated and reads an `ArcSwap` snapshot, so dashboard polling does not iterate the live `DashMap` counters.

The endpoint is intentionally node-local. In CP/DP or horizontally scaled mesh deployments, scrape every data-plane instance and aggregate source/destination edges in the observability backend.

### Policy-Deny Drilldown

`GET /mesh/policy-denies/recent` (JWT-authenticated, JSON) returns aggregated recent `mesh_authz` denies for ad-hoc triage. Each deny event captured by the plugin is appended to a process-singleton bounded ring (`PolicyDenyRecorder`). The endpoint groups events whose timestamp is inside the requested window by the `(rule, source, destination, reason)` tuple and returns the top-N rows sorted by count descending (tie-break `last_at` descending, then `rule` ascending). The recorder is exception-path only — the proxy hot path never touches it; only the `mesh_authz` deny branch records — so it has no measurable effect on allow-path latency.

| Query | Default | Maximum |
|---|---|---|
| `window` | `5m` | `1h` |
| `limit` | `50` | `1000` |

`window` accepts the compact suffixes `s` / `m` / `h` or a bare integer of seconds. Exceeding the maxima or supplying `window=0` returns `400 Bad Request`. Unknown query parameters are silently ignored so future extensions don't 4xx older deployments.

Response shape:

```json
{
  "window_seconds": 300,
  "limit": 50,
  "total_denies": 1234,
  "grouped": [
    {
      "rule": "deny-prod-from-staging",
      "source": "spiffe://cluster.local/ns/staging/sa/web",
      "destination": "spiffe://cluster.local/ns/prod/sa/api",
      "reason": "namespace_mismatch",
      "count": 87,
      "first_at": "2026-05-18T19:32:11Z",
      "last_at":  "2026-05-18T19:36:48Z"
    }
  ]
}
```

`source` and `destination` are omitted (instead of serialised as `null`) when the deny fired before either identity was known — for example unauthenticated HBONE baggage. `total_denies` reports the size of the unfiltered window slice; `grouped` is a `min(distinct_groups, limit)`-sized projection. Returns `404 Not Found` outside mesh mode.

The recorder's ring capacity defaults to `10000` events. Operators can override it with `FERRUM_MESH_POLICY_DENY_LOG_CAPACITY` (set to `0` to disable the recorder entirely; the endpoint still serves an empty `grouped` array). The ring is FIFO; oldest entries are evicted first when capacity is reached.

The endpoint complements `ferrum_mesh_requests_total{response_code="403"}` from the Prometheus dashboard — the metric counts denies in aggregate, while this endpoint preserves the drill-down dimensions an operator needs when diagnosing a misconfigured `AuthorizationPolicy`. Like the service graph, the recorder is node-local; in horizontally scaled deployments query every data-plane instance and merge by `(rule, source, destination, reason)` in the observability backend.

### Certificate and CA Telemetry

`/metrics` also exposes mesh identity health:

- `ferrum_mesh_cert_expiry_seconds{spiffe_id,source}` -- seconds until the observed X.509-SVID expires. Sources include `rotation`, `internal`, `spire_agent`, and `workload_api`.
- `ferrum_mesh_cert_rotation_failures_total{spiffe_id,source}` -- failed SVID rotation or fetch attempts.
- `ferrum_mesh_ca_health{ca_type}` -- `1` when a CA backend is healthy, `0` when the backend is unavailable or not implemented.
- `ferrum_mesh_trust_bundle_version{trust_domain,source}` -- monotonic version incremented when the observed trust bundle roots change.
- `ferrum_mesh_config_last_received_timestamp_seconds{namespace}` -- Unix timestamp of the last installed mesh slice, used for stale-config alerting.
- `ferrum_mesh_mtls_handshake_failures_total{reason}` -- frontend TLS/mTLS handshake failures by reason (`timeout` or `error`).
- `ferrum_xds_streams_rejected_total` -- aggregate count of ADS streams the CP rejected for exceeding the per-node concurrent-stream ceiling (`FERRUM_XDS_MAX_STREAMS_PER_NODE`). Emitted without labels (the offending `node_id` is captured in the structured `warn!` log at the reject site; the metric series is deliberately label-free because `Node.id` is client-controlled and would otherwise be an unbounded high-cardinality dimension). A growing value flags a misconfigured or hostile DP opening many streams.
- `ferrum_xds_first_slice_nacks_total{namespace,type_url}` -- NACKs of a required mesh-slice type emitted by the DP while still waiting for its first slice. A non-zero, growing value on a starting DP means first-slice convergence is blocked by a malformed required resource (see [xDS ADS Compatibility](#xds-ads-compatibility)).
- `ferrum_xds_warming_partial_applies_total{namespace}` -- count of mesh slices the DP applied while the required-type `version_info` strings were skewed (not all identical). Under the coherent-version gate the DP builds a slice only once every required type reports the same version, and the CP force-refreshes all subscribed required types to one snapshot version on any change, so on a healthy Ferrum-CP-to-Ferrum-DP feed this counter should stay at **0** — normal coherent xDS apply must not increment it. A non-zero or growing value is a defensive signal that a slice was installed under version skew (e.g. a CP advancing required types independently of the ECDS security carriers); investigate it as potential config drift rather than treating it as expected warming activity. Keyed by `namespace` only (low, operator-bounded cardinality, matching `ferrum_xds_first_slice_nacks_total`). The detailed per-type `version_info` strings and still-missing required types are deliberately **not** exported here — they embed config-change timestamps and content digests, so they live behind JWT on the `GET /mesh/config-drift` `convergence` block instead.

The Prometheus endpoint is intentionally unauthenticated for scraper compatibility, and mesh RED/certificate series include SPIFFE identity labels. Restrict network reachability to trusted scrapers (for example with a Kubernetes `NetworkPolicy`, private scrape port, or scrape-side reverse proxy) if namespace/service-account identity disclosure is sensitive.

The Helm chart can install a `PrometheusRule` when `observability.enabled=true` and `observability.alerts.enabled=true`. The bundled rules cover certificate expiry, rotation failures, CA health, stale DP config, mTLS handshake failures, policy-deny spikes, and injector webhook failures. The observability dashboard config map includes RED, service-graph edge count, mTLS coverage, USE-lite process panels, certificate status, and trust-bundle churn panels.

The injector webhook failure alert uses the Kubernetes API server metric `apiserver_admission_webhook_rejection_count`. Clusters that do not scrape kube-apiserver metrics will show that alert as no data; all Ferrum-emitted metric alerts continue to evaluate normally.

### Telemetry API

`MeshTelemetryResource` provides per-scope telemetry configuration, merged by specificity (most specific scope wins per section):

**Scope precedence**: `WorkloadSelector` > `Namespace` > `MeshWide`

Each section (tracing, metrics, access logging) is merged independently. Within the same scope level, later resources win. Deterministic ordering is ensured by namespace/name tie-breaking.

**Tracing configuration**:

- `sampling_percentage`: 0.0--100.0 (deterministic hash-based sampling).
- `custom_tags`: literal key-value tags injected into every span.
- `custom_header_tags`: tags resolved from request headers at runtime.
- Istio `customTags.environment` resolves environment variable values during translation and emits them as span tags. Treat write access to Telemetry resources as privileged: referencing secret-bearing env vars can expose those values through tracing sinks.
- `providers`: inline span exporters for Zipkin v2, Datadog Agent `/v0.3/traces`, Lightstep OTLP, and OpenTelemetry OTLP/HTTP JSON. Lightstep uses `accessTokenEnv` so bearer credentials stay in the local process environment instead of mesh config JSON. Multiple providers receive the same sampled span.
- `disable_span_reporting` / Istio `disableSpanReporting`: when explicitly true, suppresses span export while leaving the rest of the merged tracing config visible. Omitted values inherit from less-specific scopes; explicit false can re-enable a more-specific scope.
- `match.mode` (`SERVER` / `CLIENT` / `CLIENT_AND_SERVER`, default `SERVER`): each mesh listener stamps a traffic direction onto every accepted request — sidecar / ambient / HBONE / egress inbound listeners stamp `Inbound`, sidecar/ambient outbound capture stamps `Outbound`. The translator unions every `tracing[].match.mode` across the merged Telemetry block into a single `direction_emit` on the auto-injected `workload_metrics` plugin. The plugin emits SERVER-kind spans on inbound directions and CLIENT-kind spans on outbound directions and drops the export entirely when the listener direction is not enabled. Span payloads carry the kind in every provider format: OTLP enum `2` / `3` (SERVER / CLIENT), Zipkin v2 top-level `"kind": "SERVER"` / `"CLIENT"`, and Datadog `meta["span.kind"]` set to `"server"` / `"client"`. Non-mesh listeners (file / db / cp / dp HTTP entrypoints) leave the direction unset and the plugin falls back to its server-only default.

Datadog export groups spans by trace in the Agent v0.3 payload shape and sends the upper 64 bits of W3C 128-bit trace IDs via `_dd.p.tid` while the numeric `trace_id` field carries the low 64 bits.

**Metrics configuration**:

- `tag_overrides`: rename, remove, or set custom values for metric tags.
- `disabled_metrics`: specific metric names to suppress.

**Access logging configuration**:

- `enabled`: toggle (default true). When false, the access log plugin is not injected.
- `filter`: optional `AccessLogFilter` with `status_code_min`, `status_code_max`, `min_latency_ms`, and `errors_only`.

The access log is injected as a `stdout_logging` global under the reserved id `__mesh_access_log` (carrying the `filter` above). Like every auto-injected global, an operator-managed global of the **same plugin type** overrides it: if you define your own global `stdout_logging`, the `__mesh_access_log` injection is suppressed so transactions are not logged twice, and the Telemetry CRD's `accessLogging.filter` is **not** applied on top of your plugin. To keep the mesh-managed filter, leave access logging to the injected plugin (do not also define a global `stdout_logging`), or fold the equivalent `filter` into your own global `stdout_logging` config.

## Kubernetes Injector

`FERRUM_MODE=injector` runs a Kubernetes admission webhook that injects Ferrum mesh sidecars into pods. The injector only produces JSON patches; all mesh runtime work happens in `FERRUM_MODE=mesh`.

### Webhook Setup

The injector listens on `FERRUM_INJECTOR_LISTEN_ADDR` (default `0.0.0.0:9443`) and handles `POST /mutate`. AdmissionReview request bodies are capped before JSON parsing by `FERRUM_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB` (default `4`, max `64`).

**TLS is required and fail-closed.** Kubernetes calls admission webhooks over HTTPS, so the injector requires both `FERRUM_INJECTOR_TLS_CERT_PATH` and `FERRUM_INJECTOR_TLS_KEY_PATH` and **refuses to start** when neither is set. For local development only, set `FERRUM_INJECTOR_ALLOW_PLAINTEXT=true` to serve plaintext HTTP; the injector logs a loud warning at startup in that mode. Setting only one of the cert/key pair is always a configuration error.

**Request validation (fail-closed on injection).** The injector validates each AdmissionReview before injecting:

- **Pod-kind check:** the request must target a core (`apiGroup: ""`) `Pod` — confirmed via `request.kind` (a `GroupVersionKind`) or, when `kind` is absent, the core `pods` `request.resource`. A mis-scoped `MutatingWebhookConfiguration` that routes other kinds (or a request carrying no kind/resource metadata) is **admitted with `allowed: true` and no patch**, and a warning is logged. The injector never patches an unknown kind.
- **`dryRun`:** the patch-only webhook has no side effects, so a `dryRun: true` request returns the identical computed patch without implying any side effect.

These complement the existing boundary checks: the body-size limit (returns `413`), reserved-container-name conflicts (`ferrum-edge` / `ferrum-edge-init`) refuse injection, and invalid port/CIDR annotations are rejected with a webhook error that names the offending annotation.

Register with Kubernetes:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: ferrum-edge-injector
webhooks:
  - name: ferrum-inject.ferrum.io
    clientConfig:
      service:
        name: ferrum-edge-injector
        namespace: ferrum-system
        path: /mutate
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
        operations: ["CREATE"]
```

### Annotation Control

The injector checks annotations and labels to decide whether to inject:

| Annotation/Label | Effect |
|---|---|
| `ferrum.io/inject: "true"` | Opt-in injection |
| `sidecar.istio.io/inject: "true"` | Opt-in injection (Istio compat) |
| `ferrum.io/mesh: "enabled"` (label) | Opt-in injection |
| `ferrum.io/inject: "false"` | Skip injection |
| `sidecar.istio.io/inject: "false"` | Skip injection (Istio compat) |
| `ferrum.io/mesh: "false"` or `"disabled"` (label) | Skip injection |
| `ferrum.io/injected` | Skip (already injected) |

When `FERRUM_INJECTOR_REQUIRE_ANNOTATION=true` (default), pods must explicitly opt in via `ferrum.io/inject: "true"`, `sidecar.istio.io/inject: "true"` (Istio compat), or the `ferrum.io/mesh: "enabled"` label. When `false`, all pods are injected unless explicitly opted out.

### Port and IP-Range Capture Overrides

The injector supports per-pod capture overrides via annotations. The Istio annotation namespace is honored byte-for-byte so workloads can migrate without rewriting metadata; Ferrum-native annotations are accepted as aliases for the port lists.

| Annotation | Direction | Semantics |
|---|---|---|
| `traffic.sidecar.istio.io/includeOutboundPorts` | outbound | Comma-separated TCP destination ports included in outbound capture, or `*` for all outbound ports; when set to explicit ports, outbound REDIRECT rules are scoped to these ports |
| `ferrum.io/includeOutboundPorts` | outbound | Ferrum-native alias for the above |
| `traffic.sidecar.istio.io/excludeOutboundPorts` | outbound | Comma-separated TCP destination ports excluded from outbound capture (Istio-compatible) |
| `ferrum.io/excludeOutboundPorts` | outbound | Ferrum-native alias for the above |
| `traffic.sidecar.istio.io/excludeInboundPorts` | inbound | Comma-separated TCP destination ports excluded from inbound capture (Istio-compatible). RETURN rules are emitted BEFORE the inbound REDIRECT so the exclusion is honored |
| `ferrum.io/excludeInboundPorts` | inbound | Ferrum-native alias for the above |
| `traffic.sidecar.istio.io/excludeOutboundIPRanges` | outbound | Comma-separated CIDRs appended to the env-derived outbound exclude list (matches Istio: per-pod additive) |
| `traffic.sidecar.istio.io/includeOutboundIPRanges` | outbound | Comma-separated CIDRs that REPLACE the env-derived outbound include list when present (matches Istio: include-overrides-include) |

Port-list annotations merge with their Ferrum aliases; exclude lists also merge with the applicable injector-level defaults. `includeOutboundPorts` is annotation-only and narrows outbound REDIRECT rules to the listed TCP destination ports when the include CIDR list is only the implicit catch-all. If `includeOutboundIPRanges` is also explicit, the rule sets are additive: all ports inside the explicit CIDRs are captured, plus the listed ports to any destination. The `*` wildcard means all outbound ports to any destination, even when explicit include CIDRs are also present. Outbound exclude ports still win because their RETURN rules are emitted first. CIDR annotations are validated at admission time -- invalid ports or CIDRs are rejected with a webhook error that names the offending annotation, so a typo cannot silently produce a broken iptables plan.

**Pod-restart caveat (injector / iptables init container):** annotations consumed by the `injector` mode are evaluated at pod admission time only. Existing pods retain their previous iptables capture rules until restart; bouncing affected workloads is required for previously-ignored annotations to take effect in the init-container path. The eBPF capture path lifts this restriction for `includeOutboundPorts` -- see below.

**eBPF/ambient capture:** the eBPF capture path honors per-pod `includeOutboundPorts` annotations through the `FERRUM_INCLUDE_PORTS` BPF map (keyed by cgroup id). The node-agent parses `traffic.sidecar.istio.io/includeOutboundPorts` / `ferrum.io/includeOutboundPorts` on enrollment via the shared `crate::capture::include_outbound_ports_from_annotations` helper -- exactly the same parser the injector uses for the iptables init container -- and writes a per-cgroup `IncludePortsPolicy` record. The `connect4` / `connect6` BPF programs look up the calling task's cgroup id (`bpf_get_current_cgroup_id`); absent entries fail-open (capture every port that survived the earlier checks), so un-annotated pods retain their previous behavior. The map caps explicit ports at `INCLUDE_PORTS_MAX` (16) per pod; overflow truncates with a `warn!` -- it does not abort enrollment.

**Leaf-vs-pod cgroup keying:** `bpf_get_current_cgroup_id()` returns the *container leaf* cgroup the connecting task lives in -- a child of the pod cgroup on every Kubernetes cgroup driver (`.../kubepods-pod<uid>.slice/<container>.scope`, `.../pod<uid>/<container-id>`), not the pod cgroup itself. The **`FERRUM_WORKLOAD_IDENTITY`** map (GAP-1b source-pod identity) therefore enrolls the **whole pod cgroup subtree** -- the pod inode plus every descendant container-cgroup inode (`cgroup::collect_cgroup_tree_inodes`) -- and re-walks the subtree on each reconcile so container cgroups that start or restart after initial enrollment (Kubernetes emits many Modified events per pod) are picked up within seconds. Without this the hook's leaf-keyed lookup would always miss and node-waypoint identity resolution would fail closed in real pods. **`FERRUM_INCLUDE_PORTS`** (per-pod `includeOutboundPorts` narrowing) is keyed the same way and enrolls the same subtree, re-walking on every reconcile (like identity) so a container leaf that starts or restarts after the initial pod event still picks up the policy — without that, narrowing would silently never engage for the common case where containers start after the pod cgroup. The per-event `read_dir` is paid only for annotated pods; unannotated pods short-circuit before any walk.

**Mid-life annotation updates:** the node-agent watches Kubernetes Pod `Modified` events (kube-rs `Event::Apply` conflates added + modified) and re-reads `includeOutboundPorts` on every event. A diff against the policy stashed at enrollment time gates the BPF map write so unrelated Modified events (status updates, image-pull progress, condition flips) are skipped without syscalls -- the policy structurally compared is the post-merge, sorted, deduplicated `IncludePortsPolicy`, so reordering ports in the annotation is also a no-op. When the parsed policy differs the node-agent writes the new entry, or removes it when the annotation is stripped entirely. Failures to re-apply (annotation parse error or BPF map write error) keep the previous policy in place rather than silently widening capture; the failure is counted in `ferrum_node_agent_pod_annotation_updates_failed_total` and the successful re-apply count is exposed as `ferrum_node_agent_pod_annotation_updates_applied_total`. Cgroup-id-unavailable retries (Pod object reached the watcher before kubelet finished creating the cgroup) are intentionally not counted as failures because they are routinely observed during early pod startup and are retried on the next Apply event. Opt-in/opt-out label or annotation flips (`ferrum.io/inject` true⇄false, `ferrum.io/mesh` enabled⇄disabled) trigger enrollment or un-enrollment on the next Apply event. **Long-lived flow caveat:** the BPF programs hook `connect(2)`, so a policy change applies only to *new* outbound connections; established TCP flows continue using the redirect chosen at their original connect call and are unaffected until they close and reconnect.

**IPv6 CIDRs:** `includeOutboundIPRanges` / `excludeOutboundIPRanges` accept IPv6 CIDR literals (e.g. `fd00::/8`) and `IptablesPlan::for_config` partitions rules by address family. Any IPv6 CIDR in either the include or exclude list activates the IPv6 address family: outbound IPv6 rules are rendered for the configured include/exclude lists, and inbound IPv6 capture emits the same default redirect/exclusion shape as IPv4. If explicit include ports are set, port REDIRECT rules are emitted for IPv6 too once that family is active; without an IPv6 CIDR, include-port rules only render in the IPv4 plan. IPv4 rules are emitted through `iptables`; IPv6 rules are emitted through `ip6tables`. `FERRUM_MESH_IP6TABLES_ENABLED=auto` probes for `ip6tables` and skips only the IPv6 rule block when the binary is absent, so legacy IPv4-only nodes do not crash-loop. Set it to `true` to require `ip6tables` whenever IPv6 rules are present; this is all-or-nothing, so a missing `ip6tables` binary fails before any IPv4 rules are applied. Set it to `false` for permanent IPv4-only capture. The injector init-container script and node-agent iptables fallback both render from the same `IptablesPlan`, so their IPv6 wrapping semantics stay aligned.

### SPIFFE ID Derivation

The injector derives the workload SPIFFE ID from the pod's service account:

```
spiffe://{TRUST_DOMAIN}/ns/{NAMESPACE}/sa/{SERVICE_ACCOUNT}
```

`FERRUM_INJECTOR_TRUST_DOMAIN` (default `cluster.local`) sets the trust domain.

### Sidecar Container

The injected sidecar container runs `ferrum-edge run` with environment variables:

- `FERRUM_MODE=mesh`
- `FERRUM_NAMESPACE={pod_namespace}`
- `FERRUM_MESH_TOPOLOGY=sidecar`
- `FERRUM_MESH_CAPTURE_MODE={capture_mode}`
- `FERRUM_MESH_WORKLOAD_SPIFFE_ID=spiffe://...`
- CP connection variables forwarded from `FERRUM_DP_CP_GRPC_URLS`, TLS paths, etc.
- `FERRUM_CP_DP_GRPC_JWT_SECRET` via `valueFrom.secretKeyRef` (never plaintext)

The container runs as `FERRUM_MESH_PROXY_UID` (default 1337) with `allowPrivilegeEscalation: false`.

### Capture Modes

`FERRUM_MESH_CAPTURE_MODE` controls traffic interception:

| Mode | Description |
|---|---|
| `explicit` (default) | No automatic capture; applications must explicitly route to the proxy |
| `iptables` | Inject init container with `NET_ADMIN`/`NET_RAW` capabilities that sets up iptables rules to redirect traffic through the sidecar (inbound to 15006, outbound to 15001) |
| `ebpf` | eBPF-based capture handled by a node-level agent (requires kernel 5.7+). The injector does not inject a privileged init container for this mode -- the node agent's DaemonSet manages eBPF program attachment. Capture planning infrastructure (`EbpfPlan` with iptables fallback for pre-5.7 kernels) is available in `src/capture/mod.rs` for the node agent path. **Build requirement:** real eBPF attachment needs a binary built with the Cargo `ebpf` feature (`cargo build --features ebpf`, Linux only; Docker `--build-arg FEATURES=cloud-secrets,ebpf`). The **default published image uses a no-op mock backend** (`MockEbpfBackend`) that attaches nothing and sets `ferrum_mesh_node_topology_degraded` — see [Maturity and Support Status](#maturity-and-support-status) |

## Control Plane Integration

### MeshGrpcServer

The `MeshConfigSync.MeshSubscribe` streaming RPC is served by `MeshGrpcServer` in `src/grpc/mesh_server.rs`. It runs on the Control Plane alongside the regular `ConfigSync` service.

- **JWT authentication** on every subscribe request.
- **Namespace validation**: a single CP serves a single namespace. Mesh nodes requesting a different namespace are rejected with `FAILED_PRECONDITION`.
- **Version compatibility**: the CP validates the mesh node's Ferrum version for protocol compatibility.
- **Initial snapshot**: on subscribe, the CP loads the current `GatewayConfig`, computes a `MeshSlice` for the subscriber's identity (node ID, namespace, SPIFFE ID, labels), and sends it as the first update.
- **Delta vs full**: subsequent config changes are broadcast via tokio `broadcast` channel (capacity `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY`). The server computes `content_eq()` to suppress no-op updates. Lagging subscribers automatically receive a full snapshot.
- **Incremental apply**: DB polling deltas are applied incrementally to each stream's config shadow, and a new slice is computed and sent only if the content changed.

### MeshNodeRegistry

The CP tracks connected mesh nodes in `MeshNodeRegistry` (DashMap, `src/grpc/mesh_registry.rs`). Each entry records the node ID, version, namespace, and connection timestamps.

- Nodes are automatically removed when their gRPC stream drops (via `TrackedMeshStream`'s `Drop` implementation).
- `touch_all()` updates `last_update_at` on every broadcast.
- Stale removal uses `remove_if_stale()` with timestamp comparison to handle reconnects that raced with the old stream's drop.

### Gateway Mesh Service Discovery

Gateway database/file/DP modes can resolve mesh services through an upstream `service_discovery` block with `provider: mesh`. The provider reads the current CP-delivered `GatewayConfig.mesh` snapshot, finds a `MeshService` by `service_name` and namespace, resolves its workload SPIFFE references to workload addresses, and publishes ordinary `UpstreamTarget` entries into the existing load balancer cache.

Generated targets are tagged with `mesh.spiffe_id`, `mesh.namespace`, `mesh.service`, `mesh.trust_domain`, and `mesh.hbone=true`. This keeps the north-south gateway on the same discovery model as mesh mode while giving later gateway-to-mesh transport phases enough metadata to prefer HBONE/mTLS paths.

### Auto-Injected Plugins

Mesh mode automatically injects these global plugins with reserved IDs:

| Plugin ID | Plugin Type | Priority | Purpose |
|---|---|---|---|
| `__mesh_spiffe_identity` | `spiffe_identity` | 940 | Extract peer SPIFFE ID from TLS/DTLS client certs |
| `__mesh_authz` | `mesh_authz` | 2075 | Evaluate MeshPolicy authorization rules |
| `__mesh_workload_metrics` | `workload_metrics` | (default) | Istio/GAMMA RED metric labels from SPIFFE/HBONE identity |
| `__mesh_request_auth` | `jwks_auth` | (default) | JWT validation from MeshRequestAuthentication rules |
| `__mesh_access_log` | `stdout_logging` | (default) | Access logging with optional Telemetry API filters |

An operator-managed global plugin of the same type takes precedence over mesh-injected plugins (explicit override). See [plugin_execution_order.md](plugin_execution_order.md) for the full lifecycle phase matrix.

## Gateway-to-Mesh Bridge

Non-mesh gateway modes (`database`, `file`, `cp`, `dp`) can route traffic into the mesh via the gateway-to-mesh bridge. This enables a Ferrum gateway operating as an ingress or API gateway to forward requests to mesh workloads over HBONE with full SPIFFE mTLS.

### Trust Bundle Distribution

The Control Plane distributes gateway SPIFFE trust bundles to Data Planes via a `trust_bundles_json` side channel on the `ConfigUpdate` proto message. DPs hot-swap received bundles into the gateway SVID identity slot, enabling mutual TLS with mesh sidecars without requiring the DP to independently obtain certificates.

### HBONE Outbound Pool

When an upstream target is tagged with `mesh.hbone=true` metadata, the gateway routes requests through an HBONE HTTP/2 CONNECT pool (`HboneOutboundPool`) instead of direct HTTP. The pool uses the gateway's SPIFFE identity for mTLS and keys connections by SVID fingerprint so certificate rotation triggers fresh connections. DNS resolution uses the shared `DnsCacheResolver`.

On HBONE connect failure, the gateway falls back to plain HTTP dispatch so partially-mesh-enabled upstreams degrade gracefully.

### Mesh Service Discovery

A `service_discovery.provider: mesh` option resolves upstream targets from CP-delivered mesh service and workload snapshots. The provider maps workload addresses and ports into upstream targets with SPIFFE/HBONE metadata tags, enabling the HBONE outbound pool to route transparently. Target lists are refreshed on every mesh slice update.

Identity baggage from the client request is stripped from tunneled inner HBONE requests to prevent identity spoofing across the gateway boundary.

## Mesh Identity

### SPIRE Agent CA

`FERRUM_MESH_CA_BACKEND=spire_agent` delegates SVID issuance to a SPIRE Agent via the SPIFFE Workload API. The mesh data plane connects to the SPIRE Agent socket and receives X.509 SVIDs for its configured workload identity.

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_CA_BACKEND` | `none` | CA backend: `none` (no automatic identity), `internal` (self-signed dev CA), `spire_agent` (SPIRE Workload API) |
| `FERRUM_MESH_SPIRE_AGENT_SOCKET` | `/run/spire/sockets/agent.sock` | SPIRE Agent Workload API Unix socket path |
| `FERRUM_MESH_CERT_TTL_SECONDS` | `3600` | Requested certificate TTL for issued SVIDs |

The SPIRE backend is the recommended production path for mesh identity. `internal` is intended for development and testing only -- it generates a self-signed root CA at startup with no external trust anchor.

### Internal Dev CA and Production Guardrails

The `internal` CA backend is backed by a self-signed root produced by the dev bootstrap helper in `src/identity/ca/bootstrap.rs`. To make it impossible to accidentally run a production mesh on an unanchored self-signed root, the helper is protected by two environment guardrails, both read directly at the time the helper is invoked (they are **not** parsed into `EnvConfig`):

| Variable | Default | Semantics |
|---|---|---|
| `FERRUM_MESH_PRODUCTION_MODE` | `false` | Master kill-switch for all dev-only identity shortcuts. When `true`, the self-signed CA bootstrap is **refused unconditionally**, and so is construction of the dev-only static attestor (`FERRUM_MESH_ALLOW_STATIC_ID`). Set this in every production deployment. |
| `FERRUM_MESH_CA_BOOTSTRAP_DEV` | `false` | Explicit opt-in to generate a self-signed mesh root. The helper refuses unless this is `true`. When it runs it emits a loud `warn!` (`DEV-ONLY, never use in production`). |
| `FERRUM_MESH_ALLOW_STATIC_ID` | `false` | Sibling guardrail (not CA-specific): the dev-only `StaticAttestor`, which returns a hard-coded SPIFFE ID for any peer, refuses to construct unless this is `true` and `FERRUM_MESH_PRODUCTION_MODE` is not `true`. |

Both gates must agree before a self-signed root is minted: `FERRUM_MESH_CA_BOOTSTRAP_DEV=true` **and** `FERRUM_MESH_PRODUCTION_MODE` not `true`. Anything else fails closed.

For production mesh identity, run the SPIRE Agent backend (`FERRUM_MESH_CA_BACKEND=spire_agent`) so SVID issuance and trust-bundle distribution are anchored to a separately operated trust root. There is no `FERRUM_MESH_CA_CERT_PATH` / `FERRUM_MESH_CA_KEY_PATH` env var today — those names appear only in the bootstrap helper's refusal message as guidance for a future externally-provided-root path and are not currently read by any code path.

**No-identity startup gate.** A third member of this guardrail family is enforced at config-validation time rather than inside the identity helpers. A `mesh` data plane's runtime workload identity comes **only** from file-based gateway SVID material (`FERRUM_GATEWAY_SVID_CERT_PATH` + `KEY_PATH` + `TRUST_BUNDLE_PATH`); `FERRUM_MESH_CA_BACKEND` is parsed/validated but not yet wired to issue SVIDs into the data plane, so it does not by itself provide identity. With no gateway SVID material, the mesh can't present or verify an mTLS peer certificate, so PeerAuthentication's PERMISSIVE default would silently accept unauthenticated plaintext. `EnvConfig` validation therefore **fails startup closed** in that no-identity case unless the operator sets `FERRUM_MESH_ALLOW_NO_CA=true` to acknowledge the dev/test-only posture (a loud `warn!` is logged when it does start that way). That opt-out is read **directly from the environment** (not `ferrum.conf`), matching the rest of the family. As with the other shortcuts, `FERRUM_MESH_PRODUCTION_MODE=true` refuses the no-identity posture **unconditionally** — the opt-out is ignored — so a production mesh can never come up without identity.

## Node Agent Mode

`FERRUM_MODE=node_agent` runs a per-node DaemonSet agent that manages eBPF-based traffic capture for mesh sidecars. The node agent replaces the per-pod privileged init container used by iptables capture mode, providing lower-privilege pod injection and centralized capture management. The node-agent/proxy ABI is documented in [node_agent.md](node_agent.md).

### Architecture

The node agent runs on each Kubernetes node with the following responsibilities:

1. **Kernel probing**: verifies Linux kernel >= 5.7 and cgroup v2 + bpffs availability for eBPF program attachment.
2. **Pod watching**: monitors the Kubernetes API for pod events on the local node, matching pods that have opted into mesh injection.
3. **eBPF program attachment**: attaches cgroup-level and tc-level BPF programs to enrolled pods for transparent traffic redirection (4 cgroup + 1 tc program per pod).
4. **Lifecycle management**: enrolls/unenrolls pods with rollback on attach failure, graceful cleanup on pod deletion or agent shutdown.
5. **Fallback policy**: on kernels that lack eBPF support, fails fast by default; operators can explicitly opt into host iptables fallback with `fallbackMode: iptables` only when their node-agent image includes the required shell and iptables binaries.

### Deployment

The node agent is deployed as a Kubernetes DaemonSet with the Helm chart (`charts/ferrum-node-agent/`):

```yaml
nodeAgent:
  enabled: true
  image: ferrum-edge:latest
  captureMode: ebpf
  fallbackMode: fail      # set "iptables" only with a custom image that ships iptables tools
  resources:
    limits:
      cpu: 250m
      memory: 256Mi
  meshCapture:
    includeCidrs: []       # empty = capture all
    excludeCidrs: []
    excludePorts: []
```

Required Linux capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` (kernel >= 5.8), `CAP_SYS_ADMIN` (kernel-backcompat for 5.7.x; drop on 5.8+). Required volume mounts: `/sys/fs/bpf` (bpffs), `/sys/fs/cgroup` (cgroup v2, read-only). Required host access: `hostNetwork: true`, `hostPID: true`. See [`docs/node_agent_security.md`](node_agent_security.md) for the full security posture, including seccomp / AppArmor profiles and the kernel API each capability grants.

### Metrics

The node agent exposes Prometheus counters on the read-only admin `/metrics` endpoint. Because `/metrics` is unauthenticated, bind admin to loopback (`FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1`) or set a narrow `FERRUM_ADMIN_ALLOWED_CIDRS` allowlist when scraping over the cluster network.

- `ferrum_node_agent_pods_enrolled_total` -- total pods successfully enrolled for capture.
- `ferrum_node_agent_pods_unenrolled_total` -- total pods unenrolled (deletion or shutdown).
- `ferrum_node_agent_attach_errors_total` -- total BPF attachment or map update failures.
- `ferrum_mesh_node_topology_degraded{reason}` -- gauge. `1` with `reason ∈ {kernel_too_old, cgroup_v1, bpffs_missing}` when the node detects missing eBPF prerequisites; `0` with `reason="none"` when the eBPF path is nominal. See [node_agent.md](node_agent.md#kernel-fallback) for the full reason table and remediations.

### Mixed-kernel clusters

Mesh ambient mode requires Linux kernel >= 5.7 with cgroup v2 and bpffs for the per-pod eBPF capture path. The node agent fails fast on degraded nodes by default (`FERRUM_NODE_AGENT_FALLBACK_MODE=fail`), matching the published distroless image. The rest of the mesh data plane (slice apply, `mesh_authz`, `mesh_workload_metrics`, HBONE) is unaffected. Operators with a mix of supported and unsupported kernels should:

1. Alert on node-agent readiness/startup failures and `ferrum_mesh_node_topology_degraded == 1` to track the degraded set.
2. Label degraded nodes (e.g., `ferrum.io/capture-mode=iptables`) and configure the admission webhook (`FERRUM_MODE=injector`) to inject iptables init containers on those nodes.
3. Upgrade kernels to >= 5.7 with cgroup v2 + bpffs as the long-term remediation.

Set `FERRUM_NODE_AGENT_FALLBACK_MODE=iptables` only when running a custom node-agent image that includes `/bin/sh`, `iptables`, and `ip6tables` when IPv6 capture is enabled.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FERRUM_NODE_AGENT_NODE_NAME` | (required) | Kubernetes node name, set via downward API (`spec.nodeName`) |
| `FERRUM_NODE_AGENT_CGROUP_ROOT` | `/sys/fs/cgroup` | cgroup v2 mount point for pod cgroup resolution |
| `FERRUM_NODE_AGENT_BPF_FS_PATH` | `/sys/fs/bpf` | BPF filesystem mount point for pinned maps |
| `FERRUM_NODE_AGENT_BPF_ELF_PATH` | build-tree path | Compiled `ferrum-ebpf` ELF loaded by the aya backend (Linux `ebpf` feature only) |
| `FERRUM_NODE_AGENT_PROXY_MODE` | `local_pod` | Capture topology contract: `local_pod` or `node_waypoint` |
| `FERRUM_NODE_AGENT_ADMIN_ENABLED` | `false` | Enables the node-agent read-only admin listener for metrics/health. When enabled, defaults to loopback unless `FERRUM_ADMIN_BIND_ADDRESS` or `FERRUM_ADMIN_ALLOWED_CIDRS` is set; JWT does not affect bind because metrics/health are unauthenticated. |
| `FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT` | `15008` | HBONE redirect/listener port written into the capture contract and BPF config map. Must match the mesh proxy HBONE listener (`15008` today). |
| `FERRUM_NODE_AGENT_FALLBACK_MODE` | `fail` | Behaviour when eBPF prerequisites are missing (kernel < 5.7, cgroup v1, or bpffs unmounted). Default `fail` refuses startup with a structured error. `iptables` falls back to host iptables capture and sets `ferrum_mesh_node_topology_degraded=1`, but requires a runtime image with `/bin/sh`, `iptables`, and `ip6tables` when IPv6 capture is enabled. See [node_agent.md](node_agent.md#kernel-fallback). |
| `FERRUM_NODE_AGENT_EXCLUDED_NAMESPACES` | (empty) | Extra namespaces to exclude from capture (`kube-system`, `kube-public`, `kube-node-lease` always excluded) |
| `FERRUM_MESH_CAPTURE_INCLUDE_CIDRS` | `0.0.0.0/0` | CIDRs to capture for outbound traffic |
| `FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS` | (empty) | CIDRs to exclude from outbound capture (highest priority) |
| `FERRUM_MESH_CAPTURE_EXCLUDE_PORTS` | `15001,15006,15008,15020` | Destination TCP ports excluded from outbound capture |
| `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` | (empty) | Destination TCP ports excluded from inbound capture (mirrors Istio `excludeInboundPorts`; pod annotation `traffic.sidecar.istio.io/excludeInboundPorts` is additive) |
| `FERRUM_MESH_IP6TABLES_ENABLED` | `auto` | IPv6 iptables fan-out: `auto` probes and skips IPv6 rules when `ip6tables` is unavailable, `true` requires it when IPv6 CIDRs are configured and fails all capture setup before IPv4 rules if unavailable, `false` emits IPv4-only capture rules |

## VirtualService Translation

Istio `VirtualService` resources are translated at the Kubernetes translation layer into Ferrum proxy configuration. Beyond basic route splitting (documented in [configuration.md](configuration.md)), the following per-route features are supported:

### Retries

VirtualService `retries` are translated to Ferrum `RetryConfig`:

- `attempts` -> `retry_count`
- `retryOn` tokens: `5xx`, `gateway-error`, `connect-failure`, `reset`, `retriable-4xx`, and numeric status codes (e.g., `503`).
- `perTryTimeout` -> per-attempt timeout.

### Timeout

VirtualService `timeout` is translated to the proxy's `backend_read_timeout_ms`. Supports Go-style duration strings (`10s`, `500ms`, `1m`, `1h`).

### Fault Injection

Per-route `fault` rides on each emitted `mesh_route_dispatch` rule as a per-rule `fault` action (`{delay, abort}`) — the same `FaultRoller` math the proxy-scoped `fault_injection` plugin uses, scoped to the matching dispatch rule. This replaces the historical proxy-scoped emission, which could not be collapsed with sibling routes and previously fail-closed any merged route that carried fault.

- `fault.abort.httpStatus` + `fault.abort.percentage` → rule `fault.abort` with `status_code` + `percentage`. `abort` is dropped (along with the rest of the rule's fault) when `httpStatus` is missing or the percentage is `0`; an accompanying valid `delay` still projects.
- `fault.delay.fixedDelay` + `fault.delay.percentage` → rule `fault.delay` with `duration_ms` + `percentage`. `fixedDelay` accepts Istio's Go-style duration syntax; values outside `[1 ms, 1 h]` are rejected at translation time.
- `fault.abort.grpcStatus` (string or numeric `0..=16`) → `fault.abort.grpc_status`. The header is only stamped on the rejection response when the matching request is detected as gRPC (`content-type: application/grpc[+...]`, excluding `application/grpc-web*`); plain HTTP on the same rule never receives a stray `grpc-status` header.

**Ordering:** when both delay and abort trigger on the same request, the delay runs first, then the abort fires — matching the proxy-scoped `fault_injection` plugin so the two surfaces stay semantically identical. A global / proxy-scoped `fault_injection` plugin running before this one (priority 2940 vs 2995) sets `ctx.metadata["fault_injected"]=true`, and the per-rule fault no-ops in that case so the two surfaces never stack a second delay + abort.

**RTDS scope (limitation):** the static percentages baked into a per-rule fault action are **not** runtime-tunable via the GAP-3E RTDS keys `ferrum.fault_injection.<scope>.{abort,delay}_percent` — those keys apply only to `fault_injection` plugin instances configured with `runtime_overlay_scope`. Operators who need RTDS-driven fault percentages should either use a global / proxy-scoped `fault_injection` plugin with `runtime_overlay_scope`, or wait for a follow-on PR that introduces per-rule RTDS scoping.

Example translation:

```yaml
# VirtualService
http:
  - match: [{uri: {prefix: "/v1"}}]
    route: [{destination: {host: api.default.svc.cluster.local, port: {number: 8080}}}]
    fault:
      abort:  {httpStatus: 503, percentage: {value: 25.0}}
      delay:  {fixedDelay: "200ms", percentage: {value: 50.0}}
```

```json
// emitted mesh_route_dispatch rule (URI-only catch-all)
{
  "match": {},
  "destination": {"backend_host": "api.default.svc.cluster.local", "backend_port": 8080},
  "fault": {
    "abort": {"status_code": 503, "percentage": 25.0},
    "delay": {"duration_ms": 200, "percentage": 50.0}
  }
}
```

### Traffic Mirroring

Per-route `mirror` (Istio `http[].mirror` + `mirrorPercentage` / legacy `mirrorPercent`) is translated to a proxy-scoped [`request_mirror`](plugins.md) plugin attached to the route's proxy:

- `mirror.host` + `mirror.port` (number or `Service` port `name`) → `mirror_host` / `mirror_port`. A missing `mirror.host`, or a `port.name` that does not resolve, fails translation closed.
- `mirrorPercentage.value` (float `0–100`) or the legacy `mirrorPercent` (integer) → `percentage`. Default is `100`. A `0%` mirror emits **no** plugin (it would be a no-op).

Because mirror is a per-route action realized as a proxy-scoped plugin, a route carrying a mirror is route-local: if that route would have to be **collapsed** with a sibling route onto one Ferrum proxy (rare — same listen path, guarded predicates), translation **fails closed** rather than silently mirroring the sibling's traffic. Model such cases with distinct listen paths.

### URI / Authority Rewrite

Per-route `rewrite` (Istio `http[].rewrite`) rides on each emitted `mesh_route_dispatch` rule as a per-rule `rewrite` action, so it follows the matched route through route-collapse without rewriting sibling routes:

- `rewrite.uri` → the request path forwarded to the backend. When the route's `match.uri` is a `prefix`, Istio prefix-rewrite semantics apply — only the matched prefix is replaced and the remainder is preserved (`/api/users` with `prefix: /api`, `rewrite.uri: /v2` → `/v2/users`). For `exact` / `regex` matches (and URI-less matches) the whole path is replaced. The original path is still used for route selection and logging.
- `rewrite.authority` → the authority forwarded to the backend. The plugin writes the new authority into the request `Host` header and flips `preserve_host_header` on the effective proxy. For HTTP/1.1 backends (reqwest) the `Host` header is the on-wire request authority, so the rewrite takes full effect. For HTTP/2, gRPC, and HTTP/3 backends the `:authority` pseudo-header is derived from the backend connection target URL (the pool key's host/port), not the `Host` header; the rewrite lands in the `Host` header that travels as an application header within the H2/H3 frame, but the protocol-level `:authority` follows the backend target. HBONE CONNECT carries the rewritten `Host` in its CONNECT request headers, which the receiving mesh proxy reads as the application authority.

CRLF (and, for authority, whitespace) in rewrite values is rejected at config-load time.

### Redirect

Per-route `redirect` (Istio `http[].redirect`) rides on each emitted `mesh_route_dispatch` rule as a per-rule `redirect` action. When the rule matches, the request is answered with a 3xx + `Location` response and never reaches a backend (so a redirect route needs no `route[]` backend — Istio forbids `route` + `redirect` together):

- `redirect.uri` → replacement path (request path preserved when unset).
- `redirect.authority` → replacement authority (request `Host`/`:authority` preserved when unset).
- `redirect.scheme` → replacement scheme (`http`/`https`; request frontend scheme preserved when unset).
- `redirect.redirectCode` → status code (`300–399`, default `301`).

The redirect takes precedence over `rewrite` and the route-override destination on the same rule. When no authority is resolvable, an origin-relative `Location` (path only) is emitted.

### L4 routing (`spec.tcp` / `spec.tls`)

VirtualService L4 routing is materialized into Ferrum stream proxies, reusing the same stream + SNI machinery as the gateway and east-west passthrough:

- **`spec.tls[]`** → a **passthrough TCP** proxy keyed by SNI: `match[].sniHosts` become the proxy's `hosts`, `match[].port` (or the destination port) the listen port, and the proxy forwards the **encrypted** bytes to the destination without terminating TLS. Multiple `tls[]` matches sharing a port are SNI-routed (`resolve_proxy_by_sni`).
- **`spec.tcp[]`** → a plain **TCP** proxy keyed by `listen_port` (`match[].port`, or the destination port), forwarding to the destination.

Match predicates Ferrum's stream layer cannot express — `sourceLabels`, `sourceSubnets`, `destinationSubnets`, `gateways`, `sourceNamespace` — and **weighted multi-destination splitting** are **rejected fail-closed** (translator error, `FerrumAccepted=False`/`Invalid`) rather than silently mis-routed; model those with an explicit stream `Proxy` or an upstream-backed split. A `tls[]` match without `sniHosts`, or any L4 route without a resolvable destination port, also fails closed (a stream listener needs a concrete port).

### Destination Port Resolution

`route.destination.port` accepts either `number` (integer) or `name` (string). When a name is given, the translator resolves it against the `Service.spec.ports[].name` index built from collected core/v1 `Service` objects in the same translation batch (input order is irrelevant — Services are gathered in a pre-pass). `port.number` always wins when both are set. An unknown port name fails translation closed with the offending name in the error. Hosts are parsed as `<svc>`, `<svc>.<ns>`, `<svc>.<ns>.svc`, or `<svc>.<ns>.svc.cluster.local` (with or without a trailing dot); short hosts fall back to the VirtualService's own namespace, so port-name lookups for the same short host resolve differently depending on which namespace the VS lives in. Service ports without a `name` are silently skipped by the indexer (no panic). Numeric-port-only deployments need no changes.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: reviews
  namespace: default
spec:
  ports:
    - name: http
      port: 8080
    - name: grpc
      port: 9090
---
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: reviews-vs
  namespace: default
spec:
  hosts:
    - reviews.default.svc.cluster.local
  http:
    - match:
        - uri:
            prefix: /api
      route:
        - destination:
            host: reviews.default.svc.cluster.local
            port:
              name: http        # resolves to 8080 via the Service index above
```

## Gateway API Status

When `FERRUM_K8S_CONTROLLER_ENABLED=true` and Gateway API watching is enabled, the controller watches `GatewayClass`, `Gateway`, `HTTPRoute`, and `GRPCRoute` resources and patches their status subresources. Ferrum manages only `GatewayClass` objects whose `spec.controllerName` is `ferrum.io/gateway-controller`. `Gateway.status.conditions` and route `status.parents[].conditions` include Ferrum-authored `Accepted`, `Programmed`, `ResolvedRefs`, and `Conflicted` entries with that controller name. The status writer is driven by the same translation inputs as the control-plane config: accepted routes report programmed once Ferrum materializes a proxy, rejected routes report unresolved references for cases such as missing `ReferenceGrant` authorization or unsupported backend target kinds, and route collisions report `Conflicted=True`.

Gateway API HTTP/GRPC route conflicts are resolved deterministically before config materialization. For routes that would produce the same parent reference, hostname, and Ferrum listen path, the oldest `metadata.creationTimestamp` wins; if timestamps tie or are absent, `{namespace}/{name}` order is the tiebreaker. Losing routes are skipped during translation and receive `Accepted=False`, `Programmed=False`, and `Conflicted=True` status.

Gateway API status writing requires `get/list/watch` on `gatewayclasses`, `gateways`, `httproutes`, and `grpcroutes`, plus `patch` on their `status` subresources. `GatewayClass` is cluster-scoped; route and Gateway watches are namespaced when `FERRUM_K8S_WATCH_NAMESPACES` is set. The Helm chart grants these verbs through `controlPlane.rbac.*`; disable unused watches there when installing a narrower controller.

## Istio CRD Status

When `FERRUM_K8S_CONTROLLER_ENABLED=true` and Istio CRD watching is enabled (`FERRUM_K8S_WATCH_ISTIO_CRDS=true`, the in-pod default), the controller writes a `status.conditions[]` block to every Istio CRD it translates so `kubectl describe <kind> <name>` shows how Ferrum interpreted the resource. All nine translated kinds are covered: `AuthorizationPolicy`, `PeerAuthentication`, `RequestAuthentication`, `DestinationRule`, `VirtualService`, `ServiceEntry`, `WorkloadEntry`, `Sidecar`, and `Telemetry`.

Each resource gets a single Ferrum-owned `FerrumAccepted` condition (field manager `ferrum.io/istio-controller`) alongside a `status.ferrum.translation` detail block:

- **Accepted** — successful translation writes `FerrumAccepted=True` with a per-kind reason (`Accepted`, plus `AllowNothing`/`NoOp` for AuthorizationPolicy empty-rule semantics). The detail block carries kind-specific context: rule/host/route counts, the resolved PeerAuthentication mTLS mode and port overrides, ServiceEntry `resolution`/`location`, RequestAuthentication scope and permissive-by-default note, the WorkloadEntry service account, the Sidecar egress scope, or the Telemetry sections present.
- **Rejected** — a translator error (`K8sTranslateError`) writes `FerrumAccepted=False`, reason `Invalid`, with the error text in both the condition message and `status.ferrum.translation.error`. This is the gap this surface closes: a hard rejection of any translated kind is now visible to operators instead of being silently dropped from the slice.
- **Deferred fields** — fields Ferrum parses but does not yet enforce are listed in `status.ferrum.translation.deferred_fields` (and summarized in the condition message) so operators see the gap. Current deferred sets: DestinationRule per-subset `outlierDetection.maxEjectionPercent` (the ejection *cap*; the thresholds are applied per-subset) and `connectionPool.http.{http1MaxPendingRequests,maxRetries,h2UpgradePolicy}` (per-subset `connectionPool.tcp.connectTimeout`, `portLevelSettings[].tls`, and per-subset `outlierDetection` *thresholds* are now applied, not deferred); VirtualService `http[].corsPolicy` **only when it uses `prefix`/`regex` origin matchers** (exact-origin / legacy `allowOrigin` policies are translated to a `cors` plugin; `tcp[]`/`tls[]` L4 route blocks are translated to stream proxies — only their unsupported match predicates / weighted splitting are rejected fail-closed — while `mirror`, `mirrorPercentage`, `redirect`, and `rewrite` are enforced); Sidecar `ingress[]` listener config (Ferrum models egress scope only).

Ferrum merges its `FerrumAccepted` condition into the live `status.conditions[]` array, preserving conditions written by Istio (`pilot-discovery`/`galley`) and any other controller. `lastTransitionTime` is held stable while the condition's status/reason/message are unchanged. Status writing is read-only with respect to the proxy data plane and never aborts reconcile: if a cluster has stripped the `subresources.status` from a CRD, the writer logs a single warning per resource and no-ops. `ProxyConfig` is translated for proxy/telemetry config but is not watched and gets no status.

Istio status writing requires `get/list/watch` on the watched Istio CRDs plus `patch` on their `status` subresources; the standard Istio CRD manifests already declare `subresources: { status: {} }`.

### Pod Auto-Discovery

Control planes can opt into native Kubernetes service-registry discovery with `FERRUM_K8S_CONTROLLER_ENABLED=true` and `FERRUM_K8S_POD_DISCOVERY_ENABLED=true`. When enabled, the K8s controller watches `Pod`, `Service`, `EndpointSlice`, and `Node` resources in addition to the configured Istio/Gateway API watches. Ready Pods linked from EndpointSlices become mesh `Workload` entries, Services become mesh `MeshService` entries with their `spec.ports[]`, and Node `topology.kubernetes.io/region|zone` labels populate workload locality metadata consumed by locality-aware load balancing.

Ferrum only surfaces Pods whose `Ready` condition and declared `readinessGates[]` are green, skips Pending/Failed/Succeeded/terminating Pods, and also honors EndpointSlice readiness/serving/terminating conditions. Explicit Istio `ServiceEntry` resources for the same service host override the auto-derived `MeshService`, and explicit `WorkloadEntry` resources for the same service override auto-derived Pod workloads while the Service can still reference those explicit identities. The flag defaults to `false` for one release so operators can validate RBAC and rollout impact before enabling Pod discovery.

The controller service account needs `get`, `list`, and `watch` for namespaced `pods`, `services`, and `endpointslices`; add cluster-scoped `nodes` for locality metadata. Minimal RBAC:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ferrum-edge-k8s-discovery
rules:
  - apiGroups: [""]
    resources: ["pods", "services"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch"]
```

When `FERRUM_K8S_WATCH_ISTIO_CRDS=true` and `FERRUM_K8S_WATCH_MESH_CONFIG=true` (both default to `true`), the controller also watches the `istio` ConfigMap in the istio root namespace so `Telemetry.tracing[].providers[]` name-only references and `meshConfig.defaultProviders.tracing` resolve at translation time. The watcher is scoped with a `metadata.name=istio` field selector so it only observes the single MeshConfig object, not every ConfigMap in the root namespace. Grant `configmaps` `get/list/watch` in that namespace — preferably with a `Role`/`RoleBinding` so RBAC stays scoped:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ferrum-edge-meshconfig
  namespace: istio-system
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["istio"]
    verbs: ["get", "list", "watch"]
```

If the gateway runs in a different trust boundary from `istio-system` and cannot easily grant cross-namespace ConfigMap access, set `FERRUM_K8S_WATCH_MESH_CONFIG=false`. Telemetry name-only provider references then resolve as unknown (with an operator-visible warning), but inline-provider Telemetry continues to work.

### Locality-Aware Load Balancing

Ferrum consumes Istio-style `WorkloadEntry.locality` and auto-discovered Pod locality in `region/zone/subzone` form. Mesh slice application projects the selected source workload locality onto generated upstreams and projects target workload locality onto each upstream target. The load balancer then prefers healthy targets in this order: exact `region/zone/subzone`, same `region/zone`, same `region`, then the ordinary upstream candidate set. If every target in a preferred tier is unhealthy, selection falls through to the next tier without widening across unhealthy targets.

This priority selection applies before the configured Ferrum algorithm for the chosen tier, including per-port and subset selectors.

`DestinationRule.trafficPolicy.loadBalancer.localityLbSetting` is honored on top of the priority tiers:

- `enabled: false` disables priority preference, weighted distribute, and failover entirely (matches Istio semantics).
- `distribute[].from` matches the source workload's locality by tier: bare `*` matches any source locality, region-only values match any source in that region, `region/zone` values match any source in that zone, full `region/zone/subzone` values require an exact match, and terminal forms such as `region/zone/*` match the corresponding tier. When a match is found the load balancer overrides the priority preference with weighted locality-bucket selection: each `to[locality]` entry contributes a locality-level share (region-only `to` entries apply to every target in that region, `region/zone` entries apply to every target in that zone, full `region/zone/subzone` entries require an exact match, and terminal wildcards such as `region/zone/*` match the covered tier). If multiple `to` patterns match the same target, the most-specific pattern owns that target so an endpoint is counted in only one locality bucket. After a bucket is chosen, Ferrum runs the configured upstream, subset, or port-level algorithm within that bucket, so endpoint algorithms such as consistent hashing and weighted round-robin still apply. Targets that receive zero distribute weight are excluded, and an entry that names no reachable target falls through to the rest of the locality LB path so the upstream still serves.
- `failover[].from` matches the source workload's region. When configured, the failover region forms a fourth tier consulted after exact/zone/region — so a source with no healthy target in its own region prefers the operator-specified failover region before falling through to other regions.

The K8s translator treats `distribute`, `failover`, and `failoverPriority` as mutually exclusive Istio locality-LB modes. Combined modes are rejected at admission instead of being accepted and resolved by runtime precedence, and `failoverPriority` is currently rejected as unsupported. The translator validates each accepted entry at admission — invalid locality strings, slash-malformed locality strings, non-terminal locality wildcards, malformed failover region names (including slash-containing or slash-suffixed values), `from == to` self-failovers, and empty `to` maps return a translator error rather than silently dropping the policy.

Port-level `trafficPolicy.portLevelSettings[].loadBalancer.localityLbSetting` is honored by HTTP-family / gRPC / WebSocket / HBONE dispatch. Each per-port entry projects onto `Upstream.port_overrides[port].locality_lb_setting` at slice apply, and the load balancer builds isolated per-port locality state. When dispatch resolves to a port that has a per-port `localityLbSetting`, the per-port preference wins; ports without an override fall back to the upstream-level `trafficPolicy.loadBalancer.localityLbSetting`. The same translator validators apply to per-port entries — invalid locality strings, non-terminal wildcards, malformed failover regions, and combined modes are rejected at admission. TCP/UDP/DTLS stream proxies continue to use upstream-level locality LB only.

## xDS ADS Compatibility

Ferrum's ADS protocol state machine (subscriptions, ACK/NACK, nonce, SotW/delta) follows the Envoy ADS wire contract, but the **resource payloads are Ferrum-specific**. The CDS/EDS/LDS/RDS resources are name-only (service/port discovery) and use Ferrum-shaped names; the security- and policy-bearing slice fields plus effective workload labels ride ECDS as [Ferrum mesh-slice carriers](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds) with Ferrum-defined inner type URLs. A stock Envoy or third-party Istio control plane does not speak this carrier convention or resource-name shape, so Ferrum's xDS path is **Ferrum-CP-to-Ferrum-DP**, not a drop-in replacement for an Envoy/Istio xDS feed. With the carriers, an xDS-built slice is functionally equivalent to a `native`-built one.

**Protocol robustness.** Both sides track nonces per `(node, type URL)`. The server issues an opaque nonce (`n1:<sha256>`) per response and validates that each ACK/NACK echoes the most-recently-issued nonce (`src/xds/nonce.rs`); stale, unknown, or version-drifted ACKs are logged and ignored rather than mutating accepted state. The DP client mirrors this on the receiving side: it ACKs/NACKs with the exact nonce of the response being acted on and ignores a server retransmit of a response it already processed (a reconnect race or buggy CP would otherwise trigger a redundant slice rebuild and a stale re-ACK). Because server nonces are opaque, duplicate detection — not numeric ordering — is the staleness signal available to the client. Additionally, the CP caps **concurrent ADS streams per node id** at `FERRUM_XDS_MAX_STREAMS_PER_NODE` (default 4; `0` disables): a healthy DP keeps one stream, and streams beyond the ceiling are rejected with gRPC `RESOURCE_EXHAUSTED`, logged with the offending node id, and counted by the aggregate `ferrum_xds_streams_rejected_total` counter (label-free by design — see the Prometheus reference for the cardinality rationale). This is a per-node DoS guard for `FERRUM_XDS_ENABLED=true` fleets and only takes effect after a stream's first request resolves its node id.

**First-slice convergence and resource warming (make-before-break).** The DP gates its first slice on CDS+EDS+LDS+RDS+ECDS each returning the same valid `version_info` before `wait_for_first_slice()` unblocks (ECDS is required so the first slice is never the name-only, unprotected view). Under **resource warming** the DP tracks each type's version independently but builds only when the required set is coherent and internally consistent — concretely, when every required type has the same version and `reverse_translate` succeeds (carriers decode). A route that references a service not yet present in CDS/EDS/LDS is **skipped**, not fatal: xDS types arrive as independent responses, so a route can land before its cluster; the route is retained in the accumulator and validates once its service arrives (Envoy-aligned — a route to an unknown cluster is ACKed, not NACKed). The previous slice keeps serving through the runtime `ArcSwap` until the replacement is ready, so a partial or version-skewed set never tears down the working slice or mixes new routing with stale ECDS policy. After convergence a per-type content update — the common case being a policy/workload-only ECDS change — force-refreshes subscribed required mesh-slice types with the same snapshot version so the DP applies only a coherent CDS/EDS/LDS/RDS/ECDS set. The slice's observability `version` is the coherent required version; it is not used for change detection (`MeshSlice::content_eq` ignores it). If the CP persistently sends one malformed required type, that type is NACKed on every attempt and the first slice never converges; after `XDS_CONSECUTIVE_NACK_LIMIT` (5) consecutive NACKs the client trips its NACK circuit breaker, closes the stream, and reconnects / fails over to the next CP. To keep a wedged startup diagnosable, a NACK of a required type that occurs **before** first-slice convergence emits a structured `warn!` (node, namespace, type URL, consecutive-NACK count, breaker limit) and increments `ferrum_xds_first_slice_nacks_total{namespace, type_url}` — a non-zero, growing value on a starting DP is the signal that convergence is blocked by a malformed required resource. A genuine structural error (e.g. a malformed ECDS carrier) is still NACKed and rolls the accumulator back to the last accepted state. A dependency-skewed route is **not** treated as such an error — NACKing it would drop the new RDS, and the CP does not resend a NACKed SotW resource until a reconnect or another RDS change, so the route is skipped and retained instead.

Ferrum's ADS server honors explicit SotW (State-of-the-World) resource subscriptions per type URL on the shared `filtered_resources()` path used by CDS/EDS/LDS/RDS/SDS. A SotW request with a non-empty `resource_names` returns only the named resources for that type URL, while a wildcard subscription (`*` or an initial empty `resource_names`) returns the full collection per the Envoy ADS protocol. Subsequent empty SotW requests on the same stream preserve an established wildcard subscription; after an explicit named subscription they clear the named set and remain non-wildcard, so no resources are returned until the client names resources again. Direct per-type regression coverage exists today for CDS and RDS; EDS/LDS/SDS rely on the same code path and are covered indirectly.

Delta-xDS subscriptions across the same type URLs are additive: `resource_names_subscribe` appends to the per-stream subscription set and `resource_names_unsubscribe` removes from it, with empty lists treated as no-ops. Subscriptions persist across requests on the same stream, and updates only mutate the explicit subscription state without broadcasting unrelated resources.

Delta-xDS responses ship only resources the client doesn't already have. Each resource carries a content-derived per-resource version — the first 8 bytes (16 hex chars) of `SHA-256(type_url || 0x00 || name || 0x00 || value)`, independent of the aggregate snapshot version. The truncation is a wire-size optimization: at typical mesh-resource cardinalities (~10k per type URL) the birthday-bound collision probability sits around 3e-12. On the same stream, the delta filter also byte-compares `value` against the previous ACKed snapshot before skipping a resource, so a hash collision on its own cannot suppress a real content change on that path. Reconnect `initial_resource_versions` skips by the client's reported version match; explicit re-subscribe can always force a fresh copy. Two snapshots that contain byte-identical bytes for a resource produce identical resource versions, so:

- `DeltaDiscoveryRequest.initial_resource_versions` lets a client report what it currently has after a reconnect — resources whose versions match are skipped on the response.
- Resources that were on the previous ACKed response for the same type URL and whose bytes haven't changed are skipped on the next response.
- Explicit `resource_names_subscribe` always re-flows the resource even when unchanged, so a re-subscribe always returns a fresh copy.

ECDS (Extension Config Discovery Service) — `type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig` — is served alongside the standard xDS resource types and carries three classes of payload, all distinguished by the **inner** `Any.type_url`:

1. **Ferrum mesh-slice carriers** (GAP-1a): the CP emits the full slice — authz, PeerAuthentication, RequestAuthentication, full ServiceEntry/MeshService shape, trust bundles, ProxyConfig, workloads, effective labels, telemetry, multi-cluster, sidecar egress scope, outbound policy — as Ferrum ECDS carriers under `type.googleapis.com/ferrum.config.extension.v3.*`. Empty `Vec`/`None` fields are skipped, while effective labels always emit so an empty label map remains authoritative. This is what makes xDS reach native parity; see [Ferrum mesh-slice ECDS carriers](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds). Source of truth: `src/xds/carrier.rs`.
2. **DestinationRule carrier** (GAP-2K): inner `type_url == type.googleapis.com/ferrum.config.extension.v3.DestinationRuleCarrier` ships the original DR JSON across xDS.
3. **Operator-defined extension configs**: operators populate `MeshConfig.extension_configs` with `MeshExtensionConfig { name, type_url, value }` entries; slice construction carries them into `MeshSlice.extension_configs`, and the translator emits one ECDS resource per entry with the operator-defined inner `type_url`/bytes.

The DP dispatches on the reserved resource name plus inner `type_url`: slice-carrier and DR-carrier markers are decoded into their dedicated slice fields, and any other inner type is left for the relevant operator consumer. Delta wire-byte reduction (GAP-2L.2) extends to ECDS naturally because per-resource versions are content-derived.

RTDS (Runtime Discovery Service) — `type.googleapis.com/envoy.service.runtime.v3.Runtime` — is subscribed by the mesh xDS client so operators can change runtime knobs without rolling out a fresh slice. Each layer's `google.protobuf.Struct` payload is flattened into `MeshSlice.runtime_overlay.fields` keyed by the top-level field name; later layers override earlier ones on key conflicts. Value kinds map directly to a typed Rust enum (`RuntimeValue::{Number, String, Bool, FractionalPercent}`). The overlay surfaces via `GET /mesh/runtime-overlay` (JWT-authenticated) and the field is `#[serde(default, skip_serializing_if = "MeshRuntimeOverlay::is_empty")]` so non-RTDS deployments round-trip byte-identical.

Every proxy-accepted slice runs the overlay through the consumer dispatcher in `src/modes/mesh/runtime_overlay_consumers.rs`, which fans out to three plugin-owned snapshots (rebuilt cold, read lock-free on the hot path). Received-but-rejected slices remain visible on the raw runtime snapshot but never mutate live RTDS consumers or `GET /mesh/runtime-overlay`:

| Reserved key | Consumer | Effect |
|---|---|---|
| `ferrum.fault_injection.<scope>.abort_percent` / `.delay_percent` | `fault_injection` plugins with `runtime_overlay_scope: "<scope>"` | Replaces the static `percentage` for that fault kind for as long as the key remains in the overlay. Accepts `Number(0..=100)` or `FractionalPercent`. |
| `ferrum.request_transformer.<scope>.enabled` / `ferrum.response_transformer.<scope>.enabled` | request/response transformer plugins with `runtime_overlay_scope: "<scope>"` | When `false`, every header / query / body rule on the plugin instance is short-circuited. Missing key falls back to `default_enabled` (defaults to `true`). |
| `ferrum.log.level` | gateway-wide tracing `EnvFilter` | Rebuilt via `tracing_subscriber::reload`. Accepts any `RUST_LOG`-style directive. Parse failure logs a warning and keeps the last-good filter. |

Server-side translation (`translate_mesh_slice_to_snapshot`) does not currently emit Runtime resources — the xDS server is a CDS/EDS/LDS/RDS/SDS/ECDS originator, and RTDS layer authorship remains with the operator's external CP (Istio, custom) until a Ferrum CP-side surface lands.

## Istio Compatibility Gaps

The following Istio mesh surfaces are either deferred or have Ferrum-specific support notes:

| Surface | Status | Workaround |
|---|---|---|
| Stock Envoy / third-party Istio xDS interop (point Ferrum's xDS client at a non-Ferrum CP) | Not interoperable | Ferrum's `FERRUM_MESH_CONFIG_PROTOCOL=xds` is a **Ferrum-CP-to-Ferrum-DP** path: it follows the Envoy ADS gRPC contract, but CDS/EDS/LDS/RDS are name-only with Ferrum-shaped resource names and all security/policy fields ride [Ferrum-specific ECDS carriers](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds) with Ferrum-defined inner type URLs. A stock Envoy/Istio CP does not emit these carriers or names, so the response is unsupported and may be NACKed. Use a Ferrum CP (either protocol), or `FERRUM_MESH_CONFIG_PROTOCOL=native` |
| `EnvoyFilter` | Not planned | Use Ferrum custom plugins |
| `WasmPlugin` | Not planned | Use Ferrum custom plugins (`custom_plugins/`) |
| Outbound traffic policy (`REGISTRY_ONLY` / `ALLOW_ANY`) | Supported | `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY=registry_only` (or native/CRD slice-supplied `outbound_traffic_policy`) covers both HTTP-family egress (auto-injected `mesh_outbound_registry` plugin, rejects with `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS`, default 502) and stream-family egress on mesh outbound capture listener ports (TCP / TCP+TLS: graceful close before backend dial; UDP / UDP+DTLS: silent datagram drop). Both surfaces read the same slice-derived registry (services, ServiceEntries including wildcard hosts, workload addresses); resources with no declared ports admit any explicit Host port for that known destination, and empty registries fail closed. Stream rejects export `ferrum_mesh_outbound_registry_stream_decisions_total{protocol, decision}` instead of the host-bucketed HTTP counter. Inbound sidecar/ambient traffic is not gated by this outbound policy |
| `VirtualService` header/method/queryParam predicates beyond plugin capture | Partial | Plumbing in place via `mesh_route_dispatch` plugin (translated unconditionally, enabled by default — no opt-in env var or kill switch); supported predicates are captured as plugin config. **Method `StringMatch` supports `exact`, `prefix`, and `regex`** — regex patterns compile once at config-load time; `prefix` / `regex` patterns are uppercased at compile time (HTTP methods are uppercase ASCII per RFC 9110 §9.1); invalid regex is a hard translator/plugin construction error. **Header `StringMatch` supports `exact`, `prefix`, and `regex`** — regex patterns compile once at config-load time; invalid regex is a hard translator/plugin construction error. **`authority` `StringMatch` supports `exact`, `prefix`, and `regex`** — exact/prefix compare raw request `Host`/`:authority` case-sensitively, including explicit request ports; regex patterns are compiled verbatim and must match the full authority string, and operators who want case-insensitive regex should write `(?i)` in the pattern. `authority` is a per-rule predicate (Istio `HTTPMatchRequest.authority`), distinct from VirtualService-level `hosts` which gates proxy admission. **`sourceNamespace` is a first-class predicate** — the request hot path reads the source workload's Kubernetes namespace from `ctx.peer_spiffe_id` via `SpiffeId::namespace`; the predicate fails closed without a resolved peer identity and empty / whitespace-only operator values fail closed via `request_termination`. **`ignoreUriCase: true` affects exact/prefix URI matches only** — the translator widens escaped literal operands into case-insensitive regex listen_paths (`prefix: "/Api"` → `~(?i:/Api.*)`, `exact: "/Api"` → `~(?i:/Api)`), while `regex` URI matches keep their operator-supplied regex unchanged. The dispatch rule carries the original exact/prefix URI predicate + `ignore_uri_case: true` so the plugin re-evaluates with ASCII-only case folding at request time without per-request allocation; non-ASCII bytes compare byte-for-byte. Overlapping case variants and contained exact/prefix intersections collapse or decorate ordered dispatch rules so Ferrum's exact/prefix-before-regex router preserves Istio route order. Routing-decision rewrites via `RequestContext.route_override_*` flow through HTTP-family dispatch sites (pool keys, capability registry, circuit breaker). Translator emits the plugin with `reject_unmatched: true` so requests that miss predicates return 404 instead of falling through to the default backend. Same-path and URI-less ordered canary/default routes collapse into one Proxy with ordered dispatch rules so predicate misses can fall through when a later route exists. Per-rule `timeout` / `retries` ride on each dispatch rule and are reapplied through `RequestContext.route_override_*`. Route-level `headers.request.{set,add,remove}` and `headers.response.{set,add,remove}` are projected onto each dispatch rule as per-rule transform arrays and applied by `request_transformer` / `response_transformer`. Route-local `fault` rides on each dispatch rule as a per-rule `fault` action and collapses cleanly with sibling routes. **`http[].rewrite` and `http[].redirect` are now supported**: `rewrite.uri` (prefix-rewrite-aware) and `rewrite.authority` ride on each dispatch rule and rebase the backend request path / `Host` (authority rewrite flips `preserve_host_header` on the effective proxy); `redirect` rides on each dispatch rule and short-circuits the request with a 3xx + `Location` (no backend, so a redirect route needs no `route[]`). **`http[].mirror` is now supported** as a proxy-scoped `request_mirror` plugin (per-route; a mirror route that must collapse fails closed). **`spec.tcp` / `spec.tls` L4 routing is supported** — materialized into Ferrum stream proxies (`tls[]` → passthrough TCP keyed by SNI; `tcp[]` → plain TCP keyed by port), reusing the gateway/east-west stream + SNI machinery; unsupported match predicates (`sourceLabels`/`sourceSubnets`/`destinationSubnets`/`gateways`/`sourceNamespace`) and weighted splitting fail closed. Unsupported predicate-only candidates (`regex`/`prefix` queryParam matchers, etc.) emit proxy-scoped `request_termination` instead of widening traffic. Admission plugins such as `mesh_authz` and rate limiting still evaluate the original public proxy identity; WebSocket overrides apply to the upgrade backend only, and HBONE CONNECT evaluates `before_proxy` before the relay branch, so route overrides can select the HBONE backend. Example `authority` match: `match: [{ uri: { prefix: "/api" }, authority: { prefix: "api." } }]` routes `Host: api.staging.example.com` but not `Host: API.staging.example.com` or `Host: admin.example.com`. Example `sourceNamespace` match: `match: [{ uri: { prefix: "/internal" }, sourceNamespace: "platform" }]`. Example `ignoreUriCase`: `match: [{ uri: { prefix: "/api" }, ignoreUriCase: true }]` matches both `/api/users` and `/API/users`. |
| Pod auto-discovery (K8s native service registry) | Supported (opt-in) | Set `FERRUM_K8S_POD_DISCOVERY_ENABLED=true`; the CP watches Pod/Service/EndpointSlice/Node resources, surfaces only ready Pods, links Services through EndpointSlices, and lets explicit `WorkloadEntry` / `ServiceEntry` resources override auto-derived entries |
| `WorkloadEntry` `weight` / `locality` / `serviceAccount` | Supported | `weight` and `locality` are consumed by upstream target materialization; locality priority load balancing prefers exact, zone, then region tiers before falling back. `DestinationRule.trafficPolicy.loadBalancer.localityLbSetting.distribute` / `failover` / `enabled` are honored (see "Locality-Aware Load Balancing" above). `serviceAccount` is kept separately from the SPIFFE path so introspection/audit doesn't need to parse it. |
| `Telemetry.tracing[].providers[]` span emission | Supported | Inline provider config is emitted from the injected `workload_metrics` plugin for Zipkin v2, Datadog Agent `/v0.3/traces`, Lightstep OTLP + bearer auth via `accessTokenEnv`, and OpenTelemetry OTLP/HTTP JSON. Multiple inline providers fan out from one sampled span. `randomSamplingPercentage` is honored, `disableSpanReporting: true` suppresses export while retaining the merged config, and `tracing[].match.mode: SERVER`, `CLIENT`, `CLIENT_AND_SERVER`, or omitted mode all flow through: each mesh listener stamps a direction (inbound mTLS / HBONE termination → server, outbound capture → client) and the plugin emits the matching span kinds. Resulting spans carry their kind in every provider payload (OTLP enum `2`/`3`, Zipkin v2 top-level `"kind": "SERVER"\|"CLIENT"`, Datadog `meta["span.kind"] = "server"\|"client"`). Name-only references (`{name: "my-zipkin"}`) resolve against `meshConfig.extensionProviders` from the root-namespace `istio` ConfigMap, and omitted or empty `providers[]` use `meshConfig.defaultProviders.tracing` when configured. Unknown names are skipped with an operator-visible warning. |

## Environment Variables

Mesh-specific environment variables are listed below. For the full reference of all `FERRUM_*` variables, see [configuration.md](configuration.md).

### Core

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_CONFIG_PROTOCOL` | `native` | Config consumption protocol: `native` or `xds` |
| `FERRUM_MESH_NODE_ID` | `$HOSTNAME` or `ferrum-mesh-node` | Node identifier sent to the CP |
| `FERRUM_MESH_TOPOLOGY` | `sidecar` | Topology: `sidecar`, `ambient`, `node_waypoint`, `service_waypoint`, `east_west_gateway`, `egress_gateway` |
| `FERRUM_MESH_WAYPOINT_NAME` | (none) | Required when `FERRUM_MESH_TOPOLOGY=service_waypoint`; names the GAMMA waypoint binding requested from the CP |
| `FERRUM_MESH_WORKLOAD_SPIFFE_ID` | (none) | SPIFFE ID of this mesh workload |
| `FERRUM_MESH_WORKLOAD_LABELS` | (none) | Comma-separated `key=value` workload labels for PolicyScope matching |
| `FERRUM_MESH_TRUST_DOMAIN_ALIASES` | (none) | Additional trust domains for HBONE baggage validation |
| `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS` | (none) | HBONE peers trusted to assert baggage `source.principal`. Comma-separated SA names and/or full SPIFFE ids. Empty/unset uses defaults `[ztunnel, waypoint]` |
| `FERRUM_MESH_SIDECAR_ENFORCED` | `false` | When `true`, applies Istio `Sidecar` egress scope narrowing to `services` / `service_entries` / `destination_rules` per workload. Sidecars are always parsed; this flag gates only the slice-narrowing pass. Opt in after vetting your `Sidecar` resources |
| `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN` | `false` | Computes and reports the applicable `Sidecar` egress scope while leaving the slice unchanged. Use with `/mesh/egress-scope` before enabling enforcement |
| `FERRUM_MESH_SIDECAR_IDENTITY_NARROWING` | `false` | When `true` and `FERRUM_MESH_SIDECAR_ENFORCED=true`, filters `workloads` to SPIFFE identities referenced by services admitted by the applicable Sidecar. Default-off for rollout; trust-bundle mTLS validation and HBONE trust-domain aliasing do not depend on this list |
| `FERRUM_MESH_EGRESS_STREAM_ENABLED` | `false` | Opt-in for stream-family (TCP / UDP) egress proxy materialization in `EgressGateway` topology. Default-off because stream egress listeners are plaintext and `mesh_authz` cannot verify SPIFFE peer identity without mTLS. HTTP-family egress is unaffected |
| `FERRUM_MESH_NODE_WAYPOINT_CGROUP_SWEEP_INTERVAL_SECS` | `30` | NodeWaypoint cgroup-inode lifecycle sweep interval. Set to `0` to disable |
| `FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP` | `true` | Whether the auto-injected mesh `RequestAuthentication` (`jwks_auth`) plugin requires the JWT `exp` claim. Secure default `true` rejects `exp`-less tokens. Set `false` only for issuers that legitimately omit `exp`; a present-but-expired `exp` is always rejected regardless |
| `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED` | `false` | Opt in to live reload of the PeerAuthentication-derived inbound mTLS mode, client CA verifier, and federated SVID bundle slot on slice apply. Does not rotate frontend cert/key material (use `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED`) |
| `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS` | `0` | Seconds to wait after a backend client SVID rotation before force-draining old-generation backend pool entries. `0` keeps existing connections until normal idle/health cleanup |
| `FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS` | `300` | SPIFFE trust-bundle federation poll interval (fetches `RemoteCluster.federation_endpoint` and overlays `TrustBundleSet.federated`). `0` disables; bundles then come only from the CP slice |
| `FERRUM_MESH_FEDERATION_POLL_TIMEOUT_SECONDS` | `30` | Per-request HTTP timeout for a single federation bundle fetch |
| `FERRUM_MESH_FEDERATION_FAIL_OPEN` | `false` | **Inert** — recorded in poll-failure logs only; verifier behavior is always fail-closed (verifies against the last-good cached bundle) regardless of this value |
| `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS` | `0` | Cross-cluster endpoint discovery polling interval. `0` disables (multi-cluster stays east-west SNI passthrough + federated trust only). When `> 0`, each `RemoteCluster.control_plane_url` is dialed on this cadence to fetch remote service endpoints aggregated into local upstream targets (tagged with remote locality) for local→remote failover. Fail-closed on trust: only clusters with a federated trust bundle are dialed. See [Cross-Cluster Endpoint Discovery](#cross-cluster-endpoint-discovery) |
| `FERRUM_MESH_REMOTE_DISCOVERY_POLL_TIMEOUT_SECONDS` | `30` | Per-poll timeout for the remote-cluster `MeshSubscribe` fetch |
| `FERRUM_MESH_POLICY_DENY_LOG_CAPACITY` | `10000` | Ring capacity of the in-memory `mesh_authz` deny recorder behind `GET /mesh/policy-denies/recent`. `0` disables the recorder (endpoint still serves an empty `grouped` array) |

### Listeners

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_INBOUND_LISTEN_ADDR` | `0.0.0.0:15006` | Sidecar inbound mTLS listener |
| `FERRUM_MESH_OUTBOUND_LISTEN_ADDR` | `127.0.0.1:15001` | Sidecar/ambient outbound capture listener |
| `FERRUM_MESH_HBONE_LISTEN_ADDR` | `0.0.0.0:15008` | Ambient HBONE listener |
| `FERRUM_MESH_EAST_WEST_LISTEN_PORT` | `15443` | East-west gateway shared listener port |
| `FERRUM_MESH_EGRESS_LISTEN_ADDR` | `0.0.0.0:15090` | Egress gateway mTLS listener |

### DNS Proxy

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_DNS_PROXY_ENABLED` | `false` | Enable the transparent DNS proxy |
| `FERRUM_MESH_DNS_LISTEN_ADDR` | `127.0.0.1:15053` | DNS proxy listen address (UDP + TCP) |
| `FERRUM_MESH_DNS_UPSTREAM_ADDR` | `127.0.0.53:53` | Upstream resolver for non-mesh queries |
| `FERRUM_MESH_DNS_TTL_SECONDS` | `60` | TTL for mesh-resolved DNS responses |
| `FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES` | `1024` | Concurrent query semaphore limit |
| `FERRUM_MESH_CLUSTER_DOMAIN` | `cluster.local` | Kubernetes cluster domain for FQDN synthesis |
| `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY` | `allow_any` | Mesh-wide outbound policy: `allow_any` or `registry_only` |
| `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS` | `502` | HTTP 4xx/5xx status returned when `registry_only` rejects an unknown HTTP-family destination |

### Identity / CA

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_CA_BACKEND` | `none` | CA backend for mesh SVID issuance: `none`, `internal` (dev-only self-signed root), `spire_agent` (SPIRE Workload API). `spire` / `spire-agent` are accepted aliases for `spire_agent` |
| `FERRUM_MESH_SPIRE_AGENT_SOCKET` | `/run/spire/sockets/agent.sock` | SPIRE Agent Workload API socket path |
| `FERRUM_MESH_CERT_TTL_SECONDS` | `3600` | Requested certificate TTL |
| `FERRUM_MESH_PRODUCTION_MODE` | `false` | Master production guardrail. When `true`, the dev-only self-signed CA bootstrap and the dev-only static attestor are refused unconditionally. Read directly by the identity helpers (not parsed into `EnvConfig`). Set in every production deployment. See [Internal Dev CA and Production Guardrails](#internal-dev-ca-and-production-guardrails) |
| `FERRUM_MESH_CA_BOOTSTRAP_DEV` | `false` | Dev-only opt-in to mint a self-signed mesh root for the `internal` CA backend. The bootstrap helper refuses unless this is `true` **and** `FERRUM_MESH_PRODUCTION_MODE` is not `true`. Lab/test only |
| `FERRUM_MESH_ALLOW_STATIC_ID` | `false` | Dev-only opt-in for the `StaticAttestor` (hard-coded SPIFFE ID for any peer). Refused unless `true` and `FERRUM_MESH_PRODUCTION_MODE` is not `true`. Lab/test only |
| `FERRUM_MESH_ALLOW_NO_CA` | `false` | Dev/test opt-in to start `mesh` mode with **no workload identity** (no file-based gateway SVID material; the CA backend doesn't load a runtime SVID yet). Without it, an identity-less mesh fails startup closed (no mTLS ⇒ PERMISSIVE accepts plaintext). Read directly from the environment (not `ferrum.conf`); refused unconditionally when `FERRUM_MESH_PRODUCTION_MODE=true`. Lab/test only — see [Internal Dev CA and Production Guardrails](#internal-dev-ca-and-production-guardrails) |

### xDS

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_XDS_NODE_CLUSTER` | (from `FERRUM_NAMESPACE`) | xDS `node.cluster` identity |
| `FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS` | `10` | xDS client connect timeout |

### Node Agent

| Variable | Default | Description |
|---|---|---|
| `FERRUM_NODE_AGENT_NODE_NAME` | (required) | Kubernetes node name, set via downward API (`spec.nodeName`) |
| `FERRUM_NODE_AGENT_CGROUP_ROOT` | `/sys/fs/cgroup` | cgroup v2 mount point for pod cgroup resolution |
| `FERRUM_NODE_AGENT_BPF_FS_PATH` | `/sys/fs/bpf` | BPF filesystem mount point for pinned maps |
| `FERRUM_NODE_AGENT_BPF_ELF_PATH` | build-tree path | Compiled `ferrum-ebpf` ELF (Linux `ebpf` feature only) |
| `FERRUM_NODE_AGENT_PROXY_MODE` | `local_pod` | Capture topology contract: `local_pod` or `node_waypoint` |
| `FERRUM_NODE_AGENT_ADMIN_ENABLED` | `false` | Enables the node-agent read-only admin listener for metrics/health. When enabled, defaults to loopback unless `FERRUM_ADMIN_BIND_ADDRESS` or `FERRUM_ADMIN_ALLOWED_CIDRS` is set; JWT does not affect bind because metrics/health are unauthenticated. |
| `FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT` | `15008` | HBONE redirect/listener port written into the capture contract and BPF config map. Must match the mesh proxy HBONE listener. |
| `FERRUM_NODE_AGENT_FALLBACK_MODE` | `fail` | Behaviour when eBPF prerequisites are missing (kernel < 5.7, cgroup v1, or bpffs unmounted). Default `fail` refuses startup with a structured error. `iptables` falls back to host iptables capture and sets `ferrum_mesh_node_topology_degraded=1`, but requires a runtime image with `/bin/sh`, `iptables`, and `ip6tables` when IPv6 capture is enabled. See [node_agent.md](node_agent.md#kernel-fallback). |
| `FERRUM_NODE_AGENT_EXCLUDED_NAMESPACES` | (empty) | Extra namespaces to exclude (`kube-system`, `kube-public`, `kube-node-lease` always excluded) |
| `FERRUM_MESH_CAPTURE_INCLUDE_CIDRS` | `0.0.0.0/0` | CIDRs to capture for outbound traffic |
| `FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS` | (empty) | CIDRs to exclude from outbound capture (highest priority) |
| `FERRUM_MESH_CAPTURE_EXCLUDE_PORTS` | `15001,15006,15008,15020` | Destination TCP ports excluded from outbound capture |
| `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` | (empty) | Destination TCP ports excluded from inbound capture (mirrors Istio `excludeInboundPorts`; pod annotation `traffic.sidecar.istio.io/excludeInboundPorts` is additive) |

### Injector

| Variable | Default | Description |
|---|---|---|
| `FERRUM_INJECTOR_LISTEN_ADDR` | `0.0.0.0:9443` | Webhook listen address |
| `FERRUM_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB` | `4` | Maximum AdmissionReview request body size, in MiB, accepted before JSON parsing. Values must be 1..64 |
| `FERRUM_INJECTOR_SIDECAR_IMAGE` | `ferrum-edge:latest` | Sidecar container image |
| `FERRUM_INJECTOR_REQUIRE_ANNOTATION` | `true` | Require opt-in annotation |
| `FERRUM_INJECTOR_TLS_CERT_PATH` | (none) | Webhook TLS certificate. Required (with the key) unless `FERRUM_INJECTOR_ALLOW_PLAINTEXT=true` |
| `FERRUM_INJECTOR_TLS_KEY_PATH` | (none) | Webhook TLS private key. Required (with the cert) unless `FERRUM_INJECTOR_ALLOW_PLAINTEXT=true` |
| `FERRUM_INJECTOR_ALLOW_PLAINTEXT` | `false` | Dev-only escape hatch. When `false` (default) the injector refuses to start without TLS cert+key, since Kubernetes mandates HTTPS for admission webhooks. Set `true` to serve plaintext HTTP for local development (logs a startup warning) |
| `FERRUM_INJECTOR_TRUST_DOMAIN` | `cluster.local` | SPIFFE trust domain for ID derivation |
| `FERRUM_MESH_CAPTURE_MODE` | `explicit` | Traffic capture mode: `explicit`, `iptables`, `ebpf` |
| `FERRUM_MESH_PROXY_UID` | `1337` | Proxy user ID in injected sidecars |
| `FERRUM_MESH_IP6TABLES_ENABLED` | `auto` | IPv6 iptables fan-out: `auto`, `true` (required/all-or-nothing), or `false` |

### Shared with CP/DP

Mesh mode reuses several CP/DP environment variables. See [cp_dp_mode.md](cp_dp_mode.md) for details:

- `FERRUM_DP_CP_GRPC_URLS` (required) -- CP endpoints for config subscription.
- `FERRUM_CP_DP_GRPC_JWT_SECRET` (required) -- shared JWT secret for gRPC auth.
- `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS` -- primary CP retry interval on fallback.
- `FERRUM_XDS_STREAM_CHANNEL_CAPACITY` -- per-ADS-stream response queue capacity.
- DP gRPC TLS variables (`FERRUM_DP_GRPC_TLS_*`).
