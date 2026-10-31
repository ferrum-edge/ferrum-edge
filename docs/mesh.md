# Mesh Mode

Ferrum Edge runs as a service mesh data plane when `FERRUM_MODE=mesh`. In this mode the gateway consumes mesh configuration from a Ferrum Control Plane (native `MeshSubscribe` gRPC) or a standard xDS ADS server, materializes SPIFFE-identity-aware proxies and authorization policies, and serves traffic with automatic mTLS, identity propagation, and Istio-compatible observability. The mesh subsystem deliberately reuses the existing proxy/plugin chain so the full gateway plugin set works unchanged in mesh context.

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
  - [Stock Envoy / third-party Istio xDS interoperability](#stock-envoy--third-party-istio-xds-interoperability)
  - [Ferrum mesh-slice ECDS carriers (full parity over xDS)](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds)
  - [ECDS DestinationRule carrier (full DR semantics over xDS)](#ecds-destinationrule-carrier-full-dr-semantics-over-xds)
  - [Bootstrap Behavior](#bootstrap-behavior)
- [Mesh Data Model](#mesh-data-model)
- [MeshSlice](#meshslice)
- [Authorization](#authorization)
  - [PolicyScope Filtering](#policyscope-filtering)
  - [AuthorizationPolicy targetRefs](#authorizationpolicy-targetref--targetrefs-issue-3226)
  - [Evaluation Semantics](#evaluation-semantics)
  - [AuthorizationPolicy action: CUSTOM](#authorizationpolicy-action-custom-issue-3235)
  - [Rule Matching](#rule-matching)
  - [SPIFFE Identity](#spiffe-identity)
  - [HBONE Protocol](#hbone-protocol)
  - [Inbound Relay Destination Guard](#inbound-relay-destination-guard)
  - [Trust Domain Aliasing](#trust-domain-aliasing)
  - [Trusted HBONE Assertors](#trusted-hbone-assertors)
- [RequestAuthentication](#requestauthentication)
- [PeerAuthentication](#peerauthentication)
- [Transparent DNS Proxy](#transparent-dns-proxy)
- [Multi-Cluster](#multi-cluster)
  - [Trust Federation](#trust-federation)
  - [Cross-Cluster Endpoint Discovery](#cross-cluster-endpoint-discovery)
- [Protocol x Topology Support Matrix](#protocol-x-topology-support-matrix)
- [Egress Gateway](#egress-gateway)
- [Sidecar Egress Scoping](#sidecar-egress-scoping)
- [Sidecar Outbound Traffic Policy](#sidecar-outbound-traffic-policy)
- [Config Drift Introspection](#config-drift-introspection)
- [DestinationRule](#destinationrule)
- [Observability](#observability)
- [Kubernetes Injector](#kubernetes-injector)
  - [UDP TPROXY capture](#udp-tproxy-capture)
- [Control Plane Integration](#control-plane-integration)
- [Gateway-to-Mesh Bridge](#gateway-to-mesh-bridge)
- [Mesh Identity](#mesh-identity)
  - [SPIRE Agent CA](#spire-agent-ca)
  - [Workload API JWT-SVID](#workload-api-jwt-svid)
    - [Serving the Workload API](#serving-the-workload-api)
    - [JWT signing material, restart, and HA](#jwt-signing-material-restart-and-ha)
    - [Workload API CA error status contract](#workload-api-ca-error-status-contract)
    - [SPIRE backend: serving a Workload API is refused](#spire-backend-serving-a-workload-api-is-refused)
  - [Internal Dev CA and Production Guardrails](#internal-dev-ca-and-production-guardrails)
  - [File-Based SVIDs: Two-Process Local Mesh](#file-based-svids-two-process-local-mesh)
- [Node Agent Mode](#node-agent-mode)
- [VirtualService Translation](#virtualservice-translation)
- [Gateway API Status](#gateway-api-status)
- [Istio CRD Status](#istio-crd-status)
- [Locality-Aware Load Balancing](#locality-aware-load-balancing)
- [xDS ADS Compatibility](#xds-ads-compatibility)
- [Istio Compatibility Gaps](#istio-compatibility-gaps)
- [Migrating from Istio](#migrating-from-istio)
- [Environment Variables](#environment-variables)

## Maturity and Support Status

Ferrum's mesh subsystem is in active build-out. The paths below ship in one binary and share the same proxy/plugin chain, but they are at very different maturity levels. Use this matrix to decide what to rely on in production. Labels:

- **Stable** — exercised end-to-end (functional/integration tests against a live data path), production-suitable.
- **Beta** — feature-complete and tested, but with a documented sharp edge or a verification step still owed (see [Limitations](#limitations-and-not-supported)).
- **Experimental** — usable but with a safety-relevant caveat (plaintext, unauthenticated, or partial enforcement); opt-in and not recommended without compensating controls.
- **Dev-only** — gated behind a build feature or an explicit dev opt-in; not present in the published image's default behavior.

> **Stable** in these tables is the GA tier of the product contract ([docs/mesh_supported_matrix.md](mesh_supported_matrix.md)). GA is machine-enforced only for features enrolled in `tests/conformance/ga_contract.yaml` (see [CONFORMANCE.md](../CONFORMANCE.md) and the generated `target/conformance/coverage.md` for enrolled rows and required live assertion IDs); not every Stable row is enrolled yet.
>
> The live half is backed by two required suites: **`mesh-e2e-sidecar`** (`tests/k8s/mesh_e2e_sidecar/`) for the same-cluster sidecar rows and **`multicluster-federation`** (`tests/k8s/multicluster-federation/`) for the cross-cluster east-west rows; both are PR- and release-blocking. Poller-driven cross-cluster endpoint discovery is Beta and excluded from the GA rows.

### Config-source maturity

| Capability | Status | Notes |
|---|---|---|
| Native `MeshSubscribe` (Ferrum CP → Ferrum DP) | **Stable** | Default protocol. Full slice (authz, PeerAuth, JWT, ServiceEntry, trust bundles, ProxyConfig, workloads, telemetry, multi-cluster) is pushed directly. The most mature and recommended config path. GA-gated (`mesh.config_transport.native_subscribe`). |
| xDS ADS (Ferrum CP → Ferrum DP) | **Beta** | Functionally equivalent to native via Ferrum-specific ECDS carriers (`ferrum.config.extension.v3.*`), including `ProxyConfig` on `ProxyConfigsCarrier`. **NOT stock-Envoy / third-party-Istio interop** — a non-Ferrum CP emits only name-only CDS/EDS/LDS/RDS and no carriers, so it cannot drive a protected Ferrum mesh and may be NACKed. RTDS layers are authored by the operator's CP (Ferrum's xDS server does not originate Runtime resources). |
| Localized file source (`FERRUM_MESH_CONFIG_PROTOCOL=file`) | **Beta** | No control plane; same materialization as native/xDS; SIGHUP-only reload keeps last-good and raises `/health` `config_rejected`. See [Localized file source](#localized-file-source-no-control-plane). |
| Stock Envoy / third-party Istio xDS interop (`FERRUM_MESH_CONFIG_PROTOCOL=stock_xds`) | **Beta** | Issue #3317. A **separate protocol** from `xds`: consumes standard v3 CDS/EDS/LDS/RDS from a stock Envoy / third-party Istio control plane and projects it onto `MeshService` / `Workload` for **discovery only**. Enforcement policy comes from the mandatory local `FERRUM_MESH_FILE_CONFIG_PATH` document, so a third-party CP can change reachability but never Ferrum's security posture. Everything Ferrum does not model is refused per-resource with a field-specific diagnostic and contributes no route, endpoint, or identity. Live data-path coverage (a scripted third-party ADS server driving a real sidecar through update / deletion / NACK / refusal) runs in the hosted `data-plane-runtime` functional shard. See [Stock Envoy / third-party Istio xDS interoperability](#stock-envoy--third-party-istio-xds-interoperability). |

### Topology maturity

| Topology | Status | Notes |
|---|---|---|
| `Sidecar` + native config | **Stable** | The most mature path: inbound 15006 mTLS + outbound 15001 capture, SPIFFE-verified peers, full authz/JWT/DR enforcement. Recommended for production. GA-gated (`mesh.config_transport.native_subscribe`). |
| `Ambient` (HBONE 15008) | **Beta** | HBONE termination over mTLS is implemented and SPIFFE-trust-domain-verified. Requires eBPF ambient capture (or iptables) to actually intercept traffic — see capture maturity below. |
| `EastWestGateway` (SNI passthrough 15443) | **Stable** | TCP/SNI passthrough for multi-cluster; no TLS termination. Live-gated by the `multicluster-federation` suite (issue #2459). Cross-cluster *endpoint* discovery (vs SNI passthrough) is separate and Beta — see below. |
| `EgressGateway` — HTTP-family (15090 mTLS) | **Beta** | mTLS-terminating egress for `mesh_external` ServiceEntries with `outboundTrafficPolicy` enforcement. |
| `EgressGateway` — stream-family (TCP) | **Experimental** | Opt-in via `FERRUM_MESH_EGRESS_STREAM_ENABLED=true`. Per-port TCP stream listeners **terminate SVID-mTLS and run `mesh_authz`** at accept (parity with HTTP egress), reusing the mesh-inbound `ServerConfig` + SPIFFE peer verifier; **client certs are required** (PERMISSIVE is escalated to require a verified SVID for the egress boundary — a cert-less client is rejected, not admitted). Fail-closed (no mTLS material → listener defers its bind, never plaintext; no trust anchor under PERMISSIVE → hard error). `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true` restores the legacy plaintext + unauthenticated listener (loud startup warning; use only with compensating controls). UDP ServiceEntry ports materialize datagram-over-mesh egress under the same flag — a destination allowlist consumed by the gateway's authenticated mesh CONNECT terminator, never a UDP/DTLS listener, plus a source-side producer (`FERRUM_MESH_EGRESS_GATEWAY_ADDR`/`_SPIFFE_ID`) that originates the identity-pinned `udp` CONNECT from a `Sidecar`/`Ambient` workload; see "External UDP egress (EgressGateway)" below. Default-off topology; Experimental because protocol-aware mediation is absent and the live mTLS datapath is unit/integration-tested, not yet live-e2e. |
| `ServiceWaypoint` (GAMMA) | **Beta** | Service-scoped Ambient waypoint; CP narrows resources to the named binding. Needs the eBPF/ambient capture caveats of node-waypoint when fronting captured pods. |
| `NodeWaypoint` (sidecarless capture) | **Experimental** | IPv4/IPv6 capture, the GAP-2M identity bridge, secured service transport, destination relay authz, and per-source-pod UDP/DTLS scoping are implemented and live-gated by `node-waypoint-ebpf-live`; requires a Linux `--features ebpf` build, and IPv6 DTLS remains unit/integration-level. See [Node Waypoint](#node-waypoint) and [mesh_supported_matrix.md](mesh_supported_matrix.md). |

### Capture / data-path maturity

| Capability | Status | Notes |
|---|---|---|
| iptables capture (injector init container) | **Beta** | Requires `NET_ADMIN`/`NET_RAW`; rules applied at pod admission, restart needed to pick up new annotations. |
| eBPF ambient capture | **Dev-only** | Requires a `--features ebpf` build (the default published image refuses eBPF mode before readiness, degraded reason `ebpf_feature_disabled`) and kernel ≥ 5.7 with cgroup v2; see [Platform prerequisites](#platform-prerequisites). |
| orig-dst → proxy identity bridge (node-waypoint) | **Experimental** | Socket-cookie identity resolution (GAP-2M accept-side bridge plus per-pod identity enrollment) is complete for IPv4 and IPv6 and fails closed on any tuple/enrollment miss; see [Node Waypoint](#node-waypoint). |

### Identity / CA maturity

| Capability | Status | Notes |
|---|---|---|
| SPIRE Agent CA (`spire_agent`) | **Stable** | Recommended production identity path — delegates SVID issuance to a separately operated SPIRE installation over the Workload API. GA-gated (`mesh.identity.spire_svid_issuance`). |
| Internal self-signed CA (`internal`) | **Dev-only** | Self-signed root generated by the bootstrap helper; gated behind `FERRUM_MESH_CA_BOOTSTRAP_DEV=true` and refused when `FERRUM_MESH_PRODUCTION_MODE=true`. **Process-local**: each process mints its own root, so two `internal` processes do NOT share trust and cannot mTLS each other — use [File-Based SVIDs: Two-Process Local Mesh](#file-based-svids-two-process-local-mesh) for a local multi-process mesh. Lab/test only — see [Internal Dev CA and Production Guardrails](#internal-dev-ca-and-production-guardrails). |
| SPIFFE inbound/HBONE peer trust-domain verification | **Stable** | When gateway SVID material is configured, inbound mTLS/HBONE peers are SPIFFE-trust-domain-verified against the local + federated bundles (not just chain-validated). |
| Trust-bundle federation poller | **Beta** | Fetches `RemoteCluster.federation_endpoint` bundles and activates the same effective trust set for outbound mTLS and inbound SPIFFE verification. `FERRUM_MESH_FEDERATION_FAIL_OPEN=false` blocks CP fallback until a poll succeeds; `true` allows CP fallback during bootstrap. |

### Cross-cluster maturity

| Capability | Status | Notes |
|---|---|---|
| East-west SNI passthrough + trust federation | **Stable** | GA-gated by the `multicluster-federation` suite. See `EastWestGateway` above and [Trust Federation](#trust-federation). |
| Cross-cluster endpoint discovery (local→remote failover) | **Beta** | `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS>0` dials each `RemoteCluster.control_plane_url`. The dedicated two-CP/two-DP Toxiproxy live gate proves bounded last-good retention, independent endpoint/trust expiry, fail-closed target withdrawal, same-generation recovery, and in-flight `RemoteCluster` retirement. Requires source locality to be set for local-first preference. |

## Limitations and Not Supported

This section consolidates every known residual gap so operators do not have to reconstruct them from the prose. Items are grouped by area; each is enforced or deferred as described against the merged code.

### Not interoperable / not planned

- **Stock Envoy / third-party Istio xDS interop** — `FERRUM_MESH_CONFIG_PROTOCOL=xds` is a **Ferrum-CP-to-Ferrum-DP** path and stays that way: CDS/EDS/LDS/RDS are name-only with Ferrum-shaped resource names, and all security/policy fields ride Ferrum-defined ECDS carriers, so pointing *that* client at a non-Ferrum CP remains unsupported. For a third-party control plane use the separate `FERRUM_MESH_CONFIG_PROTOCOL=stock_xds` profile, which consumes standard v3 CDS/EDS/LDS/RDS for **discovery only** — see [Stock Envoy / third-party Istio xDS interoperability](#stock-envoy--third-party-istio-xds-interoperability) for the exact capability boundary. Enforcement policy is never sourced from a stock CP.
- **`EnvoyFilter`** — not planned. Use Ferrum custom plugins (`custom_plugins/`).
- **`WasmPlugin`** — not planned. Use Ferrum custom plugins.

### Capture / node-waypoint (see also the Maturity matrix)

- **eBPF capture is a build feature** — the default published image refuses eBPF mode before readiness; see [Platform prerequisites](#platform-prerequisites).
- **NodeWaypoint is Experimental** — identity bridge, destination metadata, and per-source-pod UDP/DTLS scoping are documented under [Node Waypoint](#node-waypoint).
- **NodeWaypoint inbound tc redirect** — opt-in (`FERRUM_NODE_AGENT_INGRESS_REDIRECT_IFACES`), IPv4 + IPv6; a single-node cluster (or any node without remote topology evidence) reports `no_remote_topology_evidence`. See [Inbound capture (tc ingress redirect)](#inbound-capture-tc-ingress-redirect).
- **Alternate policy routing and encapsulating CNIs** (inner and outer devices differ) are unsupported by the tc redirect's topology proof and stay failed closed. See [Inbound capture (tc ingress redirect)](#inbound-capture-tc-ingress-redirect).
- **Capture-destination residual risk** — the capture path is only as good as the destination inventory the config authority publishes; a workload with missing or wrong `node_waypoint` metadata is not captured for (fail closed). See [Inbound capture (tc ingress redirect)](#inbound-capture-tc-ingress-redirect).

### Authorization


- **`ipBlocks` / `remoteIpBlocks` on the stream path distinguish socket peer from forwarded address** — on the HTTP request path `ipBlocks`/`source.ip` is the immediate downstream socket peer (`direct_client_ip`) and `remoteIpBlocks`/`remote.ip` is the gateway-resolved, XFF-aware `client_ip`. On the **TCP stream path** (`on_stream_connect`) the same split applies: `source.ip` = socket peer (`StreamConnectionContext.direct_client_ip`), `remote.ip` = resolved client IP (`StreamConnectionContext.client_ip`). When **inbound PROXY protocol** (`stream_proxy_protocol: true`) is enabled on a TCP stream proxy and the upstream LB is in `FERRUM_TRUSTED_PROXIES`, the forwarded address from the PROXY header becomes `client_ip` (used for `remote.ip` / `remoteIpBlocks`) while `direct_client_ip` retains the LB's own socket-peer IP (used for `source.ip` / `ipBlocks`). Without PROXY protocol both values equal the socket peer — this is the correct Envoy-parity behavior for raw TCP not fronted by a PROXY-protocol-capable LB. On the **UDP/DTLS** stream path the same split applies through the datagram client-address envelope (`stream_proxy_protocol: true` on a `udp`/`dtls` proxy, [tcp_udp_proxy.md](tcp_udp_proxy.md#datagram-client-address-metadata-udp--dtls)): the authenticated forwarded address becomes `client_ip` (`remote.ip` / `remoteIpBlocks`) while `direct_client_ip` (`source.ip` / `ipBlocks`) keeps the balancer's socket peer. When `FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET` is set, the HMAC covers a versioned domain-separation prefix naming the exact receiving listener (receive-boundary protocol, canonical bind address, port), so an envelope minted for one listener can never authenticate on another under one process-global root secret — for every command and family, `LOCAL` and `AF_UNSPEC` included. Each authenticated envelope also carries an authenticated freshness record, and a bounded per-sender replay window admits each sequence at most once per process (cross-restart / cross-replica exposure bounded to a fixed 30-second timestamp horizon). A datagram whose envelope is absent, untrusted, unauthenticated, malformed, bound to another listener, duplicate, or stale is dropped rather than downgraded. Once a 4-tuple is admitted, a different forwarded identity is dropped and does not refresh idle activity — in the unauthenticated posture a spoof that wins a fresh-flow race can blackhole the genuine flow until the idle window, then self-heals. Without the envelope both values equal the socket peer. IP-block matchers fail closed when the IP they test is absent.
- **DENY rules treat unsourceable HTTP-only attributes as matches** — Istio semantics (see [Layer-4 sessions and CONNECT relays](#layer-4-sessions-and-connect-relays)). A DENY rule that mentions HTTP fields also matches raw TCP traffic it can see, so scope such rules to HTTP ports or they may over-match.
- **A mesh CONNECT relay is authorized as Layer-4 traffic** — HBONE and bare Sidecar CONNECT tunnels are relayed as opaque bytes, so an L7 DENY or a `paths` / `methods` ALLOW scoped to a workload reached this way judges (and can deny) the whole tunnel, and a Ferrum waypoint applies an L7 `AuthorizationPolicy` as an L4 policy. Scope such rules with `to.operation.ports` (or move L7 enforcement to an HTTP route); see [Layer-4 sessions and CONNECT relays](#layer-4-sessions-and-connect-relays).

### DestinationRule limitations / approximations / deferred fields

Field-by-field status is the [support matrix](#meshdestinationrule); these are the deferrals and deliberate differences from Istio:

- **`connectionPool.http.maxRequestsPerConnection`** — **Deferred** at every scope (no backend close-after-N-requests behavior); listed in `deferred_fields`. Use `maxConcurrentStreams` (per-connection HTTP/2 streams) or `http2MaxRequests` (destination-wide active requests).
- **`subsets[].trafficPolicy.portLevelSettings`** — **Deferred** with a translate-time warning; express per-port policy at top-level `portLevelSettings` or via subset `connectionPool` fields.
- **Precedence** — field-level precedence is `portLevelSettings` > selected subset > top-level (Istio applies subset > `portLevelSettings` — inverted on purpose), and Ferrum merges per field instead of replacing the whole `connectionPool`. See [Port-level and subset policy](#port-level-and-subset-policy).
- **`connectionPool.http.maxRetries`** — a **per-request retry-count cap**, not Envoy's cluster-wide outstanding-retry budget; it never enables retries on its own. See [DestinationRule `maxRetries` semantics](#destinationrule-maxretries-semantics).
- **`connectionPool.http.http1MaxPendingRequests`** — reinterpreted as a cap on concurrent **in-flight HTTP/1.1** requests (shed with `503`), because reqwest exposes no pending-queue hook; see the [support matrix](#meshdestinationrule) row.
- **`connectionPool.tcp.maxConnections`** — keyed per `(host, policy port)` endpoint rather than per cluster; see [DestinationRule `maxConnections` enforcement scope](#destinationrule-maxconnections-enforcement-scope).
- **`loadBalancer.simple = PASSTHROUGH`** — dials the captured original destination only when it matches a healthy pool target; otherwise (no captured destination, e.g. HTTP/3, or an ejected/unknown target) it falls back to `ROUND_ROBIN` with a warning. `MAGLEV` is rejected.
- **Stream-family per-port policy** — TCP/UDP/DTLS engage per-port `loadBalancer` / `localityLbSetting` only when all targets share one port; a per-port `consistentHash` must use a source-IP key and per-port `LEAST_LATENCY` is refused on every stream lane (fail-closed `Unsupported stream policy`). Stream paths record **no passive (outlier) ejections** themselves; they consume ejections recorded by active probes or HTTP-family traffic.

### VirtualService

- **`http[].corsPolicy` deferrals** — a credentialed exact `*`, a credentialed opaque exact `null`, and a credentialed effectively universal prefix/regex are deferred rather than reflecting arbitrary origins with credentials. Invalid or over-budget policies, and predicate-scoped policies on mesh sidecars, are not projected either; see the full translatability boundary in [CORS policy](#cors-policy-httpcorspolicy).
- **Per-rule fault percentages are not RTDS-tunable** — the RTDS fault keys apply only to `fault_injection` plugin instances with `runtime_overlay_scope`, not to per-route VS faults.

### mTLS / HBONE operator cautions

- **PERMISSIVE with no client CA degrades to no-auth (non-egress topologies)** — if `PeerAuthentication` resolves to `PERMISSIVE` but neither `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` nor gateway SVID material is configured, client certificates are **not requested or verified** (logged at startup as a `warn!`; resolved through the explicit `PermissiveNoTrustAnchor` decision in `resolve_mesh_inbound_client_auth`). The listener admits unauthenticated peers and no peer SPIFFE identity is recorded. Configure a client CA or SVID material, or use STRICT, when you need PERMISSIVE to actually capture identity. **This degradation does NOT apply to the EgressGateway topology**: there a present trust anchor escalates PERMISSIVE to require a client cert, and a missing trust anchor fails the listener closed (the egress boundary must authenticate every client) — see "EgressGateway requires client certificates" in the listener-wiring section.

### Federation / multi-cluster

- **Live two-CP discovery and cross-cluster datapath are verified across real clusters** — `tests/k8s/multicluster-federation/` remains the authoritative static SPIRE/east-west GA datapath gate, while `tests/k8s/multicluster-poller-partition/` deploys two additional real Ferrum CP/DP pairs and routes both federation and native remote discovery through independently faultable Toxiproxy links. The second gate proves short-loss retention, endpoint and trust stale boundaries, fail-closed removal, same-generation recovery, bounded/redacted metrics with admin parity, and in-flight `RemoteCluster` retirement. Both fixtures emit exact required live-assertion sets and neither relies on kind NetworkPolicy enforcement. See [Cross-Cluster Endpoint Discovery](#cross-cluster-endpoint-discovery).

## Failure-Mode Runbook

Where to look, and what to expect, when the mesh data plane misbehaves. All slice state lives in an `ArcSwap<Option<MeshSlice>>` (lock-free hot-swap); in-flight requests always see a complete old-or-new slice, never a partial one.

| Symptom | What happens | Where to look / what to do |
|---|---|---|
| **CP unreachable at startup** | `wait_for_initial_mesh_config` blocks (via `wait_for_first_slice`) until the first valid slice arrives — the DP does not serve traffic with an empty/unprotected config. The native/xDS client retries with jittered exponential backoff (1s → 30s, ±25%) across all `FERRUM_DP_CP_GRPC_URLS`. | Confirm `FERRUM_DP_CP_GRPC_URLS`, the `FERRUM_CP_DP_GRPC_JWT_SECRET`, and DP↔CP TLS. Startup logs show the connection/backoff attempts. The DP stays NotReady until converged. |
| **CP goes down after startup** | The last-good slice is retained (ArcSwap snapshot keeps serving). No new slices arrive; the client backs off and reconnects. | `GET /mesh/config-drift` shows `slice.last_received_at` / `age_seconds` going stale; alert on `ferrum_mesh_config_last_received_timestamp_seconds`. **SVID interaction:** while disconnected, SVID rotation still proceeds via the CA backend (SPIRE Agent / internal); the federation poller and CP-pushed trust bundles do not update, so a *new* federated trust domain will not appear until the CP returns. Existing identities and bundles remain valid until their own TTLs expire. |
| **Slice rejected (invalid update)** | The update is logged (`Ignoring invalid mesh slice update` / `Ignoring invalid initial mesh slice`) and dropped; the last accepted slice keeps serving. A rejected slice never advances `config-drift` `last_received_at`/fingerprint and never alters inbound trust (staged SPIFFE bundle is dropped on rejection). Over xDS, a malformed mesh-slice carrier causes the DP to NACK the whole ECDS response and retain the previous slice. | Search logs for `Ignoring invalid` and the `mesh_slice_version` + `error`. Compare `slice.fingerprint` across DPs via `GET /mesh/config-drift` to spot split-brain. |
| **eBPF capture unavailable** | The node-agent probes kernel ≥ 5.7 + cgroup v2 + bpffs once at startup. On a miss it sets `ferrum_mesh_node_topology_degraded{reason}` to `1` (reason ∈ `kernel_too_old` / `cgroup_v1` / `bpffs_missing`) and, with the default `FERRUM_NODE_AGENT_FALLBACK_MODE=fail`, refuses to start. `=iptables` falls back to host iptables capture (needs a custom image with `/bin/sh` + `iptables`). On a build without `--features ebpf`, the orig-dst bridge logs once and exits and node-waypoint accept fails closed. | Alert on `ferrum_mesh_node_topology_degraded == 1` and node-agent readiness. See [Node Agent Mode](#node-agent-mode) and [docs/node_agent.md](node_agent.md#kernel-fallback) for the per-reason remediation table. The rest of the data plane (slice apply, `mesh_authz`, `workload_metrics`, HBONE) is unaffected by node-level capture degradation. |
| **Requests denied unexpectedly** | `mesh_authz` evaluated DENY-first then implicit-deny-on-no-ALLOW-match. | `GET /mesh/policy-denies/recent` (JWT) groups recent denies by `(rule, source, destination, reason, reevaluation)`; correlate with `ferrum_mesh_requests_total{response_code="403"}`. Transaction logs carry `mesh_authz.deny_policy` (e.g. `untrusted_assertor`, `trust_domain_mismatch`, `unauthenticated_baggage`) and `mesh_authz.scope_missing` (node-waypoint per-pod scope not yet enrolled). |
| **mTLS / HBONE handshake failures** | Peer cert chain or SPIFFE trust-domain validation failed, or a plaintext peer hit a STRICT listener. | `ferrum_mesh_mtls_handshake_failures_total{reason}` (`timeout` / `error`) for mesh-wide TLS. On NodeWaypoint also `ferrum_mesh_node_waypoint_hbone_handshakes_total{phase,result}` (phased inbound_tls / inbound_connect / outbound_dial; see `docs/plans/node_waypoint_transport_adr.md`). Check that gateway SVID material (`FERRUM_GATEWAY_SVID_*`) and the slice trust bundles cover the peer's trust domain; for HBONE baggage rewrites, confirm the assertor is on `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS`. Remember PERMISSIVE-with-no-client-CA admits unauthenticated peers (see [Limitations](#limitations-and-not-supported)). **Read the client-visible label first:** `Sidecar mTLS backend unavailable: …` is an outbound `:15006` SVID-mTLS failure and involves no tunnel, while `HBONE backend unavailable: …` is an Ambient/waypoint CONNECT over `:15008` — the two have different remediations. The body carries only a fixed phase name; the operator `error!` record uses the same closed-cardinality phase plus `error_kind` (and CONNECT `peer_status` when present) and does not interpolate peer address, identity, or verifier text. Two `FERRUM_MESH_CA_BACKEND=internal` processes can never handshake each other (each mints its own root) — see [File-Based SVIDs: Two-Process Local Mesh](#file-based-svids-two-process-local-mesh). |
| **Cert / CA health** | SVID rotation or CA backend problems. | `ferrum_mesh_cert_expiry_seconds`, `ferrum_mesh_cert_rotation_failures_total`, `ferrum_mesh_ca_health{ca_type}`, `ferrum_mesh_trust_bundle_version`. |

## Observability and Troubleshooting Quick Reference

Plugin configuration diagnostics retain fixed fields and zero-based list
positions while withholding supplied identities, values and document map keys.
For example, a malformed label value identifies `mesh_slice` and
`labels[<redacted key>]`; a rejected exporter identifies the batch option or
provider position and endpoint field. Metric-tag CEL errors distinguish the
512-byte expression limit, nesting/complexity limits and integer attributes
that require `string()`. Successful constructors still warn about `mesh_wide`
assertor grants and unenforced selector policies, using sanitized identities
and separate assertor, policy and effective baggage-gate indexes.

### Admin introspection endpoints (JWT-authenticated; status codes are per-endpoint)

Every row below requires a valid admin JWT. Wrong-mode and boot-time responses are **not** a blanket `404` outside mesh mode — several surfaces return `200` with an empty body before convergence, `503` when `proxy_state` is unwired (typical `cp` mode), or `404` only on CP-only routes. Operators rely on the split between **`404` = wrong mode or endpoint not applicable** and **`200` with null/empty fields = mesh mode, not converged yet** (for example `GET /mesh/config-drift` with `last_received_at: null` vs `GET /mesh/federation` returning `404` until the first federation poll succeeds).

| Endpoint | Access | Status contract | Purpose | Diagnose |
|---|---|---|---|---|
| `GET /mesh/config-drift` (`?include_overlay=false`) | mesh DP | **404** outside mesh. **200** zeroed `resources` and omitted/null `last_received_at` before the first accepted slice. | Per-DP "where is this DP vs the CP's last push" — `slice.last_received_at`, `version`, per-kind `resources` counts, `fingerprint`, `source_protocol`/`source_cp_url`, RTDS `runtime_overlay`, and (xDS mode) the `convergence` block (per-type versions, missing required types). | Stuck DP (stale `last_received_at`), split-brain (fingerprint divergence), cross-cluster endpoint discovery (workload/service resource counts), RTDS drift, wedged xDS warming (non-empty `convergence.missing_required_types`). |
| `POST /mesh/config-revision/reset` | mesh DP; JWT **`operator`** role | **404** outside mesh. **200** `{status:"reset", cleared_revision}` (or `cleared_revision: null` when the gate held none). | Clears the accepted config revision so the next slice from any authority is eligible — recovery for a sequence rewind inside one authority (config store restored from backup without bumping `FERRUM_MESH_CONFIG_AUTHORITY_ID`). Prefer fleet-wide `FERRUM_MESH_CONFIG_K8S_AUTHORITY_ID` / `FERRUM_MESH_CONFIG_AUTHORITY_ID` bumps when possible; foreign-authority adoption uses `FERRUM_MESH_CONFIG_REVISION_ADOPT_SECS` instead. | Same-authority etcd/DB restore stuck behind the revision gate; pair with `GET /mesh/config-drift` after reset. |
| `GET /mesh/slice-drift` | **CP only** | **404** outside CP mode (including mesh DPs: `"Mesh slice-drift is only available in control-plane mode"`). **200** empty `data_planes` before the first local `MeshSubscribe` DP connects. | CP-side desired / sent / acknowledged (accepted) / applied / rejected slice versions per authenticated local MeshSubscribe identity (issues #3265, #4812). | Stuck/partitioned/rejecting DPs after a successful CP reconciliation; pair with each DP's `/mesh/config-drift`. |
| `GET /mesh/federation` | mesh DP | **404** outside mesh or before the first successful federation poll (`"No mesh federation bundles cached yet"`). | Trust-bundle federation snapshot: per-trust-domain `bundle_age_seconds` + authority counts. | Stale / missing federated bundles for cross-cluster mTLS. |
| `GET /mesh/remote-clusters` | mesh DP | **404** outside mesh. **200** empty `discovered`/`configured` before remote discovery runs. | Multicluster east-west discovery: `discovered` remote clusters (per-cluster workload/service counts + fetch age) and the `configured` remote clusters from the accepted slice (each with a `discovered` flag). | Which remote cluster is contributing endpoints; configured-but-unreachable clusters (`configured` present, `discovered: false`). |
| `GET /mesh/runtime-overlay` | mesh DP | **404** outside mesh or before the first proxy-accepted slice. **200** empty overlay after the first slice when no RTDS layers have arrived. | Live RTDS overlay (fault percentages, transformer gates, log level). | RTDS knob propagation. |
| `GET /mesh/service-graph` | mesh DP | **404** outside mesh or before the first accepted slice. | Node-local source/destination edge graph from `workload_metrics`. | Who is talking to whom (per DP; aggregate in the backend). |
| `GET /mesh/policy-denies/recent` (`?window=`, `?limit=`) | mesh DP | **404** outside mesh. **200** empty `grouped` before denies occur (also when `FERRUM_MESH_POLICY_DENY_LOG_CAPACITY=0`). | Aggregated recent `mesh_authz` denies grouped by `(rule, source, destination, reason, reevaluation)`. | Misconfigured `AuthorizationPolicy` / unexpected denies. |
| `GET /mesh/egress-scope` + `POST /mesh/egress-scope/test` | mesh DP | **503** `"No proxy state available"` when `proxy_state` is unwired (typical CP). **404** outside mesh or before an egress-scope snapshot exists. | Resolved Sidecar egress scope: admitted/denied services + outbound-registry destinations; dry-run host/port check. | Sidecar egress narrowing before/after enabling enforcement. |
| `GET /node-waypoint/identities` | NodeWaypoint mesh DP | **503** `"proxy_state unavailable in this mode"` when `proxy_state` is unwired. **404** when node-waypoint topology is not enabled. | Currently enrolled pod identities. | Node-waypoint enrollment / cookie resolution. |
| `GET /service-waypoint/services` | ServiceWaypoint mesh DP | **404** outside mesh, before the first slice, or when the slice has no `waypoint_name`. | Services bound to this waypoint in the active slice. | GAMMA waypoint binding resolution. |

For remote-cluster discovery specifically, `GET /mesh/remote-clusters` names each remote cluster the DP has fetched endpoints from (and the remote clusters the accepted slice declares); `GET /mesh/config-drift` resource counts and the locality-aware LB behavior remain useful for the aggregate workload/service totals.

### Key metrics (`/metrics`, authenticated)

Scrapers must present a valid admin JWT or `FERRUM_METRICS_BEARER_TOKEN`, or
originate from `FERRUM_METRICS_ALLOWED_CIDRS`.

- RED: `ferrum_mesh_requests_total`, `ferrum_mesh_request_duration_ms` (carry SPIFFE identity + `connection_security_policy` labels).
- Config freshness: `ferrum_mesh_config_last_received_timestamp_seconds{namespace}`.
- Config ordering: `ferrum_mesh_config_revision_rejections_total{reason}` (`stale_revision` / `incomparable_authority` / `missing_revision` / `malformed_revision` / `divergent_content` / `unidentified_content`) and `ferrum_mesh_config_revision_adoptions_total` — see [Authoritative Config Revisions And Stale-Fallback Rejection](#authoritative-config-revisions-and-stale-fallback-rejection). Fixed cardinality; the CP-supplied authority/sequence detail stays on the JWT-gated `GET /mesh/config-drift` `revision` block.
- Identity: `ferrum_mesh_cert_expiry_seconds`, `ferrum_mesh_cert_rotation_failures_total`, `ferrum_mesh_ca_health{ca_type}`, `ferrum_mesh_trust_bundle_version`, `ferrum_mesh_mtls_handshake_failures_total{reason}`.
- NodeWaypoint ADR (topology-gated): `ferrum_mesh_node_waypoint_hbone_handshakes_total{phase,result}`, `ferrum_mesh_node_waypoint_asserted_identity_total{result,reason}`, `ferrum_mesh_node_waypoint_destination_policy_rejections_total{reason}`, `ferrum_mesh_node_waypoint_missing_destination_metadata_total`, `ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total` (see `docs/plans/node_waypoint_transport_adr.md`).
- Inbound posture: `ferrum_mesh_inbound_plaintext_allowed` — `1` when the mesh inbound listener was allowed up without enforced mTLS (dev opt-out posture; production mode refuses it), `0` otherwise.
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

The inbound listener terminates mTLS from peer sidecars and forwards plaintext to the co-located application:

- **Inbound routes.** For the **local** workload (identified by its SPIFFE identity, `FERRUM_MESH_WORKLOAD_SPIFFE_ID`), Ferrum materializes an inbound route per HTTP-family service port of each Service this local pod backs (the workload record's `service_name` plus namespace, with the Service listing the workload's SPIFFE id in `workloads[]`), targeting `127.0.0.1:<appPort>`, so an mTLS-terminated request reaches the app after `mesh_authz` admission. A single pod selected by multiple Services — same SPIFFE and the same non-empty pod UID on every matching workload record — materializes one inbound Host route per Service. Missing or divergent UIDs remain ambiguous even when endpoint addresses match (hostNetwork pods can share an IP) and materialize no inbound routes. Distinct pods that only share a service-account SPIFFE likewise remain ambiguous. The backend (container) port is resolved from the signals the slice carries — a shared port **name**, else an equal port **number**, else the workload's sole container port; a workload that declares no ports defaults to the service port. When a Service uses a numeric `targetPort` that differs from `port` across multiple unnamed container ports the backend is genuinely ambiguous (the model does not yet carry `targetPort` end-to-end), so the route is **skipped with a warning** rather than misrouted — name the ports consistently or supply an explicit proxy. If an explicit proxy already routes the same host/path (overlap evaluated with the same wildcard/catch-all semantics as listen-path validation), the operator's proxy wins.
- **Multi-port selection order.** **Multi-port local services materialize one loopback sibling per HTTP-family service port**, disambiguated post-match by, in priority order: the inbound connection's captured original destination (a sidecar-less client's direct dial of the app port that the injector's iptables REDIRECTed to `:15006` — its port is the **container** port), then the request's explicit `Host`/`:authority` port (the **service** port — peer-sidecar `:15006` dials are direct and never NATed, so the authority is the channel a multi-port-aware egress sidecar controls; see the egress bullet below). A multi-port request carrying neither signal — or a signal matching no materialized sibling — is rejected 502, never guessed onto one port's backend. A single-port service accepts bare-Host clients (no port signal) and an explicit `Host` port naming either its service port (`Host: reviews:80`) or its container port (a headless `pod-0.reviews:9080` dial — single-port peers forward the client authority unchanged); a captured original destination must be its container port. Any other explicit port is rejected the same way, and every inbound port-selection rejection logs a rate-limited warning naming the route, the port signals and the reason.
- **Stream-family relay.** Stream-family local service ports (`tcp`, `tls`, and DB protocols) prepare a runtime-only raw-TCP inbound map keyed by the captured original-destination app port; when the effective PeerAuthentication mode admits plaintext and iptables REDIRECT preserves `SO_ORIGINAL_DST`, the accept loop recognizes the stream-family route before HTTP/TLS classification and relays its bytes unchanged, including an application-level TLS ClientHello beginning with `0x16`. It then runs the L4 stream plugin chain (`mesh_authz` and the other `on_stream_connect` hooks) **with the captured app port as the authorization destination** and, only if not rejected, relays those bytes to `127.0.0.1:<appPort>` before Hyper parses the connection — so a `destination.port`-scoped `AuthorizationPolicy` DENY on a Redis/MySQL/etc. port is enforced just as it is for the materialized HTTP routes. The dual-wire one-byte TLS discriminator is therefore confined to HTTP-family inbound traffic; its residual `0x16` ambiguity is harmless for valid plaintext HTTP because no valid HTTP request starts with that control byte, while STRICT is still enforced after routing. A stream-family port that resolves to the **same** container port as an HTTP-family service port installs **no** raw-TCP entry: the HTTP inbound route wins, so the request is parsed and authorized on the HTTP path rather than spliced to loopback as raw bytes. Peer-sidecar raw-TCP traffic still arrives as a mesh-mTLS CONNECT and uses the transparent inbound relay.
- **Outbound.** The outbound listener intercepts application-originated traffic (redirected by iptables or eBPF) and, on Ambient and Sidecar topologies, routes it through per-service egress routes materialized from the slice (see "Implementation status" below for the per-topology transport); multi-port services are disambiguated by the captured connection's original destination (`SO_ORIGINAL_DST`) on those materialized topologies.

**Implementation status — transport vs. materialization, per topology.** Transport (how a peer is reached on the wire) and materialization (turning the slice into routable proxies) are separate layers, and **the transport differs by topology**: **Ambient / Waypoint** speak HBONE (HTTP/2 CONNECT over mTLS, `:15008`); **Sidecar** speaks plain SVID-mTLS HTTP (`:15006`, no `:15008` listener). HBONE is *not* Sidecar's transport.

- **Ingress is handled for both.** Sidecar inbound builds materialized HTTP-family loopback routes (`:15006` → `127.0.0.1:<appPort>`) and prepares raw-TCP local app-port relay entries for stream-family service ports. Ambient/Waypoint inbound is **transparent** — an authenticated HBONE CONNECT that matches no route is relayed directly to its `:authority` (the original destination), so no route materialization is needed. The relay is guarded: the destination must be one this terminator owns (see [Inbound Relay Destination Guard](#inbound-relay-destination-guard)). Sidecar may use loopback on a declared application port because it shares the pod network namespace; Ambient and waypoints may not, because they run outside that namespace. A peerless CONNECT is rejected (403) before any dial. This transparent-relay path is **transport-agnostic** — gated on inbound direction + the H2 CONNECT shape, not on topology — so the Sidecar `:15006` listener also relays a **bare** authenticated H2 CONNECT (the raw-TCP egress destination side) through the very same guard, alongside its materialized HTTP loopback routes. A Sidecar refuses such a CONNECT when it names a port one of those HTTP routes serves (`403`, `mesh.relay.denial_reason=http_application_port`), so HTTP traffic to that port always arrives as HTTP and runs the route's plugin chain; stream-family ports keep the relay.
- **Egress is materialized for Ambient, Sidecar, and NodeWaypoint captured Service HTTP**, per topology posture: **Ambient outbound** builds per-service HBONE routes (a host-routed `/` proxy per in-mesh Service → `mesh.hbone`-tagged upstreams dialing the destination's `:15008`); **Sidecar outbound** builds per-service SVID-mTLS routes (`mesh.mtls`-tagged upstreams dialing the destination sidecar's inbound `:15006` with plain HTTP/2 over mutual TLS — never HBONE). Those two secured-transport target types carry the destination workload's SPIFFE id (`mesh.spiffe_id`), which the outbound handshake **pins**: the peer must present exactly that SVID, not merely one from an allowed trust domain. **NodeWaypoint captured Service HTTP** materializes the same host-routed Service routes, selects the backing workload first, and, when that workload has `node_waypoint` metadata, emits a `mesh.hbone` target that dials the destination NodeWaypoint while preserving the selected workload app address as the inner CONNECT authority. If the NodeWaypoint runtime is identity-backed (file SVID material or mesh CA backend), a selected workload without `node_waypoint` metadata is skipped so the route fails closed rather than dispatching plaintext. Only explicit no-CA/no-identity development runs retain the temporary plaintext captured-Service fallback. NodeWaypoint still does not synthesize pod-IP HBONE upstreams to backing pod IPs on `:15008`, where no listener is reachable; the live harness therefore requires captured Service traffic to enforce `AuthorizationPolicy` and requires denied-source direct Pod-IP attempts to fail closed rather than bypass capture. Sidecar egress yields to the local workload's own inbound loopback route (the route table holds one proxy per host+path), so a service's own-sidecar traffic stays local. Non-convention transport ports are configured with `FERRUM_MESH_EGRESS_HBONE_PORT` / `FERRUM_MESH_EGRESS_MTLS_PORT`.
  - **Multi-port egress (original-destination routing, Ambient and Sidecar).** One route + one upstream is materialized **per HTTP-family service port** (per-port upstreams keep load-balancer counters, hash rings, passive health, and pool keys isolated per app port). The route table groups a service's per-port siblings under one lowest-port representative — host tiers are (host, path)-keyed and every sibling shares its service's hosts + `/` — and the request path swaps in the sibling whose service port matches the connection's captured pre-NAT original destination, read once per accepted connection on the outbound capture listener via `SO_ORIGINAL_DST` (Linux netfilter; covers the injector's iptables REDIRECT capture). Sibling groups are derived from the prepared config's `mesh` block (each service's expected per-port route ids and **declared** HTTP-port count), never by parsing route ids. **Fail-closed:** a service *declaring* multiple HTTP-family ports with no captured original destination (non-Linux, direct dial, eBPF-rewritten capture) — even when only some ports materialized siblings — and any captured dial to a port the slice does not route are rejected with 502; captured traffic is never forwarded to a port the client did not dial. Single-HTTP-port services keep their orig-dst-free behavior, so direct dials and dev setups are unaffected. **Ambient** multi-port is transparent end-to-end (its inbound is the HBONE relay that dials the CONNECT authority's app port). **Sidecar** multi-port egress additionally rewrites the request `:authority` to `<host>:<service port>` (the per-port target carries its owning service port; the original client Host still rides `x-forwarded-host`): the destination sidecar's `:15006` dials are direct — never NATed — so the authority port is the channel its per-port **inbound** siblings disambiguate by. Single-port destinations keep the client authority byte-for-byte. Interop is fail-closed in both skew directions: a pre-disambiguation destination materialized nothing for multi-port services (404, never misrouted), and a pre-disambiguation source materialized no multi-port egress routes. Apps behind a multi-port Sidecar service observe `Host: <fqdn>:<port>`, and destination-side VirtualService `authority` exact-matchers should account for the explicit port.
  - **Raw-TCP and UDP egress (original-destination routing, Ambient and Sidecar).** See [Raw-TCP egress](#raw-tcp-egress) and [UDP egress](#udp-egress) below.
  - **WebSocket egress (Ambient and Sidecar).** A WebSocket upgrade to an in-mesh `mesh.mtls`/`mesh.hbone`-tagged destination rides the topology's secured transport on a **fresh** mesh H2 connection. The two topologies use **different inbound primitives**, because Sidecar materializes inbound routes while Ambient/Waypoint do not:
    - **Sidecar (`mesh.mtls`)** speaks an **RFC 8441 Extended CONNECT** (`:method=CONNECT` + `:protocol=websocket`) over SVID-mTLS to the peer's `:15006`. The Extended CONNECT carries the forwardable WebSocket handshake headers (`Sec-WebSocket-Protocol`, etc.; the HTTP/1.1-only framing headers `Upgrade`/`Connection`/`Sec-WebSocket-Key`/`Sec-WebSocket-Version` and `Sec-WebSocket-Extensions` are not sent) plus the preserved client `:path`+query, and the resulting H2 stream body IS the raw WebSocket frame transport — there is no inner HTTP/1.1 upgrade handshake. The destination sidecar's `:15006` listener (`auto`, advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`) detects the Extended CONNECT WebSocket and bridges it to the local app over a plain HTTP/1.1 upgrade — the same machinery a client-originated WebSocket uses (a WebSocket Extended CONNECT carries `:protocol`, so it is never confused with the bare CONNECT byte-relay). A multi-port Sidecar destination's `:authority` is rewritten to the owning service port (`mesh.mtls_authority_port`) just like HTTP egress.
    - **Ambient / Waypoint (`mesh.hbone`)** opens a **bare HBONE CONNECT byte tunnel** (the same primitive raw-TCP egress uses) to the destination workload's app addr:port on the peer's `:15008`, then speaks the WebSocket as an **inner HTTP/1.1 upgrade THROUGH the tunnel**. Ambient/Waypoint materialize **no inbound routes**, and the transparent HBONE relay that handles a route-miss CONNECT is gated on a **bare** CONNECT (it requires the `:protocol` extension to be *absent*), so an Extended CONNECT carrying `:protocol=websocket` to `:15008` would 404 before any WebSocket handler runs. Routing the byte tunnel to the app addr:port lets the relay byte-copy the upgrade straight to the loopback app, which performs the WS handshake — **no destination-side change**. The SERVICE `:authority`+`:path` the app routes on ride the inner H1 `Host`/request-target (mirroring the HTTP HBONE relay, which forwards the client Host over the relay).
    - **Shared invariants (both):** identity is **pinned** (`mesh.spiffe_id`; mandatory for `mesh.mtls`, carried when present for `mesh.hbone`); the client's `:path`+query is preserved byte-for-byte so `ws://svc-b/ws?room=1` reaches the destination as `/ws?room=1` (not `/`). Each session uses its OWN H2 connection carrying exactly ONE CONNECT stream (1:1, dropped at session end — a proxied WebSocket is one dedicated backend connection bounded by `DestinationRule.maxConnections` via the same `BackendConnectionGuard` the direct WebSocket path holds; SVID rotation is automatic per fresh dial). **Fail-closed:** a `mesh.mtls`/`mesh.hbone` WebSocket target that cannot dispatch over its secured transport (missing gateway SVID, absent/invalid pinned peer, a Sidecar peer that never negotiated Extended CONNECT, or an Ambient relay/handshake failure) fails the upgrade — it is **never** dialed in plaintext.

  - Per-port `DestinationRule.trafficPolicy.portLevelSettings` authored on the service port are fanned out onto every distinct dial port of the owning per-port upstream, so a service whose `targetPort` differs from its `port` keeps its *per-port* DR settings — **including named `targetPort`s**, which the materializer resolves per workload (a named port may legitimately resolve to different container ports across workloads; the entry lands on each).

An outbound `404` for an un-materialized destination means no route was built for it — not that mTLS/HBONE is unavailable. Both egress datapaths are exercised end-to-end (two gateways, captured request at A → mesh transport → backend behind B) by the `functional_mesh_*_egress_*` functional tests.

#### Raw-TCP egress

Stream-family service ports (`tcp`, `tls`, and the DB protocols — anything not HTTP-family) materialize **per-port upstreams only**, no route proxies: a raw stream has no Host header to route by. Instead the accept loop on the outbound capture listener matches the captured original destination **strictly against `(service VIP, service port)`** — `MeshService.cluster_ips`, populated from `Service.spec.clusterIPs` by the Kubernetes translator (file-source operators set `cluster_ips` directly) — and relays the raw byte stream through an HTTP/2 CONNECT tunnel to the LB-selected workload's app port. The tunnel transport follows the topology (the upstream target carries exactly one transport tag): **Ambient** relays over the shared HBONE pool (dial the peer's `:15008`, capability-probe-gated); **Sidecar** relays over a **fresh mesh-mTLS H2 CONNECT tunnel** (dial the peer's `:15006`, one connection per captured stream — no capability registry, because a slice-declared sidecar peer speaks mesh-mTLS by construction). Either way the dial is identity-pinned (`mesh.spiffe_id`), and the destination's inbound relay is **transport-agnostic**: its terminator recognizes an authenticated H2 CONNECT — HBONE-marked on `:15008` or bare on `:15006` — and relays it to the CONNECT `:authority` via the same machinery, so no destination-side changes are involved. Port-number-only matching is deliberately unsupported: two services may share a port number, and a captured dial to a non-mesh destination must never be tunnelled into the mesh on a coincidence. A captured destination matching a declared pair whose upstream did not materialize is **closed** (never guessed); anything else falls through to the HTTP path unchanged. **Direct pod-IP / headless dials are also routed on these materialized topologies:** a client that resolved a **headless** service itself (or otherwise dials a backing **pod IP** directly) bypasses the VIP table, so a second strict index — keyed by `(backing workload IP, resolved target port)` — routes that captured original destination to a **single-target upstream pinned to that exact workload's identity** over the topology transport. It is consulted only when the VIP lookup misses, uses the same exact-match / fail-closed rules (a declared-but-unroutable workload pair is closed, never guessed), and is built from the same forward-derived source as the per-workload upstreams (each stream-family service port × backing local-cluster workload × workload address that parses as an IP; DNS-name addresses are skipped, and the container/target port resolves with the same `targetPort` rule as the VIP path). HTTP-family headless services already route by Host, so this closes the **raw-TCP-only** headless gap; a VIP-less service with no backing workload addresses is still unroutable (warned at materialization). Per-port `DestinationRule` LB algorithm and `localityLbSetting` apply to the TCP upstreams (VIP and per-workload alike) at selection time when all targets share a single port (the same pre-selection semantics as the HTTP path). Per-port `outlierDetection` thresholds and `maxEjectionPercent` caps are honored by stream target selection, but the consulted state differs by source: upstream-scoped active health checks apply across the shared upstream, while passive ejections are proxy-id scoped and are only consulted when recorded under the same synthesized raw-relay proxy id. Passive ejections recorded by a separate HTTP-family proxy on the same upstream do not automatically protect these raw relays. Outlier thresholds are still not recorded for the raw relay itself, since raw relay sessions carry no response status — see the note in the "DestinationRule" section.

**Cross-cluster L4 extension.** The identity-pinned statement above describes same-cluster targets. Cross-cluster raw-TCP and UDP targets deliberately remove the pod pin because the SNI gateway chooses the outer-hop terminator; they require the remote trust domain, per-port SNI, gateway dial endpoint, and real-pod CONNECT authority instead. Missing metadata fails closed.

#### UDP egress

**UDP is modeled as a distinct L4 transport** (`AppProtocol::Udp`): a `protocol: UDP` port — on a Kubernetes Service **or** an Istio `ServiceEntry` — partitions out of both HTTP-family routing and the raw-TCP stream lane. The L4 `protocol: UDP` field **wins over any L7 `appProtocol`/port-name hint** (e.g. `appProtocol: http` or a name like `http3` on a UDP port still classifies as UDP — the hint describes what rides over the transport, not the transport itself). UDP egress does **not** ride this raw-TCP datapath (`SO_ORIGINAL_DST` REDIRECT does not apply to UDP); UDP uses a separate **TPROXY** capture model (see "UDP TPROXY capture" under Capture Modes) with its own capture rules, consuming listener, and datagram-over-mesh egress (dual-transport, mirroring raw-TCP egress). UDP egress materializes **per-port upstreams** (distinct `__mesh-out-upstream-*` id space → `__mesh-out-udp-upstream-*`) consulted via the route table's `mesh_udp_egress` `(VIP, UDP port)` index; a captured datagram is tunnelled over a `udp`-marked mesh CONNECT — **Ambient over HBONE (`:15008`), Sidecar over mesh-mTLS (`:15006`)** — and the destination unframes it into a local `UdpSocket` (see "UDP TPROXY capture"). Each direction coalesces datagrams that are **already** queued or readable into one bounded tunnel write (≤16 KiB, ≤1024 datagrams, FIFO, never waiting for a batch to fill) so a burst rides one h2 DATA frame instead of one per datagram; besides the per-frame savings this keeps small-datagram bursts under h2's per-connection small-DATA-frame budget (`ENHANCE_YOUR_CALM`), which would otherwise close the shared HBONE connection. Still **no route proxy** (datagrams carry no Host). Both topologies have a UDP source-capture producer: **Sidecar** via the injector's pod-netns TPROXY init rules feeding the current-netns listener, and **Ambient** via the per-pod-netns producer (`NetnsUdpCaptureManager`, #2013) that installs the UDP TPROXY rules + binds the transparent sockets INSIDE each enrolled pod's netns (the Ambient proxy runs outside the pod netns and the host-netns fallback emits no UDP rules). Ambient UDP capture stamps node-agent-attested pod UID + SPIFFE evidence inside the authenticated HBONE CONNECT; destination `mesh_authz` applies per-pod **source** scope only after the shared trusted-assertor/trust-domain gate and an exact live UID-to-SPIFFE match, otherwise it falls back to mesh-wide source scoping. Either way the `udp` CONNECT is evaluated against the **union** of the destination-scoped `AuthorizationPolicy` set that normal (non-UDP) inbound HBONE uses — the same namespace/selector policies protecting the destination workload, e.g. a DENY-all in the service namespace — **and** the source-scoped (or mesh-wide) policies, in a single deny-first evaluation, so a destination DENY/ALLOW still runs for UDP CONNECTs and cannot fall through to default-allow.

**Source-side producer for external UDP.** The gateway half ([External UDP egress](#external-udp-egress-egressgateway) under the Egress Gateway topology) is a terminator; the originator is the `Sidecar`/`Ambient` data plane, the two topologies that have a UDP source-capture producer. Source-side route materialization shares the **same** `FERRUM_MESH_EGRESS_STREAM_ENABLED` all-or-nothing opt-in as the gateway allowlist: with the flag off the source clears any prior routes and publishes nothing, so a flag-off gateway cannot be paired with still-materialized source routes that would black-hole captured datagrams. When that flag is on and `FERRUM_MESH_EGRESS_GATEWAY_ADDR` + `FERRUM_MESH_EGRESS_GATEWAY_SPIFFE_ID` are set, those sources materialize a captured-datagram route per `MESH_EXTERNAL` `ServiceEntry` UDP endpoint (`MeshConfig.external_udp_egress_routes`, upstream id space `__mesh-out-udp-ext-upstream-*`) whose single upstream target dials **that configured gateway** over SVID-mTLS, pinned to the declared gateway SPIFFE id, with the external endpoint as the CONNECT `:authority`. The route/upstream set shares `MAX_EGRESS_UDP_DESTINATIONS` with the gateway allowlist as a hard total cap, so an accepted slice cannot grow either side without bound; excess endpoint routes remain unroutable. The route folds into the SAME `mesh_udp_egress` `(destination IP, port)` index the in-mesh datapath uses, so the existing `mesh_udp_capture` session task relays it with no external special case (in-mesh service VIPs are inserted first and always win). The EgressGateway exposes only its `:15090` SVID-mTLS listener — there is no `:15008` HBONE listener on it — so both source topologies use the mesh-mTLS datagram tunnel (`MeshMtlsConnectionPool::open_datagram_tunnel`), which requires the pinned peer and runs no capability probe. Fail closed at every step, with field-specific diagnostics and never a direct unauthenticated dial of the external destination: stream-egress opt-in off ⇒ no route; no configured gateway address/identity ⇒ no route; a gateway whose SVID does not match the pinned id ⇒ refused dial; `resolution` other than `STATIC` ⇒ refused (a UDP datagram carries no Host, so only a declared endpoint address can attribute a captured datagram — the mesh DNS proxy answers external hosts with exactly those endpoint IPs); no usable IP-literal endpoint ⇒ refused; a topology with no UDP source-capture producer ⇒ nothing materialized. The producer applies the SAME per-entry admission tests the gateway half does — `location: MESH_EXTERNAL`, `exportTo` visibility for this workload's namespace, and a non-empty `hosts[]` — because an entry the gateway refuses outright can never admit the source's CONNECT, so a route for it would only ever black-hole. The route set is rebuilt and reassigned on every apply, so update/delete/flag-off withdraws steering immediately. Setting only one of the two gateway variables is a startup error rather than a silent half-configuration. `FERRUM_MESH_EGRESS_GATEWAY_ADDR` must be a bounded DNS hostname, IPv4 literal, or bracketed IPv6 literal plus a nonzero port — surrounding whitespace/control characters, wildcards, and URL/userinfo/path/query/fragment material are refused at startup without echoing the raw value; SPIFFE parse failures name the variable only and never echo the configured identity.

#### Proxy hop limit on mesh hops

Every mesh data plane runs the gateway's [proxy hop limit](routing.md#proxy-hop-limit) (`FERRUM_MAX_PROXY_HOPS`, default `10`, carried in the gateway-owned `X-Ferrum-Hops` request header):

- **Outbound hops increment.** A request captured on the outbound listener (`:15001`) is checked and forwarded with `received + 1`.
- **Inbound hops to the local workload check but do not increment.** A request on the Sidecar inbound listener (`:15006`) that is forwarded to the local application through a materialized inbound route (service-port defaults or `ingress[]` listeners) is refused at the limit, but it is forwarded with the received count unchanged. A service call therefore costs one hop, not two, when the application propagates the header to its own outbound calls. The bound still holds: anything the application sends onward leaves through the outbound hop, which increments. The exemption covers only the request forwarded to the local workload: plugin calls made on that same inbound hop, such as `mesh_authz` `CUSTOM` (ext_authz) checks and `request_mirror` shadows, are ordinary gateway hops and carry `received + 1` (see [Plugin HTTP calls and the proxy hop limit](plugins.md#plugin-http-calls-and-the-proxy-hop-limit)).
- **A target on a gateway listener always counts.** The exemption applies only when the route's loopback target is not a port this data plane listens on: the mesh listeners, Gateway and stream listeners, dedicated `ingress[]` binds, and the admin listeners. The runtime republishes that port set on every accepted slice apply, and an inbound hop increments until the first set is published. Preparation also refuses a Sidecar `ingress[]` `defaultEndpoint` or an inbound `targetPort` that names one of those ports, with a warning and for the whole entry, like a dedicated-bind conflict: two `ingress[]` binds whose `defaultEndpoint`s point at each other are both dropped.
- **Every other inbound route increments.** A plugin route override, an EgressGateway external route, an operator route, or a loopback target on any gateway listener port is forwarded with `received + 1`. Ambient and waypoint inbound HBONE relays are L4 tunnels and forward no request headers.
- A looping request is refused with `508 Loop Detected` (native gRPC: `FAILED_PRECONDITION`) at whichever hop first receives a count at the limit. The refusal is a frontend admission fence: it produces no transaction summary and no `ferrum_requests_total` row, and the refusing hop logs a rate-limited warning. Earlier Ferrum hops relay the `508` with `X-Gateway-Error: backend_error`, and none of them retries it.

### Ambient

Ztunnel-style ambient mesh proxy that terminates HBONE (HTTP/2 CONNECT over mTLS) traffic. Does not require a per-pod sidecar.

| Listener | Address | Direction | Kind |
|---|---|---|---|
| Outbound capture | `127.0.0.1:15001` | Outbound | Plaintext capture |
| HBONE | `0.0.0.0:15008` | Inbound | HBONE termination |

The HBONE listener accepts HTTP/2 CONNECT streams over mTLS on port 15008. Source identity is extracted from the mTLS peer certificate and optionally from W3C Baggage headers. See [HBONE Protocol](#hbone-protocol) below.

### Node Waypoint

Node-scoped sidecarless waypoint for pods captured by the node agent. This topology uses the same HBONE listener as ambient mode, but source pod identity is resolved from the node-agent/eBPF socket-cookie record instead of assuming one proxy per workload.
The production secured-transport target and fail-closed decisions are tracked in
[`docs/plans/node_waypoint_transport_adr.md`](plans/node_waypoint_transport_adr.md);
the current implementation remains Experimental until that ADR's SPIFFE-mTLS,
destination-policy, IPv6, and direct-inbound gates pass.

| Listener | Address | Direction | Kind |
|---|---|---|---|
| HBONE | `0.0.0.0:15008` | Inbound | HBONE termination |

At accept time the proxy reads the Linux `SO_COOKIE` value and looks up the corresponding `FERRUM_ORIG_DST4` / `FERRUM_ORIG_DST6` capture record in the `NodeWaypointIdentityResolver`. The record carries the original destination, pod UID, and a stable hash of the workload SPIFFE ID. Those records are populated by the **orig-dst bridge** (`src/ebpf/orig_dst_bridge.rs`): the bridge opens the node-agent-pinned `FERRUM_ORIG_DST4/6` maps by path and mirrors each socket-cookie record into the resolver via `record_orig_dst4`/`record_orig_dst6`. **Accept-side bridge (GAP-2M, IPv4 + IPv6):** these records are keyed by the *source pod's connect-side* socket cookie, but at accept time the proxy resolves by the *accepted server-side* socket's `SO_COOKIE` — a different kernel socket with a different cookie (see the invariant in `src/socket_opts.rs`). The kernel `sock_ops` program bridges them: at active-established it re-keys the orig-dst record by `(netns cookie, connection tuple)` (`FERRUM_ORIG_DST_BY_TUPLE4` / `FERRUM_ORIG_DST_BY_TUPLE6`), and at passive-established it re-stamps that record under the accept-side cookie, so the resolver's cookie map is reachable from the accept path with no further proxy-side change. **IPv4 and IPv6** — the v6 `sock_ops` ctx address words (`local_ip6`/`remote_ip6`) are read element-by-element with verifier-safe volatile per-`u32` loads at explicit offsets (the same per-element technique `connect6` uses for the `bpf_sock_addr` v6 fields; a whole-`[u32;4]` ctx copy trips the verifier), so IPv6 (and the IPv6 half of dual-stack) node-waypoint accepts resolve too. The in-netns outbound capture manager binds both pod-loopback families, so the same resolver path is live-gated for IPv4 and IPv6. Pod-identity enrollment is wired into the same path with no separate channel: slice apply installs a `workload_spiffe_hash`→SPIFFE index that `resolve_record` hash-joins against the eBPF-stamped `(pod_uid, hash)` to lazily enroll identities (re-validated against the current slice on every resolve). That index and the per-pod scopes are seeded at startup and on every accepted reload from the slice's ordinary `workloads` **plus** its dedicated `node_waypoint_capture_destinations` inventory, so an enrolled source pod in a namespace other than the NodeWaypoint's subscription namespace resolves with its own identity and scope instead of failing as an unknown pod; the inventory never widens routing visibility, and a pod the CP did not authorize or that is enrolled on another NodeWaypoint stays unknown. A capture-inventory source is vouched only by its exact pod UID (with a matching stamped hash), never by the SPIFFE-hash join, so withdrawing one of several pods that share a service account revokes exactly that pod. A pod UID carried by disagreeing records never resolves. The HTTP admit path re-checks on every request that the current slice still vouches the connection's identity and refuses the request with `403` once it does not, so a pod withdrawn mid-connection is not served with a missing scope (each refusal counts as an `unknown_pod` drop in `/overload.node_waypoint_drops` and emits a rate-limited warning). Two consequences follow, both deliberate. First, a resolved cross-namespace source is scoped exactly like a same-namespace enrolled pod: on its source-attributed legs, the per-pod filter applies the policies that select it, including those that reach the NodeWaypoint only through the capture inventory's AuthorizationPolicy entries. Second, NodeWaypoint UDP/DTLS source attribution (issue #3286) is unchanged: its registry-principal proof never vouches a capture-only cross-namespace source, so such a pod's datagrams stay unattributed exactly as before. Otherwise a later withdrawal or conflict would turn an attributed, scoped UDP session into an unattributed one admitted under mesh-wide-only policy. On raw TCP the same transition is closed at accept. A stream whose eBPF capture record was found but whose identity the live slice does not vouch is refused, exactly as the HBONE/HTTP listener refuses it, and counted in `/overload.node_waypoint_drops`. This covers a pod that is withdrawn, conflicted, unauthorized, or not yet enrolled. Only traffic with no capture record keeps the mesh-wide-only fallback. If two different SPIFFE IDs collide on the 64-bit truncated hash, the gate marks that hash unusable and both hash-join enrollment and cached revalidation through the gate fail closed instead of choosing one identity arbitrarily. A capture-inventory source is unaffected because it resolves by its exact eBPF-stamped pod UID, which the truncated hash cannot confuse. The `node-waypoint-ebpf-live` workflow validates this path for IPv4 and IPv6 on a live multi-pod datapath. The eBPF `connect4`/`connect6` hooks stamp each record's pod UID and SPIFFE hash from the per-cgroup `FERRUM_WORKLOAD_IDENTITY` map the node-agent writes at enrollment (see [docs/node_agent.md](node_agent.md#ebpf-build-and-capture-how-to-build-the-capture-image)). Unknown cookies, zero pod UIDs, missing workload hashes, missing pod identities, collided SPIFFE hashes, and SPIFFE-hash mismatches fail closed before TLS/HBONE processing. `/overload.node_waypoint_drops` reports per-reason counters for these fail-closed drops. On a build without `--features ebpf` the bridge logs once and exits and the resolver stays empty, so every node-waypoint accept fails closed.

**In-pod-netns outbound capture listeners.** The eBPF `connect4` and `connect6` hooks rewrite captured pod outbound TCP `SOCK_STREAM` connections to `127.0.0.1:15001` and `[::1]:15001` — but those are the **pod's** loopback addresses. Host/proxy network-namespace listeners can never receive those connections, so a host-only listener would leave node-waypoint outbound capture non-functional on a real multi-pod node: rewritten connections would be refused and scoped enforcement never engage. (The GAP-2M `sock_ops` cookie bridge also independently requires the accept socket to share the connecting pod's netns.) So in NodeWaypoint topology the mesh proxy opens dual-family listeners — bound to pod loopback (`127.0.0.1` and `[::1]`) on the port from `FERRUM_MESH_OUTBOUND_LISTEN_ADDR` (default port `15001`); if that port is `0`, capture is disabled and the manager does not start — **inside each enrolled pod's network namespace** (via `setns(CLONE_NEWNET)` on a dedicated thread; one listener per address family per pod netns, deduped by netns inode), so captured pod-loopback connections are accepted in the right namespace and the same-netns cookie bridge resolves the source pod identity. Pod discovery comes from a registry directory the node-agent publishes: `FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR` (default `/run/ferrum/node-waypoint-pods`) holds one file per enrolled pod (file name = pod UID, contents = line 1 pod cgroup path plus optional `ipv4=<pod-ip>` / `ipv6=<pod-ip>` lines from Kubernetes `status.podIPs`), written on enrollment and removed on teardown; the proxy's `NetnsCaptureManager` polls this directory, uses each family-specific pod IP as the matching listener's dynamic source override, and reconciles listeners (opening on add, closing on removal). Helm mounts this path as the same writable hostPath in the node-agent and ambient DaemonSets whenever `nodeAgent.proxyMode=node_waypoint`; a split container-local registry can make both pods Ready while no workload listener is attached. **Fail-closed listener startup:** because pod discovery and in-netns listener binds are asynchronous, a freshly enrolled pod can briefly have `connect4` or `connect6` rewriting to a pod-loopback port before the matching proxy listener exists. The node-agent still attaches both connect programs during enrollment, before marking the pod enrolled, so egress cannot bypass `mesh_authz`; early captured connects may be refused until the listener opens, but they fail closed. NodeWaypoint adds `::/0` to the capture include set so IPv6 destinations reach `connect6`; the legacy `ipv6_outbound_deny` capture-config flag stays clear for the normal dual-family path. The proxy writes `<registry_dir>/.ready4/<pod_uid>` for IPv4 readiness and `<registry_dir>/.ready6/<pod_uid>` for IPv6 readiness; the dotdirs are ignored by the pod-discovery scan. The inbound `getpeername4`/`getpeername6` programs do not redirect and are still attached at enrollment. This path is Linux-only (`setns`, `/proc/<pid>/ns/net`); on non-Linux it compiles to an unsupported stub. The reconcile/registry logic is unit-tested, and the `node-waypoint-ebpf-live` workflow gates the live `setns`/bind path and full pod-loopback IPv4/IPv6 datapaths on a disposable multi-pod kind cluster.

Operators inspect the currently enrolled pod identities via the JWT-authenticated admin endpoint `GET /node-waypoint/identities` — see [docs/admin_api.md](admin_api.md#node-waypoint-identities-mesh-nodewaypoint-topology) for the response shape. The endpoint returns 404 outside `NodeWaypoint` topology so unrelated DPs don't surface an empty stub list.

Per-pod authorization scope is published only after a mesh slice is accepted by the proxy config apply path. Slice apply installs one `NodeWaypointSlice` generation — the `workload_spiffe_hash`→SPIFFE identity gate plus the per-pod-UID scope index (`scopes_by_pod_uid`, a `PolicyScopeCache` per workload `metadata.uid`) — via a single `ArcSwap` store, so a lock-free reader never sees a new gate paired with an old or missing scope. A pod's scope is keyed **strictly** by the exact pod UID the eBPF capture stamps; a captured pod is **never** resolved through a SPIFFE-keyed index, so pods that share a service account — and therefore one SPIFFE — but carry different labels are scoped independently (each against its own labels) instead of collapsed to the label intersection, and a pod whose workload is absent from the live slice **fails closed** (no scope) rather than borrowing a same-SPIFFE workload's labels. Scope is reclaimed by slice updates, not by identity lifecycle. `resolve_*` returns the identity and its scope from a single load. Because the snapshot is stored only after `proxy_state.update_config` accepts the slice, a rejected slice never publishes scopes.

**TCP stream scoping**: raw **TCP** stream connections through a node-waypoint proxy follow the same per-pod scoping wiring as HTTP/HBONE. The TCP stream accept loop resolves each accepted connection's `SO_COOKIE` through the shared `NodeWaypointIdentityResolver`, looks up that pod's `PolicyScopeCache`, and stamps it onto the connection context so namespace-scoped and selector-scoped `AuthorizationPolicy` DENY/ALLOW rules are enforced for the correct source pod. The **same GAP-2M bridge described above for HBONE applies here**, for **IPv4 and IPv6**: same bridge as above, so the resolver (populated by the `orig-dst` bridge) is reachable from the accept path for both families. Unit/integration coverage validates policy-scoped TCP traffic; the `node-waypoint-ebpf-live` workflow collects live BPF evidence for IPv4 and IPv6 capture, verifies HTTP Service `AuthorizationPolicy` enforcement, and confirms denied-source direct Pod-IP attempts fail closed. On any tuple/byte-order mismatch no accept-side record is written and the stream resolves `None` (fail-closed, never misattributed). When the scope cannot be resolved (a GAP-2M tuple miss, no node-agent enrollment yet, non-Linux, unknown cookie, slice/identity race), `mesh_authz` falls back to its missing-scope behavior: with namespace- or selector-scoped policies configured it **fails closed** and rejects the stream (403); with only mesh-wide policies it evaluates mesh-wide normally. Either way, the transaction records `mesh_authz.scope_missing=true`.

**UDP/DTLS per-pod scoping** (issue #3286): UDP and DTLS stream sessions through a node-waypoint proxy ARE scoped per source pod. The socket-cookie channel TCP uses is unavailable — node-waypoint TCP identity is keyed by the per-connection socket cookie the eBPF `connect4`/`connect6` cgroup hooks stamp, those hooks leave UDP `connect()` unrewritten because the outbound capture listener is TCP-only, there are no UDP capture hooks, and a UDP stream proxy demultiplexes every client off one shared frontend socket carrying a single cookie — so UDP/DTLS resolves its source through a separate attribution index instead.

*How a datagram gets an identity.* The NodeWaypoint proxy is `hostNetwork: true`, so a local pod's egress is the only traffic that enters the host namespace on THAT pod's host-side interface (traffic destined *for* a pod arrives on the node uplink and is forwarded out; the node's own traffic is locally generated). `src/proxy/node_waypoint_udp_identity.rs` polls the node-agent-published enrolled-pod registry, resolves each pod's host-side veth (the same resolution the Ambient host-network capture path uses, via `plan_host_udp_bindings`, so the two cannot disagree), and publishes one lock-free generation mapping interface index → `(pod UID, attested SPIFFE ID, permitted source addresses)`. Every datagram is then admitted from two independent KERNEL facts — the ingress interface index from `IP_PKTINFO`/`IPV6_PKTINFO`, and its source address, which must be one that interface's pod is registered to use. Neither comes from the payload or from operator input, so a workload cannot assert a neighbour's identity: forging a source address does not change which interface a packet entered on. Plain UDP listeners force `IP_PKTINFO` on for a scoped listener (so `FERRUM_UDP_PKTINFO_ENABLED=false` cannot silently disable attribution); the DTLS demuxer captures the ingress interface of each peer's ClientHello and drops a later datagram that claims an established peer address but arrives on a different interface.

*What is refused, and it is always fail-closed.* An interface claimed by more than one enrolled pod (a shared-bridge CNI, or a stale registry entry pointing at a recycled veth) refuses BOTH claimants rather than guessing; so do a registry entry with no attested identity, no published pod address, an unresolvable or non-dedicated interface, a datagram with no ingress interface cmsg, an ingress interface belonging to no enrolled pod (including all off-node traffic), a source address the interface's pod does not own, and a pod whose workload has left the live mesh slice. Each of those leaves the session's per-pod scope absent, and `mesh_authz` rejects the session whenever any namespace/selector-scoped `AuthorizationPolicy` exists — there is no plaintext lane and no mesh-wide fallback while scoped enforcement applies. Refusal reasons are a closed `&'static str` set, so no registry- or peer-supplied value ever reaches a log field or metric label, and the warn is rate-limited per reason with a suppressed count.

*Churn, reuse, and reload.* The scope is resolved from the SAME live-slice read that vouches the pod, so a workload removed from the slice fails closed instead of borrowing a stale scope. An admitted session pins the exact binding that authorized its first datagram, and every later datagram is re-authorized against the CURRENT published generation and must still resolve to an attribution-identical binding. A veth index recycled onto another pod, a pod restarted under a new UID at the same address, or a registry removal therefore terminates the session rather than letting it keep relaying under evidence no longer vouched for; an unchanged republish compares equal and disturbs nothing. Interface ownership itself comes from the host route to the registry-published pod IP, which the kubelet and CNI assign and the pod cannot choose. When an address is reused, a stale registry entry and the new pod resolve the same host route and both are refused until registry cleanup; a stale entry for an address now held by a non-enrolled pod can attribute that pod's interface until the entry is collected. Ending the session is reserved for the session's OWN evidence changing: a UDP session is keyed by a source address and port that anything able to put a packet on the wire can forge, so a datagram that names an established session but entered the host namespace on a different interface is refused on its own — dropped, never forwarded — while the session continues under its still-vouched-for binding. Published bindings are bounded by `MAX_HOST_UDP_CAPTURE_INTERFACES`, with overflow refused rather than truncated. Every source-index manager-future exit—including orderly shutdown, task abort, and panic—clears the index and explicitly calls `NodeWaypointUdpSteering::shutdown`; `StreamListenerManager` retains another `Arc`, so object `Drop` alone cannot retract rules and reply-source authorization.

*The listener that carries it.* A NodeWaypoint materializes UDP/DTLS **service listeners** from the mesh service inventory when `FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED=true` (`materialize_node_waypoint_udp_listeners`). Each in-mesh `MeshService` port whose protocol is `udp` or `dtls` becomes a datagram listener in the host network namespace, with an upstream whose targets are only the service's backing pods owned by this exact Kubernetes node at their resolved `targetPort` (the same fail-closed named-`targetPort` rule the east-west materializer uses). This same-node boundary is mandatory: the backend socket's authorization mark is node-local metadata and cannot cross nodes, so selecting another node's pod would be dropped by that node's pod-veth guard. `udp` relays opaque datagrams; `dtls` terminates frontend DTLS on the listener and forwards plaintext datagrams to the backend — the same L4 transport, so every UDP-family predicate treats the two identically and only the listener's frontend posture differs. Materialization is DP-side, in the same `prepare_normalized_gateway_config_for_mesh` pass as the east-west and egress-gateway stream listeners, so it needs neither a `stream_match` (which `Proxy::validate` rejects on `udp`/`dtls`) nor a CP-side carrier. It is default-OFF because a NodeWaypoint is `hostNetwork: true`: turning it on claims node-wide port numbers for every UDP service in the slice. Enabling it also requires `FERRUM_K8S_NODE_NAME`; the chart injects the exact `spec.nodeName` value, and a missing or empty value aborts serving startup rather than widening the target set. Refusals are fail-closed and field-specific — a port already claimed by a mesh runtime listener or another stream proxy, incompatible same-port frontend postures (mixed `udp`/`dtls` or multiple `dtls` claimants), an ambiguous duplicate `(ClusterIP, port)` owner, a service port with no reachable same-node endpoint, and port `0`. Compatible plain-`udp` Services with distinct ClusterIPs share one listener and are demultiplexed by exact destination as described below. A listener that cannot BIND (a `dtls` port with no usable frontend DTLS material, or a scoped listener whose socket cannot enable the ingress cmsg for a family it serves) is recorded as a `StreamBindFailure` in stream-listener health; it is never started as a black hole. An unparseable value for the switch aborts mesh startup rather than silently serving no listeners.

*Several Services on one UDP port (issue #3861).* A `hostNetwork` NodeWaypoint can bind a given UDP port exactly once on the node, but two Kubernetes Services declaring the same UDP port is routine and valid — separate DNS, syslog, telemetry, game or custom-protocol Services in different namespaces. Ferrum therefore binds ONE shared datagram listener per compatible port and demultiplexes each received datagram by the authoritative local destination address the kernel reports (`IP_PKTINFO` / `IPV6_PKTINFO`), which survives because the Service-path steering rules rewrite nothing.

The selected route is chosen **before** pending-session lookup, established-session lookup, `on_stream_connect`, `on_udp_datagram`, backend selection, DTLS session allocation, and any accounting; it exclusively owns that datagram's upstream/endpoint set, policy scope, plugin decisions, rate-limit / access-log context, per-Service readiness, and transparent reply source. There is no fallback: a datagram whose local destination is missing or is not an exact route on this listener is dropped before a session slot, pending gate, or backend socket exists (`src/proxy/node_waypoint_udp_destination.rs`). Session identity is `(client tuple, selected destination IP, exact namespaced route owner, listener spawn generation)`. The owner is the route's `NamespacedResourceId`, stored as an `Arc` on the immutable table and cloned into the key (no per-datagram String build); hash and equality compare that `(namespace, id)`, not the `Arc` pointer or a digest. The same `(client, local destination, listener generation)` under owner A versus owner B is distinct, so a destination that changes ownership cannot reuse A's session, pending setup, or last-client cache, while adding or removing an unrelated route does not change A's owner key. The admission-time route is not a lifetime capability: before every late client forward and backend reply, including the final batched-send boundary, the session revalidates that the current complete table still assigns its destination to the exact same namespaced owner. Removal or reownership retires the old session before another datagram is emitted; an equivalent republication of that owner remains valid. Ordinary listeners keep a single `None` owner lane. One client socket may therefore address ClusterIP A and ClusterIP B on the same port concurrently without any collision or state reuse. Routes are keyed by a canonicalized address (an IPv4-mapped IPv6 local destination folds onto its IPv4 form, so a dual-stack `[::]` bind and a dedicated v4 bind agree), and route tables are immutable snapshots published behind an `ArcSwap`: adding a same-port Service republishes a complete table under the running socket rather than rebinding it, so adding B never withdraws A and removing A never interrupts B.

Fail-closed admission, all with field-specific, capped, readiness-visible diagnostics (Service ids are capped in the log line and never become metric labels):

| Shape | Outcome |
| --- | --- |
| Two or more compatible plain-`udp` Services with distinct ClusterIPs | **All serve** through one shared listener, demultiplexed by exact destination |
| Two Services publishing the SAME exact `(ClusterIP, port)` | **Both refused** (`duplicate_destination_claim`); unrelated claimants on the port keep serving |
| A port mixing `udp` and `dtls` claimants | **Every claimant refused** (`mixed_frontend_posture`) — one bound socket speaks one protocol, chosen before a destination can select a route, so there is no order-independent winner |
| Two or more `dtls` claimants on one port | **Every claimant refused** (`multiple_dtls_claimants`) — a `DtlsServer` owns its socket and carries exactly one frontend identity + client verifier, chosen before any handshake state exists |
| A headless (ClusterIP-less) Service sharing a port | **Refused** (`headless_service_on_shared_port`); the VIP-bearing claimants on that port keep serving |
| A headless Service alone on its port | **Serves**, over the direct-node-address boundary below (no steerable destination exists, so the port must have a single claimant) |
| Unspecified / loopback / multicast / broadcast ClusterIP | Never admissible as an exact destination |

A port that has never been shared keeps its own individual listener with no destination table, which is what preserves the direct-node-address lane documented below. A port already bound as a shared `__nwudp_{port}` listener stays on that socket when membership shrinks to one remaining VIP claimant: the destination table is republished in place so retracting Service A cannot unbind Service B. Direct-node-address on that previously-shared port remains unavailable until the shared listener itself is gone. Terminating DTLS is therefore one Service per port; a pre-protocol destination dispatcher that would let plain UDP and DTLS share one bound socket is a documented residual, not a supported configuration.

*How ordinary Service traffic reaches the listener (issue #3286 Service path).* Materializing a listener does not by itself make it reachable, and the gap is not a mere bypass. Trace what a workload actually does: it resolves `svc.ns.svc.cluster.local` to a ClusterIP and sends there; `cgroup/connect4`/`connect6` deliberately skip `SOCK_DGRAM` (the outbound capture listener is TCP-only), so the destination stays the ClusterIP; tc ingress on the source veth sees a destination that is no enrolled pod IP and passes it on; kube-proxy's `nat PREROUTING` DNATs the ClusterIP to a backing pod; and the pod-veth guard then DROPS that unmarked, non-DNS datagram. So without steering the Service path is a **black hole**, and only a direct dial to a node address ever reached the listener.

Ferrum closes that with transparent steering installed by the serving generation after its UDP/DTLS listeners actually bind (`src/proxy/node_waypoint_udp_steering.rs`, rules rendered by `crate::capture::node_waypoint_udp_steer_setup_script`). Mesh config preparation may derive the desired `(ClusterIP, port)` set and carry it as candidate metadata; it does **not** publish the live datapath. `StreamListenerManager` publishes a destination only while the corresponding listener is bound on the accepted serving generation, and retracts it before that listener stops, on bind failure, deferred DTLS, task failure, topology/feature disable, and shutdown. On each enrolled pod's host-side interface, datagrams to a materialized Service `(ClusterIP, port)` are exempted from conntrack in `raw PREROUTING` (so `nat` is never consulted and kube-proxy cannot DNAT them out from under the waypoint, whatever backend mode it runs), marked in `mangle PREROUTING`, and routed by a Ferrum-owned `ip rule fwmark 0x736 lookup 33136` + `ip route add local … dev lo table 33136` to LOCAL delivery. **Nothing is rewritten**, which is what makes the evidence survive: the source address is still the pod's, the ingress interface is still the pod's veth, and `IP_PKTINFO`/`IPV6_PKTINFO` reports the ClusterIP as the local address (`fib_compute_spec_dst` returns `iph->daddr` for an `RTCF_LOCAL` route), so the existing attribution and reply-source pinning apply unchanged. The listener socket is additionally made transparent (`IP_TRANSPARENT`/`IPV6_TRANSPARENT`), without which the kernel refuses a reply sourced from a ClusterIP that is not configured on the host; a scoped listener that cannot become transparent fails to start. Rules are scoped `-d <ClusterIP> --dport <port>` and never by port alone, so a workload's traffic to an unrelated host that happens to share a port number is not steered; `-i <pod veth>` is the direction discriminator, and because the waypoint's own relay dials and replies are locally generated they traverse `OUTPUT`, which is never hooked, so recursion is structurally impossible. Fail-closed throughout: destinations are published only for the listener that actually won its port after every refusal **and** actually bound on the accepted generation, either half of the pair being empty or a failed apply triggers strict exact-name teardown, a teardown error leaves predecessor state explicitly unproven and retries the whole plan on the next reconcile, and losing proven steering loses the service rather than opening an unauthorized lane. It requires `iptables`/`ip` in the NodeWaypoint image (the `-ebpf-tools` image; Helm promotes the ambient proxy to that variant when `FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED` is true, while TCP-only NodeWaypoint and the node-agent stay on distroless `-ebpf`), needs `MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS` (128) or fewer destinations, and a service with no ClusterIP (headless) has no address to steer — steering rules stay absent, but a bound NodeWaypoint UDP/DTLS listener still publishes an ACTIVE generation so the relay-cgroup sender proof stays live for the direct-node lane.

*DTLS on the steered Service path.* `dtls` listeners are steered exactly like `udp` ones, because a `DtlsServer` pins each peer's captured local destination and sources every encrypted record from it. `DtlsSessionState::reply_local` holds the WHOLE `PktinfoLocal` of the datagram that opened the peer entry — on the steered path that address is the Service ClusterIP, since steering rewrites nothing — and every server-side send goes through one helper (`send_dtls_record`): the initial handshake flight, the ordinary output drain (handshake continuation, retransmits, and encrypted application replies), and the final shutdown flush. Sends are nonblocking (`try_io(WRITABLE, …)` around `socket_opts::send_with_pktinfo`, parking the SESSION's driver task on `writable()` when the send buffer is full), so the shared demux loop is never blocked; the demux itself performs no sends. The server's socket carries `IP_TRANSPARENT`/`IPV6_TRANSPARENT` (`DtlsServerLimits::transparent_reply_source`), applied before the server object exists alongside `SO_MARK` and the ingress cmsg, or the kernel would refuse a ClusterIP source. Pinning is also an admission rule: on a scoped listener a datagram carrying NO capture is dropped before any session state is allocated or delivered, and a datagram whose capture differs from the pinned one — different ingress interface (a different source workload) or different local destination (a different Service flow) — is dropped rather than folded into the session (`dtls_scoped_capture_admits`). The pinned source is used only when its family matches the peer's; a scoped session whose pinned source and peer disagree (a dual-stack `[::]` bind serving an IPv4-mapped client — not a claimed configuration, since stream listeners bind `FERRUM_PROXY_BIND_ADDRESS`, `0.0.0.0` by default) fails the send closed rather than falling back to a route-selected source the client would discard. Session generation/removal safety, bounded channels, handshake admission, frontend mTLS, source-workload attribution, and exactly-once accounting are the same as on any other DTLS listener.

**Residuals on the Service path.** (1) The required `node-waypoint-ebpf-live` gate proves the plain-UDP Service path (`node_waypoint.udp.service_path_allow_attributed_source`: an enrolled `src-a` pod sends to the `udp-echo` ClusterIP, the backend logs the datagram, and the echo returns — which is only possible if the datagram was steered with its original destination and the reply came back sourced from the ClusterIP), same-port plain-UDP Service demultiplexing (`node_waypoint.udp.same_port_demux_*`: two compatible Services with distinct ClusterIPs on one numeric port, isolation, one client tuple addressing both, and retracting A while B continues), the DTLS Service path (`node_waypoint.dtls.service_path_allow_attributed_source` completes a real handshake against the `dtls-echo` Service DNS name / ClusterIP and echoes under the attributed source, while `node_waypoint.dtls.service_path_deny_scoped_policy` and `node_waypoint.dtls.service_path_deny_unattributed_source` prove the denied and unattributed cases with the backend confirming it saw nothing), and NodeWaypoint DTLS owner-scoped PeerAuthentication reload (`node_waypoint.dtls.reload_*`: generated `dtls-echo` moves PERMISSIVE → STRICT with a real current-CA handshake plus backend delivery, and stale-CA / unauthenticated clients are rejected with no unauthorized backend delivery) plus ordinary-slot isolation (`node_waypoint.dtls.operator_isolated_across_reload`: authenticated `/overload` `frontend_dtls_reload.generation` captured before and after that generated-owner publication is unchanged), under kube-proxy's iptables mode on kind. A bound ordinary operator DTLS listener remaining byte-identical is unit/integration evidence, not this hosted live gate. IPv6 Service steering, IPv6 DTLS, kube-proxy `ipvs` mode, and `nftables` mode are **not** exercised and are not claimed. (2) The direct-node-address lane below is retained and still tested, as a distinct documented boundary — it is not a substitute for the Service path.

*Steering lifecycle.* Desired destinations are derived during mesh materialization and carried as candidate metadata; they are **not** published from preparation. The serving `StreamListenerManager` publishes only destinations whose listeners are bound on the accepted generation and retracts them before those sockets stop. Destination and interface updates share one cold-path state machine, and task-exit ownership is generation-fenced. The source-attribution manager's own future-exit guard also clears attribution and calls steering shutdown, including on abort/panic, even though another manager retains the steering `Arc`. Ferrum-owned objects outlive their process, so the first reconcile always tears down both families. IPv4 and IPv6 cleanup are attempted independently: a missing or broken family tool, or any inspection/delete/verification failure in one family, cannot prevent the other available family from being attempted. Overall success still requires every family to be proven, so those failures remain nonzero and never set `reaped` or publish a replacement. Within a family, teardown probes and deletes only exact Ferrum-owned mark jump/chain, notrack jump/chain, policy rule, and local route—in that order—and never removes local routing if that family's mark path could still be live. If shared `ip` is unavailable, every safe xtables cleanup is still attempted and routing is retained. The local default is recognized under either iproute2 spelling (`default` or `0.0.0.0/0` / `::/0`); matching only the CIDR form would skip deletion and then miss the same live route on the post-delete check. Genuine absence is idempotent success, including iproute2's `Error: ipv4: FIB table does not exist` / `Error: ipv6: FIB table does not exist` dump (exit 2) for a never-created Ferrum table and for the table the kernel drops after its last local route is deleted; missing tools, permission/resource failures, other `ip route show` failures, delete failures, and failed absence verification remain nonzero. A failed teardown therefore cannot set `reaped`, publish or settle a replacement or inactive reply-source generation, or let the listener lifecycle stop claiming proof; the next reconcile retries. Setup still empties marking before replacing prerequisites and requires every published family to install completely. Diagnostics are bounded and contain no interface, registry, or secret material.

*Which node address a client may address the listener at (the direct-address boundary).* The listener binds the wildcard address, and every reply leaves with its source pinned by `IP_PKTINFO`/`IPV6_PKTINFO` to the EXACT local address the client's datagram was addressed to (`PktinfoLocal`, captured on the first datagram that carries a cmsg) — not to a route-selected source. That is a correctness requirement, not an optimization: a client with a `connect()`ed socket (every DTLS client, and any UDP client that connects) discards a reply whose source is not the address it dialed. The node-agent's direct-pod guard then admits a datagram to an enrolled pod only when it was emitted by the relay's own cgroup (see the reply-source section below), carries `NODE_WAYPOINT_INBOUND_AUTH_MARK`, **and** has a source that is one of the trusted node source IPs (`FERRUM_NODE_AGENT_NODE_IP` / `FERRUM_NODE_AGENT_NODE_IPS`). **The two facts compose into a deployment contract: a NodeWaypoint UDP/DTLS listener can only answer a client that addressed it at a trusted node source IP.** Addressing it at some other node-local address (the node's `status.hostIP`, say, when only the pod-CIDR gateway is declared trusted) relays the datagram to the backend normally and then loses every reply to the node's own guard — fail-closed, and deliberately not repaired by widening the trusted set implicitly or by letting the reply pick its own source. Declare every node-local address the listener is meant to answer on. This contract governs the DIRECT-address lane only: on the steered Service path the pinned source is a Service ClusterIP, which is authorized by its own exact, serving-lifecycle-bound entry in `FERRUM_UDP_REPLY_SOURCES`/`FERRUM_UDP_REPLY_SOURCES6` (see below) rather than by the trusted-node-IP set — the trusted set is deliberately NOT widened to ClusterIPs. The captured interface index is NOT reused as the send-side egress interface: it is receive-side evidence for source attribution, and `PktinfoLocal::send_ifindex` re-derives the outbound value, which is `0` for every IPv4 source and every global IPv6 source (the route table chooses the device; the pinned source address is unaffected) and carries the index only for a scoped IPv6 source — link-local unicast or interface-/link-local multicast — whose zone would otherwise be ambiguous.

*Reply-source authorization on the Service path (issue #3286).* The direct-address boundary above composes two facts — the reply's source is PINNED, and the guard admits a marked datagram only from a trusted node source IP — into "answer only where you were addressed at a trusted node IP". On the steered Service path the pinned source is the Service **ClusterIP**, which is never a configured node IP, so without further authorization the correctly marked, scoped, and attributed reply would be dropped by this node's own guard (a black hole rather than a bypass). Reply-source authorization keeps both invariants and adds an exact, live authorization for the reply's own two-tuple.

`FERRUM_UDP_REPLY_SOURCES` / `FERRUM_UDP_REPLY_SOURCES6` hold `(source address, source port)` pairs, `FERRUM_UDP_RELAY_CGROUPS` holds the relay pod's own cgroup-v2 ids, and `FERRUM_UDP_REPLY_SOURCE_GATE` is one shared BPF-visible enable value both tc UDP classifier families consult before any of the three. TCP never reads this surface. Exactness remains the boundary, but map contents alone are not authorization: stale keys can survive a failed scan/removal or a later IPv6 failure after IPv4 succeeded, and are inert while the shared gate is closed.

*A source tuple and a socket mark are both forgeable (issues #3956, #3957).* Under this datapath's threat model — a same-node workload in the HOST network namespace holding only SOCKET-level privilege (`CAP_NET_RAW` suffices for `IP_TRANSPARENT`, and for `SO_MARK` since Linux 5.17; `CAP_NET_ADMIN` grants both on any kernel) — every attribute a packet carries is attacker-chosen. `SO_MARK` sets `NODE_WAYPOINT_INBOUND_AUTH_MARK`; binding a node-local address sets a trusted node source; `IP_TRANSPARENT` plus a bind sets a published Service ClusterIP and port. So neither `node source + mark` nor `reply tuple + mark` is an authorization, and neither is their disjunction: because the reply-source map is listener-wide, a replay of one published tuple reaches **any** enrolled destination on the node, not just the Service that published it. Swapping one lane for the other moves the bypass and black-holes half the datapath — the backend dial needs the node-source lane and the source-pinned reply needs the reply-source lane.

Admission is therefore a conjunction with a **non-forgeable sender proof** at its head:

```
relay cgroup  AND  relay mark  AND  (configured node source  OR  exact live reply source)
```

The sender proof is `bpf_skb_cgroup_id()` — the cgroup-v2 id of the socket that generated the skb, recorded by the kernel at socket creation from the creating task's cgroup — matched against `FERRUM_UDP_RELAY_CGROUPS`. It is not a header field, is not settable through any socket option, and cannot be rewritten in flight, so presenting it means already running inside the waypoint's own cgroup. The remaining disjunction is between two statements that NARROW what the proven relay may claim, never between two ways of being trusted.

The helper answers only where a socket is attached to the skb, which is exactly where the relay's datagrams are: host netns → pod, i.e. the tc **egress** hook of the enrolled pod's host-side veth. Everything else reports zero and is refused — a forwarded packet from another pod or another node has been through `skb_scrub_packet`, and the tc **ingress** hook (pod-originated traffic) has not looked a socket up yet. The relay never sends through either, so nothing legitimate is lost. Zero, a closed gate, an absent map, and an absent entry all deny.

Because the helper is a `SCHED_CLS` helper gated on the kernel's `CONFIG_SOCK_CGROUP_DATA`, a kernel without it fails the classifier at **load**, not at admission — a visible enrollment failure rather than a silent open lane. That configuration is already implied: `CONFIG_CGROUP_BPF`, which this node-agent's `connect4`/`connect6` hooks require, selects it. There is a second, quieter kernel floor (issue #4021): before Linux **5.15** (commit `8520e224f547`) activating the cgroup-v1 `net_cls` or `net_prio` controller in specific ways set `cgroup_sk_alloc_disabled` — writing a `net_cls` classid, writing a `net_prio` ifpriomap, or attaching a task to a `net_prio` cgroup (mere read-only mounting does not trigger this) — so `sock_cgroup_ptr()` fell back to the root cgroup and `bpf_skb_cgroup_id()` reported the ROOT id for every socket on the node. That fails CLOSED — the root id is never inside the resolved relay pod slice — but with a symptom indistinguishable from a misresolved relay pod UID, so the effective requirement is **kernel >= 5.15, OR do not activate legacy cgroup-v1 `net_cls` or `net_prio` in those ways on the node**. See [`docs/node_agent.md`](node_agent.md) for the operator-facing statement.

*What the sender proof does NOT cover (issue #4021).* The claim above is stated at socket-level privilege because that is what holds on every supported kernel. A host-netns attacker who also holds `CAP_NET_ADMIN` still cannot forge a cgroup id, but where the classifier attaches through the legacy `clsact` qdisc rather than TCX it can `tc qdisc del dev <pod veth> clsact` and remove the guard outright. `attach_tc` uses aya's `SchedClassifier::attach`, which takes a TCX link on kernel **>= 6.6** and falls back to netlink/`clsact` below it; on the TCX path a `CAP_NET_ADMIN`-only attacker cannot preempt the program, since loading a competing one needs `CAP_BPF`. Guard removal below 6.6 is an operator-boundary concern (keep workloads out of the host netns), not a forgery this classifier can refuse.

Authorization is bound to the SERVING lifecycle, not to configuration. Serving means at least one owned NodeWaypoint UDP/DTLS listener is actually bound, started, and not finished — not that ClusterIP steering destinations exist. A bound headless/VIP-less or direct-node listener is ACTIVE with zero source tuples: the relay-cgroup sender proof stays live so marked backend dials from a configured node address are still admitted, while no ClusterIP tuple is authorized. Steering rules remain absent when there are no destinations or no attribution interfaces. Adding or removing ClusterIP destinations while a listener stays bound must not withdraw that sender proof. A configured-but-unbound or excluded listener activates nothing. The publisher is driven by the same `NodeWaypointUdpSteering` instance that owns the steering rules, which is only ever handed the actually-bound listener inventory — so a candidate address never becomes authorized by being parsed. Within one reconcile the previous generation's steering rules are torn down first, the new generation is authorized **before** any rules that will steer datagrams at it, and on teardown the order reverses (rules first, then the INACTIVE generation) so nothing is ever steered at an address whose authorization has already gone. Removing the last serving listener, bind failure, a refused plan, shutdown, and `Drop` all take the inactive retraction path. Every failure is fail-closed: a publication that cannot be written refuses the whole generation and attempts strict datapath teardown; a teardown failure retains unproven predecessor state for retry instead of claiming the Service path unsteered, and a withdrawal that cannot be completed is never recorded as done, so the next reconcile retries it instead of settling on `Unchanged`.

*How the relay cgroup set is established.* The manifest carries a third field: the publishing proxy's own Kubernetes pod UID (`FERRUM_MESH_NODE_WAYPOINT_RELAY_POD_UID`, chart-rendered from the downward API `metadata.uid` and refused as an operator-supplied value). That is a **name, not an authorization**. The node-agent resolves it against this node's own cgroup hierarchy (`resolve_pod_cgroup_path` + the bounded `collect_cgroup_tree` walk, the same machinery that enrolls per-pod workload identity) and writes the resulting pod-slice-plus-container-leaf ids; `bpf_skb_cgroup_id` reports the container LEAF, which is why the whole subtree is enrolled rather than the pod inode alone. A publisher cannot widen the sender proof by asserting an id, and the node-agent refuses the whole generation when the named pod is one of THIS node's enrolled workloads, when a resolved id belongs to an enrolled pod's subtree, when the identity resolves to no live cgroup, or when the bounded cgroup-tree walk is incomplete — more unique directory inodes than `UDP_RELAY_CGROUP_MAX_ENTRIES` (256), deeper than the walk's depth bound, or a descendant that cannot be fully enumerated. Those cases are refused whole rather than truncated, because a truncated set can omit the container leaf `bpf_skb_cgroup_id` reports. A descendant that VANISHED (`ENOENT`) is deliberately not one of them (issue #4021): a container exiting removes its cgroup directory, possibly between its parent's `readdir` and its own `stat`, and that is evidence the tree shrank rather than an inability to enumerate it — the walk re-runs (bounded) and reports the smaller tree as complete. A tree still shrinking after the last re-walk is refused, because no pass ever observed one coherent set. Exactly 256 complete directory inodes remain representable; a 257th is detected as overflow. The relay may answer for a Service address; it may never answer as one of the workloads this guard protects.

The set is re-derived host-side on every generation apply. A relay container restart restarts the proxy process, which mints a new owner token and therefore a new generation, so a moved leaf cgroup converges without any additional lifecycle machinery; a proxy that cannot name its own pod refuses every ACTIVE publication (nothing steered, and the sender proof is not opened) while an INACTIVE withdrawal generation stays publishable so teardown remains provable.

Ownership remains split: the node-agent is the sole BPF-map writer, while the proxy publishes one canonical, bounded, atomically renamed whole-set manifest and reads the exact `(owner, sequence, active)` acknowledgement. The node-agent retracts `applied` first, then disables the shared BPF gate before any map mutation. A failed acknowledgement unlink still attempts and, when fencing succeeds, closes the BPF lane, leaves state unknown/unacknowledged, and retries without applying a successor. With the gate closed it replaces the relay-cgroup map FIRST — so a relay-cgroup write failure returns before any source tuple is written, and the maps can never hold sources with no sender proof beside them — then IPv4 and IPv6 map storage, re-reads the exact manifest, enables the gate only when all three maps match that manifest, and writes `applied` last. An ACTIVE generation, including one with zero ClusterIP sources, still resolves and publishes the complete relay cgroup set and opens the gate after exact revalidation so the direct-node lane stays usable. An INACTIVE generation has zero sources and no relay identity, closes the gate, and clears both source and cgroup maps; it is the only true withdrawal. Any scan/remove/insert, partial-family, or revalidation failure leaves all residual keys inert. An acknowledgement-write failure closes the gate again. If gate disable itself fails, the node-agent reports a hard residual and does not mutate or acknowledge a new generation; it does not claim stale authorization was revoked. `validate_required` requires both family maps, `FERRUM_UDP_RELAY_CGROUPS`, and `FERRUM_UDP_REPLY_SOURCE_GATE`, including for inactive withdrawal — a NodeWaypoint that reported ready on an ELF without the relay-cgroup map would serve exactly the admission #3956 and #3957 describe. The manifest protocol is `v3`; a `v1` or `v2` manifest or acknowledgement is deliberately unparseable rather than honoured (`v2` equated an empty source set with withdrawal and would drop a bound headless listener's sender proof). Active-without-identity, inactive-with-sources, inactive-with-identity, malformed state tokens, and inconsistent counts fail closed.

*Publishing is not applying.* `NodeWaypointUdpSteering` therefore installs setup rules only once the node-agent has acknowledged the EXACT generation it published. While the acknowledgement is pending, missing, or stale the reconcile reports `PendingAck`, keeps (or reverts) the steering rules absent, and retries on the next ordinary reconcile tick — there is no wait, no sleep, and no blocked runtime worker. An acknowledgement that is later retracted reverts the installed rules on the next pass. Teardown is the mirror: the exact-name rule teardown must **succeed** before the INACTIVE generation is published, and the withdrawal is not reported `Removed` until the node-agent acknowledges that inactive generation. A failed rule teardown therefore retains the outgoing authorization and retries rules-first; a successfully published but unacknowledged withdrawal keeps being retried rather than settling. A publication or acknowledgement-read failure is a distinct `Failed` outcome that keeps the datapath fail closed. This gate closes the steered-but-unanswerable window on every add/update, and keeps a node-agent that never converges from leaving steering installed while the pod-veth guard drops every reply.

*DTLS material for those listeners, and who may change it (issue #3858).* A `dtls` listener terminates with the DTLS-specific `FERRUM_DTLS_CERT_PATH` / `FERRUM_DTLS_KEY_PATH` (plus optional `FERRUM_DTLS_CLIENT_CA_CERT_PATH` for frontend client-certificate verification), which mesh mode loads at startup — the same sources the database/file/dp serving paths use, so a listener that binds at startup and one that binds after a policy change always handshake with the same certificate.

DTLS frontend configuration and reload are **listener- and owner-scoped**. Every terminating DTLS listener carries an explicit ownership class: an ordinary operator listener configured from `FERRUM_DTLS_*`, or a Ferrum-generated `MeshNodeWaypoint` listener identified by its stable namespaced listener id. The two have SEPARATE accepted generations and separate publish entry points, and there is no process-wide DTLS fanout for either to reach the other through — a mesh slice can never live-swap an operator-owned DTLS listener, and an ordinary `FERRUM_DTLS_*` rotation can never replace the accepted mesh generation. During mesh slice preparation Ferrum derives each generated route's COMPLETE frontend config from the dedicated DTLS server identity plus that route's effective `PeerAuthentication` workload/service scope (resolved against the Service's backing workloads using the destination capture PeerAuthentication inventory unioned with the waypoint's own inbound view — a selector-scoped `portLevelMtls` overlay does not match the NodeWaypoint pod, so it is stripped from `peer_authentications` and would otherwise force `STRICT` client certificates on every generated DTLS session after a completed handshake — escalating to the most restrictive when they diverge — `Strict` requires and verifies a client certificate, `Permissive` and `Disable` do not) and the accepted client-CA + CRL snapshot. Every required candidate is built and validated **before** the slice is accepted: a malformed or truncated CA/CRL, a failed verifier build, an invalid client-side mTLS mode, or a `Strict` route with no configured `FERRUM_DTLS_CLIENT_CA_CERT_PATH` rejects the WHOLE candidate slice and retains the complete last-good routing AND DTLS serving generation for both owners — so a Permissive-to-Strict change cannot leave an already-running generated listener serving its old Permissive verifier, and new routes are never published beside stale DTLS posture. The accepted generation is stored before it is swapped into active servers, so a generated listener created or restarted after a successful slice receives exactly the generation already live on its peers, and an accepted EMPTY generation is a positive statement that stops a withdrawn-then-re-added listener from resurrecting stale owner-scoped state. Database / file / DP mode DTLS listeners are unaffected by this owner scoping. `FERRUM_FRONTEND_TLS_CERT_PATH` / `_KEY_PATH` are deliberately NOT reused: on a mesh proxy that pair is the operator override for the INBOUND TCP listener's server identity, so sharing it would make configuring a DTLS listener silently replace a SPIRE-issued inbound identity. Expiry is validated at startup with the same gate the other serving modes use. Ordinary (non-generated) DTLS without material stays visibly deferred (`FrontendDtlsDeferred`) instead of binding. When generated NodeWaypoint DTLS listeners are required, a missing dedicated `FERRUM_DTLS_CERT_PATH` / `FERRUM_DTLS_KEY_PATH` pair rejects the complete candidate before apply and retains last-good; a generated route resolving to Strict PeerAuthentication without `FERRUM_DTLS_CLIENT_CA_CERT_PATH` likewise rejects the complete candidate — the generated listener does not stay deferred while the rest of the slice applies. In Helm, mount the material with `ambient.extraVolumes` / `ambient.extraVolumeMounts`.

*Where the blanket suppression still applies.* Slice preparation's blanket fail-closed removal of NodeWaypoint UDP/DTLS service ports, proxies, synthesized outbound UDP upstreams, and mesh-DNS visibility runs ONLY where the attribution channel cannot exist — a non-Linux build, which has neither `IP_PKTINFO` attribution nor sysfs interface resolution. Both worlds are fail-closed; the difference is that attributable workloads keep working instead of the whole surface being disabled. Mesh-wide policies still evaluate normally, and scoped `AUDIT`-only policies are non-enforcing and never force suppression. NodeWaypoint remains Experimental.

#### BPF SOCK_OPS observability (GAP-SC3)

The `__mesh_bpf_metrics` plugin is auto-injected on `NodeWaypoint` topology only as a global instance and surfaces TCP-layer counters from `BPF_PROG_TYPE_SOCK_OPS` plus first-data evidence from `BPF_PROG_TYPE_SK_SKB`. The userspace consumer (`src/ebpf/event_consumer.rs::SockOpsConsumer`) drains the per-CPU ringbuf and increments a shared `BpfMetricsState`. Authenticated production `GET /metrics` appends that surface exactly once from the current plugin-cache generation's precomputed exporter (configured `prefix` preserved after `str::trim`; the trimmed value must match `[A-Za-z_][A-Za-z0-9_]*`; default `ferrum_mesh_bpf`; absent from the scrape when the plugin is not in the published configuration). Metrics emitted (Prometheus text format):

- `ferrum_mesh_bpf_tcp_events_total{event="connect"|"accept_established"|"rst"|"fin_sent"|"fin_received"}` — per-TCP-event counts. Operators correlate `accept` vs `connect` rates to spot stuck pods or pre-handshake drops. `event="rst"` counts abnormal `ESTABLISHED→CLOSE` transitions; SOCK_OPS state callbacks cannot distinguish RST-sent from RST-received, so there is no directional `rst_sent` / `rst_received` pair.
- `ferrum_mesh_bpf_drops_total{reason="bypass_uid_hit"|"exclude_cidr_hit"|"not_in_include_cidr"|"exclude_port_hit"}` — how often each BPF capture-bypass decision fired. Produced by the `connect4`/`connect6` hooks. The decision is accounted on per-CPU kernel counters in `FERRUM_SOCK_OPS_STATS`, not by counting the `SOCK_OPS_EVENT_DROP_REASON` ringbuf records: a full ring discards the record while the kernel slot still moves, so a record-counted series under-reports exactly when the node is busiest. The record itself stays in the event stream and still counts toward `ferrum_mesh_bpf_ringbuf_events_total`. Include-CIDR misses and `includeOutboundPorts` misses share `not_in_include_cidr`.
- `ferrum_mesh_bpf_srtt_microseconds`, `ferrum_mesh_bpf_syn_to_ack_microseconds`, `ferrum_mesh_bpf_accept_to_first_byte_microseconds` — TCP-layer latency **histograms** (Prometheus type `histogram`). Fixed inclusive `le` bucket upper bounds in microseconds: `100`, `250`, `500`, `1000`, `2500`, `5000`, `10000`, `25000`, `50000`, `100000`, `250000`, `500000`, `1000000`, `2500000`, `5000000`, plus `+Inf`. The `_sum` / `_count` series permit mean derivation (`sum / count`) and `histogram_quantile` percentiles. The accept-to-first-byte interval starts at the accepted socket's `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB` timestamp and ends at the first non-empty inbound SK_SKB stream-parser callback on that exact socket. It is not a handshake rename: the SOCKHASH carries the accepted socket itself, and correlation state is keyed by its socket cookie rather than the reusable network tuple. The existing IPv4/IPv6 orig-dst bridge must confirm capture before emission. Pending data, pre-enrollment data, close-before-data, failed handoff, LRU eviction, reload, reversed/wrapped `ktime`, and evidence older than one hour emit no sample. Both maps and the userspace deferred-removal queue are bounded at 65,536 entries; state is deleted on first data and terminal close, with kernel sockhash close cleanup as a backstop. A sum overflow or saturated count/bucket drops the whole sample rather than wrapping a component. Cardinality is process-global: only fixed `le` labels are emitted; peer addresses/ports, namespaces, identities, and raw cookies are never labels or logs. App-layer latency stays in `workload_metrics`.
- `ferrum_mesh_bpf_ringbuf_overruns_total` + companion `ferrum_mesh_bpf_ringbuf_in_overrun_regime` gauge — ringbuf health. Non-zero overrun count means userspace fell behind and the kernel dropped events; raise `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES` or reduce event rate. Attaching (or re-attaching after node-agent pin rotation) to a stats map that already reports a nonzero dropped total seeds **one** overrun episode so pre-reattach loss is visible; cumulative userspace counters are preserved across pin generations. The consumer also logs one `warn!` per regime entry and one `info!` on recovery — no per-event spam.

**Process split**: the node-agent owns the BPF program lifecycle — it loads `ferrum_sock_ops` from the ELF, attaches it to the cgroup root, and pins the event ringbuf, per-CPU drop counter, and accepted-socket SOCKHASH at `/sys/fs/bpf/ferrum/sock_ops_events`, `/sys/fs/bpf/ferrum/sock_ops_stats`, and `/sys/fs/bpf/ferrum/accept_first_byte_sockets`. The mesh-proxy in `NodeWaypoint` topology opens those pinned maps by path, drives a `tokio::io::unix::AsyncFd` poll loop, queues first-data SOCKHASH removal behind a bounded 250 ms grace period, and feeds decoded records through `SockOpsConsumer::handle_event` into the shared `Arc<BpfMetricsState>` that `__mesh_bpf_metrics` reads. The node-agent publishes the ringbuf pin last as the complete-generation marker, so a consumer never adopts it before the matching stats and SOCKHASH pins. There is no cross-process pointer sharing — the pinned-path contract is the entire IPC surface.

On Linux `ebpf` builds the userspace consumer retries until the node-agent pins appear: it logs one `info` line on the first miss, then backs off 1s, 2s, 4s, 8s, 16s, and 30s (capped exponential backoff at 30s) until opening the maps succeeds or shutdown fires. A missing pin does not stop the consumer; attaching after the node-agent publishes the maps does not require restarting the mesh-proxy. Builds without the `ebpf` feature or on non-Linux targets never start the consumer task. In every case the plugin keeps emitting a stable Prometheus surface populated by zeros until (and unless) the consumer attaches, so dashboards do not break. An SK_SKB load/attach failure disables only accept-to-first-byte samples and never changes capture or traffic verdicts. Node-agent reload creates a fresh unpinned correlation-map generation: in-flight evidence is deliberately discarded, while userspace aggregate counters remain attached to the current process state. The ringbuf size is sized at BPF load time by the node-agent from `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES` (default 4 MiB) — see [docs/configuration.md](configuration.md).

**Ringbuf drain bound (issue #5563)**: a pinned ringbuf outlives the mesh-proxy that drained it, so a replacement ambient pod attaches to a map whose consumer position is already non-zero. Each drain is therefore bounded by the kernel's producer position, read from the ringbuf's own metadata pages, rather than by the consumer library deciding the ring looks empty: records are consumed exactly once, a wakeup with nothing new behind the producer adds nothing, and a pass that made progress re-reads the producer position before concluding the ring is empty (a ringbuf wakeup only fires on commit). At attach — and again after pin rotation — a retained consumer position that cannot describe a live ring (ahead of the producer, or stale by more than a whole ring) is resynchronized to the producer position and logged at `warn` with both positions. That state is not cosmetic: while the consumer position is ahead of the producer the kernel's own reserve test underflows and every record is dropped, so the ring delivers nothing until it is repaired. The kernel dropped-events counter behind `ferrum_mesh_bpf_ringbuf_overruns_total` remains the sole overrun signal.

#### Platform prerequisites

- **Build and images.** Real eBPF attachment needs a Linux binary built with the `ebpf` feature. Helm renders the `-ebpf` image variant for `nodeAgent.captureMode=ebpf` and for an eBPF / `node_waypoint` ambient proxy, and promotes an enabled NodeWaypoint UDP/DTLS listener surface to the tools-capable `-ebpf-tools` variant for Service-path steering. The host iptables fallback also needs a tools-capable image (`/bin/sh` + `iptables`).
- **Kernel and capabilities.** Kernel ≥ 5.7 with cgroup v2 and bpffs. On ≥ 5.8 the node agent needs `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_PERFMON`; on the 5.7.x window it needs `CAP_SYS_ADMIN` + `CAP_NET_ADMIN`, which the chart adds only there (`nodeAgent.security.dropCapSysAdmin=false`), in every proxy mode.
- **Dedicated pod interfaces.** Veth resolution reads only host route tables and host sysfs (an exact `/32`/`/128` host route to a dedicated host-side peer), never a pod's own sysfs view; a pod reachable only through a shared CNI device such as `cni0` or `cilium_host` is refused rather than guarded. The node agent renders no `hostPID`.
- **NodeWaypoint proxy mounts.** The NodeWaypoint ambient proxy receives host PID visibility plus read-only host cgroup and bpffs mounts so it can resolve pod netns, open node-agent-pinned maps, and write per-pod ready markers only after its in-netns listener is attached.
- **CI gates.** `build-ebpf`, `build-ebpf-userspace`, `ebpf-live` (load/attach on a real kernel), and the Docker/kind multi-pod `node-waypoint-ebpf-live` workflow gate capture/identity/chart changes.

#### Destination metadata (`Workload.node_waypoint`)

Each mesh `Workload` can carry an optional `node_waypoint` object with `address`, `hbone_port` (default `15008`), expected NodeWaypoint `spiffe_id`, and optional `node_name`, `node_uid`, `network`, and `cluster`. Kubernetes pod discovery populates this object for service-backed workloads and ambient-enrolled identity-only source pods when their node has a ready host-network NodeWaypoint proxy pod in `FERRUM_K8S_CONTROLLER_NAMESPACE` with `app.kubernetes.io/name=ferrum-mesh-ambient`, service account `ferrum-mesh-ambient`, and `FERRUM_MESH_TOPOLOGY=node_waypoint`; scoped workload watches still include that trusted namespace for Pod discovery. The Helm chart sets `FERRUM_K8S_CONTROLLER_NAMESPACE` to the release namespace and requires the ambient NodeWaypoint admin health listener to stay enabled so the DaemonSet has a real readiness probe. The endpoint address comes from the proxy pod IP, `hbone_port` comes from `FERRUM_MESH_HBONE_LISTEN_ADDR` when present (then the named `hbone` container port, then default `15008`), and the expected peer identity comes from `FERRUM_MESH_WORKLOAD_SPIFFE_ID` when present (then the proxy pod's service account SPIFFE ID). Captured Service targets consume this metadata when present: they select the workload first, keep the workload app address and port as the inner CONNECT authority, dial the hosting node's NodeWaypoint endpoint via `mesh.hbone_dial_host`, and pin `mesh.hbone_peer_spiffe_id` instead of synthesizing `podIP:15008`. When the source NodeWaypoint runtime has file SVID material or a mesh CA backend (required by production mode), metadata-absent targets are skipped so the Service route fails closed instead of retaining a plaintext backend. Explicit no-CA/no-identity development runs keep the temporary plaintext fallback; the required live gate uses SPIRE-backed production mode instead. Live insert still requires that Ready trusted proxy. The control plane also remembers the last Ready endpoint per node and reattaches it only when that same node still has a trusted waypoint proxy pod that is not Ready or is terminating — explicit evidence the DaemonSet is replacing the proxy on that node — so destination metadata is not withdrawn solely because one node's proxy is briefly not Ready. Another node's trusted pod cannot retain a withdrawn node's endpoint. A node with no trusted waypoint object is a deliberate withdrawal: that node's remembered endpoint is dropped and destination metadata is cleared. A newly Ready same-node endpoint replaces the retained one. When no trusted waypoint pods remain, the inventory is cleared and destination metadata is withdrawn.

#### Stream and UDP/DTLS scoping summary

TCP stream connections through a node-waypoint proxy scope per source pod via `resolve_node_waypoint_stream_scope()` (socket-cookie → pod identity → `PolicyScopeCache`); when the connect-side resolver returns no identity, the connection fails closed with 403 if any namespace/selector-scoped `AuthorizationPolicy` exists in the mesh (else falls through to mesh-wide-only evaluation). **UDP/DTLS is scoped per source pod too** (issue #3286). The socket-cookie channel genuinely cannot serve it — eBPF capture is `connect()`-hooked and TCP-only, and a UDP proxy demuxes every client off one shared frontend socket with a single cookie — so UDP/DTLS uses a different, equally exact channel: `src/proxy/node_waypoint_udp_identity.rs` attributes each datagram from two kernel-provided facts, the INGRESS INTERFACE index (`IP_PKTINFO` / `IPV6_PKTINFO`) and the datagram's source address, which must be one the node-agent registry publishes for the pod owning that interface. A NodeWaypoint proxy is host-network, so a local pod's egress is the only traffic entering the host namespace on that pod's interface; forging a source address cannot change which interface a packet arrived on, and an interface claimed by more than one enrolled pod is refused for BOTH claimants rather than guessed. The resolved pod's `PolicyScopeCache` and SPIFFE principal are stamped onto the session before `on_stream_connect`, so `mesh_authz` enforces namespace/selector-scoped policy exactly as it does for TCP. An unattributable session leaves the scope absent and `mesh_authz` rejects it while any scoped policy exists (never a plaintext or mesh-wide fallback), and every subsequent datagram of an admitted session is re-authorized against the current registry attribution and the exact accepted mesh-slice generation that supplied its plugin chain and scope. Any later accepted slice retires that session before another datagram or reply is forwarded—even if the pod identity is unchanged or the session was admitted unattributable under mesh-wide-only policy—so policy-only updates, pod churn, veth reuse, registry removal, and re-attestation cannot inherit an old authorization lifetime. Service ports and UDP/DTLS proxies therefore stay UP under enforcing scoped policy, and — with `FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED=true` — each in-mesh service port whose protocol is `udp` or `dtls` materializes a real datagram listener on that port number (`materialize_node_waypoint_udp_listeners`), which is the configuration surface that makes this channel reachable. `dtls` is the same L4 transport as `udp`; it only selects frontend DTLS termination on the listener, and it is sourced from an `appProtocol: dtls` / port-name hint on a `protocol: UDP` Kubernetes Service port or a `dtls` Istio port protocol (a `protocol: TCP` port can never become `dtls`). Because the whole decision rests on the kernel's ingress-interface cmsg, a scoped listener that cannot enable `IP_PKTINFO`/`IPV6_RECVPKTINFO` for **every family its bound socket serves** (a dual-stack `[::]` bind serves both, so a success on one family does not excuse a failure on the other) returns a typed startup error instead of binding — the listener is recorded as a bind failure in stream-listener health, rather than reporting itself started while denying every session. When a DTLS session terminates, both relay tasks are aborted **and joined** before the handler returns, so no relay can still be forwarding after the session's scope pin and accounting have been released. The blanket suppression (slice preparation strips UDP/DTLS service ports, proxies, synthesized upstreams, and mesh-DNS visibility) remains in force only where the channel cannot exist at all — a non-Linux build, which has neither `IP_PKTINFO` attribution nor sysfs interface resolution. Mesh-wide policies still evaluate, and audit-only scoped policies never force suppression.

#### Inbound capture (tc ingress redirect)

Implemented for IPv4 and IPv6, opt-in, and live-gated. `ferrum_tc_ingress_redirect` (`ebpf/ferrum-ebpf/src/tc_ingress_redirect.rs`) is a tc **ingress** classifier attached to the node capture interfaces named by `FERRUM_NODE_AGENT_INGRESS_REDIRECT_IFACES` (unset = off, and the whole datapath stays inert). It steers inbound TCP for enrolled workloads into a dedicated **transparent inbound capture listener** with `bpf_sk_assign()` instead of a node-global `nat PREROUTING -j REDIRECT`. **The steer target is NOT the HBONE listener**: HBONE (`:15008`) terminates authenticated HTTP/2 CONNECT over verified mesh mTLS, while captured traffic is ordinary application bytes (possibly the app's own TLS), and `IP_TRANSPARENT` preserves addresses rather than transforming payloads. The capture listener is a separate protocol boundary bound on `FERRUM_MESH_INBOUND_LISTEN_ADDR` (default `0.0.0.0:15006`, unused by NodeWaypoint otherwise) — the single source of truth for the port on both the proxy and the node-agent — and it terminates nothing. **Scope is per workload and per port**: the destination must be in `FERRUM_POD_IPS`/`FERRUM_POD_IPS6` carrying `POD_CAPTURE_FLAG_INBOUND_REDIRECT`, *and* the exact `(pod address, destination port)` pair must be in `FERRUM_POD_INBOUND_PORTS`/`FERRUM_POD_INBOUND_PORTS6` (derived from the pod's declared `containerPorts`); anything else is returned untouched, so unenrolled traffic is never captured. The later userspace workload resolver accepts a matching address when its port inventory is empty or contains that port; this lookup behavior is distinct from capture admission and does not change the kernel capture port map. **IPv4 fragments are declined before any port is read** (More-Fragments or non-zero offset), because a non-first fragment's payload bytes would otherwise be parsed as ports and could be made to match a declared pair; IPv6 extension/fragment chains likewise pass through unparsed. **Original destination metadata is preserved without NAT** — addresses are never rewritten, so the capture listener's accepted socket reports the workload's real `podIP:appPort` from `getsockname()` with no conntrack table and no reverse NAT; that one listener (and no other) binds `IP_TRANSPARENT`/`IPV6_TRANSPARENT` on a wildcard address so its replies may be sourced from the captured pod address. **Security posture on the capture path is DESTINATION-EXACT**, because one capture listener serves every enrolled pod on the node: the recovered destination must resolve to exactly one workload in the userspace capture destination inventory (address match plus either an empty workload port inventory or a matching port; no address match or two records claiming the address with divergent identity closes the connection). This later lookup is distinct from kernel capture admission, whose port map is derived from declared container ports. Both gates that follow are then properties of *that* workload rather than of the listener. Direct captured plaintext is admitted only where **that workload's own** effective PeerAuthentication posture on the captured app port permits it — resolved from its namespace/labels with the canonical resolver, deliberately not from the listener-wide per-port table, so a `PERMISSIVE` pod can never admit plaintext to a `STRICT` pod sharing the app port; `STRICT` still requires verified mesh transport and refuses direct plaintext.

**Topology-readiness contract.** The explicit ingress interface set is proved
from complete remote PodCIDR/InternalIP route evidence, independent of a
peer's transient Ready health; incomplete non-Ready joining/rebooting/draining
Nodes are ignored, while incomplete `Ready=True` evidence fails closed. No
usable remote evidence (including a single-node cluster) reports
`no_remote_topology_evidence`; leave the redirect option unset when there is
no off-node path. Route ingestion observes only the procfs main IPv4/IPv6
tables, so alternate policy routing and encapsulating CNIs whose inner and
outer devices differ are unsupported and remain failed closed. When proof is
lost, the node-agent disarms the redirect map, withdraws health/capture
readiness, and rejects CNI ADD/CHECK/STATUS. The direct-pod guard remains
fail-closed, so existing enrolled workloads can be unreachable until the same
explicit proof recovers; capture is never widened or failed open.

**Cross-namespace destination policy (issue #3287).** A NodeWaypoint is typically deployed in an infrastructure namespace (`ferrum`) while the pods it captures for live in application namespaces (`payments`). The ordinary slice views — `workloads`, `peer_authentications` — are narrowed to the subscription namespace, so they can neither name a cross-namespace destination nor carry that destination's `PeerAuthentication`; resolving against them would see no policy and fall back to Istio's `PERMISSIVE` default, admitting direct plaintext to a `STRICT` pod. The capture path therefore consumes **three dedicated, least-privilege slice fields** instead:

* `node_waypoint_capture_destinations` — the workloads whose trusted `Workload.node_waypoint.spiffe_id` names **this exact NodeWaypoint**. That key is per-node, set by the config authority (never by the pod), and is the same identity the secured NodeWaypoint transport pins as the destination's server SVID.
* `node_waypoint_capture_peer_authentications` — the PeerAuthentication candidates applicable to those destinations (mesh-wide/root-namespace, namespace-scoped, and selector-scoped alike), so Istio precedence and port overrides resolve exactly as the destination's own sidecar would resolve them.
* `node_waypoint_capture_mesh_policies` — the `AuthorizationPolicy` entries the scoped evaluator would apply to one of those destinations (root-namespace/mesh-wide, namespace-scoped, and selector-scoped policies matching the destination's own namespace and labels). The ordinary `mesh_policies` view is narrowed to the subscription namespace, so without this field a `DENY` (or an `ALLOW`'s implicit-deny floor) in the captured pod's own namespace was absent and the captured connection was admitted. Under NodeWaypoint per-pod scoping `mesh_authz` unions it into its candidate set once per plugin generation; each candidate is still filtered per connection against the stamped scope, so a foreign policy never reaches a pod it does not select. Its scoped entries count toward the missing-scope fail-closed rule wherever the missing scope is a capture DESTINATION's — the synthesized inbound HBONE relay (the transparent capture relay always stamps its destination scope). They do not count where the missing scope is a SOURCE scope (unattributed UDP/DTLS sessions, outbound capture): those keep the ordinary policy census, so the inventory never refuses a session that no destination scope could satisfy. Its CUSTOM providers ride the slice's `ext_authz_providers`. A body-inspecting CUSTOM rule that only this inventory carries requests the pre-authorization body buffer (and its `maxRequestBytes` ceiling) only for a request whose destination or source scope its policy selects. It never buffers, or refuses as too large, a request to a workload it cannot select. The CP resolves it namespace-level (owner = a captured destination's namespace or the root namespace) before narrowing `mesh_policies`; the slice builder then keeps exactly the per-destination set, so a selector for a pod on another node, a namespace with no captured destination, and an unauthorized namespace's policy never leave the CP. It rides its own ECDS carrier (`NodeWaypointCaptureMeshPoliciesCarrier`), is compared by slice `content_eq`, and is part of the xDS stream fingerprint.

**Completeness evidence.** An empty `node_waypoint_capture_mesh_policies` is ambiguous on its own: "resolved, nothing applies" and "never resolved" look identical. Every capture-scoped slice build therefore stamps `node_waypoint_capture_mesh_policies_resolved: true` (native and file), and over xDS the `NodeWaypointCaptureMeshPoliciesCarrier` is emitted whenever the inventory was resolved, **including an empty one** — its presence is the evidence. A slice that carries capture destinations (or capture policies) without that evidence is refused at slice conversion, the shared step for every source at both startup and reload, and an xDS DP also NACKs it at recovery. At startup no capture-serving generation is built; on reload the previous complete generation keeps serving. A producer that predates this inventory is therefore refused rather than served with the destinations' own policies missing. The marker is only ever stamped for an inventory derived from an authoritative, pre-narrowing source. The CP resolves all three inventories before it narrows `workloads` / `peer_authentications` / `mesh_policies` (under the CP scope and bearer bounds; when the request carries no workload identity yet, as in the xDS prefilter, it keeps an in-process candidate set that the slice builder narrows to the requesting NodeWaypoint) and records that provenance on the config. The slice builder then treats that answer as authoritative even when it is empty, and never rebuilds an inventory from the narrowed — or Sidecar-egress-widened — routing views. A config narrowed without an inventory yields none and no evidence. Only an unfiltered authority document (the file source) is derived from as a whole.

**Inbound HBONE relays to capture destinations.** An authenticated inbound HBONE CONNECT relayed to an enrolled pod carries no source-pod scope. When the source assertion is honored, `mesh_authz` resolves the destination scope for the exact synthesized relay (`__mesh-inbound-hbone-relay`). The scope comes from a separate capture-destination index built from `node_waypoint_capture_destinations` in the same plugin generation, which is **authoritative** for any address it names: the relay guard admitted that destination from the same inventory, so an ordinary service-derived record that claims the same address (a stale or reused address in the subscription-namespace view) never decides the relay's scope. An address or hostname the inventory does not name keeps the ordinary service-derived index; a capture destination declared by hostname is matched ASCII-case-insensitively, exactly as the relay guard admits it. The index applies the same rules as the transparent capture resolver: addresses compare canonically (`IpAddr::to_canonical`, so an IPv4-mapped spelling is the same address on both inbound surfaces); a destination that declares ports admits only those ports; and divergent records for one address resolve nothing. An undeclared port or divergent records refuse the scope rather than falling back to the ordinary index. The destination's own `AuthorizationPolicy` is then evaluated, and the authorized backend is stamped so route dispatch stays bound to it. An unknown address, an undeclared port, ambiguous records, or an unhonored assertion leaves the relay without a scope, and the missing-scope rule refuses it (`scope_missing`) whenever scoped policy is loaded. The index never feeds routing or the ordinary destination index.

The request opts in with `MeshSliceRequest.node_waypoint_capture_scoping`, set only for `MeshTopology::NodeWaypoint`. It is deliberately **not** folded into `ambient_udp_source_scoping`, because the two flags request different evidence for different channels and neither is a superset of the other:

* `node_waypoint_capture_scoping` requests the **cross-namespace capture-destination inventory** above — a *destination*-side view (which pods this NodeWaypoint terminates for, their PeerAuthentication, and their AuthorizationPolicy), consumed by the TCP capture relay and by `mesh_authz` for captured connections and inbound HBONE relays to those pods.
* `ambient_udp_source_scoping` requests the **UDP source-workload evidence** (per-pod scopes/identities for datagram attribution).

NodeWaypoint UDP/DTLS is **source-pod scoped** (issue #3286): a NodeWaypoint attributes each datagram to its source pod from the kernel-reported ingress interface plus the node-agent registry's published source addresses (`src/proxy/node_waypoint_udp_identity.rs`), and enforces that pod's namespace/selector-scoped `AuthorizationPolicy`. That channel is *ingress-interface* based and is derived from the node-agent registry the NodeWaypoint already reads, so it needs no extra slice field — which is exactly why folding the two flags together would still be wrong: one shared flag would hand Ambient/ServiceWaypoint a capture-destination inventory they have no capture listener for, and would make the NodeWaypoint's request for destination scoping look like a request for the Ambient UDP source superset it does not consume. Native `MeshSubscribe` carries the flag as `MeshSubscribeRequest.node_waypoint_capture_scoping`; xDS carries it in `Node.metadata` and returns the inventory on its own ECDS carriers (`NodeWaypointCaptureDestinationsCarrier`, `NodeWaypointCapturePeerAuthenticationsCarrier`, `NodeWaypointCaptureMeshPoliciesCarrier`), so native and xDS reach the same posture. The file/local source derives it DP-side from the same document.

**Authorization and blast radius.** The CP resolves the inventory *before* its own namespace narrowing (after it, the cross-namespace records are already gone) but *after* applying the CP scope and the bearer `ns` claim: a `Single`-scope CP is a hard boundary for this cross-namespace evidence exactly as it is for Ambient UDP source evidence, and an explicit `ns` claim intersects the set. The inventory is **never** folded into `workloads` / `services` / `peer_authentications` / `mesh_policies`, so ordinary routing, known-destination, outbound-registry, and own-inbound-posture views stay namespace-narrow. The destinations and PeerAuthentication candidates are read by the capture resolver; the destinations additionally seed the NodeWaypoint source identity resolver (issue #6800), which vouches each such source only by its exact pod UID and never exposes it to routing; the AuthorizationPolicy entries are read only by NodeWaypoint per-pod `mesh_authz`, which applies each of them only to a connection whose stamped scope it selects. **Fail closed everywhere:** a CP that emits no inventory, a NodeWaypoint whose own SPIFFE identity is unknown, a namespace the CP or bearer does not authorize, and a pod enrolled on another node's NodeWaypoint all yield no resolvable destination — the connection is refused (and counted as `relay_destination_denied`), never resolved against `workloads` with the wrong policy view. A producer that emits destinations but no AuthorizationPolicy completeness evidence is refused at slice conversion (see **Completeness evidence** above). Incremental CP deltas carry no mesh resources, so the per-stream inventory is recomputed from the authoritative snapshot on every mesh change rather than accumulating stale destinations; `MeshSlice::content_eq` compares all three inventory fields and the completeness marker, and the xDS stream fingerprint covers the same runtime-only fields, so a destination leaving the inventory, its namespace flipping `PERMISSIVE`→`STRICT`, or a DENY added in its namespace is never deduped away.

**Residual risk.** The posture the capture path enforces is only as good as the destination inventory the config authority publishes: a workload whose `node_waypoint` endpoint metadata is missing or points at the wrong NodeWaypoint is not captured for at all (fail closed, but its inbound direct plaintext is then simply dropped by the classifier rather than relayed). Cross-*cluster* capture destinations are out of scope — the inventory is derived from the local cluster's workload records. The L4 `on_stream_connect` chain (including `__mesh_authz`) then runs with the captured app port as the authorization destination and that workload's policy scope stamped on the stream context, so namespace/selector-scoped `AuthorizationPolicy` rules are evaluated against the captured destination instead of denying every captured connection `scope_missing`; the stream is then relayed byte-for-byte so application TLS is never mistaken for mesh TLS. Every gate is fail-closed, and Sidecar inbound relay entries are unchanged (no socket mark, no destination scope). Backend dials carry the relay auth mark (`0x734`) for loop prevention and pod-veth admission. Local delivery of assigned packets rides a Ferrum-owned `ip rule fwmark 0x735 lookup 33134` at priority `101` (evaluated ahead of the kernel `main` rule at 32766, which the RPDB scans later because its priority number is higher) plus `ip route add local default dev lo table 33134`, per family; the table is distinct from the UDP TPROXY table `33133` so teardown of one never reaps the other. **Loop prevention** is four independent guards: the relay's own auth mark (`0x734`), the redirect mark itself (`0x735`), traffic already addressed to the capture port, and traffic addressed to the HBONE port. **Fail closed**: a packet that is in scope but for which no capture-listener socket resolves is dropped, never delivered unredirected; and startup refuses if the redirect is armed while the capture listener cannot bind or the node-agent/proxy port contracts disagree — the proxy validates `FERRUM_MESH_INBOUND_LISTEN_ADDR` (present, non-zero port, wildcard) with a field-specific error at the top of its serving path, because listener *planning* is infallible and would otherwise warn-and-skip the listener while the classifier kept dropping in-scope packets. **Teardown is retry-safe and ordered**: a failed classifier detach keeps its attachment recorded so `cleanup_all` really does retry it, and the Ferrum-owned local-delivery `ip rule`/`ip route` is removed only once no classifier can still be live (a live classifier without its routing strands every packet it assigns; inert leftover routing is the safe half-state and is reported rather than force-removed). **The node-global iptables fallback is NOT removed** — it remains the documented path for kernels that cannot run eBPF at all (`FERRUM_NODE_AGENT_FALLBACK_MODE=iptables`), which is a separate concern from the covered eBPF path. Verification: the shared decision table (arming, scope, all four bypasses, the fragment gate) is unit-tested in `ferrum-ebpf-common`, and the required `ebpf-live` CI job load/verifies the program on a real kernel — the only way to check the `bpf_skc_lookup_tcp`/`bpf_sk_assign`/`bpf_sk_release` reference-tracking rules — attaches and detaches it on a scratch veth tc ingress hook, round-trips both address families of the scope maps, **and drives a real TCP flow end to end** from a client in a scratch netns through the redirect into the transparent capture listener, asserting the observed original destination, a successful reply path, and that the flow is no longer steered after detach + scope clear.

**Capture-listener connection admission ([#4626](https://github.com/ferrum-edge/ferrum-edge/issues/4626)).** The transparent inbound capture listener fronts ordinary application traffic for **every enrolled pod on the node**, so exhausting it is a node-wide event rather than a per-pod one. Admission is therefore **gate 0**, in the accept loop between `accept()` and `tokio::spawn`, before any task is allocated (including for a direct dial to the capture port that would later be refused for carrying no captured original destination):

- `overload.reject_new_connections` — the same single relaxed atomic load the ordinary proxy accept loop performs, at the same boundary. Critical overload admits no captured connection.
- A connection limiter sized from `FERRUM_MAX_CONNECTIONS` with a `FERRUM_TCP_MAX_CONNECTIONS_PER_IP` per-source share. As everywhere else in Ferrum, `FERRUM_MAX_CONNECTIONS` is a **per-listener** cap rather than one process-wide pool (the in-netns capture listeners document the same choice), so this listener holds its own limiter of that size: a saturated capture path must not starve inbound HBONE, and vice versa. The per-source key is the socket peer — the redirect NATs nothing, so that IS the real client address, and the effective source the relay derives later is only knowable after the task exists.

A refused socket costs one `accept()` and one atomic: no task, no relay state, no plugin state, no backend dial. The permit is moved into the connection task and released by RAII on **every** exit — not-captured, destination-denied, `STRICT` refusal, dial failure, relay error, cancellation, and shutdown. Repeated `accept()` failures go through the shared `AcceptBackoff` plus a rate-limited error log, so `EMFILE`/`ENFILE` cannot spin the loop. Metrics are fixed-cardinality with no source-IP label: `ferrum_mesh_node_waypoint_capture_rejected_connections_total{reason="overload"|"max_connections"|"max_connections_per_ip"}`, plus `ferrum_mesh_node_waypoint_capture_active_connections` / `_max_connections` / `_max_connections_per_ip` once the listener has bound.

### Service Waypoint

Service-scoped Ambient waypoint for Istio GAMMA traffic. Set `FERRUM_MESH_TOPOLOGY=service_waypoint` and `FERRUM_MESH_WAYPOINT_NAME=<gateway-name>`; the waypoint name is required so the control plane can project only the services bound to this waypoint.

Inbound byte-stream and datagram HBONE relays resolve authorization policy scope from the exact CONNECT destination's bound workload rather than from the waypoint pod's namespace and labels. A relay whose destination scope cannot be resolved is rejected, and an allowed decision is bound to that destination so a later route override cannot substitute an unchecked backend.

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

Sidecars route external traffic to the egress gateway over mTLS. The gateway terminates mTLS, evaluates authorization policies, and forwards to the external backend. Requires a TLS server identity from `FERRUM_FRONTEND_TLS_CERT_PATH` and `FERRUM_FRONTEND_TLS_KEY_PATH`, the complete `FERRUM_GATEWAY_SVID_CERT_PATH`/`KEY_PATH`/`TRUST_BUNDLE_PATH` triple, or `FERRUM_MESH_CA_BACKEND` with `FERRUM_MESH_WORKLOAD_SPIFFE_ID`. Peer verification requires `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` or the SVID trust material; `FERRUM_TLS_NO_VERIFY=true` is refused.

#### External UDP egress (EgressGateway)

A `protocol: UDP` port on a `MESH_EXTERNAL` `ServiceEntry` materializes bounded datagram-over-mesh egress on the EgressGateway (issue #3263) — and still emits **no UDP listener**: binding one on the ServiceEntry port would collide with a sibling TCP port on the same number under the port-only stream dedup (DNS `53/TCP` + `53/UDP`) and would need DTLS material mesh never seeds. Instead the materializer publishes a runtime-only **destination allowlist** (`MeshConfig.egress_udp_destinations`), and the gateway's existing authenticated mesh CONNECT terminator (the `:15090` SVID-mTLS egress listener) relays a `udp`-marked CONNECT whose `:authority` names an admitted external destination into a local `UdpSocket`, unframing with the same `mesh_udp_frame` codec the in-mesh UDP datapath uses. Admission is **exact**: the authority host must equal a declared `hosts[]` entry or a `STATIC` `endpoints[].address` IP literal (ASCII case-insensitive) and the port must equal the declared service port. **The admitted authority is not the dial destination.** Each admission carries a precomputed, bounded set of dial endpoints: under `resolution: STATIC` a host authority dials the operator-declared `endpoints[]` (so the gateway **never DNS-resolves a STATIC host**), and an endpoint-IP authority dials **only the endpoint it names**; under `DNS`/`NONE` the entry declares no dialable endpoint set, so the host's single dial endpoint is the host itself (resolved at dial time, which is what those modes mean). A numeric `targetPort` — or, for a named service port, the endpoint's own `ports` entry — moves only the port the gateway's socket dials. Selection across multiple endpoints is a lock-free modulo cursor over the precomputed set, so it costs one relaxed atomic per CONNECT and follows the live config snapshot across reloads. The allowlist itself is bounded by a closed total destination cap (`MAX_EGRESS_UDP_DESTINATIONS`, alongside the per-destination `MAX_EGRESS_UDP_DIAL_ENDPOINTS` cap); entries beyond either cap are refused fail-closed with a field-specific warning so CONNECT-time walks stay bounded. The materializer refuses — fail closed, with field-specific warnings — `port: 0`, wildcard hosts (`*.example.com`), empty hosts, non-IP-literal `STATIC` endpoint addresses, a `STATIC` port that resolved **no** usable endpoint (the host is refused outright rather than falling back to resolving it), and a `(host, port)` pair a previous ServiceEntry already claimed; the allowlist is **rebuilt and reassigned unconditionally on every apply**, so an update or delete that withdraws a ServiceEntry immediately withdraws the admission and a topology flip away from `EgressGateway` clears it entirely. The relay requires the same authenticated, trust-domain-verified mesh peer the byte-stream relay does, re-checks the **effective** (post-route-override) destination against **precomputed dial endpoints only** before opening any socket (a STATIC hostname is a valid CONNECT authority but must never become an effective socket target — that would DNS-bypass `endpoints[]`; DNS/NONE and STATIC endpoint-IP dial targets remain usable because they are themselves dial endpoints), `connect()`s the socket so the kernel pins the reply peer to the admitted destination, honors `udp_idle_timeout_seconds`, and bounds concurrent egress relay sessions process-wide by `FERRUM_UDP_MAX_SESSIONS` (over-cap CONNECTs get `503`). It is gated by `FERRUM_MESH_EGRESS_STREAM_ENABLED`; with the flag off, nothing is admitted and there is **never** a fallback to direct unauthenticated UDP. The byte-stream relay's open-relay guard is untouched — the external allowlist is consulted only for `udp`-marked CONNECTs. The originating side is the [source-side producer for external UDP](#udp-egress) on Sidecar/Ambient data planes.

## Configuration Consumption

Mesh mode consumes configuration via one of four sources, selected by `FERRUM_MESH_CONFIG_PROTOCOL`: two Ferrum control-plane protocols (`native`, `xds`), a localized file source (`file`), or stock Envoy / third-party Istio xDS interop (`stock_xds` — discovery only; policy from `FERRUM_MESH_FILE_CONFIG_PATH`; see [Stock Envoy / third-party Istio xDS interoperability](#stock-envoy--third-party-istio-xds-interoperability)).

### Native MeshSubscribe (default)

The Ferrum-native protocol uses the `MeshConfigSync.MeshSubscribe` gRPC streaming RPC defined in `proto/ferrum.proto`. The CP pushes complete `MeshSlice` JSON payloads whenever configuration changes. The mesh node sends its identity (node ID, namespace, SPIFFE ID, workload labels) in the subscribe request so the CP can filter resources by scope.

- **Admission**: native `MeshSubscribe` draws from the same process-wide stream budgets as ConfigSync and ADS (`FERRUM_XDS_MAX_TOTAL_STREAMS` and the per-namespace / per-principal / per-node / distinct-node ceilings). The permit is taken before broadcast subscription, slice filtering/serialization, registry insertion, or response-stream allocation. Excess streams are refused with gRPC `RESOURCE_EXHAUSTED`. See [xDS ADS admission budgets](#xds-ads-admission-budgets).
- **Multi-CP failover**: ordered list of CP URLs in `FERRUM_DP_CP_GRPC_URLS`. Jittered exponential backoff (1s initial, 30s max, +/-25% jitter) per URL. Primary retry interval configurable via `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`.
- **Authentication**: JWT HS256 in gRPC `authorization` metadata, using `FERRUM_CP_DP_GRPC_JWT_SECRET`. Native local `MeshSubscribe` tokens carry the fixed purpose audience `ferrum-mesh-subscribe:local`; the control plane requires it when `remote_discovery=false`. A client and control plane that disagree on this audience refuse each other (fail closed), so upgrade native mesh clients and control planes together. Ordinary `ConfigSync` and xDS tokens are audience-less.
- **Transport security**: same TLS configuration as CP/DP mode (see [cp_dp_mode.md](cp_dp_mode.md)).
- **No-op suppression**: `MeshSlice::content_eq()` skips updates that do not change mesh-relevant fields (ignoring the transport version stamp).
- **Response binding (fail-closed)**: every non-heartbeat `MeshConfigUpdate` is validated against the exact subscription request **before** it can reach `install_slice`. The envelope `version` must equal the embedded `MeshSlice.version`; the slice's `node_id` and `namespace` must equal the ones the data plane subscribed with; when the request pins a workload SPIFFE ID or a waypoint name, the slice must echo that same value (an *omitted* echo is a mismatch, not a skipped check — otherwise a response could bypass the scope gate by dropping the field); and `ferrum_version` must be present and major/minor-compatible. A rejected response never mutates state: the last accepted slice keeps serving. A response that is not bound to this subscription (wrong node/namespace/scope, or an incompatible control-plane version) additionally **drops the stream** so multi-CP failover moves to the next control plane, while a content-level fault (unparseable slice JSON, envelope/slice version disagreement) drops only that frame and keeps the stream open. Heartbeats carry no slice and are checked only against the version contract. The slice root, its policy members (`mesh_policies`, `peer_authentications`, `request_authentications`, `ext_authz_providers`, `telemetry_resources`), and `multi_cluster` are closed schemas (issue #6616), while inventory members (`workloads`, `services`) tolerate unknown fields. Major/minor compatibility therefore does not cover a patch release that adds a closed member: during a rolling upgrade a data plane that still runs the older build refuses that control plane's slices as `invalid_slice_json` and keeps serving its last-good slice until it is upgraded, so run control plane and data planes on the same build as the [build identity gate](upgrade_guide.md#build-identity-gate) already requires for ConfigSync. Rejections increment `ferrum_mesh_config_update_rejections_total{consumer,reason}` and emit a structured `warn!` whose control-plane-supplied values are length-bounded and control-character-stripped. The same rules gate [cross-cluster endpoint discovery](#cross-cluster-endpoint-discovery).
- **Config message size**: native `MeshSubscribe` (including cross-cluster remote-discovery fetches) and xDS ADS clients accept inbound gRPC config messages up to 16 MiB. Larger control-plane responses fail closed and the last accepted slice keeps serving.
- **GA contract**: GA-enrolled as `mesh.config_transport.native_subscribe` — see [mesh_supported_matrix.md](mesh_supported_matrix.md) / `tests/conformance/ga_contract.yaml`.

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
- **RTDS subscription** (`type.googleapis.com/envoy.service.runtime.v3.Runtime`): subscribed alongside CDS/EDS/LDS/RDS/SDS/ECDS so operators can flip runtime knobs without churning the entire slice. The xDS client decodes every layer through `translate_rtds_layer`, sorts Runtime resources lexicographically by name, and merges top-level fields into a single `MeshRuntimeOverlay` carried on `MeshSlice.runtime_overlay` (later names win; duplicate names NACK). Supported value kinds: numeric (`f64`), string, bool, and Envoy `FractionalPercent`-shaped structs (`{numerator, denominator: HUNDRED | TEN_THOUSAND | MILLION}`). Other struct, list, and null values are silently dropped. The overlay is exposed via `GET /mesh/runtime-overlay`; fault percentages and transformer gates both publish with their request epoch (so a request never straddles a gate change), while the gateway-wide tracing filter and the transformer gate *provenance* maps publish after slice acceptance. See the reserved-key table under [xDS ADS Compatibility](#xds-ads-compatibility) for the full contract.

#### Stock Envoy / third-party Istio xDS interoperability

`FERRUM_MESH_CONFIG_PROTOCOL=stock_xds` (issue #3317) is a **separate protocol
name** from `xds`, not a mode of it. Everything described above about the
Ferrum-private profile — name-only resources, `ferrum.config.extension.v3.*`
ECDS carriers, the required-type version-coherence gate — does not apply to
this path.

**Split of authority.** Two config sources, and the split is the whole security
story:

| Half | Source | Owns |
|---|---|---|
| Discovery | the stock ADS server (`FERRUM_MESH_STOCK_XDS_URLS`) | `MeshService` (namespace/name/ports/protocol/cluster VIPs) and `Workload` (endpoint addresses + peer identity) |
| Policy | the local mesh document (`FERRUM_MESH_FILE_CONFIG_PATH`, **mandatory**) | authorization policies, PeerAuthentication, RequestAuthentication, trust bundles, DestinationRules, ServiceEntries, Sidecar scope, ProxyConfig, telemetry |

A third-party control plane Ferrum does not otherwise trust can therefore add or
remove **reachability**, but it can never author or weaken Ferrum's
**enforcement posture**. Startup fails closed if the policy document is missing,
invalid, or declares `services` / `workloads` — those belong to the control
plane, and two authorities for one field would make "which endpoint is
reachable" ambiguous. The document is re-read on SIGHUP (Unix) through the same
off-thread, coalesced stable-file path as `file` mode (including the 20ms
two-probe settle); a failed reload
keeps the last good policy baseline and raises authenticated `/health`
`config_rejected`, and a successful one rebuilds the slice from the current
discovery view and clears the degraded signal.

Ferrum **never mints a CP/DP JWT for a stock control plane**. The only
credential it presents is an externally issued bearer token at
`FERRUM_MESH_STOCK_XDS_TOKEN_FILE` (typically a projected Kubernetes
service-account token), re-read on every connection attempt so rotation is
picked up on reconnect. The read uses the shared regular-file-only 64 KiB
credential boundary on a detached OS thread, with at most one timed-out reader
admitted while an unavailable mount remains blocked.
`FERRUM_MESH_STOCK_XDS_URLS` is deliberately separate from
`FERRUM_DP_CP_GRPC_URLS` so a Ferrum CP is never dialed as a stock server and a
stock server never receives Ferrum CP/DP credentials.

**What is consumed.**

| Resource | Mapped to |
|---|---|
| `Cluster` (`outbound\|<port>\|\|<svc>.<ns>.svc.<domain>`, `EDS` or `STATIC`) | a `MeshService` port in `<ns>/<svc>` |
| `Cluster.transport_socket` → `UpstreamTlsContext` URI SAN matcher | the pinned peer SPIFFE identity for that service port |
| `ClusterLoadAssignment` | `Workload` entries (address, container port → `targetPort`, weight, locality); `UNHEALTHY` / `DRAINING` / `TIMEOUT` endpoints are excluded |
| `Listener` filter chains | per-port protocol classification (HCM → HTTP/HTTP2, TcpProxy → TCP) and, for a concrete-bind listener, the service VIP |
| `RouteConfiguration` virtual hosts | IP-literal domains become `MeshService.cluster_ips` |

**Namespace narrowing applies unchanged.** Discovered services flow through the
same `MeshSlice::from_gateway_config` projection as native/file config, so a
workload sees only its own namespace's services unless the local policy document
declares an Istio `Sidecar` with a wider `egress.hosts` (for example `*/*`).
That is existing mesh behaviour, not a stock-profile restriction, but it is the
first thing to check when a discovered service in another namespace does not
appear in the slice.

Peer identity comes from the control plane's **own** SAN pin, never from
endpoint metadata. A cluster with no pinned SPIFFE, or with more than one
candidate, publishes the service shape with **no dialable endpoint** plus an
explicit `no_pinned_peer_identity` / `ambiguous_peer_identity` diagnostic —
Ferrum will not dial a peer whose identity the control plane did not assert.

**Protocol behaviour.** State-of-the-world ADS with per-type nonces, ACK/NACK
carrying a field-specific `error_detail`, dependency-ordered subscriptions (EDS
follows the accepted CDS clusters by resource name, RDS follows the accepted LDS
listeners), a 25 ms debounce capped at 500 ms before a
make-before-break `install_slice`, a
five-consecutive-NACK circuit breaker, jittered 1–30 s backoff, and multi-server
failover. There is deliberately **no** cross-type version-coherence gate: a
stock CP versions each type independently and carries no Ferrum security
carriers a skew could leave stale. Warming waits for CDS, and for EDS only when
some accepted cluster actually needs it. Convergence is visible on the
JWT-gated `GET /mesh/config-drift`. Stock xDS reports closed-set type
presence (`cds=received`, …) there rather than remote `version_info`: a
third-party CP can copy the bearer into that field, and truncation is not
redaction.

**Deletion follows the SotW rule for each type, not the response contents.**
`Cluster` and `Listener` are the two types a state-of-the-world server must send
as complete state, so those responses replace what is held and a resource absent
from one is deleted. `ClusterLoadAssignment` and `RouteConfiguration` are
subscribed by name and a response for them may legitimately carry only the
subset a push touched (istiod skips recomputing a cluster its update did not
change), so those responses are **merged**, and an assignment or route
configuration is dropped only once no accepted cluster/listener references it
any more. Reading an omitted assignment as "this service has no endpoints" would
blackhole every service an ordinary endpoint update did not mention.

On reconnect the client re-subscribes with an **empty** `response_nonce` (nonces
are stream-scoped) and with the last version it actually ACCEPTED — a NACKed
version is never re-asserted, so a control plane that suppresses a resource
whose version the client already claims cannot leave the data plane
unconverged.

**Two failure outcomes, and the difference matters.** A *structural* error —
bytes that are not a well-formed resource of the announced type, an empty or
duplicated name, or an outer response/resource bound exceeded — NACKs the whole
response and rolls the accumulator back, so the last good slice keeps serving.
A well-formed EDS assignment whose endpoint count exceeds its per-cluster
ceiling is a distinct refusal: Ferrum installs that assignment with an empty
endpoint list and ACKs the response. Slice construction or installation may
also refuse independently. A *capability
refusal* — a well-formed resource using something Ferrum does not model — drops
that resource with a field-specific diagnostic and ACKs, because a stock CP
legitimately programs Envoy features Ferrum has no counterpart for and NACKing
would leave the data plane permanently unconverged. A refusal always narrows:
it contributes no route, no endpoint, and no identity, so the worst case is
traffic that is not routed. Refusals are logged (bounded, and only when the set
changes) with a stable reason code, a short type label, and counts — never a
resource name, field path, version, nonce, or other CP-authored string.
Truncation is not redaction: those values can carry a bearer the control plane
echoed from the authenticated request.

**The extension-escape closure.** Every field through which an Envoy extension,
a filesystem path, credential material, an enforcement filter, or a second
delivery channel could enter is refused:

- Cluster `cluster_type`, `filters`, `load_balancing_policy`,
  `lb_subset_config`, and any `typed_extension_protocol_options` key other than
  `envoy.extensions.upstreams.http.v3.HttpProtocolOptions`.
- Any transport socket that is not `UpstreamTlsContext` or `RawBuffer`; inline
  `tls_certificates`; a `trusted_ca` `DataSource` naming a `filename` or
  `environment_variable`; `custom_validator_config`; `custom_handshaker`; a
  non-`exact` (regex/prefix/suffix) peer-identity matcher; and Envoy's
  deprecated `match_subject_alt_names` (it carries no SAN type, so a peer
  constraint expressed there is refused **by that field name** rather than
  silently dropped and reported against the typed field).
- Listener `api_listener`, `filter_chain_matcher`, `additional_addresses`; any
  listener filter outside `original_dst` / `tls_inspector` / `http_inspector` /
  `workload_metadata` (notably `proxy_protocol` and `original_src`, which
  rewrite an authorization input); any network filter outside
  `http_connection_manager` / `tcp_proxy` plus the metadata-exchange/stats
  telemetry filters.
- **Any HTTP filter other than `envoy.filters.http.router`** and a small
  observability allowlist (`istio.metadata_exchange`, `istio.stats`,
  `istio.alpn`, `grpc_stats`, `grpc_web`, `fault`). `rbac`, `jwt_authn`,
  `ext_authz`, `cors`, `local_ratelimit`, `lua`, and `wasm` refuse the whole
  listener — silently reducing an Istio listener that carries an RBAC or JWT
  filter to plain routing would turn the control plane's DENY into an ALLOW.
  This holds even when the filter is marked `disabled` or `is_optional`,
  because either can be re-enabled per route.
- HCM `scoped_routes`; route `typed_per_filter_config`, `redirect`,
  `direct_response`, `filter_action`, `non_forwarding_action`; `safe_regex` /
  header / query-parameter / gRPC / dynamic-metadata route matchers;
  `weighted_clusters`, `cluster_header`, and cluster specifier plugins;
  virtual-host `matcher` and a non-zero `require_tls`; `vhds`.
- Any `ConfigSource` that is not `ads`.
- Every SDS `Secret`. The profile does not subscribe to SDS at all — workload
  identity and trust anchors come from Ferrum's own SPIFFE/SVID configuration —
  and an unsolicited push closes the ADS stream without sending an SDS request
  (a NACK for an unrequested type would itself subscribe under SotW semantics).
  Each key-bearing variant is refused **by field name without being decoded**,
  so control-plane-delivered private key material is never parsed, stored, or
  logged.

**Bounds.** `FERRUM_MESH_STOCK_XDS_MAX_RESOURCES` (per response, default 10000),
`FERRUM_MESH_STOCK_XDS_MAX_RESOURCE_BYTES` (per resource, default 1 MiB), and
`FERRUM_MESH_STOCK_XDS_MAX_ENDPOINTS` (per cluster, default 4096), plus internal
ceilings on filter chains, virtual hosts, routes, domains, and pinned identities
per cluster. `0` is rejected at startup — a bound of `0` would disable the
fail-closed ceiling, not lift it.

**Declared residuals.** Not driven by a stock control plane through this
profile: VirtualService-equivalent traffic shaping (weighted clusters,
header/regex matching, retries, timeouts, fault injection, mirroring),
DestinationRule subsets and traffic policy, external
`STRICT_DNS` / `LOGICAL_DNS` / `ORIGINAL_DST` clusters (so third-party egress
still needs a local `ServiceEntry`), inbound listener materialization (Ferrum
builds its own inbound routes from the discovered services under the policy
document's enforcement posture, and never from the control plane's inbound
`Listener` resources — see "Inbound identity for a multi-Service pod" below for
the one shape that materializes none), SDS, ECDS/RTDS, and delta xDS. The
decode surface is a field-exact **projection** of the upstream Envoy v3 messages
(`proto/envoy/stock/v3/stock_xds.proto`), not the vendored upstream proto tree;
every field number is taken from Envoy `v1.31.0` and a field that can change
routing, trust, or identity is either consumed or refused.

**Namespace scope.** Discovery is projected onto the typed mesh model first and
narrowed to this workload's namespace view second, exactly like every other
config source. A cluster for a service in ANOTHER namespace is therefore
published by the projection and then narrowed out of the slice, so it is never
dialable here — even when its endpoints are genuinely reachable. Its endpoints
narrow **with** it: when a stock cluster's endpoint carries an identity from
this namespace, the projection records a cross-namespace attachment, and Ferrum
admits such an attachment only together with the `MeshService` that authorizes
it (the target service must list the workload's SPIFFE id). Once narrowing has
removed that service, the endpoint is dropped rather than retained as an
unauthorizable attachment — a slice carrying one would be refused at apply, and
the resulting rollback to the last applied generation would block every LATER
control-plane change, including a state-of-the-world withdrawal, instead of
losing just the out-of-view resource. Shared identity/address endpoints are
projected as **per-service** workload records, so a foreign service that sorts
first in BTree order cannot stamp itself as the owner of a visible service's
endpoint and take that reachability with it when it narrows away.

**Inbound identity for a multi-Service pod.** Those per-service workload records
are also what the local sidecar's own inbound materialization reads, and this
projection has no pod-identity field to populate: a standard EDS endpoint
carries no Kubernetes pod UID, so `Workload.pod_uid` is always unset here.
Sidecar inbound treats several workload records that share the local SPIFFE id
but name different Services as one pod only when every record carries the same
non-empty pod UID, so a local pod a stock control plane publishes under **two or
more Services materializes no inbound routes** on this profile and participates
in egress only. That is deliberate and fail closed: a shared service-account
SPIFFE plus a shared endpoint address cannot distinguish one multi-Service pod
from two distinct pods (hostNetwork pods can share an IP), and guessing would
relay mesh-authorized traffic to the wrong loopback application. A pod backed by
a single Service is unaffected. Where a multi-Service pod must also serve mesh
inbound traffic, drive that workload from native/file config or a Ferrum CP,
which carry `pod_uid`.

A `TcpProxy` filter chain does classify its port as `AppProtocol::Tcp`, but
raw-TCP mesh egress matches captured **original destinations** against the
service VIP (a raw stream carries no `Host`), so a stock-discovered TCP port is
only routable where the platform actually redirects the connection — the same
condition as native/file config. The live matrix below therefore drives HTTP;
raw-TCP egress keeps its coverage in the capture-based mesh suites.

**Live data-path coverage.** `tests/functional/functional_mesh_stock_xds_test.rs`
drives the profile end to end against a **scripted third-party ADS server** (not
Ferrum's own `XdsAdsServer`): the production `stock_xds` client feeds a real
sidecar whose captured plaintext request traverses the materialized egress route
and SVID-mTLS into a second real sidecar and its backend. The same live fixture
proves, on that data path, that an endpoint withdrawal and a state-of-the-world
cluster withdrawal each remove reachability (and a replacement restores it),
that a structurally invalid response is NACKed with a field-specific
`error_detail` while the last-good view keeps serving, that an unpinned-peer or
subset cluster first routes under a representable resource and then loses
reachability after only the refusal-causing field changes, that a
foreign-namespace cluster is ACKed into the applied generation without freezing
a later withdrawal (the namespace itself prevents a same-host representable
pre-state, so that arm is not a before/after reachability proof), that a
listener carrying `envoy.filters.http.rbac` and a route using
`weighted_clusters` are ACKed with field-specific refusal diagnostics while the
accepted service keeps serving (semantic coverage that those constructs
contribute no listener or virtual host lives in the unit/integration suites;
the live phase does not claim a widening proof for a host that was never
dialable), and that re-pinning the peer identity to an impostor SPIFFE fails
the dial closed. It runs in the hosted `data-plane-runtime` functional shard.

#### Transport admission (issue #3853)

The stock profile dials a control plane Ferrum does not own, and the only
credential it ever presents is the external bearer named by
`FERRUM_MESH_STOCK_XDS_TOKEN_FILE`. The **complete** primary/fallback endpoint
set is therefore admitted as ONE security posture at startup, before any socket
exists, and re-checked per endpoint at connect time:

- A configured token file requires `https://` on **every** endpoint, including
  loopback. There is no development carve-out for a bearer.
- `FERRUM_MESH_PRODUCTION_MODE=true` requires TLS on every endpoint whether or
  not a bearer is configured.
- The only remaining plaintext path is `FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT`
  (default off): explicit, loopback-only (`127.0.0.0/8`, `::1`, `localhost`),
  incompatible with a bearer, and refused outright in production mode.
- A **mixed** `https://` + `http://` list is refused as a whole, so failover can
  never select a weaker transport than the primary.
- A missing/ambiguous scheme, an unsupported scheme, a missing host, userinfo,
  a non-root path, and any query component are all refused. The endpoint is an
  origin URL only (`https://host:port`, with an optional trailing `/`); tonic
  supplies the gRPC service path itself.
- Defense in depth: the `authorization` interceptor carries the selected
  endpoint's admitted classification and refuses to attach the bearer to
  anything not classified as authenticated TLS, even if top-level admission were
  bypassed.

Refusals name the endpoint by **index** plus a closed-set scheme and host class.
The configured URL is never echoed into a log line, an error, or a metric.

#### Bearer authorization lifetime (issue #3852)

A stock ADS server typically validates the bearer only at RPC admission, so the client gives every bearer-authenticated stream a finite **local** authorization lifetime:

- **Watcher.** The credential source is re-read every `FERRUM_MESH_STOCK_XDS_TOKEN_WATCH_INTERVAL_SECONDS` through the same hardened, bounded file boundary as the connect path, comparing content (symlink swaps and in-place rewrites are both detected; an unchanged token never churns the stream). At most one blocked reader exists globally, and an older read can never overwrite a newer observation.
- **Rotation and invalidation.** A rotated, removed, empty, non-regular, unreadable, oversized, or non-ASCII source retires the old stream **before** any later discovery update is accepted; an invalid source prevents reconnection (no stale-token fallback).
- **Deadline.** A JWT-shaped token contributes `exp` through a bounded, **non-verifying** decode used only to schedule a reconnect `FERRUM_MESH_STOCK_XDS_TOKEN_REFRESH_SKEW_SECONDS` early (never past `exp`; fractional `exp` is floored). An already expired token, or one with no positive window after the skew, is refused (`token_expired` / `token_expires_within_skew`). An opaque token gets `FERRUM_MESH_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECONDS`, which also caps any JWT-derived deadline. The deadline is absolute from credential **admission** (connect latency spends it), and no application activity extends it.
- **Fence.** The credential fence is checked before any response is admitted, before every install/commit, before the end-of-stream flush, and races the initial ADS RPC-open await, so a control plane that withholds headers cannot outlive rotation, invalidation, or the deadline. A stream retired for any of these discards the discovery and subscription state it produced; only the installed slice survives.
- **Failover** always materializes the newest token and re-proves it is still current before dialing and before opening the RPC; a simultaneous TLS and token rotation produces one retirement and one reconnect.
- **Disclosure.** Outcomes are fixed-cardinality (`token_source_missing`, `token_source_oversized`, `token_expired`, `token_expires_within_skew`, `credential_rotated`, `credential_source_invalid`, `credential_deadline`, …). No token byte, decoded claim, or credential path reaches a log, metric label, or `/health`. Third-party gRPC failures are rendered as canonical codes only (`grpc_unauthenticated`, `grpc_unavailable`, …), transport errors as `connect_failed` / `tls_config_rejected` / `endpoint_uri_invalid`, and CP-authored ADS fields (`type_url`, `version_info`, `nonce`, resource names, NACK text) are omitted from Ferrum logs in favor of closed-set labels, reason codes, counts, and endpoint indexes.

### Configuration-stream attempt and liveness policy

All three configuration-stream consumers — native `MeshSubscribe`, the Ferrum-private ADS profile, and the stock ADS profile — share one attempt/liveness policy (issue #3854). Partial-state semantics stay per protocol; only the *attempt outcome* is shared.

- **Remote clean EOF is an endpoint failure.** A peer that accepts the RPC and hangs up rotates to the next endpoint and grows the bounded, jittered backoff, so an accept-and-close primary cannot pin the data plane while a healthy fallback is never tried. A usable install on the attempt that just ended resets the delay before the next sleep.
- **Intentional local retirement never penalizes the endpoint.** Shutdown, gRPC TLS reload, the three stock credential events (`credential_rotated`, `credential_source_invalid`, `credential_deadline`), and proactive primary failback reconnect immediately without rotating or charging the backoff.
- **Established streams have bounded liveness.** HTTP/2 keepalive plus TCP keepalive detect a half-open or blackholed stream without standard-xDS application frames; such a failure is reported as `established_transport_failure` (an ordinary dial refusal stays `transport_failure`).
- **A mute or incomplete control plane cannot hold startup.** The first-frame clock runs from the RPC-open await to the first response frame (headers do not reset it); the first-slice clock is armed only while this data plane has never installed a slice, so a quiet control plane never tears down a converged proxy. Expired clocks are polled before admitting a ready response.
- **Policy refusal is not transport liveness.** A Ferrum-private ADS stream refused by the revision gate or NACK circuit breaker is `policy_rejected`, not a liveness failure.
- **Partial generations are never published.** An EOF mid-convergence leaves the last good slice serving and fails over.
- **Native heartbeats assist but never extend credential lifetime.** The native application-silence watchdog is armed only after a heartbeat has been observed on that stream and is labelled `heartbeat_silence_timeout`.
- **No awaited work outranks retirement.** Native status reports and ADS outbound enqueues are bounded; stock ADS enqueues are also credential-aware, so a retirement wins over a send.

| Timer | Production value |
|---|---|
| HTTP/2 keepalive PING interval / ack timeout (`keep_alive_while_idle`) | 30 s / 10 s |
| TCP keepalive | 30 s |
| Half-open detection bound (`liveness_bound_seconds`) | ~40 s |
| `first_frame_timeout` | 60 s |
| `first_slice_timeout` (never-converged only) | 120 s |
| Native application-silence watchdog | 150 s |
| Native status report / ADS outbound enqueue bound | 15 s |

**Observability.** `ferrum_mesh_config_stream_attempts_total{protocol,outcome}` counts every completed attempt, and the authenticated `/health` mesh detail carries `config_stream` with `state`, `last_attempt_outcome`, `fallback_active`, `consecutive_failures`, `credential`, and `liveness_bound_seconds` (computed from the timing policy actually running). Every value is a closed set or a counter — no endpoint URL, host, node id, credential path, token, or claim.

| `config_stream.state` | Meaning |
|---|---|
| `connected` | An RPC stream is established, usable configuration exists, and no sticky liveness failure is outstanding. Installing usable state on that stream resets `consecutive_failures` and clears `stream_liveness_failed` (an intentional local retirement does not reset the counter). |
| `stream_liveness_failed` | An established stream stopped being usable (first-frame, first-slice, heartbeat-silence, or established-transport failure). Outranks `connected` and `never_received_slice`, and stays sticky until a stream installs usable state. |
| `never_received_slice` | Startup has never completed and no liveness bound has been hit. |
| `serving_last_good` | A previously installed slice keeps serving while the stream is down or reconnecting for an ordinary, non-liveness reason. |

`fallback_active` is true only while a stream is actually established on a non-primary endpoint. `credential` distinguishes `not_configured` (no token file) from `unobserved` (configured but not yet read).

#### Ferrum mesh-slice ECDS carriers (full parity over xDS)

The name-only CDS/EDS/LDS/RDS resources Ferrum exchanges round-trip service-port discovery only. Every security- and policy-bearing slice field plus the effective workload labels used for selector matching — authorization policies, PeerAuthentication mTLS posture, RequestAuthentication/JWT rules, full ServiceEntry shape, SPIFFE trust bundles, ProxyConfig, VirtualService L4 proxies, per-pod workloads, MeshService protocol/workload-ref shape, telemetry resources, multi-cluster config, sidecar egress-scope metadata, and mesh-wide outbound traffic policy — rides the ECDS stream as a **Ferrum mesh-slice carrier**. Without these carriers, `FERRUM_MESH_CONFIG_PROTOCOL=xds` would produce an **unprotected or incomplete mesh**: the DP would rebuild the slice with those fields emptied or contextless (no authz → implicit allow-all; no PeerAuthentication → Permissive on every port; no trust bundles → no inbound mTLS authority material; no effective labels → selector-scoped policy stops matching; no L4 proxies → translated VirtualService TCP/TLS routes disappear).

This is the same mechanism as the [DestinationRule carrier](#ecds-destinationrule-carrier-full-dr-semantics-over-xds): each non-empty slice field group is JSON-serialized and wrapped in a standard `envoy.config.core.v3.TypedExtensionConfig` whose **inner** `type_url` is a Ferrum-specific marker under `type.googleapis.com/ferrum.config.extension.v3.*`. The single source of truth for the markers and their encode/decode is `src/xds/carrier.rs` (`MeshSliceCarrier`); the CP emits them in `translate_mesh_slice_carriers` (`src/xds/translator.rs`) and the DP decodes them in `reverse_translate` (`src/modes/mesh/config_consumer/xds_client.rs`).

| Slice field | Inner `type_url` (suffix after `type.googleapis.com/ferrum.config.extension.v3.`) | ECDS resource name |
| --- | --- | --- |
| `services` (full `MeshService`) | `ServicesCarrier` | `ferrum-mesh-carrier/services` |
| `workloads` (per-pod endpoints) | `WorkloadsCarrier` | `ferrum-mesh-carrier/workloads` |
| `labels` (effective workload labels) | `WorkloadLabelsCarrier` | `ferrum-mesh-carrier/workload-labels` |
| `labels_ambiguous` (shared-SPIFFE intersection marker) | `WorkloadLabelsAmbiguousCarrier` | `ferrum-mesh-carrier/workload-labels-ambiguous` |
| `virtual_service_l4_proxies` | `VirtualServiceL4ProxiesCarrier` | `ferrum-mesh-carrier/virtual-service-l4-proxies` |
| `virtual_service_l4_upstreams` | `VirtualServiceL4UpstreamsCarrier` | `ferrum-mesh-carrier/virtual-service-l4-upstreams` |
| `mesh_policies` (authz) | `MeshPoliciesCarrier` | `ferrum-mesh-carrier/mesh-policies` |
| `virtual_service_cors_policies` | `VirtualServiceCorsPoliciesCarrier` | `ferrum-mesh-carrier/virtual-service-cors-policies` |
| `istio_root_namespace` (DR lookup tier 3) | `IstioRootNamespaceCarrier` | `ferrum-mesh-carrier/istio-root-namespace` |
| `peer_authentications` | `PeerAuthenticationsCarrier` | `ferrum-mesh-carrier/peer-authentications` |
| `request_authentications` (JWT) | `RequestAuthenticationsCarrier` | `ferrum-mesh-carrier/request-authentications` |
| `service_entries` (full shape) | `ServiceEntriesCarrier` | `ferrum-mesh-carrier/service-entries` |
| `telemetry_resources` | `TelemetryResourcesCarrier` | `ferrum-mesh-carrier/telemetry-resources` |
| `proxy_configs` | `ProxyConfigsCarrier` | `ferrum-mesh-carrier/proxy-configs` |
| `trust_bundles` (SPIFFE) | `TrustBundlesCarrier` | `ferrum-mesh-carrier/trust-bundles` |
| `outbound_traffic_policy` | `OutboundTrafficPolicyCarrier` | `ferrum-mesh-carrier/outbound-traffic-policy` |
| `sidecar_outbound_traffic_policy` | `SidecarOutboundTrafficPolicyCarrier` | `ferrum-mesh-carrier/sidecar-outbound-traffic-policy` |
| `multi_cluster` | `MultiClusterCarrier` | `ferrum-mesh-carrier/multi-cluster` |
| `sidecar_egress_scope` | `SidecarEgressScopeCarrier` | `ferrum-mesh-carrier/sidecar-egress-scope` |
| `waypoint_gateway_class` (ServiceWaypoint GatewayClass stamp) | `WaypointGatewayClassCarrier` | `ferrum-mesh-carrier/waypoint-gateway-class` |
| `service_waypoint_bound_services` (ServiceWaypoint exact bound-service refs) | `ServiceWaypointBoundServicesCarrier` | `ferrum-mesh-carrier/service-waypoint-bound-services` |
| `local_inbound_services` (inbound-only view of the local workload's services) | `LocalInboundServicesCarrier` | `ferrum-mesh-carrier/local-inbound-services` |
| `local_inbound_workloads` (inbound-only view of the local workloads) | `LocalInboundWorkloadsCarrier` | `ferrum-mesh-carrier/local-inbound-workloads` |
| `local_ingress_listeners` (resolved Sidecar `ingress[]` listeners) | `LocalIngressListenersCarrier` | `ferrum-mesh-carrier/local-ingress-listeners` |
| `sidecar_ingress_declared` (fail-closed "ingress declared" marker) | `SidecarIngressDeclaredCarrier` | `ferrum-mesh-carrier/sidecar-ingress-declared` |
| `declared_ingress_http_ports` (declared HTTP-family `ingress[]` port count) | `SidecarIngressDeclaredPortsCarrier` | `ferrum-mesh-carrier/sidecar-ingress-declared-ports` |
| `revision` (authoritative config revision) | `ConfigRevisionCarrier` | `ferrum-mesh-carrier/config-revision` |
| `ambient_udp_source_workloads` (Ambient UDP source-evidence inventory) | `AmbientUdpSourceWorkloadsCarrier` | `ferrum-mesh-carrier/ambient-udp-source-workloads` |
| `node_waypoint_assertors` (exact NodeWaypoint assertor SPIFFE inventory) | `NodeWaypointAssertorsCarrier` | `ferrum-mesh-carrier/node-waypoint-assertors` |
| `node_waypoint_capture_destinations` (NodeWaypoint capture-only destination inventory) | `NodeWaypointCaptureDestinationsCarrier` | `ferrum-mesh-carrier/node-waypoint-capture-destinations` |
| `node_waypoint_capture_peer_authentications` | `NodeWaypointCapturePeerAuthenticationsCarrier` | `ferrum-mesh-carrier/node-waypoint-capture-peer-authentications` |
| `node_waypoint_capture_mesh_policies` (presence is completeness evidence) | `NodeWaypointCaptureMeshPoliciesCarrier` | `ferrum-mesh-carrier/node-waypoint-capture-mesh-policies` |
| `ext_authz_providers` (CUSTOM authorization providers) | `ExtAuthzProvidersCarrier` | `ferrum-mesh-carrier/ext-authz-providers` |

`waypoint_gateway_class` is emitted only for ServiceWaypoint slices with a known `Gateway.spec.gatewayClassName`. The DP reconstructs it before `mesh_authz` cold-path retain so GatewayClass `targetRefs` exact-match fail closed over xDS: malformed, oversized, or duplicate carriers reject the ECDS response, and a missing or removed carrier never reuses a stale class. A missing carrier is not merely "no class": if the slice also carries an **enforcing** (`ALLOW`/`DENY`) GatewayClass-targeted policy, that combination is incoherent and `reverse_translate` rejects the response so the DP keeps its last-good slice — silently dropping the policy would turn a DENY (or an ALLOW policy's implicit deny) into allow-by-default. `MeshAuthz::new` repeats the same refusal for the native/file/embedded sources. `AUDIT`-only policies are non-enforcing and stay exempt.

`service_waypoint_bound_services` is emitted only when the slice stamped a non-empty service-terminating GAMMA binding (`waypoint_for=service` or `all`). Absence (an older CP, a missing Gateway, `waypoint_for=workload`/`none`/blank/unknown, or an empty binding) is empty evidence: the inbound HBONE relay inventory is empty rather than treating the (possibly fail-open) `services` view as a binding. Malformed or oversized carriers reject the ECDS response.

**Behavior and fail-closed.** The CP always emits these alongside CDS/EDS (no env var gate), and the DP waits for the initial ECDS response before building a slice so startup cannot briefly apply the name-only, unprotected view. On the DP, a mesh-slice carrier must have both the reserved ECDS resource name and the matching inner `type_url`: a recognized pair overwrites the corresponding slice field; an unrecognized inner type (the DR carrier, or an operator's own extension config) is skipped; a reserved inner type under any other resource name NACKs the whole ECDS response (the DP keeps its last accepted slice, and the diagnostic names only the closed-schema carrier type, never the resource name) so operator-defined ECDS configs cannot impersonate security/policy carriers. A recognized carrier whose JSON fails to parse is FAIL-CLOSED: `MeshSliceCarrier::decode` returns `Err`, `recover_slice_carriers` propagates it, and the DP NACKs the entire ECDS response and retains the previous accepted slice — it does NOT skip the malformed carrier and continue with a partially populated slice. CDS/EDS service-port discovery still runs; the DP **prefers** the full `services`/`service_entries` recovered from carriers and falls back to the name-only CDS/EDS reconstruction only when no slice carrier is present at all (e.g. an internal Ferrum-shaped test CP with no carrier support). Empty `Vec`/`None` field groups emit no carrier, so "absent" and "empty" are indistinguishable on the DP — matching native, where an empty list and an absent list are equivalent. Exceptions whose presence is evidence are emitted even when empty: `WorkloadLabelsCarrier` (unconditionally — empty labels are meaningful selector context and must override any local DP labels during xDS recovery), `LocalInboundWorkloadsCarrier` (whenever the local-inbound view is `Some`, including an empty list), and `NodeWaypointCaptureMeshPoliciesCarrier` (whenever the capture policy inventory was resolved, including an empty list). `src/xds/carrier.rs` is the source of truth for the carrier set; `tests/conformance/xds_type_urls.rs` is representative conformance coverage, not an exhaustive inventory. **Ambiguous shared-SPIFFE labels are a counter-exception:** when several workloads share one SPIFFE id with **divergent** label sets and the slice request carried no explicit labels, the CP can only compute the label **intersection** (which loses information), while selector-scoped policies (authz / PeerAuthentication / RequestAuthentication / Telemetry) ride in as a **candidate-any superset** (kept if they match *any* candidate). The CP flags this by emitting `WorkloadLabelsAmbiguousCarrier`. (The common replica/endpoints case — many records for one SPIFFE with **identical** labels — is *not* flagged: the intersection equals each set and is authoritative, so the DP keeps trusting the carrier instead of preferring possibly-stale local labels.) On recovery the DP treats a flagged intersection as **non-authoritative** and prefers its own `FERRUM_MESH_WORKLOAD_LABELS` so it re-filters the superset against its real identity. Without this, a non-empty intersection (e.g. two pods sharing `app=shared` where only one has `role=api`) would replace the DP's real labels and silently drop every candidate-only selector policy — a fail-open for selector mTLS/JWT/authz whenever the intersection is non-empty. If the DP has no local labels either, it keeps the (informational) intersection. The marker is cleared on the recovered slice once the DP has resolved its authoritative labels. Operator-defined `MeshExtensionConfig` entries whose inner `type_url` is one of the mesh-slice carrier markers (or the DestinationRule carrier type) are rejected by mesh config validation, naming the entry; entries whose names start with `ferrum-mesh-carrier/` are skipped by the Ferrum CP for the same reason.

**Visibility is re-enforced at the fold, not assumed.** A carrier is raw producer input that never passed this DP's slice admission, so the two `exportTo`-bearing client-side policy carriers are gated on recovery: a `VirtualServiceCorsPoliciesCarrier` entry not exported to the DP's workload namespace is dropped (bounded `warn!` with a count only — never the carrier-supplied host, name, or `exportTo` value), exactly as a `DestinationRule` carrier's `exportTo` is enforced at materialization. Visibility LISTS themselves are validated at the ACK boundary on both carrier families — every reserved DestinationRule carrier and every `VirtualServiceCorsPoliciesCarrier` entry runs the shared `validate_mesh_export_to` before the response is ACKed, so an unsupported or self-conflicting list NACKs and the accumulator rolls back to the last accepted state instead of being ACKed and discovered inert later. Those rejection diagnostics name the carrier field and the offending INDEX, are capped at eight per rejected carrier, and never echo the carrier-supplied value. Both are then re-checked once more at materialization. `exportTo` entries on the DR, ServiceEntry, and VirtualService-CORS carriers are also canonicalized (trimmed) at decode: the shared visibility evaluator deliberately never reinterprets padded input, and ACK-time validation checks a trimmed copy, so an un-normalized `[" beta "]` would otherwise be accepted and then match nothing.

**Interop boundary.** A stock Envoy or third-party Istio control plane does not emit these inner type URLs or Ferrum-shaped resource names, so it cannot drive a protected Ferrum mesh over xDS. The carrier format is a Ferrum-to-Ferrum wire convention layered on the standard ECDS transport; it is **not** an interoperable third-party xDS extension. For full DR/policy parity, run a Ferrum CP (either protocol works) or use `FERRUM_MESH_CONFIG_PROTOCOL=native`.

**Test pin.** `xds_round_trip_preserves_protected_slice_fields()` in `src/modes/mesh/config_consumer/xds_client.rs` drives the real CP-encode → ECDS-on-the-wire → DP-decode path for a representative protected slice (authz + PeerAuthentication + ServiceEntry + trust bundle + JWT + ProxyConfig + VirtualService L4 proxy + workloads) and asserts the recovered slice equals the native one field-for-field, including resolved mTLS posture. `tests/conformance/xds_type_urls.rs` pins representative carrier type URLs.

#### ECDS DestinationRule carrier (full DR semantics over xDS)

Standard CDS/EDS bakes a `DestinationRule`'s traffic policy (LB algorithm, outlier detection, connection pool, per-subset TLS, subsets) into the Envoy `Cluster` resource at the CP, which means the original DR is unrecoverable from CDS/EDS alone. The ECDS DestinationRule carrier preserves the normalized Ferrum DR model as JSON inside a standard ECDS `TypedExtensionConfig` resource so the Ferrum DP can rebuild the full `MeshDestinationRule` server-side. This is a Ferrum-specific carrier convention layered on top of the standard ECDS resource type — it uses the standard ECDS transport (`type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig`) but a Ferrum-defined inner type URL, so it coexists with unrelated ECDS consumers on the same ADS stream.

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
    name         = "ferrum-destination-rule-carrier/<namespace>/<dr-name>"
    typed_config = Any {
      type_url = "type.googleapis.com/ferrum.config.extension.v3.DestinationRuleCarrier"
      value    = <raw bytes of the normalized MeshDestinationRule JSON>
    }
  }
```

The inner `value` is the normalized DR model as UTF-8 JSON bytes — there is no protobuf wire encoding of the DR itself, just `serde_json` over the `MeshDestinationRule` shape consumed by the DP at `src/modes/mesh/config_consumer/xds_client.rs` (see `dr_carrier_resource()` and the recovery loop). Normalization includes host canonicalization and trimming accepted `export_to` entries before slice comparison and carrier serialization. The DP iterates ECDS resources, decodes each `TypedExtensionConfig`, and applies one of these behaviors per inner payload:

- The resource name uses the reserved
  `ferrum-destination-rule-carrier/<namespace>/<name>` shape, the inner
  `type_url` matches the carrier constant, the embedded namespace/name agree
  with the reserved name, and JSON parses cleanly: the recovered
  `MeshDestinationRule` is appended to `slice.destination_rules`.
- Inner `type_url` is anything else: silently skipped (belongs to an unrelated ECDS consumer).
- A reserved carrier with a missing/wrong inner type, mismatched embedded
  identity, malformed JSON, or invalid `export_to` is rejected by the ECDS
  accumulator and NACKs the response. Remaining semantic validation runs at
  materialization and rejects the candidate slice. In both cases the
  previously applied proxy generation remains live.
- A resource that declares the DR inner type under any name other than the
  reserved `ferrum-destination-rule-carrier/<namespace>/<name>` shape is
  rejected and NACKs the response: only the reserved carrier is a
  DestinationRule. Ferrum CP emits only that shape. Mesh config validation
  rejects any operator `mesh.extension_configs` entry that declares the DR
  inner type, naming the entry, so the mistake surfaces at startup or
  admission instead of on every data plane.
- The same holds for the mesh-slice carriers: a resource that declares a
  slice-carrier inner type under any name other than that carrier's reserved
  `ferrum-mesh-carrier/…` name NACKs the response rather than being skipped.

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
  "name": "ferrum-destination-rule-carrier/default/api-dr",
  "typed_config": {
    "type_url": "type.googleapis.com/ferrum.config.extension.v3.DestinationRuleCarrier",
    "value": "<UTF-8 bytes of the MeshDestinationRule JSON below>"
  }
}
```

with the inner `value` bytes carrying the normalized DR as `MeshDestinationRule` JSON (note: the inner shape is the Ferrum `MeshDestinationRule` serde representation, not the Istio CRD YAML — Istio's nested `connectionPool.tcp.connectTimeout` flattens to `traffic_policy.connect_timeout_ms` in milliseconds, `outlierDetection.consecutive5xxErrors` → `outlier_detection.consecutive_errors`, `outlierDetection.interval` (a duration string) → `outlier_detection.interval_seconds` (a `u64`), and `tls.mode` values are lowercase `snake_case` (`istio_mutual`, `simple`, `mutual`, `disable`) per `MtlsMode`):

```json
{
  "name": "api-dr",
  "namespace": "default",
  "host": "api.default.svc.cluster.local",
  "export_to": ["*"],
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

**Emission and the per-slice diagnostic.** Ferrum CP always emits one reserved
carrier for every DestinationRule already admitted to that node's slice; there
is no feature flag. The DP always subscribes to ECDS. A Ferrum-shaped CP that
emits only CDS/EDS remains routable in the documented degraded mode, but full DestinationRule semantics are unavailable. When the DP
receives CDS clusters with zero DR-carrier ECDS resources, it emits a one-line
`debug!` per slice apply listing the fields that cannot be round-tripped from
CDS/EDS alone (`connectTimeout`, `loadBalancer`, `outlierDetection`, `subsets`,
`tls.sni`, `tls.subjectAltNames`, `tls.mode`, `exportTo`); see the diagnostic
guarded by `!dr_carrier_seen && !accumulator.resources(CDS_TYPE_URL).is_empty()`
in `src/modes/mesh/config_consumer/xds_client.rs`.

**Other notes.**

- Configuration: no `FERRUM_MESH_*` env var gates the carrier path. Ferrum CP
  emits it and the DP recognizes it whenever
  `FERRUM_MESH_CONFIG_PROTOCOL=xds`.
- Test pin: `ecds_dr_carrier_payload_recovers_destination_rule()` in `src/modes/mesh/config_consumer/xds_client.rs` round-trips the envelope and asserts that `traffic_policy.load_balancer` survives — i.e. fields baked out by a CDS-only path are recovered.

### Localized file source (no control plane)

`FERRUM_MESH_CONFIG_PROTOCOL=file` runs a mesh data plane with **no control plane at all** — the slice is built locally from a YAML/JSON document at `FERRUM_MESH_FILE_CONFIG_PATH`. This mirrors the gateway's database-vs-file duality for the mesh (cf. Kuma's universal mode): the same `MeshSlice::from_gateway_config` materialization the CP runs is executed DP-side, so authz / PeerAuthentication / JWT / ServiceEntry / DestinationRule / trust-bundle semantics are structurally identical to a CP-delivered slice.

- **Document shape**: an optional `version` stamp (must equal the current config schema version when present) plus the `mesh` section only — `workloads`, `services`, `mesh_policies`, `peer_authentications`, `service_entries`, `request_authentications`, `telemetry_resources`, `destination_rules`, `proxy_configs`, `sidecars`, `trust_bundles`, `multi_cluster`, `outbound_traffic_policy`. Gateway resources (`proxies:`, `upstreams:`, `consumers:`, `plugin_configs:`) are **rejected** at parse — mesh mode materializes its routes from the slice; plain gateway routes belong to `FERRUM_MODE=file`.
- **Startup is fail-closed**: a missing, unparsable, non-regular, oversized (>64 MiB), unstable, or mesh-invalid document refuses startup, matching file-mode validation semantics. Initial load and SIGHUP reload both use the shared bounded stable-file primitive (opened-target regular-file check, Unix `O_NONBLOCK`, streaming `limit + 1`, byte-identical dual read spanning a 20ms settle interval) on `spawn_blocking` so Tokio core workers stay free. **Format is selected from the file extension only — there is no content sniffing and no JSON fallback.** Format selection itself does not parse the document: `.json` selects the JSON parser; `.yaml`, `.yml`, and every unknown or extensionless path select YAML. YAML is a superset of JSON, so an unknown-extension path holding an ordinary JSON document still loads; but the parser genuinely is YAML, so a JSON-only shape YAML rejects (for example a mapping key past libyaml's 1024-byte simple-key limit) fails closed rather than falling back to the JSON parser. Give JSON documents a `.json` extension. Before `serde_yaml` materializes YAML, Ferrum runs a bounded, borrowed-input libyaml event preflight over the complete stream, capped at 1,000,000 events per pass. Alias-bearing documents receive a second composition/traversal pass, additionally capped at 500,000 composed nodes, 500,000 expanded value nodes, 500,000 followed aliases, 128 nesting levels, and 64 MiB of expanded scalar-plus-tag payload bytes. All phases share one 2,000,000-unit cumulative work ceiling. The expansion ceiling deliberately matches the 64 MiB read ceiling. Limit breaches and malformed/unsupported/multi-document alias streams fail closed with fixed content-free diagnostics.
- **Reload**: SIGHUP (Unix; `ferrum-edge reload`). Rapid signals are coalesced (one in-flight generation plus at most one follow-up). The requested generation advances when the signal is observed, so an older completed load cannot install before a follow-up. A failed reload (read/parse/validation/join/apply rejection) logs a warning, keeps the last good slice, and raises the shared authenticated `/health` `config_rejected` degraded signal until the proxy apply lifecycle accepts the exact current recovery candidate (Applied, or a content-identical no-op) — a provisional `install_slice` alone never clears it. Every recovery transition (cancel, new candidate, policy-identity bind, proxy accept, proxy reject) is serialized by one transition lock together with the `config_rejected` write, so an older callback can neither clear health after a newer failure nor cancel a newer pending recovery. Last-good retention is identical to CP consumers, with operator-visible degraded status. Watcher shutdown stops accepting candidates immediately, and a late completion cannot publish. Reload is signal-driven only; there is no file watcher or poll timer. Non-Unix platforms load once and require a restart.
- **Not required / not consumed**: `FERRUM_DP_CP_GRPC_URLS`, `FERRUM_CP_DP_GRPC_JWT_SECRET`, DP gRPC TLS vars. Everything else (topology, SVID material, PeerAuthentication posture, plugin injection, slice scoping via `FERRUM_MESH_WORKLOAD_SPIFFE_ID` / `FERRUM_MESH_WORKLOAD_LABELS` / Sidecar egress enforcement) behaves exactly as under native/xDS.
- **`ferrum-edge validate`**: `validate -m mesh -c slice.yaml` validates this document without Ferrum CP URLs or JWT when protocol is `file` or is inferred from the localized `{version?, mesh}` shape. `-c/--spec` supplies `FERRUM_MESH_FILE_CONFIG_PATH` for that check and does not change `run`. Explicit `native`/`xds` plus a localized slice spec, or distinct `--spec` and `FERRUM_MESH_FILE_CONFIG_PATH` values, fail closed. Identity/CA environment is still required. The report prints the active `FERRUM_NAMESPACE` and post-filter workload / service / policy counts. When the document contains namespaced resources and none survive namespace scoping, `validate` fails closed (exit 1) unless `--allow-empty-namespace` is set. An empty `mesh: {}` document is not a mismatch.
- **Observability caveat**: there is no CP heartbeat, so `/mesh/config-drift` slice age is measured from the last successfully proxy-applied slice. A SIGHUP or failed reload attempt alone does not advance that timestamp; staleness does not establish a sync failure.

### Bootstrap Behavior

All config sources share the same startup contract:

1. The mesh data plane waits for an initial valid slice before serving traffic (the file source loads it off-thread and refuses startup on error).
2. Valid updates are applied atomically via `ArcSwap`.
3. Invalid updates are logged and ignored; the last accepted configuration continues serving. Localized file / stock-xDS policy reload failures also raise authenticated `/health` `config_rejected` until a later accepted reload.
4. On config source unavailability, the gateway keeps serving cached configuration (resilience principle).

## Mesh Data Model

The mesh data model lives in `src/modes/mesh/config.rs`. Namespaced resource types carry `namespace` for scope isolation, and optional fields commonly use `#[serde(default)]`; structural types such as `TrustBundleSet` and `MultiClusterConfig` are not namespace-owned rows, and some fields (for example `MeshRule.action`) are required. `GatewayConfig.mesh` is optional and omitted when absent, preserving the non-mesh representation.

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

Logical service grouping workloads by SPIFFE ID reference. `cluster_ips`
(optional) carries the service's virtual IPs — Kubernetes `spec.clusterIPs`,
populated automatically by the K8s translator — and is what raw-TCP egress
matches captured original destinations against (see the raw-TCP egress bullet
in the Sidecar/Ambient section); HTTP-family routing never consults it, and
headless services simply omit it.

`allow_path_parameters` (optional, default `false`) opts the service in to
RFC 3986 path parameters such as `;jsessionid=`. It sets
`allow_path_parameters: true` on every HTTP-family route mesh mode materialises
for the service: the outbound routes each client builds to it, its Sidecar
inbound routes, and the Sidecar `ingress[]` routes it owns. The Kubernetes
translator sets it from the Service annotation
`ferrum.io/allow-path-parameters: "true"`. Without it, a `;` request to the
service is refused with `400 path_parameter`. See
[Path parameters and the per-service opt-in](#path-parameters-and-the-per-service-opt-in).

```yaml
name: "my-service"
namespace: "default"
ports:
  - port: 8080
    protocol: http
workloads:
  - spiffe_id: "spiffe://cluster.local/ns/default/sa/my-service"
cluster_ips: ["10.96.0.10"]
# allow_path_parameters: true   # forward /app/page;jsessionid=abc (default false)
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

**The authorization grammar is closed, and `action` is required.** Every level
of the policy document — the policy, its `scope` (including `kind: mesh_wide`)
and each `targetRefs` attachment, each rule, its `custom` action object, and
each `from` / `to` / `when` / `source_negation` matcher — rejects unknown members at
admission, on the native/file mesh document and on a direct `mesh_authz`
plugin config alike. This is not tidiness: every misspelling in this grammar
*removes* a restriction the operator wrote. `not_paths` typed `not_path` would
deserialize as an unconstrained rule, and an `action` key typed `actoin` would
fall back to an `Allow` default and silently turn a DENY into a grant. `action`
therefore has no default on the wire — write it on every rule. Omitted optional matchers keep their documented empty defaults
(an omitted `to` still means "any request"), and an explicitly empty
`rules: []` remains a valid scaffold; only an *unrecognized* member or a
missing `action` is refused. Kubernetes and xDS translation build these values
programmatically and are unaffected.

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

Per-workload mTLS mode with optional per-port overrides. The object is closed (issue #6616): an unknown member is rejected, because a misspelled `mtls_mode` would otherwise default the policy to `PERMISSIVE`.

### MeshRequestAuthentication

Declares valid JWTs for a workload scope. Permissive by default (see [RequestAuthentication](#requestauthentication)). The resource and its `jwt_rules`, `from_headers`, and `output_claim_to_headers` entries are closed (issue #6616), so a misspelled `refused` or `jwt_rules` cannot drop a refusal or a token requirement.

All applicable resources for a workload are combined into one `jwks_auth` instance, and identical rules are installed once. That instance is subject to the `jwks_auth` per-token verification bound: at most 64 rules in total, and at most 8 rules sharing one issuer. A combination past the bound fails plugin construction, so the data plane keeps its last accepted configuration rather than dropping any rule or its extraction locations.

### MeshTelemetryResource

Per-scope telemetry configuration for tracing, metrics, and access logging (see [Observability](#observability)). The whole document is closed (issue #6616): the resource, its `config`, the `tracing` / `metrics` / `access_logging` sections, each tracing provider envelope and its `config`, each `tag_overrides` entry and its `operation` (including `type: remove`), and the access-log `filter` reject unknown members, so a misspelled key cannot silently drop the setting it names.

### MeshProxyConfig (Istio ProxyConfig)

Maps an Istio `ProxyConfig` (`networking.istio.io/v1beta1`) onto a config-time, read-only data structure consumed by the mesh runtime at slice-apply time. Concurrency, image, and environment fields are informational; `tracing_sampling` is consumed by the injected `workload_metrics` plugin to set request trace-sampling metadata. This does not live-reconfigure worker counts or the process environment. Standard Istio CRD pruning and native/file/xDS input differences still apply.

```yaml
name: "api-defaults"
namespace: "default"
scope:                  # resolved from spec.selector + Istio root-namespace rule
  kind: workload_selector
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
| `spec.selector` + root-namespace rule | `scope` ([`PolicyScope`](#policyscope-filtering)) | See "Scope resolution" below — same semantics as Telemetry / PeerAuthentication |
| `spec.concurrency` | `concurrency` | Informational; rejected as `InvalidResource` if it does not fit in `u32` |
| `spec.image.imageType` | `image` | Informational; surfaced to operator tooling |
| `spec.environmentVariables` | `environment` | Informational; surfaced to operator tooling |
| `spec.tracing.sampling` | `tracing_sampling` | **Ferrum mesh-model extension, not an Istio CRD field.** Istio's `networking.istio.io/v1beta1` ProxyConfig CRD has a structural spec schema whose only properties are `selector`, `concurrency`, `image`, and `environmentVariables`, so a `spec.tracing.sampling` applied with `kubectl` is pruned by the Kubernetes API server and never reaches the watcher — supply it over native `MeshSubscribe` / file / xDS mesh config. Percentage 0-100; merged into the injected `workload_metrics` plugin's `sampling_percentage`. Where it is reachable it fails closed like `Telemetry.tracing.randomSamplingPercentage`: a non-numeric or out-of-range value is rejected as `InvalidResource` (`FerrumAccepted=False`/`Invalid`) rather than silently dropped |

**Scope resolution**: ProxyConfig honors the same Istio root-namespace + selector rules used by `Telemetry`, `RequestAuthentication`, and `PeerAuthentication`. The K8s translator routes through the shared `istio_policy_scope` helper, so [`scope`](../src/modes/mesh/config.rs) ends up as:

- `MeshWide` — resource in the Istio root namespace (`FERRUM_K8S_ISTIO_ROOT_NAMESPACE`, default `istio-system`) with no selector. Applies to every workload in the mesh.
- `WorkloadSelector { namespace: None, labels: ... }` — resource in the Istio root namespace with a selector. Applies to matching workloads across all namespaces.
- `Namespace { namespace }` — resource in any other namespace with no selector. Applies to all workloads in that namespace.
- `WorkloadSelector { namespace: Some(ns), labels: ... }` — resource in any other namespace with a selector. Applies to matching workloads in that namespace.

Within the resolved slice, [`MeshSlice::resolved_proxy_config()`](../src/modes/mesh/slice.rs) returns the most-specific applicable entry:

1. `WorkloadSelector` > `Namespace` > `MeshWide`.
2. Among same-tier matches, the ASCII-smallest `name` wins (deterministic tiebreaker mirroring the accumulator's `(namespace, name)` sort).

**`tracing.sampling` merge with `Telemetry`**: ProxyConfig `tracing_sampling` is applied first as a baseline, then `Telemetry.tracing.randomSamplingPercentage` overrides on the same `sampling_percentage` key when both are present. The more granular Telemetry API wins because it can be per-section scoped; ProxyConfig provides a per-workload-config-level default.

**Transport**: ProxyConfig is not a stock Envoy/Istio xDS resource. On Ferrum-to-Ferrum xDS it rides the dedicated ECDS `ProxyConfigsCarrier` (`ferrum-mesh-carrier/proxy-configs`) with the same slice semantics as native `MeshSubscribe` (pinned by `xds_round_trip_preserves_protected_slice_fields`). Stock Envoy/third-party Istio CPs do not emit that carrier. The Kubernetes controller watches served `networking.istio.io/v1beta1` `ProxyConfig` CRDs via `ISTIO_CRDS` (configured namespaces plus the Istio root namespace, same last-known-good/relist path as other Istio CRDs) and writes `FerrumAccepted` status — Istio's `proxyconfigs.networking.istio.io` CRD declares `subresources.status`. Only the four fields Istio's structural spec schema admits — `selector`, `concurrency`, `image.imageType`, `environmentVariables` — can arrive over that watcher; `tracing_sampling` has no CRD counterpart (the API server prunes `spec.tracing`) and must come from native/file/xDS mesh config, so cluster-sourced ProxyConfigs report `tracing.sampling: <unset>` in their `FerrumAccepted` detail. See [Istio CRD capability dimensions](configuration.md#istio-crd-capability-dimensions).

### TrustBundleSet

Local and federated X.509/JWT authority bundles for cross-cluster trust.

### MultiClusterConfig

Multi-cluster settings: local cluster identity, remote clusters, east-west gateways, and SPIFFE federation endpoints. The object and its `remote_clusters` / `east_west_gateways` entries are closed (issue #6616): an unknown member is rejected, because a misspelled `local_cluster` would leave it unset and change which endpoints destination policy scopes treat as local.

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
  load_balancer: !consistent_hash
    http_header_name: "x-user-id"
subsets:
  - name: "v1"
    labels:
      version: "v1"
```

The YAML file form uses `serde_yaml`'s externally tagged enum syntax for
`load_balancer`: `!consistent_hash` for a hash policy and
`!simple ROUND_ROBIN` (or another supported simple algorithm) for a simple
policy. JSON and native carrier representations continue to use their normal
externally tagged object form.

**Host matching**: the DR `host` is matched against upstream targets, the upstream `name`, and the upstream `id`. Short hostnames are namespace-completed (`reviews` ⇒ `reviews.{namespace}.svc.*`); namespaced (`reviews.ns`) and `.svc`-suffixed forms are also supported. A short host resolves in the RULE's own namespace, so a cross-namespace rule must use the FQDN form.

#### DestinationRule visibility and lookup

**Export visibility (`exportTo`)** — issue #2465. A DestinationRule is a candidate only for the namespaces it is exported to. Supported values:

| `exportTo` value | Visibility |
|---|---|
| omitted / `[]` on a **Kubernetes** source | Istio's public default — translated into an explicit `["*"]` |
| omitted / `[]` on a **native / file / xDS carrier** source | **Namespace-local** (fail closed by omission, the same convention `ServiceEntry.export_to` and `virtual_service_cors_policies[].export_to` already use). Write `["*"]` to publish a rule mesh-wide on those sources. |
| `["."]` | Only the namespace that declares the rule |
| `["*"]` | Every namespace in the mesh |
| `["alpha", "gamma"]` | Only the listed namespaces |

Any other token — including Istio's `~`, an empty entry, a non-RFC-1123 namespace name, a list over 64 entries, or `*` combined with an explicit namespace — is **rejected**, not interpreted: Kubernetes translation reports `FerrumAccepted=False`/`Invalid` and native/file/xDS slice validation rejects the config so the previously accepted slice stays live. Diagnostics name the field and the offending index and never echo the operator-supplied value.

`exportTo` visibility is evaluated during slice construction, BEFORE lookup selection and before a per-node slice is serialized, so a namespace-local rule never reaches — let alone affects — a subscriber outside its declared visibility. The DP defensively runs the same export-visibility evaluator again before materialization lookup, so a cross-wired or independently implemented native/xDS producer cannot bypass that boundary by sending an already-built slice. DestinationRule lookup also has a separate client/proven-owner/root eligibility tier; the shared visibility evaluator does not by itself establish parity for that owner-tier decision.

**VirtualService-derived CORS policy uses the shared export-visibility evaluator.** `virtual_service_cors_policies[].export_to` is host-targeting client-side traffic policy, so its visibility is checked during CP slice narrowing, the xDS carrier fold on the DP (see [mesh-slice carriers](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds)), and outbound `cors` plugin synthesis. This establishes export-visibility checks at those stages; it does not apply DestinationRule's separate client/proven-owner/root lookup tier to CORS.

#### DestinationRule lookup hierarchy

For each destination host Ferrum resolves the winning rule by Istio's lookup path, most specific first (issue #2469):

1. the **client** workload's own namespace,
2. the **target service's** namespace,
3. the configured **`istio_root_namespace`** (`FERRUM_K8S_ISTIO_ROOT_NAMESPACE`, default `istio-system`).

The first tier that has a visible rule wins outright; lower tiers are discarded for that destination. A rule declared in any OTHER namespace is not part of the lookup path and is refused, even if it exports itself publicly. Because the tier comes from ownership, renaming a namespace can never change which policy wins.

**Arbitration is per destination host, at both layers.** Slice admission groups by the resolved destination (owning namespace + canonical host), and the data-plane materializer resolves the winning tier per destination host of each upstream rather than once per upstream. An upstream whose targets span two services therefore carries two independent lookups: a client-namespace rule for `a.alpha` does not suppress the only rule `b.beta` has (when those lookups disagree the upstream is refused rather than merged — see [below](#an-upstream-that-spans-two-destinations)). When the matched destination host has a resolved owner, that owner is authoritative for the service tier — an upstream container namespace cannot widen it. Upstream namespace is retained only as a narrow fallback when host ownership cannot be resolved (so a ServiceEntry-derived EgressGateway upstream stamped with the gateway's namespace still admits the owner-authored service-tier rule the control plane admitted).

#### An upstream that spans two destinations

An upstream that spans two destinations is refused when its winners differ. Independent per-host *lookups* do not give per-host *application*: an `Upstream` has one set of slots, and everything a rule projects — load balancer and hash keys, backend TLS, outlier/passive thresholds, connection-pool caps, locality, subsets — is upstream-wide. So when one upstream's targets span two services whose lookups resolve to **different winning rules**, applying both would let sort order decide which service's policy governs the other (`beta`'s rule silently reshaping traffic to `alpha`'s service because `beta` sorts later). Ferrum refuses that config instead, before any upstream is mutated: on a live data plane the slice is rejected and the last good config is retained in full, and at startup the config fails to load with an error naming the upstream. Split the upstream so each destination has its own, or give both destinations one common winning rule. Unaffected: single-destination upstreams, multi-port upstreams (every target resolves to the same rule set), and an upstream whose second destination has **no** visible rule of its own — one winner is representable, and that target inherits the upstream-wide policy as it always has.

**The mesh root namespace rides the slice.** `meshConfig.rootNamespace` is carried on `MeshSlice` (native `MeshSubscribe` field, and the `IstioRootNamespaceCarrier` ECDS carrier over xDS) so the data plane can tell an admitted root-tier default apart from a rule declared in an arbitrary namespace. When the slice carries trustworthy root provenance, a rule that lands outside all three lookup namespaces at materialization is **refused**, not applied as a low-priority extra — this closes the reverse-translated xDS path, where carrier-recovered rules never pass slice admission. Refusals are reported once per apply as a bounded `warn!` carrying only a count and the subscriber's namespace. Missing, empty, or whitespace-only root provenance fails closed the same way: Unscoped rules are refused, independently provable client/service tiers still apply, and a legitimate root-tier default is unavailable rather than guessed. Blank root carriers are ignored so they cannot clear trustworthy provenance; every Ferrum-built slice carries a non-empty root namespace. A non-blank root namespace must be a lowercase RFC 1123 namespace label of at most 63 characters: native/file config rejects malformed values, and xDS NACKs a malformed carrier while retaining the last accepted slice. Diagnostics identify the field without echoing the supplied value.

**Host ownership is resolved by one shared helper on both sides.** Slice admission and data-plane materialization run the *same* target-service resolver over the destination host, in the *same* precedence order (the table below): `.svc`-qualified syntax, then an inventory-confirmed two-label `name.namespace`, then the declaring `ServiceEntry`. The two halves agreeing is load-bearing, not tidiness. An external host such as `api.example.com` pins no namespace in its own syntax, and an EgressGateway upstream synthesized from a `ServiceEntry` is stamped with the **gateway's** namespace — which no operator can choose — so if the materializer inferred ownership from the upstream alone, an owner-authored `trafficPolicy` (TLS origination, outlier detection, connect timeout) would be admitted by the control plane and then silently discarded before it reached the egress upstream. With a resolved host owner the materializer trusts that owner and does not widen it via a conflicting upstream namespace (an operator-authored or multi-target upstream in `evil` cannot grant `evil` service-tier policy for a host owned by `beta`). When ownership cannot be resolved, the upstream namespace remains a narrow fallback. The order matters as much as the sources: consulting the `ServiceEntry` index ahead of `.svc` syntax or the service inventory would let a carrier-supplied `ServiceEntry` declaring `reviews.beta` transfer ownership of `beta`'s service to its own namespace. The one input that legitimately differs between the two sides is the service inventory — the control plane uses the full mesh inventory, the data plane its slice's already-narrowed `services` — so a service narrowed out of a subscriber's slice cannot confirm the two-label shorthand there, and that host falls through to the `ServiceEntry` arm exactly as it would for a control-plane consumer that cannot see the service either.

<a id="destinationrule-target-service-ownership"></a>
**How the target-service namespace is established.** Tier 2 is a security boundary — it decides which third-party namespace may write traffic policy for a destination — so Ferrum grants it only on evidence of ownership, resolved in this order:

| DR `host` shape | Owning namespace | Evidence |
|---|---|---|
| `reviews` (short name) | the rule's own namespace | Istio short-name resolution; self-scoped by definition, so it can only make a namespace the owner of its own service |
| `reviews.beta.svc`, `reviews.beta.svc.cluster.local` | `beta` | pinned by the host's own syntax |
| `reviews.beta` (two labels) | `beta`, **only if** the service inventory contains `beta/reviews` | this shape is indistinguishable from a two-label external DNS name (`example.com` must not nominate a namespace `com`) |
| `api.example.com` declared by exactly one visible `ServiceEntry` | the **ServiceEntry's** namespace | the declaring ServiceEntry is the only record of who owns an external host |
| anything else — an external host with no visible ServiceEntry, a wildcard host, an unconfirmed two-label host, or a host claimed by visible ServiceEntries in **two different namespaces** | **none** | ownership is unknown or contested |

When no owner can be established, tier 2 is **disabled** for that host: only the client namespace and the configured root namespace may write policy for it. Ferrum never falls back to treating the *declaring* namespace of the rule as the owner, because that lets any namespace vouch for itself and become the service tier for a host it does not own. Duplicate ServiceEntry declarations *within one namespace* are still a single owner (Istio merges those); duplicates *across* namespaces are contested and resolve to "none" rather than to whichever was seen first.

This is deliberately the fail-closed direction — it can only ever narrow which rules are admitted, never widen it. The visible consequence is that a DestinationRule declared in the target's namespace is dropped when Ferrum has no record of the target (for example a `reviews.beta` rule when no `beta/reviews` Service and no ServiceEntry are in the mesh model); express such a rule with a `.svc`-qualified host, or declare the backing `Service`/`ServiceEntry`.

**Multiple DRs in the winning tier**: they are same-namespace by construction (one owner — Istio's merge case), so they apply in deterministic `(namespace, name, normalized host spelling)` order, last-writer-wins per field. The slice builder keeps a bounded set of previously reported ambiguity counts per subscriber namespace and logs a sanitized namespace/count diagnostic for each first-seen retained count; returning to a retained count is silent. Once the per-namespace count or namespace budget is saturated, unretained counts or namespaces continue to be reported, while already-retained counts remain deduplicated; overlong namespace keys are never retained and continue to report. That order is an **intra-tier tiebreak only** and is never cross-tier precedence. Including host spelling covers native input that repeats one name for distinct hosts; Kubernetes still has unique `(namespace, name)` resource identity. Operators also see `debug!` log lines when subsets or proxy `backend_connect_timeout_ms` get overwritten.

Visibility and the lookup hierarchy compose in that order: `exportTo` is absolute, so root-namespace fallback can never resurrect a rule the subscriber was never allowed to see.

**Support matrix** (canonical Istio field → Ferrum target). The auto-generated machine-readable view of this table — plus VirtualService, AuthorizationPolicy, PeerAuthentication, ServiceEntry, and xDS coverage — lives in `target/conformance/coverage.md` after `cargo test --test conformance_tests`. See [CONFORMANCE.md](../CONFORMANCE.md#istio--xds-conformance-suite) for how to run the suite and how the status enum works.

| Istio field | Status | Notes |
|---|---|---|
| `host` | Supported | Required, lowercased at admission, empty/dot-only rejected |
| `trafficPolicy.connectionPool.tcp.connectTimeout` | Supported | Applied to `Proxy.backend_connect_timeout_ms` for every proxy referencing the matching upstream |
| `trafficPolicy.connectionPool.tcp.idleTimeout` | Supported (stream-family / mesh L4 relays) | Bidirectional TCP idle bound, mapped to `tcp_idle_timeout_seconds` (`0` disables). Lands on `Upstream.port_overrides[port].tcp_idle_timeout_seconds` via the same top-level fan-out + per-port overlay as `connectTimeout` / `maxConnections` / `tcpKeepalive`, then `Proxy.dispatch_port_overrides`. Synthesized mesh L4 relays (inbound TCP, HBONE CONNECT, outbound TCP/UDP, east-west passthrough, stream egress) default `backend_read_timeout_ms` / `backend_write_timeout_ms` to `0` (disabled) so a silent backend or one-way sink is not torn down at 30s; the relay is bounded by this idle timeout, or `FERRUM_TCP_IDLE_TIMEOUT_SECONDS` when the per-proxy field is unset. Distinct from HTTP `connectionPool.http.idleTimeout` (pool idle; 0 is rejected). Sub-second durations other than `0s` are rejected; values above `MAX_TCP_IDLE_TIMEOUT` (24h) are rejected. |
| `trafficPolicy.outlierDetection.consecutive5xxErrors` / `consecutiveErrors` | Supported | → `PassiveHealthCheck.unhealthy_threshold` **and** `PassiveHealthCheck.consecutive_error_mode = true`. The threshold is an Istio-style CONSECUTIVE failure streak: a single success resets it, so a backend erroring at a low rate under high load is never ejected (issue #4292). **Omitting both fields inherits Istio's own default of 5 only when no lower-precedence outlier tier supplied a threshold** (Ferrum's native default is 3 in a sliding window). Explicit `0` disables the consecutive-5xx detector via `consecutive_5xx_ejection_disabled` rather than ejecting immediately — both matching HTTP 5xx and locally originated connection failures (Envoy's default `splitExternalLocalOriginErrors=false` bucket; Ferrum's split mode is deferred). A success observed through all-unhealthy fallback immediately clears a Ferrum ejection; Envoy otherwise retains it for `baseEjectionTime`. Malformed, negative, fractional, or out-of-range thresholds reject translation. Ferrum's native windowed passive health is unchanged for policies that are not translated from a DestinationRule. |
| `trafficPolicy.outlierDetection.interval` | Supported | → `PassiveHealthCheck.unhealthy_window_seconds` (positive duration required; sub-second rounded up). Recorded but **inert** while consecutive mode is on — Istio's `interval` is an analysis sweep period, not a failure window. A malformed/non-string/zero value rejects translation. |
| `trafficPolicy.outlierDetection.baseEjectionTime` | Supported | → `PassiveHealthCheck.healthy_after_seconds`; malformed or non-string durations reject translation. |
| `trafficPolicy.outlierDetection.maxEjectionPercent` | Supported | → `PassiveHealthCheck.max_ejection_percent`; only integer values `0..=100` are accepted. **Omitting it inherits Istio's own 10% default only when no lower-precedence outlier tier supplied a cap** (Ferrum's native default is uncapped). The cap uses Envoy's integer prospective-ejection gate, `(currently_ejected + 1) × 100 / targets <= percent`; a 10% cap therefore permits zero ejections in pools smaller than ten, while one of three is admitted at the exact 33% integer boundary. |
| `trafficPolicy.outlierDetection.consecutiveGatewayErrors` / `consecutiveLocalOriginFailures` / `minHealthPercent` | Deferred | Parsed past with a translate-time warning and surfaced in `status.ferrum.translation.deferred_fields` (field names only). Ferrum keeps one failure bucket (`unhealthy_status_codes` + connection errors) and bounds ejection with `maxEjectionPercent` alone. |
| `trafficPolicy.loadBalancer.simple = ROUND_ROBIN` | Supported | → `LoadBalancerAlgorithm::RoundRobin` |
| `trafficPolicy.loadBalancer.simple = LEAST_REQUEST` / `LEAST_CONN` | Supported | → `LoadBalancerAlgorithm::LeastConnections` |
| `trafficPolicy.loadBalancer.simple = RANDOM` | Supported | → `LoadBalancerAlgorithm::Random` |
| `trafficPolicy.loadBalancer.simple = PASSTHROUGH` | Supported (captured paths; warns) | → `LoadBalancerAlgorithm::Passthrough`: dials the captured original destination (`SO_ORIGINAL_DST`) when it matches a healthy pool target, else round-robin fallback |
| `trafficPolicy.loadBalancer.simple = MAGLEV` | Rejected | Hard error at translate time |
| `trafficPolicy.loadBalancer.consistentHash.{httpHeaderName,httpCookie.name,useSourceIp}` | Supported | Exactly one of the three required (rejected otherwise); → `LoadBalancerAlgorithm::ConsistentHashing` + `Upstream.hash_on` |
| `subsets[].name` / `subsets[].labels` | Supported | → `SubsetDefinition` entries on the upstream; second DR overwrites the first |
| `subsets[].trafficPolicy.loadBalancer` | Supported | → `SubsetTrafficPolicy.load_balancer_algorithm`; `consistentHash` also projects the subset `hash_on` key |
| `subsets[].trafficPolicy.tls` | Supported | → `SubsetTrafficPolicy.tls` (nests `MeshTrafficPolicyTls`). Cold-path `resolve_subset_traffic_policy` layers the subset's TLS overlay (mode / SNI / CA / mTLS material / SAN allow-list / `insecureSkipVerify`) onto the upstream-level TLS and stores the result on `Upstream.resolved_subset_tls[subset_name]`. `GatewayConfig::resolve_upstream_tls` then projects that overlay onto `Proxy.resolved_tls` for proxies whose `upstream_subset` selects this subset — so v1 and v2 subsets with different CAs land on different `Proxy.resolved_tls` values and partition the backend pool. `upstream_subset` also enters HTTP / H2 / gRPC / H3 pool keys as a defense-in-depth backstop on top of TLS partitioning. Subsets without `trafficPolicy.tls` fall back to upstream-level TLS. |
| `subsets[].trafficPolicy.connectionPool.tcp.connectTimeout` | Supported | Overrides `backend_connect_timeout_ms` for proxies bound to the subset (precedence over the DR top-level connectTimeout). |
| `subsets[].trafficPolicy.connectionPool.tcp.idleTimeout` | Supported (config.proxies) | Overrides `tcp_idle_timeout_seconds` for proxies bound to the subset (precedence over the DR top-level idleTimeout). Synthesized L4 relays are not in `config.proxies` and honor the top-level / per-port overlay via `dispatch_port_overrides` instead. `0` disables. |
| `subsets[].trafficPolicy.connectionPool.http.{h2UpgradePolicy,maxRetries,http1MaxPendingRequests,idleTimeout,http2MaxRequests,maxConcurrentStreams}` | Supported | Preserved in `SubsetTrafficPolicy`, resolved into `ResolvedSubsetTrafficPolicy`, and overlaid onto the selected proxy's immutable inherited-policy snapshot (`dispatch_port_override_fallback`) for each selected target. Precedence is field-level `portLevelSettings` > selected subset > top-level; sibling subsets and unmatched destinations never inherit the selected subset. **Semantics differ from Istio on purpose:** Istio applies subset > DR `portLevelSettings` and replaces the whole `connectionPool` wholesale when a subset sets any connection-pool field; Ferrum keeps the inverted tier order and field-level merge (same convention as port-level overrides). Example: top-level/port `UPGRADE` plus subset `DO_NOT_UPGRADE` → Istio forces H1 on that port for the subset; Ferrum still negotiates h2. A subset that sets only `maxRetries` also inherits top-level `DO_NOT_UPGRADE` / `idleTimeout` / `http2MaxRequests` here, where Istio's wholesale replacement would clear them. Transport, retry-cap, H1-admission, idle-timeout, destination active-request budget, and H2-stream-cap semantics match the corresponding top-level rows below (including the reqwest-H2 builder residual for `maxConcurrentStreams`). The `http2MaxRequests` admission lane carries the selected subset name, so sibling subsets keep independent budgets. Every HTTP-family shared-client/pool key already carries `upstream_subset`, so same-endpoint sibling subsets cannot first-materialize each other. Invalid values reject the DestinationRule without echoing the value. |
| `subsets[].trafficPolicy.portLevelSettings` | Deferred | Detected at translate time with a value-redacted warning and listed in `status.ferrum.translation.deferred_fields`. Not parsed or applied — Istio's highest-precedence tier. Express per-port policy at top-level `trafficPolicy.portLevelSettings` or use subset `connectionPool` fields. |
| `subsets[].trafficPolicy.outlierDetection` | Supported | Ejection thresholds (consecutive errors / interval / base-ejection) AND the `maxEjectionPercent` cap applied per-subset (`minHealthPercent` is NOT implemented — it is a deferred field), overriding upstream-level passive health for subset-bound proxies (`passive_health_for_target` for thresholds, `LoadBalancerCache::max_ejection_percent_resolved_from` for the cap, sharing one per-port > per-subset > upstream tier precedence). The cap is sized against the subset candidate pool (denominator = subset target count). The per-port cap tier applies only when a single dispatch port is resolvable pre-selection; for subset dispatch on a multi-port upstream the subset cap governs (the cap is resolved before a target's port is known). |
| `trafficPolicy.connectionPool.http.maxRequestsPerConnection` | Deferred | Parsed and validated, but not projected onto `Upstream.port_overrides` or `Proxy.pool_max_requests_per_connection` because Ferrum does not enforce backend close-after-N-requests behavior. K8s translation emits a warning and status lists `connectionPool.http.maxRequestsPerConnection` in `status.ferrum.translation.deferred_fields` at top-level, per-port, and subset scope. Negative and `> u32::MAX` values are rejected at translate time; `0` is accepted as Istio's explicit "unlimited" sentinel but still produces no effective policy. Use `http2MaxRequests` for the destination request budget and `maxConcurrentStreams` for per-HTTP/2-connection stream concurrency. |
| `trafficPolicy.connectionPool.http.idleTimeout` | Supported (HTTP-family) | Lands on the inherited dispatch fallback / explicit per-port override as `http_idle_timeout_ms` and projects onto `Proxy.pool_idle_timeout_seconds` for the per-target effective proxy, which threads into the reqwest/H2 client pool idle timeout. Sub-second durations are rejected at translate time because `pool_idle_timeout_seconds` is whole-second granular; values above `MAX_POOL_IDLE_TIMEOUT` (1 hour) are also rejected so the K8s surface stays consistent with the admin admit-path validator. Top-level and selected-subset values ride `dispatch_port_override_fallback`; explicit `portLevelSettings` entries win per-port. Precedence is field-level per-port > selected subset > top-level. The reqwest pool key includes idle timeout in its `rcfg` client-behavior segment (and every HTTP-family key already carries `upstream_subset`), so divergent idle timeouts / subsets isolate distinct shared clients (no first-creator-wins leak). Direct-H2 / gRPC key the effective H2 stream cap (and `upstream_subset`); remaining builder-only knobs such as keepalive may still document first-materializer tradeoffs. Request-only `backend_connect_timeout_ms` remains per-request and does not fragment. |
| `trafficPolicy.connectionPool.http.http2MaxRequests` | Supported (destination-wide active-request breaker; HTTP/1.1 **and** HTTP/2) | Istio's contract is "maximum number of active requests to a destination, applicable to both HTTP1.1 and HTTP2" (Envoy cluster `max_requests`), so Ferrum enforces it as a **destination-wide admission budget**, not as an HTTP/2 stream setting. Lands on the inherited dispatch fallback / explicit per-port override as `http2_max_requests`; one counter is held per stable `(namespace, logical destination, DR policy port, selected subset)` lane. The permit is taken during **backend admission** — the single funnel every HTTP-family upstream attempt passes through before dispatch (reqwest HTTP/1.1, reqwest-negotiated HTTP/2, direct H2, native gRPC, HBONE / mesh-mTLS, Unix sidecar ingress, and the HTTP/3 bridges) — and is released only when the client-visible exchange terminates (buffered completion, streamed EOF, gRPC trailers, client disconnect, backend reset, deadline, task cancellation, shutdown), never at response headers. Because the lane is the **logical destination** (referenced upstream id, or the route id for a direct backend) rather than a socket address, connection count, pool shards, LB endpoint rotation, config reloads, and peer SETTINGS cannot multiply or raise it, and two Services that resolve to the same pods keep independent budgets. Every retry attempt reacquires its own permit, and a sequential retry releases the prior attempt's permit before the next attempt acquires (Ferrum has no request hedging, so there are never two concurrent attempts for one client request). Saturation sheds **before any backend dial** with a backend-neutral `503` (gRPC `UNAVAILABLE`) that never touches passive health, the circuit breaker, or adaptive concurrency, and nothing is queued behind the limiter. A reload applies its current cap to the shared active count: lowering sheds until the count drains below the new value, raising takes effect immediately, removing stops new acquisitions while existing permits drain, and re-adding cannot forget those permits. A lane is evicted the moment its count reaches zero. Top-level and selected-subset values ride `dispatch_port_override_fallback`; explicit `portLevelSettings` entries win per-port; precedence is field-level per-port > selected subset > top-level. Zero/negative values rejected at translate time (K8s and native/file). Observability is fixed-cardinality only: `ferrum_destination_active_requests{,_admitted_total,_rejected_total}`; destination identity stays out of labels and appears only in the bounded shed log line. |
| `trafficPolicy.connectionPool.http.maxConcurrentStreams` | Supported (per-HTTP/2-connection transport control) | Istio's distinct per-connection stream limit. Lands on the inherited dispatch fallback / explicit per-port override as `h2_max_concurrent_streams` and projects onto `Proxy.pool_http2_max_concurrent_streams` via the per-target effective proxy. Threads into the direct H2 (`src/proxy/http2_pool.rs`) and gRPC (`src/proxy/grpc_proxy.rs`) builders as both `http2::Builder::max_concurrent_streams` (the SETTINGS value Ferrum advertises) and `initial_max_send_streams` (the local outbound-stream bound **until the peer's SETTINGS arrive** — a peer may raise or lower it, which is exactly why this cannot be the destination request budget). Reqwest's H2 path exposes no equivalent builder knob. Direct-H2 / gRPC pool keys include the effective `PoolConfig::for_proxy` stream cap (decimal, or `none` when that effective cap is unlimited) after `upstream_subset`, so same-subset divergent caps isolate distinct connections, inheriting the global and setting that same number explicitly share a key, and `Some(0)` / `Some(1)` collapse after clamp. Precedence is field-level per-port > selected subset > top-level. Zero/negative values rejected at translate time. |
| `trafficPolicy.connectionPool.http.h2UpgradePolicy` | Supported (plain-HTTPS only) | Lands on the inherited/per-port dispatch policy and projects onto `Proxy.h2_upgrade_policy` via the per-target effective proxy. `DO_NOT_UPGRADE` forces reqwest/H1, restricts advertised ALPN to `http/1.1`, and adds an H1 discriminator; `UPGRADE` prefers direct-H2 while remaining fail-safe against a proven-unsupported target; `DEFAULT`/absent is probe-driven. Every HTTP-family shared-client/pool key already carries the selected `upstream_subset`, and the reqwest key additionally carries the force-H1 client behavior, so incompatible subset transports cannot share connections. Scope is plain HTTP only, not gRPC or mesh tunnels. Precedence is field-level per-port > selected subset > top-level (**Semantics differ from Istio on purpose** — Istio applies subset > port-level and wholesale `connectionPool` replacement; see the subset HTTP row above). Unknown enum values reject translation. |
| `trafficPolicy.connectionPool.http.maxRetries` | Supported (per-request CAP — honest reinterpretation) | **Semantics differ from Envoy on purpose.** Ferrum treats the field as an upper bound on an existing per-request `Proxy.retry.max_retries`: `min(existing, effective_dr_cap)`. It never increases retries and never synthesizes retry behavior when no retry policy exists. A cap of zero explicitly disables an existing retry policy for the selected destination. The cap is resolved after target selection and before retry/deadline decisions; retry target rotation remains in an explicit port-policy lane when one exists, while subset/top-level fallback remains stable for the route's selected subset. Precedence is per-port > selected subset > top-level. Negative values reject translation. See [DestinationRule `maxRetries` semantics](#destinationrule-maxretries-semantics). |
| `trafficPolicy.connectionPool.http.http1MaxPendingRequests` | Supported (honest reinterpretation — max concurrent in-flight HTTP/1.1 requests) | Projects onto the selected target's effective `Proxy.pool_http1_max_pending_requests`. Ferrum caps concurrent in-flight reqwest/H1 requests (dispatch → response headers, including the H3→plain bridge) per logical destination `(namespace, upstream/Service identity, optional Service UID, policy port, selected subset)` because reqwest exposes no true connection-pending hook; the selected endpoint host is intentionally absent from the key (issue #3778), so endpoint fan-out cannot multiply the cap. Overflow is shed with a backend-neutral `503` (no circuit-breaker, passive-health, or adaptive-concurrency effect), and retry attempts reacquire independently. The gate applies only to dispatch **known HTTP/1.1 at acquire time**: a `DO_NOT_UPGRADE` proxy, a plaintext `http` backend, an HTTPS backend the capability registry classified H1-only, or any reqwest dispatch with `pool_enable_http2: false` (its ALPN omits h2). An HTTPS backend that may still negotiate h2 is left **uncapped** (that is `http2MaxRequests`'s job). Direct H2, gRPC, native H3, HBONE, and mesh-mTLS never consult it. Precedence is per-port > selected subset > top-level. Rejection logs carry a bounded scope digest and the DestinationRule policy port. Zero rejects in K8s and native/file mesh validation. |
| `trafficPolicy.connectionPool.tcp.maxConnections` | Supported (all transports Ferrum owns the socket for) | Cap on concurrent open backend connections per `(host, DestinationRule policy port)`, shared by every outbound transport so a destination gets ONE ceiling. Stream-family enforces it at backend dial (over-cap returns `Backend maxConnections reached` and may rotate to another target under `retry_on_connect_failure`); WebSocket (H1/H2/H3) holds a slot for the session and rejects an over-cap upgrade with `503` before dialing; pooled multiplexed transports (direct H2, gRPC, native HTTP/3, HBONE, Sidecar mesh-mTLS) charge one slot per physical connection for its lifetime, with an over-cap create being pre-wire and backend-health-neutral; reqwest (HTTP/1.1 and ALPN h2) is admitted per new socket inside its connector, surfacing a health-neutral `503`. Top-level applies to every target port; `portLevelSettings` overrides per port. `maxConnections <= 0` is rejected at translate time. See [DestinationRule `maxConnections` enforcement scope](#destinationrule-maxconnections-enforcement-scope). |
| `trafficPolicy.connectionPool.tcp.tcpKeepalive` (`time` / `interval` / `probes`) | Supported for stream-family AND HTTP-family multiplexed pools (direct-H2, gRPC, HBONE, mesh-mTLS); reqwest-backed HTTP and H3/QUIC are documented residuals (shared-client / non-TCP transport) | Each subfield independently optional. Applied via `setsockopt(SO_KEEPALIVE)` + `TCP_KEEPIDLE` (Linux) / `TCP_KEEPALIVE` (macOS/iOS) for `time`, `TCP_KEEPINTVL` for `interval`, `TCP_KEEPCNT` for `probes`. Set on the backend socket right after `connect()` (stream-family: TCP / TCP+TLS / TCP-passthrough; HTTP-family: the socket-owning H2-family pools resolve the same per-port override at connection creation via the shared `socket_opts::apply_pooled_tcp_keepalive` — direct-H2 `http2_pool` and `grpc_proxy` key it by the dial target's `backend_port`; the HBONE pool and the Sidecar mesh-mTLS pool key it by the destination's **app/service port** and apply it inside the shared `dial_h2_connect_sender` after dialing the transport port `:15008`/`:15006`, so it covers Ambient HBONE egress, Sidecar mesh-mTLS egress, raw-TCP egress over both transports, AND WebSocket-over-HBONE/-mesh-mTLS which ride the same dialer). Best-effort: a `setsockopt` failure logs a `warn!` and continues rather than aborting the connection. The per-port DR override is **additive and takes precedence**; absent an override the global pool keepalive (`pool_config.tcp_keepalive_seconds`, whole-seconds idle time only, applied when `enable_http_keep_alive`) remains the fallback. **First-materializer tradeoff (HTTP-family only):** keepalive is NOT part of the pool key (forbidden by the proxy-protocol rules — see `.claude/rules/proxy-protocols.md`), and these connections are pooled+shared, so the keepalive is fixed once at connection creation and the **first dispatcher to materialize a pooled connection wins**; later dispatchers that differ only in keepalive reuse the existing connection and inherit its setting — the same tradeoff already documented for `idleTimeout` / `maxRequestsPerConnection`. **Residuals:** the reqwest-backed HTTP pool (`src/connection_pool.rs`) applies `tcp_keepalive` at builder time (seconds-only) on a client SHARED across proxies that differ only in policy fields (keepalive is excluded from pool keys per the rules), so a clean per-proxy DR override is not possible there without another vendored reqwest patch — it keeps the global seconds-only keepalive (mesh egress never uses reqwest, so mesh coverage is complete; reqwest mainly serves non-mesh + localhost inbound where keepalive is moot). H3/QUIC (`src/http3/client.rs`) is UDP — `tcpKeepalive` is N/A (a QUIC keep-alive would be a separate `TransportConfig` knob). Sub-second durations and zero values are rejected at translate time because the underlying socket options are second-granular and require at least one probe. |
| `trafficPolicy.tls` | Supported | Overrides the `PeerAuthentication`-derived backend posture per matching `Upstream` when set. Mode mapping: `DISABLE` → clears `Upstream.backend_tls_*`; `SIMPLE` → enables server-cert verify + `backend_tls_server_ca_cert_path = caCertificates` (client cert/key cleared); `MUTUAL` → enables server-cert verify + projects `caCertificates`/`clientCertificate`/`privateKey` onto `Upstream.backend_tls_server_ca_cert_path`/`_client_cert_path`/`_client_key_path`; `ISTIO_MUTUAL` → enables server-cert verify + projects the workload SVID paths from `FERRUM_GATEWAY_SVID_CERT_PATH` / `FERRUM_GATEWAY_SVID_KEY_PATH` onto the upstream client cert/key fields, failing slice apply if either path is missing so stale/global client material is not used. `ISTIO_MUTUAL` projects **file-based** SVID paths for the outbound client cert, so when the mesh's only workload identity is a dynamic CA-backed SVID (`FERRUM_MESH_CA_BACKEND` with no `FERRUM_GATEWAY_SVID_*` files), `ISTIO_MUTUAL` on a generic backend / egress `ServiceEntry` upstream is intentionally **rejected (slice apply fails closed)** because the generic backend TLS path cannot present a dynamic SVID client cert — use file-based `FERRUM_GATEWAY_SVID_*` material, or an explicit `MUTUAL` policy with `clientCertificate` / `privateKey` paths, for those upstreams. Validated reloads of the `FERRUM_GATEWAY_SVID_*` files bump a generation in backend TLS and pool keys so new H2/gRPC/H3/HTTP connections rebuild client identity state without restarting; active HTTP health probes are restarted on each observed revision, and existing connections complete on their original config unless `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS` force-drains old-generation pool entries. `insecureSkipVerify: true` forces `backend_tls_verify_server_cert = false`, except that pairing it with `caCertificates: system://` is rejected at Kubernetes translation, native/file/xDS slice validation, and cold-path application: selecting system roots and then disabling verification is contradictory and must fail closed. The `system://` value must use that exact spelling with no path or query suffix. `sni` projects to `Upstream.backend_tls_sni`, onto `Proxy.resolved_tls`, into backend H2/gRPC/H3 TLS handshakes, and into the backend pool key so different SNI values never share connections. Plain HTTPS requests with an SNI override prefer the direct H2 backend pool, which sets the TLS server name natively; when that pool is unavailable or the backend speaks only HTTP/1.1, the request falls back to an HTTP/1.1 reqwest dial that carries the override in the request URL's authority while pinning the socket to the selected target (see the SNI transport paragraph below). `subjectAltNames` projects to `Upstream.backend_tls_san_allow_list`, onto `Proxy.resolved_tls`, into backend TLS verifier enforcement, and into the backend pool key so different allow-lists never share connections. If per-proxy or global no-verify is enabled, SAN allow-lists are not enforced and Ferrum logs a warning. The proxy resolves `caCertificates` / `clientCertificate` / `privateKey` with its own identity, so a rule outside the mesh root namespace may name only inline PEM, `system://`, a `k8s://` Secret in the rule's own namespace, or a local file under a `FERRUM_MESH_TENANT_TLS_FILE_ROOTS` directory (at every scope: top level, `portLevelSettings`, subsets). That variable is empty by default, so tenant rules name no local file unless the operator lists directories; a listed file must be an absolute path without `..`. A data plane re-checks the file after resolving symlinks only when it applies the rule to one of its upstreams; if the file is missing on that node or resolves outside the listed directories, backend TLS for that rule's destinations fails closed: the destination is marked refused, and every backend TLS build for it (proxy pools, capability probes, TCP+TLS and DTLS backends, health probes) fails before it reads any material, even with `FERRUM_TLS_NO_VERIFY` or a global CA and client certificate pair configured. It never falls back to the `PeerAuthentication` posture, the global CA, system roots, or the gateway's own client certificate. A warning names the rule, `ferrum_backend_tls_refusals_total` counts the refusal, and the rest of the slice still applies. The refusal marker is node-local and never serialized, and refusal clears the upstream's backend TLS fields, so the admin API (`GET /upstreams`, `GET /proxies`) and other config views show a refused upstream exactly like one with no backend TLS configured: no CA, client certificate, key, SNI, or SAN allow-list, with server-certificate verification on. Do not read empty `backend_tls_*` fields as "no backend TLS" on a mesh node. Identify refused destinations from that warning and from `ferrum_backend_tls_refusals_total{surface="slice_apply"}` (once per refused upstream per slice apply); `surface="client_build"` rises with each dispatch attempt against one, and those attempts fail with `backend TLS was refused for this destination on this node`. HBONE and Sidecar mesh-mTLS destinations never use this material (those transports authenticate with the gateway SVID), so for them the warning says traffic continues over the mesh identity. The re-check and the later TLS load are separate reads, so a link swapped inside a listed directory between them is not caught; list only directories that hold tenant-owned or immutable material. Another namespace's Secret, a file outside the listed directories, and `vault`/`aws`/`azure`/`gcp`/`managed`/`acme`/`pkcs11` sources are refused at Kubernetes translation and at native/file/xDS slice validation. Root-namespace rules are mesh-operator policy and keep every source. When the field is unset, `PeerAuthentication` drives the default mTLS posture. |
| `trafficPolicy.portLevelSettings[].port.number` + nested `connectionPool.tcp.connectTimeout` | Supported | Top-level policy applies first; per-port `connectTimeout` lands on `Upstream.port_overrides[port].connect_timeout_ms` at apply time, then `GatewayConfig::resolve_dispatch_port_overrides()` projects it onto `Proxy.dispatch_port_overrides` for O(1) hot-path lookup. All four dispatch families consult it: HTTP/H2/H3 via `resolve_effective_proxy_for_target` (`src/proxy/mod.rs`), gRPC via the same helper threaded through `proxy_grpc_request*` (`src/proxy/grpc_proxy.rs`), TCP via `tcp_timeout_policy`, re-resolved per retry attempt against the selected target's policy port (`src/proxy/tcp_proxy.rs`), and HBONE via `effective_connect_timeout_ms` in `connect_backend` (`src/proxy/hbone_proxy.rs`). Ports outside 1-65535 rejected; duplicate port entries rejected; phantom ports (DR entry references a port unused by any `Upstream.target`) skipped with a warning at apply time. The admin API rejects POST/PUT setting `Upstream.port_overrides` directly — express per-port policy as a DestinationRule (SQL/MongoDB schemas don't persist the field) |
| `trafficPolicy.portLevelSettings[].port.number` + nested `connectionPool.tcp.idleTimeout` | Supported | Same projection as per-port `connectTimeout`; stream-family / mesh L4 relays honor it as the bidirectional idle bound (`0s` disables). Does not affect stream target selection. |
| `trafficPolicy.portLevelSettings[].loadBalancer` / `outlierDetection` | Supported for HTTP-family / gRPC / WebSocket / HBONE dispatch; LB algorithm, locality, and active/passive health also engaged for stream-family when all targets share a port | Per-port load-balancer algorithm/hash settings, passive outlier thresholds, and `localityLbSetting` (`distribute` / `failover` / `failoverPriority` / `enabled`) land on `Upstream.port_overrides[port]`; the runtime builds isolated per-port LB counters/hash rings, per-port passive health, and per-port locality LB state. Dispatch on a port with an override consults the per-port locality preference first and falls back to the upstream-level `trafficPolicy.loadBalancer.localityLbSetting` when the per-port entry omits it. `failoverPriority` is inert unless applicable upstream health or that port's `outlierDetection` enables failover; a port-level signal does not alter other ports. TCP/UDP/DTLS stream paths also engage the per-port **LB algorithm** and **`localityLbSetting`** when all upstream targets share a single port (`initial_dispatch_port_override` is non-zero); the lane engages only for selection-affecting overrides, per-port `consistentHash` on a stream lane requires a source-IP hash key, per-port `LEAST_CONN` is supported on generic TCP/UDP/DTLS stream listeners, whose connection/session guards feed active-connection accounting, and per-port `LEAST_LATENCY` is refused on every stream lane (no latency signal on raw relays) — see the stream-family bullet in [Limitations](#limitations-and-not-supported). Stream paths pass active/passive health context into selection, so per-port `outlierDetection` thresholds, existing passive ejections, active health state, and the `maxEjectionPercent` cap affect TCP/UDP/DTLS target selection. Outlier thresholds are still not recorded on stream paths because raw relay sessions carry no response status. Phantom ports are skipped with a warning at apply time. Example: a top-level `ROUND_ROBIN` policy with `portLevelSettings[8080].loadBalancer.simple=RANDOM` keeps non-8080 traffic on round-robin while 8080 dispatch uses its own random counter/ring; a per-port `localityLbSetting.distribute` on 8080 weights only port-8080 traffic and leaves other ports on the upstream-level locality preference. |
| `trafficPolicy.portLevelSettings[].tls` | Supported | Resolved per port over the upstream-level TLS and projected onto the per-target effective proxy's `resolved_tls` (part of the backend pool key); takes precedence over upstream-/subset-level `trafficPolicy.tls` for dials to that port. |
| `exportTo` | Supported | Namespace export visibility. Omitted/empty on Kubernetes becomes Istio's public `["*"]`; `.`, `*`, and explicit namespace lists are honored. Enforced during slice construction, before lookup selection and before per-node slice serialization. Unsupported values (`~`, empty entries, malformed namespaces, over-long lists, `*` mixed with an explicit list) are rejected fail-closed. On the native/file/xDS-carrier sources an EMPTY list is namespace-local. See [Export visibility](#destinationrule-visibility-and-lookup). |
| DestinationRule lookup namespace | Supported | Client namespace → target service namespace → configured `istio_root_namespace`; the first tier with a visible rule wins outright. See [Lookup hierarchy](#destinationrule-lookup-hierarchy). |

`outlierDetection` precedence is field-level, consistently across threshold,
interval, base ejection time, and maximum ejection percentage: explicit
per-port values override the selected subset, which overrides top-level; an
omitted higher-tier field inherits the explicit lower-tier value. Istio's 5
and 10% defaults are applied only when no tier supplied the corresponding
field, never synthesized independently into each partial block.

Translation diagnostics use more than one channel: warnings collected by translation are returned in `K8sTranslation.warnings`, while deferred outlier-detection fields are emitted directly through `tracing::warn` and represented separately in translation status. Other returned warnings remain available to the controller at apply time.

DestinationRule `trafficPolicy.tls.sni` (and the Gateway API `BackendTLSPolicy` `validation.hostname` that projects onto the same field) is enforced on every backend path where Ferrum owns the TLS handshake — direct HTTP/2 for plain HTTPS, gRPC over H2, and native H3 — and on the **reqwest HTTP/1.1 path** as well.

reqwest exposes no per-request server-name hook: its connector derives the rustls server name from the request URL's host. The H1 dial therefore expresses the override by putting it in the URL **authority**, while keeping the socket on the load-balancer-selected target: the pooled client's `DnsCacheResolver` is pinned to that target's already-resolved, already-egress-screened address, and because the resolver answers every name with the pinned address the override hostname is never itself resolved. `backend_tls_sni` is separately validated to be a DNS hostname and never an IP literal, so it also cannot become a hyper-util URL-literal dial that would bypass the resolver — the selected backend target stays authoritative for where the socket connects. Three consequences are load-bearing:

* **ALPN is restricted to `http/1.1`** on that client. HTTP/2 derives `:authority` from the URL, which carries the server name, so h2 must not be negotiated there; the backend instead reads the authority from the explicit `Host` header dispatch sets from the effective target host (hyper-util preserves an explicit `Host`). H2-capable targets are unaffected — they keep using the direct-H2 pool, which sets the server name natively and leaves the real backend authority in place.
* **Pool identity** carries the pinned address and the force-H1 discriminator alongside the existing SNI / CA / SAN-digest / mTLS / verification components, so an SNI dial can share a client neither with a default h2-capable client nor with another target's pin. The cost is that an SNI-override route partitions its reqwest client per target (up to one per endpoint) and gives up in-client multi-address failover for that dial; only SNI-override routes pay it.
* **Retries, timeouts, and streaming bodies** behave as on any other reqwest dial, because the dial reuses the ordinary reqwest path. The retry path builds the same dial against the newly selected target, so an LB rotation between attempts still dials the rotated target under the same server name.

The `502` with `gateway-error-reason: backend_tls_sni_requires_direct_h2` therefore does not fire for an H1-only backend, a retry-enabled route, a buffering plugin, or `pool_enable_http2: false`. It is the fail-closed answer only for the cases where the dial genuinely cannot be constructed — no resolved target address to pin, or a backend URL whose authority does not carry the selected target host — so the override is never silently dropped and the handshake is never made under the wrong server name.

**Config admission does not screen these combinations.** `ferrum-edge validate` and the Admin API admit proxy-level and DestinationRule / `BackendTLSPolicy` per-port TLS SNI overlays combined with effective retry, request-body-buffering plugins, `pool_enable_http2: false`, or all three, because the H1 dial above serves them (issue #3276). What remains fail-closed is decided at runtime, where the information actually exists: the `502` above when a dial genuinely cannot be constructed, and the WebSocket transport's own pre-dial refusal (see below). Nonzero global body-size limits (`FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` / `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`, including the default 10 MiB response cap) do **not** disqualify direct-H2 — for SNI overrides and ordinary plain-HTTPS alike: the direct-H2 path enforces those limits in-path (413 on oversized requests, 502 on oversized responses) via `SizeLimitedIncoming` and size-limited body collection, preserving the same `ErrorClass` / `connection_error` contracts as the reqwest path. H3 frontend requests bridged to a non-H3 backend are served through the same reqwest H1 SNI dial, on both the buffered and streaming legs, so an HTTP/3 client reaches a BackendTLSPolicy-covered backend exactly as an HTTP/1.1 or HTTP/2 client does; the bridge keeps the real target for its circuit-breaker, load-balancer, and `backend_target` accounting and rewrites only the dial. On that bridge the dial is resolved as a **local dispatch-policy decision** — before backend admission, before the least-connections connection-start record, and before any client is fetched — so an override that cannot be expressed (an unresolvable selected target) terminates with the same fail-closed `502` and `gateway-error-reason` without dialing the backend or relaying a request body, rather than silently connecting under the target-derived server name.

**WebSocket is the one transport that still refuses an override.** `client_async_tls_with_config` derives both the `Host` header and the TLS server name from the request URI, so a distinct SNI cannot be applied there at all. A `wss://` upgrade whose effective backend TLS carries an `sni` value is refused **before dialing** (`502`, non-retryable, neutral to the circuit breaker and passive health) rather than handshaking under the URI host. That is a runtime transport limitation, not an admission rule: the configuration is still accepted, because the same upstream may legitimately serve non-WebSocket traffic through the H1/H2/H3 SNI paths.

Active **HTTP and gRPC** health probes use the same effective backend TLS server name as request traffic: a `backend_tls_sni` override becomes the probe's TLS server name, so a backend whose certificate is valid only for the override name is not marked unhealthy while serving requests successfully. The probe still dials only the already-resolved, egress-screened target candidate, and the backend still sees its own authority — the HTTP probe puts the override in the probe URL (reqwest derives the server name from the URL and has no per-request hook) while pinning that client's resolver to the real target host and sending an explicit `Host`, and that probe client is restricted to **HTTP/1.1** so the explicit `Host` stays authoritative (HTTP/2 would rebuild `:authority` from the URI, i.e. from the server name); the gRPC probe sets `domain_name` / the rustls `ServerName` from the override while `origin` keeps the target authority. The override hostname is never itself resolved. An HTTPS+SNI HTTP probe therefore builds one client per target rather than one per upstream, and fails closed — never falling back to an unpinned client — if the dial cannot be pinned. TCP and UDP probes are unaffected (no TLS handshake).

## MeshSlice

`MeshSlice` is the per-node filtered view of mesh configuration, built by `MeshSlice::from_gateway_config()`. The CP computes a slice per subscriber; in native mode the slice is pushed directly, in xDS mode the translated resources are sliced locally.

The slice builder:

1. Filters workloads by namespace.
2. Finds the selected workload (if `workload_spiffe_id` is provided) to infer labels and narrow workload selection; `request.namespace` remains the effective request namespace and is not replaced by the selected workload's namespace.
3. Filters `MeshPolicy` entries by `PolicyScope` matching against the proxy's namespace and labels.
4. Filters `PeerAuthentication` entries by workload selector.
5. Filters `ServiceEntry` entries by `export_to` visibility.
5b. Filters `MeshDestinationRule` entries by `export_to` visibility, then by Istio's client → target-service → root lookup tier, then by Sidecar egress scope, and finally resolves the winning tier per destination (see [Export visibility](#destinationrule-visibility-and-lookup)).
6. Filters `MeshRequestAuthentication` entries by scope.
7. Filters `MeshTelemetryResource` entries by scope.
8. Filters `MeshProxyConfig` entries by [`PolicyScope`](#policyscope-filtering) — same predicate as `MeshPolicy`, so root-namespace ProxyConfigs apply mesh-wide.

## Authorization

Mesh authorization is evaluated by the auto-injected `mesh_authz` plugin (priority 2075) on every request that arrives on an **inbound** leg — see [Which leg enforces which policy family](#which-leg-enforces-which-policy-family-issue-4158) immediately below. In sidecar, ambient, east-west, and egress-gateway topologies, the plugin pre-filters applicable policies at construction time (cold path) so the request hot path evaluates only the relevant subset. In `NodeWaypoint` topology, one proxy instance serves many pods, so policy scope is resolved per pod on the request path from the node-waypoint identity resolver; a pod whose scope is absent (its workload left the live slice generation) **fails closed** when namespace/selector-scoped policies are configured, and falls through to mesh-wide-only when the mesh has only mesh-wide policies.

### Which leg enforces which policy family (issue #4158)

Istio `AuthorizationPolicy` is a **destination-side** contract: a policy without `targetRefs` authorizes traffic arriving *at* the workloads it selects, and an Envoy sidecar carries no RBAC filter on its outbound listeners. Ferrum follows that split exactly. `mesh_authz` is injected as a **global** plugin, so it is reached from every materialized route, but it evaluates policy only on legs whose accepting listener is `Inbound`:

| Leg | Listener | Direction | `AuthorizationPolicy` (`mesh_authz`) | Egress scoping |
|---|---|---|---|---|
| Sidecar inbound | mTLS `:15006` | `Inbound` | Enforced (DENY-first, then ALLOW, then implicit deny) | — |
| Ambient / waypoint inbound | HBONE `:15008` | `Inbound` | Enforced | — |
| NodeWaypoint transparent inbound capture | `FERRUM_MESH_INBOUND_LISTEN_ADDR` | `Inbound` | Enforced, per-pod scoped | — |
| East-west gateway | SNI passthrough `:15443` | `Inbound` | Enforced | — |
| Egress gateway | mTLS `:15090` | `Inbound` | Enforced — this is where mesh-external traffic is authorized | ServiceEntry (`location: mesh_external`) backends |
| Sidecar / Ambient outbound capture | plaintext `:15001` (+ UDP capture) | `Outbound` | **Not enforced** | `mesh_outbound_registry` (HTTP-family) / `MeshOutboundEnforcement` (stream-family) |
| NodeWaypoint in-netns pod capture | per-pod loopback capture | `Outbound` | Enforced, resolving the **destination** Service's backing-workload scopes | as above |

The discriminator is the listener that accepted the connection (`MeshRuntimeConfig::listener_plan` → `RequestContext::mesh_direction` / `StreamConnectionContext::mesh_direction`), not a port number inspected at request time.

**Closed configuration (issue #4525).** `mesh_authz` rejects unknown top-level `config` keys at construction. This matters more here than for a typical plugin: a misspelled policy key (`policies`, `mesh_policy` instead of `mesh_policies`) would otherwise build an instance carrying **zero** policies — no ALLOW rule, so the implicit-deny floor is never raised and the plugin **allows every request**. It is therefore a construction error — file mode fails startup, Admin create/update returns HTTP 400, and the plugin cache keeps the last known-good generation. The same closure covers `trusted_hbone_assertors`: an explicit `trusted_hbone_assertors: []` is the baggage-rewrite lockdown, while an absent key restores the built-in `["ztunnel", "waypoint"]` defaults (a misspelled key is rejected rather than silently restoring them). `workload_metrics` shares the same parser and the same closure. See [Trusted HBONE Assertors](#trusted-hbone-assertors). Nested objects are closed too (issue #6616): the embedded `mesh_slice` root, its `ext_authz_providers` entries with their `include_additional_headers_in_check` / `include_request_body_in_check` objects, its `peer_authentications` and `request_authentications` entries (with their JWT rules), its `telemetry_resources` entries, its `multi_cluster` object with its remote-cluster and east-west-gateway entries, and each `node_waypoint_route_upstreams` entry and target reject unknown members.

**Why the outbound capture leg is excluded.** On `:15001` the peer is the co-located application over plaintext loopback, so no source principal can ever exist. The implicit-deny floor is raised by policy *presence* (any applicable ALLOW rule), not by a match, so evaluating policy on this leg would let a single ordinary namespace-scoped ALLOW — a `from.principals` rule, a `to.operation.paths` rule, or Istio's "ALLOW with no rules" allow-nothing sentinel (translated to a never-matching rule) — reject **every** outbound request from **every** workload in the namespace with `mesh_authz.deny_policy = implicit-deny`. Applying a standard Istio `AuthorizationPolicy` must not take a namespace's egress offline.

**What still authorizes egress.** Excluding the capture leg does not make egress unauthorized:

- `outboundTrafficPolicy: REGISTRY_ONLY` (mesh-wide `MeshConfig`, an applicable `Sidecar`, or `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY`) is enforced **on the same capture leg** — by the auto-injected `mesh_outbound_registry` plugin for HTTP-family traffic and by `MeshOutboundEnforcement` at connect / first-datagram time for the stream family. An unregistered destination is refused there.
- A destination that is not in the slice has no materialized outbound route at all, so it is not reachable through the capture listener to begin with.
- Traffic leaving through an **egress gateway** is authorized by that gateway's own inbound (`:15090`) leg, where `AuthorizationPolicy` is fully enforced.
- Every in-mesh destination still enforces its own inbound policy set. A DENY is therefore enforced end to end — on one leg, not two.

**Operational consequence.** `AUDIT` policies do not record outbound-leg evaluations, and a DENY written with the intention of blocking a *source* workload's egress is enforced at the destination rather than at the source. Use `outboundTrafficPolicy: REGISTRY_ONLY` plus `ServiceEntry` scoping, or an egress gateway, to constrain what a workload may reach.

`NodeWaypoint` is the deliberate exception in the table: one proxy instance serves every enrolled pod on the node and its in-netns capture backend is stamped `Outbound`, but that branch evaluates the **destination** Service's backing-workload scopes (`policy_applies_for_destination`) rather than the local workload's inbound policy set. That is destination-scoped enforcement reached from a source-side leg, so it stays on — including its missing-scope fail-closed gate.

### PolicyScope Filtering

Every `MeshPolicy` carries a `PolicyScope`:

| Scope | Matches when |
|---|---|
| `MeshWide` | Always |
| `Namespace { namespace }` | `proxy_namespace == policy_namespace` |
| `WorkloadSelector { selector }` | Selector namespace matches (or is unset) AND all selector labels are present on the proxy with matching values (subset match) |
| `TargetRefs { attachments }` | Istio `AuthorizationPolicy.spec.targetRef` / `spec.targetRefs` attachment scope — see the dedicated section below. |

An empty `WorkloadSelector` (`labels: {}`, `namespace: None`) intentionally matches any workload.

The canonical matching helper `policy_scope_applies_to_workload()` is shared between the slice builder and the plugin filter so scope semantics stay byte-identical across both surfaces.

### AuthorizationPolicy `targetRef` / `targetRefs` (issue #3226)

`PolicyScope::TargetRefs { attachments }` models Istio's singular
`AuthorizationPolicy.spec.targetRef` and plural `spec.targetRefs` forms. Both
flow through the same resolver and exact-match runtime scope. The supported set
is deliberately narrower than the
[Istio reference](https://istio.io/latest/docs/reference/config/security/authorization-policy/):

| Attachment | Namespace rule | Status |
|---|---|---|
| `Service` (`""` / `core`) | same namespace as the policy | Supported |
| `Gateway` (`gateway.networking.k8s.io`) | same namespace as the policy | Supported (waypoint Gateways: `istio-waypoint` / `ferrum-waypoint`) |
| `GatewayClass` (`gateway.networking.k8s.io`) | cluster-scoped; policy must live in the Istio **root namespace** | Supported; the cluster-scoped object must exist |
| `ServiceEntry` (`networking.istio.io`) | — | **Rejected fail-closed** (see below) |

**Same-namespace only, no ReferenceGrant.** Istio lists all three namespaced kinds as same-namespace. A Gateway API `ReferenceGrant` does not widen an Istio policy-attachment contract, and Ferrum's CP namespace filter (`policy_scope_can_apply_to_namespace` → `resource_owner_can_apply_to_namespace`) drops a non-root policy owner before the target namespace's DP slice is built — so a "granted" cross-namespace attachment would be accepted and then silently inert. Translation and native/file config validation both reject it.

**`ServiceEntry` is refused, not modelled.** Waypoint bindings (`MeshWaypointBinding.services`) enumerate Kubernetes Services, and destination policy scopes are indexed by `MeshService` identity — there is no ServiceEntry ↔ waypoint association. A `ServiceEntry` attachment would therefore be either inert or, worse, latched onto an unrelated same-named Kubernetes Service. Ferrum refuses it with a scoped diagnostic until the association model exists; membership is never inferred from a shared name or shared selector labels.

**Retention is OR, matching is exact.** A policy is retained by a slice (and by the `mesh_authz` cold-path filter) when **any** attachment could apply, and the non-matching arms are deliberately not pruned — the slice stays a faithful copy of the operator's policy. Retention therefore proves nothing about *which* attachment matched, so every runtime consumer re-checks the exact attachment against its own authoritative evidence:

- `WaypointAttachment::matches()` — the single shared predicate for `Gateway` (exact `namespace`+`name` of *this* waypoint) and `GatewayClass` (exact `Gateway.spec.gatewayClassName` of *this* waypoint; `istio-waypoint` never attaches to `ferrum-waypoint`).
- `PolicyScopeCache::policy_applies_for_destination()` — `Service` attachments match exact destination `(namespace, name)` membership. The service identity is stamped from the Service the destination-scope index is keyed by (`PolicyScopeCache::for_destination_service`), never from `Workload.service_name`, so a pod projected through several Services yields one scope per Service.

Without this re-check, a mixed policy such as `targetRefs: [Service reviews, Gateway waypoint-b]` — legitimately retained at `reviews`' waypoint-a — would apply to **every** destination at waypoint-a through its unmatched `waypoint-b` arm.

**Mixed valid + missing attachments stay valid — but only for inventory misses.** Native/file/`MeshSubscribe` validation defers exactly one class of failure: an attachment that names an exact `(namespace, name)` which is absent from the inventory (a missing Service, or a missing Gateway checked against a *real* `waypoint_bindings` inventory). Such an arm can never match anything, so one missing sibling does **not** invalidate a policy that still has a valid applicable target — the unmatched arm is retained for OR semantics and never becomes a wildcard. When *every* attachment is unresolved the policy still fails closed, so it cannot silently broaden.

Structural and ownership refusals are **never** deferred and reject the whole policy even beside a valid sibling arm: empty/over-long names, cross-namespace Service/Gateway, unsupported GatewayClass names, and a `GatewayClass` attachment owned outside the Istio root namespace. The `GatewayClass` case is the security-critical one — `WaypointAttachment::matches` compares the **class name alone** (no namespace, no Gateway name), so a retained non-root class arm is a live cluster-wide wildcard over every waypoint of that class, not an arm that merely fails to resolve. Deferring it would let any namespace buy class-wide reach by pairing it with a single valid same-namespace Service arm; the K8s translator rejects it unconditionally and this boundary matches.

DP slices reconstruct `MeshConfig` without `waypoint_bindings`, so Gateway presence is not proven there; live `waypoint_name` / class stamps keep matching exact and fail-closed.

**Waypoint-only.** `targetRefs` policies apply at waypoint proxies only (Istio's rule). A slice with no `waypoint_name` matches no attachment at all, and the `mesh_authz` retain will not keep a `Service`-targeted policy just because that Service appears in a Sidecar's egress-narrowed `slice.services`.

**Missing evidence never becomes allow-by-default.** The authoritative waypoint class rides its own ECDS carrier over xDS. A waypoint slice carrying an *enforcing* (`ALLOW`/`DENY`) `GatewayClass`-targeted policy with no class stamp is refused rather than having the policy silently filtered out: the xDS reverse-translation boundary rejects the response (`validate_waypoint_gateway_class_carrier`, keeping the last-good slice), and `MeshAuthz::new` refuses the plugin generation on every source (native `MeshSubscribe`, file, embedded `mesh_slice`). `AUDIT`-only policies are non-enforcing and therefore exempt.

**`PolicyScopeCache` equality is source attestation.** `service_name` / `service_namespace` are set **only** on destination scopes. Ambient UDP source indexing and NodeWaypoint capture-destination resolution collapse duplicate workload records for one pod by comparing the whole struct, so stamping a per-projection service name into `from_workload`/`new` would make those records diverge and fail closed.

**Selector policy without proxy labels.** A `WorkloadSelector`-scoped policy whose selector carries labels cannot be evaluated when no proxy labels are resolved, and the cold-path filter would drop it (leaving an empty policy set that evaluates to `Allow`). The plugin distinguishes three cases at construction:

- **Slice-driven injection, ambiguous shared-SPIFFE (`labels_ambiguous`).** The slice flagged its labels as a non-authoritative shared-SPIFFE intersection and shipped the policy as a candidate-any superset for a label-holding consumer to re-filter. Reaching the plugin with empty `slice.labels` means that recovery already failed: the per-pod NodeWaypoint consumer skips this validation entirely (it re-filters per pod), and the xDS DP only leaves the labels empty when it had no local `FERRUM_MESH_WORKLOAD_LABELS` to prefer. There is no further consumer, so the policy demonstrably applies to a candidate workload yet would be silently dropped — a fail-open. Construction **fails closed** with an error; set `FERRUM_MESH_WORKLOAD_LABELS` (or `mesh_slice.labels`) for deterministic scoping. The same fail-closed rule covers a **non-empty intersection** that cannot satisfy a candidate-only selector (e.g. the slice intersection is `app=shared` but the superset carries a `role=api` policy): the partial intersection is not this workload's authoritative identity, so construction fails closed rather than dropping the candidate-only policy. Supplying an explicit `labels` override (the documented identity pin) **clears the ambiguous marker** — those labels are then authoritative, so a candidate-only selector that does not match them is correctly dropped by the cold-path filter instead of rejecting the workload.
- **Slice-driven injection, non-ambiguous.** The slice resolved empty labels and did **not** flag them ambiguous (e.g. a single-candidate or label-less workload), so those labels are authoritative for this workload and a label-based selector simply does not apply. Construction **tolerates** it with a warning and the cold-path filter drops it from enforcement for this slice.
- **Operator-direct config (flat `mesh_policies`, no slice).** There is no downstream consumer to recover labels, so silently dropping the policy would be a fail-open. Construction **fails closed** with an error requiring the operator to supply the proxy's `labels`.

**AUDIT-only policies are exempt from every fail-closed branch above.** An `AUDIT`-action policy is non-enforcing per Istio semantics — `evaluate_mesh_authorization()` records `mesh_authz.audit_policy` metadata and continues — so dropping an unscopable audit-only selector policy never opens an allow-by-default hole and is **not** a fail-open. Construction tolerates it (with a warning; the cold-path filter still drops it from evaluation) instead of rejecting the plugin, mirroring the per-pod NodeWaypoint missing-scope check, which already treats `AUDIT` as non-enforcing. A slice that carries an audit-only selector policy **alongside** an unresolvable enforcing (`ALLOW`/`DENY`) selector still fails closed on the enforcing one.

**Ambiguous slices fail closed in the mTLS/JWT consumers too.** When a `labels_ambiguous` slice reaches the DP with no local `FERRUM_MESH_WORKLOAD_LABELS` (so the marker is preserved and `slice.labels` is only the partial intersection), the candidate-any superset can still carry a selector-scoped `PeerAuthentication` (STRICT mTLS) or `RequestAuthentication` (JWT) that the partial intersection cannot resolve. Filtering those consumers solely against the intersection would silently drop the policy — a fail-open (Permissive instead of STRICT, or no JWT validation). Both consumers therefore fail closed while the marker is set: inbound mTLS resolution **escalates to the most-restrictive candidate mode** (a candidate-only STRICT forces STRICT, never downgrading below the normally-resolved mode), and request-auth injection **installs the candidate-only JWT provider** (Istio RequestAuthentication stays permissive — a request with no token still passes; only a forged/invalid token for that issuer is rejected). A non-ambiguous slice is enforcement-identical to the plain resolution. When the DP **does** supply local labels for an ambiguous slice, recovery **merges** the authoritative common intersection (the labels every candidate shares, which the CP proved apply) with the local labels (local wins on a key collision) so common-key selector mTLS/JWT/DENY rules stay enforced while local labels resolve the divergent keys; the marker is then cleared.

### Evaluation Semantics

`evaluate_mesh_authorization_full()` processes policies in Istio's action order:

1. **CUSTOM rules checked first** -- a matching CUSTOM rule delegates the decision to its `meshConfig.extensionProviders` external authorizer *before* any DENY or ALLOW tier can settle the request. See [AuthorizationPolicy `action: CUSTOM`](#authorizationpolicy-action-custom-issue-3235).
2. **DENY rules** -- first match returns `Deny`. A DENY still refuses a request an external authorizer was willing to admit.
3. **ALLOW rules** -- if any ALLOW rule exists in the policy set but none matched, the result is **implicit deny** (Istio semantics). A CUSTOM rule does **not** contribute to that implicit-deny floor: it delegates rather than grants.
4. **AUDIT rules** -- matched audit policies are returned for logging.
5. If no CUSTOM, DENY, or ALLOW rules exist, the result is `Allow`.

**Istio empty-rule semantics**: `ALLOW` with no rules is allow-nothing (emits a `never_matches` rule so the implicit deny applies). `DENY`/`AUDIT` with no rules are no-ops. `CUSTOM` with no rules is **rejected** at translation: a ruleless delegation has no matching surface, so admitting it would produce an accepted-but-inert policy.

### AuthorizationPolicy `action: CUSTOM` (issue #3235)

An `AuthorizationPolicy` with `action: CUSTOM` delegates matching requests to an
external authorization service declared in the **root-namespace**
`meshConfig.extensionProviders` list:

```yaml
# istio-system/istio ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: istio
  namespace: istio-system
data:
  mesh: |
    extensionProviders:
    - name: sample-ext-authz
      envoyExtAuthzHttp:
        service: ext-authz.istio-system.svc.cluster.local
        port: 8000
        scheme: https           # Ferrum extension, see "Provider transport"
        timeout: 0.5s
        pathPrefix: /check
        failOpen: false
        statusOnError: "403"
        includeRequestHeadersInCheck:
        - x-request-id
        includeAdditionalHeadersInCheck:
          x-ext-authz-caller: "ferrum-mesh"
        headersToDownstreamOnDeny:
        - www-authenticate
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: delegate-admin
  namespace: default
spec:
  action: CUSTOM
  provider:
    name: sample-ext-authz
  selector:
    matchLabels: { app: reviews }
  rules:
  - to:
    - operation:
        paths: ["/admin/*"]
```

**Provider resolution is root-namespace only.** `spec.provider.name` is resolved
against `meshConfig.extensionProviders` in `FERRUM_K8S_ISTIO_ROOT_NAMESPACE`.
A tenant namespace cannot introduce or shadow a provider, so cross-namespace
provider resolution is structurally impossible rather than filtered. Each
failure mode has its own field-shaped diagnostic and **rejects the resource**
(it is never accepted-but-inert):

| Condition | Outcome |
| --- | --- |
| `provider` absent / not an object / unknown field | rejected |
| `provider.name` empty, non-string, or over 253 bytes | rejected |
| name not declared in the root-namespace meshConfig | rejected, naming the root namespace |
| name declared as a tracing (or other non-ext-auth) provider | rejected, "is not an external authorization provider" |
| name declared as `envoyExtAuthzGrpc` | rejected, "a variant Ferrum does not implement" |
| `action: CUSTOM` with no `rules` | rejected |
| `provider` on a non-CUSTOM action | rejected |

**Supported provider shape.** Only `envoyExtAuthzHttp` is implemented: the
check is a bounded HTTP request. `envoyExtAuthzGrpc` is refused at admission
rather than approximated — the Envoy gRPC check API carries attributes Ferrum
does not model, and an approximation would silently change what a policy
authorizes. The `envoyExtAuthzHttp` key set is **closed**: an unmodelled field
(including the deprecated `includeHeadersInCheck`) is rejected rather than
ignored, so an operator can never believe a field is in force when it is not.
The enclosing extension-provider oneof is closed too: an entry carrying an
HTTP ext-authz block plus any sibling provider variant or unknown field is
rejected instead of choosing whichever recognized field appears first.

**Provider transport.** Istio derives the ext-auth transport from the
destination's own mesh configuration; Ferrum's provider dial does not go
through that path, so the operator states it with a `scheme: http|https` field
on the provider block. A **non-loopback** provider must use `https`: an
unencrypted off-box check (which may carry a forwarded credential) is refused
at admission. Loopback providers (`127.0.0.1`, `::1`, `localhost`) may use
plaintext.

**`service` must be a real bare URL host** — a DNS name, an IPv4 literal, or an
IPv6 literal (bracketed or bare). Userinfo (`@`), an embedded port, a path,
query, fragment, backslash, percent-encoding, or a bracket imbalance is
rejected at admission rather than deferred to a per-request URL parse.
`pathPrefix` is validated as a real path: it must start with a single `/` and
may not carry `?`, `#`, `\`, percent-encoding, a `.` / `..` segment, or a
leading `//` — those forms can be normalized or can move the request path into
a different URL component. The composed base URL is re-parsed at config
publication and must still carry only scheme, host, port, and path.

> **Deliberate narrowing:** Istio's namespace-qualified
> `[<namespace>/]<hostname>` service syntax is **not supported** and is
> rejected with a diagnostic naming it. Ferrum dials the provider directly
> rather than resolving it through the mesh service registry, so the namespace
> qualifier has no meaning here — and silently dropping it would dial a
> different service than the operator named. Declare the fully qualified
> hostname instead.

**`statusOnError` is an HTTP status.** Upstream Istio documents it as a status
**string**, so `statusOnError: "403"` is the real operator input shape; a JSON
integer (`403`) is also accepted for hand-authored Ferrum mesh documents. The
internal representation is numeric. A value outside 4xx/5xx, an Envoy enum
*name*, a float, or a non-numeric string is rejected rather than defaulted.

**At most ONE extension provider may apply to a request.** Istio permits one
extension provider per workload. Several CUSTOM policies naming the **same**
provider coalesce into one check. Two CUSTOM policies naming **different**
providers are refused: a workload-scoped conflict is rejected at plugin
construction (the previous valid generation keeps serving), and a request that
can see two distinct applicable providers across relay/waypoint destination
scopes is denied with the stable reason `custom:provider-conflict`. Ferrum
never picks the first match — that would let policy iteration order choose
which operator's authorizer enforces. Different providers on **disjoint**
workloads or destination scopes remain fully supported: the construction-time
refusal applies only where the generation's policy set really is one workload's,
so a node-waypoint generation (which serves every enrolled pod on the node from
one listener) and a waypoint generation (whose `targetRefs` retention spans
every fronted Service) may each carry one provider per pod / per destination,
and only a request that can genuinely see two is refused.

**CUSTOM runs before DENY across destination scopes too.** A request that spans
several destination scopes (a node-waypoint relay serving many backends)
evaluates **every** applicable scope before applying a decision: a DENY in an
earlier scope is recorded and the scan continues, so a delegation carried by a
later scope is still executed and still counted. The first DENY in scope order
remains the reported policy, and it still refuses the request once the check has
run — stopping the scan at that DENY would have let scope order decide whether
an operator's authorizer ever saw a request the scope it protects applied to
(and would have hidden a two-provider conflict living in a later scope).

Identical destination scopes are collapsed when the destination index is built
at slice apply, keeping first-occurrence order. Replicas of one Deployment share
an identity, namespace and labels, so a Service backed by hundreds of endpoints
costs one scope evaluation per request, not one per endpoint. Repeating a scope
cannot change the fold above (first DENY, first AUDIT, same-provider
delegations coalesce), so the decision, reported policy and delegation are the
same either way.

**Bounds.** `timeout` is capped at 30s (default 1s), `includeRequestBodyInCheck.maxRequestBytes`
at 1 MiB, provider response reads at 64 KiB, each header list at 32 exact
entries (case-insensitively unique), and the admitted provider set at 16 per
mesh generation. In-flight checks are capped at **128 process-wide** and are
**refused immediately** at the ceiling rather than queued, so provider slowness
cannot become unbounded gateway latency or memory growth. That budget is ONE
shared pool, not one per plugin instance: every enabled `mesh_authz` instance
and every overlapping reload generation draws from it, and a check that started
on a retiring generation stays charged until it finishes, because the permit
follows the request rather than the config version. There is no per-provider or
per-instance concurrency knob.

**Nothing is retried.** The check is dispatched through a dedicated
single-attempt seam on the shared plugin HTTP client, so it keeps that client's
no-proxy, redirect-disabled, DNS/egress-policy, TLS posture, redacted logging,
latency accounting, and typed failure classification while performing **exactly
one attempt** — `FERRUM_PLUGIN_HTTP_MAX_RETRIES` does not apply. A check is a
decision, not a report: replaying it would turn one client request into several
authorization decisions and amplify load onto a struggling authorizer.

**What the check carries.** The HTTP ext-auth protocol's automatic fields are
all present: the original request **method**, the (prefixed) **path**, the
original **Host** authority, and **Content-Length** when a body is sent.
Carrying the original authority is a header only — the connection is always
dialled at the provider's own configured `service`/`port`, so a client-supplied
authority can never route the provider connection. The query string is **not**
forwarded (a credential in it must not reach the provider). With the
[proxy hop limit](routing.md#proxy-hop-limit) enabled the check also carries
the request's gateway hop count as exactly one `X-Ferrum-Hops` field line
(`received + 1`, also on an inbound hop to the local workload), so a provider
that resolves back to a Ferrum gateway is refused at the limit. Provider
configuration cannot add another: `includeRequestHeadersInCheck` and
`includeAdditionalHeadersInCheck` refuse every `x-ferrum-*` name, in the `_`
or `-` spelling, at admission.
`includeAdditionalHeadersInCheck` values are **authoritative**: a fixed
operator header replaces any same-named client header or
`includeRequestHeadersInCheck` value rather than being appended beside it, and
case-variant duplicate fixed names are rejected at admission so the winner is
never iteration-order dependent. A forwarded client header sent as several
field lines reaches the provider as ALL of them, joined with `, ` (`; ` for
`cookie`) — the same single reading the policy matchers use (see
[Rule Matching](#rule-matching)).

**The check carries the authenticated caller.** Every check also carries the
gateway-asserted identity the local rules were evaluated against, so a
provider can make an identity-aware decision ("may workload X call Y") without
trusting a client header:

| Header | Value |
| --- | --- |
| `x-ferrum-source-principal` | The authenticated source SPIFFE ID (`spiffe://<td>/ns/<ns>/sa/<sa>`): the mTLS peer, or — for authenticated HBONE from a trusted assertor — the verified baggage identity the rules were judged on. |
| `x-ferrum-source-namespace` | The Kubernetes namespace component of that SPIFFE ID. |
| `x-ferrum-source-service-account` | The service-account component of that SPIFFE ID. |
| `x-ferrum-request-principal` | The validated JWT request principal (`<iss>/<sub>`) from the mesh `RequestAuthentication` plugin. |

These are **unforgeable**: provider admission refuses every `x-ferrum-*` name
in `includeRequestHeadersInCheck` and `includeAdditionalHeadersInCheck`, and the
executor removes the names before stamping them, so the provider only ever
sees the gateway's own value. An identity the gateway does not hold (a
plaintext caller, no validated JWT) is **absent**, never empty.

**Outcome classification** follows the Istio/Envoy HTTP ext-auth protocol
exactly:

| Provider response | Outcome |
| --- | --- |
| HTTP `200` | **allow** |
| HTTP `5xx` | **failed check** — follows `failOpen`; `statusOnError` when fail-closed |
| communication failure (connect / TLS / timeout, or an unreadable / oversize `200` response) | **failed check** — follows `failOpen`; `statusOnError` when fail-closed |
| any other status (3xx, 4xx, and any non-`200` 2xx such as `204`) | **explicit denial**, carrying the provider's own status |

The denial Ferrum emits is gateway-authored and carries a fixed JSON error
body, so a denial status that cannot frame content — `1xx`, a non-`200` `2xx`
such as `204`/`205`, and `304` — is replaced by a plain `403`. Forwarding one
verbatim would put `Content-Length` on a response the client is required not to
read a body for, leaving those bytes to be misparsed as the head of the next
response on an HTTP/1.1 keep-alive connection. `3xx` (except `304`) and `4xx`
pass through unchanged, so a redirect-to-login denial paired with
`headersToDownstreamOnDeny: [location]` still works. Every field line of a
forwarded denial header survives: two `Set-Cookie` lines (a login state cookie
and a nonce cookie) reach the client as two `Set-Cookie` fields on every
protocol, and repeated list-valued fields such as `WWW-Authenticate` are joined
with `, `. Only the unrepresentable
status is replaced: the decision is still a denial and is still counted as
`denied_by_provider`.

Ferrum never uses or forwards the provider response body. Once an explicit
denial status has arrived, that status remains authoritative even if its
discarded body is oversized or cannot be drained; `failOpen` therefore cannot
convert a provider denial into an allow through a body-framing failure.

An unavailable request body for a body-inspecting provider and a concurrency
refusal are failed checks and therefore honour the selected provider's
`failOpen`. **Three** refusals are decided **without** contacting a provider and
are therefore **not** subject to `failOpen`: a provider conflict (above), a
matched delegation on a connection with no HTTP request to check, and a request
body over the selected provider's `maxRequestBytes` (below).

**Two more refusals never consult `failOpen` either, because there is no
provider to consult.** A CUSTOM rule naming a provider this generation does not
carry, and a matched CUSTOM rule in a generation with no executor at all (no
outbound HTTP client, e.g. a direct `mesh_policies` config, which carries no
provider source), are **unconditional fixed `403` refusals**. Neither has a
provider whose `failOpen` or `statusOnError` could be honoured, so a `failOpen:
true` provider elsewhere in the generation does not admit them; both count once
as `provider_unbound` and as a fail-closed check. Configure the provider, or
delete the CUSTOM policy — a delegation that cannot be executed is never
allowed to fall through to the ALLOW/DENY tiers.

**Task cancellation ends the request; it never synthesizes an allow.** The check
runs under the ordinary request deadline, so when the request is cancelled the
check future is dropped mid-flight. Nothing is recorded, no `failOpen` decision
is made, and the client sees the cancellation — `failOpen` cannot turn a
cancelled request into an admitted one.

**Request body.** `includeRequestBodyInCheck.maxRequestBytes` is folded into
the proxy's pre-`authorize` body ceiling, so an over-cap request is refused with
**413 before the check is dispatched**. That shared ceiling is the **maximum**
`maxRequestBytes` across the generation's providers, because one prebuffer
serves whichever provider the matched CUSTOM rule selects — it is **not**
necessarily the selected provider's own cap, so a generation that also carries a
higher-cap provider lets a body over a lower-cap provider's `maxRequestBytes`
reach the check. The per-provider cap is re-enforced there as an
**unconditional client-facing 413**, before any provider I/O and before a
concurrency permit is taken, and it is **never** subject to `failOpen`: with
`allowPartialMessage` refused at admission there is no truncated body a strict
provider could have decided on, so an unrelated provider's larger cap can never
admit a request the selected provider's cap excluded. (A body that is *missing*
rather than too large stays an ordinary failed check and still honours
`failOpen`.) That ceiling and the buffering it implies apply **only** to
requests a body-inspecting CUSTOM rule could actually reach: the per-request
predicate is precise on method, path, and host, so an unrelated request on the
same workload keeps its ordinary accepted body size.

> **Deliberate narrowing:** `includeRequestBodyInCheck.allowPartialMessage:
> true` is **rejected at every admission boundary** (Kubernetes translation,
> the native/file mesh document, and the xDS carrier). Envoy's partial-message
> mode checks a bounded prefix and still forwards the complete original body
> upstream; Ferrum's authorize-phase buffer *is* the body the proxy forwards, so
> honouring the flag would mean either truncating the backend-visible request or
> retaining an unbounded body behind a cap the operator asked for. An
> accepted-but-unreachable flag would be worse than a visible refusal.

**Provider-driven header mutation.** All three Istio mutation lists are
honoured, each at one fixed point of the plugin chain:

- `headersToDownstreamOnDeny` — copied onto the gateway-authored denial this
  plugin itself produces.
- `headersToUpstreamOnAllow` — on an allowed check, the named provider response
  headers are applied to the backend-bound request in `mesh_authz`'s own
  `before_proxy` hook (priority 2075). That is ONE defined point on every
  HTTP-family ingress path (HTTP/1.1, HTTP/2, gRPC, HTTP/3, and the WebSocket
  handshake all build their backend request from that hook's header map):
  after authentication and authorization, **before** `mesh_route_dispatch`
  (2995) and every request transformer (3000), which can still observe or
  override the provider's value exactly as they would a client header. The
  listed names are **provider-owned** on an allowed check: the client's copy is
  removed in every spelling a backend folds together (case-insensitive, `_` ≡
  `-`), so a forged `x-auth-request-user` can never reach the backend beside or
  instead of the provider's value; the provider's value is then installed when
  it returned one. A `failOpen` allow (the provider could not decide) installs
  nothing and still strips the client's copies — nothing vouched for them. A
  request no CUSTOM rule matched is untouched. The names the instance can
  change are declared as `modified_request_header_names` — in every `_` / `-`
  spelling the removal folds — so replay/cache ordering and the early
  route-total preview account for them. Each `mesh_authz` instance stages and
  applies only its OWN allowed result, so an operator `mesh_authz` global
  beside the force-injected `__mesh_authz` cannot overwrite or consume the
  other's provider-owned names or cookies. This is
  stricter than Envoy, which forwards a client's same-named header when the
  provider omits one.
- `headersToDownstreamOnAllow` — on an allowed check, the named provider
  response headers are applied to the backend response in `mesh_authz`'s
  `after_proxy` hook (and to the successful WebSocket handshake). `Set-Cookie`
  is **appended** beside any backend cookie (the session-refresh pattern);
  every other name replaces the response's same-named field. It is not applied
  to a gateway-generated rejection: the provider's allow did not produce that
  response.

Allowed-request results are staged in typed per-request plugin state, never in
`metadata`, so a provider-minted token can never be serialized into a
transaction log. The allow lists refuse, in addition to the hop-by-hop,
framing, routing, mesh-identity, `forwarded`, `proxy-authorization`,
`x-forwarded-*`, and `x-ferrum-*` names every mutation list refuses: for
`headersToUpstreamOnAllow`, the gateway's own identity assertions (the whole
`x-consumer-*` namespace, `x-authenticated-identity`, the GeoIP result, and
`x-path-param-*` captures, in either `_`/`-` spelling), `content-*`, and
`set-cookie`; for `headersToDownstreamOnAllow`, `content-*`. Wildcard header
entries are refused because a prefix rule cannot be shown to exclude those
names. The provider's own response **body** is never echoed to the client.
Credentials (`authorization`, `cookie`) reach a provider only by being named
explicitly in `includeRequestHeadersInCheck`; the full client header map and
the request query string are never forwarded.

**Protocol coverage.** The check runs on every HTTP-family ingress path
identically — HTTP/1.1, HTTP/2, native gRPC, and HTTP/3 — because they share
one `authorize` ladder. Layer-4 sessions (raw TCP, TLS passthrough, UDP, DTLS)
and mesh/HBONE CONNECT relays, whose tunnelled requests are opaque bytes, carry
no HTTP request the provider could judge: a CUSTOM rule that **matches** one
**denies** it rather than serving it unchecked, and its HTTP-only fields are
unsourceable there (see [Layer-4 sessions and CONNECT relays](#layer-4-sessions-and-connect-relays)), so a CUSTOM
rule carrying `paths` / `methods` / `headers` / `when: request.auth.*` still
matches an L4 connection and still closes it. Scope a CUSTOM policy with `to.operation.ports` when the selected
workload also serves non-HTTP ports.

**Reload and withdrawal.** Providers ride the mesh slice (and their own
`ExtAuthzProvidersCarrier` ECDS carrier over xDS, re-validated at the ACK
boundary), and `MeshSlice::content_eq` compares them, so editing only
`meshConfig.extensionProviders` still republishes. Each slice carries only the
providers its retained policies actually bind. Deleting a CUSTOM policy retires
its executor with the generation — there is no background task or detached
queue to leak. A provider that cannot be prepared rejects the whole plugin
generation, so the previous valid one keeps serving.

**Observability.** `ferrum_mesh_ext_authz_checks_total{outcome}` and
`ferrum_mesh_ext_authz_check_failures_total{disposition}` are fixed-cardinality:
the labels are closed enums plus the gateway namespace, never a provider,
policy, route, host, principal, or status string. `mesh_authz.ext_authz_outcome`
request metadata carries a closed reason token from a RELATED but FINER
vocabulary — see the two tables below. Every matched delegation is counted
**exactly once**, including the outcomes decided without contacting a provider
(`provider_unbound` when no executor or no binding, `provider_conflict`,
`unexecutable` for an L4 session), so a fail-closed denial is never invisible.
No request body, credential header value, provider secret, or resolved provider
URL is ever logged.

The metric's `outcome` label has **twelve** values. Ten map one-to-one to a
reason token; two pairs of reasons are deliberately folded, because the
distinction inside each pair is a diagnostic detail rather than an operational
one:

| `outcome` label | `mesh_authz.ext_authz_outcome` reason token(s) | Meaning |
| --- | --- | --- |
| `allowed` | `allowed` | The provider answered `200`. |
| `denied_by_provider` | `denied_by_provider` | An explicit provider denial, carrying its own status. |
| `provider_unbound` | `provider_unbound` | The named provider does not bind, or the generation has no executor. Fixed `403`; never `failOpen`. |
| `provider_error` | `provider_error` | The provider answered `5xx` — it could not decide. |
| `provider_conflict` | `provider_conflict` | Two different extension providers applied to one request. Never `failOpen`. |
| `unexecutable` | `unexecutable` | A matched delegation on a connection with no HTTP request to check. Never `failOpen`. |
| `timeout` | `timeout` | The check exceeded the provider's `timeout`. |
| `transport_error` | `transport_error`, `request_build_failed` | The check could not be completed on the wire, or could not be built at all. |
| `response_refused` | `response_too_large`, `response_read_failed` | An allow response larger than the 64 KiB read bound, or one that could not be read. |
| `body_unavailable` | `body_unavailable` | A body-inspecting provider had no body to inspect. A failed check `failOpen` may admit. |
| `body_too_large` | `body_too_large` | The body exceeded the SELECTED provider's `maxRequestBytes`. The unconditional over-cap refusal. |
| `concurrency_exhausted` | `concurrency_exhausted` | The process-wide in-flight budget was full; refused immediately, never queued. |

`body_unavailable` and `body_too_large` stay separate series on purpose:
folding them would hide which of the two an operator is seeing, and only the
first honours `failOpen`. `ferrum_mesh_ext_authz_check_failures_total`
`{disposition}` splits the failed checks — every outcome except `allowed`,
`denied_by_provider`, `provider_conflict`, `unexecutable`, and `body_too_large`
— into `fail_closed` and `fail_open`.

When alerting, use the `outcome` label values above; the finer reason tokens
(`response_too_large`, `response_read_failed`, `request_build_failed`) appear
only in per-request `mesh_authz.ext_authz_outcome` metadata and in the
per-provider series below.

**Per-provider attribution.** A waypoint can legitimately carry one provider
per destination Service, so two series additionally attribute checks to the
provider that ran them:

- `ferrum_mesh_ext_authz_provider_checks_total{provider,outcome}` — every
  outcome decided for a resolved provider, with `outcome` drawn from the
  closed reason-token vocabulary above (`allowed`, `denied_by_provider`,
  `timeout`, `response_too_large`, …).
- `ferrum_mesh_ext_authz_check_duration_seconds{provider}` — a histogram of the
  time from dispatching a check to the provider's response headers (or the
  failure that ended it), with buckets from 1 ms to 30 s (the timeout ceiling).

`provider` is the **operator-admitted** `extensionProviders[].name`, never a
request-supplied value; outcomes decided before a provider is resolved
(`provider_unbound`, `provider_conflict`, `unexecutable`) appear only in the
process-wide series. The label set is bounded twice: at most 16 providers per
generation, and at most 64 distinct names per process — names first seen after
that share the `provider="__overflow__"` series, so no sequence of reloads can
grow the label set. Series persist across reloads (a renamed provider keeps
its old series until restart) and are emitted only once something was
recorded.

### Rule Matching

Each `MeshRule` checks the following dimensions (all must match — a conjunction):

- **Principal matching** (`from`): Istio source-principal patterns (`<trust-domain>/ns/<namespace>/sa/<service-account>`, glob), `serviceAccounts`, namespace patterns (glob), and trust-domain patterns. Full `spiffe://...` patterns are also accepted in direct `MeshPolicy` config. Multiple `from[]` source entries are ORed.
- **Request principal matching**: `request_principals` glob patterns matched against the `{issuer}/{subject}` composite extracted by `jwks_auth`. On an HTTP-family path, when `request_principals` is non-empty and no JWT is present, the rule does not match (Istio semantics: anonymous requests fail the principal check). An empty `request_principals` list matches any request including unauthenticated ones, on every protocol. `requestPrincipals` is a JWT-derived **HTTP-only** field, unsourceable on Layer-4 sessions (see [Layer-4 sessions and CONNECT relays](#layer-4-sessions-and-connect-relays)).
- **Source negation / IP blocks** (per-source, ANDed with the positive `from`): Istio `notPrincipals`, `notServiceAccounts`, `notNamespaces`, `notTrustDomains`, `notRequestPrincipals`, `ipBlocks`, `notIpBlocks`, `remoteIpBlocks`, `notRemoteIpBlocks`. These are **conjunctive** with the positive matchers. Negative identity matchers fail the rule only when the corresponding source/JWT identity is present and matches an excluded pattern; if the identity is absent, the negative matcher succeeds, so `DENY notPrincipals: ["*"]` and `DENY notRequestPrincipals: ["*"]` catch anonymous traffic. That absent-identity rule applies to `notRequestPrincipals` only where a JWT could have been observed: on a Layer-4 session the field is unsourceable, not absent (see [Layer-4 sessions and CONNECT relays](#layer-4-sessions-and-connect-relays)), so a `from:`-only `ALLOW` carrying `notRequestPrincipals` does not grant a raw TCP/UDP/TLS-passthrough session. IP block matchers fail closed when the IP they test is absent, so a positive `ipBlocks`/`remoteIpBlocks` constraint with no resolved IP does not match. `ipBlocks`/`notIpBlocks` match the direct connection peer IP (`source.ip`); `remoteIpBlocks`/`notRemoteIpBlocks` match the gateway-resolved client IP (`remote.ip`, XFF-derived when trusted proxies are configured). Unsupported source fields fail the resource closed at translation time (mirroring the `to.operation` side); a malformed CIDR rejects the resource or direct plugin config.
- **Request matching** (`to`): methods, paths (glob), hosts (normalized, case-insensitive), ports (exact + glob patterns), headers (case-insensitive keys, normalized at config load). The negative `to.operation` matchers (`notMethods`/`notPaths`/`notHosts`/`notPorts`) are conjunctive; `notPorts` accepts the same bounded Istio port grammar as positive `ports` (`"*"`, `"<digits>*"`, `"*<digits>"` that can match an ordinary decimal port in `1..=65535`, plus literal `1`-`65535`) and evaluates through pre-normalized `not_ports` / `not_port_patterns` without per-request allocation. ALLOW/AUDIT rules fail closed when the corresponding request attribute is absent (including an unresolved destination/listener port for `notPorts`); HTTP-only operation attributes are unsourceable on Layer-4 sessions (see [Layer-4 sessions and CONNECT relays](#layer-4-sessions-and-connect-relays)), so port scoping is recommended for DENY rules that mention HTTP fields and can see TCP traffic.
  Native `to.headers` matches only the ordinary HTTP request header map and rejects the pseudo-header names `:path`, `:method`, `:authority`, and `:scheme` during config validation, for every action. Use `to.paths`, `to.methods`, or `to.hosts` for those request facts; `when: request.headers[:path]` is also supported for path conditions and participates in the raw/stripped spelling rule below.
  **The same never-match refusals apply to a `mesh_authz` plugin configured directly** — the flat `mesh_policies` form (file, database, or Admin API plugin config) and an embedded `mesh_slice` — not only to a validated mesh document: a `to.headers` pseudo-header, an invalid `hosts` / `notHosts` pattern, an inadmissible `port_patterns` / `not_port_patterns` entry, an empty `from[{}]` or `to[{}]` entry, and an empty policy `name` / `namespace` reject plugin construction with a field-specific diagnostic. Each would otherwise be accepted and silently never match, which is fail-open for a DENY.
  **A repeated request header has exactly one reading.** When a client sends the same header as several field lines, `to.headers`, `when: request.headers[...]`, and the headers forwarded to a `CUSTOM` provider all judge the SAME value: every field line joined with `, ` (`; ` for `cookie`), exactly as the gateway materializes it for the backend — Envoy's header matchers likewise join repeated values. The reading no longer depends on whether some unrelated rule happened to force header materialization; once the request headers ARE materialized (every HTTP-family dispatcher does so before `authorize`), that view is authoritative, so a header an earlier plugin removed is absent for all three surfaces and is never read back from the pristine client block, and a header an earlier plugin published under an operator-cased key (`X-Tenant`) is found case-insensitively by all three surfaces, exactly as the backend receives it; a client cannot hide `x-tenant: banned` from a DENY behind an earlier `x-tenant: ok` line, and a pattern meant to catch a value that may arrive on a later field line should be written for the joined form (for example the suffix match `*banned`).
  Plugin-written case variants (for example `X-Tenant` alongside `x-TENANT`) are folded at the shared request-map boundary before authorization and egress. List fields join in byte-wise key order; known singleton fields prefer a lowercase key, otherwise the byte-wise smallest key. See the [complete request-map rule and singleton inventory](plugins.md#plugin-written-request-header-names).
  **`headers` is where absent and unsourceable differ observably.** On a Layer-4 session a `to.headers` predicate is unsourceable (see [Layer-4 sessions and CONNECT relays](#layer-4-sessions-and-connect-relays)). On an HTTP-family request Ferrum HAS parsed the header map, so a header the client simply did not send is genuinely **absent** and fails a positive `to.headers` predicate for **every** action, DENY and `CUSTOM` included — matching Envoy's `HeaderMatcher`, where a missing field never satisfies an exact non-empty value, and matching the sibling `when: request.headers[...]` condition, which has always drawn this distinction. A DENY carrying `headers: {x-mode: blocked}` therefore refuses an HTTP request that carries `x-mode: blocked` and lets an HTTP request with no `x-mode` header through to the remaining tiers; to refuse the header-less request as well, add a second rule with no header predicate. `methods`, `paths`, `hosts` and `ports` are unaffected in practice: an HTTP-family request always carries a method and a canonical path, and a request with no resolvable authority or port has nothing for the matcher to read.
  `hosts` and `notHosts` match the literal requested hostname/authority after case, trailing-dot, and decimal-port normalization; they do not identify a service or expand its aliases. For example, one service may be reachable as `svc`, `svc.ferrum`, `svc.ferrum.svc`, and `svc.ferrum.svc.cluster.local`. A DENY naming only the FQDN does not cover the short-name aliases. To cover a destination, use an appropriately scoped policy with `to.ports`, enumerate every admitted alias, or choose a host wildcard whose breadth you intend (for example, `svc*` also covers other names beginning with `svc`). A host pattern without a port also matches that hostname with a port; explicit decimal ports are compared numerically (`svc:080` and `svc:80` are equivalent), `:*` remains a wildcard, and signed request ports are invalid. Host matching describes what the client asked for, not which service ultimately receives it.

- **Condition matching** (`when`): attribute-based with `values` (the attribute must be present and equal one of the values) and `not_values` (the attribute must not equal any value; an absent attribute satisfies a `not_values`-only condition, matching Istio's compiled `not_rule` semantics). Values follow Istio's `StringMatcherWithPrefix` grammar for most keys: `*` is a presence check, a trailing `*` is a prefix match, a leading `*` is a suffix match, and anything else — including a mid-string `*` — is an exact match on the literal text. **Three keys have their own Istio grammar and do not use that matcher** — `source.ip` / `remote.ip` / `destination.ip` are CIDR blocks, `source.serviceAccount` is an exact namespace-relative match, and `source.namespace` accepts a `*` at any position (see [Value grammars](#value-grammars-per-key) below). **Ferrum represents the complete documented Istio condition-key set** (see [Condition keys](#condition-keys) below): `source.principal` (Istio form without the `spiffe://` scheme), `source.namespace`, `source.serviceAccount`, and `source.trustDomain` (all from the resolved peer SPIFFE ID), `source.ip`, `remote.ip`, `destination.ip`, `destination.port`, `connection.sni`, `request.auth.principal`, `request.auth.presenter` (JWT `azp`), `request.auth.audiences`, `request.auth.claims[<name>]` and nested `request.auth.claims[<name>][<nested>]` string or string-list leaf values (from the validated JWT via the mesh `RequestAuthentication` plugin), `request.headers[<name>]`, and `experimental.envoy.filters.<filter>[<key>]`. Dynamic header/claim keys follow Istio's loose `validateMapKey` framing: the first `[` and final `]` delimit a non-empty interior, without an extra HTTP-header-name parse at policy admission. Known HTTP pseudo-headers (`:authority`, `:method`, `:path`, `:scheme`) come from typed request facts; unusual admitted interiors that no request or validated claim can materialize remain absent. Keys outside the documented prefixes are **rejected** at translation/config validation time with a field-specific diagnostic, so a DENY condition on an unmodelled attribute cannot silently fail open. Only the attribute keys some loaded policy references are materialized per request, so a policy set with no `when:` conditions adds no hot-path cost.

#### Layer-4 sessions and CONNECT relays

Istio's non-HTTP-port rule distinguishes two facts, and Ferrum models them separately:

- *Absent* — the path CAN source the attribute and this request simply does not carry it (a header the client omitted, an SNI-less plaintext connection, no validated JWT). Ordinary rules apply: a `values` check fails, and a `notValues`-only check passes.
- *Unsourceable* — the path can NEVER carry the attribute, or required transport evidence could not be recovered. That covers every HTTP-only field on a Layer-4 session (raw TCP, TLS passthrough, UDP, DTLS — anything authorized through the `on_stream_connect` hook, with no header map or JWT context) and on a mesh/HBONE CONNECT relay (whose tunnelled requests are relayed unparsed), plus the transport keys listed under [Condition keys](#condition-keys) when evidence is missing.

HTTP-only fields are `requestPrincipals` / `notRequestPrincipals`, the `to.operation` fields (`methods`, `paths`, `hosts`, `headers` and their negations), and `when: request.headers[...]` / `request.auth.*`. For an unsourceable field Ferrum is fail-closed in both directions: a **DENY** or **CUSTOM** rule ignores the field and still matches on its remaining constraints, and an **ALLOW** or **AUDIT** rule can never match. A matched CUSTOM rule on an L4 session or CONNECT relay refuses the connection without asking the provider. Access is never granted on an attribute the gateway cannot read, and an unevaluable condition can never disarm a DENY.

A mesh CONNECT relay (HBONE `:15008`, or a bare authenticated H2 CONNECT on the Sidecar `:15006` listener) is judged only on what it can observe — source identity, source/remote/destination IP, destination port, SNI. On a Sidecar, a bare CONNECT to a port served by a materialized HTTP inbound route is refused outright (`http_application_port`, see [Inbound Relay Destination Guard](#inbound-relay-destination-guard)), so HTTP traffic to that port is always judged as HTTP.

#### Request-path matching is done on the canonical path

`paths:` / `notPaths:` (and the `request.headers[:path]` condition) are matched
against the **canonical policy path**, not the raw request target. Ferrum
canonicalizes every HTTP/1.1, HTTP/2, and HTTP/3 request target once at the
frontend boundary — before routing, before any plugin phase, and before backend
dispatch — so the string the policy matcher reads is the string the backend
resolves. This is what stops a path-scoped DENY from being evaded, or a
path-scoped ALLOW from being widened, by an alternative spelling of the same
resource. A path that carries a `;` parameter (only possible on a service that
opts in) is matched on both its raw and its parameter-stripped spelling; see
[Authorization on an opted-in service](#path-parameters-and-the-per-service-opt-in).

A target that has more than one reading is **refused with `400`** rather than
rewritten into one of them:

| Target | Result | Reason token |
| --- | --- | --- |
| `/public/../admin/secret`, `/./admin`, `/admin/.`, `/public/..;/admin/secret` | `400` | `literal_dot_segment` |
| `/x/%2e%2e/admin`, `/%2e/admin`, `/x/%2e%2e;/admin`, `/x/..%3B/admin` | `400` | `ambiguous_dot_segment` |
| `/admin%2Fsecret` | `400` | `encoded_separator` |
| `/admin%252Fsecret`, any `%25` | `400` | `double_encoding` |
| `/api%20name`, any escape of a non-`pchar` byte | `400` | `unrepresentable_escape` |
| `/admin\secret`, `/admin%5Csecret` | `400` | `literal_backslash` / `encoded_backslash` |
| `//admin`, `/a//b`, `/;x/admin`, `/%3Bx/admin` | `400` | `empty_segment` |
| `/admin;x/users`, `/v1;version=2`, `/admin%3Bx/users` | `400` | `path_parameter`, unless the destination service opts in (see [below](#path-parameters-and-the-per-service-opt-in)) |
| `/%61dmin` | served as `/admin` | — (escape of a `pchar` byte is decoded) |
| `/a..b`, `/...`, `/v1.0/x`, `/a/` | served unchanged | — (dots inside a segment NAME are not dot segments; a trailing slash is not an empty segment) |

**Divergence from Istio, deliberate.** Istio/Envoy applies
`meshConfig.pathNormalization: DEFAULT` (RFC 3986 `remove_dot_segments`) and
*rewrites* `/public/../admin` to `/admin` before RBAC. Ferrum refuses it
instead. Removing dot segments is itself a second reading of the target, so a
backend that does not remove them would still resolve a different path than
policy evaluated; refusing cannot disagree with any backend. Operators
migrating a policy set that relied on Envoy's rewrite should expect such
requests to fail with `400` rather than be silently normalized — no
authorization decision is ever taken for them.

`mesh_authz` re-runs the same canonicalizer before it evaluates a rule. On every
target the boundary admits this is the identity and allocates nothing; a target
that somehow reached authorization without passing the boundary is denied
(`403`) and recorded with `mesh_authz.deny_policy = non_canonical_path`, never
matched literally.

Full contract, reason tokens, and the operational impact on the rest of the
gateway: [docs/request_path_canonicalization.md](request_path_canonicalization.md).

#### Path parameters and the per-service opt-in

A `;` in the canonical path (literal, or decoded from `%3B`) is refused with
`400 path_parameter` by default, because backends such as Tomcat and Spring
strip `;…` from path segments and would execute a different path than routing
and `mesh_authz` evaluated (GHSA-fcqw-793q-wg5x). Java servlet applications
that rely on URL-rewritten session ids (`/app/;jsessionid=…`,
`/app/page;jsessionid=…`) need the opt-in:

- **Native / file / Ferrum CP:** set `allow_path_parameters: true` on the
  `MeshService`. It rides the slice and the xDS `ServicesCarrier`, so every
  client sidecar and the service's own sidecar see it.
- **Kubernetes:** annotate the Service with
  `ferrum.io/allow-path-parameters: "true"`. Only `true` (any case) enables it.
  `false` keeps the default, and any other value is warned about and ignored.
- **Stock xDS control planes** cannot carry the field, so their services stay
  refused.

The opt-in applies to the routes mesh mode materialises for the service: the
outbound routes on every client (direct Pod-IP routes included), which let the
client forward the request, and the destination's Sidecar inbound and
`ingress[]` routes, which deliver it. A service that has not opted in keeps
refusing `;` on both legs.

The re-route check still applies unchanged. An opted-in `;` request is
resolved again with every parameter stripped, the same way it was resolved
(same host, listener, mesh direction filter, and port-sibling selection from
the same original destination or authority port), and refused when the
stripped path belongs to another route on the service's hosts. Materialised
routes are `/` prefixes on their own service's hosts, and a `;` changes
neither the host nor the port, so it cannot move a request onto another
service or another port sibling. It cannot skip an explicit, longer route on
the same host either: `/admin;x/users` is refused when an `/admin` route
exists there. Full rule:
[request_path_canonicalization.md](request_path_canonicalization.md#mesh-materialised-routes).

**Authorization on an opted-in service.** A `;` request to an opted-in
service has two spellings: the raw path (`/admin;x/users`) and the path with
its parameters stripped (`/admin/users`), which Tomcat and Spring execute.
`mesh_authz` evaluates each `AuthorizationPolicy` rule once per spelling, with
`to:` `paths:` / `notPaths:` and any `when: request.headers[:path]` condition
reading the same spelling, and combines the two results by action
(issue #5948):

| Action | The rule matches when |
|--------|-----------------------|
| `DENY`, `CUSTOM`, `AUDIT` | it matches on either spelling |
| `ALLOW` | it matches on both spellings |

So a `notPaths:` or `notValues:` exclusion lifts a DENY only when both
spellings are excluded, and removes an ALLOW grant when either one is. As a
result:

- a DENY on `/admin/*` refuses `/admin;x/users`, including a mesh-wide DENY
  owned by the platform team on a service whose owner opted in, and including
  a DENY written as `when: request.headers[:path]`;
- a DENY on `/api/admin/*` refuses `/api;x/admin/users`;
- an ALLOW on `*.png` does not admit `/admin/users;x.png`;
- an ALLOW on `/api/*` with `notPaths: ["/api/admin/*"]`, or with a `:path`
  condition `notValues: ["/api/admin/*"]`, does not admit
  `/api/admin;x/users`;
- a prefix ALLOW (`/app/*`) still admits `/app/page;jsessionid=abc`, and an
  exact ALLOW (`/app/page`) still does not match `/app/page;jsessionid=abc`.
  Write a prefix rule, such as `/app/page*`, for an exact path that must
  accept a `;jsessionid=` suffix.

The combination is per rule: the ALLOW implicit-deny floor is met only by one
ALLOW rule that matches on both spellings, so two ALLOW rules that each match
one spelling leave the request implicitly denied.

Residual behaviour to account for:

- The second spelling is built whenever the canonical path carries a `;`, and
  only routes with `allow_path_parameters` let such a request reach
  `mesh_authz`, so services that have not opted in are unchanged: they refuse
  `;` with `400 path_parameter` first.
- Other plugins that match on the request path still see the parameterised
  path, so review path-based plugin configuration on the routes of an
  opted-in service.
- A CUSTOM (ext_authz) provider receives the raw path only. A provider that
  makes its own path decisions must apply the stripped rule itself.
- VirtualService routes never inherit the service's opt-in. A route whose own
  `uri` literal contains `;` opts in by itself, and `mesh_authz` judges both
  spellings on it. Any other VirtualService route refuses `;`, and a `;`
  request whose stripped path belongs to one is refused by the re-route
  check. A VirtualService `/` route on the service's host makes the mesh route
  yield to it, so the service opt-in does not apply there and `;` stays
  refused (fail closed).

Full rule:
[request_path_canonicalization.md](request_path_canonicalization.md#mesh-authorization-judges-both-spellings).

#### Condition keys

Every key documented in Istio's [AuthorizationPolicy conditions](https://istio.io/latest/docs/reference/config/security/conditions/) reference is represented. The table below is the authoritative Ferrum support matrix; `MeshConditionKeyKind` in `src/modes/mesh/config.rs` is the typed classification behind it.

| `when[].key` | Value form | HTTP-family | TCP / TLS passthrough | UDP / DTLS | Source of truth |
| --- | --- | --- | --- | --- | --- |
| `source.principal` | Istio string match | yes | yes | yes | verified peer SPIFFE ID (post-baggage rewrite), scheme-less Istio form |
| `source.namespace` | wildcard, `*` at any position | yes | yes | yes | `ns` segment of the verified peer SPIFFE ID |
| `source.serviceAccount` | exact `<namespace>/<sa>` or bare `<sa>` | yes | yes | yes | `<namespace>/<service-account>` from the verified peer SPIFFE ID |
| `source.trustDomain` | Istio string match, restricted grammar | yes | yes | yes | trust domain of the verified peer SPIFFE ID |
| `source.ip` | CIDR / bare IP | yes | yes | yes | immediate socket peer (`direct_client_ip`), pre-PROXY-protocol |
| `remote.ip` | CIDR / bare IP | yes | yes | yes | resolved client IP after trusted XFF / PROXY protocol |
| `destination.ip` | CIDR / bare IP | yes | yes | no (see below) | captured pre-NAT original destination, else the connection's local address |
| `destination.port` | numeric `0..=65535` | yes | yes | yes | mesh inbound app port / captured outbound port / listener port |
| `connection.sni` | Istio string match | yes | yes | yes | frontend TLS / QUIC / DTLS ClientHello SNI; cross-cluster traffic arrives with the east-west alias `p<port>.<fqdn>` (`p<port>-udp.<fqdn>` for UDP), never the bare service FQDN |
| `request.auth.principal` | Istio string match | yes | HTTP only | HTTP only | validated JWT `iss/sub` |
| `request.auth.presenter` | Istio string match | yes | HTTP only | HTTP only | validated JWT scalar `azp` |
| `request.auth.audiences` | Istio string match | yes | HTTP only | HTTP only | validated JWT `aud` |
| `request.auth.claims[<name>]`, `request.auth.claims[<a>][<b>]` | Istio string match | yes | HTTP only | HTTP only | validated JWT scalar / string-list leaf claims |
| `request.headers[<name>]` | Istio string match | yes | HTTP only | HTTP only | request headers, matched case-insensitively; `:authority`, `:method`, `:path`, and `:scheme` use typed request facts |
| `experimental.envoy.filters.<filter>[<key>]` | Istio string match | never sourceable | never sourceable | never sourceable | Envoy dynamic metadata; Ferrum has no Envoy filter chain |

**`connection.sni` on cross-cluster traffic.** A destination sidecar or terminator reads the ClientHello SNI the client sent through the east-west gateway. That SNI is the per-port [east-west alias](#multi-port-cross-cluster-sni-aliases), `p<port>.<service>.<namespace>.svc.<cluster-domain>` (or `p<port>-udp.…` for UDP), for single-port and multi-port services alike. A `connection.sni` value written against the bare service FQDN therefore never matches cross-cluster traffic, and a DENY rule written that way does not apply to it. Match the alias instead, or use a suffix match such as `*.reviews.default.svc.cluster.local` to cover every port.

The same holds for `notValues`: a bare-FQDN `notValues` entry does not exclude cross-cluster traffic, so a DENY rule with `notValues: ["reviews.default.svc.cluster.local"]` still denies it. To deny every port of a service to cross-cluster clients, match the aliases with a suffix:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-reviews-sni
  namespace: default
spec:
  action: DENY
  rules:
  - when:
    - key: connection.sni
      # Matches p9080.reviews.default.svc.cluster.local,
      # p5353-udp.reviews.default.svc.cluster.local, and every other alias.
      values: ["*.reviews.default.svc.cluster.local"]
```

The suffix match requires the leading `.`, so it does not match the bare FQDN itself. Add `reviews.default.svc.cluster.local` to `values` if a client also sends that SNI. To name one port, list its alias, for example `p9080.reviews.default.svc.cluster.local`.

**Bare-FQDN warning.** When a data plane prepares a mesh slice, it logs a warning when an exact `connection.sni` value names a service's bare FQDN. This covers `values` and `notValues` under any action. The warning names the policy and the value and suggests `*.<fqdn>` or the explicit `p<port>[-udp].<fqdn>` aliases. It is logged once per policy and value. A value counts as a bare FQDN when it equals the base FQDN of a service in the slice, or when it has the Kubernetes Service FQDN shape `<service>.<namespace>.svc.<cluster-domain>` for the proxy's cluster domain. The shape check covers services outside the proxy's service view, such as those a Sidecar egress scope leaves out. Values containing `*` and the `p<port>[-udp].<fqdn>` aliases are never reported. The warning does not change matching.

**`connection.sni` value spelling.** Values are compared as strings with the received ClientHello SNI. Ferrum lowercases every received SNI. On TLS-terminated HTTP/1.1, HTTP/2, HTTP/3, and TCP connections, rustls accepts a trailing root dot (`admin.example.com.`), and Ferrum strips exactly one before policy sees the name. Ferrum's own ClientHello parser, used where Ferrum reads a ClientHello without terminating TLS, refuses a trailing dot. Every configuration surface (Kubernetes translation, file and native config, and `mesh_authz` construction) normalizes `connection.sni` values at load to the same spelling:

- A single trailing `.` is stripped. A value ending in `..` is left as written; it never matches.
- ASCII is lowercased.
- A non-ASCII (U-label) name is converted to its A-label (`xn--…`) with IDNA, so `bücher.example` becomes `xn--bcher-kva.example`. IDNA maps the ideographic and fullwidth full stops (`。`, `．`, `｡`) to `.`, and a trailing dot the conversion produces is stripped too. In a wildcard value, only the whole labels after a leading `*.` or before a trailing `.*` are converted (`*.bücher.example` becomes `*.xn--bcher-kva.example`).

This makes Ferrum looser than Istio on Envoy for these spellings. Envoy compares the policy text as written, so a value with a trailing dot or a U-label never matches there. In Ferrum it matches the normalized SNI. For an ALLOW rule, that means Ferrum admits connections that Envoy would not; for a DENY rule, Ferrum enforces a rule that is inert on Envoy. Write the lowercase A-label without a trailing dot to get the same behavior on both.

A non-ASCII value that cannot be converted is rejected with a field-specific validation error, in `values` and in `notValues`. Conversion fails when IDNA refuses the name, when the non-ASCII text sits in a label that a `*` only partly covers (`bü*`), or when the non-ASCII value also contains `%`. On Kubernetes, that error means the AuthorizationPolicy is not installed, so write such a name as its A-label. Other ASCII characters that DNS hostnames do not allow are not rejected either. A value containing a space or `/`, for example, is admitted and never matches.

##### Value grammars (per key)

Istio does **not** compile every condition key to the same matcher, and Ferrum follows it key by key. Treating them uniformly is not a cosmetic simplification: a value that silently never matches is fail-OPEN for a DENY.

| Key | Grammar | Istio source |
| --- | --- | --- |
| `source.ip`, `remote.ip`, `destination.ip` | CIDR block or bare IP; containment, never string matching | `ValidateIPs` |
| `destination.port` | strict decimal `0..=65535` | port validation |
| `source.serviceAccount` | **exact** `<namespace>/<service-account>`, or a bare `<service-account>` resolved against the namespace of the `AuthorizationPolicy` that declared it. `*` is **rejected** at admission — Istio compiles this key to an exact matcher, so a wildcard would install a condition that can never fire | `CheckServiceAccount`, `serviceAccountRegex` |
| `source.namespace` | wildcard match where **every** `*` is an arbitrary substring, at any position — a leading, trailing, mid-string, or repeated `*` all behave as wildcards | `srcNamespaceGenerator` |
| `source.trustDomain` | exact, presence `*`, one **leading** `*`, or one **trailing** `*`. A mid-string or repeated `*`, and any `/`, are **rejected** at admission | `CheckTrustDomainValues` |
| everything else (`source.principal`, `connection.sni`, `request.auth.*`, `request.headers[...]`, `experimental.envoy.filters.*`) | `StringMatcherWithPrefix`: `*` presence, `<prefix>*`, `*<suffix>`, otherwise exact — a mid-string `*` is **literal text** | `matcher.StringMatcherWithPrefix` |

Canonical SPIFFE workload paths `ns/<namespace>/sa/<service-account>` are read
positionally: `spiffe://cluster.local/ns/sa/sa/backend` identifies account `backend`
in namespace `sa`, producing `source.serviceAccount = sa/backend` for both HTTP
and stream authorization.

A bare `source.serviceAccount` is namespace-relative, so the same policy text means different things in different namespaces:

```yaml
# In namespace `payments`: matches only payments/checkout.
# The same YAML applied to namespace `web` matches only web/checkout.
- key: source.serviceAccount
  values: ["checkout"]
# Explicit form, namespace-independent.
- key: source.serviceAccount
  values: ["payments/checkout"]
```

**Absent vs unsourceable.** Defined once under [Layer-4 sessions and CONNECT relays](#layer-4-sessions-and-connect-relays); `source.ip`, `remote.ip`, `destination.ip`, or `destination.port` with no typed transport evidence, and every `experimental.envoy.filters.*` key, are unsourceable.

`destination.ip` evidence comes only from the transport — a trusted inbound PROXY-protocol tuple, `SO_ORIGINAL_DST`, node-waypoint eBPF capture metadata, the listener's specific bind address, or the accepted socket's local address. It is never derived from `Host`, `X-Forwarded-*`, or any other client-settable input: a client that could choose its own `destination.ip` could choose which destination-scoped rule judges it. UDP and DTLS sessions carry no such evidence, so a `destination.ip` condition there is unsourceable and fails closed as described above. A captured original destination always wins over the socket's local address, because on a capture listener the socket's local address is the interception port rather than the address the client dialled. This mesh-authz connection fact is separate from VirtualService L4 `destinationSubnets` evidence: stream routing accepts only the trusted PROXY/capture original destination, never an ordinary listener's bind/local address.

**A documented-but-unsourceable key does not reject the policy.** Rejecting the resource would drop the whole `AuthorizationPolicy`, which is fail-OPEN for a DENY, so `experimental.envoy.filters.*` conditions install normally and are enforced with the unsourceable semantics above.

**Validation and bounds.** Every configuration surface — the Kubernetes Istio translator, `MeshConfig` file/native validation, and the `mesh_authz` construction gate — runs the same `validate_mesh_condition` contract and reports field-specific diagnostics (`rules[].when[2].values[0] …`). It rejects: an unsupported or empty key, a key over 256 UTF-8 bytes or containing control characters, a condition with neither `values` nor `notValues`, an empty value, a value over 512 UTF-8 bytes or containing control characters, a malformed `source.ip` / `remote.ip` / `destination.ip` CIDR, a non-numeric or out-of-range `destination.port`, a `source.serviceAccount` containing `*` or more than one `/` (or with an empty namespace / service-account half), and a `source.trustDomain` containing `/`, more than one `*`, or a mid-string `*`. Whitespace or other unusual printable bytes inside a dynamic header/claim map key are admitted because Istio's `validateMapKey` admits them; if the request path cannot materialize that exact key, it remains absent. Every rule applies identically to `values` and `notValues` — a bound or grammar enforced on only one direction would leave the other fail-open. Collections are bounded at 64 `when[]` entries per rule and 256 entries per `values` / `notValues` list; `source.serviceAccount` carries Istio's stricter caps of 16 entries per list and 320 UTF-8 bytes per value. An externally supplied policy therefore cannot grow unbounded per-request matching work. Raw validation errors double-quote and Debug-escape unsupported keys and invalid IP blocks; rendered startup and `validate` diagnostics withhold these document values while retaining the field/index and rejection reason.

### SPIFFE Identity

The [`spiffe_identity`](plugins.md#spiffe_identity) plugin (priority 940) extracts the peer SPIFFE ID from TLS/DTLS client certificates on every inbound request. Configuration, admission, hooks, outputs, trust-domain grammar, and invalid-SVID behavior are documented in that plugin reference. This identity feeds into:

- `mesh_authz` principal matching
- Workload metrics labels (`source.principal`, `destination.principal`)
- SPIFFE-only identity admission sets the verified peer identity, provenance, and certificate-validity deadline; by itself it does not set transaction-summary `auth_method`. A separate authentication plugin may populate that field.

**SPIFFE-only chains are lifetime-bounded.** The mesh injection installs
`spiffe_identity` plus `mesh_authz` and does not require `mtls_auth`, so on those
chains the SVID alone authorizes the request. `spiffe_identity` therefore admits
a certificate-derived peer identity as an authenticated principal carrying the
leaf's `notAfter` as its authorization deadline, on the same protocol-neutral
contract `mtls_auth` uses for Consumer-mapped certificates. Requests and streams
authorized only by a peer SVID are re-checked against the leaf's validity window
on every request and are terminated at SVID expiry (or the finite
`FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS` fallback, whichever is
earlier) instead of running for the life of the transport connection. A
pre-stamped kernel-attested (node-waypoint eBPF) or HBONE-asserted
`peer_spiffe_id` carries no certificate validity window and is deliberately not
treated as certificate-bounded; explicit trust withdrawal remains the separate
mechanism described under
[frontend_tls.md — Expiry is not revocation](frontend_tls.md#expiry-is-not-revocation).

**Trust withdrawal on established inbound connections is bounded by the SVID
lifetime.** Withdrawing a peer's trust domain from the inbound SPIFFE bundle, or
publishing a CRL that revokes its leaf, is enforced on every new inbound
handshake and — through the [HBONE Admission Fence](#hbone-admission-fence) — on
every HBONE CONNECT and live tunnel. An already-established *ordinary* inbound
HTTP/1.1 keep-alive, HTTP/2, or HTTP/3 connection to a Sidecar inbound or
waypoint HTTP listener is not re-judged against the new trust: its cached
principal keeps authorizing new requests until the leaf's `notAfter` (the
per-request temporal re-check above) or until the connection closes. Mesh
inbound listeners are deliberately outside the generic frontend client-trust
retirement domain (a gateway CRL publication must not retire mesh peers), and no
mesh-scoped equivalent exists for the non-HBONE request path yet. Keep issued
SVID TTLs short (SPIRE's default is about one hour) when a trust withdrawal must
cut existing connections promptly.

For production deployments, Ferrum delegates SVID issuance and trust-bundle
distribution to a separately operated [SPIRE](https://spiffe.io/docs/latest/spire-about/)
installation. See [docs/spire_deployment.md](spire_deployment.md) for the
operator runbook covering trust-domain choice, registration entries, single-
and multi-cluster topologies, SVID rotation cadence, alert wiring, and failure
recovery.

#### Certificate revocation

When `FERRUM_TLS_CRL_FILE_PATH` is configured, Ferrum applies that CRL set
symmetrically to mesh SPIFFE peer verification: inbound mTLS/HBONE handshakes
reject revoked client SVIDs, and outbound/backend mesh dials reject revoked
server SVIDs. A peer listed in an applicable configured CRL is rejected
fail-closed even when its SVID is otherwise trusted and unexpired. Revocation is
checked on **every non-trust-anchor certificate in the built chain**, so
revoking an intermediate SVID-issuing CA also stops the SVIDs it signed. If the
bundle has no CRL from the peer certificate's issuing CA, its revocation status
is undeterminable and Ferrum accepts it, matching the shared inbound mesh CRL
model. With no CRLs configured, revocation checking is skipped. A configured CRL that has reached its own `nextUpdate` is
an error rather than a fallback to "no revocation data", so mesh handshakes it
would police stop succeeding until the CRL is refreshed; see
[frontend_tls.md → CRL Policy](frontend_tls.md#crl-policy).

The CRL set follows the same lifecycle as Ferrum's other rustls backend pools.
When backend TLS live reload is enabled, `reload_backend_tls_material` reloads
the CRL file and new mesh outbound connections use the refreshed set; existing
connections retain the verifier created for their handshake. Otherwise the CRL
set remains static until gateway restart. SVID certificate rotation and
trust-bundle/peer-auth reload paths do not independently reload the CRL set.

### HBONE Protocol

HBONE (HTTP-Based Overlay Network Environment) is HTTP/2 CONNECT over mTLS, used by the ambient topology on port 15008.

Wire-shape detection by `is_hbone_connect()`:
- Method must be `CONNECT`, version must be HTTP/2.
- Optional marker headers: `x-ferrum-mesh-protocol` or `x-istio-protocol` (value `hbone` or absent).

Shape detection alone does **not** authorize the relay. Before the transparent TCP relay is established, the HBONE handler requires an authenticated, trust-domain-verified peer SPIFFE identity (`ctx.peer_spiffe_id.is_some()`, captured by `is_authenticated_hbone_connect()`). The inbound mTLS/HBONE listener populates `peer_spiffe_id` from the verified peer certificate (via the `spiffe_identity` plugin, or the node-agent/eBPF identity on the NodeWaypoint listener), so a present identity means a verified mesh peer terminated mTLS on this listener. A bare (marker-less) HTTP/2 CONNECT with no authenticated peer — and equally a CONNECT that merely asserts an `x-*-protocol: hbone` marker without a verified peer — is rejected with `403 Forbidden` and never relayed or dialed to a backend; the rejection stamps `mesh_authz.deny_policy=hbone_unauthenticated_peer`. Legitimate Istio ztunnel/waypoint HBONE always presents an authenticated mTLS peer, so interop is unaffected. This is independent of the trust-bundle peer verification performed at TLS time — it ensures the relay itself never opens a tunnel for an unauthenticated peer. An authenticated peer whose retained chain no longer anchors in the inbound admission trust is refused through the same terminal and body, stamped `mesh_authz.deny_policy=hbone_peer_trust_withdrawn` (`hbone_udp_peer_trust_withdrawn` on the datagram relay), and one whose chain the enforced mesh inbound CRLs revoke is refused identically as `hbone_peer_revoked` (`hbone_udp_peer_revoked`); see [HBONE Admission Fence](#hbone-admission-fence).

Authentication is necessary but not sufficient: an authenticated peer still may not use this proxy as a relay into destinations it does not own. See [Inbound Relay Destination Guard](#inbound-relay-destination-guard) below.

Identity extraction from W3C Baggage headers:
- Source principal keys (with fallback aliases): `source.principal`, `source_principal`, `source.identity`, `source_identity`, `src.identity`, `src_identity`.
- Values are percent-decoded per the Baggage spec.

Gateway DPs can also originate HBONE when they have a gateway SVID loaded and an upstream target is tagged `mesh.hbone=true`. The gateway probes the target's HBONE terminator port (Ambient/waypoint `:15008`, or `mesh.hbone_port`) during backend capability refresh, then sends eligible plain HTTP traffic through HTTP/2 CONNECT over SPIFFE mTLS before trying the ordinary direct backend transports. The HBONE pool honors the proxy's effective `pool_*` overrides, including connection count, idle timeout, TCP keepalive, and HTTP/2 flow-control settings, and coalesces concurrent first connects for the same target/SVID key within the proxy's `backend_connect_timeout_ms` budget. Retry-enabled and request-body-policy routes buffer and finalize the request once, then dispatch replayable bytes plus the exact sanitized multi-value header representation through the selected target's HBONE transport on every eligible attempt; they never downgrade a mesh-tagged target to a direct application dial. The CONNECT request carries `source.principal` baggage derived from the gateway SVID; mesh-side authz still requires the baggage to agree with the authenticated peer identity. The tunneled inner HTTP request strips client-supplied identity baggage (`source.*`, `destination.*`, and aliases) while preserving non-identity baggage, so untrusted client claims cannot reach the mesh backend as application headers.

Gateways with a loaded SVID auto-enable source identity labels for the `workload_metrics` plugin. The runtime injects an internal global `workload_metrics` plugin when none exists, or augments an existing global plugin with `workload_spiffe_id` when the operator has not set one explicitly. Successful HBONE-dispatched transactions are labeled with `mesh.connection_security_policy=mutual_tls` and `mesh.gateway.transport=hbone`; mesh-aware upstream target tags such as `mesh.spiffe_id`, `mesh.namespace`, `mesh.service`, and `mesh.trust_domain` are copied to destination metadata.

Inbound HBONE CONNECT requests run the standard `before_proxy` plugin chain on the outer CONNECT request before the transparent TCP relay is established. This means `mesh_route_dispatch` (and any other `before_proxy` plugin that writes `RequestContext::route_override_*`) can match on the CONNECT request's method, headers, and query parameters, and override the backend `upstream_id`, `backend_host`/`backend_port`, resolved backend TLS materials, backend read timeout, and retry policy on a per-rule basis. The overrides flow into HBONE backend selection through `apply_route_overrides_with_upstreams`, so per-rule `timeout_ms` / `timeout_disabled` and `retry` from a translated `VirtualService` reach the HBONE relay's `backend_read_timeout` / `backend_write_timeout` / circuit-breaker decisions just as they reach the H1/H2/H3 dispatch paths. The relay itself stays a transparent byte-copy after the upgrade — `before_proxy` does not see inner H2 frames, so route decisions are made once per outer CONNECT, mirroring the post-upgrade pinning behavior of WebSocket dispatch.

### Inbound Relay Destination Guard

The authenticated inbound CONNECT terminator (HBONE `:15008`, and the bare HTTP/2 CONNECT a Sidecar accepts on `:15006`) admits **only the destinations this proxy actually terminates for**. Being declared somewhere in the mesh slice is deliberately *not* enough: relaying to another node's workload would dial that pod in plaintext from this pod's IP, skipping the destination's own `AuthorizationPolicy` set and arriving as a trusted-looking unauthenticated source under a PERMISSIVE `PeerAuthentication` posture.

A CONNECT `:authority` of `host:port` is admitted only when `host` matches a destination in one of these sets; everything else is refused. The guard never resolves DNS; it compares what the peer named against what this proxy declares:

| Topology | Admitted destinations | Loopback |
| --- | --- | --- |
| `Sidecar` | Its own accepted non-loopback local address, on the ports of the records it owns there. | Admitted on those owned ports (own network namespace). |
| `Ambient` | Its own accepted local address (as Sidecar), plus its own LOCAL workload records bounded by the node-local enrolled-pod registry. | Refused. |
| `NodeWaypoint` | CP-authorized pods enrolled on this node. | Refused. |
| `ServiceWaypoint` | Workloads backing a service bound to this exact waypoint identity. | Refused. |
| `EastWestGateway`, `EgressGateway` | None. | Refused. |

- **Sidecar** runs inside the application pod's network namespace, so its accepted local address (resolved even behind a wildcard bind) is pod-unique proof; it carries no multi-destination inventory (issue #4249). Owned records are its own LOCAL workload — same SPIFFE identity as `FERRUM_MESH_WORKLOAD_SPIFFE_ID`, same cluster, and a non-vacuous match against `FERRUM_MESH_WORKLOAD_LABELS` when configured; remote-provenance records are excluded. A same-identity sibling replica on another node is refused `address_not_terminated_here`. Loopback covers `127.0.0.1`, `::1`, IPv4-mapped loopback, and the `localhost` / `.localhost` names; Sidecar `ingress[]` remaps still dial the listener's validated loopback `defaultEndpoint`.
- **Ambient** is ztunnel-style: it runs outside the workload pods' namespaces and terminates for pods the node-agent enrols on its node, so its second source is needed. A blank workload identity leaves that source empty. Loopback (including names that resolve to it) is refused on Ambient, NodeWaypoint, and ServiceWaypoint because the dial would reach the proxy's own or the host namespace rather than the destination pod.
- **ServiceWaypoint** admits a destination only when this runtime's exact identity (`FERRUM_MESH_WAYPOINT_NAME` + namespace) has a binding claiming service traffic (`waypoint_for=service` or `all`), the destination's attached Service is one of that binding's `(namespace, service)` refs (`MeshSlice.service_waypoint_bound_services`), the slice still carries that Service, and its `workloads[]` authorizes the workload's SPIFFE. Missing, old, or empty binding evidence yields an empty relay inventory — the namespace-visible routing view (which fails open while the Gateway is absent) is not a binding.
- **EastWestGateway** is SNI passthrough; **EgressGateway** relays to external `ServiceEntry` destinations through its own admission lists.

Rules that apply across all of them:

- **Ownership is a transport fact.** The own-address arm compares the authority against the accepted socket's local address, never `Host`, `:authority` hints, or `X-Forwarded-*`.
- **Addresses are canonicalized** (IPv4-mapped IPv6 folds to IPv4, IPv6 spellings are normalized); a bracketed IPv4 literal is refused.
- **Names are matched, never resolved.** A record declaring a non-IP address (a `ServiceEntry`/`WorkloadEntry` host, a VM) admits only that exact name, ASCII-case-insensitively, on its declared ports; anything else is `unresolvable_authority`. After admission, concrete DNS answers in loopback ranges are dropped before TCP or UDP dial on Ambient, NodeWaypoint, ServiceWaypoint, and gateway topologies (mixed answers keep the non-loopback ones; all-loopback fails `address_not_terminated_here`). Sidecar ordinary relay may still dial resolved loopback on a declared application port.
- **Ports come from the owning record.** A record that declares ports admits only those; one that declares none does not constrain its address. Another workload's ports never admit a destination.
- **Ambiguous owners fail closed** (issue #4249). Several records can declare one address (`hostNetwork` pods share the node IP; replicas share identity and labels). The own-address and loopback arms admit an address only when exactly one record declares it, or when every record declaring it carries the same non-empty pod UID (one pod under several Services, ports unioned); anything else contributes nothing (`port_not_declared`). With no workload identity configured the same rule is applied to the declared workload view — not a permissive fallback.
- **A Sidecar does not relay its HTTP application ports as bytes** (issue #6110). A bare byte-stream CONNECT on the Sidecar `:15006` listener is the raw-TCP egress lane. It is refused `403` with `mesh.relay.denial_reason=http_application_port` (after ownership is proven) when its authority names a port a materialized HTTP-family inbound route serves, or when it MATCHES an HTTP-family route on the Sidecar inbound listener (service host, `ingress[]` HTTP listener host, or an operator HTTP proxy — on every Sidecar, including one with no workload identity), so the route's plugin chain cannot be skipped. When an HTTP-family and a stream-family Service port share a container port, the HTTP route wins and raw-TCP CONNECTs to it are refused — give the two Service ports distinct container ports. The same "HTTP wins a shared port" rule applies to `ingress[]` stream listeners whose `defaultEndpoint` port is also an HTTP listener's endpoint port (no captured relay, no `bind` listener, CONNECT refused, warning at slice apply). The refusal applies at the post-plugin re-check and revokes live tunnels on reload (`relay_destination`). It does not apply to stream-family ports, the `connect-udp` relay, or Ambient and waypoint HBONE. Refusals log a sampled warning naming the authority and port.
- **Ambient's node bound is the node-agent's enrolled-pod registry** (issue #4249), read from `FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR` on the node-agent's 2 s cadence into a lock-free index:
  - **Authoritative by default.** The default directory `/run/ferrum/node-waypoint-pods` makes the bound active whether or not it exists (issue #5766). A source-(2) entry is relayable only while the registry enrols its pod at that entry's own IP (and, when both sides publish one, with the attested identity); a missing entry is refused `address_not_terminated_here`, with no fallback to identity matching. Without a node agent the index never publishes and every declared relay destination is refused — run the node agent on every node that runs an Ambient proxy, or set the variable to an empty value to opt out (a startup warning; the proxy is then bounded by identity/locality only).
  - **IP-literal entries only.** While the registry is authoritative every name is refused `unresolvable_authority`, so name-only `ServiceEntry` / `WorkloadEntry` / VM destinations are not reachable through a registry-bounded Ambient relay. A lone UID-less IP-literal record at an enrolled address remains admissible.
  - **Contested addresses** (different pod UIDs, mixed present/missing UIDs, or several UID-less records for one IP) are refused for every claimant.
  - **All-or-nothing snapshots.** The poller reads a strict, bounded snapshot (entry and size caps, `O_NOFOLLOW`, regular single-link process-owned files, canonical pod-UID leaf names, a strict body grammar; dot-prefixed control entries are skipped). Any read, ownership, parse, or bound failure retracts the index immediately — no last-good, no partial publish — except an entry that vanished mid-scan (an ordinary pod teardown). A later complete snapshot republishes.
  - **Diagnostics.** The first unavailable snapshot warns that the relay inventory was retracted; a persistent outage re-warns every 60 s with `consecutive_unavailable_polls` and `unavailable_for_secs`, distinguishing a missing directory (no node agent on this node) from a malformed snapshot; recovery warns once. Diagnostics never contain registry contents, identities, pod UIDs, or leaf names.
  - A `Sidecar` carries no general relay inventory, so no registry is installed for it.
- **Fail closed, with distinct outcomes.** No slice, an unresolvable authority, an empty inventory, or a missing accepted local address refuse.
  - A destination refusal is `403` `{"error":"HBONE relay destination not allowed"}` (`{"error":"HBONE UDP relay destination not allowed"}` for datagrams) with `mesh_authz.deny_policy=hbone_relay_destination_denied` (or `hbone_udp_relay_destination_denied`) and audit metadata `mesh.relay.denial_reason` (`unresolvable_authority`, `address_not_terminated_here`, `port_not_declared`, `http_application_port`, or `ingress_endpoint_mapping_mismatch`), `mesh.relay.denied_destination`, and `mesh.relay.terminator_ip`. Only these count on `ferrum_mesh_node_waypoint_destination_policy_rejections_total{reason="relay_destination_denied"}`.
  - **No slice yet is a readiness condition:** a terminator that has not applied its first mesh slice answers `503` `{"error":"HBONE relay not ready"}` (`HBONE UDP relay not ready`) with `mesh_authz.deny_policy=hbone_relay_not_ready` (`hbone_udp_relay_not_ready`), `mesh.relay.denial_reason=no_mesh_slice`, and no denial count. `address_not_terminated_here` stays `403` even before the registry enrols a pod.
  - A refusal of a **peerless** CONNECT (no verified SPIFFE identity) answers the unauthenticated-peer terminal instead — `403` `{"error":"HBONE tunnel requires an authenticated mesh peer"}`, `mesh_authz.deny_policy=hbone_unauthenticated_peer` (`hbone_udp_unauthenticated_peer`), no `mesh.relay.*` metadata — so an unauthenticated peer learns nothing about this terminator.
  - Every refusal writes a transaction line whose `rejection_phase` is the deny policy (never a route-miss `404`); synthesis-time refusals reach the global logging chain and have no `proxy_id`.
- **Re-checked after plugins.** The guard runs at relay synthesis on the original authority and again on the effective destination after `before_proxy`, so a `mesh_route_dispatch` override cannot move the dial off the admitted set. Both decisions and the post-DNS screen read the current `RequestEpoch` mesh snapshot.

Two narrower boundaries sit beside this guard and are unaffected by it: a declared Sidecar `ingress[]` block replaces the ordinary surface with an exact `listener port → defaultEndpoint` mapping (see [Sidecar Ingress Listeners](#sidecar-ingress-listeners)), and an `EgressGateway` admits external UDP `ServiceEntry` destinations from its own precomputed dial-endpoint allowlist.

### HBONE Admission Fence

Every gate above is applied when the CONNECT arrives, but an HBONE tunnel can outlive the policy generation that admitted it — a relay is a transparent byte-copy, so nothing re-runs `mesh_authz` per inner request. The **admission fence** (`src/proxy/hbone_admission_fence.rs`, issues #5042 and #5568) re-judges live inbound HBONE tunnels (TCP and datagram relays alike) when policy or credentials change, so a stale admission cannot keep serving under a policy or credential that would now refuse it.

**Credential check at every CONNECT.** An inbound HBONE mTLS session is never re-handshaked and many CONNECTs share one pooled connection, so every CONNECT carrying a certificate-derived SPIFFE principal re-verifies its peer chain against the anchors and enforced CRLs the inbound admission trust has **in force**, before an upstream is selected. A chain that no longer anchors is refused `403` tagged `mesh_authz.deny_policy=hbone_peer_trust_withdrawn` (`hbone_udp_peer_trust_withdrawn` on the datagram relay); a revoked chain is refused identically and tagged `hbone_peer_revoked` (`hbone_udp_peer_revoked`). The body is byte-identical to the unauthenticated-peer refusal.

**What triggers a sweep.** Every request-epoch publication (config, slice, and policy applies), every PeerAuthentication swap, every publication of the inbound mTLS trust slot or the enforced inbound CRL set, every gateway trust publication, and an expiry timer parked at the earliest live peer-SVID deadline. A CONNECT that raced a publication schedules a fresh sweep. Concurrent requests coalesce to one running sweep plus one follow-up.

**Gate order and revocation reasons.** A sweep applies the gates in this order; the first failure decides the closed `reason` label:

| Order | `reason` | Revoked when |
|---|---|---|
| 1 | `proxy_withdrawn` | The admitting proxy was withdrawn or replaced |
| 2 | `peer_expired` | The admitted peer leaf's `notAfter` has passed (monotonic clock) |
| 3 | `peer_trust` | A new in-force trust revision no longer anchors the retained chain (trust domain removed or chain no longer validates) |
| 4 | `peer_revoked` | The chain still anchors but an enforced CRL revokes the leaf or an intermediate |
| 5 | `authorization_denied` | The re-evaluated authorize chain now denies (including a mapped Consumer the generation no longer carries) |
| 6 | `peer_auth_transport` | The effective PeerAuthentication mode now refuses the tunnel's transport (`STRICT` without a verified peer certificate; `DISABLE` with TLS) |
| 7 | `relay_destination` | The destination left this terminator's admitted set |
| 8 | `reuse_withdrawn` | A tunnel admitted with [inner reuse](#hbone-inner-application-connection-reuse) advertised no longer has a reuse-eligible chain (it is not a refusal: the next operation re-CONNECTs under the new chain) |
| — | `reevaluation_failed` | A re-evaluation cannot produce a verdict (an authorize plugin unwinds, the retained leaf cannot be parsed, or an in-force CRL has reached `nextUpdate` when the chain is next re-verified) |

Because the authorize chain runs before the HBONE handler on the wire, a peer failing both its credential and its policy is refused `authorization_denied` on the wire while a sweep attributes `peer_trust`.

**Revocation effect.** A revoked tunnel's relay ends with `RST_STREAM(CONNECT_ERROR)` on both the byte-stream and datagram relays (issue #5858), after the existing bounded per-direction half-close drain (100 ms), so the peer can tell a revoked tunnel from a finished one. Revocations are counted on `ferrum_mesh_hbone_tunnel_revocations_total{proxy_id, reason, namespace}`, never on `ferrum_mesh_hbone_relay_failures_total`. Logging: one `info` summary per sweep, per-tunnel records at `debug`.

**What is re-evaluated.**

- Only authorize plugins that declare `reevaluates_live_admission()` are re-run — today exactly `mesh_authz` and `access_control`. `rate_limiting`, `opa`, `waf`, `request_mirror`, and custom authorize plugins are not re-run (a sweep must not consume budgets or make external calls); they still judge every new CONNECT.
- `mesh_authz` re-applies `ALLOW`, `DENY`, and `AUDIT` from the current slice with `mesh_authz.reevaluation` set. A `CUSTOM` policy's external authorizer is **not** re-consulted: the admission-time verdict stands for the tunnel's life, and other side effects are not reissued.
- A tunnel admitted as a mapped gateway Consumer is re-judged against the current generation's record for that Consumer (by `namespace` + `id`).
- Swept denies are written to `GET /mesh/policy-denies/recent` with `reevaluation: true` (a separate grouping key from request-time denies); request-shaped counters are not written by a sweep.

**Trust and revocation material.** The re-check reads the **inbound admission trust** — the same anchors the inbound SPIFFE verifier uses on every handshake, not the gateway trust epoch — and judges the trust half only for tunnels whose peer trust domain was anchored at admission (a chain-only listener against an operator client-CA bundle is not judged by it). A trust candidate that does not compile, or a CRL candidate with an unusable record (unparseable, not yet valid, missing or past `nextUpdate`), takes no force: the last accepted material stays in force, nothing is revoked, and a sampled `warn` names only the trust-domain class. Re-verification runs once per in-force revision change, never once per sweep.

**Enabling CRL rotation.** The mesh inbound CRL set is republished only by the backend TLS live-reload task: `FERRUM_BACKEND_TLS_LIVE_RELOAD_ENABLED` must be on (default `true`; `false` pins the startup snapshot), the CRL source must be refreshable (file path, `file://`, or external URI — inline PEM is static), and the cadence is `FERRUM_BACKEND_TLS_WATCH_INTERVAL_SECONDS` (default `30`) or the external source's poll interval. A destination whose backend TLS no longer builds is skipped without withholding the publication; only an unloadable CRL file withholds it. `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` alone does **not** update this surface (see [frontend_tls.md](frontend_tls.md#crl-policy)).

**Operator note — a transiently absent federated bundle revokes.** A SPIRE agent restart that delivers the local bundle before its federation sync completes briefly publishes a trust set without the federated domain, so live tunnels from that domain are revoked with `peer_trust` (a fresh handshake would be refused too); peers reconnect once the sync lands. A burst of `peer_trust` during an agent restart points at federation sync timing, not the fence.

Operationally: a tightened `AuthorizationPolicy`, a `PeerAuthentication` mode change, a workload leaving this terminator's inventory, the admitting proxy being withdrawn, a retired CA or federated trust domain, an expired peer SVID, and a published CRL revoking an admitted peer all close affected live tunnels within one sweep, and the peer's next CONNECT is refused by the same gate. Watch `ferrum_mesh_hbone_tunnel_revocations_total` by `reason` during rollouts: `authorization_denied` is a policy rollout working, `peer_revoked` is a CRL being enforced on open sessions, `peer_expired` on a steady-state mesh means SVID rotation is not keeping up, and `proxy_withdrawn` means the admitting proxy's identity is churning across applies. A rotation that *adds* a root must produce no `peer_trust` at all.

### HBONE Inner Application Connection Reuse

The outer HBONE HTTP/2 transport is pooled (see [HBONE Outbound Pool](#hbone-outbound-pool)). Without reuse, the connection the gateway runs *inside* it is built per request — one CONNECT, one inner HTTP/1.1 handshake or nested HTTP/2 preface — so the destination sees one `accept(2)` per request and a warm call pays one or two extra round trips. Ferrum therefore holds that inner connection open across requests (issue #5042). Reuse is admissible only because the [HBONE Admission Fence](#hbone-admission-fence) can still cut a reused tunnel when policy, PeerAuthentication, trust, or credentials change.

**The capability header.** A destination stamps `x-ferrum-mesh-tunnel-reuse: fenced` on the CONNECT `200` only while the fence holds that tunnel **and** every plugin in the admitting chain classifies itself reuse-safe (`Plugin::allows_hbone_inner_reuse`, default `false`, so any unclassified or custom plugin turns reuse off for that route). An absent or unrecognized header disables reuse — one CONNECT and one inner connection per request — so interop with Istio ztunnel/waypoint and older Ferrum destinations is unaffected. The header grants nothing: it authorizes no request and carries no identity. Datagram tunnels never advertise.

**Which plugins allow reuse.** A plugin may allow reuse only when it takes no per-operation decision or side effect, or when every decision it takes is re-issued by the fence. Reusable built-ins: `mesh_authz` (only while no external authorization provider is bound), `access_control`, `spiffe_identity` (only without `require_identity` / `allowed_trust_domains`; the mesh-injected `__mesh_spiffe_identity` has neither), `workload_metrics`, `stdout_logging`, `prometheus_metrics`, `otel_tracing`, `proxy_alerts`, and `__mesh_bpf_metrics`. Refusing: anything that charges an operation (`rate_limiting`, `adaptive_concurrency`, `request_mirror`, a `CUSTOM` verdict) and bearer-credential authenticators whose lifetime the fence does not track (`jwt_auth`, `oidc`, `oauth2_introspection`, `key_auth`, `basic_auth`, `hmac_auth`, `ldap_auth`, `opa`, and `jwks_auth` wherever a `RequestAuthentication` applies). `mesh_outbound_registry` allows reuse only for a scoped instance on a listener where it does not enforce (inbound); an unscoped instance stays fail-closed. Eligibility is re-judged on every fence sweep; a tunnel whose chain stops permitting reuse is revoked `reuse_withdrawn`.

**What is pooled.** HTTP/1.1 (an exclusive lease, used by plain-HTTP HBONE dispatch) and nested HTTP/2 (shared multiplexed senders, used by native-gRPC HBONE dispatch). Raw-TCP, WebSocket, and datagram-over-HBONE are never pooled. A route whose effective `pool_enable_http_keep_alive` is off reuses neither shape.

**Isolation.** The pool key carries the complete transport and admission identity: inner protocol, application endpoint and dial peer, peer verification scope (pinned SPIFFE id, SNI override, remote trust domain), the asserted source principal and whether it is asserted for a peer or for the gateway itself, the route/policy generation (namespace, proxy, upstream, proxy lifecycle generation), the source credential generation (gateway SVID leaf fingerprint and backend SVID/trust generation), and the connection-shaping policy. Two principals or credential generations never share a connection. A pooled connection also records the earliest deadline of the credentials that admitted it and is evicted at checkout once that passes; a leaf whose expiry cannot be parsed is never poolable.

**What retires a lease.**

1. The destination's fence revoked the tunnel (the next checkout evicts it; an untouched pre-wire request is replayed once on a fresh CONNECT judged under current policy).
2. Source trust changed: an SVID rotation drain, a CRL reload, an SVID slot without a bundle, or a committed gateway trust withdrawal. A lease checked out across the drain is discarded at check-in instead of re-pooled.
3. The published configuration no longer declares the route (deleted, re-bound, or recreated proxy, or keep-alive turned off).
4. Credential expiry (the recorded deadline).
5. Idle timeout — the effective `pool_idle_timeout_seconds`, floored at 15 s — or the checkout-time sweep.

An HTTP/1.1 sender returns to the idle set **only** after a clean, fully consumed response (complete body, no error, no `Connection: close`, no cancel, no fired deadline); a streaming body carries its lease and drops it on any other terminal. An HTTP/2 sender whose connection ended (including after GOAWAY) is evicted.

**Retries.** Reuse adds only one pre-wire handback replay per dispatch, for a lease taken from the idle set when nothing reached the wire (including a connection that closed while the request was queued, issue #5720); otherwise a fresh lease reports a pre-wire `502`. Post-wire failures surface as on the unpooled path, and the ordinary `retryable_methods`-guarded retry path is the only other replay. Every new CONNECT is still fully judged, with no plaintext fallback.

**Bounds.** No new knob: at most 8 idle HTTP/1.1 connections per key, at most 4 nested HTTP/2 carriers per key (never more than `FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST`), at most 1024 pooled inner connections in total, and the 15 s idle floor. Over-cap is never an error — the connection is simply not pooled. Each pooled connection holds one outer HTTP/2 stream, so it counts against the destination's `http2MaxRequests` and is a live entry in the destination's admission fence. Nested HTTP/2 carriers track the peer's live `SETTINGS_MAX_CONCURRENT_STREAMS`; the resident carrier cap bounds pooled carriers, not concurrent RPCs — requests beyond it queue on a carrier or use a transient, unpooled one.

**Observability.** `ferrum_mesh_hbone_inner_pool_events_total{protocol, event, namespace}` counts `hit`, `miss`, `eviction`, `discard`, and `fenced` per inner protocol (`http1`, `h2`). A steady `miss` rate on a warm mesh means the destination is not advertising the fence, keep-alive is off, or the asserted source principal varies per request. `fenced` (a revocation ran while a lease was outstanding, so the connection was dropped) is the signal that a trust change reached live traffic; `discard` is a healthy connection that was simply not kept.

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

#### Matching the allow-list is not sufficient (issue #4274)

Matching an entry decides only WHETHER a peer may assert. A second, independent
check decides WHAT it may assert. Without it, a bare service-account entry
would make the whole check namespace-blind: any authenticated pod running under
a service account named `waypoint` — in **any** namespace — could send
`baggage: source.principal=spiffe://cluster.local/ns/prod/sa/payments` and both
`mesh_authz` and `workload_metrics` would honor it. `ns/attacker/sa/waypoint`
impersonating `ns/prod/sa/payments` would be a complete authorization bypass,
and the same forged header would mis-attribute metrics, the service graph,
spans, and access logs to the victim.

Every allow-list entry therefore carries an **assertion grant**:

| Entry shape | Grant | May assert |
| --- | --- | --- |
| `"waypoint"` (bare SA) | `same_namespace` | Identities in the peer's own Kubernetes namespace |
| `"spiffe://td/ns/x/sa/y"` | `same_namespace` | Identities in namespace `x` |
| `{"assertor": "<sa\|spiffe>", "asserts": ["spiffe://…", …]}` | inventory | Exactly the listed identities; `[]` authorizes nothing |
| `{"assertor": "<sa\|spiffe>", "scope": "same_namespace"}` | `same_namespace` | Same as the string form, stated explicitly |
| `{"assertor": "spiffe://…", "scope": "mesh_wide"}` | `mesh_wide` | Any identity that clears the trust-domain gate |

`mesh_wide` is the only namespace-blind grant; it must be spelled
out per entry on a full, exactly pinned SPIFFE assertor (bare service-account
matchers are rejected), and it logs a warning at construction. Both identities must
expose an `/ns/<ns>/` segment for `same_namespace` to hold; a peer with no
namespace segment may assert only itself.

The relation is evaluated in this order, and the first failing gate wins:

1. Peer matches no entry → `untrusted_assertor`.
2. Baggage trust domain is neither the peer's nor a `FERRUM_MESH_TRUST_DOMAIN_ALIASES` alias → `trust_domain_mismatch`.
3. No matched entry's grant covers the asserted identity → `assertion_out_of_scope`.
4. Otherwise the baggage identity is honored.

A peer matching several entries is authorized by the **union** of the matched
grants. An empty allow-list authorizes nothing. Plugin construction compiles
the allow-list into an exact-SPIFFE map and a service-account map, merging
duplicate matcher grants; request-time evaluation looks up the peer and at
most one service-account key and does not scan unrelated NodeWaypoint
inventory entries.

`mesh_authz` and `workload_metrics` consume the **same** three-way verdict from
one shared function — a second telemetry-only predicate is exactly how forged
baggage would reach dashboards while authz correctly rejected it. They also
read the **same** baggage input (`hbone_baggage_identity`): every pristine
wire `baggage` field-line plus the folded request-map value. At
`before_proxy`, after request transforms, `workload_metrics` rebuilds that
folded value from the pristine wire block whenever it is held (materialization's
own UTF-8 rule, so an obs-text field-line the ASCII-only raw accessor skips
still counts exactly as it did for authorization) instead of reading the
transformed map: a `baggage` header a transformer added after authorization is
never honored and one it stripped before forwarding is not lost. Only the
redacted reason code is emitted; the rejected identity is attacker-controlled
and never reaches metadata, logs, or metric labels.

**Telemetry mirrors every effective authorization gate, not the first one.**
PluginCache executes every enabled global `mesh_authz` instance. Transparent
inbound capture force-injects reserved `__mesh_authz` even when an operator
global exists, so both run; outside capture, several operator globals can
likewise be effective. Mesh injection therefore stamps an internal
`_effective_mesh_authz_baggage_gates` list on `__mesh_workload_metrics` from
those enabled configs *after* the ensure/force step:

- Disabled operator rows do not constrain or select the telemetry gate.
- An enabled **proxy- or proxy-group-scoped** `mesh_authz` replaces the
  global instance on its routes, so its gate is the one authorization runs
  there. The global telemetry instance cannot vary per proxy, so every enabled
  scoped gate joins the conjunction for all routes (deduplicated; when no
  global gate exists, the instance's own default or mesh-managed gate is
  kept beside them). If the deduplicated set would exceed the 16-gate bound,
  injection writes a single `trusted_hbone_assertors: []` gate instead: no
  baggage is honored, and workload telemetry stays constructed.
- Telemetry honors baggage only if **every** compiled gate would honor that
  peer/asserted pair and trust-domain relation. Construction compiles each
  gate with the same `TrustedAssertorIndex` / `hbone_assertion_verdict` logic
  as `mesh_authz`. Request-time evaluation allocates nothing, takes no locks,
  and scales only with the bounded number of effective gates (at most 16;
  malformed or over-bound lists fail plugin construction).
- Each gate keeps its own `trusted_hbone_assertors` absent/null/default
  contract, explicit `[]` deny, and `trust_domain_aliases`. A sibling's
  aliases or per-entry `scope: mesh_wide` cannot silently widen another gate.
- A `when:` / trigger that makes request applicability unknowable is still
  included — requiring that gate is the fail-closed direction.
- Direct or user-created `workload_metrics` without the internal field keep
  their existing single-gate config.
- When one of several gates refuses, the redacted reason uses the same
  precedence as a single gate (`untrusted_assertor` →
  `trust_domain_mismatch` → `assertion_out_of_scope`). Trust-domain mismatch
  stays distinct. The forged identity is never logged or labeled.

**Identity-backed `NodeWaypoint` needs no operator configuration for this.** A
node waypoint legitimately fronts pods in namespaces other than its own, so the
CP-derived `node_waypoint_assertors` inventory carries, per assertor, the exact
workload identities that NodeWaypoint fronts (derived from the same
`Workload.node_waypoint` bindings that admitted the assertor, including
ambient-enrolled identity-only source pods that are not Service backends).
An identity-only pod that merely shares the NodeWaypoint's node is not
fronted: it must pass the same ambient enrollment predicate the node agent
uses for capture (`ferrum.io/mesh: enabled` or `ferrum.io/inject: true`,
and not host-network, sidecar-injected, or a namespace in
`FERRUM_NODE_AGENT_EXCLUDED_NAMESPACES`).
The CP intersects that derivation with destination/cross-namespace visibility,
the CP namespace scope, **and** the subscriber's bearer `ns` claim. A
contributing workload namespace is admitted only when every applicable gate
allows it; an assertor with no remaining asserted identities is dropped rather
than serialized empty (empty would skip `asserts` and widen to same-namespace).
A beta-restricted bearer on an `{alpha,beta}` CP therefore receives neither
alpha identities nor an alpha-only assertor. Full-scope / no-bearer
publication is not narrowed by a bearer claim. Mesh injection projects each entry as
`{"assertor": "<nodewaypoint svid>", "asserts": [...]}`, so cross-namespace
source-node assertion keeps working while an assertor that fronts nothing
authorizes nothing.

Operators with Gateway-managed waypoints often run with SA names like `<gateway-name>-istio` instead of `waypoint`; override the allow-list via `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS` (comma-separated, mix-and-match SA names and full SPIFFE ids):

```
FERRUM_MESH_TRUSTED_HBONE_ASSERTORS="ztunnel,default-waypoint,spiffe://cluster.local/ns/team-a/sa/team-a-waypoint"
```

When the env var is unset or empty, mesh injection usually uses the defaults. The exception is identity-backed `NodeWaypoint`: when the runtime has file SVID material or a mesh CA backend, Ferrum derives the trusted assertor allow-list from the CP-derived `node_waypoint_assertors` inventory, built from destination-visible, CP-scope-authorized, and bearer-`ns`-authorized `Workload.node_waypoint.spiffe_id` values before namespace/service slice narrowing, each entry carrying the exact workload identities that NodeWaypoint fronts. If no NodeWaypoint assertor metadata is present, the generated allow-list is empty so HBONE baggage rewrites fail closed instead of falling back to the bare `waypoint` service-account default. To lock down baggage rewriting entirely (no peer can rewrite the authz principal), configure a `mesh_authz` global plugin override with an explicit empty list (`trusted_hbone_assertors: []`).

`FERRUM_MESH_TRUST_DOMAIN_ALIASES` continues to gate the baggage identity's trust domain — both checks apply to a baggage rewrite.

**Observability**: when baggage is dropped because the peer is not a trusted assertor, transaction logs surface `mesh_authz.ignored_baggage=untrusted_assertor` and `mesh_authz.ignored_baggage.untrusted_assertor=true`. If the resulting authz decision is a DENY, `mesh_authz.deny_policy` is stamped as `untrusted_assertor`. Trust-domain-mismatch diagnostics use the `trust_domain_mismatch` reason. Baggage dropped because a trusted assertor is not authorized for the claimed identity uses the parallel reason `assertion_out_of_scope` (`mesh_authz.ignored_baggage.assertion_out_of_scope=true`, `mesh_authz.deny_policy=assertion_out_of_scope`, `mesh.ignored_baggage=assertion_out_of_scope` on `workload_metrics`), and NodeWaypoint ADR counters carry the matching `reason="assertion_out_of_scope"` label plus the `rejected_assertion_out_of_scope` field on the authenticated `/health` snapshot.

## RequestAuthentication

`MeshRequestAuthentication` declares which JWTs are valid for a workload scope. When applicable resources with JWT rules exist in the mesh slice, the mesh runtime auto-injects a `jwks_auth` global plugin (`__mesh_request_auth`) configured from the JWT rules.

**Permissive semantics** (matching Istio): RequestAuthentication only declares which JWTs are *valid*, not which are *required*. A request with no JWT passes through. An `Authorization` header using a foreign scheme such as `Basic` also counts as no JWT and passes through without an authenticated JWT identity. An applicable but malformed or invalid Bearer JWT is rejected. Enforcement (requiring a JWT) comes from `AuthorizationPolicy` ALLOW/DENY rules that check for authenticated identity.

Each `MeshJwtRule` specifies:

| Field | Description |
|---|---|
| `issuer` | Expected JWT issuer (`iss` claim); the injected `jwks_auth` provider requires this claim to be present and exact |
| `audiences` | Accepted audience values (`aud` claim); when non-empty, `aud` must be present and any configured value may match |
| `jwks_uri` | URL to fetch the JWKS key set |
| `jwks` | Inline JWKS JSON (alternative to `jwks_uri`); keys are loaded from config without a fetch loop |
| `from_headers` | Headers to extract the JWT from (with optional prefix stripping) |
| `from_params` | Query parameters to extract the JWT from |
| `forward_original_token` | Whether to forward the original token to the backend |
| `output_claim_to_headers` | Istio `outputClaimToHeaders`: ordered `{header, claim}` list published to the backend-bound request after successful validation |

Each JWT rule resolves token locations independently. Rules with custom `from_headers` or `from_params` check those locations in declaration order; rules without custom locations continue to use the standard `Authorization: Bearer ...` lookup. When `forward_original_token: false`, the backend-bound request strips the matched rule's configured token headers or query parameters (or `Authorization` for standard lookup).

**Claim output headers (`outputClaimToHeaders`)**: each declared header is
**gateway-owned**. The injected `jwks_auth` plugin removes every declared header
from the inbound request — case-insensitively, including duplicates —
**before** validation, so an unauthenticated or invalid request can never forge
one, and sets it only from the validated token's claim. Istio `ClaimToHeader`
supports only nonblank string, integer, and boolean claims; array, object, null,
floating-point / non-integer, blank, missing, or header-illegal values leave the
destination **absent** rather than restoring the client value. Rendered values
over 8192 bytes are also omitted before the value can fan out to as many as 16
destinations. Duplicate
destination headers, reserved or credential-bearing destinations
(`authorization`, `host`, hop-by-hop/framing fields, `x-ferrum-*`,
`x-forwarded-*`), malformed header names, and malformed claim paths are rejected
at translation with `FerrumAccepted=False` / `Invalid` — a dropped mapping would
leave the header unowned and client-forgeable. Header names are compared as a
CGI-style backend reads them, with `_` treated as `-`: `X_Real_IP` is reserved
like `X-Real-IP`, and `X_Tenant_Id` duplicates `X-Tenant-Id`.

**A rejected RequestAuthentication fails closed** (issue #6656). When Ferrum
refuses a RequestAuthentication (for example a reserved or duplicate claim
header, a missing issuer, a rule with neither `jwksUri` nor `jwks` (Ferrum does
not discover keys from the issuer), a malformed `fromHeaders`, or an unsupported
`targetRef(s)` attachment), it is not dropped: dropping it would leave the
workloads it selects with no JWT validation, no token stripping and no
gateway-owned claim headers, so a forged token or a client-supplied claim header
would reach the backend. The resource is instead published as a rule-less
refusal marker with its own selector scope (a `targetRef(s)` resource covers its
namespace, or the mesh in the Istio root namespace, because the attachment cannot
be resolved), and the data plane installs a forced `request_termination`
instance (`__mesh_request_auth_refused`) that answers every HTTP request to those
workloads with `503` until the resource is fixed. The refusal is scoped to the
workload's inbound execution routes, so its outbound requests keep flowing:
the materialized Sidecar inbound routes, an EgressGateway's `mesh-egress-*`
HTTP proxies, plus the synthesized HBONE relay
proxies (`__mesh-inbound-hbone-relay` / `__mesh-ingress-connect-relay`), whose
CONNECT admission runs the global HTTP plugin chain before the tunnel opens.
On Ambient no inbound HTTP route materializes, so those relay ids are what
makes the refusal refuse inbound CONNECTs there instead of falling back to
unscoped and refusing the workload's outbound requests (issue #6736). On
NodeWaypoint and ServiceWaypoint the managed `mesh_authz` refuses relays per
destination instead (see "Shared waypoints follow the destination" below); the
relay ids are used only when an operator `mesh_authz` replaces the managed
one. EastWestGateway (SNI passthrough, no HBONE
listener) keeps the unscoped fail-closed fallback. This deliberately differs from
Istio, whose validating webhook would never admit such a resource; Ferrum
accepts some resources Istio admits but Ferrum cannot enforce faithfully, and
for those it chooses refusal over running without validation. The status reports
`FerrumAccepted=False` / `Invalid` and `status.ferrum.translation.enforcement:
refuse_all`.

**Shared waypoints follow the destination** (issue #6670). A NodeWaypoint or
ServiceWaypoint terminates requests for other workloads, so a
RequestAuthentication is matched against the workloads a request reaches, not
against the waypoint's own namespace and labels. A waypoint slice therefore
also carries the resources that select the destinations it fronts: the
visible workloads its routes reach and, on a NodeWaypoint, its capture
destinations.

- **NodeWaypoint Service routes (Layer 7).** Each HTTP route is resolved to its
  destination workloads, including every `mesh_route_dispatch` destination
  (associated or global) it may be rewritten to after authentication. A
  generated mesh Service upstream resolves to the workloads the waypoint can
  actually dial for that Service port: local members with an address and a
  resolved target port, enrolled in NodeWaypoint transport when it is secured.
  Any other destination resolves through the index `mesh_authz` uses for
  destination policy. Both lookups are keyed by namespace and upstream id,
  because generated upstream ids are unique only within a namespace.
  - A route whose destination set differs from the waypoint's own set gets a
    proxy-group `jwks_auth` instance (`__mesh_request_auth_dst_*`) that replaces
    the global `__mesh_request_auth` on that route. JWT validation, token
    stripping and claim-header ownership then apply to requests for the
    selected destination and never to an unrelated one.
  - A route whose destination is selected by no resource with a usable JWT
    rule is excluded from the global instance by its execution trigger. If
    that exclusion cannot be represented as one trigger, those routes are
    refused instead.
  - Workloads the route cannot reach are not compared: a secured NodeWaypoint
    (CA backend or configured SVID) never dials a Service workload that lacks
    NodeWaypoint metadata. A Service whose workloads are all in a remote
    cluster has no local destination set; its destination cluster enforces
    its own resources.
  - The route is refused (`503`, through the trigger of
    `__mesh_request_auth_refused`) when:
    - its destination is selected by a refused resource;
    - the workloads it can reach (several pods behind one Service, or a
      dispatch rewrite target) are selected by **different** resource sets,
      because the backend is chosen after authentication and a union would let
      one destination's providers mint principals and claim headers for
      another;
    - it reaches a modeled destination whose workloads cannot be resolved
      while destination resources exist;
    - its destination's provider union exceeds what one `jwks_auth` instance
      can verify (64 providers in total, or more than 8 sharing one issuer).
  - Refused routes are named by id in the refusal's execution trigger. A
    refusal too large for one trigger is split across additional forced
    instances (`__mesh_request_auth_refused_<n>`), so a large refusal never
    falls back to refusing healthy destinations.
  - A route with no modeled destination (for example an external
    `ServiceEntry` host) keeps the global instance.
- **Inbound relays (Layer 4).** A waypoint relay does not parse tunnelled HTTP,
  so no JWT can be validated there, on either waypoint type. `mesh_authz`
  refuses (`503`, `mesh_authz.deny_policy: request_authentication_refused`) an
  inbound HBONE relay, or a NodeWaypoint transparent-capture plaintext
  connection, whose destination workload a refused resource selects. A
  NodeWaypoint relay whose destination cannot be resolved is refused while any
  refused resource is present. On a waypoint this per-destination check also
  replaces the blanket relay refusal for a refused resource that selects the
  waypoint's own namespace or identity, so a relay to a destination that
  resource does not select keeps flowing. To require a principal, use an
  `AuthorizationPolicy`: an ALLOW that needs `requestPrincipals` never matches
  a relayed CONNECT (unsourceable on L4; see
  [Layer-4 sessions and CONNECT relays](#layer-4-sessions-and-connect-relays)). This relay check lives in the mesh-managed `mesh_authz`,
  so an operator global `mesh_authz` that replaces it (possible only without
  transparent capture) also replaces the check.

**Deferred JWT-rule fields**: `outputPayloadToHeader` and `fromCookies` are
recognized but not enforced. Both are surfaced in
`status.ferrum.translation.deferred_fields` by FIELD NAME only — a `fromCookies`
entry names the cookie a token rides in, so the value is never republished into
a cluster-readable status object.

**`targetRef` / `targetRefs`**: rejected (`FerrumAccepted=False` / `Invalid`).
Only `AuthorizationPolicy` implements end-to-end attachment; a
`RequestAuthentication` carrying only either form would read as "no selector"
and widen to the whole namespace — or the whole mesh in the Istio root
namespace — installing its JWT provider on workloads that were never in scope.
Scope it with a workload selector instead. The same refusal applies to
`Telemetry`, where widening would silently disable access logging mesh-wide.

**`exp` claim requirement**: the injected plugin requires the JWT `exp` claim by default (`FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP=true`), so tokens that omit `exp` are rejected and cannot live forever — this satisfies the gateway's `validate_exp = true` invariant. Some Istio issuers legitimately omit `exp`; set `FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP=false` to accept them. This knob is independent of expiry *validation*: a present-but-expired `exp` is always rejected regardless of the flag.

**`iss` / `aud` / `nbf`**: a configured issuer requires `iss` presence plus an exact match. Non-empty `audiences` require `aud` presence plus a match against any configured value. An empty `audiences` list is stricter than Envoy's `jwt_authn`: a token that omits `aud` is accepted, but a token that *carries* `aud` is rejected because no acceptable audience is configured (RFC 7519 §4.1.3) — set `audiences` on the `MeshJwtRule` when the issuer stamps one. `nbf` is optional, but a present not-before is validated (zero JWT leeway). Missing required claims and a future `nbf` fail closed before `mesh.request_principal` or `request.auth.*` attributes are staged.

**Authz attribute emission**: a validated token's `iss/sub` (`request.auth.principal`), audiences (`request.auth.audiences`), and scalar / string-array claims (`request.auth.claims[<name>]`) are surfaced to the `mesh_authz` plugin so `AuthorizationPolicy` `when:` conditions over those attributes are evaluated (see [Rule Matching](#rule-matching)).

## PeerAuthentication

`PeerAuthentication` controls per-workload mTLS behavior with optional per-port overrides.

mTLS modes:

| Mode | Description |
|---|---|
| `strict` | Require mTLS on all connections. Reject plaintext. |
| `permissive` (default) | Accept both mTLS and plaintext. |
| `disable` | Disable mTLS. Accept plaintext only. |

`portLevelMtls` applies only to a `PeerAuthentication` whose workload selector
contains at least one `matchLabels` entry. Omitted, `null`, and explicitly empty
selectors are namespace- or mesh-wide policies and use only their workload-level
`mtls` mode. Applicable overrides are enforced at the
earliest point where the workload app port is known. For REDIRECT-captured
connections, the inbound accept loop reads
`SO_ORIGINAL_DST` once and selects the prebuilt per-port `rustls::ServerConfig`
before the handshake. A captured Sidecar `ingress[]` listener port is translated
to its validated `defaultEndpoint` app port first, and that translated port is
carried with the connection for rejection diagnostics. Direct mesh-transport
dials have no original destination, so a policy whose app ports span TLS and
plaintext wire postures
uses a PERMISSIVE-style acceptor: it peeks without consuming the first record
and can admit either verified TLS or plaintext far enough to route the request.
As soon as the initial HTTP authority or HBONE CONNECT target resolves a
concrete app port, Ferrum checks the current atomic policy snapshot before any
request plugin runs. It then applies routing-plugin overrides and load-balancer
target selection and repeats the check against the effective target app port.
The check runs for every inbound request, including requests reused on a
captured keep-alive connection after live reload. HTTP, gRPC, and WebSocket
retry paths repeat it after retry backoff and load-balancer target rotation,
before acquiring target admission or dispatching the retry. `STRICT`
requires a verified peer certificate, `DISABLE` requires plaintext, and
`PERMISSIVE` admits either. The acceptor is not an authorization bypass: a
mismatch on the initial resolved port is rejected before plugin side effects;
a mismatch introduced by a later route override or target rotation is rejected
before backend admission or dispatch. Both paths emit a structured warning and
a protocol-appropriate 403 response (including normalized gRPC rejection).

`FERRUM_MESH_PRODUCTION_MODE=true` never enables plaintext on inbound
TLS-terminating listeners. A `PERMISSIVE` policy with usable server TLS material
is accepted at startup and on live reload, but the production listener is
coerced to TLS-only (client certificates remain optional for non-egress
topologies). If the workload-level mode or any per-app-port mode cannot produce
a usable TLS config, startup fails closed; live reload rejects the entire slice
and retains the last-good policy. East-west gateways are exempt because they do
SNI passthrough and build no inbound terminating `ServerConfig`.

The following policy requires a client certificate on port 8080 while allowing
optional client authentication on port 8081:

```yaml
name: "mixed-mode"
namespace: "default"
selector:
  labels:
    app: my-service
mtls_mode: permissive
port_overrides:
  8080: strict
  8081: permissive
```

A `PeerAuthentication` with an omitted, `null`, or empty selector applies its
workload-level mode to all workloads in its namespace (or mesh-wide when rooted
in the Istio root namespace), but its `portLevelMtls`/`port_overrides` entries
are ignored.

### Resolution and listener wiring

The listener fallback is resolved at startup from the initial mesh slice using only the winning policy's workload-level `mtls_mode`; mesh transport ports (`15006`, `15008`, and `15090`) are never treated as app-port override keys. Each app port is resolved separately via `resolve_effective_mtls_mode()`. Scope precedence (highest wins): `WorkloadSelector` > `Namespace` > `MeshWide`. Among same-tier matches the tie is resolved **fail-secure**: the more-restrictive effective mode for the app port wins (`Strict` > `Permissive` > `Disable`). This is both deterministic (so the posture cannot flap across pods or reconciles) and a genuine trust boundary — because the winner is decided by mode rather than by the policy's namespace string or name, a tenant-controlled policy cannot downgrade inbound mTLS below a trusted same-tier policy by choosing a low-sorting namespace or policy name, and a customized `FERRUM_K8S_ISTIO_ROOT_NAMESPACE` that sorts after tenant namespaces is equally safe. Two conflicting same-tier `PeerAuthentication`s are still an operator misconfiguration; only when their effective modes are identical does the resolver fall back to the value-neutral `(namespace, name)` ordering to pick a canonical winner (this differs from the sibling `ProxyConfig` resolver, which has no security posture to protect and tiebreaks by `name`). Port-level overrides within a policy are applied before the per-app-port comparison, so each app port gets the posture that the winning policy yields for that port.

The resulting `MeshClientAuth` is plumbed into the inbound TLS acceptor:

- `strict` -> TLS `Required` (client cert mandatory; plaintext rejected).
- `permissive` -> TLS `Optional` (TLS accepted with optional client cert; plaintext can be accepted by the mesh listener). **EgressGateway exception:** `permissive` with a trust anchor is escalated to `Required` — see below.
- `disable` -> TLS `Disabled` (plaintext only; mTLS connections rejected).

**EgressGateway requires client certificates.** The EgressGateway TLS listener — both the `:15090` HTTP-family mTLS-termination listener and the stream-family TCP egress listeners that share the same `ServerConfig` — is a security boundary onto external networks: a cert-less client admitted there reaches the external backend unauthenticated. For this topology, `resolve_mesh_inbound_client_auth` escalates `PERMISSIVE`-with-a-trust-anchor from `Optional` to **`Required`**, so every egress client must present a verifiable SVID even when no STRICT `PeerAuthentication` is in force (the default-allow case). The non-egress topologies (Sidecar / Ambient / waypoints) keep the standard `PERMISSIVE` → `Optional` posture. If `PERMISSIVE` resolves on an EgressGateway with **no** trust anchor at all, the listener cannot authenticate clients, so it **fails closed** (hard error, never optional-no-verify mTLS); in practice `validate_egress_gateway_mtls_config` already requires a peer verifier for this topology at config time, so this is defense-in-depth for the live-reload path. UDP ServiceEntry ports still materialize no EgressGateway listener of their own — their datagram-over-mesh relay rides the `:15090` mTLS-termination listener as a `udp`-marked CONNECT, so it inherits exactly this required-client-cert posture. The only ways an egress client skips client-cert verification are an explicit `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true` (plaintext stream listeners) or `PeerAuthentication` `DISABLE` (rejected for EgressGateway by the disable-mode topology guard). This escalation applies on **both** startup and `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true` slice apply, so a reload cannot downgrade an egress gateway to optional client auth.

**SPIFFE peer trust-domain verification**: when gateway SVID material is configured (all three of `FERRUM_GATEWAY_SVID_CERT_PATH` / `FERRUM_GATEWAY_SVID_KEY_PATH` / `FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH`), the inbound mTLS / HBONE listener verifies each peer certificate's chain **and** that the peer's SPIFFE URI-SAN trust domain matches the gateway SVID's local trust bundle or one of the slice's federated bundles. A peer cert that merely chains to the configured client CA is therefore not admitted regardless of its SPIFFE trust domain. STRICT requires + validates a peer cert; PERMISSIVE still admits peers that present no cert but trust-domain-validates any cert that is offered (so PERMISSIVE records mTLS identity when present). Without gateway SVID material, the listener falls back to chain-only verification against `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH`. In PERMISSIVE specifically, the listener requests a client certificate whenever **either** trust anchor exists (the SVID verifier is preferred, otherwise the operator client CA bundle) so an offered cert is verified and its identity recorded; only when **neither** anchor is configured does PERMISSIVE skip the certificate request entirely — and in that fully-degraded case Ferrum emits a single startup warning that inbound peer identity cannot be verified or recorded, rather than silently treating authenticated peers as anonymous. (The **EgressGateway** topology is the exception to PERMISSIVE-optional: there a present trust anchor escalates PERMISSIVE to `Required`, and a missing anchor fails the listener closed — see the EgressGateway requires-client-certificates note above.) The HBONE baggage `source.principal` trust-gate rests on this verified peer identity. When `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true`, the lock-free SVID bundle slot is re-published on slice apply so federated trust-domain additions take effect without a listener restart; file-backed and CA-backed gateway SVID rotations also republish the inbound peer-verifier bundle from the newest local roots plus the last accepted federated overlay. Slice roots for the gateway SVID's own trust domain are additive with the freshly loaded SVID local roots, which lets the control plane stage same-trust-domain CA-root rotation without replacing the SVID source's current root set.

Per-port TLS configs and their effective modes are built during startup (and during an opted-in live reload), then published as one atomic listener-fallback + app-port table. Captured connections select from that table before the handshake; after routing reveals the effective app port, every inbound HTTP-family/HBONE request reads the current atomic snapshot and performs one lookup in the pre-resolved mode table. This request-time lookup makes a stricter live reload authoritative for subsequent requests on an existing keep-alive connection; it does not repeat selector resolution or certificate parsing. The topology disable guards remain in force for every entry, so a `DISABLE` override cannot bypass the Ambient/HBONE or EgressGateway mTLS-only constraints.

The selectable app-port table uses the same runtime workload SPIFFE identity and `multi_cluster.local_cluster` context as Sidecar inbound route materialization. A local VM/WorkloadEntry tagged with the declared local cluster therefore retains its `portLevelMtls` entry at both accept-time and request-time enforcement, while a foreign cluster workload cannot contribute a local listener port.

By default, the resolved mode is captured **once at startup** from the first valid slice. Subsequent `PeerAuthentication` changes pushed via the control plane update the in-memory slice and are honored by other plugin paths (e.g. `mesh_authz`, plugin chains), but the inbound TLS `ServerConfig` is not rebuilt. If a later route-only slice would make an app port newly local while an applicable override for that port was filtered out of the fixed startup table, Ferrum rejects the whole slice instead of serving the new route under the listener fallback. Restart with the port present or enable PeerAuthentication live reload.

Set `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true` to opt in to live reload of the resolved mTLS modes and frontend client CA verifier on mesh slice apply. Coverage includes mesh HTTP/HBONE termination listeners **and** mesh-shared TCP+TLS stream listeners: a slice apply that changes a top-level or per-app-port `PeerAuthentication` mode, or rotates the client CA bundle, rebuilds the distinct required `rustls::ServerConfig` values and atomically swaps one coherent `{listener fallback, app-port table}` snapshot for future HTTP/HBONE accepts. The listener-wide config is also published to the shared TCP+TLS stream slot (snapshotted per accept). Terminating UDP+DTLS listeners are reloaded on their OWN owner-scoped path instead (issue #3858): a mesh generation reaches only Ferrum-generated `MeshNodeWaypoint` listeners, never an operator `FERRUM_DTLS_*` listener sharing the process, and new sessions snapshot the swapped material at handshake while existing handshake-complete sessions keep the material they handshook with until they end. In-mesh and egress UDP stay opaque datagram-over-mesh CONNECT/`mesh_udp_frame` paths, and `ServiceEntry` UDP ports never bind a DTLS frontend. Operator-configured UDP+DTLS listeners that happen to share the process keep their dedicated identity and client-CA policy across a mesh slice apply. If any required TLS config build fails — or the client-CA-bundle snapshot cannot be read (e.g. a secrets operator truncating the bundle file mid-write) — Ferrum **rejects the whole slice** and keeps the last good config in its entirety, so no authz/`MeshPolicy`/`RequestAuthentication`/`ServiceEntry`/endpoint update from that slice is applied either, until the rebuild succeeds (fail-closed; the inbound posture is never silently weakened). Only the *post-accept* DTLS rebuild keeps the previous config **for that path** and logs a warning without rejecting the slice. Topology-disable rejection (see below) likewise keeps the last good config wholesale.

Frontend cert/key paths are independently controlled by `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` (default `false`). When that flag is enabled, the proxy HTTPS / H2 / HTTP/3 and admin HTTPS listeners watch their cert/key files on a poll interval (`FERRUM_FRONTEND_TLS_WATCH_INTERVAL_SECONDS`, default 30s) and atomically swap a rebuilt `ServerConfig` on validated change. The two flags are orthogonal: PeerAuthentication live reload covers the mesh inbound mTLS mode + client CA verifier surface, frontend live reload covers the operator-supplied cert/key material across the proxy and admin HTTPS surfaces. See [docs/configuration.md](configuration.md#proxy-listener) for full semantics.

### Disable-mode topology guard

`PeerAuthentication.mode: disable` resolved against an `Ambient`, `NodeWaypoint`, `ServiceWaypoint`, or `EgressGateway` workload is rejected. Startup fails closed on an invalid initial slice; with `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true`, later invalid slices are rejected and the last good inbound TLS config remains active.

- **Ambient**: HBONE is HTTP/2 CONNECT over mTLS — running the inbound listener plaintext is not a valid HBONE listener. Use `permissive` or `strict`, or move the workload to `Sidecar` topology if plaintext-only inbound is intended.
- **NodeWaypoint**: the shared node listener must resolve pod identity from the node-agent/eBPF socket-cookie record before admitting HBONE traffic. Use `permissive` or `strict`.
- **ServiceWaypoint**: service-scoped Ambient waypoint traffic arrives as HBONE over mTLS. Use `permissive` or `strict`.
- **EgressGateway**: the egress listener must verify sidecar client certificates. Use `permissive` or `strict`. Note that on this topology `permissive` does not mean optional client auth: it is escalated to require a client cert (see "EgressGateway requires client certificates" above), because the egress boundary must authenticate every client.

Invalid startup mode fails closed with or without live reload. With live reload enabled, invalid incoming slices are rejected and the last good config stays active. In development, `Sidecar` accepts any resolved mode (`Disable` produces a plaintext inbound listener). In production, Sidecar `PERMISSIVE` with usable TLS is accepted but runs TLS-only, while a mode that cannot produce usable TLS (including `Disable`) fails closed. `EastWestGateway` accepts any resolved mode because it performs SNI passthrough and does not use the resolved terminating-TLS mode.

### NodeWaypoint cgroup-inode lifecycle binding

In NodeWaypoint topology one HBONE listener serves many pods. The node-agent enrolls each pod's identity into the proxy via `NodeWaypointIdentityResolver`. When the agent supplies the pod's cgroup v2 directory at enrollment time (`upsert_identity_with_cgroup`), the resolver captures the directory inode plus a small Unix metadata fingerprint, and a periodic sweep (`FERRUM_MESH_NODE_WAYPOINT_CGROUP_SWEEP_INTERVAL_SECS`, default 30s) re-stats the path:

- Inode/fingerprint unchanged → identity kept.
- Inode or fingerprint changed → pod restarted under the same UID; the identity-map entry is evicted so a fresh enrollment is required before traffic for the new instance is honoured. The fingerprint prevents missed restarts when the filesystem reuses the old inode number.
- Path gone → pod removed; the identity-map entry is evicted. The per-pod policy scope is a separate slice-published map and remains until a later accepted slice replaces it.

An independent idle identity GC task (`FERRUM_MESH_NODE_WAYPOINT_IDLE_GC_INTERVAL_SECS`, default 30s) reclaims identities enrolled **without** a cgroup path. It evicts an identity only when its pod UID is no longer referenced by a live cookie record and its identity `Arc` has no other holder (`strong_count == 1`). This removes the identity-map entry; the per-pod policy scope is held in a separate slice-published map and changes only when a later accepted slice publishes a replacement. cgroup-bound identities are left to the cgroup-binding pass above.

Set `FERRUM_MESH_NODE_WAYPOINT_CGROUP_SWEEP_INTERVAL_SECS=0` to disable only the cgroup-inode stat sweep. Set `FERRUM_MESH_NODE_WAYPOINT_IDLE_GC_INTERVAL_SECS=0` to disable lazy identity GC. Both tasks are best-effort GC, not security boundaries: the accept-path check on unknown socket cookies remains fail-closed regardless of sweep cadence.

Picking the cgroup interval is a tradeoff between eviction lag (worst-case time a stale cgroup-bound identity remains after pod removal/restart) and per-sweep stat cost. Each enrolled cgroup-bound identity costs one `stat(2)` per sweep — on the order of tens of microseconds on a warm dentry cache, so even at thousands of pods per node a sweep finishes in a few milliseconds and the work runs on a dedicated background task off the accept path. Shorten the interval to tighten the eviction window on heavy pod churn; lengthen it (or set `0`) if the operator already drives cgroup-bound identity removal explicitly from the node-agent and treats the sweep as a defence-in-depth backstop. Keep the idle GC interval enabled unless another component explicitly removes lazy identities; otherwise the lazy identity map can grow across pod churn.

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

1. The resolution table is built atomically from the `MeshSlice` on every config update via `ArcSwap`; its immutable table reads are lock-free. Mesh DNS response serialization also uses a bounded `DashMap` cache, so the entire query path is not lock-free.
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
- Locally synthesized UDP answers are clamped to the client's advertised payload size (or 512 bytes without EDNS). Matched upstream replies are forwarded whole after transaction-ID restoration; the local-answer clamp does not apply to them.
- TCP fallback for large responses.
- Concurrent query limiting via `FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES` (default 1024) using a semaphore.
- Upstream TCP forwarding uses separate 5-second deadlines for connect, reading the two-byte length, and reading the framed payload. Writes have no enclosing deadline, so there is no whole-helper five-second deadline. UDP forwarding has its own per-query timeout.
- Upstream UDP forwards use FIPS-compatible CSPRNG transaction IDs (bounded collision retry; SERVFAIL if entropy is unavailable or retries cannot find an unused random ID, with no sequential/counter fallback) and a fresh connected ephemeral-port socket per in-flight query. A response is accepted only when both the ID and the full question match the pending query, and only while that exact forward is still pending (a timed-out forward frees its 16-bit ID, so a late outcome naming a reused ID is discarded rather than retiring the newer lookup); mismatched or unknown packets are discarded without retiring the lookup. Forged or malformed discards use a static trace-level diagnostic with no client address or query contents.

## Multi-Cluster

Multi-cluster mesh support enables cross-cluster service discovery and traffic routing.

### East-West Gateways

When `FERRUM_MESH_TOPOLOGY=east_west_gateway`, the mesh runtime materializes passthrough TCP proxies from `MultiClusterConfig.east_west_gateways` entries. Each gateway entry specifies:

- `host` / `port`: backend cluster endpoint.
- `sni_hosts`: TLS SNI hostnames routed through this gateway.
- `trust_domain` / `network`: optional cross-cluster identity and network labels.

The materialized proxies use `passthrough: true` (no TLS termination), route by SNI, and share the listener on `FERRUM_MESH_EAST_WEST_LISTEN_PORT` (default 15443). Only entries matching the gateway's namespace are materialized.

In addition to remote-cluster gateways, the east-west topology materializes a TCP passthrough proxy for each local `MeshService` port. Every port follows the [SNI alias convention](#multi-port-cross-cluster-sni-aliases) and routes on `p<port>.<fqdn>` (HTTP-family and raw-TCP ports) or `p<port>-udp.<fqdn>` (UDP ports), including a service's only port. The alias depends only on the port's own number and transport, so ports sharing a number across transports still get distinct routes. Each proxy is backed by that port's resolved container port. Explicit `EastWestGateway.sni_hosts` ownership remains wildcard-aware and suppresses only the automatic SNI it directly overlaps.

### Client-Side Cross-Cluster Egress (Sidecar)

A **Sidecar** client can send application traffic to a service whose endpoints live in a remote cluster over the east-west gateways. HTTP-family materialization emits one cross-cluster target per remote network at the gateway endpoint. L4 materialization emits a per-remote-pod synthetic target so the CONNECT can retain the real pod authority, but its network dial still goes only to the remote **east-west gateway** (`mesh.mtls_dial_host` / `mesh.mtls_port`) — never directly to the remote pod. The dial:

- opens mesh-mTLS (HTTP/2-over-mTLS) to the gateway with the **ClientHello SNI overridden to the destination service port's alias**, so the gateway's SNI passthrough routes the opaque outer TLS to a destination workload;
- uses **trust-domain-scoped** peer verification: because the SNI-passthrough gateway LB-picks the destination workload, the client cannot pin a pod SPIFFE id, so it instead requires the destination's server SVID to be in **exactly the target's remote trust domain** (`mesh.trust_domain`) AND chain to a federated bundle — a federated cert from a *different* trust domain is rejected. AuthorizationPolicy at the destination does the fine-grained source check.

Local-cluster endpoints stay the first tier (cross-cluster targets carry `mesh.remote=true`). Fail-closed throughout: a missing SNI override, trust domain, gateway, dial host, or CONNECT authority refuses/skips the dial with no plaintext fallback. HTTP-family ports retain the base/per-port alias rules described below. Raw-TCP and UDP ports materialize **per-remote-pod** tunnel targets: `mesh.mtls_dial_host` carries the east-west gateway, `mesh.mtls_authority_host` carries the real destination pod address, and `target.port` carries the resolved app port. Their outer TLS uses the L4 per-port alias (protocol-disambiguated when TCP and UDP share a number), and the shared `MeshMtlsDialPlan` selects trust-domain-only verification plus the SNI override. Raw TCP then byte-relays through the bare H2 CONNECT; UDP uses the existing `udp` marker and `mesh_udp_frame` framing.

**Destination inbound relies on the standard sidecar inbound capture.** The client dials the gateway with the destination service port's alias as SNI; the gateway forwards the opaque TLS to the destination workload's **app port**, and the destination pod's inbound iptables capture REDIRECTS that app-port traffic to the sidecar's `:15006` mTLS listener — exactly as same-cluster east-west *inbound* works (`build_east_west_service_targets` forwards to the workload app/target port, not `:15006`). No destination-side change is needed for cross-cluster.

**Cross-cluster gRPC and WebSocket egress are supported for Sidecar (issue #2010).** Both ride the SAME cross-cluster mesh-mTLS transport as HTTP — the app protocol is a runtime flavor layered on top. A native-gRPC request whose LB-selected target is a cross-cluster `mesh.mtls` target skips the direct-dial gRPC pool and dispatches through the mesh-mTLS pool's cross-cluster branch (`proxy_to_backend_mesh_mtls`): hyper HTTP/2 end-to-end, `te: trailers` re-synthesized, response streamed so `grpc-status` and custom trailers relay across the two-trust-domain hop. A WebSocket upgrade opens an RFC 8441 Extended CONNECT over that same cross-cluster mesh-mTLS dial. Both the HTTP/gRPC path and the WebSocket path resolve the dial the same way through a shared `MeshMtlsDialPlan` (in-cluster pins the peer SPIFFE; cross-cluster uses `expected_peer = None` + trust-domain-only verification scoped to `mesh.trust_domain` + a ClientHello SNI override to `mesh.eastwest_sni`), so the two transports cannot drift. Fail-closed throughout: a cross-cluster target missing its SNI override or remote trust domain, or an unsupported transport, is refused (gRPC UNAVAILABLE / a failed upgrade) with no plaintext or wrong-SNI fallback. A native-gRPC request initially selected onto mesh-mTLS may use replayable retry attempts on that transport. The native-gRPC retry loop re-resolves its transport per attempt and may rotate between direct and Ambient `mesh.hbone` targets (issue #3728), but still fails closed if rotation lands on a Sidecar `mesh.mtls` or Unix-socket target, because it cannot preserve the generic mesh response/trailer pipeline mid-loop. (The WebSocket dial loop re-derives mesh egress from the rotated target on every attempt; only unsupported/malformed WS targets fail the upgrade closed.) The HTTP/3 frontend's gRPC and WebSocket bridges both dispatch over the mesh transports (issues #3284, #3620), so cross-cluster gRPC and WebSocket work from HTTP/3 clients too; Unix-socket targets still fail closed. **Ambient cross-cluster gRPC and WebSocket are both supported** over HBONE — gRPC through a nested HTTP/2 connection inside the CONNECT tunnel on every frontend (issues #3284, #3728), WebSocket through the tunnel's inner HTTP/1.1 handshake; see the Ambient section below.

### Client-Side Cross-Cluster Egress (Ambient / HBONE)

An **Ambient** client reaches a remote-cluster service over the east-west gateways too, but the shape differs from Sidecar because the inner protocol does. Ambient's inner request is an HBONE **CONNECT** whose `:authority` the destination relay (`handle_hbone_request` → `build_inbound_hbone_relay_proxy`) dials under the **open-relay guard** (`inbound_hbone_relay_destination_decision`): the authority must be a destination this terminator owns — typically a **slice-declared workload addr+port** — and a service FQDN is rejected. Loopback / DNS `localhost` is not an Ambient shortcut: the destination Ambient proxy is node-shared and would dial its own namespace. The remote pod IP is slice-declared on the destination side and known to the client (merged remote endpoints), just not directly reachable. So Ambient cross-cluster targets are **per-remote-pod**, not one-per-gateway:

- the `UpstreamTarget` identity is a **scoped synthetic host** carrying the gateway-network scope + the real pod addr (so two remote pods that share an IP across overlapping CIDRs but are reached through different gateways/networks never collapse to one load-balancer / health / circuit-breaker key); the **real pod addr:app-port** rides the `mesh.hbone_authority_host` tag and is what the inner HBONE CONNECT `:authority` uses;
- the dial host is the remote network's **east-west gateway** (`mesh.hbone_dial_host` / `mesh.hbone_port`, e.g. `:15443`) with the **ClientHello SNI overridden to the destination service port's alias** (`mesh.eastwest_sni`) so the gateway's SNI passthrough routes the opaque outer TLS;
- verification is **trust-domain-scoped** (`mesh.trust_domain`, no pod SPIFFE pin — the gateway LB-picks the destination), the same posture as the Sidecar cross-cluster path; the HBONE pool key includes the SNI override + the expected trust domain so a session verified for one (trust domain, destination) is never reused for another.

The HBONE **capability registry is bypassed** for cross-cluster targets (they dial the operator-declared gateway, never a probeable workload `:15008`) and they are excluded from capability probing. Local-cluster endpoints stay the first tier (`mesh.remote=true`). HTTP-family ports follow the [SNI alias rules](#multi-port-cross-cluster-sni-aliases). Raw-TCP and UDP reuse the same per-pod target shape with the L4 per-port alias as outer SNI and the real pod addr/app-port as CONNECT authority. Raw TCP uses the existing HBONE byte tunnel; UDP uses `get_datagram_tunnel` and the same length-delimited `mesh_udp_frame` records as same-cluster UDP. Missing SNI, trust domain, dial host, or authority fails closed before a wrong-target dial.

**Destination inbound relies on the standard inbound capture** (same as the Sidecar path above). The client dials the gateway with the destination service port's alias as SNI; the gateway forwards the opaque TLS to the destination workload's **app port** (`build_east_west_service_targets` forwards to the workload app/target port, not a mesh terminator port), and the destination pod's inbound capture REDIRECTS that app-port traffic to the Ambient HBONE terminator `:15008` — exactly as same-cluster east-west *inbound* works, and exactly how the Sidecar cross-cluster path redirects to `:15006`. No destination-side change is needed for cross-cluster. The unprivileged functional fixtures still collapse that redirect by targeting the terminator port directly; the privileged **Two-Cluster Mesh Live Datapath** CI gate (`functional_mesh_live_two_cluster_cross_cluster_protocol_matrix`) validates the real app-port → destination-capture path with separate federated SPIRE trust domains and an isolated east-west hop.

**L4 test boundary.** In-tree projection tests cover Sidecar/Ambient raw-TCP and UDP target materialization, per-port SNI generation, and destination east-west SNI relay creation. Existing unprivileged functional tests cover the raw byte-stream and framed-datagram destination relays. The privileged **Two-Cluster Mesh Live Datapath** CI gate covers the complete boundary that those harnesses cannot simulate: `SO_ORIGINAL_DST`/TPROXY in cluster A → actual SNI-passthrough east-west gateway → app-port capture and terminator in cluster B, including `mesh_udp_frame` datagrams and transparent VIP:port return-source spoofing.

**WebSocket AND native gRPC over cross-cluster HBONE (Ambient) are both supported (issues #2010, #3284, #3728).** A WebSocket upgrade to a cross-cluster HBONE target rides the SAME per-pod cross-cluster HBONE byte tunnel the HTTP path uses — dial the remote east-west gateway (`mesh.hbone_dial_host`) with the destination service port's alias as the outer-TLS SNI override (`mesh.eastwest_sni`) + trust-domain-only verification (`mesh.trust_domain`, no pinned pod SPIFFE); the inner HBONE CONNECT `:authority` is the destination pod addr:app-port (`mesh.hbone_authority_host`) the dest relay byte-copies to — then an inner HTTP/1.1 WebSocket handshake spoken THROUGH the tunnel. `get_ws_byte_tunnel` threads the cross-cluster SNI-override / trust-domain scope (mirroring `proxy_to_backend_hbone`), so the WS and HTTP HBONE paths cannot drift; a malformed cross-cluster target (missing SNI / trust domain) fails the upgrade closed. **Native gRPC over cross-cluster HBONE is supported on every frontend** — it does NOT use this HTTP/1.1-inside-the-tunnel dispatch. Native gRPC (and gRPC-Web the `grpc_web` plugin TRANSLATED, which is wire-native gRPC by dispatch time) instead runs a NESTED `hyper::client::conn::http2` client over the very same authenticated CONNECT byte tunnel through the shared `GrpcDispatchTransport`, so `grpc-status` trailers, flow control, backpressure, deadlines, and cancellation relay end-to-end. The HTTP/3 bridge wired that transport first (issue #3284) and the standard HTTP/1.1+HTTP/2 frontend reuses it (issue #3728). A malformed cross-cluster target (missing SNI override / trust domain / CONNECT authority host, or one declaring BOTH mesh transports) still fails closed BEFORE any dial with a Trailers-Only gRPC UNAVAILABLE (HTTP 200 + `grpc-status: 14`) whose message never echoes identity metadata. (PASS-THROUGH gRPC-Web is body-framed and keeps riding the cross-cluster HTTP-family path like plain HTTP.) **Sidecar cross-cluster gRPC and WebSocket are also supported** over mesh-mTLS — see [Client-Side Cross-Cluster Egress (Sidecar)](#client-side-cross-cluster-egress-sidecar) and the [Protocol x Topology Support Matrix](#protocol-x-topology-support-matrix).

### Multi-Port Cross-Cluster SNI Aliases

The east-west gateway routes purely by the ClientHello SNI, which carries a hostname but no port. Ferrum derives the deterministic DNS-safe name from `cross_cluster_service_sni`, shared by both ends. **Every service port — of a single-port or multi-port service alike — routes on an explicit per-port alias**; the base service FQDN `<service>.<namespace>.svc.<cluster-domain>` routes to **no** port:

- **HTTP-family or raw-TCP port** → `p<service-port>.<base-fqdn>` (e.g. `p8080.reviews.default.svc.cluster.local`, `p9090.reviews...`). The **numeric service port** is authoritative in the alias — a port *name* is never used for uniqueness. `p<port>` is a valid DNS label, so the alias is a valid FQDN (no colon-bearing SNI).
- **UDP port** (`udp` / `dtls`) → `p<service-port>-udp.<base-fqdn>`, always — even when no other port shares the number. A TCP-family and a UDP port on one number (DNS on 53, HTTPS plus QUIC on 443) therefore keep separate routes and targetPorts. UDP-ness comes from the port's **declared** protocol; `protocol_overrides` (keyed by port number) never moves a port between the `p<port>` and `p<port>-udp` aliases.
- **Ambiguous alias skipped.** When more than one declared port maps to the same alias — the same number on the same declared L4 transport — a peer dialing that alias could not say which port it means. Examples are an HTTP-family and a raw-TCP port on one number, duplicate native entries, or a Kubernetes Service declaring `3868/TCP` plus `3868/SCTP` (SCTP has no mesh transport model and is not UDP). Every source, Kubernetes included, handles this the same way: the Service still translates in full, so in-cluster routing, authorization and Gateway API backends are unaffected, and both ends skip only that alias for cross-cluster routing with a rate-limited warning. The service's other ports keep routing cross-cluster.

**Why alias every port (cross-cluster port skew).** Two clusters can declare *different* port sets for the same service. Routing any port on the bare base FQDN would let a client that only knows `:9090` treat it as the base while a destination that also has `:8080` materializes the base for `:8080` — the client's base-FQDN traffic would then be forwarded to the wrong port. Making the port channel the **explicit numeric port** in the alias removes any shared base-FQDN mapping. Because the label depends only on the port's own number and transport — never on which *other* ports the service declares — a client dialing `p9090.<fqdn>` is matched by a destination that materialized `:9090` on that same alias regardless of either cluster's port set, and a mismatch **fails closed** on the absent per-port proxy instead of silently cross-wiring. This also makes the scheme order-independent for free (the alias is keyed on the port number, never declaration order).

**Collision-free internal ids.** The internal east-west proxy/upstream ids are registry keys only (a `Proxy.id`/`Upstream.id`, never emitted to Kubernetes, DNS, SNI/TLS, or any wire protocol — the SNI above is built independently). Every per-port id joins the alias label with a `.` — `__mesh-ew-svc-<ns>-<name>.p<port>` — and `.` is a character a DNS-1035/1123 Kubernetes service name **cannot** contain, so a service literally named `<name>-p<port>` (whose id is `__mesh-ew-svc-<ns>-<name>-p<port>.p<port>`) can never collide with another service's alias id in the materializer's id-keyed upsert map.

**Gateway ownership is automatic (no extra operator config).** The client selects a gateway whose `sni_hosts` claim either the base FQDN or the exact alias, then dials the derived SNI. The destination auto-materializes one SNI-passthrough proxy for every supported service port, backed by that port's container port. Explicit SNI ownership on the destination gateway suppresses only overlapping automatic routes: to hand a port to an explicit `EastWestGateway` route there, list its alias (or a covering wildcard such as `*.<base-fqdn>`) in `sni_hosts` — a base-FQDN-only entry overlaps no alias.

**Fail-closed on skew.** A dial whose destination gateway did not materialize the alias finds no SNI match and fails rather than reaching another port. Missing SNI/trust-domain/authority metadata and cross-trust-domain shared endpoints remain refused. The gateway service-discovery bridge remains HTTP-family-only; raw-TCP/UDP parity applies to mesh-mode original-destination/TPROXY capture paths.

**Shared `targetPort` limitation.** When two HTTP-family service ports resolve to the **same container port** (e.g. `80 → 8080` and `90 → 8080`), the SNI alias is consumed at the SNI-passthrough gateway, which forwards both to the same workload app port. The destination's inbound selector then sees the same captured orig-dst and applies the lower port's inbound route/policy to both. This is not a misroute — both service ports reach the same backend container (the same app), so the destination treatment is consistent; only destination-side per-**service**-port policy differentiation for shared-container ports is lost (the client-side DestinationRule policy stays per service port). It is inherent to the single-SNI-per-port passthrough model; distinct container ports are fully disambiguated.

### Trust Federation

`TrustBundleSet` carries local and federated X.509/JWT authority bundles:

- `local`: the trust bundle for the local cluster's trust domain.
- `federated`: trust bundles from remote clusters, enabling cross-cluster mTLS verification.

X.509 authorities are stored as base64-encoded DER for serialization-friendly persistence. JWT authorities carry `key_id` and `public_key_pem`.

X.509 trust updates are admitted as complete sets: every local and federated
authority must decode and be usable as a rustls trust root, and every declared
trust domain must contain a usable root. A malformed Workload API response or
slice/file trust candidate never activates only its surviving domains; an
already-running verifier retains its last-known-good set.

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
freshest rotation. For a remote cluster with a `federation_endpoint`,
`FERRUM_MESH_FEDERATION_FAIL_OPEN=false` (default) makes activation
fail-closed during bootstrap: CP-supplied fallback bundles for that remote
trust domain are not used until the poller has installed a last-good bundle.
`FERRUM_MESH_FEDERATION_FAIL_OPEN=true` keeps the CP-supplied fallback active
until the first successful poll. After a bundle has been polled, transient
poll failures preserve the last-good bundle only until
`FERRUM_MESH_FEDERATION_MAX_STALE_SECONDS` (default 3600) is exceeded. At that
point the polled bundle is withdrawn from the active trust set and the slice
apply loop is woken so outbound mTLS and inbound SPIFFE verification fail
closed until a later successful poll reinstalls fresh trust. Set the max-stale
value to `0` only for dev/test indefinite retention; production mode rejects
that posture when federation polling is enabled. The effective trust set is
used for outbound mTLS and for inbound SPIFFE peer verification. Endpoints are validated at slice apply for
SSRF (link-local / loopback / cloud metadata IPs are rejected) and must use
`https://`; response bodies are capped at 2 MiB and parsed bundles are capped
at 256 X.509 + 256 JWT authorities. `mesh.multi_cluster.remote_clusters` is capped at 256 entries (see [Remote Clusters](#remote-clusters)).

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

- `ferrum_mesh_federation_poll_failures_total{trust_domain}`
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
      discovery_credential_ref: "eu-west-1"   # required for discovery; selects the per-remote discovery secret
```

- `federation_endpoint` feeds the [trust-bundle federation poller](#trust-federation) (cross-cluster mTLS verification material).
- `control_plane_url` feeds **cross-cluster endpoint discovery** (below).
- `discovery_credential_ref` selects the per-remote discovery credential resolved against `FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS` so this cluster authenticates to its own control plane with a distinct JWT secret; see [Cross-Cluster Endpoint Discovery](#cross-cluster-endpoint-discovery). Remote discovery requires it: a cluster without a resolvable reference is not polled.
- `name` doubles as the **target-cluster audience identifier** for remote discovery: the discovery token minted for this cluster carries `aud: ferrum-mesh-discovery:<name>`, and the peer control plane accepts it only when its own `FERRUM_MESH_CLUSTER_AUDIENCE` matches. It must therefore be the identifier that cluster knows itself by, not a local-only alias. The name is a **canonical identity**: leading/trailing whitespace is rejected (never silently rewritten), and uniqueness is enforced in that same trimmed identity domain so two spellings cannot collapse onto one JWT audience while remaining distinct poll/store keys. See [Remote-Discovery Audience Binding](#remote-discovery-audience-binding).
- `local_cluster` is **optional**. Remote-cluster provenance — the marker that makes [strict locality LB](#locality-aware-load-balancing) and the egress local-only filter treat an endpoint as remote — is keyed on the workload's cross-cluster identity: a discovered endpoint carries a configured `remote_clusters[].name`, so it is classified remote whether or not `local_cluster` is set. Set `local_cluster` only when you also want a *locally* declared workload that carries an explicit `cluster` tag distinguished from your remote clusters. When set, it must likewise be a canonical identifier with no leading/trailing whitespace.
- `remote_clusters` is capped at 256 entries by mesh validation to bound federation and endpoint-discovery task fan-out.

### Cross-Cluster Endpoint Discovery

When `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS > 0` (default `0`, disabled), each currently eligible `RemoteCluster.control_plane_url` is dialed over the native `MeshSubscribe` gRPC stream (authenticating with that cluster's `discovery_credential_ref` credential and TLS selected from that remote URL) to fetch that cluster's service endpoints (workloads + services). The discovered endpoints are merged into the local mesh registry at slice apply and become ordinary upstream targets, tagged with a synthetic **remote locality** (`remote-<cluster>` or `remote-<cluster>/<network>`). Because the load balancer is **locality-aware priority-tier** (see [Locality-Aware Load Balancing](#locality-aware-load-balancing)), local endpoints occupy the source region/zone tier and remote endpoints sit in the fallback tier: traffic stays local while local endpoints are healthy and **fails over to the remote cluster's endpoints only when the local tier has no healthy endpoints**.

> **Precondition — source locality required for local-first preference.** The priority-tier LB only prefers local endpoints over remote ones when the local workload's source locality is set (derived from `topology.kubernetes.io/region`+`zone` labels on the mesh slice's SPIFFE-matched workload, or from the label-based heuristic). When source locality is absent (e.g. the labels are missing or the SPIFFE-matched workload has no locality), `target_locality_ranks` is empty and the behavior depends on the **locality-LB strict mode** (`FERRUM_MESH_LOCALITY_LB_STRICT`, default `false`):
>
> - **Fail-open (default, `false`):** the LB returns local **and** remote endpoints together — traffic can go to the remote cluster even when local endpoints are healthy (not local-first). This preserves availability.
> - **Fail-closed-to-local (`true`):** the LB restricts selection to **local** endpoints — every target *not* tagged as a remote-cluster-discovered endpoint — and never widens to remote while at least one local endpoint exists. Remote provenance is keyed on an explicit per-target marker stamped from the workload's cross-cluster identity at materialization time (not on the locality string), so a real local Kubernetes region that happens to be named `remote-…` is still treated as local; a target with no remote marker counts as local. If there are **no** local endpoints it widens to the full healthy pool (local + remote) and logs a one-time `WARN` rather than black-holing traffic. Strict mode is **inert when a source locality is resolved**: priority-tier preference (exact/zone/region) is unchanged in both modes.
> - **Ambiguous locality:** when compatible local replicas disagree on source locality, Ferrum automatically applies the fail-closed-to-local behavior for that slice even if strict mode is `false`. Ambiguity is not treated as ordinary missing metadata, so a same-SPIFFE sibling cannot broaden selection to remote endpoints.
>
> Ferrum emits a startup `WARN` when discovery is enabled but no source locality can be resolved from the initial mesh slice. Ensure `topology.kubernetes.io/region` and `topology.kubernetes.io/zone` Node labels are propagated to workload locality metadata (via `FERRUM_K8S_NODE_LOCALITY_ENABLED=true`, or by stamping them directly on the mesh slice's `Workload.locality` field) before enabling discovery; prefer fixing source locality over enabling strict mode, which is a safety net rather than a substitute for correct locality metadata.
>
> Config validation additionally emits a `WARN` advisory (any mode, never an error) whenever `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS > 0` is combined with `FERRUM_MESH_LOCALITY_LB_STRICT=false`, recommending strict mode so an absent source locality cannot mix remote endpoints into selection while local endpoints are healthy. Cross-cluster east-west **gateway** failover targets are unaffected either way — they are always-failover local-first regardless of the flag; the advisory covers only plain remote workload endpoints from this Beta discovery path.

**Per-RemoteCluster discovery credentials.** Each `RemoteCluster` polled by discovery must set `discovery_credential_ref`, a reference resolved data-plane-side against `FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS` (a JSON object mapping reference -> the JWT secret that remote cluster's control plane accepts; itself resolvable through the external-secret backends and never serialized into the slice/config or logged). The data plane mints that cluster's remote `MeshSubscribe` token with the referenced secret, so (with distinct per-cluster secrets) a credential issued for cluster B cannot authenticate to cluster C — cluster B's control plane validates the HS256 signature with **B's** secret, and a token signed with B's secret simply fails to verify at C. A `RemoteCluster` with no `discovery_credential_ref`, or one that does not resolve to an installed entry, **fails closed** (it is skipped with a startup `WARN`); discovery never authenticates with the shared `FERRUM_CP_DP_GRPC_JWT_SECRET`, which would make a credential good for any one cluster good for all of them. The per-remote secret carries the local CP-DP issuer (`FERRUM_CP_DP_GRPC_JWT_ISSUER`), since the remote CP pins the issuer, not a per-remote one. Explicit JWT **audience-claim** binding is **enforced** on top of the per-remote secret — see [Remote-Discovery Audience Binding](#remote-discovery-audience-binding). Discovery is fail-closed on trust: a remote cluster is dialed **only** while a federated trust bundle for its `trust_domain` is present (configure [Trust Federation](#trust-federation) for the peer first). The discovery reconciler watches **proxy-accepted** mesh-slice updates (the same applied-slice source the federation poller uses, never a merely received slice) and federation updates, starts newly eligible clusters, stops removed or no-longer-trusted clusters, and removes their stale endpoints. Because it reconciles from the accepted slice, a slice the proxy *rejected* — including one that keeps a cluster's name + trust domain but changes its poll identity (`network`, `control_plane_url`) — never starts a poller or populates the endpoint store, and a changed poll identity stops the old poller and evicts its endpoints before the new one starts. A poll failure keeps the last-good endpoints and backs off (jittered 1s -> 30s) only until `FERRUM_MESH_REMOTE_DISCOVERY_MAX_STALE_SECONDS` (default 300) is exceeded; then the endpoints and their success/age metrics are withdrawn while the poller keeps retrying, so a later successful poll can reinstall without a slice change. Set the max-stale value to `0` only for dev/test indefinite retention; production mode rejects that posture when discovery is enabled. `control_plane_url` is SSRF-validated (cloud-metadata / link-local hosts rejected; loopback allowed for local/dev/test). In production mode, remote discovery accepts only authenticated TLS URLs (`https://` or `grpcs://`) and rejects plaintext `http://` / `grpc://`; `FERRUM_DP_GRPC_TLS_NO_VERIFY=true` is also refused when discovery is enabled.

The merge into the live proxy config is additionally filtered against the **candidate (about-to-be-applied) slice's** `multiCluster` by the stored entry's **full poll identity** — name, `trust_domain`, `network`, and the normalized `control_plane_url` — so cluster removal and control-plane identity changes are fail-closed **within the same generation**, not one generation later: when a newly-accepted slice drops a remote cluster (or declares it under a divergent `trust_domain`, `network`, **or `control_plane_url`**), that cluster contributes **no** endpoints to the config built from that slice — even before the discovery reconciler evicts the store entry. A URL-only change is caught here too: the stored entry records the normalized URL it was polled from, so endpoints fetched from the *previous* control plane are not served by the generation that accepts the new URL. A slice with no `multiCluster` at all contributes no remote endpoints. Conversely, because the pollers track the **accepted** slice, an accepted remote cluster can publish an endpoint scale-up/down while the CP's newest *received* slice is one the proxy rejects; the apply loop re-applies that overlay against the **last-accepted** slice so the change still reaches the live proxy without waiting for a fresh valid slice (fail-closed by retention if even the last-accepted slice no longer builds). A mesh-block-only change (a remote scale-up/down, or a trust-bundle overlay) produces no proxy/upstream delta, so the proxy-config apply explicitly republishes the request epoch on such changes — otherwise the request path's view of `mesh.workloads`/`mesh.services` would stay stale until an unrelated proxy/upstream change forced a republish.

#### Remote-Discovery Audience Binding

Signature + issuer + expiry bind a discovery token to a **credential**, not to a **destination**. Clusters that accept the same discovery secret and issuer — an operator reusing one discovery secret for several clusters, or a token misrouted between them — cannot tell destinations apart by signature, issuer, or expiry alone: a token minted for cluster B would verify identically at C. Per-remote secrets give signature isolation only while they are distinct; audience binding also protects against deliberate secret reuse. Ferrum therefore binds every remote-discovery token to its **target cluster** with a JWT `aud` claim.

**The target-cluster identifier.** The audience is derived from a stable, operator-visible cluster identifier that is deliberately **independent of `control_plane_url`** — an endpoint moves (DNS change, port change, new load balancer) and must never be what a credential is bound to. The identifier is:

| Side | Source | Value |
| --- | --- | --- |
| Polling data plane | `RemoteCluster.name` of the cluster being polled | minted `aud` = `ferrum-mesh-discovery:<name>` |
| Receiving control plane | `FERRUM_MESH_CLUSTER_AUDIENCE` | expected `aud` = `ferrum-mesh-discovery:<value>` |

Set `FERRUM_MESH_CLUSTER_AUDIENCE` on each cluster's control plane to the identifier its peers use in `RemoteCluster.name`. Both values are identifiers, never credentials: neither is a secret, and neither is derived from one. `RemoteCluster.name` must be configured without leading/trailing whitespace; mesh validation rejects padded or whitespace-aliased names before any remote poller starts, so the configured identity and the JWT audience stay one-to-one.

**Control-plane enforcement.** `MeshConfigSync.MeshSubscribe` carries a `remote_discovery` flag distinguishing a cross-cluster poll from an ordinary local mesh data-plane subscription. Both branches fail closed, so the flag is not a trust decision an attacker can flip to their benefit:

| Subscription class | Required `aud` | Refused |
| --- | --- | --- |
| `remote_discovery = true` (cross-cluster poll) | exactly one, equal to this cluster's `ferrum-mesh-discovery:<FERRUM_MESH_CLUSTER_AUDIENCE>` | missing, malformed (empty / non-string / empty array), **multiple or ambiguous**, mismatched, or **any** value when `FERRUM_MESH_CLUSTER_AUDIENCE` is unset |
| `remote_discovery = false` (ordinary local mesh DP) | exactly one, equal to the stable purpose `ferrum-mesh-subscribe:local` | missing, malformed, multiple/ambiguous, or any other value (including every `ferrum-mesh-discovery:` audience) |

A multi-valued `aud` is treated as **ambiguous and refused** rather than accepted on any match, so a token cannot name several clusters at once. A control plane with no `FERRUM_MESH_CLUSTER_AUDIENCE` cannot state which cluster it is, so it refuses every cross-cluster subscription outright instead of accepting an unbound one.

**Token-purpose separation.** The two token classes are kept unambiguous in both directions, so one can never silently substitute for the other:

- Cross-cluster discovery tokens carry the reserved `ferrum-mesh-discovery:` target prefix. Local mesh tokens carry the distinct fixed `ferrum-mesh-subscribe:local` purpose. Each MeshSubscribe branch requires its exact audience, so a discovery token cannot downgrade by clearing `remote_discovery`, a local token cannot upgrade by setting it, and a no-audience legacy token cannot select the false/default branch.
- Ordinary CP↔DP `ConfigSync` and xDS ADS tokens remain audience-less. Those non-MeshSubscribe surfaces continue to accept **no** audience: this preserves `jsonwebtoken`'s strict `validate_aud` posture (RFC 7519 §4.1.3), so a token minted for either MeshSubscribe purpose or some other service cannot authenticate to the ordinary CP/DP plane merely because the HS256 secret is shared. Operator-minted ConfigSync/xDS tokens must therefore not stamp an `aud`.

**Layering.** Audience binding is defense in depth **on top of** — never instead of — the existing checks: HS256 signature against the discovery credential secret (the polling DP's per-remote credential; the receiving CP's `FERRUM_CP_DP_GRPC_JWT_SECRET` must carry the same value), required `exp`/`iat`/`sub`/`iss`, pinned issuer, the `ns` namespace claim, TLS/production transport posture, and the fail-closed per-remote credential resolution all still apply, and a failure in any of them still refuses the subscription. (DP tokens still mint `role: data_plane` for operator/tooling conventions; the CP gRPC verifier does not authorize on it.)

**Compatibility.** `MeshSubscribe` has no no-audience compatibility mode: a local or remote client that sends no `aud` is refused, and a client that sends an audience is refused by a control plane whose verifier does not expect one. Mixed-version native MeshSubscribe therefore fails closed; roll the control plane and every native mesh/remote-discovery client as one compatibility unit. Ordinary `ConfigSync` and xDS tokens are not affected: they carry no audience and refuse audience-bearing tokens.

**Failure handling and diagnostics.** A refused subscription fails the whole poll: the data plane keeps that cluster's **last-good endpoints**, backs off, and imports nothing (the existing `FERRUM_MESH_REMOTE_DISCOVERY_MAX_STALE_SECONDS` window still governs eventual withdrawal). The control plane records the refusal as `ferrum_mesh_subscribe_audience_rejections_total{subscription,reason}` — `subscription` is `remote_discovery` or `local`, and the MeshSubscribe reason is one of `missing`, `malformed`, `ambiguous`, `mismatch`, or `unconfigured` — and emits an `audit.event="mesh_subscribe_audience_rejected"` `WARN`. Both labels are compile-time constants, so the series cardinality is fixed. The token, its claims, the expected audience, and the JWT secret are never logged or exported; the gRPC status returned to the caller is a fixed string that does not echo the presented audience.

#### Response Validation And Merge Rules

**Response validation is shared with local native consumption.** The remote fetch reads the first non-heartbeat `MeshConfigUpdate` through the *same* centralized, fail-closed rules the local native client applies (see [Native MeshSubscribe](#native-meshsubscribe-default) → "Response binding"): `ferrum_version` must be present and major/minor-compatible, the envelope `version` must equal the embedded `MeshSlice.version`, and the slice's `node_id`/`namespace` must match the subscription this data plane sent. Any mismatch fails the poll **before** a single workload or service is imported, so the cluster's last-good endpoints keep serving, the poller backs off, and endpoints from a wrong-cluster or wrong-namespace response are never merged into the local registry. Rejections increment `ferrum_mesh_config_update_rejections_total{consumer="remote_discovery",reason}` alongside the poll-failure counter.

Merge rules: exact duplicate workload endpoints are skipped, but workloads with the same SPIFFE ID and different addresses are retained because the same service account identity can have replicas in multiple clusters. A service the local cluster already advertises keeps its local ports/overrides and unions in the remote workload refs so it resolves both local and remote endpoints; a service that exists only remotely is added wholesale.

**Observability:** `GET /mesh/remote-clusters` (JWT-authenticated, mesh-only) surfaces the DP's live view of this discovery — the remote clusters it has actually fetched endpoints from (per-cluster workload/service counts + fetch age under `discovered`) and the remote clusters the accepted slice declares (under `configured`, each cross-referenced with a `discovered` flag). Each configured row also reports `outbound_trust_active`, `inbound_trust_active`, `trust_source` (`polled`, `control_plane`, `local`, `blocked_pending_poll`, or `none`), and polled-bundle fetch age when available. That makes asymmetric trust visible: outbound can be active while inbound is inactive if no SPIFFE verifier slot is configured, and fail-closed bootstrap appears as `trust_source: "blocked_pending_poll"`. A configured remote cluster that never appears under `discovered` is the signal that discovery is disabled, the peer's trust bundle is missing, or polls are failing. The `discovered` view is additionally scoped to the **accepted** slice's clusters (matched by full poll identity — name, trust domain, network, and normalized `control_plane_url`) as belt-and-suspenders on top of the accepted-slice reconcile above, so a cluster absent from the accepted config — or whose stored network/control-plane identity diverges from it — is never reported as live discovery (and never with a stale network) (fail closed). The per-cluster fetch age tracks the last successful **poll**, not the last endpoint **change** — a stable cluster still refreshes its age each poll, so it does not look stale to alerting. The payload reports counts and provenance only — never raw workload addresses, SPIFFE IDs, or control-plane URLs.

**Live-verification status:** aggregation and failover remain covered by hermetic integration tests, and `.github/workflows/multicluster-poller-partition-live.yml` adds the true cross-cluster gate: two Ferrum CP/DP deployments use verified TLS/mTLS, per-remote credentials, bound audiences, and four independently faultable Toxiproxy links. Its required evidence covers initial trust/endpoint installation, short-partition retention with increasing age, independent endpoint and trust expiry, inbound/outbound recomputation, target removal, same-generation recovery without a new slice, bounded/redacted metrics with admin-age parity, and withdrawal while polls are in flight without retired-state reinstall.

## Protocol x Topology Support Matrix

One table answering "does protocol X ride mesh transport Y?" across the two same-cluster topology transports, the two client-side cross-cluster east-west paths, and the gateway-to-mesh service-discovery bridge. Each cell is anchored to the authoritative section via the numbered notes below. **NodeWaypoint is deliberately out of scope for this table** — it is **Experimental** with its own sections ([Node Waypoint](#node-waypoint), [Node Agent Mode](#node-agent-mode)); its UDP/DTLS behavior (per-pod scoping via ingress-interface attribution, issue #3286) is pinned in [docs/mesh_supported_matrix.md](mesh_supported_matrix.md) and in the NodeWaypoint UDP/DTLS section above.

Column key: **Sidecar same-cluster** = Sidecar egress over plain SVID-mTLS HTTP/2 to the peer sidecar's `:15006`; **Ambient same-cluster** = Ambient/Waypoint egress over HBONE (HTTP/2 CONNECT over mTLS) to the peer's `:15008`; **Cross-cluster Sidecar / Ambient** = client-side cross-cluster egress through the east-west SNI-passthrough gateways; **SD bridge** = non-mesh gateway modes resolving mesh workloads via `service_discovery.provider: mesh` and dispatching over the configured destination topology's transport tag.

| Protocol | Sidecar same-cluster (mesh-mTLS `:15006`) | Ambient same-cluster (HBONE `:15008`) | Cross-cluster Sidecar (east-west gateway) | Cross-cluster Ambient (east-west gateway) | Gateway-to-mesh SD bridge (`provider: mesh`) |
|---|---|---|---|---|---|
| HTTP/1.1 | **Supported**; identity-pinned, fail-closed, never plaintext [1] | **Supported**; capability-probe-gated, identity-pinned [1] | **Supported** on all HTTP-family ports (per-port SNI alias); 502 on missing SNI / trust domain / gateway [2] | **Supported** on all HTTP-family ports; per-remote-pod targets [3] | **Supported**; `mesh.mtls` or `mesh.hbone` targets, fail-closed when not bridgeable [4] |
| HTTP/2 | **Supported** [1] | **Supported** [1] | **Supported** [2] | **Supported** [3] | **Supported** [4] |
| gRPC | **Supported**; trailers relayed, gRPC UNAVAILABLE on failure, never plaintext [5] | **Supported on every frontend**; nested HTTP/2 inside HBONE [5] | **Supported** on all HTTP-family ports; gRPC UNAVAILABLE on missing SNI / trust domain [5] | **Supported on every frontend**; nested HTTP/2 over the cross-cluster dial [5] | **Supported for both topologies**; fail-closed on malformed or ambiguous targets [5] |
| WebSocket | **Supported**; RFC 8441 over SVID-mTLS, never plaintext [6] | **Supported**; HBONE byte tunnel + inner HTTP/1.1 upgrade [6] | **Supported**; RFC 8441 over the cross-cluster dial, fail-closed on missing SNI / trust domain [7] | **Supported**; cross-cluster HBONE byte tunnel, fail-closed before any dial [7] | **Supported**; keyed on the same target tags [6] [7] |
| Raw TCP | **Supported (Experimental)**; strict orig-dst match, unmatched pairs fail closed [8] | **Supported (Experimental)**; same matching over the HBONE pool [8] | **Supported (Experimental)**; per-pod CONNECT, missing metadata fails closed [2] [8] | **Supported (Experimental)**; per-pod HBONE byte tunnel [3] [8] | **Not part of the bridge** [9] |
| UDP | **Supported (Experimental)**; TPROXY capture, unroutable datagrams dropped [10] | **Supported (Experimental)**; per-pod-netns producer with per-pod evidence [10] [12] | **Supported (Experimental)**; length-delimited datagrams over the cross-cluster dial [2] [10] | **Supported (Experimental)** [3] [10] [12] | **Not part of the bridge** [9] |
| DTLS-over-UDP | **Supported (Experimental), opaque**; never terminated [11] | **Supported (Experimental), opaque** [10] [11] [12] | **Supported (Experimental), opaque** [2] [10] [11] | **Supported (Experimental), opaque** [3] [10] [11] [12] | **Not part of the bridge** [9] |

Notes (authoritative sections):

1. HTTP-family egress materialization per topology — the "Implementation status" / multi-port egress bullets under [Topologies → Sidecar](#sidecar). An outbound `404` for an un-materialized destination means no route was built, not that mTLS/HBONE is unavailable.
2. [Client-Side Cross-Cluster Egress (Sidecar)](#client-side-cross-cluster-egress-sidecar): HTTP-family traffic uses the per-port SNI alias scheme. Raw-TCP and UDP use per-pod tunnel targets and explicit per-port aliases (`p<port>` for TCP, `p<port>-udp` for UDP), with separate gateway dial and real-pod CONNECT-authority tags. All use trust-domain-scoped verification and fail closed without complete metadata.
3. [Client-Side Cross-Cluster Egress (Ambient / HBONE)](#client-side-cross-cluster-egress-ambient--hbone): per-remote-pod targets cover HTTP-family, raw-TCP, and UDP; L4 uses an explicit per-port SNI alias and the existing byte/datagram tunnel framing.
4. [Gateway Mesh Service Discovery](#gateway-mesh-service-discovery) and [Gateway-to-Mesh Bridge](#gateway-to-mesh-bridge): `topology: ambient` targets carry `mesh.hbone`, `topology: sidecar` targets carry `mesh.mtls` + `mesh.mtls_authority_host` (and `mesh.mtls_authority_port` for multi-port destinations). The two transports are not interchangeable — a topology mismatch fails closed with a 502 at dispatch. Target lists refresh on the provider's poll interval (default 30s). Sidecar-path remote-cluster workloads bridge to east-west gateway failover targets through the same shared core as the mesh-mode Sidecar cross-cluster column [2] (plus the SD-bridge `mesh.mtls_authority_host` tag), for the upstream's **selected** HTTP-family port — any HTTP-family port, via its per-port SNI alias; a **non-HTTP-family** selected port, a snapshot without `mesh.multi_cluster`, or a remote group with no matching east-west gateway stays skipped fail-closed. Ambient-path remote-cluster workloads bridge through the mesh-mode Ambient per-pod HBONE core [3] when a gateway is declared for the workload network (or a catch-all gateway applies): the target identity is synthetic, the inner CONNECT authority stays the remote pod addr, and `mesh.hbone_dial_host` / `mesh.hbone_port` carry the gateway. Direct remote pod-IP Ambient targets remain only as a flat-network fallback when no gateway is declared for that workload network and no applicable catch-all gateway (a candidate whose `sni_hosts` claim the base FQDN **or** the dialed per-port alias, plus a trust-domain match, for the destination) exists — an exact-network declaration is authoritative fail-closed even when it cannot route the destination, while a non-candidate catch-all leaves the fallback in place.
5. See [Native gRPC over mesh transports](#native-grpc-over-mesh-transports) below.
6. WebSocket egress bullet under [Topologies → Sidecar](#sidecar) ("WebSocket egress (Ambient and Sidecar)"): the dispatch is keyed on the `mesh.mtls`/`mesh.hbone` target tags, identity is pinned, and a mesh-tagged WebSocket target that cannot dispatch over its secured transport fails the upgrade — it is never dialed in plaintext. The H1/H2 frontend re-evaluates the mesh WebSocket fork per connect attempt (including retry rotations); the HTTP/3 WebSocket bridge does the same through the shared mesh WebSocket connector (`connect_mesh_websocket_backend`), on the initial selection and on every connect-retry rotation, and refuses before dialing — failing the upgrade with a 502 + `gateway-error-reason` — only when the target's secured transport cannot dispatch.
7. Cross-cluster WebSocket is supported on **both** topologies (issue #2010). **Sidecar** opens an RFC 8441 Extended CONNECT over the cross-cluster mesh-mTLS dial resolved by the shared `MeshMtlsDialPlan` (east-west gateway dial + `mesh.eastwest_sni` SNI override + trust-domain-only verification), the WebSocket analogue of the gRPC/HTTP cross-cluster path. **Ambient** rides the cross-cluster HBONE byte tunnel + an inner HTTP/1.1 upgrade through it, with `get_ws_byte_tunnel` threading the same SNI-override / trust-domain scope as the HBONE HTTP path (`proxy_to_backend_hbone`); the inner CONNECT `:authority` is the destination pod addr:app-port. Both fail the upgrade closed on a malformed cross-cluster target (missing SNI / trust domain), never a plaintext / wrong-SNI dial. See [Client-Side Cross-Cluster Egress (Sidecar)](#client-side-cross-cluster-egress-sidecar) and [(Ambient / HBONE)](#client-side-cross-cluster-egress-ambient--hbone).
8. [Raw-TCP egress](#raw-tcp-egress) under Topologies → Sidecar, including the direct pod-IP / headless second index. "Experimental" is the product contract's tier for stream-family egress ([docs/mesh_supported_matrix.md](mesh_supported_matrix.md)).
9. The SD provider publishes ordinary `UpstreamTarget` entries consumed by the gateway's HTTP-family outbound pools ([Gateway Mesh Service Discovery](#gateway-mesh-service-discovery), [Gateway-to-Mesh Bridge](#gateway-to-mesh-bridge)); the raw-TCP and UDP mesh datapaths are original-destination / TPROXY **capture** paths that exist only on mesh-mode capture listeners (see [Raw-TCP egress](#raw-tcp-egress) and [UDP egress](#udp-egress)).
10. UDP egress is dual-transport (Ambient over HBONE `:15008`, Sidecar over mesh-mTLS `:15006`); see [UDP TPROXY capture](#udp-tproxy-capture) and [mesh_udp_capture.md](mesh_udp_capture.md). For Ambient, the per-pod-netns producer stamps the registry-attested `source.principal` / `source.pod_uid` on the authenticated `udp` CONNECT; destination `mesh_authz` honors that pod scope only when the peer is a trusted HBONE assertor, the principal passes the trust-domain check, and the live slice binds that exact pod UID to the same SPIFFE ID. It evaluates the union of the source-scoped and destination-scoped policies in one deny-first pass; invalid evidence falls back to mesh-wide source policies only, never a broader grant. NodeWaypoint UDP/DTLS is a separate channel (ingress-interface attribution, issue #3286).
11. DTLS is declared `protocol: UDP` and relayed byte-for-byte; the outer hop's confidentiality comes from HBONE / mesh-mTLS. East-west pod→peer only; external **DTLS** egress via the EgressGateway is out of scope (external `protocol: UDP` ServiceEntry egress is supported — see [Egress Gateway](#egress-gateway)).
12. **Enrolled Ambient destination pod UDP relay.** When the resolved destination IP belongs to an enrolled local pod, the destination relay socket is opened **inside that pod's netns**, so the reply is not re-captured; if that cannot be done safely the tunnel fails closed with a 502 (never a host-netns fallback). Live-gated by `functional_mesh_live_source_capture_udp_manager_hbone_round_trip` in `netns-capture-live`.

#### Native gRPC over mesh transports

- **Same-cluster Sidecar (`mesh.mtls`).** Native gRPC skips the direct-dial gRPC pool and rides the SVID-mTLS HTTP/2 pool, identity-pinned, with `te: trailers` re-synthesized and backend `grpc-status` trailers relayed. `FERRUM_MAX_GRPC_RECV_SIZE_BYTES` caps the request body (Trailers-Only `RESOURCE_EXHAUSTED`), and the trailer status feeds circuit-breaker / passive-health / adaptive-concurrency recording.
- **Same-cluster Ambient (`mesh.hbone`), every frontend.** Native gRPC runs a NESTED `hyper` HTTP/2 connection inside the authenticated HBONE CONNECT byte tunnel (issue #3284 for HTTP/3, #3728 for H1/H2), never the generic HTTP/1.1-in-tunnel dispatch, which cannot carry trailers. Both frontends share one transport resolver, so identity, policy, and errors cannot diverge. Inner-connection pooling follows [HBONE Inner Application Connection Reuse](#hbone-inner-application-connection-reuse).
- **Cross-cluster.** Well-formed Sidecar targets ride the mesh-mTLS cross-cluster branch (east-west dial + SNI override + trust-domain scope); Ambient targets ride the nested-HTTP/2 HBONE transport over the cross-cluster dial.
- **Deadlines.** The client `grpc-timeout` is an absolute deadline anchored at request receipt and covers pool acquisition and readiness; timeouts return Trailers-Only `DEADLINE_EXCEEDED`. On the Sidecar path `backend_read_timeout_ms` starts only after acquisition and `sender.ready()`.
- **No response buffering.** Native-gRPC responses are never buffered on a mesh path; if buffering is still demanded (`response_body_mode: buffer`, or a plugin needing the body) the request fails closed with Trailers-Only gRPC `UNAVAILABLE`.
- **Retries.** A replayable request may retry; the native-gRPC retry loop re-resolves the transport per attempt and may rotate between direct and HBONE targets, but fails closed rather than rotating onto a Sidecar mesh-mTLS or Unix target.
- **Fail-closed classes.** A cross-cluster target with no transport tag, a cross-cluster `mesh.mtls` target missing its SNI override / trust domain, a target declaring both `mesh.mtls` and `mesh.hbone`, or an unusable pinned identity / dial-host / authority tag returns Trailers-Only gRPC `UNAVAILABLE` before any dial, with a message that never echoes identity metadata.
- **gRPC-Web and HTTP/3.** Pass-through gRPC-Web rides every mesh transport like plain HTTP; translated gRPC-Web takes the same trailer-preserving path as native gRPC. The H3→gRPC bridge dispatches both mesh transports, and the H3→HTTP plain bridge (buffered) and H3 WebSocket bridge dispatch well-formed mesh targets over their secured transport; see [http3.md → Mesh transport dispatch for the H3→gRPC bridge](http3.md#mesh-transport-dispatch-for-the-h3grpc-bridge) and [Translated gRPC-Web terminal frames](http3.md#translated-grpc-web-terminal-frames).

## Egress Gateway

When `FERRUM_MESH_TOPOLOGY=egress_gateway`, the mesh runtime materializes HTTP-family **and** stream-family (TCP) proxies from `ServiceEntry` resources with `location: mesh_external`.

### Materialization Rules

- Only `MeshExternal` entries are materialized (internal entries are skipped).
- HTTP-family protocols (`http`, `http2`, `grpc`, `tls`) materialize **HTTP-family** proxies: host-routed off the shared egress listener (mTLS termination at `egress_listen_addr`, default 15090). One proxy per host across all ports — host-only routing cannot disambiguate multiple ports under the same host.
- Stream-family protocols (`tcp`, `mongo`, `redis`, `mysql`, `postgres`) are **opt-in** via `FERRUM_MESH_EGRESS_STREAM_ENABLED=true` (default `false`). When the flag is off, stream-family ports are skipped with a warning and only HTTP-family egress materializes. When the flag is on, each stream-family port materializes its own TCP proxy on the ServiceEntry's destination port (e.g., `mongo.external.io:27017/TCP` produces a TCP listener on port 27017). **Each stream egress listener terminates SVID-mTLS and runs `mesh_authz` at accept** — the same authn/z as HTTP egress: the materialized stream proxy is `frontend_tls: true` and uses the SAME mesh-inbound `ServerConfig` (server identity = gateway SVID leaf+key, peer verifier = SPIFFE against the trust bundle) that backs the egress 15090 HTTP listener, shared via the stream listener manager's TLS slot (`set_frontend_tls_config` / live `swap_frontend_tls_config`). After the handshake, the injected `__mesh_spiffe_identity` stream hook extracts the peer SPIFFE id from the verified client cert and `__mesh_authz` enforces policy **before the external backend is dialed** (TLS-terminating frontends complete crypto/admission before backend dispatch). **A client certificate is required, not optional:** because the egress gateway is a security boundary onto external networks, `resolve_mesh_inbound_client_auth` escalates a `PERMISSIVE` `PeerAuthentication` (the default when no STRICT policy is in force) to `Required` for this topology, so a cert-less TLS client is **rejected at the handshake** instead of being admitted to the external backend — the shared `ServerConfig` is built with required client auth, which is why the same protection also covers the sibling 15090 HTTP-family mTLS listener. (If `PERMISSIVE` somehow resolves with no trust anchor at all, the listener cannot authenticate clients and **fails closed** with a hard error rather than serving optional-no-verify mTLS; `validate_egress_gateway_mtls_config` already requires a peer verifier at config time, and the escalation is reapplied on `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true` slice apply so a reload cannot downgrade it.) **Fail-closed:** if no mTLS `ServerConfig` is loaded the stream listener manager *defers* the per-port bind (it never binds plaintext), mirroring the inbound posture (`enforce_mesh_inbound_fail_closed`); under `FERRUM_MESH_PRODUCTION_MODE=true` a no-identity egress gateway is already refused at startup by the inbound fail-closed gate. The explicit opt-out `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true` restores the legacy plaintext + unauthenticated listener (`frontend_tls: false`) for operators who genuinely need it, with a loud startup warning — without compensating network controls, any pod that can reach the gateway then reaches the external service through it with no SPIFFE authn/z. One proxy per port; same-port collisions across ServiceEntries skip the second entry with a warning. Multi-port stream ServiceEntries bind each port separately. ServiceEntry ports that collide with the egress gateway's own listener port (`egress_listen_addr.port()`, default `15090`) or port `0` are skipped with a warning rather than emitted — letting them through would fail to bind at runtime (`EADDRINUSE`) and reject the entire slice apply.
- Mongo / Redis / MySQL / Postgres are TCP-based at the wire level; the protocol tag is preserved on `Proxy.name` for observability but **no protocol-aware mediation** (e.g., MongoDB wire-format inspection) is performed. Protocol-level mediation is tracked separately.
- **Wildcard hosts differ by transport family.** An HTTP-family wildcard `hosts[]` entry (`*.example.com`) supports `DNS` and `NONE`: its route and configured wildcard target materialize, then request dispatch replaces the selected target with the matching concrete request authority before DNS, SNI, and connection-pool selection. Under `resolution: STATIC` with non-empty `endpoints[]`, those declared addresses remain the dial targets; without a usable endpoint the entry fails closed and never resolves either the wildcard or a request authority. Stream-family wildcard entries still require declared `STATIC` endpoints because raw streams provide no HTTP authority to concretize; such a host is skipped on the stream-family branch with a `hosts[]`-named warning and the Istio CRD status reports it in `deferred_fields` (`FerrumAccepted` stays `True` — the resource is translated, just inert for that host). A refused stream entry returns **before** claiming its listen port, so a following exact-host ServiceEntry on the same port can materialize. The datagram (`protocol: UDP`/`DTLS`) branch is stricter and refuses **every** wildcard host, including the `STATIC`-with-endpoints case, because UDP destinations use exact CONNECT `:authority` admission.
- DNS-resolution entries use ServiceEntry hosts as backend targets; static-resolution entries use endpoint addresses. Stream-family proxies pin to the first host (DNS) or all endpoints (Static) — a raw L4 listener cannot distinguish hosts (no SNI for plain TCP), so multi-host external services should be split into one SE per host.
- HTTP-family materialized proxies use host-only routing (no `listen_path`), `preserve_host_header: true`, and passive health checks. Stream-family proxies use port routing (no `hosts`), `passthrough: false` (the per-port stream listener terminates SVID-mTLS itself — the sidecar mTLS boundary IS this listener, sharing the same `ServerConfig` as the sibling 15090 HTTP-family mTLS-termination listener; this is NOT raw SNI passthrough, that flow lives in the east-west gateway), `frontend_tls: true` by default (or `false` under `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true`), and passive health checks.
- The egress gateway materialization pairs with the `mesh_outbound_registry` plugin (HTTP-family, request-path 4xx/5xx). Together with stream-family outbound enforcement at sidecar capture (connection-level drop / silent UDP datagram drop; see [Egress Scope Operations](#egress-scope-operations)), this enforces `outboundTrafficPolicy: REGISTRY_ONLY` across both transport families.

### ServiceEntry Visibility

`export_to` controls which namespaces can see a ServiceEntry:

| `export_to` value | Visibility |
|---|---|
| (empty) | Native/file config: namespace-local. Kubernetes `ServiceEntry` with omitted/empty `spec.exportTo`: mesh-wide (`*`), matching Istio |
| `"*"` | Mesh-wide |
| `"."` | Same namespace as the entry |
| `"namespace-name"` | Exported to that specific namespace |

### Baggage Stripping

`FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS`: comma-separated W3C `baggage` key prefixes removed from outbound requests at dispatch (default empty). See [configuration.md](configuration.md#mesh-runtime).

## Sidecar Egress Scoping

Istio `Sidecar` resources narrow which mesh service configuration a workload receives for egress. Ferrum translates the egress portion of a `Sidecar` into a `MeshSidecar` record and applies it at slice build time. The `Sidecar.ingress[]` block (custom inbound listeners) is also modeled — see [Sidecar Ingress Listeners](#sidecar-ingress-listeners) below.

### Behavior

When `FERRUM_MESH_SIDECAR_ENFORCED=true`, the `MeshSlice` projection narrows `services`, `service_entries`, `destination_rules`, and the projected VirtualService L4 (TCP/TLS) route proxies to the set admitted by the workload's applicable `Sidecar`. An L4 route is kept only when its backend host **and** its backend port are both admitted by the `Sidecar`'s egress scope. When `false` (the default), `Sidecar` resources are still parsed and persisted in `MeshConfig` for future use, but slice narrowing is skipped.

When `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN=true`, Ferrum computes and reports the same admitted/denied egress scope but keeps the slice unchanged. This lets operators verify would-deny behavior before enabling enforcement.

### Resolution Precedence

Most specific wins:

1. **Workload-scoped** Sidecar (`spec.workloadSelector.matchLabels` matches the workload's labels)
2. **Root-namespace workload-scoped** Sidecar (native/file `MeshSidecar` in the root namespace with a `workload_selector`: an omitted `workload_selector.namespace` matches across namespaces, an explicit one restricts matching to that namespace; Kubernetes `Sidecar` selectors stay scoped to their own resource namespace)
3. **Namespace-default** Sidecar (no `workloadSelector`)
4. **Root-namespace default** Sidecar (no `workloadSelector`, in `FERRUM_K8S_ISTIO_ROOT_NAMESPACE`, default `istio-system`)
5. **No Sidecar applies** → no narrowing

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

The `host` portion may itself be a single-label DNS wildcard (e.g. `*/*.example.com` admits `api.example.com` but not `example.com` nor `a.b.example.com`). This follows Istio Sidecar and Ferrum mesh DNS proxy semantics; proxy listener host matching uses broader DNS suffix wildcard semantics for Gateway API conformance. `MeshService` entries match their short name, `{name}.{namespace}`, `{name}.{namespace}.svc`, and `{name}.{namespace}.svc.{cluster_domain}` aliases. On the control plane this suffix follows `FERRUM_K8S_CLUSTER_DOMAIN`; in local mesh mode it follows `FERRUM_MESH_CLUSTER_DOMAIN`.

When Kubernetes `spec.egress` is omitted, Istio inherits the namespace-default outbound scope; Ferrum preserves that distinction so an ingress-only workload Sidecar does not override a namespace default. If no namespace default exists, Ferrum falls back to the root-namespace default Sidecar when one is present; otherwise omitted egress is treated as no narrowing. If a namespace-default Sidecar exists — even one with omitted egress — Ferrum does **not** fall through to the root-namespace default. This is an intentional divergence from upstream Istio for partial CP snapshots: the namespace-level object is treated as authoritative for that namespace, and an inheriting namespace default leaves the slice unnarrowed rather than guessing which root defaults the CP omitted. An explicit native/file `egress: []` or `~/*` trims all service config from the slice. When an admitted egress host also sets `spec.egress[].port.number`, Ferrum narrows matching `MeshService` and `ServiceEntry` port lists to the union of admitted ports; `DestinationRule` resources remain host-scoped because they do not carry a resource port list in the slice.

When multiple `Sidecar` resources apply at the same scope tier (two namespace-defaults, two root-namespace defaults, or two workload-scoped Sidecars both matching the same workload), the resolver picks the ASCII-smallest `name` as the deterministic tiebreak so reconciles are stable across pods and restarts.

### Workload Identity Narrowing

`FERRUM_MESH_SIDECAR_IDENTITY_NARROWING=true` adds a second, default-off narrowing pass after Sidecar egress scope has admitted services. The slice builder collects `MeshService.workloads[].spiffe_id` references from the admitted services and filters `workloads` to that reachable identity set. The flag only takes effect when `FERRUM_MESH_SIDECAR_ENFORCED=true`; with either flag disabled, workload identity lists stay namespace-wide.

The local workload identity is still preserved separately on `MeshSlice::workload_spiffe_id`. It is often not listed under any admitted service's `workloads[]`, so it can be absent from the narrowed `slice.workloads` output; operators should treat `workload_spiffe_id` as the canonical local identity field.

Before enabling identity narrowing, confirm admitted `MeshService.workloads[]` lists are populated in a few representative slices. Empty workload refs on admitted services cause the second pass to remove every workload identity from `slice.workloads`; this usually indicates EndpointSlice reconciliation lag in Kubernetes-derived config or a file-mode service typo.

Inbound mTLS peer validation continues to use the trust bundle carried in the slice, not the `workloads` list. HBONE `source.principal` baggage continues to be accepted or rejected by peer-cert trust-domain matching plus `FERRUM_MESH_TRUST_DOMAIN_ALIASES`, not by checking whether the source identity appears in the narrowed workload list.

### Migration Notes

`FERRUM_MESH_SIDECAR_ENFORCED` defaults to `false`. To roll out enforcement:

1. Apply `Sidecar` CRDs and verify the translator parses them without errors.
2. Set `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN=true` and inspect `GET /mesh/egress-scope` on a data plane to confirm the expected narrowing would apply without denying traffic.
3. Use `POST /mesh/egress-scope/test` to dry-run important destinations by host and port.
4. Set `FERRUM_MESH_SIDECAR_ENFORCED=true` on the CP and roll. DPs receive the already-narrowed slice - no DP-side configuration is required.
5. After egress narrowing is trusted, set `FERRUM_MESH_SIDECAR_IDENTITY_NARROWING=true` and roll the CP again to trim `slice.workloads` to reachable service identities.

### Egress Scope Operations

`GET /mesh/egress-scope` is a JWT-authenticated admin endpoint that returns the current workload's resolved egress scope: admitted services, admitted service-entries, known outbound registry destinations, dry-run status, and admitted/denied service counts. It returns 404 when no mesh slice has been installed yet rather than fabricating counts from raw config.

`POST /mesh/egress-scope/test` accepts JSON like `{"host":"ratings.default.svc.cluster.local","port":9080}` and returns whether the destination is currently admitted by the resolved scope. The endpoint is a dry-run check only; it never mutates slice state. It also returns 404 when no mesh slice has been installed.

When dry-run mode computes denied services, the data plane emits one transition warning when would-denies become active and one recovery info line when the next installed slice has no would-denies. It does not log per request. The `/health` response includes `mesh.egress_scope.sidecar_admitted_services` and `mesh.egress_scope.sidecar_denied_services` for readiness dashboards.

The `mesh_outbound_registry` plugin exposes `ferrum_mesh_outbound_registry_decisions_total` with `mesh_namespace`, `host`, and `decision` labels. To keep label cardinality bounded, every `host` value is one of three fixed buckets: `host="<admit_explicit>"` for admits matched by an exact registry entry, `host="<admit_wildcard>"` for admits matched by a wildcard entry, and `host="<denied>"` for every deny (the request Host header is attacker-controlled on that path). An applicable exact entry takes precedence for metrics when both kinds match; a bare-host entry cannot classify an explicit-port request as an exact admit. Operators can compare admit-vs-deny rates per namespace during rollout, but not per destination hostname. For attribution, every HTTP-lane denial (plugin hook or outbound-capture route miss) also logs a structured `warn` line, `Mesh REGISTRY_ONLY: rejecting HTTP egress to unadmitted destination`, with the denied `host` (echoed only when authority-shaped — hostname characters or a bracketed IPv6 literal, truncated to 256 bytes — and otherwise withheld as `<redacted scalar>`), `port`, `listen_port`, `client`, and `source` (`plugin` or `route_miss`). The line is rate-limited process-wide: the first denial logs immediately, then at most one line per second carrying `suppressed_since_last`. Under effective `REGISTRY_ONLY`, outbound-capture HTTP route misses take the same configured reject status and deny-bucket metric as plugin-path denials.

The plugin's `config.namespace` supplies the `mesh_namespace` metric label and defaults to `ferrum`. Mesh injection explicitly sets it to the runtime namespace; direct instances do not inherit the enclosing `PluginConfig` resource namespace. Direct instances accept listener ports in 1–65535, with `outbound_listen_ports: []` applying wherever the plugin runs. An empty effective registry rejects every destination on those listeners, including when all entries are empty or whitespace-only.

Registry entries are host authorities, with optional decimal ports in 1–65535 or `:*`, and optional leading `*.` wildcards on hostnames. Wildcards match exactly one DNS label below the suffix by default (`wildcard_match: one_label`), the same contract as Sidecar egress scoping, the mesh DNS proxy, and the stream lane; mesh auto-injection always uses it. Operator-managed instances can set `wildcard_match: dns_suffix` for Envoy/Istio-style any-depth suffix matching (`*.example.com` admits `a.b.example.com`; the base domain never matches). Suffix probing is bounded: an authority over 253 bytes or with an empty label never matches a wildcard, and at most as many suffixes are probed as the deepest configured wildcard has labels. Request `Host` / `:authority` ports use the same decimal 1–65535 grammar, so `:0`, signed, or non-numeric ports are denied rather than parsed; the shared lookup also refuses port `0` from callers that split the authority themselves (the outbound-capture route-miss gate and the stream lane). Hostname labels use ASCII letters, digits, and interior hyphens; internationalized names must be supplied in punycode. Surrounding whitespace, hostname case, trailing hostname dots, and IPv6 spelling are normalized. IPv4 names, bare or bracketed IPv6, and IPv6 any-port entries are supported; numeric IPv6 ports require brackets. URLs, paths, userinfo, internal whitespace, malformed brackets, misplaced wildcards, and invalid ports fail construction with the zero-based registry entry index. See the [plugin reference](plugins.md#mesh_outbound_registry) for all five configuration fields.

Mesh-derived registries are built by one builder that drops any slice host or name outside the entry grammar (for example ServiceEntry host `*`, `foo.*.example.com`, an underscore name, or port `0`) and logs one `warn` per resource per registry build with the schema path and ordinals (for example `service_entries[2].hosts[0]`), the resource kind, and the fixed grammar reason. The namespace and name appear only when they are DNS-1123 names and are otherwise withheld; the rejected value itself is never logged, so a mistakenly pasted URL with userinfo cannot leak credentials. The dropped destination stays denied while the rest of the registry applies, identically on the HTTP plugin, the stream lane, and the egress-scope diagnostics, so one malformed resource cannot reject the whole data-plane config. Operator-authored registries remain strict. If a mesh-derived registry still fails construction, the shared stream and HTTP route-miss enforcement state retains a deny-all registry on outbound capture listeners and emits a construction warning. It does not remove the `REGISTRY_ONLY` gate.

Stream-family egress (TCP / UDP / TCP+TLS / UDP+DTLS) is enforced at the connect / first-datagram stage rather than via a plugin: when `outbound_traffic_policy: registry_only` is active and the gateway owns at least one mesh outbound capture listener port, stream proxies bound to those ports consult the same slice-derived registry before dialing the backend. Rejection semantics differ from HTTP:

- **TCP / TCP+TLS**: graceful close of the inbound connection before any backend dial happens. No SYN ever leaves the gateway, so backend circuit breakers, pool entries, and DNS caches stay untouched by hostile traffic. `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS` does not apply — TCP has no "HTTP status" concept.
- **UDP / UDP+DTLS**: the first datagram of a would-be new session is silently dropped (UDP has no RST analogue). Existing sessions are unaffected; the check only runs on session creation. DTLS handshakes are not initiated for unadmitted destinations.

Stream decisions are exported via a sibling counter `ferrum_mesh_outbound_registry_stream_decisions_total` with `mesh_namespace`, `protocol`, and `decision` labels (`protocol` ∈ {`tcp`, `tcp_tls`, `udp`, `udp_dtls`}). It is a separate counter so the HTTP counter's label set stays stable for existing dashboards. Stream rejects do not include a per-host label — the protocol label is the only dimension dashboards need, and TCP closes happen before SNI / Host material is structured. Operators triaging denied stream traffic should consult the gateway's structured `warn!` logs (one per reject) which include `backend_host`, `backend_port`, `listen_port`, and the client IP.

Enforcement is keyed on the runtime's mesh outbound capture listener port set. Stream proxies bound to other ports (inbound, admin, HBONE, east-west gateway, egress gateway) flow through unchanged — outbound policy never gates inbound traffic.

Both lanes decide **whether the gate is armed** from the same resolved effective policy, so HTTP-family and stream-family enforcement can never disagree about that. They do not necessarily share the same admitted **registry contents**: on the multicluster path the HTTP-family registry is built from the merged materialization view (poller-discovered remote-cluster workloads and services unioned in), while the stream-family enforcement slot is built from the un-merged slice. A remote-cluster destination learned only through multi-cluster endpoint discovery can therefore be admitted for an HTTP request and refused for a raw stream connect to the same destination — asymmetric, but in the fail-closed direction. Embedding the remote clusters in the slice itself (rather than discovering them via `RemoteCluster.control_plane_url` polling) makes both lanes see the same set.

## Sidecar Outbound Traffic Policy

Istio's `Sidecar` resource carries an `outboundTrafficPolicy` block that **overrides the mesh-wide `MeshConfig.outboundTrafficPolicy`** for exactly the workloads that `Sidecar` selects. Ferrum translates it into `MeshSidecar.outbound_traffic_policy`, resolves the applicable `Sidecar` at slice build, and carries the result on `MeshSlice.sidecar_outbound_traffic_policy`.

```yaml
apiVersion: networking.istio.io/v1
kind: Sidecar
metadata:
  name: payments-strict-egress
  namespace: payments
spec:
  workloadSelector:
    matchLabels:
      app: payments
  outboundTrafficPolicy:
    mode: REGISTRY_ONLY
```

### Precedence

The effective policy for a workload is resolved once per slice apply, most specific first:

1. **Workload-scoped** — the applicable `Sidecar`'s `outboundTrafficPolicy.mode`.
2. **Mesh-wide** — the slice's `outbound_traffic_policy` (`MeshConfig.outboundTrafficPolicy.mode`, or the native/file `mesh.outbound_traffic_policy` field).
3. **Runtime default** — `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY` (default `allow_any`).

Both directions of the override are honored, matching Istio: a `Sidecar` set to `REGISTRY_ONLY` tightens an otherwise-`ALLOW_ANY` mesh, and a `Sidecar` set to `ALLOW_ANY` relaxes the registry gate for its selected workloads only. A `Sidecar` that **omits** `outboundTrafficPolicy` inherits the mesh-wide value; unlike `egress`, there is no inheritance walk to a less-specific `Sidecar`, because Istio resolves exactly one `Sidecar` per workload.

The applicable `Sidecar` is selected with the same tier precedence as [`ingress[]`](#sidecar-ingress-listeners) — workload-scoped → root workload-scoped → namespace-default → root-namespace-default, ASCII-smallest `name` as the tiebreak. Ferrum performs that selection **once** per slice build and shares it with `ingress[]` materialization; the two run under the same gate over the same labels.

#### A root-namespace `workloadSelector` outranks the workload namespace's default (differs from Istio)

This divergence applies to native/file `MeshSidecar` input only; a Kubernetes `Sidecar` with a `workloadSelector` in the root namespace selects only root-namespace workloads. In the `Sidecar`-selection order just above, the **root workload-scoped** tier — a native/file `MeshSidecar` in the Istio root namespace (`FERRUM_K8S_ISTIO_ROOT_NAMESPACE`, default `istio-system`) whose `workload_selector` matches this workload (an omitted `workload_selector.namespace` matches across namespaces; an explicit one restricts matching to that namespace) — is ranked **above** the **namespace-default** tier, a selector-less `Sidecar` in the workload's *own* namespace. Istio orders these the other way: it resolves the workload's own namespace completely before consulting the root namespace at all.

The divergence is deliberate and security-oriented. The root namespace belongs to the mesh operator and a tenant cannot write to it, so ranking the operator's **targeted** rule above a tenant's **catch-all** means a namespace-wide default dropped into a tenant namespace cannot displace a mesh-wide rule aimed at specific workloads. A tenant can still override with an equally specific rule: a `workloadSelector` `Sidecar` in their own namespace still wins the top (workload-scoped) tier.

Because this ordering also decides the workload-scoped `outboundTrafficPolicy`, it controls whether the outbound registry gate is armed — not just egress scoping. Concretely: a native/file root-namespace `MeshSidecar` whose `workload_selector` (namespace omitted) selects `app: payments` with `mode: REGISTRY_ONLY` keeps the gate armed for those pods even if the `payments` namespace also holds a selector-less `Sidecar` with `mode: ALLOW_ANY`.

#### Ambiguous workload labels resolve to the strictest applicable policy

When several workloads share one SPIFFE id with **divergent** label sets and the data plane supplied no explicit `FERRUM_MESH_WORKLOAD_LABELS`, the slice's labels are only the *intersection* of those sets (the slice is marked `labels_ambiguous`). A `workloadSelector` `Sidecar` that really does select one of those workloads can then fail to match that intersection.

Rather than let that silently fall through to a laxer tier, Ferrum resolves the policy against **each** candidate label set and keeps the strictest result, ranked `REGISTRY_ONLY` > *inherit* > `ALLOW_ANY` (*inherit* outranks `ALLOW_ANY` because the mesh-wide tier it defers to may itself be `REGISTRY_ONLY`). The fold includes the intersection-derived answer, so ambiguity can only ever **tighten** the gate, never relax it; the result is order-independent, so precedence stays deterministic. When ambiguity actually changes the outcome, the control plane emits a `warn!` naming both the intersection result and the resolved one. Supplying explicit workload labels — or distinct SPIFFE ids — resolves it exactly.

### What `ALLOW_ANY` does and does not relax

`ALLOW_ANY` turns off **only** the known-destination registry gate: unknown HTTP-family `Host` values and unknown stream destinations are passed through to the normal routing path instead of being rejected. It is not an escape hatch from anything else. Still fully in force under `ALLOW_ANY`:

- **Sidecar `egress` scope narrowing** — a destination outside the workload's egress scope is still absent from the slice, so it does not route.
- **`mesh_authz`** — `AuthorizationPolicy` DENY/ALLOW evaluation is unchanged, on both the HTTP and stream paths.
- **Identity and TLS** — mesh-mTLS/HBONE peer SVID pinning, PeerAuthentication mode, and trust-domain verification are unchanged; a mesh-tagged target that cannot dispatch over its secured transport still fails closed with `502`.
- **The HBONE/mesh-mTLS inbound open-relay guard** — an authenticated CONNECT still relays only to destinations this terminator owns.
- **Topology transport gates** — Ambient still requires HBONE `:15008`, Sidecar still requires mesh-mTLS `:15006`.
- **DNS / raw-IP routing** — the transparent DNS proxy and the strict `(VIP, port)` / `(workload IP, port)` raw-TCP indexes are unchanged; a captured dial that matches a declared-but-unroutable pair is still closed, never guessed.

Correspondingly, `REGISTRY_ONLY` refuses destinations that are absent from the slice-derived registry (services, ServiceEntries including wildcard hosts, and workload addresses — so a raw-IP `Host` escape only succeeds for an address the slice actually declares). Rejection semantics per transport family are identical to the mesh-wide policy — see [Egress Scope Operations](#egress-scope-operations).

### Enforcement gate

The workload-scoped policy is applied **only** under `FERRUM_MESH_SIDECAR_ENFORCED=true` **and not** under `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN=true` — the same effective gate as `ingress[]` materialization, and deliberately *not* the looser egress-narrowing gate. Dry-run means "report the scope that would apply, change nothing", and arming or disarming the registry gate is a live behavior change. When the gate is off, the mesh-wide policy remains in force; the workload-scoped value is never applied at reduced strength.

### Supported and fail-closed variants

| `spec.outboundTrafficPolicy` | Result |
|---|---|
| Omitted | Inherit the mesh-wide policy. Nothing is deferred. |
| `mode: ALLOW_ANY` | `ALLOW_ANY` for the selected workloads. |
| `mode: REGISTRY_ONLY` | `REGISTRY_ONLY` for the selected workloads. |
| Present object, `mode` omitted or null | **`ALLOW_ANY`** — Istio's documented Sidecar API default. This is an explicit workload-scoped value, not inheritance from the mesh-wide tier, and nothing is deferred. |
| `mode` unrecognized or not a string (`ALOW_ANY`, a whitespace-padded token, the numeric proto form, …) | **`REGISTRY_ONLY` (fail closed)** — the intent is ambiguous. The raw value is never echoed into the status. |
| Block is not an object — including an explicit `outboundTrafficPolicy: null` | **`REGISTRY_ONLY` (fail closed)** — malformed shape. An explicit top-level `null` is *not* normalized to "omitted": the top level is what decides whether a workload-scoped policy exists at all, and an operator who wrote the key asked for one, so the ambiguity fails closed instead of inheriting a possibly-laxer mesh-wide value. |
| `egressProxy` set to a non-null value | **`REGISTRY_ONLY` (fail closed)**, regardless of the declared `mode`. Ferrum cannot funnel unmatched egress through a named `Destination`; ignoring the field would send traffic the operator scoped to an egress gateway straight out instead. |
| `egressProxy: null` | Treated as **absent** (proto-JSON for "unset"), so the declared mode is honored; if the mode is also omitted/null, the documented `ALLOW_ANY` default applies. |

The resource is **never rejected** over this field. A rejected `Sidecar` is dropped from the translation entirely, which would also drop its `egress` narrowing and thereby *widen* both the workload's service view and the registry derived from it — the opposite of failing closed. On the native/file source the field is a closed enum (`allow_any` / `registry_only`), so an invalid value fails deserialization and the whole document is rejected, keeping the last good config.

### Status

The `Sidecar` `status.ferrum.translation` block reports:

- `outbound_traffic_policy` — the classified workload-scoped outcome: `ALLOW_ANY`, `REGISTRY_ONLY`, or `Inherit`. `Inherit` means the effective mode still comes from the mesh-wide/runtime tier; a fail-closed degradation reads `REGISTRY_ONLY`.
- `outbound_traffic_policy_enforced` — **resource-local eligibility**, deliberately narrow: `true` means only that this `Sidecar` carries a translatable workload-scoped policy *and* the enforcement gate above is on. It does **not** mean this `Sidecar` was selected for any workload — selection is per-workload and happens later, at slice build, against that workload's own namespace and labels. A `Sidecar` whose `workloadSelector` matches nothing still reports `true`. Use it to tell a translated-but-inert policy from an eligible one, not as proof that a given pod is gated. A **rejected** `Sidecar` reports `false` explicitly (a dropped resource enforces nothing).
- `deferred_fields` — the field-specific reason for any fail-closed degradation.

The translator and the status writer share one classification predicate, so a degradation can never be enforced without being reported (or reported without being enforced). Because the status is rewritten on every reconcile it is the always-current surface; logging is deliberately quieter, since a permanently unrepresentable `Sidecar` is re-translated on every reconcile and full sync. Each degradation emits a `debug!` carrying the namespace, name, and reason (never the operator-supplied raw value), plus exactly **one** `warn!` per process pointing at this status block.

### xDS / file / native parity

The resolved value rides its own ECDS carrier (`SidecarOutboundTrafficPolicyCarrier`), separate from the mesh-wide `OutboundTrafficPolicyCarrier` because the two are distinct precedence tiers. Absence of the carrier is the wire form of "inherit", so deleting the `Sidecar` (or flipping the enforcement gate off) simply stops emitting the resource and the DP falls back to the mesh-wide value. `MeshSlice::content_eq` compares the field, so an edit that changes *only* the mode is never suppressed by MeshSubscribe/update dedupe. On the native and `FERRUM_MESH_CONFIG_PROTOCOL=file` sources the same `MeshSlice::from_gateway_config` builder resolves it, so an xDS-built slice stays functionally equivalent to a native-built one.

## Sidecar Ingress Listeners

Istio's `Sidecar` resource has an `ingress[]` block letting a workload declare custom inbound listeners: each entry has a `port` (number + protocol + name), an optional `bind` address, and a `defaultEndpoint` (where inbound traffic to that listener is forwarded). Ferrum models these on the **inbound** side, reusing the per-port inbound loopback sibling machinery (the same path that serves the default `:15006` service-port routes).

`Sidecar` resources are always parsed/persisted; ingress materialization is **applied only under `FERRUM_MESH_SIDECAR_ENFORCED=true`** (the same gate as egress narrowing) and **not** under `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN=true` (dry-run reports egress scope but changes nothing — materializing inbound listeners is a behavior change). The applicable `Sidecar` is resolved with the same tier precedence as egress (workload-scoped → root workload-scoped → namespace-default → root-namespace-default, ASCII-smallest `name` tiebreak), but ingress is always taken from the selected `Sidecar`'s own `ingress[]` (it does not follow the egress `inherits_defaults` chain — an **omitted** `ingress` keeps the default inbound listeners, whereas a **declared** `ingress` — even an explicit empty `ingress: []` — replaces them; see [Precedence vs. the default inbound listeners](#precedence-vs-the-default-inbound-listeners-fail-closed)).

### Materialization model

Each modeled ingress entry becomes one inbound forward path on the shared
`:15006` capture listener:

- **HTTP-family** (`http`/`http2`/`grpc`/`https`) — one host-routed loopback
  route (same sibling machinery as the default service-port inbound routes).
- **Stream-family** (`tcp`/`tls`/database protocols; issue #3260) — one
  raw-TCP inbound relay in `local_inbound_tcp_routes`, keyed by the declared
  listener port and forwarding to `defaultEndpoint`. PeerAuthentication and
  AuthorizationPolicy still apply on the capture listener / L4 stream chain;
  authz uses the declared listener port (not the backend port).

Shared fields for both lanes:

- **hosts** (HTTP only) — the union of the local workload's own service FQDN variants (`{name}`, `{name}.{ns}`, `{name}.{ns}.svc`, `{name}.{ns}.svc.{cluster_domain}`). Istio only configures ingress "if and only if the workload is associated with a service"; when no local service resolves (e.g. EndpointSlice lag), the listener is dropped fail-closed (no host-less catch-all route).
- **backend** — the entry's `defaultEndpoint`, resolved to a loopback `host:port` (see supported forms below).
- **listen path** (HTTP only) — `/` (the route is selected by host, then disambiguated by port).
- **port disambiguation** — on Ferrum's shared `:15006` inbound listener, the captured original destination (the port the client dialed) **and** (HTTP) a peer sidecar's request authority are matched against the **declared listener port** (not the `defaultEndpoint` port, which is the separate forward target). HTTP reuses `select_mesh_inbound_port_route`; stream reuses the `mesh_tcp_inbound` orig-dst table. A request that addresses no declared listener port fails closed rather than being routed to an arbitrary backend.
- **authorization port** — `mesh_authz` authorizes an ingress listener on its **declared listener port** (e.g. `8443`), not the `defaultEndpoint` backend port (e.g. `8080`). An `AuthorizationPolicy` `to.operation.ports` / `when: destination.port` rule scoped to the listener port therefore matches; authorizing on the backend port would let an ALLOW miss and — worse — a port-scoped **DENY fail open**. (Service-port default inbound routes keep authorizing on the container/backend port, matching Istio inbound authz.)

### Two inbound arrival shapes (both remap to `defaultEndpoint`)

A stream ingress listener is reachable two ways, and both must forward to the
declared `defaultEndpoint` — not to the listener port:

1. **Direct plaintext capture.** iptables REDIRECT steers the connection into
   the `:15006` capture listener; `SO_ORIGINAL_DST` recovers the **declared
   listener port**, which selects the `local_inbound_tcp_routes` entry and
   relays to `defaultEndpoint`. Stream `mesh_authz` authorizes on the recovered
   original-destination port (the listener port).
2. **Identity-protected mesh-mTLS CONNECT.** A peer sidecar's raw-TCP egress
   opens a **fresh SVID-mTLS HTTP/2 CONNECT** to `:15006` whose `:authority` is
   the destination `pod-ip:<declared listener port>`. This never touches the
   REDIRECT capture table, so it is resolved at the CONNECT boundary instead
   (`build_inbound_hbone_relay_proxy` →
   `MeshConfig::resolve_sidecar_ingress_connect_relay`): the authority is
   remapped onto the listener's validated loopback `defaultEndpoint`
   (`pod-ip:16379` → `127.0.0.1:6379`), and the **declared listener port** is
   stamped onto the request so `mesh_authz` authorizes on it exactly as in the
   HTTP ingress case. PeerAuthentication resolves on the `defaultEndpoint` app
   port on both shapes (direct capture translates the listener port through the
   pre-handshake alias table; the CONNECT remap arrives with that port already).

The CONNECT remap is deliberately narrow and fails closed before any dial:

- Only for a **byte-stream** CONNECT. A datagram-over-CONNECT (`connect-udp`)
  is excluded — `ingress[]` stream listeners are TCP, and UDP is never
  remapped.
- The `:authority` host must belong to the unambiguously resolved local-service
  workload set **and equal the accepted connection's concrete local IP**. The
  second check is what distinguishes this pod from sibling replicas that share
  the same service identity. A sibling replica's IP, a bare loopback authority,
  or a service FQDN sharing the port number is refused; an unavailable accepted
  local address also fails closed.
- Exactly **one** valid, owner-stamped, **stream-family** listener must be
  declared on that port. Ambiguity (two entries on one port), a missing owner
  stamp, an off-box/`:0`/unmodeled-protocol endpoint, and an HTTP-family
  listener are all refused rather than dialed.
- A declared port that fails any of the above returns a route miss — it never
  falls back to dialing the listener port the operator replaced.
- After the plugin chain, the **effective** destination is re-checked against
  the same declared mapping, so a `mesh_route_dispatch` route override or an
  upstream selection cannot widen it (and a listener withdrawn between
  synthesis and dial fails closed).
- Once an `ingress` block is declared, it replaces the workload's ordinary
  inbound CONNECT surface as well as its materialized service-port routes.
  Unlisted ports and explicit-empty, all-unsupported, or carrier-rejected
  listener sets are refused rather than falling through to the transparent
  relay. With no declared `ingress` block, the ordinary relay applies.
- The remap is **`Sidecar`-topology only**, matching the inbound materializer it
  gates. `FERRUM_MESH_SIDECAR_ENFORCED` is topology-independent, so an
  Ambient/Waypoint proxy in a mesh that also runs sidecars can receive a slice
  whose applicable `Sidecar` declares `ingress[]`. Those topologies materialize
  no inbound routes at all and serve every authenticated inbound through the
  transparent relay, so the declaration marker is not back-projected there and
  their transparent relay applies as usual.

#### Live datapath coverage

Two `#[ignore]`d functional tests in `tests/functional/functional_mesh_mode_test.rs`
drive the shipped `ferrum-edge` binary over this lane (data-plane-runtime CI shard):

- `functional_mesh_sidecar_ingress_stream_connect_relays_declared_listener_port`
  — a Sidecar consuming a slice with one already-resolved stream
  `local_ingress_listeners` entry. A real SVID-mTLS bare HTTP/2 CONNECT naming
  `127.0.0.1:<declared listener port>` is relayed to the listener's
  `defaultEndpoint`, proven by that backend's reply tag rather than the decoy
  bound on the declared port itself. A CONNECT naming a declared workload port
  the `ingress[]` block omits is refused, even though a live backend is
  listening there and the ordinary open-relay guard would have admitted it.
- `functional_mesh_sidecar_ingress_stream_reload_withdraws_declared_listener`
  — the same datapath under `FERRUM_MESH_CONFIG_PROTOCOL=file` with
  `FERRUM_MESH_SIDECAR_ENFORCED=true`, so the data plane runs the real
  `Sidecar.ingress[]` resolution and SIGHUP is a deterministic in-test config
  refresh. An `AuthorizationPolicy` DENY scoped to the **declared listener
  port** rejects the CONNECT with 403 (authorizing on the `defaultEndpoint`
  backend port would let it fail open), and a reload that declares a different
  listener fails the withdrawn port closed while the new one serves.

### Precedence vs. the default inbound listeners (fail-closed)

Per Istio, when `ingress` is **declared** it **replaces** the workload's default per-service-port inbound listeners. Ferrum mirrors this and **fails closed on the declared signal, not on what resolved**: if the applicable `Sidecar` declares an `ingress` block, the inbound materializer emits routes **only** from the resolved `ingress[]` listeners and skips the service-port default `:15006` → `127.0.0.1:targetPort` materialization for that workload — **even if every entry was unsupported and nothing resolved**. An all-unsupported `ingress[]` therefore yields **no inbound routes** for the workload rather than silently exposing the default service-port routes the operator explicitly replaced (exposing them would be a fail-open regression).

**Omitted vs. explicit-empty `ingress` (Istio-faithful):** an **omitted** `ingress` block keeps the automatic per-service-port inbound defaults, while a **declared** `ingress` — *including an explicit empty `ingress: []`* — configures the workload's inbound listeners explicitly and replaces those defaults. So `ingress: []` suppresses the default inbound routes (the operator declared "no custom inbound listeners"), the same as a non-empty-but-all-unsupported list; it does **not** fall back to the service-port defaults. The K8s translator records `ingress` presence (mirroring `egress`'s omitted-vs-explicit-empty distinction); on the native source a non-empty list always declares, and an explicit `ingress_declared: true` carries the empty-but-declared case. Only a workload whose applicable `Sidecar` **omits** `ingress` entirely keeps the default service-port inbound behavior. This avoids any silent host+path conflict — the two never coexist for one workload. The "ingress was declared" marker is tracked separately from the resolved-listener list and rides its own ECDS carrier so it survives an empty resolved list on the xDS path.

The resolved listeners that ride the slice are **re-validated before dialing**: a `local_ingress_listeners` entry can arrive already resolved over the xDS/native carrier, so the materializer (and the router's sibling grouping) re-check each carried backend and protocol against the same allowlists `MeshSidecarIngress::resolve` enforces — a modeled HTTP/stream protocol plus loopback host + nonzero port for a TCP backend, or a modeled HTTP-family protocol plus an admissible absolute socket path for a `unix://` backend. A malformed or hostile carrier pointing a listener at an off-box host, a `:0` backend, an unmodeled protocol, or a traversal-like socket path is dropped fail-closed (never dialed), so the carrier path enforces the same invariant as CP-side resolution. A carrier that sets **both** backend shapes (a `host:port` alongside a socket path) is refused outright, so a TCP fallback can never ride along with a Unix backend.

The carrier's `protocol` field has **no compatibility default**: an omitted `protocol` decodes to `Unknown` and is therefore inert on both lanes, exactly like an explicit `udp`/`unknown`. For Unix backends, the carried HTTP protocol must also agree with the h2c marker derived at resolution. A carrier that cannot consistently say what a listener speaks never gets one — it must not silently become a live listener on the declared port.

### Supported and deferred `defaultEndpoint` forms

`defaultEndpoint` is resolved fail-closed; an entry that does not map cleanly onto a loopback `host:port` HTTP route or an admissible Unix-domain stream socket is **not** materialized and is reported in the `Sidecar` `status.ferrum.translation.deferred_fields` (the resource is still accepted):

| `defaultEndpoint` / listener | Behavior |
|---|---|
| `127.0.0.1:PORT`, `[::1]:PORT` (loopback) | Modeled; dials that loopback address + port (address family preserved). |
| `0.0.0.0:PORT`, `[::]:PORT` (instance IP) | Modeled; mapped to loopback (`127.0.0.1` / `::1`) — the sidecar app shares the pod network namespace. |
| Recognized HTTP-family `port.protocol` (`http`/`http2`/`grpc`/`grpc-web`/`https`) | Modeled — `https` is a TLS-terminated HTTP-family listener and is materialized. |
| `unix:///absolute/path.sock` | Modeled **only when the path sits under a configured `FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS` entry** (default: none, so refused). Dispatched over a `tokio::net::UnixStream` — HTTP/1.1 or h2c per the declared `port.protocol` (see "Unix-socket backends" below). |
| `unix://` with an inadmissible path (relative, `.`/`..` component, `//`, trailing `/`, NUL / control character, > 103 bytes, surrounding whitespace) | **Deferred** — the `deferred_fields` entry names the exact rule that was broken; the operator-supplied path is never echoed back. A path that is *syntactically* fine but outside the data plane's containment roots is refused at materialization instead (the control plane cannot see the data plane's allowlist). |
| Arbitrary off-box IP (`10.0.0.5:PORT`) | **Deferred** — Istio forbids arbitrary IPs; Ferrum's loopback-only model will not dial off-box. |
| Non-HTTP-family `port.protocol` (`tcp`/`tls`/`mongo`/…) with a supported loopback `defaultEndpoint` | **Modeled** (issue #3260) — materializes a raw-TCP inbound relay keyed by the declared listener port, forwarding to `defaultEndpoint`. Authz uses the listener port. |
| Missing `port.protocol` (K8s) | **Modeled as TCP** — Istio defaults an unset port protocol to TCP; Ferrum stream-models it the same way (never guesses HTTP). |
| Unrecognized `port.protocol` (e.g. a `HTPS` typo) | **Deferred** — never guessed as HTTP or as a live TCP listener. (On the native source a mistyped `protocol` fails deserialization outright.) |
| `Udp` `port.protocol` | **Deferred** — not a REDIRECT-captured TCP stream lane. |
| Omitted / empty `defaultEndpoint` | **Deferred** — Istio allows omitting it (the native model also accepts an omitted field, defaulting to empty); with no forward target there is nothing to route. |

The status writer reports the count of modeled listeners as `status.ferrum.translation.ingress_modeled` and lists deferral reasons in `deferred_fields`. The HTTP-family classification is shared by translation/resolution and the status writer (one predicate), so a modeled listener is never falsely reported as a deferred non-HTTP listener (and vice-versa). A listener `port` of `0` is a hard validation error (rejected), not a deferral.

### Unix-socket backends

A `unix://` `defaultEndpoint` names a Unix-domain **stream** socket the co-located application listens on. Ferrum dispatches matching requests over a `tokio::net::UnixStream` instead of TCP; HTTP/1.1 carriers are pooled and one h2c carrier multiplexes concurrent RPCs, while a WebSocket upgrade takes a dedicated connection. The materialized target's loopback `host:port` placeholder is never resolved or dialed (and not evaluated by `FERRUM_BACKEND_ALLOW_IPS`); the gates below are the authoritative egress policy for this transport.

#### Containment is mandatory and off by default

An unconstrained path is a **local privilege boundary** (`unix:///var/run/docker.sock` would hand request-path clients the container runtime's API), so the feature is gated on an explicit allowlist with **no default**:

| Setting | Default | Meaning |
|---|---|---|
| `FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS` | *empty* | Absolute directories a socket may live under. **Empty refuses every `unix://` endpoint.** No built-in `/run` or `/var/run` allowance. |
| `FERRUM_MESH_UNIX_SOCKET_ALLOWED_UIDS` | *empty* | Admitted owner uids. Empty admits **only** the Ferrum process's own effective uid. |

A root must be absolute, normalized, and not bare `/`; a malformed entry **fails startup**. Containment is a whole-component, strict-descendant match (`/var/runner/app.sock` is not inside `/var/run`). Both allowlists are process environment and change only with a restart.

#### Admission

Translation (CP-side) checks syntax only: the path must be absolute, free of `.`, `..`, and empty components, not end in `/`, contain no NUL/control characters or surrounding whitespace, and be at most **103 bytes**; abstract and `@`-prefixed sockets are refused. Nothing is normalized. Containment is a data-plane policy applied at materialization, so a listener the `Sidecar` status reports as modeled can still be refused by the data plane (logged; the listener never materializes).

At dial time Ferrum re-runs the whole gate and dials the **checked identity**, not the configured path:

- the path is canonicalized (symlinks, `..`, mounts resolved) and the resolved path must be syntactically valid and inside an allowed root;
- the resolved object must be a socket, owned by an admitted uid, and not group- or world-writable;
- every directory from the socket's parent up to the matched root must be a real directory owned by a trusted uid (root, Ferrum's uid, or an admitted uid) and not group/world-writable unless sticky (sticky is accepted only together with those ownership rules);
- after `connect(2)` and **before any request byte**, the connected peer's kernel-attested uid must equal the checked socket owner exactly, and the path must still name the same `(dev, ino)`, type, and owner.

The peer-credential check is enforced on Linux/Android, Apple/FreeBSD/DragonFly, NetBSD, OpenBSD, and illumos/Solaris; any other target **refuses Unix backends outright**, and an unavailable credential is a refusal. There is never a fallback to TCP or to the placeholder `host:port`. Every refusal is a pre-wire `502` classified `DispatchPolicyRejected` (health-neutral, not retried) whose body never echoes the path; a genuine dial failure (missing socket, `ECONNREFUSED`) stays an ordinary backend-down signal.

#### Protocol matrix

The wire protocol is resolved once at translation and carried on the reserved `mesh.unix_socket_h2c` tag (`"true"`/`"false"`); a missing or malformed marker is refused rather than downgraded.

| Declared `port.protocol` | Socket wire protocol | Status |
|---|---|---|
| `http` | HTTP/1.1 | Supported. Streaming bodies, size ceilings, and timeouts match the loopback-TCP path. |
| `http2`, `https` | h2c prior-knowledge HTTP/2 | Supported. TLS is not re-originated onto the socket; `:scheme` is `http`. |
| `grpc` | h2c prior-knowledge HTTP/2 | Supported natively: streaming, client deadline and cancellation, `te: trailers`, terminal `grpc-status`/`grpc-message` trailers. |
| gRPC request to an `http`-declared socket | — | **Refused** with gRPC `UNAVAILABLE` (14); declare the listener `GRPC` or `HTTP2`. |
| WebSocket upgrade to an `http`-declared socket | HTTP/1.1 (RFC 6455) | Supported (issue #3732) over a dedicated admitted carrier; admission and peer checks complete before the first upgrade byte, within the one establishment deadline, and the relay (`101` + `Sec-WebSocket-Accept` validation, limits, idle timeout, accounting) is the TCP path's. |
| WebSocket upgrade to an `http2`/`grpc`-declared socket | — | **Refused** `502` (Extended CONNECT over h2c is not implemented); never downgraded or redirected to the placeholder port. |
| Retry dispatch (reqwest-backed) | — | **Refused** `502` (defensive; materialized ingress proxies configure no retry policy). |
| HTTP/3 frontend | — | **Refused**, WebSocket included. H1 and H2 frontends both serve Unix-backed WebSockets. |
| Non-HTTP-family `port.protocol` (`tcp`/`tls`/…) | — | Deferred before any listener exists. |

The h2c path reuses the mesh-mTLS gRPC dispatch body, so gRPC deadline, never-buffer, and trailer handling are identical. h2c buffers are bounded (1 MiB stream window, 2 MiB connection window, 16 KiB max frame, capped reset-stream table).

**One establishment timeout.** A single absolute deadline from `backend_connect_timeout_ms` (5 s for a materialized ingress listener; `0` means the 5 s default; values beyond the 24-hour ceiling are refused) covers the idle sweep, admission, pool creation-lock wait, `connect(2)`, the protocol handshake — on h2c including the **peer's** initial `SETTINGS` frame — and a WebSocket upgrade. Exceeding it is a `504` (`ConnectionTimeout`); a peer that hangs up before its preface is a `502` (`ConnectionPoolError`, health-affecting, replay-safe).

#### Connection pooling

Admitted connections are pooled (issue #3731), and every **new physical connection** still runs the full admission gate. Connections are keyed by an exact structured identity (namespace, proxy id, upstream id, canonical path, admitted `(dev, ino, owner_uid)`, wire protocol). Before every checkout the path is re-admitted; a replaced socket retires every connection for that path before another request byte is written.

- **h2c / native gRPC** share one multiplexed carrier; concurrent misses coalesce behind a creation lock bounded by the establishment deadline.
- **HTTP/1.1** uses an exclusive lease returned to the idle set only after the **entire** response body has been read (declared lengths within `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES` are buffered in dispatch; larger or streaming bodies carry the lease and release it only on clean end-of-stream). Any other terminal closes the connection. If the connection stops accepting requests while a request waits, the lease is dropped: a reused lease replays once on a fresh connection, a fresh one returns a pre-wire `502`.
- **WebSocket** is never pooled.
- Idle entries are capped by `max_idle_per_host` and expire against `idle_timeout_seconds`.

**Per-target bound.** `FERRUM_MESH_UNIX_INGRESS_MAX_CONNECTIONS` (default `64`; `0` disables) caps concurrently open **physical** connections per admitted target identity (the full structured identity above). It is not a `DestinationRule` `maxConnections` lane — ingress traffic has no dial host or service port to key one on. A slot is taken only when a new physical connection (including a dedicated WebSocket) is constructed and held for that socket's lifetime. Over the bound, the request is refused **before `connect(2)`** with a `503` (`BackendConnectionLimit`, pre-wire, health-neutral, retryable onto another target).

**Keep-alive.** `FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE` (and per-proxy `pool_enable_http_keep_alive`) is honored literally for HTTP/1.1: with it off, every request gets a freshly admitted connection and resident idle H1 carriers are retired on publication. h2c is unaffected.

**Metrics.** Physical connects, hits, misses, identity retirements, setup failures, checkout refusals, and gauges for idle H1 carriers, shared h2c carriers, and open physical connections appear under `connections.unix_backend_pool` on `GET /metrics/runtime` (JWT), with fixed cardinality.

**Reload and shutdown.** The pool survives config reloads. Every successful publication retires pooled carriers whose identity the new config no longer declares (withdrawn targets, re-pointed paths, protocol flips, H1 reuse disabled), and an exchange outstanding across a publication is retired rather than re-pooled. Edited, replaced, or deleted listeners take effect on the next slice apply with no restart. Graceful shutdown drains the pool within the existing bounded shutdown sequence and then refuses every new checkout with a `503` (`DispatchPolicyRejected`). The withdrawal-fence and shutdown-latch mechanics are documented in `src/proxy/unix_backend_pool.rs`.

**Fail-closed transport gate.** The socket path rides the reserved `mesh.unix_socket` tag on the materialized upstream's single target. The `mesh.` tag namespace is stripped from workload label copies and refused on operator-provided targets (admin, API-spec import, restore, file config), so only Ferrum's trusted mesh projection can stamp it. A tagged target is dialed over a Unix stream **or refused** — never downgraded to the placeholder `host:port`.

A manual criterion harness for dial-versus-pool lives at `tests/performance/mesh/benches/unix_backend_pool.rs` (`./run.sh unix_backend_pool`).

### `bind` and `captureMode`

- **`bind` (issue #3266)** — Omitted, empty, or unspecified (`0.0.0.0` / `::`) keeps the shared capture-listener contract: inbound traffic still enters through `:15006` and is disambiguated by captured original destination / authority port. A supported **dedicated** bind (`127.0.0.1` / `::1`) is conflict-checked against Gateway/stream/mesh listener ownership and materialized as a real OS listener on `bind:port` (HTTP via `GatewayListenerManager`, stream via `StreamListenerManager`) while the shared capture path remains for mesh peers. The dedicated HTTP accept loop is stamped as mesh inbound, and its configured/accepted listener port is the authoritative AuthorizationPolicy destination port; it never widens onto an ordinary process-global frontend or falls back to the `defaultEndpoint` port for authorization. Dedicated-bind HTTP routes are exact-listener only: they do **not** participate in single-listener Service remap, so a lone loopback bind cannot steal `:15006` / process-global matches from the port-agnostic capture sibling. Unsupported or unrepresentable values (Unix-domain sockets, hostnames, `ip:port`, non-loopback addresses) fail closed with field-specific `deferred_fields` / resolve diagnostics rather than being accepted as inert metadata. A dedicated bind that collides with an already-owned port, or that pairs with a `unix://` `defaultEndpoint`, fails closed for that **whole** ingress entry: it is removed from the prepared `local_ingress_listeners` set as well as bind-proxy / capture-route materialization, so there is no silent shared-capture or authenticated-CONNECT fallback. `sidecar_ingress_declared` and `declared_ingress_http_ports` stay independent of that admission so all-rejected / empty cases still fail closed without restoring default inbound behavior or incorrectly lowering the operator-declared HTTP port count.
- **`captureMode`** — Ferrum assumes `IPTABLES`/`DEFAULT` capture (the sidecar redirect model). `captureMode: NONE` (the app handles capture itself) is not separately honored; the listener-port disambiguation relies on the captured original destination or the request authority port being present. Dedicated loopback binds still provide direct `bind:port` exposure for local dialers that bypass capture.

### xDS / file / native parity

The resolved listeners ride the slice as `local_ingress_listeners` (computed CP-side, since raw `MeshSidecar` records do not ride the slice — only the resolved view does, mirroring `local_inbound_services`). On xDS they ride a dedicated ECDS carrier (`LocalIngressListenersCarrier`); the fail-closed "ingress was declared" marker rides its own carrier (`SidecarIngressDeclaredCarrier`) so an all-unsupported `ingress[]` still suppresses the default routes on the DP even with an empty listener list. On the native and `FERRUM_MESH_CONFIG_PROTOCOL=file` sources the same `MeshSlice::from_gateway_config` builder resolves them, so an xDS-built slice stays functionally equivalent to a native-built one.

Ingress resolution is **decoupled from egress-scope inheritance**: a Sidecar that declares only `ingress[]` usually omits `spec.egress` (so it inherits the egress default), and when no namespace/root default exists no egress scope applies — but the ingress listeners still resolve, and the local-inbound service view that anchors their host identity is resolved independently of whether an egress scope was applied. An ingress-only workload Sidecar therefore models its listeners correctly instead of falling back to default inbound routing.

## Config Drift Introspection

`GET /mesh/config-drift` is a JWT-authenticated admin endpoint that surfaces a per-DP "where is this DP relative to the CP's last push?" view. Pair it with the `ferrum_mesh_config_last_received_timestamp_seconds` staleness gauge to triage stuck DPs — the metric tells you when the alert tripped; the endpoint tells you what slice content the DP actually applied.

The response always carries a `slice` block. After the first proxy-accepted slice it carries:

- `last_received_at` / `age_seconds` — wall-clock timestamp + seconds since the most recent successful proxy-applied slice. Received-but-rejected updates and reload attempts alone do not advance this field or the fingerprint. `age_seconds` clamps to zero on backwards clock skew so an alert never fires on a future-stamped slice.
- `version` / `namespace` — the slice's own `version` string and `namespace` field, surfaced for self-describing cross-DP diffs.
- `resources` — counts per resource kind (workloads, services, mesh_policies, peer_authentications, service_entries, request_authentications, destination_rules, mesh_telemetry, mesh_proxy_configs, extension_configs, virtual_service_cors_policies, ext_authz_providers) plus optional `workloads_with_node_waypoint` (omitted when zero) counting workloads whose destination `node_waypoint` metadata is present. Always present for the required kind counts; defaults to all zeros before the first slice so the shape is stable for dashboards.
- `fingerprint` — `sha256-<64 hex>` over a deterministic JSON encoding of the last proxy-accepted slice with per-DP identity metadata (`node_id`, `workload_spiffe_id`, `waypoint_name`, `labels`), `version`, and `runtime_overlay` stripped; ordering `revision` is retained. Equal fingerprints require equal retained projections, including revision and array order. A mismatch may reflect revision metadata as well as resources, so it does not alone prove resource-content divergence. The hash strips the overlay because RTDS-driven knobs (fault percentages, log level, transformer gates — see "xDS ADS Compatibility / RTDS") intentionally hot-swap without a new slice version; drift in the overlay surfaces under `runtime_overlay` instead.
- `source_protocol` / `source_cp_url` — configured source from `FERRUM_MESH_CONFIG_PROTOCOL` and the first entry of `FERRUM_DP_CP_GRPC_URLS`. Populated even before the first slice so dashboards can label DPs by source.

The optional `runtime_overlay` block (default included) summarises the live RTDS overlay as `{ key_count, keys, fingerprint }` where `keys` is the sorted list of overlay keys currently in effect and `fingerprint` hashes the typed overlay values. Pass `?include_overlay=false` to omit the block for high-frequency drift polling that only needs the slice fingerprint.

The optional `convergence` block is present only when `FERRUM_MESH_CONFIG_PROTOCOL=xds` and at least one ADS response has arrived; in native mode it is omitted entirely. It surfaces the xDS [resource-warming](#xds-ads-compatibility) state: `per_type_versions` (received `version_info` per subscribed type, keyed by short name — `cds`/`eds`/`lds`/`rds`/`sds`/`ecds`/`rtds`), `missing_required_types` (required types still awaiting an initial response — empty once the first slice can build), `converged` (every required type has responded **at one coherent `version_info`** — no required type missing and no version skew), and `version_skew` (all required types have responded but their `version_info` strings are **not** all identical). `converged` and `version_skew` are mutually exclusive: a skewed required set is a transient *waiting* state, not an applied one — the DP keeps serving the prior slice via `ArcSwap` and does not build a new one until the required versions reconverge. Because the CP force-refreshes every subscribed required type to one snapshot version on any required-mesh-slice change (including a policy/workload-only ECDS update), skew normally clears within a debounce window; a `version_skew` that persists points at a CP advancing required types independently of the ECDS security carriers and is worth investigating as config drift. This detail is exposed only by the JWT-authenticated drift endpoint because the version strings embed config-change timestamps and content digests; the aggregate `ferrum_xds_warming_partial_applies_total` counter is the low-cardinality companion signal on authenticated `/metrics`.

The endpoint returns 404 outside mesh mode and 200 with `last_received_at` elided / zeroed `resources` when mesh mode is active but no slice has been accepted yet — operators rely on the difference between "404 (wrong mode)" and "200 with no `last_received_at` (mesh mode, not converged yet)".

Operator playbook:

- **Spot a stuck DP**: walk every DP in a deployment, compare `slice.last_received_at`. A significantly older timestamp on one DP flags a missing CP→DP stream. A safe upper bound is `slice.age_seconds > 2 * FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS` (default 600 s with the 300 s primary retry); operators expecting steadier CP push cadence should tighten the threshold to a small multiple of their observed push interval.
- **Spot split brain**: walk every DP, compare `slice.fingerprint`. Matching fingerprints require equal retained canonical projections, including ordering `revision` and array order. A mismatch may reflect ordering metadata as well as resource content and is not conclusive proof that resource definitions differ; compare revisions too. An older revision may still be useful staleness evidence. Operators can recompute the fingerprint offline by (1) serialising the slice JSON with `node_id`, `workload_spiffe_id`, `waypoint_name`, `labels`, `version`, and `runtime_overlay` stripped (retain `revision`), (2) recursively sorting object keys (`BTreeMap`-style) while preserving array order, (3) SHA-256 hashing the resulting bytes, and (4) prefixing the lower-case hex digest with `sha256-`.
- **Spot RTDS drift**: compare `runtime_overlay.keys` and `runtime_overlay.fingerprint` across DPs. Missing keys point to subscription or layer merge issues; matching keys with different fingerprints mean a same-key runtime value diverged.
- **Spot a wedged xDS DP**: when `convergence.converged` is `false` with a non-empty `convergence.missing_required_types` on a starting DP, the first slice is blocked waiting on those types — cross-check `ferrum_xds_first_slice_nacks_total` for a malformed required resource (NACK loop) versus a CP that is simply not sending that type (no NACKs, type stays missing).

A CP-side endpoint that reports what slice version the CP last published to each connected DP (so external tooling can diff "what the CP thinks each DP should have" against "what each DP reports here") is available as JWT-authenticated `GET /mesh/slice-drift` on the control plane (issue #3265). That surface tracks per-authenticated-DP **desired**, **sent**, **acknowledged** (accepted at install time), **applied** (accepted by the DP's proxy runtime), and **rejected** version watermarks (with age, the refusing stage, and a closed refusal label). Pair it with this DP-local endpoint: walk `/mesh/slice-drift` on the CP and `/mesh/config-drift` on each DP.

### CP `GET /mesh/slice-drift` contract

- **Mode**: control-plane only (`404` elsewhere). Shared `X-Ferrum-Namespace` validation returns `400` for an invalid header. `200` with an empty `data_planes` list when no local mesh DP has subscribed yet.
- **Identity**: JWT `sub` bound at `MeshSubscribe` time (`node_id` must equal `sub`), bounded to 256 UTF-8 bytes independently of the gRPC header budget. Remote-discovery subscriptions are not tracked. Do not trust caller-supplied display fields as identity.
- **Watermarks**: `desired` / `sent` / `acknowledged` / `applied` each carry `version`, `at`, and `age_seconds` (clamped ≥ 0 and periodically refreshed even while a row is stable). Versions are exact opaque values: non-empty, no surrounding whitespace or control characters, and at most 256 UTF-8 bytes. `desired` advances at publication time, independently of stream polling, only when that DP's projected `MeshSlice` content changes; a backpressured connected DP therefore exposes desired-vs-sent drift, while version-only/no-op reloads and unrelated namespaces do not manufacture drift. Retained disconnected rows keep the same bounded subscription selector and content digest so that projection rule remains accurate while partitioned.
- **Received vs accepted vs applied (issue #4812)**: a data plane reports TWICE for a version it fully converges on. The install-time report (`phase = ACCEPTED`) means the slice passed the subscription-binding, envelope, and config-revision gates and became the DP's RECEIVED slice — it is **not** yet serving. The proxy runtime is a second, independent gate; only when it makes the slice the serving generation does the DP report `phase = APPLIED`, which is what stamps `applied`. Without the second report, a data plane whose runtime refused the slice would still read as `converged` — a false negative on the exact surface built to find stuck data planes.
- **Rejection privacy**: the data plane sends a closed wire enum (`MeshSliceRejectReason`), never free text, so `rejected.reason` is one of `install_refused`, `runtime_config_build`, `runtime_proxy_refused`, `runtime_trust_unusable`, `runtime_tls_reload`, `runtime_dtls_candidate`, and `rejected.stage` is `install` or `runtime`. An unrecognized wire value is refused with `InvalidArgument` rather than recorded. No caller-supplied bytes are ever retained, logged, placed in metrics, or exposed through admin diagnostics.
- **Convergence**: `converged` | `accepted` | `drifted` | `rejecting` | `pending` | `disconnected`, plus boolean `drift.desired_vs_sent` / `desired_vs_acknowledged` / `sent_vs_acknowledged` / `desired_vs_applied`. `converged` requires the desired version to be **applied**; a DP that acknowledged the desired version at install time but has not reported it as serving is `accepted`, and one whose runtime refused it is `rejecting` with the DP identity (`node_id`), `rejected.version`, `rejected.stage = runtime`, and the closed `rejected.reason` on the row.
- **Lifecycle**: each local subscription receives a fresh opaque session token on the wire (never exposed through admin, metrics, or logs). Disconnect retains the row for 300s; registry hard-caps at 4096 identities (evicts oldest disconnected, otherwise declines to track). Retained projection context is capped at 256 labels, 256 scope/claim namespaces per set, and 64 KiB aggregate selector/scope bytes; an oversized subscription is not tracked instead of growing retained state.
- **Never gates the data path**: slice-drift tracking is observability only. If the registry declines a subscription (cardinality cap, oversized retained selector) or a bookkeeping update fails, the DP is served **untracked** — it still receives its full mesh slice and every later update, with an empty `session_token` and no row here. An established stream is never terminated because a drift record failed.
- **Freshness**: a fresh row never retains a `desired` older than the published config. Above 256 tracked identities, per-stream `sent` and ACK/NACK updates coalesce into at most one snapshot rebuild per 500 ms, so published watermarks can lag by at most one maintenance interval on a large idle fleet.
- **Status path**: DPs call `MeshConfigSync.ReportMeshSliceStatus` (local-mesh audience). The report is accepted only while its token names the currently connected replacement session and its version equals the current sent version. `phase` names the gate that produced the verdict (`ACCEPTED` = install, `APPLIED` = proxy runtime) and `reject_reason` is the verdict (`UNSPECIFIED` = success at that phase, anything else a refusal). An `APPLIED` report also stamps `acknowledged`, so a lost install ACK cannot strand a serving DP in `drifted`. The runtime verdict rides a single-slot side channel on the DP: a verdict superseded before the consumer reports it is replaced rather than queued, it never resets the stream first-frame/first-slice/silence clocks, and it is bound to the exact `(version, session_token)` this stream installed, so a verdict for another generation is dropped rather than misattributed. Delayed reports from an old stream—including same-version replacement streams—fail closed. A report that fails to reach the CP is retried (bounded, up to 3 further attempts) piggybacked on later frames of the same subscription — including the 60s heartbeat — so a transient RPC failure on the last publication cannot leave a false `sent_vs_acknowledged` divergence standing. A report the CP explicitly refuses is dropped rather than retried; a report is superseded as soon as a newer one is produced.
- **Metrics**: closed-set `ferrum_mesh_slice_drift_data_planes{state=…}` (six states) and `ferrum_mesh_slice_drift_tracked_data_planes` only — never per-DP / per-version / per-reason labels.

## Authoritative Config Revisions And Stale-Fallback Rejection

Multi-CP failover must never move a data plane *backwards*. A fallback control plane that missed a poll, is partitioned from the config store, or is simply lagging still serves a structurally valid slice — and installing it would reinstate deleted routes, endpoints, authorization policies, or trust material until failback. The slice `version` cannot arbitrate that: it is a rendering of the serving CP's local `GatewayConfig.loaded_at` wall clock, so it is not comparable across replicas, clock skew, or process restarts.

Mesh slices therefore carry an authoritative **config revision** alongside `version`:

```
revision = (authority, sequence)
```

- **`authority`** names the ordering *domain*. Sequences are only comparable within one authority. Every CP replica reading the same source advertises the same value, which is exactly what makes a primary's and a fallback's slices comparable.
- **`sequence`** is a durable, source-minted cursor — never a clock and never a process-local counter.

There are **two ordering domains**, and they are never comparable with each other:

| domain | authority | sequence | published by |
|---|---|---|---|
| change log | `FERRUM_MESH_CONFIG_AUTHORITY_ID` (default `db`) | `config_changes` cursor | a database-backed CP |
| Kubernetes | `k8s`, or `k8s:<FERRUM_MESH_CONFIG_K8S_AUTHORITY_ID>` | `resourceVersion` convergence watermark | a CP running the Kubernetes CRD controller |

A `config_changes` sequence and an etcd revision are unrelated numbers, so the split is enforced structurally rather than by convention: `k8s` (and any `k8s:…`) is a **reserved** authority that a change-log CP is refused at startup, and a change-log cursor can only reach a revision through one seam that declines to touch a Kubernetes-domain one. A data plane needs no new rule — two different authorities are already `incomparable_authority`.

#### Change-log domain (database-backed CP)

The sequence follows CP scope so identical-scope replicas stay convergent across restarts: explicit `CpScope::Single` / `Set` publishes the saturating sum of the durable per-namespace `config_changes` cursors over the configured namespaces, and `CpScope::All` the store-wide sum of each namespace's high-water mark (so a namespace disappearing cannot rewind publication). Cursors are captured **before** the corresponding full loads, so a snapshot is never stamped with a later write's sequence; a namespace whose boundary cannot be read keeps its last-known-good resources and cursor. An in-process floor keeps publication monotonic while the process lives.

A CP running the Kubernetes CRD controller publishes **no** change-log revision: its mesh block is authored entirely by the Kubernetes overlay.

#### Kubernetes domain (CRD-controller CP)

A Kubernetes-controller CP sequences from `resourceVersion`. Each watch scope accumulates the highest revision it is *proven* converged through (a boundary read taken before a watcher generation starts and adopted at `InitDone`, plus every observed watch event — deletions included, so a withdrawal advances the watermark). The published sequence is the **minimum** over all registered scopes, because a reconcile snapshot contains every change only up to that point. If any scope has no evidence yet (initial list in flight, unfinished relist, unparsable `resourceVersion`), the watermark is unavailable and the CP **retains the last published sequence and refuses to advance** — divergent mesh evolved under that sequence is withheld rather than stamped with the old scalar. Before any sequence is established the CP publishes no revision and data planes bootstrap unversioned. A monotonic in-process floor covers a scope set that grows (a CRD installed later).

**Stated assumption.** Kubernetes documents `resourceVersion` as opaque. On every etcd-backed API server it is the shared numeric etcd revision, which is what makes a cross-type minimum meaningful; Ferrum requires each value to parse as an unsigned integer and treats anything else as no evidence, so the CP refuses to advance rather than ordering on values it cannot interpret.

The revision rides `MeshConfigUpdate.config_authority` / `config_sequence` on the native `MeshSubscribe` envelope (validated for agreement with the slice, like `version`) and, on the xDS path, the `ConfigRevisionCarrier` ECDS carrier, so native and xDS slices pass through the same data-plane gate. Native remote-cluster discovery applies the same comparison per remote source before replacing last-good remote endpoints.

### Comparison contract

The data plane records the revision of the slice it accepted and compares every candidate **before** the `ArcSwap` replacement:

| accepted | candidate | outcome |
|---|---|---|
| none | no revision (genuinely absent) | install (bootstrap) |
| none | well-formed revision | install (bootstrap) |
| any | present but ill-formed (blank / surrounding-whitespace / over-long / control-character authority) | **quarantine** (`malformed_revision`) — never silently downgraded to absent |
| some | no revision | **quarantine** (`missing_revision`) |
| same authority | `sequence >` accepted | install |
| same authority | `sequence ==` accepted, **identical content** | install (reconnect replay / republish) |
| same authority | `sequence ==` accepted, **different content** | **quarantine** (`divergent_content`) |
| any | revision present, content identity uncomputable | **quarantine** (`unidentified_content`) |
| same authority | `sequence <` accepted | **quarantine** (`stale_revision`) |
| other authority | any | **quarantine** (`incomparable_authority`) |

Equal sequences must install **for identical content only**: reconnecting to the same CP replays that CP's initial slice at the unchanged revision, and quarantining that would break every ordinary reconnect.

### Content binding at an equal revision

The Kubernetes domain's minimum-over-scopes watermark does not by itself guarantee that one `(authority, sequence)` names one content: a replica at scope watermarks `[110, 100]` and one at `[100, 100]` both publish `100`. Two layers close this:

- **Producer.** At the Kubernetes overlay publication boundary, a reconcile that presents different mesh content at an equal revision keeps the previously accepted mesh and revision (non-mesh Gateway/API fields may still publish); the newest mesh publishes once the sequence advances. A retaining publication requests fresh convergence evidence from every watch scope (spaced by a per-scope 5 s floor) so retention stays brief.
- **Data plane.** The gate binds a deterministic semantic content identity (the canonical slice digest, ignoring `version` and `revision`) to every accepted and applied revision. An equal-revision candidate installs only when its identity matches, so ordinary reconnect replays — even from a different replica — install, while different content is quarantined as `divergent_content` and an uncomputable identity as `unidentified_content`. The identity is compared, never rendered.

A **present but ill-formed** revision is distinct from an absent one and is refused (`malformed_revision`) even on bootstrap and on the xDS path; on the envelope, raw empty `config_authority` (the proto default) is absent, while non-empty whitespace is malformed. Absent revisions remain valid for unsequenced authorities.

A quarantined candidate mutates nothing — the last-good slice keeps serving, receive metrics do not advance, and no watcher is woken. The native stream is **dropped** so multi-CP failover moves off the lagging control plane. On xDS the response was already ACKed into the accumulator, so instead of rewinding, the gate terminates ADS and rotates CPs; the accumulator is cleared on failover, so a quarantined CP's resources never mix into the next CP's slice.

### Received versus applied (candidate lifecycle)

Passing the freshness gate makes a slice the *received* candidate, not the serving one; the proxy runtime is a second gate. Both watermarks are on `GET /mesh/config-drift`:

- **`accepted`** — the highest revision admitted into the received slot; candidate comparison runs against it.
- **`applied`** — the revision the proxy runtime last accepted (the authoritative last-good generation).

Each slot stores its revision together with its bound content identity. When the runtime accepts a candidate, `applied` advances (including equal-revision replays). When it **refuses** one, `accepted` rolls back to `applied`, so a runtime-invalid slice at a far-future sequence cannot block every valid revision beneath it; the rollback is keyed to that exact candidate, so a late rejection of N never disturbs N+1. The startup initial-config wait on native, xDS, and stock-xDS sources is the same kind of gate: a first slice that fails conversion returns the gate to no baseline, so a corrected republish at the same sequence installs. Once a generation has served, an equal-sequence candidate with different content is still `divergent_content` and anything lower is still `stale_revision`. The localized `file` source converts before installing and refuses startup outright.

### Intentional rollback

Rolling configuration back is a **write**: it allocates new change-log sequences, so it reaches data planes as a *higher* revision carrying older content and installs normally. Replaying an old generation to move a data plane backwards is never a supported operation.

### Reset semantics (no permanent lockout)

Two escape hatches, both explicit:

- A **foreign authority** observed continuously for `FERRUM_MESH_CONFIG_REVISION_ADOPT_SECS` (default 300 s, `0` disables) is adopted with a `warn!` and a bump of `ferrum_mesh_config_revision_adoptions_total`. The grace uses a monotonic process clock; NTP or manual wall-clock jumps cannot expire it early. This covers CP state loss and a deliberate source reset without an operator round trip.
- `POST /mesh/config-revision/reset` (JWT + `operator` role) clears the accepted revision so the next slice from any authority is eligible. This is the documented recovery for the one case that is never auto-adopted: a sequence rewind *inside* one authority — a config store restored from backup without bumping `FERRUM_MESH_CONFIG_AUTHORITY_ID`. Auto-adopting that would be indistinguishable from the rollback the gate exists to prevent. The reset installs nothing itself; the next slice still has to pass subscription binding and update validation.

### Observability

- Authenticated `/metrics`: `ferrum_mesh_config_revision_rejections_total{reason}` with `reason` ∈ `stale_revision` / `incomparable_authority` / `missing_revision` / `malformed_revision` / `divergent_content` / `unidentified_content` / `missing_apply_token`, and `ferrum_mesh_config_revision_adoptions_total`. These process counters aggregate the local slice gate and native remote-discovery gates; `missing_apply_token` counts local runtime commit inconsistencies, while the config-drift `rejected_total` and quarantine record describe admission refusals. Fixed cardinality — no CP-supplied authority string or sequence number reaches this surface.
- `GET /mesh/config-drift` (JWT): the `revision` block carries the accepted and applied `(authority, sequence)` watermarks, the most recent quarantine (authority, sequence, reason, consecutive count, first/last seen), the totals, the effective adopt grace, and `quarantine_active` — the "stale fallback quarantined" signal to alert on. Every authority rendered on this surface — and in the reset response and its audit log line — has control characters replaced with `.` and is truncated to 64 characters (suffix `(truncated)`); the raw control-plane string never leaves the gate, where exact ordering comparisons need it. An authority that is blank, has surrounding whitespace, is over-long, or contains control characters is refused as `malformed_revision` at the boundary and never becomes a watermark at all.

### Scope and residuals

- **Unsequenced authorities.** `FERRUM_MESH_CONFIG_PROTOCOL=file` publishes no revision and data planes apply no cross-CP ordering to it. Setting `FERRUM_MESH_CONFIG_AUTHORITY_ID=` deliberately produces the same unsequenced posture on either domain.
- **Kubernetes replica skew.** Replicas publish the same sequence once both observe a change, but can differ while a scope is quiet (each replica's floor comes from its own boundary read, refreshed on the idle relist, `FERRUM_K8S_WATCH_IDLE_RELIST_SECS`). A data plane failing over to a replica that is behind quarantines it (`stale_revision` or `divergent_content`), keeps serving last-good, and rotates on; it recovers within about one relist window or on the next cluster change. A healthy replica is never overstated, because a stalled scope holds the minimum back.
- **Kubernetes ordering-domain reset.** An etcd restore-from-backup can rewind `resourceVersion` and is never auto-adopted: recover with `POST /mesh/config-revision/reset` on the affected data planes or, fleet-wide, set `FERRUM_MESH_CONFIG_K8S_AUTHORITY_ID` to a new value so data planes adopt the new domain through the foreign-authority grace.
- **One source per authority, and matching CP scope.** Distinct config stores (or distinct clusters) must not share an authority id; the gate cannot detect that misconfiguration, though `k8s` is reserved so a database CP cannot claim the Kubernetes domain. The replicas in `FERRUM_DP_CP_GRPC_URLS` must share a `FERRUM_CP_NAMESPACES` scope, because differently scoped replicas serve different content.
- **Remote-cluster discovery.** The remote-endpoint poller keeps a per-cluster revision gate with the same equal-revision content binding (computed over the validated, tagged endpoint set), so a lagging remote replica cannot replace live remote endpoints with an older set; stale, missing, or foreign revisions fail the poll and preserve last-good endpoints. The same `FERRUM_MESH_CONFIG_REVISION_ADOPT_SECS` policy applies.

## DestinationRule

Istio `DestinationRule` resources are translated into Ferrum upstream and proxy configuration at the Kubernetes translation layer. Field-by-field support — `connectTimeout`, TCP `idleTimeout`, `outlierDetection`, every `loadBalancer.simple` algorithm (including `PASSTHROUGH` and the rejected `MAGLEV`), `consistentHash`, subsets, TLS, and the `connectionPool.http` fields — is the support matrix under [MeshDestinationRule](#meshdestinationrule); see [Passive Health Checks](load_balancing.md#passive-health-checks) for outlier-detection runtime behavior.

### Subsets

DestinationRule `subsets` are preserved as named subsets in the Ferrum upstream. Each subset can carry load-balancing, TLS, passive-health, connect-timeout, TCP idle-timeout, and `connectionPool.http.{h2UpgradePolicy,maxRetries,http1MaxPendingRequests,idleTimeout,http2MaxRequests,maxConcurrentStreams}` overrides, resolved per exact `(namespace, upstream id, subset name)` into one immutable policy generation. A proxy bound to one subset never inherits a sibling subset's values, and a proxy with no matching subset receives the top-level policy only; create, update, and removal replace the resolved config atomically. Every HTTP-family pool key includes `upstream_subset`, so sibling subsets never share connections.

`subsets[].trafficPolicy.portLevelSettings` is detected and deferred (translate-time warning + `status.ferrum.translation.deferred_fields`) but not applied — express per-port policy at top-level `trafficPolicy.portLevelSettings` or via subset `connectionPool` fields.

A DestinationRule subset whose labels match no current target is applied with **no admission-time warning** (unlike a phantom `portLevelSettings` port, which warns at apply time). A proxy bound to such a subset fails LB selection at request time (typically 503). Unknown subset *names* referenced by routes are still rejected by reference validation.

### Port-level and subset policy

Top-level and per-subset DestinationRule TLS settings (`trafficPolicy.tls`, `subsets[].trafficPolicy.tls`) are translated onto the matching Ferrum upstream's `backend_tls_*` fields and `resolved_subset_tls` map at slice-apply time. Backend handshake SNI and SAN allow-list verification are enforced on the backend TLS paths; both settings — plus the selected subset name — are included in backend pool keys so distinct TLS identities never share connections.

**Field-level precedence: `portLevelSettings` > selected subset > top-level.** Every applied `connectionPool` field (`connectTimeout`, TCP `idleTimeout`, HTTP `idleTimeout`, `http2MaxRequests`, `maxConcurrentStreams`, `maxConnections`, `tcpKeepalive`, `h2UpgradePolicy`, `maxRetries`, `http1MaxPendingRequests`) and `outlierDetection` merge per field: an omitted field inherits the next tier's value. This deliberately differs from Istio in two ways: Istio applies subset > `portLevelSettings`, and Istio replaces the whole lower-tier `connectionPool` when a subset or port entry sets any field (unset fields fall back to cluster defaults). Example: `portLevelSettings[{port:8080}].connectionPool.http.h2UpgradePolicy: UPGRADE` plus `subsets[v1]...h2UpgradePolicy: DO_NOT_UPGRADE` → Istio forces H1 for subset v1 on 8080; Ferrum negotiates h2. A subset that sets only `maxRetries: 2` also inherits a top-level `DO_NOT_UPGRADE` here. An **explicit** `h2UpgradePolicy: DEFAULT` at a higher tier clears an inherited `UPGRADE` / `DO_NOT_UPGRADE` (probe-driven); an omitted one leaves the inherited value. `maxRequestsPerConnection` is deferred at every scope and not merged.

- **Per-port policy on HTTP-family dispatch.** Port-level `connectTimeout`, `idleTimeout`, `loadBalancer`, and `outlierDetection` are enforced for HTTP/H2/H3/gRPC/WebSocket/HBONE dispatch. The policy port is the declared Service port (`dispatch_policy_port()`), so named/numeric `targetPort` remapping does not change the policy source; mesh service-discovery targets carry the owning Service port for this purpose. The inherited fallback carries the top-level overlay only, so one port's policy never leaks to a sibling port.
- **Per-port policy on stream paths.** TCP, UDP, and DTLS engage per-port `loadBalancer` (algorithm and hash key) and `localityLbSetting` at selection time only when all upstream targets share a single port; stream-lane `consistentHash` requires a source-IP hash key, per-port `LEAST_CONN` is supported on generic stream listeners, and per-port `LEAST_LATENCY` is refused on every stream lane — see [Limitations](#limitations-and-not-supported). The mesh raw-TCP/UDP tunnel dials and the HBONE capability probe honor the per-port `connectTimeout` for the destination's policy port; mesh L4 relays honor per-port `idleTimeout` (`0` disables). Per-port outlier thresholds and caps are honored by stream target selection, but outlier failures are not recorded on stream paths (raw relay sessions carry no response status).
- **`tcpKeepalive`** is enforced for stream-family dispatch and for the socket-owning multiplexed pools (direct-H2, gRPC, HBONE, mesh-mTLS — keyed by the destination's app/service port), with the global pool keepalive as fallback. Keepalive is not in the pool key, so the first dispatcher to materialize a shared connection fixes its keepalive. The reqwest pool and H3/QUIC are documented residuals.
- **Per-attempt resolution.** The per-target effective proxy (per-port HTTP fields, `connectTimeout`, per-port TLS) is re-resolved for the selected target on every attempt — H1/H2, the standalone HTTP/3 frontend (native H3, H3→HTTP bridge, H3→gRPC, H3 WebSocket), and the H1/H2 WebSocket dial loop — so a retry that rotates ports dials under the new port's policy and is checked against the original route retry ceiling. See [WebSocket policy port vs transport dial port](#websocket-policy-port-vs-transport-dial-port). The plain bridge's per-attempt rejects (per-port backend-TLS-SNI incompatibility → 502, `http1MaxPendingRequests` cap → 503) happen before backend admission or health signals.
- **`http1MaxPendingRequests`** is isolated per `(namespace, logical upstream/Service identity, optional Service UID, policy port, subset name)` and reacquired on retry; VIP and direct-pod-IP routes for one Service share a lane, and all three frontends admit into one lane per destination.
- **`idleTimeout`** projects onto `pool_idle_timeout_seconds`; **`http2MaxRequests`** is the destination-wide cross-transport active-request budget; **`maxConcurrentStreams`** is the per-connection HTTP/2 cap on direct-H2/native-gRPC (reqwest H2 has no equivalent knob). Reqwest pool keys carry an `rcfg` client-behavior segment and direct-H2/gRPC keys carry the effective `maxConcurrentStreams`, so divergent values never share a client.
- **Warmup** resolves the per-target effective proxy, so a `DO_NOT_UPGRADE` reached through any tier pre-warms its force-H1 client rather than an h2 client the data path never uses.
- **Reload.** A DestinationRule-only create/update/removal atomically republishes the affected route table and load balancer before mesh status reports the generation programmed (#3243 / #1826).

#### DestinationRule `maxRetries` semantics

Istio/Envoy `connectionPool.http.maxRetries` is a cluster-wide outstanding-retry concurrency budget. Ferrum's retry model is per-request, so it reinterprets the field as an **upper bound on the per-request retry count**:

- With an existing route retry policy (`Proxy.retry`), each attempt's budget is `min(original_route_ceiling, current_target_maxRetries)`; it can only reduce retries and never permanently lowers the route ceiling, so a looser rotated target may use up to the original ceiling.
- Without a retry policy, `maxRetries` alone does **not** enable retries.
- When retry rotation moves to a port whose `maxRetries` is stricter (including zero), that candidate is not dispatched (fail closed). Operators relying on Envoy's outstanding-retry budget should treat Ferrum's value as a per-request ceiling.

#### Retry attempts across required mesh transports

HTTP-family retries are transport-neutral for H1/H2 frontend traffic. Mesh egress targets tagged `mesh.hbone` (Ambient / Waypoint HBONE) or `mesh.mtls` (Sidecar SVID-mTLS HTTP/2) are valid in retry-enabled upstreams, including upstreams that mix plain, HBONE, and sidecar targets. The load balancer first rotates/reselects using the existing health, outlier-ejection, and retry policy. Ferrum then resolves the exact selected target's transport again for that attempt; it does not carry the first target's direct/HBONE/mTLS choice across rotation and never direct-dials a target that requires a secured mesh transport.

Target resolution is a full dispatch boundary. Each attempt reapplies the selected app/service port's `portLevelSettings`, effective timeout and connection limits, TLS identity/SNI/trust-domain verification, SVID generation, CONNECT authority, and transport pool key. This keeps plain, HBONE, same-cluster sidecar, and cross-cluster sidecar/HBONE connections isolated even when one upstream contains all of them. Missing identity, malformed cross-cluster identity/SNI metadata, an explicitly unsupported HBONE capability, authorization/policy denial, or an unavailable secured transport fails closed for that attempt without plaintext fallback. The request keeps one atomic configuration epoch: an update or delete affects newly admitted requests, while all attempts of an already admitted request use its consistent snapshot; rotating SVID/capability state is re-read at the attempt boundary.

Replayability stays conservative. When retry can fire, Ferrum drains the client upload under the request-size limit and deadline before the first backend attempt, runs request-body transforms and final-body hooks exactly once, and retains immutable `Bytes`. Backend admission, adaptive-concurrency reservations, load-balancer/circuit-breaker/passive-health accounting, DNS, pool acquisition, and identity verification remain per attempt. A pre-wire DNS/TCP/TLS/pool/handshake failure may replay for any method because no application bytes were committed. Once headers or body bytes may have reached the backend, replay requires both a configured retryable status/error and a retryable method; streaming bodies are never duplicated, and no retry begins after response bytes are committed to the client. Exhausted or unhealthy alternate candidates fall back to the retry loop's established same-target/exhaustion behavior, still through that target's re-resolved transport. Cancellation and the original absolute gRPC deadline stop backoff or dispatch without starting another attempt.

Native gRPC retains its protocol-specific transport limits: Sidecar mesh-mTLS works when it is the initially selected target, and its retries stay on the generic mesh path. The native-gRPC retry loop re-resolves the transport for every attempt and may rotate freely between direct and Ambient `mesh.hbone` targets — both are hyper HTTP/2 with an identical trailer contract, HBONE simply nesting its connection inside the authenticated CONNECT byte tunnel (issue #3728) — but it still fails closed rather than rotating into a Sidecar mesh-mTLS or Unix-socket target, whose response pipelines it does not own. A fully-streamed (non-replayable) gRPC upload is never retried on any transport. Pass-through gRPC-Web uses the HTTP-family retry planner. WebSocket connection retries already re-resolve the selected target's mesh transport before the upgrade and never retry after the upgraded stream is established.

### WebSocket policy port vs transport dial port

A proxied WebSocket has two ports, and they are deliberately allowed to differ. Both frontends (H1/H2 in `src/proxy/mod.rs`, H3 in `src/http3/websocket.rs`) resolve them identically, per backend attempt:

- **Policy port** — `UpstreamTarget::dispatch_policy_port()`, i.e. `service_port_policy_key` when mesh service discovery recorded a declared Service port that a Kubernetes `targetPort` remapped, otherwise `UpstreamTarget.port`. This is the key for the DestinationRule decisions the upgrade consumes: the `connectionPool.tcp.maxConnections` admission slot and the `resolve_backend_connection_proxy_for_target` projection. A direct dial consumes that projection's `connectTimeout` and `portLevelSettings[].tls` (CA, client cert/key, `verify_server_cert`, SAN allow-list); a mesh tunnel consumes the target-effective timeout while its identity, trust domain, and cross-cluster SNI come from the mesh dial plan rather than application-backend TLS fields. Target selection chooses the policy port; policy always follows the selected Service port, never the workload port and never the transport listener.
- **Transport dial port** — where the socket actually goes. For a direct dial that is `UpstreamTarget.port` (carried in the computed backend URL). For **mesh egress** it is neither: a `mesh.mtls` target dials the peer sidecar's `:15006` inbound listener (`mesh.mtls_port`) and a `mesh.hbone` target dials the peer's `:15008` HBONE listener (`mesh.hbone_port`), reaching the app port *through* the tunnel. Those transport listener ports are addresses, not policy sources — a `portLevelSettings` entry keyed on `15006`/`15008` never configures the upgrade.

So an HBONE WebSocket to a Service port `80` that resolves to workload port `8080` is admitted and configured from port `80`'s DestinationRule, dials `:15008`, and CONNECTs to `:8080`. Because the mesh pools also read socket-level knobs (TCP keepalive) keyed by the dial port, the per-attempt projection additionally mirrors the selected policy port's override onto the dial-port key in its dispatch-local clone, so dial-port-keyed lookups agree with the policy the upgrade was admitted under. The serialized proxy and the shared projected map are unchanged.

The direct WebSocket dial fails **closed** on a resolved backend TLS `sni` override, because `client_async_tls_with_config` derives both the `Host` header and the TLS server name from the request URI and cannot apply a separate SNI. Honoring the URI host would silently verify the wrong server name, so the upgrade is refused pre-dial as a gateway-side dispatch rejection (`502`, non-retryable, neutral to the circuit breaker and passive health) — the same posture the reqwest retry path takes for an unreplayable SNI override. Because the projection is per target, a `portLevelSettings[].tls.sni` on one port refuses only that port's upgrades; sibling ports keep dialing. Mesh egress is unaffected: its SNI is chosen explicitly by the mesh dial plans (`mesh.eastwest_sni` for cross-cluster east-west).

### DestinationRule `http2MaxRequests` enforcement scope

`connectionPool.http.http2MaxRequests` is Istio's **destination-wide active-request budget** — "maximum number of active requests to a destination; applicable to both HTTP1.1 and HTTP2" — and mirrors Envoy's cluster circuit breaker `thresholds[].max_requests`. It is not an HTTP/2 transport setting, and Ferrum deliberately does not implement it as one (issue #3775). A per-connection `SETTINGS` value cannot express it:

- HTTP/1.1 has no streams at all, yet the field explicitly applies to it;
- every physical H2/gRPC connection — and every configured pool shard — is built with its own allowance, so N connections would admit N×cap;
- a peer's SETTINGS frame replaces the local outbound bound, so the operator's ceiling would not be durable;
- an inbound `max_concurrent_streams` also describes streams the backend may open toward Ferrum, which is not an outbound request budget.

Istio's separate `connectionPool.http.maxConcurrentStreams` **is** the per-connection stream control, and it is the only one of the two that programs the hyper H2 builder.

**Where the budget is enforced.** One shared counter map (`src/backend_active_request_limit.rs`) lives on `ProxyState`. The permit is taken during **backend admission**, the single funnel every HTTP-family upstream attempt passes through before dispatch, so all of these consume one budget: reqwest HTTP/1.1, reqwest ALPN-negotiated HTTP/2, direct HTTP/2, native gRPC (unary and streaming), HBONE and Sidecar mesh-mTLS, Unix-socket sidecar ingress, the HTTP/3 frontend's plain, gRPC, and streaming-gRPC bridges, and the WebSocket upgrade paths (an upgraded session is one active request for its lifetime, as it is in Envoy).

**Lane identity.** The counter is keyed by the stable `(namespace, logical destination, DestinationRule policy port, selected subset)` policy identity. The logical destination is the referenced upstream id — the Kubernetes Service / DestinationRule cluster — or the route id for a direct-backend proxy; it is deliberately **not** a resolved host or IP, so every endpoint of one destination shares one budget (connection count, pool sharding, LB rotation, and config reloads cannot multiply it) while two Services that select the same pods keep independent budgets. The policy port is `dispatch_policy_port_for_target`, so a `targetPort` remap does not split a destination's budget and an explicit `portLevelSettings[{port}]` cap is visible to every frontend. `None` (unmatched destination) is a distinct lane from every named subset, and the subset component is length-prefixed so a hostile subset name cannot forge a sibling's lane.

**Permit lifetime.** The permit rides the backend-admission permit set, which the client-visible response body owns, so it is released exactly once when the exchange genuinely terminates: buffered completion, streamed body EOF, gRPC stream/trailer completion, downstream cancellation or drop, backend reset/GOAWAY, timeout, task cancellation, and graceful shutdown. It is **never** released at response headers — that would leave a long-lived streaming or gRPC response occupying backend capacity while uncounted, which is precisely what the field exists to prevent. Every retry attempt reacquires its own permit, and a sequential retry releases the previous attempt's permit before acquiring. Ferrum has no request hedging, so one client request never has two attempts holding permits at once.

**Overflow behavior.** A saturated destination is shed **before** a backend attempt exists — no dial, no bytes, no backend signal — with a `503` (gRPC `UNAVAILABLE` / gRPC-Web equivalent through the ordinary admission-rejection shaping). Because no backend was reached, the shed is neutral to passive health, the backend circuit breaker, and adaptive concurrency. Nothing is queued behind the limiter.

**Reload and retirement.** The lane deliberately does **not** carry a config generation. Permits admitted by the previous config remain part of the same authoritative destination count, so a reload cannot mint another allowance. Every acquire compares that shared count with the request's current effective cap: lowering sheds until active requests drain below the new cap; raising takes effect immediately; removing the field stops new acquisitions while old guards continue draining; and re-adding the field still counts those guards. Check-and-reserve, release, and at-zero eviction all run under the same `DashMap` shard lock, so a lane is evicted the moment its count returns to zero and destination/subset churn cannot grow the map for the gateway's lifetime.

**Observability.** Fixed-cardinality process totals only: `ferrum_destination_active_requests` (gauge), `ferrum_destination_active_requests_admitted_total`, and `ferrum_destination_active_requests_rejected_total`, each labelled only by the gateway namespace. Service, subset, host, and namespace identity are operator-controlled and unbounded, so they never become metric labels; the shed's bounded log line carries the proxy id, policy port, observed count, and cap.

**Interaction with `http1MaxPendingRequests`.** The two are independent. An HTTP/1.1 dispatch is bounded by both this destination-wide budget and the H1-only in-flight gate (`src/backend_pending_limit.rs`); the multiplexed transports consult only this one. A destination configuring both gets whichever binds first.

### DestinationRule `maxConnections` enforcement scope

`connectionPool.tcp.maxConnections` caps **concurrent open backend connections per destination** — Envoy's semantics. Keying is per resolved `(host, DestinationRule policy port)` endpoint, not per logical cluster, so a destination with N endpoint hosts sharing one port has an effective ceiling of N×cap (equivalent to Envoy's per-cluster total for the typical single-host mesh destination). One shared limiter on `ProxyState` serves every **outbound** transport, so a destination has ONE ceiling, not one per transport. Every transport keys the lane by the **policy** port (`dispatch_policy_port()`), never the dial address, so a `targetPort` remap and the mesh tunnel listeners (`:15008` / `:15006`) share the destination's lane. Hosts are normalized (lowercased, IPv6 brackets stripped) so spelling differences cannot split a lane; a lane's counter is evicted when its last connection closes.

| Transport / backend path | Actual backend sockets observed | `maxConnections` contract |
|---|---:|---|
| TCP / TCP+TLS stream proxy | One backend socket per stream session | Enforced at dial; over-cap dials fail before relay [1] |
| WebSocket H1/H2/H3 | One dedicated backend socket per WebSocket session | Enforced in the connect loop; over-cap upgrade returns 503 [2] |
| Direct H2, gRPC, HTTP/3, HBONE / mesh-mTLS pooled tunnels | Pooled multiplexed connection(s) | Enforced per constructed connection; slot held by the connection driver, streams unbounded [3] |
| reqwest HTTP/1.1 and ALPN-negotiated h2 | Pooled sockets reqwest keeps idle and reuses | Enforced in reqwest's connector per NEW physical socket; an idle socket still holds its slot [4] |
| Sidecar-ingress Unix backends | Pooled HTTP/1.1 + shared h2c carriers on an admitted Unix socket | **Out of scope by design** — inbound toward the co-located app, with no dial host or service port to key a lane on. Bounded by `FERRUM_MESH_UNIX_INGRESS_MAX_CONNECTIONS` per admitted target — see [Connection pooling](#connection-pooling) |

1. Stream listeners share the one `ProxyState` limiter (installed once, never swapped on reload), so a raw-TCP socket and a pooled/WebSocket socket to one destination share the ceiling.
2. A failed or rotated connect attempt frees its slot before retry. A WebSocket to a `mesh.mtls` / `mesh.hbone` destination opens exactly one 1:1 tunnel, charged once to the session's lane (never twice at the pool).
3. The slot is reserved only when a NEW physical connection is constructed (reuse and multiplexed streams take none) and is released when the connection driver ends — not when a pooled handle is evicted, so a drained-but-open connection still counts. Creation failures release it immediately. An over-cap create is **pre-wire** (retry may rotate to another target) and **backend-health-neutral**: no circuit-breaker failure, passive-health failure, load-balancer penalty, or adaptive-concurrency shrink. Direct-H2 and gRPC pools fall back to an existing shard, converging on `cap` connections. `maxConcurrentStreams` remains the per-connection stream control and `http2MaxRequests` the destination-wide request budget.
4. Admission runs through the vendored reqwest `connection_admission` hook; over-cap requests return `503` (`DispatchPolicyRejected`, health-neutral). A dispatch takes a lane lease only while a cap is configured, so a removed cap stops applying once in-flight requests drain and a changed cap is replaced by the first dispatch on the new generation. Upstreams that share one reqwest client for the same dial address but carry different caps resolve to the **strictest** cap in that lane generation (fail-closed). Residuals: a shared client used by an *uncapped* proxy for the same destination can dial unadmitted sockets, and startup warmup sockets (`FERRUM_POOL_WARMUP_ENABLED`) are admitted uncapped and then reused.

## Observability

### RED Metrics

The auto-injected `workload_metrics` plugin supplies Istio/GAMMA labels and Telemetry policy for these RED and lifecycle families. Registry updates occur only when the one enabled process-global `prometheus_metrics` plugin also observes the request or stream; mesh mode does not auto-inject that exporter. Without it, TCP lifecycle production and gRPC body scanning remain silent, just like the other plugin-owned families:

- `ferrum_mesh_requests_total` -- request counter.
- `ferrum_mesh_request_duration_ms` -- request duration histogram.
- `ferrum_mesh_request_bytes` / `ferrum_mesh_response_bytes` -- HTTP/gRPC body-size histograms (`REQUEST_SIZE` / `RESPONSE_SIZE`).
- `ferrum_mesh_tcp_connections_opened_total` / `ferrum_mesh_tcp_connections_closed_total` -- raw stream-path TCP connection lifecycle counters. Both halves are keyed on a once-only finalizer: `TCP_OPENED_CONNECTIONS` is emitted once by the stream path after the last `on_stream_connect` hook that actually ran, under the final mesh identity, tag-override, and disable metadata for that path — not from inside the `workload_metrics` hook, which several effective instances may each run over intermediate metadata. This is a connection lifecycle family, not an authorization-success counter: plugin rejection and client-disconnect-during-admission paths that reached both metrics hooks also finalize once before their disconnect summary, so opened and closed stay balanced. Captured mesh egress TCP finalizes after selected target metadata (including `mesh.destination.principal`) is stamped, or at teardown when no target was selected; UDP/DTLS streams remain excluded by their `udp` request protocol. Ambient destination relays are HTTP/2 HBONE CONNECT transactions rather than raw stream-plugin transactions, so they contribute request/response metrics and `ferrum_mesh_hbone_relay_failures_total`, not these TCP lifecycle families.
- `ferrum_mesh_tcp_sent_bytes_total` / `ferrum_mesh_tcp_received_bytes_total` -- TCP byte counters recorded on disconnect with Istio Telemetry semantics: **sent** is response bytes (backend-to-client) and **received** is request bytes (client-to-backend). This intentionally differs from the gateway-perspective `StreamTransactionSummary.bytes_sent` / `bytes_received` and `ferrum_api_bytes_sent_total` / `ferrum_api_bytes_received_total` field convention; the mesh producer maps those authoritative counters into the standard Istio directions. `TCP_SENT_BYTES` / `TCP_RECEIVED_BYTES` selectors, disable rules, and tag overrides therefore retain their Istio meaning.
- `ferrum_mesh_request_messages_total` / `ferrum_mesh_response_messages_total` -- gRPC length-prefixed message counters observed, when `prometheus_metrics` is enabled, on supported H1/H2/H3 frontend and direct-H2/HBONE/mesh-mTLS request and response body paths. Only complete 5-byte length-prefixed frames count; incomplete trailing frames are ignored. Both counters describe the **native gRPC representation exchanged with the backend**: requests are counted after the request-body transforms run (so a translated gRPC-Web request is counted once its text-mode base64 is decoded and its terminal trailer frame is stripped), and responses are counted from the backend's own frames before any gRPC-Web re-framing or base64 armouring. A gRPC-Web terminal trailer frame is metadata, not a message, and is never counted. A pass-through gRPC-Web response on HTTP/1.1 and HTTP/2 (no `grpc_web` translator, so the backend itself answers in gRPC-Web) is counted on its decoded frame stream, streamed or buffered: its own trailer frame is not a message and `grpc-web-text` base64 is decoded before frames are counted. An HTTP/3 pass-through stays on the plain transport and feeds no `grpc_response_messages_observed` count. Buffered request bodies are recorded with `fetch_max`, so a retry replaying the same buffer cannot inflate the count.

Supported Telemetry selectors are `REQUEST_COUNT`, `REQUEST_DURATION`, `REQUEST_SIZE`, `RESPONSE_SIZE`, `TCP_OPENED_CONNECTIONS`, `TCP_CLOSED_CONNECTIONS`, `TCP_SENT_BYTES`, `TCP_RECEIVED_BYTES`, `GRPC_REQUEST_MESSAGES`, `GRPC_RESPONSE_MESSAGES`, the matching `ferrum_mesh_*` names, and `ALL_METRICS`. Unknown family names and malformed policy remain construction errors. `ALL_METRICS` applies to every emitted Ferrum family above.

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
| `grpc_response_status` | Finalized gRPC status for gRPC requests (native and translated gRPC-Web): `0`–`16`, with an out-of-range, malformed, or missing terminal status reported as UNKNOWN `2`; empty for non-gRPC requests. HTTP/gRPC families only. |
| `response_flags` | Error flags |
| `connection_security_policy` | `mutual_tls` or `none` |

TCP families (`ferrum_mesh_tcp_*`) never carry `response_code` or
`grpc_response_status`, including under an `ALL_METRICS` tag override. A
`response_code` tag override whose value is the canonical decimal spelling of
a status (`set` to `"200"`, or `string(response.code)`) is the same series as
that status recorded without an override; a different spelling such as
`"0200"` is a distinct series.

#### How workload labels reach metrics (issue #6793)

When no plugin in the request's chain can observe transaction metadata (the
default sidecar chain with access logging disabled: `spiffe_identity`,
`mesh_authz`, and a `workload_metrics` instance without span exporters), the
`mesh.source.*` / `mesh.destination.*` label keys are not written to metadata;
metric labels are unaffected, and when an observer is present a label another
plugin rewrote is reported as the metadata says. Only the label keys are
deferred; the other keys keep their own stamping conditions:

- `mesh.request_protocol` and `mesh.connection_security_policy` are always written.
- `mesh.direction` is written only when the request or stream has an established mesh direction.
- Trace identity and propagation keys (`trace_id`, `span_id`, `parent_span_id`,
  `traceparent`, `tracestate`) are written only when trace context is enabled and the
  traffic is sampled or, for HTTP, carries a valid W3C `traceparent` or B3 context;
  `trace_sampled` follows the sampling decision and can be present (including as
  `false`) without them.
- Tag keys appear only as configured (custom and header-backed tags, metric tag
  overrides); derived CEL attribute keys only when an active per-family override plan
  needs them.

Optional keys can therefore be absent on mesh traffic even when labels were written.

### Service Graph

`GET /mesh/service-graph` exposes the same mesh identity labels as a node-local service graph. The graph is built by the auto-injected `workload_metrics` plugin at log time and aggregates HTTP-family traffic by `(source_principal, destination_principal)` with request count, error count, total duration, average duration, and last-seen timestamp. The admin endpoint is JWT-authenticated. Snapshots are built on demand: a read rebuilds the published `ArcSwap` snapshot only when it is at least one second old, so polling at any rate iterates the live `DashMap` at most once per second, and an unread graph costs only a background retention sweep every 30 seconds. Edges idle for five minutes are evicted. Each data plane tracks at most 10,000 live edges. Once the cap is reached, transactions for new edges are dropped (with a sampled warning) until retention frees a slot, and edges already tracked keep counting.

The endpoint is intentionally node-local. In CP/DP or horizontally scaled mesh deployments, scrape every data-plane instance and aggregate source/destination edges in the observability backend.

### Policy-Deny Drilldown

`GET /mesh/policy-denies/recent` (JWT-authenticated, JSON) returns aggregated recent `mesh_authz` denies for ad-hoc triage. Each deny event captured by the plugin is appended to a process-singleton bounded ring (`PolicyDenyRecorder`). The endpoint groups events whose timestamp is inside the requested window by the `(rule, source, destination, reason, reevaluation)` tuple and returns the top-N rows sorted by count descending (tie-break `last_at` descending, then `rule` ascending). `reevaluation: true` marks an HBONE admission-fence revocation of an already-admitted live tunnel rather than a request the peer made (see [HBONE Admission Fence](#hbone-admission-fence)). The recorder is exception-path only — the proxy hot path never touches it; only the `mesh_authz` deny branch records — so it has no measurable effect on allow-path latency.

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
      "reevaluation": false,
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
- `ferrum_mesh_node_waypoint_hbone_handshakes_total{phase,result}` -- NodeWaypoint HBONE handshake outcomes by phase (`inbound_tls` / `inbound_connect` / `outbound_dial`) and result (`success` / `failure`).
- `ferrum_mesh_node_waypoint_asserted_identity_total{result,reason}` -- asserted source-identity accept/reject with bounded reasons.
- `ferrum_mesh_node_waypoint_destination_policy_rejections_total{reason}` -- destination AuthorizationPolicy / scope / open-relay rejects.
- `ferrum_mesh_node_waypoint_missing_destination_metadata_total` / `ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total` -- fail-closed missing `Workload.node_waypoint` metadata / blocked plaintext fallback.
- `ferrum_mesh_config_update_rejections_total{consumer,reason}` -- `MeshSubscribe` responses a mesh config consumer refused **before** applying them (see [Native MeshSubscribe](#native-meshsubscribe-default) → "Response binding"). `consumer` is `native` (the local slice-installing stream) or `remote_discovery` (a cross-cluster endpoint fetch); `reason` is one of `missing_ferrum_version`, `incompatible_ferrum_version`, `unexpected_heartbeat`, `invalid_slice_json`, `envelope_version_mismatch`, `envelope_revision_mismatch`, `malformed_revision`, `node_id_mismatch`, `namespace_mismatch`, `workload_scope_mismatch`, `waypoint_scope_mismatch`, `invalid_ext_authz_content`. Both labels are compile-time constants, so the series' cardinality is fixed and no control-plane-supplied value ever reaches `/metrics` — the mismatching values stay in the structured `warn!` at the rejection site. A non-zero value means a control plane answered this data plane with something that is not bound to its subscription (cross-wiring, a stale/proxied CP, or version skew); the last-good slice keeps serving while it persists.
- `ferrum_mesh_inbound_plaintext_allowed` -- `1` when the mesh inbound listener admits plaintext (PeerAuthentication `PERMISSIVE`/`DISABLE`, or no usable server identity; dev-only because production mode refuses this), `0` otherwise. Deliberately label-free: the downgrade reason stays in the `warn!` logs at the enforcement sites. Updated at startup enforcement and on **accepted** PeerAuthentication live reloads, so a reload that heals or degrades the posture moves the gauge only once the slice is actually applied — a candidate slice the proxy rejects leaves it at the pre-reload value; topologies with no TLS-terminating inbound listener (EastWestGateway SNI passthrough) leave it at `0`.
- `ferrum_xds_streams_rejected_total` -- aggregate count of ADS streams the CP rejected at admission, in **any** scope: total, per-namespace, per-principal, per-node, distinct-node cardinality, an invalid `Node.id`, or the initial-request deadline. Emitted without labels because every dimension that could distinguish the rejections (`Node.id`, JWT subject, SPIFFE URI) is client-controlled and would be unbounded. A growing value flags a misconfigured or hostile client opening many streams.
- `ferrum_xds_stream_admission_rejections_total{reason}` -- the same ADS rejections broken down by a **closed, compile-time** reason set: `total_streams`, `namespace_streams`, `principal_streams`, `node_streams`, `node_cardinality`, `node_id_empty`, `node_id_too_long`, `node_id_unsafe_characters`, `first_request_timeout`. The label is a `&'static str` from an enum, so the series count is fixed and no client-supplied text can reach `/metrics`. The reject site logs the CP-resolved namespace and a **redacted digest** of the offending node id — never the raw value, which an authenticated peer would otherwise be able to inject into the CP log stream.
- `ferrum_xds_active_streams` / `ferrum_xds_active_node_ids` -- absolute gauges for currently active ADS streams (SotW plus Delta) and distinct active ADS node state keys. Both are label-free for the same cardinality reason and return to `0` when the last ADS stream ends. Occupancy is published by atomic deltas tied to successful aggregate/node admission and exactly-once release (never by racing load-then-store snapshots). Alert on sustained proximity to `FERRUM_XDS_MAX_TOTAL_STREAMS` / `FERRUM_XDS_MAX_ACTIVE_NODES`.
- `ferrum_cp_grpc_stream_admission_rejections_total{surface,reason}` -- native ConfigSync and MeshSubscribe refusals at the shared admission controller. `surface` is `config_sync`, `mesh_subscribe`, or `xds`; `reason` is the same closed set as the ADS counter. No node id, subject, or tenant label.
- `ferrum_cp_grpc_active_streams` / `ferrum_cp_grpc_active_node_ids` -- absolute gauges for currently active long-lived configuration streams across ConfigSync, MeshSubscribe, and ADS, and the distinct node state keys those streams hold. Label-free for the same cardinality reason. Alert on these for the shared process budget; keep the `ferrum_xds_*` gauges when you need ADS-only occupancy.
- `ferrum_xds_first_slice_nacks_total{namespace,type_url}` -- NACKs of a required mesh-slice type emitted by the DP while still waiting for its first slice. A non-zero, growing value on a starting DP means first-slice convergence is blocked by a malformed required resource (see [xDS ADS Compatibility](#xds-ads-compatibility)).
- `ferrum_xds_warming_partial_applies_total{namespace}` -- count of mesh slices the DP applied while the required-type `version_info` strings were skewed (not all identical). Under the coherent-version gate the DP builds a slice only once every required type reports the same version, and the CP force-refreshes all subscribed required types to one snapshot version on any change, so on a healthy Ferrum-CP-to-Ferrum-DP feed this counter should stay at **0** — normal coherent xDS apply must not increment it. A non-zero or growing value is a defensive signal that a slice was installed under version skew (e.g. a CP advancing required types independently of the ECDS security carriers); investigate it as potential config drift rather than treating it as expected warming activity. Keyed by `namespace` only (low, operator-bounded cardinality, matching `ferrum_xds_first_slice_nacks_total`). The detailed per-type `version_info` strings and still-missing required types are deliberately **not** exported here — they embed config-change timestamps and content digests, so they live behind JWT on the `GET /mesh/config-drift` `convergence` block instead.

The Prometheus `/metrics` endpoint is authenticated: scrapers need a valid admin
JWT, `FERRUM_METRICS_BEARER_TOKEN`, or a source IP in `FERRUM_METRICS_ALLOWED_CIDRS`.
Unauthenticated scrapes receive `401`. Mesh RED/certificate series include SPIFFE
identity labels, so restrict scrape reachability (NetworkPolicy, private scrape
port, or CIDR/bearer allowlists) if namespace/service-account identity disclosure
is sensitive.

The Helm chart can install a `PrometheusRule` when `observability.enabled=true` and `observability.alerts.enabled=true`, plus a `ServiceMonitor` for Deployments and `PodMonitor`s for host-network DaemonSets when the corresponding monitor flags stay on. Enabling observability does not change admin bind addresses; ServiceMonitor/PodMonitor require a non-loopback admin bind on each enabled target and a scrape credential (`observability.metrics.allowedCidrs` or `bearerToken.existingSecret.name`). The bundled rules cover certificate expiry, rotation failures, CA health, stale DP config, mTLS handshake failures, policy-deny spikes, and injector webhook failures. `FerrumMeshControlPlaneConfigStale` compares `time() - ferrum_mesh_config_last_received_timestamp_seconds` and is silent (no-data) until a scraped data plane emits that series — it does not use `absent()`. The observability dashboard config map includes RED, service-graph edge count, mTLS coverage, USE-lite process panels, certificate status, and trust-bundle churn panels.

The injector webhook failure alert uses the Kubernetes API server metric `apiserver_admission_webhook_rejection_count`. Clusters that do not scrape kube-apiserver metrics will show that alert as no data; all Ferrum-emitted metric alerts continue to evaluate normally.

### Telemetry API

`MeshTelemetryResource` provides per-scope telemetry configuration, merged by specificity (most specific scope wins per section):

**Scope precedence**: `WorkloadSelector` > `Namespace` > `MeshWide`

**`targetRef` / `targetRefs` is rejected** (`FerrumAccepted=False` / `Invalid`,
issue #4305). Only `AuthorizationPolicy` implements end-to-end attachment. A
`Telemetry` carrying only either form reads as "no selector" and would widen to
the whole namespace — or, in the Istio root namespace, to `MeshWide` — so a
resource meant to disable access logging for one gateway would disable it mesh
wide. Scope it with a workload selector instead.

Each section (tracing, metrics, access logging) is merged independently. Within the same scope level, later resources win. Deterministic ordering is ensured by namespace/name tie-breaking.

**Tracing configuration**:

For direct plugin configuration outside Istio translation, see the complete
[`workload_metrics` standalone reference](plugins.md#standalone-configuration),
including provider envelopes, disable aliases, sampling omission, resource-name
defaults, and exporter queue/retry ranges. Malformed recognized field types
are constructor errors; OptionalFailOpen warns and omits the invalid instance.
Across multiple effective instances, custom tag names compose within a shared
32-name admission bound; later stamped values take precedence. A skipped or
empty instance does not erase earlier tag names. The HTTP-family service graph
records one observation per terminal client transaction regardless of instance
count, honors memoized triggers, and counts nonzero final gRPC status as an
error (including native and translated gRPC-Web outcomes).

- `sampling_percentage`: 0.0--100.0. New root traces use a probabilistic PRNG decision; valid upstream W3C `traceparent` and B3 sampling decisions are inherited unchanged.
- **Propagation format.** The active gateway span is always injected toward the backend as W3C `traceparent` (plus `tracestate` when present). It is additionally injected as B3 whenever a Zipkin provider is configured (also while span reporting is disabled) or the backend request still carries any B3 header: multi-header `x-b3-traceid` / `x-b3-spanid` / `x-b3-parentspanid` (when the span has a parent) / `x-b3-sampled`, and the single-header `b3: {trace}-{span}-{sampled}[-{parent}]` form when the request used it. Every incoming B3 header (any casing, including `x-b3-flags`) is replaced, so a B3-only backend continues from the gateway span rather than the caller's. Metrics-only instances (no sampling, providers, or disabled-reporting flag) never touch trace headers.
- **Dropped spans.** A finished span an exporter refuses at enqueue, or discards at delivery, is counted on `ferrum_mesh_tracing_spans_dropped_total{provider,reason}` (`provider` ∈ `opentelemetry`, `zipkin`, `datadog`, `lightstep`, `other`; `reason` ∈ `queue_full`, `byte_budget`, `process_ceiling`, `shutting_down`, `unavailable` at enqueue, and `export_failed` — once per lost span — when an enqueued batch is discarded after a non-retryable collector response, exhausted retries, or with no HTTP client, and for the spans an OTLP HTTP-200 partial-success response reports in `rejectedSpans`, capped at the batch size), beside the rate-limited warning. Standalone `otel_tracing` exporters never count here. Labels are fixed; no endpoint or error text is exported. An instance that cannot export (span reporting disabled, or no provider) builds no span at all.
- `custom_tags`: literal key-value tags injected into every span. Tags merge by key across matching Telemetry scopes; a more-specific scope overrides only keys it names. A source change for a named tag is exclusive: literal, header, or environment replaces the less-specific source and its fallback rather than leaving both active.
- `custom_header_tags`: tags resolved from request headers at runtime. Header tags merge by key with the same more-specific-overrides behavior as literal tags. Credential-bearing source headers (`Authorization`, cookies, API/auth/CSRF tokens, and operator-configured sensitive metadata names) are rejected. Custom tag names cannot collide with `mesh.*`, `mesh_authz.*`, trace identity/sampling controls, or other reserved telemetry keys. A workload-metrics instance accepts at most 32 custom tags, 128-byte names, and 1024-byte values; an oversized runtime header value is omitted. A source header not declared in `safe_tag_sources` is copied as `[REDACTED]`.
- `custom_env_tags`: Istio `customTags.<tag>.environment` references carried as `tag_name -> env_var_name`. The Kubernetes translator never reads the controller-host environment. The mesh data plane resolves these at `workload_metrics` construction and reload (not on the request hot path). A present UTF-8 value overrides any matching `custom_tags` default; a missing variable keeps the translated `defaultValue` when one was set and otherwise omits the tag (Istio/Envoy semantics). Missing/empty environment names, non-portable env-var names, and credential-bearing names (including secret/password/token/key/credential names, the metadata redactor's credential classes such as session identifiers, passphrases/passcodes, PINs and one-time codes, JWTs, signatures and bearer assertions, database connection locations, client credential identifiers, and operator-configured sensitive metadata names) fail translation with `FerrumAccepted=False`/`Invalid`. Oversized or non-UTF-8 resolved values fail plugin construction/reload closed. Selected values are deliberately injected into transaction metadata and exported telemetry, so only trusted Telemetry authors should choose data-plane environment dimensions; diagnostics never include resolved values or rejected credential-bearing variable names.
- Istio `customTags.<tag>.header.defaultValue` is translated as the literal fallback for the same tag. An absent request header uses that default; a present header value takes precedence.
- `safe_tag_sources` (Ferrum extension, mesh `tracing` config and `workload_metrics` plugin config): header names (case-insensitive) and environment variable names (case-sensitive) whose values header and environment tags may copy verbatim. Copying fails closed: every undeclared source, including every source translated from an Istio `Telemetry` CRD, is emitted as `[REDACTED]` until an operator declares it here. Credential-shaped entries are rejected. A more specific Telemetry resource with a non-empty list replaces the inherited one.
- Istio `customTags.<tag>.environment.defaultValue` is translated into `custom_tags` as the DP fallback; the environment variable name always lands in `custom_env_tags` whether or not a default is present (no silent omission).
- `providers`: inline span exporters for Zipkin v2, Datadog Agent `/v0.3/traces`, Lightstep OTLP, and OpenTelemetry OTLP/HTTP JSON. Lightstep uses `accessTokenEnv` so bearer credentials stay in the local process environment instead of mesh config JSON; the name must be a `FERRUM_PLUGIN_SECRET_<NAME>` variable (for example `FERRUM_PLUGIN_SECRET_LIGHTSTEP_ACCESS_TOKEN`), because a Telemetry author chooses the collector URL the token is sent to. For an **inline** provider, any other name is refused at translation and again by the data-plane `workload_metrics` constructor. Name-only references to `meshConfig.extensionProviders` are checked during encompassing Istio Telemetry admission, including the dedicated secret-environment namespace rule, before publication. The helper-level constructor check is not a translation bypass for accepted Telemetry; optional-plugin quarantine remains relevant to other configuration ingress. Multiple providers receive the same sampled span. A provider URL using cleartext `http://` (an in-cluster collector such as `http://zipkin.istio-system:9411`) is admitted because injection writes `allow_plaintext: true` on the `workload_metrics` plugin, so the cleartext export is visible in the injected config. Outside mesh injection, a non-loopback `http://` provider needs that opt-in explicitly.
- `disable_span_reporting` / Istio `disableSpanReporting`: when explicitly true, suppresses span export while leaving the rest of the merged tracing config visible. Omitted values inherit from less-specific scopes; explicit false can re-enable a more-specific scope.
- `match.mode` (`SERVER` / `CLIENT` / `CLIENT_AND_SERVER`, default `SERVER`): each mesh listener stamps a traffic direction onto every accepted request — sidecar / ambient / HBONE / egress inbound listeners stamp `Inbound`, sidecar/ambient outbound capture stamps `Outbound`. The translator unions every `tracing[].match.mode` across the merged Telemetry block into a single `direction_emit` on the auto-injected `workload_metrics` plugin. The plugin emits SERVER-kind spans on inbound directions and CLIENT-kind spans on outbound directions and drops the export entirely when the listener direction is not enabled. Span payloads carry the kind in every provider format: OTLP enum `2` / `3` (SERVER / CLIENT), Zipkin v2 top-level `"kind": "SERVER"` / `"CLIENT"`, and Datadog `meta["span.kind"]` set to `"server"` / `"client"`. Non-mesh listeners (file / db / cp / dp HTTP entrypoints) leave the direction unset and the plugin falls back to its server-only default.
- Attribution follows listener direction for HTTP and stream traffic: outbound observations use the local workload as source and the routed service/selected peer as destination, except NodeWaypoint captured-Service HTTP and captured L4 use the authenticated originating pod identity resolved at accept time; inbound observations use the local workload as destination and only an authenticated peer or trusted HBONE baggage identity as source. The NodeWaypoint accept-time identity takes precedence over request baggage, and anonymous permissive inbound traffic never inherits the local workload's principal as its source.
- Request-mirror backend attempts are excluded from workload-metrics spans, matching their exclusion from client-facing RED metrics and the service graph. The primary request retains the sole span for its `(trace_id, span_id)`.

Datadog export groups spans by trace in the Agent v0.3 payload shape and sends the upper 64 bits of W3C 128-bit trace IDs via `_dd.p.tid` while the numeric `trace_id` field carries the low 64 bits.

**Closed tracing schema.** The mesh tracing config (`MeshTracingConfig`, the `tracing` block of a merged Telemetry config) rejects unknown fields, so a misspelled or removed key such as the retired singular `provider` fails the load instead of silently disabling tracing. The same config also rides the Ferrum control-plane-to-data-plane wire (native slices and the ECDS telemetry carrier), so a field added in a newer build is an unknown field to an older data plane: that data plane rejects the slice (an xDS data plane NACKs it) and keeps serving its last accepted config. The control plane and every data plane must therefore run the same Ferrum build. This is the deliberate pre-launch policy; there is no mixed-version compatibility window.

**Metrics configuration**:

- `tag_overrides`: remove, rename, or set labels on the finalized mesh metric key. Istio label names such as `source_workload`, `destination_service`, and `response_flags` are normalized to Ferrum's fixed `mesh.*` metric-label vocabulary; adding a new Istio tag dimension is not supported. Overrides preserve their `match.metric` scope and apply in declaration order. Admission permits at most 128 override entries and 16384 encoded bytes across the per-family plans stamped into transaction metadata. When several effective `workload_metrics` instances compose, a later plan replaces only the same metric family; untouched family plans survive, and CEL inputs are stamped from the union required by those final per-family plans. `UPSERT.value` accepts either a double-quoted JSON-style string literal (for example, `value: '"edge"'`) or a bounded CEL subset compiled at Telemetry translation / `workload_metrics` construction (reload) time — never re-parsed per request. Supported CEL forms are attribute reads, `string(<int attribute>)`, and `has(<string attribute>) ? <then> : <else>`, with limits of 512 UTF-8 bytes (including surrounding whitespace), 32 tokens, nesting depth 8, and 24 AST nodes. The authoritative attribute environment at metric emission (`log` / stream disconnect) is:

  | Attribute | Type | Source |
  |---|---|---|
  | `source.workload` / `namespace` / `principal` / `app` / `service` | string | finalized mesh metric key |
  | `destination.workload` / `namespace` / `principal` / `app` / `service` | string | finalized mesh metric key |
  | `request.protocol`, `response.flags`, `connection.security_policy` | string | finalized mesh metric key |
  | `request.method`, `request.host` | string | internal-only metric CEL stamps (HTTP/gRPC method and authority) |
  | `response.code` | int | HTTP/gRPC response status (`string(response.code)` required) |
  | `destination.port` | int | internal-only metric CEL stamp (same resolution as mesh authz) |

  `has(<string attribute>)` tests presence in the evaluation context, not
  “resolved attribution”. Mesh-key string attributes (`source.*`,
  `destination.*`, `request.protocol`, `response.flags`,
  `connection.security_policy`) default to the sentinel `unknown` when
  metadata is absent and are present unless an earlier ordered label
  operation removes or renames that key; after such a removal, a later
  `has(...)` can be false. Only `request.method` and `request.host` can
  otherwise be absent (missing/empty internal stamps). Integer attributes
  are not valid `has()` operands.

  Headers, body bytes, credentials, client IPs, and request paths are rejected (credential exposure and/or unbounded cardinality). HTTP-only attributes (`request.method`, `request.host`, `response.code`) fail closed when the override targets a TCP family or `ALL_METRICS`. Missing attributes evaluate to an empty sanitized label rather than inventing traffic data; output is truncated to 256 UTF-8 bytes and stripped of quotes/controls. Missing, empty, malformed, unsupported, or over-budget expressions make the Telemetry resource invalid (`FerrumAccepted=False`) with field-specific diagnostics that never echo expression text. Metric selectors are those listed under [RED Metrics](#red-metrics). Unsupported tag names, unsafe or oversized literal values, and unknown metric selectors likewise fail translation visibly. A changed label shape creates a new Prometheus series; the previous series ages out under the configured stale-entry TTL.

  **Dynamic series budget.** Exact CEL-derived label values and ordinary mesh identity series share one finite per-family live-series budget (`mesh_series_budget_per_family` on the global `prometheus_metrics` plugin; default `10_000`, range `1`–`1_000_000`) of distinct `MeshRequestKey` entries per mesh metric family in the process `MetricsRegistry`. Admission uses exact atomic reservation (not `DashMap::len()`). Already-admitted keys continue to update at capacity. A previously unseen key beyond the budget — including a newly observed legitimate identity combination — is dropped for that family and counted on the fixed-cardinality overflow series `ferrum_mesh_metric_series_overflow_total{family}` where `family` is one of the ten closed names (`request_count`, `request_duration`, `request_size`, `response_size`, `tcp_opened_connections`, `tcp_closed_connections`, `tcp_sent_bytes`, `tcp_received_bytes`, `grpc_request_messages`, `grpc_response_messages`). Stale TTL eviction releases live capacity so later distinct keys can be admitted again. Because the cap is shared across identity and CEL dimensions, CEL cardinality pressure can suppress newly observed identity series until eviction frees slots (and the reverse). `0` is rejected — there is no unlimited mode. The default is sized for large legitimate meshes (thousands of src×dst×code combinations) while bounding attacker-controlled CEL cardinality such as `request.host` or custom HTTP methods rewritten into metric labels. `request.host` / `request.method` / `destination.port` metadata is stamped only when an active CEL expression requires it, under the reserved internal-only `mesh.metrics.cel.*` namespace so those temporary values never become transaction-log or trace attributes.
- `disabled_metrics`: suppresses only the selected mesh metric family before its counter or histogram is updated. It accepts the metric selectors listed under [RED Metrics](#red-metrics). Newly accepted Telemetry configuration affects subsequent transactions immediately; an already-created series remains visible at its last value until the Prometheus stale-entry TTL evicts it, and re-enabling resumes recording without a restart.

**Access logging configuration**:

- `enabled`: toggle (default true). When false, the access log plugin is not injected.
- `filter`: optional `AccessLogFilter` with `status_code_min`, `status_code_max`, `min_latency_ms`, `errors_only`, and/or a compiled `expression` tree when the Telemetry `filter.expression` contains `||`. Pure `&&` conjunctions stay in the flat fields; `||` expressions compile to a bounded AST (`op: and|or|status_code_min|status_code_max|min_latency_ms|errors_only`) with limits of 4096 UTF-8 bytes, 64 tokens, nesting depth 16, and 32 AST nodes. Status atoms are `response.code` / `response.status`; latency accepts `response.duration` or `duration`, with integer milliseconds by default and explicit `ms` / `s` suffixes (for example, `response.code >= 500 || duration > 1s`). Unsupported identifiers, malformed operators, overflowing conversions, and over-limit input fail translation closed with field-specific diagnostics. So does a filter that can never match: a `response.code` bound outside `0..=999`, or a conjunction (flat, or anywhere inside an `||` tree) whose lower status bound exceeds its upper one. The injected `stdout_logging` is `KeepLastKnownGood`, so translation refuses these rather than producing an access log the data plane would reject.

The access log is injected as a `stdout_logging` global under the reserved id `__mesh_access_log` (carrying the `filter` above). As a global, trigger-free `stdout_logging`, it also records requests that match no route (the route-miss `404`, with `metadata.rejection_phase = "route_not_found"`). When the `GatewayConfig` handed to mesh preparation already contains an operator-managed global plugin of the **same plugin type**, that operator plugin overrides the mesh injection: if you define your own global `stdout_logging`, the `__mesh_access_log` injection is suppressed so transactions are not logged twice, and the Telemetry CRD's `accessLogging.filter` is **not** applied on top of your plugin. Native/xDS `MeshSlice` feeds do not carry operator `plugin_configs`, so slice-only runtimes receive the mesh-managed access log unless access logging is disabled by Telemetry. To keep the mesh-managed filter, leave access logging to the injected plugin (do not also define a global `stdout_logging` in a prepared config), or fold the equivalent `filter` into your own global `stdout_logging` config.

## Kubernetes Injector

`FERRUM_MODE=injector` runs a Kubernetes admission webhook that injects Ferrum mesh sidecars into pods. The injector only produces JSON patches; all mesh runtime work happens in `FERRUM_MODE=mesh`.

### Webhook Setup

The injector listens on `FERRUM_INJECTOR_LISTEN_ADDR` (default `0.0.0.0:9443`) and handles `POST /mutate`. AdmissionReview request bodies are capped before JSON parsing by `FERRUM_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB` (default `4`, max `64`).

**TLS is required and fail-closed.** Kubernetes calls admission webhooks over HTTPS, so the injector requires both `FERRUM_INJECTOR_TLS_CERT_PATH` and `FERRUM_INJECTOR_TLS_KEY_PATH` and **refuses to start** when neither is set. For local development only, set `FERRUM_INJECTOR_ALLOW_PLAINTEXT=true` to serve plaintext HTTP; the injector logs a loud warning at startup in that mode. Setting only one of the cert/key pair is always a configuration error.

**HTTP/1.1 only (plus ACME TLS-ALPN-01).** Every accepted connection is served by Hyper's HTTP/1 builder, so the injector's TLS acceptor advertises `http/1.1` and **never** `h2` — an HTTP/2-capable Kubernetes API server cannot negotiate `h2` and then send an HTTP/2 preface to the HTTP/1 parser (the shared TLS loader's `h2` offer is deliberately dropped for this listener).

`acme-tls/1` **is** still advertised, and that is deliberate rather than incidental: the shared loader installs `AcmeTlsAlpnResolver` on every listener it builds, so this acceptor can serve RFC 8737 validation certificates from the process-global ACME order store. That resolver only does so for a ClientHello offering `acme-tls/1` **alone** with SNI matching a pending/ready/processing order — never for a Kubernetes API server, which always offers `h2` and/or `http/1.1`. So an injector with a pending order already visible to that store can serve TLS-ALPN-01 validation against its own listener (expose it on `:443` for the identifier being validated), and the advertisement stays in agreement with what the resolver can actually serve. An `acme-tls/1` connection carries no HTTP, so handing the post-handshake socket to the HTTP/1 builder is inert.

**Challenge creation and refresh are external to injector mode.** Startup materializes the configured cert/key before the listener exists: the shared loader's `acme://` path (`load_acme_material` → `AcmeCertificateStore::material`) fails with a not-found error until the order has produced an issued certificate record. An injector pointed at an `acme://certificates/<id>#cert` id that has **never** been issued therefore fails to start and never reaches the TLS-ALPN resolver, so it cannot serve the challenge for its own first issuance. Bootstrap that first order another way — start from an already-materialized source (a `file://` or Kubernetes-Secret cert, which is what the webhook's `caBundle` wiring needs anyway) and switch the cert source to `acme://` once the record exists, or complete the initial order out-of-band against a different validator listener or challenge type.

Injector mode also does **not** start Ferrum's ACME renewal scheduler or refresh its process-global order store from disk. `AcmeOrderStore::open` loads `acme-orders.json` into memory once, on the first resolver lookup; an order written by another process after that lookup is not visible until the injector restarts. For externally orchestrated renewal or re-issuance, stage the pending order before the injector's first ACME lookup or restart the injector after staging it, then restart or roll the injector again after issuance so its serving certificate is rematerialized. Retaining `acme-tls/1` makes that explicit restart-based challenge path possible; it does not make injector mode renewal-self-sufficient.

**Connection bounds depend on nonzero limits.** Connections are bounded by `FERRUM_MAX_CONNECTIONS`, the TLS handshake by `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`, and the wait for HTTP/1 request headers by `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` (default `10`). Trickled or withheld headers cannot hold admission capacity open indefinitely **only while all three limits are nonzero**, and each `0` opens a different hole:

- `FERRUM_MAX_CONNECTIONS=0` removes the connection semaphore entirely, so concurrent admission connections are unbounded.
- `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS=0` makes `accept_with_optional_timeout` skip its timer, so on a **TLS** injector a client can connect and then withhold the TLS handshake indefinitely while holding a `FERRUM_MAX_CONNECTIONS` slot. The header timeout does **not** cover this: HTTP/1 parsing has not started yet, so a nonzero `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` never protects a pre-TLS stall.
- `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0` disables the header timer, so a post-handshake connection that trickles or withholds request headers is never timed out.

Keep all three nonzero on any injector reachable beyond the API server; a nonzero header timeout alone is not sufficient.

**Request validation (fail-closed on injection).** The injector validates each AdmissionReview before injecting:

- **Pod-kind check:** the request must target a core (`apiGroup: ""`) `Pod` — confirmed via `request.kind` (a `GroupVersionKind`) or, when `kind` is absent, the core `pods` `request.resource`. A mis-scoped `MutatingWebhookConfiguration` that routes other kinds (or a request carrying no kind/resource metadata) is **admitted with `allowed: true` and no patch**, and a warning is logged. The injector never patches an unknown kind.
- **`dryRun`:** the patch-only webhook has no side effects, so a `dryRun: true` request returns the identical computed patch without implying any side effect.
- **`spec.hostNetwork: true`:** never injected — see [Host-Network Pods Are Never Injected](#host-network-pods-are-never-injected) below.

These complement the existing boundary checks: the body-size limit (returns `413`), reserved-container-name conflicts (`ferrum-edge` / `ferrum-edge-init`) refuse injection, a pod with no application containers is refused (a native sidecar is not a sufficient `spec.containers` entry), unresolved named kubelet probe ports are refused, and invalid port/CIDR annotations are rejected with a webhook error that names the offending annotation.

**Self-exclusion (bootstrap deadlock).** A self-hosted mutating webhook with `failurePolicy: Fail` must not intercept its own replacement pods: when every injector replica is down, admission calls fail and pod `CREATE` in the release namespace is rejected until an operator deletes the `MutatingWebhookConfiguration`. The `charts/ferrum-mesh` chart therefore renders two guards on `sidecar-injector.ferrum.io`:

1. **`namespaceSelector`** — user `injector.namespaceSelector` matchExpressions are preserved, but the chart **always** appends `kubernetes.io/metadata.name NotIn [<Helm release namespace>]` at render time so overrides cannot drop it. Pods in the release namespace (injector, control plane, mesh CA, east-west gateway) are never gated on the webhook.
2. **`objectSelector`** — `app.kubernetes.io/name NotIn [ferrum-mesh-injector]` excludes injector pods by label regardless of namespace.

Raising `injector.replicas` reduces the chance that all endpoints disappear at once; self-exclusion ensures a total outage still does not block injector recovery. Workloads in other namespaces continue to receive admission calls, with the usual opt-in/out semantics.

Register with Kubernetes:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: ferrum-edge-injector
webhooks:
  - name: ferrum-inject.ferrum.io
    admissionReviewVersions:
      - v1
    sideEffects: None
    failurePolicy: Fail
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values:
            - ferrum-system
    objectSelector:
      matchExpressions:
        - key: app.kubernetes.io/name
          operator: NotIn
          values:
            - ferrum-mesh-injector
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
| `ferrum.io/injected` | Written by the injector as an observability marker only; not trusted as a skip signal. Re-invocation is rejected by reserved `ferrum-edge` / `ferrum-edge-init` name conflicts |

When `FERRUM_INJECTOR_REQUIRE_ANNOTATION=true` (default), pods must explicitly opt in via `ferrum.io/inject: "true"`, `sidecar.istio.io/inject: "true"` (Istio compat), or the `ferrum.io/mesh: "enabled"` label. When `false`, the positive opt-in requirement is removed for otherwise eligible pods, but a pod is still skipped when its inject annotations or `ferrum.io/mesh` label carry an explicit opt-out or an unrecognized value (for example `ferrum.io/inject: "maybe"`), and host-network pods are still never injected (see below).

**Minimum Kubernetes version: 1.29.** Native sidecar containers (`initContainers` with `restartPolicy: Always`) are beta and enabled by default from 1.29, and GA in 1.33. There is **no ordinary-container fallback**: an ordinary sidecar cannot provide startup ordering or Job completion, so the injector always emits the native-sidecar shape. On Kubernetes 1.28 the `SidecarContainers` feature gate must be enabled; on 1.27 and earlier the apiserver rejects `spec.initContainers[].restartPolicy`. Do not install the injector on clusters older than 1.29 unless that feature gate is on. The `ferrum-mesh` chart enforces this at render time: with `injector.enabled=true`, `ferrum-mesh.validateInjectorKubeVersion` fails `helm template`/`helm install` below 1.29 and names the `SidecarContainers` gate and the reported cluster version. This is deliberately not a chart-wide `Chart.yaml: kubeVersion:` constraint, so the rest of the mesh chart still installs on an older cluster with `injector.enabled=false`. A client-side `helm template` with no `--kube-version` reports the 1.20 sentinel and is skipped rather than refused.

### Host-Network Pods Are Never Injected

A pod with `spec.hostNetwork: true` shares the **node's** network namespace, so every pod-scoped mesh surface becomes node-scoped. The injector therefore **skips such pods unconditionally**, matching Istio's `injectRequired()` host-networking skip:

- In `CaptureMode::Iptables` the init container runs with `NET_ADMIN`+`NET_RAW` and appends the mesh `nat/PREROUTING` and `nat/OUTPUT` jumps into what is really the node's own nat table. That redirects **all** node TCP at `127.0.0.1:15001` / `:15006` — hijacking kubelet, CNI, DNS, the node's egress, and every other host-network pod, into a proxy that is not listening. The init container installs no cleanup trap, so the outage outlives the pod.
- Even with capture off (`ebpf` / `explicit`), the sidecar's own listeners (`15001`, `15006`, and `15008` for HBONE) would bind on the **node**, colliding with host ports and exposing a mesh inbound listener node-wide while having nothing captured to proxy.

The skip is therefore the whole injection, not just the capture half. It is evaluated **before** the opt-in gate, so neither `ferrum.io/inject: "true"` nor `FERRUM_INJECTOR_REQUIRE_ANNOTATION=false` can re-enable injection for a host-network pod. (An explicit opt-out is still honored first; it reaches the same skip.)

The pod is **admitted unmodified** (`allowed: true`, no `patch`, no `patchType`) rather than denied. Denying would turn a capture hazard into an admission outage: host-network system pods (CNI agents, node exporters, `kube-proxy`) must still be creatable in a meshed namespace, and with `failurePolicy: Fail` a denial would block them.

Because the skip is invisible from the workload's side, it is logged. Each skipped pod emits one structured `WARN` carrying the pod name (falling back to `generateName`, which is all a controller-created pod has at CREATE admission), the namespace, and the configured capture mode:

```
WARN Injector skipping pod with spec.hostNetwork=true: the pod shares the node's
     network namespace, so capture rules and sidecar listeners would apply
     node-wide; admitting the pod unmodified
     pod=kube-proxy-abcde namespace=payments capture_mode=Iptables
```

Ordinary opt-out / not-selected skips stay quiet — they are the steady-state outcome for most pods the webhook sees. Only the node-safety skip is logged.

To mesh a workload that currently requests `hostNetwork`, move it to a pod network namespace; there is no annotation that overrides this guard.

**Adjacent host-namespace fields.** `hostPID` and `hostIPC` are **not** treated as skip conditions. They share the node's PID and IPC namespaces, which no injected surface writes to: the init container's rules are scoped to the network namespace, and the sidecar's listeners are network-namespace-scoped. A `hostPID`/`hostIPC` pod that keeps its own network namespace is meshed normally.

### Port and IP-Range Capture Overrides

The injector supports per-pod capture overrides via annotations. The Istio annotation namespace is honored byte-for-byte so workloads can migrate without rewriting metadata; Ferrum-native annotations are accepted as aliases for the port lists.

| Annotation | Direction | Semantics |
|---|---|---|
| `traffic.sidecar.istio.io/includeOutboundPorts` | outbound | Comma-separated TCP destination ports included in outbound capture, or `*` for all outbound ports; when set to explicit ports, outbound REDIRECT rules are scoped to these ports |
| `ferrum.io/includeOutboundPorts` | outbound | Ferrum-native alias for the above |
| `traffic.sidecar.istio.io/excludeOutboundPorts` | outbound | Comma-separated destination ports excluded from outbound TCP capture and, when enabled, outbound UDP capture (Istio-compatible) |
| `ferrum.io/excludeOutboundPorts` | outbound | Ferrum-native alias for the above |
| `traffic.sidecar.istio.io/excludeInboundPorts` | inbound | Comma-separated TCP and UDP destination ports excluded from inbound capture (Istio-compatible). RETURN rules are emitted BEFORE the inbound REDIRECT/TPROXY catch-all so the exclusion is honored |
| `ferrum.io/excludeInboundPorts` | inbound | Ferrum-native alias for the above |
| `ferrum.io/rewriteAppProbes` | inbound | `"false"` opts out of the kubelet application-probe rewrite, leaving probes pointing at application ports AND leaving those ports captured (such probes fail under `STRICT`). Default on |
| `sidecar.istio.io/rewriteAppHTTPProbers` | inbound | Istio-compatible spelling of the above |
| `traffic.sidecar.istio.io/excludeOutboundIPRanges` | outbound | Comma-separated CIDRs appended to the env-derived outbound exclude list (matches Istio: per-pod additive) |
| `traffic.sidecar.istio.io/includeOutboundIPRanges` | outbound | Comma-separated CIDRs that REPLACE the env-derived outbound include list when present (matches Istio: include-overrides-include) |

Port-list annotations merge with their Ferrum aliases; exclude lists also merge additively with the injector-level env lists (`FERRUM_MESH_EXCLUDE_OUTBOUND_PORTS` for outbound, `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` for inbound). `includeOutboundPorts` is annotation-only and narrows outbound REDIRECT rules to the listed TCP destination ports when the include CIDR list is only the implicit catch-all. If `includeOutboundIPRanges` is also explicit, the rule sets are additive: all ports inside the explicit CIDRs are captured, plus the listed ports to any destination. The `*` wildcard means all outbound ports to any destination, even when explicit include CIDRs are also present. Outbound exclude ports still win because their RETURN rules are emitted first. CIDR annotations are validated at admission time -- invalid ports or CIDRs are rejected with a webhook error that names the offending annotation, so a typo cannot silently produce a broken iptables plan.

**Kubelet application probes are REWRITTEN, not excluded (issues [#4431](https://github.com/ferrum-edge/ferrum-edge/issues/4431), [#4533](https://github.com/ferrum-edge/ferrum-edge/issues/4533)).** Inbound capture is a protocol-wide catch-all `REDIRECT` to `:15006`, and kubelet dials `podIP:<port>` in plaintext. Under `STRICT` `PeerAuthentication` the mesh inbound listener does not demux plaintext, so a captured probe fails its handshake — a `livenessProbe` then restart-loops the container and a `readinessProbe` / `startupProbe` keeps the pod out of Ready.

Ferrum's answer is Istio's `rewriteAppHTTPProbers` model, **not** a per-port capture exclusion:

- For every application container (`spec.containers`, plus any native sidecar in `spec.initContainers`; the injected `ferrum-edge` / `ferrum-edge-init` containers are skipped) and each of `startupProbe` / `readinessProbe` / `livenessProbe`, an `httpGet`, `tcpSocket`, or `grpc` handler is replaced with `httpGet { path: /app-probe/<container>/<probeField>, port: 15020, scheme: HTTP }`. `initialDelaySeconds`, `periodSeconds`, `timeoutSeconds`, `failureThreshold`, and `successThreshold` are preserved verbatim.
- The ORIGINAL handler — with any named port already resolved against that container's `ports[].name` → `containerPort` — is recorded in the sidecar's `FERRUM_MESH_APP_PROBES` environment variable. In mesh mode the sidecar serves `FERRUM_MESH_APP_PROBE_PORT` (default `15020`) and re-runs the original probe against `127.0.0.1`: same path/port/scheme/`httpHeaders`/`Host` for `httpGet` (success = 2xx/3xx, as for kubelet), a TCP connect for `tcpSocket`, and `grpc.health.v1.Health/Check` with the spec's `service` for `grpc` (success = `SERVING`). The probe's `timeoutSeconds` bounds each request. Outcomes are counted in `ferrum_mesh_app_probe_total{container,probe,outcome}`.
- **`grpc` probes are covered.** A Kubernetes `GRPCAction` has a REQUIRED `port` and kubelet opens an ordinary TCP connection to it, so without the rewrite a gRPC-probed workload hard-fails under `STRICT`.
- `exec` probes are untouched — they run inside the container and are never captured.
- **No application port is excluded from inbound capture.** When at least one probe is rewritten, only TCP `15020` gets an inbound `RETURN`, and that port terminates in the sidecar. Unprobed pods receive no automatic `15020` exclusion, and UDP `15020` remains captured because the probe server is TCP-only. This is the security half of the design: a destination-port-wide `RETURN` for an application port would also let ordinary Service / Pod-IP traffic to that port bypass the sidecar and, with it, mesh mTLS and `mesh_authz`.
- An unresolved or ambiguous named probe port still fails admission rather than being silently left captured.
- Operator annotations and `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` remain additive (TCP and UDP); the sidecar's `15020` exclusion is emitted separately as a TCP-only rule, and only for a pod with at least one probe the sidecar will serve.
- **Opt-out:** `ferrum.io/rewriteAppProbes: "false"` (or Istio's `sidecar.istio.io/rewriteAppHTTPProbers: "false"`) leaves the probes alone AND leaves their ports captured. Under `STRICT` those probes will fail; the supported alternatives are an `exec` probe over loopback or an explicit `excludeInboundPorts` entry, whose bypass consequences the operator then owns.
- **Sidecar topology only.** Ambient / NodeWaypoint workloads get no injected sidecar and no probe rewrite; the node-agent keeps its own kubelet-probe exemption path derived from the enrolled pod spec (see `FERRUM_NODE_AGENT_NODE_IP`).
- **The probe listener has its own connection admission ([#4625](https://github.com/ferrum-edge/ferrum-edge/issues/4625)).** Because `15020` is deliberately the one port excluded from inbound capture, every peer that can reach the Pod IP reaches this listener with no mTLS and no `mesh_authz`, and a valid unauthenticated `GET /app-probe/<container>/<probe>` starts a real loopback probe. Two independent ceilings bound that, both enforced before the work exists:
  - **Connections.** `FERRUM_MESH_APP_PROBE_MAX_CONNECTIONS` (default `128`) with a `FERRUM_MESH_APP_PROBE_MAX_CONNECTIONS_PER_IP` (default `32`) per-source share, acquired in the accept loop **between `accept()` and `spawn`**. An over-limit socket is dropped there — no task, no HTTP state machine, no header buffer — so a partial-header flood cannot hold more than the ceiling for the 5s header timer. The per-source key is the socket peer (the connection is unauthenticated and pre-HTTP at that point, so there is no forwarded identity to trust); kubelet dials from the node, so a flood from any other source cannot take the share kubelet's own probes need. These are sized separately from `FERRUM_MAX_CONNECTIONS` because this is the sidecar's own status port, not a data-plane proxy listener. The permit is held for the whole connection and released by RAII on every exit: clean close, parse error, header timeout, cancellation, and shutdown.
  - **Active probes.** `FERRUM_MESH_APP_PROBE_MAX_ACTIVE_PROBES` (default `16`), taken immediately before `run_probe`. Connection capacity alone does not bound application-facing concurrency: one admitted keep-alive connection can pipeline probe requests, and each accepted one opens a fresh loopback connection into the application container that lives for up to its `timeoutSeconds` (capped at 600s) while the HTTP variant drains the whole response body. Over-budget requests are **shed, not queued** — a bounded `503` with a fixed body and `Connection: close`, recorded as a rejection rather than as a probe outcome, because no probe ran.
  - **Critical overload admits nothing.** The accept loop checks `overload.reject_new_connections` at the same boundary the ordinary proxy accept loop does. Note the consequence: while the sidecar is in critical overload, kubelet's own probes are refused too, so a `livenessProbe` can trip. That is deliberate — the shed happens only at the level where the sidecar is already failing to serve — but operators who would rather restart late than early should size `FERRUM_OVERLOAD_*` accordingly.
  - **Metrics** (fixed cardinality, no source-IP label): `ferrum_mesh_app_probe_active_connections`, `ferrum_mesh_app_probe_max_connections`, `ferrum_mesh_app_probe_max_connections_per_ip`, `ferrum_mesh_app_probe_active_probes`, `ferrum_mesh_app_probe_max_active_probes`, `ferrum_mesh_app_probe_rejected_probes_total`, and `ferrum_mesh_app_probe_rejected_connections_total{reason="overload"|"max_connections"|"max_connections_per_ip"}`. Rejection logs are rate-limited to one summary per second carrying a suppressed count.
  - Below the ceilings, ordinary kubelet probes are unaffected.

**Pod-restart caveat (injector / iptables init container):** annotations consumed by the `injector` mode are evaluated at pod admission time only. Existing pods retain their previous iptables capture rules until restart; bouncing affected workloads is required for previously-ignored annotations to take effect in the init-container path. The eBPF capture path lifts this restriction for `includeOutboundPorts` -- see below.

**eBPF/ambient capture:** the eBPF capture path honors per-pod `includeOutboundPorts` annotations through the `FERRUM_INCLUDE_PORTS` BPF map (keyed by cgroup id). The node-agent parses `traffic.sidecar.istio.io/includeOutboundPorts` / `ferrum.io/includeOutboundPorts` on enrollment via the shared `crate::capture::include_outbound_ports_from_annotations` helper -- exactly the same parser the injector uses for the iptables init container -- and writes a per-cgroup `IncludePortsPolicy` record. The `connect4` / `connect6` BPF programs look up the calling task's cgroup id (`bpf_get_current_cgroup_id`); absent entries fail-open (capture every port that survived the earlier checks), so un-annotated pods are captured on every port. The map supports `INCLUDE_PORTS_MAX` (16) distinct explicit ports per pod after alias merging, sorting, and deduplication. Overflow selects the capture-all policy with a `warn!`, subject to earlier capture exclusions, so ports beyond the cap cannot silently escape capture; it does not abort enrollment. The iptables path has no corresponding port-list cap.

**Leaf-vs-pod cgroup keying:** `bpf_get_current_cgroup_id()` returns the *container leaf* cgroup the connecting task lives in -- a child of the pod cgroup on every Kubernetes cgroup driver (`.../kubepods-pod<uid>.slice/<container>.scope`, `.../pod<uid>/<container-id>`), not the pod cgroup itself. The **`FERRUM_WORKLOAD_IDENTITY`** map (GAP-1b source-pod identity) therefore enrolls the **whole pod cgroup subtree** -- the pod inode plus every descendant container-cgroup inode (`cgroup::collect_cgroup_tree_inodes`) -- and re-walks the subtree on each reconcile so container cgroups that start or restart after initial enrollment (Kubernetes emits many Modified events per pod) are picked up within seconds. Without this the hook's leaf-keyed lookup would always miss and node-waypoint identity resolution would fail closed in real pods. **`FERRUM_INCLUDE_PORTS`** (per-pod `includeOutboundPorts` narrowing) is keyed the same way and enrolls the same subtree, re-walking on every reconcile (like identity) so a container leaf that starts or restarts after the initial pod event still picks up the policy — without that, narrowing would silently never engage for the common case where containers start after the pod cgroup. The per-event `read_dir` is paid only for annotated pods; unannotated pods short-circuit before any walk.

**Mid-life annotation updates:** the node-agent watches Kubernetes Pod `Modified` events (kube-rs `Event::Apply` conflates added + modified) and re-reads `includeOutboundPorts` on every event. A diff against the policy stashed at enrollment time gates the BPF map write so unrelated Modified events (status updates, image-pull progress, condition flips) are skipped without syscalls -- the policy structurally compared is the post-merge, sorted, deduplicated `IncludePortsPolicy`, so reordering ports in the annotation is also a no-op. When the parsed policy differs the node-agent writes the new entry, or removes it when the annotation is stripped entirely. Failures to re-apply (annotation parse error or BPF map write error) keep the previous policy in place rather than silently widening capture; the failure is counted in `ferrum_node_agent_pod_annotation_updates_failed_total` and the successful re-apply count is exposed as `ferrum_node_agent_pod_annotation_updates_applied_total`. Cgroup-id-unavailable retries (Pod object reached the watcher before kubelet finished creating the cgroup) are intentionally not counted as failures because they are routinely observed during early pod startup and are retried on the next Apply event. Opt-in/opt-out label or annotation flips (`ferrum.io/inject` true⇄false, `ferrum.io/mesh` enabled⇄disabled) trigger enrollment or un-enrollment on the next Apply event. **Long-lived flow caveat:** the BPF programs hook `connect(2)`, so a policy change applies only to *new* outbound connections; established TCP flows continue using the redirect chosen at their original connect call and are unaffected until they close and reconnect.

**IPv6 CIDRs:** `includeOutboundIPRanges` / `excludeOutboundIPRanges` accept IPv6 CIDR literals (e.g. `fd00::/8`) and `IptablesPlan::for_config` partitions rules by address family. Any IPv6 CIDR in either the include or exclude list activates the IPv6 address family: outbound IPv6 rules are rendered for the configured include/exclude lists, and inbound IPv6 capture emits the same default redirect/exclusion shape as IPv4. If explicit include ports are set, port REDIRECT rules are emitted for IPv6 too once that family is active; without an IPv6 CIDR, include-port rules only render in the IPv4 plan. IPv4 rules are emitted through `iptables`; IPv6 rules are emitted through `ip6tables`. `FERRUM_MESH_IP6TABLES_ENABLED=auto` probes for `ip6tables` and skips only the IPv6 rule block when the binary is absent, so legacy IPv4-only nodes do not crash-loop. Set it to `true` to require `ip6tables` whenever IPv6 rules are present; this is all-or-nothing, so a missing `ip6tables` binary fails before any IPv4 rules are applied. Set it to `false` for permanent IPv4-only capture. The injector init-container script and node-agent iptables fallback both render from the same `IptablesPlan`, so their IPv6 wrapping semantics stay aligned.

**Dual-stack capture listeners (issue [#4271](https://github.com/ferrum-edge/ferrum-edge/issues/4271)).** The `iptables` and `ip6tables` REDIRECT rules point at the SAME ports (`15006` inbound, `15001` outbound), so a listener set that serves only one address family black-holes the other with `ECONNREFUSED` while the pod reports ready. The Sidecar listener plan therefore derives its addresses from whether IPv6 capture rules exist (`FERRUM_MESH_CAPTURE_IPV6_ENABLED`, derived from `FERRUM_MESH_IP6TABLES_ENABLED` plus the include/exclude CIDR families when unset, and set explicitly by the injector whenever the rendered init-container plan contains `ip6tables` commands). An explicit `false` is rejected if those local rule inputs still require IPv6, because a listener-only override must not leave live `ip6tables` REDIRECTs without a consumer:

- IPv6 capture inactive: exactly the configured address, unchanged.
- A **wildcard** capture address (`0.0.0.0` / `::`, the inbound default): ONE listener on the dual-stack `[::]` wildcard with `IPV6_V6ONLY` explicitly disabled, so a single socket claims the native-v6 and the v4-mapped halves. `REDIRECT` in `PREROUTING` rewrites the destination to the receiving interface's own address, which is why inbound capture must be a wildcard bind; two sockets are not an option because a dual-stack `[::]` bind already owns the v4 wildcard on that port. The bind downgrades to `0.0.0.0` **only** when IPv6 is genuinely unavailable on the host (`EAFNOSUPPORT` / `EADDRNOTAVAIL` / `EPROTONOSUPPORT`), never on `EADDRINUSE` — falling back on a real conflict would report the listener started while IPv6 capture is black-holed.
- A **loopback** capture address (`127.0.0.1`, the outbound default): TWO listeners, `127.0.0.1` and `[::1]`. `REDIRECT` in `OUTPUT` sends locally generated traffic to `127.0.0.1` for IPv4 and `::1` for IPv6, and unlike the wildcard a dual-stack socket bound to `[::1]` does not receive IPv4 loopback traffic. This keeps outbound capture loopback-only rather than widening it to a network-reachable wildcard.
- Any other specific literal is a **startup error** naming the offending variable, because there is no defensible way to guess the workload's address in the other family.

A dual-stack accept reports an IPv4 connection's local address as the IPv4-mapped `::ffff:a.b.c.d`. `original_dst_from_raw_fd` folds that back to IPv4 before choosing the conntrack socket option, so it issues `SOL_IP`/`SO_ORIGINAL_DST` (not `SOL_IPV6`/`IP6T_SO_ORIGINAL_DST`, which answers `ENOENT` for an IPv4 flow) and recovers the real pre-NAT IPv4 destination. Native IPv6 keeps the `IP6T_SO_ORIGINAL_DST` path. Losing that value is not cosmetic: original destination drives multi-port service disambiguation and pre-handshake `PeerAuthentication.portLevelMtls` selection.

**Loopback / pod-self RETURN (issue [#4276](https://github.com/ferrum-edge/ferrum-edge/issues/4276)).** `nat FERRUM_MESH_OUTBOUND` leads with `-m addrtype --dst-type LOCAL -j RETURN`, emitted for both `iptables` and `ip6tables` and ahead of every REDIRECT in the chain. Setup deletes any prior copy and inserts the rule at position 1, so this ordering remains true when a surviving chain is reconciled rather than only when it is created fresh. `nat OUTPUT` is traversed by locally generated packets, so without it the shipped catch-all `-p tcp -d 0.0.0.0/0 -j REDIRECT --to-ports 15001` hairpins every intra-pod `127.0.0.1` connection — the universal multi-container pattern (`app` dialing a local `postgres`/`redis`) — into the mesh outbound proxy, where it matches no mesh route and is denied outright under `outboundTrafficPolicy: REGISTRY_ONLY`. In the pod netns the `LOCAL` address type covers both loopback and the pod's own IP in one family-agnostic rule; this is the same discriminator the UDP sibling chain uses (`-m addrtype ! --dst-type LOCAL` for its complementary egress scope) and it is gated on pod-netns rendering for the same reason, since pod IPs are FORWARDED rather than `LOCAL` in the host namespace.

### SPIFFE ID Derivation

The injector derives the workload SPIFFE ID from the pod's service account:

```
spiffe://{TRUST_DOMAIN}/ns/{NAMESPACE}/sa/{SERVICE_ACCOUNT}
```

`FERRUM_INJECTOR_TRUST_DOMAIN` (default `cluster.local`) sets the trust domain.

### Sidecar Container

The injected Ferrum proxy is a **Kubernetes native sidecar**: an `initContainers` entry named `ferrum-edge` with `restartPolicy: Always`. Native sidecars start before later init containers and application containers, do not block Job completion, and keep running while the workload drains. The iptables capture init (`ferrum-edge-init`, run-once) is inserted immediately after Ferrum so capture rules are installed only once the proxy's startup probe has succeeded.

That ordering is load-bearing. Mesh mode waits for the first valid control-plane slice and then binds capture listeners before `/health` reports ready. The injected startup and readiness probes are exec checks of `ferrum-edge health` (admin `/health` on loopback port 9000, **not** `/live`), so later containers — and the iptables init — wait until Ferrum is actually serving. `/live` would succeed as soon as the admin listener is up, which is too early.

The container runs `ferrum-edge run` with environment variables:

- `FERRUM_MODE=mesh`
- `FERRUM_NAMESPACE={pod_namespace}`
- `FERRUM_MESH_TOPOLOGY=sidecar`
- `FERRUM_MESH_CAPTURE_MODE={capture_mode}`
- `FERRUM_MESH_WORKLOAD_SPIFFE_ID=spiffe://...`
- CP connection variables forwarded from `FERRUM_DP_CP_GRPC_URLS`, TLS paths, etc.
- `FERRUM_CP_DP_GRPC_JWT_SECRET` via `valueFrom.secretKeyRef` (never plaintext)

The container runs as `FERRUM_MESH_PROXY_UID` (default 1337) with `allowPrivilegeEscalation: false`.

A pod with no application containers is refused: Kubernetes requires at least one non-sidecar container, and emitting only a native sidecar would be rejected by the apiserver. If the webhook cannot build a valid patch, it fails the admission request with a named error rather than emitting a broken pod.

Existing pods that still carry Ferrum as an ordinary `spec.containers` entry must be recreated. The webhook refuses to mix that legacy shape with the native sidecar.

### Capture Modes

`FERRUM_MESH_CAPTURE_MODE` controls traffic interception:

| Mode | Description |
|---|---|
| `explicit` (default) | No automatic capture; applications must explicitly route to the proxy |
| `iptables` | Inject init container with `NET_ADMIN`/`NET_RAW` capabilities that sets up iptables rules to redirect traffic through the sidecar (inbound to 15006, outbound to 15001) |
| `ebpf` | eBPF-based capture handled by a node-level agent (requires kernel 5.7+). The injector does not inject a privileged init container for this mode -- the node agent's DaemonSet manages eBPF program attachment. Capture planning infrastructure (`EbpfPlan` with iptables fallback for pre-5.7 kernels) is available in `src/capture/mod.rs` for the node agent path. **Build requirement:** real eBPF attachment needs a binary built with the Cargo `ebpf` feature (`cargo build --features ebpf`, Linux only; Docker `--target runtime-ebpf --build-arg FEATURES=cloud-secrets,ebpf`). The **default published image has no aya loader**: an eBPF-mode node-agent built without the feature refuses to start (`capture_state="unavailable"`, `ferrum_mesh_node_topology_degraded{reason="ebpf_feature_disabled"}`) rather than attaching nothing — see [Maturity and Support Status](#maturity-and-support-status) |

#### UDP TPROXY capture

TCP capture uses `nat` `REDIRECT` plus `SO_ORIGINAL_DST`, which has no UDP equivalent, so
captured UDP uses **TPROXY** in the `mangle` table: the datagram reaches a transparent
listener with its destination intact, and the listener recovers the original destination
per datagram from `IP_RECVORIGDSTADDR`. The full rule-ordering, routing, handshake, and
gate reference is in [mesh_udp_capture.md](mesh_udp_capture.md).

**Enablement.** `FERRUM_MESH_CAPTURE_UDP_ENABLED` (default `false`; when off, no `mangle`,
TPROXY, or routing rules are emitted and no listener is bound),
`FERRUM_MESH_CAPTURE_UDP_PORT` (default `15011`, distinct from the TCP outbound port), and
`FERRUM_MESH_TPROXY_MARK` (default `0x733`, deliberately not Istio's `0x539`). A malformed
UDP capture variable aborts mesh startup on a capture-relay topology. The capture listener
is emitted only for the two topologies that relay captured UDP — Ambient (HBONE) and
Sidecar (mesh-mTLS); any other topology with the flag set logs a one-time warning and
leaves UDP un-captured rather than captured-then-dropped.

| Placement | Who installs rules | Direction | Requirements | Owned state |
|---|---|---|---|---|
| **Sidecar** (injector, pod netns) | Injector init container; the injector also sets the sidecar's UDP env and `NET_ADMIN` from one switch | Outbound **and inbound** — direct inbound UDP to the app is captured and dropped (fail closed) unless the port is excluded via `excludeInboundPorts` / `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` | `NET_ADMIN`; image with `sh`, `ip`, `iptables` (`-ebpf-tools`) | `FERRUM_MESH_UDP_OUTBOUND` / `_INBOUND` / `_OUTPUT_MARK` / `_REINJECT`, table `33133`, `ip rule` priority `100` |
| **Ambient per-pod-netns** (default, #2013) | Mesh proxy, inside each enrolled pod's netns via `setns` | **Outbound only** (an inbound chain would drop the relay's own delivery) | Node-agent pod registry; proxy image with the capture tools and setns/`NET_ADMIN` | Same chains (no inbound), table `33133`, priority `100` |
| **Ambient host-netns** (#3288, `FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED=true`) | Mesh proxy in its own netns, interface-scoped | Outbound only, attributed by ingress interface | `NET_ADMIN`; a CNI with per-pod host interfaces; see [node_agent.md](node_agent.md#host-network-udp-capture-placement-issue-3288) | `FERRUM_MESH_UDP_HOST`, table `33135`, priority `101` |

The node-agent's host-netns iptables fallback emits **no** UDP rules, and eBPF capture is
TCP-only; eBPF UDP capture (#1803) is a non-goal.

**Datapath.** Each captured datagram's original destination must match a declared
`(service VIP, UDP service port)`; a match is relayed over a `udp`-marked HTTP/2 CONNECT
(Ambient → HBONE `:15008`, Sidecar → mesh-mTLS `:15006`, identity-pinned) as
length-delimited datagrams (`[u16 big-endian len][payload]`). Replies are sent from a
per-session transparent socket bound to the original destination, so they appear sourced
from the VIP:port the pod dialed. The destination terminator unframes the tunnel into a
local `UdpSocket` behind the [Inbound Relay Destination Guard](#inbound-relay-destination-guard).
A datagram matching no declared mesh UDP destination is dropped.

**Fail-closed guarantees.**

- No plaintext or alternate-hop fallback: every dial error ends the session; a missing
  gateway SVID or pinned peer refuses the dial.
- Unknown, future, or malformed CONNECT markers are rejected (405); a destination without
  UDP relay support 404s a `udp` CONNECT.
- Before binding, each Ambient placement installs its own fail-closed DROP guard —
  the per-pod-netns producer a `mangle OUTPUT` guard inside each pod netns, the
  host-netns producer an interface-scoped `mangle PREROUTING` guard (it installs no
  OUTPUT chain) — and pod UDP stays blocked by the node-agent's BPF gate until the producer publishes
  `.udp-ready/<pod_uid>`; a pod leaving capture keeps its DROP posture until the
  node-agent acknowledges the closed gate.
- Startup fails closed on an invalid capture config, a runtime image missing
  `sh`/`ip`/`iptables`, or a required IPv6 `ip6tables` failure. Routing is installed
  before the `PREROUTING` jumps, so a routing failure never leaves live chains with no
  policy route.

**Session bounds and diagnostics.** Sessions reuse the plain UDP proxy bounds
(`FERRUM_UDP_MAX_SESSIONS` — shared node-wide across Ambient producers —,
`FERRUM_UDP_CLEANUP_INTERVAL_SECONDS`, `FERRUM_UDP_RECVMMSG_BATCH_SIZE`) with
drop-on-full backpressure. The destination relay records
`hbone.udp.termination_reason` (`tunnel_closed` and `idle_timeout` end with `END_STREAM`;
`revoked`, socket errors, and write stalls reset with `RST_STREAM(CONNECT_ERROR)`);
revocations count in `ferrum_mesh_hbone_tunnel_revocations_total`, other failures in
`ferrum_mesh_hbone_relay_failures_total`.

**DTLS** rides the same path as `protocol: UDP` and is relayed opaquely — never
terminated, parsed, or SNI-routed. External DTLS egress via the EgressGateway is out of
scope.

**Cleanup ownership.** Teardown removes only exact Ferrum-owned objects (chains by name,
`ip rule del priority 100 lookup 33133`, the exact `local` route; host-netns:
priority `101` / table `33135`), so it is mark-independent and never touches a
co-resident Istio table (`133`). With Ambient UDP capture disabled, mesh startup still
runs a cleanup manager over the registry so stale rules from a prior enabled run are
removed after the node-agent acknowledges the closed gate; without that acknowledgement
the stale rules are kept fail-closed and retried. Placement changes and restarts follow
[node_agent.md → Ambient UDP upgrade notes](node_agent.md#ambient-udp-upgrade-notes).

## Control Plane Integration

### MeshGrpcServer

The `MeshConfigSync.MeshSubscribe` streaming RPC is served by `MeshGrpcServer` in `src/grpc/mesh_server.rs`. It runs on the Control Plane alongside the regular `ConfigSync` service.

- **JWT authentication** on every subscribe request.
- **Finite stream authorization**: the CP binds each admitted stream to the exact verified credential and to a monotonic deadline derived from the verified JWT `exp` plus the accepted 60-second leeway. The independent `FERRUM_CP_GRPC_MAX_STREAM_LIFETIME_SECONDS` ceiling applies as well. Heartbeats and slice broadcasts never renew either deadline. A trust-bundle reload closes only streams whose accepted credential was removed; overlapping retained credentials continue until expiry or the server ceiling. Local and cross-cluster subscriptions share this enforcement, and clients reconnect with bounded backoff while rereading/reminting credentials.
- **Namespace validation**: the requested mesh namespace must be covered by the CP scope (`FERRUM_CP_NAMESPACES`, or `FERRUM_NAMESPACE` in single-namespace mode). When `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true`, the mesh node JWT must also carry an `ns` claim authorising that namespace. Requests outside the CP scope fail with `FAILED_PRECONDITION`; claim mismatches fail with `PERMISSION_DENIED`.
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

Generated targets are tagged with `mesh.spiffe_id`, `mesh.namespace`, `mesh.service`, `mesh.trust_domain`, plus the **destination topology's transport tag** selected by `service_discovery.mesh.topology`:

- `topology: ambient` (default) — same-cluster/local targets carry `mesh.hbone=true` and dispatch through the HBONE outbound pool (HTTP/2 CONNECT over SVID mTLS to the peer's `:15008` listener). This is the right choice when the destination mesh runs the Ambient/waypoint topology. Remote-cluster workloads use the same east-west shape as mesh-mode Ambient when the snapshot carries `mesh.multi_cluster`, the upstream's selected service port is an **effective HTTP-family port** (any port, not just the first — multi-port east-west, issue #2010), and an east-west gateway is declared for the workload's network (or a catch-all gateway applies): one target per remote pod, synthetic host identity scoped by gateway endpoint + pod address, `mesh.hbone_authority_host=<remote pod addr>` as the inner CONNECT authority, `mesh.hbone_dial_host` / `mesh.hbone_port` as the gateway dial override, `mesh.eastwest_sni=<the port's p<port>.<fqdn> alias>` for SNI passthrough, `mesh.remote=true`, and no pinned `mesh.spiffe_id` (remote trust-domain verification only). Flat-network compatibility is retained only when no gateway is declared for the workload network and no applicable catch-all gateway (a candidate whose `sni_hosts` claim the base FQDN **or** the dialed per-port alias, plus a trust-domain match, for the destination) exists; once a gateway is declared for the workload's network — or an applicable catch-all exists — SNI/trust-domain/port mismatches skip the remote target fail-closed instead of falling back to a direct pod dial. A catch-all gateway that is not a candidate (its `sni_hosts`/trust domain cannot route this destination) does not suppress the fallback; an exact-network declaration is authoritative even when it is not a candidate.
- `topology: sidecar` — targets carry `mesh.mtls=true` and dispatch through the Sidecar SVID-mTLS pool (plain HTTP/2 over mutual TLS to the peer sidecar's `:15006` inbound listener). Every sidecar target also carries `mesh.mtls_authority_host` (the destination service's `<name>.<namespace>.svc` host variant): a north-south gateway's client `Host` is typically a public hostname the destination sidecar's materialized inbound routes would 404, so dispatch forces this service host as the request `:authority` (the original client `Host` rides `x-forwarded-host`). When the destination service declares **more than one** effective HTTP-family port (`protocol_overrides` applied — the same `service_http_family_ports` predicate mesh-mode materialization uses), each target additionally carries `mesh.mtls_authority_port` (the owning Service port) so the peer's per-port inbound siblings can disambiguate the direct `:15006` dial — the same contract mesh-mode Sidecar egress applies. **Remote-cluster workloads are never published as direct `remote-pod:15006` dials on the sidecar path** — such a dial with a pinned pod SPIFFE would fail in any multi-network mesh while looking like a routable failover target. Instead, when the snapshot carries `mesh.multi_cluster` and the upstream's selected service port is an **effective HTTP-family port** (any port, not just the first — multi-port east-west, issue #2010), the provider bridges them east-west exactly like mesh-mode egress — through the same shared `append_cross_cluster_mesh_targets` core, not a fork: reachable remote workloads (≥1 address, resolvable selected-port `targetPort`) are grouped per `(network, trust_domain)` and each group emits **one failover target at its remote east-west gateway endpoint** (resolved from `mesh.multi_cluster.east_west_gateways` with the same fail-closed network/SNI/trust-domain selection — the gateway is SELECTED by the base service FQDN **or** the per-port alias being dialed), tagged `mesh.cross_cluster=true` + `mesh.eastwest_sni=<the port's p<port>.<fqdn> alias>` + `mesh.mtls_port=<gateway port>` + `mesh.remote=true` and carrying **no pinned pod SPIFFE** (trust-domain-only verification). The SD bridge adds one tag on top of the materializer's shape: `mesh.mtls_authority_host` (`<name>.<namespace>.svc`), because the destination sidecar routes the inner mesh-mTLS request by `Host` — mesh-mode egress relies on the client `Host` already being the service host, which a north-south gateway's public client `Host` is not (no `mesh.mtls_authority_port` is stamped: cross-cluster traffic reaches the destination via its app port + inbound capture, which disambiguates multi-port by orig-dst). The east-west SNI alias is synthesized as `p<port>.{service}.{namespace}.svc.<FERRUM_MESH_CLUSTER_DOMAIN>` (default `cluster.local`), and the load balancer treats `mesh.cross_cluster` targets as always-failover local-first. The SD provider is HTTP-family dispatch by design, so non-HTTP-family selected ports remain outside that bridge; mesh-mode raw-TCP/UDP capture uses the separate L4 materializers described above. A snapshot without `mesh.multi_cluster`, or a remote group with no matching east-west gateway, stays skipped fail-closed.

The two transports are **not interchangeable**: mesh transports are per-topology (see [Gateway-to-Mesh Bridge](#gateway-to-mesh-bridge)), and a Sidecar peer has no HBONE listener — an `ambient`-topology upstream pointed at sidecar workloads fails closed with a `502` at dispatch rather than silently downgrading. Configure `topology` to match the destination mesh.

**Active health checks cannot probe cross-cluster gateway-routed targets**: the health checker dials plain HTTP/TCP with no cross-cluster awareness, and the bridged identities (the SNI-passthrough east-west gateway endpoint on the sidecar path, the never-dialed synthetic `mesh-xc-hbone|…` host on the ambient path) are unreachable to it, so an upstream with an active `health_check` would mark its remote failover targets unhealthy and lose cross-cluster failover. Scope active health checks to upstreams whose targets are directly probeable (or rely on passive health) when the provider bridges remote workloads.

```yaml
upstreams:
  - id: reviews-mesh
    service_discovery:
      provider: mesh
      mesh:
        service_name: reviews
        port: 9080
        topology: sidecar   # destination mesh runs the Sidecar topology
```

This keeps the north-south gateway on the same discovery model as mesh mode while dispatching over the same per-topology transport contract the mesh-mode materializer emits.

### Auto-Injected Plugins

Mesh mode automatically injects these global plugins with reserved IDs:

| Plugin ID | Plugin Type | Priority | Purpose |
|---|---|---|---|
| `__mesh_spiffe_identity` | `spiffe_identity` | 940 | Extract peer SPIFFE ID from TLS/DTLS client certs |
| `__mesh_authz` | `mesh_authz` | 2075 | Evaluate MeshPolicy authorization rules |
| `__mesh_workload_metrics` | `workload_metrics` | (default) | Istio/GAMMA RED metric labels from SPIFFE/HBONE identity |
| `__mesh_request_auth` | `jwks_auth` | (default) | JWT validation from MeshRequestAuthentication rules |
| `__mesh_access_log` | `stdout_logging` | (default) | Access logging with optional Telemetry API filters |

Reserved mesh-managed plugin IDs are updated in place on each slice apply. If a prepared `GatewayConfig` already contains an operator-managed global plugin of the same plugin type but a different ID, that operator plugin takes precedence and the corresponding mesh injection is suppressed. Native/xDS `MeshSlice` feeds do not transport operator `plugin_configs`; this override hook applies only to prepared configs that enter mesh preparation with plugin configs already present. See [plugin_execution_order.md](plugin_execution_order.md) for the full lifecycle phase matrix.

## Gateway-to-Mesh Bridge

Gateway traffic modes (`database`, `file`, `dp`) can route traffic into the mesh via the gateway-to-mesh bridge. This enables a Ferrum gateway operating as an ingress or API gateway to forward requests to mesh workloads over the destination topology's secured transport with full SPIFFE mTLS: **HBONE** (`:15008`) for Ambient/waypoint destinations, **plain SVID-mTLS HTTP/2** (`:15006`) for Sidecar destinations. The transport is selected per upstream only by `service_discovery.mesh.topology` (operator-authored targets cannot carry reserved `mesh.*` tags); it must match the destination mesh's topology — the transports are not interchangeable, and a mismatch fails closed at dispatch. `cp` mode does not proxy client traffic; it distributes mesh snapshots and trust bundles to DPs that do (see Trust Bundle Distribution below).

### Trust Bundle Distribution

The Control Plane distributes gateway SPIFFE trust bundles to Data Planes via a `trust_bundles_json` side channel on the `ConfigUpdate` proto message. DPs hot-swap received bundles into the gateway SVID identity slot, enabling mutual TLS with mesh sidecars without requiring the DP to independently obtain certificates.

### Live Trust Withdrawal

Withdrawing a gateway trust authority retires **connection ownership**, not only pool
discoverability. Clearing the HBONE / mesh-mTLS pool maps stops future lookups from
finding a connection, but an already-issued `H2ConnectTunnel` owns its HTTP/2 streams
directly, a cloned sender can open fresh streams on the established TLS session, and the
one-connection-per-session WebSocket / datagram / raw-CONNECT bridges are never in the
map at all. Every one of those would otherwise keep carrying traffic authenticated under
the withdrawn root until its own EOF or idle timeout.

Every gateway-to-mesh TLS transport — pooled and 1:1 alike — registers with the
per-process gateway trust registry (`src/proxy/mesh_trust_registry.rs`) when its
connection driver is spawned, under the accepted trust generation, and hands its driver a
retirement gate that travels with every cloned sender and the tunnel rather than living
in the pool. Pooled mesh-mTLS checkout returns that gated handle; `ready` and
`send_request` consult it synchronously before a new stream is queued.

When an accepted `Replace` or `Clear` removes any authority from the **effective**
gateway trust view (the material `build_spiffe_outbound_config` verifies peers against —
so a `Clear` is judged against the startup material it restores), the centralized
`ProxyState::commit_gateway_trust_generation_locked` publication runs one ordered
sequence:

1. fence new gateway-to-mesh request admission;
2. install the accepted trust material into every verifier source/slot it governs;
3. advance the ownership-registry generation, mark the outgoing generation retired, and
   synchronously signal every transport registered under it;
4. advance the backend security generation, drain its TLS-config caches and
   generation-keyed pools, clear the HBONE and mesh-mTLS pool maps, and publish the
   accepted gateway trust as live, reopening request admission.

Signalling is synchronous — the gate is set before the ownership-registry fence is
released — and the outer request-admission fence remains closed until material, caches,
and pool maps all reflect the accepted generation. Completing
the teardown (dropping the HTTP/2 connection, which closes the socket and errors every
stream on it) is a bounded task wake, not a drain timer: it does not wait on peer behaviour,
backend liveness, or `FERRUM_SHUTDOWN_DRAIN_SECONDS`. A retired tunnel's next read or write
fails with a fixed `gateway trust authority withdrawn` error that names no trust material,
subject, key id, fingerprint, path, or peer identity. A retired pooled mesh-mTLS sender
refuses `ready` / `send_request` synchronously by consulting the same gate, even if the
underlying HTTP/2 sender has not yet observed connection close.

A **source SVID rotation** takes the same path. When no CP/database override masks the
source trust, `ProxyState::install_gateway_runtime_svid_bundle` compares the rotated
bundle's anchors against the effective view and, if the rotation DROPS one, fences,
installs, retires the ownership generation, and advances the backend security generation
inside the same publication — so a shrinking SPIRE/file/CA-backend trust bundle cannot be
deferred behind `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS`. That rotation publishes the
backend security generation itself, so the ordinary post-install revision bump is
suppressed rather than applied twice. An additive or identity-only rotation
keeps its configured drain window and churns neither the registry nor the generation.
A masked rotation (an override installed) changes no effective authority and so is a
no-op here as well. Both replacement shapes report the same closed
`replace_removed_authority` reason, because they are indistinguishable to the live
verifier.

A dial that completes after the publication under the outgoing generation is refused at
registration (`HbonePoolError::TrustWithdrawn`) and is neither pooled nor returned; the
ticket/creation-race mechanics are documented in `src/proxy/mesh_trust_registry.rs`.

Nothing churns without a withdrawal. An identical `Replace`, an additive overlap
(`before ⊆ after`), an `Unchanged` side channel, a `Clear` with no installed override, a
`Clear` whose restored startup material still carries every authority, and every rejected
candidate leave the generation, the registry, and every live session untouched — a rejected
candidate never reaches the publication path at all, so it keeps the last-good generation
and its sessions. A JWT authority swapped in place under one `kid` **is** a withdrawal.

Observability is four fixed-cardinality families over closed label sets
(`ferrum_gateway_trust_accepted_generation`, `ferrum_gateway_trust_withdrawals_total{reason}`,
`ferrum_gateway_trust_retired_transports_total{transport}`,
`ferrum_gateway_trust_admission_refusals_total{transport}`; `reason` ∈
`replace_removed_authority`, `cleared_override`; `transport` ∈ `hbone`, `mesh_mtls`). The
generation is a local monotonic counter that identifies no authority, and no metric label,
sample value, log field, or client-visible error carries trust material.

### HBONE Outbound Pool

When an upstream target is tagged with `mesh.hbone=true` metadata, the gateway routes requests through an HBONE HTTP/2 CONNECT pool (`HboneConnectionPool`) instead of direct HTTP. The pool uses the gateway's SPIFFE identity for mTLS and keys connections by SVID fingerprint so certificate rotation triggers fresh connections. DNS resolution uses the shared `DnsCacheResolver`. A target may optionally carry `mesh.hbone_dial_host` to separate the outer TCP/TLS destination from the inner CONNECT authority host, and `mesh.hbone_peer_spiffe_id` to pin a waypoint/relay peer identity while leaving `mesh.spiffe_id` as destination workload metadata.

On HBONE connect failure or malformed HBONE target metadata, tagged dispatch fails closed with an HBONE error response instead of falling back to plain HTTP.

This pool is the OUTER transport only. The application connection the gateway runs *inside* a CONNECT tunnel is pooled separately and under a stricter contract — see [HBONE Inner Application Connection Reuse](#hbone-inner-application-connection-reuse).

**Response header-block bound.** The outbound HBONE HTTP/2 client advertises a receive-side `SETTINGS_MAX_HEADER_LIST_SIZE` derived from `FERRUM_MAX_HEADER_SIZE_BYTES` (floored at 16 KiB), so a peer holding a valid SVID cannot answer a CONNECT with a multi-megabyte HEADERS/CONTINUATION block. A pool built without that policy still defaults to 16 KiB — parity with hyper's own default, which is what every other backend transport rides — never the raw `h2` crate's 16 MiB. An ordinary over-limit response below the vendored h2 abuse threshold refuses that CONNECT stream while keeping the tunnel connection up. A decoded header list strictly greater than four times the configured receive limit is treated as abuse and can close the connection with `ENHANCE_YOUR_CALM`, affecting sibling streams. The Sidecar mesh-mTLS CONNECT pool shares the same dial path and bound.

**Pool width follows open tunnels and the peer's stream cap** (issue #5465). Each HBONE destination starts on one HTTP/2 connection. Every pooled CONNECT — an HTTP-family request tunnel or a raw-TCP session — is counted against its connection for as long as the tunnel lives, and each connection remembers the peer's `SETTINGS_MAX_CONCURRENT_STREAMS` (learned from its CONNECT responses). A new tunnel goes to the connection with the fewest open streams that still has room under its peer's cap; ties go to the oldest connection so extra connections fall idle and are pruned by the normal idle timeout. The pool dials another connection, up to `FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST`, when the least-loaded connection already carries eight or more open tunnels (opportunistically, never queueing behind another dial, with a 10 s back-off after a failed growth dial) or when every connection is at the peer's stream cap (coalesced with every other caller that hit the same wall). Growth takes the same DestinationRule `maxConnections` admission, SVID/CRL pinning and trust-retirement checks as a cold-start dial. If every connection is saturated and the pool is already at its configured width, the tunnel waits on the least-loaded connection for a sibling stream to close, bounded by the destination's connect timeout, so a burst above `cap × width` drains rather than failing.

### Sidecar SVID-mTLS Outbound Pool

When an upstream target is tagged with `mesh.mtls=true` metadata (a Sidecar-topology destination), the gateway routes requests through the Sidecar mesh-mTLS pool (`MeshMtlsConnectionPool`) — plain HTTP/2 over mutual TLS to the peer sidecar's `:15006` inbound listener — using the same gateway SPIFFE identity and SVID-fingerprint pool keying as HBONE. The target's `mesh.spiffe_id` pins the expected peer identity: the destination sidecar's server SVID URI SAN must equal it, so trust-domain membership alone is not enough. A `mesh.mtls`-tagged target that cannot dispatch over the secured transport (missing gateway SVID, missing pinned peer) fails closed with a `502` instead of falling back to plain HTTP.

**Pool width follows measured load** (issue #5043). Each destination starts on one HTTP/2 connection and stays there while traffic is light: a single connection to one peer sidecar is a fixed ceiling of roughly 70k requests/s or 2.5 GB/s no matter how many streams it multiplexes, but it is also the cheapest path per request, so the pool only dials another connection while its least-loaded connection already has eight or more requests awaiting response heads and the pool is still below `FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST` (default: CPU cores clamped to 2–8). Requests are sent on the connection with the fewest in-flight response heads; ties go to the oldest connection, so once a burst ends the extra connections fall idle and are pruned by the normal idle timeout. Growth never queues behind an in-progress dial and never bypasses DestinationRule `maxConnections`: it takes the same admission, SVID/CRL pinning and trust-retirement checks as a cold-start dial, and a growth dial that fails backs off for 10 s while requests keep flowing on the connections that exist. Sequential or lightly concurrent traffic never widens the pool.

**Failure labeling is topology-specific** (issue #3927). This pool and the HBONE pool share one error type because they share every failure shape, but they do not share their client-visible wording: a Sidecar dial opens no HTTP/2 CONNECT tunnel, so its refusals read `{"error":"Sidecar mTLS backend unavailable: <reason>"}` and never claim HBONE, while Ambient/waypoint CONNECT-over-`:15008` failures keep `{"error":"HBONE backend unavailable: <reason>"}`. `<reason>` is a fixed phrase selected from the failure's kind (`TLS handshake failed`, `TCP connect failed`, `connect timed out`, `gateway identity unavailable`, `gateway trust authority withdrawn`, …) — never an interpolated peer address, certificate subject, SPIFFE ID, trust root, or raw verifier string, and none of those values are interpolated into the operator `error!` record either (`error_kind`, `error_phase`, and CONNECT `peer_status` only). The sole exception is an HBONE CONNECT refusal, which appends the peer's own admission status (`tunnel rejected by peer with status 403`) so a destination policy denial stays distinguishable from any other tunnel refusal; a status code is not identity, address, or verifier material. Error classification, the pre/post-wire retry boundary, circuit-breaker and passive-health accounting, and the transaction-log `error_class` are identical on both transports and identical across the H1, H2, and H3 frontends; only the noun differs. gRPC-flavored dispatch on the Sidecar path uses the matching Trailers-Only `UNAVAILABLE` with `grpc-message: sidecar mTLS backend unavailable`.

### Mesh Service Discovery

A `service_discovery.provider: mesh` option resolves upstream targets from CP-delivered mesh service and workload snapshots. The provider maps workload addresses and ports into upstream targets with SPIFFE identity tags plus the configured topology's transport tag (`mesh.hbone` for `ambient`, `mesh.mtls` for `sidecar` — see [Gateway Mesh Service Discovery](#gateway-mesh-service-discovery)), enabling the matching outbound pool to route transparently. Target lists refresh on the provider's **poll interval** (`poll_interval_seconds`, default 30s): each poll reads the *current* CP-delivered snapshot, so a mesh update is picked up within one poll interval — a CP push does not refresh targets immediately. Lower the interval for tighter failover/scale-up latency.

Identity baggage from the client request is stripped from tunneled inner HBONE requests to prevent identity spoofing across the gateway boundary.

## Mesh Identity

### SPIRE Agent CA

`FERRUM_MESH_CA_BACKEND=spire_agent` delegates SVID issuance to a SPIRE Agent via the SPIFFE Workload API. The mesh data plane connects to the SPIRE Agent socket, waits for an initial X.509-SVID before binding listeners, and installs the pushed SVID into the same gateway SVID slot used by outbound HBONE/SVID-mTLS and inbound SPIFFE peer verification. The returned SPIFFE ID must match `FERRUM_MESH_WORKLOAD_SPIFFE_ID`.

The backend is configured with `FERRUM_MESH_CA_BACKEND` (`spire_agent`, alias `spire`), `FERRUM_MESH_SPIRE_AGENT_SOCKET`, and `FERRUM_MESH_WORKLOAD_SPIFFE_ID` (required when `spire_agent` or `internal` is the identity source); see [configuration.md → Mesh Runtime](configuration.md#mesh-runtime) for defaults. Under SPIRE the SVID lifetime comes from the SPIRE registration entry; `FERRUM_MESH_CERT_TTL_SECONDS` applies only to the `internal` CA.

The SPIRE backend is the recommended production path for mesh identity. `internal` is intended for development and testing only -- it generates a self-signed root CA at startup with no external trust anchor. Explicit `FERRUM_GATEWAY_SVID_*` source material takes precedence over `FERRUM_MESH_CA_BACKEND`; when both are configured Ferrum uses the configured SVID and does not start automatic CA-backed issuance.

### Workload API JWT-SVID

Ferrum's Workload API serves JWT-SVIDs **when the selected CA backend owns a JWT signing authority**, and fails closed with gRPC `UNIMPLEMENTED` when it does not. Backend support:

| `FERRUM_MESH_CA_BACKEND` | Can Ferrum serve a Workload API on it? | `FetchJWTSVID` | `FetchJWTBundles` | `ValidateJWTSVID` |
|---|---|---|---|---|
| `internal` | ✅ yes | ✅ mint | ✅ stream | ✅ validate |
| `spire` | ❌ **refused at startup** (see the boundary below) | — | — | — |
| Vault PKI / cert-manager scaffolds | ❌ no CA backend selection exists for them | — | — | — |

Under `spire`, the active mesh runtime consumes SPIRE's X.509 SVID and trust bundles for peer verification; it does not start the optional JWT-bundle client adapter. What it cannot do is **serve** a Workload API to other workloads. That distinction is the whole of the boundary section below.

#### Serving the Workload API

The JWT RPCs are reachable only through Ferrum's own in-process Workload API server, which is **off by default**. Enable it with:

```bash
FERRUM_MESH_WORKLOAD_API_ENABLED=true
FERRUM_MESH_CA_BACKEND=internal                                       # the only backend that can serve it
FERRUM_MESH_WORKLOAD_SPIFFE_ID=spiffe://example.org/ns/ferrum/sa/ferrum
FERRUM_MESH_CA_BOOTSTRAP_DEV=true
FERRUM_MESH_WORKLOAD_API_SOCKET_PATH=/run/ferrum/workload-api/socket   # parent dir must already exist
FERRUM_MESH_WORKLOAD_API_SOCKET_MODE=0660
FERRUM_MESH_WORKLOAD_API_UNIX_IDENTITY_RULES=uid:1000=spiffe://example.org/ns/default/sa/app
FERRUM_MESH_JWT_SIGNING_KEY_PEM_FILE=/etc/ferrum/jwt-signing-key.pem
```

Startup is fail-closed at every step. The surface requires `FERRUM_MESH_CA_BACKEND=internal`, `FERRUM_MESH_WORKLOAD_SPIFFE_ID`, and the dev-only `FERRUM_MESH_CA_BOOTSTRAP_DEV=true` self-signed-root opt-in (it mints from the same runtime authority the mesh SVID rotation loop drives), no explicit `FERRUM_GATEWAY_SVID_*` file override (file identity suppresses that authority source), and at least one attestor rule; a socket-contract, permission, or bind failure **fails startup** rather than leaving the surface silently unbound. Because the internal CA has only this dev/test bootstrap and that bootstrap is refused under `FERRUM_MESH_PRODUCTION_MODE=true`, Ferrum's in-process Workload API is **dev/test-only and unavailable in production mode**.

The socket is a credential-adjacent surface — whoever can replace it can impersonate the endpoint workloads dial for their identity — so the contract below is validated **before** bind:

- The path must be absolute with no `.`/`..` segment (checked on the raw path segments). Its parent directory must already exist (Ferrum never creates it) and be at most **74 bytes**, because the socket is bound in a staging directory beneath it and must fit `sockaddr_un.sun_path`.
- **Every directory from `/` down to the parent** must be a real directory (symlink components are refused, never followed), owned by this process's effective uid or root, and not group- or world-writable unless sticky.
- A regular file, directory, symlink, or another user's socket at the path is refused, never deleted. An existing socket owned by this uid is removed only when a bounded (2 s) `connect(2)` probe gets connection-refused; a live listener or any ambiguous result (`EACCES`, full backlog, timeout) refuses startup.
- The configured mode is applied without touching the process umask: the socket is bound and permissioned inside a private `0700` staging directory, then published **no-clobber** (`link(2)`, or `renamex_np(RENAME_EXCL)` on Apple filesystems — never an overwriting `rename(2)`); an occupied destination fails startup and is never removed. The published socket is re-verified (type, owner, mode, device+inode) as the bound identity.
- The mode must allow `connect(2)` (an owner or group write bit); modes such as `0000` / `0440` and world-writable modes are refused at configuration parse.
- The whole socket lifecycle (stale cleanup, publication, serving, shutdown cleanup) is serialized across same-uid processes by a retained `0600` advisory lock sidecar (`.<socket-name>.startup.lock`, 5 s wait bound). On shutdown the socket is unlinked under the lock only if it is still the exact socket bound (device, inode, socket type, owner).
- An **unexpected** termination of the serve task (transport error or panic) initiates the shared mesh shutdown rather than leaving the data plane serving with no identity endpoint.

**What is not claimed.** These checks operate on pathnames and are not atomic against a concurrent rename of an ancestor by a *trusted* actor (root or the operator); the ancestor walk removes that ability from untrusted actors, and the bound-identity checks bound the damage otherwise. Ferrum never chmods or unlinks a path it has not just confirmed is the object it bound.

#### Transport admission and lifetime bounds

Reaching the socket authorizes an identity **request**; it must not let one workload deny identity service to every other workload on the node. Admission therefore runs **before an accepted socket reaches the gRPC stack**, keyed on kernel-attested `SO_PEERCRED` (a socket whose credentials cannot be read is refused).

| Setting | Default | Bounds | Scope |
|---|---|---|---|
| `FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS_PER_UID` | `32` | ceiling `1024`; strictly below the global limit | connections per peer UID |
| `FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS` | `256` | floor `2`, ceiling `4096` | total connections |
| `FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_STREAMS` | `64` | ceiling `1024` | HTTP/2 streams per connection (advertised and load-shed with `RESOURCE_EXHAUSTED`) |
| `FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_RPCS_PER_UID` | `128` | ceiling `4096`; strictly below the service-wide limit | concurrent RPCs per peer UID |
| `FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_RPCS` | `1024` | floor `2`, ceiling `8192` | concurrent RPCs service-wide |
| `FERRUM_MESH_WORKLOAD_API_INITIAL_CONNECTION_TIMEOUT_SECONDS` | `10` | finite, nonzero | connection that never sends its first byte |
| `FERRUM_MESH_WORKLOAD_API_IDLE_TIMEOUT_SECONDS` | `900` | finite, nonzero | time since the last byte **read** from the peer (keepalive PINGs every third of it) |
| `FERRUM_MESH_WORKLOAD_API_SHUTDOWN_GRACE_SECONDS` | `10` | ceiling `300` | graceful drain before connections are force-closed |

- The per-UID quota is judged before the shared limit, as one non-blocking decision under one lock, so a saturated UID never transiently drains the shared pool. Over-limit connections are closed immediately (no wait queue) and over-limit RPCs are refused `RESOURCE_EXHAUSTED`; an RPC whose peer UID cannot be established is refused.
- Each per-UID quota must be **strictly below** its shared limit, enforced by the configuration gate and by a defensive runtime clamp (equality would let one UID hold every slot). A contradictory explicit value is refused with a diagnostic naming both settings, never silently rewritten.
- An RPC permit is taken before metadata validation, attestation, or CA issuance, and a **streaming** RPC holds it for the stream's whole life; the default RPC ceiling leaves room for the three long-lived streams a normal client keeps open on each of the 256 default connections.
- Every limit is finite: `0` is not a "disabled" spelling, and over-ceiling values are refused at configuration time rather than clamped.
- Shutdown stops admission immediately, drains for the grace period, then force-closes what is still open, so a client holding a stream open cannot hold process shutdown open.

Observability is fixed-cardinality: `ferrum_mesh_workload_api_active_connections`, `ferrum_mesh_workload_api_active_rpcs` (service-dispatched RPC streams, not every live HTTP/2 stream), `ferrum_mesh_workload_api_connections_rejected_total{reason}`, `ferrum_mesh_workload_api_connections_closed_total{reason}`, and the unlabelled `ferrum_mesh_workload_api_rpcs_rejected_total` (both RPC bounds; RPCs shed after h2 accepted the stream, not protocol-level `REFUSED_STREAM`). `reason` is a closed set; peer UID, PID, SPIFFE ID, and token material are never labels, and rejection `debug!` logs carry only fixed reason/limit context.

Attestation is never permissive. `FERRUM_MESH_WORKLOAD_API_UNIX_IDENTITY_RULES` maps a kernel-attested `SO_PEERCRED` UID — `uid:<uid>=<spiffe-id>` — to a SPIFFE ID in the local trust domain. Binary-hash-only selectors are rejected because possession of a world-executable binary does not identify the user running it. A caller matching no rule is refused; the Workload API never invents an identity. With no rules and no dev-only `FERRUM_MESH_ALLOW_STATIC_ID`, enabling the surface fails startup rather than coming up able only to reject.

On Kubernetes these are ordinary passthrough env on the mesh chart:

```yaml
ambient:
  env:
    FERRUM_MESH_WORKLOAD_API_ENABLED: "true"
    FERRUM_MESH_CA_BACKEND: internal
    FERRUM_MESH_WORKLOAD_SPIFFE_ID: spiffe://example.org/ns/ferrum/sa/ferrum
    FERRUM_MESH_CA_BOOTSTRAP_DEV: "true"
    FERRUM_MESH_WORKLOAD_API_SOCKET_PATH: /run/ferrum/workload-api/socket
    FERRUM_MESH_WORKLOAD_API_UNIX_IDENTITY_RULES: uid:1000=spiffe://example.org/ns/default/sa/app
    FERRUM_MESH_JWT_SIGNING_KEY_PEM_FILE: /var/run/secrets/ferrum/jwt-signing-key.pem
```

Mount `/run/ferrum/workload-api` (the parent directory Ferrum requires to pre-exist) and the signing-key secret; the key is a `Secret`, not a `ConfigMap`.

#### JWT signing material, restart, and HA

The trust domain's JWT signing authority is **operator-configured material**, not a per-process accident. `FERRUM_MESH_JWT_SIGNING_KEY_PEM` carries an ES256 (P-256) private key, resolvable through the ordinary external-secret suffixes (`_VAULT`, `_AWS`, `_AZURE`, `_GCP`, `_FILE`). It is deliberately **separate from the X.509 root**: a JWT bundle is published to every workload, so the certificate root is not reused across protocols, and rotating one does not disturb the other.

Because the published `kid` is the RFC 7638 thumbprint of the *public* key, the same material always yields the same `kid` and the same JWKS. That gives two properties operators depend on:

- **Restart continuity.** A token minted moments before a restart still validates afterwards, for its whole permitted lifetime.
- **HA / multi-replica agreement.** Every replica configured with the same material publishes a byte-identical JWKS and validates every other replica's tokens. No coordination, no shared state, no leader.

Distribute the same secret to every replica of a trust domain. The key is never logged, never echoed in an error, and never appears in a `Debug` rendering; only the public `kid` does.

**Rotation of configured material is EXTERNAL, and Ferrum will not do it in process.** This is a deliberate refusal, not a missing feature. A replacement key generated inside one process would be a different random key on every replica and would be lost on the next restart, so tokens minted from it would validate nowhere else and nowhere later — the precise failure stable signing material exists to prevent. Concretely, with `FERRUM_MESH_JWT_SIGNING_KEY_PEM` configured:

- `FERRUM_MESH_JWT_KEY_LIFETIME_SECONDS` must be `0`, and a nonzero value is **rejected at startup** rather than silently ignored, so an operator who thought a rotation was scheduled is told that it is not;
- the scheduled rotation task is a permanent no-op for that authority;
- an explicit rotation is refused, leaving the configured key active and every already-minted token verifiable.

Rotate with a two-step, two-key rolling config change instead:

1. Set `FERRUM_MESH_JWT_SIGNING_KEY_PEM` to the new key and `FERRUM_MESH_JWT_PREVIOUS_SIGNING_KEY_PEM` to the outgoing one. Roll the fleet. Both keys are published; new tokens use the new key, and tokens signed by the old one keep validating.
2. Once the overlap has elapsed (the JWT-SVID ceiling plus clock-skew leeway — 1 h + 60 s), remove `FERRUM_MESH_JWT_PREVIOUS_SIGNING_KEY_PEM` and roll again.

A configured previous key is published for as long as it stays configured, deliberately **not** on a process-relative timer: a timer would make a replica started later advertise a key its peer had already dropped, so two replicas of one configuration would publish different JWKS. Setting the previous key without a primary is rejected — a retired key is published for verification only, so there would be nothing to mint with.

**"Verification only" is structural, not a convention.** A retired entry holds a public-only representation — `kid`, algorithm, and SPKI public PEM — and no signing object of any kind. `FERRUM_MESH_JWT_PREVIOUS_SIGNING_KEY_PEM` is parsed only long enough to validate it (same bounds and same ES256/P-256 requirement as the primary) and derive that public metadata; the private half is dropped before startup completes, so a key the trust domain has already rotated off cannot sign in the process even by mistake. An ephemeral in-process rotation is the same: it copies the outgoing key's public metadata and leaves its signing object with the superseded state to be released.

`FERRUM_MESH_ALLOW_EPHEMERAL_JWT_KEY=true` accepts a **process-local** key when none is configured. It is dev/test only and refused under `FERRUM_MESH_PRODUCTION_MODE=true`: the key is lost on restart and differs per replica, so tokens minted moments earlier stop validating and two instances of one trust domain publish different JWKS. Without it, and without configured material, the surface refuses to start.

In-process, time-based key rotation exists **only** for this ephemeral posture — an already-discontinuous key loses nothing by being replaced — which is why `FERRUM_MESH_JWT_KEY_LIFETIME_SECONDS` is meaningful only alongside it.

The `internal` CA loads that ES256 JWT signing key at startup. Behaviour:

- **`FetchJWTSVID`** re-runs the attestor chain and mints **only** for the attested identity. The optional `spiffe_id` field is honoured only when byte-equal to the attested SPIFFE ID; any other value is `PERMISSION_DENIED`. At least one non-empty audience is required (max 32 audiences, 512 bytes each); duplicates collapse. Tokens carry `sub` (the SPIFFE ID), `aud`, `exp`, `iat`, `nbf`, and a unique `jti`, are signed `ES256` with a `kid` equal to the key's RFC 7638 JWK thumbprint, and are clamped to a 1 h ceiling (5 min default).
- **`FetchJWTBundles`** streams a JWKS document per trust domain — always including the local one — and republishes on JWT key rotation, skipping rotation signals that did not change the authority set. It never emits an empty `bundles` map as success: SPIFFE Workload API §6.2.2 requires at least the local trust-domain bundle, so "no authorities" is reported as `UNIMPLEMENTED`, never as an empty map. Malformed or oversized authority material is refused rather than published.
- **`ValidateJWTSVID`** verifies signature, key id, audience, subject SPIFFE syntax and trust domain, issuer (when present), `exp` (mandatory), `nbf`, and `iat`. It refuses `alg: none`, the HMAC family, unknown or ambiguous key ids, unknown trust domains, unknown critical headers, repeated JSON keys in the header or claims, and oversized tokens or claim documents. Rejection reasons are fixed strings — no token bytes, claim values, or key material appear in an error. On success the response carries the SPIFFE ID and the token's claims as a `google.protobuf.Struct`, exactly as the upstream SPIFFE `workload.proto` declares `ValidateJWTSVIDResponse.claims`. Claim values map to `Struct` value kinds faithfully (null, bool, string, nested object, array); JSON numbers are carried as doubles, as SPIRE does, so an integer claim beyond 2^53 loses precision. Claims nested deeper than 32 levels (the claims object is level 1) are refused with `INVALID_ARGUMENT`, keeping the response within common protobuf decoder recursion limits. A client generated from an older vendored proto that declared field 2 as JSON-encoded `bytes claims_json` must be regenerated from the upstream (or current vendored) `workload.proto` and read `claims` as a `Struct` (issue #5764; see the [upgrade guide](upgrade_guide.md#upgrading-to-098)).
- **Rotation overlap, and why it is provable.** This bounds the **ephemeral** posture's in-process rotation; configured material is rotated externally and its previous key is published for as long as it stays configured. A key retired in process stays published for verification for the maximum token lifetime plus clock-skew leeway (1 h + 60 s), so a token minted an instant before a rotation remains verifiable for its whole bounded lifetime; after that window the key disappears. Retained keys are additionally capped, bounding memory and bundle size — and the cap and the cadence are made *consistent* rather than left to collide:
  - a `FERRUM_MESH_JWT_KEY_LIFETIME_SECONDS` shorter than the overlap divided by the published-authority budget is **refused at startup** (minimum `244` at the 1 h ceiling), because no cap within the 16-authority limit could hold every still-verifiable key;
  - the retention cap is **derived up** from the cadence, so the scheduled rotation never needs to evict anything;
  - a rotation that would nevertheless have to drop a key still inside its overlap — reachable only by driving rotation far faster than the schedule — is **refused**. The active key stays active and every minted token stays verifiable; Ferrum never trades a live token's validity for a cap.
  Rotation runs on the mesh rotation task, never on a request path, and it bumps the SVID rotation revision, so the new JWKS is republished on every already-open `FetchJWTBundles` stream with no reconnect.
- **Authority bounds are enforced before publication *and* before validation.** Every trust domain's complete authority set — local and federated, locally produced or supplied through a configured external adapter — goes through one admission gate: authority count cap, exact trust-domain binding, duplicate-`kid` refusal, key-id / PEM / DER / key-type / key-size constraints, and total JWKS size. `ValidateJWTSVID` therefore cannot accept material `FetchJWTBundles` would have refused, and a malformed or oversized externally supplied bundle fails closed instead of driving an unbounded scan. Malformed federated material fails the call rather than being silently dropped from the trusted set.
- **Cryptographic admission, not just structural admission.** Shape is neither strength nor curve membership, so the same gate additionally proves each key is usable before it is published or turned into a verifier: an RSA modulus is bounded by its **significant** bit length (`2048..=8192`, so a 2041-bit modulus padded into 256 bytes is refused and leading zero octets never count), an RSA public exponent must be odd and at least 3 within a bounded encoding (`0`, `1`, `2`, and even values are refused; real keys are 65537), externally supplied `n`/`e` must be canonical unsigned big-endian with no leading zero octet (RFC 7518 §6.3.1), and an EC point must actually lie on its named curve and not be the identity. Curve membership is proven with a bounded ephemeral ECDH agreement through Ferrum's cryptographic-provider seam (`ring` on an ordinary build, the AWS-LC FIPS module on a `fips` build — see [docs/fips.md](fips.md)), so no second, unrouted elliptic implementation is introduced on a trust-admission path. Every rejection is a fixed string; no key bytes reach an error.
- **Federated trust domains are bounded at configuration, not per response.** The configured federated set is deduplicated, stripped of the local trust domain, and capped once when the service is built; an over-cap list is an error rather than a silent truncation, so the number of CA calls one bundle RPC can make is fixed before any of them is issued. Counting successfully published bundles instead would let arbitrarily many empty or failing aliases drive unbounded CA work.

Like `FetchX509Bundles`, the bundle and validate RPCs require the mandatory `workload.spiffe.io: true` metadata header but do not run the attestor chain — they consume public trust material and mint nothing. Private-key and token issuance stay gated on `FetchX509SVID` / `FetchJWTSVID`.

#### Workload API CA error status contract

When a Workload API RPC fails because the configured certificate authority returned a `CaError`, Ferrum converts that failure **once** at the Workload API boundary into a stable gRPC status. Clients must not couple to provider, configuration, filesystem, trust-domain, or OS diagnostics — those details stay server-side in structured logs that carry only fixed-cardinality `operation` and `error_class` fields.

| `CaError` variant | gRPC code | Fixed client message |
|---|---|---|
| `BadCsr` | `INVALID_ARGUMENT` | `certificate request rejected` |
| `UnknownTrustDomain` | `PERMISSION_DENIED` | `trust domain not authorized` |
| `Upstream` | `UNAVAILABLE` | `certificate authority unavailable` |
| `Config` / `Internal` / `Io` | `INTERNAL` | `certificate authority operation failed` |

This mapping applies to initial `FetchX509SVID` construction, the static/rotation response helpers shared by stream refresh, local and federated X.509 bundle fetches, the bundle-only `FetchX509Bundles` RPC (which still requires the mandatory metadata header but does not run attestation), and the JWT-authority collection path used by `FetchJWTBundles` / `ValidateJWTSVID`. Transient CA failures on an already-open rotation stream stay server-side and do not terminate a healthy stream; entitlement denials from re-attestation remain terminal `PERMISSION_DENIED`. Workload attestation failures keep their own fixed `PERMISSION_DENIED` / `workload attestation failed` contract and are not affected by this mapping.

#### SPIRE backend: serving a Workload API is refused

**`FERRUM_MESH_WORKLOAD_API_ENABLED=true` together with `FERRUM_MESH_CA_BACKEND=spire` is refused at startup**, with a diagnostic naming both settings. This is a terminal capability boundary, not a deferral, and it applies to the *whole surface* rather than to the JWT RPCs alone.

A SPIRE agent issues only the **calling process's own** attested identity. Ferrum's `SpireAgentCa` therefore fetches Ferrum's agent SVID and refuses every other subject, while a Workload API server exists precisely to issue for a *different*, locally attested downstream workload:

- `FetchX509SVID` would ask that CA to issue for the attested caller's SPIFFE ID, which it cannot do — every request would fail;
- `FetchJWTSVID` is authorized by SPIRE against the calling process too, so proxying the agent's own mint RPC would return a token whose `sub` is Ferrum's SPIFFE ID rather than the workload's. A silent identity substitution is strictly worse for a relying party than a refusal, so Ferrum does not do it and **must not** be "fixed" to.

Minting for a delegated subject requires SPIRE's delegated-identity / admin API — an explicitly authorized integration outside the Workload API surface Ferrum consumes. Until such an integration exists, enabling the surface on this backend is refused rather than allowed to bind an endpoint that could only mis-issue or reject.

**What still works under `spire` is X.509 consumption, which is a different capability.** The active mesh runtime consumes the agent's X.509 SVID and trust bundles through its dedicated fetch loop, retaining the last good identity across reconnects and publishing rotations to the live TLS slots. The reusable `SpireAgentCa` / `WorkloadApiClient` adapter can decode a bounded `FetchJWTBundles` stream when explicitly constructed, but mesh startup does not construct that adapter or start its JWT stream, so SPIRE JWT authorities do not back Ferrum validation. None of the X.509 consumption amounts to delegated issuance, and the docs deliberately do not conflate the two.

Workloads that need SVID mint alongside a SPIRE deployment should call their local SPIRE agent's Workload API directly — that is the socket SPIRE authorizes them on — or run `FERRUM_MESH_CA_BACKEND=internal` with configured JWT signing material.

Mesh `RequestAuthentication` / `jwks_auth` continues to validate application JWTs via its own JWKS fetch and is unrelated to Workload API JWT-SVIDs. See [docs/spire_deployment.md](spire_deployment.md#jwt-svids).

### Internal Dev CA and Production Guardrails

The `internal` CA backend is backed by a self-signed root produced by the dev bootstrap helper in `src/identity/ca/bootstrap.rs`. To make it impossible to accidentally run a production mesh on an unanchored self-signed root, the helper is protected by two environment guardrails, both read directly at the time the helper is invoked (they are **not** parsed into `EnvConfig`):

- `FERRUM_MESH_PRODUCTION_MODE` — master switch: when `true`, the self-signed CA bootstrap, the dev-only static attestor, the process-local JWT signing key (`FERRUM_MESH_ALLOW_EPHEMERAL_JWT_KEY`), the no-identity posture (`FERRUM_MESH_ALLOW_NO_CA`), and `FERRUM_TLS_NO_VERIFY` / `FERRUM_ADMIN_TLS_NO_VERIFY` are refused unconditionally. Set it in every production deployment.
- `FERRUM_MESH_CA_BOOTSTRAP_DEV` — explicit opt-in to mint a self-signed mesh root; the helper logs a `DEV-ONLY, never use in production` warning when it runs.
- `FERRUM_MESH_ALLOW_STATIC_ID` — sibling guardrail for the dev-only `StaticAttestor` (hard-coded SPIFFE ID for any peer).

Defaults and full descriptions are in [configuration.md → Mesh Runtime](configuration.md#mesh-runtime).

Both gates must agree before a self-signed root is minted: `FERRUM_MESH_CA_BOOTSTRAP_DEV=true` **and** `FERRUM_MESH_PRODUCTION_MODE` not `true`. Anything else fails closed.

Relatedly, running the Experimental `FERRUM_MESH_TOPOLOGY=node_waypoint` topology under `FERRUM_MESH_PRODUCTION_MODE=true` logs a startup `warn!` (not a refusal — the production identity guardrails all still apply, and the NodeWaypoint eBPF live gate deliberately runs the production identity profile) noting that Experimental surfaces are excluded from the GA contract (see [mesh_supported_matrix.md](mesh_supported_matrix.md)).

**The internal root is process-local and stays that way.** The bootstrap helper mints the root **in memory, per process**. There is no env var, admin endpoint, or CLI flag that persists, exports, or imports it, and none is planned: an export surface would turn a dev shortcut into a distributable private CA key. Two `internal` processes on one host therefore hold two unrelated roots and cannot complete mTLS in either direction — the outbound SPIFFE verifier rejects the peer chain, and no PERMISSIVE setting creates a plaintext east-west fallback for sidecar outbound. To run more than one mesh process locally, give each one file-based SVID material issued by a **shared** root: see [File-Based SVIDs: Two-Process Local Mesh](#file-based-svids-two-process-local-mesh).

For production mesh identity, run the SPIRE Agent backend (`FERRUM_MESH_CA_BACKEND=spire_agent`) so SVID issuance and trust-bundle distribution are anchored to a separately operated trust root. There is no `FERRUM_MESH_CA_CERT_PATH` / `FERRUM_MESH_CA_KEY_PATH` env var — those names appear only in the bootstrap helper's refusal message as guidance for a possible externally-provided-root path and are not read by any code path.

**No-identity startup gate.** A third member of this guardrail family is enforced at config-validation time rather than inside the identity helpers. A `mesh` data plane's runtime workload identity can come from configured gateway SVID material (`FERRUM_GATEWAY_SVID_CERT_*` + `KEY_*` + `TRUST_BUNDLE_*`) or automatic CA-backed SVID issuance (`FERRUM_MESH_CA_BACKEND=spire_agent|internal` plus `FERRUM_MESH_WORKLOAD_SPIFFE_ID`). With neither source, the mesh can't present or verify an mTLS peer certificate, so PeerAuthentication's PERMISSIVE default would silently accept unauthenticated plaintext. `EnvConfig` validation therefore **fails startup closed** in that no-identity case unless the operator sets `FERRUM_MESH_ALLOW_NO_CA=true` to acknowledge the dev/test-only posture (a loud `warn!` is logged when it does start that way). That opt-out is read **directly from the environment** (not `ferrum.conf`), matching the rest of the family. As with the other shortcuts, `FERRUM_MESH_PRODUCTION_MODE=true` refuses the no-identity posture **unconditionally** — the opt-out is ignored — so a production mesh can never come up without identity.

**TLS verification bypasses under production.** The same shared `EnvConfig` validation path refuses `FERRUM_TLS_NO_VERIFY=true` and `FERRUM_ADMIN_TLS_NO_VERIFY=true` whenever `FERRUM_MESH_PRODUCTION_MODE=true`. Those switches remain an explicit development opt-in with a loud warning outside production; under production mesh posture they fail closed with a diagnostic that names the exact offending variable(s) and never echoes secret or source values. The guard is topology-independent (sidecar, ambient, service/node waypoint, east-west gateway, and egress gateway) and runs before listeners, service-discovery pollers, health checks, plugin clients, or admin client activity can start — the same path both `ferrum-edge validate` and runtime startup use. FIPS enforce remains an independent defense that also refuses these switches; production mesh mode does not weaken or topology-special-case it. Prefer verified TLS with system roots or `FERRUM_TLS_CA_BUNDLE_PATH`.

**Runtime inbound mTLS fail-closed (the robust complement).** The gate above is a fast config-time *presence* check; it cannot see whether the configured SVID sources actually load or whether the resolved PeerAuthentication mode would still leave the inbound listener serving plaintext. The mesh therefore also fails closed at the runtime TLS-setup path, where the inbound listener's real posture is known (`enforce_mesh_inbound_fail_closed`). Three refinements make this exact:

1. **Gateway/runtime SVID backs the inbound server identity.** When no explicit `FERRUM_FRONTEND_TLS_CERT_PATH` / `KEY_PATH` is set, the mesh workload SVID backs the inbound listener's server certificate, so a mesh configured with only workload SVID material presents that SVID as its inbound server cert and serves mTLS instead of falling open to plaintext under the default PERMISSIVE mode. Both SVID sources resolve the same way: the inbound server certificate **resolves live from the gateway SVID slot** (a rustls `ResolvesServerCert` backed by the same shared slot that receives rotations). For **configured `FERRUM_GATEWAY_SVID_*` material**, the source watcher feeds that slot: file/`file://` sources poll every second, provider sources use their secret-refresh cadence, and inline PEM remains static until configuration reload. A successful source rotation makes the inbound listener present the new leaf on the next handshake and refreshes the SPIFFE peer verifier from the rotated trust bundle plus the last accepted federated overlay, with no restart or slice apply. For **CA-backed SVIDs** (`FERRUM_MESH_CA_BACKEND=spire_agent` / `internal`) the CA-backed SVID source (`start_mesh_ca_backend_svid_source`) installs each issued SVID into the same slot, so inbound server identity and peer-verifier local roots follow CA/SPIRE rotation through the identical live resolver. In-flight TLS sessions keep their established parameters; only new handshakes see the new leaf and verifier roots. Fail-closed semantics: at startup a configured SVID source whose slot holds no usable material hard-errors before listeners bind, and if a later rotation installs material that cannot back a server certificate (or empties the slot), inbound handshakes fail — loudly, once per bad rotation — rather than silently serving a stale leaf that masks a broken rotation pipeline until it expires. Explicit `FERRUM_FRONTEND_TLS_*` material remains a static operational input (the operator owns its rotation; the frontend live-reload flag covers it separately).
2. **Suppress plaintext on production inbound listeners.** Under `FERRUM_MESH_PRODUCTION_MODE=true`, a `PERMISSIVE` workload or app port with usable server TLS material is accepted at startup and on live reload, but plaintext demultiplexing is disabled and that port runs TLS-only. A mode that cannot produce a usable TLS config (including `DISABLE` or missing server identity) is refused at startup. With PeerAuthentication live reload enabled, such an incoming slice is rejected in its entirety and the last-good policy remains active. In development, plaintext-capable modes are allowed with a loud warning: reaching plaintext there is intentional — either an explicit `PeerAuthentication` mode or a no-identity posture admitted by the config-time `FERRUM_MESH_ALLOW_NO_CA` gate.
3. **Refuse a configured-but-broken SVID verifier.** If gateway SVID material is configured (all three `FERRUM_GATEWAY_SVID_*` paths named) but fails to load while the listener serves TLS — e.g. a valid leaf/key but a corrupt trust bundle — the SPIFFE peer-trust-domain verifier would be silently absent. The operator named all three paths intending verification, so this is a genuine fault, **fatal regardless of `FERRUM_MESH_PRODUCTION_MODE`** (mirroring how a broken SVID cert/key already hard-errors; `ProxyState` construction independently rejects the same broken material). This is distinct from the dev-tolerated plaintext cases above.

Topologies with no TLS-terminating inbound listener (EastWestGateway SNI passthrough forwards encrypted bytes) are exempt from all three.

When `FERRUM_MESH_CA_BACKEND=spire_agent`, rotation is pushed by the SPIRE Agent Workload API stream and backend pool generations advance after each post-startup update. When `FERRUM_MESH_CA_BACKEND=internal`, Ferrum mints an initial dev SVID and rotates it at half of its validity window; post-startup rotation failures keep the current identity and retry with jittered exponential backoff. In both modes, startup refuses to bind listeners until the first SVID is loaded.

### File-Based SVIDs: Two-Process Local Mesh

`FERRUM_MESH_CA_BACKEND=internal` is **process-local**. Each process that
bootstraps it mints its **own** self-signed root in memory, and there is no
export, persist, or share surface for that root — deliberately, because such a
surface would turn a dev shortcut into a distributable private CA key. Two
`internal` processes therefore do **not** share trust: the client presents an
SVID signed by root A, the destination verifies it against root B, and the
outbound SPIFFE verifier rejects the chain. Sidecar outbound **always** presents
and verifies SVIDs; there is no plaintext east-west fallback, and PERMISSIVE on
the destination's inbound listener does not create one (PERMISSIVE relaxes what
the *destination* accepts, never what the *client* sends).

The supported way to run two mesh processes on one host is the same file-based
SVID material a production deployment uses: SPIRE, cert-manager, or an operator
script writes three files per workload, and Ferrum reads them. Nothing in this
recipe has to be undone for production — only the *issuer* changes.

#### What each process needs

| Variable | Meaning |
|---|---|
| `FERRUM_GATEWAY_SVID_CERT_PATH` | Leaf-first PEM chain for this process's own SVID |
| `FERRUM_GATEWAY_SVID_KEY_PATH` | PKCS#8 private key for that leaf |
| `FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH` | PEM trust bundle — the **shared** root(s) both processes chain to |
| `FERRUM_MESH_WORKLOAD_SPIFFE_ID` | This process's own workload identity, used for slice scoping |

All three `FERRUM_GATEWAY_SVID_*` sources are loaded **together**. Naming one or
two of them is refused at `ferrum-edge validate` and at startup — a leaf without
its key or its trust bundle can neither present nor verify a peer certificate,
so a partial tuple is a misconfiguration, never a fallback. Each source also
accepts `file://`, inline PEM, or a `_VAULT` / `_AWS` / `_AZURE` / `_GCP` /
`_FILE` provider suffix; see [Runtime inbound mTLS fail-closed](#internal-dev-ca-and-production-guardrails)
for the rotation and fail-closed semantics that then apply.

With file SVIDs configured you do **not** need `FERRUM_MESH_ALLOW_NO_CA`, and
you do not need a CA backend at all: file SVIDs *are* the workload identity, and
they take precedence over `FERRUM_MESH_CA_BACKEND` when both are set.

#### Certificate contract

| Requirement | Why / enforced by |
|---|---|
| Cert file is a **leaf-first** PEM chain; each entry is issued by the next | `validate_certificate_chain_order` verifies issuer/subject linkage **and** the signature. The final root may be omitted, as is conventional for a presentation chain |
| Leaf is not a CA; this recipe emits `basicConstraints = critical, CA:FALSE` | `validate_leaf_is_not_ca` refuses an explicit `CA:TRUE`. The loader also accepts an omitted basic-constraints extension, but an explicit critical `CA:FALSE` keeps the intended workload-leaf role unambiguous |
| Leaf carries `subjectAltName = URI:spiffe://<trust-domain>/…` | Sidecar peer verification reads the SPIFFE identity from the certificate URI SAN, so this two-process recipe requires it. `FERRUM_GATEWAY_SPIFFE_ID` can supply the bundle's local identity when a certificate has no SPIFFE URI SAN, but it does not add a SAN to that certificate and cannot make a SAN-less leaf usable for this peer-verified sidecar path |
| Leaf carries `extendedKeyUsage = serverAuth, clientAuth` | A sidecar is **both** ends: it terminates inbound mTLS and presents a client cert outbound. Peer verification runs through rustls' `WebPkiClientVerifier` in both directions |
| Key is **PKCS#8** (`-----BEGIN PRIVATE KEY-----`) | `read_pkcs8_key_source` rejects PKCS#1 / SEC1 (`BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`) |
| Key matches the leaf | `verify_leaf_key_match` compares canonical DER `SubjectPublicKeyInfo` bytes |
| Every certificate is currently valid | `validate_cert_is_current` distinguishes not-yet-valid from expired |
| Trust bundle holds the **shared** root(s) | Both processes must chain to the same root, or the peer verifier fails with a chain-verify error |

The trust bundle is the local trust anchor set for this process's **own** trust
domain. Federating a *second* trust domain is a slice-level `trust_bundles`
concern, not a file-material one — see [Trust Federation](#trust-federation).

#### File permissions

Ferrum does not enforce a mode on SVID material, so the filesystem is the whole
boundary. Give the private key `0600` and the directory holding it `0700`, both
owned by the uid the mesh process runs as. The trust bundle and the leaf are
public material (`0644` is fine). The **root CA key** is not consumed by Ferrum
at all — keep it out of the process's directory entirely, and never commit any
of it.

#### Step 1 — one shared root, two SVIDs

Run this once, on the machine that will host both processes. It is a dev
issuance script, not a CA: for anything beyond a laptop, use SPIRE
(`FERRUM_MESH_CA_BACKEND=spire_agent`).

```bash
export MESH_DIR="$HOME/ferrum-local-mesh"
export TRUST_DOMAIN="cluster.local"
export MESH_NS="ferrum"

mkdir -p "$MESH_DIR"/{ca,svc,client,conf}
chmod 700 "$MESH_DIR" "$MESH_DIR/ca" "$MESH_DIR/svc" "$MESH_DIR/client"

# The single root BOTH processes trust. Its key never leaves $MESH_DIR/ca.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$MESH_DIR/ca/root.key" -out "$MESH_DIR/ca/root.crt" \
  -days 30 -subj "/CN=ferrum-local-dev-root" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
chmod 600 "$MESH_DIR/ca/root.key"

# One X.509-SVID per workload: CA:FALSE leaf, SPIFFE URI SAN, serverAuth +
# clientAuth, PKCS#8 key, plus a copy of the shared root as the trust bundle.
issue_svid() {
  local dir="$1" spiffe_id="$2"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$dir/svid.key" -out "$dir/svid.csr" -subj "/CN=${spiffe_id##*/}"
  cat > "$dir/svid.ext" <<EXT
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = URI:$spiffe_id
EXT
  openssl x509 -req -in "$dir/svid.csr" -days 7 -sha256 \
    -CA "$MESH_DIR/ca/root.crt" -CAkey "$MESH_DIR/ca/root.key" -CAcreateserial \
    -extfile "$dir/svid.ext" -out "$dir/svid.crt"
  cp "$MESH_DIR/ca/root.crt" "$dir/bundle.pem"
  rm -f "$dir/svid.csr" "$dir/svid.ext"
  chmod 600 "$dir/svid.key"
  chmod 644 "$dir/svid.crt" "$dir/bundle.pem"
}

issue_svid "$MESH_DIR/svc"    "spiffe://$TRUST_DOMAIN/ns/$MESH_NS/sa/svc"
issue_svid "$MESH_DIR/client" "spiffe://$TRUST_DOMAIN/ns/$MESH_NS/sa/client"

# Confirm the contract before starting anything.
openssl x509 -in "$MESH_DIR/svc/svid.crt" -noout -text |
  grep -E "CA:FALSE|URI:spiffe|TLS Web (Server|Client) Authentication"
openssl verify -CAfile "$MESH_DIR/ca/root.crt" \
  "$MESH_DIR/svc/svid.crt" "$MESH_DIR/client/svid.crt"
head -1 "$MESH_DIR/svc/svid.key"   # must print -----BEGIN PRIVATE KEY-----
```

#### Step 2 — one shared mesh document

Both processes read the **same** localized mesh document
(`FERRUM_MESH_CONFIG_PROTOCOL=file`, no control plane). It declares one in-mesh
service `svc` backed by the destination workload's app at `127.0.0.1:18080`,
under STRICT `PeerAuthentication`. The destination recognizes
`spiffe://cluster.local/ns/ferrum/sa/svc` as **local** (via its own
`FERRUM_MESH_WORKLOAD_SPIFFE_ID`) and materializes the inbound loopback route;
the client's identity differs, so the same document materializes an **egress**
route for it instead.

```bash
cat > "$MESH_DIR/conf/mesh.yaml" <<YAML
mesh:
  workloads:
    - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$MESH_NS/sa/svc
      service_name: svc
      namespace: $MESH_NS
      trust_domain: $TRUST_DOMAIN
      service_account: svc
      addresses:
        - 127.0.0.1
      ports:
        - port: 18080
          protocol: http
          name: http
      selector:
        labels:
          app: svc
        namespace: $MESH_NS
  services:
    - name: svc
      namespace: $MESH_NS
      ports:
        - port: 18080
          protocol: http
          name: http
      workloads:
        - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$MESH_NS/sa/svc
  peer_authentications:
    - name: mesh-strict
      namespace: $MESH_NS
      mtls_mode: strict
YAML
```

#### Step 3 — the two processes

The destination binds the conventional sidecar inbound port; the client binds a
**different** one, because both processes share one loopback interface. The
client's outbound dial targets `127.0.0.1:15006` — the destination's inbound
listener — which is `FERRUM_MESH_EGRESS_MTLS_PORT`'s default. Move the
destination's inbound port and you must move that variable on the client to
match.

Destination (workload `sa/svc`, inbound `:15006`):

```bash
FERRUM_MODE=mesh \
FERRUM_NAMESPACE=$MESH_NS \
FERRUM_MESH_TOPOLOGY=sidecar \
FERRUM_MESH_CONFIG_PROTOCOL=file \
FERRUM_MESH_FILE_CONFIG_PATH="$MESH_DIR/conf/mesh.yaml" \
FERRUM_MESH_WORKLOAD_SPIFFE_ID="spiffe://$TRUST_DOMAIN/ns/$MESH_NS/sa/svc" \
FERRUM_GATEWAY_SVID_CERT_PATH="$MESH_DIR/svc/svid.crt" \
FERRUM_GATEWAY_SVID_KEY_PATH="$MESH_DIR/svc/svid.key" \
FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH="$MESH_DIR/svc/bundle.pem" \
FERRUM_MESH_INBOUND_LISTEN_ADDR=127.0.0.1:15006 \
FERRUM_MESH_OUTBOUND_LISTEN_ADDR=127.0.0.1:15001 \
FERRUM_MESH_DNS_PROXY_ENABLED=false \
FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS=0 \
FERRUM_POOL_WARMUP_ENABLED=false \
FERRUM_PROXY_HTTP_PORT=0 \
FERRUM_ADMIN_HTTP_PORT=15020 \
FERRUM_LOG_LEVEL=info \
  ferrum-edge run
```

Client (workload `sa/client`, outbound `:15101`, inbound moved to `:15106`):

```bash
FERRUM_MODE=mesh \
FERRUM_NAMESPACE=$MESH_NS \
FERRUM_MESH_TOPOLOGY=sidecar \
FERRUM_MESH_CONFIG_PROTOCOL=file \
FERRUM_MESH_FILE_CONFIG_PATH="$MESH_DIR/conf/mesh.yaml" \
FERRUM_MESH_WORKLOAD_SPIFFE_ID="spiffe://$TRUST_DOMAIN/ns/$MESH_NS/sa/client" \
FERRUM_GATEWAY_SVID_CERT_PATH="$MESH_DIR/client/svid.crt" \
FERRUM_GATEWAY_SVID_KEY_PATH="$MESH_DIR/client/svid.key" \
FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH="$MESH_DIR/client/bundle.pem" \
FERRUM_MESH_INBOUND_LISTEN_ADDR=127.0.0.1:15106 \
FERRUM_MESH_OUTBOUND_LISTEN_ADDR=127.0.0.1:15101 \
FERRUM_MESH_EGRESS_MTLS_PORT=15006 \
FERRUM_MESH_DNS_PROXY_ENABLED=false \
FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS=0 \
FERRUM_POOL_WARMUP_ENABLED=false \
FERRUM_PROXY_HTTP_PORT=0 \
FERRUM_ADMIN_HTTP_PORT=15120 \
FERRUM_LOG_LEVEL=info \
  ferrum-edge run
```

Run `ferrum-edge validate` with the same environment first: it applies the same
identity gates startup does, including the all-three-together file-SVID rule.

#### Step 4 — verify

```bash
# 1. The destination app the mesh fronts (any plain HTTP server will do).
python3 -m http.server 18080 --bind 127.0.0.1 &

# 2. Both processes started as above.

# 3. Drive the client's OUTBOUND listener with the destination service FQDN.
#    The Host header selects the materialized egress route; the client then
#    dials 127.0.0.1:15006 with SVID-mTLS and pins the peer identity.
curl -sS -D- -o /dev/null \
  -H "Host: svc.$MESH_NS.svc.cluster.local" \
  http://127.0.0.1:15101/
```

A `200` proves the whole path: outbound route match → client SVID presented →
destination STRICT inbound verified the client's chain **and** trust domain →
inbound loopback route → app. Confirm the identities actually in use on the
authenticated admin surfaces of each process (`:15020` / `:15120`).

The client also **pins** the destination's SPIFFE ID: the peer must present
exactly `spiffe://cluster.local/ns/ferrum/sa/svc`, not merely some certificate
from a trusted root. Swapping the destination's SVID for a different identity
under the same root still fails closed.

#### Reading a failure

Sidecar outbound failures are labeled for the transport that actually failed
(issue #3927):

| Client sees | Means |
|---|---|
| `{"error":"Sidecar mTLS backend unavailable: TLS handshake failed"}` | The `:15006` SVID-mTLS handshake failed — mismatched roots, an expired leaf, a missing EKU, or a destination that is not listening TLS. **No HBONE tunnel is involved on this path.** |
| `{"error":"Sidecar mTLS backend unavailable: TCP connect failed"}` | The destination's inbound port is wrong or nothing is listening |
| `{"error":"Sidecar mTLS backend unavailable: gateway identity unavailable"}` | This process has no usable SVID in its slot |
| `{"error":"HBONE backend unavailable: …"}` | An **Ambient / waypoint** dial (HTTP/2 CONNECT over `:15008`). Seeing this from a `sidecar`-topology process means the target was tagged for the Ambient transport, not that the sidecar path failed. A CONNECT refusal appends the peer's admission status (`… tunnel rejected by peer with status 403` is a destination authorization denial) |

The public reason is a fixed phrase chosen from the failure's kind. Peer
addresses, certificate subjects, SPIFFE IDs, trust roots, and raw
rustls/SPIFFE verifier text are **not** in the client body and are **not**
interpolated into the operator `error!` record. That record carries
closed-cardinality `error_kind`, `error_phase` (the same fixed phrase), and
`peer_status` only for a CONNECT admission refusal. The transaction log
records `error_class=tls_error`, so retry, circuit-breaker, and passive-health
accounting treat it like any other TLS failure.

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

The node agent is deployed as a Kubernetes DaemonSet with the Helm chart (`charts/ferrum-mesh/`):

```yaml
nodeAgent:
  enabled: true
  # Empty image fields inherit image.repository/tag; with captureMode=ebpf the
  # chart renders <tag>-ebpf automatically.
  image:
    repository: ""
    tag: ""
  captureMode: ebpf
  proxyMode: node_waypoint
  fallbackMode: fail      # set "iptables" only with a custom image that ships iptables tools
  resources:
    limits:
      cpu: 250m
      memory: 256Mi
  capture:
    includeCidrs: "0.0.0.0/0"
    excludeCidrs: ""
    excludePorts: "15001,15006,15008,15020"

# Required when nodeAgent.proxyMode is node_waypoint: the chart refuses to
# render NodeWaypoint mode without ambient enabled in that topology.
ambient:
  enabled: true
  env:
    FERRUM_MESH_TOPOLOGY: node_waypoint
```

Required Linux capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` (kernel >= 5.8), `CAP_SYS_ADMIN` only for kernel-backcompat on 5.7.x (`nodeAgent.security.dropCapSysAdmin=false`; no proxy mode adds it, since veth resolution never enters pod network namespaces). Required volume mounts: `/sys/fs/bpf` (bpffs), `/sys/fs/cgroup` (cgroup v2, read-only). Required host access: `hostNetwork: true`; the node agent takes no `hostPID` (the NodeWaypoint ambient proxy keeps its own). See [`docs/node_agent_security.md`](node_agent_security.md) for the full security posture, including seccomp / AppArmor profiles and the kernel API each capability grants.

### Host-network UDP capture (issue #3288)

Ambient UDP source-capture runs in one of two placements: **`pod-netns`** (the
default, inside each pod's network namespace) or **`host-netns`**
(`FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED=true`, in the mesh proxy's own
namespace; requires `FERRUM_MESH_CAPTURE_UDP_ENABLED=true` and
`FERRUM_MESH_TOPOLOGY=ambient`, otherwise startup fails). Both feed the same
session, relay, and return-path machinery; the host placement attributes each
datagram by ingress interface plus registry-published source address and needs a
CNI with per-pod host interfaces.

- Changing placement or the enabled state is runtime-enforced: it requires the
  two-release cleanup/finalize procedure with one operator-chosen generation.
- Every node-agent restart costs roughly 2.5 seconds of fail-closed UDP per node
  (traffic is dropped, never bypasses capture).
- Ambient nodes without eBPF support refuse node-agent startup rather than use the
  iptables fallback.

The full placement behaviour, ownership/cleanup, upgrade notes, migration
procedure, and the privileged node preflight are in
[node_agent.md → Host-network UDP capture placement](node_agent.md#host-network-udp-capture-placement-issue-3288)
and [Ambient UDP upgrade notes](node_agent.md#ambient-udp-upgrade-notes).

#### Ambient UDP placement migration (enforced hard-upgrade guard)

Moved to [node_agent.md → Ambient UDP placement migration](node_agent.md#ambient-udp-placement-migration-enforced-hard-upgrade-guard).

#### The privileged node preflight

Moved to [node_agent.md → The privileged node preflight](node_agent.md#the-privileged-node-preflight).

### Metrics

The node agent exposes Prometheus counters on the read-only admin `/metrics`
endpoint. The endpoint requires a valid admin JWT or
`FERRUM_METRICS_BEARER_TOKEN`, or a source address admitted by
`FERRUM_METRICS_ALLOWED_CIDRS`; keep that allowlist narrow when scraping over
the cluster network.

- `ferrum_node_agent_pods_enrolled_total` -- total pods successfully enrolled for capture.
- `ferrum_node_agent_pods_unenrolled_total` -- total pods unenrolled (deletion or shutdown).
- `ferrum_node_agent_attach_errors_total` -- total BPF attachment or map update failures.
- `ferrum_node_agent_capture_state{state}` -- gauge. Exactly one state is `1` (`starting`, `ready`, `unavailable`, `partially_attached`, `identity_bridge_unavailable`, `node_global_fallback`).
- `ferrum_mesh_node_topology_degraded{reason}` -- gauge. `1` with the first startup degradation reason; `0` with `reason="none"` when the eBPF path is nominal. See [node_agent.md](node_agent.md#kernel-fallback) for the full reason table and remediations.

### Mixed-kernel clusters

Mesh ambient mode requires Linux kernel >= 5.7 with cgroup v2 and bpffs for the per-pod eBPF capture path. The node agent fails fast on degraded nodes by default (`FERRUM_NODE_AGENT_FALLBACK_MODE=fail`), matching the published distroless `-ebpf` image: it includes `ip` and its runtime libraries for the supported capture path but deliberately omits a shell and the iptables fallback tools. The separately published `-ebpf-tools` variant is the tools-capable superset for the paths that genuinely shell out (the Ambient UDP capture lifecycle and `FERRUM_NODE_AGENT_FALLBACK_MODE=iptables`). The rest of the mesh data plane (slice apply, `mesh_authz`, `mesh_workload_metrics`, HBONE) is unaffected. Operators with a mix of supported and unsupported kernels should:

1. Alert on node-agent readiness/startup failures, `ferrum_node_agent_capture_state{state!="ready"} == 1`, and `ferrum_mesh_node_topology_degraded == 1` to track the degraded set.
2. Label degraded nodes (e.g., `ferrum.io/capture-mode=iptables`) and configure the admission webhook (`FERRUM_MODE=injector`) to inject iptables init containers on those nodes.
3. Upgrade kernels to >= 5.7 with cgroup v2 + bpffs as the long-term remediation.

Set `FERRUM_NODE_AGENT_FALLBACK_MODE=iptables` only when running a custom node-agent image that includes `/bin/sh`, `iptables`, and `ip6tables` when IPv6 capture is enabled.

### Environment Variables

The node-agent variables are indexed under [Node Agent](#node-agent) in Environment Variables at the end of this guide; the capture variables it shares with the injector are under [Injector](#injector). Both link to the canonical tables in configuration.md.

## VirtualService Translation

Istio `VirtualService` resources are translated at the Kubernetes translation layer into Ferrum proxy configuration. Beyond basic route splitting (documented in [configuration.md](configuration.md)), the following per-route features are supported:

### Match predicates

HTTP match predicates are captured by the `mesh_route_dispatch` plugin (translated unconditionally, enabled by default). The translator emits it with `reject_unmatched: true`, so a request that misses every predicate returns 404 instead of falling through to the default backend.

- **`method`, `headers`, `authority`, `queryParams` `StringMatch`** support `exact`, `prefix`, and `regex`. Regex compiles once at config load; invalid regex is a hard translator/plugin construction error. Method `prefix`/`regex` patterns are uppercased. `authority` exact/prefix compare raw `Host`/`:authority` case-sensitively (including an explicit port); authority regex must match the full string (write `(?i)` for case-insensitive). `authority` is a per-rule predicate, distinct from VirtualService-level `hosts`. `queryParams` regex matches the full canonical decoded value.
- **`withoutHeaders`** (`match.without_headers`): any listed header that is present and matches vetoes the rule; presence-only `withoutHeaders: {x-legacy: {}}` projects as `{regex: ".*"}` (header must be absent).
- **`port`** (`match.port`) is read from trusted provenance only — the capture original destination, otherwise the frontend listener port, never `Host`.
- **`sourceNamespace`** reads the peer SPIFFE identity's namespace; it fails closed without a resolved peer, and empty/whitespace values fail closed via `request_termination`.
- **`ignoreUriCase: true`** affects exact/prefix URI matches only (widened to case-insensitive regex listen paths and re-evaluated with ASCII-only case folding); `regex` URI matches are unchanged.
- A malformed operand (invalid regex, empty prefix, invalid or case-colliding `withoutHeaders` name, non-integer or `0` port) and the unsupported `sourceLabels` / `gateways` / `scheme` HTTP predicates emit proxy-scoped `request_termination` instead of widening traffic.
- Same-path and URI-less ordered routes collapse into one Proxy with ordered dispatch rules so predicate misses fall through to a later route; per-rule `timeout`, `retries`, header transforms, and `fault` ride on each dispatch rule. Admission plugins such as `mesh_authz` and rate limiting still evaluate the original public proxy identity.

Example: `match: [{ uri: { prefix: "/api" }, authority: { prefix: "api." } }]` routes `Host: api.staging.example.com` but not `Host: API.staging.example.com`.

### Retries

VirtualService `retries` populate the emitted proxy's retry policy and are also projected onto each emitted `mesh_route_dispatch` rule as route-local `retry` (Ferrum `RetryConfig` after strict admission):

- `attempts` -> `max_retries`
- `retryOn` supports `5xx`, `gateway-error`, `connect-failure`, `reset`, `refused-stream`, `retriable-status-codes`, and numeric HTTP status codes (for example `503`); `retriable-4xx` is not recognized.
- When `retryOn` includes `retriable-status-codes`, `retriableStatusCodes` supplies the explicit status codes to retry (valid codes are 100 through 599).
- `perTryTimeout` is not translated; the separate route-level `timeout` controls the backend read timeout.

Route-local `retry` and destination `backend_tls` objects reject unknown keys at plugin admission (same fail-closed contract as `reject_unmatched` / `requires_node_waypoint_authz`). Shared proxy/upstream `RetryConfig` and `BackendTlsConfig` deserialization is not affected; only the mesh-route wire shapes are strict.

### Timeout

VirtualService `timeout` is translated to the proxy's `backend_read_timeout_ms`. Supports Go-style duration strings (`10s`, `500ms`, `1m`, `1h`).

### Fault Injection

Per-route `fault` rides on each emitted `mesh_route_dispatch` rule as a per-rule `fault` action (`{delay, abort}`) — the same `FaultRoller` math the proxy-scoped `fault_injection` plugin uses, scoped to the matching dispatch rule.

- `fault.abort.httpStatus` + `fault.abort.percentage` → rule `fault.abort` with `status_code` + `percentage`. `abort` is dropped (along with the rest of the rule's fault) when `httpStatus` is missing or the percentage is `0`; an accompanying valid `delay` still projects.
- `fault.delay.fixedDelay` + `fault.delay.percentage` → rule `fault.delay` with `duration_ms` + `percentage`. `fixedDelay` accepts Istio's Go-style duration syntax. Positive values above Ferrum's one-minute runtime cap are clamped to 60 seconds, with a translator warning and `status.ferrum.translation.clamped_fields` entry; zero or unparseable values are omitted.
- `fault.abort.grpcStatus` (string or numeric `0..=16`) → `fault.abort.grpc_status`. The header is only stamped when the immutable pre-plugin request flavor is native gRPC; gRPC-Web, WebSocket, and plain HTTP never receive a stray `grpc-status` header even if an earlier hook rewrites `content-type`.

**Delayed-work retention bounds:** a per-rule delay shares the proxy-scoped plugin's bounds exactly — the one-minute ceiling, the process-wide `FERRUM_MAX_CONCURRENT_FAULT_DELAYS` budget (shared with every `fault_injection` instance), and cancellation on peer departure or shutdown drain. A delay cut short because the client transport is gone rejects `499` instead of falling through to the route override; the reason is recorded in `fault_delay_outcome`. See `docs/plugins.md` → `fault_injection`.

**Ordering:** when both delay and abort trigger on the same request, the delay runs first, then the abort fires — matching the proxy-scoped `fault_injection` plugin so the two surfaces stay semantically identical. A global / proxy-scoped `fault_injection` plugin running before this one (priority 2940 vs 2995) sets `ctx.metadata["fault_injected"]=true`, and the per-rule fault no-ops in that case so the two surfaces never stack a second delay + abort.

**RTDS scope (limitation):** the static percentages baked into a per-rule fault action are **not** runtime-tunable via the RTDS keys `ferrum.fault_injection.<scope>.{abort,delay}_percent` — those keys apply only to `fault_injection` plugin instances configured with a non-null `runtime_overlay_scope`. A null scope is equivalent to omission. Operators who need RTDS-driven fault percentages should use a global / proxy-scoped `fault_injection` plugin with `runtime_overlay_scope`.

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

### Header Transforms

Per-route `headers.{request,response}.{set,add,remove}` (Istio
`http[].headers`) is projected onto every emitted `mesh_route_dispatch` rule as
`request_transform` / `response_transform`, and the translator auto-attaches the
consuming transformer instances on the materialized proxy —
`istio-vs-req-xform-{proxy_id}` (`request_transformer`) and
`istio-vs-resp-xform-{proxy_id}` (`response_transformer`), each emitted exactly
once and only when a rule actually carries transforms of that direction. An
operator-configured `request_transformer` / `response_transformer` on the same
route wins (no second instance is emitted); route-level rules are applied after
the last eligible instance's static rules, so a later static rule cannot undo a
route `remove` or `set`.

- `set` → `update` (insert or replace), `add` → append (comma-joined;
  newline-joined for `Set-Cookie`), `remove` → delete every value for the key.
  Rules apply in declaration order, so an `add` after a `remove` reinstates the
  header with the new value.
- `headers.request.remove: [x-internal-auth]` strips the CLIENT header before
  backend dispatch — this is the security-relevant case, and it is why a
  malformed sibling entry is not silently dropped.
- Per-destination `http[].route[].headers` is applied for a route with exactly
  ONE destination before the route-level block, matching Envoy's weighted-
  cluster → route ordering so the route-level `set` wins. On a weighted
  multi-destination route it is reported in
  `status.ferrum.translation.deferred_fields` instead: the split materializes
  one upstream with weighted targets, so no per-destination rule exists to bind
  the transform to and applying it would hit every share.
- Request `set` on `Host` or `:authority` is projected onto the typed route
  authority rewrite so it works across HTTP versions; it is not sent through
  the generic header transformer. `add` remains invalid for authority.
- Malformed header names, non-string or header-illegal values (CR/LF and other
  control bytes), unknown fields under `headers` / `headers.{direction}`, and
  `set`/`add` targeting a framing or hop-by-hop header (`content-length`,
  `connection`, `keep-alive`, `proxy-connection`, `te`,
  `trailer`, `transfer-encoding`, `upgrade`) are rejected at translation with
  `FerrumAccepted=False` / `Invalid`. Diagnostics name the header and field,
  never the value. `remove` may name any header.

### Traffic Mirroring

Per-route `mirror` (Istio `http[].mirror` + `mirrorPercentage` / legacy `mirrorPercent`) is translated to a proxy-scoped [`request_mirror`](plugins.md) plugin attached to the route's proxy:

- `mirror.host` + `mirror.port` (number or `Service` port `name`) → `mirror_host` / `mirror_port`. A missing `mirror.host`, or a `port.name` that does not resolve, fails translation closed.
- `mirrorPercentage.value` (float `0–100`) or the legacy `mirrorPercent` (integer) → `percentage`. Default is `100`. A `0%` mirror emits **no** plugin (it would be a no-op).

Because mirror is a per-route action realized as a proxy-scoped plugin, a route carrying a mirror is route-local: if that route would have to be **collapsed** with a sibling route onto one Ferrum proxy (rare — same listen path, guarded predicates), translation **fails closed** rather than silently mirroring the sibling's traffic. Model such cases with distinct listen paths.

The shadow request reflects the final selected route. When `rewrite.uri` is
present and the mirror plugin has no explicit `mirror_path`, it reuses the
rebased URI without consuming the override required by primary dispatch. An
explicit `mirror_path` is an operator override and wins. For route-local mesh
mirrors, the configured mirror destination remains the dial/TLS identity, while
the application Host/authority is the selected rewritten authority (or the
selected request Host when no authority rewrite exists) with the Envoy/Istio
`-shadow` suffix. This mesh-only behavior does not relax standalone
`request_mirror` egress sanitization.

### URI / Authority Rewrite

Per-route `rewrite` (Istio `http[].rewrite`) rides on each emitted `mesh_route_dispatch` rule as a per-rule `rewrite` action, so it follows the matched route through route-collapse without rewriting sibling routes:

- `rewrite.uri` → the request path forwarded to the backend. When the route's `match.uri` is a `prefix`, Istio prefix-rewrite semantics apply — only the matched prefix is replaced and the remainder is preserved (`/api/users` with `prefix: /api`, `rewrite.uri: /v2` → `/v2/users`). The replacement is literal: the unmatched suffix is appended verbatim, so a prefix that ends inside a path segment keeps that segment intact (`prefix: /prefix/old`, `rewrite.uri: /new` → `/prefix/oldtail` forwards as `/newtail`, not `/new/tail`). Two boundary adjustments survive that: a doubled separator is collapsed when both sides carry a `/`, which is Envoy's documented `prefix: /prefix` + `prefix_rewrite: /` pairing (`/prefix/etc` → `/etc`); and a suffix whose first complete segment is `.` or `..` keeps its segment boundary, so a traversal operand written immediately after the matched prefix remains visible and is refused (`/prefix/old../admin` composes `/new/../admin` and is rejected with 400). Other dot-leading suffixes remain literal: `/prefix/old.env` becomes `/new.env` and `/prefix/old..hidden` becomes `/new..hidden`. For `exact` / `regex` matches (and URI-less matches) the whole path is replaced. The original path is still used for route selection and logging.
- `rewrite.authority` → the authority forwarded to the backend. The plugin writes the new authority into the request `Host` header and flips `preserve_host_header` on the effective proxy. For HTTP/1.1 backends (reqwest) the `Host` header is the on-wire request authority, so the rewrite takes full effect. For HTTP/2, gRPC, and HTTP/3 backends the `:authority` pseudo-header is derived from the backend connection target URL (the pool key's host/port), not the `Host` header; the rewrite lands in the `Host` header that travels as an application header within the H2/H3 frame, but the protocol-level `:authority` follows the backend target. HBONE CONNECT carries the rewritten `Host` in its CONNECT request headers, which the receiving mesh proxy reads as the application authority.

`rewrite.uri` must be a canonical absolute path without a query or fragment; percent escapes, dot segments, backslashes, and CRLF are rejected at config load. The composed prefix replacement and request suffix are checked again before publishing the override. A composition that creates a dot segment or forbidden escape is refused with HTTP 400 (or the corresponding RPC error), before backend-path policy and dispatch; dot segments are never removed. Existing slash joining, backend base-path composition, and the original client path used for route selection and logging are preserved. The shared before-proxy boundary applies the canonical path contract to provider overrides as well, including deferred and absolute overrides.

CRLF and whitespace in authority rewrite values are rejected at config load.

### Redirect

Per-route `redirect` (Istio `http[].redirect`) rides on each emitted `mesh_route_dispatch` rule as a per-rule `redirect` action. When the rule matches, the request is answered with a 3xx + `Location` response and never reaches a backend (so a redirect route needs no `route[]` backend — Istio forbids `route` + `redirect` together):

- `redirect.uri` → replacement path (request path preserved when unset). When the rule carries `match_prefix`, only that prefix is replaced and the unmatched suffix is appended verbatim, sharing the literal-substitution contract described under [URI / Authority Rewrite](#uri--authority-rewrite). The composed path is canonicalized before `Location` is emitted; a composition containing a `.` or `..` segment is refused with `400` rather than redirected.
- `redirect.authority` → replacement authority (request `Host`/`:authority` preserved when unset).
- `redirect.port` → replacement authority port (mutually exclusive with `derivePort`; request host preserved when authority is unset).
- `redirect.derivePort` → dynamic port selection projected as `derive_port`:
  - `FROM_PROTOCOL_DEFAULT` → scheme default (`80` for `http`, `443` for `https`), including when `scheme` is also overridden.
  - `FROM_REQUEST_PORT` → trusted request port: original-destination port when capture rewrote the accept socket, otherwise the frontend listener port. Spoofable forwarding headers (`X-Forwarded-Port`, `Forwarded`) are never consulted.
- `redirect.scheme` → replacement scheme (`http`/`https`; request frontend scheme preserved when unset).
- `redirect.redirectCode` → status code (`300–399`, default `301`).

Scheme-default ports are omitted from the rendered `Location` authority (`http://host` not `http://host:80`; `https://host` not `https://host:443`). Bracketed IPv6 authorities keep their brackets when a non-default port is applied. Invalid `port` / `derivePort` values and setting both fields together fail translation closed with field-specific diagnostics.

The redirect takes precedence over `rewrite` and the route-override destination on the same rule. When no authority is resolvable, an origin-relative `Location` (path only) is emitted.

### L4 routing (`spec.tcp` / `spec.tls`)

VirtualService L4 routing is materialized into Ferrum stream proxies, reusing the same stream + SNI machinery as the gateway and east-west passthrough:

- **`spec.tls[]`** → a **passthrough TCP** proxy keyed by SNI: `match[].sniHosts` become the proxy's `hosts`, `match[].port` (or the destination port) the listen port, and the proxy forwards the **encrypted** bytes to the destination without terminating TLS. Multiple `tls[]` matches sharing a port are SNI-routed (`resolve_proxy_by_sni`), then filtered by any compiled L4 `stream_match`.
- **`spec.tcp[]`** → a plain **TCP** proxy keyed by `listen_port` (`match[].port`, or the destination port), forwarding to the destination. Multiple matches sharing a port with L4 predicates share one listener and resolve by first-match `stream_match` evaluation.

SNI routing is not exclusive to `passthrough: true`: the same plane admits any stream listener that terminates nothing, including an ordinary `tcp` listener with `frontend_tls: false` that declares `hosts` (issue #3264). The peek, precedence ladder, normalization rules, and fail-closed admission for indeterminate ClientHellos are documented once in [TCP/UDP stream proxy → Opaque TLS SNI routing](tcp_udp_proxy.md#opaque-tls-sni-routing) and apply identically to mesh-materialized `tls[]` proxies, Gateway API `TLSRoute`, east-west passthrough, and hand-authored stream proxies.

Optional L4 match predicates compile onto `Proxy.stream_match` (AND within one match arm; OR across match candidates) and are evaluated from trustworthy evidence before the stream route is selected:

| Predicate | Evidence | Deny-by-absence |
|---|---|---|
| `sourceLabels` | On the `mesh` arm in Sidecar topology, the authoritative local workload labels materialized with the accepted slice; for ambient/NodeWaypoint runtime matching, labels from the exact NodeWaypoint pod scope or authenticated-peer-SPIFFE workloads narrowed by authoritative canonical client IP. Missing or divergent replica evidence fails closed | Yes |
| `sourceNamespace` | On the `mesh` arm in Sidecar topology, the unambiguously resolved local workload namespace, verified against the sidecar SPIFFE identity; for ambient/NodeWaypoint runtime matching, the namespace from exact authenticated source-workload evidence | Yes |
| `sourceSubnets` | Authoritative canonical `client_ip`: the trusted PROXY-protocol forwarded source after peer validation, otherwise the direct socket peer; never a client header | Yes |
| `destinationSubnets` | Capture original destination: NodeWaypoint eBPF resolver metadata first, then `SO_ORIGINAL_DST` as the non-eBPF fallback | Yes |
| `gateways` | Listener-configured binding (`FERRUM_STREAM_GATEWAY_REF`) — never inferred from wire data | Yes |

Istio gateway semantics: omitted VS/`match.gateways` defaults to the reserved `mesh` token; match-level `gateways` override VS-level; short names qualify as `{vs-namespace}/{name}`. Ferrum supplies the process-level implicit `mesh` binding only in `mesh` mode with **Sidecar** topology, because that is the topology that materializes sidecar-applicable L4 VirtualServices onto these stream listeners. Non-mesh listeners and Ambient/Waypoint/NodeWaypoint topologies receive no implicit binding and therefore cannot be accidentally classified as mesh; an operator may explicitly configure trusted `mesh` or canonical `namespace/name`, while an explicit empty value clears the binding and denies gateway predicates. The binding is parsed once during startup and is never wire-derived. A present top-level `spec.gateways` must be a non-empty string array; malformed, mixed, or empty values reject the L4 resource instead of widening it to `mesh`. Named-gateway data planes must set `FERRUM_STREAM_GATEWAY_REF` to `namespace/name`. Invalid label keys/values, namespaces, gateway names, CIDRs, and over-bound matcher lists fail admission closed for translated and hand-authored/file/admin configurations. **Weighted multi-destination splitting** materializes an upstream-backed stream proxy with relative WRR weights (zero-weight multi-destination legs skipped; all-zero multi-destination splits materialize a fail-closed `ferrum-zero-weight.invalid.` blackhole backend so the match remains traffic-capturing). Invalid weights and multi-destination port disagreement without `match.port` fail closed. `destination.subset` fails closed on **any** `tcp[]`/`tls[]` destination, single or weighted — a stream proxy has no subset selector, so a subset destination is rejected rather than silently widened to the whole service. A `tls[]` match without `sniHosts`, or any L4 route without a resolvable destination port, also fails closed.

**Rule order, visibility, and bounds.** Rules keep VirtualService declaration order, including an earlier catch-all or wildcard TLS rule; generic hand-authored passthrough proxies without L4 criteria keep exact-SNI-before-wildcard precedence. Every `tls[].match.sniHosts` entry must be a subset of `spec.hosts`; Istio wildcard SNI additionally materializes its suffix apex. `spec.exportTo` projects each L4 proxy into the sidecar or named-gateway namespace that may consume it, with match-level gateway overrides filtered per namespace. The combined `tcp[]`/`tls[]` candidate count is capped at `MAX_L4_CANDIDATE_PROXIES` (64) before materialization, and `candidates × export namespaces` at `MAX_PROJECTED_L4_PROXIES` (1024), both fail-closed. Weighted L4 upstreams ride `MeshSlice.virtual_service_l4_upstreams` / `VirtualServiceL4UpstreamsCarrier` beside the L4 proxies so reload/delete cannot retain a stale load-balancer set.

`sourceLabels` and `sourceNamespace` are Istio source-workload selectors, not predicates on an inbound peer connection. For a Sidecar `mesh` arm, Ferrum resolves them once against the accepted slice's local workload identity/namespace/labels, removes non-applicable arms, and retains the remaining subnet/gateway/SNI predicates with AND semantics and declaration order intact. The local workload must resolve unambiguously; a shared SPIFFE with divergent labels cannot lend one replica's labels to another. Named-gateway projections remain independent of these selectors. The projected L4 proxies ride native and xDS mesh-slice updates, and slice content equality includes them so update/delete cannot retain stale applicability or listener candidates.

### CORS policy (`http[].corsPolicy`)

`http[].corsPolicy` is translated to a proxy-scoped `cors` plugin.

- **Matchers.** The full `allowOrigins[]` `StringMatch` set — `exact`, `prefix`, `regex` — plus the legacy `allowOrigin` list. `exact` is projected onto the plugin's LITERAL `{"exact": ...}` matcher byte-for-byte (issue #3254), so a wildcard-shaped exact such as `*.example.com` or a noncanonical `https://Example.com:443` is never reinterpreted or canonicalized; `prefix` is a literal byte-prefix and `regex` an RE2 full match, compiled once at config load. A matching origin is reflected verbatim.
- **Credentialed wildcards.** Uncredentialed exact `*` is Istio allow-all. Credentialed exact `*`, opaque exact `null`, and credentialed effectively universal prefix/regex are **deferred** (issue #4269). Prefix breadth is judged at the origin boundary (issue #4522: only `scheme://host:` pins the host), and regex breadth is probed against reserved DNS-shaped origins (issue #4521).
- **Bounds** (shared by translator, plugin, and native/file validation, issue #3253): 64 `allowOrigins[]` entries, 512 bytes per matcher value, and for `regex` a 64 KiB compiled-program limit, 64 KiB lazy-DFA limit, and AST nesting depth 24. An un-compilable or over-budget matcher, an empty/whitespace-only `exact`, an empty `prefix`, an invalid method/header token, or an unknown matcher leaves the policy unprojected (warned, `deferred_fields`) — never approximated or widened. Configure the `cors` plugin directly for those.
- **Forwarding semantics.** Unmatched actual requests and omitted/`UNSPECIFIED`/`FORWARD` unmatched preflights are forwarded with the upstream status/body preserved, every upstream `Access-Control-*` response field stripped, and no gateway CORS authorization added; `IGNORE` answers a local 200 without CORS authorization. A participating policy strips upstream `Access-Control-*` fields even without an `Origin`. Omitted or empty method/header lists stay empty, omitted `maxAge` stays absent, and method/header lists govern preflight only.
- **Sidecar carriage.** On mesh sidecars a translatable policy also rides `mesh.virtual_service_cors_policies` (one entry per VS host) and the client sidecar synthesizes the `cors` plugin onto its outbound routes (issue #1973). Per host, the **first sidecar-applicable** `http[]` entry decides: if it is host-wide (no `match`, or a catch-all `/` prefix) its translatable policy is carried; if it has no policy, an untranslatable one, or is predicate-scoped (narrower uri, `headers`, `port`, `sourceLabels`, …), nothing is carried. Sidecar applicability is resolved per entry (`match[].gateways` override `spec.gateways`; the `mesh` gateway applies to sidecars). Synthesis is client-Sidecar-topology only.
- **`exportTo` visibility** uses the shared ServiceEntry/DestinationRule evaluator and is enforced at CP slice narrowing, the xDS carrier fold, and DP plugin synthesis. An omitted `exportTo` is carried as `["*"]`; an empty `export_to` on native/file is namespace-local. A malformed `exportTo` (non-array, non-string entry, `~`, empty entry, invalid namespace, over 64 entries, or `*` mixed with a namespace) makes the VirtualService `FerrumAccepted=False`/`Invalid` and is rejected by native/file/xDS slice validation.

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

When `FERRUM_K8S_CONTROLLER_ENABLED=true` and Gateway API watching is enabled, the controller watches the kinds below and writes status for them. For conformance scope and the release-gating labs see [`docs/gateway_api_conformance.md`](gateway_api_conformance.md).

### Watched kinds

- `GatewayClass`, `Gateway`, `ListenerSet` (optional; discovery skips when the CRD is absent).
- `HTTPRoute`, `GRPCRoute`, `TCPRoute`, `TLSRoute`, `UDPRoute`, `ReferenceGrant`.
- `BackendTLSPolicy`, `BackendLBPolicy` (historical `v1alpha2`, when installed), `XBackendTrafficPolicy` (pinned `v1.5.1` experimental successor).
- `UDPResponseAmplificationPolicy` (`gateway.ferrum.io/v1alpha1`; discovery skips when the CRD is absent).
- MCS `ServiceImport` (`multicluster.x-k8s.io`, when installed) for GEP-1748 backendRefs.

Status subresources are written for GatewayClass, Gateway, ListenerSet, the route kinds, `BackendTLSPolicy`, `UDPResponseAmplificationPolicy`, and BackendLB/`XBackendTrafficPolicy`.

### Status ownership

- **GatewayClass / Gateway / ListenerSet:** Kubernetes server-side apply with field manager `ferrum.io/gateway-controller` and `force=true`; their condition/listener arrays are keyed list-maps, so Ferrum applies only the fields it owns. Each apply carries the freshly read `metadata.resourceVersion` as a compare-and-swap precondition (`force` wins field-manager ownership, not a stale resourceVersion); a live read that fails or lacks a non-empty `resourceVersion` refuses the write and fails the batch.
- **Route `status.parents` and policy `status.ancestors`:** atomic arrays in the upstream CRDs, so Ferrum follows the read-modify-write mandate: preserve fresh non-Ferrum entries, replace Ferrum-owned ones (within the 16-entry ancestor budget for policies), guard the merge patch with `metadata.resourceVersion`, and refetch/re-merge/retry up to five times with jitter after `409 Conflict`. A late write against a newer live object is a `409`, never a stale overwrite.
- Ferrum manages only `GatewayClass` objects whose `spec.controllerName` is `ferrum.io/gateway-controller`. A Gateway is Ferrum-managed only when that class is present in the current authoritative snapshot with that controller name; an absent or foreign-owned class (including a foreign object named `ferrum`) is ignored, and Ferrum withdraws generated listeners, proxies, route attachments, and frontend TLS on the next complete reconcile. Ownership is never inferred from the class name. Non-default Ferrum-owned class names work when explicitly referenced. The `ferrum-mesh` chart creates the class by default (`gatewayClass.create`).
- `Gateway.status.conditions` and route `status.parents[].conditions` carry Ferrum-authored `Accepted`, `Programmed`, `ResolvedRefs`, and `Conflicted`. Accepted routes report programmed from typed route-to-parent materialization records (never by parsing proxy IDs); rejected routes report unresolved references (missing `ReferenceGrant`, unsupported backend kinds); route collisions report `Conflicted=True`.
- **`BackendTLSPolicy`** is translated onto Service-backed HTTPRoute/GRPCRoute backends and receives `PolicyStatus` (`status.ancestors[]`). Its ancestor is the targeted Service (the verdict takes no Gateway as input), so Ferrum contributes at most one entry, and only for a policy whose Service a managed Gateway effectively routes to. Conditions use the portable `PolicyConditionReason` vocabulary (`Accepted` / `Conflicted` / `Invalid` / `NoValidCACertificate` / `TargetNotFound`; `ResolvedRefs` / `InvalidCACertificateRef` / `InvalidKind` / `RefNotPermitted`).
- **Full ancestor map:** if other controllers have filled a policy's 16-entry `ancestors` maximum, Ferrum publishes no entry, but the policy still translates (backend TLS, session persistence). The ceiling constrains only the status writer, so a controller with status-write access cannot disable the policy's effect.
- When Istio status writing is also enabled, both writers observe the same Kubernetes object generation per reconcile (one shared snapshot) with independent update plans and failure handling. Status planning reuses the primary translation result instead of retranslating per object.

### Bounded status writes

A status patch batch runs inline on the single serialized reconcile loop, so while it runs no other object's status is published (issue #4239). The bounds:

| Bound | Value |
|---|---|
| Per API request | 5 s |
| Per object read-modify-write | 10 s |
| Per writer batch (also clamps the two above) | 15 s |
| Reconciler backstop around the batch | 20 s |
| Gateway API status plan budget per reconcile | 256 candidates (rotating cursor; Istio status planning is unlimited) |
| Consecutive failed batches before the cursor advances anyway | 3 (`STATUS_WINDOW_MAX_FAILED_BATCHES`, issue #6370) |
| Route/policy `409 Conflict` retry attempts | 5, with jitter |

- The plan budget applies *before* per-object status computation, so it bounds CPU as well as API writes. Every eligible Gateway API kind (including GatewayClass and Gateway) shares the window and is planned within `ceil(eligible_candidates / 256)` successful rounds for a stable set.
- A budget expiry names the object (kind, namespace, name, read or write), counts `ferrum_k8s_controller_status_request_timeouts_total`, and fails the batch; the same window is retried next reconcile, with succeeded objects dropping out. After three consecutive failed batches the cursor advances so a persistently failing object (for example a 403/422) cannot starve the rest; it stays unsynchronized until its next turn.
- Abandoning an in-flight write is not a CAS — a timed-out request can still finish later — which is why SSA applies carry the `resourceVersion` precondition.
- Keep the batch budget well below any external observer's wait (such as the Gateway API conformance suite's parent-status wait).

### Route kinds and release gating

- **TCPRoute:** live attachment/traffic/status/update/deletion evidence is release-gated by the Gateway API conformance black-box lab; Ferrum does not advertise an upstream `GATEWAY-TCP` profile on the pinned `v1.5.1` channel.
- **TLSRoute:** release-gated by the same lab. Dual-watched at `gateway.networking.k8s.io/v1` and `v1alpha2`; discovery skips an unserved version, and objects under both versions are de-duplicated by `(group, kind, namespace, name)` (as for `HTTPRoute` `v1`/`v1beta1`). Materializes SNI passthrough stream proxies on `protocol: TLS` / `tls.mode: Passthrough` listeners. `TLSRouteModeTerminate` is not implemented: non-Passthrough TLS listeners are rejected and never materialized. No upstream `GATEWAY-TLS` profile is advertised.
- **UDPRoute:** release-gated by the required `Tests` aggregate (translation/status by CI Unit Tests; the live UDP data path on `start_udp_listener` by CI Integration Tests). No upstream `GATEWAY-UDP` profile is advertised. `UDPRoute` does not claim `ServiceImport` backendRefs.
- **HTTPRoute/GRPCRoute conflicts** are resolved before materialization: for routes producing the same parent reference, hostname, and listen path, the oldest `metadata.creationTimestamp` wins, then `{namespace}/{name}`. A loser gets `Conflicted=True`; a parent with another surviving match can stay `Accepted=True` / `Programmed=True`. Do not infer the same result for UDPRoute.

### UDPResponseAmplificationPolicy

Ferrum Direct Policy Attachment for UDP response-amplification limits. Ordinary `UDPRoute` translation never programs an unlimited relay: Ferrum projects a finite default of `8.0` unless a valid policy wins, and an invalid, unauthorized, or deleted policy fails closed to the next precedence. Unlimited requires `mode: Unlimited` and `acknowledgeUnsafeAmplification: true`. Cross-namespace `targetRefs` require a `ReferenceGrant` from `gateway.ferrum.io`/`UDPResponseAmplificationPolicy` to `Gateway` or `UDPRoute`. Policy `status.ancestors` carries `Accepted`/`ResolvedRefs` for every named target; a policy naming none (the `GatewayClass.parametersRef`-only shape, or unparseable `targetRefs`: duplicates, `sectionName` on a `UDPRoute` target, a foreign `group`) publishes an empty array, and its rejection is visible only as a controller warning. `UDPRoute.status.parents[].conditions` includes `UDPAmplificationProtection` (`FiniteDefault` / `FinitePolicy` / `ExplicitUnlimited`, or `False` / `NotProgrammed`). See [`docs/tcp_udp_proxy.md`](tcp_udp_proxy.md).

### BackendLBPolicy / XBackendTrafficPolicy

Direct attachment uses the same oldest-wins precedence as translation (creationTimestamp, then full resource identity across kinds). Field validation runs first, then conflicts: a policy that wins every Service target stays `Accepted=True`; one that loses any target is `Accepted=False` / `Conflicted` and is withdrawn from *every* Service it targets, so a `Conflicted` policy never steers traffic. Invalid policies keep field-specific `UnsupportedValue` rejection and never win conflicts. Status preserves other implementations' ancestor entries and keeps `lastTransitionTime` for unchanged conditions.

### Listener `allowedRoutes.namespaces.selector`

The selector is an atomic security boundary. Ferrum validates it completely before attachment (label-key/value syntax, string-only `matchLabels`, expression field types, the `In`/`NotIn` non-empty-values rule, the `Exists`/`DoesNotExist` empty-values rule). Any malformed component invalidates that listener as a whole: no subset of its requirements is kept, no cross-namespace route attaches, and a valid-to-invalid update withdraws prior materialization. Listener status reports `Accepted=False` / `Programmed=False` with reason `Invalid` and a value-redacted field path. Valid sibling listeners reconcile independently.

### MCS ServiceImport backendRefs

- Only the exact `multicluster.x-k8s.io` API group matches. TCP ports are admitted (an omitted protocol defaults to `TCP`); UDP, SCTP, unknown, or malformed protocols report `UnsupportedProtocol`. An omitted backendRef port is derived only when the import exposes exactly one valid TCP port.
- HTTPRoute/GRPCRoute backends can expand across ready MCS-labeled EndpointSlice addresses when pod discovery is enabled; TCPRoute/TLSRoute keep the ClusterSet DNS name. A **named** `ServiceImport.spec.ports[]` entry maps to the like-named slice port, an **unnamed** one to a single-port slice; a slice with no unambiguous mapping is skipped and the backend falls back to the ClusterSet DNS name.
- A slice is used only when its `endpointslice.kubernetes.io/managed-by` names a controller other than Kubernetes' own (`endpointslice-controller.k8s.io` / `endpointslicemirroring-controller.k8s.io`), its `multicluster.kubernetes.io/service-name` names an observed ServiceImport in its namespace, and the namespace is inside the controller's Pod watch scope; otherwise it is ignored with a translation warning. `managed-by` is provenance against label propagation, not proof of authorship.
- Within an admitted slice an address is refused (with a warning) when it is on the special-address deny list (loopback, link-local, unspecified, multicast, broadcast, cloud metadata, including NAT64 and IPv4-compatible forms), is not an IP, belongs to an endpoint whose `targetRef` names another namespace, or is this cluster's infrastructure (another namespace's observed Pod, a Service ClusterIP, an observed Node address, an observed Node's Pod CIDR). The exported same-named Service's own ClusterIP (Submariner Lighthouse's local-cluster slice) is kept only while that Service's own slices pass backendRef attribution with no finding. Everything else is admitted as a remote endpoint; when nothing is left the backend falls back to the ClusterSet DNS name.
- Node checks need the Node watch (`FERRUM_K8S_NODE_LOCALITY_ENABLED=true` with `nodes` `list`/`watch` RBAC) and other-namespace Pod checks need a cluster-wide Pod watch (`FERRUM_CP_NAMESPACES="*"` with `FERRUM_K8S_WATCH_NAMESPACES` unset); the default CP has neither, so those addresses are admitted and each reconcile that admits an import slice logs what went unchecked.
- Trust boundary: the MCS controller plus EndpointSlice write RBAC. Restrict EndpointSlice writes in import namespaces to the MCS controller. A ReferenceGrant to a ServiceImport extends that trust to every route it authorizes (unlike `FERRUM_K8S_ALLOW_SELECTORLESS_EXTERNAL_ENDPOINTS`, which never applies through a grant).
- The DNS fallback dials the ServiceImport port; for a `type: Headless` import that reaches Pod addresses, so keep its port equal to the container port or make sure its slices are admitted.

### backendRef endpoint attribution

- backendRefs stay inside the referenced Service's namespace on every route kind. `type: ExternalName` Services are refused (`ResolvedRefs=False` / `UnsupportedProtocol`).
- Every other Service is checked against the EndpointSlices carrying its `kubernetes.io/service-name` label (including slices that also carry the MCS label). Selector-less and selector-backed Services are checked the same way, because anyone who can write EndpointSlices can attach an extra slice by label (the CVE-2021-25740 class).
- With pod discovery enabled, the backendRef is admitted only when every endpoint address (ready or not) belongs to an observed, non-host-network, non-terminal Pod in the Service's namespace and to no other namespace's Pod. An endpoint reporting both `ready: false` and `serving: false` is skipped. For a selector-backed Service an endpoint is also admitted when its `targetRef` names an observed same-namespace Pod whose status reports that address (host-network DaemonSets); otherwise a `targetRef` can refuse but never vouch.
- A Pod's IP claim outlives the Pod by 60 seconds (counted from the first reconcile that no longer observes it). With a cluster-wide Pod watch scope it vouches for any endpoint; with a restricted scope (the default) only for an endpoint reporting `terminating: true` with explicit `ready: false`. A claim from a Pod observed now always wins.
- Always refused: a `targetRef` naming another namespace, an IP another namespace's observed Pod reports, an FQDN or unparseable address, and the special-address deny list (`0.0.0.0/8`, loopback, link-local, multicast, broadcast, `169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`, `168.63.129.16`, including NAT64 `64:ff9b::/96` and IPv4-compatible forms). The deny list applies before any Pod claim.
- Unclaimed addresses are refused unless `FERRUM_K8S_ALLOW_SELECTORLESS_EXTERNAL_ENDPOINTS=true`, which admits them only for a selector-less Service, only for same-namespace routes, never through a ReferenceGrant, and never for a Service ClusterIP, Node address, or Node Pod CIDR. The opt-in is active only with the Node watch (`FERRUM_K8S_POD_DISCOVERY_ENABLED=true` plus `FERRUM_K8S_NODE_LOCALITY_ENABLED=true` and `nodes` `list`/`watch` RBAC, chart `controlPlane.rbac.nodeLocality`); otherwise the CP logs a startup or translation warning and unattributed IPs stay refused.
- A refusal fails the HTTPRoute/GRPCRoute backend closed, rejects a TCPRoute/TLSRoute/UDPRoute, reports `ResolvedRefs=False` / `RefNotPermitted`, and logs a translation warning.
- Without observed Pods in the Service's namespace (pod discovery off, or outside the watch scope), a selector-less Service is refused as unverifiable and a selector-backed Service is admitted with a warning. Keep pod discovery on wherever Gateway API routes are translated.
- An EndpointSlice controller lagging far behind a deletion, or a slice observed before its Pod, can refuse a backend until a later reconcile. A selector-backed Service fed by a third-party EndpointSlice writer (KubeVirt, Multus, some multi-cluster setups) is refused: move it to a selector-less Service and set the opt-in. The guard is built only when the snapshot contains a Gateway API route.

### RBAC

| Verbs | Resources |
|---|---|
| `get/list/watch` | `gatewayclasses`, `gateways`, `listenersets`, `httproutes`, `grpcroutes`, `tcproutes`, `tlsroutes`, `udproutes`, `referencegrants`, `backendtlspolicies`, `backendlbpolicies` (`gateway.networking.k8s.io`) |
| `get/list/watch` | `xbackendtrafficpolicies` (`gateway.networking.x-k8s.io` — not covered by a `gateway.networking.k8s.io` grant) |
| `get/list/watch` | `udpresponseamplificationpolicies` (`gateway.ferrum.io`) |
| `get/list/watch` | `serviceimports` (`multicluster.x-k8s.io`) |
| `get/list/watch` | core `namespaces` (part of the `allowedRoutes.namespaces.from: Selector` authorization boundary), `secrets`, `configmaps`, `services` |
| `get/list/watch` | `endpointslices` (`discovery.k8s.io`) |
| `get/patch/update` | `status` of `gatewayclasses`, `gateways`, `listenersets`, `httproutes`, `grpcroutes`, `tcproutes`, `tlsroutes`, `udproutes`, `backendtlspolicies`, `backendlbpolicies` (`gateway.networking.k8s.io`), `xbackendtrafficpolicies` (`gateway.networking.x-k8s.io`), and `udpresponseamplificationpolicies` (`gateway.ferrum.io`) |

The chart's `templates/control-plane-rbac.yaml` is the reference grant.

A watched kind that is installed but not granted is not a quiet degradation: every list is rejected `403` and the reflector retries for the life of the process. `GatewayClass` and `Namespace` watches are cluster-scoped; route, Gateway, ListenerSet, and ServiceImport watches are namespaced when `FERRUM_K8S_WATCH_NAMESPACES` is set. The Helm chart grants these verbs through `controlPlane.rbac.*`; disable unused watches there for a narrower controller.

### Synthetic Gateway / ListenerSet MeshService names

Each materializable Gateway or ListenerSet listener is also published as a synthetic `MeshService` so mesh inventory and status correlation share one object identity. The generated name is:

```text
{kind}-{parent_byte_len}-{parent_name}-{listener_name}
```

where `kind` is `gateway` or `listenerset`, and `parent_byte_len` is the UTF-8 byte length of the parent resource name in decimal (no leading zeros except for an empty name). Examples: Gateway `edge` listener `https` → `gateway-4-edge-https`; ListenerSet `extra` listener `extra-http` → `listenerset-5-extra-extra-http`.

Mesh consumers key services by `(namespace, name)`. A plain hyphen join of parent and listener is ambiguous (`a-b`+`c` vs `a`+`b-c`), so one entry could overwrite the other while exact listener provenance still reported both Programmed. Length-prefixing the parent makes `(parent, listener)` injective within each kind. Kind prefixes keep Gateway- and ListenerSet-derived names disjoint even when resource names collide across kinds. Ferrum does **not** truncate these names to a DNS-label ceiling: `MeshService.name` validation only requires a non-empty string, and truncating would reintroduce collisions. Programmed status still follows typed listener provenance (`GatewayApiListenerKey` / ListenerSet `programmed_listeners`), never a reconstruct-from-name guess.

## Istio CRD Status

When `FERRUM_K8S_CONTROLLER_ENABLED=true` and Istio CRD watching is enabled (`FERRUM_K8S_WATCH_ISTIO_CRDS=true`, the in-pod default), the controller writes a `status.conditions[]` block to every Istio CRD it translates so `kubectl describe <kind> <name>` shows how Ferrum interpreted the resource. All ten translated kinds are covered: `AuthorizationPolicy`, `PeerAuthentication`, `RequestAuthentication`, `DestinationRule`, `VirtualService`, `ServiceEntry`, `WorkloadEntry`, `Sidecar`, `Telemetry`, and `ProxyConfig`. Istio status planning shares the same primary-translation reuse path as Gateway API status (one materialization plus skip errors; no per-object filtered retranslate) and remains unlimited — the rotating 256-candidate budget is Gateway API only.

Each resource gets a single Ferrum-owned `FerrumAccepted` condition (field manager `ferrum.io/istio-controller`) alongside a `status.ferrum.translation` detail block:

- **Accepted** — successful translation writes `FerrumAccepted=True` with a per-kind reason (`Accepted`, plus `AllowNothing`/`NoOp` for AuthorizationPolicy empty-rule semantics). The detail block carries kind-specific context: rule/host/route counts, the resolved PeerAuthentication mTLS mode and port overrides, ServiceEntry `resolution`/`location`, RequestAuthentication scope and permissive-by-default note, the WorkloadEntry service account plus attached `service`/`service_namespace` (and `cross_namespace_service` when the host targets another namespace), the Sidecar egress scope, the Telemetry sections present, or the ProxyConfig scope plus concurrency/image/environment/tracing.sampling fields.
- **Rejected** — a translator error (`K8sTranslateError`) writes `FerrumAccepted=False`, reason `Invalid`, with the error text in both the condition message and `status.ferrum.translation.error`, so a hard rejection of any translated kind is visible to operators instead of being silently dropped from the slice.
- **Deferred fields** — fields Ferrum parses but does not yet enforce are listed in `status.ferrum.translation.deferred_fields` (and summarized in the condition message) so operators see the gap. DestinationRule `connectionPool.http.maxRequestsPerConnection` is deferred at top-level, `portLevelSettings`, and subset scope because backend close-after-N-requests is unsupported. The subset-scoped `h2UpgradePolicy`, `maxRetries`, `http1MaxPendingRequests`, `idleTimeout`, `http2MaxRequests`, and `maxConcurrentStreams` fields are applied and are therefore absent from deferred status and translator ignored-field warnings (reqwest's H2 path still lacks a `maxConcurrentStreams` builder knob — documented as a transport caveat, not a deferred field; the `http2MaxRequests` budget is enforced gateway-side and therefore covers reqwest too). Invalid or unrepresentable values still reject with a field-specific, value-redacted diagnostic. VirtualService `http[].corsPolicy` is deferred only when it is unrepresentable — an un-compilable `regex`, a malformed/unknown matcher, an `exact` (or legacy `allowOrigin` entry) that is empty/whitespace-only or beyond the 512-byte matcher bound (uncredentialed exact `*` is supported; credentialed exact `*`, opaque exact `null`, and credentialed effectively universal prefix/regex are deferred to preserve the source credential behavior; wildcard-shaped and noncanonical exacts are projected literally rather than deferred), an `allowOrigins[]` list beyond 64 entries, an over-complex regex, or an `allowMethods`/`allowHeaders`/`exposeHeaders` entry that is padded or not a valid HTTP method / header name, or an unknown `unmatchedPreflights` value; Sidecar `ingress[]` listeners are deferred only when Ferrum cannot model them (an inadmissible Unix-socket path, non-loopback `defaultEndpoint`, an unrecognized protocol or `UDP`, or omitted `defaultEndpoint`; see [Supported and deferred `defaultEndpoint` forms](#supported-and-deferred-defaultendpoint-forms)). An admissible Unix-socket path is modeled and remains subject to the data plane's explicit containment-root policy. Sidecar `outboundTrafficPolicy` is translated and enforced (see [Sidecar Outbound Traffic Policy](#sidecar-outbound-traffic-policy)); an omitted/null `mode` in a present object uses Istio's documented `ALLOW_ANY` default and defers nothing. A `deferred_fields` entry appears only when a present block is not exactly representable — an unrecognized/non-string `mode`, a non-object block, or an unsupported `egressProxy` — and always names the fail-closed `REGISTRY_ONLY` outcome Ferrum enforces instead.

Ferrum merges its `FerrumAccepted` condition into the live `status.conditions[]` array, preserving conditions written by Istio (`pilot-discovery`/`galley`) and any other controller. Each write is a JSON Merge Patch guarded by `metadata.resourceVersion` and UID: a concurrent foreign update yields HTTP 409, Ferrum re-reads the latest object, re-merges only `Ferrum*` condition types, and retries with bounded backoff. Exhausted retries leave the newer foreign status intact and surface a retryable error for the next reconcile — they never fall back to an unversioned patch. Every production plan carries the watch-snapshot UID; an identity-less plan is refused before GET/PATCH so a delete/recreate cannot adopt a replacement object. `field_manager = ferrum.io/istio-controller` is an identity string on that merge patch; it is **not** Server-Side Apply ownership or conflict detection. `lastTransitionTime` is held stable while the condition's status/reason/message are unchanged. Status writing is read-only with respect to the proxy data plane and never aborts reconcile: if a cluster has stripped the `subresources.status` from a CRD, the writer logs a single warning per resource and no-ops. `ProxyConfig` is modeled, translated, watched via `ISTIO_CRDS` (`networking.istio.io/v1beta1`), transported on native `MeshSubscribe` and Ferrum xDS `ProxyConfigsCarrier`, and receives `FerrumAccepted` status — Istio's authoritative CRD manifests declare `subresources.status` for `proxyconfigs.networking.istio.io`. See [Istio CRD capability dimensions](configuration.md#istio-crd-capability-dimensions).

Istio status writing requires `get/list/watch` on the watched Istio CRDs plus `patch` on their `status` subresources; the standard Istio CRD manifests already declare `subresources: { status: {} }`. Conflict, retry, recreate, not-found, unsupported-subresource, and missing-UID outcomes are exported as unlabeled `ferrum_k8s_controller_istio_status_*` counters on `/metrics` (no labels; never object names, UIDs, condition text, or API messages). See [prometheus_metrics.md](prometheus_metrics.md#istio-status-cas).

Hosted proof that a real API-server competing status writer cannot clobber Ferrum or lose the foreign condition lives in `tests/k8s_istio_status_cas_live.rs`, launched by `.github/workflows/istio-status-cas-live.yml` against Kind using the pinned tools in `.github/actions/setup-kubernetes-tools`. The in-process mock in `tests/integration/k8s_controller_istio_status_cas_tests.rs` remains the fast CAS unit surface; it is not a substitute for that live lane.

#### Proving a withdrawal was observed

A resource deleted in Kubernetes but still served has two causes: the controller never observed the withdrawal (a watch that stopped delivering without failing, bounded only by `FERRUM_K8S_WATCH_IDLE_RELIST_SECS`), or it did and the fault is downstream in CP→DP distribution or listener rebuild. The signals:

- **`ferrum_k8s_controller_watch_deletes_total`** counts observed watch `Delete` events; read it next to `ferrum_k8s_controller_watch_idle_relists_total`, because a relist that drops an object delivers no `Delete`. `ferrum_k8s_controller_config_publications_total` counts changed-snapshot publications and `ferrum_k8s_controller_reconciliations_total` counts passes started. These are process totals, not per-object proof.
- **`ferrum_k8s_controller_watch_relist_missed_deletes_total`** / **`..._missed_adds_total`** advance when a relist's authoritative list disagrees with the store it retires — the direct proof of a missed delete.
- **Relist warning:** `Relisted … store disagrees with the generation it replaced` names the objects that vanished or appeared without a watch event (anywhere between the retiring stream being dropped and the successful replacement list, which can span several minutes).
- **No-change log line:** a reconcile that changes nothing emits one rate-limited `Reconciliation found no config change` line per minute carrying the watch counters; `Reconciliation complete` appears only when a reconcile swaps configuration.
- **Failed lists:** a scope refused with HTTP 403 is held two minutes between attempts and other failed lists back off from 0.8 s to 30 s; the fault is logged at error once per streak/class change and at info on recovery, and `ferrum_k8s_controller_watch_errors_total` counts every attempt.

The reconcile snapshot is deterministic — deduplicated across served-version aliases (GA, then beta, then alpha) and ordered by group, kind, namespace, and name — so the same cluster state always translates the same way. Each served-version scope relists on its own schedule, so a stale deleted Gateway is retired only once every alias scope that held it has relisted. Because the snapshot keeps the GA alias, a `session_persistence` cookie name (which hashes the served `apiVersion`) changes once on upgrade where a compatibility alias used to win. The Gateway API TLSRoute lab also asserts black-box traffic withdrawal (issue #4491).

### Kubernetes Mesh Overlay Ownership And Withdrawal

The Kubernetes controller publishes mesh state as an **overlay** it owns independently of the CP `GatewayConfig` proxy snapshot. CP database full loads never carry `mesh`. Ownership is explicit rather than inferred from the presence of a mesh block:

- **No mesh authority.** A controller that watches no mesh-contributing kind — no Istio CRDs (`FERRUM_K8S_WATCH_ISTIO_CRDS=false`), no Gateway API (`FERRUM_K8S_WATCH_GATEWAY_API_CRDS=false`), and no pod discovery (`FERRUM_K8S_POD_DISCOVERY_ENABLED=false`) — owns no mesh objects. It never withdraws mesh state published by another source, and a reconcile carries no mesh update at all.
- **Mesh authority.** With any of those watches enabled, the controller authoritatively owns exactly the mesh objects its latest successful translation produced — no more.

Composition is **layered**, not namespace-scoped. On each reconcile the control plane rebuilds the served mesh as *non-Kubernetes base layer + Kubernetes overlay*, retaining the base verbatim on the composed snapshot (`base_mesh` on `K8sMeshOverlay::Authoritative`). Valid non-Kubernetes mesh bases come from native / file / xDS sources (and any other composition path that supplies mesh before overlay merge); CP database snapshots are not mesh authors. Ownership is therefore keyed by object identity — collection plus namespace plus the resource's own name (host for `DestinationRule` / VirtualService CORS policies) — never by namespace alone. A namespace routinely holds objects from several sources at once, so a namespace-scoped withdrawal would erase mesh state Kubernetes never published.

Mesh workloads have no `metadata.name`, so their identity is **tiered**:

- A **pod-backed** workload (one carrying a non-empty Kubernetes pod UID) is identified by that **pod UID alone**. The pod UID is the stable identity of the logical workload; its addresses, SPIFFE id, service account, and locality all legitimately change while the same `Pod` object is reconciled, so folding those into the identity would leave two logical copies of one pod in the composed mesh.
- Every **other** workload — `WorkloadEntry`, VM, and natively/xDS-authored workloads, which carry no pod identity — is identified by its **SPIFFE id plus addresses**. That composite is what keeps two distinct workloads sharing one service account (and therefore one SPIFFE id) from collapsing into a single entry. An explicitly empty pod UID is treated as absent and uses this tier.

Two consequences worth stating explicitly:

- **Mixed sources in one namespace coexist.** A natively authored `MeshService` in `payments` survives a Kubernetes publish, a Kubernetes withdrawal, and a watch-scope change, even when Kubernetes also owns objects of the same kind in `payments`. The layering helper preserves any non-Kubernetes mesh base supplied by a valid composition path (for example a live reconcile merge that retains `base_mesh` on the composed snapshot). CP database full loads are not such a path: they clear `mesh` before overlay re-merge and do not author mesh objects.
- **A same-name collision resolves deterministically.** If Kubernetes and another source both author, say, a `PeerAuthentication` named `strict-mtls` in `payments`, the Kubernetes object wins while the overlay is present; when Kubernetes withdraws it, the other source's object is restored rather than lost. The base layer is never edited, only re-layered.

Deleting the **last** mesh-contributing Kubernetes object therefore withdraws the overlay instead of leaving the previous snapshot live. An authoritative snapshot that translates to an empty mesh removes every Kubernetes-owned mesh object — `Service`/`Pod`-derived services and workloads, `AuthorizationPolicy`, `PeerAuthentication`, `RequestAuthentication`, `DestinationRule`, `ServiceEntry`, `WorkloadEntry`, `Sidecar`, `Telemetry`, `ProxyConfig`, and waypoint bindings — while every object owned by another source survives untouched. Mesh-global blocks (`trust_bundles`, `multi_cluster`, the mesh-wide `outboundTrafficPolicy`, extension configs) are not produced by the Kubernetes translator and are never withdrawn by it. The **workload-scoped** `Sidecar.outboundTrafficPolicy` is not a mesh-global block: it lives on the `Sidecar` object, so it is withdrawn with that object like any other Kubernetes-owned mesh resource, and the workload falls back to the mesh-wide policy.

Operational properties:

- **Atomic.** The withdrawal is one `ArcSwap` compare-and-swap of a complete `GatewayConfig` under the CP publication gate, followed by one full mesh broadcast. An in-flight request holds either the complete pre-withdrawal snapshot or the complete post-withdrawal one — never a half-withdrawn mesh.
- **Idempotent.** A repeated empty snapshot produces no content change, so nothing is re-committed and nothing is re-broadcast.
- **Fail-closed on translation failure.** A translation that cannot be produced (repeated failure on the same resource) publishes nothing at all, so a broken CRD can never be mistaken for a deletion. Only a *successful* translation withdraws.
- **Survives CP full reload.** CP database full-load finalization clears `GatewayConfig.mesh` before the independently accepted Kubernetes overlay is re-merged. The overlay slot stores the authoritative empty translation as translated, so a later DB full reload re-merges the withdrawal rather than resurrecting deleted Kubernetes mesh. The freshly loaded DB snapshot supplies the non-mesh `GatewayConfig` base for overlay composition; because that path supplies no non-Kubernetes mesh base, there is no second mesh layer to retain. The helper's retained `base_mesh` contract applies only to composition paths that actually supply one.
- **Independent of watch scope.** Withdrawal is "absent from the new translation", not "in a namespace that left the watch set", so shrinking `FERRUM_K8S_WATCH_NAMESPACES` cannot strand a Kubernetes object — including a waypoint binding or policy whose own namespace differs from the namespaces of the services it governs.
- **Visible.** The withdrawal is logged (`Kubernetes mesh overlay withdrawn…`, carrying no resource identifiers or policy contents), the published snapshot stops advertising mesh on the admin status surfaces, and mesh data planes receive a fresh slice whose resource counts and fingerprint reflect the removal on [`/mesh/config-drift`](#config-drift-introspection).

Because withdrawal follows the Kubernetes source of truth, deleting every `AuthorizationPolicy` restores the Istio default (allow when no `ALLOW` rules exist) and deleting every `PeerAuthentication` restores the default mTLS mode — the same posture a fresh cluster starts in. Keep at least one mesh-wide policy in the Istio root namespace if you need a standing floor.

### Pod Auto-Discovery

Control planes enable native Kubernetes service-registry discovery with `FERRUM_K8S_CONTROLLER_ENABLED=true` and `FERRUM_K8S_POD_DISCOVERY_ENABLED=true`. When enabled, the K8s controller watches `Pod`, `Service`, `EndpointSlice`, and `Node` resources in addition to the configured Istio/Gateway API watches. Ready Pods linked from EndpointSlices become mesh `Workload` entries, Services become mesh `MeshService` entries with their `spec.ports[]`, and Node `topology.kubernetes.io/region|zone` labels populate workload locality metadata consumed by locality-aware load balancing. An EndpointSlice endpoint is authored with the slice, so it never decides a workload identity on its own: an address joins a Pod's `Workload` (and the Pod's SPIFFE identity joins the Service's `workloads`) only when the Pod, named by the endpoint's `targetRef` or found by its IP, is in the Service's own namespace (the EndpointSlice controller never names another), the Pod's own `status.podIP` / `status.podIPs` reports that address, no observed non-host-network Pod of another namespace reports it too, and it is not an address that can never be a backend (loopback, link-local, cloud metadata, and the rest of the backendRef deny list). Any other address is dropped and the Service's translation warning counts the drops by reason; an endpoint left with no address attaches nothing to the Service. The `Workload` carries the Pod's own spelling of each address, once per IP, so a slice writing an IPv4-mapped `::ffff:a.b.c.d` for a Pod reporting `a.b.c.d` publishes `a.b.c.d`. An endpoint without a `targetRef` resolves its Pod by IP only when exactly one observed, non-host-network Pod reports that IP: a Node IP, which every host-network Pod on the Node reports, identifies no Pod, and attaching a host-network Pod (a DaemonSet) takes the same-namespace `targetRef` the EndpointSlice controller always writes. Another namespace's host-network Pod reporting the same Node IP does not refuse that attachment; the data plane tells host-network workloads on one Node apart by Pod UID.

Ferrum only surfaces Pods whose `Ready` condition and declared `readinessGates[]` are green, skips Pending/Failed/Succeeded/terminating Pods, and also honors EndpointSlice readiness/serving/terminating conditions. Explicit Istio `ServiceEntry` resources for the same service host override the auto-derived `MeshService`, and explicit `WorkloadEntry` resources for the same service override auto-derived Pod workloads while the Service can still reference those explicit identities. Cross-namespace `WorkloadEntry.service` hosts require a target-namespace Gateway API `ReferenceGrant` (`WorkloadEntry` → `Service`) plus an authoritative translated Service; see the WorkloadEntry row in [Istio Compatibility Gaps](#istio-compatibility-gaps). When unset, the flag defaults to `true` inside a Kubernetes pod (detected via `KUBERNETES_SERVICE_HOST`) and `false` elsewhere; set it to `false` explicitly to validate RBAC and rollout impact before enabling Pod discovery.

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

Ferrum consumes Istio-style `WorkloadEntry.locality` and auto-discovered Pod locality in `region/zone/subzone` form. Mesh slice application projects the selected source workload locality onto generated upstreams and projects target workload locality onto each upstream target. Projection requires consensus among label-compatible same-SPIFFE local candidates: when those siblings disagree on locality, `source_locality` is left unset and locality-first preference is off for that slice (fail closed), rather than picking an ordering-dependent sibling. The load balancer then prefers healthy targets in this order: exact `region/zone/subzone`, same `region/zone`, same `region`, then the ordinary upstream candidate set. If every target in a preferred tier is unhealthy, selection falls through to the next tier without widening across unhealthy targets.

When the **source** locality cannot be resolved (missing labels / no SPIFFE-matched workload locality), there is no tier to prefer, so the default behavior is to return the full candidate set — mixed local + remote. Setting `FERRUM_MESH_LOCALITY_LB_STRICT=true` opts into strict local-first instead: with an absent source locality the LB restricts selection to local endpoints (every target not tagged as remote-cluster-discovered; remote provenance is an explicit per-target marker stamped from the workload's cross-cluster identity, *not* the locality string, so a local region named `remote-…` still counts as local — as does an untagged target) and widens to the full healthy pool only when no local endpoint exists, logging a one-time `WARN`. The flag is inert once a source locality is resolved and never changes priority-tier behavior. See the precondition note under [Cross-Cluster Endpoint Discovery](#cross-cluster-endpoint-discovery).

**Two distinct remote-target classes in multi-cluster deployments.** The load balancer distinguishes cross-cluster east-west **gateway** targets from plain remote **workload endpoints**, and only the second class is governed by `FERRUM_MESH_LOCALITY_LB_STRICT` (`src/load_balancer.rs`: `target_is_cross_cluster` / `target_is_local`, `LoadBalancer.cross_cluster_failover_present`):

- **Cross-cluster east-west gateway targets** (`mesh.cross_cluster=true`, materialized by the [client-side cross-cluster egress paths](#client-side-cross-cluster-egress-sidecar)) are **categorically always-failover**: the remote gateway LB-picks the backend, so when any candidate is such a target the balancer enforces local-first selection on the no-source-locality path **even while `FERRUM_MESH_LOCALITY_LB_STRICT` is at its default `false`**, widening to the remote gateway only when no local endpoint is healthy — otherwise a service with healthy local endpoints would round-robin onto the remote gateway instead of using it purely as failover.
- **Plain remote workload endpoints** (`mesh.remote=true` without the cross-cluster gateway marker — the Beta [Cross-Cluster Endpoint Discovery](#cross-cluster-endpoint-discovery) path) follow the flag as described above: with the default `false` and an **absent** source locality, selection returns the mixed local + remote pool even while local endpoints are healthy. Set `FERRUM_MESH_LOCALITY_LB_STRICT=true` for production multi-cluster deployments that use remote endpoint discovery, so an unresolved source locality cannot spill traffic onto remote endpoints while local ones are healthy.

This priority selection applies before the configured Ferrum algorithm for the chosen tier, including per-port and subset selectors.

`DestinationRule.trafficPolicy.loadBalancer.localityLbSetting` is honored on top of the priority tiers:

- `enabled: false` disables priority preference, weighted distribute, failover, and failover-priority tiers entirely (matches Istio semantics).
- `distribute[].from` matches the source workload's locality by tier: bare `*` matches any source locality, region-only values match any source in that region, `region/zone` values match any source in that zone, full `region/zone/subzone` values require an exact match, and terminal forms such as `region/zone/*` match the corresponding tier. When a match is found the load balancer overrides the priority preference with weighted locality-bucket selection: each `to[locality]` entry contributes a locality-level share (region-only `to` entries apply to every target in that region, `region/zone` entries apply to every target in that zone, full `region/zone/subzone` entries require an exact match, and terminal wildcards such as `region/zone/*` match the covered tier). If multiple `to` patterns match the same target, the most-specific pattern owns that target so an endpoint is counted in only one locality bucket. After a bucket is chosen, Ferrum runs the configured upstream, subset, or port-level algorithm within that bucket, so endpoint algorithms such as consistent hashing and weighted round-robin still apply. Targets that receive zero distribute weight are excluded, and an entry that names no reachable target falls through to the rest of the locality LB path so the upstream still serves.
- `failover[].from` matches the source workload's region. When configured, the failover region forms a fourth tier consulted after exact/zone/region — so a source with no healthy target in its own region prefers the operator-specified failover region before falling through to other regions.
- `failoverPriority` is an ordered list of workload-label keys (`key`) or key/value overrides containing exactly one equals sign (`key=value`). It is applied only when an effective failover/health signal exists: upstream active or passive health, or the applicable per-port/per-subset passive policy (`DestinationRule.outlierDetection`). Without such a signal the list is inert and the baseline locality selection remains unchanged, matching Istio's `enableFailover` gate. When enabled it **replaces** the default region/zone/subzone tiers with label-match priority tiers: endpoints matching all N configured labels with the source (or the configured override values) have priority P(0); matching the first N-1 labels yields P(1); matching none yields P(N). Matching is prefix-ordered — the nth label is considered only when the first n-1 matched. If the entire source-label map is empty, Ferrum does not create failover-priority tiers. With a non-empty source map, an individually missing configured key still compares as an empty string on each side (Istio map-lookup semantics), so missing-on-both matches and missing-on-one mismatches. Duplicate list positions are kept; expected values follow Istio's override-map semantics (last `key=value` wins for that key at every position, including bare-key entries), with an operator-visible warning on duplicate identical raw strings. Entries with more than one `=` (for example `a=b=c`) are rejected at K8s translation and native/file/xDS validation with a field-specific `FerrumAccepted=False` / `Invalid` diagnostic — Istio's `strings.Split` falls back to treating such an entry as the bare key before the first `=`, so the same YAML can be accepted there and rejected here. Well-known topology keys (`topology.kubernetes.io/region`, `topology.kubernetes.io/zone`, `topology.istio.io/subzone`, `topology.istio.io/network`, `topology.istio.io/cluster`, `kubernetes.io/hostname`) resolve from explicit workload/endpoint labels and, for region/zone/subzone/network/cluster, from derived locality / network / cluster metadata stamped at materialization. Source labels are projected onto `Upstream.source_labels` at slice apply from authoritative `MeshSlice.labels` (`FERRUM_MESH_WORKLOAD_LABELS` / CP request); same-SPIFFE local replicas may only enrich missing keys and contribute derived topology when every compatible candidate agrees (fail closed — never rank from a sibling's first-match labels). Non-truncating endpoint ranks are precomputed into the load-balancer cache and recomputed on endpoint / locality / label reload (`update_targets` / config delta). FerrumAccepted status surfaces an inactive-policy advisory in `deferred_fields` when the applicable DestinationRule policy has no `outlierDetection` (Ferrum active health may independently enable it).

The K8s translator treats `distribute`, `failover`, and `failoverPriority` as mutually exclusive Istio locality-LB modes. Combined modes are rejected at admission instead of being accepted and resolved by runtime precedence. The translator validates each accepted entry at admission — invalid locality strings, slash-malformed locality strings, non-terminal locality wildcards, malformed failover region names (including slash-containing or slash-suffixed values), `from == to` self-failovers, empty `to` maps, empty `failoverPriority` arrays, non-string `failoverPriority` entries, and malformed `key` / `key=value` entries (empty key, leading/trailing whitespace, or more than one `=`) return a translator error rather than silently dropping the policy or degrading to another locality mode.

Port-level `trafficPolicy.portLevelSettings[].loadBalancer.localityLbSetting` is honored by HTTP-family / gRPC / WebSocket / HBONE dispatch. Each per-port entry projects onto `Upstream.port_overrides[port].locality_lb_setting` at slice apply, and the load balancer builds isolated per-port locality state. When dispatch resolves to a port that has a per-port `localityLbSetting`, the per-port preference wins; ports without an override fall back to the upstream-level `trafficPolicy.loadBalancer.localityLbSetting`. Failover-priority activation is resolved for that selection lane: upstream health applies to every port, while a port-level `outlierDetection` enables only that port (and subset passive health enables its subset lane). The same translator validators apply to per-port entries — invalid locality strings, non-terminal wildcards, malformed failover regions, empty/malformed `failoverPriority` entries, and combined modes are rejected at admission. TCP/UDP/DTLS stream proxies honor a per-port `localityLbSetting` only when all upstream targets share one port (see [Port-level and subset policy](#port-level-and-subset-policy)); otherwise they use the upstream-level setting.

## xDS ADS Compatibility

Ferrum's ADS protocol state machine (subscriptions, ACK/NACK, nonce, SotW/delta) follows the Envoy ADS wire contract, but the **resource payloads are Ferrum-specific**. The CDS/EDS/LDS/RDS resources are name-only (service/port discovery) and use Ferrum-shaped names; the security- and policy-bearing slice fields plus effective workload labels ride ECDS as [Ferrum mesh-slice carriers](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds) with Ferrum-defined inner type URLs. A stock Envoy or third-party Istio control plane does not speak this carrier convention or resource-name shape, so the `FERRUM_MESH_CONFIG_PROTOCOL=xds` path is **Ferrum-CP-to-Ferrum-DP** (for a stock CP see [`stock_xds`](#stock-envoy--third-party-istio-xds-interoperability), discovery only), not a drop-in replacement for an Envoy/Istio xDS feed. With the carriers, an xDS-built slice is functionally equivalent to a `native`-built one.

**Protocol robustness.** Both sides track nonces per `(node, type URL)`. The server issues an opaque nonce (`n1:<sha256>`) per response and validates that each ACK/NACK echoes the most-recently-issued nonce (`src/xds/nonce.rs`); stale, unknown, or version-drifted ACKs are logged and ignored rather than mutating accepted state. The DP client mirrors this on the receiving side: it ACKs/NACKs with the exact nonce of the response being acted on and ignores a server retransmit of a response it already processed (a reconnect race or buggy CP would otherwise trigger a redundant slice rebuild and a stale re-ACK). Because server nonces are opaque, duplicate detection — not numeric ordering — is the staleness signal available to the client. Additionally, the CP applies the layered admission budgets described in [xDS ADS admission budgets](#xds-ads-admission-budgets) before and during each stream.

#### xDS ADS admission budgets

`Node.id` is chosen by the client on every stream. A per-node ceiling alone therefore bounds nothing in aggregate: a namespace-authorized bearer could stay under it while cycling unique node ids, and each admitted stream costs a Tokio task, a request stream, a response channel, a subscription set, a filtered `GatewayConfig`, snapshot and nonce state, identity/scoping entries, and a broadcast receiver. Control planes therefore enforce **five independent budgets plus a `Node.id` contract and an ADS-only initial-request deadline** (issues #3741 and #4432) for **ConfigSync, MeshSubscribe, SotW ADS, and Delta ADS from one shared controller**. Native streams are covered even when `FERRUM_XDS_ENABLED=false`. Every setting is documented in [configuration.md](configuration.md).

| Scope | Setting | Default | Enforced |
|-------|---------|---------|----------|
| Total active configuration streams (process) | `FERRUM_XDS_MAX_TOTAL_STREAMS` | `8192` | at reservation, before any per-stream allocation |
| Active streams per namespace/tenant | `FERRUM_XDS_MAX_STREAMS_PER_NAMESPACE` | `4096` | same reservation |
| Active streams per authenticated principal (JWT `sub`) | `FERRUM_XDS_MAX_STREAMS_PER_PRINCIPAL` | `2048` | same reservation |
| Active streams per node state key | `FERRUM_XDS_MAX_STREAMS_PER_NODE` | `4` | native: on the subscribe RPC (node id already present); ADS: on the first request, once `Node.id` is known |
| Distinct active node state keys | `FERRUM_XDS_MAX_ACTIVE_NODES` | `16384` | same registration |

A node state key exists only while at least one admitted stream holds it, so distinct active nodes can never exceed active streams. `FERRUM_XDS_MAX_ACTIVE_NODES` therefore **binds only when it is set below `FERRUM_XDS_MAX_TOTAL_STREAMS`**, or when the total-stream budget is unbounded (`0`). At the shipped defaults (`16384` > `8192`) the total-stream budget saturates first and the distinct-node ceiling is defense in depth: lower it when you want the node-scoped maps bounded more tightly than the stream count.

**Ordering is deterministic and outermost-first** — total → namespace → principal → node streams → node cardinality. The first saturated scope returns gRPC `RESOURCE_EXHAUSTED`, and a failure in an inner scope rolls the outer reservations back, so a refused stream never leaves partial admission state.

**The reservation happens before the allocations it bounds.** Total/namespace/principal capacity is taken in the gRPC handler itself — before the ADS relay task is spawned, before the per-stream response channel exists, before the broadcast subscription, and before the filtered `GatewayConfig` snapshot is built. Native ConfigSync and MeshSubscribe additionally register the node layer on that same subscribe RPC because `node_id` is already present. A refusal at that point allocates none of them. The reservation is then moved into a permit that lives inside the response stream (native) or the ADS relay task, so it is released exactly once on every exit: normal completion, request-stream error, first-message error, auth-lease expiry, lag/recovery error, client cancellation, response-channel receiver drop, forced task abort, and process shutdown.

**SotW, Delta, ConfigSync, and MeshSubscribe share one budget.** All four RPCs reserve from the same process-wide controller, so a client cannot split a flood across methods or connections to double its allowance.

**`Node.id` is validated before it is used.** It must be non-empty, at most `FERRUM_XDS_MAX_NODE_ID_BYTES` UTF-8 bytes (default `253`), and printable ASCII (`0x21`–`0x7E`) only. That single rule rejects control characters (including CR/LF log injection and NUL), all whitespace, and every non-ASCII form (bidi overrides, zero-width joiners, homoglyphs) while still admitting hostnames, Kubernetes pod identities, and Istio `~`-delimited node ids. Validation runs **before** the value is cloned, stored in any map, folded into a state key, or written to a log line; violations return `INVALID_ARGUMENT`. Log sites emit a non-reversible digest of the id, never the raw bytes.

**Principals cannot alias one another's state.** The mutable per-stream state key is `namespace + full-width SHA-256 digest of the authenticated JWT subject + Node.id`, with the namespace and principal segments length-prefixed so no combination of values can forge another key. The principal digest is deliberately **not truncated** (64 hex characters), because it is the boundary that keeps one principal off another's per-principal quota and mutable state; a client picks its own JWT `sub`, so a truncated digest would be a tractable collision target. That digest is separate — different hash domain, different width — from the short 16-character digest log sites use to redact a client-supplied `Node.id`; a log identifier is only a correlation aid and is never used as a key. Neither the raw subject nor the raw `Node.id` is ever stored in a map key, state key, log field, or metric label. `Node.id` is descriptive metadata only; it authorizes nothing. Two unrelated principals inside one namespace that pick the same `Node.id` therefore get separate snapshot, nonce, workload-identity, waypoint, scoping, and per-node quota entries. Node-scoped state is cleaned atomically when that key's last stream exits.

**A stalled ADS stream is bounded too.** An admitted ADS stream that never sends a first request — and so never identifies a node — is closed with `DEADLINE_EXCEEDED` after `FERRUM_XDS_FIRST_REQUEST_TIMEOUT_SECONDS` (default `30`), releasing its task, channel, and permit. Native ConfigSync and MeshSubscribe already carry `node_id` on the RPC, so this deadline is ADS-only.

**`0` means unbounded and is refused in production.** Any budget set to `0` disables that scope. Under `FERRUM_MESH_PRODUCTION_MODE=true` a control plane refuses that at `ferrum-edge validate` and at startup unless the operator sets `FERRUM_XDS_ALLOW_UNBOUNDED_STREAM_LIMITS=true`, **including when ADS is disabled** — native streams still use the shared budget. The ADS-only first-request deadline is omitted from that check while `FERRUM_XDS_ENABLED=false`. Startup logs the resolved budgets, and warns loudly whenever any scope is unbounded, override or not.

**The sizing unit is one stream per DP *or per mesh workload*** (issue #4531). Every injected sidecar and every ambient node proxy holds one `MeshSubscribe` stream for its whole life, so a mesh-enabled namespace's stream count is its workload count. Because native mesh subscribers must present `node_id == JWT sub`, a fleet sharing one ServiceAccount token presents a single principal, so the per-principal budget is a fleet bound and not a tenancy bound. Size each budget at **≥ fleet ÷ CP replicas**, with headroom for the reconnect overlap of a rolling update.

Each layer emits a rate-limited `warn!` (at most once per 60s per layer) naming the layer, its `FERRUM_XDS_MAX_*` variable, and the current/limit values once its occupancy reaches 80% of the ceiling, so growth into a budget is visible before the first `RESOURCE_EXHAUSTED`. A data plane that *is* refused records it as reconnecting rather than authority loss — see [cp_dp_mode.md](cp_dp_mode.md) — so a capacity refusal does not latch `FERRUM_DP_CONFIG_MAX_STALE_SECONDS`.

**Sizing.** Peak occupancy memory is roughly `FERRUM_XDS_MAX_TOTAL_STREAMS × (per-stream channel capacity × response size + one filtered GatewayConfig + one snapshot)`, plus one broadcast receiver per stream. The node-scoped ADS maps add `min(FERRUM_XDS_MAX_ACTIVE_NODES, FERRUM_XDS_MAX_TOTAL_STREAMS) × (snapshot + nonce + identity/waypoint/scoping entries)` — the `min` because a node state key only exists while a stream holds it. **These are per CP process**: a control plane running `N` replicas admits up to `N ×` the configured limits in aggregate, so divide the fleet-wide budget by the replica count when sizing. `FERRUM_XDS_MAX_TOTAL_STREAMS` is the **only** aggregate bound on configuration-stream occupancy — do not rely on `FERRUM_CP_GRPC_MAX_CONNECTIONS` for it. That setting bounds gRPC *connections*, and one HTTP/2 connection multiplexes up to `FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS` (default `1000`) concurrent streams, so the transport ceiling is orders of magnitude looser than the stream ceiling. Size it from the memory formula above and your real DP **and mesh workload** count; the default `8192` is a workload-scale starting point, not a connection-ceiling mirror.

**First-slice convergence and resource warming (make-before-break).** The DP gates its first slice on CDS+EDS+LDS+RDS+ECDS each returning the same valid `version_info` before `wait_for_first_slice()` unblocks (ECDS is required so the first slice is never the name-only, unprotected view). Under **resource warming** the DP tracks each type's version independently but builds only when the required set is coherent and internally consistent — concretely, when every required type has the same version and `reverse_translate` succeeds (carriers decode). A route that references a service not yet present in CDS/EDS/LDS is **skipped**, not fatal: xDS types arrive as independent responses, so a route can land before its cluster; the route is retained in the accumulator and validates once its service arrives (Envoy-aligned — a route to an unknown cluster is ACKed, not NACKed). The previous slice keeps serving through the runtime `ArcSwap` until the replacement is ready, so a partial or version-skewed set never tears down the working slice or mixes new routing with stale ECDS policy. After convergence a per-type content update — the common case being a policy/workload-only ECDS change — force-refreshes subscribed required mesh-slice types with the same snapshot version so the DP applies only a coherent CDS/EDS/LDS/RDS/ECDS set. The slice's observability `version` is the coherent required version; it is not used for change detection (`MeshSlice::content_eq` ignores it). If the CP persistently sends one malformed required type, that type is NACKed on every attempt and the first slice never converges; after `XDS_CONSECUTIVE_NACK_LIMIT` (5) consecutive NACKs the client trips its NACK circuit breaker, closes the stream, and reconnects / fails over to the next CP. To keep a wedged startup diagnosable, a NACK of a required type that occurs **before** first-slice convergence emits a structured `warn!` (node, namespace, type URL, consecutive-NACK count, breaker limit) and increments `ferrum_xds_first_slice_nacks_total{namespace, type_url}` — a non-zero, growing value on a starting DP is the signal that convergence is blocked by a malformed required resource. A genuine structural error (e.g. a malformed ECDS carrier) is still NACKed and rolls the accumulator back to the last accepted state. A dependency-skewed route is **not** treated as such an error — NACKing it would drop the new RDS, and the CP does not resend a NACKed SotW resource until a reconnect or another RDS change, so the route is skipped and retained instead.

Ferrum's ADS server honors explicit SotW (State-of-the-World) resource subscriptions per type URL on the shared `filtered_resources()` path used by CDS/EDS/LDS/RDS/SDS. A SotW request with a non-empty `resource_names` returns only the named resources for that type URL, while a wildcard subscription (`*` or an initial empty `resource_names`) returns the full collection per the Envoy ADS protocol. Subsequent empty SotW requests on the same stream preserve an established wildcard subscription; after an explicit named subscription they clear the named set and remain non-wildcard, so no resources are returned until the client names resources again. Direct per-type regression coverage exists for CDS and RDS; EDS/LDS/SDS rely on the same code path and are covered indirectly.

Delta-xDS subscriptions across the same type URLs are additive: `resource_names_subscribe` appends to the per-stream subscription set and `resource_names_unsubscribe` removes from it, with empty lists treated as no-ops. Subscriptions persist across requests on the same stream, and updates only mutate the explicit subscription state without broadcasting unrelated resources.

Delta-xDS responses ship only resources the client doesn't already have. Each resource carries a content-derived per-resource version — the first 8 bytes (16 hex chars) of `SHA-256(type_url || 0x00 || name || 0x00 || value)`, independent of the aggregate snapshot version. The truncation is a wire-size optimization: at typical mesh-resource cardinalities (~10k per type URL) the birthday-bound collision probability sits around 3e-12. On the same stream, the delta filter also byte-compares `value` against the previous ACKed snapshot before skipping a resource, so a hash collision on its own cannot suppress a real content change on that path. Reconnect `initial_resource_versions` skips by the client's reported version match; explicit re-subscribe can always force a fresh copy. Two snapshots that contain byte-identical bytes for a resource produce identical resource versions, so:

- `DeltaDiscoveryRequest.initial_resource_versions` lets a client report what it currently has after a reconnect — resources whose versions match are skipped on the response.
- Resources that were on the previous ACKed response for the same type URL and whose bytes haven't changed are skipped on the next response.
- Explicit `resource_names_subscribe` always re-flows the resource even when unchanged, so a re-subscribe always returns a fresh copy.

ECDS (Extension Config Discovery Service) — `type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig` — is served alongside the standard xDS resource types and carries three classes of payload, all distinguished by the **inner** `Any.type_url`:

1. **Ferrum mesh-slice carriers**: the CP emits the full slice — authz, PeerAuthentication, RequestAuthentication, full ServiceEntry/MeshService shape, trust bundles, ProxyConfig, workloads, effective labels, telemetry, multi-cluster, sidecar egress scope, outbound policy — as Ferrum ECDS carriers under `type.googleapis.com/ferrum.config.extension.v3.*`. Empty `Vec`/`None` fields are skipped, while effective labels always emit so an empty label map remains authoritative. This is what makes xDS reach native parity; see [Ferrum mesh-slice ECDS carriers](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds). Source of truth: `src/xds/carrier.rs`.
2. **DestinationRule carrier**: inner `type_url == type.googleapis.com/ferrum.config.extension.v3.DestinationRuleCarrier` ships the original DR JSON across xDS.
3. **Operator-defined extension configs**: operators populate `MeshConfig.extension_configs` with `MeshExtensionConfig { name, type_url, value }` entries; slice construction carries them into `MeshSlice.extension_configs`, and the translator emits one ECDS resource per entry with the operator-defined inner `type_url`/bytes.

The DP dispatches on the reserved resource name plus inner `type_url`: slice-carrier and DR-carrier markers are decoded into their dedicated slice fields, and any other inner type is left for the relevant operator consumer. Delta wire-byte reduction extends to ECDS naturally because per-resource versions are content-derived.

RTDS (Runtime Discovery Service) — `type.googleapis.com/envoy.service.runtime.v3.Runtime` — is subscribed by the mesh xDS client so operators can change runtime knobs without rolling out a fresh slice. Each layer's `google.protobuf.Struct` payload is flattened into `MeshSlice.runtime_overlay.fields` keyed by the top-level field name. SotW wire order has no precedence meaning: Ferrum sorts Runtime resources lexicographically by name and applies them in that order, so later names win on key conflicts. Duplicate Runtime resource names are rejected and NACKed without replacing the last accepted set. Value kinds map directly to a typed Rust enum (`RuntimeValue::{Number, String, Bool, FractionalPercent}`). The overlay surfaces via `GET /mesh/runtime-overlay` (JWT-authenticated) and the field is `#[serde(default, skip_serializing_if = "MeshRuntimeOverlay::is_empty")]` so non-RTDS deployments round-trip byte-identical.

**Every request-affecting RTDS knob is bound to the generation that supplied it.** Fault percentages *and* transformer gates are materialized into their candidate plugin configs from the same accepted overlay, validated, built into immutable plugin instances, and published atomically with the plugin cache / config request epoch. Two guarantees follow, and both are part of the operator contract:

- **A request observes exactly one complete accepted generation.** A request that has been admitted keeps the rules, scope, defaults, *and* gate it started with, for its whole lifetime — however long it is in flight (a slow upload, a slow backend, a streaming response) and however many overlay updates land meanwhile. A gate change never applies to an in-flight request; it applies to requests admitted after it was published.
- **A request is wholly enabled or wholly disabled.** A transformer's gate is resolved once per instance and consulted by every phase, so paired rules cannot come apart: a request-side marker header is never added without its paired body removal, and a response's buffer/stream selection can never disagree with its later header and body rules.

A rejected candidate mutates nothing — the previous generation keeps serving in its entirety (last-known-good), including its gate. After acceptance, `src/modes/mesh/runtime_overlay_consumers.rs` publishes the gateway-wide tracing knob and the transformer gate *provenance* maps (see the note below the table). Received-but-rejected slices remain visible on the raw runtime snapshot but never mutate live RTDS consumers or `GET /mesh/runtime-overlay`:

| Reserved key | Consumer | Effect |
|---|---|---|
| `ferrum.fault_injection.<scope>.abort_percent` / `.delay_percent` | `fault_injection` plugins with `runtime_overlay_scope: "<scope>"` | Replaces the static `percentage` for that fault kind for as long as the key remains in the overlay. Accepts `Number(0..=100)` or `FractionalPercent`. Zero removes that side for the generation; omitted and null sibling sides count as absent, so removing the only object side disables the instance without rejecting the generation. An omitted or null `runtime_overlay_scope` disables RTDS scoping. |
| `ferrum.request_transformer.<scope>.enabled` / `ferrum.response_transformer.<scope>.enabled` | request/response transformer plugins with `runtime_overlay_scope: "<scope>"` | When `false`, every header / query / body rule on the plugin instance is short-circuited. The accepted value is materialized into the instance's own effective config as the reserved `runtime_overlay_resolved_enabled`, so the gate ships in the same request generation as the rules it gates and is resolved once, immutably, per instance. A scope the accepted overlay does not name falls back to `default_enabled` (defaults to `true`). Because an RTDS-only change would otherwise leave every static field identical, the affected transformer instances are re-stamped so the candidate plugin cache genuinely rebuilds them; unrelated scopes keep their instances. Publishing a changed **response**-side gate map also retires `response_caching` entries stored under the previous publication: a cached response is a finalized representation that replays with presentation transforms skipped, so it is refetched from the origin rather than replayed under a policy that did not produce it. Reapplying the identical current map is a no-op; every real gate transition, including an A→B→A cycle, receives a fresh identity and conservatively retires earlier entries. |
| `ferrum.log.level` | gateway-wide tracing `EnvFilter` | Rebuilt via `tracing_subscriber::reload`. Accepts any `RUST_LOG`-style directive. Parse failure logs a warning and keeps the last-good filter. |

**Why the transformer gate maps are still published after acceptance.** The maps in `runtime_overlay_consumers.rs` do not drive transformer behavior — that comes from each instance's materialized config. They remain the *provenance* surface: the response-side publication identity is what `response_caching` binds its stored entries to, what `request_deduplication` folds into the content fingerprint of a Redis-persisted replay, and what `GET /mesh/runtime-overlay` reports. Removing the publication would silently stop retiring cached and persisted representations across a policy change.

That publication identity is not sufficient on its own, because it lands *after* the request epoch. A request whose authenticate/authorize phase spans a whole slice apply keeps the plugin generation it pinned — that is the guarantee above — while pinning the newly published identity, so the identity alone can attribute old-generation bytes to the new policy. Both `response_caching` and `request_deduplication` therefore also bind each retained representation to the *effective presentation-policy digest* of the generation that shaped it (`RequestContext::response_presentation_policy_digest`, taken from the request's own plugin-cache view). Since the gate is materialized into the transformer's configuration, that digest covers the gate and the static rules together, per instance. A difference in either half retires the representation; if the digest is unavailable because a presentation policy is dynamic, no representation is retained or replayed.

Server-side translation (`translate_mesh_slice_to_snapshot`) does not emit Runtime resources — the xDS server is a CDS/EDS/LDS/RDS/SDS/ECDS originator, and RTDS layers are authored by the operator's external CP (Istio, custom).

## Istio Compatibility Gaps

The following Istio mesh surfaces are either deferred or have Ferrum-specific support notes:

| Surface | Status | Workaround |
|---|---|---|
| Stock Envoy / third-party Istio xDS interop (point Ferrum's **Ferrum-private** xDS client at a non-Ferrum CP) | Not interoperable | `FERRUM_MESH_CONFIG_PROTOCOL=xds` is a **Ferrum-CP-to-Ferrum-DP** path: CDS/EDS/LDS/RDS are name-only with Ferrum-shaped resource names and all security/policy fields ride [Ferrum-specific ECDS carriers](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds). A stock CP emits neither, so that response is unsupported and may be NACKed |
| Stock Envoy / third-party Istio xDS interop (`FERRUM_MESH_CONFIG_PROTOCOL=stock_xds`) | Supported for discovery | Consumes standard v3 CDS/EDS/LDS/RDS from a stock control plane and maps it onto `MeshService` / `Workload`. Enforcement policy (authorization, PeerAuthentication, JWT, trust bundles, DestinationRule, Sidecar scope) comes from the mandatory local `FERRUM_MESH_FILE_CONFIG_PATH` document, never from the stock CP. Traffic shaping, subsets, external DNS clusters, SDS, ECDS/RTDS, and delta xDS are out of scope — see [Stock Envoy / third-party Istio xDS interoperability](#stock-envoy--third-party-istio-xds-interoperability) |
| `EnvoyFilter` | Not planned | Use Ferrum custom plugins |
| `WasmPlugin` | Not planned | Use Ferrum custom plugins (`custom_plugins/`) |
| Outbound traffic policy (`REGISTRY_ONLY` / `ALLOW_ANY`) | Supported | `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY=registry_only`, the native/CRD slice-supplied mesh-wide `outbound_traffic_policy`, or a workload-scoped `Sidecar.outboundTrafficPolicy` that overrides both (see [Sidecar Outbound Traffic Policy](#sidecar-outbound-traffic-policy)) covers both HTTP-family egress (auto-injected `mesh_outbound_registry` plugin and outbound-capture route misses, both rejecting with `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS`, default 502) and stream-family egress on mesh outbound capture listener ports (TCP / TCP+TLS: graceful close before backend dial; UDP / UDP+DTLS: silent datagram drop). Both surfaces read the same slice-derived registry (services, ServiceEntries including wildcard hosts, workload addresses); resources with no declared ports admit any explicit Host port for that known destination, and empty registries fail closed. HTTP decision metrics use fixed host buckets (`<admit_explicit>`, `<admit_wildcard>`, `<denied>`); stream rejects export `ferrum_mesh_outbound_registry_stream_decisions_total{protocol, decision}` instead. Inbound sidecar/ambient traffic is not gated by this outbound policy |
| `VirtualService` header/method/queryParam predicates beyond plugin capture | Partial | Remaining unsupported HTTP predicates: `sourceLabels`, `gateways`, `scheme` (fail closed via `request_termination`). Everything else: see [VirtualService Translation](#virtualservice-translation) and its [Match predicates](#match-predicates). |
| Pod auto-discovery (K8s native service registry) | Supported | `FERRUM_K8S_POD_DISCOVERY_ENABLED` (defaults to `true` in-pod, `false` outside); the CP watches Pod/Service/EndpointSlice/Node resources, surfaces only ready Pods, links Services through EndpointSlices, and lets explicit `WorkloadEntry` / `ServiceEntry` resources override auto-derived entries |
| `WorkloadEntry` `weight` / `locality` / `serviceAccount` / cross-namespace `service` | Supported | `weight` and `locality` are consumed by upstream target materialization; locality priority load balancing prefers exact, zone, then region tiers before falling back. `DestinationRule.trafficPolicy.loadBalancer.localityLbSetting.distribute` / `failover` / `failoverPriority` / `enabled` are honored (see "Locality-Aware Load Balancing" above). `serviceAccount` is kept separately from the SPIFFE path so introspection/audit doesn't need to parse it. Cross-namespace `spec.service` hosts (`<svc>.<ns>.svc` / FQDN) attach only when a Gateway API `ReferenceGrant` in the **target Service namespace** permits `from: {group: networking.istio.io, kind: WorkloadEntry, namespace: <WorkloadEntry namespace>}` → `to: {group: "", kind: Service}` (optional `name`) **and** the target Service exists in the translated inventory; missing/unauthorized/stale targets fail closed with `FerrumAccepted=False`. Same-namespace hosts need no grant. Ambiguous two-label DNS names such as `reviews.prod` stay literal and do not widen as Kubernetes Service keys. Accepted status reports `service` / `service_namespace` / `cross_namespace_service`. |
| `Telemetry.tracing[].providers[]` span emission | Supported | Inline provider config is emitted from the injected `workload_metrics` plugin for Zipkin v2, Datadog Agent `/v0.3/traces`, Lightstep OTLP + bearer auth via `accessTokenEnv`, and OpenTelemetry OTLP/HTTP JSON. Multiple inline providers fan out from one sampled span. `randomSamplingPercentage` is honored, `disableSpanReporting: true` suppresses export while retaining the merged config, and `tracing[].match.mode: SERVER`, `CLIENT`, `CLIENT_AND_SERVER`, or omitted mode all flow through: each mesh listener stamps a direction (inbound mTLS / HBONE termination → server, outbound capture → client) and the plugin emits the matching span kinds. Resulting spans carry their kind in every provider payload (OTLP enum `2`/`3`, Zipkin v2 top-level `"kind": "SERVER"\|"CLIENT"`, Datadog `meta["span.kind"] = "server"\|"client"`). Name-only references (`{name: "my-zipkin"}`) resolve against `meshConfig.extensionProviders` from the root-namespace `istio` ConfigMap, and omitted or empty `providers[]` use `meshConfig.defaultProviders.tracing` when configured. Unknown names are skipped with an operator-visible warning. |

## Migrating from Istio

Ferrum is positioned as a **native consumer of Istio's configuration model**, not a drop-in Envoy replacement. The Kubernetes controller natively watches and translates **ten Istio CRDs** — `AuthorizationPolicy`, `PeerAuthentication`, `RequestAuthentication`, `DestinationRule`, `VirtualService`, `ServiceEntry`, `WorkloadEntry`, `Sidecar`, `Telemetry`, and `ProxyConfig` — writing a `FerrumAccepted` condition into each resource's `status.conditions[]` plus a `status.ferrum.translation` detail block, with parsed-but-unenforced fields surfaced in `deferred_fields` so gaps are operator-visible (see [Istio CRD Status](#istio-crd-status)). `FERRUM_MESH_CONFIG_PROTOCOL=xds` is **Ferrum-CP-to-Ferrum-DP only**: it follows the Envoy ADS wire contract, but the resource payloads are Ferrum-specific. A stock Envoy/Istio CP can supply CDS/EDS/LDS/RDS discovery only through [`stock_xds`](#stock-envoy--third-party-istio-xds-interoperability), with enforcement policy from a local file document (see [xDS ADS Compatibility](#xds-ads-compatibility) and the first rows of [Istio Compatibility Gaps](#istio-compatibility-gaps)). `EnvoyFilter` and `WasmPlugin` are explicit non-goals — their extension role maps to Ferrum custom plugins (`custom_plugins/`). For the field-level "is my resource supported" answer, do not rely on this summary: the authoritative sources are [docs/mesh_supported_matrix.md](mesh_supported_matrix.md) (the product contract), the per-CRD tables in this document ([DestinationRule](#destinationrule), [VirtualService Translation](#virtualservice-translation), [Istio Compatibility Gaps](#istio-compatibility-gaps)), and the conformance-generated `target/conformance/coverage.md` (the enrolled GA rows and required live assertion IDs).

| Istio surface | Ferrum answer |
|---|---|
| The ten translated CRDs (AuthorizationPolicy, PeerAuthentication, RequestAuthentication, DestinationRule, VirtualService, ServiceEntry, WorkloadEntry, Sidecar, Telemetry, ProxyConfig) | Natively consumed by the K8s controller with `FerrumAccepted` status feedback and `deferred_fields` for parsed-but-unenforced fields ([Istio CRD Status](#istio-crd-status)) |
| istiod xDS → Envoy data plane | Ferrum CP → Ferrum DP: native `MeshSubscribe` (recommended) or Ferrum xDS (`xds`) with Ferrum ECDS carriers. A stock Envoy/Istio CP supplies CDS/EDS/LDS/RDS discovery only through [`stock_xds`](#stock-envoy--third-party-istio-xds-interoperability), with enforcement policy from a local file document ([xDS ADS Compatibility](#xds-ads-compatibility)) |
| `EnvoyFilter` / `WasmPlugin` | Not planned — use Ferrum custom plugins (`custom_plugins/`) ([Istio Compatibility Gaps](#istio-compatibility-gaps)) |
| Field-level support status | [docs/mesh_supported_matrix.md](mesh_supported_matrix.md) + the per-CRD tables here + `target/conformance/coverage.md` |

## Environment Variables

The canonical reference for every mesh variable (defaults, ranges, and descriptions) is
[configuration.md](configuration.md). The groups below link to the matching section.

### Core

`FERRUM_MESH_CONFIG_PROTOCOL`, `FERRUM_MESH_TOPOLOGY`, workload identity/labels, Sidecar scoping,
federation, remote discovery, and locality flags: see
[configuration.md → Mesh Runtime](configuration.md#mesh-runtime).

### Listeners

Inbound, outbound, HBONE, east-west, and egress listener addresses and transport ports: see
[configuration.md → Mesh Runtime](configuration.md#mesh-runtime).

### DNS Proxy

`FERRUM_MESH_DNS_*`, `FERRUM_MESH_CLUSTER_DOMAIN`, and the outbound traffic policy: see
[configuration.md → Mesh Runtime](configuration.md#mesh-runtime).

A malformed, blank, or out-of-range TTL, concurrency, or cache value (including `0` for the concurrency and cache limits) fails mesh startup and `ferrum-edge validate` with an error naming the variable and its range; it does not fall back to the default.

### Identity / CA

`FERRUM_MESH_CA_BACKEND`, `FERRUM_MESH_SPIRE_AGENT_SOCKET`, `FERRUM_MESH_CERT_TTL_SECONDS`, and the
production/dev guardrails (`FERRUM_MESH_PRODUCTION_MODE`, `FERRUM_MESH_CA_BOOTSTRAP_DEV`,
`FERRUM_MESH_ALLOW_STATIC_ID`, `FERRUM_MESH_ALLOW_NO_CA`): see
[configuration.md → Mesh Runtime](configuration.md#mesh-runtime).

### xDS

`FERRUM_MESH_XDS_NODE_CLUSTER` and `FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS`: see
[configuration.md → Mesh Runtime](configuration.md#mesh-runtime).

### Node Agent

`FERRUM_NODE_AGENT_*` plus the node-agent / Ambient capture settings
(`FERRUM_MESH_CAPTURE_INCLUDE_CIDRS`, `FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS`,
`FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS`, `FERRUM_MESH_APP_PROBE_PORT`): see
[configuration.md → Node Agent](configuration.md#node-agent). `FERRUM_MESH_CAPTURE_EXCLUDE_PORTS`
(default `15001,15006,15008,15020`) is the node-agent fallback / Ambient producer outbound
exclude list; it is not read by the injector.

### Injector

`FERRUM_INJECTOR_*`, `FERRUM_MESH_CAPTURE_MODE`, `FERRUM_MESH_PROXY_UID`, the IPv6 capture
toggles, and `FERRUM_MESH_EXCLUDE_OUTBOUND_PORTS` (the injector's outbound exclude list for TCP
and enabled UDP capture, merged additively with `traffic.sidecar.istio.io/excludeOutboundPorts`):
see [configuration.md → Kubernetes Mesh Integration](configuration.md#kubernetes-mesh-integration).

The compiled-in default is `ferrumedge/ferrum-edge:v<CARGO_PKG_VERSION>`, the
same Docker Hub repository the Helm charts use (`image.repository`) plus the
`v*` image tag the release workflow publishes. Helm always sets
`FERRUM_INJECTOR_SIDECAR_IMAGE` from the chart image; the binary default is the
bare-binary path. An unset value logs one WARN at injector startup. An explicit
`latest` tag or an untagged name (Docker's implicit `latest`) fails closed at
startup. A digest-only pin (`repository@sha256:…`) is accepted here.

For iptables injection, the image must provide `/bin/sh`, `ip`, `iptables`, and
`ip6tables`. The binary rejects a non-tools image at injector startup and at
admission before emitting a patch. The `-ebpf-tools` tag is a deployment
capability declaration, not a remote filesystem inspection: custom images must
carry that tag and actually supply these tools. A tools tag may pin a digest
(`registry/repository:version-ebpf-tools@sha256:...`); a bare digest cannot
express this capability and is refused for iptables capture. Explicit and eBPF
injection continue to accept ordinary distroless sidecar images.

The Helm chart reads `injector.env.FERRUM_MESH_CAPTURE_MODE` (default
`explicit`), independently of `ambient.captureMode`. For `iptables`, it promotes
the chart's image tag to `-ebpf-tools`, including promotion from `-ebpf` without
double suffixes. An explicit `injector.env.FERRUM_INJECTOR_SIDECAR_IMAGE` is
emitted once and preserved verbatim; a non-tools override fails rendering.
The injector Deployment itself does not run the capture script and keeps the
ordinary chart image.

### Kubernetes Controller

The in-cluster Istio / Gateway API translation controller runs on the **control plane** (`FERRUM_MODE=cp`; started from `src/modes/control_plane.rs`) — a mesh-mode data plane does **not** run it, even in-cluster, so set `FERRUM_K8S_*` and `FERRUM_GATEWAY_API_*` on the CP. See [configuration.md → Kubernetes Mesh Integration](configuration.md#kubernetes-mesh-integration), [Istio CRD Status](#istio-crd-status), and [Pod Auto-Discovery](#pod-auto-discovery).

### Shared with CP/DP

The `native` and `xds` protocols require `FERRUM_DP_CP_GRPC_URLS` and `FERRUM_CP_DP_GRPC_JWT_SECRET`; the `file` protocol (no control plane) requires neither. Failover, ADS queue, and DP gRPC TLS settings are shared with CP/DP mode: see [configuration.md → Control Plane / Data Plane](configuration.md#control-plane--data-plane) and [cp_dp_mode.md](cp_dp_mode.md).
