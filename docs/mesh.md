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
- [Protocol x Topology Support Matrix](#protocol-x-topology-support-matrix)
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
- [Migrating from Istio](#migrating-from-istio)
- [Environment Variables](#environment-variables)

## Maturity and Support Status

Ferrum's mesh subsystem is in active build-out. The paths below ship in one binary and share the same proxy/plugin chain, but they are at very different maturity levels. Use this matrix to decide what to rely on in production. Labels:

- **Stable** — exercised end-to-end (functional/integration tests against a live data path), production-suitable.
- **Beta** — feature-complete and tested, but with a documented sharp edge or a verification step still owed (see [Limitations](#limitations-and-not-supported)).
- **Experimental** — usable but with a safety-relevant caveat (plaintext, unauthenticated, or partial enforcement); opt-in and not recommended without compensating controls.
- **Dev-only** — gated behind a build feature or an explicit dev opt-in; not present in the published image's default behavior.

> For the one-screen **product contract** (what to rely on, the GA promise, and the explicit non-goals), see [docs/mesh_supported_matrix.md](mesh_supported_matrix.md). The contract's **GA** tier is the maturity bar these tables label **Stable**, and it is machine-enforced *for the features enrolled in the conformance GA contract* — such a feature regressing (or its test being deleted) fails the conformance suite (`tests/conformance/ga_scope.rs`). The source of truth is `tests/conformance/ga_contract.yaml`; generated `target/conformance/coverage.md` includes the enrolled semantic rows and required live assertion IDs. That contract is populated incrementally as each area is verified, so it does **not** yet enroll every row labeled Stable here (e.g. SPIFFE inbound/HBONE peer trust-domain verification has no contract row of its own — only the inbound peer-SVID verification decision is pinned, under `mesh.identity.spire_svid_issuance`). Native `MeshSubscribe` and `Sidecar` + native config ARE GA-gated via `mesh.config_transport.native_subscribe`, live-backed by the required `sidecar.config.native_subscribe_delivered` assertion from the suite's CP + native-subscribe leg; SPIFFE identity plumbing is enrolled as `mesh.identity.spire_svid_issuance`.
>
> The contract's **live** half is backed by two suites: `mesh-e2e-sidecar` for the same-cluster sidecar rows, and `multicluster-federation` for the cross-cluster east-west rows (described at the end of this note). In `mesh-e2e-sidecar` (`tests/k8s/mesh_e2e_sidecar/`, workflow `.github/workflows/mesh-e2e-sidecar-live.yml`), a kind + SPIRE cluster drives the real captured sidecar datapath — STRICT-mTLS positive and plaintext-rejected negative, a destination-side AuthorizationPolicy 403, RequestAuthentication JWT (valid → 200, missing → 403, wrong-key signature → 401), a two-phase DestinationRule `connectTimeout` timing proof, a DR `maxConnections=1` WebSocket flow (one held session admitted, a concurrent upgrade rejected 503, recovery after release), and a CP + native-subscribe leg (a Ferrum CP in `cp` mode builds its mesh model from the cluster's real Services/pods via K8s pod discovery; a captured sidecar DP on `FERRUM_MESH_CONFIG_PROTOCOL=native` serves traffic only if the MeshSubscribe-delivered slice materialized its inbound routes, and its JWT-authenticated `GET /mesh/config-drift` must attribute the slice to the native transport) — emitting `sidecar.*` live assertions the workflow then validates against the contract (`tests/conformance/live_contract.rs`: required IDs present + passed for the exact suite/profile/commit, no duplicate or stale artifacts). Those Stable sidecar rows — PeerAuthentication STRICT, AuthorizationPolicy ALLOW/DENY, RequestAuthentication JWT, DR `connectTimeout`/`maxConnections`, VirtualService CORS, SPIFFE identity plumbing (`mesh.identity.spire_svid_issuance`, live-backed by `sidecar.spire.workload_entries` plus the SVID-carried STRICT-mTLS positive), and native `MeshSubscribe` config transport (`mesh.config_transport.native_subscribe`, live-backed by `sidecar.config.native_subscribe_delivered`) — are enrolled **vertically**: semantic conformance assertion → GA contract row → required live assertion. VS CORS is live-backed since issue #1973 closed: the mesh slice carries `virtual_service_cors_policies` (K8s translator emission per VS host, file-source expressible, own xDS ECDS carrier), the client sidecar synthesizes the `cors` plugin onto its materialized outbound routes, and the suite proves an allowed Origin reflected, a sidecar-answered Istio 200 preflight, plus unmatched actual and preflight forwarding without gateway-added CORS authorization. The complete M2 contract is **PR- and release-blocking**: a deploy-only smoke (`mesh-e2e-sidecar` in `ci.yml`) gates every PR touching the suite's surfaces; the dedicated live workflow's result — fixture **plus** artifact validation — is a merge-blocking required check (its `Mesh E2E Sidecar Live` gate job, required via branch protection, the same pattern as the Gateway API lab); and the live suite runs on every main push so `release.yml`'s `validate-release-sha` can refuse any tag whose SHA lacks a green, contract-validated live run. The cross-cluster east-west rows (`mesh.multicluster.*`, issue #2459) are enrolled the same way against the `multicluster-federation` suite (`tests/k8s/multicluster-federation/`, workflow `.github/workflows/multicluster-federation-live.yml`, platform profile `kind-spire-multicluster-federation`): semantics pinned by `tests/conformance/mesh_multicluster_federation.rs` plus the `EastWestGateway topology` row, live-gated by thirteen required `multicluster.*` assertions, and blocking at the same three points — the fixture's own fail-closed required-assertion check, the workflow's `Multicluster Federation Live` gate job (which re-validates the emitted `live-assertions.json` against the contract), and `release.yml` SHA validation. Poller-driven cross-cluster *endpoint discovery* stays Experimental and is excluded from every one of those rows.

### Config-source maturity

| Capability | Status | Notes |
|---|---|---|
| Native `MeshSubscribe` (Ferrum CP → Ferrum DP) | **Stable** | Default protocol. Full slice (authz, PeerAuth, JWT, ServiceEntry, trust bundles, ProxyConfig, workloads, telemetry, multi-cluster) is pushed directly. The most mature and recommended config path. Enrolled in the conformance GA contract as `mesh.config_transport.native_subscribe` (semantics: `tests/conformance/mesh_config_transport.rs`; live: `sidecar.config.native_subscribe_delivered` via the `mesh-e2e-sidecar` CP + native-subscribe leg). |
| xDS ADS (Ferrum CP → Ferrum DP) | **Beta** | Functionally equivalent to native via Ferrum-specific ECDS carriers (`ferrum.config.extension.v3.*`), including `ProxyConfig` on `ProxyConfigsCarrier`. **NOT stock-Envoy / third-party-Istio interop** — a non-Ferrum CP emits only name-only CDS/EDS/LDS/RDS and no carriers, so it cannot drive a protected Ferrum mesh and may be NACKed. RTDS layers are authored by the operator's CP (Ferrum's xDS server does not originate Runtime resources). |
| Localized file source (`FERRUM_MESH_CONFIG_PROTOCOL=file`) | **Beta** | No control plane: the DP builds its slice locally from `FERRUM_MESH_FILE_CONFIG_PATH` through the same materialization path as native/xDS, so enforcement parity is structural. Fail-closed initial load; SIGHUP reload (Unix) keeps the last good slice on error. Sharp edges: reload is signal-driven only (no file watching), and there is no CP heartbeat — `/mesh/config-drift` staleness reflects the last SIGHUP, not a sync failure. |
| Stock Envoy / third-party Istio xDS interop | **Not supported** | See [Limitations](#limitations-and-not-supported). Use native or a Ferrum CP. |

### Topology maturity

| Topology | Status | Notes |
|---|---|---|
| `Sidecar` + native config | **Stable** | The most mature path: inbound 15006 mTLS + outbound 15001 capture, SPIFFE-verified peers, full authz/JWT/DR enforcement. Recommended for production. GA-gated together with the native transport: `mesh.config_transport.native_subscribe` requires the live `sidecar.config.native_subscribe_delivered` assertion, proven by a captured sidecar DP on `FERRUM_MESH_CONFIG_PROTOCOL=native` whose inbound datapath materializes only from the CP-delivered slice. |
| `Ambient` (HBONE 15008) | **Beta** | HBONE termination over mTLS is implemented and SPIFFE-trust-domain-verified. Requires eBPF ambient capture (or iptables) to actually intercept traffic — see capture maturity below. |
| `EastWestGateway` (SNI passthrough 15443) | **Stable** | TCP/SNI passthrough for multi-cluster; no TLS termination. Live-gated by the `multicluster-federation` suite (issue #2459). Cross-cluster *endpoint* discovery (vs SNI passthrough) is separate and Experimental — see below. |
| `EgressGateway` — HTTP-family (15090 mTLS) | **Beta** | mTLS-terminating egress for `mesh_external` ServiceEntries with `outboundTrafficPolicy` enforcement. |
| `EgressGateway` — stream-family (TCP) | **Experimental** | Opt-in via `FERRUM_MESH_EGRESS_STREAM_ENABLED=true`. Per-port TCP stream listeners **terminate SVID-mTLS and run `mesh_authz`** at accept (parity with HTTP egress), reusing the mesh-inbound `ServerConfig` + SPIFFE peer verifier; **client certs are required** (PERMISSIVE is escalated to require a verified SVID for the egress boundary — a cert-less client is rejected, not admitted). Fail-closed (no mTLS material → listener defers its bind, never plaintext; no trust anchor under PERMISSIVE → hard error). `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true` restores the legacy plaintext + unauthenticated listener (loud startup warning; use only with compensating controls). UDP ServiceEntry ports are classified but not materialized by EgressGateway; see the UDP/DTLS notes below. Default-off topology; Experimental because protocol-aware mediation is absent and the live mTLS datapath is unit/integration-tested, not yet live-e2e. |
| `ServiceWaypoint` (GAMMA) | **Beta** | Service-scoped Ambient waypoint; CP narrows resources to the named binding. Needs the eBPF/ambient capture caveats of node-waypoint when fronting captured pods. |
| `NodeWaypoint` (sidecarless capture) | **Experimental** | HBONE listener is implemented; the GAP-2M accept-side bridge is implemented in the kernel `sock_ops` program (re-keys the orig-dst record by connection tuple, then re-stamps it under the accept-side cookie), and per-pod identity enrollment is wired (slice apply installs a `workload_spiffe_hash`→SPIFFE index that `resolve_record` hash-joins against the eBPF-stamped `(pod_uid, hash)` to lazily enroll identities). NodeWaypoint startup now treats the SOCK_OPS bridge as required: if it cannot attach, node-agent reports `identity_bridge_unavailable` and refuses readiness. The `node-waypoint-ebpf-live` GitHub Actions workflow builds Docker images, creates a disposable dual-stack two-worker kind cluster, installs a minimal SPIRE Server/Agent fixture, registers per-node NodeWaypoint Workload API SVID entries, collects BPF link/map evidence while gating capture/identity/chart changes, admits `src-a` IPv4 and IPv6 Service ClusterIP traffic, rejects `src-b` IPv4 and IPv6 Service ClusterIP traffic with live `AuthorizationPolicy`, checks denied-source and unmanaged direct Pod-IP attempts fail closed instead of bypassing capture, and forces source workload IPv4 reuse so the replacement UID/identity must be admitted while the old registry markers are gone. NodeWaypoint does not synthesize pod-IP HBONE upstreams to backing pod `:15008`; direct Pod-IP is guarded as a bypass surface in this live gate rather than advertised as a routable allowed-source path. **IPv4 and IPv6 capture, secured service transport, and destination relay authz are live-gated:** the in-netns manager binds `127.0.0.1:<port>` and `[::1]:<port>` inside each enrolled pod netns, `connect4`/`connect6` rewrite to those listeners, both `sock_ops` bridge paths handle `AF_INET` and `AF_INET6`, Kubernetes pod discovery populates `Workload.node_waypoint` from trusted ready host-network NodeWaypoint proxy pods on the destination node, and captured Service targets that carry that metadata use SPIFFE-mTLS HBONE to the destination NodeWaypoint endpoint while preserving the selected workload app address as CONNECT authority. The source NodeWaypoint asserts the captured source workload SPIFFE ID in trusted HBONE baggage while the outer mTLS connection remains pinned to the NodeWaypoint SVID, so destination `mesh_authz` can evaluate AuthorizationPolicy source matches against the originating workload. Identity-backed NodeWaypoint runtimes skip metadata-absent service targets so they cannot become plaintext backends; explicit no-CA/no-identity development runs retain the temporary plaintext fallback. Destination-side validation uses the selected workload destination scope only on the synthesized inbound HBONE relay when the trusted source assertion is honored; missing or untrusted relay baggage keeps the missing-source-scope fail-closed path, and the live gate now pins a wrong exact assertor SPIFFE ID to prove authenticated-but-untrusted baggage is rejected. The production identity profile is live-gated with Workload API SVID metrics, plaintext/no-client-SVID HBONE rejection, and SPIRE Agent plus NodeWaypoint restart recovery before traffic and policy are accepted. The pod-veth tc guard now drops unmarked direct traffic to enrolled pod IPs on host-side veth ingress; only the inbound HBONE relay backend dial is authorized with the Ferrum socket mark. **UDP/DTLS** stream authz is mesh-wide-only by architectural blocker (eBPF capture is `connect()`-hooked and TCP-only). Slice preparation accepts enforcing namespace/selector-scoped `AuthorizationPolicy` updates but disables NodeWaypoint UDP/DTLS service ports and UDP/DTLS proxies so unsupported traffic fails closed during config preparation; mesh-wide policies still evaluate, and audit-only scoped policies do not force suppression. Missing TCP scope or unresolved capture identity still rejects with 403 when scoped policies exist; with only mesh-wide policies, supported paths fall through to mesh-wide-only evaluation. Requires a Linux `--features ebpf` build; Helm automatically selects `…:<tag>-ebpf` for enabled eBPF node-agent and NodeWaypoint proxy DaemonSets. |

### Capture / data-path maturity

| Capability | Status | Notes |
|---|---|---|
| iptables capture (injector init container) | **Beta** | Requires `NET_ADMIN`/`NET_RAW`; rules applied at pod admission, restart needed to pick up new annotations. |
| eBPF ambient capture | **Dev-only** | Requires a build with `--features ebpf`. The default published image has no aya loader, but enabled eBPF node-agent mode now refuses the mock backend before readiness (`capture_state="unavailable"`, degraded reason `ebpf_feature_disabled`). Helm renders the Linux-only `-ebpf` image variant (`ferrumedge/ferrum-edge:<tag>-ebpf` / `ghcr.io/ferrum-edge/ferrum-edge:<tag>-ebpf`) automatically for `nodeAgent.captureMode=ebpf`, and for the ambient/NodeWaypoint proxy when it is configured for eBPF or `FERRUM_MESH_TOPOLOGY=node_waypoint`. Real capture needs kernel **≥ 5.7** with cgroup v2 and, on kernel **≥ 5.8**, `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON`; on the **5.7.x** window use `CAP_SYS_ADMIN` + `CAP_NET_ADMIN`. `node_waypoint` mode also needs `CAP_SYS_ADMIN` on modern kernels for pod-netns `setns()`/veth discovery, so the chart adds it automatically for that topology. The NodeWaypoint ambient proxy additionally receives host PID visibility plus read-only host cgroup and bpffs mounts so it can resolve pod netns, open node-agent-pinned maps, and write per-pod ready markers only after its in-netns listener is attached. CI builds the BPF object (`build-ebpf`), compiles the userspace loader (`build-ebpf-userspace`), load/attach-tests programs on a real kernel (`ebpf-live`), and runs the Docker/kind multi-pod datapath gate (`node-waypoint-ebpf-live`) for capture/identity/chart changes. Inbound TC redirect is deferred; the destination tc direct-inbound guard is implemented, and the iptables fallback is node-global and needs a custom runtime image with `/bin/sh` + `iptables`. |
| orig-dst → proxy identity bridge (node-waypoint) | **Experimental** | `src/ebpf/orig_dst_bridge.rs` mirrors socket-cookie records into the resolver (+ installs a synchronous accept-path fallback); the **accept-side cookie bridge (GAP-2M) is implemented** in the kernel `sock_ops` program (re-keys orig-dst by connection tuple, re-stamps under the accept-side cookie), and **per-pod identity enrollment is wired** (hash-join of the slice's `workload_spiffe_hash`→SPIFFE index against the eBPF-stamped `(pod_uid, hash)`), so resolution is complete end-to-end with no further proxy-side change — **IPv4 and IPv6**: both bridge paths handle `AF_INET` and `AF_INET6` (v6 ctx address words read element-by-element with verifier-safe volatile loads into `FERRUM_ORIG_DST_BY_TUPLE6`), and the in-netns manager now binds both pod-loopback families. The userspace resolver merges both families by socket cookie. The `node-waypoint-ebpf-live` workflow validates IPv4 and IPv6 end-to-end capture; tuple/byte-order/enrollment misses fail closed (never misattribute), including a cached pod whose workload a later slice removes because `resolve_record` re-validates against the current slice index on every resolve. |

### Identity / CA maturity

| Capability | Status | Notes |
|---|---|---|
| SPIRE Agent CA (`spire_agent`) | **Stable** | Recommended production identity path — delegates SVID issuance to a separately operated SPIRE installation over the Workload API. Enrolled in the conformance GA contract as `mesh.identity.spire_svid_issuance` (semantics: `tests/conformance/mesh_spiffe_identity.rs`; live: `sidecar.spire.workload_entries` + the SVID-carried STRICT-mTLS positive in `mesh-e2e-sidecar`). |
| Internal self-signed CA (`internal`) | **Dev-only** | Self-signed root generated by the bootstrap helper; gated behind `FERRUM_MESH_CA_BOOTSTRAP_DEV=true` and refused when `FERRUM_MESH_PRODUCTION_MODE=true`. Lab/test only — see [Internal Dev CA and Production Guardrails](#internal-dev-ca-and-production-guardrails). |
| SPIFFE inbound/HBONE peer trust-domain verification | **Stable** | When gateway SVID material is configured, inbound mTLS/HBONE peers are SPIFFE-trust-domain-verified against the local + federated bundles (not just chain-validated). |
| Trust-bundle federation poller | **Beta** | Fetches `RemoteCluster.federation_endpoint` bundles and activates the same effective trust set for outbound mTLS and inbound SPIFFE verification. `FERRUM_MESH_FEDERATION_FAIL_OPEN=false` blocks CP fallback until a poll succeeds; `true` allows CP fallback during bootstrap. |

### Cross-cluster maturity

| Capability | Status | Notes |
|---|---|---|
| East-west SNI passthrough + trust federation | **GA** | See `EastWestGateway` above and [Trust Federation](#trust-federation). |
| Cross-cluster endpoint discovery (local→remote failover) | **Experimental** | `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS>0` dials each `RemoteCluster.control_plane_url`. Aggregation + locality failover are integration-tested with a mockable source, and the production `MeshSubscribe` dialer has in-process two-CP loopback coverage. A true two-network, poller-driven live fixture remains deferred. Requires source locality to be set for local-first preference. |

## Limitations and Not Supported

This section consolidates every known residual gap so operators do not have to reconstruct them from the prose. Items are grouped by area; each is enforced or deferred as described against the merged code.

### Not interoperable / not planned

- **Stock Envoy / third-party Istio xDS interop** — Ferrum's `FERRUM_MESH_CONFIG_PROTOCOL=xds` is a **Ferrum-CP-to-Ferrum-DP** path. It follows the Envoy ADS gRPC contract, but CDS/EDS/LDS/RDS are name-only with Ferrum-shaped resource names, and all security/policy fields ride Ferrum-defined ECDS carriers. A stock Envoy/Istio CP does not emit these, so pointing Ferrum's xDS client at a non-Ferrum CP is unsupported and may be NACKed. Use native, or a Ferrum CP over xDS.
- **`EnvoyFilter`** — not planned. Use Ferrum custom plugins (`custom_plugins/`).
- **`WasmPlugin`** — not planned. Use Ferrum custom plugins.
- **Per-node ADS stream ceiling** — `FERRUM_XDS_MAX_STREAMS_PER_NODE` (default `4`, `0`=unbounded) bounds concurrent ADS streams under one node id; excess streams are rejected with gRPC `RESOURCE_EXHAUSTED` and counted by `ferrum_xds_streams_rejected_total`. (Resource warming / make-before-break across types is now implemented — see [xDS ADS Compatibility](#xds-ads-compatibility).)

### Capture / node-waypoint (see also the Maturity matrix)

- **eBPF capture is a build feature** — the default published image lacks the aya loader, but enabled eBPF node-agent mode rejects that mock backend before readiness instead of silently no-op'ing. Helm automatically selects the `-ebpf` image tag for enabled eBPF node-agent and NodeWaypoint proxy DaemonSets. CI load/attach-tests the programs on a real ≥5.7 kernel (`ebpf-live`) and gates capture/identity/chart changes with the Docker/kind multi-pod `node-waypoint-ebpf-live` workflow.
- **Node-waypoint identity: GAP-2M bridge implemented (IPv4 + IPv6), capture live-gated** — the accept-side socket-cookie bridge is implemented in the kernel `sock_ops` program (re-keys orig-dst by connection tuple, re-stamps under the accept-side cookie), so cookie resolution can succeed with `--features ebpf`. **IPv4 and IPv6**: the v6 ctx address words are read element-by-element with verifier-safe volatile loads (the per-element technique that sidesteps the verifier's rejection of a whole-`[u32;4]` ctx copy) and keyed by `FERRUM_ORIG_DST_BY_TUPLE6`, so the v6 accept-side bridge resolves on the same footing as IPv4. The in-netns manager binds both `127.0.0.1:<port>` and `[::1]:<port>` inside enrolled pod netns, and the `node-waypoint-ebpf-live` workflow validates both capture families; a tuple/byte-order mismatch fails closed (never misattributes).
- **Node-waypoint destination metadata** — each mesh `Workload` can carry an optional `node_waypoint` object with `address`, `hbone_port` (default `15008`), expected NodeWaypoint `spiffe_id`, and optional `node_name`, `node_uid`, `network`, and `cluster`. Kubernetes pod discovery populates this object for service-backed workloads when their node has a ready host-network NodeWaypoint proxy pod in `FERRUM_K8S_CONTROLLER_NAMESPACE` with `app.kubernetes.io/name=ferrum-mesh-ambient`, service account `ferrum-mesh`, and `FERRUM_MESH_TOPOLOGY=node_waypoint`; scoped workload watches still include that trusted namespace for Pod discovery. The Helm chart sets `FERRUM_K8S_CONTROLLER_NAMESPACE` to the release namespace and requires the ambient NodeWaypoint admin health listener to stay enabled so the DaemonSet has a real readiness probe. The endpoint address comes from the proxy pod IP, `hbone_port` comes from `FERRUM_MESH_HBONE_LISTEN_ADDR` when present (then the named `hbone` container port, then default `15008`), and the expected peer identity comes from `FERRUM_MESH_WORKLOAD_SPIFFE_ID` when present (then the proxy pod's service account SPIFFE ID). Captured Service targets consume this metadata when present: they select the workload first, keep the workload app address and port as the inner CONNECT authority, dial the hosting node's NodeWaypoint endpoint via `mesh.hbone_dial_host`, and pin `mesh.hbone_peer_spiffe_id` instead of synthesizing `podIP:15008`. When the source NodeWaypoint runtime has file SVID material or a mesh CA backend (required by production mode), metadata-absent targets are skipped so the Service route fails closed instead of retaining a plaintext backend. Explicit no-CA/no-identity development runs keep the temporary plaintext fallback; the required live gate uses SPIRE-backed production mode instead.
- **Node-waypoint UDP/DTLS stream authz is mesh-wide-only** — TCP stream connections through a node-waypoint proxy now scope per source pod via `resolve_node_waypoint_stream_scope()` (socket-cookie → pod identity → `PolicyScopeCache`); when the connect-side resolver returns no identity, the connection fails closed with 403 if any namespace/selector-scoped `AuthorizationPolicy` exists in the mesh (else falls through to mesh-wide-only evaluation). **UDP/DTLS** scope is unresolvable by architecture — eBPF capture is `connect()`-hooked and TCP-only, and a UDP proxy demuxes all clients off one shared frontend socket — so UDP node-waypoint authz is always mesh-wide-only. NodeWaypoint slice preparation accepts scoped policy updates but disables UDP/DTLS service ports and UDP/DTLS proxies when enforcing namespace/selector-scoped policies exist, so UDP/DTLS fails closed instead of continuing under stale no-policy config; mesh-wide policies still evaluate, and audit-only scoped policies do not force suppression.
- **Inbound TC ingress redirect implemented (IPv4 + IPv6), opt-in and live-gated** — `ferrum_tc_ingress_redirect` (`ebpf/ferrum-ebpf/src/tc_ingress_redirect.rs`) is a tc **ingress** classifier attached to the node capture interfaces named by `FERRUM_NODE_AGENT_INGRESS_REDIRECT_IFACES` (unset = off, and the whole datapath stays inert). It steers inbound TCP for enrolled workloads into a dedicated **transparent inbound capture listener** with `bpf_sk_assign()` instead of a node-global `nat PREROUTING -j REDIRECT`. **The steer target is NOT the HBONE listener**: HBONE (`:15008`) terminates authenticated HTTP/2 CONNECT over verified mesh mTLS, while captured traffic is ordinary application bytes (possibly the app's own TLS), and `IP_TRANSPARENT` preserves addresses rather than transforming payloads. The capture listener is a separate protocol boundary bound on `FERRUM_MESH_INBOUND_LISTEN_ADDR` (default `0.0.0.0:15006`, unused by NodeWaypoint otherwise) — the single source of truth for the port on both the proxy and the node-agent — and it terminates nothing. **Scope is per workload and per port**: the destination must be in `FERRUM_POD_IPS`/`FERRUM_POD_IPS6` carrying `POD_CAPTURE_FLAG_INBOUND_REDIRECT`, *and* the exact `(pod address, destination port)` pair must be in `FERRUM_POD_INBOUND_PORTS`/`FERRUM_POD_INBOUND_PORTS6` (derived from the pod's declared `containerPorts`); anything else is returned untouched, so unenrolled traffic is never captured. **IPv4 fragments are declined before any port is read** (More-Fragments or non-zero offset), because a non-first fragment's payload bytes would otherwise be parsed as ports and could be made to match a declared pair; IPv6 extension/fragment chains likewise pass through unparsed. **Original destination metadata is preserved without NAT** — addresses are never rewritten, so the capture listener's accepted socket reports the workload's real `podIP:appPort` from `getsockname()` with no conntrack table and no reverse NAT; that one listener (and no other) binds `IP_TRANSPARENT`/`IPV6_TRANSPARENT` on a wildcard address so its replies may be sourced from the captured pod address. **Security posture on the capture path is DESTINATION-EXACT**, because one capture listener serves every enrolled pod on the node: the recovered destination must resolve to exactly one workload in a dedicated **NodeWaypoint capture destination inventory** (address match plus a port the workload declares — no match, an empty inventory, or two records claiming the address with divergent identity all close the connection), and both gates that follow are then properties of *that* workload rather than of the listener. Direct captured plaintext is admitted only where **that workload's own** effective PeerAuthentication posture on the captured app port permits it — resolved from its namespace/labels with the canonical resolver, deliberately not from the listener-wide per-port table, so a `PERMISSIVE` pod can never admit plaintext to a `STRICT` pod sharing the app port; `STRICT` still requires verified mesh transport and refuses direct plaintext.

  **Cross-namespace destination policy (issue #3287).** A NodeWaypoint is typically deployed in an infrastructure namespace (`ferrum`) while the pods it captures for live in application namespaces (`payments`). The ordinary slice views — `workloads`, `peer_authentications` — are narrowed to the subscription namespace, so they can neither name a cross-namespace destination nor carry that destination's `PeerAuthentication`; resolving against them would see no policy and fall back to Istio's `PERMISSIVE` default, admitting direct plaintext to a `STRICT` pod. The capture path therefore consumes **two dedicated, least-privilege slice fields** instead:

  * `node_waypoint_capture_destinations` — the workloads whose trusted `Workload.node_waypoint.spiffe_id` names **this exact NodeWaypoint**. That key is per-node, set by the config authority (never by the pod), and is the same identity the secured NodeWaypoint transport pins as the destination's server SVID.
  * `node_waypoint_capture_peer_authentications` — the PeerAuthentication candidates applicable to those destinations (mesh-wide/root-namespace, namespace-scoped, and selector-scoped alike), so Istio precedence and port overrides resolve exactly as the destination's own sidecar would resolve them.

  The request opts in with `MeshSliceRequest.node_waypoint_capture_scoping`, set only for `MeshTopology::NodeWaypoint`. It is deliberately **not** folded into `ambient_udp_source_scoping`: NodeWaypoint UDP stays mesh-wide-only by architecture, so one shared flag would either hand NodeWaypoint a UDP source superset it must not act on, or leave Ambient/ServiceWaypoint carrying a capture inventory they have no capture listener for. Native `MeshSubscribe` carries the flag as `MeshSubscribeRequest.node_waypoint_capture_scoping`; xDS carries it in `Node.metadata` and returns the inventory on its own ECDS carriers (`NodeWaypointCaptureDestinationsCarrier`, `NodeWaypointCapturePeerAuthenticationsCarrier`), so native and xDS reach the same posture. The file/local source derives it DP-side from the same document.

  **Authorization and blast radius.** The CP resolves the inventory *before* its own namespace narrowing (after it, the cross-namespace records are already gone) but *after* applying the CP scope and the bearer `ns` claim: a `Single`-scope CP is a hard boundary for this cross-namespace evidence exactly as it is for Ambient UDP source evidence, and an explicit `ns` claim intersects the set. The inventory is **never** folded into `workloads` / `services` / `peer_authentications`, so ordinary routing, known-destination, outbound-registry, and own-inbound-posture views stay namespace-narrow. It is read by the capture resolver and nothing else. **Fail closed everywhere:** a legacy CP that emits no inventory, a NodeWaypoint whose own SPIFFE identity is unknown, a namespace the CP or bearer does not authorize, and a pod enrolled on another node's NodeWaypoint all yield no resolvable destination — the connection is refused (and counted as `relay_destination_denied`), never resolved against `workloads` with the wrong policy view. Incremental CP deltas carry no mesh resources, so the per-stream inventory is recomputed from the authoritative snapshot on every mesh change rather than accumulating stale destinations; `MeshSlice::content_eq` compares both fields so a destination leaving the inventory, or its namespace flipping `PERMISSIVE`→`STRICT`, is never deduped away.

  **Residual risk.** The posture the capture path enforces is only as good as the destination inventory the config authority publishes: a workload whose `node_waypoint` endpoint metadata is missing or points at the wrong NodeWaypoint is not captured for at all (fail closed, but its inbound direct plaintext is then simply dropped by the classifier rather than relayed). Cross-*cluster* capture destinations are out of scope — the inventory is derived from the local cluster's workload records. The L4 `on_stream_connect` chain (including `__mesh_authz`) then runs with the captured app port as the authorization destination and that workload's policy scope stamped on the stream context, so namespace/selector-scoped `AuthorizationPolicy` rules are evaluated against the captured destination instead of denying every captured connection `scope_missing`; the stream is then relayed byte-for-byte so application TLS is never mistaken for mesh TLS. Every gate is fail-closed, and Sidecar inbound relay entries are unchanged (no socket mark, no destination scope). Backend dials carry the relay auth mark (`0x734`) for loop prevention and pod-veth admission. Local delivery of assigned packets rides a Ferrum-owned `ip rule fwmark 0x735 lookup 33134` at priority `101` (evaluated ahead of the kernel `main` rule at 32766, which the RPDB scans later because its priority number is higher) plus `ip route add local default dev lo table 33134`, per family; the table is distinct from the UDP TPROXY table `33133` so teardown of one never reaps the other. **Loop prevention** is four independent guards: the relay's own auth mark (`0x734`), the redirect mark itself (`0x735`), traffic already addressed to the capture port, and traffic addressed to the HBONE port. **Fail closed**: a packet that is in scope but for which no capture-listener socket resolves is dropped, never delivered unredirected; and startup refuses if the redirect is armed while the capture listener cannot bind or the node-agent/proxy port contracts disagree — the proxy validates `FERRUM_MESH_INBOUND_LISTEN_ADDR` (present, non-zero port, wildcard) with a field-specific error at the top of its serving path, because listener *planning* is infallible and would otherwise warn-and-skip the listener while the classifier kept dropping in-scope packets. **Teardown is retry-safe and ordered**: a failed classifier detach keeps its attachment recorded so `cleanup_all` really does retry it, and the Ferrum-owned local-delivery `ip rule`/`ip route` is removed only once no classifier can still be live (a live classifier without its routing strands every packet it assigns; inert leftover routing is the safe half-state and is reported rather than force-removed). **The node-global iptables fallback is NOT removed** — it remains the documented path for kernels that cannot run eBPF at all (`FERRUM_NODE_AGENT_FALLBACK_MODE=iptables`), which is a separate concern from the covered eBPF path. Verification: the shared decision table (arming, scope, all four bypasses, the fragment gate) is unit-tested in `ferrum-ebpf-common`, and the required `ebpf-live` CI job load/verifies the program on a real kernel — the only way to check the `bpf_skc_lookup_tcp`/`bpf_sk_assign`/`bpf_sk_release` reference-tracking rules — attaches and detaches it on a scratch veth tc ingress hook, round-trips both address families of the scope maps, **and drives a real TCP flow end to end** from a client in a scratch netns through the redirect into the transparent capture listener, asserting the observed original destination, a successful reply path, and that the flow is no longer steered after detach + scope clear.

### Authorization

- **`ipBlocks` / `remoteIpBlocks` on the stream path now distinguish socket peer from forwarded address** — on the HTTP request path `ipBlocks`/`source.ip` is the immediate downstream socket peer (`direct_client_ip`) and `remoteIpBlocks`/`remote.ip` is the gateway-resolved, XFF-aware `client_ip`. On the **TCP stream path** (`on_stream_connect`) the same split now applies: `source.ip` = socket peer (`StreamConnectionContext.direct_client_ip`), `remote.ip` = resolved client IP (`StreamConnectionContext.client_ip`). When **inbound PROXY protocol** (`stream_proxy_protocol: true`) is enabled on a TCP stream proxy and the upstream LB is in `FERRUM_TRUSTED_PROXIES`, the forwarded address from the PROXY header becomes `client_ip` (used for `remote.ip` / `remoteIpBlocks`) while `direct_client_ip` retains the LB's own socket-peer IP (used for `source.ip` / `ipBlocks`). Without PROXY protocol both values equal the socket peer — this is the correct Envoy-parity behavior for raw TCP not fronted by a PROXY-protocol-capable LB. **UDP/DTLS** streams never receive PROXY protocol (it is TCP-borne), so `source.ip` and `remote.ip` always equal the socket peer on the UDP path. IP-block matchers fail closed when the IP they test is absent.
- **DENY rules treat missing HTTP-only attributes as matches** — Istio semantics. Port-scope DENY rules that mention HTTP fields and can see TCP traffic, or they may over-match.

### DestinationRule (parsed but inert / approximated / deferred)

- **`connectionPool.http.maxRequestsPerConnection`** — **Deferred**: parsed and validated, but not projected or enforced because Ferrum has no backend close-after-N-requests behavior for the shared backend pools. K8s status lists it in `status.ferrum.translation.deferred_fields`; negative values are rejected and `0` is accepted as Istio's unlimited sentinel but still deferred. Use `http2MaxRequests` for HTTP/2-family concurrency.
- **`connectionPool.tcp.maxConnections`** — enforced for **stream-family (TCP)** and **HTTP-family WebSocket** (H1/H2/H3) via an RAII guard on `ProxyState.backend_conn_limit`. The pooled multiplexed transports (reqwest H1/H2, direct H2, gRPC, H3, HBONE) do **not** enforce it because their backend-connection lifecycle is pool-internal (reuse, sharding, idle eviction) and a request-keyed counter would measure request concurrency rather than open connections — use `http2MaxRequests` / `h2_max_concurrent_streams` for HTTP/2-family concurrency instead. Full rationale in [DestinationRule `maxConnections` enforcement scope](#destinationrule-maxconnections-enforcement-scope).
- **`connectionPool.http.h2UpgradePolicy`** — **applied** to the plain-HTTPS backend HTTP/1.1-vs-HTTP/2 dispatch fork (top-level / `portLevelSettings` only — set inside a subset it is deferred-and-warned, see below). `DO_NOT_UPGRADE` forces the reqwest/H1 path even when the backend capability registry proves H2 **and** restricts the reqwest client's ALPN to `http/1.1` (with a force-H1 reqwest pool-key discriminator) so a TLS backend cannot ALPN-negotiate h2; `UPGRADE` prefers direct-H2 (and treats an unclassified `Unknown` target as a hint to try H2, staying fail-safe against a proven-`Unsupported` one); `DEFAULT`/absent leaves probe-driven behavior unchanged (`DEFAULT` is carried explicitly so an explicit port-level `DEFAULT` clears an inherited top-level override). Does NOT touch gRPC (always H2) or HBONE/mesh-mTLS transport selection. Unknown enum values are rejected at translate time.
- **`connectionPool.http.maxRetries`** — **applied** as a **per-request retry-count CAP**, NOT Envoy's cluster-wide outstanding-retry budget (see [DestinationRule `maxRetries` semantics](#destinationrule-maxretries-semantics)). Caps an existing `Proxy.retry` to `min(existing, maxRetries)`; never increases retries and does NOT synthesize a retry policy when none exists. Zero/negative values are rejected at translate time.
- **`connectionPool.http.http1MaxPendingRequests`** — **applied** (top-level / `portLevelSettings` only — set inside a subset it is deferred-and-warned, see below) as a per-`(host, port)` cap on the **reqwest/HTTP-1.1** backend-dispatch path. **Honest reinterpretation — max concurrent in-flight H1 requests** (mirroring how DR `maxRetries` is reinterpreted as a per-request cap): Envoy's knob bounds the *pending-queue* depth (requests admitted but not yet assigned a connection), but Ferrum dispatches H1 over reqwest, whose `send().await` resolves at **response headers** and exposes **no connection-acquisition hook** — so true pending-queue depth is not measurable. Ferrum therefore reframes the knob as a bound on how many H1 requests are **simultaneously in flight** to a destination (measured dispatch → response-headers); when a destination is at its cap a new H1 request is **shed with a 503** ("upstream overflow", classified `dispatch_policy_rejected`) rather than queued unboundedly. Because the shed happens before any backend dial, it is **neutral to backend health** — not retried, does not trip the backend circuit breaker / passive health, and does not shrink the adaptive-concurrency permit (a `client_side_no_backend_signal` class). The connection-failure **retry** path re-enters the same gate per attempt (the initial attempt's slot is released before the retry loop runs), so `retry_on_connect_failure` retries are bounded too. The gate is consulted only for dispatch **known HTTP/1.1 at acquire time** (`reqwest_dispatch_is_http1_only`): a `DO_NOT_UPGRADE` proxy, a **plaintext `http`** backend (reqwest never speaks h2c over cleartext), or an **HTTPS backend the capability registry has already classified H2-unsupported (H1-only)**; an HTTPS backend that may still ALPN-negotiate h2 is left **uncapped** (an `http1*` knob must not 503 an h2 backend — that is `http2MaxRequests`'s job). Under the in-flight framing there is **no body-shape exclusion** — bodyless GET/HEAD and streamed-upload requests are capped alike. **HTTP/1.1-scoped by design**: the multiplexed transports (direct H2, gRPC, HTTP/3, HBONE, mesh-mTLS) return before the reqwest path and never consult it. **Coverage note:** service-discovery upstreams are covered by the top-level `connectionPool.http` fallback (`dispatch_port_override_fallback`), and explicit per-port entries win when the selected target carries its declared service-port policy key, including named `targetPort` resolutions. The HTTP/3 frontend applies the selected-target effective proxy before native-H3, H3→gRPC, and H3→plain dispatch, so these knobs are no longer H1/H2-only from a configuration standpoint; transport-scoped behavior still applies (for example, this `http1*` cap is enforced only when dispatch is known HTTP/1.1). For an **HTTPS, h2-enabled** backend the cap engages only once the capability registry has confirmed the target H1-only; before that the dispatch may still ALPN-negotiate h2 (the default reqwest rustls config advertises h2 ALPN verbatim — see `build_rustls_for_reqwest`), so it is left uncapped to avoid 503-ing an h2 backend. Enforced via an RAII guard on `ProxyState.backend_pending_limit` (see `src/backend_pending_limit.rs`), a sharded `CachePadded` atomic CAS-bumped alloc-free per resolved `(host, port)`. Zero is rejected at translate time, and the native/file mesh-config path applies the same positive-value validation (`Some(0)` would shed every H1 request to the destination).
  When `pool_enable_http2: false`, Ferrum treats the reqwest dispatch as known HTTP/1.1 immediately because the preconfigured-rustls path omits h2 ALPN, so the cap applies without waiting for capability-registry classification.
- **Per-subset `connectionPool.tcp.connectTimeout`** — **applied**: it overrides `backend_connect_timeout_ms` for proxies whose `upstream_subset` selects the subset, taking precedence over the DestinationRule's top-level `connectTimeout`. **Per-subset `loadBalancer.consistentHash`** — **applied**: the subset policy carries both `LoadBalancerAlgorithm::ConsistentHashing` and the subset `hash_on` key, with request-time precedence matching selection (per-port > per-subset > upstream). **Per-subset `outlierDetection`** — **applied in full**: the thresholds (consecutive errors, interval, base-ejection time, min-health) resolve into the subset's passive-health overlay consulted by `passive_health_for_target`, and the `maxEjectionPercent` **cap** resolves per-subset via `LoadBalancerCache::max_ejection_percent_resolved_from`, both ahead of the upstream-level passive health for subset-bound proxies. The cap and the thresholds share the SAME per-port > per-subset > upstream tier precedence, so they are always drawn from the same tier, and the cap is sized against the **subset's** candidate pool (denominator = subset target count, not the whole upstream). One asymmetry: the cap is resolved *before* a target (and its port) is selected, so the per-port cap tier only applies when a single dispatch port is resolvable up front (non-subset dispatch, single-port upstreams, or port-pinned retries); for a subset-routed dispatch on a *multi-port* upstream no single dispatch port exists pre-selection, so the **subset** cap governs (falling back to the upstream cap) — this mirrors the long-standing thresholds-vs-cap asymmetry, since the thresholds reach a per-port overlay only because they run per selected target. Other per-subset `connectionPool` fields beyond `connectTimeout` are still parsed-and-warned.
- **`portLevelSettings[].tls`** — **applied** per-port: resolved over the upstream-level TLS at apply time and projected onto the per-target effective proxy's `resolved_tls` (which is part of the backend pool key, so a distinct per-port TLS posture fragments its own pool). Takes precedence over the upstream-/subset-level `trafficPolicy.tls` for dials to that port.
- **`loadBalancer.simple = PASSTHROUGH`** — true passthrough on captured paths: when the request's captured original destination (`SO_ORIGINAL_DST` on the mesh capture listeners) matches a target in the upstream's pool, that target is dialed (bypassing load balancing); when no original destination was captured (non-mesh / non-captured paths, e.g. HTTP/3) or it matches no (healthy) pool target, selection falls back to `ROUND_ROBIN` (warns). A passthrough-selected target still respects active/passive health — an ejected original-destination target falls back to round-robin among healthy targets. `MAGLEV` is a hard reject.
- Stream-family (TCP/UDP/DTLS) upstreams engage per-port `loadBalancer` (algorithm and hash key) and `localityLbSetting` at selection time when all upstream targets share a single port (i.e. the LB cache resolves a non-zero `initial_dispatch_port_override`), matching the pre-selection semantics the HTTP path uses. The port lane engages only for **selection-affecting** overrides (`loadBalancer` algorithm / `consistentHash` key / `localityLbSetting`); a per-port entry that carries only `connectTimeout` / `maxConnections` / `tcpKeepalive` / `outlierDetection` never changes stream selection. For a subset-routed stream proxy a per-port override that sets no algorithm keeps the **subset's** algorithm/hash ring while still scoping candidates and locality to the port lane. Three stream-lane rules are **fail-closed** (the connection is refused with a typed `Unsupported stream policy` setup error, classified as a request error — no backend-health penalty, no retry): a per-port `consistentHash` on an engaged stream lane must resolve to a **source-IP** hash key (header/cookie keys are HTTP-only — raw streams carry no headers); per-port `LEAST_CONN` is rejected on the generic TCP/UDP stream listeners, which keep no stream LB accounting (the **mesh** raw-TCP/UDP relays DO maintain per-target connection counts via their LB connection guards, so per-port `LEAST_CONN` selects normally there); and per-port `LEAST_LATENCY` is rejected on **every** stream lane — generic and mesh alike — because raw byte relays record no response latency. Stream consistent hashing (upstream-level or port-lane) hashes the **client IP**; previously stream selection used a static per-proxy hash key, which pinned all of a proxy's connections to one target — existing `consistentHash` stream configs now distribute per client. Stream selection now consults the same active-health and per-proxy passive-ejection state as HTTP-family dispatch, including the `maxEjectionPercent` cap at the resolved pre-selection tier. A passive-health-only per-port override scopes health/ejection caps to that port even though it does not engage the LB port lane; otherwise the cap resolves at subset/upstream scope. TCP `retry_on_connect_failure` rotation reuses the same health context and returns no alternate when the remaining candidates are unhealthy instead of synthesizing an unhealthy retry fallback. Per-port `outlierDetection` thresholds are still not recorded by stream paths — raw relay sessions carry no response status — so stream paths consume ejections recorded by active probes or HTTP-family traffic on the same proxy/upstream, but do not create new passive ejections themselves. Per-port `connectTimeout` and `maxConnections` apply to stream dial independently (they are post-selection).

### VirtualService

- **`spec.tcp[]` / `spec.tls[]` L4 routing** — **supported** (materialized into Ferrum stream proxies, reusing the gateway/east-west stream + SNI machinery): `tls[]` → a passthrough TCP proxy keyed by SNI (`sniHosts`, encrypted bytes forwarded with no TLS termination); `tcp[]` → a plain TCP proxy keyed by port. Match predicates the stream layer cannot express (`sourceLabels` / `sourceSubnets` / `destinationSubnets` / `gateways` / `sourceNamespace`) and weighted multi-destination splitting are **rejected fail-closed** (`FerrumAccepted=False`/`Invalid`) rather than mis-routed. (`mirror`, `mirrorPercentage`, `redirect`, and `rewrite` are fully translated.)
- **`http[].corsPolicy`** — translated to a proxy-scoped `cors` plugin. The full Istio `allowOrigins[]` `StringMatch` set is projected — `exact`, `prefix`, and `regex` (plus the legacy `allowOrigin` exact string list) — along with `allowMethods`/`allowHeaders`/`exposeHeaders`/`maxAge`/`allowCredentials`/`unmatchedPreflights`. Omitted, `UNSPECIFIED`, and `FORWARD` unmatched preflights are forwarded with the upstream status/body preserved, every upstream `Access-Control-*` response field stripped, and no gateway CORS authorization fields added; `IGNORE` receives a local 200 without CORS authorization. Unmatched actual requests are likewise forwarded with the upstream status/body preserved, every upstream `Access-Control-*` response field stripped, and no gateway CORS authorization fields added. A participating translated policy owns `Access-Control-*` response fields even when a request has no `Origin`: Ferrum strips those upstream fields while preserving unrelated response headers, preventing a shared-cache replay from widening the gateway policy. Omitted or empty method/header lists remain empty and omitted `maxAge` remains absent. Method/header lists govern preflight only and never reject an actual request; when native and translated instances compose, an empty Istio list still narrows the aggregate preflight policy without blocking the actual request. Exact `*` (including legacy `allowOrigin: ["*"]`) is Istio allow-all when credentials are false or omitted. A credentialed exact `*` stays deferred because Ferrum's native wildcard representation cannot emit the concrete request origin required for credentialed CORS; it is never translated into wildcard-without-credentials, and the native/file mesh carrier rejects the same unrepresentable combination. Every OTHER `exact` value is projected onto the `cors` plugin's LITERAL `{"exact": ...}` matcher, byte-for-byte (issue #3254): a wildcard-shaped exact such as `*.example.com` keeps its upstream literal meaning and is NEVER reinterpreted as Ferrum's native wildcard-subdomain syntax (which would authorize every subdomain the source never matched), and a noncanonical exact such as `https://Example.com:443` is carried verbatim instead of being canonicalized into permission for the browser-serialized origin. These shapes are therefore translated now rather than deferred. The plugin's NATIVE plain-string `allowed_origins` form keeps its own canonicalizing, case-insensitive, wildcard-subdomain semantics; the translator never emits it for an Istio matcher. The `cors` plugin's `allowed_origins` accepts the same matcher shapes as object entries (`{"exact": ...}` / `{"prefix": ...}` / `{"regex": ...}`): `exact` is a literal byte-for-byte, case-sensitive comparison with the request `Origin`, `prefix` is a literal byte-prefix, and `regex` is an RE2 full match (same `StringMatch` semantics Ferrum applies elsewhere); a matching origin is reflected verbatim into `Access-Control-Allow-Origin`. Matchers are admitted against EXPLICIT bounds shared by the translator, the plugin, and native/file mesh validation (issue #3253): at most 64 `allowOrigins[]` entries, 512 bytes per matcher value, and — for `regex` — a 64 KiB compiled-program limit, a 64 KiB lazy-DFA limit, and an AST nesting limit of 24. Every `regex` is compiled ONCE at config construction/reload, never per request (the engine is finite-automaton based, so there is no catastrophic backtracking). An un-compilable or over-complex `regex`, an over-budget matcher value or list, an empty/whitespace-only `exact`, an empty `prefix`, or an otherwise malformed/unknown origin matcher makes the policy non-translatable: it is left unprojected (warned, surfaced as a `deferred_fields` entry) rather than silently approximated, truncated, or widened — configure the `cors` plugin directly for those. Routing on the route is unaffected either way. On **mesh sidecars** a translatable `corsPolicy` ALSO rides the slice as `mesh.virtual_service_cors_policies` (one entry per VS host; the FIRST SIDECAR-APPLICABLE entry decides, mirroring Istio's in-order first-match evaluation: if it is host-wide-representable — no `match`, or a catch-all `/` prefix, with `name`/`ignoreUriCase` treated as non-scoping metadata — its translatable corsPolicy is carried; if it has no corsPolicy, its policy is untranslatable, or it is PREDICATE-SCOPED (narrower uri, `headers`, `port`, `sourceLabels`, …), nothing is carried — a scoped entry wins part of the host's traffic with its own (possibly absent) CORS, and the materialized mesh route has no path predicates to keep the two apart, so a later route's policy is never promoted host-wide. Entries invisible to sidecars neither donate nor suppress. Exact matchers are carried literally, so a whitespace-padded, noncanonical, or non-`scheme://host[:port]` exact is representable (it simply matches only that literal string) rather than deferred; only an empty/whitespace-only or over-budget exact is non-translatable — deferred by the K8s translator and rejected fail-closed at slice validation on the native/file source, which runs the SAME `plugins::cors` admission predicates. The legacy `allowOrigin` string list shares the same exact-origin gate, and `allowMethods`/`allowHeaders`/`exposeHeaders` entries must pass the plugin's method/header-name admission — an invalid token defers the policy (K8s) or rejects the slice (native/file) instead of failing `cors` plugin construction on the data plane; carried hosts are normalized (trim, trailing-dot strip, ASCII-lowercase) by `MeshConfig::normalize()` on the config sources AND again as the synthesis match key, so a slice arriving over the native/xDS carriers matches its service without config-source normalization), and the client sidecar synthesizes the `cors` plugin onto its materialized outbound routes from it (issue #1973). Only sidecar-applicable routes are carried, resolved PER `http[]` ENTRY: Istio's `match[].gateways` OVERRIDE the top-level `spec.gateways` list, so a match naming the reserved `mesh` gateway applies to sidecars even under an ingress-only VS, a match naming only non-mesh gateways is skipped even under a mesh-bound VS (skipped entries neither donate nor suppress the carried policy), and a match without `gateways` — or an entry with no `match` — inherits the VS-level scope (`spec.gateways` omitted or containing `mesh`). Synthesis is client-**Sidecar**-topology-only; uncredentialed exact `*` is carried as Istio allow-all, noncanonical and wildcard-shaped exacts such as `*.example.com` are carried as literal matchers, and credentialed exact `*` remains non-translatable and defers, and `spec.exportTo` visibility is honored by slice narrowing with ServiceEntry semantics (an omitted exportTo is carried as an explicit `["*"]`; an EMPTY `export_to` on the native/file source is namespace-local by Ferrum convention).
- **Per-rule fault percentages are not RTDS-tunable** — the GAP-3E RTDS fault keys apply only to `fault_injection` plugin instances with `runtime_overlay_scope`, not to per-route VS faults.

### mTLS / HBONE operator cautions

- **PERMISSIVE with no client CA degrades to no-auth (non-egress topologies)** — if `PeerAuthentication` resolves to `PERMISSIVE` but neither `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` nor gateway SVID material is configured, client certificates are **not requested or verified** (logged at startup as a `warn!`; resolved through the explicit `PermissiveNoTrustAnchor` decision in `resolve_mesh_inbound_client_auth`). The listener admits unauthenticated peers and no peer SPIFFE identity is recorded. Configure a client CA or SVID material, or use STRICT, when you need PERMISSIVE to actually capture identity. **This degradation does NOT apply to the EgressGateway topology**: there a present trust anchor escalates PERMISSIVE to require a client cert, and a missing trust anchor fails the listener closed (the egress boundary must authenticate every client) — see "EgressGateway requires client certificates" in the listener-wiring section.

### Federation / multi-cluster

- **Live two-CP discovery round trip is verified in-process; the cross-cluster DATAPATH is now verified across two real clusters** — the gRPC dialer is covered by an in-process loopback round trip against a real `MeshSubscribe` server, and `tests/k8s/multicluster-federation/` (workflow `.github/workflows/multicluster-federation-live.yml`) stands up two SPIRE-federated kind clusters (per-cluster trust domains, manual bundle exchange) and proves BIDIRECTIONAL authenticated cross-cluster east-west traffic over Sidecar mesh-mTLS (A→B and B→A both `200 svc-<dest>`) plus a destination-side MeshPolicy denial of a federated rogue (`403`), gated on `multicluster.*` live assertions. The dedicated live workflow runs that fixture on every relevant PR and every `main` push (issue #2459) and is the authoritative datapath/release gate; the fixture itself fails closed when any required `multicluster.*` assertion is missing, failed, or skipped, the workflow's `gate` job then re-validates the emitted `live-assertions.json` artifact (exact schema/suite/commit/platform profile, freshness, no duplicates, exactly the required id set, every required id `pass`), and the hosted conformance suite pins both required sets to the enforced `multicluster-federation` rows of `tests/conformance/ga_contract.yaml`. The legacy `FERRUM_MULTICLUSTER_DEPLOY_ONLY=1` CI job remains a distinct packaging-and-rollout smoke and does not satisfy that live gate. The same fixture also injects two Stage-3 failure scenarios (gated): peer-trust revocation (drop the federated bundle from the dest slice + reload → A→B fails closed → restore → recover) and dest endpoint black-hole (scale `svc` to 0 → A→B fails fast → scale up + re-render gateway → recover). Network-partition / last-good retention is deferred — it is a federation/remote-discovery POLLER property, which this static file-config fixture does not run (a separate poller-driven fixture is required). See [Cross-Cluster Endpoint Discovery](#cross-cluster-endpoint-discovery).

## Failure-Mode Runbook

Where to look, and what to expect, when the mesh data plane misbehaves. All slice state lives in an `ArcSwap<Option<MeshSlice>>` (lock-free hot-swap); in-flight requests always see a complete old-or-new slice, never a partial one.

| Symptom | What happens | Where to look / what to do |
|---|---|---|
| **CP unreachable at startup** | `wait_for_initial_mesh_config` blocks (via `wait_for_first_slice`) until the first valid slice arrives — the DP does not serve traffic with an empty/unprotected config. The native/xDS client retries with jittered exponential backoff (1s → 30s, ±25%) across all `FERRUM_DP_CP_GRPC_URLS`. | Confirm `FERRUM_DP_CP_GRPC_URLS`, the `FERRUM_CP_DP_GRPC_JWT_SECRET`, and DP↔CP TLS. Startup logs show the connection/backoff attempts. The DP stays NotReady until converged. |
| **CP goes down after startup** | The last-good slice is retained (ArcSwap snapshot keeps serving). No new slices arrive; the client backs off and reconnects. | `GET /mesh/config-drift` shows `slice.last_received_at` / `age_seconds` going stale; alert on `ferrum_mesh_config_last_received_timestamp_seconds`. **SVID interaction:** while disconnected, SVID rotation still proceeds via the CA backend (SPIRE Agent / internal); the federation poller and CP-pushed trust bundles do not update, so a *new* federated trust domain will not appear until the CP returns. Existing identities and bundles remain valid until their own TTLs expire. |
| **Slice rejected (invalid update)** | The update is logged (`Ignoring invalid mesh slice update` / `Ignoring invalid initial mesh slice`) and dropped; the last accepted slice keeps serving. A rejected slice never advances `config-drift` `last_received_at`/fingerprint and never alters inbound trust (staged SPIFFE bundle is dropped on rejection). Over xDS, a malformed mesh-slice carrier causes the DP to NACK the whole ECDS response and retain the previous slice. | Search logs for `Ignoring invalid` and the `mesh_slice_version` + `error`. Compare `slice.fingerprint` across DPs via `GET /mesh/config-drift` to spot split-brain. |
| **eBPF capture unavailable** | The node-agent probes kernel ≥ 5.7 + cgroup v2 + bpffs once at startup. On a miss it sets `ferrum_mesh_node_topology_degraded{reason}` to `1` (reason ∈ `kernel_too_old` / `cgroup_v1` / `bpffs_missing`) and, with the default `FERRUM_NODE_AGENT_FALLBACK_MODE=fail`, refuses to start. `=iptables` falls back to host iptables capture (needs a custom image with `/bin/sh` + `iptables`). On a build without `--features ebpf`, the orig-dst bridge logs once and exits and node-waypoint accept fails closed. | Alert on `ferrum_mesh_node_topology_degraded == 1` and node-agent readiness. See [Node Agent Mode](#node-agent-mode) and [docs/node_agent.md](node_agent.md#kernel-fallback) for the per-reason remediation table. The rest of the data plane (slice apply, `mesh_authz`, `workload_metrics`, HBONE) is unaffected by node-level capture degradation. |
| **Requests denied unexpectedly** | `mesh_authz` evaluated DENY-first then implicit-deny-on-no-ALLOW-match. | `GET /mesh/policy-denies/recent` (JWT) groups recent denies by `(rule, source, destination, reason)`; correlate with `ferrum_mesh_requests_total{response_code="403"}`. Transaction logs carry `mesh_authz.deny_policy` (e.g. `untrusted_assertor`, `trust_domain_mismatch`, `unauthenticated_baggage`) and `mesh_authz.scope_missing` (node-waypoint per-pod scope not yet enrolled). |
| **mTLS / HBONE handshake failures** | Peer cert chain or SPIFFE trust-domain validation failed, or a plaintext peer hit a STRICT listener. | `ferrum_mesh_mtls_handshake_failures_total{reason}` (`timeout` / `error`) for mesh-wide TLS. On NodeWaypoint also `ferrum_mesh_node_waypoint_hbone_handshakes_total{phase,result}` (phased inbound_tls / inbound_connect / outbound_dial; see `docs/plans/node_waypoint_transport_adr.md`). Check that gateway SVID material (`FERRUM_GATEWAY_SVID_*`) and the slice trust bundles cover the peer's trust domain; for HBONE baggage rewrites, confirm the assertor is on `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS`. Remember PERMISSIVE-with-no-client-CA admits unauthenticated peers (see [Limitations](#limitations-and-not-supported)). |
| **Cert / CA health** | SVID rotation or CA backend problems. | `ferrum_mesh_cert_expiry_seconds`, `ferrum_mesh_cert_rotation_failures_total`, `ferrum_mesh_ca_health{ca_type}`, `ferrum_mesh_trust_bundle_version`. |

## Observability and Troubleshooting Quick Reference

### Admin introspection endpoints (all JWT-authenticated; 404 outside mesh mode / wrong topology)

| Endpoint | Purpose | Diagnose |
|---|---|---|
| `GET /mesh/config-drift` (`?include_overlay=false`) | Per-DP "where is this DP vs the CP's last push" — `slice.last_received_at`, `version`, per-kind `resources` counts, `fingerprint`, `source_protocol`/`source_cp_url`, RTDS `runtime_overlay`, and (xDS mode) the `convergence` block (per-type versions, missing required types). | Stuck DP (stale `last_received_at`), split-brain (fingerprint divergence), cross-cluster endpoint discovery (workload/service resource counts), RTDS drift, wedged xDS warming (non-empty `convergence.missing_required_types`). |
| `GET /mesh/federation` | Trust-bundle federation snapshot: per-trust-domain `bundle_age_seconds` + authority counts. | Stale / missing federated bundles for cross-cluster mTLS. |
| `GET /mesh/remote-clusters` | Multicluster east-west discovery: `discovered` remote clusters (per-cluster workload/service counts + fetch age) and the `configured` remote clusters from the accepted slice (each with a `discovered` flag). | Which remote cluster is contributing endpoints; configured-but-unreachable clusters (`configured` present, `discovered: false`). |
| `GET /mesh/runtime-overlay` | Live RTDS overlay (fault percentages, transformer gates, log level). | RTDS knob propagation. |
| `GET /mesh/service-graph` | Node-local source/destination edge graph from `workload_metrics`. | Who is talking to whom (per DP; aggregate in the backend). |
| `GET /mesh/policy-denies/recent` (`?window=`, `?limit=`) | Aggregated recent `mesh_authz` denies grouped by `(rule, source, destination, reason)`. | Misconfigured `AuthorizationPolicy` / unexpected denies. |
| `GET /mesh/egress-scope` + `POST /mesh/egress-scope/test` | Resolved Sidecar egress scope: admitted/denied services + outbound-registry destinations; dry-run host/port check. | Sidecar egress narrowing before/after enabling enforcement. |
| `GET /node-waypoint/identities` (NodeWaypoint only) | Currently enrolled pod identities. | Node-waypoint enrollment / cookie resolution. |
| `GET /service-waypoint/services` (ServiceWaypoint only) | Services bound to this waypoint in the active slice. | GAMMA waypoint binding resolution. |

For remote-cluster discovery specifically, `GET /mesh/remote-clusters` names each remote cluster the DP has fetched endpoints from (and the remote clusters the accepted slice declares); `GET /mesh/config-drift` resource counts and the locality-aware LB behavior remain useful for the aggregate workload/service totals.

### Key metrics (`/metrics`, authenticated)

Scrapers must present a valid admin JWT or `FERRUM_METRICS_BEARER_TOKEN`, or
originate from `FERRUM_METRICS_ALLOWED_CIDRS`.

- RED: `ferrum_mesh_requests_total`, `ferrum_mesh_request_duration_ms` (carry SPIFFE identity + `connection_security_policy` labels).
- Config freshness: `ferrum_mesh_config_last_received_timestamp_seconds{namespace}`.
- Config ordering: `ferrum_mesh_config_revision_rejections_total{reason}` (`stale_revision` / `incomparable_authority` / `missing_revision` / `malformed_revision`) and `ferrum_mesh_config_revision_adoptions_total` — see [Authoritative Config Revisions And Stale-Fallback Rejection](#authoritative-config-revisions-and-stale-fallback-rejection). Fixed cardinality; the CP-supplied authority/sequence detail stays on the JWT-gated `GET /mesh/config-drift` `revision` block.
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

The inbound listener terminates mTLS from peer sidecars and forwards plaintext to the co-located application: for the **local** workload (identified by its SPIFFE identity, `FERRUM_MESH_WORKLOAD_SPIFFE_ID`), Ferrum materializes an inbound route per HTTP-family service port of each Service that both names the workload's service and lists the workload's SPIFFE id in its `workloads[]`, targeting `127.0.0.1:<appPort>`, so an mTLS-terminated request reaches the app after `mesh_authz` admission. The backend (container) port is resolved from the signals the slice carries — a shared port **name**, else an equal port **number**, else the workload's sole container port; a workload that declares no ports defaults to the service port. When a Service uses a numeric `targetPort` that differs from `port` across multiple unnamed container ports the backend is genuinely ambiguous (the model does not yet carry `targetPort` end-to-end), so the route is **skipped with a warning** rather than misrouted — name the ports consistently or supply an explicit proxy. If an explicit proxy already routes the same host/path (overlap evaluated with the same wildcard/catch-all semantics as listen-path validation), the operator's proxy wins. **Multi-port local services materialize one loopback sibling per HTTP-family service port**, disambiguated post-match by, in priority order: the inbound connection's captured original destination (a sidecar-less client's direct dial of the app port that the injector's iptables REDIRECTed to `:15006` — its port is the **container** port), then the request's explicit `Host`/`:authority` port (the **service** port — peer-sidecar `:15006` dials are direct and never NATed, so the authority is the channel a multi-port-aware egress sidecar controls; see the egress bullet below). A multi-port request carrying neither signal — or a signal matching no materialized sibling — is rejected 502, never guessed onto one port's backend; single-port services accept bare-Host clients and older peers exactly as before. Stream-family local service ports (`tcp`, `tls`, and DB protocols) prepare a runtime-only raw-TCP inbound map keyed by the captured original-destination app port; when the effective PeerAuthentication mode admits plaintext and iptables REDIRECT preserves `SO_ORIGINAL_DST`, the accept loop recognizes the stream-family route before HTTP/TLS classification and relays its bytes unchanged, including an application-level TLS ClientHello beginning with `0x16`. It then runs the L4 stream plugin chain (`mesh_authz` and the other `on_stream_connect` hooks) **with the captured app port as the authorization destination** and, only if not rejected, relays those bytes to `127.0.0.1:<appPort>` before Hyper parses the connection — so a `destination.port`-scoped `AuthorizationPolicy` DENY on a Redis/MySQL/etc. port is enforced just as it is for the materialized HTTP routes. The dual-wire one-byte TLS discriminator is therefore confined to HTTP-family inbound traffic; its residual `0x16` ambiguity is harmless for valid plaintext HTTP because no valid HTTP request starts with that control byte, while STRICT is still enforced after routing. A stream-family port that resolves to the **same** container port as an HTTP-family service port installs **no** raw-TCP entry: the HTTP inbound route wins, so the request is parsed and authorized on the HTTP path rather than spliced to loopback as raw bytes. Peer-sidecar raw-TCP traffic still arrives as a mesh-mTLS CONNECT and uses the transparent inbound relay. The outbound listener intercepts application-originated traffic (redirected by iptables or eBPF) and, on Ambient and Sidecar topologies, routes it through per-service egress routes materialized from the slice (see "Implementation status" below for the per-topology transport); multi-port services are disambiguated by the captured connection's original destination (`SO_ORIGINAL_DST`) on those materialized topologies.

**Implementation status — transport vs. materialization, per topology.** Transport (how a peer is reached on the wire) and materialization (turning the slice into routable proxies) are separate layers, and **the transport differs by topology**: **Ambient / Waypoint** speak HBONE (HTTP/2 CONNECT over mTLS, `:15008`); **Sidecar** speaks plain SVID-mTLS HTTP (`:15006`, no `:15008` listener). HBONE is *not* Sidecar's transport.

- **Ingress is handled for both.** Sidecar inbound builds materialized HTTP-family loopback routes (`:15006` → `127.0.0.1:<appPort>`) and prepares raw-TCP local app-port relay entries for stream-family service ports. Ambient/Waypoint inbound is **transparent** — an authenticated HBONE CONNECT that matches no route is relayed directly to its `:authority` (the original destination), so no route materialization is needed. The relay is guarded: the destination must be a local target — a loopback address on an application port declared by the slice, or an in-mesh workload address+port the slice declares — so an authenticated peer can never use the terminator as an open proxy to arbitrary hosts or undeclared localhost listeners, and a peerless CONNECT is rejected (403) before any dial. This transparent-relay path is **transport-agnostic** — gated on inbound direction + the H2 CONNECT shape, not on topology — so the Sidecar `:15006` listener also relays a **bare** authenticated H2 CONNECT (the raw-TCP egress destination side) through the very same guard, alongside its materialized HTTP loopback routes.
- **Egress is materialized for Ambient, Sidecar, and NodeWaypoint captured Service HTTP**, per topology posture: **Ambient outbound** builds per-service HBONE routes (a host-routed `/` proxy per in-mesh Service → `mesh.hbone`-tagged upstreams dialing the destination's `:15008`); **Sidecar outbound** builds per-service SVID-mTLS routes (`mesh.mtls`-tagged upstreams dialing the destination sidecar's inbound `:15006` with plain HTTP/2 over mutual TLS — never HBONE). Those two secured-transport target types carry the destination workload's SPIFFE id (`mesh.spiffe_id`), which the outbound handshake **pins**: the peer must present exactly that SVID, not merely one from an allowed trust domain. **NodeWaypoint captured Service HTTP** materializes the same host-routed Service routes, selects the backing workload first, and, when that workload has `node_waypoint` metadata, emits a `mesh.hbone` target that dials the destination NodeWaypoint while preserving the selected workload app address as the inner CONNECT authority. If the NodeWaypoint runtime is identity-backed (file SVID material or mesh CA backend), a selected workload without `node_waypoint` metadata is skipped so the route fails closed rather than dispatching plaintext. Only explicit no-CA/no-identity development runs retain the temporary plaintext captured-Service fallback. NodeWaypoint still does not synthesize pod-IP HBONE upstreams to backing pod IPs on `:15008`, where no listener is reachable; the live harness therefore requires captured Service traffic to enforce `AuthorizationPolicy` and requires denied-source direct Pod-IP attempts to fail closed rather than bypass capture. Sidecar egress yields to the local workload's own inbound loopback route (the route table holds one proxy per host+path), so a service's own-sidecar traffic stays local. Non-convention transport ports are configured with `FERRUM_MESH_EGRESS_HBONE_PORT` / `FERRUM_MESH_EGRESS_MTLS_PORT`.
  - **Multi-port egress (original-destination routing, Ambient and Sidecar).** One route + one upstream is materialized **per HTTP-family service port** (per-port upstreams keep load-balancer counters, hash rings, passive health, and pool keys isolated per app port). The route table groups a service's per-port siblings under one lowest-port representative — host tiers are (host, path)-keyed and every sibling shares its service's hosts + `/` — and the request path swaps in the sibling whose service port matches the connection's captured pre-NAT original destination, read once per accepted connection on the outbound capture listener via `SO_ORIGINAL_DST` (Linux netfilter; covers the injector's iptables REDIRECT capture). Sibling groups are derived from the prepared config's `mesh` block (each service's expected per-port route ids and **declared** HTTP-port count), never by parsing route ids. **Fail-closed:** a service *declaring* multiple HTTP-family ports with no captured original destination (non-Linux, direct dial, eBPF-rewritten capture) — even when only some ports materialized siblings — and any captured dial to a port the slice does not route are rejected with 502; captured traffic is never forwarded to a port the client did not dial. Single-HTTP-port services keep their orig-dst-free behavior, so direct dials and dev setups are unaffected. **Ambient** multi-port is transparent end-to-end (its inbound is the HBONE relay that dials the CONNECT authority's app port). **Sidecar** multi-port egress additionally rewrites the request `:authority` to `<host>:<service port>` (the per-port target carries its owning service port; the original client Host still rides `x-forwarded-host`): the destination sidecar's `:15006` dials are direct — never NATed — so the authority port is the channel its per-port **inbound** siblings disambiguate by. Single-port destinations keep the client authority byte-for-byte. Interop is fail-closed in both skew directions: a pre-disambiguation destination materialized nothing for multi-port services (404, never misrouted), and a pre-disambiguation source materialized no multi-port egress routes. Apps behind a multi-port Sidecar service observe `Host: <fqdn>:<port>`, and destination-side VirtualService `authority` exact-matchers should account for the explicit port.
  - **Raw-TCP egress (original-destination routing, Ambient and Sidecar).** Stream-family service ports (`tcp`, `tls`, and the DB protocols — anything not HTTP-family) materialize **per-port upstreams only**, no route proxies: a raw stream has no Host header to route by. Instead the accept loop on the outbound capture listener matches the captured original destination **strictly against `(service VIP, service port)`** — `MeshService.cluster_ips`, populated from `Service.spec.clusterIPs` by the Kubernetes translator (file-source operators set `cluster_ips` directly) — and relays the raw byte stream through an HTTP/2 CONNECT tunnel to the LB-selected workload's app port. The tunnel transport follows the topology (the upstream target carries exactly one transport tag): **Ambient** relays over the shared HBONE pool (dial the peer's `:15008`, capability-probe-gated); **Sidecar** relays over a **fresh mesh-mTLS H2 CONNECT tunnel** (dial the peer's `:15006`, one connection per captured stream — no capability registry, because a slice-declared sidecar peer speaks mesh-mTLS by construction). Either way the dial is identity-pinned (`mesh.spiffe_id`), and the destination's inbound relay is **transport-agnostic**: its terminator recognizes an authenticated H2 CONNECT — HBONE-marked on `:15008` or bare on `:15006` — and relays it to the CONNECT `:authority` via the same machinery, so no destination-side changes are involved. Port-number-only matching is deliberately unsupported: two services may share a port number, and a captured dial to a non-mesh destination must never be tunnelled into the mesh on a coincidence. A captured destination matching a declared pair whose upstream did not materialize is **closed** (never guessed); anything else falls through to the HTTP path unchanged. **Direct pod-IP / headless dials are also routed on these materialized topologies:** a client that resolved a **headless** service itself (or otherwise dials a backing **pod IP** directly) bypasses the VIP table, so a second strict index — keyed by `(backing workload IP, resolved target port)` — routes that captured original destination to a **single-target upstream pinned to that exact workload's identity** over the topology transport. It is consulted only when the VIP lookup misses, uses the same exact-match / fail-closed rules (a declared-but-unroutable workload pair is closed, never guessed), and is built from the same forward-derived source as the per-workload upstreams (each stream-family service port × backing local-cluster workload × workload address that parses as an IP; DNS-name addresses are skipped, and the container/target port resolves with the same `targetPort` rule as the VIP path). HTTP-family headless services already route by Host, so this closes the **raw-TCP-only** headless gap; a VIP-less service with no backing workload addresses is still unroutable (warned at materialization). Per-port `DestinationRule` LB algorithm and `localityLbSetting` apply to the TCP upstreams (VIP and per-workload alike) at selection time when all targets share a single port (the same pre-selection semantics as the HTTP path). Per-port `outlierDetection` thresholds and `maxEjectionPercent` caps are honored by stream target selection, but the consulted state differs by source: upstream-scoped active health checks apply across the shared upstream, while passive ejections are proxy-id scoped and are only consulted when recorded under the same synthesized raw-relay proxy id. Passive ejections recorded by a separate HTTP-family proxy on the same upstream do not automatically protect these raw relays. Outlier thresholds are still not recorded for the raw relay itself, since raw relay sessions carry no response status — see the note in the "DestinationRule" section. **UDP is now modeled as a distinct L4 transport** (`AppProtocol::Udp`): a `protocol: UDP` port — on a Kubernetes Service **or** an Istio `ServiceEntry` — partitions out of both HTTP-family routing and the raw-TCP stream lane (previously it was silently mis-classified as HTTP). The L4 `protocol: UDP` field **wins over any L7 `appProtocol`/port-name hint** (e.g. `appProtocol: http` or a name like `http3` on a UDP port still classifies as UDP — the hint describes what rides over the transport, not the transport itself). UDP egress does **not** ride this raw-TCP datapath (`SO_ORIGINAL_DST` REDIRECT does not apply to UDP); UDP uses a separate **TPROXY** capture model (see "UDP TPROXY capture" under Capture Modes) — capture-rule emission landed in F3 §3.3 **Stage 2**, the consuming listener in **Stage 3**, and **datagram-over-mesh egress in Stage 4** (dual-transport, mirroring raw-TCP egress). UDP egress materializes **per-port upstreams** (distinct `__mesh-out-upstream-*` id space → `__mesh-out-udp-upstream-*`) consulted via the route table's `mesh_udp_egress` `(VIP, UDP port)` index; a captured datagram is tunnelled over a `udp`-marked mesh CONNECT — **Ambient over HBONE (`:15008`), Sidecar over mesh-mTLS (`:15006`)** — and the destination unframes it into a local `UdpSocket` (see "UDP TPROXY capture"). Still **no route proxy** (datagrams carry no Host). Both topologies have a UDP source-capture producer: **Sidecar** via the injector's pod-netns TPROXY init rules feeding the current-netns listener, and **Ambient** via the per-pod-netns producer (`NetnsUdpCaptureManager`, #2013) that installs the UDP TPROXY rules + binds the transparent sockets INSIDE each enrolled pod's netns (the Ambient proxy runs outside the pod netns and the host-netns fallback emits no UDP rules). Ambient UDP capture stamps node-agent-attested pod UID + SPIFFE evidence inside the authenticated HBONE CONNECT; destination `mesh_authz` applies per-pod **source** scope only after the shared trusted-assertor/trust-domain gate and an exact live UID-to-SPIFFE match, otherwise it falls back to mesh-wide source scoping. Either way the `udp` CONNECT is evaluated against the **union** of the destination-scoped `AuthorizationPolicy` set that normal (non-UDP) inbound HBONE uses — the same namespace/selector policies protecting the destination workload, e.g. a DENY-all in the service namespace — **and** the source-scoped (or mesh-wide) policies, in a single deny-first evaluation, so a destination DENY/ALLOW still runs for UDP CONNECTs and cannot fall through to default-allow. The EgressGateway ServiceEntry materializer still explicitly **skips** UDP ports (external-UDP egress out of scope; a one-time deferred warning flags it), so no premature EgressGateway UDP listener is emitted.
    - **Cross-cluster L4 extension.** The identity-pinned statement above describes same-cluster targets. Cross-cluster raw-TCP and UDP targets deliberately remove the pod pin because the SNI gateway chooses the outer-hop terminator; they require the remote trust domain, per-port SNI, gateway dial endpoint, and real-pod CONNECT authority instead. Missing metadata fails closed.
  - **WebSocket egress (Ambient and Sidecar).** A WebSocket upgrade to an in-mesh `mesh.mtls`/`mesh.hbone`-tagged destination rides the topology's secured transport on a **fresh** mesh H2 connection instead of the pre-mesh plaintext/TLS dial that ignored the mesh tag. The two topologies use **different inbound primitives**, because Sidecar materializes inbound routes while Ambient/Waypoint do not:
    - **Sidecar (`mesh.mtls`)** speaks an **RFC 8441 Extended CONNECT** (`:method=CONNECT` + `:protocol=websocket`) over SVID-mTLS to the peer's `:15006`. The Extended CONNECT carries the forwardable WebSocket handshake headers (`Sec-WebSocket-Protocol`, etc.; the HTTP/1.1-only framing headers `Upgrade`/`Connection`/`Sec-WebSocket-Key`/`Sec-WebSocket-Version` and `Sec-WebSocket-Extensions` are not sent) plus the preserved client `:path`+query, and the resulting H2 stream body IS the raw WebSocket frame transport — there is no inner HTTP/1.1 upgrade handshake. The destination sidecar's `:15006` listener (`auto`, advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`) detects the Extended CONNECT WebSocket and bridges it to the local app over a plain HTTP/1.1 upgrade — the same machinery a client-originated WebSocket uses (a WebSocket Extended CONNECT carries `:protocol`, so it is never confused with the bare CONNECT byte-relay). A multi-port Sidecar destination's `:authority` is rewritten to the owning service port (`mesh.mtls_authority_port`) just like HTTP egress.
    - **Ambient / Waypoint (`mesh.hbone`)** opens a **bare HBONE CONNECT byte tunnel** (the same primitive raw-TCP egress uses) to the destination workload's app addr:port on the peer's `:15008`, then speaks the WebSocket as an **inner HTTP/1.1 upgrade THROUGH the tunnel**. Ambient/Waypoint materialize **no inbound routes**, and the transparent HBONE relay that handles a route-miss CONNECT is gated on a **bare** CONNECT (it requires the `:protocol` extension to be *absent*), so an Extended CONNECT carrying `:protocol=websocket` to `:15008` would 404 before any WebSocket handler runs. Routing the byte tunnel to the app addr:port lets the relay byte-copy the upgrade straight to the loopback app, which performs the WS handshake — **no destination-side change**. The SERVICE `:authority`+`:path` the app routes on ride the inner H1 `Host`/request-target (mirroring the HTTP HBONE relay, which forwards the client Host over the relay).
    - **Shared invariants (both):** identity is **pinned** (`mesh.spiffe_id`; mandatory for `mesh.mtls`, carried when present for `mesh.hbone`); the client's `:path`+query is preserved byte-for-byte so `ws://svc-b/ws?room=1` reaches the destination as `/ws?room=1` (not `/`). Each session uses its OWN H2 connection carrying exactly ONE CONNECT stream (1:1, dropped at session end — a proxied WebSocket is one dedicated backend connection bounded by `DestinationRule.maxConnections` via the same `BackendConnectionGuard` the direct WebSocket path holds; SVID rotation is automatic per fresh dial). **Fail-closed:** a `mesh.mtls`/`mesh.hbone` WebSocket target that cannot dispatch over its secured transport (missing gateway SVID, absent/invalid pinned peer, a Sidecar peer that never negotiated Extended CONNECT, or an Ambient relay/handshake failure) fails the upgrade — it is **never** dialed in plaintext.

  - Per-port `DestinationRule.trafficPolicy.portLevelSettings` authored on the service port are fanned out onto every distinct dial port of the owning per-port upstream, so a service whose `targetPort` differs from its `port` keeps its *per-port* DR settings — **including named `targetPort`s**, which the materializer resolves per workload (a named port may legitimately resolve to different container ports across workloads; the entry lands on each). The former named-`targetPort` residual is closed; the planned move to service-discovery-backed outbound upstreams was evaluated and rejected (runtime-resolved targets would break the Ambient HBONE capability gate and per-pod identity pinning without closing the residual, since dispatch keys overrides by the selected target's dial port either way).

An outbound `404` for an un-materialized destination means no route was built for it — not that mTLS/HBONE is unavailable. Both egress datapaths are exercised end-to-end (two gateways, captured request at A → mesh transport → backend behind B) by the `functional_mesh_*_egress_*` functional tests.

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

At accept time the proxy reads the Linux `SO_COOKIE` value and looks up the corresponding `FERRUM_ORIG_DST4` / `FERRUM_ORIG_DST6` capture record in the `NodeWaypointIdentityResolver`. The record carries the original destination, pod UID, and a stable hash of the workload SPIFFE ID. Those records are populated by the **orig-dst bridge** (`src/ebpf/orig_dst_bridge.rs`): the bridge opens the node-agent-pinned `FERRUM_ORIG_DST4/6` maps by path and mirrors each socket-cookie record into the resolver via `record_orig_dst4`/`record_orig_dst6`. **Accept-side bridge (GAP-2M, IPv4 + IPv6):** these records are keyed by the *source pod's connect-side* socket cookie, but at accept time the proxy resolves by the *accepted server-side* socket's `SO_COOKIE` — a different kernel socket with a different cookie (see the invariant in `src/socket_opts.rs`). The kernel `sock_ops` program bridges them: at active-established it re-keys the orig-dst record by `(netns cookie, connection tuple)` (`FERRUM_ORIG_DST_BY_TUPLE4` / `FERRUM_ORIG_DST_BY_TUPLE6`), and at passive-established it re-stamps that record under the accept-side cookie, so the resolver's cookie map is reachable from the accept path with no further proxy-side change. **IPv4 and IPv6** — the v6 `sock_ops` ctx address words (`local_ip6`/`remote_ip6`) are read element-by-element with verifier-safe volatile per-`u32` loads at explicit offsets (the same per-element technique `connect6` uses for the `bpf_sock_addr` v6 fields; a whole-`[u32;4]` ctx copy trips the verifier), so IPv6 (and the IPv6 half of dual-stack) node-waypoint accepts resolve too. The in-netns outbound capture manager now binds both pod-loopback families, so the same resolver path is live-gated for IPv4 and IPv6. Pod-identity enrollment is wired into the same path with no separate channel: slice apply installs a `workload_spiffe_hash`→SPIFFE index that `resolve_record` hash-joins against the eBPF-stamped `(pod_uid, hash)` to lazily enroll identities (re-validated against the current slice on every resolve). If two different SPIFFE IDs collide on the 64-bit truncated hash, the gate marks that hash unusable and both lazy enrollment and cached revalidation fail closed instead of choosing one identity arbitrarily. The `node-waypoint-ebpf-live` workflow validates this path for IPv4 and IPv6 on a live multi-pod datapath. The eBPF `connect4`/`connect6` hooks stamp each record's pod UID and SPIFFE hash from the per-cgroup `FERRUM_WORKLOAD_IDENTITY` map the node-agent writes at enrollment (see [docs/node_agent.md](node_agent.md#ebpf-build-and-capture-how-to-build-the-capture-image)). Unknown cookies, zero pod UIDs, missing workload hashes, missing pod identities, collided SPIFFE hashes, and SPIFFE-hash mismatches fail closed before TLS/HBONE processing. `/overload.node_waypoint_drops` reports per-reason counters for these fail-closed drops. On a build without `--features ebpf` the bridge logs once and exits and the resolver stays empty, so every node-waypoint accept fails closed.

**In-pod-netns outbound capture listeners.** The eBPF `connect4` and `connect6` hooks rewrite captured pod outbound connections to `127.0.0.1:15001` and `[::1]:15001` — but those are the **pod's** loopback addresses. Host/proxy network-namespace listeners can never receive those connections, so a host-only listener would leave node-waypoint outbound capture non-functional on a real multi-pod node: rewritten connections would be refused and scoped enforcement never engage. (The GAP-2M `sock_ops` cookie bridge also independently requires the accept socket to share the connecting pod's netns.) So in NodeWaypoint topology the mesh proxy opens dual-family listeners — bound to pod loopback (`127.0.0.1` and `[::1]`) on the port from `FERRUM_MESH_OUTBOUND_LISTEN_ADDR` (default port `15001`); if that port is `0`, capture is disabled and the manager does not start — **inside each enrolled pod's network namespace** (via `setns(CLONE_NEWNET)` on a dedicated thread; one listener per address family per pod netns, deduped by netns inode), so captured pod-loopback connections are accepted in the right namespace and the same-netns cookie bridge resolves the source pod identity. Pod discovery comes from a registry directory the node-agent publishes: `FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR` (default `/run/ferrum/node-waypoint-pods`) holds one file per enrolled pod (file name = pod UID, contents = line 1 pod cgroup path plus optional `ipv4=<pod-ip>` / `ipv6=<pod-ip>` lines from Kubernetes `status.podIPs`), written on enrollment and removed on teardown; the proxy's `NetnsCaptureManager` polls this directory, uses each family-specific pod IP as the matching listener's dynamic source override, and reconciles listeners (opening on add, closing on removal). Helm mounts this path as the same writable hostPath in the node-agent and ambient DaemonSets whenever `nodeAgent.proxyMode=node_waypoint`; a split container-local registry can make both pods Ready while no workload listener is attached. **Fail-closed listener startup:** because pod discovery and in-netns listener binds are asynchronous, a freshly enrolled pod can briefly have `connect4` or `connect6` rewriting to a pod-loopback port before the matching proxy listener exists. The node-agent still attaches both connect programs during enrollment, before marking the pod enrolled, so egress cannot bypass `mesh_authz`; early captured connects may be refused until the listener opens, but they fail closed. NodeWaypoint adds `::/0` to the capture include set so IPv6 destinations reach `connect6`; the legacy `ipv6_outbound_deny` capture-config flag stays clear for the normal dual-family path. The proxy writes `<registry_dir>/.ready/<pod_uid>` for the historical IPv4 readiness marker, `<registry_dir>/.ready4/<pod_uid>` for IPv4 readiness, and `<registry_dir>/.ready6/<pod_uid>` for IPv6 readiness; the dotdirs are ignored by the pod-discovery scan. The inbound `getpeername4`/`getpeername6` programs do not redirect and are still attached at enrollment. This path is Linux-only (`setns`, `/proc/<pid>/ns/net`); on non-Linux it compiles to an unsupported stub. The reconcile/registry logic is unit-tested, and the `node-waypoint-ebpf-live` workflow gates the live `setns`/bind path and full pod-loopback IPv4/IPv6 datapaths on a disposable multi-pod kind cluster.

Operators inspect the currently enrolled pod identities via the JWT-authenticated admin endpoint `GET /node-waypoint/identities` — see [docs/admin_api.md](admin_api.md#node-waypoint-identities-mesh-nodewaypoint-topology) for the response shape. The endpoint returns 404 outside `NodeWaypoint` topology so unrelated DPs don't surface an empty stub list.

Per-pod authorization scope is published only after a mesh slice is accepted by the proxy config apply path. Slice apply installs one `NodeWaypointSlice` generation — the `workload_spiffe_hash`→SPIFFE identity gate plus the per-pod-UID scope index (`scopes_by_pod_uid`, a `PolicyScopeCache` per workload `metadata.uid`) — via a single `ArcSwap` store, so a lock-free reader never sees a new gate paired with an old or missing scope. A pod's scope is keyed **strictly** by the exact pod UID the eBPF capture stamps; a captured pod is **never** resolved through a SPIFFE-keyed index, so pods that share a service account — and therefore one SPIFFE — but carry different labels are scoped independently (each against its own labels) instead of collapsed to the label intersection, and a pod whose workload is absent from the live slice **fails closed** (no scope) rather than borrowing a same-SPIFFE workload's labels. Scope is reclaimed by slice updates, not by identity lifecycle. `resolve_*` returns the identity and its scope from a single load. Because the snapshot is stored only after `proxy_state.update_config` accepts the slice, a rejected slice never publishes scopes.

**TCP stream scoping**: raw **TCP** stream connections through a node-waypoint proxy follow the same per-pod scoping wiring as HTTP/HBONE. The TCP stream accept loop resolves each accepted connection's `SO_COOKIE` through the shared `NodeWaypointIdentityResolver`, looks up that pod's `PolicyScopeCache`, and stamps it onto the connection context so namespace-scoped and selector-scoped `AuthorizationPolicy` DENY/ALLOW rules are enforced for the correct source pod. The **same GAP-2M bridge described above for HBONE applies here**, for **IPv4 and IPv6**: the kernel `sock_ops` program re-keys the connect-side orig-dst record under the accept-side cookie (the v6 path reads the ctx address words element-by-element with verifier-safe volatile loads into `FERRUM_ORIG_DST_BY_TUPLE6`), so the resolver (populated by the `orig-dst` bridge) is reachable from the accept path for both families. Unit/integration coverage validates policy-scoped TCP traffic; the `node-waypoint-ebpf-live` workflow collects live BPF evidence for IPv4 and IPv6 capture, verifies HTTP Service `AuthorizationPolicy` enforcement, and confirms denied-source direct Pod-IP attempts fail closed. On any tuple/byte-order mismatch no accept-side record is written and the stream resolves `None` (fail-closed, never misattributed). When the scope cannot be resolved (a GAP-2M tuple miss, no node-agent enrollment yet, non-Linux, unknown cookie, slice/identity race), `mesh_authz` falls back to its missing-scope behavior: with namespace- or selector-scoped policies configured it **fails closed** and rejects the stream (403); with only mesh-wide policies it evaluates mesh-wide normally. Either way, the transaction records `mesh_authz.scope_missing=true`.

**UDP/DTLS limitation**: **UDP and DTLS** stream connections through a node-waypoint proxy cannot be scoped per-pod. Per-pod scoping cannot be wired for UDP without a new capture path: node-waypoint identity is keyed by the per-connection TCP socket cookie that the eBPF `connect4`/`connect6` cgroup hooks stamp with the source pod, there are no UDP capture hooks, and a UDP stream proxy demultiplexes every client off one shared frontend socket that carries a single cookie — so there is no per-source-pod cookie to resolve. Because Ferrum cannot distinguish two source pods safely from UDP/DTLS metadata in this topology, slice preparation accepts enforcing namespace- or selector-scoped `AuthorizationPolicy` updates but disables NodeWaypoint UDP/DTLS service ports and UDP/DTLS proxies in the prepared config, making unsupported UDP/DTLS fail closed instead of retaining an older no-policy config. Mesh-wide policies still evaluate normally, and scoped `AUDIT`-only policies are non-enforcing and do not force suppression. TCP and HTTP/HBONE share the same per-pod scoping wiring for IPv4 and IPv6 capture; NodeWaypoint still remains Experimental, but production identity-profile coverage is now part of the live H2 gate rather than a UDP/DTLS blocker.

#### BPF SOCK_OPS observability (GAP-SC3)

The `__mesh_bpf_metrics` plugin is auto-injected on `NodeWaypoint` topology only and surfaces the TCP-layer counters published by the `BPF_PROG_TYPE_SOCK_OPS` program. The userspace consumer (`src/ebpf/event_consumer.rs::SockOpsConsumer`) drains the per-CPU ringbuf and increments a shared `BpfMetricsState`. Authenticated production `GET /metrics` appends that surface exactly once from the current plugin-cache generation's precomputed exporter (configured `prefix` preserved; absent from the scrape when the plugin is not in the published configuration). Metrics emitted (Prometheus text format):

- `ferrum_mesh_bpf_tcp_events_total{event="connect"|"accept_established"|"rst"|"fin_sent"|"fin_received"}` — per-TCP-event counts. Operators correlate `accept` vs `connect` rates to spot stuck pods or pre-handshake drops. `event="rst"` counts abnormal `ESTABLISHED→CLOSE` transitions; SOCK_OPS state callbacks cannot distinguish RST-sent from RST-received, so there is no directional `rst_sent` / `rst_received` pair.
- `ferrum_mesh_bpf_drops_total{reason="bypass_uid_hit"|"exclude_cidr_hit"|"not_in_include_cidr"|"exclude_port_hit"}` — how often each BPF capture-bypass decision fired. Produced by the `connect4`/`connect6` hooks (same ringbuf + dropped-counter contract as SOCK_OPS lifecycle events). Include-CIDR misses and `includeOutboundPorts` misses share `not_in_include_cidr`.
- `ferrum_mesh_bpf_srtt_microseconds`, `ferrum_mesh_bpf_syn_to_ack_microseconds` — TCP-layer latency **histograms** (Prometheus type `histogram`). Fixed inclusive `le` bucket upper bounds in microseconds: `100`, `250`, `500`, `1000`, `2500`, `5000`, `10000`, `25000`, `50000`, `100000`, `250000`, `500000`, `1000000`, `2500000`, `5000000`, plus `+Inf`. The historical `_sum` / `_count` series are preserved so operators can still derive means (`sum / count`) and use `histogram_quantile` for percentiles. Zero samples are ignored; a sample that would overflow the `u64` sum is dropped entirely. Cardinality is process-global (no per-flow labels). App-layer latency stays in `workload_metrics`. Accept-to-first-byte is **not** exported: SOCK_OPS has no first-inbound-data-byte callback, so a zero family would advertise an unsupported contract.
- `ferrum_mesh_bpf_ringbuf_overruns_total` + companion `ferrum_mesh_bpf_ringbuf_in_overrun_regime` gauge — ringbuf health. Non-zero overrun count means userspace fell behind and the kernel dropped events; raise `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES` or reduce event rate. Attaching (or re-attaching after node-agent pin rotation) to a stats map that already reports a nonzero dropped total seeds **one** overrun episode so pre-reattach loss is visible; cumulative userspace counters are preserved across pin generations. The consumer also logs one `warn!` per regime entry and one `info!` on recovery — no per-event spam.

**Process split**: the node-agent owns the BPF program lifecycle — it loads `ferrum_sock_ops` from the ELF, attaches it to the cgroup root, and pins the event ringbuf + per-CPU drop counter at `/sys/fs/bpf/ferrum/sock_ops_events` and `/sys/fs/bpf/ferrum/sock_ops_stats`. The mesh-proxy in `NodeWaypoint` topology opens those pinned maps by path, drives a `tokio::io::unix::AsyncFd` poll loop, and feeds decoded records through `SockOpsConsumer::handle_event` into the shared `Arc<BpfMetricsState>` that `__mesh_bpf_metrics` reads. There is no cross-process pointer sharing — the pinned-path contract is the entire IPC surface.

When the kernel-side program is not pinned (no node-agent on the host, kernel < 5.7, or a build without the `ebpf` feature), the consumer logs one info line at startup and exits; the plugin keeps emitting a stable Prometheus surface populated by zeros so dashboards do not break. The ringbuf size is sized at BPF load time by the node-agent from `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES` (default 4 MiB) — see [docs/configuration.md](configuration.md).

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

Sidecars route external traffic to the egress gateway over mTLS. The gateway terminates mTLS, evaluates authorization policies, and forwards to the external backend. Requires frontend TLS certificates and a client CA for mTLS verification.

## Configuration Consumption

Mesh mode consumes configuration via one of three sources, selected by `FERRUM_MESH_CONFIG_PROTOCOL`: two Control-Plane protocols (`native`, `xds`) and a localized file source (`file`).

### Native MeshSubscribe (default)

The Ferrum-native protocol uses the `MeshConfigSync.MeshSubscribe` gRPC streaming RPC defined in `proto/ferrum.proto`. The CP pushes complete `MeshSlice` JSON payloads whenever configuration changes. The mesh node sends its identity (node ID, namespace, SPIFFE ID, workload labels) in the subscribe request so the CP can filter resources by scope.

- **Multi-CP failover**: ordered list of CP URLs in `FERRUM_DP_CP_GRPC_URLS`. Jittered exponential backoff (1s initial, 30s max, +/-25% jitter) per URL. Primary retry interval configurable via `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`.
- **Authentication**: JWT HS256 in gRPC `authorization` metadata, using `FERRUM_CP_DP_GRPC_JWT_SECRET`. Native local `MeshSubscribe` tokens carry the fixed purpose audience `ferrum-mesh-subscribe:local`; the control plane requires it when `remote_discovery=false`. This is intentionally a breaking, fail-closed wire change: clients that predate the local audience are refused by new control planes, and new local clients are refused by old control planes whose non-discovery verifier accepts no audience. Upgrade native mesh clients and control planes together. Ordinary `ConfigSync` and xDS tokens remain audience-less and unchanged.
- **Transport security**: same TLS configuration as CP/DP mode (see [cp_dp_mode.md](cp_dp_mode.md)).
- **No-op suppression**: `MeshSlice::content_eq()` skips updates that do not change mesh-relevant fields (ignoring the transport version stamp).
- **Response binding (fail-closed)**: every non-heartbeat `MeshConfigUpdate` is validated against the exact subscription request **before** it can reach `install_slice`. The envelope `version` must equal the embedded `MeshSlice.version`; the slice's `node_id` and `namespace` must equal the ones the data plane subscribed with; when the request pins a workload SPIFFE ID or a waypoint name, the slice must echo that same value (an *omitted* echo is a mismatch, not a skipped check — otherwise a response could bypass the scope gate by dropping the field); and `ferrum_version` must be present and major/minor-compatible. A rejected response never mutates state: the last accepted slice keeps serving. A response that is not bound to this subscription (wrong node/namespace/scope, or an incompatible control-plane version) additionally **drops the stream** so multi-CP failover moves to the next control plane, while a content-level fault (unparseable slice JSON, envelope/slice version disagreement) drops only that frame and keeps the stream open. Heartbeats carry no slice and are checked only against the version contract. Rejections increment `ferrum_mesh_config_update_rejections_total{consumer,reason}` and emit a structured `warn!` whose control-plane-supplied values are length-bounded and control-character-stripped. The same rules gate [cross-cluster endpoint discovery](#cross-cluster-endpoint-discovery).
- **Config message size**: native `MeshSubscribe` (including cross-cluster remote-discovery fetches) and xDS ADS clients accept inbound gRPC config messages up to 16 MiB. Larger control-plane responses fail closed and the last accepted slice keeps serving.
- **GA contract**: this transport is enrolled as `mesh.config_transport.native_subscribe` — semantics pinned by `tests/conformance/mesh_config_transport.rs` (namespace-scoped `MeshSlice` snapshot build, `content_eq` no-op suppression, fail-closed apply of malformed updates) and live-gated by the required `sidecar.config.native_subscribe_delivered` assertion from the `mesh-e2e-sidecar` CP + native-subscribe leg.

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

#### Ferrum mesh-slice ECDS carriers (full parity over xDS)

The name-only CDS/EDS/LDS/RDS resources Ferrum exchanges round-trip service-port discovery only. Every security- and policy-bearing slice field plus the effective workload labels used for selector matching — authorization policies, PeerAuthentication mTLS posture, RequestAuthentication/JWT rules, full ServiceEntry shape, SPIFFE trust bundles, ProxyConfig, per-pod workloads, MeshService protocol/workload-ref shape, telemetry resources, multi-cluster config, sidecar egress-scope metadata, and mesh-wide outbound traffic policy — rides the ECDS stream as a **Ferrum mesh-slice carrier**. Without these, `FERRUM_MESH_CONFIG_PROTOCOL=xds` produced an **unprotected mesh**: the DP rebuilt the slice with every one of those fields emptied or contextless (no authz → implicit allow-all; no PeerAuthentication → Permissive on every port; no trust bundles → no inbound mTLS authority material; no effective labels → selector-scoped policy stops matching).

This is the same mechanism as the [DestinationRule carrier](#ecds-destinationrule-carrier-full-dr-semantics-over-xds): each non-empty slice field group is JSON-serialized and wrapped in a standard `envoy.config.core.v3.TypedExtensionConfig` whose **inner** `type_url` is a Ferrum-specific marker under `type.googleapis.com/ferrum.config.extension.v3.*`. The single source of truth for the markers and their encode/decode is `src/xds/carrier.rs` (`MeshSliceCarrier`); the CP emits them in `translate_mesh_slice_carriers` (`src/xds/translator.rs`) and the DP decodes them in `reverse_translate` (`src/modes/mesh/config_consumer/xds_client.rs`).

| Slice field | Inner `type_url` (suffix after `type.googleapis.com/ferrum.config.extension.v3.`) | ECDS resource name |
| --- | --- | --- |
| `services` (full `MeshService`) | `ServicesCarrier` | `ferrum-mesh-carrier/services` |
| `workloads` (per-pod endpoints) | `WorkloadsCarrier` | `ferrum-mesh-carrier/workloads` |
| `labels` (effective workload labels) | `WorkloadLabelsCarrier` | `ferrum-mesh-carrier/workload-labels` |
| `labels_ambiguous` (shared-SPIFFE intersection marker) | `WorkloadLabelsAmbiguousCarrier` | `ferrum-mesh-carrier/workload-labels-ambiguous` |
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

**Behavior and fail-closed.** The CP always emits these alongside CDS/EDS (no env var gate), and the DP waits for the initial ECDS response before building a slice so startup cannot briefly apply the name-only, unprotected view. On the DP, a mesh-slice carrier must have both the reserved ECDS resource name and the matching inner `type_url`: a recognized pair overwrites the corresponding slice field; an unrecognized inner type (the DR carrier, or an operator's own extension config) is skipped; a reserved inner type under any other resource name is `warn!`-logged and skipped so operator-defined ECDS configs cannot impersonate security/policy carriers. A recognized carrier whose JSON fails to parse is FAIL-CLOSED: `MeshSliceCarrier::decode` returns `Err`, `recover_slice_carriers` propagates it, and the DP NACKs the entire ECDS response and retains the previous accepted slice — it does NOT skip the malformed carrier and continue with a partially populated slice. CDS/EDS service-port discovery still runs; the DP **prefers** the full `services`/`service_entries` recovered from carriers and falls back to the name-only CDS/EDS reconstruction only when no slice carrier is present at all (e.g. an internal Ferrum-shaped test CP with no carrier support). Empty `Vec`/`None` field groups emit no carrier, so "absent" and "empty" are indistinguishable on the DP — matching native, where an empty list and an absent list are equivalent. Effective workload labels are the exception: the CP emits `WorkloadLabelsCarrier` even when the label map is empty, because empty labels are meaningful selector context and must override any local DP labels during xDS recovery. **Ambiguous shared-SPIFFE labels are a counter-exception:** when several workloads share one SPIFFE id with **divergent** label sets and the slice request carried no explicit labels, the CP can only compute the label **intersection** (which loses information), while selector-scoped policies (authz / PeerAuthentication / RequestAuthentication / Telemetry) ride in as a **candidate-any superset** (kept if they match *any* candidate). The CP flags this by emitting `WorkloadLabelsAmbiguousCarrier`. (The common replica/endpoints case — many records for one SPIFFE with **identical** labels — is *not* flagged: the intersection equals each set and is authoritative, so the DP keeps trusting the carrier instead of preferring possibly-stale local labels.) On recovery the DP treats a flagged intersection as **non-authoritative** and prefers its own `FERRUM_MESH_WORKLOAD_LABELS` so it re-filters the superset against its real identity. Without this, a non-empty intersection (e.g. two pods sharing `app=shared` where only one has `role=api`) would replace the DP's real labels and silently drop every candidate-only selector policy — a fail-open for selector mTLS/JWT/authz whenever the intersection is non-empty. If the DP has no local labels either, it keeps the (informational) intersection. The marker is cleared on the recovered slice once the DP has resolved its authoritative labels. Operator-defined `MeshExtensionConfig` entries whose names start with `ferrum-mesh-carrier/` or whose inner `type_url` is one of the mesh-slice carrier markers are skipped by the Ferrum CP for the same reason.

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

### Localized file source (no control plane)

`FERRUM_MESH_CONFIG_PROTOCOL=file` runs a mesh data plane with **no control plane at all** — the slice is built locally from a YAML/JSON document at `FERRUM_MESH_FILE_CONFIG_PATH`. This mirrors the gateway's database-vs-file duality for the mesh (cf. Kuma's universal mode): the same `MeshSlice::from_gateway_config` materialization the CP runs is executed DP-side, so authz / PeerAuthentication / JWT / ServiceEntry / DestinationRule / trust-bundle semantics are structurally identical to a CP-delivered slice.

- **Document shape**: an optional `version` stamp (must equal the current config schema version when present) plus the `mesh` section only — `workloads`, `services`, `mesh_policies`, `peer_authentications`, `service_entries`, `request_authentications`, `telemetry_resources`, `destination_rules`, `proxy_configs`, `sidecars`, `trust_bundles`, `multi_cluster`, `outbound_traffic_policy`. Gateway resources (`proxies:`, `upstreams:`, `consumers:`, `plugin_configs:`) are **rejected** at parse — mesh mode materializes its routes from the slice; plain gateway routes belong to `FERRUM_MODE=file`.
- **Startup is fail-closed**: a missing, unparsable, or mesh-invalid document refuses startup, matching file-mode validation semantics.
- **Reload**: SIGHUP (Unix; `ferrum-edge reload`). A failed reload logs a warning and keeps the last good slice — identical to how the CP consumers retain the last accepted slice. Reload is signal-driven only; there is no file watcher or poll timer. Non-Unix platforms load once and require a restart.
- **Not required / not consumed**: `FERRUM_DP_CP_GRPC_URLS`, `FERRUM_CP_DP_GRPC_JWT_SECRET`, DP gRPC TLS vars. Everything else (topology, SVID material, PeerAuthentication posture, plugin injection, slice scoping via `FERRUM_MESH_WORKLOAD_SPIFFE_ID` / `FERRUM_MESH_WORKLOAD_LABELS` / Sidecar egress enforcement) behaves exactly as under native/xDS.
- **Observability caveat**: there is no CP heartbeat, so `/mesh/config-drift` slice staleness reflects time since the last SIGHUP reload rather than a sync failure.

### Bootstrap Behavior

All three config sources share the same startup contract:

1. The mesh data plane waits for an initial valid slice before serving traffic (the file source loads it synchronously and refuses startup on error).
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

Logical service grouping workloads by SPIFFE ID reference. `cluster_ips`
(optional) carries the service's virtual IPs — Kubernetes `spec.clusterIPs`,
populated automatically by the K8s translator — and is what raw-TCP egress
matches captured original destinations against (see the raw-TCP egress bullet
in the Sidecar/Ambient section); HTTP-family routing never consults it, and
headless services simply omit it.

```yaml
name: "my-service"
namespace: "default"
ports:
  - port: 8080
    protocol: http
workloads:
  - spiffe_id: "spiffe://cluster.local/ns/default/sa/my-service"
cluster_ips: ["10.96.0.10"]
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
| `trafficPolicy.loadBalancer.simple = PASSTHROUGH` | Supported (captured paths; warns) | → `LoadBalancerAlgorithm::Passthrough`: dials the captured original destination (`SO_ORIGINAL_DST`) when it matches a healthy pool target, else round-robin fallback |
| `trafficPolicy.loadBalancer.simple = MAGLEV` | Rejected | Hard error at translate time |
| `trafficPolicy.loadBalancer.consistentHash.{httpHeaderName,httpCookie.name,useSourceIp}` | Supported | Exactly one of the three required (rejected otherwise); → `LoadBalancerAlgorithm::ConsistentHashing` + `Upstream.hash_on` |
| `subsets[].name` / `subsets[].labels` | Supported | → `SubsetDefinition` entries on the upstream; second DR overwrites the first |
| `subsets[].trafficPolicy.loadBalancer` | Supported | → `SubsetTrafficPolicy.load_balancer_algorithm`; `consistentHash` also projects the subset `hash_on` key |
| `subsets[].trafficPolicy.tls` | Supported | → `SubsetTrafficPolicy.tls` (nests `MeshTrafficPolicyTls`). Cold-path `resolve_subset_traffic_policy_tls` layers the subset's TLS overlay (mode / SNI / CA / mTLS material / SAN allow-list / `insecureSkipVerify`) onto the upstream-level TLS and stores the result on `Upstream.resolved_subset_tls[subset_name]`. `GatewayConfig::resolve_upstream_tls` then projects that overlay onto `Proxy.resolved_tls` for proxies whose `upstream_subset` selects this subset — so v1 and v2 subsets with different CAs land on different `Proxy.resolved_tls` values and partition the backend pool. `upstream_subset` also enters HTTP / H2 / gRPC / H3 pool keys as a defense-in-depth backstop on top of TLS partitioning. Subsets without `trafficPolicy.tls` fall back to upstream-level TLS, identical to today's behavior. |
| `subsets[].trafficPolicy.connectionPool.tcp.connectTimeout` | Supported | Overrides `backend_connect_timeout_ms` for proxies bound to the subset (precedence over the DR top-level connectTimeout). Other per-subset `connectionPool` fields are still ignored (warns). |
| `subsets[].trafficPolicy.outlierDetection` | Supported | Ejection thresholds (consecutive errors / interval / base-ejection / min-health) AND the `maxEjectionPercent` cap applied per-subset, overriding upstream-level passive health for subset-bound proxies (`passive_health_for_target` for thresholds, `LoadBalancerCache::max_ejection_percent_resolved_from` for the cap, sharing one per-port > per-subset > upstream tier precedence). The cap is sized against the subset candidate pool (denominator = subset target count). The per-port cap tier applies only when a single dispatch port is resolvable pre-selection; for subset dispatch on a multi-port upstream the subset cap governs (the cap is resolved before a target's port is known). |
| `trafficPolicy.connectionPool.http.maxRequestsPerConnection` | Deferred | Parsed and validated, but not projected onto `Upstream.port_overrides` or `Proxy.pool_max_requests_per_connection` because Ferrum does not enforce backend close-after-N-requests behavior. K8s translation emits a warning and status lists `connectionPool.http.maxRequestsPerConnection` in `status.ferrum.translation.deferred_fields` at top-level, per-port, and subset scope. Negative and `> u32::MAX` values are rejected at translate time; `0` is accepted as Istio's explicit "unlimited" sentinel but still produces no effective policy. Use `http2MaxRequests` for HTTP/2-family concurrency. |
| `trafficPolicy.connectionPool.http.idleTimeout` | Supported (HTTP-family) | Lands on `Upstream.port_overrides[port].http_idle_timeout_ms` and projects onto `Proxy.pool_idle_timeout_seconds` for the per-target effective proxy, which threads into the reqwest/H2 client pool idle timeout. Sub-second durations are rejected at translate time because `pool_idle_timeout_seconds` is whole-second granular; values above `MAX_POOL_IDLE_TIMEOUT` (1 hour) are also rejected so the K8s surface stays consistent with the admin admit-path validator. Top-level fan-out applies to every target port; per-port `portLevelSettings` overrides per-port. The reqwest pool key includes idle timeout in its `rcfg` client-behavior segment, so divergent per-port idle timeouts isolate distinct shared clients (no first-creator-wins leak). Direct-H2 / gRPC still document first-materializer tradeoffs for builder-only knobs that are not in those keys. Request-only `backend_connect_timeout_ms` remains per-request and does not fragment. |
| `trafficPolicy.connectionPool.http.http2MaxRequests` | Supported (HTTP-family) | Lands on `Upstream.port_overrides[port].h2_max_concurrent_streams` and projects onto `Proxy.pool_http2_max_concurrent_streams` via the per-target effective proxy. Threads into the direct H2 (`src/proxy/http2_pool.rs`) and gRPC (`src/proxy/grpc_proxy.rs`) builders as both `http2::Builder::max_concurrent_streams` (peer SETTINGS) and `initial_max_send_streams` (local outbound-stream initial cap). Reqwest's H2 path does not expose the same builder knobs today. Top-level fan-out applies to every target port; per-port `portLevelSettings` overrides per-port. Zero/negative values rejected at translate time. Direct-H2 / gRPC pool keys exclude this builder-only cap (first-materializer tradeoff): two proxies that share `(host, port, TLS)` but configure different per-port H2 caps share the first connection materialised with the first proxy's cap — operators wanting strict per-proxy isolation fragment via `dns_override`. Reqwest does not consume this knob in `create_client`. |
| `trafficPolicy.connectionPool.http.h2UpgradePolicy` | Supported (plain-HTTPS only) | Lands on `Upstream.port_overrides[port].h2_upgrade_policy` and projects onto `Proxy.h2_upgrade_policy` via the per-target effective proxy. Consulted at the plain-HTTPS HTTP/1.1-vs-HTTP/2 dispatch fork (`should_dispatch_direct_h2` in `src/proxy/mod.rs`): `DO_NOT_UPGRADE` forces the reqwest/H1 path even when the backend capability registry classifies the target `h2_tls` Supported (the one exception is a backend-TLS SNI override, which still requires direct-H2 because reqwest cannot apply a per-request SNI — that case wins and is documented); `UPGRADE` prefers direct-H2 and treats an unclassified `Unknown` target as a hint to try H2 (fail-safe: a target proven `Unsupported` is never forced onto H2). `DO_NOT_UPGRADE` additionally restricts the reqwest client's advertised ALPN to `http/1.1` (the BuiltRustls/`use_preconfigured_tls` path uses the config's ALPN verbatim, so a TLS backend can no longer ALPN-negotiate h2) and carries a force-H1 discriminator in the reqwest pool key so it never shares a connection with the default h2-capable client. `DEFAULT` is represented as the explicit `H2UpgradePolicy::Default` variant (and absent is `None`); both are probe-driven at the dispatch fork, but `DEFAULT` is carried (not collapsed to `None`) so an EXPLICIT port-level `DEFAULT` can CLEAR an inherited top-level `UPGRADE`/`DO_NOT_UPGRADE` for that port. **Scope is strictly plain-HTTP h1-vs-h2** — it does NOT affect gRPC (always H2) or HBONE/mesh-mTLS transport selection. Top-level fan-out applies to every target port; per-port `portLevelSettings` overrides per-port (field-level merge — see the merge-semantics note below the table). Set inside a `subsets[].trafficPolicy` it is NOT applied (deferred + warned), because the subset apply path builds a `SubsetTrafficPolicy` that carries no `connectionPool.http`. Unknown enum values are rejected at translate time. |
| `trafficPolicy.connectionPool.http.maxRetries` | Supported (per-request CAP — honest reinterpretation) | **Semantics differ from Envoy on purpose.** Envoy's `connectionPool.http.maxRetries` is a cluster-wide *outstanding-retry concurrency budget*; Ferrum's retry model (`Proxy.retry`, per-request) has no such gauge, so Ferrum treats DR `maxRetries` as an **upper bound on the per-request retry count** — see [DestinationRule `maxRetries` semantics](#destinationrule-maxretries-semantics). Lands on `Upstream.port_overrides[port].max_retries` and is applied by `cap_proxy_retry_for_target` once the dispatch target port is known (before any HTTP/gRPC/WebSocket retry loop reads `proxy.retry`): if the proxy already has a retry policy the effective `max_retries` becomes `min(existing, maxRetries)` (never increased); if the proxy has NO retry policy this field does NOT enable retries (an Istio `maxRetries` is a budget, not a retry-policy enabler). Top-level fan-out applies to every target port; per-port `portLevelSettings` overrides per-port (field-level merge — see the merge-semantics note below the table). Set inside a `subsets[].trafficPolicy` it is NOT applied (deferred + warned), because the subset apply path builds a `SubsetTrafficPolicy` that carries no `connectionPool.http`. Zero/negative values rejected at translate time. |
| `trafficPolicy.connectionPool.http.http1MaxPendingRequests` | Supported (honest reinterpretation — max concurrent in-flight HTTP/1.1 requests) | Lands on `Upstream.port_overrides[port].http1_max_pending_requests` and projects onto `Proxy.pool_http1_max_pending_requests` via the per-target effective proxy. **Semantics differ from Envoy on purpose** (like DR `maxRetries`): Envoy bounds the connection-pool *pending-queue* depth, but Ferrum dispatches H1 over reqwest, whose `send().await` resolves at **response headers** with **no connection-acquisition hook**, so true pending-queue depth is not measurable — Ferrum instead caps **concurrent in-flight H1 requests** per `(host, port)` (measured dispatch → response-headers). Enforced on the **reqwest/HTTP-1.1** backend-dispatch path (`proxy_to_backend` in `src/proxy/mod.rs`) via a sharded `CachePadded` atomic CAS-bumped alloc-free (`src/backend_pending_limit.rs`, like `backend_conn_limit`): a request that cannot acquire a slot is **shed with a 503** ("upstream overflow"), classified `dispatch_policy_rejected`. Because the shed precedes any backend dial, it is a `client_side_no_backend_signal` — **neutral to backend health**: not retried, does not trip the backend circuit breaker / passive health, and does not shrink the adaptive-concurrency permit for a backend that was never dialed. The slot is acquired immediately before dispatch onto the shared reqwest client and released by an RAII guard the moment `send()` returns (response headers / dial failed), BEFORE response-body collection — so it spans the dispatch → response-headers in-flight window, NOT the response-stream lifetime. The gate is consulted only for dispatch **known HTTP/1.1 at acquire time** (`reqwest_dispatch_is_http1_only`): a `DO_NOT_UPGRADE` proxy, a **plaintext `http`** backend (reqwest never speaks h2c over cleartext), or an **HTTPS backend the capability registry has already classified H2-unsupported (H1-only)** (where the direct-H2 pool is bypassed onto reqwest-H1); an HTTPS backend that may still ALPN-negotiate h2 is left **uncapped** (an `http1*` knob must not 503 an h2 backend — that is `http2MaxRequests`'s job). Under the in-flight framing there is **no body-shape exclusion** — bodyless GET/HEAD and streamed-upload requests are capped alike. **HTTP/1.1-scoped by design**: the direct-H2 / gRPC / HTTP/3 / HBONE / mesh-mTLS branches return before the reqwest path, so the multiplexed transports never consult the gate (`http2MaxRequests` → `h2_max_concurrent_streams` governs their concurrency). The connection-failure retry path (`proxy_to_backend_retry`) **re-enters the same gate per attempt** under the same H1 predicate (the initial attempt's slot is released before the retry loop runs), so `retry_on_connect_failure` retries are bounded too and an attempt never double-counts. Top-level fan-out applies to every target port; per-port `portLevelSettings` overrides per-port. Set inside a `subsets[].trafficPolicy` it is NOT applied (deferred + warned), because the subset apply path builds a `SubsetTrafficPolicy` that carries no `connectionPool.http`. Zero is rejected at translate time, and the native/file mesh-config `MeshConfig::validate()` path applies the same positive-value check (`Some(0)` would shed every H1 request to the destination). |
| `trafficPolicy.connectionPool.tcp.maxConnections` | Supported (stream-family + HTTP-family WebSocket) | Cap on concurrent open backend connections per target, enforced via a per-`(host, port)` CAS-bumped counter on `Upstream.port_overrides[port].max_connections`. **Stream-family** (TCP / TCP+TLS / TCP-passthrough) enforces it at backend dial; exceeding the cap returns a typed `StreamSetupKind::BackendMaxConnectionsExceeded` (logged as `Backend maxConnections reached`) and the relay retry loop tries another LB target if `RetryConfig.retry_on_connect_failure` is enabled. **HTTP-family WebSocket** (H1/H2 in `src/proxy/mod.rs` and H3 in `src/http3/websocket.rs`) also enforces it: a proxied WebSocket opens one dedicated backend connection whose lifetime equals the session, so an RAII guard (`src/backend_conn_limit.rs::BackendConnectionGuard`) held on `ProxyState.backend_conn_limit` for the session bounds concurrent open connections per destination; exceeding the cap rejects the upgrade with `503` (`rejection_phase=backend_max_connections`) before dialing, and a closed/failed session releases its slot (no leak). The pooled, multiplexed HTTP transports (reqwest H1/H2, direct H2, gRPC, HTTP/3, HBONE) do **not** enforce the field — see the "DestinationRule `maxConnections` enforcement scope" note below for why. Top-level fan-out applies to every target port; per-port `portLevelSettings.connectionPool.tcp.maxConnections` overrides the fan-out for that specific port. `maxConnections <= 0` is rejected at translate time. |
| `trafficPolicy.connectionPool.tcp.tcpKeepalive` (`time` / `interval` / `probes`) | Supported for stream-family AND HTTP-family multiplexed pools (direct-H2, gRPC, HBONE, mesh-mTLS); reqwest-backed HTTP and H3/QUIC are documented residuals (shared-client / non-TCP transport) | Each subfield independently optional. Applied via `setsockopt(SO_KEEPALIVE)` + `TCP_KEEPIDLE` (Linux) / `TCP_KEEPALIVE` (macOS/iOS) for `time`, `TCP_KEEPINTVL` for `interval`, `TCP_KEEPCNT` for `probes`. Set on the backend socket right after `connect()` (stream-family: TCP / TCP+TLS / TCP-passthrough; HTTP-family: the socket-owning H2-family pools resolve the same per-port override at connection creation via the shared `socket_opts::apply_pooled_tcp_keepalive` — direct-H2 `http2_pool` and `grpc_proxy` key it by the dial target's `backend_port`; the HBONE pool and the Sidecar mesh-mTLS pool key it by the destination's **app/service port** and apply it inside the shared `dial_h2_connect_sender` after dialing the transport port `:15008`/`:15006`, so it covers Ambient HBONE egress, Sidecar mesh-mTLS egress, raw-TCP egress over both transports, AND WebSocket-over-HBONE/-mesh-mTLS which ride the same dialer). Best-effort: a `setsockopt` failure logs a `warn!` and continues rather than aborting the connection. The per-port DR override is **additive and takes precedence**; absent an override the global pool keepalive (`pool_config.tcp_keepalive_seconds`, whole-seconds idle time only, applied when `enable_http_keep_alive`) remains the fallback — so existing non-mesh behavior is unchanged. **First-materializer tradeoff (HTTP-family only):** keepalive is NOT part of the pool key (forbidden by the proxy-protocol rules — see `.claude/rules/proxy-protocols.md`), and these connections are pooled+shared, so the keepalive is fixed once at connection creation and the **first dispatcher to materialize a pooled connection wins**; later dispatchers that differ only in keepalive reuse the existing connection and inherit its setting — the same tradeoff already documented for `idleTimeout` / `maxRequestsPerConnection`. **Residuals:** the reqwest-backed HTTP pool (`src/connection_pool.rs`) applies `tcp_keepalive` at builder time (seconds-only) on a client SHARED across proxies that differ only in policy fields (keepalive is excluded from pool keys per the rules), so a clean per-proxy DR override is not possible there without another vendored reqwest patch — it keeps the global seconds-only keepalive (mesh egress never uses reqwest, so mesh coverage is complete; reqwest mainly serves non-mesh + localhost inbound where keepalive is moot). H3/QUIC (`src/http3/client.rs`) is UDP — `tcpKeepalive` is N/A (a QUIC keep-alive would be a separate `TransportConfig` knob). Sub-second durations and zero values are rejected at translate time because the underlying socket options are second-granular and require at least one probe. |
| `trafficPolicy.tls` | Supported | Overrides the `PeerAuthentication`-derived backend posture per matching `Upstream` when set. Mode mapping: `DISABLE` → clears `Upstream.backend_tls_*`; `SIMPLE` → enables server-cert verify + `backend_tls_server_ca_cert_path = caCertificates` (client cert/key cleared); `MUTUAL` → enables server-cert verify + projects `caCertificates`/`clientCertificate`/`privateKey` onto `Upstream.backend_tls_server_ca_cert_path`/`_client_cert_path`/`_client_key_path`; `ISTIO_MUTUAL` → enables server-cert verify + projects the workload SVID paths from `FERRUM_GATEWAY_SVID_CERT_PATH` / `FERRUM_GATEWAY_SVID_KEY_PATH` onto the upstream client cert/key fields, failing slice apply if either path is missing so stale/global client material is not used. `ISTIO_MUTUAL` projects **file-based** SVID paths for the outbound client cert, so when the mesh's only workload identity is a dynamic CA-backed SVID (`FERRUM_MESH_CA_BACKEND` with no `FERRUM_GATEWAY_SVID_*` files), `ISTIO_MUTUAL` on a generic backend / egress `ServiceEntry` upstream is intentionally **rejected (slice apply fails closed)** because the generic backend TLS path cannot present a dynamic SVID client cert — use file-based `FERRUM_GATEWAY_SVID_*` material, or an explicit `MUTUAL` policy with `clientCertificate` / `privateKey` paths, for those upstreams. Validated reloads of the `FERRUM_GATEWAY_SVID_*` files bump a generation in backend TLS and pool keys so new H2/gRPC/H3/HTTP connections rebuild client identity state without restarting; active HTTP health probes are restarted on each observed revision, and existing connections complete on their original config unless `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS` force-drains old-generation pool entries. `insecureSkipVerify: true` forces `backend_tls_verify_server_cert = false`. `sni` projects to `Upstream.backend_tls_sni`, onto `Proxy.resolved_tls`, into backend H2/gRPC/H3 TLS handshakes, and into the backend pool key so different SNI values never share connections. Plain HTTPS requests with an SNI override use the direct H2 backend pool instead of reqwest because reqwest cannot express per-request backend SNI overrides. `subjectAltNames` projects to `Upstream.backend_tls_san_allow_list`, onto `Proxy.resolved_tls`, into backend TLS verifier enforcement, and into the backend pool key so different allow-lists never share connections. If per-proxy or global no-verify is enabled, SAN allow-lists are not enforced and Ferrum logs a warning. When the field is unset, behavior is identical to today and `PeerAuthentication` continues to drive the default mTLS posture. |
| `trafficPolicy.portLevelSettings[].port.number` + nested `connectionPool.tcp.connectTimeout` | Supported | Top-level policy applies first; per-port `connectTimeout` lands on `Upstream.port_overrides[port].connect_timeout_ms` at apply time, then `GatewayConfig::resolve_dispatch_port_overrides()` projects it onto `Proxy.dispatch_port_overrides` for O(1) hot-path lookup. All four dispatch families consult it: HTTP/H2/H3 via `resolve_effective_proxy_for_target` (`src/proxy/mod.rs`), gRPC via the same helper threaded through `proxy_grpc_request*` (`src/proxy/grpc_proxy.rs`), TCP via `effective_backend_connect_timeout_ms` in `TcpConnParams` (`src/proxy/tcp_proxy.rs`), and HBONE via `effective_connect_timeout_ms` in `connect_backend` (`src/proxy/hbone_proxy.rs`). Ports outside 1-65535 rejected; duplicate port entries rejected; phantom ports (DR entry references a port unused by any `Upstream.target`) skipped with a warning at apply time. The admin API rejects POST/PUT setting `Upstream.port_overrides` directly — express per-port policy as a DestinationRule (SQL/MongoDB schemas don't persist the field) |
| `trafficPolicy.portLevelSettings[].loadBalancer` / `outlierDetection` | Supported for HTTP-family / gRPC / WebSocket / HBONE dispatch; LB algorithm, locality, and active/passive health also engaged for stream-family when all targets share a port | Per-port load-balancer algorithm/hash settings, passive outlier thresholds, and `localityLbSetting` (`distribute` / `failover` / `enabled`) land on `Upstream.port_overrides[port]`; the runtime builds isolated per-port LB counters/hash rings, per-port passive health, and per-port locality LB state. Dispatch on a port with an override consults the per-port locality preference first and falls back to the upstream-level `trafficPolicy.loadBalancer.localityLbSetting` when the per-port entry omits it. TCP/UDP/DTLS stream paths also engage the per-port **LB algorithm** and **`localityLbSetting`** when all upstream targets share a single port (`initial_dispatch_port_override` is non-zero); the lane engages only for selection-affecting overrides, per-port `consistentHash` on a stream lane requires a source-IP hash key, per-port `LEAST_CONN` is refused on the generic stream listeners (fail-closed typed setup error; mesh raw-TCP/UDP relays keep connection counts and select normally), and per-port `LEAST_LATENCY` is refused on every stream lane (no latency signal on raw relays) — see the stream-family bullet in [Limitations](#limitations-and-not-supported). Stream paths pass active/passive health context into selection, so per-port `outlierDetection` thresholds, existing passive ejections, active health state, and the `maxEjectionPercent` cap affect TCP/UDP/DTLS target selection. Outlier thresholds are still not recorded on stream paths because raw relay sessions carry no response status. Phantom ports are skipped with a warning at apply time. Migration note: operators who previously set these fields expecting warning-only behavior should audit them before upgrade because they now affect HTTP-family/gRPC/WebSocket/HBONE routing and ejection decisions. Example: a top-level `ROUND_ROBIN` policy with `portLevelSettings[8080].loadBalancer.simple=RANDOM` keeps non-8080 traffic on round-robin while 8080 dispatch uses its own random counter/ring; a per-port `localityLbSetting.distribute` on 8080 weights only port-8080 traffic and leaves other ports on the upstream-level locality preference. |
| `exportTo` | Ignored | DRs are scoped to their declared namespace at slice-filter time |

Translator warnings surface in the `K8sTranslation.warnings` returned from `translate_k8s_objects`, so operators see them at apply time.

DestinationRule `trafficPolicy.tls.sni` is enforced only on backend paths where Ferrum owns the TLS handshake: direct HTTP/2 for plain HTTPS, gRPC over H2, and native H3. Because reqwest cannot express a per-request backend SNI override, Ferrum rejects SNI-overridden plain HTTPS requests that cannot use the direct H2 backend pool (request-body replay for retries, request-body-buffering plugins, `pool_enable_http2: false`, or an H1-only backend) with `502` and a `gateway-error-reason: backend_tls_sni_requires_direct_h2` header instead of silently dropping the override. **Config admission** rejects those guaranteed-outage combinations (effective retry, request-body-buffering plugins, and `pool_enable_http2: false`) for proxy-level and DestinationRule per-port TLS SNI overlays so `ferrum-edge validate` fails closed before production. The buffering leg is derived from each plugin's own `Plugin::requires_request_body_buffering()` answer, computed from a plugin instance built out of the same parsed configuration the runtime plugin cache builds, so conditionally-buffering plugins (for example `compression` only with `decompress_request`, `waf` only with active request-body rules, `body_validator` only with request-side validation) are screened exactly and new buffering plugins are covered automatically. That construction is inert: it never starts background tasks, never publishes candidate state, and never touches node-local files or the network — `geo_restriction`, `oidc_relying_party`, and `udp_logging` are never constructed at all, and `body_validator` is inspected through its shape-only constructor. Custom (`custom_plugins/`) and unknown plugin names remain the documented residual: admission logs a value-redacted warning and admits them, and the runtime `502` above stays the fail-closed backstop. Nonzero global body-size limits (`FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` / `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`, including the default 10 MiB response cap) do **not** disqualify SNI routes: the direct-H2 path enforces those limits in-path (413 on oversized requests, 502 on oversized responses) via `SizeLimitedIncoming` and size-limited body collection. Ordinary (non-SNI) plain HTTPS still prefers the reqwest path when either body-size limit is nonzero — a silent performance cliff away from the direct-H2 pool that is only logged at `debug!`. H3 frontend requests bridged to a non-H3 backend now fail closed with the same 502/header policy; use an H2/H3-capable backend for those routes until the bridge grows a direct-H2 fallback. Active HTTP/H2/H3/gRPC health probes still use the target host as the TLS server name, so a backend certificate that only matches the override name can be marked unhealthy even though request traffic succeeds. Prefer TCP/passive health checks or a certificate that covers both names until active probes grow the same SNI override path. As a last-resort operational escape hatch, `backend_tls_verify_server_cert=false` avoids the certificate-name check for active probes, but it also disables backend certificate verification for request traffic.

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
8. Filters `MeshProxyConfig` entries by [`PolicyScope`](#policyscope-filtering) — same predicate as `MeshPolicy`, so root-namespace ProxyConfigs apply mesh-wide.

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

**Selector policy without proxy labels.** A `WorkloadSelector`-scoped policy whose selector carries labels cannot be evaluated when no proxy labels are resolved, and the cold-path filter would drop it (leaving an empty policy set that evaluates to `Allow`). The plugin distinguishes three cases at construction:

- **Slice-driven injection, ambiguous shared-SPIFFE (`labels_ambiguous`).** The slice flagged its labels as a non-authoritative shared-SPIFFE intersection and shipped the policy as a candidate-any superset for a label-holding consumer to re-filter. Reaching the plugin with empty `slice.labels` means that recovery already failed: the per-pod NodeWaypoint consumer skips this validation entirely (it re-filters per pod), and the xDS DP only leaves the labels empty when it had no local `FERRUM_MESH_WORKLOAD_LABELS` to prefer. There is no further consumer, so the policy demonstrably applies to a candidate workload yet would be silently dropped — a fail-open. Construction **fails closed** with an error; set `FERRUM_MESH_WORKLOAD_LABELS` (or `mesh_slice.labels`) for deterministic scoping. The same fail-closed rule covers a **non-empty intersection** that cannot satisfy a candidate-only selector (e.g. the slice intersection is `app=shared` but the superset carries a `role=api` policy): the partial intersection is not this workload's authoritative identity, so construction fails closed rather than dropping the candidate-only policy. Supplying an explicit `labels` override (the documented identity pin) **clears the ambiguous marker** — those labels are then authoritative, so a candidate-only selector that does not match them is correctly dropped by the cold-path filter instead of rejecting the workload.
- **Slice-driven injection, non-ambiguous.** The slice resolved empty labels and did **not** flag them ambiguous (e.g. a single-candidate or label-less workload), so those labels are authoritative for this workload and a label-based selector simply does not apply. Construction **tolerates** it with a warning and the cold-path filter drops it from enforcement for this slice.
- **Operator-direct config (flat `mesh_policies`, no slice).** There is no downstream consumer to recover labels, so silently dropping the policy would be a fail-open. Construction **fails closed** with an error requiring the operator to supply the proxy's `labels`.

**AUDIT-only policies are exempt from every fail-closed branch above.** An `AUDIT`-action policy is non-enforcing per Istio semantics — `evaluate_mesh_authorization()` records `mesh_authz.audit_policy` metadata and continues — so dropping an unscopable audit-only selector policy never opens an allow-by-default hole and is **not** a fail-open. Construction tolerates it (with a warning; the cold-path filter still drops it from evaluation) instead of rejecting the plugin, mirroring the per-pod NodeWaypoint missing-scope check, which already treats `AUDIT` as non-enforcing. A slice that carries an audit-only selector policy **alongside** an unresolvable enforcing (`ALLOW`/`DENY`) selector still fails closed on the enforcing one.

**Ambiguous slices fail closed in the mTLS/JWT consumers too.** When a `labels_ambiguous` slice reaches the DP with no local `FERRUM_MESH_WORKLOAD_LABELS` (so the marker is preserved and `slice.labels` is only the partial intersection), the candidate-any superset can still carry a selector-scoped `PeerAuthentication` (STRICT mTLS) or `RequestAuthentication` (JWT) that the partial intersection cannot resolve. Filtering those consumers solely against the intersection would silently drop the policy — a fail-open (Permissive instead of STRICT, or no JWT validation). Both consumers therefore fail closed while the marker is set: inbound mTLS resolution **escalates to the most-restrictive candidate mode** (a candidate-only STRICT forces STRICT, never downgrading below the normally-resolved mode), and request-auth injection **installs the candidate-only JWT provider** (Istio RequestAuthentication stays permissive — a request with no token still passes; only a forged/invalid token for that issuer is rejected). A non-ambiguous slice is enforcement-identical to the plain resolution. When the DP **does** supply local labels for an ambiguous slice, recovery **merges** the authoritative common intersection (the labels every candidate shares, which the CP proved apply) with the local labels (local wins on a key collision) so common-key selector mTLS/JWT/DENY rules stay enforced while local labels resolve the divergent keys; the marker is then cleared.

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

#### Certificate revocation

When `FERRUM_TLS_CRL_FILE_PATH` is configured, Ferrum applies that CRL set
symmetrically to mesh SPIFFE peer verification: inbound mTLS/HBONE handshakes
reject revoked client SVIDs, and outbound/backend mesh dials reject revoked
server SVIDs. A peer listed in an applicable configured CRL is rejected
fail-closed even when its SVID is otherwise trusted and unexpired. If the
bundle has no CRL from the peer certificate's issuing CA, its revocation status
is undeterminable and Ferrum accepts it, matching the shared inbound mesh CRL
model. With no CRLs configured, revocation checking is skipped and handshake
behavior is unchanged.

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

When the env var is unset or empty, mesh injection usually uses the defaults. The exception is identity-backed `NodeWaypoint`: when the runtime has file SVID material or a mesh CA backend, Ferrum derives the trusted assertor allow-list from the CP-derived `node_waypoint_assertors` inventory, built from scope-authorized `Workload.node_waypoint.spiffe_id` values before namespace/service slice narrowing. If no NodeWaypoint assertor metadata is present, the generated allow-list is empty so HBONE baggage rewrites fail closed instead of falling back to the bare `waypoint` service-account default. To lock down baggage rewriting entirely (no peer can rewrite the authz principal), configure a `mesh_authz` global plugin override with an explicit empty list (`trusted_hbone_assertors: []`).

`FERRUM_MESH_TRUST_DOMAIN_ALIASES` continues to gate the baggage identity's trust domain — both checks apply to a baggage rewrite.

**Observability**: when baggage is dropped because the peer is not a trusted assertor, transaction logs surface `mesh_authz.ignored_baggage=untrusted_assertor` and `mesh_authz.ignored_baggage.untrusted_assertor=true`. If the resulting authz decision is a DENY, `mesh_authz.deny_policy` is stamped as `untrusted_assertor`. Trust-domain-mismatch diagnostics retain their existing `trust_domain_mismatch` reason.

## RequestAuthentication

`MeshRequestAuthentication` declares which JWTs are valid for a workload scope. When applicable resources with JWT rules exist in the mesh slice, the mesh runtime auto-injects a `jwks_auth` global plugin (`__mesh_request_auth`) configured from the JWT rules.

**Permissive semantics** (matching Istio): RequestAuthentication only declares which JWTs are *valid*, not which are *required*. A request with no JWT passes through. An `Authorization` header using a foreign scheme such as `Basic` also counts as no JWT and passes through without an authenticated JWT identity. An applicable but malformed or invalid Bearer JWT is rejected. Enforcement (requiring a JWT) comes from `AuthorizationPolicy` ALLOW/DENY rules that check for authenticated identity.

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

**EgressGateway requires client certificates.** The EgressGateway TLS listener — both the `:15090` HTTP-family mTLS-termination listener and the F6.1 stream-family TCP egress listeners that share the same `ServerConfig` — is a security boundary onto external networks: a cert-less client admitted there reaches the external backend unauthenticated. For this topology, `resolve_mesh_inbound_client_auth` escalates `PERMISSIVE`-with-a-trust-anchor from `Optional` to **`Required`**, so every egress client must present a verifiable SVID even when no STRICT `PeerAuthentication` is in force (the default-allow case). The non-egress topologies (Sidecar / Ambient / waypoints) keep the standard `PERMISSIVE` → `Optional` posture unchanged. If `PERMISSIVE` resolves on an EgressGateway with **no** trust anchor at all, the listener cannot authenticate clients, so it **fails closed** (hard error, never optional-no-verify mTLS); in practice `validate_egress_gateway_mtls_config` already requires a peer verifier for this topology at config time, so this is defense-in-depth for the live-reload path. UDP ServiceEntry ports do not currently materialize EgressGateway listeners, so they do not share this TLS listener path. The only ways an egress client skips client-cert verification are an explicit `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true` (plaintext stream listeners) or `PeerAuthentication` `DISABLE` (rejected for EgressGateway by the disable-mode topology guard). This escalation applies on **both** startup and `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true` slice apply, so a reload cannot downgrade an egress gateway to optional client auth.

**SPIFFE peer trust-domain verification**: when gateway SVID material is configured (all three of `FERRUM_GATEWAY_SVID_CERT_PATH` / `FERRUM_GATEWAY_SVID_KEY_PATH` / `FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH`), the inbound mTLS / HBONE listener verifies each peer certificate's chain **and** that the peer's SPIFFE URI-SAN trust domain matches the gateway SVID's local trust bundle or one of the slice's federated bundles. This closes the gap where a peer cert that merely chained to the configured client CA was admitted regardless of its SPIFFE trust domain. STRICT requires + validates a peer cert; PERMISSIVE still admits peers that present no cert but trust-domain-validates any cert that is offered (so PERMISSIVE records mTLS identity when present). Without gateway SVID material, the listener keeps the prior chain-only verification against `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH`. In PERMISSIVE specifically, the listener requests a client certificate whenever **either** trust anchor exists (the SVID verifier is preferred, otherwise the operator client CA bundle) so an offered cert is verified and its identity recorded; only when **neither** anchor is configured does PERMISSIVE skip the certificate request entirely — and in that fully-degraded case Ferrum emits a single startup warning that inbound peer identity cannot be verified or recorded, rather than silently treating authenticated peers as anonymous. (The **EgressGateway** topology is the exception to PERMISSIVE-optional: there a present trust anchor escalates PERMISSIVE to `Required`, and a missing anchor fails the listener closed — see the EgressGateway requires-client-certificates note above.) The HBONE baggage `source.principal` trust-gate now rests on this verified peer identity. When `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true`, the lock-free SVID bundle slot is re-published on slice apply so federated trust-domain additions take effect without a listener restart; file-backed and CA-backed gateway SVID rotations also republish the inbound peer-verifier bundle from the newest local roots plus the last accepted federated overlay. Slice roots for the gateway SVID's own trust domain are additive with the freshly loaded SVID local roots, which lets the control plane stage same-trust-domain CA-root rotation without replacing the SVID source's current root set.

Per-port TLS configs and their effective modes are built during startup (and during an opted-in live reload), then published as one atomic listener-fallback + app-port table. Captured connections select from that table before the handshake; after routing reveals the effective app port, every inbound HTTP-family/HBONE request reads the current atomic snapshot and performs one lookup in the pre-resolved mode table. This request-time lookup makes a stricter live reload authoritative for subsequent requests on an existing keep-alive connection; it does not repeat selector resolution or certificate parsing. The topology disable guards remain in force for every entry, so a `DISABLE` override cannot bypass the Ambient/HBONE or EgressGateway mTLS-only constraints.

The selectable app-port table uses the same runtime workload SPIFFE identity and `multi_cluster.local_cluster` context as Sidecar inbound route materialization. A local VM/WorkloadEntry tagged with the declared local cluster therefore retains its `portLevelMtls` entry at both accept-time and request-time enforcement, while a foreign cluster workload cannot contribute a local listener port.

By default, the resolved mode is captured **once at startup** from the first valid slice. Subsequent `PeerAuthentication` changes pushed via the control plane update the in-memory slice and are honored by other plugin paths (e.g. `mesh_authz`, plugin chains), but the inbound TLS `ServerConfig` is not rebuilt. If a later route-only slice would make an app port newly local while an applicable override for that port was filtered out of the fixed startup table, Ferrum rejects the whole slice instead of serving the new route under the listener fallback. Restart with the port present or enable PeerAuthentication live reload.

Set `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true` to opt in to live reload of the resolved mTLS modes and frontend client CA verifier on mesh slice apply. Coverage includes mesh HTTP/HBONE termination listeners **and** mesh-shared TCP+TLS / UDP+DTLS stream listeners: a slice apply that changes a top-level or per-app-port `PeerAuthentication` mode, or rotates the client CA bundle, rebuilds the distinct required `rustls::ServerConfig` values and atomically swaps one coherent `{listener fallback, app-port table}` snapshot for future HTTP/HBONE accepts. The listener-wide config is also published to the shared TCP+TLS stream slot (snapshotted per accept), and the DTLS `FrontendDtlsConfig` is rebuilt on every active `DtlsServer` (new sessions snapshot the swapped material at handshake; existing handshake-complete sessions keep the material they handshook with until they end). If any required TLS config build fails — or the client-CA-bundle snapshot cannot be read (e.g. a secrets operator truncating the bundle file mid-write) — Ferrum **rejects the whole slice** and keeps the last good config in its entirety, so no authz/`MeshPolicy`/`RequestAuthentication`/`ServiceEntry`/endpoint update from that slice is applied either, until the rebuild succeeds (fail-closed; the inbound posture is never silently weakened). Only the *post-accept* DTLS rebuild keeps the previous config **for that path** and logs a warning without rejecting the slice. Topology-disable rejection (see below) likewise keeps the last good config wholesale.

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
- Inode or fingerprint changed → pod restarted under the same UID; identity (and its per-pod policy scope) is evicted so a fresh enrollment is required before traffic for the new instance is honoured. The fingerprint prevents missed restarts when the filesystem reuses the old inode number.
- Path gone → pod removed; identity and policy scope are evicted.

An independent idle identity GC task (`FERRUM_MESH_NODE_WAYPOINT_IDLE_GC_INTERVAL_SECS`, default 30s) reclaims identities enrolled **without** a cgroup path — which is what the production lazy hash-join enrollment produces (it has no cgroup to bind, and nothing calls the explicit removal API for it). For those, the idle GC evicts an identity only when its pod UID is no longer referenced by a live cookie record **and** its identity `Arc` has no other holder (`strong_count == 1`): a removed/restarted pod's accept-side cookies age out of the mirrored `FERRUM_ORIG_DST4/6` view within a poll interval, so the orphaned identity (and its per-pod policy scope) is reclaimed instead of accumulating across pod churn. Prompt aging-out depends on the `sock_ops` program **removing the orig-dst record on TCP close** (not just on LRU pressure): without that, a closed connection's cookie would linger in the LRU map on a low-churn node and keep the dead pod's record mirrored indefinitely. The `strong_count` guard protects in-flight connections: the HTTP/HBONE accept path stores the resolved identity `Arc` on the connection for its whole lifetime and re-queries the per-pod scope on every request, so a connection whose cookie the BPF LRU evicted mid-flight still pins its identity (`strong_count > 1`) and keeps its scope until it closes — without the guard the cookie-only signal would wrongly drop the scope and downgrade later streams to mesh-wide. TCP streams resolve their scope once at accept and never re-query, so they are unaffected regardless. An evicted-but-still-live idle pod simply re-enrolls on its next connection. cgroup-bound identities are left to the cgroup-binding pass above and are never touched by this idle pass.

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

In addition to remote-cluster gateways, the east-west topology materializes a TCP passthrough proxy for each local `MeshService` port. HTTP-family ports keep the phase-3 convention: a service with exactly one HTTP-family port uses the base service FQDN; every HTTP port of a multi-port service uses `p<port>.<fqdn>`. L4 ports use `p<port>.<fqdn>` even when they are the service's only port; if TCP and UDP share one number, the aliases become `p<port>-tcp.<fqdn>` and `p<port>-udp.<fqdn>` so different targetPorts cannot collide. Each proxy is backed by that port's resolved container port. Explicit `EastWestGateway.sni_hosts` ownership remains wildcard-aware and suppresses only the automatic SNI it directly overlaps.

### Client-Side Cross-Cluster Egress (Sidecar)

A **Sidecar** client can send application traffic to a service whose endpoints live in a remote cluster over the east-west gateways. HTTP-family materialization emits one cross-cluster target per remote network at the gateway endpoint. L4 materialization emits a per-remote-pod synthetic target so the CONNECT can retain the real pod authority, but its network dial still goes only to the remote **east-west gateway** (`mesh.mtls_dial_host` / `mesh.mtls_port`) — never directly to the remote pod. The dial:

- opens mesh-mTLS (HTTP/2-over-mTLS) to the gateway with the **ClientHello SNI overridden to the destination service FQDN**, so the gateway's SNI passthrough routes the opaque outer TLS to a destination workload;
- uses **trust-domain-scoped** peer verification: because the SNI-passthrough gateway LB-picks the destination workload, the client cannot pin a pod SPIFFE id, so it instead requires the destination's server SVID to be in **exactly the target's remote trust domain** (`mesh.trust_domain`) AND chain to a federated bundle — a federated cert from a *different* trust domain is rejected. AuthorizationPolicy at the destination does the fine-grained source check.

Local-cluster endpoints stay the first tier (cross-cluster targets carry `mesh.remote=true`). Fail-closed throughout: a missing SNI override, trust domain, gateway, dial host, or CONNECT authority refuses/skips the dial with no plaintext fallback. HTTP-family ports retain the base/per-port alias rules described below. Raw-TCP and UDP ports now materialize **per-remote-pod** tunnel targets: `mesh.mtls_dial_host` carries the east-west gateway, `mesh.mtls_authority_host` carries the real destination pod address, and `target.port` carries the resolved app port. Their outer TLS uses the L4 per-port alias (protocol-disambiguated when TCP and UDP share a number), and the shared `MeshMtlsDialPlan` selects trust-domain-only verification plus the SNI override. Raw TCP then byte-relays through the bare H2 CONNECT; UDP uses the existing `udp` marker and `mesh_udp_frame` framing.

**Destination inbound relies on the standard sidecar inbound capture.** The client dials the gateway with the destination service FQDN as SNI; the gateway forwards the opaque TLS to the destination workload's **app port**, and the destination pod's inbound iptables capture REDIRECTS that app-port traffic to the sidecar's `:15006` mTLS listener — exactly as same-cluster east-west *inbound* works (`build_east_west_service_targets` forwards to the workload app/target port, not `:15006`). No destination-side change is needed for cross-cluster.

**Cross-cluster gRPC and WebSocket egress are supported for Sidecar (issue #2010).** Both ride the SAME cross-cluster mesh-mTLS transport as HTTP — the app protocol is a runtime flavor layered on top. A native-gRPC request whose LB-selected target is a cross-cluster `mesh.mtls` target skips the direct-dial gRPC pool and dispatches through the mesh-mTLS pool's cross-cluster branch (`proxy_to_backend_mesh_mtls`): hyper HTTP/2 end-to-end, `te: trailers` re-synthesized, response streamed so `grpc-status` and custom trailers relay across the two-trust-domain hop. A WebSocket upgrade opens an RFC 8441 Extended CONNECT over that same cross-cluster mesh-mTLS dial. Both the HTTP/gRPC path and the WebSocket path resolve the dial the same way through a shared `MeshMtlsDialPlan` (in-cluster pins the peer SPIFFE; cross-cluster uses `expected_peer = None` + trust-domain-only verification scoped to `mesh.trust_domain` + a ClientHello SNI override to `mesh.eastwest_sni`), so the two transports cannot drift. Fail-closed throughout: a cross-cluster target missing its SNI override or remote trust domain, or an unsupported transport, is refused (gRPC UNAVAILABLE / a failed upgrade) with no plaintext or wrong-SNI fallback. A **gRPC** retry that rotates onto a mesh-tagged target additionally fails closed — the gRPC retry loop dials the direct pool and cannot switch to a mesh transport mid-loop. (The WebSocket dial loop instead re-derives the mesh egress from the rotated target on each attempt, so a WS retry onto a *supported* mesh target — including a cross-cluster Sidecar one — re-dispatches over mesh normally; only unsupported/malformed WS targets fail the upgrade closed.) The HTTP/3 frontend still has no mesh dispatch, so cross-cluster gRPC/WebSocket on H3 fail closed. **Ambient cross-cluster gRPC remains fail-closed**; Ambient cross-cluster **WebSocket is now supported** over HBONE (HBONE inner protocol; see the Ambient section below).

### Client-Side Cross-Cluster Egress (Ambient / HBONE)

An **Ambient** client reaches a remote-cluster service over the east-west gateways too, but the shape differs from Sidecar because the inner protocol does. Ambient's inner request is an HBONE **CONNECT** whose `:authority` the destination relay (`handle_hbone_request` → `build_inbound_hbone_relay_proxy`) dials under the **open-relay guard** (`inbound_hbone_relay_destination_allowed`): the authority must be loopback or a **slice-declared workload addr+port** — a service FQDN is rejected. The remote pod IP is slice-declared on the destination side and known to the client (merged remote endpoints), just not directly reachable. So Ambient cross-cluster targets are **per-remote-pod**, not one-per-gateway:

- the `UpstreamTarget` identity is a **scoped synthetic host** carrying the gateway-network scope + the real pod addr (so two remote pods that share an IP across overlapping CIDRs but are reached through different gateways/networks never collapse to one load-balancer / health / circuit-breaker key); the **real pod addr:app-port** rides the `mesh.hbone_authority_host` tag and is what the inner HBONE CONNECT `:authority` uses;
- the dial host is the remote network's **east-west gateway** (`mesh.hbone_dial_host` / `mesh.hbone_port`, e.g. `:15443`) with the **ClientHello SNI overridden to the destination service FQDN** (`mesh.eastwest_sni`) so the gateway's SNI passthrough routes the opaque outer TLS;
- verification is **trust-domain-scoped** (`mesh.trust_domain`, no pod SPIFFE pin — the gateway LB-picks the destination), the same posture as the Sidecar cross-cluster path; the HBONE pool key includes the SNI override + the expected trust domain so a session verified for one (trust domain, destination) is never reused for another.

The HBONE **capability registry is bypassed** for cross-cluster targets (they dial the operator-declared gateway, never a probeable workload `:15008`) and they are excluded from capability probing. Local-cluster endpoints stay the first tier (`mesh.remote=true`). HTTP-family ports retain the phase-3 alias rules. Raw-TCP and UDP reuse the same per-pod target shape with the L4 per-port alias as outer SNI and the real pod addr/app-port as CONNECT authority. Raw TCP uses the existing HBONE byte tunnel; UDP uses `get_datagram_tunnel` and the same length-delimited `mesh_udp_frame` records as same-cluster UDP. Missing SNI, trust domain, dial host, or authority fails closed before a wrong-target dial.

**Destination inbound relies on the standard inbound capture** (same as the Sidecar path above). The client dials the gateway with the destination service FQDN as SNI; the gateway forwards the opaque TLS to the destination workload's **app port** (`build_east_west_service_targets` forwards to the workload app/target port, not a mesh terminator port), and the destination pod's inbound capture REDIRECTS that app-port traffic to the Ambient HBONE terminator `:15008` — exactly as same-cluster east-west *inbound* works, and exactly how the Sidecar cross-cluster path redirects to `:15006`. No destination-side change is needed for cross-cluster. The unprivileged functional fixtures still collapse that redirect by targeting the terminator port directly; the privileged **Two-Cluster Mesh Live Datapath** CI gate (`functional_mesh_live_two_cluster_cross_cluster_protocol_matrix`) validates the real app-port → destination-capture path with separate federated SPIRE trust domains and an isolated east-west hop.

**L4 test boundary.** In-tree projection tests cover Sidecar/Ambient raw-TCP and UDP target materialization, per-port SNI generation, and destination east-west SNI relay creation. Existing unprivileged functional tests cover the raw byte-stream and framed-datagram destination relays. The privileged **Two-Cluster Mesh Live Datapath** CI gate covers the complete boundary that those harnesses cannot simulate: `SO_ORIGINAL_DST`/TPROXY in cluster A → actual SNI-passthrough east-west gateway → app-port capture and terminator in cluster B, including `mesh_udp_frame` datagrams and transparent VIP:port return-source spoofing.

**WebSocket over cross-cluster HBONE (Ambient) IS supported (issue #2010); gRPC is not.** A WebSocket upgrade to a cross-cluster HBONE target rides the SAME per-pod cross-cluster HBONE byte tunnel the HTTP path uses — dial the remote east-west gateway (`mesh.hbone_dial_host`) with the destination service FQDN as the outer-TLS SNI override (`mesh.eastwest_sni`) + trust-domain-only verification (`mesh.trust_domain`, no pinned pod SPIFFE); the inner HBONE CONNECT `:authority` is the destination pod addr:app-port (`mesh.hbone_authority_host`) the dest relay byte-copies to — then an inner HTTP/1.1 WebSocket handshake spoken THROUGH the tunnel. `get_ws_byte_tunnel` threads the cross-cluster SNI-override / trust-domain scope (mirroring `proxy_to_backend_hbone`), so the WS and HTTP HBONE paths cannot drift; a malformed cross-cluster target (missing SNI / trust domain) fails the upgrade closed. **Native gRPC over cross-cluster HBONE remains fail-closed** — refused before any dial with a Trailers-Only gRPC UNAVAILABLE (HTTP 200 + `grpc-status: 14`) because the HBONE inner protocol is HTTP/1.1 over a byte tunnel and cannot carry the HTTP/2 trailers gRPC requires, cross-cluster or not (the same limitation as same-cluster Ambient gRPC). (PASS-THROUGH gRPC-Web is body-framed and rides the cross-cluster HTTP-family path like plain HTTP; gRPC-Web the `grpc_web` plugin TRANSLATED is wire-native gRPC by dispatch time and is refused pre-dial the same way.) **Sidecar cross-cluster gRPC and WebSocket are also supported** over mesh-mTLS — see [Client-Side Cross-Cluster Egress (Sidecar)](#client-side-cross-cluster-egress-sidecar) and the [Protocol x Topology Support Matrix](#protocol-x-topology-support-matrix).

### Multi-Port Cross-Cluster SNI Aliases

The east-west gateway routes purely by the ClientHello SNI, which carries a hostname but no port. Ferrum derives the deterministic DNS-safe name from `cross_cluster_service_sni`, shared by both ends:

- **Single HTTP-family port** → the bare base service FQDN `<service>.<namespace>.svc.<cluster-domain>` (e.g. `reviews.default.svc.cluster.local`). Unambiguous (only one port is possible) and byte-identical to the pre-multi-port behavior — same SNI, and the internal east-west proxy keeps its port-less id.
- **Multiple HTTP-family ports** → an **explicit per-port alias for EVERY port, including the numerically lowest**: `p<service-port>.<base-fqdn>` (e.g. `p8080.reviews...`, `p9090.reviews...`). The bare base FQDN routes to **no** port for a multi-port service. The **numeric service port** is authoritative in the alias — a port *name* is never used for uniqueness. `p<port>` is a valid DNS label, so the alias is a valid FQDN (no colon-bearing SNI).
- **Raw-TCP or UDP port** → `p<service-port>.<base-fqdn>`. If TCP and UDP share that numeric port, use `p<service-port>-tcp.<base-fqdn>` and `p<service-port>-udp.<base-fqdn>`. L4 payloads carry no HTTP authority, so even a single L4 port uses an explicit alias; the transport suffix prevents different TCP/UDP targetPorts from sharing one gateway route.

**Why alias every port of a multi-port service (codex #2040 Finding A — cross-cluster port skew).** Two clusters can declare *different* HTTP port sets for the same service. Routing the lowest port on the bare base FQDN would let a client that only knows `:9090` treat it as the base while a destination that also has `:8080` materializes the base for `:8080` — the client's base-FQDN traffic would then be forwarded to the wrong port. Making the port channel the **explicit numeric port** in the alias removes any shared base-FQDN mapping: a client dialing `p9090.<fqdn>` is matched by a destination that materialized `:9090` on that same alias regardless of either cluster's port set, and a mismatch **fails closed** on the absent per-port proxy instead of silently cross-wiring. This also makes the scheme order-independent for free (the alias is keyed on the port number, never declaration order).

**Collision-free internal ids (codex #2040 Finding B).** The internal east-west proxy/upstream ids are registry keys only (a `Proxy.id`/`Upstream.id`, never emitted to Kubernetes, DNS, SNI/TLS, or any wire protocol — the SNI above is built independently). A multi-port service's per-port id joins the port marker with a `.` — `__mesh-ew-svc-<ns>-<name>.p<port>` — and `.` is a character a DNS-1035/1123 Kubernetes service name **cannot** contain, so a service literally named `<name>-p<port>` (whose bare id is `__mesh-ew-svc-<ns>-<name>-p<port>`, no dot) can never collide with the alias id in the materializer's id-keyed upsert map. A single-port service keeps the port-less id unchanged.

**Gateway ownership is automatic (no extra operator config).** The client selects a gateway whose `sni_hosts` claim either the base FQDN or the exact alias, then dials the derived SNI. The destination auto-materializes one SNI-passthrough proxy for every supported service port, backed by that port's container port. Explicit SNI ownership suppresses only overlapping automatic routes.

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
used for outbound mTLS and for inbound SPIFFE peer verification; a polled trust
domain is no longer outbound-only. Endpoints are validated at slice apply for
SSRF (link-local / loopback / cloud metadata IPs are rejected) and must use
`https://`; response bodies are capped at 2 MiB and parsed bundles are capped
at 256 X.509 + 256 JWT authorities.
Mesh validation caps `mesh.multi_cluster.remote_clusters` at 256 entries, bounding federation poller fan-out before any remote endpoint is spawned.

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
      discovery_credential_ref: "eu-west-1"   # optional; selects the per-remote discovery secret
```

- `federation_endpoint` feeds the [trust-bundle federation poller](#trust-federation) (cross-cluster mTLS verification material).
- `control_plane_url` feeds **cross-cluster endpoint discovery** (below).
- `discovery_credential_ref` (optional) selects the per-remote discovery credential resolved against `FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS` so this cluster authenticates to its own control plane with a distinct JWT secret; see [Cross-Cluster Endpoint Discovery](#cross-cluster-endpoint-discovery). Unset falls back to the shared CP-DP secret (deprecated in production).
- `name` doubles as the **target-cluster audience identifier** for remote discovery: the discovery token minted for this cluster carries `aud: ferrum-mesh-discovery:<name>`, and the peer control plane accepts it only when its own `FERRUM_MESH_CLUSTER_AUDIENCE` matches. It must therefore be the identifier that cluster knows itself by, not a local-only alias. The name is a **canonical identity**: leading/trailing whitespace is rejected (never silently rewritten), and uniqueness is enforced in that same trimmed identity domain so two spellings cannot collapse onto one JWT audience while remaining distinct poll/store keys. See [Remote-Discovery Audience Binding](#remote-discovery-audience-binding).
- `local_cluster` is **optional**. Remote-cluster provenance — the marker that makes [strict locality LB](#locality-aware-load-balancing) and the egress local-only filter treat an endpoint as remote — is keyed on the workload's cross-cluster identity: a discovered endpoint carries a configured `remote_clusters[].name`, so it is classified remote whether or not `local_cluster` is set. Set `local_cluster` only when you also want a *locally* declared workload that carries an explicit `cluster` tag distinguished from your remote clusters. When set, it must likewise be a canonical identifier with no leading/trailing whitespace.
- `remote_clusters` is capped at 256 entries by mesh validation to bound federation and endpoint-discovery task fan-out.

### Cross-Cluster Endpoint Discovery

When `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS > 0` (default `0`, disabled), each currently eligible `RemoteCluster.control_plane_url` is dialed over the native `MeshSubscribe` gRPC stream (reusing the DP↔CP gRPC JWT secret and TLS selected from that remote URL) to fetch that cluster's service endpoints (workloads + services). The discovered endpoints are merged into the local mesh registry at slice apply and become ordinary upstream targets, tagged with a synthetic **remote locality** (`remote-<cluster>` or `remote-<cluster>/<network>`). Because the load balancer is **locality-aware priority-tier** (see [Locality-Aware Load Balancing](#locality-aware-load-balancing)), local endpoints occupy the source region/zone tier and remote endpoints sit in the fallback tier: traffic stays local while local endpoints are healthy and **fails over to the remote cluster's endpoints only when the local tier has no healthy endpoints**.

> **Precondition — source locality required for local-first preference.** The priority-tier LB only prefers local endpoints over remote ones when the local workload's source locality is set (derived from `topology.kubernetes.io/region`+`zone` labels on the mesh slice's SPIFFE-matched workload, or from the label-based heuristic). When source locality is absent (e.g. the labels are missing or the SPIFFE-matched workload has no locality), `target_locality_ranks` is empty and the behavior depends on the **locality-LB strict mode** (`FERRUM_MESH_LOCALITY_LB_STRICT`, default `false`):
>
> - **Fail-open (default, `false`):** the LB returns local **and** remote endpoints together — traffic can go to the remote cluster even when local endpoints are healthy (not local-first). This preserves availability and is the historical behavior.
> - **Fail-closed-to-local (`true`):** the LB restricts selection to **local** endpoints — every target *not* tagged as a remote-cluster-discovered endpoint — and never widens to remote while at least one local endpoint exists. Remote provenance is keyed on an explicit per-target marker stamped from the workload's cross-cluster identity at materialization time (not on the locality string), so a real local Kubernetes region that happens to be named `remote-…` is still treated as local; a target with no remote marker counts as local. If there are **no** local endpoints it widens to the full healthy pool (local + remote) and logs a one-time `WARN` rather than black-holing traffic. Strict mode is **inert when a source locality is resolved**: priority-tier preference (exact/zone/region) is unchanged in both modes.
>
> Ferrum emits a startup `WARN` when discovery is enabled but no source locality can be resolved from the initial mesh slice. Ensure `topology.kubernetes.io/region` and `topology.kubernetes.io/zone` Node labels are propagated to workload locality metadata (via `FERRUM_K8S_NODE_LOCALITY_ENABLED=true`, or by stamping them directly on the mesh slice's `Workload.locality` field) before enabling discovery; prefer fixing source locality over enabling strict mode, which is a safety net rather than a substitute for correct locality metadata.
>
> Config validation additionally emits a `WARN` advisory (any mode, never an error) whenever `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS > 0` is combined with `FERRUM_MESH_LOCALITY_LB_STRICT=false`, recommending strict mode so an absent source locality cannot mix remote endpoints into selection while local endpoints are healthy. Cross-cluster east-west **gateway** failover targets are unaffected either way — they are always-failover local-first regardless of the flag; the advisory covers only plain remote workload endpoints from this Experimental discovery path.

**Per-RemoteCluster discovery credentials.** Each `RemoteCluster` may set `discovery_credential_ref`, a reference resolved data-plane-side against `FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS` (a JSON object mapping reference -> the JWT secret that remote cluster's control plane accepts; itself resolvable through the external-secret backends and never serialized into the slice/config or logged). The data plane mints that cluster's remote `MeshSubscribe` token with the referenced secret, so a credential issued for cluster B cannot authenticate to cluster C — cluster B's control plane validates the HS256 signature with **B's** secret, and a token signed with B's secret simply fails to verify at C. A `discovery_credential_ref` that does not resolve to an installed entry **fails that cluster closed** (it is skipped, never silently downgraded to the shared secret). When a `RemoteCluster` sets no `discovery_credential_ref`, discovery falls back to the shared `FERRUM_CP_DP_GRPC_JWT_SECRET`; this shared-secret posture is **deprecated in production multi-cluster** (a credential good for any one cluster is then good for all of them) and emits a startup `WARN`. The per-remote secret carries the same issuer the shared path uses (`FERRUM_CP_DP_GRPC_JWT_ISSUER`), since the remote CP pins the issuer, not a per-remote one. Explicit JWT **audience-claim** binding is now **enforced** on top of the per-remote secret — see [Remote-Discovery Audience Binding](#remote-discovery-audience-binding). Discovery is fail-closed on trust: a remote cluster is dialed **only** while a federated trust bundle for its `trust_domain` is present (configure [Trust Federation](#trust-federation) for the peer first). The discovery reconciler watches **proxy-accepted** mesh-slice updates (the same applied-slice source the federation poller uses, never a merely received slice) and federation updates, starts newly eligible clusters, stops removed or no-longer-trusted clusters, and removes their stale endpoints. Because it reconciles from the accepted slice, a slice the proxy *rejected* — including one that keeps a cluster's name + trust domain but changes its poll identity (`network`, `control_plane_url`) — never starts a poller or populates the endpoint store, and a changed poll identity stops the old poller and evicts its endpoints before the new one starts. A poll failure keeps the last-good endpoints and backs off (jittered 1s -> 30s) only until `FERRUM_MESH_REMOTE_DISCOVERY_MAX_STALE_SECONDS` (default 300) is exceeded; then the endpoints and their success/age metrics are withdrawn while the poller keeps retrying, so a later successful poll can reinstall without a slice change. Set the max-stale value to `0` only for dev/test indefinite retention; production mode rejects that posture when discovery is enabled. `control_plane_url` is SSRF-validated (cloud-metadata / link-local hosts rejected; loopback allowed for local/dev/test). In production mode, remote discovery accepts only authenticated TLS URLs (`https://` or `grpcs://`) and rejects plaintext `http://` / `grpc://`; `FERRUM_DP_GRPC_TLS_NO_VERIFY=true` is also refused when discovery is enabled. Mesh validation caps `mesh.multi_cluster.remote_clusters` at 256 entries, bounding endpoint-discovery task fan-out before any remote CP is dialed.

The merge into the live proxy config is additionally filtered against the **candidate (about-to-be-applied) slice's** `multiCluster` by the stored entry's **full poll identity** — name, `trust_domain`, `network`, and the normalized `control_plane_url` — so cluster removal and control-plane identity changes are fail-closed **within the same generation**, not one generation later: when a newly-accepted slice drops a remote cluster (or declares it under a divergent `trust_domain`, `network`, **or `control_plane_url`**), that cluster contributes **no** endpoints to the config built from that slice — even before the discovery reconciler evicts the store entry. A URL-only change is now caught here too: the stored entry records the normalized URL it was polled from, so endpoints fetched from the *previous* control plane are not served by the generation that accepts the new URL. A slice with no `multiCluster` at all contributes no remote endpoints. Conversely, because the pollers track the **accepted** slice, an accepted remote cluster can publish an endpoint scale-up/down while the CP's newest *received* slice is one the proxy rejects; the apply loop re-applies that overlay against the **last-accepted** slice so the change still reaches the live proxy without waiting for a fresh valid slice (fail-closed by retention if even the last-accepted slice no longer builds). A mesh-block-only change (a remote scale-up/down, or a trust-bundle overlay) produces no proxy/upstream delta, so the proxy-config apply explicitly republishes the request epoch on such changes — otherwise the request path's view of `mesh.workloads`/`mesh.services` would stay stale until an unrelated proxy/upstream change forced a republish.

#### Remote-Discovery Audience Binding

Signature + issuer + expiry bind a discovery token to a **credential**, not to a **destination**. Two clusters that share the deprecated fallback `FERRUM_CP_DP_GRPC_JWT_SECRET` and the same `FERRUM_CP_DP_GRPC_JWT_ISSUER` therefore used to accept each other's discovery tokens: a token minted for cluster B, replayed or misrouted to cluster C, verified identically at C. Ferrum now binds every remote-discovery token to its **target cluster** with a JWT `aud` claim.

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

**Layering.** Audience binding is defense in depth **on top of** — never instead of — the existing checks: HS256 signature against the per-remote (or shared) secret, required `exp`/`iat`/`sub`/`iss`, pinned issuer, the `ns` namespace claim, TLS/production transport posture, and the fail-closed per-remote credential resolution all still apply unchanged, and a failure in any of them still refuses the subscription. (DP tokens still mint `role: data_plane` for operator/tooling conventions; the CP gRPC verifier does not authorize on it.)

**Compatibility.** The local-purpose audience deliberately removes legacy no-audience compatibility for `MeshSubscribe`. A pre-change local native client sends `remote_discovery=false` with no `aud` and is refused by a new control plane. A pre-#3202 remote poller also sends the proto3 false/default with the old no-audience token; it is indistinguishable from that legacy local request and is likewise refused. In the other direction, a new local or remote MeshSubscribe client sends an audience that an old control plane's non-audience verifier refuses. Mixed-version native MeshSubscribe therefore fails closed; roll the control plane and every native mesh/remote-discovery client as one compatibility unit. This does **not** change ordinary `ConfigSync` or xDS token shapes or verification: they continue to carry no audience and refuse audience-bearing tokens.

**Failure handling and diagnostics.** A refused subscription fails the whole poll: the data plane keeps that cluster's **last-good endpoints**, backs off, and imports nothing (the existing `FERRUM_MESH_REMOTE_DISCOVERY_MAX_STALE_SECONDS` window still governs eventual withdrawal). The control plane records the refusal as `ferrum_mesh_subscribe_audience_rejections_total{subscription,reason}` — `subscription` is `remote_discovery` or `local`, and the MeshSubscribe reason is one of `missing`, `malformed`, `ambiguous`, `mismatch`, or `unconfigured` — and emits an `audit.event="mesh_subscribe_audience_rejected"` `WARN`. Both labels are compile-time constants, so the series cardinality is fixed. The token, its claims, the expected audience, and the JWT secret are never logged or exported; the gRPC status returned to the caller is a fixed string that does not echo the presented audience.

#### Response Validation And Merge Rules

**Response validation is shared with local native consumption.** The remote fetch reads the first non-heartbeat `MeshConfigUpdate` through the *same* centralized, fail-closed rules the local native client applies (see [Native MeshSubscribe](#native-meshsubscribe-default) → "Response binding"): `ferrum_version` must be present and major/minor-compatible, the envelope `version` must equal the embedded `MeshSlice.version`, and the slice's `node_id`/`namespace` must match the subscription this data plane sent. Any mismatch fails the poll **before** a single workload or service is imported, so the cluster's last-good endpoints keep serving, the poller backs off, and endpoints from a wrong-cluster or wrong-namespace response are never merged into the local registry. Rejections increment `ferrum_mesh_config_update_rejections_total{consumer="remote_discovery",reason}` alongside the poll-failure counter.

Merge rules: exact duplicate workload endpoints are skipped, but workloads with the same SPIFFE ID and different addresses are retained because the same service account identity can have replicas in multiple clusters. A service the local cluster already advertises keeps its local ports/overrides and unions in the remote workload refs so it resolves both local and remote endpoints; a service that exists only remotely is added wholesale.

**Observability:** `GET /mesh/remote-clusters` (JWT-authenticated, mesh-only) surfaces the DP's live view of this discovery — the remote clusters it has actually fetched endpoints from (per-cluster workload/service counts + fetch age under `discovered`) and the remote clusters the accepted slice declares (under `configured`, each cross-referenced with a `discovered` flag). Each configured row also reports `outbound_trust_active`, `inbound_trust_active`, `trust_source` (`polled`, `control_plane`, `local`, `blocked_pending_poll`, or `none`), and polled-bundle fetch age when available. That makes asymmetric trust visible: outbound can be active while inbound is inactive if no SPIFFE verifier slot is configured, and fail-closed bootstrap appears as `trust_source: "blocked_pending_poll"`. A configured remote cluster that never appears under `discovered` is the signal that discovery is disabled, the peer's trust bundle is missing, or polls are failing. The `discovered` view is additionally scoped to the **accepted** slice's clusters (matched by full poll identity — name, trust domain, network, and normalized `control_plane_url`) as belt-and-suspenders on top of the accepted-slice reconcile above, so a cluster absent from the accepted config — or whose stored network/control-plane identity diverges from it — is never reported as live discovery (and never with a stale network) (fail closed). The per-cluster fetch age tracks the last successful **poll**, not the last endpoint **change** — a stable cluster still refreshes its age each poll, so it does not look stale to alerting. The payload reports counts and provenance only — never raw workload addresses, SPIFFE IDs, or control-plane URLs.

**Live-verification status:** the aggregation + failover path is covered by tests with a mockable remote source, and the production `MeshSubscribe` gRPC dialer is covered by an **in-process two-CP round trip** — tests stand up a real `MeshSubscribe` gRPC server on a loopback port and drive the production dialer against it (channel dial, DP↔CP JWT mint + server-side verification, heartbeat skipping, slice decode, endpoint extraction, and a full discovery-loop install). The remaining live-verification step is a **true cross-cluster deployment** (two mesh control planes on separate networks) exercising the dialer under real network churn / loss / latency.

## Protocol x Topology Support Matrix

One table answering "does protocol X ride mesh transport Y?" across the two same-cluster topology transports, the two client-side cross-cluster east-west paths, and the gateway-to-mesh service-discovery bridge. Statuses use this document's own failure-mode language; each cell is anchored to the authoritative section via the numbered notes below. **NodeWaypoint is deliberately out of scope for this table** — it is **Experimental** with its own sections ([Node Waypoint](#node-waypoint), [Node Agent Mode](#node-agent-mode)); its UDP/DTLS limits (mesh-wide UDP/DTLS policy only, per-pod UDP/DTLS authorization scoping architecturally out of scope) are pinned in [docs/mesh_supported_matrix.md](mesh_supported_matrix.md) and in the NodeWaypoint UDP/DTLS limitation above.

Column key: **Sidecar same-cluster** = Sidecar egress over plain SVID-mTLS HTTP/2 to the peer sidecar's `:15006`; **Ambient same-cluster** = Ambient/Waypoint egress over HBONE (HTTP/2 CONNECT over mTLS) to the peer's `:15008`; **Cross-cluster Sidecar / Ambient** = client-side cross-cluster egress through the east-west SNI-passthrough gateways; **SD bridge** = non-mesh gateway modes resolving mesh workloads via `service_discovery.provider: mesh` and dispatching over the configured destination topology's transport tag.

| Protocol | Sidecar same-cluster (mesh-mTLS `:15006`) | Ambient same-cluster (HBONE `:15008`) | Cross-cluster Sidecar (east-west gateway) | Cross-cluster Ambient (east-west gateway) | Gateway-to-mesh SD bridge (`provider: mesh`) |
|---|---|---|---|---|---|
| HTTP/1.1 | **Supported** — per-service/per-port SVID-mTLS routes, identity-pinned; fail-closed, never plaintext [1] | **Supported** — per-service HBONE routes, capability-probe-gated, identity-pinned [1] | **Supported** — all HTTP-family service ports (per-port `p<port>` SNI alias, issue #2010 phase 3); fail-closed (502) on missing SNI override / trust domain / gateway [2] | **Supported** — all HTTP-family service ports (per-port SNI alias); per-remote-pod targets via the gateway dial-override [3] | **Supported** — `mesh.mtls` (+ authority host/port tags) or `mesh.hbone` targets; poll-interval refresh; sidecar and ambient paths bridge remote-cluster workloads through east-west gateway targets when bridgeable (all HTTP-family ports via per-port SNI alias; otherwise fail-closed) [4] |
| HTTP/2 | **Supported** — same HTTP-family egress; both frontend flavors dispatch over the topology's HTTP/2-based transport [1] | **Supported** [1] | **Supported** — same all-HTTP-family-ports / per-port-SNI-alias bounds [2] | **Supported** [3] | **Supported** [4] |
| gRPC | **Supported** — native gRPC skips the direct-dial gRPC pool and rides the SVID-mTLS HTTP/2 egress path: identity-pinned, `te: trailers` re-synthesized, response streamed so `grpc-status` trailers relay end-to-end; fails closed with gRPC UNAVAILABLE (never a plaintext dial) when the transport cannot dispatch [5] | **Fail-closed** — refused before any dial with gRPC UNAVAILABLE: the HBONE inner protocol is HTTP/1.1 over a byte tunnel and cannot carry the HTTP/2 trailers gRPC requires (native gRPC-over-HBONE is explicitly out of scope; use Sidecar mesh-mTLS for native gRPC, or gRPC-Web pass-through when Ambient transport is required) [5] | **Supported** — native gRPC rides the cross-cluster mesh-mTLS branch (east-west gateway dial + destination-FQDN SNI override + trust-domain-only verification) across **all HTTP-family service ports** (per-port SNI alias, phase 3), HTTP/2 end-to-end so `grpc-status` trailers relay across the two-trust-domain hop; fail-closed (gRPC UNAVAILABLE, never a plaintext dial) on a missing SNI override / trust domain, a retry rotation, or an unsupported transport [5] | **Fail-closed** — HBONE has no HTTP/2 trailer path, cross-cluster or not; refused pre-dial like same-cluster Ambient [5] | **Supported for `topology: sidecar`** (`mesh.mtls` targets dispatch exactly like the Sidecar column, same-cluster and cross-cluster); **fail-closed for `topology: ambient`** (`mesh.hbone` targets refuse native gRPC pre-dial); the HTTP/3 frontend's gRPC bridge fails closed for ANY mesh-tagged target [5] |
| WebSocket | **Supported** — RFC 8441 Extended CONNECT over SVID-mTLS to `:15006`; fail-closed, never plaintext [6] | **Supported** — bare HBONE CONNECT byte tunnel + inner HTTP/1.1 upgrade through the tunnel [6] | **Supported** — RFC 8441 Extended CONNECT over the cross-cluster mesh-mTLS dial (shared `MeshMtlsDialPlan`: east-west gateway dial + destination-FQDN SNI override + trust-domain-only verification) across **all HTTP-family service ports** (per-port SNI alias, phase 3); fail-closed on missing SNI/trust-domain or a failed upgrade, never a plaintext/wrong-SNI dial [7] | **Supported** — the upgrade rides the cross-cluster HBONE byte tunnel (dial the remote east-west gateway with a destination-FQDN SNI override + trust-domain-only verification; inner CONNECT `:authority` = the destination pod addr:app-port) + an inner HTTP/1.1 upgrade through the tunnel, mirroring the HBONE HTTP path via `get_ws_byte_tunnel`; fail-closed **before any dial** on a missing SNI override / trust domain / authority host, or on a failed upgrade [7] | **Supported** — the WebSocket-over-mesh dispatch keys on the same `mesh.mtls`/`mesh.hbone` target tags; a Sidecar OR Ambient SD-bridged east-west failover target now upgrades through the east-west gateway (cross-cluster) [6] [7] |
| Raw TCP | **Supported (Experimental)** — captured orig-dst matched strictly against `(service VIP, service port)`; fresh mesh-mTLS H2 CONNECT tunnel per captured stream; unmatched / unmaterialized pairs fail closed [8] | **Supported (Experimental)** — same strict orig-dst matching, relayed over the shared HBONE pool (capability-probe-gated) [8] | **Supported (Experimental)** — per-pod bare CONNECT over the east-west mesh-mTLS dial; `p<port>.<fqdn>` SNI + trust-domain-only verification; missing dial/authority metadata fails closed [2] [8] | **Supported (Experimental)** — per-pod HBONE byte tunnel through the east-west dial with the same per-port SNI/trust-domain scope [3] [8] | **Not part of the bridge** — SD targets feed HTTP-family dispatch only [9] |
| UDP | **Supported (Experimental)** — TPROXY capture → `udp`-marked mesh CONNECT over mesh-mTLS; unroutable datagrams dropped fail-closed [10] | **Supported (Experimental)** — per-pod-netns TPROXY producer captures source UDP inside each enrolled pod's netns, stamps trusted per-pod evidence on the HBONE CONNECT, and lets destination `mesh_authz` apply namespace/selector scope when the assertor and live workload binding validate; enrolled destination pod replies use a destination pod-netns relay socket when the registry maps the destination IP [10] [12] | **Supported (Experimental)** — the same cross-cluster Sidecar dial carries `udp`-marked, length-delimited datagrams [2] [10] | **Supported (Experimental)** — `get_datagram_tunnel` carries SNI/trust-domain overrides through the east-west gateway; full live TPROXY fixture remains as described in [10] [12] | **Not part of the bridge** [9] |
| DTLS-over-UDP | **Supported (Experimental), opaque** — a DTLS port is declared `protocol: UDP` and rides the same UDP datapath byte-for-byte; the mesh never terminates the DTLS session [11] | **Supported (Experimental), opaque** — rides the same Ambient per-pod evidence/authorization path and destination pod-netns relay socket where applicable; DTLS is framed byte-for-byte and never terminated [10] [11] [12] | **Supported (Experimental), opaque** — identical to the cross-cluster UDP cell; DTLS records are never terminated [2] [10] [11] | **Supported (Experimental), opaque** — identical to the cross-cluster UDP cell [3] [10] [11] [12] | **Not part of the bridge** [9] |

Notes (authoritative sections):

1. HTTP-family egress materialization per topology — the "Implementation status" / multi-port egress bullets under [Topologies → Sidecar](#sidecar). An outbound `404` for an un-materialized destination means no route was built, not that mTLS/HBONE is unavailable.
2. [Client-Side Cross-Cluster Egress (Sidecar)](#client-side-cross-cluster-egress-sidecar): HTTP-family traffic keeps the phase-3 base/per-port scheme. Raw-TCP and UDP use per-pod tunnel targets and explicit per-port aliases (`-tcp` / `-udp` when both share a number), with separate gateway dial and real-pod CONNECT-authority tags. All use trust-domain-scoped verification and fail closed without complete metadata.
3. [Client-Side Cross-Cluster Egress (Ambient / HBONE)](#client-side-cross-cluster-egress-ambient--hbone): per-remote-pod targets cover HTTP-family, raw-TCP, and UDP; L4 uses an explicit per-port SNI alias and the existing byte/datagram tunnel framing.
4. [Gateway Mesh Service Discovery](#gateway-mesh-service-discovery) and [Gateway-to-Mesh Bridge](#gateway-to-mesh-bridge): `topology: ambient` targets carry `mesh.hbone`, `topology: sidecar` targets carry `mesh.mtls` + `mesh.mtls_authority_host` (and `mesh.mtls_authority_port` for multi-port destinations). The two transports are not interchangeable — a topology mismatch fails closed with a 502 at dispatch. Target lists refresh on the provider's poll interval (default 30s). Sidecar-path remote-cluster workloads bridge to east-west gateway failover targets through the same shared core as the mesh-mode Sidecar cross-cluster column [2] (plus the SD-bridge `mesh.mtls_authority_host` tag), for the upstream's **selected** HTTP-family port — any HTTP-family port, via its per-port SNI alias (a single-HTTP-port service uses the base FQDN); a **non-HTTP-family** selected port, a snapshot without `mesh.multi_cluster`, or a remote group with no matching east-west gateway stays skipped fail-closed. Ambient-path remote-cluster workloads bridge through the mesh-mode Ambient per-pod HBONE core [3] when a gateway is declared for the workload network (or a catch-all gateway applies): the target identity is synthetic, the inner CONNECT authority stays the remote pod addr, and `mesh.hbone_dial_host` / `mesh.hbone_port` carry the gateway. Direct remote pod-IP Ambient targets remain only as a flat-network fallback when no gateway is declared for that workload network and no applicable catch-all gateway (a candidate whose `sni_hosts` claim the base FQDN **or** the dialed per-port alias, plus a trust-domain match, for the destination) exists — an exact-network declaration is authoritative fail-closed even when it cannot route the destination, while a non-candidate catch-all leaves the fallback in place.
5. **Same-cluster Sidecar**: a native-gRPC request (content-type `application/grpc*`) whose LB-selected target carries `mesh.mtls` skips the direct-dial gRPC branch in `src/proxy/mod.rs` and dispatches through the generic mesh-mTLS gate + pool (`proxy_to_backend_mesh_mtls`): hyper HTTP/2 end-to-end with pinned peer SVID, streaming request body, `te: trailers` re-synthesized after the hop-by-hop strip (the gRPC HTTP/2 mapping mandates it), and the streaming H2 response arm relays backend trailers (`grpc-status`) after hop-by-hop filtering — the same trailer semantics as the direct gRPC pool. The gRPC receive limit (`FERRUM_MAX_GRPC_RECV_SIZE_BYTES`) caps the request body — declared content-length and streamed bytes alike — with the direct pool's Trailers-Only RESOURCE_EXHAUSTED on overflow, and a `grpc-status` trailer maps into circuit-breaker / passive-health / adaptive-concurrency outcome recording at body EOF exactly like the direct pool (an HTTP 200 + `grpc-status: 14` records as the mapped 503, not a success; Trailers-Only errors are mapped from the header-borne status; a translated gRPC-Web stream is classified from the native trailer before it is body-framed). The client `grpc-timeout` is honored with the direct pool's regimes: for streaming native gRPC and translated gRPC-Web it bounds the response body by an absolute deadline anchored at request receipt; if another response policy explicitly selects the compatible buffered gRPC-Web fallback, the deadline is capped by `backend_read_timeout_ms` and shared across send + body collection. Timeouts return the Trailers-Only DEADLINE_EXCEEDED shape before client-visible translation. Native-gRPC responses are **never buffered** on this path (a buffered mesh response cannot re-emit wire trailers): if buffering is still demanded after the content-type refinement (explicit `response_body_mode: buffer`, or a plugin that needs the response body for this content-type) the request fails closed with a Trailers-Only gRPC UNAVAILABLE — the direct (non-mesh) gRPC path keeps its buffer-with-trailers behavior unchanged. When the mesh-mTLS transport cannot dispatch at all (effective retry config, request-body buffering, missing gateway SVID) the mesh-mTLS dispatch gate fails closed with a Trailers-Only gRPC UNAVAILABLE naming the reason. **Same-cluster Ambient**: the HBONE inner protocol is HTTP/1.1 through a CONNECT byte tunnel (no trailer path — see the WebSocket-over-HBONE inner-HTTP/1.1 note [6]), so native gRPC to a `mesh.hbone` target is refused **pre-dial** with gRPC UNAVAILABLE; native gRPC-over-HBONE is explicitly out of scope for Ambient; Ferrum does not run a nested HTTP/2 client inside the HBONE byte tunnel. Use Sidecar mesh-mTLS for native gRPC, or gRPC-Web pass-through when Ambient transport is required. **Cross-cluster**: for **Sidecar** (`mesh.mtls`), a WELL-FORMED cross-cluster target (carrying the `mesh.eastwest_sni` override AND `mesh.trust_domain`) now falls through onto the mesh-mTLS pool's cross-cluster branch exactly like a same-cluster `mesh.mtls` target (issue #2010), so `grpc-status` trailers relay across the east-west hop; a MALFORMED one (missing SNI / trust domain) fails closed with a clean gRPC UNAVAILABLE rather than reaching a 502. For **Ambient** (`mesh.hbone`) it stays refused pre-dial per the guard at [Client-Side Cross-Cluster Egress (Ambient / HBONE)](#client-side-cross-cluster-egress-ambient--hbone) (HBONE's HTTP/1.1 inner tunnel has no trailer path). The classifier (`classify_grpc_mesh_dispatch`) is the single predicate every gRPC surface consults. A gRPC retry that **rotates** onto a mesh-tagged target also fails closed — mesh transports do not dispatch retries. **Pass-through gRPC-Web** frames its trailers inside the response body (no HTTP/2 trailers needed), so it falls through and rides every mesh transport like plain HTTP. gRPC-Web the `grpc_web` plugin **translated** is wire-native gRPC by dispatch time, so to an Ambient `mesh.hbone` target (same-cluster or cross-cluster HBONE) it is refused pre-dial with the same Trailers-Only gRPC UNAVAILABLE as native gRPC (the HTTP/1.1 inner tunnel would drop its trailers); with the `grpc_web` translation plugin on a Sidecar mesh-mTLS route (same-cluster or cross-cluster), **binary-mode** gRPC-Web works end-to-end: the translated request streams as wire-native gRPC (the gRPC receive limit applies), backend DATA is relayed incrementally, and the shared adapter converts the terminal HTTP/2 trailers into exactly one gRPC-Web body frame. If another response policy explicitly requires buffering, the existing whole-body transform remains the compatible fallback and preserves the folded terminal metadata. **Text-mode** (`application/grpc-web-text`) translation still requires request-body buffering (base64 decode), which the mesh dispatch gates refuse fail-closed (probe slot released) — use binary mode or gRPC-Web pass-through (translate at the destination) for text-mode clients on mesh routes. **HTTP/3 frontend**: the H3 frontend has no mesh transport dispatch, so H3→gRPC bridge requests, H3→HTTP plain-bridge requests, and plain requests selected for the native-H3 backend pool all fail closed before any direct dial when the selected target requires HBONE, mesh-mTLS, or cross-cluster east-west mesh transport; gRPC gets Trailers-Only UNAVAILABLE, plain HTTP gets a 502 with `gateway-error-reason`, and the H3 WebSocket bridge refuses the upgrade with the same 502 shape (note [6]).
   For the Sidecar mesh-mTLS response path in note 5, the operator `backend_read_timeout_ms` window begins only after pool acquisition and `sender.ready()` complete. The receipt-anchored client RPC deadline still covers acquisition and readiness, so slow pool work cannot evade the client's total ceiling while also no longer consuming the operator's response-read allowance.

6. WebSocket egress bullet under [Topologies → Sidecar](#sidecar) ("WebSocket egress (Ambient and Sidecar)"): the dispatch is keyed on the `mesh.mtls`/`mesh.hbone` target tags, identity is pinned, and a mesh-tagged WebSocket target that cannot dispatch over its secured transport fails the upgrade — it is never dialed in plaintext. The H1/H2 frontend re-evaluates the mesh WebSocket fork per connect attempt (including retry rotations); the HTTP/3 WebSocket bridge has no mesh WebSocket transport at all, so it refuses a mesh-tagged target — on the initial selection and on every connect-retry rotation — before dialing, failing the upgrade with a 502 + `gateway-error-reason`.
7. Cross-cluster WebSocket is supported on **both** topologies (issue #2010). **Sidecar** opens an RFC 8441 Extended CONNECT over the cross-cluster mesh-mTLS dial resolved by the shared `MeshMtlsDialPlan` (east-west gateway dial + `mesh.eastwest_sni` SNI override + trust-domain-only verification), the WebSocket analogue of the gRPC/HTTP cross-cluster path. **Ambient** rides the cross-cluster HBONE byte tunnel + an inner HTTP/1.1 upgrade through it, with `get_ws_byte_tunnel` threading the same SNI-override / trust-domain scope as the HBONE HTTP path (`proxy_to_backend_hbone`); the inner CONNECT `:authority` is the destination pod addr:app-port. Both fail the upgrade closed on a malformed cross-cluster target (missing SNI / trust domain), never a plaintext / wrong-SNI dial. See [Client-Side Cross-Cluster Egress (Sidecar)](#client-side-cross-cluster-egress-sidecar) and [(Ambient / HBONE)](#client-side-cross-cluster-egress-ambient--hbone).
8. Raw-TCP egress bullet under [Topologies → Sidecar](#sidecar) ("Raw-TCP egress (original-destination routing, Ambient and Sidecar)"), including the direct pod-IP / headless second index. "Experimental" is the product contract's tier for stream-family egress ([docs/mesh_supported_matrix.md](mesh_supported_matrix.md)).
9. The SD provider publishes ordinary `UpstreamTarget` entries consumed by the gateway's HTTP-family outbound pools ([Gateway Mesh Service Discovery](#gateway-mesh-service-discovery), [Gateway-to-Mesh Bridge](#gateway-to-mesh-bridge)); the raw-TCP and UDP mesh datapaths are original-destination / TPROXY **capture** paths that exist only on mesh-mode capture listeners (see the raw-TCP / UDP egress bullets under [Topologies → Sidecar](#sidecar)).
10. Raw-TCP / UDP egress bullet under [Topologies → Sidecar](#sidecar) plus the "UDP TPROXY capture" section under Capture Modes: UDP egress is dual-transport (Ambient over HBONE `:15008`, Sidecar over mesh-mTLS `:15006`). Both topologies have a source-capture producer: **Sidecar** via the injector's pod-netns TPROXY init rules + current-netns listener; **Ambient** via `NetnsUdpCaptureManager`, which installs the rules and binds capture/reply sockets inside each enrolled pod netns. For Ambient, the node-agent registry now attests the workload SPIFFE ID next to the pod UID; the per-netns producer stamps both as `source.principal` / `source.pod_uid` baggage on the existing authenticated `udp` CONNECT. Destination `mesh_authz` honors pod scope only when (1) the mTLS peer is in the same `trusted_hbone_assertors` allow-list used by TCP/HTTP baggage, (2) the asserted principal passes the existing trust-domain/alias check, and (3) the live slice maps that exact, unambiguous pod UID to the same SPIFFE ID. It then evaluates the **union** of the source-scoped namespace/selector policies for that workload with the destination-scoped policy set that normal (non-UDP) inbound HBONE evaluates (the same policies protecting the destination workload, such as a DENY-all in the service namespace), in a single deny-first pass so a destination DENY/ALLOW still runs for the `udp` CONNECT. Missing/malformed evidence, a missing/duplicate workload binding, a principal/UID mismatch, or baggage from an untrusted peer discards the source stamp and evaluates **mesh-wide source policies only** (still unioned with the destination policy set); it never creates a broader grant from the stamp. **This does not change NodeWaypoint UDP/DTLS**, whose shared-socket/cookie limitation remains mesh-wide-only/disabled under enforcing scoped policy as documented above. The privileged `netns-capture-live` gate exercises the source-capture path through HBONE and verifies the transparent return source; the separate enrolled-destination two-pod fixture remains the residual described in [12].
11. "DTLS passthrough (F3 §3.3 Stage 5) — opaque, never terminated" under the UDP TPROXY capture section: there is no separate `Dtls` `AppProtocol`; the inner DTLS handshake/records are framed and relayed byte-for-byte, with the outer mesh hop's confidentiality coming from HBONE / mesh-mTLS. East-west pod→peer only; external DTLS/UDP egress via the EgressGateway stays out of scope.
12. **Enrolled Ambient destination pod UDP relay.** `handle_hbone_udp_request` resolves the CONNECT authority, checks the open-relay guard, then maps the resolved destination IP through the node-agent registry. When the IP belongs to an enrolled local pod, the destination-side UDP relay socket is created and connected **inside that pod's netns**; delivery to the app and the app's reply are pod-local, so the pod's own OUTPUT `! --dst-type LOCAL` capture rule does not re-capture the reply. If the registry hit cannot be opened safely, the tunnel fails closed with a 502 rather than falling back to the host-netns relay socket. Non-enrolled and loopback destinations keep the host/current-netns socket path. Remaining work is live two-pod `netns-capture-live` coverage for the full Ambient source-capture → HBONE → enrolled-destination relay path.

## Egress Gateway

When `FERRUM_MESH_TOPOLOGY=egress_gateway`, the mesh runtime materializes HTTP-family **and** stream-family (TCP) proxies from `ServiceEntry` resources with `location: mesh_external`.

### Materialization Rules

- Only `MeshExternal` entries are materialized (internal entries are skipped).
- HTTP-family protocols (`http`, `http2`, `grpc`, `tls`) materialize **HTTP-family** proxies: host-routed off the shared egress listener (mTLS termination at `egress_listen_addr`, default 15090). One proxy per host across all ports — host-only routing cannot disambiguate multiple ports under the same host.
- Stream-family protocols (`tcp`, `mongo`, `redis`, `mysql`, `postgres`) are **opt-in** via `FERRUM_MESH_EGRESS_STREAM_ENABLED=true` (default `false`). When the flag is off, stream-family ports are skipped with a warning and only HTTP-family egress materializes. When the flag is on, each stream-family port materializes its own TCP proxy (T5-A) on the ServiceEntry's destination port (e.g., `mongo.external.io:27017/TCP` produces a TCP listener on port 27017). **Each stream egress listener terminates SVID-mTLS and runs `mesh_authz` at accept** — the same authn/z as HTTP egress: the materialized stream proxy is `frontend_tls: true` and uses the SAME mesh-inbound `ServerConfig` (server identity = gateway SVID leaf+key, peer verifier = SPIFFE against the trust bundle) that backs the egress 15090 HTTP listener, shared via the stream listener manager's TLS slot (`set_frontend_tls_config` / live `swap_frontend_tls_config`). After the handshake, the injected `__mesh_spiffe_identity` stream hook extracts the peer SPIFFE id from the verified client cert and `__mesh_authz` enforces policy **before the external backend is dialed** (TLS-terminating frontends complete crypto/admission before backend dispatch). **A client certificate is required, not optional:** because the egress gateway is a security boundary onto external networks, `resolve_mesh_inbound_client_auth` escalates a `PERMISSIVE` `PeerAuthentication` (the default when no STRICT policy is in force) to `Required` for this topology, so a cert-less TLS client is **rejected at the handshake** instead of being admitted to the external backend — the shared `ServerConfig` is built with required client auth, which is why the same protection also covers the sibling 15090 HTTP-family mTLS listener. (If `PERMISSIVE` somehow resolves with no trust anchor at all, the listener cannot authenticate clients and **fails closed** with a hard error rather than serving optional-no-verify mTLS; `validate_egress_gateway_mtls_config` already requires a peer verifier at config time, and the escalation is reapplied on `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true` slice apply so a reload cannot downgrade it.) **Fail-closed:** if no mTLS `ServerConfig` is loaded the stream listener manager *defers* the per-port bind (it never binds plaintext), mirroring the inbound posture (`enforce_mesh_inbound_fail_closed`); under `FERRUM_MESH_PRODUCTION_MODE=true` a no-identity egress gateway is already refused at startup by the inbound fail-closed gate. The explicit opt-out `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true` restores the legacy plaintext + unauthenticated listener (`frontend_tls: false`) for operators who genuinely need it, with a loud startup warning — without compensating network controls, any pod that can reach the gateway then reaches the external service through it with no SPIFFE authn/z. One proxy per port; same-port collisions across ServiceEntries skip the second entry with a warning. Multi-port stream ServiceEntries bind each port separately. ServiceEntry ports that collide with the egress gateway's own listener port (`egress_listen_addr.port()`, default `15090`) or port `0` are skipped with a warning rather than emitted — letting them through would fail to bind at runtime (`EADDRINUSE`) and reject the entire slice apply.
- Mongo / Redis / MySQL / Postgres are TCP-based at the wire level; the protocol tag is preserved on `Proxy.name` for observability but **no protocol-aware mediation** (e.g., MongoDB wire-format inspection) is performed. Protocol-level mediation is tracked separately.
- DNS-resolution entries use ServiceEntry hosts as backend targets; static-resolution entries use endpoint addresses. Stream-family proxies pin to the first host (DNS) or all endpoints (Static) — a raw L4 listener cannot distinguish hosts (no SNI for plain TCP), so multi-host external services should be split into one SE per host.
- HTTP-family materialized proxies use host-only routing (no `listen_path`), `preserve_host_header: true`, and passive health checks. Stream-family proxies use port routing (no `hosts`), `passthrough: false` (the per-port stream listener terminates SVID-mTLS itself — the sidecar mTLS boundary IS this listener, sharing the same `ServerConfig` as the sibling 15090 HTTP-family mTLS-termination listener; this is NOT raw SNI passthrough, that flow lives in the east-west gateway), `frontend_tls: true` by default (or `false` under `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true`), and passive health checks.
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

Istio `Sidecar` resources narrow which mesh service configuration a workload receives for egress. Ferrum translates the egress portion of a `Sidecar` into a `MeshSidecar` record and applies it at slice build time. The `Sidecar.ingress[]` block (custom inbound listeners) is also modeled — see [Sidecar Ingress Listeners](#sidecar-ingress-listeners) below.

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

The `host` portion may itself be a single-label DNS wildcard (e.g. `*/*.example.com` admits `api.example.com` but not `example.com` nor `a.b.example.com`). This follows Istio Sidecar and Ferrum mesh DNS proxy semantics; proxy listener host matching uses broader DNS suffix wildcard semantics for Gateway API conformance. `MeshService` entries match their short name, `{name}.{namespace}`, `{name}.{namespace}.svc`, and `{name}.{namespace}.svc.{cluster_domain}` aliases. On the control plane this suffix follows `FERRUM_K8S_CLUSTER_DOMAIN`; in local mesh mode it follows `FERRUM_MESH_CLUSTER_DOMAIN`.

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

The `mesh_outbound_registry` plugin exposes `ferrum_mesh_outbound_registry_decisions_total` with `mesh_namespace`, `host`, and `decision` labels. To keep label cardinality bounded, every `host` value is one of three fixed buckets: `host="<admit_explicit>"` for admits matched by an exact registry entry, `host="<admit_wildcard>"` for admits matched by a one-label wildcard entry, and `host="<denied>"` for every deny (the request Host header is attacker-controlled on that path). Operators can compare admit-vs-deny rates per namespace during rollout, but not per destination hostname — consult application logs for the requested host of denied traffic. Under effective `REGISTRY_ONLY`, outbound-capture HTTP route misses take the same configured reject status and deny-bucket metric as plugin-path denials.

Stream-family egress (TCP / UDP / TCP+TLS / UDP+DTLS) is enforced at the connect / first-datagram stage rather than via a plugin: when `outbound_traffic_policy: registry_only` is active and the gateway owns at least one mesh outbound capture listener port, stream proxies bound to those ports consult the same slice-derived registry before dialing the backend. Rejection semantics differ from HTTP:

- **TCP / TCP+TLS**: graceful close of the inbound connection before any backend dial happens. No SYN ever leaves the gateway, so backend circuit breakers, pool entries, and DNS caches stay untouched by hostile traffic. `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS` does not apply — TCP has no "HTTP status" concept.
- **UDP / UDP+DTLS**: the first datagram of a would-be new session is silently dropped (UDP has no RST analogue). Existing sessions are unaffected; the check only runs on session creation. DTLS handshakes are not initiated for unadmitted destinations.

Stream decisions are exported via a sibling counter `ferrum_mesh_outbound_registry_stream_decisions_total` with `mesh_namespace`, `protocol`, and `decision` labels (`protocol` ∈ {`tcp`, `tcp_tls`, `udp`, `udp_dtls`}). Keeping it as a sibling rather than adding a `protocol` label to the HTTP counter preserves Wave-1 dashboard compatibility. Stream rejects do not include a per-host label — the protocol label is the only dimension dashboards need, and TCP closes happen before SNI / Host material is structured. Operators triaging denied stream traffic should consult the gateway's structured `warn!` logs (one per reject) which include `backend_host`, `backend_port`, `listen_port`, and the client IP.

Enforcement is keyed on the runtime's mesh outbound capture listener port set. Stream proxies bound to other ports (inbound, admin, HBONE, east-west gateway, egress gateway) flow through unchanged — outbound policy never gates inbound traffic.

## Sidecar Ingress Listeners

Istio's `Sidecar` resource has an `ingress[]` block letting a workload declare custom inbound listeners: each entry has a `port` (number + protocol + name), an optional `bind` address, and a `defaultEndpoint` (where inbound traffic to that listener is forwarded). Ferrum models these on the **inbound** side, reusing the per-port inbound loopback sibling machinery (the same path that serves the default `:15006` service-port routes).

`Sidecar` resources are always parsed/persisted; ingress materialization is **applied only under `FERRUM_MESH_SIDECAR_ENFORCED=true`** (the same gate as egress narrowing) and **not** under `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN=true` (dry-run reports egress scope but changes nothing — materializing inbound listeners is a behavior change). The applicable `Sidecar` is resolved with the same tier precedence as egress (workload-scoped → root workload-scoped → namespace-default → root-namespace-default, ASCII-smallest `name` tiebreak), but ingress is always taken from the selected `Sidecar`'s own `ingress[]` (it does not follow the egress `inherits_defaults` chain — an **omitted** `ingress` keeps the default inbound listeners, whereas a **declared** `ingress` — even an explicit empty `ingress: []` — replaces them; see [Precedence vs. the default inbound listeners](#precedence-vs-the-default-inbound-listeners-fail-closed)).

### Materialization model

Each modeled ingress entry becomes one inbound loopback route:

- **hosts** — the union of the local workload's own service FQDN variants (`{name}`, `{name}.{ns}`, `{name}.{ns}.svc`, `{name}.{ns}.svc.{cluster_domain}`). Istio only configures ingress "if and only if the workload is associated with a service"; when no local service resolves (e.g. EndpointSlice lag), the listener is dropped fail-closed (no host-less catch-all route).
- **backend** — the entry's `defaultEndpoint`, resolved to a loopback `host:port` (see supported forms below).
- **listen path** — `/` (the route is selected by host, then disambiguated by port).
- **port disambiguation** — on Ferrum's shared `:15006` inbound listener, the captured original destination (the port the client dialed) **and** a peer sidecar's request authority are matched against the **declared listener port** (not the `defaultEndpoint` port, which is the separate forward target). This reuses `select_mesh_inbound_port_route`: multiple ingress listeners on one workload are siblings disambiguated by listener port, and a request that addresses no declared listener port fails closed with `502` rather than being routed to an arbitrary backend.

- **authorization port** — `mesh_authz` authorizes an ingress listener on its **declared listener port** (e.g. `8443`), not the `defaultEndpoint` backend port (e.g. `8080`). An `AuthorizationPolicy` `to.operation.ports` / `when: destination.port` rule scoped to the listener port therefore matches; authorizing on the backend port would let an ALLOW miss and — worse — a port-scoped **DENY fail open**. (Service-port default inbound routes keep authorizing on the container/backend port, matching Istio inbound authz.) The listener port is stamped onto the request at port selection and read by authz; if it is somehow unavailable for an ingress route, authz fails closed (it never falls back to the backend port).

### Precedence vs. the default inbound listeners (fail-closed)

Per Istio, when `ingress` is **declared** it **replaces** the workload's default per-service-port inbound listeners. Ferrum mirrors this and **fails closed on the declared signal, not on what resolved**: if the applicable `Sidecar` declares an `ingress` block, the inbound materializer emits routes **only** from the resolved `ingress[]` listeners and skips the service-port default `:15006` → `127.0.0.1:targetPort` materialization for that workload — **even if every entry was unsupported and nothing resolved**. An all-unsupported `ingress[]` therefore yields **no inbound routes** for the workload rather than silently exposing the default service-port routes the operator explicitly replaced (exposing them would be a fail-open regression).

**Omitted vs. explicit-empty `ingress` (Istio-faithful):** an **omitted** `ingress` block keeps the automatic per-service-port inbound defaults, while a **declared** `ingress` — *including an explicit empty `ingress: []`* — configures the workload's inbound listeners explicitly and replaces those defaults. So `ingress: []` suppresses the default inbound routes (the operator declared "no custom inbound listeners"), the same as a non-empty-but-all-unsupported list; it does **not** fall back to the service-port defaults. The K8s translator records `ingress` presence (mirroring `egress`'s omitted-vs-explicit-empty distinction); on the native source a non-empty list always declares, and an explicit `ingress_declared: true` carries the empty-but-declared case. Only a workload whose applicable `Sidecar` **omits** `ingress` entirely keeps the default service-port inbound behavior. This avoids any silent host+path conflict — the two never coexist for one workload. The "ingress was declared" marker is tracked separately from the resolved-listener list and rides its own ECDS carrier so it survives an empty resolved list on the xDS path.

The resolved listeners that ride the slice are **re-validated before dialing**: a `local_ingress_listeners` entry can arrive already resolved over the xDS/native carrier, so the materializer (and the router's sibling grouping) re-check each carried `endpoint_host`/`endpoint_port` against the same loopback-host + nonzero-port allowlist `MeshSidecarIngress::resolve` enforces. A malformed or hostile carrier pointing a listener at an off-box host or a `:0` backend is dropped fail-closed (never dialed), so the carrier path enforces the same invariant as CP-side resolution.

### Supported and deferred `defaultEndpoint` forms

`defaultEndpoint` is resolved fail-closed; an entry that does not map cleanly onto a loopback `host:port` HTTP route is **not** materialized and is reported in the `Sidecar` `status.ferrum.translation.deferred_fields` (the resource is still accepted):

| `defaultEndpoint` / listener | Behavior |
|---|---|
| `127.0.0.1:PORT`, `[::1]:PORT` (loopback) | Modeled; dials that loopback address + port (address family preserved). |
| `0.0.0.0:PORT`, `[::]:PORT` (instance IP) | Modeled; mapped to loopback (`127.0.0.1` / `::1`) — the sidecar app shares the pod network namespace. |
| Recognized HTTP-family `port.protocol` (`http`/`http2`/`grpc`/`grpc-web`/`https`) | Modeled — `https` is a TLS-terminated HTTP-family listener and is materialized. |
| `unix:///path/to/socket` | **Deferred** — Ferrum's backend model is `host:port` only; not representable. |
| Arbitrary off-box IP (`10.0.0.5:PORT`) | **Deferred** — Istio forbids arbitrary IPs; Ferrum's loopback-only model will not dial off-box. |
| Non-HTTP-family `port.protocol` (`tcp`/`tls`/`mongo`/…) | **Deferred** — raw-TCP inbound has no Host/route and is not modeled here. |
| Missing or **unrecognized** `port.protocol` (e.g. a `HTPS` typo) | **Deferred** — a custom inbound listener routes only *recognized* HTTP-family protocols; a missing protocol (Istio defaults an unset port to TCP) or a mistyped string is **not** guessed as HTTP and is reported as a deferred non-HTTP listener, so it is never exposed on the HTTP request path. (The service-port default path keeps the `unknown → HTTP` convention for auto-discovered ports; this stricter rule applies only to explicitly declared `ingress[]` listeners. On the native source a mistyped `protocol` fails deserialization outright.) |
| Omitted / empty `defaultEndpoint` | **Deferred** — Istio allows omitting it (the native model also accepts an omitted field, defaulting to empty); with no forward target there is nothing to route. |

The status writer reports the count of modeled listeners as `status.ferrum.translation.ingress_modeled` and lists deferral reasons in `deferred_fields`. The HTTP-family classification is shared by translation/resolution and the status writer (one predicate), so a modeled listener is never falsely reported as a deferred non-HTTP listener (and vice-versa). A listener `port` of `0` is a hard validation error (rejected), not a deferral.

### `bind` and `captureMode` limitations

- **`bind`** — Ferrum's capture model funnels all inbound through the shared `:15006` listener (matched by captured original destination = the dialed listener port), so a custom `bind` address does **not** open a separate OS listener; it is preserved on the parsed model for observability. Unix-socket `bind` values are invalid (Istio rejects them too).
- **`captureMode`** — Ferrum assumes `IPTABLES`/`DEFAULT` capture (the sidecar redirect model). `captureMode: NONE` (the app handles capture itself) is not separately honored; the listener-port disambiguation relies on the captured original destination or the request authority port being present.

### xDS / file / native parity

The resolved listeners ride the slice as `local_ingress_listeners` (computed CP-side, since raw `MeshSidecar` records do not ride the slice — only the resolved view does, mirroring `local_inbound_services`). On xDS they ride a dedicated ECDS carrier (`LocalIngressListenersCarrier`); the fail-closed "ingress was declared" marker rides its own carrier (`SidecarIngressDeclaredCarrier`) so an all-unsupported `ingress[]` still suppresses the default routes on the DP even with an empty listener list. On the native and `FERRUM_MESH_CONFIG_PROTOCOL=file` sources the same `MeshSlice::from_gateway_config` builder resolves them, so an xDS-built slice stays functionally equivalent to a native-built one.

Ingress resolution is **decoupled from egress-scope inheritance**: a Sidecar that declares only `ingress[]` usually omits `spec.egress` (so it inherits the egress default), and when no namespace/root default exists no egress scope applies — but the ingress listeners still resolve, and the local-inbound service view that anchors their host identity is resolved independently of whether an egress scope was applied. An ingress-only workload Sidecar therefore models its listeners correctly instead of falling back to default inbound routing.

## Config Drift Introspection

`GET /mesh/config-drift` is a JWT-authenticated admin endpoint that surfaces a per-DP "where is this DP relative to the CP's last push?" view. Pair it with `ferrum_mesh_config_last_received_timestamp_seconds` (the gauge the GAP-3E Grafana dashboards already alert on) to triage stuck DPs — the metric tells you when the alert tripped; the endpoint tells you what slice content the DP actually applied.

The response always carries a `slice` block. After the first proxy-accepted slice it carries:

- `last_received_at` / `age_seconds` — wall-clock timestamp + seconds since the most recent proxy-accepted slice. Received-but-rejected updates do not advance this field or the fingerprint. `age_seconds` clamps to zero on backwards clock skew so an alert never fires on a future-stamped slice.
- `version` / `namespace` — the slice's own `version` string and `namespace` field, surfaced for self-describing cross-DP diffs.
- `resources` — counts per resource kind (workloads, services, mesh_policies, peer_authentications, service_entries, request_authentications, destination_rules, mesh_telemetry, mesh_proxy_configs, extension_configs). Always present; defaults to all zeros before the first slice so the shape is stable for dashboards.
- `fingerprint` — `sha256-<64 hex>` over a deterministic JSON encoding of the last proxy-accepted slice with per-DP identity metadata (`node_id`, `workload_spiffe_id`, `waypoint_name`, `labels`), `version`, and `runtime_overlay` stripped. Two DPs in the same namespace expecting the same resources produce the same fingerprint even when the CP re-stamps a no-op publish; divergence flags split-brain. The hash strips the overlay because RTDS-driven knobs (fault percentages, log level, transformer gates — see "xDS ADS Compatibility / RTDS") intentionally hot-swap without a new slice version; drift in the overlay surfaces under `runtime_overlay` instead.
- `source_protocol` / `source_cp_url` — configured source from `FERRUM_MESH_CONFIG_PROTOCOL` and the first entry of `FERRUM_DP_CP_GRPC_URLS`. Populated even before the first slice so dashboards can label DPs by source.

The optional `runtime_overlay` block (default included) summarises the live RTDS overlay as `{ key_count, keys, fingerprint }` where `keys` is the sorted list of overlay keys currently in effect and `fingerprint` hashes the typed overlay values. Pass `?include_overlay=false` to omit the block for high-frequency drift polling that only needs the slice fingerprint.

The optional `convergence` block is present only when `FERRUM_MESH_CONFIG_PROTOCOL=xds` and at least one ADS response has arrived; in native mode it is omitted entirely. It surfaces the xDS [resource-warming](#xds-ads-compatibility) state: `per_type_versions` (received `version_info` per subscribed type, keyed by short name — `cds`/`eds`/`lds`/`rds`/`sds`/`ecds`/`rtds`), `missing_required_types` (required types still awaiting an initial response — empty once the first slice can build), `converged` (every required type has responded **at one coherent `version_info`** — no required type missing and no version skew), and `version_skew` (all required types have responded but their `version_info` strings are **not** all identical). `converged` and `version_skew` are mutually exclusive: a skewed required set is a transient *waiting* state, not an applied one — the DP keeps serving the prior slice via `ArcSwap` and does not build a new one until the required versions reconverge. Because the CP force-refreshes every subscribed required type to one snapshot version on any required-mesh-slice change (including a policy/workload-only ECDS update), skew normally clears within a debounce window; a `version_skew` that persists points at a CP advancing required types independently of the ECDS security carriers and is worth investigating as config drift. This detail is exposed only by the JWT-authenticated drift endpoint because the version strings embed config-change timestamps and content digests; the aggregate `ferrum_xds_warming_partial_applies_total` counter is the low-cardinality companion signal on authenticated `/metrics`.

The endpoint returns 404 outside mesh mode and 200 with `last_received_at` elided / zeroed `resources` when mesh mode is active but no slice has been accepted yet — operators rely on the difference between "404 (wrong mode)" and "200 with no `last_received_at` (mesh mode, not converged yet)".

Operator playbook:

- **Spot a stuck DP**: walk every DP in a deployment, compare `slice.last_received_at`. A significantly older timestamp on one DP flags a missing CP→DP stream. A safe upper bound is `slice.age_seconds > 2 * FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS` (default 600 s with the 300 s primary retry); operators expecting steadier CP push cadence should tighten the threshold to a small multiple of their observed push interval.
- **Spot split brain**: walk every DP, compare `slice.fingerprint`. All DPs in the same namespace expecting the same resources should agree — divergence means at least one DP is on a stale or wrong slice. Operators can recompute the fingerprint offline by (1) serialising the slice JSON with `node_id`, `workload_spiffe_id`, `waypoint_name`, `labels`, `version`, and `runtime_overlay` stripped, (2) recursively sorting object keys (`BTreeMap`-style) while preserving array order, (3) SHA-256 hashing the resulting bytes, and (4) prefixing the lower-case hex digest with `sha256-`.
- **Spot RTDS drift**: compare `runtime_overlay.keys` and `runtime_overlay.fingerprint` across DPs. Missing keys point to subscription or layer merge issues; matching keys with different fingerprints mean a same-key runtime value diverged.
- **Spot a wedged xDS DP**: when `convergence.converged` is `false` with a non-empty `convergence.missing_required_types` on a starting DP, the first slice is blocked waiting on those types — cross-check `ferrum_xds_first_slice_nacks_total` for a malformed required resource (NACK loop) versus a CP that is simply not sending that type (no NACKs, type stays missing).

A CP-side endpoint that reports what slice version the CP last published to each connected DP (so external tooling can diff "what the CP thinks each DP should have" against "what each DP reports here") is future work; this endpoint covers the DP-local half of the drift picture.

## Authoritative Config Revisions And Stale-Fallback Rejection

Multi-CP failover must never move a data plane *backwards*. A fallback control plane that missed a poll, is partitioned from the config store, or is simply lagging still serves a structurally valid slice — and installing it would reinstate deleted routes, endpoints, authorization policies, or trust material until failback. The slice `version` cannot arbitrate that: it is a rendering of the serving CP's local `GatewayConfig.loaded_at` wall clock, so it is not comparable across replicas, clock skew, or process restarts.

Mesh slices therefore carry an authoritative **config revision** alongside `version`:

```
revision = (authority, sequence)
```

- **`authority`** names the ordering *domain*. Sequences are only comparable within one authority. Every CP replica reading the same config store advertises the same value (`FERRUM_MESH_CONFIG_AUTHORITY_ID`, default `db`), which is exactly what makes a primary's and a fallback's slices comparable.
- **`sequence`** is a durable `config_changes` change-log cursor — not a clock and not a process-local counter. Its *domain* follows CP scope so identical-scope replicas stay convergent across restarts:
  - Explicit `CpScope::Single` / `Set`: the maximum durable `latest_change_sequence(namespace)` over the configured namespaces — the same cursors incremental polling advances from. An unrelated namespace outside the scope cannot advance a restarted replica ahead of its still-running peer.
  - `CpScope::All`: the store-wide `config_changes` high-water mark, because the dynamically discovered namespace list can shrink after the last resource in a namespace is deleted; without the global watermark a restarted All-scope CP would rewind. An in-process floor additionally protects full reload while the process is alive.

Every namespace cursor—and, for sequenced `All`, the store-global watermark—is captured **before** the corresponding full resource loads begin. This is deliberately conservative across SQL snapshot transactions, replica-set Mongo snapshot transactions, and standalone Mongo's sequential reads: a write that commits after the boundary may already appear in the full snapshot and be harmlessly replayed by the next incremental poll, but an older snapshot can never be stamped with that later write's sequence or advance the polling cursor past it. In explicit `Single`/`Set` scope, a namespace whose boundary cannot be read is demoted independently: its resource load is skipped, its last-known-good resources and cursor are retained, and healthy namespaces continue. Sequenced `All` scope retains the entire prior snapshot on any boundary, load, or validation failure because a partial LKG aggregate cannot safely claim the store-global watermark. Unsequenced `All` scope (including a CP with the Kubernetes controller enabled) publishes no global revision, so it retains the same per-namespace LKG continuation: failed tenants keep their resources and cursors while healthy tenants refresh. The in-process floor is applied only after these safe captures as a monotonic lower bound; it is not a substitute for boundary ordering.

The revision rides `MeshConfigUpdate.config_authority` / `config_sequence` on the native `MeshSubscribe` envelope (a duplicate of the slice's own value, validated for agreement exactly like `version`) and, on the xDS path, its own ECDS carrier (`ConfigRevisionCarrier`) so a native-built and an xDS-built slice materialize identical ordering metadata and pass through the same data-plane gate. Native remote-cluster discovery applies the same comparison per remote source after endpoint validation and before replacing last-good remote endpoints.

### Comparison contract

The data plane records the revision of the slice it accepted and compares every candidate **before** the `ArcSwap` replacement:

| accepted | candidate | outcome |
|---|---|---|
| none | no revision (genuinely absent) | install (bootstrap) |
| none | well-formed revision | install (bootstrap) |
| any | present but ill-formed (blank / surrounding-whitespace / over-long / control-character authority) | **quarantine** (`malformed_revision`) — never silently downgraded to absent |
| some | no revision | **quarantine** (`missing_revision`) |
| same authority | `sequence >` accepted | install |
| same authority | `sequence ==` accepted | install (reconnect replay / republish) |
| same authority | `sequence <` accepted | **quarantine** (`stale_revision`) |
| other authority | any | **quarantine** (`incomparable_authority`) |

Equal sequences must install: reconnecting to the same CP replays that CP's initial slice at the unchanged revision, and quarantining it would break every ordinary reconnect.

A **present but ill-formed** revision is distinct from an absent one. Centralized `MeshConfigUpdate` validation refuses an embedded (or envelope) ill-formed revision before install, and `MeshRevisionGate::admit` refuses the same shape even on bootstrap — including the xDS path, which reaches the shared gate without that update validator. Filtering an ill-formed authority to "absent" would otherwise let a hostile first frame with an empty envelope stamp pass as consistently unversioned, install, and retain no watermark. On the envelope, distinguish raw empty (`config_authority=""`, the proto default — genuinely absent) from raw non-empty whitespace (`"   "`): the latter is present/malformed and rejected with a bounded static diagnostic that does not echo the authority text. Genuinely absent revisions remain valid for unsequenced authorities (K8s controller / file protocol).

A quarantined candidate mutates nothing — the last-good slice keeps serving, the receive metric and `last_received_at` do not advance, and no watcher is woken. On the native stream a quarantine also **drops the stream** so multi-CP failover moves off the lagging control plane; staying attached would only let it keep serving stale generations.

On the xDS path the ADS response was already folded into the resource accumulator and ACKed before the slice was rebuilt, so the gate does not rewind it. That is deliberate: rewinding would desynchronize local state from versions already ACKed. A revision quarantine instead terminates ADS and triggers the existing multi-CP rotation. The accumulator is state-of-the-world state scoped to a single control-plane URL and is cleared wholesale on failover (`reset_for_new_control_plane`), so a quarantined CP's resources cannot mix into the next CP's slice. The last-good live slice remains untouched throughout.

### Received versus applied (candidate lifecycle)

Passing the freshness gate makes a slice the *received* candidate, not the serving one. The mesh proxy runtime is a second, independent gate: slice→config preparation or the proxy config apply can still refuse it, leaving the previous generation live. The gate therefore tracks two watermarks, both on `GET /mesh/config-drift`:

- **`accepted`** — the highest revision admitted into the received slot. This is what candidate comparison runs against, so a burst of updates still orders correctly while an earlier one is mid-apply.
- **`applied`** — the revision of the slice the proxy runtime last accepted. This is the authoritative last-good generation.

When the runtime accepts a candidate, `applied` advances to it (including a content-no-op or equal-revision replay, where the runtime accepts with no config delta). When the runtime **refuses** one, `accepted` is rolled back to `applied`, so every revision between them stays eligible. Without that rollback, a single runtime-invalid slice published at a far-future sequence would advance the watermark past every valid revision beneath it and block recovery with a generation that never served a request — the exact lockout the reset endpoint exists to avoid needing. The rollback is keyed to the exact received candidate (`(authority, sequence)` equality plus received-slot identity), so a *late* rejection of N never disturbs an N+1 that arrived while N was being applied. A candidate refused before anything was ever applied returns the gate to no baseline at all, rather than poisoning startup and fallback. Runtime apply work also captures a gate-epoch token before asynchronous preparation; reset advances the epoch, so a pre-reset apply that completes late can update the serving-content snapshot without resurrecting either cleared watermark.

### Intentional rollback

Rolling configuration back is a **write**: it allocates new change-log sequences, so it reaches data planes as a *higher* revision carrying older content and installs normally. Replaying an old generation to move a data plane backwards is never a supported operation.

### Reset semantics (no permanent lockout)

Two escape hatches, both explicit:

- A **foreign authority** observed continuously for `FERRUM_MESH_CONFIG_REVISION_ADOPT_SECS` (default 300 s, `0` disables) is adopted with a `warn!` and a bump of `ferrum_mesh_config_revision_adoptions_total`. The grace uses a monotonic process clock; NTP or manual wall-clock jumps cannot expire it early. This covers CP state loss and a deliberate source reset without an operator round trip.
- `POST /mesh/config-revision/reset` (JWT + `operator` role) clears the accepted revision so the next slice from any authority is eligible. This is the documented recovery for the one case that is never auto-adopted: a sequence rewind *inside* one authority — a config store restored from backup without bumping `FERRUM_MESH_CONFIG_AUTHORITY_ID`. Auto-adopting that would be indistinguishable from the rollback the gate exists to prevent. The reset installs nothing itself; the next slice still has to pass subscription binding and update validation.

### Observability

- Authenticated `/metrics`: `ferrum_mesh_config_revision_rejections_total{reason}` with `reason` ∈ `stale_revision` / `incomparable_authority` / `missing_revision` / `malformed_revision`, and `ferrum_mesh_config_revision_adoptions_total`. These process counters aggregate the local slice gate and native remote-discovery gates. Fixed cardinality — no CP-supplied authority string or sequence number reaches this surface.
- `GET /mesh/config-drift` (JWT): the `revision` block carries the accepted and applied `(authority, sequence)` watermarks, the most recent quarantine (authority, sequence, reason, consecutive count, first/last seen), the totals, the effective adopt grace, and `quarantine_active` — the "stale fallback quarantined" signal to alert on. Every authority rendered on this surface — and in the reset response and its audit log line — is control-character-stripped and truncated to 64 characters; the raw control-plane string never leaves the gate, where exact ordering comparisons need it. An authority that is blank, has surrounding whitespace, is over-long, or contains control characters is refused as `malformed_revision` at the boundary and never becomes a watermark at all.

### Scope and residuals

- **Unsequenced authorities.** A CP running the Kubernetes CRD controller (`FERRUM_K8S_CONTROLLER_ENABLED=true`) publishes **no** revision: the controller reconciles CRDs into the in-memory snapshot on its own cadence with no cross-replica monotonic sequence to order against (a max-over-live-objects `metadata.resourceVersion` *decreases* when the highest-versioned object is deleted, and per-replica high-water marks diverge). Mixing sequenced DB snapshots with unsequenced controller snapshots inside one authority would make the gate flap, so such a CP publishes nothing and data planes apply no cross-CP ordering — the pre-existing behavior. Giving the K8s authority a shared monotonic revision (an informer list/bookmark `resourceVersion` watermark) is follow-up work. The same applies to `FERRUM_MESH_CONFIG_PROTOCOL=file`, which is inherently local and ordered by the operator's own edits.
- **One store per authority, and matching CP scope.** Two CPs pointed at *different* config stores while advertising the same `FERRUM_MESH_CONFIG_AUTHORITY_ID` is a misconfiguration the gate cannot detect — their sequences are not comparable but claim to be. Give distinct stores distinct authority ids. Likewise, the replicas a data plane lists in `FERRUM_DP_CP_GRPC_URLS` must share a `FERRUM_CP_NAMESPACES` scope: differently scoped replicas can serve different content and must not claim equal revisions. Within one shared scope, full-load stamping uses the scope's sequence domain (max of explicit namespace cursors for `Single`/`Set`; store-global high-water mark for `All`) plus an in-process floor, so identical-scope replicas converge across restarts and an All-scope namespace disappearance cannot rewind publication. Native `MeshSlice::content_eq` deliberately ignores `revision`, so a revision-only stamp change does not fan out frames to already-subscribed clients.
- **Remote-cluster discovery.** The multicluster remote-endpoint poller validates envelope/slice agreement through the shared validator and keeps a per-cluster revision gate across one-shot reconnect polls and source-identity rotations. Endpoint content and trust-domain boundaries are validated before provisional admission; the applied watermark commits only after the generation-checked endpoint-store install (including a live dedup), and a retired generation rolls admission back. Thus an invalid or non-installed far-future slice cannot poison recovery; stale/missing/foreign revisions fail the poll and preserve last-good endpoints. Removing the cluster declaration drops its endpoints and prunes its gate, while a still-declared URL/credential rotation retains the gate. The same `FERRUM_MESH_CONFIG_REVISION_ADOPT_SECS` policy controls foreign-authority adoption.

## DestinationRule

Istio `DestinationRule` resources are translated into Ferrum upstream and proxy configuration at the Kubernetes translation layer. The following fields are supported:

### Traffic Policy

- **`connectionPool.tcp.connectTimeout`**: mapped to the proxy's `backend_connect_timeout_ms`.
- **`outlierDetection`**: translated to Ferrum passive health checks (`unhealthy_threshold` / `unhealthy_window_seconds` / `healthy_after_seconds` / `max_ejection_percent`). Automatic recovery after `baseEjectionTime` is scoped to the ejecting proxy and the **effective** per-port / subset / upstream policy that caused the ejection (deadline stored on the entry; independent cooldowns when two proxies share an endpoint; SD-discovered targets recover the same way as static ones). See [Passive Health Checks](load_balancing.md#passive-health-checks).

### Load Balancer

Simple load balancer algorithms are mapped directly:

| Istio `simple` | Ferrum algorithm |
|---|---|
| `ROUND_ROBIN` | `round_robin` |
| `LEAST_REQUEST` / `LEAST_CONN` | `least_connections` |
| `RANDOM` | `random` |

Consistent hash load balancing (`consistentHash`) is translated to Ferrum's `consistent_hashing` algorithm with the hash key derived from `httpHeaderName`, `httpCookie`, or `useSourceIp`.

### Subsets

DestinationRule `subsets` are preserved as named subsets in the Ferrum upstream. Each subset can carry a `loadBalancer` override that takes precedence over the top-level traffic policy. Subset-level `tls` is also applied per subset: the cold-path apply layers the subset's TLS overlay onto the upstream-level TLS and stores the result on `Upstream.resolved_subset_tls[subset_name]`. `GatewayConfig::resolve_upstream_tls` then projects that overlay onto `Proxy.resolved_tls` for proxies whose `upstream_subset` selects the subset, so two proxies pointed at the same upstream but at different subsets (each carrying distinct `caCertificates` / `clientCertificate` / `privateKey` / `sni` / `subjectAltNames`) land on different resolved TLS values and partition the backend pool. Subset-level `outlierDetection` is applied in full onto that same `resolved_subset_tls` overlay (thresholds + `maxEjectionPercent`, with automatic recovery honoring the subset `baseEjectionTime`); subset-scoped `connectionPool.http.{h2UpgradePolicy,maxRetries}` remain deferred-and-warned — see the DestinationRule status table above.

### Deferred Fields

Top-level and per-subset DestinationRule TLS settings (`trafficPolicy.tls`, `subsets[].trafficPolicy.tls`) are translated onto the matching Ferrum upstream's `backend_tls_*` fields and `resolved_subset_tls` map at slice-apply time. Backend handshake SNI consumption and SAN allow-list verification are enforced on the backend TLS paths; both settings — plus the selected subset name — are included in backend pool keys so distinct TLS identities never share connections.

Port-level `connectionPool.tcp.connectTimeout`, `loadBalancer`, and `outlierDetection` are **all enforced** for HTTP/H2/H3/gRPC/WebSocket/HBONE dispatch via `Upstream.port_overrides[port]` + `Proxy.dispatch_port_overrides[port]`. TCP, UDP, and DTLS stream paths engage per-port **`loadBalancer`** (algorithm and hash key) and **`localityLbSetting`** at selection time when all upstream targets share a single port (`initial_dispatch_port_override` non-zero); the lane engages only for selection-affecting overrides, stream-lane `consistentHash` requires a source-IP hash key, per-port `LEAST_CONN` is refused (fail-closed) on the generic stream listeners, and per-port `LEAST_LATENCY` is refused on every stream lane — see [Limitations](#limitations-and-not-supported). The mesh raw-TCP/UDP tunnel dials (HBONE `:15008` / mesh-mTLS `:15006`) and the HBONE capability probe honor the per-port `connectTimeout` for the destination's policy port. Per-port `outlierDetection` thresholds and `maxEjectionPercent` caps are honored by stream target selection using active/passive health context. Outlier thresholds are still not recorded for stream paths (raw relay sessions carry no response status). Per-port `connectTimeout` and `maxConnections`/`tcpKeepalive` apply to stream dial regardless. Port-level `connectionPool.tcp.maxConnections` is enforced for stream-family dispatch and for HTTP-family **WebSocket** dispatch (see the scope note below). Port-level `connectionPool.tcp.tcpKeepalive` is now enforced for stream-family dispatch AND for the socket-owning HTTP-family multiplexed pools (direct-H2, gRPC, HBONE, mesh-mTLS — resolved at connection creation via `socket_opts::apply_pooled_tcp_keepalive`; the HBONE / mesh-mTLS sites key it by the destination's app/service port even though the transport dial is `:15008`/`:15006`), with the global pool keepalive as fallback. Because keepalive is excluded from the pool key (per `.claude/rules/proxy-protocols.md`) and these connections are shared, the first dispatcher to materialize a pooled connection fixes its keepalive (first-materializer tradeoff, like `idleTimeout`). The reqwest-backed HTTP pool (shared client) and H3/QUIC (UDP transport) are documented residuals — see the `tcpKeepalive` row in the DestinationRule table above.

Top-level and per-port `connectionPool.http.{idleTimeout, http2MaxRequests}` are projected per port onto the same `Upstream.port_overrides[port]` slot and consumed by HTTP-family / gRPC dispatch via the per-target effective proxy (`Proxy.pool_idle_timeout_seconds`, `Proxy.pool_http2_max_concurrent_streams`). **Service-discovery upstreams** (`service_discovery` set — including `provider: mesh`) cannot fan the *top-level* `connectionPool.http` block onto a known apply-time port set because their targets resolve at runtime, so the top-level overlay is captured on `Upstream.dispatch_port_override_fallback`, projected onto `Proxy.dispatch_port_override_fallback`, and applied by `resolve_effective_proxy_for_target` / `cap_proxy_retry_for_target` to whatever port the LB selects — an explicit `portLevelSettings` entry for that port still wins. This is a runtime-by-selected-port application of the same overlay, not runtime-resolved target materialization (the rejected outbound-SD rework). `connectionPool.http.maxRequestsPerConnection` is parsed and validated but **deferred**: it is not projected onto `Upstream.port_overrides` or the effective proxy because Ferrum has no backend close-after-N-requests behavior; status lists it under `deferred_fields`. `connectionPool.http.h2UpgradePolicy` projects onto `Proxy.h2_upgrade_policy` and drives the plain-HTTPS h1-vs-h2 dispatch fork; `connectionPool.http.maxRetries` lands on `port_overrides[port].max_retries` and caps the per-request `Proxy.retry.max_retries` (see [DestinationRule `maxRetries` semantics](#destinationrule-maxretries-semantics)). `connectionPool.http.http1MaxPendingRequests` lands on `port_overrides[port].http1_max_pending_requests`, projects onto `Proxy.pool_http1_max_pending_requests`, and is enforced as a per-`(host, port)` **concurrent-in-flight-H1 cap** (honestly reinterpreted from Envoy's pending-queue — reqwest has no connection-acquisition hook; 503 "upstream overflow" when full, neutral to backend health) on the reqwest/HTTP-1.1 dispatch path only (see the DR status table row + `src/backend_pending_limit.rs`). `h2UpgradePolicy` / `maxRetries` / `http1MaxPendingRequests` remain deferred-and-warned when set inside a `subsets[].trafficPolicy` (the subset apply path carries no `connectionPool.http`).

**Dispatch-path coverage (H1/H2 and HTTP/3 frontends).** The per-target effective-proxy override pipeline — `resolve_effective_proxy_for_target` plus `cap_proxy_retry_for_target` for the `maxRetries` cap — applies the DR per-port overrides (`h2UpgradePolicy` / `idleTimeout` / `http2MaxRequests` / `connectTimeout` / per-port TLS, plus `maxRetries` and the service-discovery top-level fallback) after the LB-selected target is known. It runs on the H1/H2 (`handle_proxy_request_inner`) path and on the standalone HTTP/3 frontend (`src/http3/server.rs`) before retry-dependent buffering/native-H3 decisions, H3→gRPC, and H3 WebSocket dispatch read the proxy. Every H3 dispatch loop that can rotate retry targets re-resolves the effective proxy per attempt from the selected target's retry-capped but otherwise unresolved base proxy — the buffered native-H3 retry loop, the H3→HTTP plain bridge, the H3→gRPC bridge (initial and retried attempts; the streaming variant resolves its single selected target), and the H3 WebSocket dial loop — so retry targets do not inherit the first target's port-level TLS/SNI/H1 policy. The H1/H2 path re-resolves per attempt in `proxy_to_backend` / `proxy_to_backend_retry`, and — since issue #2416 — its WebSocket backend dial does too: the dial loop in `handle_websocket_request_authenticated` calls `resolve_backend_connection_proxy_for_target` for the CURRENT target at the top of every attempt (the same helper the H3 WebSocket bridge uses), so a retry that rotates from one port to another dials under the second port's `connectTimeout`, trust roots, client identity, and verification posture rather than the unresolved route-level policy. DNS override and TTL remain route-level inputs; target rotation changes the resolution hostname but does not project a port-level DNS policy that does not exist. Both the direct TCP/TLS dial and the mesh egress dial (`connect_mesh_websocket_backend`) receive that one target-effective proxy; there is no longer a WebSocket exception to this pipeline. See [WebSocket policy port vs transport dial port](#websocket-policy-port-vs-transport-dial-port) for what "the target's port" means when the transport rides an HBONE or mesh-mTLS tunnel. The plain bridge's per-attempt dispatch-policy rejects — a per-port backend-TLS-SNI incompatibility (502) and the `http1MaxPendingRequests` pending-cap (503) — happen before backend admission, backend dial, or backend-health signal, matching H1/H2 ordering.

**Warmup pre-warm of DR force-H1 (`DO_NOT_UPGRADE`) clients.** Startup pool warmup (`warmup_connection_pools` in `src/proxy/mod.rs`) computes its reqwest warmup candidates from the **base** `Proxy` (before `resolve_effective_proxy_for_target`), so a DR `h2UpgradePolicy: DO_NOT_UPGRADE` per-port override does not get its dedicated force-H1 reqwest client *pre*-warmed. This is correct-but-unoptimized, not a correctness gap: the force-H1 client (ALPN restricted to `http/1.1`, with its own force-H1 pool-key discriminator) is built **lazily on first real dispatch** under its own pool key, so behavior is identical — only the one-time warm-connection optimization is missed for that client. Resolving effective proxies during warmup (a broader change) is a tracked P3 follow-up.

#### DestinationRule `maxRetries` semantics

Istio/Envoy `connectionPool.http.maxRetries` is a **cluster-wide outstanding-retry concurrency budget** — a ceiling on how many retries may be *in flight at once across the whole cluster*, independent of any single request's retry count (Envoy's per-route retry count lives on the route's `retryPolicy`). Ferrum's retry model is **per-request**: `Proxy.retry` (set e.g. from a VirtualService) carries a `max_retries` applied per request in `src/retry.rs`; there is no cluster-wide outstanding-retry gauge.

Rather than ignore the field, Ferrum **honestly reinterprets** DR `maxRetries` as an **upper bound on the per-request retry count**:

- If the route/proxy already has a retry policy (`Proxy.retry` is `Some`), the effective `max_retries` becomes `min(existing, dr_maxRetries)` — it can only *reduce* retries, never raise them.
- If there is **no** retry policy, DR `maxRetries` alone does **not** enable retries (a budget is not a retry-policy enabler) — Ferrum does not synthesize a retry policy from it.

The cap is applied by `cap_proxy_retry_for_target` in `src/proxy/mod.rs`, once the dispatch target's port is resolved and before any HTTP / gRPC / WebSocket retry loop reads `proxy.retry`, so all retry paths observe the capped value with no double-application. This is a documented semantic difference from Envoy — operators relying on Envoy's outstanding-retry-budget behavior should treat Ferrum's interpretation as a per-request ceiling instead.

#### Retry policy conflicts with required mesh transports (rejected at admission)

Mesh egress targets that require a per-topology secured transport are tagged `mesh.hbone` (Ambient / Waypoint HBONE — H2 CONNECT over mTLS) or `mesh.mtls` (Sidecar SVID-mTLS HTTP). At runtime the dispatch path **forces those transports off whenever a retry policy is effective** for the request (replaying a CONNECT tunnel / mesh-secured dispatch is unsafe) and then **fails closed with a `502`** — a silent reachability gap. Mesh-materialized proxies never set `Proxy.retry`, so this only arises when an operator manually combines a `Proxy.retry` policy with mesh-tagged targets in database / file / native mesh-config mode.

To surface the conflict instead of 502-ing every matched request, `GatewayConfig::validate_upstream_references` (and the equivalent admin CRUD admission checks for proxy and upstream writes) **reject** a retry-enabled proxy whose effective upstream targets require a mesh transport:

- A retry policy counts as **effective** using the same gates the runtime applies: `max_retries > 0`, and either `retry_on_connect_failure` (method-agnostic) or status-code retries whose `retryable_methods` actually overlap the proxy's `allowed_methods` (status retries scoped to methods the proxy cannot serve can never fire, so they do **not** trigger rejection).
- A target's `mesh.hbone` / `mesh.mtls` requirement is detected with the **runtime tag predicates** (`target_hbone_enabled` / `target_mesh_mtls_enabled`), so the boolish truthy values the dispatch path honors (`true` / `yes` / `on` / `1`) are matched, not just the literal `"true"`.
- **Subset-aware:** when the proxy selects an `upstream_subset`, only targets in that subset are considered — a retry policy is allowed when the selected subset excludes all mesh-only targets.
- **Mesh service-discovery upstreams** (`service_discovery.provider = mesh`) are treated as mesh-transport-requiring even with no static targets, because discovered targets are stamped with the configured `topology`'s transport tag once the discoverer populates them (`mesh.hbone=true` for `ambient`, `mesh.mtls=true` for `sidecar`).
- **Route overrides:** `mesh_route_dispatch` rules that override `route_override_upstream_id` to a different (mesh-tagged) upstream are included in the conflict check, so a plain default upstream with a mesh-routed override is rejected rather than 502-ing the matched traffic.

The fix is admission-only (issue #1669, option (a)) — it does not change the runtime dispatch behavior; it converts a silent 502 into an actionable config error. Operators who need retry on a mesh destination must drop the conflicting `Proxy.retry` (or scope it to a non-mesh subset).

A remaining dispatch-time defense-in-depth gap is tracked separately: the generic HTTP retry loop does not yet re-screen mesh transport tags when a retry rotation lands on a mesh-tagged target in a mixed upstream, so that residual is issue #2008. The gRPC retry loop already re-screens on rotation and fails closed; the follow-up is to give the HTTP retry loop the same per-attempt guard before any plain direct dial can occur.

#### Port-level `connectionPool` merge semantics

Istio treats a matching `portLevelSettings[]` entry as a **complete replacement** of the destination-level `connectionPool` for that port — fields not respecified in the port entry fall back to the *cluster default*, not to the destination-level value. **Ferrum intentionally applies a field-level merge**: the destination-level (top-level) `connectionPool` fans out to every target port first, then each `portLevelSettings` entry overlays its set fields on top (an omitted field leaves the inherited value in place). This is the product contract across every applied `connectionPool` knob (`connectTimeout`, `idleTimeout`, `http2MaxRequests`, `maxConnections`, `tcpKeepalive`, `h2UpgradePolicy`, `maxRetries`, and `http1MaxPendingRequests`). `maxRequestsPerConnection` is excluded from this merge because it is deferred and not projected.

One field-specific nuance for `h2UpgradePolicy`: because Istio's `DEFAULT` is carried as the explicit `H2UpgradePolicy::Default` variant (not collapsed to "absent"), an **explicit** port-level `h2UpgradePolicy: DEFAULT` overlays as "probe-driven", which **clears** an inherited top-level `UPGRADE` / `DO_NOT_UPGRADE` for that port — the operator explicitly chose default. An **omitted** port-level `h2UpgradePolicy` leaves the inherited value untouched. `Default` and absent (`None`) behave identically at the dispatch fork.

#### Top-level `connectionPool.http` on service-discovery upstreams

The "top-level fans out to every target port" behavior described above relies on the upstream's target ports being known at apply time. A **service-discovery** upstream (any `service_discovery` provider, including `provider: mesh`) resolves its targets at runtime, so there is no apply-time port set to fan onto. For such upstreams the top-level `connectionPool.http` overlay is captured on `Upstream.dispatch_port_override_fallback` (accumulated additively across matching rules with the same `apply_connection_pool_http_to_port_override` helper used for the fan-out), projected onto `Proxy.dispatch_port_override_fallback`, and applied by `resolve_effective_proxy_for_target` / `cap_proxy_retry_for_target` to **whatever port the load balancer selects**. This is a runtime-by-selected-port application of the *same* overlay — it does **not** materialize the discovery-resolved targets as static upstreams (the outbound service-discovery rework that was evaluated and rejected; see the per-port outbound materialization note above).

An explicit `portLevelSettings` entry for the selected target's policy port still wins: the per-port `dispatch_port_overrides` map is consulted first and the fallback is the field-level `.or(...)`. The fallback carries the **top-level overlay ONLY** — `dispatch_port_override_fallback_from_upstream` deliberately does **not** fold the upstream's per-port entries into it (folding cross-leaks one port's `connectionPool.http` onto another on a multi-port upstream). Mesh service-discovery targets that dial a resolved workload port different from the declared Service port carry the owning Service port in an internal, serde-skipped `UpstreamTarget.service_port_policy_key`; dispatch reads `target.dispatch_policy_port()` for DestinationRule policy and still dials `target.port`. This covers named `targetPort`, numeric `targetPort`, service-port-equals-workload-port, and multi-port services without inferring policy from a port name or leaking one Service port's policy to a sibling. Generic SD targets without that internal identity continue to use their dial port as the policy key and then the top-level fallback when no explicit entry matches. Immediate route-table rebuild on a DR-only edit to the SD fallback remains a separate #1816 route-rebuild item.

#### Subset-scoped `connectionPool.http.{h2UpgradePolicy, maxRetries}` are not applied

`h2UpgradePolicy` and `maxRetries` are applied only when set at the **top-level** `trafficPolicy` or in a `portLevelSettings[]` entry. When set inside a `subsets[].trafficPolicy`, they are **parsed and validated** (a malformed value still fails the resource closed) but **not applied** — the mesh apply path turns a subset into a `SubsetTrafficPolicy` that carries only LB / TLS / `connectTimeout` / passive-health, with no `connectionPool.http` slot, so these two fields cannot reach `port_overrides` / the effective `Proxy` for a subset. They therefore emit an operator-visible warning at translate time and are surfaced in the DestinationRule `status.ferrum.translation.deferred_fields` block (see "Istio CRD Status"). Wiring subset `connectionPool.http` through `SubsetTrafficPolicy` is out of scope; apply these fields at the top-level or `portLevelSettings` instead.

Reqwest pool keys include an inspectable `rcfg` client-behavior segment for every setting baked into the shared `reqwest::Client` (including per-port `idleTimeout`), so divergent client-level values isolate distinct clients. Direct-H2 and gRPC pool keys still exclude several builder-only knobs such as `http2MaxRequests`, so two proxies that share `(host, port, TLS)` but configure different per-port H2 stream caps can still share a first-materialised connection — operators wanting strict isolation there fragment via `dns_override` (or distinct `upstream_subset` / `backend_tls_*` material). Request-only `backend_connect_timeout_ms` remains per-request and does not fragment any pool.

### WebSocket policy port vs transport dial port

A proxied WebSocket has two ports, and they are deliberately allowed to differ. Both frontends (H1/H2 in `src/proxy/mod.rs`, H3 in `src/http3/websocket.rs`) resolve them identically, per backend attempt:

- **Policy port** — `UpstreamTarget::dispatch_policy_port()`, i.e. `service_port_policy_key` when mesh service discovery recorded a declared Service port that a Kubernetes `targetPort` remapped, otherwise `UpstreamTarget.port`. This is the key for the DestinationRule decisions the upgrade consumes: the `connectionPool.tcp.maxConnections` admission slot and the `resolve_backend_connection_proxy_for_target` projection. A direct dial consumes that projection's `connectTimeout` and `portLevelSettings[].tls` (CA, client cert/key, `verify_server_cert`, SAN allow-list); a mesh tunnel consumes the target-effective timeout while its identity, trust domain, and cross-cluster SNI come from the mesh dial plan rather than application-backend TLS fields. Target selection chooses the policy port; policy always follows the selected Service port, never the workload port and never the transport listener.
- **Transport dial port** — where the socket actually goes. For a direct dial that is `UpstreamTarget.port` (carried in the computed backend URL). For **mesh egress** it is neither: a `mesh.mtls` target dials the peer sidecar's `:15006` inbound listener (`mesh.mtls_port`) and a `mesh.hbone` target dials the peer's `:15008` HBONE listener (`mesh.hbone_port`), reaching the app port *through* the tunnel. Those transport listener ports are addresses, not policy sources — a `portLevelSettings` entry keyed on `15006`/`15008` never configures the upgrade.

So an HBONE WebSocket to a Service port `80` that resolves to workload port `8080` is admitted and configured from port `80`'s DestinationRule, dials `:15008`, and CONNECTs to `:8080`. Because the mesh pools also read socket-level knobs (TCP keepalive) keyed by the dial port, the per-attempt projection additionally mirrors the selected policy port's override onto the dial-port key in its dispatch-local clone, so dial-port-keyed lookups agree with the policy the upgrade was admitted under. The serialized proxy and the shared projected map are unchanged.

The direct WebSocket dial fails **closed** on a resolved backend TLS `sni` override, because `client_async_tls_with_config` derives both the `Host` header and the TLS server name from the request URI and cannot apply a separate SNI. Honoring the URI host would silently verify the wrong server name, so the upgrade is refused pre-dial as a gateway-side dispatch rejection (`502`, non-retryable, neutral to the circuit breaker and passive health) — the same posture the reqwest retry path takes for an unreplayable SNI override. Because the projection is per target, a `portLevelSettings[].tls.sni` on one port refuses only that port's upgrades; sibling ports keep dialing. Mesh egress is unaffected: its SNI is chosen explicitly by the mesh dial plans (`mesh.eastwest_sni` for cross-cluster east-west).

### DestinationRule `maxConnections` enforcement scope

`connectionPool.tcp.maxConnections` caps **concurrent open backend connections per destination** — Envoy's semantics. Keying is per resolved `(host, port)` endpoint, not per logical cluster, so a destination with N endpoint hosts sharing one port has an effective ceiling of N×cap rather than Envoy's per-cluster total (the two are equivalent for the typical single-host mesh destination). Ferrum enforces it everywhere it owns the backend connection's lifecycle and that lifecycle maps onto an open-connection count:

| Transport / backend path | Actual backend sockets observed | `maxConnections` contract |
|---|---:|---|
| TCP / TCP+TLS stream proxy | One backend socket per stream session | Enforced with `BackendConnectionLimiter`; over-cap dials fail before relay |
| WebSocket H1/H2 | One dedicated backend socket per WebSocket session | Enforced with `ProxyState.backend_conn_limit`; over-cap upgrade returns 503 |
| WebSocket H3 | One dedicated backend socket per WebSocket session | Enforced with the same backend connection limiter in `http3/websocket.rs` |
| reqwest HTTP/1.1 | reqwest owns an internal pool; concurrent H1 requests can open multiple backend sockets | Not enforced; `http1MaxPendingRequests` is the supported H1 request-concurrency gate |
| reqwest HTTP/2 | reqwest owns an internal multiplexed pool | Not enforced; use `http2MaxRequests` where direct-H2/gRPC paths apply |
| Direct H2 | Pooled multiplexed H2 connection(s), sharded by pool settings | Not enforced as an open-socket cap; use `http2MaxRequests` |
| gRPC | Pooled multiplexed H2 connection(s) | Not enforced as an open-socket cap; use `http2MaxRequests` |
| HTTP/3 | Pooled QUIC connection(s), UDP transport | Not enforced; TCP connection cap is not meaningful for QUIC |
| HBONE / mesh-mTLS pooled HTTP egress | Pooled multiplexed H2 CONNECT transport connection(s) | Not enforced for pooled HTTP-family requests; raw TCP / WS / UDP tunnel sessions that use fresh dedicated tunnels are governed by their session-specific paths |

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

Istio Telemetry selectors for standard families Ferrum does not emit (request/response size, TCP connection/byte, and gRPC message families) are accepted and ignored with one bounded construction-time warning, so those family-specific overrides do not suppress the optional `workload_metrics` plugin. Unknown family names and malformed policy remain construction errors. `ALL_METRICS` applies only to the two emitted Ferrum families.

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
- `ferrum_mesh_node_waypoint_hbone_handshakes_total{phase,result}` -- NodeWaypoint HBONE handshake outcomes by phase (`inbound_tls` / `inbound_connect` / `outbound_dial`) and result (`success` / `failure`).
- `ferrum_mesh_node_waypoint_asserted_identity_total{result,reason}` -- asserted source-identity accept/reject with bounded reasons.
- `ferrum_mesh_node_waypoint_destination_policy_rejections_total{reason}` -- destination AuthorizationPolicy / scope / open-relay rejects.
- `ferrum_mesh_node_waypoint_missing_destination_metadata_total` / `ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total` -- fail-closed missing `Workload.node_waypoint` metadata / blocked plaintext fallback.
- `ferrum_mesh_config_update_rejections_total{consumer,reason}` -- `MeshSubscribe` responses a mesh config consumer refused **before** applying them (see [Native MeshSubscribe](#native-meshsubscribe-default) → "Response binding"). `consumer` is `native` (the local slice-installing stream) or `remote_discovery` (a cross-cluster endpoint fetch); `reason` is one of `missing_ferrum_version`, `incompatible_ferrum_version`, `unexpected_heartbeat`, `invalid_slice_json`, `envelope_version_mismatch`, `node_id_mismatch`, `namespace_mismatch`, `workload_scope_mismatch`, `waypoint_scope_mismatch`. Both labels are compile-time constants, so the series' cardinality is fixed and no control-plane-supplied value ever reaches `/metrics` — the mismatching values stay in the structured `warn!` at the rejection site. A non-zero value means a control plane answered this data plane with something that is not bound to its subscription (cross-wiring, a stale/proxied CP, or version skew); the last-good slice keeps serving while it persists.
- `ferrum_mesh_inbound_plaintext_allowed` -- `1` when the mesh inbound listener admits plaintext (PeerAuthentication `PERMISSIVE`/`DISABLE`, or no usable server identity; dev-only because production mode refuses this), `0` otherwise. Deliberately label-free: the downgrade reason stays in the `warn!` logs at the enforcement sites. Updated at startup enforcement and on **accepted** PeerAuthentication live reloads, so a reload that heals or degrades the posture moves the gauge only once the slice is actually applied — a candidate slice the proxy rejects leaves it at the pre-reload value; topologies with no TLS-terminating inbound listener (EastWestGateway SNI passthrough) leave it at `0`.
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

- `sampling_percentage`: 0.0--100.0. New root traces use a probabilistic PRNG decision; valid upstream W3C `traceparent` and B3 sampling decisions are inherited unchanged.
- `custom_tags`: literal key-value tags injected into every span. Tags merge by key across matching Telemetry scopes; a more-specific scope overrides only keys it names. A source change for a named tag is exclusive: literal, header, or environment replaces the less-specific source and its fallback rather than leaving both active.
- `custom_header_tags`: tags resolved from request headers at runtime. Header tags merge by key with the same more-specific-overrides behavior as literal tags. Credential-bearing source headers (`Authorization`, cookies, API/auth/CSRF tokens, and operator-configured sensitive metadata names) are rejected. Custom tag names cannot collide with `mesh.*`, `mesh_authz.*`, trace identity/sampling controls, or other reserved telemetry keys. A workload-metrics instance accepts at most 32 custom tags, 128-byte names, and 1024-byte values; an oversized runtime header value is omitted.
- `custom_env_tags`: Istio `customTags.<tag>.environment` references carried as `tag_name -> env_var_name`. The Kubernetes translator never reads the controller-host environment. The mesh data plane resolves these at `workload_metrics` construction and reload (not on the request hot path). A present UTF-8 value overrides any matching `custom_tags` default; a missing variable keeps the translated `defaultValue` when one was set and otherwise omits the tag (Istio/Envoy semantics). Missing/empty environment names, non-portable env-var names, and credential-bearing names (including secret/password/token/key/credential names, database connection locations, client credential identifiers, and operator-configured sensitive metadata names) fail translation with `FerrumAccepted=False`/`Invalid`. Oversized or non-UTF-8 resolved values fail plugin construction/reload closed. Selected values are deliberately injected into transaction metadata and exported telemetry, so only trusted Telemetry authors should choose data-plane environment dimensions; diagnostics never include resolved values or rejected credential-bearing variable names.
- Istio `customTags.<tag>.header.defaultValue` is translated as the literal fallback for the same tag. An absent request header uses that default; a present header value takes precedence.
- Istio `customTags.<tag>.environment.defaultValue` is translated into `custom_tags` as the DP fallback; the environment variable name always lands in `custom_env_tags` whether or not a default is present (no silent omission).
- `providers`: inline span exporters for Zipkin v2, Datadog Agent `/v0.3/traces`, Lightstep OTLP, and OpenTelemetry OTLP/HTTP JSON. Lightstep uses `accessTokenEnv` so bearer credentials stay in the local process environment instead of mesh config JSON. Multiple providers receive the same sampled span.
- `disable_span_reporting` / Istio `disableSpanReporting`: when explicitly true, suppresses span export while leaving the rest of the merged tracing config visible. Omitted values inherit from less-specific scopes; explicit false can re-enable a more-specific scope.
- `match.mode` (`SERVER` / `CLIENT` / `CLIENT_AND_SERVER`, default `SERVER`): each mesh listener stamps a traffic direction onto every accepted request — sidecar / ambient / HBONE / egress inbound listeners stamp `Inbound`, sidecar/ambient outbound capture stamps `Outbound`. The translator unions every `tracing[].match.mode` across the merged Telemetry block into a single `direction_emit` on the auto-injected `workload_metrics` plugin. The plugin emits SERVER-kind spans on inbound directions and CLIENT-kind spans on outbound directions and drops the export entirely when the listener direction is not enabled. Span payloads carry the kind in every provider format: OTLP enum `2` / `3` (SERVER / CLIENT), Zipkin v2 top-level `"kind": "SERVER"` / `"CLIENT"`, and Datadog `meta["span.kind"]` set to `"server"` / `"client"`. Non-mesh listeners (file / db / cp / dp HTTP entrypoints) leave the direction unset and the plugin falls back to its server-only default.
- Attribution follows listener direction for HTTP and stream traffic: outbound observations use the local workload as source and the routed service/selected peer as destination, except NodeWaypoint captured-Service HTTP and captured L4 use the authenticated originating pod identity resolved at accept time; inbound observations use the local workload as destination and only an authenticated peer or trusted HBONE baggage identity as source. The NodeWaypoint accept-time identity takes precedence over request baggage, and anonymous permissive inbound traffic never inherits the local workload's principal as its source.
- Request-mirror backend attempts are excluded from workload-metrics spans, matching their exclusion from client-facing RED metrics and the service graph. The primary request retains the sole span for its `(trace_id, span_id)`.

Datadog export groups spans by trace in the Agent v0.3 payload shape and sends the upper 64 bits of W3C 128-bit trace IDs via `_dd.p.tid` while the numeric `trace_id` field carries the low 64 bits.

**Metrics configuration**:

- `tag_overrides`: remove, rename, or set labels on the finalized mesh metric key. Istio label names such as `source_workload`, `destination_service`, and `response_flags` are normalized to Ferrum's fixed `mesh.*` metric-label vocabulary; adding a new Istio tag dimension is not supported. Overrides preserve their `match.metric` scope and apply in declaration order. Ferrum does not evaluate general Istio CEL expressions in `UPSERT.value`: the only accepted form is a double-quoted JSON-style string literal (for example, `value: '"edge"'`), whose decoded value becomes the label value. Missing, empty, or non-literal expressions such as `request.host` and `string(destination.port)` make the Telemetry resource invalid (`FerrumAccepted=False`) instead of being emitted as literal expression text. Supported metric selectors are `REQUEST_COUNT`, `REQUEST_DURATION`, `ferrum_mesh_requests_total`, `ferrum_mesh_request_duration_ms`, and `ALL_METRICS`. Unsupported tag names, unsafe or oversized values, and unknown metric selectors likewise fail translation visibly. A changed label shape creates a new Prometheus series; the previous series ages out under the configured stale-entry TTL.
- `disabled_metrics`: suppresses only the selected mesh metric family before its counter or histogram is updated. It accepts the same metric selectors as `tag_overrides`. Newly accepted Telemetry configuration affects subsequent transactions immediately; an already-created series remains visible at its last value until the Prometheus stale-entry TTL evicts it, and re-enabling resumes recording without a restart.

**Access logging configuration**:

- `enabled`: toggle (default true). When false, the access log plugin is not injected.
- `filter`: optional `AccessLogFilter` with `status_code_min`, `status_code_max`, `min_latency_ms`, `errors_only`, and/or a compiled `expression` tree when the Telemetry `filter.expression` contains `||`. Pure `&&` conjunctions stay in the flat fields; `||` expressions compile to a bounded AST (`op: and|or|status_code_min|status_code_max|min_latency_ms|errors_only`) with limits of 4096 UTF-8 bytes, 64 tokens, nesting depth 16, and 32 AST nodes. Status atoms are `response.code` / `response.status`; latency accepts `response.duration` or `duration`, with integer milliseconds by default and explicit `ms` / `s` suffixes (for example, `response.code >= 500 || duration > 1s`). Unsupported identifiers, malformed operators, overflowing conversions, and over-limit input fail translation closed with field-specific diagnostics.

The access log is injected as a `stdout_logging` global under the reserved id `__mesh_access_log` (carrying the `filter` above). When the `GatewayConfig` handed to mesh preparation already contains an operator-managed global plugin of the **same plugin type**, that operator plugin overrides the mesh injection: if you define your own global `stdout_logging`, the `__mesh_access_log` injection is suppressed so transactions are not logged twice, and the Telemetry CRD's `accessLogging.filter` is **not** applied on top of your plugin. Native/xDS `MeshSlice` feeds do not currently carry operator `plugin_configs`, so slice-only runtimes receive the mesh-managed access log unless access logging is disabled by Telemetry. To keep the mesh-managed filter, leave access logging to the injected plugin (do not also define a global `stdout_logging` in a prepared config), or fold the equivalent `filter` into your own global `stdout_logging` config.

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
| `ferrum.io/injected` | Written by the injector as an observability marker only; not trusted as a skip signal. Re-invocation is rejected by reserved `ferrum-edge` / `ferrum-edge-init` name conflicts |

When `FERRUM_INJECTOR_REQUIRE_ANNOTATION=true` (default), pods must explicitly opt in via `ferrum.io/inject: "true"`, `sidecar.istio.io/inject: "true"` (Istio compat), or the `ferrum.io/mesh: "enabled"` label. When `false`, all pods are injected unless explicitly opted out.

### Port and IP-Range Capture Overrides

The injector supports per-pod capture overrides via annotations. The Istio annotation namespace is honored byte-for-byte so workloads can migrate without rewriting metadata; Ferrum-native annotations are accepted as aliases for the port lists.

| Annotation | Direction | Semantics |
|---|---|---|
| `traffic.sidecar.istio.io/includeOutboundPorts` | outbound | Comma-separated TCP destination ports included in outbound capture, or `*` for all outbound ports; when set to explicit ports, outbound REDIRECT rules are scoped to these ports |
| `ferrum.io/includeOutboundPorts` | outbound | Ferrum-native alias for the above |
| `traffic.sidecar.istio.io/excludeOutboundPorts` | outbound | Comma-separated TCP destination ports excluded from outbound capture (Istio-compatible) |
| `ferrum.io/excludeOutboundPorts` | outbound | Ferrum-native alias for the above |
| `traffic.sidecar.istio.io/excludeInboundPorts` | inbound | Comma-separated TCP and UDP destination ports excluded from inbound capture (Istio-compatible). RETURN rules are emitted BEFORE the inbound REDIRECT/TPROXY catch-all so the exclusion is honored |
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

#### UDP TPROXY capture (F3 §3.3, flag-gated, Stages 2–4 — capture rules + listener + datagram-over-mesh egress, dual-transport)

TCP mesh capture uses iptables `REDIRECT` in the `nat` table: REDIRECT rewrites the
packet's destination to the proxy port, and the proxy recovers the pre-NAT
original destination per-connection via `SO_ORIGINAL_DST`. **This does not work for
UDP.** UDP is connectionless, REDIRECT rewrites the destination with no
per-datagram recoverable original address, and there is no UDP equivalent of
`SO_ORIGINAL_DST`. Captured UDP therefore uses **TPROXY** instead:

- **TPROXY in the `mangle` table** (`FERRUM_MESH_CAPTURE_UDP_ENABLED=true`): TPROXY
  delivers the datagram to a transparent listener socket **without rewriting its
  destination**, so the Stage 3 listener recovers the original destination
  per-datagram from the `IP_RECVORIGDSTADDR` cmsg. New `mangle`-table chains
  mirror the TCP include/exclude/CIDR scoping with `-p udp ... -j TPROXY --on-port
  <FERRUM_MESH_CAPTURE_UDP_PORT> --tproxy-mark <FERRUM_MESH_TPROXY_MARK>/<mask>`,
  jumped from `mangle PREROUTING`. Sidecar UDP capture emits
  `FERRUM_MESH_UDP_OUTBOUND`, `FERRUM_MESH_UDP_INBOUND`, and the
  `FERRUM_MESH_UDP_OUTPUT_MARK` / `FERRUM_MESH_UDP_REINJECT`
  locally-generated-egress loop. **Inbound UDP is fail-closed by default:** direct
  pod-app-bound (`--dst-type LOCAL`) datagrams are captured rather than allowed to
  bypass mesh identity and `mesh_authz`. Until a dedicated plaintext inbound UDP
  relay exists, those direct datagrams do not match the egress route table and are
  dropped by the capture listener; authenticated datagram-over-mesh traffic still
  reaches the destination through the mesh UDP relay. Operators that intentionally
  need plaintext/direct inbound UDP for a port must configure
  `traffic.sidecar.istio.io/excludeInboundPorts`, `ferrum.io/excludeInboundPorts`,
  or `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` so the inbound RETURN rule is
  emitted before the UDP TPROXY catch-all. These dst-based PREROUTING chains are
  **PREROUTING-only**, so — unlike the TCP `nat OUTPUT` outbound chain — they carry
  **no proxy-UID `-m owner --uid-owner` self-exclusion** (owner-match is
  OUTPUT-context only). The pod's **own** locally-generated UDP egress (which never
  hits PREROUTING) is captured separately via a `mangle OUTPUT` MARK chain whose
  proxy-UID owner RETURN provides that self-exclusion — see the OUTPUT-MARK loop
  bullet below. The UDP listener port (default `15011`) is **distinct from the TCP
  outbound port** (`15001`) because UDP and TCP cannot share one listener socket.
- **Direction scoping (both chains ride PREROUTING).** The TCP chains stay
  direction-disjoint by hook (inbound = `nat PREROUTING`, outbound = `nat OUTPUT`);
  TPROXY cannot use that (it is PREROUTING-only), so both UDP chains ride
  `mangle PREROUTING` and are kept disjoint by **destination address type**
  instead: the outbound TPROXY rules carry `-m addrtype ! --dst-type LOCAL` (egress
  = a remote destination) and the inbound catch-all carries `-m addrtype
  --dst-type LOCAL` (inbound = the pod's own IP). The **OUTBOUND jump is installed
  before the INBOUND jump** so pod egress is matched first — otherwise the inbound
  catch-all (xt_TPROXY returns `NF_ACCEPT`, ending PREROUTING traversal) would
  swallow egress and bypass the outbound include/exclude/CIDR/port rules. The
  `addrtype` match needs no extra capability beyond the `NET_ADMIN` the init
  container already grants. **Pod-netns only (host-netns node-agent limitation).**
  The `--dst-type LOCAL` discriminator is correct only in the **pod** network
  namespace, where the pod's own IP is `LOCAL` — exactly the injector init
  container's context. The **node-agent DaemonSet runs `hostNetwork: true`** (host
  netns), where pod IPs are **FORWARDED, not `LOCAL`**, so inbound UDP to a pod
  would match the OUTBOUND chain's `! --dst-type LOCAL` discriminator and be
  mis-captured as egress. There is no host-netns-safe `addrtype`-style
  discriminator without per-pod IP knowledge the iptables fallback does not carry,
  so the **node-agent's host-netns iptables fallback emits NO UDP TPROXY rules**
  (`CaptureConfig::host_netns` short-circuits `udp_tproxy_commands_for_family`) and
  logs the limitation when `FERRUM_MESH_CAPTURE_UDP_ENABLED=true`. **Node-agent
  host-netns UDP capture is unsupported in this stage**, and **eBPF does not cover
  UDP either** — the eBPF capture programs are `connect()`-cgroup-hooked and
  TCP-only (no UDP hooks; see the node-waypoint UDP/DTLS limitation above). UDP
  capture lives in the **injector's pod-netns path** (its iptables init container
  runs in the pod netns, where the pod IP is `LOCAL` so the direction split holds);
  node-agent / node-waypoint UDP capture is a **future stage**.
- **Transparent-routing plumbing** (raw `ip` commands, not iptables): TPROXY
  delivery additionally needs `ip rule add priority <P> fwmark <mark>/<mask> lookup
  <table>` plus `ip route add local 0.0.0.0/0 dev lo table <table>` (and the `ip -6`
  equivalents under the IPv6 fan-out) so the kernel routes the marked datagram to
  the local socket. **The `ip rule` priority is a low constant (`100`), separate
  from the routing TABLE number (`33133`).** The RPDB is priority-ordered and the
  kernel's built-in `main` table rule is priority `32766`; if the fwmark rule sat
  above it, `main` would resolve the marked datagram to its normal route before the
  fwmark lookup engaged and captured UDP would silently black-hole — so the rule
  must sit BELOW `main`. The **routing table is a Ferrum-owned number (`33133`),
  NOT Istio's inbound-TPROXY table `133`** — a co-resident Istio install owns
  `133`, and Ferrum must never risk that table's routes. **Fail closed when the
  routing is unavailable:** TPROXY local delivery is useless without this `ip
  rule`/`ip route`, so when UDP capture is enabled the setup script (a) **fatally**
  preflights `command -v ip` **before** installing any UDP mangle/TPROXY rule (a
  runtime image without `iproute2` fails the `set -e` script and installs nothing —
  TPROXY rules and routing go in together or not at all, never the silent
  half-state), and (b) the load-bearing routing **ADD** commands are **not**
  `|| true` (a failed add aborts the script). Only the delete-before-add stays
  best-effort. **Idempotent setup:** `ip rule add` appends, so the rule is assigned
  the explicit priority (`100`) and is delete-by-priority **before** add (and the
  route is delete-before-add), so a node-agent fallback crash/retry before cleanup
  never stacks a duplicate rule. **Routing installed BEFORE the PREROUTING jumps.**
  The `ip rule`/`ip route` plumbing is emitted **before** the two `mangle
  PREROUTING -j FERRUM_MESH_UDP_*` jumps (which is what actually starts steering UDP
  into the chains). The injector init container runs the whole `set -e` script with
  **no cleanup trap**, so installing the jumps first and then failing on `ip
  rule`/`ip route` would leave the pod with TPROXY chains live but no policy routing
  — the exact half-installed black-hole this design avoids. Emitting routing first
  means a routing failure aborts the `set -e` script before any capture is wired
  (the chains/rules are inert until the jumps are appended last); the node-agent's
  sequential runner gets the same ordering. The mark (default `0x733`, 1843) is **Ferrum-owned
  and deliberately NOT Istio's conventional TPROXY mark `0x539`**: Ferrum's
  higher-priority fwmark rule (priority `100`) matches the mark and steers it to
  the Ferrum table, so defaulting to `0x539` would hijack a co-resident Istio's
  marked packets into Ferrum's table and break Istio traffic. It also avoids common masked CNI mark classes
  such as `0xF00/0xF00`; within Ferrum it is
  collision-free — Ferrum uses no other packet marks; the `1337` proxy UID is a
  socket-owner match, a disjoint namespace from `skb->mark`.
- **Default OFF.** The flag defaults off and, when off, emits **no**
  `mangle`/TPROXY/routing rules and binds **no** listener. **The injector
  produces only Sidecar pods, and Sidecar UDP egress is now ENABLED (#1808), so
  when the operator sets `FERRUM_MESH_CAPTURE_UDP_ENABLED` the injector installs
  the UDP TPROXY rules AND sets the sidecar's UDP-enable env** — a single central
  switch (`injector::sidecar_udp_capture_supported()`, now `true`) enables the
  init container's rule emission, the runtime-enable env, and the
  transparent-bind capability (`NET_ADMIN`) together. This matches the
  mesh-runtime listener gate (Sidecar binds the UDP listener), so an injected
  Sidecar with the flag set both diverts UDP into the capture port and binds the
  listener — **the first working end-to-end UDP path**. The rules (Stage 2) and
  the consuming listener come up together behind the **same** flag, and the
  webhook propagates `FERRUM_MESH_CAPTURE_UDP_ENABLED`,
  `FERRUM_MESH_CAPTURE_UDP_PORT`, and `FERRUM_MESH_TPROXY_MARK` from the **same**
  injector config that drives the init container's TPROXY rules (these are not in
  `SIDECAR_ENV_KEYS`, which only copy the injector's own runtime env). The
  **node-agent / ambient host-netns** path still installs no UDP TPROXY rules
  (`CaptureConfig::host_netns` short-circuits `udp_tproxy_commands_for_family` —
  the `--dst-type LOCAL` direction split is unsafe in the host netns). Ambient's
  UDP source-capture instead rides the **per-pod-netns producer** (#2013, see the
  end-to-end status bullet under Stages 3–4): it installs the UDP TPROXY rules and
  binds the transparent sockets INSIDE each enrolled pod's netns via `setns`, so
  the host-netns "no UDP rules" invariant is **preserved** while Ambient still
  captures UDP. eBPF UDP capture (#1803) stays a non-goal. **Fail-closed on
  malformed settings:** on a capture-relay
  runtime (Ambient or Sidecar), when the flag is set but a UDP capture var is
  malformed, mesh startup aborts (`serve_mesh_runtime` validates the env before
  binding any listener) rather than silently omitting the listener while diverted
  UDP hits a now-unbound port.
- **Stages 3–4 — consuming UDP listener + datagram-over-mesh egress (Ambient OR Sidecar).**
  When `FERRUM_MESH_CAPTURE_UDP_ENABLED=true`, the **two topologies that relay
  captured UDP** — Ambient (HBONE) and Sidecar (mesh-mTLS) — emit the
  **`PlaintextUdpCapture` mesh listener**. UDP egress materialization is
  dual-transport on exactly those two, so emitting this listener for a topology
  with no UDP relay (EastWestGateway / EgressGateway / waypoints) would divert the
  pod's UDP into a listener with no relay and **black-hole every captured
  datagram**; instead, such a topology with the flag set logs a **one-time
  warning** and emits **no** capture listener, leaving UDP **un-captured** (it
  passes through) rather than captured-then-dropped. (The injector/init
  TPROXY-rule emission for a Sidecar pod is gated to MATCH this — see "Default
  OFF" above: the injector installs the UDP rules and sets the UDP-enable env
  whenever the operator enables capture, so the init container and the runtime
  agree.) On a capture-relay topology the listener is bound on the
  **dual-stack IPv6 wildcard**
  (`[::]`, independent of the TCP outbound listener family) and the Stage-2
  `FERRUM_MESH_CAPTURE_UDP_PORT` (default `15011`) — a
  wildcard bind because TPROXY (`--on-port` only, no `--on-ip`) leaves each
  datagram's original (non-local) destination intact, so a specific-IP socket
  would never receive them; only a wildcard `IP_TRANSPARENT` socket claims the
  captured non-local dests. A single dual-stack `[::]` socket (V6ONLY disabled,
  both v4+v6 transparency + orig-dst opts set) captures **both** v4-mapped and v6
  datagrams; a v4-only bind would black-hole the v6 half when IPv6 capture rules
  (`ip6tables` TPROXY) are present. On a host without IPv6 the `[::]` bind fails
  and the listener falls back to the v4 wildcard (v6 capture then unavailable,
  logged). The listener (`src/proxy/mesh_udp_capture.rs`, Linux-only):
  binds a **transparent** UDP socket (`IP_TRANSPARENT`/`IPV6_TRANSPARENT`, so it
  can claim the TPROXY-diverted datagrams whose destination is the captured
  pod's real `service:port`, not the listener's own bind address), enables
  **`IP_RECVORIGDSTADDR`/`IPV6_RECVORIGDSTADDR`** to recover each datagram's
  original destination **per-datagram from the cmsg** (TPROXY delivers without
  rewriting the destination, so — unlike the TCP path's `SO_ORIGINAL_DST`
  getsockopt — the orig-dst rides ancillary data), drains datagrams via
  `recvmmsg` (always, since the orig-dst lives in the cmsg `recv_from` cannot
  surface), and keys a lightweight session by **`(client SocketAddr, orig-dst
  SocketAddr)`**. **Stage 4 — datagram-over-mesh egress (dual-transport).** Each
  captured datagram's recovered original destination is matched **strictly
  against `(service VIP, UDP service port)`** by the route table's
  `mesh_udp_egress` index (a UDP analogue of the raw-TCP VIP table,
  forward-derived from the prepared mesh block: UDP service ports ×
  `cluster_ips`). A routable match relays the datagram over a **`udp`-marked
  HTTP/2 CONNECT tunnel** to the LB-selected workload's app port via a
  **dual-transport branch mirroring raw-TCP egress** (the target carries exactly
  one transport tag): **Ambient `mesh.hbone`** rides the HBONE pool
  (`:15008`, capability-probe-gated, identity-pinned `mesh.spiffe_id` →
  `HboneConnectionPool::get_datagram_tunnel`); **Sidecar `mesh.mtls`** rides a
  fresh mesh-mTLS H2 CONNECT (`:15006`/`mesh.mtls_port`, REQUIRED pinned
  `mesh.spiffe_id`, NO capability registry →
  `MeshMtlsConnectionPool::open_datagram_tunnel`). Either way the tunnel carries
  **length-delimited datagrams** (`[u16 big-endian len][payload]`,
  `src/proxy/mesh_udp_frame.rs`) rather than a raw byte stream. Concurrency is a **per-session mpsc+task** model:
  the recv loop only does the route lookup + a (drop-on-full) channel send (UDP
  backpressure is "drop"), and the per-session task opens the tunnel, frames each
  datagram, and writes it. **Return path:** the per-session task reads framed
  reply datagrams off the tunnel and sends them to the pod from a **per-session
  transparent UDP socket bound (non-locally, via `IP_TRANSPARENT`) to the
  captured original destination**, so replies appear **sourced from the VIP:port
  the pod dialed** (without this the pod would drop every reply as coming from the
  wrong address). On the **destination** side, the peer's inbound HBONE terminator
  recognizes the `udp` marker, **unframes the tunnel into a local `UdpSocket`** to
  the CONNECT `:authority` (the open-relay guard bounds the authority to a
  loopback / slice-known workload addr+port exactly as for the byte-stream relay),
  and frames replies back. The destination's inbound relay is **transport-agnostic**:
  `is_udp_hbone_connect` matches the `udp` marker regardless of which listener the
  CONNECT arrived on (Ambient `:15008` or Sidecar `:15006`), funnelling through the
  same `build_inbound_hbone_relay_proxy` + `handle_hbone_udp_request`, so no
  destination-side change is involved. A captured datagram matching **no** declared
  mesh UDP destination — or a declared pair whose upstream did not materialize — is
  **dropped** (fail closed; UDP has no fall-through HTTP path and a non-mesh
  destination must never be tunnelled in on a port coincidence). **Scope:**
  egress is **dual-transport** (the materializer gates `Ambient => HBONE, Sidecar
  => SidecarMtls, _ => return`); other topologies materialize no UDP egress.
  **Both skew directions fail closed:** a destination that predates Stage 4 has no
  `udp` branch, so a `udp` CONNECT to it 404s (its `is_hbone_connect` rejects the
  `udp` marker). DoS bounds are reused from the
  plain UDP proxy: a bounded session map (`FERRUM_UDP_MAX_SESSIONS`, enforced with
  a lock-free atomic count so a spoofed-source flood never walks every DashMap
  shard), an idle-expiry sweep (`FERRUM_UDP_CLEANUP_INTERVAL_SECONDS`), and the
  recvmmsg batch cap (`FERRUM_UDP_RECVMMSG_BATCH_SIZE`); GRO-coalesced reads are
  framed **per segment**, not as one superblock. When capture is enabled the
  capture port is added to `reserved_gateway_ports()`, so a mesh UDP/DTLS stream
  proxy or ServiceEntry declaring the same listen port is rejected at validation
  rather than racing the capture listener at startup. The listener carries
  `node_waypoint_policy_scope: None` (UDP has no per-source-pod cookie — see the
  UDP/DTLS limitation above). **Linux-only** (`IP_TRANSPARENT` + recvmsg cmsg);
  on other platforms the listener is a no-op stub. With the flag off there is no
  listener and no capture rules. **Destination relay e2e-tested (F3 §3.3 Stage 7):**
  the inbound relay (`handle_hbone_udp_request` / `relay_hbone_udp`) is now exercised
  end-to-end by the `functional_mesh_udp_dest_*` functional tests — a `udp`-marked
  mTLS HTTP/2 CONNECT into a spawned Ambient gateway → framed datagram → local UDP
  echo backend → framed reply byte-for-byte (`..._relays_datagram_round_trip`), plus
  the fail-closed negatives (`..._off_allowlist_authority_is_refused` →
  open-relay-guard refuse; `..._untrusted_peer_fails_closed` → STRICT inbound
  rejects an unchained client SVID). These need no root/netns (the client synthesizes
  the `udp` CONNECT). For enrolled Ambient destination pods, the handler maps the
  resolved destination IP through the pod registry and opens the relay socket inside
  that destination pod netns; the registry lookup is unit-pinned, while the full
  source-capture + enrolled-destination round trip needs a root/netns env and rides
  the §3.1 `netns-capture-live` follow-up (issue #2013).
- **End-to-end status (#1808, #2013): both topologies now have a UDP source-capture
  producer.** The **Sidecar** mesh-mTLS datagram relay (`open_datagram_tunnel`) pairs
  the reusable Stage-4 codec / materialization / dest-side unframe with the
  **injector pod-netns TPROXY producer** (Stage 2) + the current-netns capture
  listener: capture→frame→mesh-mTLS CONNECT (`:15006`)→peer→unframe→local
  `UdpSocket`→return. The **Ambient** producer (#2013) closes the former gap: its
  proxy runs OUTSIDE the pod netns and the node-agent host-netns path emits no UDP
  TPROXY rules, so the **per-pod-netns producer** (`src/proxy/netns_udp_capture.rs`,
  `NetnsUdpCaptureManager` + `ProxyNetnsUdpBackend`) installs the UDP TPROXY rules
  and binds the transparent capture + reply sockets INSIDE each enrolled pod's netns
  (`setns` on a dedicated OS thread), then runs the SAME
  `run_mesh_udp_capture_on_socket` capture/egress loop with a
  `PodNetnsReplySocketFactory`. It reuses the injector's OUTBOUND rule shapes
  (`IptablesPlan::udp_setup_script` / `udp_teardown_script` over the shared
  `udp_tproxy_commands_for_family`) but is **outbound-only** — it does NOT emit the
  inbound `--dst-type LOCAL` chain the injector does. The producer installs rules
  inside EVERY enrolled pod netns (including DESTINATION pods), where an inbound
  chain would capture and drop the HBONE relay's own delivery to the local app
  (`handle_hbone_udp_request` → local `UdpSocket`) AND the source pod's return-path
  reply to the client — black-holing the relayed UDP both ways. It rides the per-pod
  registry the node-agent publishes (also published for Ambient while UDP is
  disabled so stale-rule cleanup can still resolve current pod netns). Before
  touching stale state or binding the unprivileged capture port,
  it installs a dedicated fail-closed OUTPUT guard that mirrors the exact configured
  outbound capture scope. The guard uses alternating chains so guarded retries build
  and activate a replacement before removing the prior guard; a workload that
  pre-binds the capture port therefore gets DROP, never plaintext bypass. The guard is
  removed only after the socket is adopted and the full TPROXY ruleset is live. Failed
  attempts leave a stable-netns cleanup handle with the manager, so pod removal
  retains ownership of guard cleanup and retries transient errors; shutdown
  attempts cleanup through that same stable handle inside the bounded teardown set.
  Cleanup removes every duplicate guard jump and strictly detaches any
  partial live-capture OUTPUT path before releasing the guard. The guarded-to-live
  switch propagates xtables resource errors and also probes stale IPv6 guard chains
  independently of the current IPv6 setting. First-install detection is portable
  across iptables backends: the guard establishes chain existence with `-S` before
  every OUTPUT-jump probe, including strict release of the inactive generation.
  A fresh pod netns therefore never checks a jump whose target chain does not yet
  exist (a case where nft-backed iptables returns exit status 2 while legacy
  returns 1), while any other non-1 status on an existence or jump probe still
  aborts the install and retains the fail-closed cleanup owner. Enrollment also
  starts closed: the node-agent marks each enrolled pod's BPF pod-IP entry UDP-not-ready before registry
  publication, so the host-veth tc classifier drops pod-originated UDP until the
  producer publishes `.udp-ready/<pod_uid>` after the guarded-to-live transition.
  Re-enrollment removes stale readiness first, and both marker and BPF transitions
  reconcile idempotently. Producer stop first persists
  `.udp-ack-required/<pod_uid>`, invalidates stale acknowledgements, then removes
  readiness and waits for the
  node-agent's `.udp-not-ready/<pod_uid>` acknowledgement that the BPF gate closed;
  if the acknowledgement is unavailable, stop retains the in-netns DROP guard
  instead of reopening plaintext. Successful pod removal also persists a
  node-agent-owned `.udp-gate-cleaned/<pod_uid>` proof. A periodic responder in
  both enabled and disabled reconciliation uses that proof to answer a later
  durable `.udp-ack-required` request after the UID has left live pod state,
  including after node-agent restart; a request without verified cleanup proof
  is never acknowledged. Verified handshakes are retained for ten minutes
  (20 times the ordinary 30-second orphan-marker grace), covering producer polls,
  bounded responder batches, and realistic producer/node-agent restarts without
  leaking marker triples forever after a producer ack timeout. The enabled
  producer keeps polling a timed-out close while the UID remains absent and
  removes its retained guard when a late verified acknowledgement arrives; a
  same-UID re-enrollment instead owns the normal pre-open teardown. Once reaped,
  a late producer must persist a fresh request (which refreshes the retention
  window) and retains its fail-closed guard unless the node-agent can
  re-establish cleanup proof. The privileged
  `netns-capture-live` gate
  verifies the real manager/backend source producer, including its transparent
  bind, full HBONE round trip, return-source spoofing, no-route fail-closed
  behavior, capture-disabled absence, idempotent reconcile, pod-deletion cleanup,
  and bind-collision handling. A status-2 active-guard inspection is a hard
  failure after the portable first-install fix above. The producer tears down
  only its own rules on pod removal / config change /
  shutdown. Its stop signal is also threaded into every per-session tunnel task;
  producer close signals every session task and awaits `JoinSet::shutdown()`,
  which aborts and joins the tasks before the pod-netns reply factory and stable
  netns handle are released. Per-producer loops observe only the manager's stop
  signal, so global shutdown cannot race ahead of the manager's marker retraction
  and retain-guard decision. Graceful shutdown AWAITS the per-netns teardown.
  When Ambient UDP capture is disabled, mesh startup still runs a best-effort
  cleanup manager over the registry so stale pod-netns `FERRUM_MESH_UDP_*` rules
  from a prior enabled crash/kill are removed instead of black-holing workload
  UDP. If it observes a stale `.udp-ready` marker, cleanup durably records the
  pending ack before retracting readiness and waits for the
  node-agent's closed-gate acknowledgement against one shared deadline; without
  that acknowledgement it preserves the stale rules fail-closed and retries
  instead of reopening plaintext. Startup is **fail-closed**: an
  invalid capture config, a runtime image missing `sh`/`ip`/`iptables`, or a required
  IPv6 `ip6tables` mangle table failure aborts mesh startup rather than silently
  retrying with nothing captured. The producer **disables the proxy-UID owner-match
  RETURN** and clears only the implicit sidecar-port exclude defaults — there is no
  co-located proxy in the pod netns to exclude, so all app UDP egress is captured
  unless the operator explicitly set `FERRUM_MESH_CAPTURE_EXCLUDE_PORTS`; keeping the
  sidecar's `1337` or implicit port exclusions here would fail OPEN.
  **Scoped policy:** the registry-derived source workload SPIFFE ID and pod UID are
  fixed per capture manager and stamped into the already-authenticated HBONE baggage
  on every `udp` CONNECT. Destination `mesh_authz` evaluates the `udp` CONNECT against
  the union of the destination-scoped policy set (the same namespace/selector policies
  normal inbound HBONE enforces for the destination workload) and the per-pod
  **source** namespace/selector scope, applying the latter only after the normal
  trusted-assertor + trust-domain checks and an exact live pod-UID↔SPIFFE binding
  check. A ServiceWaypoint resolves the destination scope from the CONNECT authority's
  bound Service workload rather than the waypoint namespace and rejects the CONNECT if
  that destination scope is missing. A default single-namespace CP never exports
  Ambient UDP source evidence outside its configured namespace. Absent, malformed,
  stale, mismatched, or untrusted evidence discards the
  source stamp and falls back to mesh-wide source scoping (still unioned with the
  destination policy set, never broader). NodeWaypoint UDP/DTLS remains
  unchanged and does not gain per-pod scoping. Ambient producers share one node-wide session limiter, so
  `FERRUM_UDP_MAX_SESSIONS` is not multiplied by pod count. The reconcile /
  rule-generation / registry logic is unit-tested, and the full Ambient live
  source-capture e2e is enforced by
  `functional_mesh_live_source_capture_udp_manager_hbone_round_trip` in
  `netns-capture-live`: fresh pod netns → production manager/backend TPROXY rules
  and capture socket → recovered original destination → HBONE datagram tunnel →
  destination echo → transparent reply sourced from the original VIP:port. The
  separate enrolled-destination two-pod fixture remains the residual described in
  [12]. eBPF UDP capture stays a non-goal (#1803 per-pod TC not resurrected).
- **DTLS passthrough (F3 §3.3 Stage 5) — opaque, never terminated.** There is no
  separate `Dtls` `AppProtocol`: a DTLS service port is declared `protocol: UDP` and
  rides the exact same `mesh_udp_egress` datapath as any other UDP datagram. The mesh
  relays DTLS **opaquely** — it never terminates the DTLS session, parses the
  ClientHello, or routes on DTLS SNI (unlike the standalone `passthrough` UDP/DTLS
  stream proxy, which peeks the first ClientHello for SNI). The inner DTLS handshake
  and records are framed and relayed **byte-for-byte** (`mesh_udp_frame`); the
  **outer** mesh hop's confidentiality/integrity come from HBONE / mesh-mTLS, while the
  inner DTLS stays end-to-end between the two workloads. This is the plan's "UDP via
  the mesh is datagram-over-stream with documented semantics" posture (Istio likewise
  does not terminate mesh DTLS). **East-west pod→peer only**; external DTLS/UDP egress
  via the EgressGateway stays out of scope (its ServiceEntry UDP ports are classified
  but not materialized). The opaque relay is regression-pinned by
  `dtls_handshake_datagram_round_trips_opaque` in `mesh_udp_frame`.
- **Fail-closed contract (F3 §3.3 Stage 6) — every relay decision drops/rejects on
  doubt.** The UDP datapath mirrors the raw-TCP egress fail-closed table
  gate-for-gate; the hardening landed incrementally across Stages 3–4 (and the
  #1808 dual-transport work), and this stage consolidates the contract so a future
  change knows what to preserve. Each gate has a regression pin:

  | Gate | Enforced at | Failure mode | Pinned by |
  |---|---|---|---|
  | **Routability** — orig-dst ∈ `mesh_udp_egress` (strict VIP : UDP service port) | source capture, **before** any slot/task is reserved | drop datagram; no session created | `unroutable_destination_is_dropped_without_a_slot` |
  | **Gateway SVID present** | egress dial (HBONE / mesh-mTLS) | end session; **never plaintext** | `open_datagram_tunnel_fails_closed_without_svid` |
  | **Capability probe** — Ambient `Udp` enrolled before dial | egress session (Ambient branch) | drop; no blind dial | probe gate widened to `Http\|Tcp\|Udp`; `egress_transport_branch_selects_by_tag` |
  | **Pinned-peer SPIFFE** | egress dial | refuse dial on missing/corrupt pin | `mtls_expected_peer_is_required_and_fails_closed` |
  | **Transport selection** — materializer stamps exactly one of `mesh.hbone` / `mesh.mtls`; runtime precedence is HBONE → mesh-mTLS | egress session | end session if neither tag (a both-tags target — only reachable via a corrupted upstream, never the materializer — resolves to HBONE by precedence, which never relaxes a gate) | `egress_transport_branch_selects_by_tag` |
  | **Authenticated peer** (dest) — `peer_spiffe_id.is_some()` | dest handler, before any socket opens | 403 | predicate by `authenticated_hbone_*_without_peer_is_rejected` + inline handler reject (`ctx.peer_spiffe_id.is_none()`); the fail-closed OUTCOME is e2e-tested by `functional_mesh_udp_dest_untrusted_peer_fails_closed` (under STRICT inbound the unchained peer is rejected at the TLS layer; the handler's own 403 stays predicate-pinned) |
  | **Open-relay guard** (dest) — loopback / slice-declared workload addr + port only, re-checked on the **post-route-override** effective destination | dest handler | 403 | `inbound_hbone_relay_guard_allows_only_local_destinations` |
  | **Marker discipline** — `udp`/`hbone` predicates disjoint; an unknown / future / malformed (incl. non-UTF-8) marker → neither | dispatch | 405 — the non-WebSocket-CONNECT gate (`!is_hbone_connect_any`) rejects an unrecognized CONNECT before routing; both skew directions | `connect_marker_classification_is_exhaustive_and_fail_closed`, `udp_and_hbone_predicates_are_disjoint` |
  | **Session DoS bounds** — count + queued-bytes + idle sweep | source capture | shed / reap | `session_cap_sheds_new_flows_but_serves_existing`, `egress_enqueue_caps_queued_bytes_not_just_count` |
  | **Return-path isolation** — per-session transparent socket bound to orig-dst, send-only, reply only to the captured client | return path | structural (one socket ↔ one client) | `canonicalize_unmaps_v4_mapped_clients_only`, `teardown_does_not_clobber_replacement_session` |

  There is **no plaintext or alternate-hop fallback** anywhere on the relay: every
  dial error path ends the session. The posture was confirmed by two independent
  read-only audits plus an adversarial red-team pass over 10 attack classes
  (slot/epoch TOCTOU, return-path cross-talk, route-override guard bypass, marker
  confusion, unauthenticated relay, capability drop→open, transport downgrade,
  teardown fail-open, codec desync, orig-dst spoofing) — no fail-open path was
  found. One residual is noted for completeness: the inbound open-relay guard
  validates the destination **string** before DNS resolution, so a workload that
  declared a *hostname* (rather than a pod IP) as its address could in principle
  resolve off-box. This is **not UDP-specific** — the byte-stream HBONE relay's
  `connect_backend` has the byte-for-byte identical resolve-after-string-guard
  pattern — and is inert in practice (workload addresses are pod IPs / loopback,
  which resolve to themselves), so hardening it (validate the *resolved* IP in both
  relays) is out of scope for this UDP stage.
- **Locally-generated pod UDP egress: OUTPUT-MARK → lo-reroute → PREROUTING-TPROXY
  loop.** TPROXY runs **only in `PREROUTING`**, never for locally-generated (OUTPUT)
  packets — jumping into a `-j TPROXY` chain from `mangle OUTPUT` is invalid and can
  make iptables setup fail outright. But Linux routes a pod's **own** application UDP
  egress through **OUTPUT → POSTROUTING and never through PREROUTING**, so the
  PREROUTING TPROXY chains alone would never see the primary egress case (outbound
  UDP capture would be inert in the pod netns). Ferrum closes this with the standard
  "TPROXY for locally-generated traffic" pattern (the injector / pod-netns path):
  - A `mangle OUTPUT` chain `FERRUM_MESH_UDP_OUTPUT_MARK` **MARKs** the pod's egress
    (`-j MARK --set-mark <mark>/<mask>`, **not** TPROXY) using the **same fwmark** the
    PREROUTING TPROXY rules use, with the same include/exclude/CIDR/port scoping. It
    leads with a `-m mark --mark <mark>/<mask> -j RETURN` anti-loop guard and a
    proxy-UID `-m owner --uid-owner <uid> -j RETURN` self-exclusion — **owner-match
    IS valid in OUTPUT** (it is invalid in PREROUTING, which is why the dst-based
    OUTBOUND chain carries no owner RETURN). **The MARK rules ALSO carry the SAME
    `-m addrtype ! --dst-type LOCAL` egress scope (codex r9)** as the PREROUTING
    OUTBOUND TPROXY rules — the two render from one shared selector set so the OUTPUT
    capture scoping matches PREROUTING exactly. In the OUTPUT context the pod's own IP
    AND loopback are `--dst-type LOCAL` (locally generated *and* locally destined),
    while genuine egress to other hosts is non-LOCAL; without the scope the catch-all
    `-p udp -d 0.0.0.0/0 -j MARK` would also fwmark pod-to-self / loopback UDP, reroute
    it to `lo`, and TPROXY-capture it — but self/loopback UDP must **never** be captured
    (only real egress). The proxy's own egress is still separately excluded by the
    owner RETURN above; the `! --dst-type LOCAL` scope additionally covers a **non-proxy
    local destination** (another UID's pod-to-self / loopback datagram) the owner RETURN
    cannot. So locally-generated pod UDP egress is captured **only to real, non-local
    destinations**.
  - The **existing** fwmark `ip rule` (priority `100` → table `33133`) + `ip route add
    local 0.0.0.0/0 dev lo table 33133` then reroute the marked datagram to loopback.
    A `local`-type route makes the kernel treat the datagram as destined for this
    host, so it is diverted to the **INPUT** path (not re-emitted via OUTPUT) — OUTPUT
    is therefore traversed **exactly once** and there is **no loop**.
  - The rerouted datagram re-enters and traverses **PREROUTING** once, where a
    dedicated `FERRUM_MESH_UDP_REINJECT` chain (jumped from PREROUTING **first**)
    holds a single **mark-match** `-p udp -m mark --mark <mark>/<mask> -j TPROXY
    --on-port <udp_port> --tproxy-mark <mark>/<mask>` rule that captures it to the UDP
    capture port. It matches by the **mark** (the only reliable selector — TPROXY /
    loopback do **not** rewrite the header, so the datagram still carries its
    **original remote destination** and would otherwise also match the dst-based
    OUTBOUND chain); xt_TPROXY returns `NF_ACCEPT` and ends traversal, so jumping into
    the reinject chain before the OUTBOUND/INBOUND chains guarantees the rerouted
    datagram is TPROXY'd **exactly once** and never double-processed. The reinject
    rule lives in its own custom chain (reaped by name, mark-independent) rather than
    as a bare PREROUTING rule, so the create+flush idempotency that protects the other
    chains against a changed `FERRUM_MESH_TPROXY_MARK` (the built-in PREROUTING chain
    cannot be flushed) covers it too.

  This is the **injector (pod-netns) path only**. The **node-agent host-netns
  fallback still emits NO UDP rules at all** (the `addrtype` direction split is wrong
  in the host netns — see the pod-netns-only limitation above; eBPF is the supported
  node-agent UDP capture path), so the OUTPUT MARK chain is likewise not emitted
  there. **Full datapath correctness** of the OUTPUT-MARK → lo-reroute →
  PREROUTING-TPROXY loop (and of the PREROUTING-visible inbound/forwarded capture) is
  validated by the **Stage-7 `netns-capture-live` e2e**, not by these unit tests
  (which assert only the emitted rule shapes); the consuming transparent UDP listener
  itself arrives in **Stage 3**, so until then the flag stays default-off.

Cleanup (`IptablesPlan::cleanup_commands(udp_capture_enabled)`) removes all four
`mangle` chains (`FERRUM_MESH_UDP_INBOUND` / `FERRUM_MESH_UDP_OUTBOUND` /
`FERRUM_MESH_UDP_OUTPUT_MARK` / `FERRUM_MESH_UDP_REINJECT`), deletes their
PREROUTING jumps **and the `mangle OUTPUT -j FERRUM_MESH_UDP_OUTPUT_MARK` jump**,
and tears down routing state by deleting **only the EXACT Ferrum-owned rule** (`ip
rule del priority 100 lookup 33133`) and **the exact route** (`ip route del local
0.0.0.0/0 dev lo table 33133`) — never `ip rule del lookup <table>` or `ip route
flush table <table>`, which could drop a co-resident route. Every iptables target
is an exact Ferrum-owned object (chain by name, jump by exact `-j <chain>` spec),
so teardown is **mark-independent** and reaps stale state even across a changed
`FERRUM_MESH_TPROXY_MARK` (the mark-match TPROXY rule lives inside the reinject
chain, reaped by name, never as a bare PREROUTING rule). Cleanup deletes stay
best-effort (`|| true`) — unlike the load-bearing setup adds, teardown must never
fail on already-absent state or a missing `ip` binary. The UDP teardown is **gated
on `udp_capture_enabled`**, so a non-UDP install never touches routing state it
never created. The init container already grants `NET_ADMIN`, which covers the
TPROXY/MARK targets, the `addrtype` direction scoping, the owner-match, and the `ip
rule`/`ip route` plumbing — no extra capability is needed.

## Control Plane Integration

### MeshGrpcServer

The `MeshConfigSync.MeshSubscribe` streaming RPC is served by `MeshGrpcServer` in `src/grpc/mesh_server.rs`. It runs on the Control Plane alongside the regular `ConfigSync` service.

- **JWT authentication** on every subscribe request.
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

- `topology: ambient` (default) — same-cluster/local targets carry `mesh.hbone=true` and dispatch through the HBONE outbound pool (HTTP/2 CONNECT over SVID mTLS to the peer's `:15008` listener). This is the right choice when the destination mesh runs the Ambient/waypoint topology. Remote-cluster workloads use the same east-west shape as mesh-mode Ambient when the snapshot carries `mesh.multi_cluster`, the upstream's selected service port is an **effective HTTP-family port** (any port, not just the first — multi-port east-west, issue #2010 phase 3), and an east-west gateway is declared for the workload's network (or a catch-all gateway applies): one target per remote pod, synthetic host identity scoped by gateway endpoint + pod address, `mesh.hbone_authority_host=<remote pod addr>` as the inner CONNECT authority, `mesh.hbone_dial_host` / `mesh.hbone_port` as the gateway dial override, `mesh.eastwest_sni=<base FQDN for a single-port service, or the `p<port>.<fqdn>` alias for each port of a multi-port service>` for SNI passthrough, `mesh.remote=true`, and no pinned `mesh.spiffe_id` (remote trust-domain verification only). Flat-network compatibility is retained only when no gateway is declared for the workload network and no applicable catch-all gateway (a candidate whose `sni_hosts` claim the base FQDN **or** the dialed per-port alias, plus a trust-domain match, for the destination) exists; once a gateway is declared for the workload's network — or an applicable catch-all exists — SNI/trust-domain/port mismatches skip the remote target fail-closed instead of falling back to a direct pod dial. A catch-all gateway that is not a candidate (its `sni_hosts`/trust domain cannot route this destination) does not suppress the fallback; an exact-network declaration is authoritative even when it is not a candidate.
- `topology: sidecar` — targets carry `mesh.mtls=true` and dispatch through the Sidecar SVID-mTLS pool (plain HTTP/2 over mutual TLS to the peer sidecar's `:15006` inbound listener). Every sidecar target also carries `mesh.mtls_authority_host` (the destination service's `<name>.<namespace>.svc` host variant): a north-south gateway's client `Host` is typically a public hostname the destination sidecar's materialized inbound routes would 404, so dispatch forces this service host as the request `:authority` (the original client `Host` rides `x-forwarded-host`). When the destination service declares **more than one** effective HTTP-family port (`protocol_overrides` applied — the same `service_http_family_ports` predicate mesh-mode materialization uses), each target additionally carries `mesh.mtls_authority_port` (the owning Service port) so the peer's per-port inbound siblings can disambiguate the direct `:15006` dial — the same contract mesh-mode Sidecar egress applies. **Remote-cluster workloads are never published as direct `remote-pod:15006` dials on the sidecar path** — such a dial with a pinned pod SPIFFE would fail in any multi-network mesh while looking like a routable failover target. Instead, when the snapshot carries `mesh.multi_cluster` and the upstream's selected service port is an **effective HTTP-family port** (any port, not just the first — multi-port east-west, issue #2010 phase 3), the provider bridges them east-west exactly like mesh-mode egress — through the same shared `append_cross_cluster_mesh_targets` core, not a fork: reachable remote workloads (≥1 address, resolvable selected-port `targetPort`) are grouped per `(network, trust_domain)` and each group emits **one failover target at its remote east-west gateway endpoint** (resolved from `mesh.multi_cluster.east_west_gateways` with the same fail-closed network/SNI/trust-domain selection — the gateway is SELECTED by the base service FQDN **or** the per-port alias being dialed), tagged `mesh.cross_cluster=true` + `mesh.eastwest_sni=<the base FQDN for a single-port service, or the `p<port>.<fqdn>` alias for each port of a multi-port service>` + `mesh.mtls_port=<gateway port>` + `mesh.remote=true` and carrying **no pinned pod SPIFFE** (trust-domain-only verification). The SD bridge adds one tag on top of the materializer's shape: `mesh.mtls_authority_host` (`<name>.<namespace>.svc`), because the destination sidecar routes the inner mesh-mTLS request by `Host` — mesh-mode egress relies on the client `Host` already being the service host, which a north-south gateway's public client `Host` is not (no `mesh.mtls_authority_port` is stamped: cross-cluster traffic reaches the destination via its app port + inbound capture, which disambiguates multi-port by orig-dst). The east-west SNI FQDN is synthesized as `{service}.{namespace}.svc.<FERRUM_MESH_CLUSTER_DOMAIN>` (default `cluster.local`), and the load balancer treats `mesh.cross_cluster` targets as always-failover local-first. The SD provider is HTTP-family dispatch by design, so non-HTTP-family selected ports remain outside that bridge; mesh-mode raw-TCP/UDP capture uses the separate L4 materializers described above. A snapshot without `mesh.multi_cluster`, or a remote group with no matching east-west gateway, stays skipped fail-closed.

The two transports are **not interchangeable**: mesh transports are per-topology (see [Datapath Layering](#gateway-to-mesh-bridge)), and a Sidecar peer has no HBONE listener — an `ambient`-topology upstream pointed at sidecar workloads fails closed with a `502` at dispatch rather than silently downgrading. Configure `topology` to match the destination mesh.

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

Reserved mesh-managed plugin IDs are updated in place on each slice apply. If a prepared `GatewayConfig` already contains an operator-managed global plugin of the same plugin type but a different ID, that operator plugin takes precedence and the corresponding mesh injection is suppressed. Native/xDS `MeshSlice` feeds do not currently transport operator `plugin_configs`; this override hook applies only to prepared configs that enter mesh preparation with plugin configs already present. See [plugin_execution_order.md](plugin_execution_order.md) for the full lifecycle phase matrix.

## Gateway-to-Mesh Bridge

Non-mesh gateway modes (`database`, `file`, `cp`, `dp`) can route traffic into the mesh via the gateway-to-mesh bridge. This enables a Ferrum gateway operating as an ingress or API gateway to forward requests to mesh workloads over the destination topology's secured transport with full SPIFFE mTLS: **HBONE** (`:15008`) for Ambient/waypoint destinations, **plain SVID-mTLS HTTP/2** (`:15006`) for Sidecar destinations. The transport is selected per upstream by `service_discovery.mesh.topology` (or by which `mesh.*` transport tag statically configured targets carry); it must match the destination mesh's topology — the transports are not interchangeable, and a mismatch fails closed at dispatch.

### Trust Bundle Distribution

The Control Plane distributes gateway SPIFFE trust bundles to Data Planes via a `trust_bundles_json` side channel on the `ConfigUpdate` proto message. DPs hot-swap received bundles into the gateway SVID identity slot, enabling mutual TLS with mesh sidecars without requiring the DP to independently obtain certificates.

### HBONE Outbound Pool

When an upstream target is tagged with `mesh.hbone=true` metadata, the gateway routes requests through an HBONE HTTP/2 CONNECT pool (`HboneOutboundPool`) instead of direct HTTP. The pool uses the gateway's SPIFFE identity for mTLS and keys connections by SVID fingerprint so certificate rotation triggers fresh connections. DNS resolution uses the shared `DnsCacheResolver`. A target may optionally carry `mesh.hbone_dial_host` to separate the outer TCP/TLS destination from the inner CONNECT authority host, and `mesh.hbone_peer_spiffe_id` to pin a waypoint/relay peer identity while leaving `mesh.spiffe_id` as destination workload metadata.

On HBONE connect failure or malformed HBONE target metadata, tagged dispatch fails closed with an HBONE error response instead of falling back to plain HTTP.

### Sidecar SVID-mTLS Outbound Pool

When an upstream target is tagged with `mesh.mtls=true` metadata (a Sidecar-topology destination), the gateway routes requests through the Sidecar mesh-mTLS pool (`MeshMtlsConnectionPool`) — plain HTTP/2 over mutual TLS to the peer sidecar's `:15006` inbound listener — using the same gateway SPIFFE identity and SVID-fingerprint pool keying as HBONE. The target's `mesh.spiffe_id` pins the expected peer identity: the destination sidecar's server SVID URI SAN must equal it, so trust-domain membership alone is not enough. A `mesh.mtls`-tagged target that cannot dispatch over the secured transport (missing gateway SVID, missing pinned peer) fails closed with a `502` instead of falling back to plain HTTP.

### Mesh Service Discovery

A `service_discovery.provider: mesh` option resolves upstream targets from CP-delivered mesh service and workload snapshots. The provider maps workload addresses and ports into upstream targets with SPIFFE identity tags plus the configured topology's transport tag (`mesh.hbone` for `ambient`, `mesh.mtls` for `sidecar` — see [Gateway Mesh Service Discovery](#gateway-mesh-service-discovery)), enabling the matching outbound pool to route transparently. Target lists refresh on the provider's **poll interval** (`poll_interval_seconds`, default 30s): each poll reads the *current* CP-delivered snapshot, so a mesh update is picked up within one poll interval — a CP push does not refresh targets immediately. Lower the interval for tighter failover/scale-up latency.

Identity baggage from the client request is stripped from tunneled inner HBONE requests to prevent identity spoofing across the gateway boundary.

## Mesh Identity

### SPIRE Agent CA

`FERRUM_MESH_CA_BACKEND=spire_agent` delegates SVID issuance to a SPIRE Agent via the SPIFFE Workload API. The mesh data plane connects to the SPIRE Agent socket, waits for an initial X.509-SVID before binding listeners, and installs the pushed SVID into the same gateway SVID slot used by outbound HBONE/SVID-mTLS and inbound SPIFFE peer verification. The returned SPIFFE ID must match `FERRUM_MESH_WORKLOAD_SPIFFE_ID`.

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_CA_BACKEND` | `none` | CA backend: `none` (no automatic identity), `internal` (self-signed dev CA), `spire_agent` (SPIRE Workload API) |
| `FERRUM_MESH_SPIRE_AGENT_SOCKET` | `/run/spire/sockets/agent.sock` | SPIRE Agent Workload API Unix socket path |
| `FERRUM_MESH_CERT_TTL_SECONDS` | `3600` | Requested certificate TTL for issued SVIDs |
| `FERRUM_MESH_WORKLOAD_SPIFFE_ID` | none | Required when `spire_agent` or `internal` is the selected identity source; identifies the local workload SVID to fetch or mint |

The SPIRE backend is the recommended production path for mesh identity. `internal` is intended for development and testing only -- it generates a self-signed root CA at startup with no external trust anchor. Explicit file-based `FERRUM_GATEWAY_SVID_*` material takes precedence over `FERRUM_MESH_CA_BACKEND`; when both are configured Ferrum uses the file SVID and does not start automatic CA-backed issuance.

### Internal Dev CA and Production Guardrails

The `internal` CA backend is backed by a self-signed root produced by the dev bootstrap helper in `src/identity/ca/bootstrap.rs`. To make it impossible to accidentally run a production mesh on an unanchored self-signed root, the helper is protected by two environment guardrails, both read directly at the time the helper is invoked (they are **not** parsed into `EnvConfig`):

| Variable | Default | Semantics |
|---|---|---|
| `FERRUM_MESH_PRODUCTION_MODE` | `false` | Master kill-switch for all dev-only identity shortcuts. When `true`, the self-signed CA bootstrap is **refused unconditionally**, and so is construction of the dev-only static attestor (`FERRUM_MESH_ALLOW_STATIC_ID`). Set this in every production deployment. |
| `FERRUM_MESH_CA_BOOTSTRAP_DEV` | `false` | Explicit opt-in to generate a self-signed mesh root. The helper refuses unless this is `true`. When it runs it emits a loud `warn!` (`DEV-ONLY, never use in production`). |
| `FERRUM_MESH_ALLOW_STATIC_ID` | `false` | Sibling guardrail (not CA-specific): the dev-only `StaticAttestor`, which returns a hard-coded SPIFFE ID for any peer, refuses to construct unless this is `true` and `FERRUM_MESH_PRODUCTION_MODE` is not `true`. |

Both gates must agree before a self-signed root is minted: `FERRUM_MESH_CA_BOOTSTRAP_DEV=true` **and** `FERRUM_MESH_PRODUCTION_MODE` not `true`. Anything else fails closed.

Relatedly, running the Experimental `FERRUM_MESH_TOPOLOGY=node_waypoint` topology under `FERRUM_MESH_PRODUCTION_MODE=true` logs a startup `warn!` (not a refusal — the production identity guardrails all still apply, and the NodeWaypoint eBPF live gate deliberately runs the production identity profile) noting that Experimental surfaces are excluded from the GA contract (see [mesh_supported_matrix.md](mesh_supported_matrix.md)).

For production mesh identity, run the SPIRE Agent backend (`FERRUM_MESH_CA_BACKEND=spire_agent`) so SVID issuance and trust-bundle distribution are anchored to a separately operated trust root. There is no `FERRUM_MESH_CA_CERT_PATH` / `FERRUM_MESH_CA_KEY_PATH` env var today — those names appear only in the bootstrap helper's refusal message as guidance for a future externally-provided-root path and are not currently read by any code path.

**No-identity startup gate.** A third member of this guardrail family is enforced at config-validation time rather than inside the identity helpers. A `mesh` data plane's runtime workload identity can come from file-based gateway SVID material (`FERRUM_GATEWAY_SVID_CERT_PATH` + `KEY_PATH` + `TRUST_BUNDLE_PATH`) or automatic CA-backed SVID issuance (`FERRUM_MESH_CA_BACKEND=spire_agent|internal` plus `FERRUM_MESH_WORKLOAD_SPIFFE_ID`). With neither source, the mesh can't present or verify an mTLS peer certificate, so PeerAuthentication's PERMISSIVE default would silently accept unauthenticated plaintext. `EnvConfig` validation therefore **fails startup closed** in that no-identity case unless the operator sets `FERRUM_MESH_ALLOW_NO_CA=true` to acknowledge the dev/test-only posture (a loud `warn!` is logged when it does start that way). That opt-out is read **directly from the environment** (not `ferrum.conf`), matching the rest of the family. As with the other shortcuts, `FERRUM_MESH_PRODUCTION_MODE=true` refuses the no-identity posture **unconditionally** — the opt-out is ignored — so a production mesh can never come up without identity.

**Runtime inbound mTLS fail-closed (the robust complement).** The gate above is a fast config-time *presence* check; it cannot see whether the SVID files actually load or whether the resolved PeerAuthentication mode would still leave the inbound listener serving plaintext. The mesh therefore also fails closed at the runtime TLS-setup path, where the inbound listener's real posture is known (`enforce_mesh_inbound_fail_closed`). Three refinements make this exact:

1. **Gateway/runtime SVID backs the inbound server identity.** When no explicit `FERRUM_FRONTEND_TLS_CERT_PATH` / `KEY_PATH` is set, the mesh workload SVID backs the inbound listener's server certificate, so a mesh configured with only workload SVID material presents that SVID as its inbound server cert and serves mTLS instead of falling open to plaintext under the default PERMISSIVE mode. Both SVID sources resolve the same way: the inbound server certificate **resolves live from the gateway SVID slot** (a rustls `ResolvesServerCert` backed by the same shared slot that receives rotations). For **file-based `FERRUM_GATEWAY_SVID_*`** material the SVID file watcher feeds that slot, so after a file-based SVID rotation the inbound listener presents the new leaf on the next handshake and refreshes the SPIFFE peer verifier from the rotated trust bundle plus the last accepted federated overlay, with no restart or slice apply. For **CA-backed SVIDs** (`FERRUM_MESH_CA_BACKEND=spire_agent` / `internal`) the CA-backed SVID source (`start_mesh_ca_backend_svid_source`) installs each issued SVID into the same slot, so inbound server identity and peer-verifier local roots follow CA/SPIRE rotation through the identical live resolver. In-flight TLS sessions keep their established parameters; only new handshakes see the new leaf and verifier roots. Fail-closed semantics: at startup a configured SVID source whose slot holds no usable material hard-errors before listeners bind, and if a later rotation installs material that cannot back a server certificate (or empties the slot), inbound handshakes fail — loudly, once per bad rotation — rather than silently serving a stale leaf that masks a broken rotation pipeline until it expires. Explicit `FERRUM_FRONTEND_TLS_*` material remains a static operational input (the operator owns its rotation; the frontend live-reload flag covers it separately).
2. **Suppress plaintext on production inbound listeners.** Under `FERRUM_MESH_PRODUCTION_MODE=true`, a `PERMISSIVE` workload or app port with usable server TLS material is accepted at startup and on live reload, but plaintext demultiplexing is disabled and that port runs TLS-only. A mode that cannot produce a usable TLS config (including `DISABLE` or missing server identity) is refused at startup. With PeerAuthentication live reload enabled, such an incoming slice is rejected in its entirety and the last-good policy remains active. In development, plaintext-capable modes are allowed with a loud warning: reaching plaintext there is intentional — either an explicit `PeerAuthentication` mode or a no-identity posture admitted by the config-time `FERRUM_MESH_ALLOW_NO_CA` gate.
3. **Refuse a configured-but-broken SVID verifier.** If gateway SVID material is configured (all three `FERRUM_GATEWAY_SVID_*` paths named) but fails to load while the listener serves TLS — e.g. a valid leaf/key but a corrupt trust bundle — the SPIFFE peer-trust-domain verifier would be silently absent. The operator named all three paths intending verification, so this is a genuine fault, **fatal regardless of `FERRUM_MESH_PRODUCTION_MODE`** (mirroring how a broken SVID cert/key already hard-errors; `ProxyState` construction independently rejects the same broken material). This is distinct from the dev-tolerated plaintext cases above.

Topologies with no TLS-terminating inbound listener (EastWestGateway SNI passthrough forwards encrypted bytes) are exempt from all three.

When `FERRUM_MESH_CA_BACKEND=spire_agent`, rotation is pushed by the SPIRE Agent Workload API stream and backend pool generations advance after each post-startup update. When `FERRUM_MESH_CA_BACKEND=internal`, Ferrum mints an initial dev SVID and rotates it at half of its validity window; post-startup rotation failures keep the current identity and retry with jittered exponential backoff. In both modes, startup refuses to bind listeners until the first SVID is loaded.

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
  meshCapture:
    includeCidrs: []       # empty = capture all
    excludeCidrs: []
    excludePorts: []
```

Required Linux capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` (kernel >= 5.8), `CAP_SYS_ADMIN` for kernel-backcompat on 5.7.x and for every `node_waypoint` deployment's pod-netns `setns()`/veth discovery. Required volume mounts: `/sys/fs/bpf` (bpffs), `/sys/fs/cgroup` (cgroup v2, read-only). Required host access: `hostNetwork: true`, `hostPID: true`. See [`docs/node_agent_security.md`](node_agent_security.md) for the full security posture, including seccomp / AppArmor profiles and the kernel API each capability grants.

### Ambient UDP upgrade notes

Ambient topology now keeps the per-pod registry and stale-rule cleanup lifecycle
active even when UDP capture is disabled. Consequently, an Ambient node without
eBPF support refuses node-agent startup instead of entering the former host
iptables fallback: that fallback cannot publish the registry, so proceeding
would strand fail-closed pod-netns guards. Existing Ambient fleets relying on
the fallback must move workloads to eBPF-capable nodes before upgrading.

The Helm chart provisions every `ambient` deployment with an enabled node-agent
for this lifecycle, including when UDP capture is currently off and even when
`nodeAgent.captureMode=iptables`. Both DaemonSets receive the shared registry and
`FERRUM_MESH_TOPOLOGY=ambient`, so an iptables fallback reaches the node-agent's
fail-closed startup check instead of silently bypassing cleanup. In the supported
eBPF configuration, the node-agent/proxy pair uses the tools-capable `-ebpf`
image, shares the pod-registry hostPath, and grants the setns/`NET_ADMIN`
capabilities needed for stale pod-netns cleanup. This is a deliberate
security-footprint increase that makes a later enabled-to-disabled rollout
repairable without another chart shape change.

Every node-agent restart re-derives enrollment from the live Kubernetes pod
list. During that relist it removes existing `.udp-ready` markers and closes the
host-veth UDP gate; producers rewrite readiness on their next registry poll
(at most two seconds) and the node-agent reopens the gate on its next readiness
reconcile (at most 250 ms). Budget roughly 2.5 seconds of fail-closed UDP
unavailability per node-agent restart; traffic is dropped during the interval,
not allowed to bypass capture.

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

Mesh ambient mode requires Linux kernel >= 5.7 with cgroup v2 and bpffs for the per-pod eBPF capture path. The node agent fails fast on degraded nodes by default (`FERRUM_NODE_AGENT_FALLBACK_MODE=fail`), matching the published distroless image. The rest of the mesh data plane (slice apply, `mesh_authz`, `mesh_workload_metrics`, HBONE) is unaffected. Operators with a mix of supported and unsupported kernels should:

1. Alert on node-agent readiness/startup failures, `ferrum_node_agent_capture_state{state!="ready"} == 1`, and `ferrum_mesh_node_topology_degraded == 1` to track the degraded set.
2. Label degraded nodes (e.g., `ferrum.io/capture-mode=iptables`) and configure the admission webhook (`FERRUM_MODE=injector`) to inject iptables init containers on those nodes.
3. Upgrade kernels to >= 5.7 with cgroup v2 + bpffs as the long-term remediation.

Set `FERRUM_NODE_AGENT_FALLBACK_MODE=iptables` only when running a custom node-agent image that includes `/bin/sh`, `iptables`, and `ip6tables` when IPv6 capture is enabled.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FERRUM_NODE_AGENT_NODE_NAME` | (required) | Kubernetes node name, set via downward API (`spec.nodeName`) |
| `FERRUM_NODE_AGENT_NODE_IP` | (empty) | Single trusted host source IP used to reach local pods. **Required in NodeWaypoint**: the inbound HBONE relay dials backend pods from this node-local source, and the source-bound guard drops the relay's traffic (and all direct inbound to enrolled pods) without it — the agent fails closed when no node source IP is set. Also exempts kubelet HTTP/TCP/gRPC probe ports derived from the enrolled pod spec. CNI-specific (e.g. the pod-CIDR gateway, which may differ from `status.hostIP`); the Helm chart does not auto-populate this value. |
| `FERRUM_NODE_AGENT_NODE_IPS` | (empty) | Comma-separated trusted host source IPs; merged with `FERRUM_NODE_AGENT_NODE_IP` for the same allowlist. **Required in NodeWaypoint** for every address family used by enrolled pods — a dual-stack node needs both an IPv4 and an IPv6 source, or that family's relay dials are dropped and enrollment reports the topology degraded. Do not include broad host-network sources. |
| `FERRUM_NODE_AGENT_CGROUP_ROOT` | `/sys/fs/cgroup` | cgroup v2 mount point for pod cgroup resolution |
| `FERRUM_NODE_AGENT_BPF_FS_PATH` | `/sys/fs/bpf` | BPF filesystem mount point for pinned maps |
| `FERRUM_NODE_AGENT_BPF_ELF_PATH` | build-tree path | Compiled `ferrum-ebpf` ELF loaded by the aya backend (Linux `ebpf` feature only) |
| `FERRUM_NODE_AGENT_PROXY_MODE` | `local_pod` | Capture topology contract: `local_pod` or `node_waypoint` |
| `FERRUM_NODE_AGENT_ADMIN_ENABLED` | `false` | Enables the node-agent read-only admin listener for metrics/health. When enabled, defaults to loopback unless `FERRUM_ADMIN_BIND_ADDRESS` or `FERRUM_ADMIN_ALLOWED_CIDRS` is set; `/metrics` requires an admin JWT, `FERRUM_METRICS_BEARER_TOKEN`, or a source in `FERRUM_METRICS_ALLOWED_CIDRS`, while health detail requires authenticated admin access. |
| `FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT` | `15008` | HBONE redirect/listener port written into the capture contract and BPF config map. Must match the mesh proxy HBONE listener (`15008` today). |
| `FERRUM_NODE_AGENT_FALLBACK_MODE` | `fail` | Behaviour when eBPF prerequisites are missing (kernel < 5.7, cgroup v1, or bpffs unmounted). Default `fail` refuses startup with a structured error. `iptables` falls back to host iptables capture and sets `ferrum_mesh_node_topology_degraded=1`, but requires a runtime image with `/bin/sh`, `iptables`, and `ip6tables` when IPv6 capture is enabled. See [node_agent.md](node_agent.md#kernel-fallback). |
| `FERRUM_NODE_AGENT_EXCLUDED_NAMESPACES` | (empty) | Extra namespaces to exclude from capture (`kube-system`, `kube-public`, `kube-node-lease` always excluded) |
| `FERRUM_MESH_CAPTURE_INCLUDE_CIDRS` | `0.0.0.0/0` | CIDRs to capture for outbound traffic |
| `FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS` | (empty) | CIDRs to exclude from outbound capture (highest priority) |
| `FERRUM_MESH_CAPTURE_EXCLUDE_PORTS` | `15001,15006,15008,15020` | Destination TCP ports excluded from outbound capture |
| `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` | (empty) | Destination TCP and UDP ports excluded from inbound capture (mirrors Istio `excludeInboundPorts`; pod annotation `traffic.sidecar.istio.io/excludeInboundPorts` is additive) |
| `FERRUM_MESH_IP6TABLES_ENABLED` | `auto` | IPv6 iptables fan-out: `auto` probes and skips IPv6 rules when `ip6tables` is unavailable, `true` requires it when IPv6 CIDRs are configured and fails all capture setup before IPv4 rules if unavailable, `false` emits IPv4-only capture rules |

## VirtualService Translation

Istio `VirtualService` resources are translated at the Kubernetes translation layer into Ferrum proxy configuration. Beyond basic route splitting (documented in [configuration.md](configuration.md)), the following per-route features are supported:

### Retries

VirtualService `retries` populate the emitted proxy's retry policy and are also projected onto each emitted `mesh_route_dispatch` rule as route-local `retry` (Ferrum `RetryConfig` after strict admission):

- `attempts` -> `max_retries`
- `retryOn` tokens: `5xx`, `gateway-error`, `connect-failure`, `reset`, `retriable-4xx`, and numeric status codes (e.g., `503`).
- `perTryTimeout` -> per-attempt timeout.

Route-local `retry` and destination `backend_tls` objects reject unknown keys at plugin admission (same fail-closed contract as `reject_unmatched` / `requires_node_waypoint_authz`). Shared proxy/upstream `RetryConfig` and `BackendTlsConfig` deserialization paths are unchanged; only the mesh-route wire shapes are strict.

### Timeout

VirtualService `timeout` is translated to the proxy's `backend_read_timeout_ms`. Supports Go-style duration strings (`10s`, `500ms`, `1m`, `1h`).

### Fault Injection

Per-route `fault` rides on each emitted `mesh_route_dispatch` rule as a per-rule `fault` action (`{delay, abort}`) — the same `FaultRoller` math the proxy-scoped `fault_injection` plugin uses, scoped to the matching dispatch rule. This replaces the historical proxy-scoped emission, which could not be collapsed with sibling routes and previously fail-closed any merged route that carried fault.

- `fault.abort.httpStatus` + `fault.abort.percentage` → rule `fault.abort` with `status_code` + `percentage`. `abort` is dropped (along with the rest of the rule's fault) when `httpStatus` is missing or the percentage is `0`; an accompanying valid `delay` still projects.
- `fault.delay.fixedDelay` + `fault.delay.percentage` → rule `fault.delay` with `duration_ms` + `percentage`. `fixedDelay` accepts Istio's Go-style duration syntax. Positive values above Ferrum's one-minute runtime cap are clamped to 60 seconds, with a translator warning and `status.ferrum.translation.clamped_fields` entry; zero or unparseable values are omitted.
- `fault.abort.grpcStatus` (string or numeric `0..=16`) → `fault.abort.grpc_status`. The header is only stamped when the immutable pre-plugin request flavor is native gRPC; gRPC-Web, WebSocket, and plain HTTP never receive a stray `grpc-status` header even if an earlier hook rewrites `content-type`.

**Delayed-work retention bounds:** a per-rule delay shares the proxy-scoped plugin's bounds exactly — the one-minute ceiling, the process-wide `FERRUM_MAX_CONCURRENT_FAULT_DELAYS` budget (shared with every `fault_injection` instance), and cancellation on peer departure or shutdown drain. A delay cut short because the client transport is gone rejects `499` instead of falling through to the route override; the reason is recorded in `fault_delay_outcome`. See `docs/plugins.md` → `fault_injection`.

**Ordering:** when both delay and abort trigger on the same request, the delay runs first, then the abort fires — matching the proxy-scoped `fault_injection` plugin so the two surfaces stay semantically identical. A global / proxy-scoped `fault_injection` plugin running before this one (priority 2940 vs 2995) sets `ctx.metadata["fault_injected"]=true`, and the per-rule fault no-ops in that case so the two surfaces never stack a second delay + abort.

**RTDS scope (limitation):** the static percentages baked into a per-rule fault action are **not** runtime-tunable via the GAP-3E RTDS keys `ferrum.fault_injection.<scope>.{abort,delay}_percent` — those keys apply only to `fault_injection` plugin instances configured with a non-null `runtime_overlay_scope`. A null scope is equivalent to omission. Operators who need RTDS-driven fault percentages should either use a global / proxy-scoped `fault_injection` plugin with `runtime_overlay_scope`, or wait for a follow-on PR that introduces per-rule RTDS scoping.

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

- `rewrite.uri` → the request path forwarded to the backend. When the route's `match.uri` is a `prefix`, Istio prefix-rewrite semantics apply — only the matched prefix is replaced and the remainder is preserved (`/api/users` with `prefix: /api`, `rewrite.uri: /v2` → `/v2/users`). For `exact` / `regex` matches (and URI-less matches) the whole path is replaced. The original path is still used for route selection and logging.
- `rewrite.authority` → the authority forwarded to the backend. The plugin writes the new authority into the request `Host` header and flips `preserve_host_header` on the effective proxy. For HTTP/1.1 backends (reqwest) the `Host` header is the on-wire request authority, so the rewrite takes full effect. For HTTP/2, gRPC, and HTTP/3 backends the `:authority` pseudo-header is derived from the backend connection target URL (the pool key's host/port), not the `Host` header; the rewrite lands in the `Host` header that travels as an application header within the H2/H3 frame, but the protocol-level `:authority` follows the backend target. HBONE CONNECT carries the rewritten `Host` in its CONNECT request headers, which the receiving mesh proxy reads as the application authority.

CRLF (and, for authority, whitespace) in rewrite values is rejected at config-load time.

### Redirect

Per-route `redirect` (Istio `http[].redirect`) rides on each emitted `mesh_route_dispatch` rule as a per-rule `redirect` action. When the rule matches, the request is answered with a 3xx + `Location` response and never reaches a backend (so a redirect route needs no `route[]` backend — Istio forbids `route` + `redirect` together):

- `redirect.uri` → replacement path (request path preserved when unset).
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

When `FERRUM_K8S_CONTROLLER_ENABLED=true` and Gateway API watching is enabled, the controller watches `GatewayClass`, `Gateway`, `HTTPRoute`, `GRPCRoute`, `TCPRoute`, and `TLSRoute` resources and writes their status subresources. When Istio status writing is also enabled, both writers observe the same immutable Kubernetes object generation for that reconcile (one shared snapshot; no second full deep copy), while retaining independent update plans and failure handling. Status planning builds immutable indexes (managed classes/gateways, parent refs, a precomputed ReferenceGrant from×to permission index, services/secrets, conflicts) once per reconcile, reuses the primary translation/materialization result (plus per-object skip errors keyed with exact-or-versionless identity) instead of retranslating a filtered snapshot once per status object, and borrows included `K8sObject` values during translation rather than deep-cloning `spec`/`status` JSON. Gateway API status planning alone applies a fair deterministic work budget of 256 candidates *before* expensive per-object status computation so the cap bounds CPU as well as API writes. All eligible Gateway API status kinds — including GatewayClass and Gateway — share that deterministic window (planning itself can be expensive, so these kinds are not exempted), and therefore enter it within at most `ceil(eligible_candidates / 256)` successful planning/patch rounds for a stable candidate set. The rotating cursor advances after an empty successful plan or a successful patch batch; patch errors and batch timeouts leave the cursor unchanged so the same bounded window retries on the next serialized reconcile. Istio status planning reuses the same translation/index snapshot path but remains unlimited. Each writer's complete Kubernetes status-patch batch has a 60-second wall-clock ceiling: a stalled API request is cancelled so it cannot retain the reconcile loop indefinitely, and unfinished updates are retried by a later watch event or periodic full sync. GatewayClass and Gateway status use Kubernetes server-side apply with the stable `ferrum.io/gateway-controller` field manager and `force=true`; their structural condition/listener arrays are keyed list-maps, so Ferrum applies only the fields it owns. Route `status.parents` is atomic in the upstream CRDs and therefore cannot be safely split by SSA ownership. Route writes instead follow the Gateway API read-modify-write mandate: preserve fresh non-Ferrum parents, replace Ferrum-owned parents, guard the merge patch with `metadata.resourceVersion`, and refetch/re-merge/retry up to five times with jitter after `409 Conflict`. Ferrum manages only `GatewayClass` objects whose `spec.controllerName` is `ferrum.io/gateway-controller`. `Gateway.status.conditions` and route `status.parents[].conditions` include Ferrum-authored `Accepted`, `Programmed`, `ResolvedRefs`, and `Conflicted` entries with that controller name. The status writer is driven by the same translation inputs as the control-plane config: accepted routes report programmed from typed route-to-parent materialization records captured when Ferrum generates proxies (never by parsing proxy IDs), rejected routes report unresolved references for cases such as missing `ReferenceGrant` authorization or unsupported backend target kinds, and route collisions report `Conflicted=True`. Live `TCPRoute` attachment/traffic/status/update/deletion evidence is release-gated by the Gateway API conformance black-box lab (see [`docs/gateway_api_conformance.md`](gateway_api_conformance.md)); Ferrum does not advertise an upstream `GATEWAY-TCP` profile on the pinned Gateway API `v1.5.1` channel.

Gateway API HTTP/GRPC route conflicts are resolved deterministically before config materialization. For routes that would produce the same parent reference, hostname, and Ferrum listen path, the oldest `metadata.creationTimestamp` wins; if timestamps tie or are absent, `{namespace}/{name}` order is the tiebreaker. Losing routes are skipped during translation and receive `Accepted=False`, `Programmed=False`, and `Conflicted=True` status.

Gateway listener `allowedRoutes.namespaces.selector` is an atomic security
boundary. Ferrum validates the complete selector before attachment, including
Kubernetes label-key/value syntax, string-only `matchLabels`, expression field
types, the `In`/`NotIn` non-empty-values rule, and the
`Exists`/`DoesNotExist` empty-values rule. Any malformed component invalidates
that listener as a whole: no subset of its AND requirements is retained, no
cross-namespace route attaches, and a valid-to-invalid update withdraws prior
materialization. Listener status reports `Accepted=False` and
`Programmed=False` with reason `Invalid` and a stable, value-redacted field
path. Valid `All`, `Same`, empty-selector, and well-formed selector behavior is
unchanged, and valid sibling listeners reconcile independently.

Gateway API status writing requires `get/list/watch` on `gatewayclasses`, `gateways`, `httproutes`, `grpcroutes`, `tcproutes`, `tlsroutes`, and `referencegrants`, plus `patch` on their `status` subresources. `GatewayClass` is cluster-scoped; route and Gateway watches are namespaced when `FERRUM_K8S_WATCH_NAMESPACES` is set. The Helm chart grants these verbs through `controlPlane.rbac.*`; disable unused watches there when installing a narrower controller.

## Istio CRD Status

When `FERRUM_K8S_CONTROLLER_ENABLED=true` and Istio CRD watching is enabled (`FERRUM_K8S_WATCH_ISTIO_CRDS=true`, the in-pod default), the controller writes a `status.conditions[]` block to every Istio CRD it translates so `kubectl describe <kind> <name>` shows how Ferrum interpreted the resource. All ten translated kinds are covered: `AuthorizationPolicy`, `PeerAuthentication`, `RequestAuthentication`, `DestinationRule`, `VirtualService`, `ServiceEntry`, `WorkloadEntry`, `Sidecar`, `Telemetry`, and `ProxyConfig`. Istio status planning shares the same primary-translation reuse path as Gateway API status (one materialization plus skip errors; no per-object filtered retranslate) and remains unlimited — the rotating 256-candidate budget is Gateway API only.

Each resource gets a single Ferrum-owned `FerrumAccepted` condition (field manager `ferrum.io/istio-controller`) alongside a `status.ferrum.translation` detail block:

- **Accepted** — successful translation writes `FerrumAccepted=True` with a per-kind reason (`Accepted`, plus `AllowNothing`/`NoOp` for AuthorizationPolicy empty-rule semantics). The detail block carries kind-specific context: rule/host/route counts, the resolved PeerAuthentication mTLS mode and port overrides, ServiceEntry `resolution`/`location`, RequestAuthentication scope and permissive-by-default note, the WorkloadEntry service account, the Sidecar egress scope, the Telemetry sections present, or the ProxyConfig scope plus concurrency/image/environment/tracing.sampling fields.
- **Rejected** — a translator error (`K8sTranslateError`) writes `FerrumAccepted=False`, reason `Invalid`, with the error text in both the condition message and `status.ferrum.translation.error`. This is the gap this surface closes: a hard rejection of any translated kind is now visible to operators instead of being silently dropped from the slice.
- **Deferred fields** — fields Ferrum parses but does not yet enforce are listed in `status.ferrum.translation.deferred_fields` (and summarized in the condition message) so operators see the gap. Current DestinationRule deferred sets: `connectionPool.http.maxRequestsPerConnection` is deferred at top-level, `portLevelSettings`, and subset scope because backend close-after-N-requests is unsupported; `connectionPool.http.{h2UpgradePolicy,maxRetries,http1MaxPendingRequests}` are deferred ONLY when set inside a `subsets[].trafficPolicy` (applied at top-level/port, but the subset apply path builds a `SubsetTrafficPolicy` with no `connectionPool.http`, so they are not applied for subsets). Applied DR fields include `idleTimeout`, `http2MaxRequests`, `maxRetries` (per-request cap), `h2UpgradePolicy`, and `http1MaxPendingRequests` at top-level/port scope, per-subset `connectionPool.tcp.connectTimeout`, `portLevelSettings[].tls`, and the full per-subset `outlierDetection` (both *thresholds* and the `maxEjectionPercent` *cap*). VirtualService `http[].corsPolicy` is deferred only when it is unrepresentable — an un-compilable `regex`, a malformed/unknown matcher, an `exact` (or legacy `allowOrigin` entry) that is empty/whitespace-only or beyond the 512-byte matcher bound (uncredentialed exact `*` is supported; credentialed exact `*` is deferred to preserve the source credential behavior; wildcard-shaped and noncanonical exacts are now projected LITERALLY rather than deferred), an `allowOrigins[]` list beyond 64 entries, an over-complex regex, or an `allowMethods`/`allowHeaders`/`exposeHeaders` entry that is padded or not a valid HTTP method / header name, or an unknown `unmatchedPreflights` value; Sidecar `ingress[]` listeners are deferred only when Ferrum cannot model them (Unix-socket / non-loopback `defaultEndpoint`, non-HTTP-family protocol, omitted `defaultEndpoint`).

Ferrum merges its `FerrumAccepted` condition into the live `status.conditions[]` array, preserving conditions written by Istio (`pilot-discovery`/`galley`) and any other controller. `lastTransitionTime` is held stable while the condition's status/reason/message are unchanged. Status writing is read-only with respect to the proxy data plane and never aborts reconcile: if a cluster has stripped the `subresources.status` from a CRD, the writer logs a single warning per resource and no-ops. `ProxyConfig` is modeled, translated, watched via `ISTIO_CRDS` (`networking.istio.io/v1beta1`), transported on native `MeshSubscribe` and Ferrum xDS `ProxyConfigsCarrier`, and receives `FerrumAccepted` status — Istio's authoritative CRD manifests declare `subresources.status` for `proxyconfigs.networking.istio.io`. See [Istio CRD capability dimensions](configuration.md#istio-crd-capability-dimensions).

Istio status writing requires `get/list/watch` on the watched Istio CRDs plus `patch` on their `status` subresources; the standard Istio CRD manifests already declare `subresources: { status: {} }`.

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

Deleting the **last** mesh-contributing Kubernetes object therefore withdraws the overlay instead of leaving the previous snapshot live. An authoritative snapshot that translates to an empty mesh removes every Kubernetes-owned mesh object — `Service`/`Pod`-derived services and workloads, `AuthorizationPolicy`, `PeerAuthentication`, `RequestAuthentication`, `DestinationRule`, `ServiceEntry`, `WorkloadEntry`, `Sidecar`, `Telemetry`, `ProxyConfig`, and waypoint bindings — while every object owned by another source survives untouched. Mesh-global blocks (`trust_bundles`, `multi_cluster`, `outboundTrafficPolicy`, extension configs) are not produced by the Kubernetes translator and are never withdrawn by it.

Operational properties:

- **Atomic.** The withdrawal is one `ArcSwap` compare-and-swap of a complete `GatewayConfig` under the CP publication gate, followed by one full mesh broadcast. An in-flight request holds either the complete pre-withdrawal snapshot or the complete post-withdrawal one — never a half-withdrawn mesh.
- **Idempotent.** A repeated empty snapshot produces no content change, so nothing is re-committed and nothing is re-broadcast.
- **Fail-closed on translation failure.** A translation that cannot be produced (repeated failure on the same resource) publishes nothing at all, so a broken CRD can never be mistaken for a deletion. Only a *successful* translation withdraws.
- **Survives CP full reload.** CP database full-load finalization clears `GatewayConfig.mesh` before the independently accepted Kubernetes overlay is re-merged. The overlay slot stores the authoritative empty translation as translated, so a later DB full reload re-merges the withdrawal rather than resurrecting deleted Kubernetes mesh. The freshly loaded DB snapshot supplies the non-mesh `GatewayConfig` base for overlay composition; because that path supplies no non-Kubernetes mesh base, there is no second mesh layer to retain. The helper's retained `base_mesh` contract applies only to composition paths that actually supply one.
- **Independent of watch scope.** Withdrawal is "absent from the new translation", not "in a namespace that left the watch set", so shrinking `FERRUM_K8S_WATCH_NAMESPACES` cannot strand a Kubernetes object — including a waypoint binding or policy whose own namespace differs from the namespaces of the services it governs.
- **Visible.** The withdrawal is logged (`Kubernetes mesh overlay withdrawn…`, carrying no resource identifiers or policy contents), the published snapshot stops advertising mesh on the admin status surfaces, and mesh data planes receive a fresh slice whose resource counts and fingerprint reflect the removal on [`/mesh/config-drift`](#config-drift-introspection).

Because withdrawal follows the Kubernetes source of truth, deleting every `AuthorizationPolicy` restores the Istio default (allow when no `ALLOW` rules exist) and deleting every `PeerAuthentication` restores the default mTLS mode — the same posture a fresh cluster starts in. Keep at least one mesh-wide policy in the Istio root namespace if you need a standing floor.

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

When the **source** locality cannot be resolved (missing labels / no SPIFFE-matched workload locality), there is no tier to prefer, so the default behavior is to return the full candidate set — mixed local + remote. Setting `FERRUM_MESH_LOCALITY_LB_STRICT=true` opts into strict local-first instead: with an absent source locality the LB restricts selection to local endpoints (every target not tagged as remote-cluster-discovered; remote provenance is an explicit per-target marker stamped from the workload's cross-cluster identity, *not* the locality string, so a local region named `remote-…` still counts as local — as does an untagged target) and widens to the full healthy pool only when no local endpoint exists, logging a one-time `WARN`. The flag is inert once a source locality is resolved and never changes priority-tier behavior. See the precondition note under [Cross-Cluster Endpoint Discovery](#cross-cluster-endpoint-discovery).

**Two distinct remote-target classes in multi-cluster deployments.** The load balancer distinguishes cross-cluster east-west **gateway** targets from plain remote **workload endpoints**, and only the second class is governed by `FERRUM_MESH_LOCALITY_LB_STRICT` (`src/load_balancer.rs`: `target_is_cross_cluster` / `target_is_local`, `LoadBalancer.cross_cluster_failover_present`):

- **Cross-cluster east-west gateway targets** (`mesh.cross_cluster=true`, materialized by the [client-side cross-cluster egress paths](#client-side-cross-cluster-egress-sidecar)) are **categorically always-failover**: the remote gateway LB-picks the backend, so when any candidate is such a target the balancer enforces local-first selection on the no-source-locality path **even while `FERRUM_MESH_LOCALITY_LB_STRICT` is at its default `false`**, widening to the remote gateway only when no local endpoint is healthy — otherwise a service with healthy local endpoints would round-robin onto the remote gateway instead of using it purely as failover.
- **Plain remote workload endpoints** (`mesh.remote=true` without the cross-cluster gateway marker — the Experimental [Cross-Cluster Endpoint Discovery](#cross-cluster-endpoint-discovery) path) follow the flag as described above: with the default `false` and an **absent** source locality, selection returns the mixed local + remote pool even while local endpoints are healthy. Set `FERRUM_MESH_LOCALITY_LB_STRICT=true` for production multi-cluster deployments that use remote endpoint discovery, so an unresolved source locality cannot spill traffic onto remote endpoints while local ones are healthy.

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

**Why the transformer gate maps are still published after acceptance.** The maps in `runtime_overlay_consumers.rs` no longer drive transformer behavior — that comes from each instance's materialized config. They remain the *provenance* surface: the response-side publication identity is what `response_caching` binds its stored entries to, what `request_deduplication` folds into the content fingerprint of a Redis-persisted replay, and what `GET /mesh/runtime-overlay` reports. Removing the publication would silently stop retiring cached and persisted representations across a policy change.

That publication identity is not sufficient on its own, because it lands *after* the request epoch. A request whose authenticate/authorize phase spans a whole slice apply keeps the plugin generation it pinned — that is the guarantee above — while pinning the newly published identity, so the identity alone can attribute old-generation bytes to the new policy. Both `response_caching` and `request_deduplication` therefore also bind each retained representation to the *effective presentation-policy digest* of the generation that shaped it (`RequestContext::response_presentation_policy_digest`, taken from the request's own plugin-cache view). Since the gate is materialized into the transformer's configuration, that digest covers the gate and the static rules together, per instance. A difference in either half retires the representation; if the digest is unavailable because a presentation policy is dynamic, no representation is retained or replayed.

Server-side translation (`translate_mesh_slice_to_snapshot`) does not currently emit Runtime resources — the xDS server is a CDS/EDS/LDS/RDS/SDS/ECDS originator, and RTDS layer authorship remains with the operator's external CP (Istio, custom) until a Ferrum CP-side surface lands.

## Istio Compatibility Gaps

The following Istio mesh surfaces are either deferred or have Ferrum-specific support notes:

| Surface | Status | Workaround |
|---|---|---|
| Stock Envoy / third-party Istio xDS interop (point Ferrum's xDS client at a non-Ferrum CP) | Not interoperable | Ferrum's `FERRUM_MESH_CONFIG_PROTOCOL=xds` is a **Ferrum-CP-to-Ferrum-DP** path: it follows the Envoy ADS gRPC contract, but CDS/EDS/LDS/RDS are name-only with Ferrum-shaped resource names and all security/policy fields ride [Ferrum-specific ECDS carriers](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds) with Ferrum-defined inner type URLs. A stock Envoy/Istio CP does not emit these carriers or names, so the response is unsupported and may be NACKed. Use a Ferrum CP (either protocol), or `FERRUM_MESH_CONFIG_PROTOCOL=native` |
| `EnvoyFilter` | Not planned | Use Ferrum custom plugins |
| `WasmPlugin` | Not planned | Use Ferrum custom plugins (`custom_plugins/`) |
| Outbound traffic policy (`REGISTRY_ONLY` / `ALLOW_ANY`) | Supported | `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY=registry_only` (or native/CRD slice-supplied `outbound_traffic_policy`) covers both HTTP-family egress (auto-injected `mesh_outbound_registry` plugin and outbound-capture route misses, both rejecting with `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS`, default 502) and stream-family egress on mesh outbound capture listener ports (TCP / TCP+TLS: graceful close before backend dial; UDP / UDP+DTLS: silent datagram drop). Both surfaces read the same slice-derived registry (services, ServiceEntries including wildcard hosts, workload addresses); resources with no declared ports admit any explicit Host port for that known destination, and empty registries fail closed. HTTP decision metrics use fixed host buckets (`<admit_explicit>`, `<admit_wildcard>`, `<denied>`); stream rejects export `ferrum_mesh_outbound_registry_stream_decisions_total{protocol, decision}` instead. Inbound sidecar/ambient traffic is not gated by this outbound policy |
| `VirtualService` header/method/queryParam predicates beyond plugin capture | Partial | Plumbing in place via `mesh_route_dispatch` plugin (translated unconditionally, enabled by default — no opt-in env var or kill switch); supported predicates are captured as plugin config. **Method `StringMatch` supports `exact`, `prefix`, and `regex`** — regex patterns compile once at config-load time; `prefix` / `regex` patterns are uppercased at compile time (HTTP methods are uppercase ASCII per RFC 9110 §9.1); invalid regex is a hard translator/plugin construction error. **Header `StringMatch` supports `exact`, `prefix`, and `regex`** — regex patterns compile once at config-load time; invalid regex is a hard translator/plugin construction error. **`authority` `StringMatch` supports `exact`, `prefix`, and `regex`** — exact/prefix compare raw request `Host`/`:authority` case-sensitively, including explicit request ports; regex patterns are compiled verbatim and must match the full authority string, and operators who want case-insensitive regex should write `(?i)` in the pattern. `authority` is a per-rule predicate (Istio `HTTPMatchRequest.authority`), distinct from VirtualService-level `hosts` which gates proxy admission. **`sourceNamespace` is a first-class predicate** — the request hot path reads the source workload's Kubernetes namespace from `ctx.peer_spiffe_id` via `SpiffeId::namespace`; the predicate fails closed without a resolved peer identity and empty / whitespace-only operator values fail closed via `request_termination`. **`ignoreUriCase: true` affects exact/prefix URI matches only** — the translator widens escaped literal operands into case-insensitive regex listen_paths (`prefix: "/Api"` → `~(?i:/Api.*)`, `exact: "/Api"` → `~(?i:/Api)`), while `regex` URI matches keep their operator-supplied regex unchanged. The dispatch rule carries the original exact/prefix URI predicate + `ignore_uri_case: true` so the plugin re-evaluates with ASCII-only case folding at request time without per-request allocation; non-ASCII bytes compare byte-for-byte. Overlapping case variants and contained exact/prefix intersections collapse or decorate ordered dispatch rules so Ferrum's exact/prefix-before-regex router preserves Istio route order. Routing-decision rewrites via `RequestContext.route_override_*` flow through HTTP-family dispatch sites (pool keys, capability registry, circuit breaker). Translator emits the plugin with `reject_unmatched: true` so requests that miss predicates return 404 instead of falling through to the default backend. Same-path and URI-less ordered canary/default routes collapse into one Proxy with ordered dispatch rules so predicate misses can fall through when a later route exists. Per-rule `timeout` / `retries` ride on each dispatch rule and are reapplied through `RequestContext.route_override_*`. Route-level `headers.request.{set,add,remove}` and `headers.response.{set,add,remove}` are projected onto each dispatch rule as per-rule transform arrays and applied by `request_transformer` / `response_transformer`. Route-local `fault` rides on each dispatch rule as a per-rule `fault` action and collapses cleanly with sibling routes. **`http[].rewrite` and `http[].redirect` are now supported**: `rewrite.uri` (prefix-rewrite-aware) and `rewrite.authority` ride on each dispatch rule and rebase the backend request path / `Host` (authority rewrite flips `preserve_host_header` on the effective proxy); `redirect` rides on each dispatch rule and short-circuits the request with a 3xx + `Location` (no backend, so a redirect route needs no `route[]`). **`http[].mirror` is now supported** as a proxy-scoped `request_mirror` plugin (per-route; a mirror route that must collapse fails closed). **`spec.tcp` / `spec.tls` L4 routing is supported** — materialized into Ferrum stream proxies (`tls[]` → passthrough TCP keyed by SNI; `tcp[]` → plain TCP keyed by port), reusing the gateway/east-west stream + SNI machinery; unsupported match predicates (`sourceLabels`/`sourceSubnets`/`destinationSubnets`/`gateways`/`sourceNamespace`) and weighted splitting fail closed. Unsupported predicate-only candidates (`regex`/`prefix` queryParam matchers, etc.) emit proxy-scoped `request_termination` instead of widening traffic. Admission plugins such as `mesh_authz` and rate limiting still evaluate the original public proxy identity; WebSocket overrides apply to the upgrade backend only, and HBONE CONNECT evaluates `before_proxy` before the relay branch, so route overrides can select the HBONE backend. Example `authority` match: `match: [{ uri: { prefix: "/api" }, authority: { prefix: "api." } }]` routes `Host: api.staging.example.com` but not `Host: API.staging.example.com` or `Host: admin.example.com`. Example `sourceNamespace` match: `match: [{ uri: { prefix: "/internal" }, sourceNamespace: "platform" }]`. Example `ignoreUriCase`: `match: [{ uri: { prefix: "/api" }, ignoreUriCase: true }]` matches both `/api/users` and `/API/users`. |
| Pod auto-discovery (K8s native service registry) | Supported (opt-in) | Set `FERRUM_K8S_POD_DISCOVERY_ENABLED=true`; the CP watches Pod/Service/EndpointSlice/Node resources, surfaces only ready Pods, links Services through EndpointSlices, and lets explicit `WorkloadEntry` / `ServiceEntry` resources override auto-derived entries |
| `WorkloadEntry` `weight` / `locality` / `serviceAccount` | Supported | `weight` and `locality` are consumed by upstream target materialization; locality priority load balancing prefers exact, zone, then region tiers before falling back. `DestinationRule.trafficPolicy.loadBalancer.localityLbSetting.distribute` / `failover` / `enabled` are honored (see "Locality-Aware Load Balancing" above). `serviceAccount` is kept separately from the SPIFFE path so introspection/audit doesn't need to parse it. |
| `Telemetry.tracing[].providers[]` span emission | Supported | Inline provider config is emitted from the injected `workload_metrics` plugin for Zipkin v2, Datadog Agent `/v0.3/traces`, Lightstep OTLP + bearer auth via `accessTokenEnv`, and OpenTelemetry OTLP/HTTP JSON. Multiple inline providers fan out from one sampled span. `randomSamplingPercentage` is honored, `disableSpanReporting: true` suppresses export while retaining the merged config, and `tracing[].match.mode: SERVER`, `CLIENT`, `CLIENT_AND_SERVER`, or omitted mode all flow through: each mesh listener stamps a direction (inbound mTLS / HBONE termination → server, outbound capture → client) and the plugin emits the matching span kinds. Resulting spans carry their kind in every provider payload (OTLP enum `2`/`3`, Zipkin v2 top-level `"kind": "SERVER"\|"CLIENT"`, Datadog `meta["span.kind"] = "server"\|"client"`). Name-only references (`{name: "my-zipkin"}`) resolve against `meshConfig.extensionProviders` from the root-namespace `istio` ConfigMap, and omitted or empty `providers[]` use `meshConfig.defaultProviders.tracing` when configured. Unknown names are skipped with an operator-visible warning. |

## Migrating from Istio

Ferrum is positioned as a **native consumer of Istio's configuration model**, not a drop-in Envoy replacement. The Kubernetes controller natively watches and translates **ten Istio CRDs** — `AuthorizationPolicy`, `PeerAuthentication`, `RequestAuthentication`, `DestinationRule`, `VirtualService`, `ServiceEntry`, `WorkloadEntry`, `Sidecar`, `Telemetry`, and `ProxyConfig` — writing a `FerrumAccepted` condition into each resource's `status.conditions[]` plus a `status.ferrum.translation` detail block, with parsed-but-unenforced fields surfaced in `deferred_fields` so gaps are operator-visible (see [Istio CRD Status](#istio-crd-status)). Ferrum's xDS path is **Ferrum-CP-to-Ferrum-DP only**: it follows the Envoy ADS wire contract, but the resource payloads are Ferrum-specific, so a stock Envoy or third-party Istio control plane cannot drive a Ferrum data plane, and Ferrum cannot join an existing Envoy/Istio xDS fleet (see [xDS ADS Compatibility](#xds-ads-compatibility) and the first row of [Istio Compatibility Gaps](#istio-compatibility-gaps)). `EnvoyFilter` and `WasmPlugin` are explicit non-goals — their extension role maps to Ferrum custom plugins (`custom_plugins/`). For the field-level "is my resource supported" answer, do not rely on this summary: the authoritative sources are [docs/mesh_supported_matrix.md](mesh_supported_matrix.md) (the product contract), the per-CRD tables in this document ([DestinationRule](#destinationrule), [VirtualService Translation](#virtualservice-translation), [Istio Compatibility Gaps](#istio-compatibility-gaps)), and the conformance-generated `target/conformance/coverage.md` (the enrolled GA rows and required live assertion IDs).

| Istio surface | Ferrum answer |
|---|---|
| The ten translated CRDs (AuthorizationPolicy, PeerAuthentication, RequestAuthentication, DestinationRule, VirtualService, ServiceEntry, WorkloadEntry, Sidecar, Telemetry, ProxyConfig) | Natively consumed by the K8s controller with `FerrumAccepted` status feedback and `deferred_fields` for parsed-but-unenforced fields ([Istio CRD Status](#istio-crd-status)) |
| istiod xDS → Envoy data plane | Ferrum CP → Ferrum DP only: native `MeshSubscribe` (recommended) or Ferrum xDS with Ferrum ECDS carriers; **not** stock-Envoy / third-party-Istio interoperable ([xDS ADS Compatibility](#xds-ads-compatibility)) |
| `EnvoyFilter` / `WasmPlugin` | Not planned — use Ferrum custom plugins (`custom_plugins/`) ([Istio Compatibility Gaps](#istio-compatibility-gaps)) |
| Field-level support status | [docs/mesh_supported_matrix.md](mesh_supported_matrix.md) + the per-CRD tables here + `target/conformance/coverage.md` |

## Environment Variables

Mesh-specific environment variables are listed below. For the full reference of all `FERRUM_*` variables, see [configuration.md](configuration.md).

### Core

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_CONFIG_PROTOCOL` | `native` | Config consumption protocol: `native`, `xds`, or `file` (localized file source — requires `FERRUM_MESH_FILE_CONFIG_PATH`) |
| `FERRUM_MESH_NODE_ID` | `$HOSTNAME` or `ferrum-mesh-node` | Node identifier sent to the CP |
| `FERRUM_MESH_TOPOLOGY` | `sidecar` | Topology: `sidecar`, `ambient`, `node_waypoint`, `service_waypoint`, `east_west_gateway`, `egress_gateway` |
| `FERRUM_MESH_WAYPOINT_NAME` | (none) | Required when `FERRUM_MESH_TOPOLOGY=service_waypoint`; names the GAMMA waypoint binding requested from the CP |
| `FERRUM_MESH_WORKLOAD_SPIFFE_ID` | (none) | SPIFFE ID of this mesh workload |
| `FERRUM_MESH_WORKLOAD_LABELS` | (none) | Comma-separated `key=value` workload labels for PolicyScope matching |
| `FERRUM_MESH_TRUST_DOMAIN_ALIASES` | (none) | Additional trust domains for HBONE baggage validation |
| `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS` | (none) | HBONE peers trusted to assert baggage `source.principal`. Comma-separated SA names and/or full SPIFFE ids. Empty/unset uses defaults `[ztunnel, waypoint]`, except identity-backed `NodeWaypoint` derives exact assertor SPIFFE IDs from the scope-authorized CP-derived `node_waypoint_assertors` inventory and uses an empty list when none exists |
| `FERRUM_MESH_SIDECAR_ENFORCED` | `false` | When `true`, applies Istio `Sidecar` egress scope narrowing to `services` / `service_entries` / `destination_rules` per workload. Sidecars are always parsed; this flag gates only the slice-narrowing pass. Opt in after vetting your `Sidecar` resources |
| `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN` | `false` | Computes and reports the applicable `Sidecar` egress scope while leaving the slice unchanged. Use with `/mesh/egress-scope` before enabling enforcement |
| `FERRUM_MESH_SIDECAR_IDENTITY_NARROWING` | `false` | When `true` and `FERRUM_MESH_SIDECAR_ENFORCED=true`, filters `workloads` to SPIFFE identities referenced by services admitted by the applicable Sidecar. Default-off for rollout; trust-bundle mTLS validation and HBONE trust-domain aliasing do not depend on this list |
| `FERRUM_MESH_EGRESS_STREAM_ENABLED` | `false` | Opt-in for **TCP** stream egress proxy materialization in `EgressGateway` topology. When enabled, each per-port TCP listener **terminates SVID-mTLS and runs `mesh_authz`** at accept (same authn/z as HTTP egress, reusing the mesh-inbound `ServerConfig` + SPIFFE peer verifier; client certs required). UDP ServiceEntry ports are classified but **not yet materialized** (deferred with a warning — the UDP capture/egress + DTLS datapath is unimplemented), so this flag produces no UDP listener today. Default-off because protocol-aware mediation is absent and the mTLS datapath is not yet live-e2e verified. Set `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true` to restore the legacy plaintext + unauthenticated listener. HTTP-family egress is unaffected |
| `FERRUM_MESH_NODE_WAYPOINT_CGROUP_SWEEP_INTERVAL_SECS` | `30` | NodeWaypoint cgroup-inode lifecycle sweep interval for cgroup-bound identities. Set to `0` to disable only cgroup stats |
| `FERRUM_MESH_NODE_WAYPOINT_IDLE_GC_INTERVAL_SECS` | `30` | NodeWaypoint lazy identity GC interval for identities enrolled without a cgroup binding. Set to `0` only when another component explicitly removes lazy identities |
| `FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP` | `true` | Whether the auto-injected mesh `RequestAuthentication` (`jwks_auth`) plugin requires the JWT `exp` claim. Secure default `true` rejects `exp`-less tokens. Set `false` only for issuers that legitimately omit `exp`; a present-but-expired `exp` is always rejected regardless |
| `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED` | `false` | Opt in to live reload of the PeerAuthentication-derived listener-wide and per-app-port inbound mTLS configs, client CA verifier, and federated SVID bundle slot on slice apply. Does not rotate frontend cert/key material (use `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED`) |
| `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS` | `0` | Seconds to wait after a backend client SVID rotation before force-draining old-generation backend pool entries. `0` keeps existing connections until normal idle/health cleanup |
| `FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS` | `300` | SPIFFE trust-bundle federation poll interval (fetches `RemoteCluster.federation_endpoint` and overlays `TrustBundleSet.federated`). `0` disables; bundles then come only from the CP slice. `remote_clusters` is capped at 256 entries |
| `FERRUM_MESH_FEDERATION_POLL_TIMEOUT_SECONDS` | `30` | Per-request HTTP timeout for a single federation bundle fetch |
| `FERRUM_MESH_FEDERATION_MAX_STALE_SECONDS` | `3600` | Maximum age for a last-good polled federation bundle after poll failures. Once exceeded, the bundle is withdrawn and the effective trust set is recomputed. `0` means indefinite retention for dev/test only; production mode rejects `0` while polling is enabled |
| `FERRUM_MESH_FEDERATION_FAIL_OPEN` | `false` | Federation bootstrap policy. `false` blocks CP-supplied fallback bundles for remotes with `federation_endpoint` until the poller installs a last-good bundle. `true` allows CP fallback during bootstrap |
| `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS` | `0` | Cross-cluster endpoint discovery polling interval. `0` disables (multi-cluster stays east-west SNI passthrough + federated trust only). When `> 0`, each `RemoteCluster.control_plane_url` is dialed on this cadence to fetch remote service endpoints aggregated into local upstream targets (tagged with remote locality) for local→remote failover. Fail-closed on trust: only clusters with a federated trust bundle are dialed. `remote_clusters` is capped at 256 entries. See [Cross-Cluster Endpoint Discovery](#cross-cluster-endpoint-discovery) |
| `FERRUM_MESH_REMOTE_DISCOVERY_POLL_TIMEOUT_SECONDS` | `30` | Per-poll timeout for the remote-cluster `MeshSubscribe` fetch |
| `FERRUM_MESH_REMOTE_DISCOVERY_MAX_STALE_SECONDS` | `300` | Maximum age for last-good remote endpoints after discovery poll failures. Once exceeded, endpoints and their success/age metrics are withdrawn while the poller keeps retrying. `0` means indefinite retention for dev/test only; production mode rejects `0` while discovery is enabled |
| `FERRUM_MESH_LOCALITY_LB_STRICT` | `false` | Strict local-first locality LB. `false` (default, fail-open): an absent upstream source locality returns mixed local + remote endpoints. `true` (fail-closed-to-local): an absent source locality restricts selection to local endpoints (those without the explicit remote-cluster-provenance marker — keyed on cross-cluster identity at materialization, not the locality string), widening to the full healthy pool with a one-time `WARN` only when no local endpoint exists. Inert when source locality is resolved. See [Locality-Aware Load Balancing](#locality-aware-load-balancing) |
| `FERRUM_MESH_POLICY_DENY_LOG_CAPACITY` | `10000` | Ring capacity of the in-memory `mesh_authz` deny recorder behind `GET /mesh/policy-denies/recent`. `0` disables the recorder (endpoint still serves an empty `grouped` array) |

### Listeners

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_INBOUND_LISTEN_ADDR` | `0.0.0.0:15006` | Sidecar inbound mTLS listener |
| `FERRUM_MESH_OUTBOUND_LISTEN_ADDR` | `127.0.0.1:15001` | Sidecar/ambient outbound capture listener |
| `FERRUM_MESH_HBONE_LISTEN_ADDR` | `0.0.0.0:15008` | Ambient HBONE listener |
| `FERRUM_MESH_EAST_WEST_LISTEN_PORT` | `15443` | East-west gateway shared listener port |
| `FERRUM_MESH_EGRESS_LISTEN_ADDR` | `0.0.0.0:15090` | Egress gateway mTLS listener |
| `FERRUM_MESH_EGRESS_HBONE_PORT` | `15008` | Destination HBONE transport port dialed for Ambient/Waypoint mesh egress (the peer's HBONE listener). Stamped as the `mesh.hbone_port` upstream tag |
| `FERRUM_MESH_EGRESS_MTLS_PORT` | `15006` | Destination SVID-mTLS transport port dialed for Sidecar mesh egress (the peer sidecar's inbound listener). Stamped as the `mesh.mtls_port` upstream tag |

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
| `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS` | `502` | HTTP error status returned when `registry_only` rejects an unknown HTTP-family destination |

### Identity / CA

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_CA_BACKEND` | `none` | CA backend for mesh SVID issuance: `none`, `internal` (dev-only self-signed root), `spire_agent` (SPIRE Workload API). `spire` / `spire-agent` are accepted aliases for `spire_agent` |
| `FERRUM_MESH_SPIRE_AGENT_SOCKET` | `/run/spire/sockets/agent.sock` | SPIRE Agent Workload API socket path |
| `FERRUM_MESH_CERT_TTL_SECONDS` | `3600` | Requested certificate TTL |
| `FERRUM_MESH_PRODUCTION_MODE` | `false` | Master production guardrail. When `true`, the dev-only self-signed CA bootstrap and the dev-only static attestor are refused unconditionally. Read directly by the identity helpers (not parsed into `EnvConfig`). Set in every production deployment. See [Internal Dev CA and Production Guardrails](#internal-dev-ca-and-production-guardrails) |
| `FERRUM_MESH_CA_BOOTSTRAP_DEV` | `false` | Dev-only opt-in to mint a self-signed mesh root for the `internal` CA backend. The bootstrap helper refuses unless this is `true` **and** `FERRUM_MESH_PRODUCTION_MODE` is not `true`. Lab/test only |
| `FERRUM_MESH_ALLOW_STATIC_ID` | `false` | Dev-only opt-in for the `StaticAttestor` (hard-coded SPIFFE ID for any peer). Refused unless `true` and `FERRUM_MESH_PRODUCTION_MODE` is not `true`. Lab/test only |
| `FERRUM_MESH_ALLOW_NO_CA` | `false` | Dev/test opt-in to start `mesh` mode with **no workload identity** — i.e. neither file-based gateway SVID material (`FERRUM_GATEWAY_SVID_*`) **nor** a CA backend (`FERRUM_MESH_CA_BACKEND=spire_agent|internal` + `FERRUM_MESH_WORKLOAD_SPIFFE_ID`). Without it, an identity-less mesh fails startup closed (no mTLS ⇒ PERMISSIVE accepts plaintext). Read directly from the environment (not `ferrum.conf`); refused unconditionally when `FERRUM_MESH_PRODUCTION_MODE=true`. Lab/test only — see [Internal Dev CA and Production Guardrails](#internal-dev-ca-and-production-guardrails) |

### xDS

| Variable | Default | Description |
|---|---|---|
| `FERRUM_MESH_XDS_NODE_CLUSTER` | (from `FERRUM_NAMESPACE`) | xDS `node.cluster` identity |
| `FERRUM_MESH_XDS_CONNECT_TIMEOUT_SECONDS` | `10` | xDS client connect timeout |

### Node Agent

| Variable | Default | Description |
|---|---|---|
| `FERRUM_NODE_AGENT_NODE_NAME` | (required) | Kubernetes node name, set via downward API (`spec.nodeName`) |
| `FERRUM_NODE_AGENT_NODE_IP` | (empty) | Single trusted host source IP used to reach local pods. **Required in NodeWaypoint**: the inbound HBONE relay dials backend pods from this node-local source, and the source-bound guard drops the relay's traffic (and all direct inbound to enrolled pods) without it — the agent fails closed when no node source IP is set. Also exempts kubelet HTTP/TCP/gRPC probe ports derived from the enrolled pod spec. CNI-specific (e.g. the pod-CIDR gateway, which may differ from `status.hostIP`); the Helm chart does not auto-populate this value. |
| `FERRUM_NODE_AGENT_NODE_IPS` | (empty) | Comma-separated trusted host source IPs; merged with `FERRUM_NODE_AGENT_NODE_IP` for the same allowlist. **Required in NodeWaypoint** for every address family used by enrolled pods — a dual-stack node needs both an IPv4 and an IPv6 source, or that family's relay dials are dropped and enrollment reports the topology degraded. Do not include broad host-network sources. |
| `FERRUM_NODE_AGENT_CGROUP_ROOT` | `/sys/fs/cgroup` | cgroup v2 mount point for pod cgroup resolution |
| `FERRUM_NODE_AGENT_BPF_FS_PATH` | `/sys/fs/bpf` | BPF filesystem mount point for pinned maps |
| `FERRUM_NODE_AGENT_BPF_ELF_PATH` | build-tree path | Compiled `ferrum-ebpf` ELF (Linux `ebpf` feature only) |
| `FERRUM_NODE_AGENT_PROXY_MODE` | `local_pod` | Capture topology contract: `local_pod` or `node_waypoint` |
| `FERRUM_NODE_AGENT_ADMIN_ENABLED` | `false` | Enables the node-agent read-only admin listener for metrics/health. When enabled, defaults to loopback unless `FERRUM_ADMIN_BIND_ADDRESS` or `FERRUM_ADMIN_ALLOWED_CIDRS` is set; `/metrics` requires an admin JWT, `FERRUM_METRICS_BEARER_TOKEN`, or a source in `FERRUM_METRICS_ALLOWED_CIDRS`, while health detail requires authenticated admin access. |
| `FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT` | `15008` | HBONE redirect/listener port written into the capture contract and BPF config map. Must match the mesh proxy HBONE listener. |
| `FERRUM_NODE_AGENT_FALLBACK_MODE` | `fail` | Behaviour when eBPF prerequisites are missing (kernel < 5.7, cgroup v1, or bpffs unmounted). Default `fail` refuses startup with a structured error. `iptables` falls back to host iptables capture and sets `ferrum_mesh_node_topology_degraded=1`, but requires a runtime image with `/bin/sh`, `iptables`, and `ip6tables` when IPv6 capture is enabled. See [node_agent.md](node_agent.md#kernel-fallback). |
| `FERRUM_NODE_AGENT_EXCLUDED_NAMESPACES` | (empty) | Extra namespaces to exclude (`kube-system`, `kube-public`, `kube-node-lease` always excluded) |
| `FERRUM_MESH_CAPTURE_INCLUDE_CIDRS` | `0.0.0.0/0` | CIDRs to capture for outbound traffic |
| `FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS` | (empty) | CIDRs to exclude from outbound capture (highest priority) |
| `FERRUM_MESH_CAPTURE_EXCLUDE_PORTS` | `15001,15006,15008,15020` | Destination TCP ports excluded from outbound capture |
| `FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS` | (empty) | Destination TCP and UDP ports excluded from inbound capture (mirrors Istio `excludeInboundPorts`; pod annotation `traffic.sidecar.istio.io/excludeInboundPorts` is additive) |

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

### Kubernetes Controller

These configure the in-cluster Istio / Gateway API translation controller and native service-registry discovery. The controller runs on the **control plane** (`FERRUM_MODE=cp`; started from `src/modes/control_plane.rs`) — a mesh-mode data plane does **not** run it, even in-cluster, so set these on the CP. See [Istio CRD Status](#istio-crd-status) and [Pod Auto-Discovery](#pod-auto-discovery).

| Variable | Default | Description |
|---|---|---|
| `FERRUM_K8S_CONTROLLER_ENABLED` | auto (true in-pod, false outside) | Enable the in-cluster Istio/Gateway-API translation controller. Detected from `KUBERNETES_SERVICE_HOST`; explicit operator value wins |
| `FERRUM_K8S_POD_DISCOVERY_ENABLED` | auto (true in-pod, false outside) | Watch Pod/Service/EndpointSlice/Node for native service-registry discovery |
| `FERRUM_K8S_WATCH_ISTIO_CRDS` | `true` | Watch and translate Istio CRDs (and write `status.conditions[]`) |
| `FERRUM_K8S_WATCH_GATEWAY_API_CRDS` | `true` | Watch and translate Gateway API CRDs (GatewayClass/Gateway/HTTPRoute/GRPCRoute) and write their status |
| `FERRUM_GATEWAY_API_DATA_PLANE_SERVICE_NAMESPACE` | (none) | Namespace of the routable Ferrum data-plane Service used to gate Gateway API `Gateway.status.conditions[Programmed]` |
| `FERRUM_GATEWAY_API_DATA_PLANE_SERVICE_NAME` | (none) | Name of the routable Ferrum data-plane Service used to gate Gateway API `Gateway.status.conditions[Programmed]` |
| `FERRUM_GATEWAY_API_STATUS_ADDRESS` | (none) | Optional address advertised in `Gateway.status.addresses` |
| `FERRUM_K8S_WATCH_MESH_CONFIG` | `true` | Watch the `istio` ConfigMap (MeshConfig) so name-only Telemetry providers resolve |
| `FERRUM_K8S_WATCH_NAMESPACES` | (CP scope) | Comma-separated namespace watch scope; unset falls back to the CP namespace scope |
| `FERRUM_K8S_ISTIO_ROOT_NAMESPACE` | `istio-system` | Root namespace for mesh-wide (selector-less) Istio resources |
| `FERRUM_K8S_CLUSTER_DOMAIN` | `cluster.local` | Cluster DNS domain for FQDN synthesis on the control plane |
| `FERRUM_K8S_TRUST_DOMAIN` | `cluster.local` | SPIFFE trust domain used by the controller |
| `FERRUM_K8S_NODE_LOCALITY_ENABLED` | `false` | Stamp Node `topology.kubernetes.io/region\|zone` labels onto workload locality |
| `FERRUM_K8S_FULL_SYNC_INTERVAL_SECS` | `300` | Periodic re-reconcile interval (seconds) over the current reflector-store contents; it does not re-list Kubernetes |
| `FERRUM_K8S_WATCH_IDLE_RELIST_SECS` | `300` | Rebuild a watch scope's reflector from an authoritative list once it has delivered no event for this long; the safety valve against a watch that stalls without failing. A quiet scope is indistinguishable from a stalled one (bookmarks never leave kube-rs), so this is also the per-scope full-list rate. `0` disables; clamped to `0`–`86400` |
| `FERRUM_K8S_RECONCILE_DEBOUNCE_MS` | `500` | Debounce window coalescing rapid watch events before a reconcile |
| `FERRUM_K8S_KUBECONFIG_PATH` | (in-cluster) | Path to a kubeconfig for out-of-cluster runs. When unset, the controller tries the in-cluster service-account config first, then falls back to standard kubeconfig inference (`KUBECONFIG` / `~/.kube/config`) — so an out-of-cluster CP often needs no explicit path |

### Shared with CP/DP

Mesh mode reuses several CP/DP environment variables. See [cp_dp_mode.md](cp_dp_mode.md) for details:

- `FERRUM_DP_CP_GRPC_URLS` (required for `native`/`xds`) -- CP endpoints for config subscription. Not required when `FERRUM_MESH_CONFIG_PROTOCOL=file` (no control plane).
- `FERRUM_CP_DP_GRPC_JWT_SECRET` (required for `native`/`xds`) -- shared JWT secret for gRPC auth. Not required for the `file` protocol.
- `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS` -- primary CP retry interval on fallback.
- `FERRUM_XDS_STREAM_CHANNEL_CAPACITY` -- per-ADS-stream response queue capacity.
- DP gRPC TLS variables (`FERRUM_DP_GRPC_TLS_*`).
