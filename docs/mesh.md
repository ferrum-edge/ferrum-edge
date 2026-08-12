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
  - [AuthorizationPolicy targetRefs](#authorizationpolicy-targetrefs-issue-3226)
  - [Evaluation Semantics](#evaluation-semantics)
  - [AuthorizationPolicy action: CUSTOM](#authorizationpolicy-action-custom-issue-3235)
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
- [Sidecar Outbound Traffic Policy](#sidecar-outbound-traffic-policy)
- [Config Drift Introspection](#config-drift-introspection)
- [DestinationRule](#destinationrule)
- [Observability](#observability)
- [Kubernetes Injector](#kubernetes-injector)
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
> The contract's **live** half is backed by two suites: `mesh-e2e-sidecar` for the same-cluster sidecar rows, and `multicluster-federation` for the cross-cluster east-west rows (described at the end of this note). In `mesh-e2e-sidecar` (`tests/k8s/mesh_e2e_sidecar/`, workflow `.github/workflows/mesh-e2e-sidecar-live.yml`), a kind + SPIRE cluster drives the real captured sidecar datapath — STRICT-mTLS positive and plaintext-rejected negative, a destination-side AuthorizationPolicy 403, RequestAuthentication JWT (valid → 200, missing → 403, wrong-key signature → 401), a two-phase DestinationRule `connectTimeout` timing proof, a DR `maxConnections=1` WebSocket flow (one held session admitted, a concurrent upgrade rejected 503, recovery after release), and a CP + native-subscribe leg (a Ferrum CP in `cp` mode builds its mesh model from the cluster's real Services/pods via K8s pod discovery; a captured sidecar DP on `FERRUM_MESH_CONFIG_PROTOCOL=native` serves traffic only if the MeshSubscribe-delivered slice materialized its inbound routes, and its JWT-authenticated `GET /mesh/config-drift` must attribute the slice to the native transport) — emitting `sidecar.*` live assertions the workflow then validates against the contract (`tests/conformance/live_contract.rs`: required IDs present + passed for the exact suite/profile/commit, no duplicate or stale artifacts). Those Stable sidecar rows — PeerAuthentication STRICT, AuthorizationPolicy ALLOW/DENY, RequestAuthentication JWT, DR `connectTimeout`/`maxConnections`, VirtualService CORS, SPIFFE identity plumbing (`mesh.identity.spire_svid_issuance`, live-backed by `sidecar.spire.workload_entries` plus the SVID-carried STRICT-mTLS positive), and native `MeshSubscribe` config transport (`mesh.config_transport.native_subscribe`, live-backed by `sidecar.config.native_subscribe_delivered`) — are enrolled **vertically**: semantic conformance assertion → GA contract row → required live assertion. The DestinationRule `exportTo` visibility and lookup-hierarchy rows are also release-blocking: the fixture drives those behaviors on the captured client egress datapath against a multi-namespace DestinationRule model and emits their required live assertions. VS CORS is live-backed since issue #1973 closed: the mesh slice carries `virtual_service_cors_policies` (K8s translator emission per VS host, file-source expressible, own xDS ECDS carrier), the client sidecar synthesizes the `cors` plugin onto its materialized outbound routes, and the suite proves an allowed Origin reflected, a sidecar-answered Istio 200 preflight, plus unmatched actual and preflight forwarding without gateway-added CORS authorization. The complete M2 contract is **PR- and release-blocking**: a deploy-only smoke (`mesh-e2e-sidecar` in `ci.yml`) gates every PR touching the suite's surfaces; the dedicated live workflow's result — fixture **plus** artifact validation — is a merge-blocking required check (its `Mesh E2E Sidecar Live` gate job, required via branch protection, the same pattern as the Gateway API lab); and the live suite runs on every main push so `release.yml`'s `validate-release-sha` can refuse any tag whose SHA lacks a green, contract-validated live run. The cross-cluster east-west rows (`mesh.multicluster.*`, issue #2459) are enrolled the same way against the `multicluster-federation` suite (`tests/k8s/multicluster-federation/`, workflow `.github/workflows/multicluster-federation-live.yml`, platform profile `kind-spire-multicluster-federation`): semantics pinned by `tests/conformance/mesh_multicluster_federation.rs` plus the `EastWestGateway topology` row, live-gated by thirteen required `multicluster.*` assertions, and blocking at the same three points — the fixture's own fail-closed required-assertion check, the workflow's `Multicluster Federation Live` gate job (which re-validates the emitted `live-assertions.json` against the contract), and `release.yml` SHA validation. Poller-driven cross-cluster *endpoint discovery* is Beta and is excluded from every one of those GA rows; its separate required partition live gate covers the Beta lifecycle contract.

### Config-source maturity

| Capability | Status | Notes |
|---|---|---|
| Native `MeshSubscribe` (Ferrum CP → Ferrum DP) | **Stable** | Default protocol. Full slice (authz, PeerAuth, JWT, ServiceEntry, trust bundles, ProxyConfig, workloads, telemetry, multi-cluster) is pushed directly. The most mature and recommended config path. Enrolled in the conformance GA contract as `mesh.config_transport.native_subscribe` (semantics: `tests/conformance/mesh_config_transport.rs`; live: `sidecar.config.native_subscribe_delivered` via the `mesh-e2e-sidecar` CP + native-subscribe leg). |
| xDS ADS (Ferrum CP → Ferrum DP) | **Beta** | Functionally equivalent to native via Ferrum-specific ECDS carriers (`ferrum.config.extension.v3.*`), including `ProxyConfig` on `ProxyConfigsCarrier`. **NOT stock-Envoy / third-party-Istio interop** — a non-Ferrum CP emits only name-only CDS/EDS/LDS/RDS and no carriers, so it cannot drive a protected Ferrum mesh and may be NACKed. RTDS layers are authored by the operator's CP (Ferrum's xDS server does not originate Runtime resources). |
| Localized file source (`FERRUM_MESH_CONFIG_PROTOCOL=file`) | **Beta** | No control plane: the DP builds its slice locally from `FERRUM_MESH_FILE_CONFIG_PATH` through the same materialization path as native/xDS, so enforcement parity is structural. Fail-closed initial load; SIGHUP reload (Unix) keeps the last good slice on error. Sharp edges: reload is signal-driven only (no file watching), and there is no CP heartbeat — `/mesh/config-drift` staleness reflects the last SIGHUP, not a sync failure. |
| Stock Envoy / third-party Istio xDS interop (`FERRUM_MESH_CONFIG_PROTOCOL=stock_xds`) | **Beta** | Issue #3317. A **separate protocol** from `xds`: consumes standard v3 CDS/EDS/LDS/RDS from a stock Envoy / third-party Istio control plane and projects it onto `MeshService` / `Workload` for **discovery only**. Enforcement policy comes from the mandatory local `FERRUM_MESH_FILE_CONFIG_PATH` document, so a third-party CP can change reachability but never Ferrum's security posture. Everything Ferrum does not model is refused per-resource with a field-specific diagnostic and contributes no route, endpoint, or identity. See [Stock Envoy / third-party Istio xDS interoperability](#stock-envoy--third-party-istio-xds-interoperability). |

### Topology maturity

| Topology | Status | Notes |
|---|---|---|
| `Sidecar` + native config | **Stable** | The most mature path: inbound 15006 mTLS + outbound 15001 capture, SPIFFE-verified peers, full authz/JWT/DR enforcement. Recommended for production. GA-gated together with the native transport: `mesh.config_transport.native_subscribe` requires the live `sidecar.config.native_subscribe_delivered` assertion, proven by a captured sidecar DP on `FERRUM_MESH_CONFIG_PROTOCOL=native` whose inbound datapath materializes only from the CP-delivered slice. |
| `Ambient` (HBONE 15008) | **Beta** | HBONE termination over mTLS is implemented and SPIFFE-trust-domain-verified. Requires eBPF ambient capture (or iptables) to actually intercept traffic — see capture maturity below. |
| `EastWestGateway` (SNI passthrough 15443) | **Stable** | TCP/SNI passthrough for multi-cluster; no TLS termination. Live-gated by the `multicluster-federation` suite (issue #2459). Cross-cluster *endpoint* discovery (vs SNI passthrough) is separate and Beta — see below. |
| `EgressGateway` — HTTP-family (15090 mTLS) | **Beta** | mTLS-terminating egress for `mesh_external` ServiceEntries with `outboundTrafficPolicy` enforcement. |
| `EgressGateway` — stream-family (TCP) | **Experimental** | Opt-in via `FERRUM_MESH_EGRESS_STREAM_ENABLED=true`. Per-port TCP stream listeners **terminate SVID-mTLS and run `mesh_authz`** at accept (parity with HTTP egress), reusing the mesh-inbound `ServerConfig` + SPIFFE peer verifier; **client certs are required** (PERMISSIVE is escalated to require a verified SVID for the egress boundary — a cert-less client is rejected, not admitted). Fail-closed (no mTLS material → listener defers its bind, never plaintext; no trust anchor under PERMISSIVE → hard error). `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true` restores the legacy plaintext + unauthenticated listener (loud startup warning; use only with compensating controls). UDP ServiceEntry ports materialize datagram-over-mesh egress under the same flag — a destination allowlist consumed by the gateway's authenticated mesh CONNECT terminator, never a UDP/DTLS listener, plus a source-side producer (`FERRUM_MESH_EGRESS_GATEWAY_ADDR`/`_SPIFFE_ID`) that originates the identity-pinned `udp` CONNECT from a `Sidecar`/`Ambient` workload; see "External UDP egress (EgressGateway)" below. Default-off topology; Experimental because protocol-aware mediation is absent and the live mTLS datapath is unit/integration-tested, not yet live-e2e. |
| `ServiceWaypoint` (GAMMA) | **Beta** | Service-scoped Ambient waypoint; CP narrows resources to the named binding. Needs the eBPF/ambient capture caveats of node-waypoint when fronting captured pods. |
| `NodeWaypoint` (sidecarless capture) | **Experimental** | HBONE listener is implemented; the GAP-2M accept-side bridge is implemented in the kernel `sock_ops` program (re-keys the orig-dst record by connection tuple, then re-stamps it under the accept-side cookie), and per-pod identity enrollment is wired (slice apply installs a `workload_spiffe_hash`→SPIFFE index that `resolve_record` hash-joins against the eBPF-stamped `(pod_uid, hash)` to lazily enroll identities). NodeWaypoint startup now treats the SOCK_OPS bridge as required: if it cannot attach, node-agent reports `identity_bridge_unavailable` and refuses readiness. The `node-waypoint-ebpf-live` GitHub Actions workflow builds Docker images, creates a disposable dual-stack two-worker kind cluster, installs a minimal SPIRE Server/Agent fixture, registers per-node NodeWaypoint Workload API SVID entries, collects BPF link/map evidence while gating capture/identity/chart changes, admits `src-a` IPv4 and IPv6 Service ClusterIP traffic, rejects `src-b` IPv4 and IPv6 Service ClusterIP traffic with live `AuthorizationPolicy`, checks denied-source and unmanaged direct Pod-IP attempts fail closed instead of bypassing capture, and forces source workload IPv4 reuse so the replacement UID/identity must be admitted while the old registry markers are gone. NodeWaypoint does not synthesize pod-IP HBONE upstreams to backing pod `:15008`; direct Pod-IP is guarded as a bypass surface in this live gate rather than advertised as a routable allowed-source path. **IPv4 and IPv6 capture, secured service transport, and destination relay authz are live-gated:** the in-netns manager binds `127.0.0.1:<port>` and `[::1]:<port>` inside each enrolled pod netns, `connect4`/`connect6` rewrite to those listeners, both `sock_ops` bridge paths handle `AF_INET` and `AF_INET6`, Kubernetes pod discovery populates `Workload.node_waypoint` from trusted ready host-network NodeWaypoint proxy pods on the destination node, and captured Service targets that carry that metadata use SPIFFE-mTLS HBONE to the destination NodeWaypoint endpoint while preserving the selected workload app address as CONNECT authority. The source NodeWaypoint asserts the captured source workload SPIFFE ID in trusted HBONE baggage while the outer mTLS connection remains pinned to the NodeWaypoint SVID, so destination `mesh_authz` can evaluate AuthorizationPolicy source matches against the originating workload. Identity-backed NodeWaypoint runtimes skip metadata-absent service targets so they cannot become plaintext backends; explicit no-CA/no-identity development runs retain the temporary plaintext fallback. Destination-side validation uses the selected workload destination scope only on the synthesized inbound HBONE relay when the trusted source assertion is honored; missing or untrusted relay baggage keeps the missing-source-scope fail-closed path, and the live gate now pins a wrong exact assertor SPIFFE ID to prove authenticated-but-untrusted baggage is rejected. The production identity profile is live-gated with Workload API SVID metrics, plaintext/no-client-SVID HBONE rejection, and SPIRE Agent plus NodeWaypoint restart recovery before traffic and policy are accepted. The pod-veth tc guard now drops unmarked direct traffic to enrolled pod IPs on host-side veth ingress; only the inbound HBONE relay backend dial is authorized with the Ferrum socket mark. **UDP/DTLS** stream authz is mesh-wide-only by architectural blocker (eBPF capture is `connect()`-hooked and TCP-only). Slice preparation accepts enforcing namespace/selector-scoped `AuthorizationPolicy` updates but disables NodeWaypoint UDP/DTLS service ports and UDP/DTLS proxies so unsupported traffic fails closed during config preparation; mesh-wide policies still evaluate, and audit-only scoped policies do not force suppression. Missing TCP scope or unresolved capture identity still rejects with 403 when scoped policies exist; with only mesh-wide policies, supported paths fall through to mesh-wide-only evaluation. Requires a Linux `--features ebpf` build; Helm automatically selects `…:<tag>-ebpf` for enabled eBPF node-agent and NodeWaypoint proxy DaemonSets. |

### Capture / data-path maturity

| Capability | Status | Notes |
|---|---|---|
| iptables capture (injector init container) | **Beta** | Requires `NET_ADMIN`/`NET_RAW`; rules applied at pod admission, restart needed to pick up new annotations. |
| eBPF ambient capture | **Dev-only** | Requires a build with `--features ebpf`. The default published image has no aya loader, but enabled eBPF node-agent mode now refuses the mock backend before readiness (`capture_state="unavailable"`, degraded reason `ebpf_feature_disabled`). Helm renders the Linux-only `-ebpf` image variant (`ferrumedge/ferrum-edge:<tag>-ebpf` / `ghcr.io/ferrum-edge/ferrum-edge:<tag>-ebpf`) automatically for `nodeAgent.captureMode=ebpf`, and for the ambient/NodeWaypoint proxy when it is configured for eBPF or `FERRUM_MESH_TOPOLOGY=node_waypoint`. Real capture needs kernel **≥ 5.7** with cgroup v2 and, on kernel **≥ 5.8**, `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON`; on the **5.7.x** window use `CAP_SYS_ADMIN` + `CAP_NET_ADMIN`. `node_waypoint` mode also needs `CAP_SYS_ADMIN` on modern kernels for pod-netns `setns()`/veth discovery, so the chart adds it automatically for that topology. The NodeWaypoint ambient proxy additionally receives host PID visibility plus read-only host cgroup and bpffs mounts so it can resolve pod netns, open node-agent-pinned maps, and write per-pod ready markers only after its in-netns listener is attached. CI builds the BPF object (`build-ebpf`), compiles the userspace loader (`build-ebpf-userspace`), load/attach-tests programs on a real kernel (`ebpf-live`), and runs the Docker/kind multi-pod datapath gate (`node-waypoint-ebpf-live`) for capture/identity/chart changes. The opt-in NodeWaypoint inbound tc redirect is implemented and fail-closed; the destination tc direct-inbound guard is also implemented, while the iptables fallback remains node-global and needs a tools-capable runtime image with `/bin/sh` + `iptables` — the published `-ebpf-tools` variant, or your own equivalent. |
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
| Cross-cluster endpoint discovery (local→remote failover) | **Beta** | `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS>0` dials each `RemoteCluster.control_plane_url`. The dedicated two-CP/two-DP Toxiproxy live gate proves bounded last-good retention, independent endpoint/trust expiry, fail-closed target withdrawal, same-generation recovery, and in-flight `RemoteCluster` retirement. Requires source locality to be set for local-first preference. |

## Limitations and Not Supported

This section consolidates every known residual gap so operators do not have to reconstruct them from the prose. Items are grouped by area; each is enforced or deferred as described against the merged code.

### Not interoperable / not planned

- **Stock Envoy / third-party Istio xDS interop** — `FERRUM_MESH_CONFIG_PROTOCOL=xds` is a **Ferrum-CP-to-Ferrum-DP** path and stays that way: CDS/EDS/LDS/RDS are name-only with Ferrum-shaped resource names, and all security/policy fields ride Ferrum-defined ECDS carriers, so pointing *that* client at a non-Ferrum CP remains unsupported. For a third-party control plane use the separate `FERRUM_MESH_CONFIG_PROTOCOL=stock_xds` profile, which consumes standard v3 CDS/EDS/LDS/RDS for **discovery only** — see [Stock Envoy / third-party Istio xDS interoperability](#stock-envoy--third-party-istio-xds-interoperability) for the exact capability boundary. Enforcement policy is never sourced from a stock CP.
- **`EnvoyFilter`** — not planned. Use Ferrum custom plugins (`custom_plugins/`).
- **`WasmPlugin`** — not planned. Use Ferrum custom plugins.
- **Aggregate ADS admission budgets** — the CP bounds total, per-namespace, per-principal, per-node, and distinct-node ADS occupancy, plus `Node.id` shape and an initial-request deadline. See [xDS ADS admission budgets](#xds-ads-admission-budgets). (Resource warming / make-before-break across types is now implemented — see [xDS ADS Compatibility](#xds-ads-compatibility).)

### Capture / node-waypoint (see also the Maturity matrix)

- **eBPF capture is a build feature** — the default published image lacks the aya loader, but enabled eBPF node-agent mode rejects that mock backend before readiness instead of silently no-op'ing. Helm automatically selects the `-ebpf` image tag for enabled eBPF node-agent and NodeWaypoint proxy DaemonSets. CI load/attach-tests the programs on a real ≥5.7 kernel (`ebpf-live`) and gates capture/identity/chart changes with the Docker/kind multi-pod `node-waypoint-ebpf-live` workflow.
- **Node-waypoint identity: GAP-2M bridge implemented (IPv4 + IPv6), capture live-gated** — the accept-side socket-cookie bridge is implemented in the kernel `sock_ops` program (re-keys orig-dst by connection tuple, re-stamps under the accept-side cookie), so cookie resolution can succeed with `--features ebpf`. **IPv4 and IPv6**: the v6 ctx address words are read element-by-element with verifier-safe volatile loads (the per-element technique that sidesteps the verifier's rejection of a whole-`[u32;4]` ctx copy) and keyed by `FERRUM_ORIG_DST_BY_TUPLE6`, so the v6 accept-side bridge resolves on the same footing as IPv4. The in-netns manager binds both `127.0.0.1:<port>` and `[::1]:<port>` inside enrolled pod netns, and the `node-waypoint-ebpf-live` workflow validates both capture families; a tuple/byte-order mismatch fails closed (never misattributes).
- **Node-waypoint destination metadata** — each mesh `Workload` can carry an optional `node_waypoint` object with `address`, `hbone_port` (default `15008`), expected NodeWaypoint `spiffe_id`, and optional `node_name`, `node_uid`, `network`, and `cluster`. Kubernetes pod discovery populates this object for service-backed workloads when their node has a ready host-network NodeWaypoint proxy pod in `FERRUM_K8S_CONTROLLER_NAMESPACE` with `app.kubernetes.io/name=ferrum-mesh-ambient`, service account `ferrum-mesh`, and `FERRUM_MESH_TOPOLOGY=node_waypoint`; scoped workload watches still include that trusted namespace for Pod discovery. The Helm chart sets `FERRUM_K8S_CONTROLLER_NAMESPACE` to the release namespace and requires the ambient NodeWaypoint admin health listener to stay enabled so the DaemonSet has a real readiness probe. The endpoint address comes from the proxy pod IP, `hbone_port` comes from `FERRUM_MESH_HBONE_LISTEN_ADDR` when present (then the named `hbone` container port, then default `15008`), and the expected peer identity comes from `FERRUM_MESH_WORKLOAD_SPIFFE_ID` when present (then the proxy pod's service account SPIFFE ID). Captured Service targets consume this metadata when present: they select the workload first, keep the workload app address and port as the inner CONNECT authority, dial the hosting node's NodeWaypoint endpoint via `mesh.hbone_dial_host`, and pin `mesh.hbone_peer_spiffe_id` instead of synthesizing `podIP:15008`. When the source NodeWaypoint runtime has file SVID material or a mesh CA backend (required by production mode), metadata-absent targets are skipped so the Service route fails closed instead of retaining a plaintext backend. Explicit no-CA/no-identity development runs keep the temporary plaintext fallback; the required live gate uses SPIRE-backed production mode instead.
- **Node-waypoint UDP/DTLS stream authz is mesh-wide-only** — TCP stream connections through a node-waypoint proxy now scope per source pod via `resolve_node_waypoint_stream_scope()` (socket-cookie → pod identity → `PolicyScopeCache`); when the connect-side resolver returns no identity, the connection fails closed with 403 if any namespace/selector-scoped `AuthorizationPolicy` exists in the mesh (else falls through to mesh-wide-only evaluation). **UDP/DTLS** scope is unresolvable by architecture — eBPF capture is `connect()`-hooked and TCP-only, and a UDP proxy demuxes all clients off one shared frontend socket — so UDP node-waypoint authz is always mesh-wide-only. NodeWaypoint slice preparation accepts scoped policy updates but disables UDP/DTLS service ports and UDP/DTLS proxies when enforcing namespace/selector-scoped policies exist, so UDP/DTLS fails closed instead of continuing under stale no-policy config; mesh-wide policies still evaluate, and audit-only scoped policies do not force suppression.
- **Inbound TC ingress redirect implemented (IPv4 + IPv6), opt-in and live-gated** — `ferrum_tc_ingress_redirect` (`ebpf/ferrum-ebpf/src/tc_ingress_redirect.rs`) is a tc **ingress** classifier attached to the node capture interfaces named by `FERRUM_NODE_AGENT_INGRESS_REDIRECT_IFACES` (unset = off, and the whole datapath stays inert). It steers inbound TCP for enrolled workloads into a dedicated **transparent inbound capture listener** with `bpf_sk_assign()` instead of a node-global `nat PREROUTING -j REDIRECT`. **The steer target is NOT the HBONE listener**: HBONE (`:15008`) terminates authenticated HTTP/2 CONNECT over verified mesh mTLS, while captured traffic is ordinary application bytes (possibly the app's own TLS), and `IP_TRANSPARENT` preserves addresses rather than transforming payloads. The capture listener is a separate protocol boundary bound on `FERRUM_MESH_INBOUND_LISTEN_ADDR` (default `0.0.0.0:15006`, unused by NodeWaypoint otherwise) — the single source of truth for the port on both the proxy and the node-agent — and it terminates nothing. **Scope is per workload and per port**: the destination must be in `FERRUM_POD_IPS`/`FERRUM_POD_IPS6` carrying `POD_CAPTURE_FLAG_INBOUND_REDIRECT`, *and* the exact `(pod address, destination port)` pair must be in `FERRUM_POD_INBOUND_PORTS`/`FERRUM_POD_INBOUND_PORTS6` (derived from the pod's declared `containerPorts`); anything else is returned untouched, so unenrolled traffic is never captured. **IPv4 fragments are declined before any port is read** (More-Fragments or non-zero offset), because a non-first fragment's payload bytes would otherwise be parsed as ports and could be made to match a declared pair; IPv6 extension/fragment chains likewise pass through unparsed. **Original destination metadata is preserved without NAT** — addresses are never rewritten, so the capture listener's accepted socket reports the workload's real `podIP:appPort` from `getsockname()` with no conntrack table and no reverse NAT; that one listener (and no other) binds `IP_TRANSPARENT`/`IPV6_TRANSPARENT` on a wildcard address so its replies may be sourced from the captured pod address. **Security posture on the capture path is DESTINATION-EXACT**, because one capture listener serves every enrolled pod on the node: the recovered destination must resolve to exactly one workload in a dedicated **NodeWaypoint capture destination inventory** (address match plus a port the workload declares — no match, an empty inventory, or two records claiming the address with divergent identity all close the connection), and both gates that follow are then properties of *that* workload rather than of the listener. Direct captured plaintext is admitted only where **that workload's own** effective PeerAuthentication posture on the captured app port permits it — resolved from its namespace/labels with the canonical resolver, deliberately not from the listener-wide per-port table, so a `PERMISSIVE` pod can never admit plaintext to a `STRICT` pod sharing the app port; `STRICT` still requires verified mesh transport and refuses direct plaintext.

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

  **Cross-namespace destination policy (issue #3287).** A NodeWaypoint is typically deployed in an infrastructure namespace (`ferrum`) while the pods it captures for live in application namespaces (`payments`). The ordinary slice views — `workloads`, `peer_authentications` — are narrowed to the subscription namespace, so they can neither name a cross-namespace destination nor carry that destination's `PeerAuthentication`; resolving against them would see no policy and fall back to Istio's `PERMISSIVE` default, admitting direct plaintext to a `STRICT` pod. The capture path therefore consumes **two dedicated, least-privilege slice fields** instead:

  * `node_waypoint_capture_destinations` — the workloads whose trusted `Workload.node_waypoint.spiffe_id` names **this exact NodeWaypoint**. That key is per-node, set by the config authority (never by the pod), and is the same identity the secured NodeWaypoint transport pins as the destination's server SVID.
  * `node_waypoint_capture_peer_authentications` — the PeerAuthentication candidates applicable to those destinations (mesh-wide/root-namespace, namespace-scoped, and selector-scoped alike), so Istio precedence and port overrides resolve exactly as the destination's own sidecar would resolve them.

  The request opts in with `MeshSliceRequest.node_waypoint_capture_scoping`, set only for `MeshTopology::NodeWaypoint`. It is deliberately **not** folded into `ambient_udp_source_scoping`: NodeWaypoint UDP stays mesh-wide-only by architecture, so one shared flag would either hand NodeWaypoint a UDP source superset it must not act on, or leave Ambient/ServiceWaypoint carrying a capture inventory they have no capture listener for. Native `MeshSubscribe` carries the flag as `MeshSubscribeRequest.node_waypoint_capture_scoping`; xDS carries it in `Node.metadata` and returns the inventory on its own ECDS carriers (`NodeWaypointCaptureDestinationsCarrier`, `NodeWaypointCapturePeerAuthenticationsCarrier`), so native and xDS reach the same posture. The file/local source derives it DP-side from the same document.

  **Authorization and blast radius.** The CP resolves the inventory *before* its own namespace narrowing (after it, the cross-namespace records are already gone) but *after* applying the CP scope and the bearer `ns` claim: a `Single`-scope CP is a hard boundary for this cross-namespace evidence exactly as it is for Ambient UDP source evidence, and an explicit `ns` claim intersects the set. The inventory is **never** folded into `workloads` / `services` / `peer_authentications`, so ordinary routing, known-destination, outbound-registry, and own-inbound-posture views stay namespace-narrow. It is read by the capture resolver and nothing else. **Fail closed everywhere:** a legacy CP that emits no inventory, a NodeWaypoint whose own SPIFFE identity is unknown, a namespace the CP or bearer does not authorize, and a pod enrolled on another node's NodeWaypoint all yield no resolvable destination — the connection is refused (and counted as `relay_destination_denied`), never resolved against `workloads` with the wrong policy view. Incremental CP deltas carry no mesh resources, so the per-stream inventory is recomputed from the authoritative snapshot on every mesh change rather than accumulating stale destinations; `MeshSlice::content_eq` compares both fields so a destination leaving the inventory, or its namespace flipping `PERMISSIVE`→`STRICT`, is never deduped away.

  **Residual risk.** The posture the capture path enforces is only as good as the destination inventory the config authority publishes: a workload whose `node_waypoint` endpoint metadata is missing or points at the wrong NodeWaypoint is not captured for at all (fail closed, but its inbound direct plaintext is then simply dropped by the classifier rather than relayed). Cross-*cluster* capture destinations are out of scope — the inventory is derived from the local cluster's workload records. The L4 `on_stream_connect` chain (including `__mesh_authz`) then runs with the captured app port as the authorization destination and that workload's policy scope stamped on the stream context, so namespace/selector-scoped `AuthorizationPolicy` rules are evaluated against the captured destination instead of denying every captured connection `scope_missing`; the stream is then relayed byte-for-byte so application TLS is never mistaken for mesh TLS. Every gate is fail-closed, and Sidecar inbound relay entries are unchanged (no socket mark, no destination scope). Backend dials carry the relay auth mark (`0x734`) for loop prevention and pod-veth admission. Local delivery of assigned packets rides a Ferrum-owned `ip rule fwmark 0x735 lookup 33134` at priority `101` (evaluated ahead of the kernel `main` rule at 32766, which the RPDB scans later because its priority number is higher) plus `ip route add local default dev lo table 33134`, per family; the table is distinct from the UDP TPROXY table `33133` so teardown of one never reaps the other. **Loop prevention** is four independent guards: the relay's own auth mark (`0x734`), the redirect mark itself (`0x735`), traffic already addressed to the capture port, and traffic addressed to the HBONE port. **Fail closed**: a packet that is in scope but for which no capture-listener socket resolves is dropped, never delivered unredirected; and startup refuses if the redirect is armed while the capture listener cannot bind or the node-agent/proxy port contracts disagree — the proxy validates `FERRUM_MESH_INBOUND_LISTEN_ADDR` (present, non-zero port, wildcard) with a field-specific error at the top of its serving path, because listener *planning* is infallible and would otherwise warn-and-skip the listener while the classifier kept dropping in-scope packets. **Teardown is retry-safe and ordered**: a failed classifier detach keeps its attachment recorded so `cleanup_all` really does retry it, and the Ferrum-owned local-delivery `ip rule`/`ip route` is removed only once no classifier can still be live (a live classifier without its routing strands every packet it assigns; inert leftover routing is the safe half-state and is reported rather than force-removed). **The node-global iptables fallback is NOT removed** — it remains the documented path for kernels that cannot run eBPF at all (`FERRUM_NODE_AGENT_FALLBACK_MODE=iptables`), which is a separate concern from the covered eBPF path. Verification: the shared decision table (arming, scope, all four bypasses, the fragment gate) is unit-tested in `ferrum-ebpf-common`, and the required `ebpf-live` CI job load/verifies the program on a real kernel — the only way to check the `bpf_skc_lookup_tcp`/`bpf_sk_assign`/`bpf_sk_release` reference-tracking rules — attaches and detaches it on a scratch veth tc ingress hook, round-trips both address families of the scope maps, **and drives a real TCP flow end to end** from a client in a scratch netns through the redirect into the transparent capture listener, asserting the observed original destination, a successful reply path, and that the flow is no longer steered after detach + scope clear.

### Authorization

- **`ipBlocks` / `remoteIpBlocks` on the stream path now distinguish socket peer from forwarded address** — on the HTTP request path `ipBlocks`/`source.ip` is the immediate downstream socket peer (`direct_client_ip`) and `remoteIpBlocks`/`remote.ip` is the gateway-resolved, XFF-aware `client_ip`. On the **TCP stream path** (`on_stream_connect`) the same split now applies: `source.ip` = socket peer (`StreamConnectionContext.direct_client_ip`), `remote.ip` = resolved client IP (`StreamConnectionContext.client_ip`). When **inbound PROXY protocol** (`stream_proxy_protocol: true`) is enabled on a TCP stream proxy and the upstream LB is in `FERRUM_TRUSTED_PROXIES`, the forwarded address from the PROXY header becomes `client_ip` (used for `remote.ip` / `remoteIpBlocks`) while `direct_client_ip` retains the LB's own socket-peer IP (used for `source.ip` / `ipBlocks`). Without PROXY protocol both values equal the socket peer — this is the correct Envoy-parity behavior for raw TCP not fronted by a PROXY-protocol-capable LB. **UDP/DTLS** streams never receive PROXY protocol (it is TCP-borne), so `source.ip` and `remote.ip` always equal the socket peer on the UDP path. IP-block matchers fail closed when the IP they test is absent.
- **DENY rules treat missing HTTP-only attributes as matches** — Istio semantics. Port-scope DENY rules that mention HTTP fields and can see TCP traffic, or they may over-match.

### DestinationRule limitations / approximations / deferred fields

- **`connectionPool.http.maxRequestsPerConnection`** — **Deferred**: parsed and validated, but not projected or enforced because Ferrum has no backend close-after-N-requests behavior for the shared backend pools. K8s status lists it in `status.ferrum.translation.deferred_fields`; negative values are rejected and `0` is accepted as Istio's unlimited sentinel but still deferred. Use `http2MaxRequests` for HTTP/2-family concurrency.
- **`connectionPool.tcp.maxConnections`** — **applied everywhere Ferrum owns the physical backend connection**: stream-family (TCP/TCP+TLS), HTTP-family WebSocket (H1/H2/H3), the pooled multiplexed transports (direct H2, gRPC, native HTTP/3, HBONE, Sidecar mesh-mTLS), and the reqwest transports (HTTP/1.1 and ALPN-negotiated HTTP/2) — all through one shared RAII counter on `ProxyState.backend_conn_limit`, keyed per `(host, DestinationRule policy port)`. A pooled connection reserves its slot at construction and hands it to that connection's own driver, so the slot retires exactly when the socket dies and reuse/multiplexing takes NO extra slot (`http2MaxRequests` / `h2_max_concurrent_streams` remains the *stream*-concurrency knob). reqwest is admitted the same way inside its own connector via the vendored `connection_admission` hook, so an idle socket reqwest retains still holds its slot and all reqwest pool keys for a destination share ONE ceiling. Full contract in [DestinationRule `maxConnections` enforcement scope](#destinationrule-maxconnections-enforcement-scope).
- **`connectionPool.http.h2UpgradePolicy`** — **applied** to the plain-HTTPS backend HTTP/1.1-vs-HTTP/2 dispatch fork at top-level, `portLevelSettings`, and selected-subset scope. `DO_NOT_UPGRADE` forces the reqwest/H1 path even when the backend capability registry proves H2 **and** restricts the reqwest client's ALPN to `http/1.1` (with both a force-H1 client discriminator and the selected subset in every HTTP-family pool key) so incompatible transports cannot share a client or connection; `UPGRADE` prefers direct-H2 (and treats an unclassified `Unknown` target as a hint to try H2, staying fail-safe against a proven-`Unsupported` one); `DEFAULT`/absent leaves probe-driven behavior unchanged (`DEFAULT` is carried explicitly so an explicit higher-precedence value clears an inherited override). Does NOT touch gRPC (always H2) or HBONE/mesh-mTLS transport selection. Unknown enum values are rejected at translate time.
- **`connectionPool.http.maxRetries`** — **applied** as a **per-request retry-count CAP**, NOT Envoy's cluster-wide outstanding-retry budget (see [DestinationRule `maxRetries` semantics](#destinationrule-maxretries-semantics)). Caps each attempt to `min(original_route_ceiling, target_maxRetries)`; never increases retries and does NOT synthesize a retry policy when none exists. The original route ceiling remains available across target rotation. Zero explicitly disables an existing retry policy for the destination; negative values are rejected at translate time.
- **`connectionPool.http.http1MaxPendingRequests`** — **applied** at top-level, `portLevelSettings`, and selected-subset scope as a per-logical-destination `(namespace, upstream/Service identity, policy port, selected subset)` cap on the **reqwest/HTTP-1.1** backend-dispatch path (and the H3→plain reqwest bridge). **Honest reinterpretation — max concurrent in-flight H1 requests** (mirroring how DR `maxRetries` is reinterpreted as a per-request cap): Envoy's knob bounds the *pending-queue* depth (requests admitted but not yet assigned a connection), but Ferrum dispatches H1 over reqwest, whose `send().await` resolves at **response headers** and exposes **no connection-acquisition hook** — so true pending-queue depth is not measurable. Ferrum therefore reframes the knob as a bound on how many H1 requests are **simultaneously in flight** to a logical destination and selected subset (measured dispatch → response-headers); when a lane is at its cap a new H1 request is **shed with a 503** ("upstream overflow", classified `dispatch_policy_rejected`) rather than queued unboundedly. The lane is keyed by precomputed logical identity (namespace/tenant, stable logical upstream/Service identity, optional Kubernetes Service UID when stamped, policy port, selected subset) — **not** by the selected endpoint host — so endpoint fan-out / DNS rotation cannot multiply the cap and independent Services sharing pods remain isolated (issue #3778). Mesh VIP/service-host and direct-pod routes for one Service use its FQDN; ordinary upstreams retain their resource ids. Because the shed happens before any backend dial, it is **neutral to backend health** — not retried, does not trip the backend circuit breaker / passive health, and does not shrink the adaptive-concurrency permit (a `client_side_no_backend_signal` class). The connection-failure **retry** path re-enters the same gate per attempt (the initial attempt's slot is released before the retry loop runs), so `retry_on_connect_failure` retries are bounded too. The gate is consulted only for dispatch **known HTTP/1.1 at acquire time** (`reqwest_dispatch_is_http1_only`): a `DO_NOT_UPGRADE` proxy, a **plaintext `http`** backend (reqwest never speaks h2c over cleartext), or an **HTTPS backend the capability registry has already classified H2-unsupported (H1-only)**; an HTTPS backend that may still ALPN-negotiate h2 is left **uncapped** (an `http1*` knob must not 503 an h2 backend — that is `http2MaxRequests`'s job). Under the in-flight framing there is **no body-shape exclusion** — bodyless GET/HEAD and streamed-upload requests are capped alike. **HTTP/1.1-scoped by design**: the multiplexed transports (direct H2, gRPC, HTTP/3, HBONE, mesh-mTLS) return before the reqwest path and never consult it. **Coverage note:** target rotation re-resolves the current target's effective policy, while the selected subset remains fixed for the route; explicit per-port entries win over selected-subset policy, which wins over top-level policy. The HTTP/3 frontend applies the selected-target effective proxy before native-H3, H3→gRPC, and H3→plain dispatch, so these knobs are no longer H1/H2-only from a configuration standpoint; transport-scoped behavior still applies. Enforced via an RAII guard on `ProxyState.backend_pending_limit` (see `src/backend_pending_limit.rs`), a sharded `CachePadded` atomic gate whose guard releases on success, error, deadline, retry transition, or task cancellation. Length-prefixed encoding isolates namespaces, logical upstream/Service identities plus optional K8s UIDs, policy ports, and subset names; zero-count keys are race-safely retired when the last guard drops. Cap updates use the requesting epoch's effective cap against the shared count so existing guards release exactly once. Zero is rejected at translate time, and native/file mesh validation applies the same positive-value rule.
  When `pool_enable_http2: false`, Ferrum treats the reqwest dispatch as known HTTP/1.1 immediately because the preconfigured-rustls path omits h2 ALPN, so the cap applies without waiting for capability-registry classification.
- **Per-subset policy** — `connectionPool.tcp.connectTimeout`, `connectionPool.http.{h2UpgradePolicy,maxRetries,http1MaxPendingRequests,idleTimeout,http2MaxRequests}`, consistent hashing, TLS, and outlier policy are applied for proxies whose `upstream_subset` selects the subset. The HTTP fields use field-level precedence `portLevelSettings` > selected subset > top-level; unmatched destinations receive only top-level policy. **Semantics differ from Istio on purpose.** Istio applies **subset > DR `portLevelSettings`**, and a subset that sets *any* `connectionPool` field replaces the whole top-level `connectionPool` wholesale (`MergeSubsetTrafficPolicy` / `MergeTrafficPolicy`). Ferrum keeps the inverted tier order and field-level merge (the same deliberate convention already used for port-level overrides). Example: DR sets `portLevelSettings[{port:8080}].connectionPool.http.h2UpgradePolicy: UPGRADE` and `subsets[v1].trafficPolicy.connectionPool.http.h2UpgradePolicy: DO_NOT_UPGRADE` — Istio sends subset-v1 traffic on 8080 forced-H1; Ferrum negotiates h2. Likewise a subset setting only `maxRetries: 2` inherits a top-level `DO_NOT_UPGRADE` here, where Istio's wholesale replacement clears it. `subsets[].trafficPolicy.portLevelSettings` is **not applied** (deferred with a translate-time warning); express per-port policy at top-level `trafficPolicy.portLevelSettings` or use subset `connectionPool` fields.
- **`portLevelSettings[].tls`** — **applied** per-port: resolved over the upstream-level TLS at apply time and projected onto the per-target effective proxy's `resolved_tls` (which is part of the backend pool key, so a distinct per-port TLS posture fragments its own pool). Takes precedence over the upstream-/subset-level `trafficPolicy.tls` for dials to that port.
- **`loadBalancer.simple = PASSTHROUGH`** — true passthrough on captured paths: when the request's captured original destination (`SO_ORIGINAL_DST` on the mesh capture listeners) matches a target in the upstream's pool, that target is dialed (bypassing load balancing); when no original destination was captured (non-mesh / non-captured paths, e.g. HTTP/3) or it matches no (healthy) pool target, selection falls back to `ROUND_ROBIN` (warns). A passthrough-selected target still respects active/passive health — an ejected original-destination target falls back to round-robin among healthy targets. `MAGLEV` is a hard reject.
- Stream-family (TCP/UDP/DTLS) upstreams engage per-port `loadBalancer` (algorithm and hash key) and `localityLbSetting` at selection time when all upstream targets share a single port (i.e. the LB cache resolves a non-zero `initial_dispatch_port_override`), matching the pre-selection semantics the HTTP path uses. The port lane engages only for **selection-affecting** overrides (`loadBalancer` algorithm / `consistentHash` key / `localityLbSetting`); a per-port entry that carries only `connectTimeout` / `maxConnections` / `tcpKeepalive` / `outlierDetection` never changes stream selection. For a subset-routed stream proxy a per-port override that sets no algorithm keeps the **subset's** algorithm/hash ring while still scoping candidates and locality to the port lane. Three stream-lane rules are **fail-closed** (the connection is refused with a typed `Unsupported stream policy` setup error, classified as a request error — no backend-health penalty, no retry): a per-port `consistentHash` on an engaged stream lane must resolve to a **source-IP** hash key (header/cookie keys are HTTP-only — raw streams carry no headers); per-port `LEAST_CONN` is rejected on the generic TCP/UDP stream listeners, which keep no stream LB accounting (the **mesh** raw-TCP/UDP relays DO maintain per-target connection counts via their LB connection guards, so per-port `LEAST_CONN` selects normally there); and per-port `LEAST_LATENCY` is rejected on **every** stream lane — generic and mesh alike — because raw byte relays record no response latency. Stream consistent hashing (upstream-level or port-lane) hashes the **client IP**; previously stream selection used a static per-proxy hash key, which pinned all of a proxy's connections to one target — existing `consistentHash` stream configs now distribute per client. Stream selection now consults the same active-health and per-proxy passive-ejection state as HTTP-family dispatch, including the `maxEjectionPercent` cap at the resolved pre-selection tier. A passive-health-only per-port override scopes health/ejection caps to that port even though it does not engage the LB port lane; otherwise the cap resolves at subset/upstream scope. TCP `retry_on_connect_failure` rotation reuses the same health context and returns no alternate when the remaining candidates are unhealthy instead of synthesizing an unhealthy retry fallback. Per-port `outlierDetection` thresholds are still not recorded by stream paths — raw relay sessions carry no response status — so stream paths consume ejections recorded by active probes or HTTP-family traffic on the same proxy/upstream, but do not create new passive ejections themselves. Per-port `connectTimeout` and `maxConnections` apply to stream dial independently (they are post-selection).

### VirtualService

- **`spec.tcp[]` / `spec.tls[]` L4 routing** — **supported** (materialized into Ferrum stream proxies, reusing the gateway/east-west stream + SNI machinery): `tls[]` → a passthrough TCP proxy keyed by SNI (`sniHosts`, encrypted bytes forwarded with no TLS termination); `tcp[]` → a plain TCP proxy keyed by port. Optional L4 match predicates (`sourceLabels` / `sourceSubnets` / `destinationSubnets` / `gateways` / `sourceNamespace`) compile onto `Proxy.stream_match` and are evaluated from trustworthy connection/workload metadata (authoritative client IP after the trusted PROXY boundary, capture original destination, canonical `ns/<namespace>/sa/<service-account>` peer SPIFFE identity / unambiguous workload labels, listener gateway binding) before route selection — missing or ambiguous evidence denies the predicate; malformed values fail closed at common admission and translation (`FerrumAccepted=False`/`Invalid`). Rules retain VirtualService declaration order, including an earlier catch-all or wildcard TLS rule; generic hand-authored passthrough proxies without L4 criteria retain exact-SNI-before-wildcard precedence. `spec.exportTo` projects each L4 proxy into the sidecar or named-gateway runtime namespace that may consume it, and match-level gateway overrides are filtered per projected namespace. Every `tls[].match.sniHosts` entry must be a subset of `spec.hosts`; Istio wildcard SNI additionally materializes its suffix apex because Istio includes that name while Ferrum's generic wildcard deliberately does not. The combined `tcp[]`/`tls[]` candidate count is bounded at `MAX_L4_CANDIDATE_PROXIES` (64) before proxy materialization — that ceiling is the CRD-controlled fan-out. After `exportTo` namespace projection the product `candidates × export namespaces` is additionally fail-closed at `MAX_PROJECTED_L4_PROXIES` (1024): the namespace factor is environmental (omitted/empty/`*` `exportTo` expands to known watched namespaces), so a single ordinary L4 route must still translate in large multi-namespace meshes, while a hostile match-port fan-out remains capped at 64. Weighted multi-destination `tcp[]`/`tls[]` splits materialize an upstream-backed stream proxy (`istio-vs-l4-upstream-*`) with relative WRR weights; zero-weight legs in a multi-destination split are skipped (all-zero multi-destination splits materialize a fail-closed `ferrum-zero-weight.invalid.` blackhole backend so the match remains traffic-capturing); invalid weights and multi-destination port disagreement without `match.port` fail closed with field-specific diagnostics. A missing destination port and `destination.subset` fail closed on **any** `tcp[]`/`tls[]` destination, single or weighted: a stream proxy has no subset selector, so a subset destination is rejected rather than silently widened to the whole service. Weighted L4 upstreams ride `MeshSlice.virtual_service_l4_upstreams` / the ECDS `VirtualServiceL4UpstreamsCarrier` beside the L4 proxies so mesh reload/delete cannot retain a stale load-balancer set. (`mirror`, `mirrorPercentage`, `redirect`, and `rewrite` are fully translated.)
- **`http[].corsPolicy`** — translated to a proxy-scoped `cors` plugin. The full Istio `allowOrigins[]` `StringMatch` set is projected — `exact`, `prefix`, and `regex` (plus the legacy `allowOrigin` exact string list) — along with `allowMethods`/`allowHeaders`/`exposeHeaders`/`maxAge`/`allowCredentials`/`unmatchedPreflights`. Omitted, `UNSPECIFIED`, and `FORWARD` unmatched preflights are forwarded with the upstream status/body preserved, every upstream `Access-Control-*` response field stripped, and no gateway CORS authorization fields added; `IGNORE` receives a local 200 without CORS authorization. Unmatched actual requests are likewise forwarded with the upstream status/body preserved, every upstream `Access-Control-*` response field stripped, and no gateway CORS authorization fields added. A participating translated policy owns `Access-Control-*` response fields even when a request has no `Origin`: Ferrum strips those upstream fields while preserving unrelated response headers, preventing a shared-cache replay from widening the gateway policy. Omitted or empty method/header lists remain empty and omitted `maxAge` remains absent. Method/header lists govern preflight only and never reject an actual request; when native and translated instances compose, an empty Istio list still narrows the aggregate preflight policy without blocking the actual request. Exact `*` (including legacy `allowOrigin: ["*"]`) is Istio allow-all when credentials are false or omitted. A credentialed exact `*` stays deferred because Ferrum's native wildcard representation cannot emit the concrete request origin required for credentialed CORS; it is never translated into wildcard-without-credentials, and the native/file mesh carrier rejects the same unrepresentable combination. Every OTHER `exact` value is projected onto the `cors` plugin's LITERAL `{"exact": ...}` matcher, byte-for-byte (issue #3254): a wildcard-shaped exact such as `*.example.com` keeps its upstream literal meaning and is NEVER reinterpreted as Ferrum's native wildcard-subdomain syntax (which would authorize every subdomain the source never matched), and a noncanonical exact such as `https://Example.com:443` is carried verbatim instead of being canonicalized into permission for the browser-serialized origin. These shapes are therefore translated now rather than deferred. The plugin's NATIVE plain-string `allowed_origins` form keeps its own canonicalizing, case-insensitive, wildcard-subdomain semantics; the translator never emits it for an Istio matcher. The `cors` plugin's `allowed_origins` accepts the same matcher shapes as object entries (`{"exact": ...}` / `{"prefix": ...}` / `{"regex": ...}`): `exact` is a literal byte-for-byte, case-sensitive comparison with the request `Origin`, `prefix` is a literal byte-prefix, and `regex` is an RE2 full match (same `StringMatch` semantics Ferrum applies elsewhere); a matching origin is reflected verbatim into `Access-Control-Allow-Origin`. Matchers are admitted against EXPLICIT bounds shared by the translator, the plugin, and native/file mesh validation (issue #3253): at most 64 `allowOrigins[]` entries, 512 bytes per matcher value, and — for `regex` — a 64 KiB compiled-program limit, a 64 KiB lazy-DFA limit, and an AST nesting limit of 24. Every `regex` is compiled ONCE at config construction/reload, never per request (the engine is finite-automaton based, so there is no catastrophic backtracking). An un-compilable or over-complex `regex`, an over-budget matcher value or list, an empty/whitespace-only `exact`, an empty `prefix`, or an otherwise malformed/unknown origin matcher makes the policy non-translatable: it is left unprojected (warned, surfaced as a `deferred_fields` entry) rather than silently approximated, truncated, or widened — configure the `cors` plugin directly for those. Routing on the route is unaffected either way. On **mesh sidecars** a translatable `corsPolicy` ALSO rides the slice as `mesh.virtual_service_cors_policies` (one entry per VS host; the FIRST SIDECAR-APPLICABLE entry decides, mirroring Istio's in-order first-match evaluation: if it is host-wide-representable — no `match`, or a catch-all `/` prefix, with `name`/`ignoreUriCase` treated as non-scoping metadata — its translatable corsPolicy is carried; if it has no corsPolicy, its policy is untranslatable, or it is PREDICATE-SCOPED (narrower uri, `headers`, `port`, `sourceLabels`, …), nothing is carried — a scoped entry wins part of the host's traffic with its own (possibly absent) CORS, and the materialized mesh route has no path predicates to keep the two apart, so a later route's policy is never promoted host-wide. Entries invisible to sidecars neither donate nor suppress. Exact matchers are carried literally, so a whitespace-padded, noncanonical, or non-`scheme://host[:port]` exact is representable (it simply matches only that literal string) rather than deferred; only an empty/whitespace-only or over-budget exact is non-translatable — deferred by the K8s translator and rejected fail-closed at slice validation on the native/file source, which runs the SAME `plugins::cors` admission predicates. The legacy `allowOrigin` string list shares the same exact-origin gate, and `allowMethods`/`allowHeaders`/`exposeHeaders` entries must pass the plugin's method/header-name admission — an invalid token defers the policy (K8s) or rejects the slice (native/file) instead of failing `cors` plugin construction on the data plane; carried hosts are normalized (trim, trailing-dot strip, ASCII-lowercase) by `MeshConfig::normalize()` on the config sources AND again as the synthesis match key, so a slice arriving over the native/xDS carriers matches its service without config-source normalization), and the client sidecar synthesizes the `cors` plugin onto its materialized outbound routes from it (issue #1973). Only sidecar-applicable routes are carried, resolved PER `http[]` ENTRY: Istio's `match[].gateways` OVERRIDE the top-level `spec.gateways` list, so a match naming the reserved `mesh` gateway applies to sidecars even under an ingress-only VS, a match naming only non-mesh gateways is skipped even under a mesh-bound VS (skipped entries neither donate nor suppress the carried policy), and a match without `gateways` — or an entry with no `match` — inherits the VS-level scope (`spec.gateways` omitted or containing `mesh`). Synthesis is client-**Sidecar**-topology-only; uncredentialed exact `*` is carried as Istio allow-all, noncanonical and wildcard-shaped exacts such as `*.example.com` are carried as literal matchers, and credentialed exact `*` remains non-translatable and defers, and `spec.exportTo` visibility is honored by slice narrowing with ServiceEntry semantics (an omitted exportTo is carried as an explicit `["*"]`; an EMPTY `export_to` on the native/file source is namespace-local by Ferrum convention). Visibility is evaluated by the ONE shared evaluator ServiceEntry and DestinationRule use, and it is enforced at the SAME three points a DestinationRule's is — CP slice narrowing, the xDS carrier fold on the DP, and outbound `cors` plugin synthesis on the DP — so a carrier that bypassed slice admission cannot inject another namespace's CORS behavior onto this workload's routes, and the carried list gets the same fail-closed boundary check `DestinationRule.exportTo` gets at BOTH boundaries: a non-array `spec.exportTo`, a non-string entry, `~`, an empty entry, a malformed namespace name, a list over 64 entries, or `*` mixed with an explicit namespace makes the VirtualService `FerrumAccepted=False`/`Invalid` at translation and is rejected by native/file/xDS slice validation — never silently dropped and defaulted to the public `["*"]`.
- **Per-rule fault percentages are not RTDS-tunable** — the GAP-3E RTDS fault keys apply only to `fault_injection` plugin instances with `runtime_overlay_scope`, not to per-route VS faults.

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
| **Requests denied unexpectedly** | `mesh_authz` evaluated DENY-first then implicit-deny-on-no-ALLOW-match. | `GET /mesh/policy-denies/recent` (JWT) groups recent denies by `(rule, source, destination, reason)`; correlate with `ferrum_mesh_requests_total{response_code="403"}`. Transaction logs carry `mesh_authz.deny_policy` (e.g. `untrusted_assertor`, `trust_domain_mismatch`, `unauthenticated_baggage`) and `mesh_authz.scope_missing` (node-waypoint per-pod scope not yet enrolled). |
| **mTLS / HBONE handshake failures** | Peer cert chain or SPIFFE trust-domain validation failed, or a plaintext peer hit a STRICT listener. | `ferrum_mesh_mtls_handshake_failures_total{reason}` (`timeout` / `error`) for mesh-wide TLS. On NodeWaypoint also `ferrum_mesh_node_waypoint_hbone_handshakes_total{phase,result}` (phased inbound_tls / inbound_connect / outbound_dial; see `docs/plans/node_waypoint_transport_adr.md`). Check that gateway SVID material (`FERRUM_GATEWAY_SVID_*`) and the slice trust bundles cover the peer's trust domain; for HBONE baggage rewrites, confirm the assertor is on `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS`. Remember PERMISSIVE-with-no-client-CA admits unauthenticated peers (see [Limitations](#limitations-and-not-supported)). |
| **Cert / CA health** | SVID rotation or CA backend problems. | `ferrum_mesh_cert_expiry_seconds`, `ferrum_mesh_cert_rotation_failures_total`, `ferrum_mesh_ca_health{ca_type}`, `ferrum_mesh_trust_bundle_version`. |

## Observability and Troubleshooting Quick Reference

### Admin introspection endpoints (all JWT-authenticated; 404 outside mesh mode / wrong topology)

| Endpoint | Purpose | Diagnose |
|---|---|---|
| `GET /mesh/config-drift` (`?include_overlay=false`) | Per-DP "where is this DP vs the CP's last push" — `slice.last_received_at`, `version`, per-kind `resources` counts, `fingerprint`, `source_protocol`/`source_cp_url`, RTDS `runtime_overlay`, and (xDS mode) the `convergence` block (per-type versions, missing required types). | Stuck DP (stale `last_received_at`), split-brain (fingerprint divergence), cross-cluster endpoint discovery (workload/service resource counts), RTDS drift, wedged xDS warming (non-empty `convergence.missing_required_types`). |
| `GET /mesh/slice-drift` (CP mode) | CP-side desired / sent / acknowledged / rejected slice versions per authenticated local MeshSubscribe identity (issue #3265). | Stuck/partitioned/rejecting DPs after a successful CP reconciliation; pair with each DP's `/mesh/config-drift`. |
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

The inbound listener terminates mTLS from peer sidecars and forwards plaintext to the co-located application: for the **local** workload (identified by its SPIFFE identity, `FERRUM_MESH_WORKLOAD_SPIFFE_ID`), Ferrum materializes an inbound route per HTTP-family service port of each Service that both names the workload's service and lists the workload's SPIFFE id in its `workloads[]`, targeting `127.0.0.1:<appPort>`, so an mTLS-terminated request reaches the app after `mesh_authz` admission. The backend (container) port is resolved from the signals the slice carries — a shared port **name**, else an equal port **number**, else the workload's sole container port; a workload that declares no ports defaults to the service port. When a Service uses a numeric `targetPort` that differs from `port` across multiple unnamed container ports the backend is genuinely ambiguous (the model does not yet carry `targetPort` end-to-end), so the route is **skipped with a warning** rather than misrouted — name the ports consistently or supply an explicit proxy. If an explicit proxy already routes the same host/path (overlap evaluated with the same wildcard/catch-all semantics as listen-path validation), the operator's proxy wins. **Multi-port local services materialize one loopback sibling per HTTP-family service port**, disambiguated post-match by, in priority order: the inbound connection's captured original destination (a sidecar-less client's direct dial of the app port that the injector's iptables REDIRECTed to `:15006` — its port is the **container** port), then the request's explicit `Host`/`:authority` port (the **service** port — peer-sidecar `:15006` dials are direct and never NATed, so the authority is the channel a multi-port-aware egress sidecar controls; see the egress bullet below). A multi-port request carrying neither signal — or a signal matching no materialized sibling — is rejected 502, never guessed onto one port's backend; single-port services accept bare-Host clients and older peers exactly as before. Stream-family local service ports (`tcp`, `tls`, and DB protocols) prepare a runtime-only raw-TCP inbound map keyed by the captured original-destination app port; when the effective PeerAuthentication mode admits plaintext and iptables REDIRECT preserves `SO_ORIGINAL_DST`, the accept loop recognizes the stream-family route before HTTP/TLS classification and relays its bytes unchanged, including an application-level TLS ClientHello beginning with `0x16`. It then runs the L4 stream plugin chain (`mesh_authz` and the other `on_stream_connect` hooks) **with the captured app port as the authorization destination** and, only if not rejected, relays those bytes to `127.0.0.1:<appPort>` before Hyper parses the connection — so a `destination.port`-scoped `AuthorizationPolicy` DENY on a Redis/MySQL/etc. port is enforced just as it is for the materialized HTTP routes. The dual-wire one-byte TLS discriminator is therefore confined to HTTP-family inbound traffic; its residual `0x16` ambiguity is harmless for valid plaintext HTTP because no valid HTTP request starts with that control byte, while STRICT is still enforced after routing. A stream-family port that resolves to the **same** container port as an HTTP-family service port installs **no** raw-TCP entry: the HTTP inbound route wins, so the request is parsed and authorized on the HTTP path rather than spliced to loopback as raw bytes. Peer-sidecar raw-TCP traffic still arrives as a mesh-mTLS CONNECT and uses the transparent inbound relay. The outbound listener intercepts application-originated traffic (redirected by iptables or eBPF) and, on Ambient and Sidecar topologies, routes it through per-service egress routes materialized from the slice (see "Implementation status" below for the per-topology transport); multi-port services are disambiguated by the captured connection's original destination (`SO_ORIGINAL_DST`) on those materialized topologies.

**Implementation status — transport vs. materialization, per topology.** Transport (how a peer is reached on the wire) and materialization (turning the slice into routable proxies) are separate layers, and **the transport differs by topology**: **Ambient / Waypoint** speak HBONE (HTTP/2 CONNECT over mTLS, `:15008`); **Sidecar** speaks plain SVID-mTLS HTTP (`:15006`, no `:15008` listener). HBONE is *not* Sidecar's transport.

- **Ingress is handled for both.** Sidecar inbound builds materialized HTTP-family loopback routes (`:15006` → `127.0.0.1:<appPort>`) and prepares raw-TCP local app-port relay entries for stream-family service ports. Ambient/Waypoint inbound is **transparent** — an authenticated HBONE CONNECT that matches no route is relayed directly to its `:authority` (the original destination), so no route materialization is needed. The relay is guarded: the destination must be a local target — a loopback address on an application port declared by the slice, or an in-mesh workload address+port the slice declares — so an authenticated peer can never use the terminator as an open proxy to arbitrary hosts or undeclared localhost listeners, and a peerless CONNECT is rejected (403) before any dial. This transparent-relay path is **transport-agnostic** — gated on inbound direction + the H2 CONNECT shape, not on topology — so the Sidecar `:15006` listener also relays a **bare** authenticated H2 CONNECT (the raw-TCP egress destination side) through the very same guard, alongside its materialized HTTP loopback routes.
- **Egress is materialized for Ambient, Sidecar, and NodeWaypoint captured Service HTTP**, per topology posture: **Ambient outbound** builds per-service HBONE routes (a host-routed `/` proxy per in-mesh Service → `mesh.hbone`-tagged upstreams dialing the destination's `:15008`); **Sidecar outbound** builds per-service SVID-mTLS routes (`mesh.mtls`-tagged upstreams dialing the destination sidecar's inbound `:15006` with plain HTTP/2 over mutual TLS — never HBONE). Those two secured-transport target types carry the destination workload's SPIFFE id (`mesh.spiffe_id`), which the outbound handshake **pins**: the peer must present exactly that SVID, not merely one from an allowed trust domain. **NodeWaypoint captured Service HTTP** materializes the same host-routed Service routes, selects the backing workload first, and, when that workload has `node_waypoint` metadata, emits a `mesh.hbone` target that dials the destination NodeWaypoint while preserving the selected workload app address as the inner CONNECT authority. If the NodeWaypoint runtime is identity-backed (file SVID material or mesh CA backend), a selected workload without `node_waypoint` metadata is skipped so the route fails closed rather than dispatching plaintext. Only explicit no-CA/no-identity development runs retain the temporary plaintext captured-Service fallback. NodeWaypoint still does not synthesize pod-IP HBONE upstreams to backing pod IPs on `:15008`, where no listener is reachable; the live harness therefore requires captured Service traffic to enforce `AuthorizationPolicy` and requires denied-source direct Pod-IP attempts to fail closed rather than bypass capture. Sidecar egress yields to the local workload's own inbound loopback route (the route table holds one proxy per host+path), so a service's own-sidecar traffic stays local. Non-convention transport ports are configured with `FERRUM_MESH_EGRESS_HBONE_PORT` / `FERRUM_MESH_EGRESS_MTLS_PORT`.
  - **Multi-port egress (original-destination routing, Ambient and Sidecar).** One route + one upstream is materialized **per HTTP-family service port** (per-port upstreams keep load-balancer counters, hash rings, passive health, and pool keys isolated per app port). The route table groups a service's per-port siblings under one lowest-port representative — host tiers are (host, path)-keyed and every sibling shares its service's hosts + `/` — and the request path swaps in the sibling whose service port matches the connection's captured pre-NAT original destination, read once per accepted connection on the outbound capture listener via `SO_ORIGINAL_DST` (Linux netfilter; covers the injector's iptables REDIRECT capture). Sibling groups are derived from the prepared config's `mesh` block (each service's expected per-port route ids and **declared** HTTP-port count), never by parsing route ids. **Fail-closed:** a service *declaring* multiple HTTP-family ports with no captured original destination (non-Linux, direct dial, eBPF-rewritten capture) — even when only some ports materialized siblings — and any captured dial to a port the slice does not route are rejected with 502; captured traffic is never forwarded to a port the client did not dial. Single-HTTP-port services keep their orig-dst-free behavior, so direct dials and dev setups are unaffected. **Ambient** multi-port is transparent end-to-end (its inbound is the HBONE relay that dials the CONNECT authority's app port). **Sidecar** multi-port egress additionally rewrites the request `:authority` to `<host>:<service port>` (the per-port target carries its owning service port; the original client Host still rides `x-forwarded-host`): the destination sidecar's `:15006` dials are direct — never NATed — so the authority port is the channel its per-port **inbound** siblings disambiguate by. Single-port destinations keep the client authority byte-for-byte. Interop is fail-closed in both skew directions: a pre-disambiguation destination materialized nothing for multi-port services (404, never misrouted), and a pre-disambiguation source materialized no multi-port egress routes. Apps behind a multi-port Sidecar service observe `Host: <fqdn>:<port>`, and destination-side VirtualService `authority` exact-matchers should account for the explicit port.
  - **Raw-TCP egress (original-destination routing, Ambient and Sidecar).** Stream-family service ports (`tcp`, `tls`, and the DB protocols — anything not HTTP-family) materialize **per-port upstreams only**, no route proxies: a raw stream has no Host header to route by. Instead the accept loop on the outbound capture listener matches the captured original destination **strictly against `(service VIP, service port)`** — `MeshService.cluster_ips`, populated from `Service.spec.clusterIPs` by the Kubernetes translator (file-source operators set `cluster_ips` directly) — and relays the raw byte stream through an HTTP/2 CONNECT tunnel to the LB-selected workload's app port. The tunnel transport follows the topology (the upstream target carries exactly one transport tag): **Ambient** relays over the shared HBONE pool (dial the peer's `:15008`, capability-probe-gated); **Sidecar** relays over a **fresh mesh-mTLS H2 CONNECT tunnel** (dial the peer's `:15006`, one connection per captured stream — no capability registry, because a slice-declared sidecar peer speaks mesh-mTLS by construction). Either way the dial is identity-pinned (`mesh.spiffe_id`), and the destination's inbound relay is **transport-agnostic**: its terminator recognizes an authenticated H2 CONNECT — HBONE-marked on `:15008` or bare on `:15006` — and relays it to the CONNECT `:authority` via the same machinery, so no destination-side changes are involved. Port-number-only matching is deliberately unsupported: two services may share a port number, and a captured dial to a non-mesh destination must never be tunnelled into the mesh on a coincidence. A captured destination matching a declared pair whose upstream did not materialize is **closed** (never guessed); anything else falls through to the HTTP path unchanged. **Direct pod-IP / headless dials are also routed on these materialized topologies:** a client that resolved a **headless** service itself (or otherwise dials a backing **pod IP** directly) bypasses the VIP table, so a second strict index — keyed by `(backing workload IP, resolved target port)` — routes that captured original destination to a **single-target upstream pinned to that exact workload's identity** over the topology transport. It is consulted only when the VIP lookup misses, uses the same exact-match / fail-closed rules (a declared-but-unroutable workload pair is closed, never guessed), and is built from the same forward-derived source as the per-workload upstreams (each stream-family service port × backing local-cluster workload × workload address that parses as an IP; DNS-name addresses are skipped, and the container/target port resolves with the same `targetPort` rule as the VIP path). HTTP-family headless services already route by Host, so this closes the **raw-TCP-only** headless gap; a VIP-less service with no backing workload addresses is still unroutable (warned at materialization). Per-port `DestinationRule` LB algorithm and `localityLbSetting` apply to the TCP upstreams (VIP and per-workload alike) at selection time when all targets share a single port (the same pre-selection semantics as the HTTP path). Per-port `outlierDetection` thresholds and `maxEjectionPercent` caps are honored by stream target selection, but the consulted state differs by source: upstream-scoped active health checks apply across the shared upstream, while passive ejections are proxy-id scoped and are only consulted when recorded under the same synthesized raw-relay proxy id. Passive ejections recorded by a separate HTTP-family proxy on the same upstream do not automatically protect these raw relays. Outlier thresholds are still not recorded for the raw relay itself, since raw relay sessions carry no response status — see the note in the "DestinationRule" section. **UDP is now modeled as a distinct L4 transport** (`AppProtocol::Udp`): a `protocol: UDP` port — on a Kubernetes Service **or** an Istio `ServiceEntry` — partitions out of both HTTP-family routing and the raw-TCP stream lane (previously it was silently mis-classified as HTTP). The L4 `protocol: UDP` field **wins over any L7 `appProtocol`/port-name hint** (e.g. `appProtocol: http` or a name like `http3` on a UDP port still classifies as UDP — the hint describes what rides over the transport, not the transport itself). UDP egress does **not** ride this raw-TCP datapath (`SO_ORIGINAL_DST` REDIRECT does not apply to UDP); UDP uses a separate **TPROXY** capture model (see "UDP TPROXY capture" under Capture Modes) — capture-rule emission landed in F3 §3.3 **Stage 2**, the consuming listener in **Stage 3**, and **datagram-over-mesh egress in Stage 4** (dual-transport, mirroring raw-TCP egress). UDP egress materializes **per-port upstreams** (distinct `__mesh-out-upstream-*` id space → `__mesh-out-udp-upstream-*`) consulted via the route table's `mesh_udp_egress` `(VIP, UDP port)` index; a captured datagram is tunnelled over a `udp`-marked mesh CONNECT — **Ambient over HBONE (`:15008`), Sidecar over mesh-mTLS (`:15006`)** — and the destination unframes it into a local `UdpSocket` (see "UDP TPROXY capture"). Still **no route proxy** (datagrams carry no Host). Both topologies have a UDP source-capture producer: **Sidecar** via the injector's pod-netns TPROXY init rules feeding the current-netns listener, and **Ambient** via the per-pod-netns producer (`NetnsUdpCaptureManager`, #2013) that installs the UDP TPROXY rules + binds the transparent sockets INSIDE each enrolled pod's netns (the Ambient proxy runs outside the pod netns and the host-netns fallback emits no UDP rules). Ambient UDP capture stamps node-agent-attested pod UID + SPIFFE evidence inside the authenticated HBONE CONNECT; destination `mesh_authz` applies per-pod **source** scope only after the shared trusted-assertor/trust-domain gate and an exact live UID-to-SPIFFE match, otherwise it falls back to mesh-wide source scoping. Either way the `udp` CONNECT is evaluated against the **union** of the destination-scoped `AuthorizationPolicy` set that normal (non-UDP) inbound HBONE uses — the same namespace/selector policies protecting the destination workload, e.g. a DENY-all in the service namespace — **and** the source-scoped (or mesh-wide) policies, in a single deny-first evaluation, so a destination DENY/ALLOW still runs for UDP CONNECTs and cannot fall through to default-allow. **External UDP egress (EgressGateway).** A `protocol: UDP` port on a `MESH_EXTERNAL` `ServiceEntry` now materializes bounded datagram-over-mesh egress on the EgressGateway (issue #3263) — and still emits **no UDP listener**: binding one on the ServiceEntry port would collide with a sibling TCP port on the same number under the port-only stream dedup (DNS `53/TCP` + `53/UDP`) and would need DTLS material mesh never seeds. Instead the materializer publishes a runtime-only **destination allowlist** (`MeshConfig.egress_udp_destinations`), and the gateway's existing authenticated mesh CONNECT terminator (the `:15090` SVID-mTLS egress listener) relays a `udp`-marked CONNECT whose `:authority` names an admitted external destination into a local `UdpSocket`, unframing with the same `mesh_udp_frame` codec the in-mesh UDP datapath uses. Admission is **exact**: the authority host must equal a declared `hosts[]` entry or a `STATIC` `endpoints[].address` IP literal (ASCII case-insensitive) and the port must equal the declared service port. **The admitted authority is not the dial destination.** Each admission carries a precomputed, bounded set of dial endpoints: under `resolution: STATIC` a host authority dials the operator-declared `endpoints[]` (so the gateway **never DNS-resolves a STATIC host**), and an endpoint-IP authority dials **only the endpoint it names**; under `DNS`/`NONE` the entry declares no dialable endpoint set, so the host's single dial endpoint is the host itself (resolved at dial time, which is what those modes mean). A numeric `targetPort` — or, for a named service port, the endpoint's own `ports` entry — moves only the port the gateway's socket dials. Selection across multiple endpoints is a lock-free modulo cursor over the precomputed set, so it costs one relaxed atomic per CONNECT and follows the live config snapshot across reloads. The allowlist itself is bounded by a closed total destination cap (`MAX_EGRESS_UDP_DESTINATIONS`, alongside the per-destination `MAX_EGRESS_UDP_DIAL_ENDPOINTS` cap); entries beyond either cap are refused fail-closed with a field-specific warning so CONNECT-time walks stay bounded. The materializer refuses — fail closed, with field-specific warnings — `port: 0`, wildcard hosts (`*.example.com`), empty hosts, non-IP-literal `STATIC` endpoint addresses, a `STATIC` port that resolved **no** usable endpoint (the host is refused outright rather than falling back to resolving it), and a `(host, port)` pair a previous ServiceEntry already claimed; the allowlist is **rebuilt and reassigned unconditionally on every apply**, so an update or delete that withdraws a ServiceEntry immediately withdraws the admission and a topology flip away from `EgressGateway` clears it entirely. The relay requires the same authenticated, trust-domain-verified mesh peer the byte-stream relay does, re-checks the **effective** (post-route-override) destination against **precomputed dial endpoints only** before opening any socket (a STATIC hostname is a valid CONNECT authority but must never become an effective socket target — that would DNS-bypass `endpoints[]`; DNS/NONE and STATIC endpoint-IP dial targets remain usable because they are themselves dial endpoints), `connect()`s the socket so the kernel pins the reply peer to the admitted destination, honors `udp_idle_timeout_seconds`, and bounds concurrent egress relay sessions process-wide by `FERRUM_UDP_MAX_SESSIONS` (over-cap CONNECTs get `503`). It is gated by `FERRUM_MESH_EGRESS_STREAM_ENABLED`; with the flag off, nothing is admitted and there is **never** a fallback to direct unauthenticated UDP. The byte-stream relay's open-relay guard is untouched — the external allowlist is consulted only for `udp`-marked CONNECTs.

  **Source-side producer for external UDP.** The gateway half above is a terminator; the originator is the `Sidecar`/`Ambient` data plane, the two topologies that have a UDP source-capture producer. Source-side route materialization shares the **same** `FERRUM_MESH_EGRESS_STREAM_ENABLED` all-or-nothing opt-in as the gateway allowlist: with the flag off the source clears any prior routes and publishes nothing, so a flag-off gateway cannot be paired with still-materialized source routes that would black-hole captured datagrams. When that flag is on and `FERRUM_MESH_EGRESS_GATEWAY_ADDR` + `FERRUM_MESH_EGRESS_GATEWAY_SPIFFE_ID` are set, those sources materialize a captured-datagram route per `MESH_EXTERNAL` `ServiceEntry` UDP endpoint (`MeshConfig.external_udp_egress_routes`, upstream id space `__mesh-out-udp-ext-upstream-*`) whose single upstream target dials **that configured gateway** over SVID-mTLS, pinned to the declared gateway SPIFFE id, with the external endpoint as the CONNECT `:authority`. The route/upstream set shares `MAX_EGRESS_UDP_DESTINATIONS` with the gateway allowlist as a hard total cap, so an accepted slice cannot grow either side without bound; excess endpoint routes remain unroutable. The route folds into the SAME `mesh_udp_egress` `(destination IP, port)` index the in-mesh datapath uses, so the existing `mesh_udp_capture` session task relays it with no external special case (in-mesh service VIPs are inserted first and always win). The EgressGateway exposes only its `:15090` SVID-mTLS listener — there is no `:15008` HBONE listener on it — so both source topologies use the mesh-mTLS datagram tunnel (`MeshMtlsConnectionPool::open_datagram_tunnel`), which requires the pinned peer and runs no capability probe. Fail closed at every step, with field-specific diagnostics and never a direct unauthenticated dial of the external destination: stream-egress opt-in off ⇒ no route; no configured gateway address/identity ⇒ no route; a gateway whose SVID does not match the pinned id ⇒ refused dial; `resolution` other than `STATIC` ⇒ refused (a UDP datagram carries no Host, so only a declared endpoint address can attribute a captured datagram — the mesh DNS proxy answers external hosts with exactly those endpoint IPs); no usable IP-literal endpoint ⇒ refused; a topology with no UDP source-capture producer ⇒ nothing materialized. The producer applies the SAME per-entry admission tests the gateway half does — `location: MESH_EXTERNAL`, `exportTo` visibility for this workload's namespace, and a non-empty `hosts[]` — because an entry the gateway refuses outright can never admit the source's CONNECT, so a route for it would only ever black-hole. The route set is rebuilt and reassigned on every apply, so update/delete/flag-off withdraws steering immediately. Setting only one of the two gateway variables is a startup error rather than a silent half-configuration. `FERRUM_MESH_EGRESS_GATEWAY_ADDR` must be a bounded DNS hostname, IPv4 literal, or bracketed IPv6 literal plus a nonzero port — surrounding whitespace/control characters, wildcards, and URL/userinfo/path/query/fragment material are refused at startup without echoing the raw value; SPIFFE parse failures name the variable only and never echo the configured identity.
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

The `__mesh_bpf_metrics` plugin is auto-injected on `NodeWaypoint` topology only and surfaces TCP-layer counters from `BPF_PROG_TYPE_SOCK_OPS` plus first-data evidence from `BPF_PROG_TYPE_SK_SKB`. The userspace consumer (`src/ebpf/event_consumer.rs::SockOpsConsumer`) drains the per-CPU ringbuf and increments a shared `BpfMetricsState`. Authenticated production `GET /metrics` appends that surface exactly once from the current plugin-cache generation's precomputed exporter (configured `prefix` preserved; absent from the scrape when the plugin is not in the published configuration). Metrics emitted (Prometheus text format):

- `ferrum_mesh_bpf_tcp_events_total{event="connect"|"accept_established"|"rst"|"fin_sent"|"fin_received"}` — per-TCP-event counts. Operators correlate `accept` vs `connect` rates to spot stuck pods or pre-handshake drops. `event="rst"` counts abnormal `ESTABLISHED→CLOSE` transitions; SOCK_OPS state callbacks cannot distinguish RST-sent from RST-received, so there is no directional `rst_sent` / `rst_received` pair.
- `ferrum_mesh_bpf_drops_total{reason="bypass_uid_hit"|"exclude_cidr_hit"|"not_in_include_cidr"|"exclude_port_hit"}` — how often each BPF capture-bypass decision fired. Produced by the `connect4`/`connect6` hooks (same ringbuf + dropped-counter contract as SOCK_OPS lifecycle events). Include-CIDR misses and `includeOutboundPorts` misses share `not_in_include_cidr`.
- `ferrum_mesh_bpf_srtt_microseconds`, `ferrum_mesh_bpf_syn_to_ack_microseconds`, `ferrum_mesh_bpf_accept_to_first_byte_microseconds` — TCP-layer latency **histograms** (Prometheus type `histogram`). Fixed inclusive `le` bucket upper bounds in microseconds: `100`, `250`, `500`, `1000`, `2500`, `5000`, `10000`, `25000`, `50000`, `100000`, `250000`, `500000`, `1000000`, `2500000`, `5000000`, plus `+Inf`. The `_sum` / `_count` series permit mean derivation (`sum / count`) and `histogram_quantile` percentiles. The accept-to-first-byte interval starts at the accepted socket's `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB` timestamp and ends at the first non-empty inbound SK_SKB stream-parser callback on that exact socket. It is not a handshake rename: the SOCKHASH carries the accepted socket itself, and correlation state is keyed by its socket cookie rather than the reusable network tuple. The existing IPv4/IPv6 orig-dst bridge must confirm capture before emission. Pending data, pre-enrollment data, close-before-data, failed handoff, LRU eviction, reload, reversed/wrapped `ktime`, and evidence older than one hour emit no sample. Both maps and the userspace deferred-removal queue are bounded at 65,536 entries; state is deleted on first data and terminal close, with kernel sockhash close cleanup as a backstop. A sum overflow or saturated count/bucket drops the whole sample rather than wrapping a component. Cardinality is process-global: only fixed `le` labels are emitted; peer addresses/ports, namespaces, identities, and raw cookies are never labels or logs. App-layer latency stays in `workload_metrics`.
- `ferrum_mesh_bpf_ringbuf_overruns_total` + companion `ferrum_mesh_bpf_ringbuf_in_overrun_regime` gauge — ringbuf health. Non-zero overrun count means userspace fell behind and the kernel dropped events; raise `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES` or reduce event rate. Attaching (or re-attaching after node-agent pin rotation) to a stats map that already reports a nonzero dropped total seeds **one** overrun episode so pre-reattach loss is visible; cumulative userspace counters are preserved across pin generations. The consumer also logs one `warn!` per regime entry and one `info!` on recovery — no per-event spam.

**Process split**: the node-agent owns the BPF program lifecycle — it loads `ferrum_sock_ops` from the ELF, attaches it to the cgroup root, and pins the event ringbuf, per-CPU drop counter, and accepted-socket SOCKHASH at `/sys/fs/bpf/ferrum/sock_ops_events`, `/sys/fs/bpf/ferrum/sock_ops_stats`, and `/sys/fs/bpf/ferrum/accept_first_byte_sockets`. The mesh-proxy in `NodeWaypoint` topology opens those pinned maps by path, drives a `tokio::io::unix::AsyncFd` poll loop, queues first-data SOCKHASH removal behind a bounded 250 ms grace period, and feeds decoded records through `SockOpsConsumer::handle_event` into the shared `Arc<BpfMetricsState>` that `__mesh_bpf_metrics` reads. The node-agent publishes the ringbuf pin last as the complete-generation marker, so a consumer never adopts it before the matching stats and SOCKHASH pins. There is no cross-process pointer sharing — the pinned-path contract is the entire IPC surface.

When the kernel-side program is not pinned (no node-agent on the host, kernel < 5.7, or a build without the `ebpf` feature), the consumer logs one info line at startup and exits; the plugin keeps emitting a stable Prometheus surface populated by zeros so dashboards do not break. An SK_SKB load/attach failure disables only accept-to-first-byte samples and never changes capture or traffic verdicts. Node-agent reload creates a fresh unpinned correlation-map generation: in-flight evidence is deliberately discarded, while userspace aggregate counters remain attached to the current process state. The ringbuf size is sized at BPF load time by the node-agent from `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES` (default 4 MiB) — see [docs/configuration.md](configuration.md).

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

#### Stock Envoy / third-party Istio xDS interoperability

`FERRUM_MESH_CONFIG_PROTOCOL=stock_xds` (issue #3317) is a **separate protocol
name** from `xds`, not a mode of it. Everything described above about the
Ferrum-private profile — name-only resources, `ferrum.config.extension.v3.*`
ECDS carriers, the required-type version-coherence gate — is unchanged and is
never reached by this path.

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
reachable" ambiguous. The document is re-read on SIGHUP (Unix); a failed reload
keeps the last good policy baseline, and a successful one rebuilds the slice
from the current discovery view.

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
JWT-gated `GET /mesh/config-drift`.

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
duplicated name, or a declared bound exceeded — NACKs the whole response and
rolls the accumulator back, so the last good slice keeps serving. A *capability
refusal* — a well-formed resource using something Ferrum does not model — drops
that resource with a field-specific diagnostic and ACKs, because a stock CP
legitimately programs Envoy features Ferrum has no counterpart for and NACKing
would leave the data plane permanently unconverged. A refusal always narrows:
it contributes no route, no endpoint, and no identity, so the worst case is
traffic that is not routed. Refusals are logged (bounded, and only when the set
changes) with a stable reason code and the offending field path — never a
resource payload.

**The extension-escape closure.** Every field through which an Envoy extension,
a filesystem path, credential material, an enforcement filter, or a second
delivery channel could enter is refused:

- Cluster `cluster_type`, `filters`, `load_balancing_policy`,
  `lb_subset_config`, and any `typed_extension_protocol_options` key other than
  `envoy.extensions.upstreams.http.v3.HttpProtocolOptions`.
- Any transport socket that is not `UpstreamTlsContext` or `RawBuffer`; inline
  `tls_certificates`; a `trusted_ca` `DataSource` naming a `filename` or
  `environment_variable`; `custom_validator_config`; `custom_handshaker`; a
  non-`exact` (regex/prefix/suffix) peer-identity matcher.
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
builds its own from the policy document), SDS, ECDS/RTDS, and delta xDS. The
decode surface is a field-exact **projection** of the upstream Envoy v3 messages
(`proto/envoy/stock/v3/stock_xds.proto`), not the vendored upstream proto tree;
every field number is taken from Envoy `v1.31.0` and a field that can change
routing, trust, or identity is either consumed or refused.

**Where the code lives.** `src/xds/stock.rs` (decode, capability classification,
projection onto the typed mesh model) and
`src/modes/mesh/config_consumer/stock_xds_client.rs` (the ADS stream machine and
the policy/discovery merge). Tests:
`tests/unit/gateway_core/stock_xds_tests.rs`,
`tests/integration/mesh_stock_xds_tests.rs`, and
`tests/conformance/stock_xds_interop.rs`.

#### Ferrum mesh-slice ECDS carriers (full parity over xDS)

The name-only CDS/EDS/LDS/RDS resources Ferrum exchanges round-trip service-port discovery only. Every security- and policy-bearing slice field plus the effective workload labels used for selector matching — authorization policies, PeerAuthentication mTLS posture, RequestAuthentication/JWT rules, full ServiceEntry shape, SPIFFE trust bundles, ProxyConfig, VirtualService L4 proxies, per-pod workloads, MeshService protocol/workload-ref shape, telemetry resources, multi-cluster config, sidecar egress-scope metadata, and mesh-wide outbound traffic policy — rides the ECDS stream as a **Ferrum mesh-slice carrier**. Without these, `FERRUM_MESH_CONFIG_PROTOCOL=xds` produced an **unprotected or incomplete mesh**: the DP rebuilt the slice with those fields emptied or contextless (no authz → implicit allow-all; no PeerAuthentication → Permissive on every port; no trust bundles → no inbound mTLS authority material; no effective labels → selector-scoped policy stops matching; no L4 proxies → translated VirtualService TCP/TLS routes disappear).

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

`waypoint_gateway_class` is emitted only for ServiceWaypoint slices with a known `Gateway.spec.gatewayClassName`. The DP reconstructs it before `mesh_authz` cold-path retain so GatewayClass `targetRefs` exact-match fail closed over xDS: malformed, oversized, or duplicate carriers reject the ECDS response, and a missing or removed carrier never reuses a stale class. A missing carrier is not merely "no class": if the slice also carries an **enforcing** (`ALLOW`/`DENY`) GatewayClass-targeted policy, that combination is incoherent and `reverse_translate` rejects the response so the DP keeps its last-good slice — silently dropping the policy would turn a DENY (or an ALLOW policy's implicit deny) into allow-by-default. `MeshAuthz::new` repeats the same refusal for the native/file/embedded sources. `AUDIT`-only policies are non-enforcing and stay exempt.

**Behavior and fail-closed.** The CP always emits these alongside CDS/EDS (no env var gate), and the DP waits for the initial ECDS response before building a slice so startup cannot briefly apply the name-only, unprotected view. On the DP, a mesh-slice carrier must have both the reserved ECDS resource name and the matching inner `type_url`: a recognized pair overwrites the corresponding slice field; an unrecognized inner type (the DR carrier, or an operator's own extension config) is skipped; a reserved inner type under any other resource name is `warn!`-logged and skipped so operator-defined ECDS configs cannot impersonate security/policy carriers. A recognized carrier whose JSON fails to parse is FAIL-CLOSED: `MeshSliceCarrier::decode` returns `Err`, `recover_slice_carriers` propagates it, and the DP NACKs the entire ECDS response and retains the previous accepted slice — it does NOT skip the malformed carrier and continue with a partially populated slice. CDS/EDS service-port discovery still runs; the DP **prefers** the full `services`/`service_entries` recovered from carriers and falls back to the name-only CDS/EDS reconstruction only when no slice carrier is present at all (e.g. an internal Ferrum-shaped test CP with no carrier support). Empty `Vec`/`None` field groups emit no carrier, so "absent" and "empty" are indistinguishable on the DP — matching native, where an empty list and an absent list are equivalent. Effective workload labels are the exception: the CP emits `WorkloadLabelsCarrier` even when the label map is empty, because empty labels are meaningful selector context and must override any local DP labels during xDS recovery. **Ambiguous shared-SPIFFE labels are a counter-exception:** when several workloads share one SPIFFE id with **divergent** label sets and the slice request carried no explicit labels, the CP can only compute the label **intersection** (which loses information), while selector-scoped policies (authz / PeerAuthentication / RequestAuthentication / Telemetry) ride in as a **candidate-any superset** (kept if they match *any* candidate). The CP flags this by emitting `WorkloadLabelsAmbiguousCarrier`. (The common replica/endpoints case — many records for one SPIFFE with **identical** labels — is *not* flagged: the intersection equals each set and is authoritative, so the DP keeps trusting the carrier instead of preferring possibly-stale local labels.) On recovery the DP treats a flagged intersection as **non-authoritative** and prefers its own `FERRUM_MESH_WORKLOAD_LABELS` so it re-filters the superset against its real identity. Without this, a non-empty intersection (e.g. two pods sharing `app=shared` where only one has `role=api`) would replace the DP's real labels and silently drop every candidate-only selector policy — a fail-open for selector mTLS/JWT/authz whenever the intersection is non-empty. If the DP has no local labels either, it keeps the (informational) intersection. The marker is cleared on the recovered slice once the DP has resolved its authoritative labels. Operator-defined `MeshExtensionConfig` entries whose names start with `ferrum-mesh-carrier/` or whose inner `type_url` is one of the mesh-slice carrier markers are skipped by the Ferrum CP for the same reason.

**Visibility is re-enforced at the fold, not assumed.** A carrier is raw producer input that never passed this DP's slice admission, so the two `exportTo`-bearing client-side policy carriers are gated on recovery: a `VirtualServiceCorsPoliciesCarrier` entry not exported to the DP's workload namespace is dropped (bounded `warn!` with a count only — never the carrier-supplied host, name, or `exportTo` value), exactly as the legacy `DestinationRule` carrier is gated to the workload namespace. Visibility LISTS themselves are validated at the ACK boundary on both carrier families — every recognized DestinationRule carrier (reserved AND legacy) and every `VirtualServiceCorsPoliciesCarrier` entry runs the shared `validate_mesh_export_to` before the response is ACKed, so an unsupported or self-conflicting list NACKs and the accumulator rolls back to the last accepted state instead of being ACKed and discovered inert later. Those rejection diagnostics name the carrier field and the offending INDEX, are capped at eight per rejected carrier, and never echo the carrier-supplied value. Both are then re-checked once more at materialization. `exportTo` entries on the DR, ServiceEntry, and VirtualService-CORS carriers are also canonicalized (trimmed) at decode: the shared visibility evaluator deliberately never reinterprets padded input, and ACK-time validation checks a trimmed copy, so an un-normalized `[" beta "]` would otherwise be accepted and then match nothing.

**Interop boundary.** A stock Envoy or third-party Istio control plane does not emit these inner type URLs or Ferrum-shaped resource names, so it cannot drive a protected Ferrum mesh over xDS. The carrier format is a Ferrum-to-Ferrum wire convention layered on the standard ECDS transport; it is **not** an interoperable third-party xDS extension. For full DR/policy parity, run a Ferrum CP (either protocol works) or use `FERRUM_MESH_CONFIG_PROTOCOL=native`.

**Test pin.** `xds_round_trip_preserves_protected_slice_fields()` in `src/modes/mesh/config_consumer/xds_client.rs` drives the real CP-encode → ECDS-on-the-wire → DP-decode path for a representative protected slice (authz + PeerAuthentication + ServiceEntry + trust bundle + JWT + ProxyConfig + VirtualService L4 proxy + workloads) and asserts the recovered slice equals the native one field-for-field, including resolved mTLS posture. `tests/conformance/xds_type_urls.rs` pins the carrier type-URL set.

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

The inner `value` is the normalized DR model as UTF-8 JSON bytes — there is no protobuf wire encoding of the DR itself, just `serde_json` over the `MeshDestinationRule` shape consumed by the DP at `src/modes/mesh/config_consumer/xds_client.rs` (see `dr_carrier_resource()` and the recovery loop). Normalization includes host canonicalization and trimming accepted `export_to` entries before slice comparison and carrier serialization. The DP iterates ECDS resources, decodes each `TypedExtensionConfig`, and applies one of three behaviors per inner payload:

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
- A legacy, non-reserved operator extension using the DR inner type keeps its
  historic ROUTING compatibility — the resource name is not constrained, and a
  carrier declaring another namespace is skipped rather than rejected — but it
  is **not** best-effort on CONTENT. Recognition is by inner `type_url` alone,
  and anything that declares Ferrum's DestinationRule type is a DestinationRule
  by its producer's own declaration, so malformed JSON and an unsupported
  `export_to` NACK the ECDS response exactly as they do for the reserved shape.
  Accepting them would ACK a response whose policy then silently vanishes at
  materialization — traffic served with the operator's DestinationRule missing.
  Ferrum CP never emits the legacy shape.

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
is no feature flag. The DP always subscribes to ECDS. A legacy or third-party
Ferrum-shaped CP that emits only CDS/EDS remains routable in the documented
degraded mode, but full DestinationRule semantics are unavailable. When the DP
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

Visibility is evaluated during slice construction, BEFORE lookup selection and before a per-node slice is serialized, so a namespace-local rule never reaches — let alone affects — a subscriber outside its declared visibility. The DP defensively runs the same evaluator again before materialization lookup, so a cross-wired or independently implemented native/xDS producer cannot bypass the boundary by sending an already-built slice.

**VirtualService-derived CORS policy is gated identically.** `virtual_service_cors_policies[].export_to` is host-targeting client-side traffic policy with the same blast radius as a DestinationRule, so it runs through the SAME shared evaluator at the same three points: slice narrowing on the CP, the xDS carrier fold on the DP (see [mesh-slice carriers](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds)), and outbound `cors` plugin synthesis on the DP. A namespace that cannot override a workload's DestinationRules therefore cannot inject CORS behavior onto its outbound routes either — including over a carrier that bypassed slice admission.

#### DestinationRule lookup hierarchy

For each destination host Ferrum resolves the winning rule by Istio's lookup path, most specific first (issue #2469):

1. the **client** workload's own namespace,
2. the **target service's** namespace,
3. the configured **`istio_root_namespace`** (`FERRUM_K8S_ISTIO_ROOT_NAMESPACE`, default `istio-system`).

The first tier that has a visible rule wins outright; lower tiers are discarded for that destination. A rule declared in any OTHER namespace is not part of the lookup path and is refused, even if it exports itself publicly. Because the tier comes from ownership, renaming a namespace can never change which policy wins.

**Arbitration is per destination host, at both layers.** Slice admission groups by the resolved destination (owning namespace + canonical host), and the data-plane materializer resolves the winning tier per destination host of each upstream rather than once per upstream. An upstream whose targets span two services therefore carries two independent lookups: a client-namespace rule for `a.alpha` no longer suppresses the only rule `b.beta` has (when those lookups disagree the upstream is refused rather than merged — see [below](#an-upstream-that-spans-two-destinations)). When the matched destination host has a resolved owner, that owner is authoritative for the service tier — an upstream container namespace cannot widen it. Upstream namespace is retained only as a narrow fallback when host ownership cannot be resolved (so a ServiceEntry-derived EgressGateway upstream stamped with the gateway's namespace still admits the owner-authored service-tier rule the control plane admitted).

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

**Multiple DRs in the winning tier**: they are same-namespace by construction (one owner — Istio's merge case), so they apply in deterministic `(namespace, name, normalized host spelling)` order, last-writer-wins per field, and the slice builder logs a bounded warning naming only the count of ambiguous destinations. That warning fires on CHANGE, not on every slice build: splitting one host's policy across two DestinationRules in a single namespace is an ordinary Istio pattern, and the builder runs once per subscriber per config generation, so an unconditional warning would be per-reload × per-DP log spam. That order is an **intra-tier tiebreak only** and is never cross-tier precedence. Including host spelling covers native input that repeats one name for distinct hosts; Kubernetes still has unique `(namespace, name)` resource identity. Operators also see `debug!` log lines when subsets or proxy `backend_connect_timeout_ms` get overwritten.

Visibility and the lookup hierarchy compose in that order: `exportTo` is absolute, so root-namespace fallback can never resurrect a rule the subscriber was never allowed to see.

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
| `subsets[].trafficPolicy.tls` | Supported | → `SubsetTrafficPolicy.tls` (nests `MeshTrafficPolicyTls`). Cold-path `resolve_subset_traffic_policy` layers the subset's TLS overlay (mode / SNI / CA / mTLS material / SAN allow-list / `insecureSkipVerify`) onto the upstream-level TLS and stores the result on `Upstream.resolved_subset_tls[subset_name]`. `GatewayConfig::resolve_upstream_tls` then projects that overlay onto `Proxy.resolved_tls` for proxies whose `upstream_subset` selects this subset — so v1 and v2 subsets with different CAs land on different `Proxy.resolved_tls` values and partition the backend pool. `upstream_subset` also enters HTTP / H2 / gRPC / H3 pool keys as a defense-in-depth backstop on top of TLS partitioning. Subsets without `trafficPolicy.tls` fall back to upstream-level TLS, identical to today's behavior. |
| `subsets[].trafficPolicy.connectionPool.tcp.connectTimeout` | Supported | Overrides `backend_connect_timeout_ms` for proxies bound to the subset (precedence over the DR top-level connectTimeout). |
| `subsets[].trafficPolicy.connectionPool.http.{h2UpgradePolicy,maxRetries,http1MaxPendingRequests,idleTimeout,http2MaxRequests}` | Supported | Preserved in `SubsetTrafficPolicy`, resolved into `ResolvedSubsetTrafficPolicy`, and overlaid onto the selected proxy's immutable inherited-policy snapshot (`dispatch_port_override_fallback`) for each selected target. Precedence is field-level `portLevelSettings` > selected subset > top-level; sibling subsets and unmatched destinations never inherit the selected subset. **Semantics differ from Istio on purpose:** Istio applies subset > DR `portLevelSettings` and replaces the whole `connectionPool` wholesale when a subset sets any connection-pool field; Ferrum keeps the inverted tier order and field-level merge (same convention as port-level overrides). Example: top-level/port `UPGRADE` plus subset `DO_NOT_UPGRADE` → Istio forces H1 on that port for the subset; Ferrum still negotiates h2. A subset that sets only `maxRetries` also inherits top-level `DO_NOT_UPGRADE` / `idleTimeout` / `http2MaxRequests` here, where Istio's wholesale replacement would clear them. Transport, retry-cap, H1-admission, idle-timeout, and H2-stream-cap semantics match the corresponding top-level rows below (including the reqwest-H2 residual for `http2MaxRequests`). Every HTTP-family shared-client/pool key already carries `upstream_subset`, so same-endpoint sibling subsets cannot first-materialize each other. Invalid values reject the DestinationRule without echoing the value. |
| `subsets[].trafficPolicy.portLevelSettings` | Deferred | Detected at translate time with a value-redacted warning and listed in `status.ferrum.translation.deferred_fields`. Not parsed or applied — Istio's highest-precedence tier. Express per-port policy at top-level `trafficPolicy.portLevelSettings` or use subset `connectionPool` fields. |
| `subsets[].trafficPolicy.outlierDetection` | Supported | Ejection thresholds (consecutive errors / interval / base-ejection / min-health) AND the `maxEjectionPercent` cap applied per-subset, overriding upstream-level passive health for subset-bound proxies (`passive_health_for_target` for thresholds, `LoadBalancerCache::max_ejection_percent_resolved_from` for the cap, sharing one per-port > per-subset > upstream tier precedence). The cap is sized against the subset candidate pool (denominator = subset target count). The per-port cap tier applies only when a single dispatch port is resolvable pre-selection; for subset dispatch on a multi-port upstream the subset cap governs (the cap is resolved before a target's port is known). |
| `trafficPolicy.connectionPool.http.maxRequestsPerConnection` | Deferred | Parsed and validated, but not projected onto `Upstream.port_overrides` or `Proxy.pool_max_requests_per_connection` because Ferrum does not enforce backend close-after-N-requests behavior. K8s translation emits a warning and status lists `connectionPool.http.maxRequestsPerConnection` in `status.ferrum.translation.deferred_fields` at top-level, per-port, and subset scope. Negative and `> u32::MAX` values are rejected at translate time; `0` is accepted as Istio's explicit "unlimited" sentinel but still produces no effective policy. Use `http2MaxRequests` for HTTP/2-family concurrency. |
| `trafficPolicy.connectionPool.http.idleTimeout` | Supported (HTTP-family) | Lands on the inherited dispatch fallback / explicit per-port override as `http_idle_timeout_ms` and projects onto `Proxy.pool_idle_timeout_seconds` for the per-target effective proxy, which threads into the reqwest/H2 client pool idle timeout. Sub-second durations are rejected at translate time because `pool_idle_timeout_seconds` is whole-second granular; values above `MAX_POOL_IDLE_TIMEOUT` (1 hour) are also rejected so the K8s surface stays consistent with the admin admit-path validator. Top-level and selected-subset values ride `dispatch_port_override_fallback`; explicit `portLevelSettings` entries win per-port. Precedence is field-level per-port > selected subset > top-level. The reqwest pool key includes idle timeout in its `rcfg` client-behavior segment (and every HTTP-family key already carries `upstream_subset`), so divergent idle timeouts / subsets isolate distinct shared clients (no first-creator-wins leak). Direct-H2 / gRPC key the effective H2 stream cap (and `upstream_subset`); remaining builder-only knobs such as keepalive may still document first-materializer tradeoffs. Request-only `backend_connect_timeout_ms` remains per-request and does not fragment. |
| `trafficPolicy.connectionPool.http.http2MaxRequests` | Supported (HTTP-family) | Lands on the inherited dispatch fallback / explicit per-port override as `h2_max_concurrent_streams` and projects onto `Proxy.pool_http2_max_concurrent_streams` via the per-target effective proxy. Threads into the direct H2 (`src/proxy/http2_pool.rs`) and gRPC (`src/proxy/grpc_proxy.rs`) builders as both `http2::Builder::max_concurrent_streams` (peer SETTINGS) and `initial_max_send_streams` (local outbound-stream initial cap). Reqwest's H2 path does not expose the same builder knobs today. Top-level and selected-subset values ride `dispatch_port_override_fallback`; explicit `portLevelSettings` entries win per-port. Precedence is field-level per-port > selected subset > top-level. Zero/negative values rejected at translate time. Direct-H2 / gRPC pool keys include the effective `pool_http2_max_concurrent_streams` (`none` when unset) after `upstream_subset`, so same-subset divergent caps and configured-versus-removed values isolate distinct connections on update/delete. Sibling subsets stay isolated because every HTTP-family pool key already carries `upstream_subset`. Reqwest does not consume this knob in `create_client` and therefore does not key on it. |
| `trafficPolicy.connectionPool.http.h2UpgradePolicy` | Supported (plain-HTTPS only) | Lands on the inherited/per-port dispatch policy and projects onto `Proxy.h2_upgrade_policy` via the per-target effective proxy. `DO_NOT_UPGRADE` forces reqwest/H1, restricts advertised ALPN to `http/1.1`, and adds an H1 discriminator; `UPGRADE` prefers direct-H2 while remaining fail-safe against a proven-unsupported target; `DEFAULT`/absent is probe-driven. Every HTTP-family shared-client/pool key already carries the selected `upstream_subset`, and the reqwest key additionally carries the force-H1 client behavior, so incompatible subset transports cannot share connections. Scope is plain HTTP only, not gRPC or mesh tunnels. Precedence is field-level per-port > selected subset > top-level (**Semantics differ from Istio on purpose** — Istio applies subset > port-level and wholesale `connectionPool` replacement; see the subset HTTP row above). Unknown enum values reject translation. |
| `trafficPolicy.connectionPool.http.maxRetries` | Supported (per-request CAP — honest reinterpretation) | **Semantics differ from Envoy on purpose.** Ferrum treats the field as an upper bound on an existing per-request `Proxy.retry.max_retries`: `min(existing, effective_dr_cap)`. It never increases retries and never synthesizes retry behavior when no retry policy exists. A cap of zero explicitly disables an existing retry policy for the selected destination. The cap is resolved after target selection and before retry/deadline decisions; retry target rotation remains in an explicit port-policy lane when one exists, while subset/top-level fallback remains stable for the route's selected subset. Precedence is per-port > selected subset > top-level. Negative values reject translation. See [DestinationRule `maxRetries` semantics](#destinationrule-maxretries-semantics). |
| `trafficPolicy.connectionPool.http.http1MaxPendingRequests` | Supported (honest reinterpretation — max concurrent in-flight HTTP/1.1 requests) | Projects onto the selected target's effective `Proxy.pool_http1_max_pending_requests`. Ferrum caps concurrent in-flight reqwest/H1 requests (including the H3→plain bridge) per logical destination `(namespace, upstream/Service identity, policy port, selected subset)` because reqwest exposes no true connection-pending hook. The selected endpoint host is intentionally absent from the key (issue #3778). A sharded `CachePadded` gate rejects overflow with a backend-neutral 503; its RAII permit releases at response headers or on every error, deadline, cancellation, and retry exit. Retry attempts reacquire independently. Direct H2, gRPC, native H3, HBONE, and mesh-mTLS do not consult the H1 gate (distinct from #3775's cross-protocol `http2MaxRequests` active-request breaker). Precedence is per-port > selected subset > top-level. Mesh VIP/service-host and direct-pod upstreams for one Service share its FQDN identity; Kubernetes Service UID additionally isolates delete/recreate (generation is not part of the lane). Native upstreams retain their resource ids, so duplicate display names do not collapse unrelated resources. Cap updates keep the shared count while checking the requesting epoch's cap; zero-count keys retire race-safely. Structured rejection logs carry a bounded FNV-1a scope digest plus the effective DestinationRule policy port (distinct from the dial port under targetPort remapping). Zero rejects K8s and native/file mesh validation. |
| `trafficPolicy.connectionPool.tcp.maxConnections` | Supported (all transports Ferrum owns the socket for) | Cap on concurrent open backend connections per destination, enforced via a per-`(host, DestinationRule policy port)` shard-locked counter on `Upstream.port_overrides[port].max_connections` (`src/backend_conn_limit.rs`; the cap check, the reservation and the at-zero eviction all run under the same `DashMap` shard lock, so an idle destination drains from the map instead of retaining a zero-count entry for every host the gateway has ever dialed), shared by every transport so a destination gets ONE ceiling rather than one per transport. **Stream-family** (TCP / TCP+TLS / TCP-passthrough) enforces it at backend dial; exceeding the cap returns a typed `StreamSetupKind::BackendMaxConnectionsExceeded` (logged as `Backend maxConnections reached`) and the relay retry loop tries another LB target if `RetryConfig.retry_on_connect_failure` is enabled. **HTTP-family WebSocket** (H1/H2 in `src/proxy/mod.rs`, H3 in `src/http3/websocket.rs`) holds an RAII guard for the session; exceeding the cap rejects the upgrade with `503` (`rejection_phase=backend_max_connections`) before dialing. **Pooled multiplexed transports** (direct H2, gRPC, native HTTP/3, HBONE, Sidecar mesh-mTLS) reserve a shared slot at connection construction and hand it to that connection's driver, so it retires exactly when the socket closes (handshake failure, idle eviction, pool drain, reload/update/delete, SVID-rotation drain, shutdown) and unlimited multiplexed streams ride one admitted connection; an over-cap create is a pre-wire, backend-health-neutral `BackendConnectionLimit` (it may rotate to another LB target but records no circuit-breaker / passive-health / adaptive-concurrency failure for a destination that was never dialed) and the pool first falls back to an already-established shard so a capped destination keeps serving by multiplexing. **reqwest** (HTTP/1.1 and ALPN-negotiated HTTP/2) is admitted inside reqwest's own connector via the vendored `ClientBuilder::connection_admission` hook, so pooled reuse and multiplexed streams take no slot while an idle socket still holds one; an over-cap dial is refused and surfaced as a backend-health-neutral `503`. See the "DestinationRule `maxConnections` enforcement scope" note below for the per-transport contract. Top-level fan-out applies to every target port; per-port `portLevelSettings.connectionPool.tcp.maxConnections` overrides the fan-out for that specific port. `maxConnections <= 0` is rejected at translate time. |
| `trafficPolicy.connectionPool.tcp.tcpKeepalive` (`time` / `interval` / `probes`) | Supported for stream-family AND HTTP-family multiplexed pools (direct-H2, gRPC, HBONE, mesh-mTLS); reqwest-backed HTTP and H3/QUIC are documented residuals (shared-client / non-TCP transport) | Each subfield independently optional. Applied via `setsockopt(SO_KEEPALIVE)` + `TCP_KEEPIDLE` (Linux) / `TCP_KEEPALIVE` (macOS/iOS) for `time`, `TCP_KEEPINTVL` for `interval`, `TCP_KEEPCNT` for `probes`. Set on the backend socket right after `connect()` (stream-family: TCP / TCP+TLS / TCP-passthrough; HTTP-family: the socket-owning H2-family pools resolve the same per-port override at connection creation via the shared `socket_opts::apply_pooled_tcp_keepalive` — direct-H2 `http2_pool` and `grpc_proxy` key it by the dial target's `backend_port`; the HBONE pool and the Sidecar mesh-mTLS pool key it by the destination's **app/service port** and apply it inside the shared `dial_h2_connect_sender` after dialing the transport port `:15008`/`:15006`, so it covers Ambient HBONE egress, Sidecar mesh-mTLS egress, raw-TCP egress over both transports, AND WebSocket-over-HBONE/-mesh-mTLS which ride the same dialer). Best-effort: a `setsockopt` failure logs a `warn!` and continues rather than aborting the connection. The per-port DR override is **additive and takes precedence**; absent an override the global pool keepalive (`pool_config.tcp_keepalive_seconds`, whole-seconds idle time only, applied when `enable_http_keep_alive`) remains the fallback — so existing non-mesh behavior is unchanged. **First-materializer tradeoff (HTTP-family only):** keepalive is NOT part of the pool key (forbidden by the proxy-protocol rules — see `.claude/rules/proxy-protocols.md`), and these connections are pooled+shared, so the keepalive is fixed once at connection creation and the **first dispatcher to materialize a pooled connection wins**; later dispatchers that differ only in keepalive reuse the existing connection and inherit its setting — the same tradeoff already documented for `idleTimeout` / `maxRequestsPerConnection`. **Residuals:** the reqwest-backed HTTP pool (`src/connection_pool.rs`) applies `tcp_keepalive` at builder time (seconds-only) on a client SHARED across proxies that differ only in policy fields (keepalive is excluded from pool keys per the rules), so a clean per-proxy DR override is not possible there without another vendored reqwest patch — it keeps the global seconds-only keepalive (mesh egress never uses reqwest, so mesh coverage is complete; reqwest mainly serves non-mesh + localhost inbound where keepalive is moot). H3/QUIC (`src/http3/client.rs`) is UDP — `tcpKeepalive` is N/A (a QUIC keep-alive would be a separate `TransportConfig` knob). Sub-second durations and zero values are rejected at translate time because the underlying socket options are second-granular and require at least one probe. |
| `trafficPolicy.tls` | Supported | Overrides the `PeerAuthentication`-derived backend posture per matching `Upstream` when set. Mode mapping: `DISABLE` → clears `Upstream.backend_tls_*`; `SIMPLE` → enables server-cert verify + `backend_tls_server_ca_cert_path = caCertificates` (client cert/key cleared); `MUTUAL` → enables server-cert verify + projects `caCertificates`/`clientCertificate`/`privateKey` onto `Upstream.backend_tls_server_ca_cert_path`/`_client_cert_path`/`_client_key_path`; `ISTIO_MUTUAL` → enables server-cert verify + projects the workload SVID paths from `FERRUM_GATEWAY_SVID_CERT_PATH` / `FERRUM_GATEWAY_SVID_KEY_PATH` onto the upstream client cert/key fields, failing slice apply if either path is missing so stale/global client material is not used. `ISTIO_MUTUAL` projects **file-based** SVID paths for the outbound client cert, so when the mesh's only workload identity is a dynamic CA-backed SVID (`FERRUM_MESH_CA_BACKEND` with no `FERRUM_GATEWAY_SVID_*` files), `ISTIO_MUTUAL` on a generic backend / egress `ServiceEntry` upstream is intentionally **rejected (slice apply fails closed)** because the generic backend TLS path cannot present a dynamic SVID client cert — use file-based `FERRUM_GATEWAY_SVID_*` material, or an explicit `MUTUAL` policy with `clientCertificate` / `privateKey` paths, for those upstreams. Validated reloads of the `FERRUM_GATEWAY_SVID_*` files bump a generation in backend TLS and pool keys so new H2/gRPC/H3/HTTP connections rebuild client identity state without restarting; active HTTP health probes are restarted on each observed revision, and existing connections complete on their original config unless `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS` force-drains old-generation pool entries. `insecureSkipVerify: true` forces `backend_tls_verify_server_cert = false`, except that pairing it with `caCertificates: system://` is rejected at Kubernetes translation, native/file/xDS slice validation, and cold-path application: selecting system roots and then disabling verification is contradictory and must fail closed. The `system://` value must use that exact spelling with no path or query suffix. `sni` projects to `Upstream.backend_tls_sni`, onto `Proxy.resolved_tls`, into backend H2/gRPC/H3 TLS handshakes, and into the backend pool key so different SNI values never share connections. Plain HTTPS requests with an SNI override prefer the direct H2 backend pool, which sets the TLS server name natively; when that pool is unavailable or the backend speaks only HTTP/1.1, the request falls back to an HTTP/1.1 reqwest dial that carries the override in the request URL's authority while pinning the socket to the selected target (see the SNI transport paragraph below). `subjectAltNames` projects to `Upstream.backend_tls_san_allow_list`, onto `Proxy.resolved_tls`, into backend TLS verifier enforcement, and into the backend pool key so different allow-lists never share connections. If per-proxy or global no-verify is enabled, SAN allow-lists are not enforced and Ferrum logs a warning. When the field is unset, behavior is identical to today and `PeerAuthentication` continues to drive the default mTLS posture. |
| `trafficPolicy.portLevelSettings[].port.number` + nested `connectionPool.tcp.connectTimeout` | Supported | Top-level policy applies first; per-port `connectTimeout` lands on `Upstream.port_overrides[port].connect_timeout_ms` at apply time, then `GatewayConfig::resolve_dispatch_port_overrides()` projects it onto `Proxy.dispatch_port_overrides` for O(1) hot-path lookup. All four dispatch families consult it: HTTP/H2/H3 via `resolve_effective_proxy_for_target` (`src/proxy/mod.rs`), gRPC via the same helper threaded through `proxy_grpc_request*` (`src/proxy/grpc_proxy.rs`), TCP via `effective_backend_connect_timeout_ms` in `TcpConnParams` (`src/proxy/tcp_proxy.rs`), and HBONE via `effective_connect_timeout_ms` in `connect_backend` (`src/proxy/hbone_proxy.rs`). Ports outside 1-65535 rejected; duplicate port entries rejected; phantom ports (DR entry references a port unused by any `Upstream.target`) skipped with a warning at apply time. The admin API rejects POST/PUT setting `Upstream.port_overrides` directly — express per-port policy as a DestinationRule (SQL/MongoDB schemas don't persist the field) |
| `trafficPolicy.portLevelSettings[].loadBalancer` / `outlierDetection` | Supported for HTTP-family / gRPC / WebSocket / HBONE dispatch; LB algorithm, locality, and active/passive health also engaged for stream-family when all targets share a port | Per-port load-balancer algorithm/hash settings, passive outlier thresholds, and `localityLbSetting` (`distribute` / `failover` / `failoverPriority` / `enabled`) land on `Upstream.port_overrides[port]`; the runtime builds isolated per-port LB counters/hash rings, per-port passive health, and per-port locality LB state. Dispatch on a port with an override consults the per-port locality preference first and falls back to the upstream-level `trafficPolicy.loadBalancer.localityLbSetting` when the per-port entry omits it. `failoverPriority` is inert unless applicable upstream health or that port's `outlierDetection` enables failover; a port-level signal does not alter other ports. TCP/UDP/DTLS stream paths also engage the per-port **LB algorithm** and **`localityLbSetting`** when all upstream targets share a single port (`initial_dispatch_port_override` is non-zero); the lane engages only for selection-affecting overrides, per-port `consistentHash` on a stream lane requires a source-IP hash key, per-port `LEAST_CONN` is refused on the generic stream listeners (fail-closed typed setup error; mesh raw-TCP/UDP relays keep connection counts and select normally), and per-port `LEAST_LATENCY` is refused on every stream lane (no latency signal on raw relays) — see the stream-family bullet in [Limitations](#limitations-and-not-supported). Stream paths pass active/passive health context into selection, so per-port `outlierDetection` thresholds, existing passive ejections, active health state, and the `maxEjectionPercent` cap affect TCP/UDP/DTLS target selection. Outlier thresholds are still not recorded on stream paths because raw relay sessions carry no response status. Phantom ports are skipped with a warning at apply time. Migration note: operators who previously set these fields expecting warning-only behavior should audit them before upgrade because they now affect HTTP-family/gRPC/WebSocket/HBONE routing and ejection decisions. Example: a top-level `ROUND_ROBIN` policy with `portLevelSettings[8080].loadBalancer.simple=RANDOM` keeps non-8080 traffic on round-robin while 8080 dispatch uses its own random counter/ring; a per-port `localityLbSetting.distribute` on 8080 weights only port-8080 traffic and leaves other ports on the upstream-level locality preference. |
| `exportTo` | Supported | Namespace export visibility. Omitted/empty on Kubernetes becomes Istio's public `["*"]`; `.`, `*`, and explicit namespace lists are honored. Enforced during slice construction, before lookup selection and before per-node slice serialization. Unsupported values (`~`, empty entries, malformed namespaces, over-long lists, `*` mixed with an explicit list) are rejected fail-closed. On the native/file/xDS-carrier sources an EMPTY list is namespace-local. See [Export visibility](#destinationrule-visibility-and-lookup). |
| DestinationRule lookup namespace | Supported | Client namespace → target service namespace → configured `istio_root_namespace`; the first tier with a visible rule wins outright. See [Lookup hierarchy](#destinationrule-lookup-hierarchy). |

Translator warnings surface in the `K8sTranslation.warnings` returned from `translate_k8s_objects`, so operators see them at apply time.

DestinationRule `trafficPolicy.tls.sni` (and the Gateway API `BackendTLSPolicy` `validation.hostname` that projects onto the same field) is enforced on every backend path where Ferrum owns the TLS handshake — direct HTTP/2 for plain HTTPS, gRPC over H2, and native H3 — and, since the H1 transport work, on the **reqwest HTTP/1.1 path** as well.

reqwest exposes no per-request server-name hook: its connector derives the rustls server name from the request URL's host. The H1 dial therefore expresses the override by putting it in the URL **authority**, while keeping the socket on the load-balancer-selected target: the pooled client's `DnsCacheResolver` is pinned to that target's already-resolved, already-egress-screened address, and because the resolver answers every name with the pinned address the override hostname is never itself resolved. `backend_tls_sni` is separately validated to be a DNS hostname and never an IP literal, so it also cannot become a hyper-util URL-literal dial that would bypass the resolver — the selected backend target stays authoritative for where the socket connects. Three consequences are load-bearing:

* **ALPN is restricted to `http/1.1`** on that client. HTTP/2 derives `:authority` from the URL, which now carries the server name, so h2 must not be negotiated there; the backend instead reads the authority from the explicit `Host` header dispatch sets from the effective target host (hyper-util preserves an explicit `Host`). H2-capable targets are unaffected — they keep using the direct-H2 pool, which sets the server name natively and leaves the real backend authority in place.
* **Pool identity** carries the pinned address and the force-H1 discriminator alongside the existing SNI / CA / SAN-digest / mTLS / verification components, so an SNI dial can share a client neither with a default h2-capable client nor with another target's pin. The cost is that an SNI-override route partitions its reqwest client per target (up to one per endpoint) and gives up in-client multi-address failover for that dial; only SNI-override routes pay it.
* **Retries, timeouts, and streaming bodies** are unchanged, because the dial reuses the ordinary reqwest path. The retry path builds the same dial against the newly selected target, so an LB rotation between attempts still dials the rotated target under the same server name.

The `502` with `gateway-error-reason: backend_tls_sni_requires_direct_h2` therefore no longer fires for an H1-only backend, a retry-enabled route, a buffering plugin, or `pool_enable_http2: false`. It remains the fail-closed answer for the cases where the dial genuinely cannot be constructed — no resolved target address to pin, or a backend URL whose authority does not carry the selected target host — so the override is never silently dropped and the handshake is never made under the wrong server name.

**Config admission does not screen these combinations.** `ferrum-edge validate` and the Admin API once rejected three shapes for proxy-level and DestinationRule / `BackendTLSPolicy` per-port TLS SNI overlays — effective retry, request-body-buffering plugins, and `pool_enable_http2: false` — on the premise that only the direct-H2 pool could carry a server name (issue #2954). The H1 dial above serves all three, so those rejections refused configurations that work; they are removed (issue #3276), along with the request-body-buffering admission screener that derived the third leg. A `BackendTLSPolicy` hostname combined with retry, a buffering plugin, `pool_enable_http2: false`, or all three is admitted and served. What remains fail-closed is decided at runtime, where the information actually exists: the `502` above when a dial genuinely cannot be constructed, and the WebSocket transport's own pre-dial refusal (see below). Nonzero global body-size limits (`FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` / `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`, including the default 10 MiB response cap) do **not** disqualify direct-H2 — for SNI overrides and ordinary plain-HTTPS alike: the direct-H2 path enforces those limits in-path (413 on oversized requests, 502 on oversized responses) via `SizeLimitedIncoming` and size-limited body collection, preserving the same `ErrorClass` / `connection_error` contracts as the reqwest path. H3 frontend requests bridged to a non-H3 backend are served through the same reqwest H1 SNI dial, on both the buffered and streaming legs, so an HTTP/3 client reaches a BackendTLSPolicy-covered backend exactly as an HTTP/1.1 or HTTP/2 client does; the bridge keeps the real target for its circuit-breaker, load-balancer, and `backend_target` accounting and rewrites only the dial. On that bridge the dial is resolved as a **local dispatch-policy decision** — before backend admission, before the least-connections connection-start record, and before any client is fetched — so an override that cannot be expressed (an unresolvable selected target) terminates with the same fail-closed `502` and `gateway-error-reason` without dialing the backend or relaying a request body, rather than silently connecting under the target-derived server name.

**WebSocket is the one transport that still refuses an override.** `client_async_tls_with_config` derives both the `Host` header and the TLS server name from the request URI, so a distinct SNI cannot be applied there at all. A `wss://` upgrade whose effective backend TLS carries an `sni` value is refused **before dialing** (`502`, non-retryable, neutral to the circuit breaker and passive health) rather than handshaking under the URI host. That is a runtime transport limitation, not an admission rule: the configuration is still accepted, because the same upstream may legitimately serve non-WebSocket traffic through the H1/H2/H3 SNI paths.

Active **HTTP and gRPC** health probes use the same effective backend TLS server name as request traffic: a `backend_tls_sni` override becomes the probe's TLS server name, so a backend whose certificate is valid only for the override name is no longer marked unhealthy while serving requests successfully. The probe still dials only the already-resolved, egress-screened target candidate, and the backend still sees its own authority — the HTTP probe puts the override in the probe URL (reqwest derives the server name from the URL and has no per-request hook) while pinning that client's resolver to the real target host and sending an explicit `Host`, and that probe client is restricted to **HTTP/1.1** so the explicit `Host` stays authoritative (HTTP/2 would rebuild `:authority` from the URI, i.e. from the server name); the gRPC probe sets `domain_name` / the rustls `ServerName` from the override while `origin` keeps the target authority. The override hostname is never itself resolved. An HTTPS+SNI HTTP probe therefore builds one client per target rather than one per upstream, and fails closed — never falling back to an unpinned client — if the dial cannot be pinned. TCP and UDP probes are unaffected (no TLS handshake).

## MeshSlice

`MeshSlice` is the per-node filtered view of mesh configuration, built by `MeshSlice::from_gateway_config()`. The CP computes a slice per subscriber; in native mode the slice is pushed directly, in xDS mode the translated resources are sliced locally.

The slice builder:

1. Filters workloads by namespace.
2. Finds the selected workload (if `workload_spiffe_id` is provided) for effective namespace/labels.
3. Filters `MeshPolicy` entries by `PolicyScope` matching against the proxy's namespace and labels.
4. Filters `PeerAuthentication` entries by workload selector.
5. Filters `ServiceEntry` entries by `export_to` visibility.
5b. Filters `MeshDestinationRule` entries by `export_to` visibility, then by Istio's client → target-service → root lookup tier, then by Sidecar egress scope, and finally resolves the winning tier per destination (see [Export visibility](#destinationrule-visibility-and-lookup)).
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
| `TargetRefs { attachments }` | Istio `AuthorizationPolicy.spec.targetRefs` attachment scope — see the dedicated section below. |

An empty `WorkloadSelector` (`labels: {}`, `namespace: None`) intentionally matches any workload.

The canonical matching helper `policy_scope_applies_to_workload()` is shared between the slice builder and the plugin filter so scope semantics stay byte-identical across both surfaces.

### AuthorizationPolicy `targetRefs` (issue #3226)

`PolicyScope::TargetRefs { attachments }` models Istio `AuthorizationPolicy.spec.targetRefs`. The supported set is deliberately narrower than the [Istio reference](https://istio.io/latest/docs/reference/config/security/authorization-policy/):

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

Without this, a mixed policy such as `targetRefs: [Service reviews, Gateway waypoint-b]` — legitimately retained at `reviews`' waypoint-a — would have applied to **every** destination at waypoint-a through its unmatched `waypoint-b` arm.

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

**Bounds.** `timeout` is capped at 30s (default 1s), `includeRequestBodyInCheck.maxRequestBytes`
at 1 MiB, provider response reads at 64 KiB, each header list at 32 exact
entries (case-insensitively unique), and the admitted provider set at 16 per
mesh generation. In-flight checks are capped process-wide and are **refused
immediately** at the ceiling rather than queued, so provider slowness cannot
become unbounded gateway latency or memory growth.

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
forwarded (a credential in it must not reach the provider).
`includeAdditionalHeadersInCheck` values are **authoritative**: a fixed
operator header replaces any same-named client header or
`includeRequestHeadersInCheck` value rather than being appended beside it, and
case-variant duplicate fixed names are rejected at admission so the winner is
never iteration-order dependent.

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
`headersToDownstreamOnDeny: [location]` still works. Only the unrepresentable
status is replaced: the decision is still a denial and is still counted as
`denied_by_provider`.

Ferrum never uses or forwards the provider response body. Once an explicit
denial status has arrived, that status remains authoritative even if its
discarded body is oversized or cannot be drained; `failOpen` therefore cannot
convert a provider denial into an allow through a body-framing failure.

A provider name this generation does not carry, a generation with no executor,
an unavailable request body for a body-inspecting provider, a concurrency
refusal, and task cancellation are all failed checks and therefore also honour
`failOpen`. **Three** refusals are decided **without** contacting a provider and
are therefore **not** subject to `failOpen`: a provider conflict (above), a
matched delegation on a connection with no HTTP request to check, and a request
body over the selected provider's `maxRequestBytes` (below).

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

**Mutation is deliberately narrow.** `headersToDownstreamOnDeny` is honoured:
those headers land on the gateway-authored denial this plugin itself produces.
`headersToUpstreamOnAllow` and `headersToDownstreamOnAllow` are **rejected at
admission**. Ferrum runs the check in the `authorize` phase, before route
dispatch and before every request/response transformer, so a header written
there would order differently against operator-authored rules on each ingress
path; a protocol-dependent mutation of an authenticated request is exactly the
gap this feature must not introduce. Wildcard header entries are refused for
the same reason a prefix rule cannot be shown to exclude hop-by-hop, routing,
mesh-identity, or gateway-reserved names. The provider's own response **body**
is never echoed to the client. Credentials (`authorization`, `cookie`) reach a
provider only by being named explicitly in `includeRequestHeadersInCheck`; the
full client header map and the request query string are never forwarded.

**Protocol coverage.** The check runs on every HTTP-family ingress path
identically — HTTP/1.1, HTTP/2, native gRPC, HTTP/3, and HTTP relayed inside a
mesh/HBONE CONNECT — because they share one `authorize` ladder. Layer-4
sessions (raw TCP, TLS passthrough, UDP, DTLS) carry no HTTP request and cannot
be checked: a CUSTOM rule that **matches** an L4 connection **denies** it rather
than serving it unchecked. Following Istio, HTTP-only fields are treated as
**always matched** on a non-HTTP port for `DENY` **and `CUSTOM`** alike, so a
CUSTOM rule carrying `paths` / `methods` / `headers` / `when: request.auth.*`
still matches an L4 connection and still closes it — it does not quietly become
inert. Scope a CUSTOM policy with `to.operation.ports` when the selected
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
request metadata carries the same closed reason token. Every matched
delegation is counted **exactly once**, including the outcomes decided without
contacting a provider (`provider_unbound` when no executor or no binding,
`provider_conflict`, `unexecutable` for an L4 session), so a fail-closed
denial is never invisible. `outcome` values are `allowed`, `denied_by_provider`,
`provider_unbound`, `provider_error`, `provider_conflict`, `unexecutable`,
`timeout`, `transport_error`, `response_refused`, `body_unavailable`,
`body_too_large`, and `concurrency_exhausted`. `body_unavailable` (a failed
check `failOpen` may admit) and `body_too_large` (the unconditional over-cap
refusal) are deliberately separate series. No request body, credential header
value, provider secret, or resolved provider URL is ever logged.

### Rule Matching

Each `MeshRule` checks the following dimensions (all must match — a conjunction):

- **Principal matching** (`from`): Istio source-principal patterns (`<trust-domain>/ns/<namespace>/sa/<service-account>`, glob), `serviceAccounts`, namespace patterns (glob), and trust-domain patterns. Full `spiffe://...` patterns are also accepted in direct `MeshPolicy` config. Multiple `from[]` source entries are ORed.
- **Request principal matching**: `request_principals` glob patterns matched against the `{issuer}/{subject}` composite extracted by `jwks_auth`. When `request_principals` is non-empty and no JWT is present, the rule does not match (Istio semantics: anonymous requests fail the principal check). An empty `request_principals` list matches any request including unauthenticated ones.
- **Source negation / IP blocks** (per-source, ANDed with the positive `from`): Istio `notPrincipals`, `notServiceAccounts`, `notNamespaces`, `notTrustDomains`, `notRequestPrincipals`, `ipBlocks`, `notIpBlocks`, `remoteIpBlocks`, `notRemoteIpBlocks`. These are **conjunctive** with the positive matchers. Negative identity matchers fail the rule only when the corresponding source/JWT identity is present and matches an excluded pattern; if the identity is absent, the negative matcher succeeds, so `DENY notPrincipals: ["*"]` and `DENY notRequestPrincipals: ["*"]` catch anonymous traffic. IP block matchers fail closed when the IP they test is absent, so a positive `ipBlocks`/`remoteIpBlocks` constraint with no resolved IP does not match. `ipBlocks`/`notIpBlocks` match the direct connection peer IP (`source.ip`); `remoteIpBlocks`/`notRemoteIpBlocks` match the gateway-resolved client IP (`remote.ip`, XFF-derived when trusted proxies are configured). Unsupported source fields fail the resource closed at translation time (mirroring the `to.operation` side); a malformed CIDR rejects the resource or direct plugin config.
- **Request matching** (`to`): methods, paths (glob), hosts (normalized, case-insensitive), ports (exact + glob patterns), headers (case-insensitive keys, normalized at config load). The negative `to.operation` matchers (`notMethods`/`notPaths`/`notHosts`/`notPorts`) are conjunctive; `notPorts` accepts the same bounded Istio port grammar as positive `ports` (`"*"`, `"<digits>*"`, `"*<digits>"` that can match an ordinary decimal port in `1..=65535`, plus literal `1`-`65535`) and evaluates through pre-normalized `not_ports` / `not_port_patterns` without per-request allocation. ALLOW/AUDIT rules fail closed when the corresponding request attribute is absent (including an unresolved destination/listener port for `notPorts`); DENY rules follow Istio and treat missing HTTP-only operation attributes as matches, so port scoping is recommended for DENY rules that mention HTTP fields and can see TCP traffic.
- **Condition matching** (`when`): attribute-based with `values` (the attribute must be present and equal one of the values) and `not_values` (the attribute must not equal any value; an absent attribute satisfies a `not_values`-only condition, matching Istio's compiled `not_rule` semantics). Values follow Istio's `StringMatcherWithPrefix` grammar for most keys: `*` is a presence check, a trailing `*` is a prefix match, a leading `*` is a suffix match, and anything else — including a mid-string `*` — is an exact match on the literal text. **Three keys have their own Istio grammar and do not use that matcher** — `source.ip` / `remote.ip` / `destination.ip` are CIDR blocks, `source.serviceAccount` is an exact namespace-relative match, and `source.namespace` accepts a `*` at any position (see [Value grammars](#value-grammars-per-key) below). **Ferrum represents the complete documented Istio condition-key set** (see [Condition keys](#condition-keys) below): `source.principal` (Istio form without the `spiffe://` scheme), `source.namespace`, `source.serviceAccount`, and `source.trustDomain` (all from the resolved peer SPIFFE ID), `source.ip`, `remote.ip`, `destination.ip`, `destination.port`, `connection.sni`, `request.auth.principal`, `request.auth.presenter` (JWT `azp`), `request.auth.audiences`, `request.auth.claims[<name>]` and nested `request.auth.claims[<name>][<nested>]` string or string-list leaf values (from the validated JWT via the mesh `RequestAuthentication` plugin), `request.headers[<name>]`, and `experimental.envoy.filters.<filter>[<key>]`. Dynamic header/claim keys follow Istio's loose `validateMapKey` framing: the first `[` and final `]` delimit a non-empty interior, without an extra HTTP-header-name parse at policy admission. Known HTTP pseudo-headers (`:authority`, `:method`, `:path`, `:scheme`) come from typed request facts; unusual admitted interiors that no request or validated claim can materialize remain absent. Keys outside the documented prefixes are **rejected** at translation/config validation time with a field-specific diagnostic, so a DENY condition on an unmodelled attribute cannot silently fail open. Only the attribute keys some loaded policy references are materialized per request, so a policy set with no `when:` conditions adds no hot-path cost.

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
| `connection.sni` | Istio string match | yes | yes | yes | frontend TLS / QUIC / DTLS ClientHello SNI |
| `request.auth.principal` | Istio string match | yes | HTTP only | HTTP only | validated JWT `iss/sub` |
| `request.auth.presenter` | Istio string match | yes | HTTP only | HTTP only | validated JWT scalar `azp` |
| `request.auth.audiences` | Istio string match | yes | HTTP only | HTTP only | validated JWT `aud` |
| `request.auth.claims[<name>]`, `request.auth.claims[<a>][<b>]` | Istio string match | yes | HTTP only | HTTP only | validated JWT scalar / string-list leaf claims |
| `request.headers[<name>]` | Istio string match | yes | HTTP only | HTTP only | request headers, matched case-insensitively; `:authority`, `:method`, `:path`, and `:scheme` use typed request facts |
| `experimental.envoy.filters.<filter>[<key>]` | Istio string match | never sourceable | never sourceable | never sourceable | Envoy dynamic metadata; Ferrum has no Envoy filter chain |

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

**Absent vs unsourceable.** These are different facts and Istio gives them different semantics, so Ferrum models them separately.

- *Absent* — the path CAN source the attribute and this request simply does not carry it (a header the client omitted, an SNI-less plaintext connection, no validated JWT). Ordinary Istio rules apply: a `values` check fails, and a `notValues`-only check passes.
- *Unsourceable* — the path can NEVER carry the attribute, or required transport evidence could not be recovered. That is an HTTP-only key on a raw TCP / TLS-passthrough / UDP / DTLS connection (anything authorized through the L4 `on_stream_connect` hook, which has no header map and no JWT context at all), `source.ip`, `remote.ip`, `destination.ip`, or `destination.port` with no typed transport evidence, or any `experimental.envoy.filters.*` key. A mesh / HBONE CONNECT relay is deliberately NOT in this class: it is authorized on the request path, where Ferrum has parsed the CONNECT's own header map and can genuinely source `request.headers[...]` from it. Ferrum applies Istio's documented non-HTTP-port behavior, which is fail-closed in both directions: a **DENY** rule ignores the field and still matches on its remaining constraints, and an **ALLOW** or **AUDIT** rule can never match. Access is never granted on an attribute the gateway cannot read, and an unevaluable condition can never disarm a DENY.

`destination.ip` evidence comes only from the transport — a trusted inbound PROXY-protocol tuple, `SO_ORIGINAL_DST`, node-waypoint eBPF capture metadata, the listener's specific bind address, or the accepted socket's local address. It is never derived from `Host`, `X-Forwarded-*`, or any other client-settable input: a client that could choose its own `destination.ip` could choose which destination-scoped rule judges it. UDP and DTLS sessions carry no such evidence today, so a `destination.ip` condition there is unsourceable and fails closed as described above. A captured original destination always wins over the socket's local address, because on a capture listener the socket's local address is the interception port rather than the address the client dialled. This mesh-authz connection fact is separate from VirtualService L4 `destinationSubnets` evidence: stream routing accepts only the trusted PROXY/capture original destination, never an ordinary listener's bind/local address.

**A documented-but-unsourceable key does not reject the policy.** Rejecting the resource would drop the whole `AuthorizationPolicy`, which is fail-OPEN for a DENY, so `experimental.envoy.filters.*` conditions install normally and are enforced with the unsourceable semantics above.

**Validation and bounds.** Every configuration surface — the Kubernetes Istio translator, `MeshConfig` file/native validation, and the `mesh_authz` construction gate — runs the same `validate_mesh_condition` contract and reports field-specific diagnostics (`rules[].when[2].values[0] …`). It rejects: an unsupported or empty key, a key over 256 UTF-8 bytes or containing control characters, a condition with neither `values` nor `notValues`, an empty value, a value over 512 UTF-8 bytes or containing control characters, a malformed `source.ip` / `remote.ip` / `destination.ip` CIDR, a non-numeric or out-of-range `destination.port`, a `source.serviceAccount` containing `*` or more than one `/` (or with an empty namespace / service-account half), and a `source.trustDomain` containing `/`, more than one `*`, or a mid-string `*`. Whitespace or other unusual printable bytes inside a dynamic header/claim map key are admitted because Istio's `validateMapKey` admits them; if the request path cannot materialize that exact key, it remains absent. Every rule applies identically to `values` and `notValues` — a bound or grammar enforced on only one direction would leave the other fail-open. Collections are bounded at 64 `when[]` entries per rule and 256 entries per `values` / `notValues` list; `source.serviceAccount` carries Istio's stricter caps of 16 entries per list and 320 UTF-8 bytes per value. An externally supplied policy therefore cannot grow unbounded per-request matching work, and no diagnostic echoes an operator-supplied value except an IP block, whose exact text is required to fix the CIDR.

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

Gateway DPs can also originate HBONE when they have a gateway SVID loaded and an upstream target is tagged `mesh.hbone=true`. The gateway probes the target's sidecar HBONE port (`15008`, or `mesh.hbone_port`) during backend capability refresh, then sends eligible plain HTTP traffic through HTTP/2 CONNECT over SPIFFE mTLS before trying the ordinary direct backend transports. The HBONE pool honors the proxy's effective `pool_*` overrides, including connection count, idle timeout, TCP keepalive, and HTTP/2 flow-control settings, and coalesces concurrent first connects for the same target/SVID key within the proxy's `backend_connect_timeout_ms` budget. Retry-enabled and request-body-policy routes buffer and finalize the request once, then dispatch replayable bytes plus the exact sanitized multi-value header representation through the selected target's HBONE transport on every eligible attempt; they never downgrade a mesh-tagged target to a direct application dial. The CONNECT request carries `source.principal` baggage derived from the gateway SVID; mesh-side authz still requires the baggage to agree with the authenticated peer identity. The tunneled inner HTTP request strips client-supplied identity baggage (`source.*`, `destination.*`, and aliases) while preserving non-identity baggage, so untrusted client claims cannot reach the mesh backend as application headers.

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

**EgressGateway requires client certificates.** The EgressGateway TLS listener — both the `:15090` HTTP-family mTLS-termination listener and the F6.1 stream-family TCP egress listeners that share the same `ServerConfig` — is a security boundary onto external networks: a cert-less client admitted there reaches the external backend unauthenticated. For this topology, `resolve_mesh_inbound_client_auth` escalates `PERMISSIVE`-with-a-trust-anchor from `Optional` to **`Required`**, so every egress client must present a verifiable SVID even when no STRICT `PeerAuthentication` is in force (the default-allow case). The non-egress topologies (Sidecar / Ambient / waypoints) keep the standard `PERMISSIVE` → `Optional` posture unchanged. If `PERMISSIVE` resolves on an EgressGateway with **no** trust anchor at all, the listener cannot authenticate clients, so it **fails closed** (hard error, never optional-no-verify mTLS); in practice `validate_egress_gateway_mtls_config` already requires a peer verifier for this topology at config time, so this is defense-in-depth for the live-reload path. UDP ServiceEntry ports still materialize no EgressGateway listener of their own — their datagram-over-mesh relay rides the `:15090` mTLS-termination listener as a `udp`-marked CONNECT, so it inherits exactly this required-client-cert posture. The only ways an egress client skips client-cert verification are an explicit `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true` (plaintext stream listeners) or `PeerAuthentication` `DISABLE` (rejected for EgressGateway by the disable-mode topology guard). This escalation applies on **both** startup and `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true` slice apply, so a reload cannot downgrade an egress gateway to optional client auth.

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

**Cross-cluster gRPC and WebSocket egress are supported for Sidecar (issue #2010).** Both ride the SAME cross-cluster mesh-mTLS transport as HTTP — the app protocol is a runtime flavor layered on top. A native-gRPC request whose LB-selected target is a cross-cluster `mesh.mtls` target skips the direct-dial gRPC pool and dispatches through the mesh-mTLS pool's cross-cluster branch (`proxy_to_backend_mesh_mtls`): hyper HTTP/2 end-to-end, `te: trailers` re-synthesized, response streamed so `grpc-status` and custom trailers relay across the two-trust-domain hop. A WebSocket upgrade opens an RFC 8441 Extended CONNECT over that same cross-cluster mesh-mTLS dial. Both the HTTP/gRPC path and the WebSocket path resolve the dial the same way through a shared `MeshMtlsDialPlan` (in-cluster pins the peer SPIFFE; cross-cluster uses `expected_peer = None` + trust-domain-only verification scoped to `mesh.trust_domain` + a ClientHello SNI override to `mesh.eastwest_sni`), so the two transports cannot drift. Fail-closed throughout: a cross-cluster target missing its SNI override or remote trust domain, or an unsupported transport, is refused (gRPC UNAVAILABLE / a failed upgrade) with no plaintext or wrong-SNI fallback. A native-gRPC request initially selected onto mesh-mTLS may use replayable retry attempts on that transport. The native-gRPC retry loop re-resolves its transport per attempt and may rotate between direct and Ambient `mesh.hbone` targets (issue #3728), but still fails closed if rotation lands on a Sidecar `mesh.mtls` or Unix-socket target, because it cannot preserve the generic mesh response/trailer pipeline mid-loop. (The WebSocket dial loop re-derives mesh egress from the rotated target on every attempt; only unsupported/malformed WS targets fail the upgrade closed.) The HTTP/3 frontend's **gRPC** bridge dispatches both mesh transports (issue #3284), so cross-cluster gRPC works there too; the H3 **WebSocket** bridge still has no mesh transport and fails closed. **Ambient cross-cluster gRPC and WebSocket are both supported** over HBONE — gRPC through a nested HTTP/2 connection inside the CONNECT tunnel on every frontend (issues #3284, #3728), WebSocket through the tunnel's inner HTTP/1.1 handshake; see the Ambient section below.

### Client-Side Cross-Cluster Egress (Ambient / HBONE)

An **Ambient** client reaches a remote-cluster service over the east-west gateways too, but the shape differs from Sidecar because the inner protocol does. Ambient's inner request is an HBONE **CONNECT** whose `:authority` the destination relay (`handle_hbone_request` → `build_inbound_hbone_relay_proxy`) dials under the **open-relay guard** (`inbound_hbone_relay_destination_allowed`): the authority must be loopback or a **slice-declared workload addr+port** — a service FQDN is rejected. The remote pod IP is slice-declared on the destination side and known to the client (merged remote endpoints), just not directly reachable. So Ambient cross-cluster targets are **per-remote-pod**, not one-per-gateway:

- the `UpstreamTarget` identity is a **scoped synthetic host** carrying the gateway-network scope + the real pod addr (so two remote pods that share an IP across overlapping CIDRs but are reached through different gateways/networks never collapse to one load-balancer / health / circuit-breaker key); the **real pod addr:app-port** rides the `mesh.hbone_authority_host` tag and is what the inner HBONE CONNECT `:authority` uses;
- the dial host is the remote network's **east-west gateway** (`mesh.hbone_dial_host` / `mesh.hbone_port`, e.g. `:15443`) with the **ClientHello SNI overridden to the destination service FQDN** (`mesh.eastwest_sni`) so the gateway's SNI passthrough routes the opaque outer TLS;
- verification is **trust-domain-scoped** (`mesh.trust_domain`, no pod SPIFFE pin — the gateway LB-picks the destination), the same posture as the Sidecar cross-cluster path; the HBONE pool key includes the SNI override + the expected trust domain so a session verified for one (trust domain, destination) is never reused for another.

The HBONE **capability registry is bypassed** for cross-cluster targets (they dial the operator-declared gateway, never a probeable workload `:15008`) and they are excluded from capability probing. Local-cluster endpoints stay the first tier (`mesh.remote=true`). HTTP-family ports retain the phase-3 alias rules. Raw-TCP and UDP reuse the same per-pod target shape with the L4 per-port alias as outer SNI and the real pod addr/app-port as CONNECT authority. Raw TCP uses the existing HBONE byte tunnel; UDP uses `get_datagram_tunnel` and the same length-delimited `mesh_udp_frame` records as same-cluster UDP. Missing SNI, trust domain, dial host, or authority fails closed before a wrong-target dial.

**Destination inbound relies on the standard inbound capture** (same as the Sidecar path above). The client dials the gateway with the destination service FQDN as SNI; the gateway forwards the opaque TLS to the destination workload's **app port** (`build_east_west_service_targets` forwards to the workload app/target port, not a mesh terminator port), and the destination pod's inbound capture REDIRECTS that app-port traffic to the Ambient HBONE terminator `:15008` — exactly as same-cluster east-west *inbound* works, and exactly how the Sidecar cross-cluster path redirects to `:15006`. No destination-side change is needed for cross-cluster. The unprivileged functional fixtures still collapse that redirect by targeting the terminator port directly; the privileged **Two-Cluster Mesh Live Datapath** CI gate (`functional_mesh_live_two_cluster_cross_cluster_protocol_matrix`) validates the real app-port → destination-capture path with separate federated SPIRE trust domains and an isolated east-west hop.

**L4 test boundary.** In-tree projection tests cover Sidecar/Ambient raw-TCP and UDP target materialization, per-port SNI generation, and destination east-west SNI relay creation. Existing unprivileged functional tests cover the raw byte-stream and framed-datagram destination relays. The privileged **Two-Cluster Mesh Live Datapath** CI gate covers the complete boundary that those harnesses cannot simulate: `SO_ORIGINAL_DST`/TPROXY in cluster A → actual SNI-passthrough east-west gateway → app-port capture and terminator in cluster B, including `mesh_udp_frame` datagrams and transparent VIP:port return-source spoofing.

**WebSocket AND native gRPC over cross-cluster HBONE (Ambient) are both supported (issues #2010, #3284, #3728).** A WebSocket upgrade to a cross-cluster HBONE target rides the SAME per-pod cross-cluster HBONE byte tunnel the HTTP path uses — dial the remote east-west gateway (`mesh.hbone_dial_host`) with the destination service FQDN as the outer-TLS SNI override (`mesh.eastwest_sni`) + trust-domain-only verification (`mesh.trust_domain`, no pinned pod SPIFFE); the inner HBONE CONNECT `:authority` is the destination pod addr:app-port (`mesh.hbone_authority_host`) the dest relay byte-copies to — then an inner HTTP/1.1 WebSocket handshake spoken THROUGH the tunnel. `get_ws_byte_tunnel` threads the cross-cluster SNI-override / trust-domain scope (mirroring `proxy_to_backend_hbone`), so the WS and HTTP HBONE paths cannot drift; a malformed cross-cluster target (missing SNI / trust domain) fails the upgrade closed. **Native gRPC over cross-cluster HBONE is supported on every frontend** — it does NOT use this HTTP/1.1-inside-the-tunnel dispatch. Native gRPC (and gRPC-Web the `grpc_web` plugin TRANSLATED, which is wire-native gRPC by dispatch time) instead runs a NESTED `hyper::client::conn::http2` client over the very same authenticated CONNECT byte tunnel through the shared `GrpcDispatchTransport`, so `grpc-status` trailers, flow control, backpressure, deadlines, and cancellation relay end-to-end. The HTTP/3 bridge wired that transport first (issue #3284) and the standard HTTP/1.1+HTTP/2 frontend reuses it (issue #3728). A malformed cross-cluster target (missing SNI override / trust domain / CONNECT authority host, or one declaring BOTH mesh transports) still fails closed BEFORE any dial with a Trailers-Only gRPC UNAVAILABLE (HTTP 200 + `grpc-status: 14`) whose message never echoes identity metadata. (PASS-THROUGH gRPC-Web is body-framed and keeps riding the cross-cluster HTTP-family path like plain HTTP.) **Sidecar cross-cluster gRPC and WebSocket are also supported** over mesh-mTLS — see [Client-Side Cross-Cluster Egress (Sidecar)](#client-side-cross-cluster-egress-sidecar) and the [Protocol x Topology Support Matrix](#protocol-x-topology-support-matrix).

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
> - **Ambiguous locality:** when compatible local replicas disagree on source locality, Ferrum automatically applies the fail-closed-to-local behavior for that slice even if strict mode is `false`. Ambiguity is not treated as ordinary missing metadata, so a same-SPIFFE sibling cannot broaden selection to remote endpoints.
>
> Ferrum emits a startup `WARN` when discovery is enabled but no source locality can be resolved from the initial mesh slice. Ensure `topology.kubernetes.io/region` and `topology.kubernetes.io/zone` Node labels are propagated to workload locality metadata (via `FERRUM_K8S_NODE_LOCALITY_ENABLED=true`, or by stamping them directly on the mesh slice's `Workload.locality` field) before enabling discovery; prefer fixing source locality over enabling strict mode, which is a safety net rather than a substitute for correct locality metadata.
>
> Config validation additionally emits a `WARN` advisory (any mode, never an error) whenever `FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS > 0` is combined with `FERRUM_MESH_LOCALITY_LB_STRICT=false`, recommending strict mode so an absent source locality cannot mix remote endpoints into selection while local endpoints are healthy. Cross-cluster east-west **gateway** failover targets are unaffected either way — they are always-failover local-first regardless of the flag; the advisory covers only plain remote workload endpoints from this Beta discovery path.

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

**Live-verification status:** aggregation and failover remain covered by hermetic integration tests, and `.github/workflows/multicluster-poller-partition-live.yml` adds the true cross-cluster gate: two Ferrum CP/DP deployments use verified TLS/mTLS, per-remote credentials, bound audiences, and four independently faultable Toxiproxy links. Its required evidence covers initial trust/endpoint installation, short-partition retention with increasing age, independent endpoint and trust expiry, inbound/outbound recomputation, target removal, same-generation recovery without a new slice, bounded/redacted metrics with admin-age parity, and withdrawal while polls are in flight without retired-state reinstall.

## Protocol x Topology Support Matrix

One table answering "does protocol X ride mesh transport Y?" across the two same-cluster topology transports, the two client-side cross-cluster east-west paths, and the gateway-to-mesh service-discovery bridge. Statuses use this document's own failure-mode language; each cell is anchored to the authoritative section via the numbered notes below. **NodeWaypoint is deliberately out of scope for this table** — it is **Experimental** with its own sections ([Node Waypoint](#node-waypoint), [Node Agent Mode](#node-agent-mode)); its UDP/DTLS limits (mesh-wide UDP/DTLS policy only, per-pod UDP/DTLS authorization scoping architecturally out of scope) are pinned in [docs/mesh_supported_matrix.md](mesh_supported_matrix.md) and in the NodeWaypoint UDP/DTLS limitation above.

Column key: **Sidecar same-cluster** = Sidecar egress over plain SVID-mTLS HTTP/2 to the peer sidecar's `:15006`; **Ambient same-cluster** = Ambient/Waypoint egress over HBONE (HTTP/2 CONNECT over mTLS) to the peer's `:15008`; **Cross-cluster Sidecar / Ambient** = client-side cross-cluster egress through the east-west SNI-passthrough gateways; **SD bridge** = non-mesh gateway modes resolving mesh workloads via `service_discovery.provider: mesh` and dispatching over the configured destination topology's transport tag.

| Protocol | Sidecar same-cluster (mesh-mTLS `:15006`) | Ambient same-cluster (HBONE `:15008`) | Cross-cluster Sidecar (east-west gateway) | Cross-cluster Ambient (east-west gateway) | Gateway-to-mesh SD bridge (`provider: mesh`) |
|---|---|---|---|---|---|
| HTTP/1.1 | **Supported** — per-service/per-port SVID-mTLS routes, identity-pinned; fail-closed, never plaintext [1] | **Supported** — per-service HBONE routes, capability-probe-gated, identity-pinned [1] | **Supported** — all HTTP-family service ports (per-port `p<port>` SNI alias, issue #2010 phase 3); fail-closed (502) on missing SNI override / trust domain / gateway [2] | **Supported** — all HTTP-family service ports (per-port SNI alias); per-remote-pod targets via the gateway dial-override [3] | **Supported** — `mesh.mtls` (+ authority host/port tags) or `mesh.hbone` targets; poll-interval refresh; sidecar and ambient paths bridge remote-cluster workloads through east-west gateway targets when bridgeable (all HTTP-family ports via per-port SNI alias; otherwise fail-closed) [4] |
| HTTP/2 | **Supported** — same HTTP-family egress; both frontend flavors dispatch over the topology's HTTP/2-based transport [1] | **Supported** [1] | **Supported** — same all-HTTP-family-ports / per-port-SNI-alias bounds [2] | **Supported** [3] | **Supported** [4] |
| gRPC | **Supported** — native gRPC skips the direct-dial gRPC pool and rides the SVID-mTLS HTTP/2 egress path: identity-pinned, `te: trailers` re-synthesized, response streamed so `grpc-status` trailers relay end-to-end; replayable requests may retry on mesh-mTLS; fails closed with gRPC UNAVAILABLE (never a plaintext dial) when the transport cannot dispatch [5] | **Supported on every frontend** (issue #3284 for HTTP/3, #3728 for the standard H1/H2 frontend) — native gRPC rides a NESTED hyper HTTP/2 connection inside the authenticated HBONE CONNECT byte tunnel, identity-pinned, so `grpc-status` trailers, flow control, backpressure, deadlines, and cancellation relay end-to-end. Both frontends materialize it through the SAME `GrpcDispatchTransport`, so identity/policy/error behavior cannot diverge; only the GENERIC HTTP-family HBONE dispatch (HTTP/1.1 inside the tunnel) cannot carry those trailers, and native gRPC never takes it [5] | **Supported** — native gRPC rides the cross-cluster mesh-mTLS branch (east-west gateway dial + destination-FQDN SNI override + trust-domain-only verification) across **all HTTP-family service ports** (per-port SNI alias, phase 3), HTTP/2 end-to-end so `grpc-status` trailers relay across the two-trust-domain hop; replayable requests may retry on mesh-mTLS; fail-closed (gRPC UNAVAILABLE, never a plaintext dial) on a missing SNI override / trust domain or unsupported transport [5] | **Supported on every frontend** — the same nested-HTTP/2 HBONE transport over the cross-cluster dial (remote east-west gateway + destination-FQDN SNI override + trust-domain-only verification; the CONNECT authority is the real remote pod from `mesh.hbone_authority_host`), on the standard H1/H2 frontend as well as HTTP/3 [5] | **Supported for both topologies** — `mesh.mtls` targets dispatch exactly like the Sidecar column (same-cluster and cross-cluster) and `mesh.hbone` targets dispatch over the nested HTTP/2 connection inside the HBONE CONNECT tunnel, same-cluster and cross-cluster alike, on the standard H1/H2 frontend (issue #3728) and the HTTP/3 gRPC bridge (issue #3284) alike; both fail closed for malformed cross-cluster, ambiguous-transport, and unresolvable-identity targets [5] |
| WebSocket | **Supported** — RFC 8441 Extended CONNECT over SVID-mTLS to `:15006`; fail-closed, never plaintext [6] | **Supported** — bare HBONE CONNECT byte tunnel + inner HTTP/1.1 upgrade through the tunnel [6] | **Supported** — RFC 8441 Extended CONNECT over the cross-cluster mesh-mTLS dial (shared `MeshMtlsDialPlan`: east-west gateway dial + destination-FQDN SNI override + trust-domain-only verification) across **all HTTP-family service ports** (per-port SNI alias, phase 3); fail-closed on missing SNI/trust-domain or a failed upgrade, never a plaintext/wrong-SNI dial [7] | **Supported** — the upgrade rides the cross-cluster HBONE byte tunnel (dial the remote east-west gateway with a destination-FQDN SNI override + trust-domain-only verification; inner CONNECT `:authority` = the destination pod addr:app-port) + an inner HTTP/1.1 upgrade through the tunnel, mirroring the HBONE HTTP path via `get_ws_byte_tunnel`; fail-closed **before any dial** on a missing SNI override / trust domain / authority host, or on a failed upgrade [7] | **Supported** — the WebSocket-over-mesh dispatch keys on the same `mesh.mtls`/`mesh.hbone` target tags; a Sidecar OR Ambient SD-bridged east-west failover target now upgrades through the east-west gateway (cross-cluster) [6] [7] |
| Raw TCP | **Supported (Experimental)** — captured orig-dst matched strictly against `(service VIP, service port)`; fresh mesh-mTLS H2 CONNECT tunnel per captured stream; unmatched / unmaterialized pairs fail closed [8] | **Supported (Experimental)** — same strict orig-dst matching, relayed over the shared HBONE pool (capability-probe-gated) [8] | **Supported (Experimental)** — per-pod bare CONNECT over the east-west mesh-mTLS dial; `p<port>.<fqdn>` SNI + trust-domain-only verification; missing dial/authority metadata fails closed [2] [8] | **Supported (Experimental)** — per-pod HBONE byte tunnel through the east-west dial with the same per-port SNI/trust-domain scope [3] [8] | **Not part of the bridge** — SD targets feed HTTP-family dispatch only [9] |
| UDP | **Supported (Experimental)** — TPROXY capture → `udp`-marked mesh CONNECT over mesh-mTLS; unroutable datagrams dropped fail-closed [10] | **Supported (Experimental)** — per-pod-netns TPROXY producer captures source UDP inside each enrolled pod's netns, stamps trusted per-pod evidence on the HBONE CONNECT, and lets destination `mesh_authz` apply namespace/selector scope when the assertor and live workload binding validate; enrolled destination pod replies use a destination pod-netns relay socket when the registry maps the destination IP [10] [12] | **Supported (Experimental)** — the same cross-cluster Sidecar dial carries `udp`-marked, length-delimited datagrams [2] [10] | **Supported (Experimental)** — `get_datagram_tunnel` carries SNI/trust-domain overrides through the east-west gateway; full live TPROXY fixture remains as described in [10] [12] | **Not part of the bridge** [9] |
| DTLS-over-UDP | **Supported (Experimental), opaque** — a DTLS port is declared `protocol: UDP` and rides the same UDP datapath byte-for-byte; the mesh never terminates the DTLS session [11] | **Supported (Experimental), opaque** — rides the same Ambient per-pod evidence/authorization path and destination pod-netns relay socket where applicable; DTLS is framed byte-for-byte and never terminated [10] [11] [12] | **Supported (Experimental), opaque** — identical to the cross-cluster UDP cell; DTLS records are never terminated [2] [10] [11] | **Supported (Experimental), opaque** — identical to the cross-cluster UDP cell [3] [10] [11] [12] | **Not part of the bridge** [9] |

Notes (authoritative sections):

1. HTTP-family egress materialization per topology — the "Implementation status" / multi-port egress bullets under [Topologies → Sidecar](#sidecar). An outbound `404` for an un-materialized destination means no route was built, not that mTLS/HBONE is unavailable.
2. [Client-Side Cross-Cluster Egress (Sidecar)](#client-side-cross-cluster-egress-sidecar): HTTP-family traffic keeps the phase-3 base/per-port scheme. Raw-TCP and UDP use per-pod tunnel targets and explicit per-port aliases (`-tcp` / `-udp` when both share a number), with separate gateway dial and real-pod CONNECT-authority tags. All use trust-domain-scoped verification and fail closed without complete metadata.
3. [Client-Side Cross-Cluster Egress (Ambient / HBONE)](#client-side-cross-cluster-egress-ambient--hbone): per-remote-pod targets cover HTTP-family, raw-TCP, and UDP; L4 uses an explicit per-port SNI alias and the existing byte/datagram tunnel framing.
4. [Gateway Mesh Service Discovery](#gateway-mesh-service-discovery) and [Gateway-to-Mesh Bridge](#gateway-to-mesh-bridge): `topology: ambient` targets carry `mesh.hbone`, `topology: sidecar` targets carry `mesh.mtls` + `mesh.mtls_authority_host` (and `mesh.mtls_authority_port` for multi-port destinations). The two transports are not interchangeable — a topology mismatch fails closed with a 502 at dispatch. Target lists refresh on the provider's poll interval (default 30s). Sidecar-path remote-cluster workloads bridge to east-west gateway failover targets through the same shared core as the mesh-mode Sidecar cross-cluster column [2] (plus the SD-bridge `mesh.mtls_authority_host` tag), for the upstream's **selected** HTTP-family port — any HTTP-family port, via its per-port SNI alias (a single-HTTP-port service uses the base FQDN); a **non-HTTP-family** selected port, a snapshot without `mesh.multi_cluster`, or a remote group with no matching east-west gateway stays skipped fail-closed. Ambient-path remote-cluster workloads bridge through the mesh-mode Ambient per-pod HBONE core [3] when a gateway is declared for the workload network (or a catch-all gateway applies): the target identity is synthetic, the inner CONNECT authority stays the remote pod addr, and `mesh.hbone_dial_host` / `mesh.hbone_port` carry the gateway. Direct remote pod-IP Ambient targets remain only as a flat-network fallback when no gateway is declared for that workload network and no applicable catch-all gateway (a candidate whose `sni_hosts` claim the base FQDN **or** the dialed per-port alias, plus a trust-domain match, for the destination) exists — an exact-network declaration is authoritative fail-closed even when it cannot route the destination, while a non-candidate catch-all leaves the fallback in place.
5. **Same-cluster Sidecar**: a native-gRPC request (content-type `application/grpc*`) whose LB-selected target carries `mesh.mtls` skips the direct-dial gRPC branch in `src/proxy/mod.rs` and dispatches through the generic mesh-mTLS gate + pool (`proxy_to_backend_mesh_mtls`): hyper HTTP/2 end-to-end with pinned peer SVID, a streamed or once-finalized replayable request body, `te: trailers` re-synthesized after the hop-by-hop strip (the gRPC HTTP/2 mapping mandates it), and the streaming H2 response arm relays backend trailers (`grpc-status`) after hop-by-hop filtering — the same trailer semantics as the direct gRPC pool. The gRPC receive limit (`FERRUM_MAX_GRPC_RECV_SIZE_BYTES`) caps the request body — declared content-length and streamed bytes alike — with the direct pool's Trailers-Only RESOURCE_EXHAUSTED on overflow, and a `grpc-status` trailer maps into circuit-breaker / passive-health / adaptive-concurrency outcome recording at body EOF exactly like the direct pool (an HTTP 200 + `grpc-status: 14` records as the mapped 503, not a success; Trailers-Only errors are mapped from the header-borne status; a translated gRPC-Web stream is classified from the native trailer before it is body-framed). The client `grpc-timeout` is honored with the direct pool's regimes: for streaming native gRPC and translated gRPC-Web it bounds the response body by an absolute deadline anchored at request receipt; if another response policy explicitly selects the compatible buffered gRPC-Web fallback, the deadline is capped by `backend_read_timeout_ms` and shared across send + body collection. Timeouts return the Trailers-Only DEADLINE_EXCEEDED shape before client-visible translation. Native-gRPC responses are **never buffered** on this path (a buffered mesh response cannot re-emit wire trailers): if buffering is still demanded after the content-type refinement (explicit `response_body_mode: buffer`, or a plugin that needs the response body for this content-type) the request fails closed with a Trailers-Only gRPC UNAVAILABLE — the direct (non-mesh) gRPC path keeps its buffer-with-trailers behavior unchanged. Retry and request-body policy may prebuffer the upload; only an unavailable gateway SVID, malformed identity/SNI/trust metadata, or an unsupported secured transport blocks dispatch. **Same-cluster Ambient**: native gRPC to a `mesh.hbone` target does NOT use the generic HTTP-family HBONE dispatch (which speaks HTTP/1.1 through the CONNECT byte tunnel and has no trailer path — see the WebSocket-over-HBONE inner-HTTP/1.1 note [6]). It instead resolves the shared `GrpcDispatchTransport` inside the native-gRPC branch and runs a NESTED `hyper::client::conn::http2` client over the same authenticated byte tunnel. The HTTP/3 bridge wired that transport first (issue #3284); the standard H1/H2 frontend reuses the identical resolver, dial plan, and error mapping (issue #3728), so the same route behaves identically on both frontends — see the shared-transport paragraph at the end of this note. **Cross-cluster**: for **Sidecar** (`mesh.mtls`), a WELL-FORMED cross-cluster target (carrying the `mesh.eastwest_sni` override AND `mesh.trust_domain`) now falls through onto the mesh-mTLS pool's cross-cluster branch exactly like a same-cluster `mesh.mtls` target (issue #2010), so `grpc-status` trailers relay across the east-west hop; a MALFORMED one (missing SNI / trust domain) fails closed with a clean gRPC UNAVAILABLE rather than reaching a 502. For **Ambient** (`mesh.hbone`) BOTH frontends dispatch it over the nested-HTTP/2 HBONE transport's cross-cluster dial (see [Client-Side Cross-Cluster Egress (Ambient / HBONE)](#client-side-cross-cluster-egress-ambient--hbone)); an incomplete east-west dial plan still fails closed pre-dial. The classifier (`classify_grpc_mesh_dispatch`) is the single predicate every gRPC surface consults. A native-gRPC request initially selected onto mesh-mTLS may retry with the same trailer-preserving transport; the native-gRPC retry loop re-resolves the transport per attempt and may rotate between direct and HBONE targets (both are hyper HTTP/2 with an identical trailer contract), while a rotation onto a Sidecar mesh-mTLS or Unix target still fails closed rather than switching response pipelines mid-loop. **Pass-through gRPC-Web** frames its trailers inside the response body (no HTTP/2 trailers needed), so it falls through and rides every mesh transport like plain HTTP. gRPC-Web the `grpc_web` plugin **translated** is wire-native gRPC by dispatch time, so to an Ambient `mesh.hbone` target (same-cluster or cross-cluster HBONE) it takes the SAME nested-HTTP/2 HBONE transport as native gRPC rather than the generic HTTP-family path that would drop its trailers; with the `grpc_web` translation plugin on a Sidecar mesh-mTLS route (same-cluster or cross-cluster), binary- and text-mode gRPC-Web use the same trailer-preserving path after any required request decoding/finalization, and the shared adapter converts terminal HTTP/2 trailers into the client-visible gRPC-Web frame. If another response policy explicitly requires buffering, the existing whole-body transform remains the compatible fallback and preserves the folded terminal metadata. **Shared mesh gRPC transport (both frontends)**: the H3→gRPC bridge dispatches BOTH mesh transports, same-cluster and cross-cluster, on both the buffered/retryable path and the channel-backed streaming path (issue #3284); the standard H1/H2 native-gRPC branch dispatches the Ambient HBONE transport through the SAME resolver (`proxy::resolve_grpc_dispatch_transport` → `GrpcDispatchTransport::for_target`) on its split, mixed, fully-streaming, and retry paths (issue #3728). A Sidecar `mesh.mtls` target still reaches the generic mesh-mTLS path on the H1/H2 frontend (it falls through before the native branch) and is defensively refused inside it. A Sidecar `mesh.mtls` target rides the SAME SVID-mTLS HTTP/2 pool as the H1/H2 frontend (pinned peer same-cluster; east-west gateway dial + destination-FQDN SNI override + trust-domain scope cross-cluster), and its request `:authority` is resolved by the same shared resolver the generic mesh-mTLS path uses, so the peer sidecar's materialized inbound route (including the multi-port service-port rewrite) matches identically. An Ambient `mesh.hbone` target rides a NESTED hyper HTTP/2 connection run over the authenticated HBONE CONNECT byte tunnel: the outer hop is the ordinary pooled Ambient dial (`:15008` / `mesh.hbone_port`, identity-pinned same-cluster; remote east-west gateway + SNI override + trust-domain scope cross-cluster), the destination's transparent relay byte-copies the tunnel to the local app socket, and the inner connection is therefore an ordinary h2c connection to the gRPC server. This is why HBONE gRPC works at all: the generic HTTP-family HBONE dispatch runs `hyper::client::conn::http1` inside the tunnel and would drop the trailers, whereas the gRPC transport runs `hyper::client::conn::http2` over the same bytes — which is exactly why native gRPC is routed to this transport instead of falling through to that path on either frontend. The inner connection is 1:1 with the CONNECT stream (one per RPC, like the WebSocket-over-HBONE and raw-TCP-over-HBONE egress paths), so there is no inner-connection cache to poison across SVID rotation; its inner request `:authority` is the destination's own app address:port (or a preserved client `Host`), matching the HBONE inner-request Host fallback, and its CONNECT baggage asserts this gateway's own SVID (a north-south client, H1/H2 or H3 alike, is a caller — not an authenticated mesh peer whose principal could be forwarded). Because a cross-cluster Ambient `target.host` is a scoped SYNTHETIC identity that is not a valid URI authority, the transport takes only the path and query from the gateway-built backend URL and rebuilds the request line — the gRPC analogue of the generic path's `rewrite_backend_url_authority_host`. Either way it is HTTP/2 end-to-end, so framing, `grpc-status` trailers, streaming backpressure, `grpc-timeout` deadline propagation, and cancellation all behave exactly as they do on the direct gRPC pool. Retry rotation re-resolves the transport per attempt: rotating onto a mesh-tagged target re-dials over ITS own dial plan, and rotating onto an undispatchable one fails closed. Undispatchable targets still fail closed before any direct dial — a cross-cluster target with no transport tag, a cross-cluster `mesh.mtls` target missing its SNI override / trust domain, a corrupted target declaring BOTH `mesh.mtls` and `mesh.hbone` (mutually exclusive topologies, so either choice would be a guess), and any target whose pinned `mesh.spiffe_id` / HBONE dial-host / CONNECT-authority-host tag is present but unusable — with a Trailers-Only gRPC UNAVAILABLE whose message names the failed contract but never the target's identity metadata. The H3→HTTP plain-bridge, plain requests selected for the native-H3 backend pool, and the H3 WebSocket bridge are unchanged and still fail closed for ANY mesh-tagged target: plain HTTP gets a 502 with `gateway-error-reason` and the WebSocket bridge refuses the upgrade with the same 502 shape (note [6]).
   For the Sidecar mesh-mTLS response path in note 5, the operator `backend_read_timeout_ms` window begins only after pool acquisition and `sender.ready()` complete. The receipt-anchored client RPC deadline still covers acquisition and readiness, so slow pool work cannot evade the client's total ceiling while also no longer consuming the operator's response-read allowance.

6. WebSocket egress bullet under [Topologies → Sidecar](#sidecar) ("WebSocket egress (Ambient and Sidecar)"): the dispatch is keyed on the `mesh.mtls`/`mesh.hbone` target tags, identity is pinned, and a mesh-tagged WebSocket target that cannot dispatch over its secured transport fails the upgrade — it is never dialed in plaintext. The H1/H2 frontend re-evaluates the mesh WebSocket fork per connect attempt (including retry rotations); the HTTP/3 WebSocket bridge has no mesh WebSocket transport at all, so it refuses a mesh-tagged target — on the initial selection and on every connect-retry rotation — before dialing, failing the upgrade with a 502 + `gateway-error-reason`.
7. Cross-cluster WebSocket is supported on **both** topologies (issue #2010). **Sidecar** opens an RFC 8441 Extended CONNECT over the cross-cluster mesh-mTLS dial resolved by the shared `MeshMtlsDialPlan` (east-west gateway dial + `mesh.eastwest_sni` SNI override + trust-domain-only verification), the WebSocket analogue of the gRPC/HTTP cross-cluster path. **Ambient** rides the cross-cluster HBONE byte tunnel + an inner HTTP/1.1 upgrade through it, with `get_ws_byte_tunnel` threading the same SNI-override / trust-domain scope as the HBONE HTTP path (`proxy_to_backend_hbone`); the inner CONNECT `:authority` is the destination pod addr:app-port. Both fail the upgrade closed on a malformed cross-cluster target (missing SNI / trust domain), never a plaintext / wrong-SNI dial. See [Client-Side Cross-Cluster Egress (Sidecar)](#client-side-cross-cluster-egress-sidecar) and [(Ambient / HBONE)](#client-side-cross-cluster-egress-ambient--hbone).
8. Raw-TCP egress bullet under [Topologies → Sidecar](#sidecar) ("Raw-TCP egress (original-destination routing, Ambient and Sidecar)"), including the direct pod-IP / headless second index. "Experimental" is the product contract's tier for stream-family egress ([docs/mesh_supported_matrix.md](mesh_supported_matrix.md)).
9. The SD provider publishes ordinary `UpstreamTarget` entries consumed by the gateway's HTTP-family outbound pools ([Gateway Mesh Service Discovery](#gateway-mesh-service-discovery), [Gateway-to-Mesh Bridge](#gateway-to-mesh-bridge)); the raw-TCP and UDP mesh datapaths are original-destination / TPROXY **capture** paths that exist only on mesh-mode capture listeners (see the raw-TCP / UDP egress bullets under [Topologies → Sidecar](#sidecar)).
10. Raw-TCP / UDP egress bullet under [Topologies → Sidecar](#sidecar) plus the "UDP TPROXY capture" section under Capture Modes: UDP egress is dual-transport (Ambient over HBONE `:15008`, Sidecar over mesh-mTLS `:15006`). Both topologies have a source-capture producer: **Sidecar** via the injector's pod-netns TPROXY init rules + current-netns listener; **Ambient** via `NetnsUdpCaptureManager`, which installs the rules and binds capture/reply sockets inside each enrolled pod netns. For Ambient, the node-agent registry now attests the workload SPIFFE ID next to the pod UID; the per-netns producer stamps both as `source.principal` / `source.pod_uid` baggage on the existing authenticated `udp` CONNECT. Destination `mesh_authz` honors pod scope only when (1) the mTLS peer is in the same `trusted_hbone_assertors` allow-list used by TCP/HTTP baggage, (2) the asserted principal passes the existing trust-domain/alias check, and (3) the live slice maps that exact, unambiguous pod UID to the same SPIFFE ID. It then evaluates the **union** of the source-scoped namespace/selector policies for that workload with the destination-scoped policy set that normal (non-UDP) inbound HBONE evaluates (the same policies protecting the destination workload, such as a DENY-all in the service namespace), in a single deny-first pass so a destination DENY/ALLOW still runs for the `udp` CONNECT. Missing/malformed evidence, a missing/duplicate workload binding, a principal/UID mismatch, or baggage from an untrusted peer discards the source stamp and evaluates **mesh-wide source policies only** (still unioned with the destination policy set); it never creates a broader grant from the stamp. **This does not change NodeWaypoint UDP/DTLS**, whose shared-socket/cookie limitation remains mesh-wide-only/disabled under enforcing scoped policy as documented above. The privileged `netns-capture-live` gate exercises the source-capture path through HBONE to a host-loopback echo and verifies the transparent return source; the enrolled-destination two-pod fixture (destination pod-netns relay) remains the residual tracked on [#3621](https://github.com/ferrum-edge/ferrum-edge/issues/3621) — see [12].
11. "DTLS passthrough (F3 §3.3 Stage 5) — opaque, never terminated" under the UDP TPROXY capture section: there is no separate `Dtls` `AppProtocol`; the inner DTLS handshake/records are framed and relayed byte-for-byte, with the outer mesh hop's confidentiality coming from HBONE / mesh-mTLS. East-west pod→peer only; external **DTLS** egress via the EgressGateway stays out of scope (external `protocol: UDP` ServiceEntry egress is supported — see "External UDP egress (EgressGateway)").
12. **Enrolled Ambient destination pod UDP relay.** `handle_hbone_udp_request` resolves the CONNECT authority, checks the open-relay guard, then maps the resolved destination IP through the node-agent registry. When the IP belongs to an enrolled local pod, the destination-side UDP relay socket is created and connected **inside that pod's netns**; delivery to the app and the app's reply are pod-local, so the pod's own OUTPUT `! --dst-type LOCAL` capture rule does not re-capture the reply. If the registry hit cannot be opened safely, the tunnel fails closed with a 502 rather than falling back to the host-netns relay socket. Non-enrolled and loopback destinations keep the host/current-netns socket path. `functional_mesh_live_source_capture_udp_manager_hbone_round_trip` exercises source-capture through HBONE to a host-loopback echo only; live two-pod `netns-capture-live` coverage for the full Ambient source-capture → HBONE → enrolled-destination relay path is tracked on [#3621](https://github.com/ferrum-edge/ferrum-edge/issues/3621).

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

When `FERRUM_MESH_SIDECAR_ENFORCED=true`, the `MeshSlice` projection narrows `services`, `service_entries`, `destination_rules`, and the projected VirtualService L4 (TCP/TLS) route proxies to the set admitted by the workload's applicable `Sidecar`. An L4 route is kept only when its backend host **and** its backend port are both admitted by the `Sidecar`'s egress scope. When `false` (the default), `Sidecar` resources are still parsed and persisted in `MeshConfig` for future use, but slice narrowing is skipped and behavior is identical to today.

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

In the `Sidecar`-selection order just above, the **root workload-scoped** tier — a `Sidecar` in the Istio root namespace (`FERRUM_K8S_ISTIO_ROOT_NAMESPACE`, default `istio-system`) carrying an explicit `workloadSelector` that matches this workload — is ranked **above** the **namespace-default** tier, a selector-less `Sidecar` in the workload's *own* namespace. Istio orders these the other way: it resolves the workload's own namespace completely before consulting the root namespace at all.

The divergence is deliberate and security-oriented. The root namespace belongs to the mesh operator and a tenant cannot write to it, so ranking the operator's **targeted** rule above a tenant's **catch-all** means a namespace-wide default dropped into a tenant namespace cannot displace a mesh-wide rule aimed at specific workloads. A tenant can still override with an equally specific rule: a `workloadSelector` `Sidecar` in their own namespace still wins the top (workload-scoped) tier.

Since this ordering now also decides the workload-scoped `outboundTrafficPolicy`, it controls whether the outbound registry gate is armed — not just egress scoping. Concretely: a root-namespace `Sidecar` selecting `app: payments` with `mode: REGISTRY_ONLY` keeps the gate armed for those pods even if the `payments` namespace also holds a selector-less `Sidecar` with `mode: ALLOW_ANY`.

#### Ambiguous workload labels resolve to the strictest applicable policy

When several workloads share one SPIFFE id with **divergent** label sets and the data plane supplied no explicit `FERRUM_MESH_WORKLOAD_LABELS`, the slice's labels are only the *intersection* of those sets (the slice is marked `labels_ambiguous`). A `workloadSelector` `Sidecar` that really does select one of those workloads can then fail to match that intersection.

Rather than let that silently fall through to a laxer tier, Ferrum resolves the policy against **each** candidate label set and keeps the strictest result, ranked `REGISTRY_ONLY` > *inherit* > `ALLOW_ANY` (*inherit* outranks `ALLOW_ANY` because the mesh-wide tier it defers to may itself be `REGISTRY_ONLY`). The fold includes the intersection-derived answer, so ambiguity can only ever **tighten** the gate, never relax it; the result is order-independent, so precedence stays deterministic. When ambiguity actually changes the outcome, the control plane emits a `warn!` naming both the intersection result and the resolved one. Supplying explicit workload labels — or distinct SPIFFE ids — resolves it exactly.

### What `ALLOW_ANY` does and does not relax

`ALLOW_ANY` turns off **only** the known-destination registry gate: unknown HTTP-family `Host` values and unknown stream destinations are passed through to the normal routing path instead of being rejected. It is not an escape hatch from anything else. Still fully in force under `ALLOW_ANY`:

- **Sidecar `egress` scope narrowing** — a destination outside the workload's egress scope is still absent from the slice, so it does not route.
- **`mesh_authz`** — `AuthorizationPolicy` DENY/ALLOW evaluation is unchanged, on both the HTTP and stream paths.
- **Identity and TLS** — mesh-mTLS/HBONE peer SVID pinning, PeerAuthentication mode, and trust-domain verification are unchanged; a mesh-tagged target that cannot dispatch over its secured transport still fails closed with `502`.
- **The HBONE/mesh-mTLS inbound open-relay guard** — an authenticated CONNECT still relays only to loopback or a slice-declared in-mesh workload address.
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
  is excluded — `ingress[]` stream listeners are TCP and UDP behavior is
  unchanged.
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
  relay. With no declared `ingress` block, ordinary Ambient/Waypoint relay
  behavior is unchanged.
- The remap is **`Sidecar`-topology only**, matching the inbound materializer it
  gates. `FERRUM_MESH_SIDECAR_ENFORCED` is topology-independent, so an
  Ambient/Waypoint proxy in a mesh that also runs sidecars can receive a slice
  whose applicable `Sidecar` declares `ingress[]`. Those topologies materialize
  no inbound routes at all and serve every authenticated inbound through the
  transparent relay, so the declaration marker is not back-projected there and
  their relay behavior is unchanged.

#### Live datapath coverage

Two `#[ignore]`d functional tests in `tests/functional/functional_mesh_mode_test.rs`
drive the shipped `ferrum-edge` binary over this lane (data-plane CI shard):

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

A `unix://` `defaultEndpoint` names a Unix-domain **stream** socket the co-located application listens on. Ferrum admits the path, then dispatches matching requests over a `tokio::net::UnixStream` instead of a TCP connection. Those connections are **pooled** — HTTP/1.1 carriers are reused across requests and one h2c carrier multiplexes concurrent RPCs (see "Connection pooling" below); only a WebSocket upgrade takes a dedicated, non-reusable connection. Its schema-compatible loopback `host:port` carrier is never resolved or dialed and is not evaluated by `FERRUM_BACKEND_ALLOW_IPS`; the socket-specific containment, ownership, inode, and peer-credential gates below are the authoritative egress policy for this local transport.

#### Containment is mandatory and off by default

A `Sidecar` is operator-authored config, and the socket path names a local filesystem object the Ferrum process — often the most privileged process in the pod — would connect to. An unconstrained path is therefore a **local privilege boundary**: `unix:///var/run/docker.sock` would hand every request-path client the container runtime's API.

So the feature is gated on an explicit allowlist with **no default**:

| Setting | Default | Meaning |
|---|---|---|
| `FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS` | *empty* | Absolute directories a socket may live under. **Empty refuses every `unix://` endpoint.** No built-in `/run` or `/var/run` allowance. |
| `FERRUM_MESH_UNIX_SOCKET_ALLOWED_UIDS` | *empty* | Admitted owner uids. Empty admits **only** the Ferrum process's own effective uid. |

A root must be absolute, normalized, and not bare `/` (which would contain everything and make the allowlist a no-op); a malformed entry **fails startup** rather than being silently skipped. Containment is a whole-**component** match and requires a strict descendant, so `/var/runner/app.sock` is *not* inside `/var/run`, and the root directory itself is never dialable.

#### The two-stage gate

**Translation / materialization** (`crate::util::unix_socket::admit_configured_path`) applies syntax plus containment, with no filesystem I/O — a control plane does not share the workload's filesystem, so the *syntax* half runs CP-side (`MeshSidecarIngress::resolve`, and the `Sidecar` status writer's `deferred_fields` classification) while **containment is a data-plane policy** applied by `ResolvedIngressListener::endpoint_is_valid`/`backend` when the slice is materialized. A path is syntactically admitted only when it is absolute; free of `.`, `..`, and empty (`//`) components; not a directory (no trailing `/`); free of NUL bytes, ASCII control characters, and surrounding whitespace; and at most **103 bytes** — the usable `sockaddr_un.sun_path` budget on the smallest supported platform (macOS/BSD reserve 104 including the terminating NUL; Linux allows 108), so a path admitted on one platform always dials on another. Nothing is normalized or trimmed: the byte sequence dialed is exactly the one written. Abstract (Linux `\0`-prefixed) and `@`-prefixed sockets are refused — Istio does not define them for `defaultEndpoint`.

Because the CP-side `ingress_modeled` count cannot see the data plane's allowlist, a listener reported as modeled by the `Sidecar` status writer is still subject to data-plane containment; a refusal there is logged by the data plane and the listener simply never materializes.

**Dial time** (`admit_socket_for_connect`) re-runs the whole gate — the value may have crossed a CP/DP, file, or xDS boundary since — and adds the facts that only exist at connect. It does **not** return a yes/no: it returns the **checked identity** (`AdmittedUnixSocket` — the canonical path, the owner uid, and the `(dev, ino)` of the exact object inspected), and that identity, not the configured pathname, is what gets dialed.

- the path is `canonicalize`d, which fully resolves symlinks, `..`, and mount points; the **resolved** path must itself be syntactically dialable and must land inside an allowed root. This is what stops a symlink planted inside an allowed directory from redirecting the dial to `/var/run/docker.sock`; a symlink that stays *inside* a root is fine;
- the resolved object must be a Unix-domain **socket** (a regular file, directory, or FIFO is refused);
- its owner uid must be admitted — `FERRUM_MESH_UNIX_SOCKET_ALLOWED_UIDS` when set, otherwise the Ferrum process's own effective uid;
- the socket must not be group- or world-writable;
- **every directory from the socket's parent up to and including the matched containment root** must be a real directory (not a symlink, not another file type), owned by a trusted uid, and not group/world-writable without the sticky bit. Checking only the immediate parent is not enough: a writable ancestor lets an attacker rename or replace a whole checked subtree without ever touching the parent that was inspected. Above the matched root the walk stops — the root is the operator's declared trust boundary, and whoever can rewrite it can also rewrite the configuration that named it.

The **trusted directory owners** are uid 0 (root can rewrite any of these checks regardless, so treating it as untrusted would only produce false refusals), the Ferrum process's own effective uid, and every uid in `FERRUM_MESH_UNIX_SOCKET_ALLOWED_UIDS` (those name the co-located application, which is the intended peer). Nothing else.

**The sticky bit, stated exactly.** Sticky (`/tmp` semantics) only stops a user from renaming or unlinking an entry they do *not* own; the directory's owner and the entry's owner are always exempt. Sticky is therefore accepted **only** in combination with the two ownership rules above — every directory on the chain is trusted-owned and the socket entry itself is owned by an admitted uid — which together are what proves no untrusted directory owner and no untrusted group member can rename or replace a checked descendant. Sticky alone never admits anything.

**TOCTOU.** A filesystem check and the subsequent `connect(2)` cannot be made atomic through the POSIX path API. Ferrum closes the gap on the *identity* side instead of leaving the window open: the dial targets the canonical path from the checked identity, and then — after `connect(2)` returns and **before a single request byte is written** — the transport asserts both of:

1. the **connected peer's uid equals the checked socket owner's uid, exactly**. Not "some uid in the allowlist": the allowlist decides which sockets may be admitted at all, this decides that the connection reached the very socket that was admitted. The credential is the kernel's, taken from the established connection (`SO_PEERCRED` on Linux — a `struct ucred` captured when the connection was established and never updated afterwards, so on the connecting side it is the credential set of the process that called `listen(2)`);
2. the checked path still names the same `(dev, ino)`, file type, and owner. Unlinking and re-binding a socket always produces a new inode, so a swap inside the window is visible even when the replacement is owned by the same uid.

Either failure — and an *unavailable* credential, which is identity ambiguity and therefore also a failure — closes the connection unused. There is no fallback to TCP, to the placeholder `host:port`, or to a weaker check.

**Platform contract.** The connected-peer check is enforced on Linux/Android (`SO_PEERCRED`), Apple/FreeBSD/DragonFly (`getpeereid(3)`), NetBSD (`LOCAL_PEERCRED`), and illumos/Solaris (`getpeerucred(3)`). Any other Unix target — and any non-Unix target — **refuses Unix backends outright** rather than dialing with a weaker guarantee than Linux enforces. Sidecar mesh deployments are Linux-only in practice, so this is a compile-time posture rather than a live limitation.

Every refusal is a pre-wire, gateway-side policy decision: `ErrorClass::DispatchPolicyRejected` (health-neutral, not retried), surfaced as a `502` whose body never echoes the operator-supplied path. A genuine dial failure — missing socket, wedged app, `ECONNREFUSED` — stays an ordinary backend-down signal (`ConnectionRefused` / `ConnectionTimeout`), so the circuit breaker and passive health see it.

#### Protocol matrix

The wire protocol is resolved **once at translation** from the declared `port.protocol` and carried on its own reserved tag (`mesh.unix_socket_h2c`) as the explicit string `"true"` or `"false"`. Dispatch never infers it: a missing or malformed marker is refused so a partially stripped h2c carrier cannot silently downgrade to HTTP/1.1.

| Declared `port.protocol` | Socket wire protocol | Status |
|---|---|---|
| `http` | HTTP/1.1 | Supported. Streaming request and response bodies, size ceilings, and timeouts are the loopback-TCP path's. |
| `http2`, `https` | h2c prior-knowledge HTTP/2 | Supported. (`https` is mapped to `Http2` by the Istio translator; a `defaultEndpoint` is a plaintext hop to a co-located app, so TLS is not re-originated onto the socket and the request `:scheme` is `http`.) |
| `grpc` | h2c prior-knowledge HTTP/2 | Supported, natively: full request/response streaming, the receipt-anchored client deadline, upstream cancellation on deadline expiry, `te: trailers` regeneration, and terminal `grpc-status`/`grpc-message` **trailers**. |
| gRPC request to an `http`-declared socket | — | **Refused** with gRPC `UNAVAILABLE` (14). HTTP/1.1 cannot carry gRPC trailers, and a downgrade would silently corrupt the RPC. Declare the listener `GRPC` or `HTTP2`. |
| WebSocket upgrade to an `http`-declared socket | HTTP/1.1 (RFC 6455) | Supported (issue #3732). The upgrade is spoken over the **admitted** `UnixStream` by a dedicated, non-reusable HTTP/1.1 carrier; admission, containment, owner/mode/type, inode identity, and peer-UID verification all complete inside the one establishment deadline and **before the first upgrade byte**; the upgrade exchange itself is bounded by what *remains* of that same deadline, not by a second full `backend_connect_timeout_ms` timer. Frame/message limits, origin and plugin gates, `101` + exact `Sec-WebSocket-Accept` validation, bytes coalesced with the handshake response, idle timeout, admission permits, connection accounting, circuit-breaker/passive-health/load-balancer accounting, cancellation, and graceful shutdown are the TCP path's — the same `run_websocket_proxy` relay serves both. |
| WebSocket upgrade to an `http2`/`grpc`-declared socket | — | **Refused** `502`. That form would need RFC 8441 Extended CONNECT over the h2c Unix carrier, which is not implemented. It is refused rather than downgraded to an HTTP/1.1 upgrade the h2c-only app cannot answer, and never falls back to the target's placeholder `host:port` (the gateway's own inbound listener port — a fallback would loop the proxy into itself). Gateway-side and pre-dial: `ErrorClass::DispatchPolicyRejected`, health-neutral and not retried. |
| Retry dispatch (reqwest-backed) | — | **Refused** `502`. The materialized ingress proxies configure no retry policy, so this is a defensive gate, not a live limitation. |
| HTTP/3 frontend | — | **Refused**, WebSocket included. The H3 bridge has no Unix transport; mesh capture is TCP-only, so an H3 frontend cannot reach a Sidecar ingress listener in practice. H1 and H2 frontends both serve Unix-backed WebSockets (an H2 frontend's RFC 8441 Extended CONNECT is relayed to the backend's HTTP/1.1 upgrade, exactly as on TCP). |
| Non-HTTP-family `port.protocol` (`tcp`/`tls`/…) | — | Deferred before any listener exists (raw-TCP inbound has no Host/route). |

The h2c path is not a second implementation of the gRPC-over-HTTP/2 contract: it reuses `proxy_to_backend_mesh_mtls`'s dispatch body with the pooled SVID-mTLS sender swapped for a pooled h2c `UnixStream` sender, so gRPC flavor detection, deadline handling, the never-buffer-native-gRPC rule, and streaming trailer forwarding are literally the same code on both transports and cannot drift. Every h2c buffer is bounded: a 1 MiB initial stream window, a 2 MiB connection window, a 16 KiB max frame size, and a capped reset-stream table, on top of the request/response body ceilings the caller already applies.

#### Timeouts, lifecycle, and the transport gate

The connect is bounded by the proxy's `backend_connect_timeout_ms` (5s for a materialized ingress listener), falling back to 5s if unset; exceeding it yields a `504` with `ErrorClass::ConnectionTimeout`. Read/write bounds and request/response body ceilings are the same ones the loopback-TCP path applies.

**One budget per establishment, opened before any work.** That deadline is created as an absolute instant at the very top of a checkout — before the pool's amortized idle sweep (which scans the pool's maps and `stat`s socket paths), before path admission, before any pool creation-lock wait, before `connect(2)`, before the protocol handshake, and (for a WebSocket) before the RFC 6455 upgrade exchange — and every one of those stages is bounded by that same instant. No stage derives a second budget from `backend_connect_timeout_ms`, so an establishment can never consume two or three full setup budgets. The synchronous maintenance and admission `stat`s cannot be preempted while they execute, but the time they cost is charged all the same: the next bounded await resolves immediately once the deadline has passed. An unreasonable operator duration still fails closed rather than becoming an effectively unbounded wait: a `backend_connect_timeout_ms` past the 24-hour ceiling config validation already enforces on timeout fields, or one the platform clock cannot represent, is refused at the dial with the ordinary connect-timeout response. Every value an admitted configuration can produce is unaffected, and `0` keeps its documented meaning (the 5s Unix default).

On an h2c socket that one budget is **end-to-end over establishment**, and establishment means the **peer's** HTTP/2 connection preface, not the client's. Hyper's h2c `handshake()` writes the client preface and never reads, so it completes against a peer that merely accepted the socket; the dial therefore also waits for the peer's own initial `SETTINGS` frame (RFC 9113 §3.4) — the same observation the gRPC pool's h2c path uses — before the sender is handed to dispatch. Admission, `connect(2)`, the client handshake, and that wait share the single budget captured before the connect, so a slow connect cannot re-arm a fresh one. This is what stops a co-located app that accepts and then wedges from pinning a request task indefinitely when the client supplied no gRPC deadline and no backend read timeout is configured. A peer that hangs up before completing its preface is a `502` with `ErrorClass::ConnectionPoolError` (evidence about the app, health-affecting, pre-wire and therefore replay-safe); exceeding the budget is the `504` above.

#### Connection pooling

Admitted connections are **pooled** (issue #3731) by `src/proxy/unix_backend_pool.rs`. Pooling never weakens admission: every **new physical connection** still runs the full containment / ownership / file-type / inode / peer-UID gate under the single establishment deadline above.

Connections are keyed by a **structured** transport identity — namespace, proxy id, effective upstream id, canonical resolved path, the admitted `(dev, ino, owner_uid)`, and the wire protocol. Retirement compares those fields exactly; there is deliberately no substring matching on a formatted key anywhere in the pool, because a substring rule on a security-sensitive retirement can both under- and over-retire.

Before **every** checkout the path is re-admitted and its live `(dev, ino, owner_uid)` compared against the identity the pooled connections were admitted with. A mismatch — the socket file was replaced — retires every connection for that canonical path, across protocols and proxies, **before any further request byte is written**, and the caller re-admits and re-dials.

Per protocol:

- **h2c / native gRPC** — the multiplexable sender is shared, so concurrent RPCs ride one admitted connection's streams. Concurrent misses for one identity are coalesced behind a creation lock bounded by the same establishment deadline as the dial, so a burst opens one connection rather than N. A closed or GOAWAY carrier is evicted and replaced on the next checkout; a failed establishment leaves nothing pooled and is counted as a pool setup failure, not charged to the backend as a request failure.
- **HTTP/1.1** — an **exclusive** lease, kept for the whole exchange and returned to the idle set only after the **entire** response body has been read. That holds for buffered *and* streaming responses. A buffered response reads the body inside the dispatch function and checks the carrier in there. When keep-alive reuse is enabled, a backend response that declares a `Content-Length` **within the gateway's eager-buffer cutoff** (`FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES`, default 64 KiB, and never a stream-mandated content type such as SSE) is forced onto that in-dispatch buffered path even if the proxy's `response_body_mode` is `stream` (mesh ingress's default): returning the carrier from the client-visible body's `Ready(None)` races a frontend `Connection: close` teardown that can drop the body without that terminal poll and otherwise force one dial per request. That cutoff is the same eager-buffer contract every other transport applies, and it is the boundary on purpose — buffering a larger declared length would make the retained bytes unbounded by that knob, fold an "unlimited" response ceiling down to the fail-closed per-response fallback (turning a previously streamable large response into a `502`), and multiply resident memory by concurrency against the shared response-buffer budget. A larger, chunked, or unknown-length streaming response is not buffered: the body leaves the dispatch function, so the lease travels with it, owned by the response body that holds the backend stream and released **only** from that body's clean end-of-stream. Every other terminal (a body error, a backend close, a client disconnect or cancellation, an early body drop, a read timeout, an aborted request, an expired client deadline, shutdown) drops the lease instead, which closes the connection — `Drop` never returns a carrier to the pool. The carrier is never handed to another request while a body is still streaming: the lease is the only handle on it and it is not in the idle set.

  Receiving response headers is never sufficient, and neither is hyper's own `SendRequest::ready()` on its own — h1 `can_write_head()` is already true while a response body is still being read, so readiness alone would re-pool a connection mid-body and pipeline the next request onto it. Readiness is used only as the *second* half of the check-in, after the caller has proven the body is complete, because `try_send_request` does not wait for readiness and a sender pooled before its dispatcher re-arms would bounce the next request. A response hyper reports as end-of-stream at header time (`204`, `304`, `HEAD`, `Content-Length: 0`) checks in immediately.
- **WebSocket** — never pooled. An RFC 6455 upgrade consumes its carrier for the whole session, so it uses a dedicated admitted dial.

Bounds: the idle set per identity is capped by the global `max_idle_per_host`, entries expire against the effective `idle_timeout_seconds`, and an amortized sweep (at most once per interval, process-wide) evicts closed, expired, and identity-changed entries.

**Per-target physical-connection bound.** Pooling is not a way to open unbounded connections into the local application. `FERRUM_MESH_UNIX_INGRESS_MAX_CONNECTIONS` (default `64`; `0` disables it) caps the concurrently open **physical** connections one admitted target identity may hold. It is deliberately **not** an Istio `DestinationRule` `connectionPool.tcp.maxConnections`: a `DestinationRule` is **outbound**, client-side policy about a destination service this workload calls, while sidecar ingress is traffic the mesh has already accepted being handed to the co-located app over a socket with no network authority, no dial host, and no service port to resolve a rule against — and the materialized ingress upstream's placeholder `127.0.0.1:<listener_port>` target under a synthetic `__mesh-ingress-unix-*` id would in practice match no rule at all. The bound's lane is the pool's **complete structured identity** — namespace, proxy id, effective upstream id, configured and canonical socket path, the admitted `(dev, ino, owner_uid)`, and the wire protocol — so sibling ingress listeners on one workload, an `http` ⇄ `http2` flip, and a replaced socket object each get their own lane and can neither steal nor accidentally share one. A slot is taken at the one point a **new physical connection** is about to be constructed — never on a pool hit and never per multiplexed h2c stream. A dedicated WebSocket is a new physical connection and therefore holds one slot for its complete session relay; a target pinned at `1` still serves an unbounded number of sequential HTTP/1.1 requests and concurrent RPCs over one pooled carrier, but cannot open a second dedicated WebSocket beside it. Pooled-carrier guards are owned by their connection-driver futures; a WebSocket's equivalent lease is owned beside the session relay. Both forms hold the slot for exactly the socket's lifetime — idle residence included — and release it on handshake failure, close, relay termination, eviction, withdrawal, drain, shutdown, cancellation, and a driver panic alike. An over-bound refusal is decided **before `connect(2)`**: no socket is opened and no application byte is written, and it surfaces as a typed `503` with `ErrorClass::BackendConnectionLimit` — pre-wire, health-neutral (an application at its configured transport capacity is not an unhealthy one), and retryable onto another target with its own lane.

**Keep-alive.** `FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE` (and the per-proxy `pool_enable_http_keep_alive` override) is honored literally for HTTP/1.1 on this transport: with it off, a carrier is neither taken from nor returned to the idle set, so every request gets its own freshly admitted connection. Publication also treats the effective setting as part of the reusable live-identity set: an H1 target whose keep-alive/reuse is off is omitted from the published live set so resident idle H1 carriers are retired synchronously before reconciliation returns — otherwise a full idle set at the default physical and idle caps (both 64) could keep every physical slot occupied while new traffic must dial fresh and receive `BackendConnectionLimit` until idle expiry. h2c is unaffected — HTTP/2 has no keep-alive negotiation, and stream multiplexing is the transport's defining behavior rather than a keep-alive optimization.

**Metrics.** The pool exports physical connects, hits, misses, identity retirements, setup failures, gateway-side checkout refusals (path admission, per-target connection-bound refusals, and the shutdown latch), and gauges for idle HTTP/1.1 carriers, shared h2c carriers, and open physical connections. They appear on the JWT-authenticated runtime metrics endpoint under `connections.unix_backend_pool` (`GET /metrics/runtime`). Cardinality is fixed: one object for the whole pool, never a per-target label. Every field is one atomic read — the gauges are maintained at each insert/removal and at each connection-driver spawn/completion, so producing the snapshot never scans a map and the request path never pays for it.

**Lifecycle.** The pool is owned by `ProxyState`, which *survives* a config reload (the config itself is swapped through an `ArcSwap`), so publication retires withdrawn carriers explicitly rather than relying on the pool being rebuilt:

- **Config publication / reload.** **Every** successfully published request epoch hands the pool the exact set of *reusable* `mesh.unix_socket` target identities *the config that publication made current* declares — `(namespace, proxy id, upstream id, configured socket path, wire protocol)`. HTTP/1.1 identities whose effective keep-alive/reuse is off are omitted so idle H1 carriers cannot remain continuously live across that policy flip. That is all three swap paths: the full-snapshot rebuild, the incremental delta branch of the same call, and the separate `apply_incremental` path database and CP/DP deltas use; and it runs before any early return, so a mesh-only or projected-content republication that carries no `ConfigDelta` reconciles too. Anything pooled outside that set is retired in one pass before it can serve another request. That covers a withdrawn target, a deleted proxy or upstream, a proxy re-bound to a different namespace or upstream, a re-pointed socket path, an `http` ⇄ `http2` flip, and an H1 reuse disable. Comparison is exact tuple equality — never a substring, prefix, or path-containment rule. A **rejected** candidate and one the swap reported as genuinely unchanged never become current, so neither reconciles nor advances the generation.
- **The withdrawal fence.** Retiring the idle sets is only part of it: an exclusive HTTP/1.1 lease that is checked out is *not* in the idle set, so publication cannot see it, and its exchange can finish long after its target was withdrawn. A still-open, still-same-inode connection expresses nothing about config, so a late check-in would otherwise repopulate the pool under an identity that no longer exists. Every retirement therefore advances a monotonic **publication generation** *before* its retirement pass runs, and three rules hang off that counter:

  1. **The lease token.** Each lease records the generation it was taken under, and a check-in is admitted only while that is still current. This closes same-key ABA: a target withdrawn and re-added under the identical tuple is a new incarnation, and a lease from the previous one may not re-enter it. The cost is that a lease outstanding across any publication is retired instead of reused (one connection per in-flight exchange per publication).
  2. **The entry token.** Each pooled entry also carries the generation it was published into the map under, and a checkout refuses any entry whose token is not current, reading both under the same map guard. Without this, the two-read check-in fence leaves the old-generation entry *visible* between its insert and its own withdrawal, and a checkout landing in that window could pop it and adopt it under its own generation. The retirement pass *advances* the token of every entry it observes under a still-declared identity, while holding that entry's shard, so an unrelated publication preserves continuously-live idle carriers instead of emptying the pool.
  3. **The live-set snapshot and withdrawal tombstone.** Publication installs a lock-free snapshot of the exact identities it declares. A check-in or h2c publish compares the identity already owned by its structured pool key against that snapshot, without constructing strings, before the carrier can become reusable. This covers a withdrawn identity even when the retirement pass had no existing slot to tombstone. For keys the pass can see, an absent identity also keeps an emptied, marked slot, closing the map insertion race under the same shard guard. A later publication that declares the identity again clears the mark on an empty slot, so the re-added incarnation starts from a freshly admitted dial.

  Publication orders itself "bump, install live snapshot, then retire", and a check-in reads the generation, checks the snapshot, inserts a uniquely identified entry, releases the shard, and re-reads: either the pass saw the entry (and removed or re-stamped it) or the check-in observes the bump and withdraws exactly the entry it inserted, by id, so a losing cleanup can never delete a newer sibling carrier. The same sequence guards the shared h2c carrier published at the end of a dial. Post-swap maintenance is serialized by the request epoch's monotonic config generation, so an older publisher that resumes late cannot overwrite a newer live-set verdict.
- **Socket replacement.** A change to the filesystem object itself (a new inode or a new owner uid) is invisible to config, so it is caught on the checkout path by the re-admission described above.
- **Driver ownership.** Every physical connection's driver future is **registered with the pool**, not detached with a bare `tokio::spawn`. Dropping the sender maps is not equivalent: a carrier checked out into an in-flight exchange, or cloned into a multiplexed h2c request, is deliberately absent from those maps and keeps its connection open, so a detached driver would be unreachable at shutdown. Registration is what makes the close/await contract below bounded and complete.
- **Graceful shutdown.** Each serving mode drains the pool from inside its existing bounded shutdown sequence — after accept loops stop and after in-flight requests have had their `FERRUM_SHUTDOWN_DRAIN_SECONDS` budget — so the drain neither shortens nor is shortened by that window. The drain latches the pool closed and advances the publication generation, so a streaming response finishing in the last moments of the drain retires its carrier instead of re-pooling it — including one whose check-in read the latch a moment before it was set. It then drops every pooled carrier (which closes each connection whose only remaining sender was the pooled one) and **awaits the remaining drivers under one bounded budget**, then **cancels and joins** whatever has not ended when that budget expires, under a second bounded budget. Joining the cancelled tasks is load-bearing rather than ceremony: a cancelled task releases its target connection slot and its share of the open-connections gauge when the runtime drops it, and joining is what observes that. The wait cannot be unbounded; the second budget limits how long the drain waits for cancelled tasks to reach a runtime cancellation point and be dropped. If one does not do so before expiry, that fact is logged rather than silently presented as a completed join. The drain is therefore `async` at every serving-mode call site.
- **The shutdown latch refuses checkouts, not just check-ins.** Once latched, **every** checkout — HTTP/1.1, the forced-fresh HTTP/1.1 replay, and the h2c cold path — fails closed as its first act, before the establishment deadline, the idle sweep, path admission, and `connect(2)`. A request arriving after the drain therefore opens no socket and reserves no slot on the target's bound, and it surfaces as a `503` with `ErrorClass::DispatchPolicyRejected`: health-neutral (the gateway shutting down says nothing about the application) and not retried, because every Unix target in the process shares the one latched pool. The drain sets **both** latches *before* it retires any pooled carrier, and it sets them in a specific **order**: the driver tracker's registration flag first, under the tracker's map lock, and only then the pool's own flag. The two are independent pieces of state, so they cannot land atomically; the order is what carries the guarantee. Because the pool's flag is stored last, from the instant *anyone* can observe the pool latched closed, driver registration is already closed — there is no interval, retirement or otherwise, during which the pool reads as shutting down while a racing establishment could still be adopted. The reverse interval is deliberate and bounded: between the tracker close and the pool store a checkout can still pass the entry gate and dial, which is the same in-flight-establishment case described below and settles the same way. A checkout that passed that gate *before* the latch and reaches driver registration *after* it is resolved atomically by the tracker — the latch read, the spawn, and the map insert happen under one lock acquisition — so the losing side spawns **nothing**: no task to abort, no detached handle, no gauge or connection slot charged and released later. Its un-spawned driver future is dropped (closing the socket it just established), its connection slot is released, and it returns the same refusal rather than a sender backed by a connection nobody drives. What that does **not** claim: an establishment already in flight when the latch is set — or one that started inside the short window between the tracker close and the pool store — is not owned by that drain and may still hold its target's connection slot for the remainder of its own bounded establishment deadline; it settles exactly — slot released, gauge untouched, socket closed — before its own call returns.

The containment allowlist (`FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS`) and UID allowlist (`FERRUM_MESH_UNIX_SOCKET_ALLOWED_UIDS`) are process environment and cannot change without a restart.

A criterion harness for the dial-versus-pool comparison lives at `tests/performance/mesh/benches/unix_backend_pool.rs` (`./run.sh unix_backend_pool`). It is manually driven and has no budget gate.

A listener that is edited, replaced, or deleted takes effect on the next slice apply exactly like a TCP one: the materialized route and its backing upstream are rebuilt from the new slice, so a removed listener stops routing (leaving no orphaned upstream) and a re-pointed one dials the new socket with no restart.

**Fail-closed transport gate.** The socket path rides the reserved `mesh.unix_socket` tag on the materialized upstream's single target — the same mechanism `mesh.hbone` / `mesh.mtls` use, and the same reserved `mesh.` namespace that is stripped from every operator/workload label copy, so a pod label can never forge it. Operator-provided upstream targets are also forbidden from setting any `mesh.*` tag through admin create/update, API-spec import, restore, or file configuration; only Ferrum's trusted mesh projection may stamp those transport markers. A target carrying the tag is dialed over a Unix stream **or the request is refused**; it is never downgraded to the target's placeholder `host:port` (which nothing listens on).

### `bind` and `captureMode`

- **`bind` (issue #3266)** — Omitted, empty, or unspecified (`0.0.0.0` / `::`) keeps the shared capture-listener contract: inbound traffic still enters through `:15006` and is disambiguated by captured original destination / authority port. A supported **dedicated** bind (`127.0.0.1` / `::1`) is conflict-checked against Gateway/stream/mesh listener ownership and materialized as a real OS listener on `bind:port` (HTTP via `GatewayListenerManager`, stream via `StreamListenerManager`) while the shared capture path remains for mesh peers. The dedicated HTTP accept loop is stamped as mesh inbound, and its configured/accepted listener port is the authoritative AuthorizationPolicy destination port; it never widens onto an ordinary process-global frontend or falls back to the `defaultEndpoint` port for authorization. Dedicated-bind HTTP routes are exact-listener only: they do **not** participate in single-listener Service remap, so a lone loopback bind cannot steal `:15006` / process-global matches from the port-agnostic capture sibling. Unsupported or unrepresentable values (Unix-domain sockets, hostnames, `ip:port`, non-loopback addresses) fail closed with field-specific `deferred_fields` / resolve diagnostics rather than being accepted as inert metadata. A dedicated bind that collides with an already-owned port, or that pairs with a `unix://` `defaultEndpoint`, fails closed for that **whole** ingress entry: it is removed from the prepared `local_ingress_listeners` set as well as bind-proxy / capture-route materialization, so there is no silent shared-capture or authenticated-CONNECT fallback. `sidecar_ingress_declared` and `declared_ingress_http_ports` stay independent of that admission so all-rejected / empty cases still fail closed without restoring default inbound behavior or incorrectly lowering the operator-declared HTTP port count.
- **`captureMode`** — Ferrum assumes `IPTABLES`/`DEFAULT` capture (the sidecar redirect model). `captureMode: NONE` (the app handles capture itself) is not separately honored; the listener-port disambiguation relies on the captured original destination or the request authority port being present. Dedicated loopback binds still provide direct `bind:port` exposure for local dialers that bypass capture.

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

A CP-side endpoint that reports what slice version the CP last published to each connected DP (so external tooling can diff "what the CP thinks each DP should have" against "what each DP reports here") is available as JWT-authenticated `GET /mesh/slice-drift` on the control plane (issue #3265). That surface tracks per-authenticated-DP **desired**, **sent**, **acknowledged**, and **rejected** version watermarks (with age and a closed redacted NACK label). Pair it with this DP-local endpoint: walk `/mesh/slice-drift` on the CP and `/mesh/config-drift` on each DP.

### CP `GET /mesh/slice-drift` contract

- **Mode**: control-plane only (`404` elsewhere). `200` with an empty `data_planes` list when no local mesh DP has subscribed yet.
- **Identity**: JWT `sub` bound at `MeshSubscribe` time (`node_id` must equal `sub`), bounded to 256 UTF-8 bytes independently of the gRPC header budget. Remote-discovery subscriptions are not tracked. Do not trust caller-supplied display fields as identity.
- **Watermarks**: `desired` / `sent` / `acknowledged` each carry `version`, `at`, and `age_seconds` (clamped ≥ 0 and periodically refreshed even while a row is stable). Versions are exact opaque values: non-empty, no surrounding whitespace or control characters, and at most 256 UTF-8 bytes. `desired` advances at publication time, independently of stream polling, only when that DP's projected `MeshSlice` content changes; a backpressured connected DP therefore exposes desired-vs-sent drift, while version-only/no-op reloads and unrelated namespaces do not manufacture drift. Retained disconnected rows keep the same bounded subscription selector and content digest so that projection rule remains accurate while partitioned.
- **NACK privacy**: `rejected.reason` is the fixed label `reported_rejection`. Authenticated caller text is discarded, never retained, logged, placed in metrics, or exposed through admin diagnostics.
- **Convergence**: `converged` | `drifted` | `rejecting` | `pending` | `disconnected`, plus boolean `drift.desired_vs_sent` / `desired_vs_acknowledged` / `sent_vs_acknowledged`.
- **Lifecycle**: each local subscription receives a fresh opaque session token on the wire (never exposed through admin, metrics, or logs). Disconnect retains the row for 300s; registry hard-caps at 4096 identities (evicts oldest disconnected, otherwise declines to track). Retained projection context is capped at 256 labels, 256 scope/claim namespaces per set, and 64 KiB aggregate selector/scope bytes; an oversized subscription is not tracked instead of growing retained state.
- **Never gates the data path**: slice-drift tracking is observability only. If the registry declines a subscription (cardinality cap, oversized retained selector) or a bookkeeping update fails, the DP is served **untracked** — it still receives its full mesh slice and every later update, its wire frames simply carry an empty `session_token` and no row appears here. An established stream is never terminated because a drift record failed. Diagnostics are fixed-cardinality (closed-set field labels only, never caller bytes), and the guarded state recovers from mutex poisoning rather than latching it, so one panic under that lock cannot disable mesh configuration delivery.
- **Desired at subscribe**: a publication landing between the subscribe path's config load and its registry insert reconciles a registry that does not yet contain the new identity. Subscribe therefore re-stamps `desired` from the currently published config, under the registry lock, immediately after opening the session — a fresh row can never retain a `desired` older than the published config, in either interleaving.
- **Snapshot publication**: admission, mutation, snapshot rebuild, and publication are serialized on this cold path; reads remain lock-free snapshots. Because one CP publication fans out to every connected stream, per-stream `sent` and per-DP ACK/NACK updates coalesce into at most one snapshot rebuild per 500 ms once more than 256 identities are tracked (below that the snapshot is always exactly current). Coalesced state is flushed by the next session open/replace, disconnect, publication reconcile, or retention sweep, so the published watermarks are at most one maintenance interval behind on an otherwise idle large fleet.
- **ACK path**: DPs call `MeshConfigSync.ReportMeshSliceStatus` (local-mesh audience). The report is accepted only while its token names the currently connected replacement session and its version equals the current sent version. Empty `error_message` = ACK; non-empty = NACK. Delayed reports from an old stream—including same-version replacement streams—fail closed. A report that fails to reach the CP is retried (bounded, up to 3 further attempts) piggybacked on later frames of the same subscription — including the 60s heartbeat — so a transient RPC failure on the last publication cannot leave a false `sent_vs_acknowledged` divergence standing. A report the CP explicitly refuses is dropped rather than retried; a report is superseded as soon as a newer one is produced.
- **Metrics**: closed-set `ferrum_mesh_slice_drift_data_planes{state=…}` and `ferrum_mesh_slice_drift_tracked_data_planes` only — never per-DP / per-version / per-reason labels.

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

The `sequence` *domain* follows CP scope so identical-scope replicas stay convergent across restarts:
  - Explicit `CpScope::Single` / `Set`: the maximum durable `latest_change_sequence(namespace)` over the configured namespaces — the same cursors incremental polling advances from. An unrelated namespace outside the scope cannot advance a restarted replica ahead of its still-running peer.
  - `CpScope::All`: the store-wide `config_changes` high-water mark, because the dynamically discovered namespace list can shrink after the last resource in a namespace is deleted; without the global watermark a restarted All-scope CP would rewind. An in-process floor additionally protects full reload while the process is alive.

Every namespace cursor—and, for sequenced `All`, the store-global watermark—is captured **before** the corresponding full resource loads begin. This is deliberately conservative across SQL snapshot transactions, replica-set Mongo snapshot transactions, and standalone Mongo's sequential reads: a write that commits after the boundary may already appear in the full snapshot and be harmlessly replayed by the next incremental poll, but an older snapshot can never be stamped with that later write's sequence or advance the polling cursor past it. In explicit `Single`/`Set` scope, a namespace whose boundary cannot be read is demoted independently: its resource load is skipped, its last-known-good resources and cursor are retained, and healthy namespaces continue. Sequenced `All` scope retains the entire prior snapshot on any boundary, load, or validation failure because a partial LKG aggregate cannot safely claim the store-global watermark. Unsequenced `All` scope publishes no global revision, so it retains the same per-namespace LKG continuation: failed tenants keep their resources and cursors while healthy tenants refresh. The in-process floor is applied only after these safe captures as a monotonic lower bound; it is not a substitute for boundary ordering.

A CP running the Kubernetes CRD controller publishes **no** change-log revision. Its mesh block is authored entirely by the Kubernetes overlay — CP database full loads clear `mesh` and re-merge it from the overlay slot — so a `config_changes` cursor describes no part of the mesh snapshot and must not stamp it.

#### Kubernetes domain (CRD-controller CP)

A Kubernetes-controller CP sequences from `resourceVersion`, the only value in the Kubernetes API that is comparable (one number space), shared (minted by the API server, identical for every client), and monotonic (etcd's cluster-global revision counter never rewinds for the life of the cluster).

Three alternatives are *not* used, and each is a real failure rather than a stylistic choice:

- **max over live object metadata** *decreases* when the highest-versioned object in a scope is deleted. A replica restarting after such a deletion relists, recomputes a lower maximum, and publishes below the revision its still-running peer already published — a rewind *inside* one authority, which is exactly the case the gate never auto-adopts. In a quiet namespace, recovery would need an operator reset.
- **a wall clock or process-local counter** is not shared. That is why `MeshSlice.version` exists only for observability.
- **the current cluster revision read at reconcile time** describes the cluster, not this replica's reflectors. A stalled watcher would make it claim freshness it does not have.

Instead each watch scope accumulates the highest revision it is *proven* converged through, from two kinds of evidence:

- **A boundary read** taken immediately *before* a watcher generation starts — a one-item consistent list on the same resource and scope. kube-rs consumes list metadata and watch bookmarks internally and surfaces neither, so the generation's own list revision is unavailable; but its list is a quorum read at the *current* cluster revision, which is ≥ any revision already returned to any client, so a revision read just before it is necessarily ≤ it. The boundary is adopted only when that generation reports `InitDone`, i.e. when its store actually holds a list computed at or after the boundary.
- **Observed watch events.** A watch resumed from a list revision delivers every change in order, so processing an event stamped `r` proves the scope has seen everything up to `r`. **Deletions count**: a `DELETED` event carries the object stamped with the *deletion* revision, so a withdrawal advances the watermark instead of lowering it. Objects delivered by an initial list are held back until `InitDone`, because the reflector publishes an initial list to its store atomically there.

**The coherence point.** A reconcile snapshot is the union of independently converging scopes, so it is not a coherent cluster snapshot at any single revision. The strongest true statement is that it contains every change up to the **minimum** of its scopes' watermarks — so that minimum is the sequence, and:

- the scope set is pinned under the same store-set lock that materializes the snapshot, and the watermark is read **first**; between the two reads a reflector can only move forward, so the snapshot is never older than the sequence claims;
- a registered scope with no evidence yet — initial list in flight, relist unfinished, `resourceVersion` unparsable — makes the whole watermark unavailable, because a snapshot missing a resource type must not be stamped as complete;
- an unavailable watermark publishes neither an unsequenced nor an optimistic frame: the CP **retains the last published sequence and refuses to advance**. Divergent mesh that evolved under that equal scalar is retained at the reconciler publication boundary — the last accepted mesh stays bound to the retained sequence until the sequence can advance — so data planes see either an identical equal-revision replay or no mesh change, never a newly evolved snapshot stamped with the old scalar. Before any sequence has ever been established the CP publishes no revision at all, and data planes bootstrap unversioned exactly as they did before.

Per scope the watermark is a running maximum, so it never falls. The aggregate minimum *can* fall when the scope set grows — a CRD installed later adds a scope with younger evidence — so publication applies the same kind of in-process monotonic floor the change-log domain uses. Across a restart no floor is needed: a fresh boundary read returns a current cluster revision, which is ≥ anything the previous process could have observed.

**Stated assumption.** Kubernetes documents `resourceVersion` as opaque and does not guarantee comparability across resource types. On every etcd-backed API server it is the shared etcd revision, which is what makes a cross-type minimum meaningful. Ferrum therefore requires each value to parse as an unsigned integer and treats anything else as *no evidence*: an API server whose version space is not the numeric one produces no watermark, and the CP refuses to advance rather than ordering on values it cannot interpret.

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
| same authority | `sequence ==` accepted, **identical content** | install (reconnect replay / republish) |
| same authority | `sequence ==` accepted, **different content** | **quarantine** (`divergent_content`) |
| any | revision present, content identity uncomputable | **quarantine** (`unidentified_content`) |
| same authority | `sequence <` accepted | **quarantine** (`stale_revision`) |
| other authority | any | **quarantine** (`incomparable_authority`) |

Equal sequences must install **for identical content only**: reconnecting to the same CP replays that CP's initial slice at the unchanged revision, and quarantining that would break every ordinary reconnect.

### Content binding at an equal revision

A scalar revision orders snapshots only if the producer guarantees that one `(authority, sequence)` names exactly one config content. The Kubernetes domain's MIN-over-scopes watermark does not guarantee that on its own: the published sequence is the *minimum* per-scope convergence watermark, while the latest-only reflector snapshot may already contain later changes from another scope (or may keep evolving while incomplete evidence pins the floor). A replica at scope watermarks `[110, 100]` and one at `[100, 100]` both compute sequence `100`, and only the first one's snapshot carries the change made at `110`.

The **producer** therefore binds mesh content to the authoritative scalar at the Kubernetes overlay publication boundary (`publish_k8s_reconcile`, inside `CpPublicationGate`): when a reconcile presents different mesh content but an equal revision, the previously accepted mesh (and that revision) are retained — the divergent candidate is neither stored in `K8sOverlaySlot` nor merged into `config_arc` nor broadcast. Non-mesh Gateway/API fields may still publish. When the sequence later advances, the newest candidate mesh — including withdrawals — publishes normally. Equal revision with identical mesh remains an idempotent republish. Unversioned bootstrap (no sequence established yet) is unchanged. DB full-reload recomposition reads the same retained overlay, so a later poll cannot resurrect a withheld divergent mesh.

Retention is correct but must be **brief**: while it lasts, data planes serve mesh content older than the cluster describes. The published sequence is a MINIMUM over watch scopes, so it is pinned by the quietest one, and a quiet scope's watermark only moves when a new watcher generation adopts a fresh pre-list boundary. Waiting for the idle relist alone would make a change in one busy scope invisible to the mesh for up to a whole `FERRUM_K8S_WATCH_IDLE_RELIST_SECS` window (300 s by default) on a single, healthy control-plane replica. A retaining publication therefore **requests** fresh convergence evidence (`K8sConfigRevisionTracker::request_evidence_refresh`) and every watch scope starts a new generation, spaced by a per-scope 5 s floor so a churning cluster cannot turn this into a list storm. This acquires proof; it fabricates none — a scope that cannot relist, or whose boundary read fails, still contributes no evidence and the sequence still refuses to advance, and the data-plane `MeshRevisionGate` is untouched.

The **data-plane gate** remains the cross-replica defense: it binds a deterministic **semantic content identity** to every accepted and applied revision, and an equal-revision candidate installs only when its identity matches the one already bound. The identity is the canonical slice digest (`slice_content_digest`: the observability-only `version` and the ordering-only `revision` are cleared, then the JSON is canonicalized), so two semantically identical slices agree regardless of which replica serialized them — which is what keeps ordinary reconnect replays installable, including a replay from a *different* replica. Native `MeshSubscribe` and xDS both install through `MeshRuntimeState::install_slice`, so both bind the same identity.

Divergent content at an equal revision that still reaches a data plane (for example from another replica that accepted different content at the same minimum watermark) is quarantined as `divergent_content`. Treat it as evidence that some producer's scalar revision is insufficient or inconsistent for its ordering domain, not as a transient condition — the data plane keeps serving its last-good slice and, like every other revision quarantine, terminates the stream so multi-CP failover moves off the inconsistent producer. A candidate whose identity cannot be computed at all is quarantined as `unidentified_content`: an unprovable binding fails closed. The comparison and the binding happen in the same critical section as admission, so there is no window a caller could race, and no digest, content fragment, or payload byte ever reaches a log line, a metric label, or an admin surface — the identity is compared, never rendered.

A **present but ill-formed** revision is distinct from an absent one. Centralized `MeshConfigUpdate` validation refuses an embedded (or envelope) ill-formed revision before install, and `MeshRevisionGate::admit` refuses the same shape even on bootstrap — including the xDS path, which reaches the shared gate without that update validator. Filtering an ill-formed authority to "absent" would otherwise let a hostile first frame with an empty envelope stamp pass as consistently unversioned, install, and retain no watermark. On the envelope, distinguish raw empty (`config_authority=""`, the proto default — genuinely absent) from raw non-empty whitespace (`"   "`): the latter is present/malformed and rejected with a bounded static diagnostic that does not echo the authority text. Genuinely absent revisions remain valid for unsequenced authorities (K8s controller / file protocol).

A quarantined candidate mutates nothing — the last-good slice keeps serving, the receive metric and `last_received_at` do not advance, and no watcher is woken. On the native stream a quarantine also **drops the stream** so multi-CP failover moves off the lagging control plane; staying attached would only let it keep serving stale generations.

On the xDS path the ADS response was already folded into the resource accumulator and ACKed before the slice was rebuilt, so the gate does not rewind it. That is deliberate: rewinding would desynchronize local state from versions already ACKed. A revision quarantine instead terminates ADS and triggers the existing multi-CP rotation. The accumulator is state-of-the-world state scoped to a single control-plane URL and is cleared wholesale on failover (`reset_for_new_control_plane`), so a quarantined CP's resources cannot mix into the next CP's slice. The last-good live slice remains untouched throughout.

### Received versus applied (candidate lifecycle)

Passing the freshness gate makes a slice the *received* candidate, not the serving one. The mesh proxy runtime is a second, independent gate: slice→config preparation or the proxy config apply can still refuse it, leaving the previous generation live. The gate therefore tracks two watermarks, both on `GET /mesh/config-drift`:

- **`accepted`** — the highest revision admitted into the received slot. This is what candidate comparison runs against, so a burst of updates still orders correctly while an earlier one is mid-apply.
- **`applied`** — the revision of the slice the proxy runtime last accepted. This is the authoritative last-good generation.

Both slots store their revision **and its bound content identity together**, and every transition moves the pair, so a rollback restores the applied revision with the identity that revision was applied with and the equal-revision check is never evaluated against a stale identity. The apply token minted before asynchronous preparation carries that identity too, so a commit binds the pair the gate actually admitted.

When the runtime accepts a candidate, `applied` advances to it (including a content-no-op or equal-revision replay, where the runtime accepts with no config delta). When the runtime **refuses** one, `accepted` is rolled back to `applied`, so every revision between them stays eligible. Without that rollback, a single runtime-invalid slice published at a far-future sequence would advance the watermark past every valid revision beneath it and block recovery with a generation that never served a request — the exact lockout the reset endpoint exists to avoid needing. The rollback is keyed to the exact received candidate (`(authority, sequence)` equality plus received-slot identity), so a *late* rejection of N never disturbs an N+1 that arrived while N was being applied. A candidate refused before anything was ever applied returns the gate to no baseline at all, rather than poisoning startup and fallback. Runtime apply work also captures a gate-epoch token before asynchronous preparation; reset advances the epoch, so a pre-reset apply that completes late can update the serving-content snapshot without resurrecting either cleared watermark.

### Intentional rollback

Rolling configuration back is a **write**: it allocates new change-log sequences, so it reaches data planes as a *higher* revision carrying older content and installs normally. Replaying an old generation to move a data plane backwards is never a supported operation.

### Reset semantics (no permanent lockout)

Two escape hatches, both explicit:

- A **foreign authority** observed continuously for `FERRUM_MESH_CONFIG_REVISION_ADOPT_SECS` (default 300 s, `0` disables) is adopted with a `warn!` and a bump of `ferrum_mesh_config_revision_adoptions_total`. The grace uses a monotonic process clock; NTP or manual wall-clock jumps cannot expire it early. This covers CP state loss and a deliberate source reset without an operator round trip.
- `POST /mesh/config-revision/reset` (JWT + `operator` role) clears the accepted revision so the next slice from any authority is eligible. This is the documented recovery for the one case that is never auto-adopted: a sequence rewind *inside* one authority — a config store restored from backup without bumping `FERRUM_MESH_CONFIG_AUTHORITY_ID`. Auto-adopting that would be indistinguishable from the rollback the gate exists to prevent. The reset installs nothing itself; the next slice still has to pass subscription binding and update validation.

### Observability

- Authenticated `/metrics`: `ferrum_mesh_config_revision_rejections_total{reason}` with `reason` ∈ `stale_revision` / `incomparable_authority` / `missing_revision` / `malformed_revision` / `divergent_content` / `unidentified_content`, and `ferrum_mesh_config_revision_adoptions_total`. These process counters aggregate the local slice gate and native remote-discovery gates. Fixed cardinality — no CP-supplied authority string or sequence number reaches this surface.
- `GET /mesh/config-drift` (JWT): the `revision` block carries the accepted and applied `(authority, sequence)` watermarks, the most recent quarantine (authority, sequence, reason, consecutive count, first/last seen), the totals, the effective adopt grace, and `quarantine_active` — the "stale fallback quarantined" signal to alert on. Every authority rendered on this surface — and in the reset response and its audit log line — is control-character-stripped and truncated to 64 characters; the raw control-plane string never leaves the gate, where exact ordering comparisons need it. An authority that is blank, has surrounding whitespace, is over-long, or contains control characters is refused as `malformed_revision` at the boundary and never becomes a watermark at all.

### Scope and residuals

- **Unsequenced authorities.** `FERRUM_MESH_CONFIG_PROTOCOL=file` is inherently local and ordered by the operator's own edits, so it publishes no revision and data planes apply no cross-CP ordering to it. Setting `FERRUM_MESH_CONFIG_AUTHORITY_ID=` disables publication on either domain and produces the same unsequenced posture deliberately. (A Kubernetes-controller CP is no longer in this list: it publishes the Kubernetes domain described above.)
- **Kubernetes replica skew.** Two Kubernetes-controller replicas publish the *same* sequence as soon as they have both observed the same change — event revisions are cluster-minted and identical. They can differ while a scope is quiet, because each replica's floor for that scope comes from its own boundary read, which is refreshed on the idle relist (`FERRUM_K8S_WATCH_IDLE_RELIST_SECS`, default 300 s). A data plane failing over to a replica that is behind quarantines it (`stale_revision`), keeps serving its last-good slice, and rotates on; it recovers within about one relist window, or immediately on the next cluster change. A replica that is behind on one scope while publishing the same *minimum* watermark as its peer — the case the scalar sequence cannot express — is quarantined as `divergent_content` instead, on the same terms. That is the gate working in the conservative direction, but operators who want a tighter bound can lower the relist interval. A replica that is merely *withholding its own* changed mesh under a pinned minimum does not wait for that interval: it requests an immediate evidence refresh, so its own propagation delay is one relist round trip, not one relist window. A **replica whose watchers are healthy is never overstated**: the sequence is the minimum over its scopes, so a stalled or unconverged scope holds the whole watermark back.
- **Kubernetes ordering-domain reset.** An etcd restore-from-backup is the one event that can rewind `resourceVersion` inside a cluster. Like a config store restored from backup, it is never auto-adopted inside one authority: recover with `POST /mesh/config-revision/reset` on the affected data planes, or — preferably, because it is fleet-wide and needs no per-DP call — set `FERRUM_MESH_CONFIG_K8S_AUTHORITY_ID` to a new value so the CP publishes a new ordering domain, which data planes adopt through the normal foreign-authority grace period.
- **One source per authority, and matching CP scope.** Two CPs pointed at *different* config stores while advertising the same `FERRUM_MESH_CONFIG_AUTHORITY_ID` is a misconfiguration the gate cannot detect — their sequences are not comparable but claim to be. Give distinct stores distinct authority ids. The same rule applies to the Kubernetes domain: two CPs watching *different* clusters must not share a `FERRUM_MESH_CONFIG_K8S_AUTHORITY_ID` value. What the gate *does* prevent structurally is the cross-domain case — `k8s` is reserved, so a database CP cannot claim the Kubernetes domain even by accident. Likewise, the replicas a data plane lists in `FERRUM_DP_CP_GRPC_URLS` must share a `FERRUM_CP_NAMESPACES` scope: differently scoped replicas can serve different content and must not claim equal revisions. Within one shared scope, full-load stamping uses the scope's sequence domain (max of explicit namespace cursors for `Single`/`Set`; store-global high-water mark for `All`) plus an in-process floor, so identical-scope replicas converge across restarts and an All-scope namespace disappearance cannot rewind publication. Native `MeshSlice::content_eq` deliberately ignores `revision`, so a revision-only stamp change does not fan out frames to already-subscribed clients.
- **Remote-cluster discovery.** The multicluster remote-endpoint poller validates envelope/slice agreement through the shared validator and keeps a per-cluster revision gate across one-shot reconnect polls and source-identity rotations. Endpoint content and trust-domain boundaries are validated before provisional admission; the applied watermark commits only after the generation-checked endpoint-store install (including a live dedup), and a retired generation rolls admission back. The same equal-revision content binding applies here, computed over exactly the workloads and services that will be installed — *after* validation, trust-domain enforcement, and workload tagging, since those steps mutate the endpoint set — so a lagging remote replica cannot replace live remote endpoints with an older set at an equal revision. Thus an invalid or non-installed far-future slice cannot poison recovery; stale/missing/foreign revisions fail the poll and preserve last-good endpoints. Removing the cluster declaration drops its endpoints and prunes its gate, while a still-declared URL/credential rotation retains the gate. The same `FERRUM_MESH_CONFIG_REVISION_ADOPT_SECS` policy controls foreign-authority adoption.

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

DestinationRule `subsets` are preserved as named subsets in the Ferrum upstream. Each subset can carry load-balancing, TLS, passive-health, connect-timeout, and `connectionPool.http.{h2UpgradePolicy,maxRetries,http1MaxPendingRequests,idleTimeout,http2MaxRequests}` overrides. Cold-path resolution stores one coherent `ResolvedSubsetTrafficPolicy` per upstream/subset, then `GatewayConfig::resolve_dispatch_port_overrides` projects the selected subset's HTTP values onto that proxy's inherited dispatch-policy snapshot. Two proxies pointed at sibling subsets therefore receive distinct immutable policy and TLS values; an unmatched proxy receives the top-level policy only. Every HTTP-family shared client/pool key includes `upstream_subset`, while behavior-changing reqwest ALPN configuration also has its existing `h1` client discriminator.

**Semantics differ from Istio on purpose** for HTTP connection-pool precedence: Ferrum uses field-level merge with `portLevelSettings` > selected subset > top-level. Istio applies subset > DR `portLevelSettings` and replaces the whole top-level `connectionPool` wholesale when a subset sets any connection-pool field. Example: DR `portLevelSettings[{port:8080}].connectionPool.http.h2UpgradePolicy: UPGRADE` plus `subsets[v1].trafficPolicy.connectionPool.http.h2UpgradePolicy: DO_NOT_UPGRADE` → Istio forces H1 for subset-v1 on 8080; Ferrum negotiates h2. A subset that sets only `maxRetries: 2` also inherits a top-level `DO_NOT_UPGRADE` here, where Istio's wholesale replacement clears it. This matches Ferrum's established field-level merge convention for port-level overrides.

`subsets[].trafficPolicy.portLevelSettings` is detected and deferred (translate-time warning + `status.ferrum.translation.deferred_fields`) but not applied — express per-port policy at top-level `trafficPolicy.portLevelSettings` or via subset `connectionPool` fields.

A DestinationRule subset whose labels match no current target is applied with **no admission-time warning** (unlike a phantom `portLevelSettings` port, which warns at apply time). A proxy bound to such a subset fails LB selection at request time (typically 503). Unknown subset *names* referenced by routes are still rejected by reference validation — do not confuse a named-but-empty label match with an unknown subset name.

### Deferred Fields

Top-level and per-subset DestinationRule TLS settings (`trafficPolicy.tls`, `subsets[].trafficPolicy.tls`) are translated onto the matching Ferrum upstream's `backend_tls_*` fields and `resolved_subset_tls` map at slice-apply time. Backend handshake SNI consumption and SAN allow-list verification are enforced on the backend TLS paths; both settings — plus the selected subset name — are included in backend pool keys so distinct TLS identities never share connections.

Port-level `connectionPool.tcp.connectTimeout`, `loadBalancer`, and `outlierDetection` are **all enforced** for HTTP/H2/H3/gRPC/WebSocket/HBONE dispatch via `Upstream.port_overrides[port]` + `Proxy.dispatch_port_overrides[port]`. TCP, UDP, and DTLS stream paths engage per-port **`loadBalancer`** (algorithm and hash key) and **`localityLbSetting`** at selection time when all upstream targets share a single port (`initial_dispatch_port_override` non-zero); the lane engages only for selection-affecting overrides, stream-lane `consistentHash` requires a source-IP hash key, per-port `LEAST_CONN` is refused (fail-closed) on the generic stream listeners, and per-port `LEAST_LATENCY` is refused on every stream lane — see [Limitations](#limitations-and-not-supported). The mesh raw-TCP/UDP tunnel dials (HBONE `:15008` / mesh-mTLS `:15006`) and the HBONE capability probe honor the per-port `connectTimeout` for the destination's policy port. Per-port `outlierDetection` thresholds and `maxEjectionPercent` caps are honored by stream target selection using active/passive health context. Outlier thresholds are still not recorded for stream paths (raw relay sessions carry no response status). Per-port `connectTimeout` and `maxConnections`/`tcpKeepalive` apply to stream dial regardless. Port-level `connectionPool.tcp.maxConnections` is enforced for stream-family dispatch, for HTTP-family **WebSocket** dispatch, for the pooled multiplexed transports (direct H2, gRPC, native H3, HBONE, mesh-mTLS), and for the reqwest transports (see the scope note below). The pooled transports read the cap through the same per-dispatch effective proxy the rest of the per-port policy uses, and `ResolvedPortOverride::policy_port` carries the service port a `targetPort` remap was mirrored from so the counter lane stays on the destination's policy port. Port-level `connectionPool.tcp.tcpKeepalive` is now enforced for stream-family dispatch AND for the socket-owning HTTP-family multiplexed pools (direct-H2, gRPC, HBONE, mesh-mTLS — resolved at connection creation via `socket_opts::apply_pooled_tcp_keepalive`; the HBONE / mesh-mTLS sites key it by the destination's app/service port even though the transport dial is `:15008`/`:15006`), with the global pool keepalive as fallback. Because keepalive is excluded from the pool key (per `.claude/rules/proxy-protocols.md`) and these connections are shared, the first dispatcher to materialize a pooled connection fixes its keepalive (first-materializer tradeoff, like `idleTimeout`). The reqwest-backed HTTP pool (shared client) and H3/QUIC (UDP transport) are documented residuals — see the `tcpKeepalive` row in the DestinationRule table above.

All five applied `connectionPool.http` fields—`h2UpgradePolicy`, `maxRetries`, `http1MaxPendingRequests`, `idleTimeout`, and `http2MaxRequests`—use an inherited fallback on every DestinationRule-backed proxy. Top-level supplies the base, the selected subset overlays it, and an explicit field in the selected target's `portLevelSettings` overlays both. This exact field-level precedence is therefore **per-port > selected subset > top-level**; omitted fields inherit from the next tier. **Semantics differ from Istio on purpose:** Istio applies subset > DR `portLevelSettings` and replaces the whole `connectionPool` wholesale when a subset sets any connection-pool field; Ferrum keeps the inverted tier order and field-level merge. Example: port-8080 `UPGRADE` plus subset-v1 `DO_NOT_UPGRADE` → Istio forces H1 on 8080 for that subset; Ferrum negotiates h2. A subset that sets only `maxRetries` inherits top-level `DO_NOT_UPGRADE` / `idleTimeout` / `http2MaxRequests` here, where Istio's wholesale replacement would clear them. `DEFAULT` is an explicit H2 value and clears a lower-tier H2 choice. Service-discovery targets use `dispatch_policy_port()` so named/numeric `targetPort` remapping does not change the policy source. Each retry/LB attempt resolves the effective transport and H1 admission policy for its current target from the unresolved proxy snapshot; the selected subset is route-stable, and explicit port-policy rotation remains pinned to that port lane. `maxRetries` is capped before retry/deadline decisions and is never synthesized. `http1MaxPendingRequests` is isolated per `(namespace, logical upstream/Service identity, optional Kubernetes Service UID, policy port, subset name)` and reacquired on retry. Mesh VIP/service-host routes and direct-pod-IP routes for the same Service use its cold-stamped FQDN plus UID, so endpoint fan-out cannot multiply the cap; ordinary upstreams retain their resource id, so duplicate display names cannot collapse unrelated resources. Distinct subset names remain isolated. The `port` in that key is the DR **policy** port (`dispatch_policy_port()`, i.e. the declared Service port under `targetPort` remapping), derived once by `dispatch_policy_port_for_target` and used identically by the H1/H2 initial attempt, the H1/H2 retry attempt, and both H3→HTTP plain-bridge dispatch sites — so all three frontends admit into ONE lane per destination instead of splitting a cap of N into 2N, and an explicit `portLevelSettings` cap keyed by the Service port is visible to every frontend. The dial host/port appears only in the shed's log line. `idleTimeout` projects onto `pool_idle_timeout_seconds` (reqwest `rcfg` identity); `http2MaxRequests` projects onto direct-H2/native-gRPC builders and those pools' keys (reqwest H2 has no equivalent knob). Every HTTP-family shared-client/pool key already carries `upstream_subset`, so same-endpoint sibling subsets cannot first-materialize each other. `connectionPool.http.maxRequestsPerConnection` remains deferred at all three scopes; `subsets[].trafficPolicy.portLevelSettings` is also deferred (not applied).

**Dispatch-path coverage (H1/H2 and HTTP/3 frontends).** The per-target effective-proxy override pipeline — `resolve_effective_proxy_for_target` plus the `cap_proxy_retry_for_target` / `route_retry_ceiling` seam for DestinationRule `maxRetries` — applies the DR per-port overrides (`h2UpgradePolicy` / `idleTimeout` / `http2MaxRequests` / `connectTimeout` / per-port TLS, plus `maxRetries` and the service-discovery top-level fallback) after the LB-selected target is known. It runs on the H1/H2 (`handle_proxy_request_inner`) path and on the standalone HTTP/3 frontend (`src/http3/server.rs`) before retry-dependent buffering/native-H3 decisions, H3→gRPC, and H3 WebSocket dispatch read the proxy. The original route retry ceiling is retained on `Proxy.retry`; every H3 dispatch loop that can rotate retry targets re-resolves the effective proxy per attempt from the selected target's unresolved base proxy and re-checks `retry_attempt_allowed_for_target` against that original ceiling — the buffered native-H3 retry loop, the H3→HTTP plain bridge, the H3→gRPC bridge (initial and retried attempts; the streaming variant resolves its single selected target), and the H3 WebSocket dial loop — so retry targets do not inherit the first target's port-level TLS/SNI/H1 policy or get blocked by a permanently lowered initial-port retry projection. The H1/H2 path re-resolves per attempt in `proxy_to_backend` / `proxy_to_backend_retry`, and — since issue #2416 — its WebSocket backend dial does too: the dial loop in `handle_websocket_request_authenticated` calls `resolve_backend_connection_proxy_for_target` for the CURRENT target at the top of every attempt (the same helper the H3 WebSocket bridge uses), so a retry that rotates from one port to another dials under the second port's `connectTimeout`, trust roots, client identity, and verification posture rather than the unresolved route-level policy. DNS override and TTL remain route-level inputs; target rotation changes the resolution hostname but does not project a port-level DNS policy that does not exist. Both the direct TCP/TLS dial and the mesh egress dial (`connect_mesh_websocket_backend`) receive that one target-effective proxy; there is no longer a WebSocket exception to this pipeline. See [WebSocket policy port vs transport dial port](#websocket-policy-port-vs-transport-dial-port) for what "the target's port" means when the transport rides an HBONE or mesh-mTLS tunnel. The plain bridge's per-attempt dispatch-policy rejects — a per-port backend-TLS-SNI incompatibility (502) and the `http1MaxPendingRequests` in-flight cap (503) — happen before backend admission, backend dial, or backend-health signal, matching H1/H2 ordering.

**Warmup pre-warm of DR force-H1 (`DO_NOT_UPGRADE`) clients.** Startup pool warmup (`warmup_connection_pools` in `src/proxy/mod.rs`) resolves the **per-target effective proxy** (`resolve_effective_proxy_for_target`) for every reqwest warmup candidate, so the startup HEAD probe offers the same ALPN and lands on the same pool key as the first real dispatch to that target. A DR `h2UpgradePolicy: DO_NOT_UPGRADE` reached through *any* tier — explicit `portLevelSettings`, the selected subset, or the top-level overlay (the latter two carried on `Proxy.dispatch_port_override_fallback`) — therefore pre-warms its dedicated force-H1 client (ALPN restricted to `http/1.1`, with the `h1` pool-key discriminator) rather than ALPN-negotiating h2 against a backend the operator forbade H2 for and parking that idle connection on a client the data path never uses. The dedup key is likewise derived from the effective proxy, so two ports of one upstream that resolve to different client behavior (force-H1 ALPN, per-port TLS, per-port `idleTimeout`) get distinct warmup tasks. Warmup is a cold startup path, so this resolution runs per target with no hot-path fast-path.

#### DestinationRule `maxRetries` semantics

Istio/Envoy `connectionPool.http.maxRetries` is a **cluster-wide outstanding-retry concurrency budget** — a ceiling on how many retries may be *in flight at once across the whole cluster*, independent of any single request's retry count (Envoy's per-route retry count lives on the route's `retryPolicy`). Ferrum's retry model is **per-request**: `Proxy.retry` (set e.g. from a VirtualService) carries a `max_retries` applied per request in `src/retry.rs`; there is no cluster-wide outstanding-retry gauge.

Rather than ignore the field, Ferrum **honestly reinterprets** DR `maxRetries` as an **upper bound on the per-request retry count**:

- If the route/proxy already has a retry policy (`Proxy.retry` is `Some`), each attempt's effective budget is `min(original_route_ceiling, target_dr_maxRetries)` — it can only *reduce* retries relative to the original route ceiling, never raise them or permanently lower `Proxy.retry`.
- If there is **no** retry policy, DR `maxRetries` alone does **not** enable retries (a budget is not a retry-policy enabler) — Ferrum does not synthesize a retry policy from it.

The cap is enforced by allocation-free helpers in `src/proxy/mod.rs` (`route_retry_ceiling`, `effective_retry_max_retries_for_target`, `retry_attempt_allowed_for_target`) once the dispatch target's policy port is known. The post-selection seam `cap_proxy_retry_for_target` retains the **original** route/`Proxy.retry` ceiling on the proxy — it must **not** permanently lower `max_retries` to `min(route, initial_target)`, because that would make the initial port's cap an absolute sequence ceiling and block a looser rotated candidate from using up to the original route budget. Each attempt is authorized by `min(original_route_ceiling, current_target_cap)`; each candidate is preflighted by `min(original_route_ceiling, candidate_cap)`. When the failed target's policy port has no live `dispatch_port_overrides` entry, retry selection stays on the full upstream and may rotate onto a different port whose explicit `maxRetries` is stricter (including zero) or looser (up to the original route ceiling). A stricter/zero candidate is never dispatched; a looser candidate may continue up to its own cap but never above the original route ceiling. An explicit per-port override still engages the policy-port retry lane. The selected subset's inherited cap remains stable across endpoint rotation within that subset tier. Thus no target can inherit a sibling subset's cap, no lower-precedence cap can increase an existing retry policy, and a stricter rotated port fails closed without being dispatched. This is a documented semantic difference from Envoy — operators relying on Envoy's outstanding-retry-budget behavior should treat Ferrum's interpretation as a per-request ceiling instead.

#### Retry attempts across required mesh transports

HTTP-family retries are transport-neutral for H1/H2 frontend traffic. Mesh egress targets tagged `mesh.hbone` (Ambient / Waypoint HBONE) or `mesh.mtls` (Sidecar SVID-mTLS HTTP/2) are valid in retry-enabled upstreams, including upstreams that mix plain, HBONE, and sidecar targets. The load balancer first rotates/reselects using the existing health, outlier-ejection, and retry policy. Ferrum then resolves the exact selected target's transport again for that attempt; it does not carry the first target's direct/HBONE/mTLS choice across rotation and never direct-dials a target that requires a secured mesh transport.

Target resolution is a full dispatch boundary. Each attempt reapplies the selected app/service port's `portLevelSettings`, effective timeout and connection limits, TLS identity/SNI/trust-domain verification, SVID generation, CONNECT authority, and transport pool key. This keeps plain, HBONE, same-cluster sidecar, and cross-cluster sidecar/HBONE connections isolated even when one upstream contains all of them. Missing identity, malformed cross-cluster identity/SNI metadata, an explicitly unsupported HBONE capability, authorization/policy denial, or an unavailable secured transport fails closed for that attempt without plaintext fallback. The request keeps one atomic configuration epoch: an update or delete affects newly admitted requests, while all attempts of an already admitted request use its consistent snapshot; rotating SVID/capability state is re-read at the attempt boundary.

Replayability stays conservative. When retry can fire, Ferrum drains the client upload under the request-size limit and deadline before the first backend attempt, runs request-body transforms and final-body hooks exactly once, and retains immutable `Bytes`. Backend admission, adaptive-concurrency reservations, load-balancer/circuit-breaker/passive-health accounting, DNS, pool acquisition, and identity verification remain per attempt. A pre-wire DNS/TCP/TLS/pool/handshake failure may replay for any method because no application bytes were committed. Once headers or body bytes may have reached the backend, replay requires both a configured retryable status/error and a retryable method; streaming bodies are never duplicated, and no retry begins after response bytes are committed to the client. Exhausted or unhealthy alternate candidates fall back to the retry loop's established same-target/exhaustion behavior, still through that target's re-resolved transport. Cancellation and the original absolute gRPC deadline stop backoff or dispatch without starting another attempt.

Native gRPC retains its protocol-specific transport limits: Sidecar mesh-mTLS works when it is the initially selected target, and its retries stay on the generic mesh path. The native-gRPC retry loop re-resolves the transport for every attempt and may rotate freely between direct and Ambient `mesh.hbone` targets — both are hyper HTTP/2 with an identical trailer contract, HBONE simply nesting its connection inside the authenticated CONNECT byte tunnel (issue #3728) — but it still fails closed rather than rotating into a Sidecar mesh-mTLS or Unix-socket target, whose response pipelines it does not own. A fully-streamed (non-replayable) gRPC upload is never retried on any transport. Pass-through gRPC-Web uses the HTTP-family retry planner. WebSocket connection retries already re-resolve the selected target's mesh transport before the upgrade and never retry after the upgraded stream is established.

#### Port-level `connectionPool` merge semantics

Istio treats a matching `portLevelSettings[]` entry as a **complete replacement** of the destination-level `connectionPool` for that port — fields not respecified in the port entry fall back to the *cluster default*, not to the destination-level value. **Ferrum intentionally applies a field-level merge**: the five applied HTTP fields keep the destination-level value on an inherited fallback while each `portLevelSettings` entry stores only its explicit fields in a separate per-port slot; dispatch consults that slot first and then the fallback. TCP fields that require apply-time port materialization retain their bounded top-level fan-out, followed by the same additive per-port overlay. An omitted field therefore leaves the inherited value in place. This is the product contract across every applied `connectionPool` knob (`connectTimeout`, `idleTimeout`, `http2MaxRequests`, `maxConnections`, `tcpKeepalive`, `h2UpgradePolicy`, `maxRetries`, and `http1MaxPendingRequests`). `maxRequestsPerConnection` is excluded from this merge because it is deferred and not projected.

One field-specific nuance for `h2UpgradePolicy`: because Istio's `DEFAULT` is carried as the explicit `H2UpgradePolicy::Default` variant (not collapsed to "absent"), an **explicit** port-level `h2UpgradePolicy: DEFAULT` overlays as "probe-driven", which **clears** an inherited top-level `UPGRADE` / `DO_NOT_UPGRADE` for that port — the operator explicitly chose default. An **omitted** port-level `h2UpgradePolicy` leaves the inherited value untouched. `Default` and absent (`None`) behave identically at the dispatch fork.

#### Inherited `connectionPool.http` and service-discovery upstreams

`Upstream.dispatch_port_override_fallback` is the cold-path carrier for all five applied HTTP fields. Top-level `h2UpgradePolicy`, `maxRetries`, `http1MaxPendingRequests`, `idleTimeout`, and `http2MaxRequests` form its base for every upstream; `GatewayConfig::resolve_dispatch_port_overrides` overlays the proxy's selected subset, if any, without mutating the shared upstream or sibling proxies. Service-discovery upstreams use the same carrier because they have no apply-time target-port set. The fallback is applied by `resolve_effective_proxy_for_target` / `cap_proxy_retry_for_target` to the current LB target.

An explicit `portLevelSettings` entry for the selected target's policy port still wins: the per-port `dispatch_port_overrides` map is consulted first and the fallback is the field-level `.or(...)`. The fallback carries the **top-level overlay ONLY** — `dispatch_port_override_fallback_from_upstream` deliberately does **not** fold the upstream's per-port entries into it (folding cross-leaks one port's `connectionPool.http` onto another on a multi-port upstream). Mesh service-discovery targets that dial a resolved workload port different from the declared Service port carry the owning Service port in an internal, serde-skipped `UpstreamTarget.service_port_policy_key`; dispatch reads `target.dispatch_policy_port()` for DestinationRule policy and still dials `target.port`. This covers named `targetPort`, numeric `targetPort`, service-port-equals-workload-port, and multi-port services without inferring policy from a port name or leaking one Service port's policy to a sibling. Generic SD targets without that internal identity continue to use their dial port as the policy key and then the top-level fallback when no explicit entry matches. A DestinationRule-only create/update/removal that changes these `#[serde(skip)]` projections atomically republishes the affected route table (and LB) before mesh status/revision reports the generation programmed (#3243 / #1826): `ProxyState` compares projected proxy dispatch/TLS content even when serialized proxy `updated_at` is unchanged, so route-held `Arc<Proxy>` values cannot stay stale until an unrelated event.

#### Subset-scoped HTTP connection-pool precedence and isolation

`SubsetTrafficPolicy` preserves `h2UpgradePolicy`, `maxRetries`, `http1MaxPendingRequests`, `idleTimeout`, and `http2MaxRequests`; native, Kubernetes, xDS, and slice representations all carry the same typed values. Apply builds a `ResolvedSubsetTrafficPolicy` in the same immutable generation as subset TLS, load balancing, and passive health. Projection is by the exact `(namespace, upstream id, subset name)` tuple. A v1 proxy cannot inherit v2 policy, and a proxy with no matching subset cannot inherit either. Create, reload, update, and removal replace the resolved config atomically; in-flight requests retain their prior `ArcSwap` snapshot.

The target-effective precedence is field-level **`portLevelSettings` > selected subset > top-level**. Each tier may override one of the five applied HTTP connection-pool fields without erasing unrelated inherited fields. Initial dispatch and every retry/LB attempt resolve transport and H1 admission from the current target's policy port. The route-selected subset itself does not change during endpoint rotation, so its retry cap remains coherent for that subset tier; when rotation leaves a port with no live override entry, the candidate's per-port `maxRetries` is re-resolved before dispatch and a stricter (or zero) cap fails closed.

Reqwest pool keys include an inspectable `rcfg` client-behavior segment for every setting baked into the shared `reqwest::Client` (including per-port / selected-subset `idleTimeout`), so divergent client-level values isolate distinct clients. Direct-H2 and gRPC pool keys include the effective `http2MaxRequests` (`Proxy.pool_http2_max_concurrent_streams`, encoded as a decimal or `none`) after `upstream_subset`, so same-subset cap changes and removals rebuild connections instead of reusing a first-materialised builder limit. Sibling subsets already stay isolated because every HTTP-family pool key carries `upstream_subset`. Request-only `backend_connect_timeout_ms` remains per-request and does not fragment any pool.

### WebSocket policy port vs transport dial port

A proxied WebSocket has two ports, and they are deliberately allowed to differ. Both frontends (H1/H2 in `src/proxy/mod.rs`, H3 in `src/http3/websocket.rs`) resolve them identically, per backend attempt:

- **Policy port** — `UpstreamTarget::dispatch_policy_port()`, i.e. `service_port_policy_key` when mesh service discovery recorded a declared Service port that a Kubernetes `targetPort` remapped, otherwise `UpstreamTarget.port`. This is the key for the DestinationRule decisions the upgrade consumes: the `connectionPool.tcp.maxConnections` admission slot and the `resolve_backend_connection_proxy_for_target` projection. A direct dial consumes that projection's `connectTimeout` and `portLevelSettings[].tls` (CA, client cert/key, `verify_server_cert`, SAN allow-list); a mesh tunnel consumes the target-effective timeout while its identity, trust domain, and cross-cluster SNI come from the mesh dial plan rather than application-backend TLS fields. Target selection chooses the policy port; policy always follows the selected Service port, never the workload port and never the transport listener.
- **Transport dial port** — where the socket actually goes. For a direct dial that is `UpstreamTarget.port` (carried in the computed backend URL). For **mesh egress** it is neither: a `mesh.mtls` target dials the peer sidecar's `:15006` inbound listener (`mesh.mtls_port`) and a `mesh.hbone` target dials the peer's `:15008` HBONE listener (`mesh.hbone_port`), reaching the app port *through* the tunnel. Those transport listener ports are addresses, not policy sources — a `portLevelSettings` entry keyed on `15006`/`15008` never configures the upgrade.

So an HBONE WebSocket to a Service port `80` that resolves to workload port `8080` is admitted and configured from port `80`'s DestinationRule, dials `:15008`, and CONNECTs to `:8080`. Because the mesh pools also read socket-level knobs (TCP keepalive) keyed by the dial port, the per-attempt projection additionally mirrors the selected policy port's override onto the dial-port key in its dispatch-local clone, so dial-port-keyed lookups agree with the policy the upgrade was admitted under. The serialized proxy and the shared projected map are unchanged.

The direct WebSocket dial fails **closed** on a resolved backend TLS `sni` override, because `client_async_tls_with_config` derives both the `Host` header and the TLS server name from the request URI and cannot apply a separate SNI. Honoring the URI host would silently verify the wrong server name, so the upgrade is refused pre-dial as a gateway-side dispatch rejection (`502`, non-retryable, neutral to the circuit breaker and passive health) — the same posture the reqwest retry path takes for an unreplayable SNI override. Because the projection is per target, a `portLevelSettings[].tls.sni` on one port refuses only that port's upgrades; sibling ports keep dialing. Mesh egress is unaffected: its SNI is chosen explicitly by the mesh dial plans (`mesh.eastwest_sni` for cross-cluster east-west).

### DestinationRule `maxConnections` enforcement scope

`connectionPool.tcp.maxConnections` caps **concurrent open backend connections per destination** — Envoy's semantics. Keying is per resolved `(host, DestinationRule policy port)` endpoint, not per logical cluster, so a destination with N endpoint hosts sharing one port has an effective ceiling of N×cap rather than Envoy's per-cluster total (the two are equivalent for the typical single-host mesh destination). One shared `BackendConnectionLimiter` (`src/backend_conn_limit.rs`) lives on `ProxyState` and every **outbound** transport admits against it, so a destination has ONE ceiling, not one per transport. The one path deliberately outside it is the sidecar-**ingress** Unix backend transport, which carries traffic the mesh already accepted into the co-located application and is bounded by its own inbound per-target setting instead — see the table row below. The cap check, the reservation and the drop-time release all run under the same `DashMap` shard lock (the shape `src/backend_pending_limit.rs` uses), which is what lets the last release evict the destination's counter: mesh dial hosts are pod IPs and reqwest authorities can come from wildcard-host routing, so retaining a zero-count entry per destination ever dialed would grow the map for the gateway's lifetime. Every transport keys the lane by the **policy** port (`UpstreamTarget::dispatch_policy_port()`), never the dial/transport address, so a Kubernetes `targetPort` remap and the mesh tunnel listeners (`:15008` / `:15006`) share the destination's lane instead of splitting the ceiling. The pools that key and dial from `proxy.backend_host`/`backend_port` (direct H2, gRPC) get this through the mirrored, `policy_port`-stamped entry `resolve_backend_connection_proxy_for_target` writes; the pools that receive the LB-selected target as an explicit argument (native HTTP/3) are handed the policy port explicitly alongside it, because their effective proxy's `dispatch_port_overrides` remain keyed by the service port. The host half of the key is normalized inside the limiter (lowercased, IPv6 brackets stripped), because raw TCP / WebSocket / the direct pools pass the configured host verbatim while reqwest's connector sees a URL-normalized authority — without that, `Backend.Example` and `backend.example` (or `[::1]` and `::1`) would allocate two counters for one destination.

| Transport / backend path | Actual backend sockets observed | `maxConnections` contract |
|---|---:|---|
| TCP / TCP+TLS stream proxy | One backend socket per stream session | Enforced with `BackendConnectionLimiter`; over-cap dials fail before relay |
| WebSocket H1/H2 | One dedicated backend socket per WebSocket session | Enforced with `ProxyState.backend_conn_limit`; over-cap upgrade returns 503 |
| WebSocket H3 | One dedicated backend socket per WebSocket session | Enforced with the same backend connection limiter in `http3/websocket.rs` |
| Direct H2 | Pooled multiplexed H2 connection(s), sharded by pool settings | Enforced per constructed connection; slot held by the connection driver, streams unbounded |
| gRPC | Pooled multiplexed H2 connection(s) | Enforced per constructed connection; slot held by the connection driver, streams unbounded |
| HTTP/3 | Pooled QUIC connection(s), UDP transport | Enforced per constructed QUIC connection; slot held by the spawned h3 connection driver, which owns the QUIC connection and its socket |
| HBONE / mesh-mTLS pooled tunnels | Pooled multiplexed H2 CONNECT transport connection(s) | Enforced per constructed tunnel connection, keyed by the destination's app/service policy port (not `:15008`/`:15006`) |
| reqwest HTTP/1.1 | Pooled sockets reqwest keeps idle and reuses across requests | Enforced in reqwest's connector per NEW physical socket; slot held by the connection object, so an idle socket still holds it |
| reqwest, ALPN-negotiated h2 | Pooled multiplexed H2 connection(s) | Same connector admission; multiplexed streams take no additional slot |
| Sidecar-ingress Unix backends | Pooled HTTP/1.1 carriers + shared h2c carriers on an admitted Unix socket | **Out of scope by design.** A `DestinationRule` is outbound, client-side policy; this transport is inbound, toward the co-located app, and has no dial host or service port to key a lane on. Bounded instead by `FERRUM_MESH_UNIX_INGRESS_MAX_CONNECTIONS` per admitted target identity — see [Connection pooling](#connection-pooling) |

- **Stream-family (TCP / TCP+TLS / TCP-passthrough)**: each accepted stream dials one dedicated backend socket whose lifetime equals the relay session. Enforced at dial with an RAII counter on the shared `BackendConnectionLimiter`, reached through `TcpProxyMetrics.backend_inflight` (`src/proxy/tcp_proxy.rs`). That field is an `Arc` **handle** to the one limiter `ProxyState` builds, not a per-listener limiter: `StreamListenerManager::attach_backend_conn_limit` installs it before the first `reconcile()` and every spawned listener's metrics clone the same instance, so a raw-TCP socket and a pooled/WebSocket socket to one destination share the configured ceiling, and two stream listeners cannot each get their own copy of it. The install is one-shot (`OnceLock`), so a config reload or listener restart can never swap the limiter out from under relays whose guards are still counted. Listener-local observability counters (`active_connections`, `active_backend_connections`, byte counters) stay per listener.
- **HTTP-family WebSocket (H1/H2/H3)**: a proxied WebSocket opens one dedicated, non-pooled backend connection whose lifetime equals the session. Acquired in the WebSocket connect loop (so a failed/rotated connect attempt frees its slot before retry) and held for the session. Over the cap, the upgrade is rejected with `503` before dialing.
  - **One socket, one charge — mesh WebSocket egress.** A WebSocket to a `mesh.mtls` / `mesh.hbone` destination still opens exactly ONE physical connection: `open_ws_connect_tunnel` (Sidecar `:15006`) and `get_ws_byte_tunnel` (Ambient `:15008`) dial a fresh **1:1** tunnel per session rather than reusing a pooled one. That socket's slot is the session guard the connect loop already holds on the logical `(backend host, policy port)` lane, so those two dials deliberately pass NO admission lane of their own. Admitting inside the pool as well would charge one socket twice — and at `maxConnections: 1` the dial would refuse itself, failing *every* upgrade to a capped mesh destination. The pooled/shared tunnel creates and the raw-TCP / datagram tunnel dials have no caller-side guard and therefore keep admitting their own connections. Pinned by `mesh_websocket_dedicated_dials_do_not_double_charge_the_session_slot` and `non_websocket_mesh_tunnel_dials_still_resolve_their_own_admission_lane` in `tests/integration/mesh_destination_rule_max_connections_tests.rs`.
- **Pooled multiplexed transports (direct H2, gRPC, native HTTP/3, HBONE, mesh-mTLS)**: the slot is reserved at the exact moment a NEW physical connection is about to be constructed — after the pool has already missed its cache, so reuse never takes a slot — and is then handed to that connection's own lifecycle owner: the spawned hyper/`h2` connection-driver task for the H2-family pools, and the spawned `h3` connection-driver task for QUIC (it owns the `h3_quinn::Connection`, so its `poll_close` resolves exactly when the QUIC connection ends). The slot is deliberately NOT parked on the pooled handle: an evicted or force-drained handle can drop while the physical connection is still open, which would release the slot early and let a replacement connection push the destination past the cap. Consequences, all of them exact rather than approximated:
  - **Creation failure** (DNS, TCP, TLS, ALPN mismatch, h2/h3 handshake) drops the reservation before any driver exists, so nothing leaks. The reservation is cloned per DNS candidate, so a failed candidate frees its clone while a later candidate can still succeed.
  - **Reuse** of a pooled connection takes no slot at all, and **multiplexed streams** are unbounded by this knob — `http2MaxRequests` / `h2_max_concurrent_streams` remains the stream-concurrency control.
  - **Idle eviction, unhealthy replacement, `clear()`, `force_drain_svid_generation` (SVID rotation), config reload/update/delete, and shutdown** all drop the pooled handle. The slot retires when the driver ends — i.e. when the socket actually closes — which is the point of holding it there: a drained-but-still-open connection keeps occupying its slot, so a replacement to the same destination is admitted only once the old driver has terminated, and then it is admitted normally. There is no separate retirement path to keep in sync.
  - **Over-cap create** returns a refusal classified `BackendConnectionLimit` (`Http2PoolError::MaxConnectionsExceeded`, `GrpcBackendUnavailableKind::MaxConnections`, `HbonePoolError::MaxConnectionsExceeded`, and the typed marker the native-H3 `anyhow` create surface carries). That class exists because the refusal is simultaneously **pre-wire** — so `retry_on_connect_failure` may rotate to another LB target with its own lane — and **backend-health-neutral** (a `client_side_no_backend_signal` class): the ceiling is the operator's own gateway-side policy, so a saturated cap records no circuit-breaker failure, no passive-health failure, no load-balancer penalty sample, and no adaptive-concurrency shrink. That is the *full* raw-TCP over-cap posture, which rotates targets **and** records `cb.record_neutral()`. Using the generic `ConnectionPoolError` here would have ejected a perfectly healthy destination from the load balancer whenever live traffic saturated its configured cap. The retry loop's per-attempt circuit-breaker record honors the same neutrality, so a rotating over-cap retry cannot open the breaker either. The direct-H2 and gRPC pools first fall back to an already-established shard, so a destination whose cap is smaller than `http2_connections_per_host` simply converges on `cap` connections and multiplexes onto them instead of failing requests.
- **reqwest (HTTP/1.1 and ALPN-negotiated HTTP/2)**: `reqwest::Client` owns and hides its internal socket pool (`src/connection_pool.rs`), so the slot is taken inside reqwest's own connector — the one place a NEW physical socket is dialed — through the vendored `ClientBuilder::connection_admission` hook (`docs/upstream-reqwest-patches/003-connection-admission-hook/`). Pooled reuse and multiplexed H2 streams never reach the connector and take no slot; the token the hook returns is owned by the connection object, so an idle socket reqwest retains after a request STILL holds its slot, and the slot retires when the socket actually closes. A request-lifetime slot would have been wrong on both counts — it reads zero while sockets stay open, and it counts H2 streams rather than connections. One shared hook across every `reqwest::Client` means divergent pool keys (TLS material, `rcfg`, forced-H1 ALPN, subset) for one destination share ONE ceiling.
- **reqwest lane binding**: the connector sees only the dial `(host, port)` from the request URI, so the dispatch path takes an RAII **lane lease** (dial `(host, port)` → policy port + cap) immediately before handing the request to reqwest and releases it when `send()` resolves — exactly the window in which that request can cause a new physical dial. Leases are taken only when a cap is configured, so an uncapped destination touches nothing. Over the cap the dial is refused and the request is answered `503`, classified `DispatchPolicyRejected` (recognized from the connector error chain by `backend_conn_limit::is_backend_connection_limit_error`) so it stays neutral to backend health, circuit breaker, and adaptive concurrency. The connection-failure retry path takes its own lease for the (possibly rotated) retry target and re-enters the same gate per attempt.
  - **Reload/update/delete.** A lane exists *exactly while* some capped dispatch holds a lease on it, so a `maxConnections` an operator removed stops applying as soon as the requests dispatched under the old configuration drain — there is no epoch registry to sweep and nothing to leak. A cap the operator *changed* is replaced wholesale by the first dispatch carrying the newer config generation; a request pinned to a retired generation keeps its lease (the destination stays governed) but may never weaken the live policy back to the retired one.
  - **Conflicting lanes resolve to the strictest, deterministically.** Several logical upstreams (different proxies, subsets, or `targetPort` remaps) can resolve DIFFERENT `(policy port, cap)` for the SAME dial address. `maxConnections` is deliberately not part of the reqwest pool key — it changes admission, not connection identity — so those upstreams share one `reqwest::Client` and therefore one physical socket pool. A socket admitted under the laxer lane is then *reused* by the stricter upstream, so binding each connect attempt to its own publisher's lane would not enforce the stricter cap; it would only decide, nondeterministically, which request paid for the socket. Ferrum therefore admits against the strictest live lane (lowest cap, ties broken by policy port), which is order-independent, fail-closed, and identical to the exact configured cap in the ordinary single-lane case. Pinned by `conflicting_reqwest_lanes_resolve_to_the_strictest_in_either_order` in `tests/integration/mesh_destination_rule_connection_pool_audit_tests.rs`.
  - **Residual.** A reqwest `reqwest::Client` shared with a proxy that has *no* cap for the same destination can still dial unadmitted sockets (nothing leases a lane for it), and startup warmup probes (`FERRUM_POOL_WARMUP_ENABLED`) run before any dispatch holds a lease, so a warmup socket is admitted uncapped and is then reused by real traffic rather than added to it.

## Observability

### RED Metrics

The auto-injected `workload_metrics` plugin supplies Istio/GAMMA labels and Telemetry policy for these RED and lifecycle families. Registry updates occur only when the one enabled process-global `prometheus_metrics` plugin also observes the request or stream; mesh mode does not auto-inject that exporter. Without it, TCP lifecycle production and gRPC body scanning remain silent, just like the other plugin-owned families:

- `ferrum_mesh_requests_total` -- request counter.
- `ferrum_mesh_request_duration_ms` -- request duration histogram.
- `ferrum_mesh_request_bytes` / `ferrum_mesh_response_bytes` -- HTTP/gRPC body-size histograms (`REQUEST_SIZE` / `RESPONSE_SIZE`).
- `ferrum_mesh_tcp_connections_opened_total` / `ferrum_mesh_tcp_connections_closed_total` -- raw stream-path TCP connection lifecycle counters. Both halves are keyed on a once-only finalizer: `TCP_OPENED_CONNECTIONS` is emitted once by the stream path after the last `on_stream_connect` hook that actually ran, under the final mesh identity, tag-override, and disable metadata for that path — not from inside the `workload_metrics` hook, which several effective instances may each run over intermediate metadata. This is a connection lifecycle family, not an authorization-success counter: plugin rejection and client-disconnect-during-admission paths that reached both metrics hooks also finalize once before their disconnect summary, so opened and closed stay balanced. Captured mesh egress TCP finalizes after selected target metadata (including `mesh.destination.principal`) is stamped, or at teardown when no target was selected; UDP/DTLS streams remain excluded by their `udp` request protocol. Ambient destination relays are HTTP/2 HBONE CONNECT transactions rather than raw stream-plugin transactions, so they contribute request/response metrics and `ferrum_mesh_hbone_relay_failures_total`, not these TCP lifecycle families.
- `ferrum_mesh_tcp_sent_bytes_total` / `ferrum_mesh_tcp_received_bytes_total` -- TCP byte counters recorded on disconnect with Istio Telemetry semantics: **sent** is response bytes (backend-to-client) and **received** is request bytes (client-to-backend). This intentionally differs from the gateway-perspective `StreamTransactionSummary.bytes_sent` / `bytes_received` and `ferrum_api_bytes_sent_total` / `ferrum_api_bytes_received_total` field convention; the mesh producer maps those authoritative counters into the standard Istio directions. `TCP_SENT_BYTES` / `TCP_RECEIVED_BYTES` selectors, disable rules, and tag overrides therefore retain their Istio meaning.
- `ferrum_mesh_request_messages_total` / `ferrum_mesh_response_messages_total` -- gRPC length-prefixed message counters observed, when `prometheus_metrics` is enabled, on supported H1/H2/H3 frontend and direct-H2/HBONE/mesh-mTLS request and response body paths. Only complete 5-byte length-prefixed frames count; incomplete trailing frames are ignored. Both counters describe the **native gRPC representation exchanged with the backend**: requests are counted after the request-body transforms run (so a translated gRPC-Web request is counted once its text-mode base64 is decoded and its terminal trailer frame is stripped), and responses are counted from the backend's own frames before any gRPC-Web re-framing or base64 armouring. A gRPC-Web terminal trailer frame is metadata, not a message, and is never counted. Buffered request bodies are recorded with `fetch_max`, so a retry replaying the same buffer cannot inflate the count.

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
- `ferrum_xds_streams_rejected_total` -- aggregate count of ADS streams the CP rejected at admission, in **any** scope: total, per-namespace, per-principal, per-node, distinct-node cardinality, an invalid `Node.id`, or the initial-request deadline. Emitted without labels because every dimension that could distinguish the rejections (`Node.id`, JWT subject, SPIFFE URI) is client-controlled and would be unbounded. A growing value flags a misconfigured or hostile client opening many streams.
- `ferrum_xds_stream_admission_rejections_total{reason}` -- the same rejections broken down by a **closed, compile-time** reason set: `total_streams`, `namespace_streams`, `principal_streams`, `node_streams`, `node_cardinality`, `node_id_empty`, `node_id_too_long`, `node_id_unsafe_characters`, `first_request_timeout`. The label is a `&'static str` from an enum, so the series count is fixed and no client-supplied text can reach `/metrics`. The reject site logs the CP-resolved namespace and a **redacted digest** of the offending node id — never the raw value, which an authenticated peer would otherwise be able to inject into the CP log stream.
- `ferrum_xds_active_streams` / `ferrum_xds_active_node_ids` -- absolute gauges for currently active ADS streams (SotW plus Delta) and distinct active node state keys. Both are label-free for the same cardinality reason and return to `0` when the last stream ends. Occupancy is published by atomic deltas tied to successful aggregate/node admission and exactly-once release (never by racing load-then-store snapshots). Alert on sustained proximity to `FERRUM_XDS_MAX_TOTAL_STREAMS` / `FERRUM_XDS_MAX_ACTIVE_NODES`.
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
  metadata is absent and are therefore always present — for example,
  `has(source.workload)` is always true and cannot distinguish anonymous or
  unresolved peers from named workloads. Only `request.method` and
  `request.host` can be absent (missing/empty internal stamps). Integer
  attributes are not valid `has()` operands.

  Headers, body bytes, credentials, client IPs, and request paths are rejected (credential exposure and/or unbounded cardinality). HTTP-only attributes (`request.method`, `request.host`, `response.code`) fail closed when the override targets a TCP family or `ALL_METRICS`. Missing attributes evaluate to an empty sanitized label rather than inventing traffic data; output is truncated to 256 UTF-8 bytes and stripped of quotes/controls. Missing, empty, malformed, unsupported, or over-budget expressions make the Telemetry resource invalid (`FerrumAccepted=False`) with field-specific diagnostics that never echo expression text. Supported metric selectors are `REQUEST_COUNT`, `REQUEST_DURATION`, `REQUEST_SIZE`, `RESPONSE_SIZE`, `TCP_OPENED_CONNECTIONS`, `TCP_CLOSED_CONNECTIONS`, `TCP_SENT_BYTES`, `TCP_RECEIVED_BYTES`, `GRPC_REQUEST_MESSAGES`, `GRPC_RESPONSE_MESSAGES`, the matching `ferrum_mesh_*` names, and `ALL_METRICS`. Unsupported tag names, unsafe or oversized literal values, and unknown metric selectors likewise fail translation visibly. A changed label shape creates a new Prometheus series; the previous series ages out under the configured stale-entry TTL.

  **Dynamic series budget.** Exact CEL-derived label values and ordinary mesh identity series share one finite per-family live-series budget (`mesh_series_budget_per_family` on the global `prometheus_metrics` plugin; default `10_000`, range `1`–`1_000_000`) of distinct `MeshRequestKey` entries per mesh metric family in the process `MetricsRegistry`. Admission uses exact atomic reservation (not `DashMap::len()`). Already-admitted keys continue to update at capacity. A previously unseen key beyond the budget — including a newly observed legitimate identity combination — is dropped for that family and counted on the fixed-cardinality overflow series `ferrum_mesh_metric_series_overflow_total{family}` where `family` is one of the ten closed names (`request_count`, `request_duration`, `request_size`, `response_size`, `tcp_opened_connections`, `tcp_closed_connections`, `tcp_sent_bytes`, `tcp_received_bytes`, `grpc_request_messages`, `grpc_response_messages`). Stale TTL eviction releases live capacity so later distinct keys can be admitted again. Because the cap is shared across identity and CEL dimensions, CEL cardinality pressure can suppress newly observed identity series until eviction frees slots (and the reverse). `0` is rejected — there is no unlimited mode. The default is sized for large legitimate meshes (thousands of src×dst×code combinations) while bounding attacker-controlled CEL cardinality such as `request.host` or custom HTTP methods rewritten into metric labels. `request.host` / `request.method` / `destination.port` metadata is stamped only when an active CEL expression requires it, under the reserved internal-only `mesh.metrics.cel.*` namespace so those temporary values never become transaction-log or trace attributes.
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
| `ebpf` | eBPF-based capture handled by a node-level agent (requires kernel 5.7+). The injector does not inject a privileged init container for this mode -- the node agent's DaemonSet manages eBPF program attachment. Capture planning infrastructure (`EbpfPlan` with iptables fallback for pre-5.7 kernels) is available in `src/capture/mod.rs` for the node agent path. **Build requirement:** real eBPF attachment needs a binary built with the Cargo `ebpf` feature (`cargo build --features ebpf`, Linux only; Docker `--target runtime-ebpf --build-arg FEATURES=cloud-secrets,ebpf`). The **default published image uses a no-op mock backend** (`MockEbpfBackend`) that attaches nothing and sets `ferrum_mesh_node_topology_degraded` — see [Maturity and Support Status](#maturity-and-support-status) |

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
  discriminator, so the **node-agent's host-netns iptables fallback emits NO UDP
  TPROXY rules** (`CaptureConfig::host_netns` short-circuits
  `udp_tproxy_commands_for_family`) and logs the limitation when
  `FERRUM_MESH_CAPTURE_UDP_ENABLED=true`. The node-agent has no UDP listener
  either, and rules without a socket are a black hole, so it stays out of the UDP
  datapath entirely; **eBPF does not cover UDP** — the eBPF capture programs are
  `connect()`-cgroup-hooked and TCP-only (no UDP hooks; see the node-waypoint
  UDP/DTLS limitation above). What DOES capture UDP in the host namespace is the
  mesh proxy's **host-network UDP capture path**
  (`FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED`, issue #3288), which replaces the
  `addrtype` split with an **ingress-interface** split — see "Host-network UDP
  capture" below. UDP capture otherwise lives in the **injector's pod-netns path**
  (its iptables init container
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
  **pod-netns rule generator** still installs no UDP TPROXY rules for
  `host_netns` (`CaptureConfig::host_netns` short-circuits
  `udp_tproxy_commands_for_family` — the `--dst-type LOCAL` direction split is
  unsafe in the host netns). Ambient's UDP source-capture rides one of two
  placements, both consuming the same relay/session machinery:

  * **Per-pod-netns producer** (#2013, the default; see the end-to-end status
    bullet under Stages 3–4): installs the UDP TPROXY rules and binds the
    transparent sockets INSIDE each enrolled pod's netns via `setns`.
  * **Host-network capture** (#3288, `FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED=true`;
    see "Host-network UDP capture" below): installs interface-scoped rules and one
    transparent socket in the proxy's own namespace, entering no pod namespace.

  eBPF UDP capture (#1803) stays a non-goal. **Fail-closed on
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
  framed **per segment**, not as one superblock. When the mesh proxy itself binds
  the capture port (Sidecar, or Ambient with the host-netns placement), that port
  is added to `reserved_gateway_ports()`, so a mesh UDP/DTLS stream proxy or
  ServiceEntry declaring the same listen port is rejected at validation rather
  than racing the capture listener at startup. Ambient's default per-pod-netns
  placement binds inside each pod and therefore does not reserve the host port.
  The listener carries
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
  source-capture + enrolled-destination round trip (destination pod-netns relay
  socket, tc-inbound admit, and reply path inside the destination pod netns) is
  not yet live-gated — tracked on [#3621](https://github.com/ferrum-edge/ferrum-edge/issues/3621).
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
  destination echo on host loopback (not an enrolled destination pod netns) →
  transparent reply sourced from the original VIP:port. The enrolled-destination
  two-pod fixture (destination workload inside its own pod netns with registry
  mapping and tc-inbound guard) remains the residual tracked on
  [#3621](https://github.com/ferrum-edge/ferrum-edge/issues/3621); see [12].
  eBPF UDP capture stays a non-goal (#1803 per-pod TC not resurrected).
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
  does not terminate mesh DTLS). **East-west pod→peer only** for DTLS; external
  **DTLS** egress via the EgressGateway stays out of scope. External `protocol: UDP`
  ServiceEntry egress IS materialized (issue #3263) — see "External UDP egress
  (EgressGateway)" — including the source-side producer that originates the
  `udp` CONNECT. The opaque relay is regression-pinned by
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

The SPIRE backend is the recommended production path for mesh identity. `internal` is intended for development and testing only -- it generates a self-signed root CA at startup with no external trust anchor. Explicit `FERRUM_GATEWAY_SVID_*` source material takes precedence over `FERRUM_MESH_CA_BACKEND`; when both are configured Ferrum uses the configured SVID and does not start automatic CA-backed issuance.

### Workload API JWT-SVID

Ferrum's Workload API serves JWT-SVIDs **when the selected CA backend owns a JWT signing authority**, and fails closed with gRPC `UNIMPLEMENTED` when it does not. Backend support today:

| `FERRUM_MESH_CA_BACKEND` | Can Ferrum serve a Workload API on it? | `FetchJWTSVID` | `FetchJWTBundles` | `ValidateJWTSVID` |
|---|---|---|---|---|
| `internal` | ✅ yes | ✅ mint | ✅ stream | ✅ validate |
| `spire` | ❌ **refused at startup** (see the boundary below) | — | — | — |
| Vault PKI / cert-manager scaffolds | ❌ no CA backend selection exists for them today | — | — | — |

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

Startup is fail-closed at every step. The surface requires `FERRUM_MESH_CA_BACKEND=internal`, `FERRUM_MESH_WORKLOAD_SPIFFE_ID`, and the dev-only `FERRUM_MESH_CA_BOOTSTRAP_DEV=true` self-signed-root opt-in (it mints from the same runtime authority the mesh SVID rotation loop drives), no explicit `FERRUM_GATEWAY_SVID_*` file override (file identity suppresses that authority source), and at least one attestor rule; a socket-contract, permission, or bind failure **fails startup** rather than leaving the surface silently unbound. Because the internal CA currently has only this dev/test bootstrap and that bootstrap is refused under `FERRUM_MESH_PRODUCTION_MODE=true`, Ferrum's in-process Workload API is currently **dev/test-only and unavailable in production mode**.

The socket is a credential-adjacent surface — whoever can replace it can impersonate the endpoint workloads dial for their identity — so the contract below is validated **before** bind, and each clause is a guarantee Ferrum actually enforces rather than an aspiration:

- the path must be absolute and contain no `.`/`..` component. The check reads the **raw Unix path segments**, not `Path::components()`: that iterator normalizes an embedded `.` away, so a rejection written over it would have accepted `/run/ferrum/./workload-api/socket` — a path that is not the one the operator wrote;
- the parent directory must already exist. Ferrum never creates it, because creating it would mean choosing its owner and mode on the operator's behalf, and a directory created under a planted symlink is exactly the escape this refuses. It must also be at most **74 bytes**, because the socket is bound inside a private staging directory beneath it and *that* path is what has to fit `sockaddr_un.sun_path`;
- **every directory component from `/` down to that parent** is checked, not just the parent: whoever controls an ancestor can rename the whole subtree aside and substitute their own, so a pristine parent under a writable `/run` proves nothing. Each component must be
  - a real directory — a **symlink component is refused, never followed**, because a link's owner rather than the directory's decides where the socket lands, and because a followed link means the path an operator reads in configuration and the path Ferrum binds are different objects;
  - owned by this process's effective uid **or by root**. Ownership is checked independently of mode: a directory's owner may modify its entries whatever the permission bits say, so a `0700` directory belonging to another user is refused even though nothing in it looks writable;
  - **not group- or world-writable** unless it carries the sticky bit. Group-writable counts: a member of that group is an untrusted actor exactly as a world user is. Sticky is what makes shared-writable safe (`/tmp`, `/run` on some distributions) — a non-owner can create entries but cannot unlink or rename ours. The directory's own owner is *not* constrained by sticky, which is why the ownership check above is not redundant with this one;
- a regular file, a directory, a symlink, or another user's socket at the path is refused rather than deleted;
- an existing socket **owned by this uid is still not assumed stale**. Ownership was never evidence of staleness: a second Ferrum process running as the same user would have unlinked the first one's *live* Workload API socket and taken over the endpoint workloads dial for their identity. So liveness is established positively, with a real Unix-domain `connect(2)`:
  - a **successful connection means live** — startup is refused and nothing is unlinked;
  - only a **connection-refused / not-listening** result admits the socket as leftover from a crashed run;
  - **anything ambiguous fails closed** (`EACCES`, a listener whose backlog is full, a timeout, any other error). "We could not tell" is never read as "nobody is there".

  The probe is **asynchronous and bounded** (2s). A blocking connect from the startup path would let a peer that is listening but no longer draining its accept queue hold startup open indefinitely — an outcome neither of the refusals above covers — so the connect runs on the async socket under a deadline, and expiring that deadline is simply one more answer we did not get: ambiguous, therefore fatal. Immediately before the unlink the artifact's device, inode, type, and owner are re-checked against what was probed. Because a pathname recheck plus `unlink(2)` is not one atomic POSIX operation, Ferrum additionally serializes the complete socket lifecycle — stale cleanup, no-clobber publication, serving, and identity-checked shutdown cleanup — with a per-socket advisory lock. Concurrent same-uid Ferrum processes therefore cannot publish in either the startup or shutdown recheck-to-unlink gap: a contender probes a published winner as live and refuses, while a contender that sees no reachable listener waits up to the bounded 5s lock deadline. The `0600` lock sidecar (`.<socket-name>.startup.lock`) is created under the already-validated parent and deliberately retained across runs so waiters never lock an unlinked inode while a newcomer locks a replacement inode;
- the configured mode is established **without ever touching the process umask**. The umask is process-global, and by the time this runs mesh mode has already started admin and background tasks that create files, so narrowing it would silently change *their* permissions. Instead the socket is published in three steps: a private staging directory is created under the validated parent with `mkdir(2)` mode `0700` (a requested `0700` can only be narrowed by a umask, never widened, and its mode is verified anyway); the socket is bound **inside** it and permissioned and verified there, so whatever mode `bind(2)` applied is unreachable to any other user for the whole window and no permissive temporary endpoint ever exists; then it is **published onto the configured path with a primitive that refuses an existing destination** and re-verified afterwards as a socket owned by this process with exactly the configured mode and the same `(device, inode)`. That pair becomes the **bound identity**. If it cannot be established, startup fails and every artifact (staged socket, staging directory, a published socket that failed its post-publication check) is removed identity-checked;
- publication is **no-clobber, not `rename(2)`**. POSIX rename silently replaces whatever is at the destination, and the destination is probed for liveness *before* the socket is bound — so a peer that binds the path in between would have had its live listener clobbered by the same startup that refuses to unlink one. Ferrum publishes with `link(2)` instead: it fails atomically with `EEXIST` when the destination exists, and it creates a second name for the inode the listener is already bound to, which a workload's connect resolves to exactly as it would the staged name. Only the staging alias is then unlinked. Apple filesystems refuse a hard link to anything but a regular file, so `renamex_np(RENAME_EXCL)` plays the same role there; a filesystem offering neither fails startup rather than falling back to an overwriting rename. **An occupied destination fails startup and the competing artifact is never removed**;
- the mode itself must permit a connection. `connect(2)` on a Unix socket requires **write** permission, so a mode with no owner or group write bit — `0000`, `0440` — is refused at configuration parse rather than bound and then found to reject every workload. World-writable is refused for the opposite reason;
- on shutdown the socket is unlinked while the lifecycle lock is still held and only if it is still the exact socket Ferrum bound: same device and inode, **still of socket type, and still owned by this effective uid**. Device+inode alone is an incomplete identity, because inode numbers are reused and a regular file that landed on the freed inode would otherwise satisfy it. Cleanup completes before the lock is released, so a restarted peer cannot publish a replacement in the final recheck-to-unlink window;
- an **unexpected** termination of the serve task — a tonic transport error, or a panic — initiates the shared mesh shutdown rather than leaving the data plane serving traffic with no identity endpoint. A requested shutdown is quiet: the shared flag is always set first, and the observer checks it before reporting anything.

**What is not claimed.** A POSIX Unix socket exposes no descriptor-based route to its bound filesystem inode — on Linux `fchmod(2)` on a socket fd addresses the anonymous `sockfs` inode, not the bound name — so these checks operate on pathnames and are not atomic with respect to a concurrent rename of an ancestor by a *trusted* actor (root, or the operator). The publication step is atomic against a competing *entry* at the socket path itself, which is what closes the probe-to-publish window; it is not atomic against an ancestor being moved out from under it. What the ancestor walk removes is the ability of an **untrusted** actor to perform such a rename at all; the bound-identity verification and the inode-checked cleanup bound the damage otherwise. Ferrum never chmods or unlinks a path it has not just confirmed is the object it bound.

#### Transport admission and lifetime bounds

Reaching the socket authorizes an identity **request**. It must not also grant one workload the ability to deny identity service to every other workload sharing the node, which is what an unbounded transport does: idle Unix connections, HTTP/2 stream fan-out, and RPC producers are all resources a socket-group member can allocate, and every per-RPC protection in this surface (latest-wins rotation delivery, the entitlement recheck, producer shutdown) begins *after* an RPC has already been admitted. Because this surface delivers X.509-SVID, JWT-SVID, and trust-bundle material, exhausting it prevents unrelated local workloads from renewing identity and cascades into mesh mTLS failures as their existing credentials expire.

Admission therefore runs **before an accepted socket ever reaches the gRPC stack**:

- **Kernel peer credentials first.** `SO_PEERCRED` is read off the accepted socket. It is kernel-attested and cannot be spoofed by the caller, unlike anything in gRPC metadata, and it is the only trustworthy key for a per-principal quota. A socket whose credentials cannot be read is **refused** — fail-closed, because an unattributable connection cannot be charged to any quota.
- **Per-peer-UID connections** (`FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS_PER_UID`, default `32`, hard ceiling `1024`) and then **total connections** (`FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS`, default `256`, hard ceiling `4096`), as **one** decision under a single lock. Both are taken without waiting. The order is load-bearing: taking the shared global permit first would let a burst from an already-saturated UID each hold a global slot while it queued for the per-UID check, transiently emptying the pool and refusing an innocent second UID — the exact denial the per-UID quota exists to prevent. A caller over either limit has its socket closed immediately: there is no wait queue, because a backlog of would-be connections holding descriptors behind the ceiling is the exhaustion the ceiling exists to prevent. The per-UID quota is the half that matters under attack — the global ceiling is a single shared resource and is exactly what a flood consumes first, leaving every other workload with nothing.
- The per-UID quota must be **strictly below** the global ceiling, and both the configuration gate and the defensive runtime clamp enforce that. A quota equal to the global ceiling is not a fair share: one UID may then hold every connection. A globally fair transport therefore has room for at least two connections, so `FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS` has a floor of `2` and the clamp caps the quota at `max_connections - 1` for any input, including `0`, `1`, and values far over either ceiling.
- The admitted socket is wrapped in a type that **owns** the permit, so release is tied to the connection object's lifetime rather than to any particular code path: clean close, transport error, a handshake that never completes, a cancelled task, and a panic unwind all drop the wrapper and all release the permit.

HTTP/2 and RPC ceilings sit on top. `FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_STREAMS` (default `64`, hard ceiling `1024`) is advertised as `SETTINGS_MAX_CONCURRENT_STREAMS` *and* applied as a per-connection request-concurrency limit with load shedding, so a request past it is answered `RESOURCE_EXHAUSTED` rather than buffered. `FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_RPCS` (default `1024`, minimum `2`, hard ceiling `8192`) bounds the product service-wide; its permit is taken at the top of every RPC — before metadata validation, attestation, CA issuance, or any spawned rotation producer — and for a **streaming** RPC it is held for the whole life of the response stream, which is where the producer task, rotation subscription, and pending private-key slot actually live. That permit lifetime is why the default is sized from *legitimate* occupancy rather than from request rate: a normal client keeps up to three long-lived streams open (`FetchX509SVID`, `FetchX509Bundles`, `FetchJWTBundles`), so the default leaves room for three on each of the 256 default connections. A service-wide ceiling below that would make the shipped configuration contradict itself — the connection ceiling would admit peers this ceiling then had to shed, and the shed would land on SVID renewal. An explicit operator value is never silently rewritten: a contradictory one is refused with a diagnostic naming both settings.

**Fair share applies to RPCs too, not only to connections.** A per-UID *connection* quota does not bound a UID's share of the *service*: at the defaults one socket-group UID may hold 32 connections x 64 streams = 2048 concurrent RPCs, comfortably more than the service-wide ceiling, and the two bundle RPCs require only the mandatory `workload.spiffe.io` metadata header — no attestation, no entitlement — so occupying every permit costs an attacker nothing. Every other workload's SVID renewal would then be shed with `RESOURCE_EXHAUSTED`. `FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_RPCS_PER_UID` (default `128`, hard ceiling `4096`) closes that, keyed on the same kernel-attested `UdsConnectInfo` peer UID the connection quota uses and applying the identical two-level decision: the per-UID quota is judged first, then the service-wide ceiling, as one non-blocking decision under one lock, so a burst from a saturated UID never transiently drains the shared pool and sheds an innocent peer. A refused RPC creates no per-UID state, so a shed flood cannot grow the map, and a UID's entry is removed when its last permit drops, so the map is bounded by peers *currently holding* permits. An RPC whose peer UID cannot be established is refused rather than admitted unattributed. Like the connection quota, it must be **strictly below** its shared ceiling on both the configuration gate and the defensive runtime clamp — equality lets one UID hold every permit, which is the denial the bound exists to prevent.

Two lifetime deadlines close the remaining shapes. `FERRUM_MESH_WORKLOAD_API_INITIAL_CONNECTION_TIMEOUT_SECONDS` (default `10`) bounds a connection that never sends its first byte — the cheapest flood, and the one no per-request timeout can see. `FERRUM_MESH_WORKLOAD_API_IDLE_TIMEOUT_SECONDS` (default `900`) bounds time since the last byte **read from the peer**. Reads rather than writes are the liveness evidence on purpose: the server's own keepalive PINGs are writes, so counting writes would make the deadline unreachable. The keepalive interval is derived from the idle deadline (a third of it), so a live long-lived `FetchX509SVID` stream is refreshed by the peer's PING ACKs even while it is application-idle, and a peer that has stopped participating is closed.

Shutdown is bounded in three steps: admission stops immediately, the server drains gracefully for `FERRUM_MESH_WORKLOAD_API_SHUTDOWN_GRACE_SECONDS` (default `10`, hard ceiling `300`), and anything still open is then force-closed from inside the transport. The force close is load-bearing rather than a courtesy — each accepted connection is served from a detached task, and a Workload API client is *designed* to hold a stream open across rotations, so a peer that simply never closes would otherwise hold process shutdown open indefinitely.

Every limit is finite by construction. `0` is not a "disabled" spelling for any of them, an over-ceiling value is **refused** at configuration time rather than silently clamped (the number an operator sets and the number the process enforces must be the same), and the admission layer additionally clamps whatever it is handed, so a hard ceiling holds even if the runtime is reached another way.

Observability is fixed-cardinality: `ferrum_mesh_workload_api_active_connections`, `ferrum_mesh_workload_api_active_rpcs`, `ferrum_mesh_workload_api_connections_rejected_total{reason}`, `ferrum_mesh_workload_api_connections_closed_total{reason}`, and `ferrum_mesh_workload_api_rpcs_rejected_total`. The `reason` dimension is a closed set of compile-time constants. The RPC-shed counter is deliberately **unlabelled** and covers both RPC bounds together: the only honest key for the per-UID half is the peer UID, and a synthetic stand-in that operators would learn to map back to a principal is the same disclosure with extra steps, so which of the two bounds refused is stated only in the (off-by-default, UID-free) `debug!`. Peer UID, PID, SPIFFE ID, and token material are never metric labels — they are attacker-influenced or credential-adjacent, so a label built from one would be both an unbounded cardinality dimension and a disclosure surface. Rejection `debug!` logs carry only fixed reason/limit context and no raw caller identifiers or credential metadata; they are off by default and therefore cannot themselves be flooded into a disk-exhaustion primitive.

The two RPC families are the closest thing here to a stream observation, and the relationship is **one-way** — their help text states exactly that and no more. Every admitted Workload API RPC occupies exactly one HTTP/2 stream for its whole lifetime, but not every live HTTP/2 stream is an admitted Workload API RPC: an unknown or malformed route is rejected before service dispatch, and a stream past the advertised `SETTINGS_MAX_CONCURRENT_STREAMS` is refused inside the h2 state machine with `REFUSED_STREAM` before any Ferrum code runs. Neither is counted. So `ferrum_mesh_workload_api_active_rpcs` is the count of **service-dispatched** Workload API RPC streams rather than the live stream count, and `ferrum_mesh_workload_api_rpcs_rejected_total` counts RPCs shed *after* h2 had already opened and accepted their stream — a `RESOURCE_EXHAUSTED` gRPC result on a live stream, not a protocol-level stream refusal. There is deliberately no second stream family: transport-level excess streams are refused where this layer cannot see them, and a counter claiming to observe them would be claiming coverage the implementation does not have.

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
- **`ValidateJWTSVID`** verifies signature, key id, audience, subject SPIFFE syntax and trust domain, issuer (when present), `exp` (mandatory), `nbf`, and `iat`. It refuses `alg: none`, the HMAC family, unknown or ambiguous key ids, unknown trust domains, unknown critical headers, repeated JSON keys in the header or claims, and oversized tokens or claim documents. Rejection reasons are fixed strings — no token bytes, claim values, or key material appear in an error.
- **Rotation overlap, and why it is provable.** This bounds the **ephemeral** posture's in-process rotation; configured material is rotated externally and its previous key is published for as long as it stays configured. A key retired in process stays published for verification for the maximum token lifetime plus clock-skew leeway (1 h + 60 s), so a token minted an instant before a rotation remains verifiable for its whole bounded lifetime; after that window the key disappears. Retained keys are additionally capped, bounding memory and bundle size — and the cap and the cadence are made *consistent* rather than left to collide:
  - a `FERRUM_MESH_JWT_KEY_LIFETIME_SECONDS` shorter than the overlap divided by the published-authority budget is **refused at startup** (minimum `244` at the 1 h ceiling), because no cap within the 16-authority limit could hold every still-verifiable key;
  - the retention cap is **derived up** from the cadence, so the scheduled rotation never needs to evict anything;
  - a rotation that would nevertheless have to drop a key still inside its overlap — reachable only by driving rotation far faster than the schedule — is **refused**. The active key stays active and every minted token stays verifiable; Ferrum never trades a live token's validity for a cap.
  Rotation runs on the mesh rotation task, never on a request path, and it bumps the SVID rotation revision, so the new JWKS is republished on every already-open `FetchJWTBundles` stream with no reconnect.
- **Authority bounds are enforced before publication *and* before validation.** Every trust domain's complete authority set — local and federated, locally produced or supplied through a configured external adapter — goes through one admission gate: authority count cap, exact trust-domain binding, duplicate-`kid` refusal, key-id / PEM / DER / key-type / key-size constraints, and total JWKS size. `ValidateJWTSVID` therefore cannot accept material `FetchJWTBundles` would have refused, and a malformed or oversized externally supplied bundle fails closed instead of driving an unbounded scan. Malformed federated material fails the call rather than being silently dropped from the trusted set.
- **Cryptographic admission, not just structural admission.** Shape is neither strength nor curve membership, so the same gate additionally proves each key is usable before it is published or turned into a verifier: an RSA modulus is bounded by its **significant** bit length (`2048..=8192`, so a 2041-bit modulus padded into 256 bytes is refused and leading zero octets never count), an RSA public exponent must be odd and at least 3 within a bounded encoding (`0`, `1`, `2`, and even values are refused; real keys are 65537), externally supplied `n`/`e` must be canonical unsigned big-endian with no leading zero octet (RFC 7518 §6.3.1), and an EC point must actually lie on its named curve and not be the identity. Curve membership is proven with a bounded ephemeral ECDH agreement through Ferrum's cryptographic-provider seam (`ring` on an ordinary build, the AWS-LC FIPS module on a `fips` build — see [docs/fips.md](fips.md)), so no second, unrouted elliptic implementation is introduced on a trust-admission path. Every rejection is a fixed string; no key bytes reach an error.
- **Federated trust domains are bounded at configuration, not per response.** The configured federated set is deduplicated, stripped of the local trust domain, and capped once when the service is built; an over-cap list is an error rather than a silent truncation, so the number of CA calls one bundle RPC can make is fixed before any of them is issued. Counting successfully published bundles instead would have let arbitrarily many empty or failing aliases drive unbounded CA work.

Like `FetchX509Bundles`, the bundle and validate RPCs require the mandatory `workload.spiffe.io: true` metadata header but do not run the attestor chain — they consume public trust material and mint nothing. Private-key and token issuance stay gated on `FetchX509SVID` / `FetchJWTSVID`.

#### Workload API CA error status contract

When a Workload API RPC fails because the configured certificate authority returned a `CaError`, Ferrum converts that failure **once** at the Workload API boundary into a stable gRPC status. Clients must not couple to provider, configuration, filesystem, trust-domain, or OS diagnostics — those details stay server-side in structured logs that carry only fixed-cardinality `operation` and `error_class` fields.

| `CaError` variant | gRPC code | Fixed client message |
|---|---|---|
| `BadCsr` | `INVALID_ARGUMENT` | `certificate request rejected` |
| `UnknownTrustDomain` | `PERMISSION_DENIED` | `trust domain not authorized` |
| `Upstream` | `UNAVAILABLE` | `certificate authority unavailable` |
| `Config` / `Internal` / `Io` | `INTERNAL` | `certificate authority operation failed` |

This mapping applies to initial `FetchX509SVID` construction, the static/rotation response helpers shared by stream refresh, local and federated X.509 bundle fetches, the bundle-only `FetchX509Bundles` RPC (which still requires the mandatory metadata header but does not run attestation), and the JWT-authority collection path used by `FetchJWTBundles` / `ValidateJWTSVID`. Transient CA failures on an already-open rotation stream stay server-side and do not terminate a healthy stream; entitlement denials from re-attestation remain terminal `PERMISSION_DENIED` as before. Workload attestation failures keep their own fixed `PERMISSION_DENIED` / `workload attestation failed` contract and are unchanged by this mapping.

#### SPIRE backend: serving a Workload API is refused

**`FERRUM_MESH_WORKLOAD_API_ENABLED=true` together with `FERRUM_MESH_CA_BACKEND=spire` is refused at startup**, with a diagnostic naming both settings. This is a terminal capability boundary, not a deferral, and it applies to the *whole surface* rather than to the JWT RPCs alone.

A SPIRE agent issues only the **calling process's own** attested identity. Ferrum's `SpireAgentCa` therefore fetches Ferrum's agent SVID and refuses every other subject, while a Workload API server exists precisely to issue for a *different*, locally attested downstream workload:

- `FetchX509SVID` would ask that CA to issue for the attested caller's SPIFFE ID, which it cannot do — every request would fail;
- `FetchJWTSVID` is authorized by SPIRE against the calling process too, so proxying the agent's own mint RPC would return a token whose `sub` is Ferrum's SPIFFE ID rather than the workload's. A silent identity substitution is strictly worse for a relying party than a refusal, so Ferrum does not do it and **must not** be "fixed" to.

Minting for a delegated subject requires SPIRE's delegated-identity / admin API — an explicitly authorized integration outside the Workload API surface Ferrum consumes. Until such an integration exists, enabling the surface on this backend is refused rather than allowed to bind an endpoint that could only mis-issue or reject.

**What still works under `spire` is X.509 consumption, which is a different capability.** The active mesh runtime consumes the agent's X.509 SVID and trust bundles through its dedicated fetch loop, retaining the last good identity across reconnects and publishing rotations to the live TLS slots. The reusable `SpireAgentCa` / `WorkloadApiClient` adapter can decode a bounded `FetchJWTBundles` stream when explicitly constructed, but mesh startup does not construct that adapter or start its JWT stream today. This change therefore makes no production claim that SPIRE JWT authorities back Ferrum validation. None of the X.509 consumption amounts to delegated issuance, and the docs deliberately do not conflate the two.

Workloads that need SVID mint alongside a SPIRE deployment should call their local SPIRE agent's Workload API directly — that is the socket SPIRE authorizes them on — or run `FERRUM_MESH_CA_BACKEND=internal` with configured JWT signing material.

Mesh `RequestAuthentication` / `jwks_auth` continues to validate application JWTs via its own JWKS fetch and is unrelated to Workload API JWT-SVIDs. See [docs/spire_deployment.md](spire_deployment.md#jwt-svids).

### Internal Dev CA and Production Guardrails

The `internal` CA backend is backed by a self-signed root produced by the dev bootstrap helper in `src/identity/ca/bootstrap.rs`. To make it impossible to accidentally run a production mesh on an unanchored self-signed root, the helper is protected by two environment guardrails, both read directly at the time the helper is invoked (they are **not** parsed into `EnvConfig`):

| Variable | Default | Semantics |
|---|---|---|
| `FERRUM_MESH_PRODUCTION_MODE` | `false` | Master kill-switch for all dev-only identity shortcuts **and** gateway-wide TLS verification bypasses. When `true`, the self-signed CA bootstrap, construction of the dev-only static attestor (`FERRUM_MESH_ALLOW_STATIC_ID`), the process-local JWT signing key (`FERRUM_MESH_ALLOW_EPHEMERAL_JWT_KEY`), the no-identity posture (`FERRUM_MESH_ALLOW_NO_CA`), and **`FERRUM_TLS_NO_VERIFY` / `FERRUM_ADMIN_TLS_NO_VERIFY`** are **refused unconditionally** (the TLS switches at the shared `EnvConfig` validation path used by both `validate` and runtime startup, for every mesh topology, before listeners or background pollers start). Set this in every production deployment. |
| `FERRUM_MESH_CA_BOOTSTRAP_DEV` | `false` | Explicit opt-in to generate a self-signed mesh root. The helper refuses unless this is `true`. When it runs it emits a loud `warn!` (`DEV-ONLY, never use in production`). |
| `FERRUM_MESH_ALLOW_STATIC_ID` | `false` | Sibling guardrail (not CA-specific): the dev-only `StaticAttestor`, which returns a hard-coded SPIFFE ID for any peer, refuses to construct unless this is `true` and `FERRUM_MESH_PRODUCTION_MODE` is not `true`. |

Both gates must agree before a self-signed root is minted: `FERRUM_MESH_CA_BOOTSTRAP_DEV=true` **and** `FERRUM_MESH_PRODUCTION_MODE` not `true`. Anything else fails closed.

Relatedly, running the Experimental `FERRUM_MESH_TOPOLOGY=node_waypoint` topology under `FERRUM_MESH_PRODUCTION_MODE=true` logs a startup `warn!` (not a refusal — the production identity guardrails all still apply, and the NodeWaypoint eBPF live gate deliberately runs the production identity profile) noting that Experimental surfaces are excluded from the GA contract (see [mesh_supported_matrix.md](mesh_supported_matrix.md)).

For production mesh identity, run the SPIRE Agent backend (`FERRUM_MESH_CA_BACKEND=spire_agent`) so SVID issuance and trust-bundle distribution are anchored to a separately operated trust root. There is no `FERRUM_MESH_CA_CERT_PATH` / `FERRUM_MESH_CA_KEY_PATH` env var today — those names appear only in the bootstrap helper's refusal message as guidance for a future externally-provided-root path and are not currently read by any code path.

**No-identity startup gate.** A third member of this guardrail family is enforced at config-validation time rather than inside the identity helpers. A `mesh` data plane's runtime workload identity can come from configured gateway SVID material (`FERRUM_GATEWAY_SVID_CERT_*` + `KEY_*` + `TRUST_BUNDLE_*`) or automatic CA-backed SVID issuance (`FERRUM_MESH_CA_BACKEND=spire_agent|internal` plus `FERRUM_MESH_WORKLOAD_SPIFFE_ID`). With neither source, the mesh can't present or verify an mTLS peer certificate, so PeerAuthentication's PERMISSIVE default would silently accept unauthenticated plaintext. `EnvConfig` validation therefore **fails startup closed** in that no-identity case unless the operator sets `FERRUM_MESH_ALLOW_NO_CA=true` to acknowledge the dev/test-only posture (a loud `warn!` is logged when it does start that way). That opt-out is read **directly from the environment** (not `ferrum.conf`), matching the rest of the family. As with the other shortcuts, `FERRUM_MESH_PRODUCTION_MODE=true` refuses the no-identity posture **unconditionally** — the opt-out is ignored — so a production mesh can never come up without identity.

**TLS verification bypasses under production.** The same shared `EnvConfig` validation path refuses `FERRUM_TLS_NO_VERIFY=true` and `FERRUM_ADMIN_TLS_NO_VERIFY=true` whenever `FERRUM_MESH_PRODUCTION_MODE=true`. Those switches remain an explicit development opt-in with a loud warning outside production; under production mesh posture they fail closed with a diagnostic that names the exact offending variable(s) and never echoes secret or source values. The guard is topology-independent (sidecar, ambient, service/node waypoint, east-west gateway, and egress gateway) and runs before listeners, service-discovery pollers, health checks, plugin clients, or admin client activity can start — the same path both `ferrum-edge validate` and runtime startup use. FIPS enforce remains an independent defense that also refuses these switches; production mesh mode does not weaken or topology-special-case it. Prefer verified TLS with system roots or `FERRUM_TLS_CA_BUNDLE_PATH`.

**Runtime inbound mTLS fail-closed (the robust complement).** The gate above is a fast config-time *presence* check; it cannot see whether the configured SVID sources actually load or whether the resolved PeerAuthentication mode would still leave the inbound listener serving plaintext. The mesh therefore also fails closed at the runtime TLS-setup path, where the inbound listener's real posture is known (`enforce_mesh_inbound_fail_closed`). Three refinements make this exact:

1. **Gateway/runtime SVID backs the inbound server identity.** When no explicit `FERRUM_FRONTEND_TLS_CERT_PATH` / `KEY_PATH` is set, the mesh workload SVID backs the inbound listener's server certificate, so a mesh configured with only workload SVID material presents that SVID as its inbound server cert and serves mTLS instead of falling open to plaintext under the default PERMISSIVE mode. Both SVID sources resolve the same way: the inbound server certificate **resolves live from the gateway SVID slot** (a rustls `ResolvesServerCert` backed by the same shared slot that receives rotations). For **configured `FERRUM_GATEWAY_SVID_*` material**, the source watcher feeds that slot: file/`file://` sources poll every second, provider sources use their secret-refresh cadence, and inline PEM remains static until configuration reload. A successful source rotation makes the inbound listener present the new leaf on the next handshake and refreshes the SPIFFE peer verifier from the rotated trust bundle plus the last accepted federated overlay, with no restart or slice apply. For **CA-backed SVIDs** (`FERRUM_MESH_CA_BACKEND=spire_agent` / `internal`) the CA-backed SVID source (`start_mesh_ca_backend_svid_source`) installs each issued SVID into the same slot, so inbound server identity and peer-verifier local roots follow CA/SPIRE rotation through the identical live resolver. In-flight TLS sessions keep their established parameters; only new handshakes see the new leaf and verifier roots. Fail-closed semantics: at startup a configured SVID source whose slot holds no usable material hard-errors before listeners bind, and if a later rotation installs material that cannot back a server certificate (or empties the slot), inbound handshakes fail — loudly, once per bad rotation — rather than silently serving a stale leaf that masks a broken rotation pipeline until it expires. Explicit `FERRUM_FRONTEND_TLS_*` material remains a static operational input (the operator owns its rotation; the frontend live-reload flag covers it separately).
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

### Host-network UDP capture (issue #3288)

`FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED=true` (default `false`, requires
`FERRUM_MESH_CAPTURE_UDP_ENABLED=true` and `FERRUM_MESH_TOPOLOGY=ambient`) moves
Ambient's UDP source-capture from each pod's network namespace into the mesh
proxy's own. Setting it without the capture switch, or on any topology but
Ambient, is a **startup error**, not a silent no-op — both halves are enforced in
the process (the capture-switch half in `capture::udp_capture_settings_from_env`,
the topology half in `modes::mesh::validate_udp_host_netns_placement` on the
serving path), so a direct-env or hand-rolled-manifest deployment that never
renders the chart still fails closed rather than starting with no producer. It
captures the same traffic and feeds the same session, relay, overload, and
return-path machinery as the per-pod-netns producer — only the placement differs.

**Why the host namespace needed a different mechanism.** The pod-netns generator
splits inbound from outbound with `-m addrtype --dst-type LOCAL`, which is only
true inside a pod. In the host namespace pod IPs are forwarded, not local, so
inbound-to-pod UDP would match the outbound chain's `! --dst-type LOCAL` and be
mis-captured. The host path therefore does not use `addrtype` at all.

**The discriminator is the ingress interface.** In `mangle PREROUTING`, every
capture rule carries `-i <that pod's host-side interface>`:

| Traffic | Where it appears in the host namespace | Captured? |
|---|---|---|
| An enrolled pod's egress | `PREROUTING` on **that pod's** interface | **Yes** — this is the whole capture set |
| Traffic destined for a pod | `PREROUTING` on the **node uplink**, then forwarded | No — never matches a pod interface |
| The node's own traffic (kubelet, CNI, DNS, `hostNetwork` pods, the proxy's own relay egress) | `OUTPUT` only | No — **the host path installs no `mangle OUTPUT` chain at all** |

That last row is structural, not a filter: there is no OUTPUT chain, no `-j MARK`,
and no loopback reinjection loop, so node traffic cannot be captured even by
misconfiguration.

**Per-datagram identity.** One transparent socket serves every enrolled pod, so
evidence is resolved per datagram from two kernel-provided facts — the original
destination (`IP_RECVORIGDSTADDR`, un-rewritten by TPROXY) and the ingress
interface index (`IP_PKTINFO`/`IPV6_PKTINFO`, a fatal `setsockopt` for this path).
The interface index must map to exactly one enrolled pod **and** the datagram's
source address must be one that pod published in the registry. Neither fact comes
from the datagram payload, so forging a source address does not change which
interface a packet entered on. A datagram failing either check is dropped; the
path never falls back to an unattested or mesh-wide identity.

**Requires per-pod host interfaces.** Two enrolled pods resolving to one interface
(a shared-bridge CNI, or a stale registry entry on a recycled veth) make
attribution ambiguous, so **both** are refused — first-wins would be a
cross-tenant identity bug. Refused pods are not captured and their readiness
marker is withheld, so the node-agent's tc guard keeps their UDP egress closed
rather than letting it bypass the mesh. A pod is also refused when it has no
attested SPIFFE identity, no published address, an unresolvable interface, or a
name this path will not place in an `iptables -i` argument (notably a `+` suffix,
which would be a prefix wildcard).

**Privileges.** The host UDP path needs `NET_ADMIN` plus `iproute2`/`iptables` in
the image — but **not** `hostPID`, `SYS_ADMIN`, or `SYS_PTRACE`, because no
namespace is entered. The chart narrows those capabilities automatically when
this placement is selected while retaining the ambient container's baseline
`NET_RAW`. The registry hostPath and read-only host cgroup mount stay (the
enrolled-pod set and interface resolution use them); interface resolution falls
back to the host route table keyed on the registry-published pod IP when `/proc`
is not shared. That fallback covers **both families** — `/proc/net/route` for a
v4 address and `/proc/net/ipv6_route` for a v6 one — which is what lets an
IPv6-only enrolled pod use this placement at all: without `hostPID` the route
table is the only resolver, so a v4-only fallback would refuse every such pod
while the path claimed dual-stack support. Route fallback accepts only an
unambiguous `RTF_UP` host route (`/32` for IPv4 or `/128` for IPv6), and the
resolved sysfs device must expose a distinct non-zero peer `iflink`: a broader
subnet route commonly names a shared CNI bridge, while a self-linked device is
not a dedicated pod peer. Using either in `iptables -i` could capture enrolled
and unenrolled neighbours alike. Two devices claiming the same host route
resolve to nothing rather than to a guess, an oversized table refuses instead
of answering from a truncated view, and malformed rows are ignored unless a
valid, unambiguous host route remains.

**Ownership and cleanup.** The path owns `mangle` chain `FERRUM_MESH_UDP_HOST`,
guards `FERRUM_MESH_UDP_HOST_GUARD_A`/`_B`, routing table `33135`, and `ip rule`
priority `101` — all disjoint from the pod-netns path (`33133`/`100`) and from the
node-agent's tc ingress-redirect table (`33134`), so neither teardown can remove
the other's state. Startup reaps the previous generation before installing
anything — but only **after** discharging its durable readiness handshake (next
paragraph); a deployment that is **not** using this placement runs the same
recovery-then-reap, so a switched-away node cannot keep a jump into a chain no
socket serves. Reconciliation rebuilds the chain's contents behind a scope-exact
DROP guard while the `PREROUTING` jump stays constant; guard install, capture install,
socket bind, or guard release failing all leave the node dropping enrolled UDP
egress rather than leaking it. Shutdown retracts readiness, waits briefly (bounded
to fit inside mesh mode's background-task drain) for the node-agent to acknowledge
that its BPF gates closed, and only then removes everything; without the
acknowledgement it installs the DROP guard and retires the capture jumps/routes
while retaining the guard. The wait must not exceed that drain budget: an aborted
handshake leaves socketless host jumps and fwmark routes behind.

**Hosted live-kernel coverage (#3705).** The required
`ambient-host-udp-live` workflow exercises the production
`ProxyHostUdpBackend` / host-netns TPROXY path with
`FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED=true` on a privileged runner: two
independent workload netns/veth pairs, IPv4 and IPv6 delivery, original-destination
recovery, ingress-ifindex attribution, identical-tuple isolation by interface,
transparent replies, restart/reinstall, exact Ferrum-owned cleanup, and explicit
negatives (source spoofing, missing/zero pktinfo, unenrolled/ambiguous interfaces,
node-originated and inbound-to-pod traffic, fail-closed prerequisite/partial-install
contracts). `FERRUM_LIVE_TESTS_REQUIRED=1` converts unsupported runners into hard
failures. Bounded redacted diagnostics capture rules/routes, Ferrum chains, socket
bind state, interface indexes, and post-cleanup state.

**A restart is a handshake too.** Readiness is durable and shared with the
node-agent, so a generation that dies — a crash, a restart, a rollout that
switches placement or turns UDP capture off — leaves behind BOTH its `mangle`
state and an open BPF UDP gate for every pod it readied. Leaving the rules is
safe (a capture path whose socket died with its process drops), but removing them
while those gates are open is exactly a plaintext window, and the stale interface
set does not bound the damage: a pod that restarted onto a new veth has no stale
rule at all and an open gate regardless. So the first thing a new generation does
is **not** a teardown. It reads the durable `.udp-ready` and `.udp-ack-required`
directories, puts every pod they name back through the ordinary close handshake
(persist a fresh `.udp-ack-required`, delete any `.udp-not-ready` so a stale
acknowledgement cannot authorize this handoff, then retract `.udp-ready`), and
waits for the node-agent to republish `.udp-not-ready`. Nothing is applied and
nothing is removed until that settles, and a reap that fails is retried rather
than logged once — an abandoned `PREROUTING` jump would otherwise black-hole the
node's UDP with no code path left to clean it up. A pod also settles when
readiness REAPPEARS for it: this recovery's own retraction removed the marker, so
a marker that exists again was published by the incoming per-pod-netns producer,
which publishes only once it is capturing that pod inside its namespace — its
egress no longer reaches the host namespace at all. Without that clause the two
halves of a placement switch would deadlock, each waiting on the other. On a node
whose placement is now the pod-netns producer, mesh startup runs one bounded
recovery pass before returning to unrelated listener startup. If safe retraction
is still incomplete, recovery continues in the background and only the incoming
UDP producer waits on that boundary, so it cannot fight recovery over the shared
markers; admin, HBONE, and other proxy listeners still start. Until the boundary
resolves, predecessor rules remain installed and enrolled UDP stays fail-closed.
Stale-state reaping can continue after the incoming producer starts because
discovery/retraction is then frozen, and republished readiness is the
acknowledgement that settles a placement switch.

**A pod LEAVING capture is a handshake, not a rule deletion.** Removing a
`.udp-ready` marker does not synchronously close the node-agent's BPF UDP gate,
so a pod that is removed or becomes refused keeps its capture rule until the
node-agent publishes the matching `.udp-not-ready` acknowledgement — the same
durable `.udp-ack-required` handshake shutdown and the pod-netns cleanup manager
use. Until then the guard installed for the rebuild covers the **union** of the
interfaces the new generation captures and the interfaces of every pod still
owing an acknowledgement, so the departing pod's egress is dropped rather than
released in plaintext; a failed persistence or an acknowledgement timeout keeps
that posture and retries on the next poll. A pod that re-enters capture before
its acknowledgement arrives cancels the handshake and is readied again by the
ordinary apply path. Withdrawing (or re-attributing) a binding also **restarts
the shared capture listener** before the new evidence generation goes live: a
session admitted earlier still holds the old workload identity and its
transparent reply socket, so a one-way return stream would otherwise keep
reaching a removed — or recycled — pod address until it idled out. A pure
addition is not disruptive and leaves live sessions alone. The capture loop is
supervised on every reconcile: one that exits on its own (a socket error, a
panicked task) is detected, the datapath is guarded, stale evidence is cleared,
and the loop is restarted through the normal guarded apply path instead of the
node black-holing captured traffic while readiness stays published. An
operator-requested shutdown is never mistaken for such an exit.

**Placement migration is runtime-enforced.** Host cleanup cannot enter workload
network namespaces, and pod cleanup must not guess that host objects are absent.
Ferrum therefore rejects a stable requested placement that differs from the
durable node-local owner. The Helm chart also records the rendered target and
migration tuple in `ferrum-mesh-udp-placement-<release>`; on upgrade it rejects a
direct target change before accepting a disruptive DaemonSet rollout. The only
supported change is the explicit cleanup/finalize procedure below.

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
eBPF configuration the node-agent keeps the distroless `-ebpf` image, while the
ambient proxy is rendered with the tools-capable `-ebpf-tools` image, shares the
pod-registry hostPath, and is granted the setns/`NET_ADMIN` capabilities needed
for stale pod-netns cleanup. The image split is load-bearing, not cosmetic: the
UDP producer and the disabled stale-rule cleanup manager both execute generated
`sh -c` scripts calling `ip`/`iptables`/`ip6tables`, and the distroless `-ebpf`
image ships none of them, so `preflight_capture_tools` refuses startup there by
design. `-ebpf-tools` is a strict superset of `-ebpf` (same binaries, same BPF
ELF) on a Debian base; it is not distroless and runs as root, so only the pod
that needs the tools receives it. This is a deliberate security-footprint
increase that makes a later enabled-to-disabled rollout repairable without
another chart shape change.

Every node-agent restart re-derives enrollment from the live Kubernetes pod
list. During that relist it removes existing `.udp-ready` markers and closes the
host-veth UDP gate; producers rewrite readiness on their next registry poll
(at most two seconds) and the node-agent reopens the gate on its next readiness
reconcile (at most 250 ms). Budget roughly 2.5 seconds of fail-closed UDP
unavailability per node-agent restart; traffic is dropped during the interval,
not allowed to bypass capture.

#### Ambient UDP placement migration (enforced hard-upgrade guard)

Every placement or enabled-state change uses one operator-chosen generation and
two explicit releases. The placements are `pod-netns`, `host-netns`, and
`disabled`; the destination must agree with
`FERRUM_MESH_CAPTURE_UDP_ENABLED` and
`FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED`. A later transition must choose a
new generation rather than reusing the most recently completed value.

The Helm-side contract is a live-cluster guard. Run these transitions with
`helm upgrade` under an identity allowed to read the release namespace: Helm's
`lookup` must read the installed
`ferrum-mesh-udp-placement-<release>` ConfigMap. `helm template` does not query
the cluster. Without `--is-upgrade` it therefore cannot enforce predecessor
ordering; with `--is-upgrade` its empty lookup is treated as a pre-contract
release and blocks ordinary upgrades. GitOps/client-render pipelines must add
an equivalent cluster-state admission gate if they need the Helm-side check.
The per-node durable runtime guard remains authoritative, fail-closed, and
independent of that pipeline gate.

1. Render the destination switches plus
   `FERRUM_MESH_CAPTURE_UDP_MIGRATION_PHASE=cleanup`, a new
   `..._GENERATION`, and exact `..._FROM` / `..._TO` values. Do not use Helm
   `--wait`: cleanup pods deliberately remain unready. The chart temporarily
   uses `maxUnavailable: 100%` so that intentional unready state cannot deadlock
   the DaemonSet rollout. This can restart every Ambient proxy simultaneously,
   interrupting HBONE and raw TCP as well as UDP; finalize applies the same
   strategy and can create a second mesh-wide restart. Schedule both releases
   in a maintenance window sized for complete Ambient data-plane interruption.
   When the predecessor is `pod-netns` (or the conservative
   `disabled` case), the cleanup pod retains `hostPID`, `SYS_ADMIN`,
   `SYS_PTRACE`, and `NET_ADMIN`; stable/final host placement drops the setns
   privilege set.
2. Wait for every node's authenticated `/health` detail
   `mesh.udp_placement_migration.phase` to become `cleanup_complete` (the HTTP
   status remains 503 because readiness is intentionally false), or for
   `ferrum_mesh_udp_placement_migration_phase{phase="cleanup_complete"}` to be 1.
   `ferrum_mesh_udp_placement_migration_outstanding` and the bounded
   `..._failures_total{reason}` family diagnose progress without generation or
   pod-UID labels. A cleanup image missing the required setns/iptables tooling
   reports phase `failed` with reason `pod_cleanup_failed`; the UDP producer and
   cleanup stay stopped, but admin/HBONE/TCP listeners remain available for
   diagnosis while readiness stays false. Repair the image or privileges and
   restart the same cleanup tuple.
3. Upgrade the same destination with phase `finalize` and the identical
   generation/from/to tuple. Helm requires the installed cleanup ConfigMap, and
   each incoming proxy independently requires its node-local durable completion
   proof before publishing readiness or starting a producer. An early finalize
   therefore fails closed on only the nodes lacking proof; it never guesses from
   a missing marker.
4. After the finalize DaemonSet is ready, remove generation/from/to and return
   phase to `stable`. The durable active owner remains, so later restarts resume
   the selected producer without repeating migration. Use a committed values
   file that omits the three tuple keys for this release; do not carry them
   forward with `--reuse-values`.

**Node reboots and scale-out.** The node-local durable record lives in the pod
registry hostPath (`nodeAgent.podRegistryDir`, default `/run/ferrum/...`, which
is tmpfs on a systemd host). A node reboot recreates that directory, and a node
that joins the cluster after the migration never had one, so neither carries a
durable record. Both nonetheless provably carry **no** predecessor rules: pod
network namespaces do not survive a reboot, and a new node has never run a
predecessor producer. From the stable release onward the chart therefore renders
`FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED` from the **installed**
`ferrum-mesh-udp-placement-<release>` ConfigMap — only when that installed
contract already records the same target in a `stable` or `finalize` phase, so
the release that performs a change can never attest itself. A node with no
durable record then adopts that placement, records it durably, logs the
adoption, sets `mesh.udp_placement_migration.established_adoption` on
authenticated `/health`, and increments
`ferrum_mesh_udp_placement_migration_established_adoptions_total`. The
attestation is consulted **only** when the durable record is absent: a present
record that disagrees with the requested placement is still the hard rejection
above, so an in-place flip on a running node can never be authorized this way.

A GitOps or client-render pipeline that bypasses Helm's `lookup` must supply the
same value from its own cluster-state gate. Omitting it is fail-closed but
costly: rebooted and newly joined nodes keep readiness false with failure reason
`migration_required` until an explicit cleanup/finalize pair runs. A node that
somehow missed both migration releases while its workloads kept running (for
example a node whose Ambient DaemonSet pod was unschedulable throughout, and
which then rebooted or was reimaged) can be adopted by the attestation; its
workloads were already fail-closed after the predecessor producer stopped, so
this costs availability that was already lost and never opens plaintext egress.

For example, pod-netns to host-netns uses one tuple throughout (replace
`$GENERATION` with a deployment identifier):

```bash
helm upgrade ferrum ./charts/ferrum-mesh --reuse-values \
  --set-string ambient.env.FERRUM_MESH_CAPTURE_UDP_ENABLED=true \
  --set-string ambient.env.FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED=true \
  --set-string ambient.env.FERRUM_MESH_CAPTURE_UDP_MIGRATION_PHASE=cleanup \
  --set-string ambient.env.FERRUM_MESH_CAPTURE_UDP_MIGRATION_GENERATION="$GENERATION" \
  --set-string ambient.env.FERRUM_MESH_CAPTURE_UDP_MIGRATION_FROM=pod-netns \
  --set-string ambient.env.FERRUM_MESH_CAPTURE_UDP_MIGRATION_TO=host-netns

# After every node reports cleanup_complete:
helm upgrade ferrum ./charts/ferrum-mesh --reuse-values \
  --set-string ambient.env.FERRUM_MESH_CAPTURE_UDP_MIGRATION_PHASE=finalize
```

Host-netns to pod-netns reverses `FROM`/`TO` and sets the host switch false in
the cleanup release. Enabled to disabled sets `TO=disabled` and disables capture
in that release; disabled to enabled names the incoming placement. A `disabled`
predecessor conservatively reaps both ownership domains, which covers a legacy
disabled node. Any pre-contract node with no durable owner record also reaps
both domains, regardless of the declared predecessor, so a mistaken legacy
placement claim cannot strand Ferrum-owned rules. Accordingly, the first Helm
upgrade from any pre-contract release requires an explicit cleanup adoption
release even when the requested placement appears unchanged or disabled: the
missing ConfigMap cannot prove whether that older release owned pod- or
host-netns rules. Initial installs are unaffected.

**Abort and durable-state recovery (maintenance only).** There is deliberately
no online `cleanup -> stable` or tuple-switch transition. Once cleanup is
persisted, resuming/finalizing that exact tuple is the only traffic-bearing
path. If the tuple is wrong, or a node rejects a corrupt/truncated/unsupported,
non-regular, multiply-linked, foreign-UID, or unreadable
`.udp-placement-state-v1.json`, use this fail-closed procedure:

1. Enter a maintenance window, cordon every node selected by both the Ambient
   and node-agent DaemonSets, drain all enrolled workloads, and verify there is
   no workload UDP, HBONE, or TCP traffic left on those nodes. Do not delete or
   rewrite either artifact while traffic is active.
2. Stop both DaemonSets and verify that no Ambient proxy or node-agent pod is
   running on any affected node. This is the proof that neither the pod-netns
   nor host-netns producer can start while ownership is repaired.
3. Repair the Helm artifact first. Set
   `ferrum-mesh-udp-placement-<release>` back to the known predecessor
   (`target=<from>`, `phase=stable`, and empty `generation/from/to`) for a true
   abort, or to the new cleanup-adoption tuple for corrupt/unknown ownership.
   This ordering prevents the next Helm operation from authorizing a producer
   before node-local state is repaired.
4. On **every** node in the DaemonSet scope, repair the registry hostPath named
   by `nodeAgent.podRegistryDir`. For a true abort, atomically replace
   `.udp-placement-state-v1.json` with
   `{"version":1,"active":"<from>","pending":null,"completed":null}`;
   create the temp file in the same directory, use the mesh container's
   effective UID and a single link, fsync the file, rename it, then fsync the
   directory. Retract `.udp-registry-synced` while both processes are stopped.
   For corrupt or unknown ownership, quarantine the rejected state outside the
   registry, leave the state path absent, create an empty
   `.udp-placement-quarantined` tombstone beside it, and then run a fresh
   explicit cleanup adoption release; absent state makes cleanup probe **both**
   ownership domains. The tombstone is load-bearing, not a note: while it is
   present, **every** stable bootstrap from an absent record is refused —
   including a release-attested adoption — so a proxy that restarts between the
   quarantine and the cleanup release cannot silently adopt a placement instead
   of proving cleanup. A successful finalize removes it. Never guess ownership, chown a live file, follow a symlink, or
   repair only a subset of nodes.
5. Verify both artifacts and their tuple on every node before resuming the
   DaemonSets. Apply the matching Helm values only after that verification so
   the repaired ConfigMap becomes the release contract rather than a transient
   manual edit. Keep nodes drained until the node-agent has completed its
   relist, the intended Ambient producer is ready, and authenticated health
   shows the expected phase. Then uncordon nodes under the normal rollout
   policy.

A planned `securityContext` UID change must use the same stopped-and-drained
procedure (or retain the old UID until after the migration); the reader rejects
old-UID state by design. Re-adopting `host-netns` from **rejected** state always
requires cleanup/finalize—a corrupt, truncated, foreign-UID, or unreadable
record is a hard failure, never an absence—and re-adopting it from **absent**
state requires either cleanup/finalize or the release-level
`FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED` attestation described under
"Node reboots and scale-out", which a `.udp-placement-quarantined` tombstone
refuses. Stable host startup never fabricates a predecessor proof from node-local
inspection.

**Recovery and churn contract.** Cleanup persists `(generation, from, to)`
before touching rules. A proxy restart resumes only that tuple; a different or
stale generation is rejected, and a completed generation cannot bind a later
transition to a registry marker left by the earlier rollout. Each node-agent
restart/relist first retracts its
generation acknowledgement, closes UDP gates, reconstructs the registry from
the Kubernetes pod list, and then atomically publishes `.udp-registry-synced`
as a bounded, versioned proof containing that generation and a fresh publication
identity. Every later pod/CNI capture mutation retracts the marker first and
republishes a new identity only after the registry and retry state converge. The
cleanup supervisor requires the exact same proof before and after every pass;
disappearance or replacement resets both repeated-pass counters and the pod
registry fingerprint. It checks that proof again immediately before persisting
completion. Pod-netns cleanup starts only after that proof and requires two
identical complete registry passes under one publication, so partial per-pod
cleanup, temporarily unresolvable netns handles, pod deletion/recreation, and a
crash between any passes simply retry. Pods created after the predecessor stopped
have no predecessor rules and join the current registry pass; pods removed
during the phase lose their namespace and cannot retain rules. Cleanup always probes both
IPv4 and IPv6 exact Ferrum chain/jump/rule/route names, even when the new config
disables one family, and never flushes a table or sweeps foreign state.

The existing gate acknowledgement remains load-bearing throughout. A missing or
stale `.udp-not-ready` cannot authorize cleanup because cleanup writes a fresh
`.udp-ack-required`, removes the stale acknowledgement, and retracts
`.udp-ready` in that order. Until a fresh acknowledgement arrives, predecessor
capture or a scope-exact DROP guard remains and the incoming placement stays
unready. Thus interruption after readiness retraction, partial netns cleanup,
host cleanup, durable proof publication, or before final producer publication
costs availability but never opens plaintext egress.

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

`sourceLabels` and `sourceNamespace` are Istio source-workload selectors, not predicates on an inbound peer connection. For a Sidecar `mesh` arm, Ferrum resolves them once against the accepted slice's local workload identity/namespace/labels, removes non-applicable arms, and retains the remaining subnet/gateway/SNI predicates with AND semantics and declaration order intact. The local workload must resolve unambiguously; a shared SPIFFE with divergent labels cannot lend one replica's labels to another. Named-gateway projections remain independent of these selectors. The projected L4 proxies ride native and xDS mesh-slice updates, and slice content equality includes them so update/delete cannot retain stale applicability or listener candidates.

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

When `FERRUM_K8S_CONTROLLER_ENABLED=true` and Gateway API watching is enabled, the controller watches `GatewayClass`, `Gateway`, `ListenerSet` (optional; discovery skips when the CRD is absent), `HTTPRoute`, `GRPCRoute`, `TCPRoute`, `TLSRoute`, `UDPRoute`, `ReferenceGrant`, `BackendTLSPolicy`, `BackendLBPolicy` (historical `v1alpha2`, when installed), and `XBackendTrafficPolicy` (pinned `v1.5.1` experimental successor), plus MCS `ServiceImport` (`multicluster.x-k8s.io`, when that CRD is installed) for GEP-1748 backendRefs, resources and writes status subresources for the GatewayClass, Gateway, ListenerSet, route, `BackendTLSPolicy`, and BackendLB/`XBackendTrafficPolicy` kinds. `BackendTLSPolicy` is translated onto Service-backed HTTPRoute/GRPCRoute backends and receives Gateway API `PolicyStatus` (`status.ancestors[]`) patches: its ancestor is the targeted Service itself rather than the managed Gateways that route to it — Ferrum's overlay decision and its `Accepted`/`ResolvedRefs` verdict take no Gateway as input, so the verdict provably cannot vary per Gateway, and Ferrum's own contribution is bounded at one entry no matter how many Gateways route to the Service. Ferrum still writes status only for a policy whose targeted Service a managed Gateway *effectively* routes to (a route that materialized on an accepted parentRef, not merely one naming a Gateway). If third-party controllers have already filled the CRD's 16-entry `ancestors` maximum, Gateway API forbids adding another entry, so Ferrum publishes none — but the policy still translates and still governs backend TLS. That ceiling is an output constraint on the status writer alone: `status.ancestors` is mutable state owned by other controllers, and gating translation on it would let any controller holding status-write access disable backend TLS origination and fault covered traffic. A full ancestor map therefore costs reporting fidelity for that policy, not traffic. Each Ferrum ancestor carries Ferrum-authored `Accepted` and `ResolvedRefs` conditions using the portable `PolicyConditionReason` vocabulary (`Accepted` / `Conflicted` / `Invalid` / `NoValidCACertificate` / `TargetNotFound`; `ResolvedRefs` / `InvalidCACertificateRef` / `InvalidKind` / `RefNotPermitted`). Like route `status.parents`, `status.ancestors` is an atomic array in the upstream CRD, so it follows the same read-modify-write mandate: preserve fresh non-Ferrum ancestors, replace Ferrum-owned ones within the remaining 16-entry budget, guard with `metadata.resourceVersion`, and refetch/re-merge/retry after `409 Conflict`. When Istio status writing is also enabled, both writers observe the same immutable Kubernetes object generation for that reconcile (one shared snapshot; no second full deep copy), while retaining independent update plans and failure handling. Status planning builds immutable indexes (managed classes/gateways, parent refs, a precomputed ReferenceGrant from×to permission index, services/secrets, conflicts) once per reconcile, reuses the primary translation/materialization result (plus per-object skip errors keyed with exact-or-versionless identity) instead of retranslating a filtered snapshot once per status object, and borrows included `K8sObject` values during translation rather than deep-cloning `spec`/`status` JSON. Gateway API status planning alone applies a fair deterministic work budget of 256 candidates *before* expensive per-object status computation so the cap bounds CPU as well as API writes. All eligible Gateway API status kinds — including GatewayClass and Gateway — share that deterministic window (planning itself can be expensive, so these kinds are not exempted), and therefore enter it within at most `ceil(eligible_candidates / 256)` successful planning/patch rounds for a stable candidate set. The rotating cursor advances after an empty successful plan or a successful patch batch; patch errors and batch timeouts leave the cursor unchanged so the same bounded window retries on the next serialized reconcile. Istio status planning reuses the same translation/index snapshot path but remains unlimited. Each writer's complete Kubernetes status-patch batch has a 60-second wall-clock ceiling: a stalled API request is cancelled so it cannot retain the reconcile loop indefinitely, and unfinished updates are retried by a later watch event or periodic full sync. GatewayClass, Gateway, and ListenerSet status use Kubernetes server-side apply with the stable `ferrum.io/gateway-controller` field manager and `force=true`; their structural condition/listener arrays are keyed list-maps, so Ferrum applies only the fields it owns. Route `status.parents` is atomic in the upstream CRDs and therefore cannot be safely split by SSA ownership. Route writes instead follow the Gateway API read-modify-write mandate: preserve fresh non-Ferrum parents, replace Ferrum-owned parents, guard the merge patch with `metadata.resourceVersion`, and refetch/re-merge/retry up to five times with jitter after `409 Conflict`. Ferrum manages only `GatewayClass` objects whose `spec.controllerName` is `ferrum.io/gateway-controller`. `Gateway.status.conditions` and route `status.parents[].conditions` include Ferrum-authored `Accepted`, `Programmed`, `ResolvedRefs`, and `Conflicted` entries with that controller name. The status writer is driven by the same translation inputs as the control-plane config: accepted routes report programmed from typed route-to-parent materialization records captured when Ferrum generates proxies (never by parsing proxy IDs), rejected routes report unresolved references for cases such as missing `ReferenceGrant` authorization or unsupported backend target kinds, and route collisions report `Conflicted=True`. Live `TCPRoute` attachment/traffic/status/update/deletion evidence is release-gated by the Gateway API conformance black-box lab (see [`docs/gateway_api_conformance.md`](gateway_api_conformance.md)); Ferrum does not advertise an upstream `GATEWAY-TCP` profile on the pinned Gateway API `v1.5.1` channel.

MCS backendRefs match only objects from the exact `multicluster.x-k8s.io` API group. Ferrum admits TCP ports (an omitted `ServiceImport.spec.ports[].protocol` uses the Kubernetes `TCP` default) and reports `UnsupportedProtocol` for UDP, SCTP, unknown, or malformed protocols. An omitted backendRef port is derived only when the import exposes exactly one valid TCP port; zero or multiple TCP candidates fail closed. HTTPRoute/GRPCRoute backends can expand across ready MCS-labeled EndpointSlice addresses when pod discovery is enabled, while TCPRoute/TLSRoute always retain the stable ClusterSet DNS name rather than selecting and discarding all but one EndpointSlice address. A `ServiceImport` carries no `targetPort`, so expansion never assumes the ClusterSet port number is also the container port: a **named** `ServiceImport.spec.ports[]` entry resolves against the like-named MCS EndpointSlice port (the same name-based mapping a core Service uses for a named `targetPort`), and an **unnamed** entry resolves against a single-port slice. A slice that offers no unambiguous mapping is skipped and the backend falls back to the ClusterSet DNS name instead of dialing the ClusterSet port number on a pod address. `UDPRoute` does not claim `ServiceImport` backendRefs and keeps core `Service` legs only.

Live `TLSRoute` attachment, SNI passthrough traffic, status, update, and deletion evidence is also release-gated by that black-box lab. `TLSRoute` materializes SNI passthrough stream proxies on Gateway `protocol: TLS` / `tls.mode: Passthrough` listeners. `TLSRouteModeTerminate` is not implemented or advertised: Ferrum rejects non-Passthrough TLS listeners and never materializes their routes or a backend-port fallback. Ferrum does not advertise an upstream `GATEWAY-TLS` profile on the pinned Gateway API `v1.5.1` channel.

`UDPRoute` is release-gated by the required `Tests` aggregate instead of the black-box conformance lab — translation/status/update/deletion by CI Unit Tests, and the live UDP data path (a translated route serving a real datagram round trip on `start_udp_listener`) by CI Integration Tests. Ferrum does not advertise an upstream `GATEWAY-UDP` profile on the pinned Gateway API `v1.5.1` channel.

Gateway API HTTP/GRPC route conflicts are resolved deterministically before config materialization. For routes that would produce the same parent reference, hostname, and Ferrum listen path, the oldest `metadata.creationTimestamp` wins; if timestamps tie or are absent, `{namespace}/{name}` order is the tiebreaker. Losing routes are skipped during translation and receive `Accepted=False`, `Programmed=False`, and `Conflicted=True` status.

`BackendLBPolicy` / `XBackendTrafficPolicy` Direct attachment uses the same oldest-wins None-merge precedence as translation (creationTimestamp, then full resource identity across kinds). Status planning evaluates field validation first, then conflicts: a policy that wins every Service target stays `Accepted=True`; a challenger that loses any targeted Service is `Accepted=False` with reason `Conflicted` (atomic multi-target fail-closed). Translation applies the same atomic rule: a policy that loses any one of its Services is withdrawn from *every* Service it targets, so the Services carrying session persistence are exactly those whose policy reports `Accepted=True` and a policy the operator was told is `Conflicted` never steers live traffic. Invalid policies keep field-specific `UnsupportedValue` rejection and never participate as conflict winners. Ferrum's policy `status.ancestors` write preserves ancestor entries owned by other implementations (GEP-713 shared status) and keeps `lastTransitionTime` for a condition whose value did not change, so a steady-state policy is not re-patched on every reconcile. If those foreign entries fill the shared 16-entry ancestor map, Gateway API forbids adding another entry, so Ferrum publishes none — but the policy still translates and session persistence still reaches the data plane. That ceiling is an output constraint on the status writer alone: `status.ancestors` is mutable state owned by other controllers, and gating translation on it would let any controller holding status-write access drop stickiness. A full ancestor map therefore costs reporting fidelity for that policy, not persistence behavior.

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

Gateway API status writing requires `get/list/watch` on `gatewayclasses`, `gateways`, `listenersets`, `httproutes`, `grpcroutes`, `tcproutes`, `tlsroutes`, `udproutes`, `referencegrants`, and `backendtlspolicies`, plus `get/list/watch` on MCS `serviceimports`, plus `get/list/watch` on core `secrets`/`configmaps`/`services`/`endpointslices` for certificate, BackendTLSPolicy CA, and optional EndpointSlice backend resolution, plus `patch` on Gateway/ListenerSet/route/`backendtlspolicies` `status` subresources. `GatewayClass` is cluster-scoped; route, Gateway, ListenerSet, and ServiceImport watches are namespaced when `FERRUM_K8S_WATCH_NAMESPACES` is set. The Helm chart grants these verbs through `controlPlane.rbac.*`; disable unused watches there when installing a narrower controller.

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
- **Rejected** — a translator error (`K8sTranslateError`) writes `FerrumAccepted=False`, reason `Invalid`, with the error text in both the condition message and `status.ferrum.translation.error`. This is the gap this surface closes: a hard rejection of any translated kind is now visible to operators instead of being silently dropped from the slice.
- **Deferred fields** — fields Ferrum parses but does not yet enforce are listed in `status.ferrum.translation.deferred_fields` (and summarized in the condition message) so operators see the gap. DestinationRule `connectionPool.http.maxRequestsPerConnection` is deferred at top-level, `portLevelSettings`, and subset scope because backend close-after-N-requests is unsupported. The subset-scoped `h2UpgradePolicy`, `maxRetries`, `http1MaxPendingRequests`, `idleTimeout`, and `http2MaxRequests` fields are applied and are therefore absent from deferred status and translator ignored-field warnings (reqwest's H2 path still lacks an `http2MaxRequests` builder knob — documented as a transport caveat, not a deferred field). Invalid or unrepresentable values still reject with a field-specific, value-redacted diagnostic. VirtualService `http[].corsPolicy` is deferred only when it is unrepresentable — an un-compilable `regex`, a malformed/unknown matcher, an `exact` (or legacy `allowOrigin` entry) that is empty/whitespace-only or beyond the 512-byte matcher bound (uncredentialed exact `*` is supported; credentialed exact `*` is deferred to preserve the source credential behavior; wildcard-shaped and noncanonical exacts are now projected LITERALLY rather than deferred), an `allowOrigins[]` list beyond 64 entries, an over-complex regex, or an `allowMethods`/`allowHeaders`/`exposeHeaders` entry that is padded or not a valid HTTP method / header name, or an unknown `unmatchedPreflights` value; Sidecar `ingress[]` listeners are deferred only when Ferrum cannot model them (an inadmissible Unix-socket path, non-loopback `defaultEndpoint`, non-HTTP-family protocol, or omitted `defaultEndpoint`). An admissible Unix-socket path is modeled and remains subject to the data plane's explicit containment-root policy. Sidecar `outboundTrafficPolicy` is translated and enforced (see [Sidecar Outbound Traffic Policy](#sidecar-outbound-traffic-policy)); an omitted/null `mode` in a present object uses Istio's documented `ALLOW_ANY` default and defers nothing. A `deferred_fields` entry appears only when a present block is not exactly representable — an unrecognized/non-string `mode`, a non-object block, or an unsupported `egressProxy` — and always names the fail-closed `REGISTRY_ONLY` outcome Ferrum enforces instead.

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

Control planes can opt into native Kubernetes service-registry discovery with `FERRUM_K8S_CONTROLLER_ENABLED=true` and `FERRUM_K8S_POD_DISCOVERY_ENABLED=true`. When enabled, the K8s controller watches `Pod`, `Service`, `EndpointSlice`, and `Node` resources in addition to the configured Istio/Gateway API watches. Ready Pods linked from EndpointSlices become mesh `Workload` entries, Services become mesh `MeshService` entries with their `spec.ports[]`, and Node `topology.kubernetes.io/region|zone` labels populate workload locality metadata consumed by locality-aware load balancing.

Ferrum only surfaces Pods whose `Ready` condition and declared `readinessGates[]` are green, skips Pending/Failed/Succeeded/terminating Pods, and also honors EndpointSlice readiness/serving/terminating conditions. Explicit Istio `ServiceEntry` resources for the same service host override the auto-derived `MeshService`, and explicit `WorkloadEntry` resources for the same service override auto-derived Pod workloads while the Service can still reference those explicit identities. Cross-namespace `WorkloadEntry.service` hosts require a target-namespace Gateway API `ReferenceGrant` (`WorkloadEntry` → `Service`) plus an authoritative translated Service; see the WorkloadEntry row in [Istio Compatibility Gaps](#istio-compatibility-gaps). The flag defaults to `false` for one release so operators can validate RBAC and rollout impact before enabling Pod discovery.

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

Port-level `trafficPolicy.portLevelSettings[].loadBalancer.localityLbSetting` is honored by HTTP-family / gRPC / WebSocket / HBONE dispatch. Each per-port entry projects onto `Upstream.port_overrides[port].locality_lb_setting` at slice apply, and the load balancer builds isolated per-port locality state. When dispatch resolves to a port that has a per-port `localityLbSetting`, the per-port preference wins; ports without an override fall back to the upstream-level `trafficPolicy.loadBalancer.localityLbSetting`. Failover-priority activation is resolved for that selection lane: upstream health applies to every port, while a port-level `outlierDetection` enables only that port (and subset passive health enables its subset lane). The same translator validators apply to per-port entries — invalid locality strings, non-terminal wildcards, malformed failover regions, empty/malformed `failoverPriority` entries, and combined modes are rejected at admission. TCP/UDP/DTLS stream proxies continue to use upstream-level locality LB only.

## xDS ADS Compatibility

Ferrum's ADS protocol state machine (subscriptions, ACK/NACK, nonce, SotW/delta) follows the Envoy ADS wire contract, but the **resource payloads are Ferrum-specific**. The CDS/EDS/LDS/RDS resources are name-only (service/port discovery) and use Ferrum-shaped names; the security- and policy-bearing slice fields plus effective workload labels ride ECDS as [Ferrum mesh-slice carriers](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds) with Ferrum-defined inner type URLs. A stock Envoy or third-party Istio control plane does not speak this carrier convention or resource-name shape, so Ferrum's xDS path is **Ferrum-CP-to-Ferrum-DP**, not a drop-in replacement for an Envoy/Istio xDS feed. With the carriers, an xDS-built slice is functionally equivalent to a `native`-built one.

**Protocol robustness.** Both sides track nonces per `(node, type URL)`. The server issues an opaque nonce (`n1:<sha256>`) per response and validates that each ACK/NACK echoes the most-recently-issued nonce (`src/xds/nonce.rs`); stale, unknown, or version-drifted ACKs are logged and ignored rather than mutating accepted state. The DP client mirrors this on the receiving side: it ACKs/NACKs with the exact nonce of the response being acted on and ignores a server retransmit of a response it already processed (a reconnect race or buggy CP would otherwise trigger a redundant slice rebuild and a stale re-ACK). Because server nonces are opaque, duplicate detection — not numeric ordering — is the staleness signal available to the client. Additionally, the CP applies the layered admission budgets described in [xDS ADS admission budgets](#xds-ads-admission-budgets) before and during each stream.

#### xDS ADS admission budgets

`Node.id` is chosen by the client on every stream. A per-node ceiling alone therefore bounds nothing in aggregate: a namespace-authorized bearer could stay under it while cycling unique node ids, and each admitted stream costs a Tokio task, a request stream, a response channel, a subscription set, a filtered `GatewayConfig`, snapshot and nonce state, identity/scoping entries, and a broadcast receiver. `FERRUM_XDS_ENABLED=true` control planes therefore enforce **five independent budgets plus a `Node.id` contract and an initial-request deadline** (issue #3741). Every setting is documented in [configuration.md](configuration.md).

| Scope | Setting | Default | Enforced |
|-------|---------|---------|----------|
| Total active ADS streams (process) | `FERRUM_XDS_MAX_TOTAL_STREAMS` | `1024` | at reservation, before any per-stream allocation |
| Active ADS streams per namespace/tenant | `FERRUM_XDS_MAX_STREAMS_PER_NAMESPACE` | `512` | same reservation |
| Active ADS streams per authenticated principal (JWT `sub`) | `FERRUM_XDS_MAX_STREAMS_PER_PRINCIPAL` | `256` | same reservation |
| Active ADS streams per node state key | `FERRUM_XDS_MAX_STREAMS_PER_NODE` | `4` | on the first request, once `Node.id` is known |
| Distinct active node state keys | `FERRUM_XDS_MAX_ACTIVE_NODES` | `2048` | same registration |

A node state key exists only while at least one admitted stream holds it, so distinct active nodes can never exceed active streams. `FERRUM_XDS_MAX_ACTIVE_NODES` therefore **binds only when it is set below `FERRUM_XDS_MAX_TOTAL_STREAMS`**, or when the total-stream budget is unbounded (`0`). At the shipped defaults (`2048` > `1024`) the total-stream budget saturates first and the distinct-node ceiling is defense in depth: lower it when you want the node-scoped maps bounded more tightly than the stream count.

**Ordering is deterministic and outermost-first** — total → namespace → principal → node streams → node cardinality. The first saturated scope returns gRPC `RESOURCE_EXHAUSTED`, and a failure in an inner scope rolls the outer reservations back, so a refused stream never leaves partial admission state.

**The reservation happens before the allocations it bounds.** Total/namespace/principal capacity is taken in the gRPC handler itself — before the relay task is spawned, before the per-stream response channel exists, before the broadcast subscription, and before the filtered `GatewayConfig` snapshot is built. A refusal at that point allocates none of them. The reservation is then moved into a permit that lives inside the stream task, so it is released exactly once on every exit: normal completion, request-stream error, first-message error, client cancellation, response-channel receiver drop, forced task abort, and process shutdown.

**SotW and Delta share one budget.** `StreamAggregatedResources` and `DeltaAggregatedResources` reserve from the same process-wide controller, so a client cannot split a flood across the two methods or across connections to double its allowance.

**`Node.id` is validated before it is used.** It must be non-empty, at most `FERRUM_XDS_MAX_NODE_ID_BYTES` UTF-8 bytes (default `253`), and printable ASCII (`0x21`–`0x7E`) only. That single rule rejects control characters (including CR/LF log injection and NUL), all whitespace, and every non-ASCII form (bidi overrides, zero-width joiners, homoglyphs) while still admitting hostnames, Kubernetes pod identities, and Istio `~`-delimited node ids. Validation runs **before** the value is cloned, stored in any map, folded into a state key, or written to a log line; violations return `INVALID_ARGUMENT`. Log sites emit a non-reversible digest of the id, never the raw bytes.

**Principals cannot alias one another's state.** The mutable per-stream state key is `namespace + full-width SHA-256 digest of the authenticated JWT subject + Node.id`, with the namespace and principal segments length-prefixed so no combination of values can forge another key. The principal digest is deliberately **not truncated** (64 hex characters), because it is the boundary that keeps one principal off another's per-principal quota and mutable state; a client picks its own JWT `sub`, so a truncated digest would be a tractable collision target. That digest is separate — different hash domain, different width — from the short 16-character digest log sites use to redact a client-supplied `Node.id`; a log identifier is only a correlation aid and is never used as a key. Neither the raw subject nor the raw `Node.id` is ever stored in a map key, state key, log field, or metric label. `Node.id` is descriptive metadata only; it authorizes nothing. Two unrelated principals inside one namespace that pick the same `Node.id` therefore get separate snapshot, nonce, workload-identity, waypoint, scoping, and per-node quota entries. Node-scoped state is cleaned atomically when that key's last stream exits.

**A stalled stream is bounded too.** An admitted stream that never sends a first request — and so never identifies a node — is closed with `DEADLINE_EXCEEDED` after `FERRUM_XDS_FIRST_REQUEST_TIMEOUT_SECONDS` (default `30`), releasing its task, channel, and permit.

**`0` means unbounded and is refused in production.** Any budget set to `0` disables that scope. Under `FERRUM_MESH_PRODUCTION_MODE=true` an ADS-enabled control plane refuses that at `ferrum-edge validate` and at startup unless the operator sets `FERRUM_XDS_ALLOW_UNBOUNDED_STREAM_LIMITS=true`. Startup logs the resolved budgets, and warns loudly whenever any scope is unbounded, override or not.

**Sizing.** Peak ADS memory is roughly `FERRUM_XDS_MAX_TOTAL_STREAMS × (FERRUM_XDS_STREAM_CHANNEL_CAPACITY × response size + one filtered GatewayConfig + one snapshot)`, plus one broadcast receiver per stream. The node-scoped maps add `min(FERRUM_XDS_MAX_ACTIVE_NODES, FERRUM_XDS_MAX_TOTAL_STREAMS) × (snapshot + nonce + identity/waypoint/scoping entries)` — the `min` because a node state key only exists while a stream holds it. **These are per CP process**: a control plane running `N` replicas admits up to `N ×` the configured limits in aggregate, so divide the fleet-wide budget by the replica count when sizing. `FERRUM_XDS_MAX_TOTAL_STREAMS` is the **only** aggregate bound on ADS occupancy — do not rely on `FERRUM_CP_GRPC_MAX_CONNECTIONS` for it. That setting bounds gRPC *connections*, and one HTTP/2 connection multiplexes up to `FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS` (default `1000`) concurrent ADS streams, so the transport ceiling is orders of magnitude looser than the stream ceiling. The default `1024` merely mirrors the default connection ceiling's magnitude; size it from the memory formula above and your real DP count.

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
| Stock Envoy / third-party Istio xDS interop (point Ferrum's **Ferrum-private** xDS client at a non-Ferrum CP) | Not interoperable | `FERRUM_MESH_CONFIG_PROTOCOL=xds` is a **Ferrum-CP-to-Ferrum-DP** path: CDS/EDS/LDS/RDS are name-only with Ferrum-shaped resource names and all security/policy fields ride [Ferrum-specific ECDS carriers](#ferrum-mesh-slice-ecds-carriers-full-parity-over-xds). A stock CP emits neither, so that response is unsupported and may be NACKed |
| Stock Envoy / third-party Istio xDS interop (`FERRUM_MESH_CONFIG_PROTOCOL=stock_xds`) | Supported for discovery | Consumes standard v3 CDS/EDS/LDS/RDS from a stock control plane and maps it onto `MeshService` / `Workload`. Enforcement policy (authorization, PeerAuthentication, JWT, trust bundles, DestinationRule, Sidecar scope) comes from the mandatory local `FERRUM_MESH_FILE_CONFIG_PATH` document, never from the stock CP. Traffic shaping, subsets, external DNS clusters, SDS, ECDS/RTDS, and delta xDS are out of scope — see [Stock Envoy / third-party Istio xDS interoperability](#stock-envoy--third-party-istio-xds-interoperability) |
| `EnvoyFilter` | Not planned | Use Ferrum custom plugins |
| `WasmPlugin` | Not planned | Use Ferrum custom plugins (`custom_plugins/`) |
| Outbound traffic policy (`REGISTRY_ONLY` / `ALLOW_ANY`) | Supported | `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY=registry_only`, the native/CRD slice-supplied mesh-wide `outbound_traffic_policy`, or a workload-scoped `Sidecar.outboundTrafficPolicy` that overrides both (see [Sidecar Outbound Traffic Policy](#sidecar-outbound-traffic-policy)) covers both HTTP-family egress (auto-injected `mesh_outbound_registry` plugin and outbound-capture route misses, both rejecting with `FERRUM_MESH_OUTBOUND_REGISTRY_REJECT_STATUS`, default 502) and stream-family egress on mesh outbound capture listener ports (TCP / TCP+TLS: graceful close before backend dial; UDP / UDP+DTLS: silent datagram drop). Both surfaces read the same slice-derived registry (services, ServiceEntries including wildcard hosts, workload addresses); resources with no declared ports admit any explicit Host port for that known destination, and empty registries fail closed. HTTP decision metrics use fixed host buckets (`<admit_explicit>`, `<admit_wildcard>`, `<denied>`); stream rejects export `ferrum_mesh_outbound_registry_stream_decisions_total{protocol, decision}` instead. Inbound sidecar/ambient traffic is not gated by this outbound policy |
| `VirtualService` header/method/queryParam predicates beyond plugin capture | Partial | Plumbing in place via `mesh_route_dispatch` plugin (translated unconditionally, enabled by default — no opt-in env var or kill switch); supported predicates are captured as plugin config. **Method `StringMatch` supports `exact`, `prefix`, and `regex`** — regex patterns compile once at config-load time; `prefix` / `regex` patterns are uppercased at compile time (HTTP methods are uppercase ASCII per RFC 9110 §9.1); invalid regex is a hard translator/plugin construction error. **Header `StringMatch` supports `exact`, `prefix`, and `regex`** — regex patterns compile once at config-load time; invalid regex is a hard translator/plugin construction error. **`authority` `StringMatch` supports `exact`, `prefix`, and `regex`** — exact/prefix compare raw request `Host`/`:authority` case-sensitively, including explicit request ports; regex patterns are compiled verbatim and must match the full authority string, and operators who want case-insensitive regex should write `(?i)` in the pattern. `authority` is a per-rule predicate (Istio `HTTPMatchRequest.authority`), distinct from VirtualService-level `hosts` which gates proxy admission. **`sourceNamespace` is a first-class predicate** — the request hot path reads the source workload's Kubernetes namespace from `ctx.peer_spiffe_id` via `SpiffeId::namespace`; the predicate fails closed without a resolved peer identity and empty / whitespace-only operator values fail closed via `request_termination`. **`ignoreUriCase: true` affects exact/prefix URI matches only** — the translator widens escaped literal operands into case-insensitive regex listen_paths (`prefix: "/Api"` → `~(?i:/Api.*)`, `exact: "/Api"` → `~(?i:/Api)`), while `regex` URI matches keep their operator-supplied regex unchanged. The dispatch rule carries the original exact/prefix URI predicate + `ignore_uri_case: true` so the plugin re-evaluates with ASCII-only case folding at request time without per-request allocation; non-ASCII bytes compare byte-for-byte. Overlapping case variants and contained exact/prefix intersections collapse or decorate ordered dispatch rules so Ferrum's exact/prefix-before-regex router preserves Istio route order. Routing-decision rewrites via `RequestContext.route_override_*` flow through HTTP-family dispatch sites (pool keys, capability registry, circuit breaker). Translator emits the plugin with `reject_unmatched: true` so requests that miss predicates return 404 instead of falling through to the default backend. Same-path and URI-less ordered canary/default routes collapse into one Proxy with ordered dispatch rules so predicate misses can fall through when a later route exists. Per-rule `timeout` / `retries` ride on each dispatch rule and are reapplied through `RequestContext.route_override_*`. Route-level `headers.request.{set,add,remove}` and `headers.response.{set,add,remove}` are projected onto each dispatch rule as per-rule transform arrays and applied by `request_transformer` / `response_transformer`. Route-local `fault` rides on each dispatch rule as a per-rule `fault` action and collapses cleanly with sibling routes. **`http[].rewrite` and `http[].redirect` are now supported**: `rewrite.uri` (prefix-rewrite-aware) and `rewrite.authority` ride on each dispatch rule and rebase the backend request path / `Host` (authority rewrite flips `preserve_host_header` on the effective proxy); `redirect` rides on each dispatch rule and short-circuits the request with a 3xx + `Location` (no backend, so a redirect route needs no `route[]`). **`http[].mirror` is now supported** as a proxy-scoped `request_mirror` plugin (per-route; a mirror route that must collapse fails closed). **`spec.tcp` / `spec.tls` L4 routing is supported** — materialized into Ferrum stream proxies (`tls[]` → passthrough TCP keyed by SNI; `tcp[]` → plain TCP keyed by port), reusing the gateway/east-west stream + SNI machinery; L4 match predicates (`sourceLabels`/`sourceSubnets`/`destinationSubnets`/`gateways`/`sourceNamespace`) compile onto `Proxy.stream_match`; weighted multi-destination splits materialize an upstream-backed stream proxy (`istio-vs-l4-upstream-*`). Unsupported predicate-only candidates (`regex`/`prefix` queryParam matchers, etc.) emit proxy-scoped `request_termination` instead of widening traffic. Admission plugins such as `mesh_authz` and rate limiting still evaluate the original public proxy identity; WebSocket overrides apply to the upgrade backend only, and HBONE CONNECT evaluates `before_proxy` before the relay branch, so route overrides can select the HBONE backend. Example `authority` match: `match: [{ uri: { prefix: "/api" }, authority: { prefix: "api." } }]` routes `Host: api.staging.example.com` but not `Host: API.staging.example.com` or `Host: admin.example.com`. Example `sourceNamespace` match: `match: [{ uri: { prefix: "/internal" }, sourceNamespace: "platform" }]`. Example `ignoreUriCase`: `match: [{ uri: { prefix: "/api" }, ignoreUriCase: true }]` matches both `/api/users` and `/API/users`. |
| Pod auto-discovery (K8s native service registry) | Supported (opt-in) | Set `FERRUM_K8S_POD_DISCOVERY_ENABLED=true`; the CP watches Pod/Service/EndpointSlice/Node resources, surfaces only ready Pods, links Services through EndpointSlices, and lets explicit `WorkloadEntry` / `ServiceEntry` resources override auto-derived entries |
| `WorkloadEntry` `weight` / `locality` / `serviceAccount` / cross-namespace `service` | Supported | `weight` and `locality` are consumed by upstream target materialization; locality priority load balancing prefers exact, zone, then region tiers before falling back. `DestinationRule.trafficPolicy.loadBalancer.localityLbSetting.distribute` / `failover` / `failoverPriority` / `enabled` are honored (see "Locality-Aware Load Balancing" above). `serviceAccount` is kept separately from the SPIFFE path so introspection/audit doesn't need to parse it. Cross-namespace `spec.service` hosts (`<svc>.<ns>.svc` / FQDN) attach only when a Gateway API `ReferenceGrant` in the **target Service namespace** permits `from: {group: networking.istio.io, kind: WorkloadEntry, namespace: <WorkloadEntry namespace>}` → `to: {group: "", kind: Service}` (optional `name`) **and** the target Service exists in the translated inventory; missing/unauthorized/stale targets fail closed with `FerrumAccepted=False`. Same-namespace hosts keep prior behavior (no grant required). Ambiguous two-label DNS names such as `reviews.prod` stay literal and do not widen as Kubernetes Service keys. Accepted status reports `service` / `service_namespace` / `cross_namespace_service`. |
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
| `FERRUM_MESH_NODE_ID` | `$HOSTNAME` or `ferrum-mesh-node` | Node identifier sent to the CP. On the xDS path it becomes `DiscoveryRequest.node.id` and must satisfy the CP's [`Node.id` contract](#xds-ads-admission-budgets): non-empty, at most `FERRUM_XDS_MAX_NODE_ID_BYTES` UTF-8 bytes, printable ASCII (`0x21`–`0x7E`) only |
| `FERRUM_MESH_TOPOLOGY` | `sidecar` | Topology: `sidecar`, `ambient`, `node_waypoint`, `service_waypoint`, `east_west_gateway`, `egress_gateway` |
| `FERRUM_MESH_WAYPOINT_NAME` | (none) | Required when `FERRUM_MESH_TOPOLOGY=service_waypoint`; names the GAMMA waypoint binding requested from the CP |
| `FERRUM_MESH_WORKLOAD_SPIFFE_ID` | (none) | SPIFFE ID of this mesh workload |
| `FERRUM_MESH_WORKLOAD_LABELS` | (none) | Comma-separated `key=value` workload labels for PolicyScope matching |
| `FERRUM_MESH_TRUST_DOMAIN_ALIASES` | (none) | Additional trust domains for HBONE baggage validation |
| `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS` | (none) | HBONE peers trusted to assert baggage `source.principal`. Comma-separated SA names and/or full SPIFFE ids. Empty/unset uses defaults `[ztunnel, waypoint]`, except identity-backed `NodeWaypoint` derives exact assertor SPIFFE IDs from the scope-authorized CP-derived `node_waypoint_assertors` inventory and uses an empty list when none exists |
| `FERRUM_MESH_SIDECAR_ENFORCED` | `false` | When `true`, applies Istio `Sidecar` egress scope narrowing to `services` / `service_entries` / `destination_rules` / projected VirtualService L4 route proxies per workload. Sidecars are always parsed; this flag gates only the slice-narrowing pass. Opt in after vetting your `Sidecar` resources |
| `FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN` | `false` | Computes and reports the applicable `Sidecar` egress scope while leaving the slice unchanged. Use with `/mesh/egress-scope` before enabling enforcement |
| `FERRUM_MESH_SIDECAR_IDENTITY_NARROWING` | `false` | When `true` and `FERRUM_MESH_SIDECAR_ENFORCED=true`, filters `workloads` to SPIFFE identities referenced by services admitted by the applicable Sidecar. Default-off for rollout; trust-bundle mTLS validation and HBONE trust-domain aliasing do not depend on this list |
| `FERRUM_MESH_EGRESS_STREAM_ENABLED` | `false` | Opt-in for **stream-family (TCP + UDP)** egress materialization in `EgressGateway` topology. When enabled, each per-port TCP listener **terminates SVID-mTLS and runs `mesh_authz`** at accept (same authn/z as HTTP egress, reusing the mesh-inbound `ServerConfig` + SPIFFE peer verifier; client certs required). UDP ServiceEntry ports materialize a **destination allowlist** instead of a listener: the gateway's authenticated mesh CONNECT terminator relays a `udp`-marked CONNECT for an admitted external destination into a local `UdpSocket` (issue #3263), bounded by `FERRUM_UDP_MAX_SESSIONS`. With the flag off nothing UDP is admitted and there is no plaintext fallback. Default-off because protocol-aware mediation is absent and the mTLS datapath is not yet live-e2e verified. Set `FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT=true` to restore the legacy plaintext + unauthenticated listener. HTTP-family egress is unaffected |
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
| `FERRUM_MESH_EGRESS_GATEWAY_ADDR` | — | **Source-side** EgressGateway `host:port` for captured EXTERNAL UDP (issue #3263). Set on a `sidecar`/`ambient` data plane. Requires `FERRUM_MESH_EGRESS_GATEWAY_SPIFFE_ID`; one without the other is a startup error. Host must be a bounded DNS hostname, IPv4 literal, or bracketed IPv6 literal (surrounding whitespace/control, wildcards / URL material refused without echoing the raw value). Also requires the shared `FERRUM_MESH_EGRESS_STREAM_ENABLED=true` opt-in used by the gateway allowlist. Unset or flag-off means captured external UDP is dropped, never direct-dialed |
| `FERRUM_MESH_EGRESS_GATEWAY_SPIFFE_ID` | — | SPIFFE id pinned as the expected mTLS peer when dialing `FERRUM_MESH_EGRESS_GATEWAY_ADDR`. A gateway whose SVID does not match refuses the dial. Surrounding whitespace/control and invalid identities are refused with a bounded class diagnostic that never echoes the configured value |

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
| `FERRUM_MESH_PRODUCTION_MODE` | `false` | Master production guardrail. When `true`, the dev-only self-signed CA bootstrap, the dev-only static attestor, the process-local JWT signing key (`FERRUM_MESH_ALLOW_EPHEMERAL_JWT_KEY`), the no-identity posture, and gateway-wide TLS verification bypasses (`FERRUM_TLS_NO_VERIFY` / `FERRUM_ADMIN_TLS_NO_VERIFY`) are refused unconditionally. Read directly by the identity helpers (not parsed into `EnvConfig`). Set in every production deployment. See [Internal Dev CA and Production Guardrails](#internal-dev-ca-and-production-guardrails) |
| `FERRUM_MESH_CA_BOOTSTRAP_DEV` | `false` | Dev-only opt-in to mint a self-signed mesh root for the `internal` CA backend. The bootstrap helper refuses unless this is `true` **and** `FERRUM_MESH_PRODUCTION_MODE` is not `true`. Lab/test only |
| `FERRUM_MESH_ALLOW_STATIC_ID` | `false` | Dev-only opt-in for the `StaticAttestor` (hard-coded SPIFFE ID for any peer). Refused unless `true` and `FERRUM_MESH_PRODUCTION_MODE` is not `true`. Lab/test only |
| `FERRUM_MESH_ALLOW_NO_CA` | `false` | Dev/test opt-in to start `mesh` mode with **no workload identity** — i.e. neither configured gateway SVID material (`FERRUM_GATEWAY_SVID_*`) **nor** a CA backend (`FERRUM_MESH_CA_BACKEND=spire_agent|internal` + `FERRUM_MESH_WORKLOAD_SPIFFE_ID`). Without it, an identity-less mesh fails startup closed (no mTLS ⇒ PERMISSIVE accepts plaintext). Read directly from the environment (not `ferrum.conf`); refused unconditionally when `FERRUM_MESH_PRODUCTION_MODE=true`. Lab/test only — see [Internal Dev CA and Production Guardrails](#internal-dev-ca-and-production-guardrails) |

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
| `FERRUM_K8S_WATCH_GATEWAY_API_CRDS` | `true` | Watch and translate Gateway API CRDs (GatewayClass/Gateway/HTTPRoute/GRPCRoute/TCPRoute/TLSRoute/UDPRoute) and write their status |
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
