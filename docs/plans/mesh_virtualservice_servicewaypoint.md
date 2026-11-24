# ServiceWaypoint `VirtualService` `http[]` Routing and Cross-Namespace Destinations Design

Status: Proposed design specification (tracker: [#7423](https://github.com/ferrum-edge/ferrum-edge/issues/7423)).

## Context

Issue [#7390](https://github.com/ferrum-edge/ferrum-edge/issues/7390) and
[#7416](https://github.com/ferrum-edge/ferrum-edge/issues/7416) surfaced that
mesh-bound Istio `VirtualService` `http[]` routes (weighted splits, header/URI
match dispatch, rewrites, retries, timeouts, faults, and mirrors) were applied
only on `NodeWaypoint` data planes. PR
[#7431](https://github.com/ferrum-edge/ferrum-edge/pull/7431) extended the
existing `NodeWaypoint` projection and data-plane rebinding machinery to
`Sidecar` data planes (client-side on the outbound capture listener `:15001`,
over pinned SVID-mTLS), and closed an inbound confused-deputy vector by
excluding carried `istio-vs-*` routes from every inbound mesh listener via
`mesh_route_admitted_for_direction`.

Three architectural gaps remain on tracker
[#7423](https://github.com/ferrum-edge/ferrum-edge/issues/7423):

1. **`ServiceWaypoint` projection and L7 termination.** Today a
   `ServiceWaypoint` binds a single inbound HBONE listener (`0.0.0.0:15008`,
   `MeshTrafficDirection::Inbound`), materializes no HTTP routes, and relays
   authenticated HTTP/2 `CONNECT` tunnels transparently at L4 through
   `build_inbound_hbone_relay_proxy` (`src/proxy/mod.rs`) and
   `handle_hbone_request` (`src/proxy/hbone_proxy.rs`). Applying
   `VirtualService` `http[]` routes requires terminating HTTP/1.1 and HTTP/2
   inside admitted HBONE tunnels and dispatching inner requests without
   weakening the inbound-listener exclusion on `Sidecar` `:15006` or
   `NodeWaypoint` `:15008`.
2. **Cross-namespace carried destinations.** PR #7431 refuses any carried
   `VirtualService` route whose direct destination, `mesh_route_dispatch` rule
   destination, or weighted-split leg names a `Service` in another namespace
   (`cross_namespace_refused` / `cross_namespace_leg` in
   `src/modes/mesh/mod.rs`), because `GatewayConfig::validate_upstream_references`
   resolves `upstream_id` within a single namespace and `VirtualService`
   translation has no cross-namespace authorization contract comparable to
   Gateway API `ReferenceGrant`.
3. **Live E2E weighted-split infrastructure.** Neither `Sidecar` nor
   `ServiceWaypoint` has a live kind-cluster 90/10 weighted-split assertion.
   `mesh-e2e-sidecar`'s client sidecars consume `FERRUM_MESH_CONFIG_PROTOCOL=file`
   (which rejects gateway route resources) and its `ferrum-cp` runs with
   `FERRUM_K8S_WATCH_ISTIO_CRDS=false` and no Istio CRDs installed.

### Explicit Non-Goals

- **`Ambient` stays L4-only.** Consistent with Istio Ambient (`ztunnel`),
  `MeshTopology::Ambient` continues to carry no `http_routes` and flags
  `http[]` routes as unapplied. Operators bind a `ServiceWaypoint` or use
  `NodeWaypoint`/`Sidecar` for L7 routing.
- **Gateway API GAMMA `HTTPRoute` with `Service` `parentRefs`.** Out of scope
  for this specification. The HBONE inner HTTP server and bound-Service route
  index designed here are shaped so GAMMA `HTTPRoute` can target the same
  dispatcher in a later track without re-architecting `:15008`.
- **No weakening of existing transport or tenancy invariants.** `Sidecar`
  inbound `:15006` and `NodeWaypoint` inbound `:15008` continue to reject
  carried `istio-vs-*` routes; `GatewayConfig::validate_upstream_references`
  remains strictly namespace-local; no silent plaintext fallback is introduced
  for identity-backed in-mesh targets.

## Architecture Overview

```text
Ambient / NodeWaypoint / HBONE Client
  │  mTLS + HTTP/2 CONNECT :authority = <bound-service-ip|host|workload-ip>:<port>
  │  (optional outer baggage: source.principal)
  ▼
ServiceWaypoint :15008 (MeshListenerKind::HboneTermination, Inbound)
  ├─ Gate 1: Verified peer SPIFFE + HbonePeerCredential (trust anchors + CRLs)
  ├─ Gate 2: PeerAuthentication transport posture + trusted_hbone_assertors baggage
  ├─ Gate 3: Binding guard against MeshSlice.service_waypoint_bound_services
  │
  ├──[Stream-family port or connect-udp]──▶ Existing L4 transparent relay
  │                                          (handle_hbone_request / handle_hbone_udp_request)
  │
  └──[HTTP-family port on bound Service]──▶ HboneAdmissionFence (ServiceWaypointL7 gate)
                                              │  200 OK → TokioIo<Upgraded>
                                              ▼
                                            Inner HTTP/1.1 + HTTP/2 Server
                                            (hyper_util::server::conn::auto::Builder)
                                              │  Per inner request:
                                              │  1. Stamp trusted outer identity + ServiceWaypointL7Context
                                              │  2. Pin lookup to bound Service's route table (host mismatch → 403)
                                              │  3. Destination-scoped RequestAuthentication
                                              │  4. Per-branch mesh_authz (ALLOW/DENY/CUSTOM, targetRefs + L7 attrs)
                                              │  5. mesh_route_dispatch + weighted_splits leg selection + transforms/fault/mirror/cors
                                              │  6. Dispatch selected leg over HBONE / SVID-mTLS / DR-originated external TLS
                                              ▼
                                            Destination Workload (bound Service, split leg, or authorized x-ns Service)
```

## 1. L7 Termination and Route Dispatch on the HBONE Inbound Listener

### 1.1 Outer `CONNECT` Classification: L4 Relay vs. L7 Termination

Today, every arriving `CONNECT` on `ServiceWaypoint` `:15008` misses the router
and enters `build_inbound_hbone_relay_proxy` (`src/proxy/mod.rs`), which checks
`inbound_hbone_relay_destination_decision` against `inbound_relay_destinations`
(derived strictly from `service_waypoint_backing_workloads`, issue #4251) and
synthesizes `__mesh-inbound-hbone-relay`.

With `ServiceWaypoint` L7 termination, the outer `CONNECT` boundary runs a
deterministic, fail-closed classification **before** dialing any backend:

1. **Datagram tunnels (`connect-udp`, `is_udp_hbone_connect == true`)** always
   stay on the existing `handle_hbone_udp_request` L4 datagram relay path.
2. **Outer trust and credential gates run identically to L4 HBONE:**
   - Verified peer SPIFFE identity (`is_authenticated_hbone_connect()`,
     `ctx.peer_spiffe_id.is_some()`). Peerless `CONNECT` is rejected `403`
     (`hbone_unauthenticated_peer`).
   - Live credential and CRL verification via
     `HbonePeerCredential::from_admitted_connect` against
     `ProxyState::mesh_inbound_admission` (`hbone_peer_trust_withdrawn` /
     `hbone_peer_revoked`).
   - Outer `PeerAuthentication` transport check (`mesh_inbound_peer_auth_transport_mismatch`).
   - Trusted HBONE baggage evaluation (`hbone_assertion_verdict` with the
     mandatory `#4274` order `untrusted_assertor` → `trust_domain_mismatch` →
     `assertion_out_of_scope` → honored). The resolved outer source principal
     (honored baggage principal if asserted, otherwise the verified peer SPIFFE
     ID) is captured once per outer tunnel.
3. **Binding and port-family resolution** consults a precomputed, immutable
   `ServiceWaypointL7TargetIndex` built per `RequestEpoch` from
   `MeshSlice.service_waypoint_bound_services` and `MeshSlice.services` (empty
   unless `service_waypoint_runtime_identity_matches` holds and `waypoint_for`
   is `service` or `all`):
   - **Service-VIP / Service-host authority** (`<ClusterIP>:<svc_port>` or any
     canonical host variant of a bound `MeshService` with `<svc_port>`):
     - If `<svc_port>` is an HTTP-family port (`service_http_family_ports`):
       admit as `ServiceWaypointConnectMode::TerminateL7(ServiceWaypointL7Target { namespace, service, service_port })`.
     - If `<svc_port>` is a stream-family port: fail closed for VIP-only L4
       unless a backing-workload relay target resolves, or route through the
       bound Service's L4 target selector (never terminated as HTTP).
   - **Backing-workload authority** (`<podIP>:<app_port>`):
     - Look up `<podIP>` in the bound backing workloads (`service_waypoint_backing_workloads`).
     - If `<podIP>:<app_port>` maps unambiguously to **exactly one** bound
       Service HTTP-family `(namespace, service, service_port)`: admit as
       `ServiceWaypointConnectMode::TerminateL7(...)`.
     - If `<podIP>:<app_port>` maps to a stream-family port: keep the existing
       L4 transparent byte-stream relay (`handle_hbone_request`).
     - If `<podIP>:<app_port>` maps to **multiple** bound Services with
       conflicting HTTP port ownership: fail closed `403` (ambiguous target —
       see [Failure Modes](#4-failure-modes-fail-closed)).
   - **Anything outside `service_waypoint_bound_services`** (including
     loopback, unbound Services visible in the namespace, remote-provenance
     workloads, or undeclared ports): fail closed through the existing
     `InboundConnectRelayRefusal` terminal (`403 hbone_relay_destination_denied`,
     or `503 hbone_relay_not_ready` before the first slice).

### 1.2 Outer Admission Fence and Inner HTTP Server Lifecycle

For `ServiceWaypointConnectMode::TerminateL7(target)`:

- **No backend TCP dial occurs at outer `CONNECT` time.** Backend selection
  depends on the inner HTTP request (URI, headers, weighted-split leg, or
  `mesh_route_dispatch` rule).
- **Admission Fence registration.** Before returning `200 OK` on the outer
  `CONNECT`, register the tunnel in `ProxyState.hbone_admission_fence` with a
  new `HboneRelayDestinationGate::ServiceWaypointL7 { service_namespace, service_name, service_port }`
  variant, capturing `peer_credential`, `admission_sweep_epoch`, and the
  verified outer `RequestContext`.
  - Every `HboneAdmissionFence` sweep re-checks:
    1. `proxy_withdrawn` (lifecycle),
    2. Credential gate (`peer_expired` → `peer_trust` → `peer_revoked`),
    3. Outer `PeerAuthentication` transport posture,
    4. Bound-service liveness: `(service_namespace, service_name, service_port)`
       must still exist as an HTTP-family port in the current epoch's
       `ServiceWaypointL7TargetIndex` (withdrawal revokes as `relay_destination`).
  - Note on per-request authorization vs. outer sweep: outer `CONNECT` does
    **not** run L7-only `mesh_authz` rules (method/path/header/JWT claims do
    not exist on the outer `CONNECT`), because every inner HTTP request runs
    the full `mesh_authz` + `RequestAuthentication` chain against the current
    `RequestEpoch`. Outer `mesh_authz` still enforces L4/principal-only denies
    applicable to the bound Service if configured, or defers L7 evaluation to
    the inner dispatcher while keeping credential/binding revocation live on
    the outer fence.
- **Inner connection reuse (`x-ferrum-mesh-tunnel-reuse: fenced`).** Because an
  L7-terminated HBONE tunnel already runs the full per-request plugin chain
  (including `rate_limiting`, `mesh_authz` CUSTOM `ext_authz`, `waf`,
  `mesh_route_dispatch`, and `RequestAuthentication`) on **every** inner HTTP
  request, inner HTTP/1.1 keep-alive and HTTP/2 multiplexing inside the tunnel
  do not skip per-operation plugins. The outer `200 OK` may advertise
  `x-ferrum-mesh-tunnel-reuse: fenced` whenever `tunnel.fence_in_force()` holds
  (so an Ambient/NodeWaypoint caller's `HboneInnerConnectionPool` can reuse the
  fenced tunnel across requests), while the fence continues to cut the outer
  tunnel immediately on peer credential expiry, trust/CRL revocation, or
  bound-Service withdrawal.
- **Inner HTTP/1.1 + HTTP/2 serving.** After `hbone_on_upgrade.await` returns
  `Upgraded`, wrap `TokioIo::new(upgraded)` and serve it with Ferrum's existing
  `hyper_util::server::conn::auto::Builder` (matching `src/proxy/mod.rs`),
  applying the configured HTTP/1.1 and HTTP/2 frame/header/stream ceilings,
  idle timeout, and graceful shutdown drain.
  - Drive the connection future in `tokio::select!` against
    `tunnel.revocation_token()` and `OverloadState` shutdown:
    - On clean close or idle timeout: retire the fence entry and close the
      outer stream cleanly (`END_STREAM`).
    - On fence revocation, inner HTTP protocol framing error, or overload
      abort: call `tunnel.retire()` first, then reset the outer `CONNECT`
      stream via `end_hbone_connect_stream(stream, true)`
      (`RST_STREAM(CONNECT_ERROR)`), preserving the `#5781`/`#5858` contract.
  - Connection accounting: track active L7 tunnels under the listener's
    existing `FERRUM_MAX_CONNECTIONS` permit (the outer H2 connection already
    holds a connection permit) and bound concurrent inner L7 tunnels per
    process (defaulting to a dedicated ceiling or sharing the HBONE stream cap)
    so a peer cannot multiply inner hyper tasks unboundedly over one outer H2
    connection. Each inner HTTP request acquires a normal `RequestGuard` inside
    `ProxyBody` for graceful shutdown drain parity.

### 1.3 Inner Request Context and Coexistence with `mesh_route_admitted_for_direction`

PR #7431 introduced `mesh_route_admitted_for_direction` (`src/modes/mesh/mod.rs`),
which unconditionally blocks carried `istio-vs-*` routes whenever
`request_direction == Some(MeshTrafficDirection::Inbound)`. That guard MUST
remain intact for every direct outer listener (`Sidecar` `:15006`,
`NodeWaypoint` `:15008`, and direct non-CONNECT requests arriving on
`ServiceWaypoint` `:15008`).

For each inner HTTP request parsed inside an L7-terminated `ServiceWaypoint`
HBONE tunnel:

1. **Unforgeable outer provenance.** The inner `service_fn` constructs a fresh
   `RequestContext` and copies **only** verified outer transport facts:
   - `peer_spiffe_id`: the outer tunnel's verified peer SPIFFE ID.
   - Resolved outer source identity (including any honored `source.principal`
     from the outer `CONNECT` baggage). Inner HTTP `baggage` headers are
     **never** treated as HBONE identity assertions.
   - `tls_client_cert_der` / peer trust metadata (for `mesh_authz` principal
     and `sourceNamespace` checks).
   - `orig_dst` / trusted port provenance set to the outer `CONNECT`'s bound
     `service_port` (so `match.port` and `destination.port` read trusted outer
     provenance, never the client-supplied `Host` header).
   - A runtime-only, unforgeable context struct:
     ```rust
     pub(crate) struct ServiceWaypointL7Context {
         pub bound_service_namespace: String,
         pub bound_service_name: String,
         pub bound_service_port: u16,
     }
     ```
     carried on `RequestContext` (skipped by serialization and never set by any
     outer listener).
2. **Bound-Service route pinning (anti-spoofing).**
   - Introduce a scoped admission predicate (or pass `Option<&ServiceWaypointL7Context>`
     into the router lookup alongside `mesh_direction`):
     - When `service_waypoint_l7.is_none()`: `mesh_route_admitted_for_direction`
       behaves **byte-for-byte identically** to today — `istio-vs-*` routes are
       never admitted on `Inbound`.
     - When `service_waypoint_l7 == Some(sw)`: the router consults ONLY the
       precomputed per-bound-Service route partition keyed by
       `(sw.bound_service_namespace, sw.bound_service_name, sw.bound_service_port)`.
   - **Host validation.** Before matching a route inside that partition, verify
     that the inner request's normalized `Host`/`:authority` host (stripping any
     optional matching `:service_port`) belongs to that bound Service's
     admitted host set (the Service's canonical host variants plus any carried
     `VirtualService` host explicitly bound to that Service).
     - An inner request with a mismatched `Host` (for example, opening an outer
       `CONNECT` to bound Service `A` and sending inner `Host: service-b.ns.svc`
       or `Host: attacker.example.com`) is rejected immediately with `403`
       (`mesh_authz.deny_policy = "service_waypoint_host_mismatch"`), logged,
       and never routed to Service `B` or an external host.
   - **Precedence inside the bound-Service partition.** Carried `istio-vs-*`
     routes bound to `(service_ns, service_name)` shadow the bound Service's
     default materialized L7 route (`__mesh-sw-service-{ns}-{svc}-{port}`) on
     matching paths, while non-matching paths (or a Service with no
     `VirtualService`) fall through cleanly to the default bound Service route.

### 1.4 Inner Plugin Chain, Policy Evaluation, and Backend Transport

Once the inner request resolves a route inside the bound-Service partition, it
executes the standard Ferrum HTTP request pipeline with the following
`ServiceWaypoint`-specific guarantees:

- **`RequestAuthentication` destination scoping.** Generalize
  `scope_request_auth_to_node_waypoint_destinations` (`src/modes/mesh/mod.rs`)
  to run for both `NodeWaypoint` and `ServiceWaypoint`. Every candidate
  destination a carried route can reach (direct backend, dispatch rule
  branches, and weighted-split legs) must resolve to the same effective
  `RequestAuthentication` set; disagreement refuses the route fail-closed.
- **`AuthorizationPolicy` (`mesh_authz`) per-branch evaluation.** Generalize
  `thread_node_waypoint_route_branches_to_authz` (`src/modes/mesh/mod.rs`) to
  run for `ServiceWaypoint` as well as `NodeWaypoint`:
  - `mesh_authz` evaluates destination-scoped policies (including `targetRefs`
    matching the waypoint `Gateway`, its `GatewayClass`, or the bound
    `Service`, plus namespace and root-namespace policies) for the route's own
    destination and every `mesh_route_dispatch` branch / `weighted_splits` leg.
  - Because the inner request is terminated at L7, `mesh_authz` evaluates the
    full L7 attribute set (HTTP method, path, headers, `request_principals`,
    JWT claims, and trusted outer source principal / `sourceNamespace`).
  - `CUSTOM` external authorization runs only for the branch/leg the dispatch
    finalizer actually selects, matching the existing NodeWaypoint `#7383`/`#7387`
    semantics.
- **`mesh_route_dispatch` and companion route plugins.** Reuse unchanged:
  `mesh_route_dispatch` (including `weighted_splits` leg-by-leg dispatch via
  `select_weighted_split_leg`), `request_transformer`, `response_transformer`,
  `request_termination` (fault injection / unsupported-match 404), `cors`, and
  `request_mirror` (loopback-only per GHSA-gcwp-xp94-4pcv).
  - Unlike Sidecar outbound capture (which resolves `match.sourceNamespace`
    statically from its own workload), `ServiceWaypoint` serves requests from
    many callers and evaluates `match.sourceNamespace` **dynamically per
    request** from the outer tunnel's verified source principal (identical to
    `NodeWaypoint`).
- **Backend dispatch transport (Waypoint → Destination Workload):**

| Selected leg / destination | Transport | Peer identity pinning | Failure posture |
|---|---|---|---|
| Local-cluster backing workload with `Workload.node_waypoint` (Ambient/NodeWaypoint node) | HBONE (`mesh.hbone=true`, outer dial to `node_waypoint.address:hbone_port`, inner CONNECT authority = `<podIP>:<targetPort>`) | Pinned `node_waypoint.spiffe_id` (`mesh.spiffe_id`); outer baggage carries original source principal when waypoint is a trusted assertor | Fail closed `502` (`hbone_required`) if HBONE cannot be established; never downgrade to plaintext |
| Local-cluster backing workload enrolled as Ambient pod HBONE (`:15008`, no `node_waypoint` metadata) | HBONE (`mesh.hbone=true`, outer dial to `<podIP>:15008`, inner authority = `<podIP>:<targetPort>`) | Pinned workload `spiffe_id` (`mesh.spiffe_id`) | Fail closed `502` (`hbone_required`) |
| Local-cluster backing workload with Sidecar mTLS (`mesh.mtls` capability) | SVID-mTLS HTTP/2 (`:15006`), route-scoped authority clone presenting `<svc>.<ns>.svc:<port>` | Pinned workload `spiffe_id` (`mesh.spiffe_id`) | Fail closed `502` (`Sidecar mTLS backend unavailable`) |
| Local-cluster backing workload with no mesh proxy in explicit non-production / dev mode (`FERRUM_MESH_ALLOW_NO_CA=true`) | Direct HTTP to `<podIP>:<targetPort>` | None (explicit dev opt-out only) | Refused in `FERRUM_MESH_PRODUCTION_MODE=true` when identity/transport metadata is absent |
| External split leg (`ServiceEntry` / external host) | HTTP or DR-originated HTTPS (`project_node_waypoint_leg_origination` on residual upstream) | Per DestinationRule `tls` settings (SNI, CA, client cert) | Direct external backend with TLS-originating or wildcard DR refused fail-closed |
| Remote-cluster backing workload (`remote_provenance == true`) | Refused unless routed via East-West gateway transport (never plaintext pod dial) | N/A | Fail closed (excluded from direct backing targets, matching `service_waypoint_backing_workloads`) |

- **Loop prevention.** ServiceWaypoint materialized upstreams dial workload
  endpoints (or their node HBONE terminators), never a Service `ClusterIP` or
  the waypoint's own listener address. Inner requests preserve and increment
  `X-Ferrum-Hop-Limit` (without the Sidecar local-loopback exemption), so a
  misconfigured multi-waypoint chain terminates fail-closed instead of looping.

## 2. Destinations in Other Namespaces (Authz and Tenancy Rules)

PR #7431 refused cross-namespace destinations on every topology
(`cross_namespace_refused` / `cross_namespace_leg`) because `VirtualService`
translation lacked a cross-namespace permission boundary and
`validate_upstream_references` is strictly namespace-local.

### 2.1 Tenancy and Authorization Contract (Gateway API Parity)

Cross-namespace `VirtualService` `http[]` destinations MUST satisfy the same
defense-in-depth guarantees Ferrum enforces for Gateway API `HTTPRoute`
`backendRefs` (`src/config_sources/k8s/backend_ref.rs::checked_backend_namespace`)
and cross-namespace `WorkloadEntry.spec.service`
(`src/config_sources/k8s/mod.rs::resolve_workload_entry_service_attachment`):

1. **Default deny.** A `VirtualService` in namespace `A` referencing a
   in-cluster `Service` in namespace `B` (`B != A`, parsed from `<svc>.<ns>` or
   `<svc>.<ns>.svc[.<cluster_domain>]`) is **refused by default**.
2. **Explicit Gateway API `ReferenceGrant` in the target namespace (`B`).**
   During Kubernetes translation (`src/config_sources/k8s/istio.rs`), a
   cross-namespace `VirtualService` destination is admitted ONLY when a valid
   `ReferenceGrant` in namespace `B` matches:
   - `spec.from[]`: `group == "networking.istio.io"`, `kind == "VirtualService"`,
     `namespace == A`
   - `spec.to[]`: `group == ""` (core), `kind == "Service"`, and `name` is
     omitted or equals `<svc>`.
   - Missing, malformed, or mismatched grants fail closed: the `VirtualService`
     translation returns `K8sTranslateError` (`FerrumAccepted=False`, reason
     `RefNotPermitted`), and no partial/ungranted route is emitted.
3. **Target Service existence and `ExternalName` refusal.**
   - The target `(B, <svc>)` MUST exist in the translated Service inventory.
   - `type: ExternalName` Services are **refused fail-closed** (matching
     `backend_ref.rs:235`), because an `ExternalName` DNS alias can redirect to
     a third namespace or loopback and bypass `ReferenceGrant`.
4. **`EndpointSlice` attribution guard (issue #6108 parity).**
   - Every cross-namespace `VirtualService` destination runs through the shared
     `EndpointSliceGuard` (`core::endpoint_slice_guard`), refusing
     `ForeignEndpoint`, `UnattributedEndpoint`, and `Unverifiable` findings.
   - `FERRUM_K8S_ALLOW_SELECTORLESS_EXTERNAL_ENDPOINTS` NEVER widens
     cross-namespace `VirtualService` destinations (identical to Gateway API).
   - Build `EndpointSliceGuard` whenever the snapshot contains either a Gateway
     API route **or** a `VirtualService` with a cross-namespace Service
     destination.
5. **Control-plane scope and bearer `ns` tenancy ceiling.**
   - `CpScope::Single`, `CpScope::Set`, and the subscribing DP's gRPC JWT `ns`
     claim remain hard boundaries. A CP that does not watch or is not
     authorized for namespace `B` never exposes `B`'s `Service`, `Workload`,
     `DestinationRule`, `AuthorizationPolicy`, or `RequestAuthentication`
     resources, even if a `ReferenceGrant` exists in etcd.
6. **Non-K8s (`file` / `database` / direct API) configs.**
   - `MeshVirtualServiceHttpRoutes` gains an explicit
     `authorized_cross_namespace_targets: Vec<MeshWaypointServiceRef>` field
     (default empty, `#[serde(default, skip_serializing_if = "Vec::is_empty")]`).
   - The K8s translator populates this list strictly from targets that passed
     gates 2–4 above.
   - File/DB operators must explicitly declare authorized cross-namespace
     targets (still bounded by `CpScope` and subscriber visibility); bare host
     strings alone never authorize cross-namespace routing.
7. **Subscriber visibility and scope intersection.**
   - **Sidecar / NodeWaypoint:** In addition to `authorized_cross_namespace_targets`,
     the target Service must be visible in the subscriber's slice (admitted by
     namespace visibility and any applicable `Sidecar.egress` scope).
   - **ServiceWaypoint:** An authorized cross-namespace target Service of a
     carried route on a bound Service is projected into the waypoint's slice
     **only** for L7 route dispatch — it is **never** added to
     `MeshSlice.service_waypoint_bound_services` and **never** added to
     `MeshConfig.inbound_relay_destinations`, so an L4 HBONE `CONNECT` cannot
     use a `VirtualService` split leg to widen the waypoint's open-relay guard.
     Instead, the CP carries the target Service, its backing workloads, its
     visible `DestinationRule`s, and its destination `AuthorizationPolicy` /
     `RequestAuthentication` resources through dedicated slice scoping so L7
     authorization and DR enforcement stay exact.

### 2.2 Data-Plane Upstream Representation Without Weakening Namespace Locality

`GatewayConfig::validate_upstream_references` (`src/config/types.rs:5896`)
requires every `Proxy.upstream_id` and `mesh_route_dispatch` `upstream_id` to
resolve within `proxy.namespace`. Keeping that invariant prevents cross-tenant
ID collisions across the entire gateway core.

To support an authorized cross-namespace destination `(svc_ns, svc_name, port)`
referenced by a carried route in `route_ns`:

1. **Verify authorization at DP bind time** (`bind_carried_http_routes_to_node_waypoint_transport`):
   - Check that `(svc_ns, svc_name)` is listed in the carrying route's
     `authorized_cross_namespace_targets` (carried on `MeshHttpRouteSet` /
     `HttpRoutesCarrier`) AND that `(svc_ns, svc_name, port)` has a
     materialized transport upstream in `config.upstreams` under `svc_ns`.
   - If either check fails, refuse the route (`cross_namespace_refused`) so the
     host falls back to its plain Service route without rejecting unrelated
     routes in the slice.
2. **Create a route-namespace transport clone post-DR and post-locality:**
   - During `bind_carried_http_routes_to_node_waypoint_transport`, reserve a
     deterministic, collision-free, route-namespace upstream ID
     (`__mesh-out-vs-xns-upstream-<sha256_prefix(route_ns|svc_ns|svc_name|port)>`
     for Sidecar/NodeWaypoint, `__mesh-sw-vs-xns-upstream-<digest>` for
     ServiceWaypoint) so all `Proxy.upstream_id`, `mesh_route_dispatch` rule
     destinations, and `weighted_splits` legs resolve inside `route_ns`.
   - Populate the clone **after** `apply_destination_rules` and
     `project_mesh_source_locality` (extending the exact post-DR cloning stage
     used by `clone_sidecar_carried_destination_upstreams`), copying targets
     and projected DR policy from the `svc_ns` Service upstream:
     - **DestinationRule lookup precedence** stays Istio-accurate: the `svc_ns`
       Service upstream already received the winning rule from
       `subscriber_ns → svc_ns → istio_root_namespace` (honoring `exportTo`).
     - **Admission budget sharing:** Set `Upstream::admission_upstream_id` (plus
       target namespace identity) to the `svc_ns` Service upstream so
       `http2MaxRequests` and `http1MaxPendingRequests` share the destination
       Service's single concurrency lane across same-namespace and
       cross-namespace callers.
     - **Sidecar `:authority` stamping:** Targets carry
       `MESH_MTLS_AUTHORITY_HOST_TAG = "<svc_name>.<svc_ns>.svc"` and
       `MESH_MTLS_AUTHORITY_PORT_TAG = "<port>"` (or port-only when an admitted
       `rewrite.authority` names the `svc_ns` Service), so the destination
       Sidecar routes the request onto its inbound table.
     - **Waypoint destination authorization & `RequestAuthentication`:** Each
       target carries `UPSTREAM_TARGET_SERVICE_NAMESPACE_TAG = svc_ns`,
       `UPSTREAM_TARGET_SERVICE_NAME_TAG = svc_name`, and
       `UPSTREAM_TARGET_SERVICE_PORT_TAG = port`. `thread_node_waypoint_route_branches_to_authz`
       and `scope_request_auth_to_node_waypoint_destinations` resolve policy
       scope from those target tags (not from `proxy.namespace`), so a
       cross-namespace leg is authorized against `svc_ns`'s policies, never
       `route_ns`'s.

## 3. Config Projection from `VirtualService` `http[]` to `ServiceWaypoint`

### 3.1 Wire and Request Contract

- **`MeshSliceRequest` (`src/modes/mesh/slice.rs`):** Add
  `pub service_waypoint_http_routes: bool`, populated only when
  `runtime.topology == MeshTopology::ServiceWaypoint`
  (`requests_service_waypoint_http_routes`). Keeping this distinct from
  `node_waypoint_capture_scoping` and `sidecar_http_routes` prevents a
  `ServiceWaypoint` from ever receiving `NodeWaypoint` capture inventories and
  lets mixed/rolling versions negotiate capabilities explicitly.
- **Native `MeshSubscribe` (`proto/ferrum.proto`):** Add additive field
  `bool service_waypoint_http_routes = 11;` on `MeshSubscribeRequest`.
- **xDS ADS (`src/xds/carrier.rs`, `src/xds/server.rs`):** Mirror
  `service_waypoint_http_routes` on `XdsNodeMetadata` and `XdsNodeScoping`.
  Carried routes reuse the existing `HttpRoutesCarrier`
  (`ferrum-mesh-carrier/http-routes`), extended with the optional
  `authorized_cross_namespace_targets` metadata per route binding (with
  strict schema and size bounds).

### 3.2 Control-Plane Projection and Anti-Hijack Scoping

In `MeshSlice::from_gateway_config` (`src/modes/mesh/slice.rs`):

1. **Compute `service_waypoint_bound_services` first** (via
   `service_waypoint_bound_service_refs`: non-empty only when the exact
   `(waypoint_namespace, waypoint_name)` matches a `MeshWaypointBinding` with
   `waypoint_for` in `{"service", "all"}`).
2. **Strict binding gate (no fail-open for HTTP routes).** Although
   `narrow_for_service_waypoint` preserves namespace-visible `services` during
   a rollout window before a `Gateway` object lands, `http_routes` MUST NOT
   fail open: when `request.service_waypoint_http_routes` is true and
   `service_waypoint_bound_services` is empty, project an **empty**
   `MeshHttpRouteSet`.
3. **Host and owner admission for bound Services.** A `MeshVirtualServiceHttpRoutes`
   binding is projected onto a `ServiceWaypoint` slice only when ALL of the
   following hold:
   - At least one proxy in the binding declares a `hosts[]` entry matching a
     canonical host variant of a bound Service `(svc_ns, svc_name)` in
     `service_waypoint_bound_services` (proxies in the same VirtualService
     targeting unrelated hosts are excluded).
   - **Anti-hijack namespace rule:** The VirtualService lives in `svc_ns` (the
     bound Service's own namespace) OR in `waypoint_namespace` (when the
     Service bound a cross-namespace waypoint via
     `istio.io/use-waypoint-namespace` and the VirtualService's `exportTo`
     admits `svc_ns`). A VirtualService in an unrelated third namespace — even
     with `exportTo: ["*"]` — is NOT admitted onto another tenant's
     `ServiceWaypoint`, preventing cross-tenant route hijacking on shared
     waypoints.
   - Self-containment checks match `node_waypoint_http_route_set`: every plugin
     association resolves to a proxy-owned `istio-vs-*` plugin config and every
     upstream reference resolves to a carried `istio-vs-upstream-*` upstream.
   - Every destination in the route is either a bound Service, an external host
     (subject to waypoint egress rules), or a cross-namespace Service explicitly
     listed in `authorized_cross_namespace_targets` and visible under
     `CpScope`/JWT `ns`.
4. **Dependent resource projection for authorized cross-namespace legs.** When
   an admitted `ServiceWaypoint` route has an authorized cross-namespace
   destination `(target_ns, target_svc)`, `narrow_for_service_waypoint` retains
   that target Service, its backing workloads, its applicable
   `DestinationRule`s, and its destination `AuthorizationPolicy` /
   `RequestAuthentication` resources in the slice (tagged separately from
   `service_waypoint_bound_services` so L4 open-relay admission stays strictly
   bounded to `service_waypoint_bound_services`).
5. **Coherence and equality.** `MeshSlice::content_eq`, xDS
   `config_fingerprint`, and `inject_mesh_global_plugins` (which strips
   `http_routes` from `__mesh_authz`'s embedded `mesh_slice`) continue to cover
   `http_routes` identically across all three L7 topologies.

### 3.3 Data-Plane Decode and Materialization

In `prepare_normalized_gateway_config_for_mesh` (`src/modes/mesh/mod.rs`):

1. `MeshTopology::serves_virtual_service_http_routes()` returns `true` for
   `NodeWaypoint`, `Sidecar`, and (once L7 HBONE termination lands)
   `ServiceWaypoint`.
2. `decode_http_route_set` runs unchanged: exact translator-shaped plugin
   allowlist (`CARRIED_ROUTE_PLUGIN_KINDS`), duplicate-ID rejection
   (`refuse_duplicate_carried_ids`), eager `MeshRouteDispatch::new` / `cors` /
   transformer / `request_termination` constructor validation, and rejection of
   wire-supplied `weighted_splits`. Any violation rejects the entire slice
   candidate and retains the last-good generation.
3. `materialize_service_waypoint_l7_routes` (ServiceWaypoint-only) materializes
   for each bound Service's HTTP-family port:
   - A default L7 Service upstream (`__mesh-sw-upstream-{ns}-{svc}-{port}`)
     carrying the backing workloads with the transport tags from
     [Section 1.4](#14-inner-plugin-chain-policy-evaluation-and-backend-transport).
   - A default L7 Service proxy (`__mesh-sw-service-{ns}-{svc}-{port}`) used
     when no carried VirtualService route matches a path on that bound Service.
   - Any authorized cross-namespace destination Service referenced by a carried
     route gets its target upstream materialized under `target_ns` (no
     top-level route proxy), ready for post-DR cloning into `route_ns`.
4. `bind_carried_http_routes_to_node_waypoint_transport` (renamed or shared
   across all three L7 topologies) rebinds carried route destinations and
   weighted splits onto the materialized upstreams, builds leg-by-leg
   `weighted_splits` for DR-governed legs, and rejects unmodeled/unauthorized
   routes back to the bound Service's default L7 route.
5. `thread_node_waypoint_route_branches_to_authz`,
   `scope_request_auth_to_node_waypoint_destinations`,
   `apply_destination_rules`, `project_mesh_source_locality`, and post-DR
   cross-namespace upstream cloning execute in the same deterministic order as
   today.
6. Build `ServiceWaypointL7TargetIndex` and the per-bound-Service route table
   partition once per `RequestEpoch` (zero per-request locks or allocations on
   the hot path).

## 4. Failure Modes (Fail Closed)

Every failure boundary below is fail-closed: it either rejects the slice
candidate while retaining last-good, refuses the individual route back to the
bound Service's default L7 route, or rejects/resets the request/tunnel without
falling back to unauthenticated, plaintext, or L4-bypass behavior.

| Failure scenario | Detection boundary | Behavior | Client / operator signal |
|---|---|---|---|
| Missing `Gateway` binding, `waypoint_for: none\|workload`, or mismatched `waypoint_name` | CP projection + DP `service_waypoint_backing_workloads` | `http_routes` empty; L7 target index empty; outer `CONNECT` refused | `403 hbone_relay_destination_denied`; `GET /service-waypoint/services` shows 0 bound services |
| Malformed `http_routes`, non-translator plugin record/body, duplicate ID, wire `weighted_splits` | DP `decode_http_route_set` | Reject whole slice candidate; retain last-good generation | `MeshSliceRejectReason::RuntimeConfigBuild`; structured `warn!` |
| Peerless, untrusted, expired, or CRL-revoked outer `CONNECT` | Outer `:15008` `handle_hbone_request` / `HbonePeerCredential` | Reject before upgrade or L7 server spawn | `403` fixed unauthenticated-peer body; `mesh_authz.deny_policy` records exact reason |
| Live credential expiry, trust/CRL withdrawal, or bound-Service removal | `HboneAdmissionFence` sweep | Retire fence entry; abort inner HTTP server; `RST_STREAM(CONNECT_ERROR)` on outer stream | `ferrum_mesh_hbone_tunnel_revocations_total{reason}`; `ferrum_mesh_service_waypoint_l7_tunnel_terminations_total{reason="fence_revoked"}` |
| Direct HTTP request on `:15008` (outside `CONNECT`) or peer hitting `Sidecar` `:15006` / `NodeWaypoint` `:15008` | `mesh_route_admitted_for_direction` | Carried `istio-vs-*` routes never matched | `404` (or local inbound route fallthrough on Sidecar) |
| Inner HTTP `Host`/`:authority` does not match the outer `CONNECT`'s bound Service | Inner ServiceWaypoint dispatcher (before route match) | Refuse immediately; never consult another Service's routes | `403` (`mesh_authz.deny_policy=service_waypoint_host_mismatch`); sampled `warn!`; refusal counter |
| Non-HTTP / malformed bytes (e.g. raw TCP or TLS ClientHello) inside an HTTP-port `CONNECT` | Inner `hyper` server | Close inner connection and reset outer `CONNECT` with `RST_STREAM(CONNECT_ERROR)`; **never** fall back to L4 relay | `ferrum_mesh_service_waypoint_l7_tunnel_terminations_total{reason="inner_protocol_error"}` |
| Ambiguous backing-pod IP:port owned by two bound Services on the same port | Outer `ServiceWaypointL7TargetIndex` lookup | Refuse outer `CONNECT` before upgrade | `403` (`address_not_terminated_here` / `ambiguous_service_waypoint_target`) |
| Missing destination `AuthorizationPolicy` scope or `RequestAuthentication` disagreement across split legs | `mesh_authz` / `scope_request_auth_to_node_waypoint_destinations` | `403 destination_scope_missing` or route-level refusal | `/mesh/policy-denies/recent` entry; refusal metric |
| Cross-namespace destination without `ReferenceGrant`, `ExternalName` Service, or `EndpointSliceGuard` finding | K8s translator (`istio.rs`) + DP bind guard | Translator rejects VirtualService (`FerrumAccepted=False`/`RefNotPermitted`); DP refuses unverified cross-ns route (`cross_namespace_refused`) | VirtualService `status.conditions[]`; cold-path `warn!` count |
| Unmodeled in-cluster Service, 0 reachable workloads, >32 legs / >64 candidates / >64 splits, direct external TLS-originating or wildcard DR | DP `bind_carried_http_routes_to_node_waypoint_transport` | Refuse individual route; bound Service keeps default L7 route; never dial Service DNS in plaintext | Cold-path `warn!` counts; `ferrum_mesh_service_waypoint_route_refusals_total` |
| Missing HBONE/mTLS transport metadata on an in-mesh target in production mode | DP materializer / pool dispatch | Skip target or fail dial closed; never downgrade to plaintext | `502` (`hbone_required` / `Sidecar mTLS backend unavailable`) |
| Multi-waypoint forwarding loop | `X-Ferrum-Hop-Limit` header check | Reject inner request before backend dial | `508 Loop Detected` |

## 5. Observability

All new metrics use closed-cardinality `&'static str` labels (never SPIFFE IDs,
hostnames, pod IPs, or URIs), and must be added to both
`docs/prometheus_metric_contract.json` and `docs/prometheus_metrics.md` in the
PR that introduces them.

### 5.1 Prometheus Metrics

- **Existing metrics reused:**
  - Standard mesh L7 RED metrics (`ferrum_mesh_requests_total`,
    `ferrum_mesh_request_duration_seconds`, request/response byte counters) via
    `workload_metrics` + `prometheus_metrics` on every inner HTTP request,
    preserving trusted outer source principal attribution.
  - `ferrum_mesh_hbone_tunnel_revocations_total{proxy_id,reason,namespace}` for
    outer L7-terminated tunnels revoked by `HboneAdmissionFence`.
  - `ferrum_mesh_hbone_relay_failures_total` remains scoped to L4 transparent
    relays so L4 byte-copy errors and L7 HTTP errors remain cleanly separated.
- **New bounded families for `ServiceWaypoint` L7 termination:**
  - `ferrum_mesh_service_waypoint_l7_tunnels_active{namespace}` (gauge):
    concurrent L7-terminated HBONE `CONNECT` tunnels.
  - `ferrum_mesh_service_waypoint_l7_tunnel_terminations_total{reason,namespace}`
    (counter): `reason` ∈ `{clean_close, idle_timeout, fence_revoked, inner_protocol_error, overload}`.
  - `ferrum_mesh_service_waypoint_route_refusals_total{reason,namespace}`
    (counter): `reason` ∈ `{host_mismatch, cross_namespace_refused, unmodeled_service, authority_rewrite_refused, unrepresentable_split, binding_absent}`.

### 5.2 Admin API, Diagnostics, and Kubernetes Status

- **`GET /service-waypoint/services`** (JWT-authenticated): extend each bound
  Service entry with `l7_http_ports: [u16]` and `virtual_service_route_count: usize`
  so operators can verify that a `VirtualService` attached to its bound Service
  without exposing raw route rules or predicates. Keep the 404 contract outside
  `ServiceWaypoint` or before the first slice.
- **`GET /mesh/config-drift`** and **`GET /mesh/policy-denies/recent`**
  (JWT-authenticated): report slice convergence and inner L7 denials
  (`service_waypoint_host_mismatch`, `route_branch_unauthorized`,
  `destination_scope_missing`) alongside existing entries.
- **Diagnostic references:** Inner L7 gateway-authored error responses
  (403/404/502/503/508) emit `X-Ferrum-Diagnostic-Ref` normally without leaking
  internal topology.
- **Kubernetes `VirtualService` status (`src/k8s_controller/istio_status.rs`):**
  - Keep `status.ferrum.translation.mesh_http_routes: sidecar_and_node_waypoint`
    until `ServiceWaypoint` L7 termination actually ships.
  - Once `ServiceWaypoint` L7 routing lands, advance the value to
    `sidecar_node_and_service_waypoint` and update
    `VIRTUAL_SERVICE_MESH_HTTP_ROUTES_NOTE` so it names only `Ambient` (the L4
    data plane) as not applying `http[]` routes.
  - Update `docs/mesh.md`, `docs/mesh_supported_matrix.md`, `FEATURES.md`,
    `README.md`, and `tests/unit/config/docs_backlog_parity_tests.rs` in the
    same change.

### 5.3 Structured Logging

- Peer-drivable inner failures (host mismatch, malformed inner HTTP framing)
  emit `warn_sampled!` with closed-cardinality reason labels and transport
  ports only — never request headers, bodies, cookies, or bearer tokens.
- Cold-path slice preparation logs bounded refusal counts (`cross_namespace_refused`,
  `unrepresentable_splits`, `tls_origination_refused`,
  `wildcard_direct_backend_refused`) at `warn!`.

## 6. Live E2E Infrastructure Needed

### 6.1 Why `mesh-e2e-sidecar` Cannot Assert a Live 90/10 Split Today

Inspecting `tests/k8s/mesh_e2e_sidecar/manifests.yaml` and
`tests/k8s/mesh_e2e_sidecar/README.md` shows three concrete blockers:

1. **File-source client Sidecars.** `client` and `rogue` run
   `FERRUM_MESH_CONFIG_PROTOCOL=file` backed by ConfigMaps. `file_source`
   accepts `{version?, mesh}` only (`deny_unknown_fields`) and cannot carry
   gateway `proxies`/`upstreams` produced by `VirtualService` `http[]`
   translation.
2. **No Istio CRDs or CRD watching on `ferrum-cp`.** `manifests.yaml` sets
   `FERRUM_K8S_WATCH_ISTIO_CRDS=false` and `FERRUM_K8S_WATCH_GATEWAY_API_CRDS=false`
   on `ferrum-cp`, its namespaced `Role` grants `get/list/watch` only on core
   `pods`, `services`, and `discovery.k8s.io/endpointslices`, and the kind
   cluster installs no Istio or Gateway API CRDs.
3. **No `ServiceWaypoint` live kind suite.** There is currently no
   `tests/k8s/mesh_e2e_service_waypoint/` harness or workflow.

### 6.2 Checked-In CRD Fixtures (Offline, Deterministic)

Following the pattern already established by
`tests/fixtures/k8s/istio_authorizationpolicy_status_crd.yaml` (used by
`.github/workflows/istio-status-cas-live.yml`), check in minimal, pinned
structural CRDs under `tests/fixtures/k8s/` with `subresources.status` enabled
so CI never fetches manifests from the network:

- `tests/fixtures/k8s/istio_virtualservice_crd.yaml` (`networking.istio.io/v1beta1`, `VirtualService`)
- `tests/fixtures/k8s/istio_destinationrule_crd.yaml` (`networking.istio.io/v1beta1`, `DestinationRule`)
- `tests/fixtures/k8s/gateway_api_referencegrant_crd.yaml` (`gateway.networking.k8s.io/v1beta1`, `ReferenceGrant`)
- `tests/fixtures/k8s/gateway_api_gateway_crd.yaml` (`gateway.networking.k8s.io/v1`, `Gateway`, for `ServiceWaypoint` bindings)

### 6.3 `mesh-e2e-sidecar` Additions (Live Sidecar 90/10 Split Gate)

Keep the existing file-source `client` / `rogue` / `svc` / `wssvc` / `drsvc-*`
deployments untouched so the existing 19 GA assertions keep their exact
isolation, and extend the fixture with:

1. **CRD installation in `run.sh`:** `kubectl apply -f` the pinned
   `VirtualService`, `DestinationRule`, and `ReferenceGrant` CRDs and wait for
   `condition=Established` before deploying `ferrum-cp`.
2. **`ferrum-cp` CRD watching and RBAC (`manifests.yaml`):**
   - Flip `FERRUM_K8S_WATCH_ISTIO_CRDS=true` (and
     `FERRUM_K8S_WATCH_GATEWAY_API_CRDS=true` when exercising
     `ReferenceGrant`).
   - Expand `ferrum-cp`'s namespaced `Role` with `get/list/watch` on
     `networking.istio.io` (`virtualservices`, `destinationrules`,
     `serviceentries`, `workloadentries`, `sidecars`, `proxyconfigs`),
     `security.istio.io` (`authorizationpolicies`, `peerauthentications`,
     `requestauthentications`), `telemetry.istio.io` (`telemetries`),
     `gateway.networking.k8s.io` (`referencegrants`), and `get/patch/update` on
     `*/status` so `IstioStatusWriter` writes real `FerrumAccepted` status.
   - Keep `ferrum-cp`'s production mTLS + JWT gRPC transport unchanged.
3. **Dedicated native-protocol client Sidecar (`vs-client`):**
   - Mirrors `capp`'s proven native subscription configuration:
     `FERRUM_MESH_TOPOLOGY=sidecar`, `FERRUM_MESH_CONFIG_PROTOCOL=native`,
     `FERRUM_DP_CP_GRPC_URLS=https://ferrum-cp.<ns>.svc.cluster.local:50051`,
     projected mTLS client Secret + HS256 JWT Secret, SPIRE Workload API SVID,
     and outbound iptables REDIRECT capture (`:15001`).
   - Register its SPIRE workload entry (`sa/vs-client`).
4. **Split backends and live assertions:**
   - Two STRICT-mTLS native-subscribed Sidecar backend Services (`vssvc-v1`,
     `vssvc-v2`) with distinct echo markers (`v1`, `v2`), plus a frontend
     Service `vssvc` targeted by a `kubectl apply`'d `VirtualService` with a
     90/10 split (`vssvc-v1`: 90, `vssvc-v2`: 10) and a header-match override
     (`x-canary: true` → `vssvc-v2`).
   - Assert via `kubectl get virtualservice -o json` that `FerrumAccepted=True`
     is written by `ferrum-cp`.
   - **`sidecar.virtual_service.weighted_split_90_10`:** Issue 200 sequential
     captured HTTP requests from `vs-client` to `http://vssvc:8080/`, verify
     HTTP 200 on all 200, both markers observed, and `v1` share within
     `[85%, 95%]` (170–190 of 200; tight around Ferrum's deterministic weighted
     cycle while tolerating single-request rollout settle).
   - **`sidecar.virtual_service.header_match_dispatch`:** Issue requests with
     `x-canary: true` and assert 100% reach `vssvc-v2`.
   - Enroll both assertions in `tests/conformance/ga_contract.yaml` before
     removing the Sidecar GA headline qualification in
     `docs/mesh_supported_matrix.md`.

### 6.4 Dedicated `ServiceWaypoint` Live E2E Suite (`mesh-e2e-service-waypoint`)

Create a separate kind harness (`tests/k8s/mesh_e2e_service_waypoint/`) and
initially optional workflow (`.github/workflows/mesh-e2e-service-waypoint-live.yml`,
using the shared `tests/k8s/lib/live_assertions.sh` schema and trusted-base
relevance filter) deploying:

- SPIRE server + agent issuing workload SVIDs for the client, the
  `ServiceWaypoint` pod, and backend pods;
- `ferrum-cp` with Istio + Gateway API CRD watching enabled over mTLS + JWT;
- A `Gateway` (`gatewayClassName: istio-waypoint`) and a `ServiceWaypoint`
  Deployment (`FERRUM_MESH_TOPOLOGY=service_waypoint`,
  `FERRUM_MESH_WAYPOINT_NAME=<gw>`, `FERRUM_MESH_CONFIG_PROTOCOL=native`);
- Bound Services (`istio.io/use-waypoint: <gw>`) in the waypoint namespace plus
  a second namespace (`beta`) for cross-namespace `ReferenceGrant` tests;
- An HBONE client workload sending authenticated HTTP/2 `CONNECT` tunnels over
  SPIRE mTLS to the `ServiceWaypoint` `:15008` listener.

Required live assertions:

1. `service_waypoint.virtual_service.weighted_split_90_10` — 200 inner HTTP
   requests over HBONE confirm 90/10 split across `v1`/`v2` backends.
2. `service_waypoint.virtual_service.header_match_and_per_branch_authz` —
   header-matched branch routes to `v2` and enforces `v2`'s own
   `AuthorizationPolicy` independently of `v1`'s.
3. `service_waypoint.virtual_service.host_spoof_rejected` — outer `CONNECT` to
   bound Service `A` with inner `Host: B` returns `403`.
4. `service_waypoint.virtual_service.cross_namespace_reference_grant` —
   cross-namespace destination in `beta` is rejected without `ReferenceGrant`,
   admitted after applying `ReferenceGrant`, and withdrawn after deleting it.
5. `service_waypoint.hbone.fence_revocation_on_binding_withdrawal` — removing
   `istio.io/use-waypoint` revokes an open L7 HBONE tunnel with
   `RST_STREAM(CONNECT_ERROR)` and increments
   `ferrum_mesh_hbone_tunnel_revocations_total`.
6. `service_waypoint.status.mesh_http_routes_reported` — `VirtualService`
   status reports `FerrumAccepted=True` with updated `mesh_http_routes` scope.

## 7. Proposed Follow-Up Issues

The remaining work under [#7423](https://github.com/ferrum-edge/ferrum-edge/issues/7423)
splits into five independently shippable issues. Each delivers verifiable value
and tests on its own without blocking earlier slices.

### Follow-Up 1: Cross-Namespace `VirtualService` `http[]` Destinations with `ReferenceGrant` and `EndpointSlice` Parity

- **Scope:**
  - Add `ReferenceGrant` (`networking.istio.io/VirtualService` → core `Service`),
    target existence, `ExternalName` refusal, and `EndpointSliceGuard` checks
    in `src/config_sources/k8s/istio.rs` for cross-namespace `VirtualService`
    `http[]` destinations.
  - Carry `authorized_cross_namespace_targets` on `MeshVirtualServiceHttpRoutes`
    and `MeshHttpRouteSet` (native JSON + `HttpRoutesCarrier`).
  - Enforce `CpScope` / JWT `ns` ceilings during CP projection.
  - Materialize post-DR, post-locality route-namespace transport clones
    (`__mesh-out-vs-xns-upstream-*`) in `src/modes/mesh/mod.rs` while keeping
    `GatewayConfig::validate_upstream_references` strictly namespace-local,
    preserving shared `admission_upstream_id` budgets, Sidecar `:authority`
    stamping, and target-namespace `mesh_authz`/`RequestAuthentication`
    resolution.
- **Dependencies:** None (lands cleanly on `Sidecar` and `NodeWaypoint` first;
  reused directly by `ServiceWaypoint` in Follow-Ups 2–3).
- **Acceptance Criteria:**
  - K8s translation tests prove: missing/mismatched `ReferenceGrant` fails
    closed (`FerrumAccepted=False`, `RefNotPermitted`); `ExternalName` and
    `ForeignEndpoint`/`UnattributedEndpoint`/`Unverifiable` EndpointSlices fail
    closed; `FERRUM_K8S_ALLOW_SELECTORLESS_EXTERNAL_ENDPOINTS` never widens
    cross-namespace routes.
  - Integration tests on `Sidecar` and `NodeWaypoint` prove authorized
    cross-namespace direct destinations, `mesh_route_dispatch` branches, and
    DR-governed 90/10 weighted splits route cleanly with destination-namespace
    DR policy, Sidecar `:authority`, and NodeWaypoint destination-namespace
    `AuthorizationPolicy`/`RequestAuthentication`.
  - Unverified cross-namespace targets on the DP wire are refused
    (`cross_namespace_refused`) without rejecting the rest of the slice.
  - `validate_upstream_references` remains strictly namespace-local.

### Follow-Up 2: `ServiceWaypoint` `http_routes` Control-Plane Projection, Wire Contract, and DP Materialization

- **Scope:**
  - Add `MeshSubscribeRequest.service_waypoint_http_routes = 11` in
    `proto/ferrum.proto`, `MeshSliceRequest.service_waypoint_http_routes`, and
    `XdsNodeMetadata.service_waypoint_http_routes` (`src/xds/carrier.rs`,
    `src/xds/server.rs`).
  - Project `http_routes` for `ServiceWaypoint` in `src/modes/mesh/slice.rs`,
    strictly gated on non-empty `service_waypoint_bound_services` (`waypoint_for`
    in `service`/`all`), honoring `istio.io/use-waypoint-namespace` and the
    anti-hijack namespace rule, and retaining authorized cross-namespace leg
    dependencies without widening `service_waypoint_bound_services` or
    `inbound_relay_destinations`.
  - Add DP bound-Service L7 upstream/route materialization,
    `ServiceWaypointL7TargetIndex`, and per-bound-Service route partition
    building (keeping `:15008` L4 relay behavior untouched until Follow-Up 3).
  - Extend `GET /service-waypoint/services` (and `openapi.yaml`) with
    `l7_http_ports` and `virtual_service_route_count`.
- **Dependencies:** Follow-Up 1 (optional for same-namespace routes, required
  for cross-namespace leg projection).
- **Acceptance Criteria:**
  - Native `MeshSubscribe` and xDS ADS round-trip tests prove identical
    `ServiceWaypoint` slices (`content_eq` and xDS `config_fingerprint` cover
    `http_routes` and `service_waypoint_http_routes`).
  - Missing `Gateway` binding, `waypoint_for: none`, and `waypoint_for: workload`
    all project empty `http_routes` (no fail-open).
  - A `VirtualService` in an unrelated third namespace with `exportTo: ["*"]`
    is excluded from another tenant's `ServiceWaypoint` slice.
  - `inbound_relay_destinations` never widens to cross-namespace split legs.
  - `mesh_route_admitted_for_direction` continues to reject carried `istio-vs-*`
    routes on every direct outer inbound listener.

### Follow-Up 3: L7 HTTP/1.1 & HTTP/2 Termination and Bound-Service Dispatch on `ServiceWaypoint` HBONE `:15008`

- **Scope:**
  - Implement outer `CONNECT` classification (HTTP-family bound Service port vs.
    L4 stream/UDP passthrough) and `HboneRelayDestinationGate::ServiceWaypointL7`
    registration in `HboneAdmissionFence`.
  - Serve upgraded L7 `CONNECT` streams through
    `hyper_util::server::conn::auto::Builder`, wired to fence revocation
    (`RST_STREAM(CONNECT_ERROR)`), idle timeout, overload/stream caps, and
    `RequestGuard` drain.
  - Propagate verified outer SPIFFE identity, honored outer baggage
    `source.principal`, and `ServiceWaypointL7Context` into each inner
    `RequestContext`; enforce bound-Service host pinning (`403
    service_waypoint_host_mismatch`) while keeping `mesh_route_admitted_for_direction`
    strict for all outer inbound listeners.
  - Generalize `thread_node_waypoint_route_branches_to_authz` and
    `scope_request_auth_to_node_waypoint_destinations` to `ServiceWaypoint`, and
    wire outbound HBONE / SVID-mTLS / DR-originated external TLS dispatch with
    hop-limit loop prevention and no plaintext downgrade.
  - Add bounded `ServiceWaypoint` L7 Prometheus metrics to code,
    `docs/prometheus_metric_contract.json`, and `docs/prometheus_metrics.md`.
  - Update `status.ferrum.translation.mesh_http_routes` to
    `sidecar_node_and_service_waypoint`, `VIRTUAL_SERVICE_MESH_HTTP_ROUTES_NOTE`,
    `docs/mesh.md`, `docs/mesh_supported_matrix.md`, `FEATURES.md`, `README.md`,
    and `tests/unit/config/docs_backlog_parity_tests.rs`.
- **Dependencies:** Follow-Up 2 (and Follow-Up 1 for cross-namespace legs).
- **Acceptance Criteria:**
  - Functional and integration tests over real HBONE `CONNECT` tunnels prove:
    - 90/10 weighted split checked over 1000 selections (including DR-governed
      leg-by-leg dispatch and external residual TLS origination);
    - URI/header/method/`sourceNamespace` match dispatch, rewrites, retries,
      timeouts, faults, CORS, and loopback mirrors;
    - per-branch `ALLOW`/`DENY`/`CUSTOM` `AuthorizationPolicy` (including
      `Gateway`/`GatewayClass`/`Service` `targetRefs`) and destination-scoped
      `RequestAuthentication`;
    - inner host spoofing returns `403` and never reaches another bound Service;
    - non-HTTP bytes inside an HTTP-port `CONNECT` reset with `CONNECT_ERROR`
      and never fall back to L4 relay;
    - live `HboneAdmissionFence` revocation on peer trust/CRL/expiry or
      binding withdrawal cuts the outer tunnel with `CONNECT_ERROR`;
    - `Sidecar` `:15006`, `NodeWaypoint` `:15008`, and direct non-CONNECT
      requests on `ServiceWaypoint` `:15008` still refuse carried `istio-vs-*`
      routes;
    - stream-family ports and `connect-udp` on bound Services stay on L4 relay.
  - Prometheus metric contract and docs parity tests pass in CI.

### Follow-Up 4: Live 90/10 `VirtualService` Split Gate in `mesh-e2e-sidecar`

- **Scope:**
  - Check in pinned offline CRD fixtures under `tests/fixtures/k8s/`
    (`VirtualService`, `DestinationRule`, `ReferenceGrant`).
  - Update `tests/k8s/mesh_e2e_sidecar/manifests.yaml` and `run.sh` to install
    those CRDs in kind, enable `FERRUM_K8S_WATCH_ISTIO_CRDS=true` + RBAC on
    `ferrum-cp`, deploy the dedicated native-protocol `vs-client` Sidecar and
    `vssvc-v1`/`vssvc-v2` backends, and assert live 90/10 split distribution,
    header-match override, and `FerrumAccepted=True` status.
  - Enroll the new live assertions in `tests/conformance/ga_contract.yaml`
    (with owner review before restoring Sidecar GA headline wording in
    `docs/mesh_supported_matrix.md`).
- **Dependencies:** None (exercises the Sidecar projection already landed in
  PR #7431; cross-namespace live assertion can be added here or after Follow-Up 1).
- **Acceptance Criteria:**
  - `Mesh E2E Sidecar Live` workflow passes in kind with real SPIRE SVIDs and
    production mTLS + JWT `ferrum-cp`.
  - `sidecar.virtual_service.weighted_split_90_10` and
    `sidecar.virtual_service.header_match_dispatch` pass in
    `live-assertions.json`, validated by `tests/conformance/live_contract.rs`.
  - All 19 existing file-source and native-subscribe GA assertions remain green
    and isolated.

### Follow-Up 5: Live `ServiceWaypoint` E2E Suite in Kind (`mesh-e2e-service-waypoint`)

- **Scope:**
  - Add pinned `Gateway` CRD fixture (`tests/fixtures/k8s/gateway_api_gateway_crd.yaml`).
  - Build `tests/k8s/mesh_e2e_service_waypoint/` (`manifests.yaml`, `run.sh`,
    `README.md`) and `.github/workflows/mesh-e2e-service-waypoint-live.yml`
    using the shared `live_assertions.sh` schema and trusted-base path filter.
  - Exercise all six `service_waypoint.*` live assertions from
    [Section 6.4](#64-dedicated-servicewaypoint-live-e2e-suite-mesh-e2e-service-waypoint)
    plus `/metrics` counter-movement checks on the new L7 tunnel/refusal
    families.
- **Dependencies:** Follow-Ups 1, 2, and 3.
- **Acceptance Criteria:**
  - Live kind workflow passes end-to-end with SPIRE-issued SVIDs and native
    mTLS + JWT `ferrum-cp`.
  - All six `service_waypoint.*` assertions pass in `live-assertions.json` and
    new Prometheus counters move as expected.
  - `docs/mesh_supported_matrix.md` records the live-gated `ServiceWaypoint` L7
    `VirtualService` coverage.
