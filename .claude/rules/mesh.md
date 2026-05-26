---
paths:
  - "src/modes/mesh/**"
  - "src/modes/injector.rs"
  - "src/modes/node_agent.rs"
  - "src/modes/node_agent_cni_server.rs"
  - "src/bin/ferrum-cni.rs"
  - "src/cni/**"
  - "src/capture/**"
  - "src/ebpf/**"
  - "src/grpc/mesh_*"
  - "src/k8s_controller/**"
  - "src/plugins/mesh/**"
  - "src/plugins/mesh_route_dispatch.rs"
  - "src/xds/**"
  - "src/service_discovery/mesh.rs"
  - "charts/ferrum-mesh/**"
  - "docs/mesh.md"
  - "docs/node_agent.md"
  - "docs/node_agent_security.md"
  - "docs/spire_deployment.md"
  - "docs/kubernetes_deployment.md"
  - "tests/conformance/**"
  - "tests/integration/*mesh*"
  - "tests/integration/*hbone*"
  - "tests/integration/*ambient*"
  - "tests/integration/*waypoint*"
  - "tests/integration/*ztunnel*"
  - "tests/integration/*cni*"
  - "tests/integration/*k8s*"
  - "tests/functional/*{mesh,node_agent,ambient,waypoint,ztunnel,cni,injector}*"
  - "tests/performance/mesh*/**"
---

# Mesh Rules

Full operator docs live in `docs/mesh.md`. Keep this file to implementation invariants.

## Topologies And Runtime

- `MeshTopology` drives listeners: `Sidecar` uses inbound 15006 mTLS and outbound 15001 capture; `Ambient` uses HBONE 15008 and outbound 15001; `EastWestGateway` uses SNI passthrough on 15443; `EgressGateway` uses mTLS inbound 15090 to external ServiceEntry backends.
- All topologies share the normal proxy and plugin chain.
- Mesh runtime state is `ArcSwap<Option<MeshSlice>>` in `runtime.rs`; slice apply is lock-free hot-swap like `GatewayConfig`.
- `wait_for_first_slice()` blocks startup until the first valid slice arrives.
- Native config consumption uses `MeshConfigSync.MeshSubscribe` gRPC. xDS uses ADS for CDS/EDS/LDS/RDS/SDS with 25 ms debounce.
- Native and xDS clients use jittered exponential backoff from 1s to 30s, plus/minus 25%, multi-CP failover via `FERRUM_DP_CP_GRPC_URLS`, and JWT metadata.

## Scope And Policy Semantics

- Scope-aware resources must use the shared `policy_scope_applies_to_workload` / `scope_applies_to_workload` helpers. Do not fork predicates.
- Single-winner precedence (`WorkloadSelector` > `Namespace` > `MeshWide`) applies only where one effective setting is resolved, such as `PeerAuthentication` and `MeshProxyConfig`.
- `MeshPolicy` and `MeshRequestAuthentication` are additive after filtering. `MeshTelemetryResource` merges by section.
- Authorization evaluation is DENY first, then ALLOW. Any ALLOW rule with no match causes implicit deny.
- `RequestMatch` negative fields (`not_methods`, `not_paths`, `not_hosts`, `not_ports`) are conjunctive with positive fields in one rule. Do not split them into separate deny policies.
- Istio empty-rule translation must preserve action semantics: ALLOW with no `rules` is allow-nothing via a never-matching rule; DENY and AUDIT with no `rules` are no-ops.

## Mesh Plugin Injection

- `inject_mesh_global_plugins()` auto-injects reserved-ID globals on slice apply: `__mesh_spiffe_identity` priority 940, `__mesh_authz` priority 2075, `__mesh_workload_metrics`, `__mesh_request_auth` only when JWT rules exist, and `__mesh_access_log` (a `stdout_logging` instance carrying the Telemetry `accessLogging` filter).
- Operator-managed globals of the same type override mesh-injected plugins.
- Mesh plugin injection must preserve normal plugin lifecycle ordering and transaction logging.

## HBONE Identity Boundary

- HBONE is HTTP/2 CONNECT over mTLS on port 15008.
- Baggage `source.principal` rewrites the authz principal only when the authenticated peer is in `mesh_authz.trusted_hbone_assertors` and the baggage trust domain matches the peer cert or `FERRUM_MESH_TRUST_DOMAIN_ALIASES`.
- Untrusted assertors keep their own peer-cert identity even when baggage is present.
- Dropped baggage must surface in transaction metadata as `mesh_authz.ignored_baggage.untrusted_assertor=true`; denied requests contribute `mesh_authz.deny_policy=untrusted_assertor`.
- Trust-domain mismatches use the existing `trust_domain_mismatch` reason.
- Default trusted assertor service accounts are `ztunnel` and `waypoint`. `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS` accepts bare service-account names or full SPIFFE IDs.
- Explicit empty `trusted_hbone_assertors: []` disables baggage rewriting entirely.
- Keep fallback baggage key aliases in `HboneIdentity::from_headers()` in sync with tests.

## PeerAuthentication And TLS Reload

- By default, inbound mesh mTLS mode resolves once from the initial slice.
- With `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true`, only resolved mTLS mode and frontend client CA verifier may hot-swap on slice apply.
- Frontend cert/key paths remain restart-required inputs for mesh peer auth reload.
- Coverage includes mesh HTTP/HBONE termination listeners and mesh-shared TCP+TLS / UDP+DTLS stream listeners.
- `apply_mesh_inbound_tls_reload` publishes swapped `ServerConfig` into HBONE, shared stream TLS, and active `DtlsServer` frontend DTLS configs.
- Failed rebuilds keep the previous config for that path and log a warning; do not reject the whole slice.
- `Disable` is rejected for Ambient and EgressGateway slice updates and keeps the last good config.

## DestinationRule And Materialization

- DestinationRule `connectionPool.tcp.connectTimeout` lands on `Upstream.port_overrides[port].connect_timeout_ms` and is enforced by HTTP/H2/H3, gRPC, TCP, and HBONE dispatch.
- Port-level `loadBalancer` and `outlierDetection` land on the same override slot and use isolated per-port LB counters/hash rings and passive thresholds for HTTP-family, gRPC, WebSocket, and HBONE.
- `connectionPool.http.maxRequestsPerConnection`, `idleTimeout`, and `http2MaxRequests` land on `http_max_requests_per_connection`, `http_idle_timeout_ms`, and `h2_max_concurrent_streams`.
- Dispatch projects port overrides through `resolve_effective_proxy_for_target()` onto the owned `Proxy` clone; direct H2 and gRPC builders consume H2 caps through `max_concurrent_streams` and `initial_max_send_streams`.
- `http_max_requests_per_connection` is wire-projected but currently inert at runtime because hyper lacks a close-after-N knob.
- `connectionPool.tcp.maxConnections` and `tcpKeepalive` land on `max_connections` and `tcp_keepalive`; TCP-family dispatch enforces them today.
- `maxConnections` exhaustion returns `StreamSetupKind::BackendMaxConnectionsExceeded`; keepalive setsockopt failures warn and continue.
- TCP/UDP/DTLS stream proxies enforce only connect timeout, max connections, and tcp keepalive per port; they use upstream-level LB/passive policy.
- Phantom DestinationRule ports are skipped with a warning.
- Admin API POST/PUT of `Upstream.port_overrides` is rejected; DestinationRule is canonical.
- `materialize_east_west_gateway_proxies()` creates SNI-passthrough TCP proxies only for east-west topology.
- `materialize_egress_gateway_proxies()` creates HTTP-family proxies from `mesh_external` ServiceEntries only for egress topology.

## Injector, Node Agent, And CNI

- Injector mode serves `POST /mutate` Kubernetes AdmissionReview and emits JSON patches only.
- Sidecars run as `PROXY_UID`; optional iptables init container requires `NET_ADMIN`.
- IPv4/IPv6 capture CIDRs must stay partitioned into `iptables` and `ip6tables` blocks. `FERRUM_MESH_IP6TABLES_ENABLED=auto|true|false` controls IPv6 fan-out.
- Cleanup scripts are best-effort even when `ip6tables` is missing.
- Injected SPIFFE ID format is `spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}`.
- JWT secrets in injected manifests use `SecretKeyRef`, never plaintext.
- Opt in with `ferrum.io/inject=true` or `ferrum.io/mesh=enabled`; opt out with `sidecar.istio.io/inject=false` or `ferrum.io/inject=false`.
- Node-agent CNI is opt-in with `FERRUM_NODE_AGENT_CNI_ENABLED=false` by default.
- When enabled, node-agent binds `FERRUM_NODE_AGENT_CNI_SOCKET_PATH` and the `ferrum-cni` binary forwards kubelet ADD/DEL/CHECK over that socket.
- kube-rs watcher remains source of truth; CNI only closes the kubelet-vs-watcher race and does not carry labels or annotations.

## Kubernetes Controller

- `FERRUM_K8S_CONTROLLER_ENABLED` and `FERRUM_K8S_POD_DISCOVERY_ENABLED` default true inside pods detected by `KUBERNETES_SERVICE_HOST`; outside pods they default false.
- Explicit operator `false` wins over pod detection.
- If `FERRUM_K8S_WATCH_NAMESPACES` is unset, watch scope falls back to CP scope: `Single`/`Set` use namespaced watches, `All` uses cluster-wide.
- Istio status writer patches `status.conditions[]` (a `FerrumAccepted` condition plus a `status.ferrum.translation` detail block) for all nine translated Istio kinds when `watch_istio == true`: AuthorizationPolicy, PeerAuthentication, RequestAuthentication, DestinationRule, VirtualService, ServiceEntry, WorkloadEntry, Sidecar, and Telemetry. Successful translation writes `FerrumAccepted=True`; a `K8sTranslateError` writes `FerrumAccepted=False`/`Invalid` with the translator's reason so rejections are visible to `kubectl`.
- Keep `istio_api_resource`/`is_supported_istio_kind` in `src/k8s_controller/istio_status.rs` in lock-step with `ISTIO_CRDS` in `src/k8s_controller/watcher.rs` (group + plural).
- Parsed-but-unenforced fields are surfaced as `status.ferrum.translation.deferred_fields` rather than only logged: DestinationRule `portLevelSettings[].tls`, per-subset `connectionPool.tcp.connectTimeout`/`outlierDetection`, and `connectionPool.http.{http1MaxPendingRequests,maxRetries,h2UpgradePolicy}`; VirtualService `tcp[]`/`tls[]` routes and `http[].{mirror,mirrorPercentage,corsPolicy,redirect,rewrite}`; Sidecar `ingress[]`. The DR `connectionPool.http` deferred set is mirrored by a translator warning in `src/config_sources/k8s/istio.rs`; keep the two lists in sync.
- Status writer failures, such as missing `subresources.status`, warn and no-op; they never abort reconcile.
- `ProxyConfig` is translated but not watched (`ISTIO_CRDS`) and not surfaced by the status writer.
