# Port handoff audit for issue #5579

Static audit against `5ce0a7594`, covering every `drop_and_take_port` call under
`tests/` and the `unbound_port`, `unbound_tcp_port`, and `unbound_udp_port`
entry points. Counts below refer to call sites, not runtime allocations.

The shared reservation constructors now exclude the host's ephemeral
source-port range (see [Functional Testing Guide](functional_testing.md#subprocess-harness-process-identity)).
This deliberately makes **every** TCP, UDP, pair, and colocated reservation safe
to release without requiring each caller to select a special allocator.
Native fixtures should still keep their sockets; `TestSocket::bind_test(:0)`
and held refused-connect reservations retain their existing allocation policy.

## Subprocess binds

All files in this table are under `tests/functional/`. These sockets must be
released because the child binds its own listeners. They inherit the shared
range policy; the future refused stream reservation uses `reserve_future_tcp_port`.

| File | `drop_and_take_port` sites / consumer |
| --- | --- |
| `functional_admin_connection_limit_test.rs` | 1 admin HTTPS |
| `functional_ai_semantic_firewall_streaming_test.rs` | 1 H3 frontend |
| `functional_capability_registry_test.rs` | 1 HTTPS/H3 frontend |
| `functional_cli_test.rs` | 6 stream, proxy/admin pairs, CP gRPC |
| `functional_cors_protocol_test.rs` | 1 HTTPS/H3 frontend |
| `functional_forwarded_via_headers_test.rs` | 1 H3 frontend |
| `functional_grpc_message_metrics_test.rs` | 1 H3 frontend |
| `functional_h3_auth_lifetime_test.rs` | 1 H3 frontend |
| `functional_h3_grpc_streaming_test.rs` | 1 H3 frontend |
| `functional_h3_grpc_web_test.rs` | 1 H3 frontend |
| `functional_h3_soap_utf16_test.rs` | 1 H3 frontend |
| `functional_injector_serving_test.rs` | 1 injector listener |
| `functional_load_testing_replay_test.rs` | 1 HTTPS/H3 frontend |
| `functional_max_forwards_test.rs` | 1 HTTPS/H3 frontend |
| `functional_mesh_mode_test.rs` | 3: non-Linux mesh helper, two SPIRE children; Linux mesh already excludes its namespace's source range |
| `functional_node_agent_test.rs` | 1 admin listener |
| `functional_openapi_client_contract_test.rs` | 1 HTTPS/H3 frontend |
| `functional_overload_test.rs` | 1 H3 frontend |
| `functional_response_caching_conditional_test.rs` | 2 colocated TCP/UDP halves |
| `functional_response_mock_grpc_exclusion_test.rs` | 1 H3 frontend |
| `functional_retry_test.rs` | 1 H3 frontend |
| `functional_serverless_grpc_terminate_test.rs` | 1 H3 frontend |
| `functional_stream_listener_failure_test.rs` | 1 future stream listener, initially bound without listening |
| `functional_tcp_idle_timeout_env_test.rs` | 1 TCP stream frontend |
| `functional_tls_lifecycle_test.rs` | 3 HTTPS, TCP and UDP frontends |
| `functional_waf_unlisted_content_type_h3_test.rs` | 1 H3 frontend |
| `scripted_backend_h3_tests.rs` | 1 H3 frontend |
| `scripted_backend_streaming_latency_tests.rs` | 1 HTTPS frontend |

The generic binary harness had two additional bind-zero/drop paths outside this
grep: `ephemeral_port` and `hold_ephemeral_port_excluding`. Both now delegate to
the shared non-ephemeral allocator, including CP gRPC and per-attempt env ports.

## In-process binds and fixtures

Files are under `tests/integration/` unless qualified. Production APIs that
accept only addresses still need a release/rebind and inherit the range policy;
changing those APIs is outside this test-scaffolding fix.

| File | Sites / classification and action |
| --- | --- |
| `apply_incremental_outcome_tests.rs` | 1 stream reconciler bind; retain handoff |
| `datagram_client_address_datapath_tests.rs` | 2: UDP gateway binds itself; DTLS demux now takes the held UDP socket |
| `dtls_accept_isolation_tests.rs` | 1 DTLS gateway bind; retain handoff |
| `frontend_tls_live_reload_tests.rs` | 2: proxy TLS binds itself; admin HTTPS now takes the held listener |
| `gateway_api_udproute_datapath_tests.rs` | 1 loop handing UDP ports to the listener manager |
| `mesh_outbound_registry_stream_tests.rs` | 2 TCP/UDP start-listener APIs bind themselves |
| `mesh_peer_auth_live_reload_tests.rs` | 1 proxy TLS listener binds itself |
| `tcp_fast_path_l4_plugins_tests.rs` | 1 TCP start-listener API binds itself |
| `tcp_frontend_tls_order_tests.rs` | 1 TCP/TLS start-listener API binds itself |
| `udp_fault_injection_tests.rs` | 1 UDP start-listener API binds itself |
| `udp_hook_concurrency_tests.rs` | 1 UDP start-listener API binds itself |
| `scripted_backend_smoke_tests.rs` | 5: four inactive backend numbers remain unlistened; one deliberate admin-to-stream release/rebind proves ownership transfer |
| `tests/unit/gateway_core/stream_runtime_tests.rs` | 1 reconciler binds its own listener |
| `tests/scaffolding/port_registry_tests.rs` | 1 deliberate wildcard rebind tests lease retention |
| `tests/scaffolding/ports.rs` | helper implementations and the existing handoff regression; inherit the policy |

## Bare-port helpers

`functional_udp_proxy_test.rs` uses `unbound_tcp_port` for gateway HTTP/admin
and `unbound_udp_port` for gateway streams. Every native UDP/DTLS backend in that
file now receives its held socket instead of releasing/rebinding a port.
`scripted_backend_udp_tests.rs` hands its three numbers to a gateway child.
`functional_load_balancer_test.rs` hands proxy/admin numbers to a child and
keeps its unavailable-backend case unlistened.

The following functional modules' local `alloc_port`, `free_port`, or
`ephemeral_port` wrappers delegate to `unbound_port` and therefore inherit the
policy for their subprocess listeners and any address-only fixture APIs:

- `functional_ai_response_guard_grpc_test`, `functional_cli_test`,
  `functional_graceful_shutdown_test`, `functional_grpc_plugins_test`,
  `functional_grpc_test`, `functional_h3_mtls_early_data_test`,
  `functional_host_only_routing_test`, `functional_mtls_acl_test`,
  `functional_mtls_test`, `functional_overload_test`,
  `functional_regex_routing_test`, `functional_router_cache_test`,
  `functional_serverless_mirror_test`, `functional_service_discovery_test`,
  `functional_stream_listener_failure_test`, `functional_tls_lifecycle_test`,
  `functional_tls_only_test`, `functional_websocket_limits_test`,
  `functional_websocket_test`, and `namespace_helpers`.

The integration `gateway_listener_observability_tests` and
`gateway_listener_quic_udp_collision_tests` wrappers feed in-process listener
managers that bind themselves. Scaffolding readiness tests deliberately leave
ports unbound until their readiness probes observe a later bind. The registry
test deliberately verifies that handoff numbers remain leased.

Refused/unavailable destinations in `functional_tcp_proxy_test`,
`functional_grpc_test`, `functional_load_balancer_test`, and
`integration/scripted_backend_smoke_tests`, plus the no-response UDP destination
in `scaffolding/clients/udp.rs`, keep their existing unlistened semantics.
All genuine `reserve_refused_tcp_port` consumers stay held and unchanged;
only the future stream listener that later hands its number to a subprocess
switches constructors.

## Readiness evidence

Every `wait_for_spawned_gateway` caller was inspected: the UDP/DTLS spawners,
three CLI spawners, the load-balancer spawner, and the readiness regressions now
use `GatewayChildGuard::spawn`. Their previous stdout/stderr were null, so no
successful-run log reader is displaced. The generic `TestGateway` always
captures startup diagnostics while preserving opt-in successful-run log APIs.
Identity checks and child liveness checks still gate readiness.

The historical exit on port 33125 cannot be conclusively attributed to
`EADDRINUSE`: that child's output was discarded. Static inspection establishes
the bind-zero/drop/spawn race and the fact that 33125 is within Linux's default
source range. Excluding the actual range deterministically removes automatic
source allocation from that window; future failures carry the child's own
output to distinguish explicit listener collisions from other startup errors.
