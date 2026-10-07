# Ferrum Edge Documentation Index

Every document under `docs/`, grouped by who reads it. Start with the row that
matches what you are doing; the [configuration reference](configuration.md) is
the authoritative source for every `FERRUM_*` setting named anywhere else.

Repository-root companions: [README.md](../README.md),
[FEATURES.md](../FEATURES.md), [ARCHITECTURE.md](../ARCHITECTURE.md),
[PRODUCTION_READINESS.md](../PRODUCTION_READINESS.md), [SECURITY.md](../SECURITY.md),
[CONTRIBUTING.md](../CONTRIBUTING.md), [CHANGELOG.md](../CHANGELOG.md),
[CUSTOM_PLUGINS.md](../CUSTOM_PLUGINS.md), [WEBSOCKET.md](../WEBSOCKET.md),
[CONFORMANCE.md](../CONFORMANCE.md), [openapi.yaml](../openapi.yaml).

## Start here

| Document | What it covers |
|---|---|
| [hardening.md](hardening.md) | **Production hardening checklist** — every surface, the setting that secures it, and the "never in production" list |
| [threat_model.md](threat_model.md) | **Threat model** — trust boundaries, attacker capabilities, controls, and documented residuals |
| [support_policy.md](support_policy.md) | **Support, versioning, and deprecation policy** — what a version number promises today and after 1.0 |
| [configuration.md](configuration.md) | The complete `FERRUM_*` environment variable reference and file-mode config format |

## Operator

Running and securing a gateway.

| Document | What it covers |
|---|---|
| [cli.md](cli.md) | CLI subcommands and flags |
| [docker.md](docker.md) | Docker and Docker Compose deployment |
| [kubernetes_deployment.md](kubernetes_deployment.md) | Kubernetes deployment, Helm charts, probes, and raw manifests |
| [k8s_cert_manager.md](k8s_cert_manager.md) | Kubernetes Secret TLS sources and cert-manager integration |
| [infrastructure_sizing.md](infrastructure_sizing.md) | Capacity and sizing guidance |
| [multi_region_ha.md](multi_region_ha.md) | Multi-region high availability |
| [graceful_shutdown.md](graceful_shutdown.md) | Shutdown sequence, draining, and rolling deploys |
| [overload_manager.md](overload_manager.md) | Load shedding, thresholds, and the `/overload` endpoint |
| [upgrade_guide.md](upgrade_guide.md) | Safe upgrade procedure, rollback, and per-release breaking changes |
| [migrations.md](migrations.md) | Build-out database baselines, initialization, and custom-plugin migrations |
| [mongodb.md](mongodb.md) | MongoDB deployment notes |
| [database_tls.md](database_tls.md) | PostgreSQL and MySQL TLS/mTLS |
| [frontend_tls.md](frontend_tls.md) | Frontend and admin TLS, mTLS, CRL policy, and reload behaviour |
| [backend_mtls.md](backend_mtls.md) | Backend TLS verification, client certificates, and backend CRL policy |
| [pkcs11_tls.md](pkcs11_tls.md) | Non-extractable TLS keys through a PKCS#11 token |
| [fips.md](fips.md) | FIPS 140-2 / 140-3 build profile and what it enforces |
| [client_ip_resolution.md](client_ip_resolution.md) | Trusted proxies, `X-Forwarded-For`, and original-scheme resolution |
| [waf.md](waf.md) | Web application firewall: modes, rule pack, scoring, and limits |
| [size_limits.md](size_limits.md) | Request and response size ceilings |
| [cache_management.md](cache_management.md) | Response cache behaviour and invalidation |
| [notifications.md](notifications.md) | Notification delivery |
| [proxy_alerts.md](proxy_alerts.md) | The `proxy_alerts` plugin |
| [prometheus_metrics.md](prometheus_metrics.md) | The Prometheus metric contract |
| [runbooks/gateway.md](runbooks/gateway.md) | First-response procedure for every alert the `ferrum-gateway` chart ships |
| [admin_metrics.md](admin_metrics.md) | `/metrics/runtime` JSON diagnostics |
| [log_schema.md](log_schema.md) | Customizing transaction log output |
| [error_classification.md](error_classification.md) | How failures are classified and surfaced |
| [node_agent.md](node_agent.md) | Node agent capture contract |
| [node_agent_security.md](node_agent_security.md) | Node agent privileges, blast radius, and containment |
| [spire_deployment.md](spire_deployment.md) | SPIRE deployment for mesh workload identity |

## Platform engineer

Topology, routing, and the control plane.

| Document | What it covers |
|---|---|
| [routing.md](routing.md) | Request routing and match semantics |
| [request_path_canonicalization.md](request_path_canonicalization.md) | Path normalization before routing |
| [load_balancing.md](load_balancing.md) | Load-balancing algorithms and health integration |
| [retry.md](retry.md) | Retry policy and bounds |
| [connection_pooling.md](connection_pooling.md) | Backend connection pool sizing and warmup |
| [connection_saturation_benchmark.md](connection_saturation_benchmark.md) | Connection saturation benchmark results |
| [dns_resolver.md](dns_resolver.md) | DNS cache, warmup, TTL overrides, and static entries |
| [http3.md](http3.md) | HTTP/3 (QUIC) frontend and backend |
| [tcp_udp_proxy.md](tcp_udp_proxy.md) | TCP/UDP/DTLS stream proxy, encryption matrices, and Gateway API routes |
| [response_body_streaming.md](response_body_streaming.md) | Streaming response semantics |
| [cp_dp_mode.md](cp_dp_mode.md) | Control plane / data plane distributed mode |
| [cp_namespace_tenancy.md](cp_namespace_tenancy.md) | Multi-namespace control plane, JWT tenancy, and trust binding |
| [mesh.md](mesh.md) | Mesh mode: topologies, config sources, data model, and maturity |
| [mesh_supported_matrix.md](mesh_supported_matrix.md) | Mesh supported-feature product contract |
| [mesh_multicluster_federation_runbook.md](mesh_multicluster_federation_runbook.md) | Multicluster federation runbook |
| [gateway_api_conformance.md](gateway_api_conformance.md) | Kubernetes Gateway API conformance (canonical) |
| [admin_api.md](admin_api.md) | Admin API reference: auth, health tiers, and every endpoint |
| [admin_batch_api.md](admin_batch_api.md) | Batch admin operations |
| [admin_backup_restore.md](admin_backup_restore.md) | Backup and restore |
| [admin_read_only_mode.md](admin_read_only_mode.md) | Read-only admin mode |
| [api_specs.md](api_specs.md) | OpenAPI/Swagger spec-driven provisioning |
| [openapi_validator.md](openapi_validator.md) | The OpenAPI validator plugin |
| [oidc_relying_party.md](oidc_relying_party.md) | OIDC relying-party integration |
| [plugins.md](plugins.md) | Plugin reference: every built-in plugin and its schema |
| [plugin_execution_order.md](plugin_execution_order.md) | Hook phases and ordering |
| [plugins/ai_tool_governor.md](plugins/ai_tool_governor.md) | `ai_tool_governor` plugin |
| [plugins/api_chargeback_sink.md](plugins/api_chargeback_sink.md) | `api_chargeback_sink` plugin |
| [ai_prompt_compressor.md](ai_prompt_compressor.md) | `ai_prompt_compressor` plugin |
| [cors_plugin.md](cors_plugin.md) | CORS plugin |

## Developer

Contributing to Ferrum Edge itself.

| Document | What it covers |
|---|---|
| [ci_cd.md](ci_cd.md) | CI/CD pipeline, required checks, and protected surfaces |
| [coverage.md](coverage.md) | Coverage collection and thresholds |
| [dependency-policy.md](dependency-policy.md) | Dependency governance, vendored patches, and the advisory gate |
| [fuzz.md](fuzz.md) | Adversarial fuzz and property-testing lane |
| [functional_testing.md](functional_testing.md) | Functional test suite overview |
| [functional_testing_auth_acl.md](functional_testing_auth_acl.md) | Authentication and ACL functional tests |
| [functional_testing_database.md](functional_testing_database.md) | Database-mode functional tests |
| [functional_testing_file_mode.md](functional_testing_file_mode.md) | File-mode functional tests |
| [functional_testing_load_stress.md](functional_testing_load_stress.md) | Load and stress testing |
| [functional_testing_port_handoffs.md](functional_testing_port_handoffs.md) | Test port-handoff audit (issue #5579) |
| [protocol_perf_regression.md](protocol_perf_regression.md) | Protocol performance regression gate |
| [scaling_reload_diagnostics.md](scaling_reload_diagnostics.md) | 30,000-proxy scale harness publication and slow-query diagnostics |
| [route_status_profile.md](route_status_profile.md) | Isolated route-status measurements in the Resources Scale Benchmark workflow |
| [h1_internal_profile.md](h1_internal_profile.md) | `bench-h1-profile` hosted HTTP/1 internal profiling feature |
| [pool_internal_profile.md](pool_internal_profile.md) | `bench-pool-profile` H2/native-gRPC pool acquisition profiling |
| [udp_internal_profile.md](udp_internal_profile.md) | `bench-udp-profile` UDP internal profiling |
| [unit_compile_diagnostics.md](unit_compile_diagnostics.md) | Retained CI unit-test compilation diagnostics |
| [ci_policy_performance.md](ci_policy_performance.md) | Trusted Cross verifier CI performance |
| [ghcr_cache_migration.md](ghcr_cache_migration.md) | Moving the BuildKit cache to GHCR |
| [native_cache_envelope.md](native_cache_envelope.md) | Native compiler-cache container-envelope proof |
| [native_compiler_store_transfer.md](native_compiler_store_transfer.md) | Native compiler-store transfer proof |
| [release_profile_study.md](release_profile_study.md) | Release build profile (LTO / codegen units) study |
| [release_platform_build_study.md](release_platform_build_study.md) | Non-publishing macOS/Windows/Linux release-build timing study |
| [plans/diagnostic_ref_cross_replica_adr.md](plans/diagnostic_ref_cross_replica_adr.md) | ADR: diagnostic reference lookup across replicas |
| [plans/mesh_multicluster_lifecycle_adr.md](plans/mesh_multicluster_lifecycle_adr.md) | ADR: mesh multicluster lifecycle |
| [plans/node_waypoint_transport_adr.md](plans/node_waypoint_transport_adr.md) | ADR: NodeWaypoint secured transport |
| [plans/test_framework_scripted_backends.md](plans/test_framework_scripted_backends.md) | Scripted-backend test framework record |
| [backlog/issue_2110_register.md](backlog/issue_2110_register.md) | Historical deferral register for issue #2110 |

## Dated reports

Point-in-time measurements and reviews. They record what was observed on the
stated date and are not updated as behaviour changes.

| Document | What it covers |
|---|---|
| [benchmark_audit_2026_09_17.md](benchmark_audit_2026_09_17.md) | Gateway benchmark audit ([results](benchmark_audit_2026_09_17_results.json)) |
| [benchmark_h2_grpc_2026_09_18.md](benchmark_h2_grpc_2026_09_18.md) | H2/gRPC adaptive-window observation ([results](benchmark_h2_grpc_2026_09_18_results.json)) |
| [benchmark_h3_preflight_2026_09_18.md](benchmark_h3_preflight_2026_09_18.md) | H3 observer capability results ([results](benchmark_h3_preflight_2026_09_18_results.json)) |
| [benchmark_h3_smoke_2026_09_18.md](benchmark_h3_smoke_2026_09_18.md) | H3 live smoke lifecycle loss ([results](benchmark_h3_smoke_2026_09_18_results.json)) |
| [benchmark_h2_guard_transitions_2026_09_19.md](benchmark_h2_guard_transitions_2026_09_19.md) | H2 guard campaign findings and transition follow-up |
| [benchmark_wss_tcp_2026_09_19.md](benchmark_wss_tcp_2026_09_19.md) | WSS and TCP/TLS missing-payload audit ([results](benchmark_wss_tcp_2026_09_19_results.json)) |
| [ci_throughput_2026-09-08.md](ci_throughput_2026-09-08.md) | Hosted CI throughput follow-up ([cache inventory](ci_throughput_2026-09-08_cache.json)) |
| [ci_pr_validation_review_2026_09_24.md](ci_pr_validation_review_2026_09_24.md) | PR validation scope review |

## Reference data

Machine-readable contracts checked by CI.

| File | What it is |
|---|---|
| [prometheus_metric_contract.json](prometheus_metric_contract.json) | The metric contract `prometheus_metrics.md` documents |
| [vendored-patch-lifecycle.json](vendored-patch-lifecycle.json) | Vendored-patch lifecycle inventory enforced by the dependency audit |

## Vendored upstream patches

Each directory holds the patch itself plus the upstream issue and pull-request
text. Governance lives in [dependency-policy.md](dependency-policy.md).

### h3

- [Overview](upstream-h3-patches/README.md)
- 001 — [recv frame drain on QUIC close](upstream-h3-patches/001-recv-frame-drain-on-quic-close/README.md)
  ([issue](upstream-h3-patches/001-recv-frame-drain-on-quic-close/issue.md),
  [PR text](upstream-h3-patches/001-recv-frame-drain-on-quic-close/pr-description.md),
  [patch](upstream-h3-patches/001-recv-frame-drain-on-quic-close/h3-frame-rs.patch))
- 002 — [Extended CONNECT `:protocol = websocket`](upstream-h3-patches/002-extended-connect-websocket-protocol/README.md)
  ([issue](upstream-h3-patches/002-extended-connect-websocket-protocol/issue.md),
  [PR text](upstream-h3-patches/002-extended-connect-websocket-protocol/pr-description.md),
  [patch](upstream-h3-patches/002-extended-connect-websocket-protocol/h3-ext-rs.patch))
- 003 — [peek buffered trailers before FIN](upstream-h3-patches/003-peek-buffered-trailers-before-fin/README.md)
  ([issue](upstream-h3-patches/003-peek-buffered-trailers-before-fin/issue.md),
  [PR text](upstream-h3-patches/003-peek-buffered-trailers-before-fin/pr-description.md),
  [patch](upstream-h3-patches/003-peek-buffered-trailers-before-fin/h3-peek-buffered-trailers.patch))
- 004 — [`SendStreamStopped` watch](upstream-h3-patches/004-send-stream-stopped-watch/README.md)
  ([issue](upstream-h3-patches/004-send-stream-stopped-watch/issue.md),
  [PR text](upstream-h3-patches/004-send-stream-stopped-watch/pr-description.md),
  [patch](upstream-h3-patches/004-send-stream-stopped-watch/h3-send-stream-stopped-watch.patch))
- 005 — [buffered non-`DATA` frame ceiling](upstream-h3-patches/005-max-buffered-frame-len/README.md)
  ([issue](upstream-h3-patches/005-max-buffered-frame-len/issue.md),
  [PR text](upstream-h3-patches/005-max-buffered-frame-len/pr-description.md),
  [patch](upstream-h3-patches/005-max-buffered-frame-len/h3-max-buffered-frame-len.patch))

### h3-quinn

- [Overview](upstream-h3-quinn-patches/README.md)
- 001 — [`stop_sending` during an in-flight read](upstream-h3-quinn-patches/001-stop-sending-during-in-flight-read/README.md)
  ([issue](upstream-h3-quinn-patches/001-stop-sending-during-in-flight-read/issue.md),
  [PR text](upstream-h3-quinn-patches/001-stop-sending-during-in-flight-read/pr-description.md),
  [patch](upstream-h3-quinn-patches/001-stop-sending-during-in-flight-read/h3-quinn-stop-sending-in-flight-read.patch))
- 002 — [`SendStream::stopped` watch](upstream-h3-quinn-patches/002-send-stream-stopped-watch/README.md)
  ([issue](upstream-h3-quinn-patches/002-send-stream-stopped-watch/issue.md),
  [PR text](upstream-h3-quinn-patches/002-send-stream-stopped-watch/pr-description.md),
  [patch](upstream-h3-quinn-patches/002-send-stream-stopped-watch/h3-quinn-send-stream-stopped-watch.patch))

### hyper

- 001 — [reset an upgraded HTTP/2 CONNECT stream with `CONNECT_ERROR`](upstream-hyper-patches/001-upgraded-h2-connect-error-reset/README.md)
  ([issue text](upstream-hyper-patches/001-upgraded-h2-connect-error-reset/issue.md),
  [PR text](upstream-hyper-patches/001-upgraded-h2-connect-error-reset/pr-description.md),
  [patch](upstream-hyper-patches/001-upgraded-h2-connect-error-reset/hyper-upgraded-h2-connect-error-reset.patch))
- 004 — [bound HTTP/2 request body write stalls](upstream-hyper-patches/004-h2-body-write-timeout/README.md)
  ([patch](upstream-hyper-patches/004-h2-body-write-timeout/hyper-h2-body-write-timeout.patch))
- 005 — [coalesce DATA frames cut from small HTTP/2 window increments](upstream-hyper-patches/005-h2-small-window-coalescing/README.md)
  ([patch](upstream-hyper-patches/005-h2-small-window-coalescing/hyper-h2-small-window-coalescing.patch))

### h2

- 001 — [coalesce DATA frames into one write](upstream-h2-patches/001-coalesce-data-frame-writes/README.md)
  (upstream [hyperium/h2#902](https://github.com/hyperium/h2/issues/902) /
  [#903](https://github.com/hyperium/h2/pull/903),
  [patch](upstream-h2-patches/001-coalesce-data-frame-writes/h2-coalesce-data-frame-writes.patch))
- 002 — [update the automatic DATA-frame budget at runtime](upstream-h2-patches/002-runtime-data-frame-budget/README.md)
  (upstream [hyperium/h2#965](https://github.com/hyperium/h2/pull/965),
  [patch](upstream-h2-patches/002-runtime-data-frame-budget/h2-runtime-data-frame-budget.patch))
- 003 — [report a stream's assigned send window apart from the send buffer](upstream-h2-patches/003-assigned-send-capacity/README.md)
  ([patch](upstream-h2-patches/003-assigned-send-capacity/h2-assigned-send-capacity.patch))

### hyper-util

- 001 — [release an HTTP/1 sender once its dispatcher stops reading](upstream-hyper-util-patches/001-release-h1-sender-on-dispatch-close/README.md)
  ([issue](upstream-hyper-util-patches/001-release-h1-sender-on-dispatch-close/issue.md),
  [patch](upstream-hyper-util-patches/001-release-h1-sender-on-dispatch-close/hyper-util-release-h1-sender-on-dispatch-close.patch))

### reqwest

- 001 — [per-request `connect_timeout`](upstream-reqwest-patches/001-per-request-connect-timeout/README.md)
  ([patch](upstream-reqwest-patches/001-per-request-connect-timeout/reqwest-3017.patch))
- 002 — [selectable rustls provider fallback](upstream-reqwest-patches/002-selectable-rustls-provider/README.md)
- 003 — [physical-connection admission hook](upstream-reqwest-patches/003-connection-admission-hook/README.md)
- 004 — [report an established connection's socket](upstream-reqwest-patches/004-connection-established-fd/README.md)

### sqlx

- 001 — [verify-ca hostname-error compatibility](upstream-sqlx-patches/001-verify-ca-name-context/README.md)

### tungstenite

- [Overview](upstream-tungstenite-patches/README.md)
- 003 — [optional `WebSocketConfig::auto_pong`](upstream-tungstenite-patches/003-optional-auto-pong/README.md)
  ([patch](upstream-tungstenite-patches/003-optional-auto-pong/tungstenite-auto-pong.patch))
- 004 — [physical-fragment accounting](upstream-tungstenite-patches/004-fragment-accounting/README.md)
  ([patch](upstream-tungstenite-patches/004-fragment-accounting/tungstenite-fragment-accounting.patch))

### dimpl

- 001 — [certificate chains and private-key zeroization](upstream-dimpl-patches/001-certificate-chain-and-key-zeroization/README.md)
  ([issue](upstream-dimpl-patches/001-certificate-chain-and-key-zeroization/issue.md),
  [PR text](upstream-dimpl-patches/001-certificate-chain-and-key-zeroization/pr-description.md),
  [patch](upstream-dimpl-patches/001-certificate-chain-and-key-zeroization/dimpl-0.6.1-ferrum.patch))
