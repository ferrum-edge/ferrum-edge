---
paths:
  - "src/plugins/**"
  - "src/plugin_cache.rs"
  - "src/notifications/**"
  - "custom_plugins/**"
  - "docs/plugins.md"
  - "docs/plugin_execution_order.md"
  - "docs/log_schema.md"
  - "docs/notifications.md"
  - "docs/proxy_alerts.md"
  - "docs/cors_plugin.md"
  - "FEATURES.md"
  - "tests/unit/plugins/**"
  - "tests/unit/notifications/**"
  - "tests/integration/*log_schema*"
  - "tests/integration/*deferred_log*"
  - "tests/functional/*plugin*"
  - "tests/functional/*logging*"
  - "tests/functional/*redis*"
---

# Plugin Rules

## Model And Scopes

- Plugins have `id`, `config`, optional `priority_override`, and a priority where lower runs first.
- Scopes are `global`, `proxy`, and `proxy_group`.
- Multiple instances per proxy are allowed.
- A proxy/group-scoped plugin replaces a same-named global for that proxy.
- Multiple scoped instances of the same type may coexist.
- `proxy_group` is one shared instance for its associated proxies; stateful plugins share counters and are cascade-deleted when no proxies remain.

## Lifecycle Order

Preserve phase order and protocol matrix from `src/plugins/mod.rs` and `docs/plugin_execution_order.md`:

1. `on_request_received`: tracing/CORS/termination/IP+geo/bot/spec_expose/spiffe/SSE/gRPC-Web/size+rate/tx_debug
2. `authenticate`: mTLS, JWKS, JWT, keyauth, LDAP, basicauth, HMAC
3. `authorize`: ACL, mesh_authz, rate limiting
4. `before_proxy`: SOAP, AI plugins, workload metrics, transformers, serverless, mock, gRPC deadline, mirror, load, cache, compression
5. `on_final_request_body`: body validator and gRPC-Web validation
6. `after_proxy`: response-side counterpart to before_proxy
   - Successful H1/H2/H3 WebSocket handshakes bypass general `after_proxy` and
     instead run the synchronous, non-rejecting
     `apply_websocket_handshake_response_headers` boundary in configured order.
     Transport-owned handshake/framing fields are stripped afterward and
     restored only by proxy core.
7. `normalize_response_body`: provider/protocol adapters produce the client-visible buffered representation
8. `on_response_body`: AI response guard and token metrics inspect the normalized body
9. `transform_response_body`: ordinary client-facing body rewrites
10. `on_final_response_body`: dedup/cache store, size limiting, response cache predictor
11. `log`: stdout/statsd/http/tcp/kafka/loki/udp/ws/tx_debug/prometheus/chargeback
12. `on_ws_frame`: WS size, rate, and frame logging
13. `on_stream_connect` / `on_stream_disconnect`: TCP+TLS after handshake; UDP+DTLS after DTLS handshake
14. `on_udp_datagram`: bidirectional datagram hooks only when `requires_udp_datagram_hooks()`

Streaming response inspectors are staged: `Normalize` runs before `Inspect`,
with configured plugin order preserved within each stage. Do not hard-code
plugin names or change request-side priorities to obtain response representation
ordering.

Plugin rejects for `application/grpc` must become trailers-only gRPC errors.

## Request Context And Body Rules

- Multi-auth accepts `ctx.identified_consumer` or `ctx.authenticated_identity`; first success wins. Empty chain rejects.
- `ctx.auth_method: Option<&'static str>` is set by `run_auth_impl()` on first successful auth and by stream mTLS auth. Values are compiled-in literals from `AuthMechanism::mechanism_name()`.
- `auth_method` flows to `TransactionSummary`, `StreamTransactionSummary`, and `WsDisconnectContext` for HTTP/1.1, H2, H3, gRPC, WebSocket, TCP, UDP, and DTLS.
- Multi-credential rotation stores each credential type as an array. `FERRUM_MAX_CREDENTIALS_PER_TYPE` defaults to 2.
- `PUT /consumers/:id/credentials/:type` replaces the array, `POST` appends one entry, and `DELETE .../:index` removes one entry.
- Indexable credentials insert all entries into `ConsumerIndex`; secret-based credentials iterate over the array.
- Body buffering is two-tier: `PluginCache.requires_request/response_body_buffering()` for the upper bound, then per-request `should_buffer_*_body(&RequestContext)`.
- gRPC uses `GrpcBody::Streaming(Incoming)` when there are no body plugins and no retries; otherwise `Buffered(Full<Bytes>)`.
- In `before_proxy(ctx, headers)`, read headers from the `headers` parameter, never `ctx.headers`. The handler may have moved headers out of `ctx.headers` when no plugin modifies request headers.
- `ctx.authenticated_identity` is first-class for rate-limit/cache keys, log summaries, and backend identity header injection.
- `response_mock` strips a proxy prefix `listen_path` before rule matching, except for root, regex, exact (`=`), and host-only scopes. It participates in WebSocket upgrade handshakes via `HTTP_FAMILY_PROTOCOLS` but only short-circuits the HTTP handshake response; it does not mock upgraded frame streams.

## Mesh Authz Plugin

- Every `MeshPolicy` carries `PolicyScope`; mesh_authz must filter `slice.mesh_policies` at construction using `policy_scope_applies_to_workload(policy, proxy_namespace, proxy_labels)`.
- Without filtering, namespace-scoped DENY and unrelated ALLOW policies can affect the wrong workload. Do not remove the cold-path filter.
- Proxy identity comes from embedded `mesh_slice` namespace/labels, explicit plugin JSON `namespace`/`labels`, or both with explicit fields winning.
- Empty `WorkloadSelector` intentionally matches any workload.
- Node-waypoint topology is the exception: construction filter is skipped with `per_pod_policy_scoping: true`.
- Node-waypoint request path uses `ctx.node_waypoint_policy_scope` and `PolicyScopeCache::policy_applies`.
- Missing node-waypoint scope sets `ctx.metadata["mesh_authz.scope_missing"] = "true"`. On **both** the HTTP/HBONE request path and stream (TCP/UDP) connections, a missing scope **fails closed** (Reject 403, `mesh_authz.deny_policy = scope_missing`) when any namespace/selector-scoped policy is configured; with only mesh-wide policies the mesh is fully evaluable and it falls through to mesh-wide-only. (Since the resolver derives a pod's scope from the same single slice generation that vouches its identity, a missing scope is not an enrollment race — it means the workload left the live slice gate, so a long-lived HTTP/2 connection from a removed workload must not keep serving with scoped policies silently withheld.)
- Slice apply stages workload SPIFFE scope index before validation and publishes only after `proxy_state.update_config` accepts the plugin cache.
- Istio empty-rule semantics apply here too: ALLOW with no rules is allow-nothing; DENY/AUDIT with no rules are no-ops.

## Transaction Logs And Redaction

- `TransactionSummary` and `StreamTransactionSummary` live in `src/plugins/mod.rs`.
- HTTP summaries carry body-streaming fields such as `body_error_class`, `body_completed`, and `bytes_streamed`.
- Stream summaries carry `disconnect_direction` and `disconnect_cause`.
- Error classifiers include reqwest, gRPC proxy, boxed, H2 pool, and H3 classifiers.
- Summary `metadata` serializes through `metadata_redaction::serialize_redacted_metadata`.
- Redact metadata values when lowercased key contains built-ins: `authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `x-csrf-token`, `bearer`, `password`, `secret`, `token`.
- Also redact operator substrings from `FERRUM_LOG_REDACT_METADATA_KEYS`.
- Redaction happens at serialization; in-memory metadata stays unchanged for later plugin phases.
- New logger sinks get redaction automatically only if they serialize `TransactionSummary` / `StreamTransactionSummary` through serde.

## Log Schema

- `src/plugins/utils/log_schema/` lets operators shape logger output with `schema:` or `schema_ref:`.
- It supports rename, omit, reorder, static fields, derived fields, metadata flatten/omit, and timestamp conversion.
- Default path must remain byte-for-byte identical and zero allocation when no schema is configured.
- Metadata redaction must apply for renamed metadata and flattened metadata too.
- `transaction_log_schema` is global-only and constructed first during plugin-cache rebuild so later plugins can resolve `schema_ref`.
- Non-shipping plugins such as `prometheus_metrics`, `api_chargeback`, and `transaction_debugger` reject `schema:` and `schema_ref:`.
- Field-registry drift is covered by `tests/integration/log_schema_registry_tests.rs`.

## Centralized Rate Limiting

- `rate_limiting`, `ai_rate_limiter`, `ws_rate_limiting`, and `udp_rate_limiting` support `sync_mode: "redis"`.
- Shared Redis client lives in `src/plugins/utils/redis_rate_limiter.rs`.
- Algorithm is two-window weighted with pipelined `INCR`/`GET`/`EXPIRE`; no Lua.
- Key format is `{prefix}:{rate_key}:{window_index}`. Default prefix is `{FERRUM_NAMESPACE}:{plugin_name}`.
- Redis outage falls back to in-memory and reconnects in the background.
- `redis_username` and `redis_password` plugin fields are honored on plain and TLS code paths and override URL user-info.
- `rediss://` uses global `FERRUM_TLS_*`.

## Adding Or Validating Plugins

- New plugin file: `src/plugins/my_plugin.rs`, implements `Plugin`, constructor returns `Result<Self, String>`.
- Add a priority constant in `src/plugins/mod.rs`.
- Override `supported_protocols()` when not HTTP-only. Use the existing protocol constants.
- Register in `create_plugin_with_http_client()` with `?` on `new()` and add to `available_plugins()`.
- Add unit tests for valid and invalid configs in `tests/unit/plugins/` and register the module.
- Update `FEATURES.md`, `README.md`, `docs/plugin_execution_order.md`, `src/plugins/builtin_parity.rs` (`BUILTIN_PLUGIN_PARITY_META`), and `openapi.yaml`. CI enforces registry/order-table/protocol-matrix set parity via `tests/unit/plugins/plugin_doc_parity_tests.rs`.
- All `new()` constructors return `Result<Self, String>`. Return `Err` for no-op config, invalid regex/enum/ranges, or impossible behavior.
- Admin API validation uses `validate_plugin_config_definition()` and returns HTTP 400. File mode validation fails startup. DB mode warns for existing bad data.
- Shared entrypoint is `plugins::validate_plugin_config(name, config)`.

## File Dependencies And Custom Plugins

- Backend TLS file validation belongs to `validate_all_fields_with_ip_policy()`: file mode fatal, DB/CP admin warn, DP rejects update and keeps old config.
- Plugin file dependencies, such as MaxMind `.mmdb`, belong to `validate_plugin_file_dependencies()`: file fatal; DB warns for absent/unreadable files; CP admin validates structure but skips node-local files; DP validates and refreshes its node-local files off the runtime worker for full snapshots and affected incremental rebuilds. On DB/DP runtime nodes, absent/unreadable files use the configured request-time fallback, while readable invalid files reject the new plugin generation. Exception: a DP forced node-local refresh retains the live generation's last-known-good MMDB snapshot for a temporarily unavailable path instead of degrading. Retention is keyed on `db_path` and the instance is still rebuilt from the incoming config, so a concurrent geo policy change applies and a repointed `db_path` never inherits the old snapshot.
- Plugin constructors with file deps should tolerate missing files, log a warning, store `None`, and apply configured request-time fallback policy.
- Frontend TLS cert failure is always fatal.
- Custom plugins live under `custom_plugins/` and may export `plugin_migrations() -> Vec<CustomPluginMigration>`.
- SQL plugin migrations are tracked in `_ferrum_plugin_migrations` by `(plugin_name, version)`.
- `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=false` warns on pending plugin migrations at database/cp startup; it does not mutate schema.
- `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=true` applies pending plugin migrations before `load_full_config`; failure is fatal.
- Standalone migrate mode always applies plugin migrations. MongoDB custom plugin migration support is constructor-created collections/indexes only.

## Notifications

- `src/notifications/` is plugin-agnostic and reusable from overload manager, mesh policy enforcement, or custom plugins.
- `proxy_alerts` is one consumer of the notification layer, not the owner.
- Keep channel dispatch bounded-concurrency and templating `${var}` compatible with `docs/notifications.md`.
