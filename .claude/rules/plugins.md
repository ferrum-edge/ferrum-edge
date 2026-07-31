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
- Exception: `api_chargeback` admits at most one effective instance per proxy
  after merge (shared `/charges` registry is exactly-once) and requires every
  enabled instance to agree on the process-global render/cleanup/budget
  tunables (`max_entries` / `max_retained_bytes` included). The registry admits
  at most `max_entries` retained billing rows (complete entry keys — one
  principal can occupy many slots across proxy/status/family/currency/
  namespace/price dimensions); a refused new row folds into the
  fixed-cardinality internal overflow row
  (`__cardinality_overflow__~sha256:ferrum-edge/api-chargeback/overflow/v1`)
  rather than being dropped (per-identity attribution lost). That sentinel is
  in the digest-form identity class, so a real principal can never share its
  registry key. Authenticated `GET /charges` before the plugin is configured
  must not claim the process-global registry (empty response; later accepted
  generation sizes the hot map with its configured pool shard count).
- Billing identities are never prefix-truncated. External identity claims above
  512 bytes are rejected at the authentication boundary
  (`commit_authentication_attempt`); anything still needing a bound inside
  chargeback uses `chargeback::bounded_billing_identity` (prefix + SHA-256
  digest of the complete value; marker-bearing values always digested).
- Exception: `request_deduplication` may not be effective on the same proxy as
  `mcp_gateway`; its response rewrite comes from live upstream discovery state
  that no persisted digest can witness (`DYNAMIC_RESPONSE_PRESENTATION_PLUGINS`,
  mirrored at runtime by `ResponsePresentationPolicy::Dynamic`).
  Deduplication runs at priority 3010, after route dispatch and
  `request_transformer` header/query rules but before terminate-mode
  `serverless_function`. Plugin-cache admission rejects every same-protocol
  header/query mutator at or after deduplication, including priority overrides,
  and rejects any deferred request-body transformer whose final bytes are not
  exactly the body produced by the pre-`before_proxy` normalization phase.
- `response_caching` likewise requires the proxy's private proof that the
  complete GET/HEAD upload is empty before lookup, binds the complete
  backend-visible request target (including the effective outbound query),
  rejects later header/query mutation, and rejects deferred body transforms that
  could synthesize bytes after lookup. Configured request decompression remains
  compatible because its exact final body is published during pre-`before_proxy`
  normalization. Its request-header dimension is the complete `Vary` tuple, not
  the raw header view: RFC 9111 §4.1 selection is target + `Vary`, and a
  conditional revalidation, a client `no-cache` refresh, and `Content-Length: 0`
  are addressed to an entry rather than selecting a different one — keying the
  raw view would put each of them in a partition the entry cannot be reached
  from and make the `Vary` index unreachable. Cross-caller isolation is the
  mandatory caller partition. `Authorization`, `Proxy-Authorization`, and
  `Cookie` remain mandatory Vary names even for anonymous entries because
  downstream shared caches cannot observe Ferrum's private caller partition;
  present values are hashed and absence is a distinct keyed state. The RFC
  shared-cache authorization admission checks both pristine inbound and live
  backend-visible `Authorization`, so request transforms cannot erase it.
- `proxy_group` is one shared instance for its associated proxies; stateful plugins share counters and are cascade-deleted when no proxies remain.

## Lifecycle Order

Preserve phase order and protocol matrix from `src/plugins/mod.rs` and `docs/plugin_execution_order.md`:

1. `on_request_received`: tracing/CORS/termination/IP+geo/bot/spec_expose/spiffe/SSE/gRPC-Web/size+rate/tx_debug
2. `authenticate`: mTLS, JWKS, JWT, keyauth, LDAP, basicauth, HMAC
3. `authorize`: ACL, mesh_authz, rate limiting
4. `normalize_buffered_request_body_before_before_proxy`: configured request decompression (and any future early body normalizers) after the pre-`before_proxy` buffer is stored
4b. `validate_client_request_body_contract`: CLIENT-contract admission over the ORIGINAL client representation, after normalization and before any `before_proxy`/`transform_request_body` hook can reshape it. Read-only (admit or reject, never rewrite). `openapi_validator` owns this phase; its `on_final_request_body` is the BACKEND-contract fallback when this validator did not select over the pristine client view but can select after a `before_proxy` route override or header/target rewrite, and is skipped per instance once the client phase decided, so one request is never charged twice (`GHSA-896v-jx23-9g6p`). Unknown-operation admission (`fail_on_unknown_operation`) is rejected in `before_proxy`, not deferred to the final fallback. HBONE CONNECT is NOT a fallback path — the proxy skips request-body buffering for it and returns into `handle_hbone_request` before any final-body hook, so tunnel bytes are never a request body here. The phase also covers the transport-proven-empty H1/H2 `GET`/`HEAD`/`OPTIONS` fast path (validated against `&[]` without materializing a buffer), so a required client body is enforced identically on H1/H2/H3. A plugin declaring `validates_client_request_body_contract()` MUST also declare `requires_request_body_before_before_proxy()`; `validate_plugin_security_composition` rejects the composition otherwise. A plugin here must select buffering from the matched route/operation, never from an attacker-omittable `Content-Type` (`GHSA-6p78-6x8c-9g9x`).
5. `before_proxy`: SOAP, AI plugins, workload metrics, transformers, mock, gRPC deadline, load, cache, compression
6. `on_final_request_body`: body validator, gRPC-Web validation, WAF body rules, OpenAPI request schema (backend-final fallback), post-transform request-size ceiling, `ai_prompt_compressor` staged marker-sanitization rejection (4055), and `ai_semantic_cache` exact/semantic lookup (4057). `ai_semantic_cache` looks up here — not in `before_proxy` — so its replay partition binds the finalized outbound headers/query/destination and fully transformed request body, and a hit cannot bypass fail-closed final-body policy.
6b. `dispatch_finalized_request_egress`: irreversible outbound request egress
    (`request_mirror`, `serverless_function`, `ai_federation`) over the immutable
    backend-visible body and finalized pre-egress header snapshot, after every
    hook in step 6 accepted it
    (GHSA-4vr5-4wm3-x5xv). A rejection from final request-body policy therefore
    implies no mirror, function, or provider was contacted; backend admission
    and transport checks still occur later. Runs at most once per request
    (`RequestContext.finalized_request_egress_dispatched`), so retries never
    re-fire it. `pre_proxy` header injection goes through the backend header
    overlay, which the proxy merges only after re-stripping reserved gateway
    assertions and re-applying the egress baggage policy. None of these plugins
    has a `before_proxy` egress hook — do not add one back.
7. `after_proxy`: response-side counterpart to before_proxy
   - Successful H1/H2/H3 WebSocket handshakes bypass general `after_proxy` and
     instead run the synchronous, non-rejecting
     `apply_websocket_handshake_response_headers` boundary in configured order.
     Transport-owned handshake/framing fields are stripped afterward and
     restored only by proxy core.
8. `normalize_response_body`: provider/protocol adapters produce the client-visible buffered representation
9. `on_response_body`: AI response guard and token metrics inspect the normalized body
10. `transform_response_body`: ordinary client-facing body rewrites
11. `on_final_response_body`: dedup/cache store, size limiting, response cache predictor
12. `log`: stdout/statsd/http/tcp/kafka/loki/udp/ws/tx_debug/prometheus/chargeback
13. `on_ws_frame`: WS size, rate, and frame logging
    - First terminal Close from an admission/mutating hook wins; later mutating
      plugins are skipped for that frame while observational hooks
      (`observes_ws_frame_decisions`) may still record the final decision.
    - Delivery-accurate observers use `prepare_ws_frame_delivery` /
      `emit_ws_frame_delivery` after the control-frame guard and a successful
      destination sink accept (same success boundary as frame/byte counters).
      Peer Close bypasses mutating hooks and is observed on that delivery path.
14. `on_stream_connect` / `on_stream_disconnect`: TCP+TLS after handshake; UDP+DTLS after DTLS handshake
15. `on_udp_datagram`: bidirectional datagram hooks only when `requires_udp_datagram_hooks()`

Streaming response inspectors are staged: `Normalize` runs before `Inspect`,
with configured plugin order preserved within each stage. Do not hard-code
plugin names or change request-side priorities to obtain response representation
ordering.

Plugin rejects for `application/grpc` must become trailers-only gRPC errors. The single
exception is the `serverless_function` terminate contract: a validated function response
stamps request-scoped provenance (`RequestContext.serverless_grpc_terminate_frame`) that
authorizes exactly that byte-identical frame to be emitted as HEADERS + one uncompressed
unary DATA frame + plugin-authored terminal trailers. Reject body shape and reject
`content-type`/`grpc-status` headers are never provenance, and the terminate contract is
entered only for the request-scoped native-gRPC flavor the frontend stamps at intake —
never for a mutable effective `content-type`. Authorization binds the authored HTTP status
as well as the frame bytes, and that authorized representation — and only it — runs the
shared synthetic response-body policy lifecycle so configured gRPC response validators are
not bypassed. Invalidated authorization (rewritten frame, replaced response, changed
status) FAILS CLOSED: the body is dropped and a residual `grpc-status: 0` is replaced by
the rejection's own status, or `INTERNAL` — never emitted as an empty Trailers-Only
success. The status-only shape stamps the same provenance with an EMPTY frame: it can
never authorize DATA, but while the reply is unchanged (authored status, still-empty body)
it stays trailers-only and its COMPLETE terminal metadata (`grpc-status`, optional
`grpc-message`, `grpc-status-details-bin`, validated custom trailers) is restored from the
authored provenance instead of the decorated reject header map; an omitted `grpc_message`
stays omitted rather than becoming a synthesized reason. A changed status or an unauthored
body fails closed identically AND discards every terminal key the contract authored, so a
replacement error never ships beside the original contract's `grpc-status-details-bin` or
custom trailers. `grpc_message` is authored as text and emitted percent-encoded per the
gRPC HTTP mapping, with the 8 KiB wire ceiling measured on the encoded value.
That per-field ceiling bounds one value; the COMPLETE terminal block
(`grpc-status`, `grpc-message`, `grpc-status-details-bin`, every custom trailer,
and `content-type`) carries a separate 16 KiB aggregate budget charged as
name + value + 32 bytes per field — the HTTP/2 `SETTINGS_MAX_HEADER_LIST_SIZE` /
HTTP/3 `SETTINGS_MAX_FIELD_SECTION_SIZE` accounting — so 32 individually valid
8 KiB trailers cannot authorize ~256 KiB of terminal metadata.
The raw function output is screened with the shared bounded
`crate::util::json_dup_keys` scanner BEFORE `serde_json::from_slice`: a duplicate
object member name (byte-identical, escaped-equivalent, or nested inside
`trailers`) makes the authored terminal metadata parser-dependent, so it fails
closed under the fixed `invalid_grpc_terminate_response` class with a
fixed-cardinality reason that never echoes body bytes. Do not add a second
ad hoc duplicate-key parser here.
`request_deduplication` is not in this picture at all — it is `HTTP_ONLY_PROTOCOLS` while
`HttpFlavor::Grpc` selects the `ProxyProtocol::Grpc` plugin view, so it is never effective
on a native-gRPC request.

## Request Context And Body Rules

- Multi-auth accepts `ctx.identified_consumer` or `ctx.authenticated_identity`; first success wins. Empty chain rejects.
- `ctx.auth_method: Option<&'static str>` is set by `run_auth_impl()` on first successful auth and by stream mTLS auth. Values are compiled-in literals from `AuthMechanism::mechanism_name()`.
- `auth_method` flows to `TransactionSummary`, `StreamTransactionSummary`, and `WsDisconnectContext` for HTTP/1.1, H2, H3, gRPC, WebSocket, TCP, UDP, and DTLS.
- Multi-credential rotation stores each credential type as an array. `FERRUM_MAX_CREDENTIALS_PER_TYPE` defaults to 2.
- `PUT /consumers/:id/credentials/:type` replaces the array, `POST` appends one entry, and `DELETE .../:index` removes one entry.
- Indexable credentials insert all entries into `ConsumerIndex`; secret-based credentials iterate over the array.
- Body buffering is two-tier: `PluginCache.requires_request/response_body_buffering()` for the upper bound, then per-request `should_buffer_*_body(&RequestContext)`.
- A configured finalized-egress plugin forces buffered request-body
  finalization to complete BEFORE backend dispatch (the `has_finalized_request_egress`
  term in `final_request_body_requirements`), because the ordinary ladder
  otherwise finalizes inside `proxy_to_backend`. On H1/H2 that term is gated to
  non-gRPC initially; once routing selects the transport, protocol-classified
  gRPC that uses generic dispatch is also pulled through terminal preparation.
  Native gRPC reaches the egress boundary from its own branch after its own
  transform/final-hook pass.
- Composition admission fails closed for anything that still egresses earlier:
  `egresses_request_body_before_finalization()` may not coexist with a
  request-body transformer, with any built-in final request hook that can reject
  the backend-visible body on an HTTP/gRPC request-body protocol
  (`enforces_finalized_request_policy()`), or with
  `dispatches_finalized_request_egress()` on the same plugin.
- gRPC uses `GrpcBody::Streaming(Incoming)` when there are no body plugins and no retries; otherwise `Buffered(Full<Bytes>)`.
- In `before_proxy(ctx, headers)`, read headers from the `headers` parameter, never `ctx.headers`. The handler may have moved headers out of `ctx.headers` when no plugin modifies request headers.
- `ctx.authenticated_identity` is first-class for rate-limit/cache keys, log summaries, and backend identity header injection.
- `response_mock` strips a proxy prefix `listen_path` before rule matching, except for root, regex, exact (`=`), and host-only scopes. It supports HTTP and WebSocket upgrade handshakes only (not native gRPC): a match short-circuits the HTTP handshake response and does not mock upgraded frame streams. Native gRPC is excluded because `response_mock` has no provenance-authorized framed unary `Reject` contract; only `serverless_function` terminate does.

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
- `prometheus_metrics` still rejects `schema:` / `schema_ref:` — its label names are baked into the time-series store.
- `SchemaCapabilities.family` (`RecordFamily`) selects the field inventory. Non-summary families: `api_chargeback` (the `/charges` per-proxy billing row), `api_chargeback_sink` (the exported `ChargeEvent`), `transaction_debugger` (its own HTTP/stream/WS diagnostic names). A family rejects, with a plugin- and field-specific diagnostic, whatever it cannot express: `summary_type`, `timestamp_format`, and `metadata` for the two chargeback families, `order` for the chargeback report (sorted `serde_json::Map` document), `backend_host` for charge events, and every derived kind but `summary_kind` for the billing row.
- Projection applies only at the externally emitted representation. It must never reach billing identity, charge accounting, registry/accumulator/snapshot keys, Prometheus labels, or spool ownership.
- `api_chargeback`'s projection governs the one process-global render cache, so `validate_composition` requires every enabled instance to agree on `schema` / `schema_ref` exactly like the other shared tunables.
- `api_chargeback_sink` projects at `write_json_each_row`, the single funnel for the ClickHouse INSERT body and the durable spool artifact. `charge_body_byte_bound` must keep adding the precomputed per-row projection surcharge so the retained-byte reservation still precedes serialization.
- Field-registry drift is covered by `tests/integration/log_schema_registry_tests.rs`.

## Centralized Rate Limiting

- `rate_limiting`, `graphql`, `grpc_method_router`, `ai_rate_limiter`,
  `ws_rate_limiting`, and `udp_rate_limiting` support `sync_mode: "redis"`.
- Shared Redis client lives in `src/plugins/utils/redis_rate_limiter.rs`.
- Algorithm is two-window weighted with pipelined `INCR`/`GET`/`EXPIRE`; no Lua.
- Key format is `{escaped-prefix:escaped-rate-key}:{window_index}` — the braces
  are a Redis Cluster hash tag so every key of one atomic operation shares a
  slot; `%`, braces, and `:` are percent-escaped inside it. Default prefix is
  `{FERRUM_NAMESPACE}:{plugin_name}:{plugin-config-id}` — the config-id component
  isolates independent policies of one plugin type inside a namespace while
  replicas of the same policy keep sharing a budget. An explicit
  `redis_key_prefix` is the shared-budget opt-in.
- Every rate-limit window is bounded by `MAX_RATE_LIMIT_WINDOW_SECONDS`
  (2678400), and ordinary HTTP/GraphQL/gRPC request caps are bounded by
  `MAX_RATE_LIMIT_MAX_REQUESTS` (1000000);
  TTL/retention math uses the saturating helpers in
  `src/plugins/utils/rate_limit.rs`. Local sliding windows retain a fixed
  `SLIDING_WINDOW_BUCKET_COUNT` (64) aggregate buckets per key — never one
  timestamp per request. All six Redis-backed rate-limit plugin roots
  (`rate_limiting`, `graphql`, `grpc_method_router`, `ai_rate_limiter`,
  `ws_rate_limiting`, `udp_rate_limiting`) are closed key sets enforced by
  `reject_unknown_keys` against the plugin's `*_CONFIG_KEYS` allowlist, and each
  must stay in exact parity with an `additionalProperties: false` OpenAPI
  schema. A new root key therefore lands in the runtime allowlist,
  `openapi.yaml`, and `docs/plugins.md` together — none of these roots accepts
  an undeclared property. Parity is enforced by
  `rate_limiter_configs_are_closed_and_bounded_in_openapi` and
  `graphql_config_schema_matches_runtime_validation` in
  `tests/unit/openapi_yaml_tests.rs`.
- Redis outage behavior is `redis_failure_policy` (`fail_closed` default,
  `local_fallback` opt-in); only the opt-in falls back to in-memory. The client
  reconnects in the background either way. `request_deduplication` expresses the
  same choice as `on_redis_unavailable` and does NOT accept
  `redis_failure_policy`; `ai_semantic_cache` has neither.
- Redis Cluster is NOT supported and is screened, not assumed: `INFO CLUSTER`
  at connect plus `MOVED`/`ASK`/`CROSSSLOT`/`CLUSTERDOWN`/`TRYAGAIN` reactively.
  The proactive probe is bounded by `redis_connect_timeout_seconds` (no new
  key); an unanswered probe is a retryable outage, never proof of Cluster, and
  its unscreened connection must not carry a policy command.
  Rejection is terminal for the client — recovery pings must never clear it, and
  no connection publication, command success, or recovery that completes after
  the rejection may restore availability (one `EnforcementAvailability` atomic;
  `publish_reachable` cannot beat `reject_topology`).
- `ai_rate_limiter` admission only reserves an estimate, so the authoritative
  post-response reconciliation is also fail-closed: an `enforcement_unavailable`
  charge on a 2xx returns the same generic 503 as admission. A non-2xx response
  keeps its status (a failed charge/release there only over-counts).
- Local and explicit Redis-fallback maps reserve hard cardinality atomically:
  existing keys retain their active budgets at capacity, while previously unseen
  keys fail closed until idle-state pruning frees a slot.
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
