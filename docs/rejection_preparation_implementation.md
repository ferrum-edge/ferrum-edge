# Rejection preparation implementation status

PR #6011, issues #6008/#6009; implementation round 19. **Incomplete. P2 remains
open.** The owner approved the 883-line round-17 contract identified by SHA-256
`641067eed12615706ff40f2ec81d5797bd379753e905b16ec265f02bedf60346`.
Approval authorizes implementation; it does not establish hosted qualification.
The separate unresolved-route HTTP 503/native-gRPC 14 profile remains pending.

## Implemented primitives

`src/plugins/terminal_preparation.rs` contains:

- Explicit `Undeclared`, `PureNoop`, and finite `Prepared` declarations with
  typed preparation/trigger/cursor fact sets. The public `Plugin` default is
  `Undeclared`, including inherited no-op hooks. No plugin-name trust is used.
- A fixed 64-entry manifest, checked C/O sum, 4 KiB rounding, one 128 KiB
  carrier plus 4 KiB root, 256-byte slots, 512-byte wrapper credit, and max-W
  reuse. R/C eligibility is a union; default-false rejection does not omit C.
  A failed candidate is permanently refused, including subsequent admission of
  its otherwise valid prefix. This is a primitive, not yet a cache publication
  gate.
- Dependency checks refusing response scope decisions during preparation,
  post-suspension writes of preparation-only facts, and earlier cursor writes
  consumed by later preparation/trigger reads.
- A process ledger with byte and ticket counts in one atomic word. Admission
  reserves both in one CAS, without waiting or allocating staging. Fixed limits
  are 128 MiB, 1,024 tickets, 2 MiB control and 32 MiB workspace. Zero control is
  refused; there is no environment/config override. The process singleton is
  provided, but frontends do not yet use it.
- Unique control/workspace drop owners. Sharing a control owner via `Arc`
  shares one request ticket. A workspace borrows its control owner, allows one
  interval at a time, cannot move into a `Send` future and returns its process
  credit independently. Reservation does not eagerly allocate either 2 MiB
  control or 32 MiB scratch. The typed
  terminal driver must still enforce dropping workspace before suspension.
- Policy constants for field occurrences/names/values, patch count, exact rate
  key/prefix/wire key, cookie, detached summary and emergency bytes. Constants
  alone do not enforce these dynamic surfaces. Fixed capacity wording/body are
  staged; no new wire outcome is active yet.

The inherited no-op implementations from proposal section 5 explicitly declare
`PureNoop`, including the six authentication macro expansions, config-only
`TransactionLogSchema`, `WafWsSession`, and `ExampleAuditPlugin`.
`PluginInstanceWrapper` delegates the actual inner declaration without evaluating
a trigger. Admission placeholders, deferred CORS, route finalizers and active
response hooks remain undeclared pending their actual manifest/operation
migration. No async adapter was added. Ordinary successful-backend and unrelated
WebSocket/stream contracts continue through their existing implementations.

## Concrete dependency boundary

The existing `AiRateLimiter::adjust_usage` calls
`RateLimitBackend::check_with_redis_key_and_local_capacity`, whose token algorithm
uses `RedisRateLimitClient::sliding_window_increment_by`,
`incrby_with_expire_floor_zero`, and related helpers. Those helpers build
`redis::Pipeline` and await `query_async` on the shared multiplexed connection.

The published Redis **1.2.1** archive was inspected statically and verified
against its `Cargo.lock` checksum:
`72d32a1ac9123f0d84fda64bfc02a271d9868483162dd2d9099b5c362ece064c`.
Its relevant actual APIs are:

- `pipeline.rs`, `Pipeline::query_async` passes the pipeline to
  `ConnectionLike::req_packed_commands`; `Pipeline::get_packed_pipeline` returns
  a newly allocated `Vec<u8>`.
- `aio/multiplexed_connection.rs`, `send_packed_commands` builds that packed
  vector internally and returns owned `Vec<Value>` replies. Its public API
  accepts no caller capacity credit, bounded encoder or bounded reply sink.
- `parser.rs`, `value` materializes server bulk strings with `bs.to_vec()` and
  server-declared arrays with `count_min_max`. String/error/map representations
  also allocate before Ferrum receives the result. Its recursion limit does not
  bound aggregate owned capacity. Converting a decoded reply to `i64` occurs
  after these allocations, so a scalar result type does not provide the bound.

The current API cannot refuse these allocations against an individual terminal
operation's C/O credit before growth. Bounding Ferrum's logical key and checking
the returned result afterward leaves this boundary unimplemented. Treating
client encoding/reply temporaries as free shared pool memory is not conforming.

A complete implementation needs either a capacity-aware Redis dependency API,
including encoding and reply construction under the caller's finite credit, or
a separately implemented bounded RESP transport integrated with the existing
screened pool and command deadlines. It must preserve MULTI/EXEC, current/
previous token keys, backend switching, floor-zero compensation, uncertainty
and exactly-one logical reconciliation. It cannot substitute another bucket or
release a paid provider call. A dependency patch also needs normal generated
lockfile/provenance checks; this round did not invent a lockfile, add a dependency,
patch a vendor tree or execute project tooling. ROOT must resolve this concrete
boundary before declaring the limiter migration conforming.

## Exact remaining implementation

The following approved work has **not** been implemented by this round:

| Proposal area | Remaining source/API work |
| --- | --- |
| Section 1 / 4 R/C execution | Replace `OwnedRejectionHookFuture`, `owned_rejection_hook_future`, `run_after_proxy_hooks_on_rejection`, `run_charged_terminal_after_proxy_hook` and both detached runners with raw-free typed operation/result owners and the ordered cursor. The current futures still own a cloned `RequestContext` and `Arc<dyn Plugin>`. |
| Section 2 early pinning | Add the actual finite manifest to `PluginCacheRequestView` and admission siblings; reserve the shared ticket before lifecycle/body/external work on H1/H2/native H3 and every bridge. Carry it through response/cleanup ownership without another reservation. |
| Section 3 capacity wire / teardown | Implement fixed inline HTTP 503, native-gRPC Trailers-Only 8 and translated binary/text gRPC-Web framing; retire caller/replay/text/binary/decode/collector owners on every failure. Preserve authoritative terminals and genuine paid-operation accounting. |
| Section 4 ordered effects | Prepare every eligible instance before external polling, separate audit capture from replacer actions, retain response/result order, once-state, route finalizer/provenance, cookie/HEAD/compression owners and authorization/deadline/detachment semantics. |
| Section 5 active migrations | Implement every prepared response hook listed in the approved table, the core route finalizer, actual wrapper trigger preparation, and config-derived declarations for composition placeholders. Finite numbers alone do not replace their current methods. |
| Section 5 custom API | Define reviewed custom raw-free preparation/operation/result ownership, migrate `ExamplePlugin`, and refuse incompatible/undeclared/spoofed compositions in full/incremental caches and pure CP/admin/DB/DP admission. The new declaration method is only the first API piece. |
| Section 6 audit | Replace shared `MD_FINAL_REQ_SEEN` authority with private per-instance Complete/Refuted/Unfinished state; carry the exact reached body/method/final hook headers through H1/H2 adoption and native H3. Move staging/commit/record handles with immediate abort cleanup. |
| Section 6 parser / capacities | Implement reserve-before-growth bounded JSON/protobuf/redaction arenas and exact retained audit capacity charging; enforce every dynamic header/key/cookie/patch/encoder limit before allocation or call. Existing ordinary `serde_json::Value` parsing is not a bounded 32 MiB arena. |
| Governance | Complete lifecycle/custom/config/OpenAPI parity as the actual runtime/config refusal surfaces land. Hand off the public plugin capability change to ferrum-contracts `plugin-catalog`; PR metadata remains ROOT-owned. |

This inventory is a delivery record for code preserved on the assigned branch,
not a replacement proposal or a request for renewed policy approval. The approved
scope remains unchanged. No raw-retention exception, settled-path exemption,
first-poll trust or weakening fallback is implemented as a purported repair.

## Hosted acceptance status

External `terminal_preparation_tests` exercise the actual staged primitives:
64/65 slots; 1,024/1,025 tickets with a small control reservation; exact control
capacity, page rounding and arithmetic overflow; max-W reuse; 128 MiB process
exhaustion; zero-allocation failed admission and workspace reservation measured
by the existing thread-local allocation counter; concurrent CAS admission;
clone/last-owner drop; failed-workspace recovery; whole-candidate refusal;
dependency rejection; inherited/overridden unknown declarations and built-in-name
spoof; and source parity of explicit no-op implementations/auth macro expansions.
These fixtures are registered in `unit_gateway_core_tests`. The existing
allocator's behavior and strict assertions are unchanged.

All ten section-7 acceptance areas still require the full runtime migration and
exact-head hosted evidence. In particular, registry publication parity, dynamic
capacity surfaces, real held-limiter/second-collector retirement, A/rejector/B
keyed digests, ordered results, paid limiter semantics, staging rollback,
deadline/detachment, and real H1/H2/H3/native-gRPC/gRPC-Web/socket/WS companions
are **pending**. No mock primitive or source assertion is substituted for them.
No local compiler, formatter, test, script, server or container was run. Local
verification is static source/diff review and `git diff --check`; hosted
formatting, lint, compile and all dynamic semantic tests remain unverified.

## Arithmetic discrepancy for ROOT

The nine rows used by the proposal's illustrative example total C+O = **511
KiB**, rather than its stated 611 KiB. Root + carrier + nine slots therefore
total 645.25 KiB and round to **648 KiB**. Nine wrappers add 4.5 KiB, rounding to
**652 KiB**. The code and external fixture follow the approved section-2 checked
sum and section-5 per-symbol numbers. No cap or per-symbol bound was enlarged to
reproduce the erroneous illustration. The optional core route finalizer adds
its own C/O **and slot**, as required by the formula. This discrepancy is not
throughput evidence or justification to relax any approved bound.

No release version/tag, advisory affected/patched field, downstream/canonical
source decision or unrelated #6012 conditional acknowledgement was changed.

## Files changed in round 19

- `CUSTOM_PLUGINS.md`
- `custom_plugins/examples/example_audit_plugin.rs`
- `docs/plugin_execution_order.md`
- `docs/rejection_preparation_design.md`
- `docs/rejection_preparation_implementation.md`
- `src/plugin_cache.rs`
- `src/plugins/access_control.rs`
- `src/plugins/adaptive_concurrency.rs`
- `src/plugins/ai_prompt_compressor.rs`
- `src/plugins/ai_prompt_shield.rs`
- `src/plugins/ai_request_guard.rs`
- `src/plugins/ai_semantic_firewall.rs`
- `src/plugins/ai_token_metrics.rs`
- `src/plugins/ai_tool_governor.rs`
- `src/plugins/api_chargeback.rs`
- `src/plugins/api_chargeback_sink.rs`
- `src/plugins/bot_detection.rs`
- `src/plugins/fault_injection.rs`
- `src/plugins/geo_restriction.rs`
- `src/plugins/graphql.rs`
- `src/plugins/grpc_deadline.rs`
- `src/plugins/grpc_method_router.rs`
- `src/plugins/http_logging.rs`
- `src/plugins/ip_restriction.rs`
- `src/plugins/jwks_auth.rs`
- `src/plugins/kafka_logging.rs`
- `src/plugins/load_testing.rs`
- `src/plugins/loki_logging.rs`
- `src/plugins/mesh/authz.rs`
- `src/plugins/mesh/bpf_metrics.rs`
- `src/plugins/mesh/outbound_registry.rs`
- `src/plugins/mesh/spiffe_identity.rs`
- `src/plugins/mesh_route_dispatch.rs`
- `src/plugins/mod.rs`
- `src/plugins/oauth2_introspection.rs`
- `src/plugins/opa.rs`
- `src/plugins/prometheus_metrics.rs`
- `src/plugins/proxy_alerts/mod.rs`
- `src/plugins/request_deduplication.rs`
- `src/plugins/request_mirror.rs`
- `src/plugins/request_size_limiting.rs`
- `src/plugins/request_termination.rs`
- `src/plugins/request_transformer.rs`
- `src/plugins/response_mock.rs`
- `src/plugins/serverless_function.rs`
- `src/plugins/soap_ws_security.rs`
- `src/plugins/statsd_logging.rs`
- `src/plugins/stdout_logging.rs`
- `src/plugins/tcp_connection_throttle.rs`
- `src/plugins/tcp_logging.rs`
- `src/plugins/terminal_preparation.rs`
- `src/plugins/transaction_log_schema.rs`
- `src/plugins/udp_logging.rs`
- `src/plugins/udp_rate_limiting.rs`
- `src/plugins/utils/auth_flow.rs`
- `src/plugins/waf/websocket.rs`
- `src/plugins/ws_frame_logging.rs`
- `src/plugins/ws_logging.rs`
- `src/plugins/ws_message_size_limiting.rs`
- `src/plugins/ws_rate_limiting.rs`
- `tests/unit/gateway_core/mod.rs`
- `tests/unit/gateway_core/response_coalescing_allocation_tests.rs`
- `tests/unit/gateway_core/terminal_preparation_tests.rs`
