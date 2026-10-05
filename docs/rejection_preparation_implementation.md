# Rejection preparation implementation status

PR #6011, issues #6008/#6009; implementation round 20. **Draft subset only.
P2 remains open; the whole approved contract is not implemented or qualified.**
The owner approved the complete 883-line round-17 contract identified by SHA-256
`641067eed12615706ff40f2ec81d5797bd379753e905b16ec265f02bedf60346`.
No further policy approval is requested. The separate unresolved-route HTTP 503 /
native-gRPC 14 profile remains pending. The capacity HTTP 503 / native-gRPC 8
profile is approved; interim refusals below are not final qualification of it.

## Implemented runtime boundary

- The actual protocol-filtered R/C union compiles into a generation-owned,
  fixed 64-entry manifest. R includes reject delegates; C includes ordinary
  charged-terminal non-replacers even with a default-false reject gate. Actual
  declarations and instance identity determine enrollment. Custom reported
  names never grant a declaration. Pure built-in candidate placeholders call
  sealed, implementation-owned declaration functions; config-sensitive field
  bounds use real constructors. Trigger/priority wrappers include wrapper credit.
- Full/incremental runtime preparation and pure candidate admission call the
  same composition refusal gate, including HTTP, native gRPC and the HTTP /
  native-policy gRPC-Web union. Unknown, unimplemented, over-capacity and
  incompatible dependency compositions refuse the complete chain. Trigger
  admission uses the actual implementation. Disabled configs retain staging
  behavior. Publication/CP/admin/DB/DP parity is statically connected, not
  dynamically qualified.
- `PluginCacheRequestView` and its ordinary/global/gRPC-Web siblings pin the
  manifest. Preparation reuses this manifest and refuses a different/unpinned
  actual chain; it does not recompile one on the request path. H1/H2 and native
  H3 admit its ticket before request lifecycle,
  body collection or request provider work; cross-protocol dispatch carries the
  context's pin. The shared process ledger remains 128 MiB / 1,024 tickets,
  2 MiB control and max 32 MiB synchronous workspace. Ticket/context clones,
  prepared slots, extracted field/cookie payloads and H1/H2 `ProxyBody` share
  one control owner. Native H3 keeps
  the stack context owner. No eager 2/32 MiB buffer is allocated.
- `ReachedRequestView` provides only a synchronous borrow. `view.patch()` uses
  private admitted output credit. The closed `PreparedTerminalOp` /
  `TerminalResult` variants are Noop, Fields, EmptyBody and moved Cookie. Their
  owner contains no plugin/context/raw body/collector/closure/future. The whole
  chain prepares before any operation is consumed; every operation is taken
  once in order. The public preparation boundary retires context body/text,
  collector and governed/decode plaintext on success and partial refusal.
- `OwnedRejectionHookFuture`, its context-cloning constructor/poller/adopter,
  the old charged hook runner, and both opaque rejection/charged detached
  runners are removed. Rejection and ordinary charged-terminal dispatch accept
  only the typed chain. There is no old async-hook adapter. Only immediate
  operations are currently available: **no terminal external-I/O or detached
  operation is implemented**. Ordinary admitted successful-backend hooks keep
  their existing async lifecycle.
- Authorization is checked before preparation and before each result action;
  gateway/charged/early-upload/capacity authority suppresses replacement actions.
  All union participants prepare in source order, including C-only participants
  on an R path. The view separately reports `action_allowed()`; suppressed
  results are discarded. This is audit infrastructure, not an audit migration.
  One-shot HEAD/cookie preparers check
  action eligibility before consuming state; suppressed capture must still
  prepare independently.
- Field patches check output/action credit before allocation, use fixed vector
  capacity and exact-size boxed fields, and reject invalid custom names/CRLF.
  Cursor growth checks actual String capacities, map backing, cookie field
  occurrences, peak replacement allocation and the 98,304 + 32,768-byte carrier
  split. Limits remain 256 occurrences, 256-byte names, 16,384-byte values,
  64 patch actions and 16,384-byte cookies. Cookie preparation moves the staged
  string through a private capacity-checked `TerminalCookie` wrapper; it is
  neither cloned nor consumed twice.
- Failed frontend admission emits static HTTP 503 JSON (empty HEAD content),
  native gRPC HTTP 200 Trailers-Only status 8, or exact binary/base64 gRPC-Web
  status-8 trailer DATA profiles with canonical content type/expose/Vary fields.
  H1/H2 drop the request intake before return; H3 stops intake after its bounded
  terminal write. The fixed emergency header/body shape uses the independent
  4,096-byte allowance and calls no plugin or recursive rejection chain.
- A fresh gateway-authored terminal can retain its headers in place through a
  later deadline without creating an old provenance snapshot. Existing mixed
  backend/gateway snapshot lineage is **explicitly unsupported/refused**; typed
  operations never call the old allocation-heavy snapshot recorder. The ordinary
  charged path does not label backend fields gateway-owned; unsupported lineage
  at authorization expiry drops optional fields before the fixed auth terminal.
  This refusal
  is an interim draft boundary, not an approved final provenance behavior.

## Actual active migrations

| Implementation | Prepared operation / bound |
| --- | --- |
| `otel_tracing` | Canonical 55-byte traceparent field; C/O 1,024 each. |
| `correlation_id` | Private request ID, at most 8,192 bytes; C/O 12,288 each. |
| `rate_limiting` | Identity-field removal and three validated numeric telemetry fields; C 4,096 / O 8,192. No new Redis operation here. |
| `security_headers` | Config-derived exact field/action output, at most 65,536; C 1,024. Oversize refuses the whole composition rather than omitting/quarantining this security participant. |
| `oidc_relying_party` | Move staged cookie once, capacity at most 16,384; C/O 16,384 each. |
| `spec_expose` | Consume the HEAD marker once and emit EmptyBody; C/O 1,024 each. |
| `ai_semantic_cache` | Closed cache-status field; C/O 1,024 each. |
| `ExamplePlugin` | Custom two-field patch built with admitted credit; C 1,024 / O 16,384. |

The round-19 explicit no-op inventory remains. Pure candidate rows now delegate
to those same source-owned declarations. Deferred CORS and the mesh request-only
sentinel are no-ops; **the active CORS response finalizer is still refused**.
No source-owned registry row trusts an arbitrary runtime `Plugin::name()`.

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

The assigned follow-up is a separately implemented bounded RESP transport,
including encoding and reply construction under the caller's finite credit,
integrated with the existing screened pool/TLS/config and command deadlines.
This requires no new dependency or locally generated lockfile. It must preserve MULTI/EXEC, current/
previous token keys, backend switching, floor-zero compensation, uncertainty
and exactly-one logical reconciliation. It cannot substitute another bucket or
release a paid provider call. A dependency patch also needs normal generated
lockfile/provenance checks; this round did not invent a lockfile, add a dependency,
patch a vendor tree or execute project tooling. ROOT must resolve this concrete
boundary before declaring the limiter migration conforming.

## Exact remaining implementation / root follow-up

| Area | Missing work and current refusal |
| --- | --- |
| Audit (section 6) | All `ai_transcript_audit` and `transaction_debugger` active terminal capture remains Undeclared/refused. No private per-instance Complete/Refuted/Unfinished reached-body/method/header authority, staging guard transfer, immediate audit abort, or record-lease move has been implemented. Shared `MD_FINAL_REQ_SEEN` is not replaced. |
| Bounded audit parser | No bounded JSON/protobuf/redaction arena or reserve-before-node/encoder growth migration. Ordinary `serde_json::Value` paths are not claimed conforming. |
| Limiter / paid provider | `ai_rate_limiter`, including local/federation accounting and Redis reconciliation, remains Undeclared/refused before request provider work in configured terminal chains. No paid-operation cancellation/once/uncertainty semantics are invented. Root must implement the bounded RESP path described above with existing pool/TLS/config/deadline semantics. |
| Other active hooks | `CorsPlugin`/`CorsFinalizer`, `response_transformer`/core route-header finalizer, `compression`, `sse`, `mesh/workload_metrics`, `a2a_gateway`, `ai_federation`, `ai_stream_router`, `body_validator`, `openapi_validator`, `waf`, `ai_response_guard`, `response_size_limiting`, `response_caching`, `grpc_web`, `transaction_debugger`, and the audit/limiter rows above remain Undeclared/refused in their effective HTTP R/C union. There is no opaque fallback. Configuring a currently unmigrated participant can reject an otherwise valid proxy config. |
| External operations / cursor | Add reviewed typed I/O/result/cleanup variants, selected-response scope and replacement/result replay, authorization/deadline rechecks before every external poll, independent finite detach summary, held-operation cancellation and once/paid-state semantics. The immediate driver is not an implementation of these requirements. |
| Provenance / final policies | Migrate mixed backend/gateway provenance, exact authored-field/cookie occurrence ownership and route finalizers under finite cursor credit; preserve every admitted terminal's final header/body policy and HEAD/CORS/compression semantics. Current legacy-lineage refusal must be retired by the full migration. |
| Complete teardown proof | Context retirement and existing retained-upload handoffs are connected, but every raw caller/replay/decode/collector/request-view sibling and cancellation site still needs exact-head real ownership proof. Committed-response/logging observers keep their existing separate lifecycle; no claim is made that their opaque state is a conforming typed terminal operation. |
| Capacity details | Qualified fixed-arena emergency storage, header-map allocator/backing bounds, replacement field occurrence accounting, all key/prefix/wire encoder bounds and all per-symbol temporary allocations still need full implementation/hosted proof. New constants and conservative checks are not sufficient evidence. |
| Config / governance | Hosted full/delta/global/custom/trigger/pure-CP/admin/DB/DP publication parity is pending. Config-dependent declarations for every active hook are pending. Root must publish the edge-owned plugin-catalog contract handoff; this branch does not claim ferrum-contracts publication. |

`mcp_gateway` is a distinct existing case: its default-false reject gate plus
explicit response-replacer capability puts it outside the current R/C union.
Its ordinary successful-response lifecycle remains unchanged; no new terminal
operation is claimed. Configuring future terminal eligibility without a real
declaration will refuse it. Enabled inactive audits still conservatively refuse
until their config-derived no-op declaration is implemented.

## Tests and qualification

External `unit_gateway_core_tests` retain the strict round-19 ledger assertions:
64/65 participants, 1,024/1,025 tickets, process/control/workspace exhaustion,
zero-allocation failures, CAS concurrency, max-W reuse, dependency rejection,
clone/last-owner release and the approved checked-sum arithmetic.

New external fixtures cover complete synchronous preparation before ordered
once-only actions, context body/text retirement on success/partial refusal,
absence of old-hook invocation, charged default-false enrollment, capture/action
suppression, actual-chain name spoof and missing-operation refusal, no-copy
zero/oversize patch credit, shared once-state, carrier capacities/256+1 field or
cookie occurrence edges and exact native/binary/text emergency profiles. The
source authorization guard now checks the remaining awaited phases and the
new typed before-prepare/before-action gates; dynamic fixture assertions are
not weakened or disabled.

**No local project code, compiler, formatter, test, script, server or container
was executed.** Only static source/diff review, hand formatting and
`git diff --check` are permitted here. All hosted formatting/lint/compile tests
are pending. Existing opaque-hook fixtures may require legitimate typed
migration; an old unsupported-hook expectation must not be used as a reason to
restore an adapter or relax a real ownership assertion.

All ten section-7 runtime acceptance areas remain unqualified. Root must obtain
fresh independent exact-final review plus actual hosted CI, including real held
limiter + second collector, A/rejector/B reached keyed digests, active audit
staging rollback, paid/provider/Redis once semantics, scope/ordering/deadlines,
dynamic dense-parser and 64+1/1,024+1 exhaustion, and real H1/H2/native-H3/bridges/
native-gRPC/gRPC-Web/socket/WebSocket admitted-success companions. No primitive,
source assertion or newly written unexecuted test substitutes for these gates.

## Arithmetic discrepancy for ROOT

The nine rows used by the proposal's illustrative example total C+O = **511
KiB**, rather than its stated 611 KiB. Root + carrier + nine slots therefore
total 645.25 KiB and round to **648 KiB**. Nine wrappers add 4.5 KiB, rounding to
**652 KiB**. The code and external fixture follow the approved section-2 checked
sum and section-5 per-symbol numbers. No cap or per-symbol bound was enlarged to
reproduce the erroneous illustration. The optional core route finalizer adds
its own C/O **and slot**, as required by the formula. This discrepancy is not
throughput evidence or justification to relax any approved bound.

The normal merge preserves main source commit
`0d917701b63ef38210c49df830f48cf0457cbc7d`, its 0.9.12 versions/charts/history
and #6012 qualified conditional API. Round-20 implementation does not change
release/canonical/advisory fields or the #6012 acknowledgement contract.

## Complete round-20 file inventory

The implementation delta changes these 72 files. The shared declaration rows
are mechanical source-owned no-op registry parity, not new runtime effects.

- `CUSTOM_PLUGINS.md`
- `custom_plugins/examples/example_plugin.rs`
- `docs/admin_api.md`
- `docs/configuration.md`
- `docs/plugin_execution_order.md`
- `docs/rejection_preparation_implementation.md`
- `openapi.yaml`
- `src/http3/server.rs`
- `src/plugin_cache.rs`
- `src/plugins/access_control.rs`
- `src/plugins/adaptive_concurrency.rs`
- `src/plugins/ai_prompt_compressor.rs`
- `src/plugins/ai_prompt_shield.rs`
- `src/plugins/ai_request_guard.rs`
- `src/plugins/ai_semantic_cache.rs`
- `src/plugins/ai_semantic_firewall.rs`
- `src/plugins/ai_token_metrics.rs`
- `src/plugins/ai_tool_governor.rs`
- `src/plugins/api_chargeback.rs`
- `src/plugins/api_chargeback_sink.rs`
- `src/plugins/bot_detection.rs`
- `src/plugins/correlation_id.rs`
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
- `src/plugins/oidc_relying_party.rs`
- `src/plugins/opa.rs`
- `src/plugins/otel_tracing.rs`
- `src/plugins/prometheus_metrics.rs`
- `src/plugins/proxy_alerts/mod.rs`
- `src/plugins/rate_limiting.rs`
- `src/plugins/request_deduplication.rs`
- `src/plugins/request_mirror.rs`
- `src/plugins/request_size_limiting.rs`
- `src/plugins/request_termination.rs`
- `src/plugins/request_transformer.rs`
- `src/plugins/response_mock.rs`
- `src/plugins/security_headers.rs`
- `src/plugins/serverless_function.rs`
- `src/plugins/soap_ws_security.rs`
- `src/plugins/spec_expose.rs`
- `src/plugins/statsd_logging.rs`
- `src/plugins/stdout_logging.rs`
- `src/plugins/tcp_connection_throttle.rs`
- `src/plugins/tcp_logging.rs`
- `src/plugins/terminal_preparation.rs`
- `src/plugins/udp_logging.rs`
- `src/plugins/udp_rate_limiting.rs`
- `src/plugins/utils/auth_flow.rs`
- `src/plugins/ws_frame_logging.rs`
- `src/plugins/ws_logging.rs`
- `src/plugins/ws_message_size_limiting.rs`
- `src/plugins/ws_rate_limiting.rs`
- `src/proxy/body.rs`
- `src/proxy/mod.rs`
- `tests/unit/gateway_core/stream_auth_lifetime_tests.rs`
- `tests/unit/gateway_core/terminal_preparation_tests.rs`

The preceding normal merge commit
`2cf9658a7f1b96f9b9308d7f1806bdb773333763` brings main into this assigned branch.
Relative to `86f1393d26331f582aec3ee63c17f798e647e1dd`, it changes these 27 files.
Only CHANGELOG/upgrade-guide conflicts needed combined resolution: incoming
release history/versions/charts were retained and draft #6011 notes kept under
Unreleased. The imported lockfiles are main's existing files, not locally
regenerated dependency graphs.

- `CHANGELOG.md`
- `Cargo.lock`
- `Cargo.toml`
- `README.md`
- `charts/ferrum-gateway/Chart.yaml`
- `charts/ferrum-gateway/README.md`
- `charts/ferrum-gateway/examples/migrate-job-config.yaml`
- `charts/ferrum-gateway/examples/migrate-job-status.yaml`
- `charts/ferrum-gateway/examples/migrate-job-up-dry-run.yaml`
- `charts/ferrum-gateway/examples/migrate-job-up.yaml`
- `charts/ferrum-mesh/Chart.yaml`
- `charts/ferrum-mesh/README.md`
- `docs/admin_contracts_handoff_5992_5994.md`
- `docs/cli.md`
- `docs/client_ip_resolution.md`
- `docs/database_tls.md`
- `docs/deployment_mutations.md`
- `docs/functional_testing.md`
- `docs/grpc_qualification_6006.md`
- `docs/hardening.md`
- `docs/kubernetes_deployment.md`
- `docs/mongodb.md`
- `docs/releases/v0.9.11.md`
- `docs/releases/v0.9.12.md`
- `docs/upgrade_guide.md`
- `fuzz/Cargo.lock`
- `tests/performance/mesh/Cargo.lock`
