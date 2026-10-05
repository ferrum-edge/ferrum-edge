# P2 rejection preparation: internal design for owner decision

Status: investigation only for #6008/#6009 and PR #6011. **P2 remains open.**
This document does not change the supported plugin contract. The source inventory
was inspected at `669d02009dc8bccdfebf757b6b215a38a91ff15a`; symbol names below
identify the relevant boundaries. No local project execution or new hosted
qualification established this design. ROOT owns the security/profile decision.

## Existing ownership and the preservation conflict

In `src/proxy/mod.rs`, `owned_rejection_hook_future` (line 24589 at the inspected
head) owns a complete cloned `RequestContext`, response headers and optional
response body. It lends that context to `Plugin::after_proxy` until completion.
`run_after_proxy_hooks_on_rejection` creates it in both the post-deadline
single-poll arm and the live RPC-deadline race. A pending hook can move into
`spawn_detached_rejection_cleanup`; charged terminals instead use
`spawn_detached_charged_terminal_hook`. `run_charged_terminal_after_proxy_hook`
is a third constructor site on the ordinary response ladder.
That third site is important: `run_after_proxy_hooks:26926` visits every
effective plugin over a charged backend terminal, not just hooks opting into
`applies_after_proxy_on_reject`. Only response replacers are skipped there.

`RequestContext` derives `Clone` (`src/plugins/mod.rs:2301`). Its
`request_body_bytes` shares the charged allocation, `metadata["request_body"]`
copies the text, and `request_buffer_charge` shares the collector charge.
`discard_retained_request_metadata` (line 4646) removes those three owners only
from the context it receives. Caller retirement, settled-path retirement and
clearing the original context cannot remove owners from a pending future.
Detachment still has the existing five-second/earlier-authorization bound; that
time bound does not restore upload admission before suspension.

The public trait (`src/plugins/mod.rs:10933`) accepts `&mut RequestContext`
through an async hook. `CUSTOM_PLUGINS.md` documents readable/writable context
and reject participation; `custom_plugins/mod.rs` registers arbitrary
`Arc<dyn Plugin>` factories. There is no prohibition on raw reads, rewrites or
clones after an await. For example, this legal hook body illustrates the conflict:

```rust,ignore
external_operation().await; // one externally visible invocation
let body = ctx.request_body_bytes.as_ref();
// Inspect body and/or replace metadata["request_body"] for a later audit instance.
```

This is a contract counterexample, not an executed reproducer. Retirement before
the await removes the later input. Capturing audit first misses the later rewrite.
Restarting the hook can invoke the external operation twice. Waiting for it keeps
the raw allocation across await. Rust also prevents mutating the borrowed context
behind the suspended hook. Generic first-poll inspection cannot establish that a
future will never read raw state on a later poll or already retained a clone.
Consequently the requested retirement rule and the unrestricted opaque contract
cannot both be preserved. No partial P2 repair is implemented in this commit.

## Complete implemented-hook inventory

The inventory is a source scan of `src/plugins`, `src/plugin_cache.rs` and
`custom_plugins`, rather than a trust decision based on `Plugin::name()`.
Every concrete built-in `after_proxy` override is below. `R` means it opts into
the reject runner; `B` means the ordinary response ladder (the default reject
gate is false). Non-replacers from either group also run in that ladder's
charged-terminal mode. All rows except `ai_rate_limiter` finish without a suspension:
their direct and transitive helpers are synchronous. Their listed reads and
mutations therefore happen before returning Ready; they have **no post-await
reads or mutations**. Raw body access is called out explicitly. Other context
reads still matter when building the proposed staged representation.

| Implementation / source anchor | Gate | Reads and effects before any await |
| --- | --- | --- |
| `otel_tracing.rs:1043` | R | Reads staged traceparent; writes its response field. |
| `correlation_id.rs:330` | R | Reads the private authoritative request ID via `request_id`; echoes it under the configured response name. |
| `cors.rs:1172`, `CorsPlugin` | R | Reads deferral and staged CORS state; `finalize_cors_response` sanitizes/decorates response headers and always returns Continue. CORS rejection belongs to request finalization. |
| `cors.rs:1252`, CORS finalizer | R | Sanitizes/decorates that same response state once at the chain's finalizer position, retaining the selected response. |
| `security_headers.rs:147` | R | No context input; configured response field rules. |
| `spec_expose.rs:980` | R, replacer | Consumes the HEAD marker; returns the selected status/headers with empty bytes. |
| `oidc_relying_party.rs:2717` | R | Takes the staged rotated-session cookie once and appends it to Set-Cookie. |
| `rate_limiting.rs:1223` | R | Reads previously admitted rate-limit metadata; strips the identity header and optionally copies rate telemetry. No rate-store I/O here. |
| `response_transformer.rs:1311` | R | Reads enabled/replay/provenance flags; applies static response rules, records authored fields. The chain finalizer, not this hook, consumes the route response override. |
| `compression.rs:2077` | R, replacer | Reads method/protocol, rejection/cache-hit/replay state, negotiated Accept-Encoding, response status/headers, response ceiling and per-instance admission/encode ownership. Settles the instance's negotiation vote; releases/transfers/claims permits and encode ownership; stages algorithm/encoding/Vary or returns fixed 406. No raw request body read. |
| `sse.rs:813` | R | Reads origin/encoding/no-transform stamps and response headers/status; stages wrap/relabel/retry markers and SSE headers. |
| `mesh/workload_metrics.rs:1239` | R | Reads source-scope/principal/peer identity, request headers and trace metadata. Can re-annotate source labels; echoes traceparent and removes captured tracing markers. |
| `ai_transcript_audit.rs:5201` | R, active replacer | Reads instance-owned staging/captured state, instance candidate ownership and the shared request metadata flag `MD_FINAL_REQ_SEEN`. That shared flag gates raw text/binary capture or gRPC refutation and can suppress an unfinished peer's decision. Then reads rejection/replaceability markers, method/framing, response status/headers, sampling/admission and sink health; reserves queue/commit leases or returns fail-closed 503. Details below. |
| `ai_rate_limiter.rs:2694` | R | Reads/writes reservation, genuine backend status, federation status/tokens, release and usage markers, identity/IP and response-stream posture; awaits reconciliation. Its post-await accesses are inventoried below. No raw body read in this hook or reconciliation. |
| `a2a_gateway.rs:1524` | B | Reads instance claim, content type and receipt time; marks streaming in the claim and optional latency metadata. |
| `ai_federation.rs:7215` | B | Reads the owned stream claim, status and media/coding; sets provider status/completion provenance, removes release-on-commit, stages stream outcome or rejects/repairs stream headers. |
| `ai_semantic_cache.rs:5216` | B | Reads instance cache status; writes the cache-status field. |
| `ai_stream_router.rs:3674` | B | Reads owned provider/normalization claim, status and media/coding; rejects unsupported representations or stages provider coding and repairs normalized SSE headers. |
| `body_validator.rs:3242` | B | Reads response buffering applicability, request method and original event-stream witness; refuses unbounded response validation. |
| `openapi_validator.rs:1445` | B | Same method/stream/buffering gate, plus context-selected operation; `handle_violation` stages validation telemetry/disposition. |
| `waf/mod.rs:1936` | B | Initializes WAF metadata; reads request exemptions and response scope; synchronously scans header rules, updates scores and instance digest; refuses an unbounded governed stream. |
| `ai_response_guard.rs:3408` | B | Reads native-gRPC classification, response applicability, method and original-stream witness; stages uninspectable disposition/refusal. |
| `response_size_limiting.rs:171` | B | Reads method, status, Content-Length and original-stream witness; rejects ambiguous/over-limit length or an unbounded required buffered check. |
| `response_caching.rs:3535` | B | Reads pending invalidation/status, cache-status metadata and staged Vary/caller policy; applies invalidation and publishes status/Vary. |
| `grpc_web.rs:4814` | B | Moves staged trailer/shadow fields into metadata; reads rejected-accept, translation-owner/original media and provenance state. Stages HTTP/unframed-error status; writes client media/Vary/expose headers and authored-field provenance. |
| `mcp_gateway.rs:7634`, `bridge_after_proxy:2253` | B, replacement capability | Reads instance/tool-result/bridge claims, response media/coding/length and backend failure provenance. Can stage a bridge observation/conversion, JSON-RPC terminal and repaired fields, or refuse uninspectable tool results. `may_replace_rejection_response=true` does not itself enable the default-false reject gate. |
| `transaction_debugger.rs:1131` | B | Reads method/path, redaction and response-capture posture; emits redacted response-header/capture diagnostics. |

The remaining current built-ins inherit the no-op async default and default-false
reject gate. They perform no raw reads/mutations before or after await in
`after_proxy`: `request_termination`, `mesh_outbound_registry`, `ip_restriction`,
`geo_restriction`, `bot_detection`, `grpc_method_router`, `spiffe_identity`,
`mtls_auth`, `jwks_auth`, `oauth2_introspection`, `jwt_auth`, `key_auth`, `ldap_auth`,
`basic_auth`, `hmac_auth`, `soap_ws_security`, `access_control`,
`tcp_connection_throttle`, `mesh_authz`, `opa`, `adaptive_concurrency`,
`request_deduplication`, `request_size_limiting`, `ws_message_size_limiting`,
`graphql`, `ws_rate_limiting`, `udp_rate_limiting`, `ai_prompt_shield`,
`fault_injection`, `ai_semantic_firewall`, `ai_request_guard`, `ai_tool_governor`,
`mesh_route_dispatch`, `request_transformer`, `serverless_function`,
`response_mock`, `grpc_deadline`, `load_testing`, `request_mirror`,
`ai_prompt_compressor`, `ai_token_metrics`, `stdout_logging`, `ws_frame_logging`,
`statsd_logging`, `http_logging`, `tcp_logging`, `kafka_logging`, `loki_logging`,
`udp_logging`, `ws_logging`, `proxy_alerts`, `prometheus_metrics`,
`api_chargeback`, `api_chargeback_sink`, `__mesh_bpf_metrics`,
`transaction_log_schema`. Their other lifecycle hooks are separate contracts and
are not safe to invoke as substitutes for rejection preparation.

Wrapped/opaque cases complete the inventory:

| Contract / source | Before first await | After first await |
| --- | --- | --- |
| `PluginInstanceWrapper`, `src/plugin_cache.rs:1442` | Calls `runs(ctx, PostAuth)`; memoizes the instance trigger and skips false. Then invokes inner `after_proxy` once. Delegates reject/replacer capabilities. | All inner accesses remain permitted; wrapping does not narrow its mutable context borrow. |
| `DeferredCorsPlugin`, `src/plugin_cache.rs:332` | No-op `after_proxy`, reject gate false; actual finalization belongs to the distinct CORS finalizer. | None. |
| `MeshRouteDispatchFinalizer`, `src/plugin_cache.rs:381` | Inherits the no-op/default-false hook; its unmatched-route work is request-phase only. | None. |
| Composition-only wrappers in `src/plugin_cache.rs` | Inherit the default no-op, with no reject enrollment. | None. |
| Public default, `src/plugins/mod.rs:10933` | Continue; no context access. | None. An override has the unrestricted contract. |
| Custom factories, `custom_plugins/mod.rs`; any injected `Arc<dyn Plugin>` | Arbitrary supported context/body/header reads, rewrites, clones, private state and external effects; may opt into rejection and replacement. | The same accesses/effects remain supported. There is no inspectable universal inventory of opaque code. |
| Example, `custom_plugins/examples/example_plugin.rs:266` | Synchronous configured response fields, default-false reject gate. | None in this example; it does not constrain other custom plugins. |
| Example audit, `custom_plugins/examples/example_audit_plugin.rs:818` | Inherits the no-op/default-false hook; its separate observer hooks do not establish an opaque rejection contract. | None in `after_proxy`. |

`PluginTriggerGate::admits_request` (`src/plugins/trigger.rs:192`) reuses the
private per-instance decision or evaluates and memoizes the first eligible
PostAuth decision. A false decision writes only the bounded skip marker.
Identity-reading PreAuth gates run without deciding; read-only capability
queries with missing decisions report "runs". `HttpTriggerFacts:438` reads
method/path and authoritative identity from the context, pristine wire headers
(folded headers only without a wire map), query/cookie facts and frontend
protocol/authority/scope. It never treats public metadata as trigger authority.
Preparation must carry these private decisions, rather than bulk re-evaluating
triggers against a later response or a reconstructed metadata map.

### Limiter's suspension inventory

`ai_rate_limiter::after_proxy` records genuine backend status only outside
rejection and only for a reserved instance. Federation reconciliation reads
actual tokens and the original federation status and claims the instance's
federation-recorded flag **before** await. Gateway refusal releases only when
`should_release_gateway_rejection` proves no successful backend consumed tokens.
An ordinary non-2xx backend response has its own release branch.

`reconcile_usage` (`ai_rate_limiter.rs:1094`) reads the reservation count/id,
window index/backend and identity/IP rate key. It sets actual-token/release
ownership markers before `adjust_usage(...).await`. After that await it can:

- Re-read identity/IP with `rate_key(ctx)` for local accounting on unavailable
  centralized enforcement; use the original reservation provenance; update
  local-accounted metadata and counters; return the fail-closed status when
  replacing a successful response remains possible.
- Write exposed per-instance limit/window/remaining/usage via `store_metadata`.
  The non-2xx release and unmetered `Warn` branches also write these after
  their respective awaits.
- Return into the parent hook, which reads response media/coding, AI-call,
  compressed-candidate, reservation and unmetered markers; stages encoded-stream
  and unmetered disposition; optionally refuses unreserved unmetered streams;
  copies exposed headers from the updated metadata.

For usage-less successful federation responses, `reconcile_usage` also reads
the AI-request and compressed-candidate markers and sets the unmetered-action
marker before any suspension. `ChargeEstimate` keeps the reservation (or
refuses an unsafe compressed zero estimate); `Reject` refuses synchronously;
`Warn` invokes the same `adjust_usage` release once and then writes the returned
metadata. Those mode decisions are reached instead of, not after, its
actual-token/non-2xx reconciliation branches. The parent hook's post-await
response/header decisions still follow whichever reconciliation branch ran.

No branch reads `request_body_bytes` or `metadata["request_body"]` here.
`classify_request_tokens` does read raw text, but runs during request admission,
not in `after_proxy`/`reconcile_usage`. Preparation can freeze the key and
reservation facts and produce a typed reconciliation operation; cleanup still
needs its post-await result patches and response decisions. Merely moving the
existing mutable-context reconcile future to another task retains the defect.

### Audit capture, method/framing and sink decisions

`ai_transcript_audit::after_proxy` has no await. `request_capture_route:3123`
uses native-gRPC classification and `grpc_method_path:3088`, preferring
`grpc_full_method` over `ctx.path`. It therefore sees the client method before
routing, or the backend-effective method after deferred routing. An enrolled
candidate refuted by that method is discarded; a gRPC-owned unenrolled body is
never interpreted as HTTP JSON.

`capture_short_circuit_grpc_request:3426` prefers the live peer-rewritten UTF-8
text, temporarily taking/restoring it, then falls back to the charged binary
Bytes (including non-UTF-8 protobuf). The helper receives no finalized header
map and uses the candidate's staged encoding/framing witness. A genuine
pre-finalization short circuit has no final map; a partially reached final
chain must not be mistaken for that case.
`capture_staged_request:4013` reclassifies the final HTTP view, preserves staged
MCP classification, refreshes stream/model/tool data, and respects sampling,
scan and retained-byte limits. `AuditStaging::captured` is instance-owned and
prevents a second expensive capture pass. In contrast, `MD_FINAL_REQ_SEEN`
(`ai_transcript_audit.rs:488`) is shared request metadata, written by any active
audit's final-request hook (`5101`) and checked by each audit's `after_proxy`
(`5213`). It is not evidence that this instance completed its final hook.
Capture storage has its own retained-byte lease, independent of upload admission.

A partial final-hook chain exposes the distinction: audit A completes capture
and writes the shared flag; an intervening final hook rejects; audit B's final
hook never runs. B retains provisional, uncaptured staging, but A's shared flag
suppresses B's reject-path capture/refutation. With request capture enabled and
response capture disabled, B's synthetic final-response fallback returns early
(`on_final_response_body:5334`) and cannot rescue that request capture. The
existing implementation therefore does not guarantee one authoritative decision
for every eligible audit instance. This inventory correction is **not a fix**.

The proposed preparation needs completion keyed by stable instance identity:
unfinished, captured (including its bounded sampling/omission outcome), or refuted.
Unfinished includes an unreached final hook whose backend-effective method now
enrolls a previously unstaged candidate; preserve that existing final-hook
transition as well. A completed instance must never re-read carried pre-transform
metadata. An unfinished instance needs the authoritative method, body and header
view of the phase actually reached before rejection. If the final-body chain
began, that is its fully transformed body, backend-effective method and finalized
hook header map, even when B's own hook was not reached. A genuine pre-finalization
short circuit instead uses the live peer-rewritten text/binary and staged framing
witness under the existing method rules. Core must explicitly carry which phase
and view were reached; neither the shared flag nor a reconstructed `ctx.headers`
map proves it. No per-instance completion carrier or reached-view handoff is
implemented here. Ordinary backend capture remains at the existing final hook;
the proposal must preserve its digest, enrollment/refutation and no-recapture
semantics while completing each unfinished eligible instance once at its ordered
preparation position.

Capture happens before the replaceability check. An already-fixed nonreplaceable
response does not claim an ignored sink refusal. For a replaceable response,
`stream_fail_closed_rejection:2867` and `ensure_commit_admission:2715` inspect
response status/media, per-instance sampling/admissibility, logger capacity,
commit lease and sink health. They can return 503. This decision is distinct
from capturing the request. **Core currently skips the entire active audit hook
as a response replacer after a deadline**; later detached cleanup also skips
replacers. Thus simply polling all non-replacers cannot guarantee audit capture.

Audit request capture does not call limiter reconciliation or consume its
reservation outcome. Moving it behind a pending limiter preserves the old
retention bug; moving all response/sink decisions ahead of reconciliation can
change their response input. The proposed split must separate raw capture from
those response-dependent decisions explicitly.

## Proposed phase contract and algorithm (not implemented)

The narrow proposal is synchronous preparation for rejection and charged
terminal handling, with a separate async cleanup hook. Ordinary
successful-backend `after_proxy` stays on its existing contract. New names/types
below are design placeholders. Preparation enrollment must cover both the
reject-gated runner and every non-replacer visited by the ordinary ladder's
charged-terminal branch; preserving that third constructor site with the old
opaque future would leave P2 open.

1. Transfer/drop every redundant caller/replay upload owner through the existing
   retirement handoff. Retain one authoritative raw view solely for preparation.
   Never clone a full context into an async rejection future.
2. Walk the effective pinned chain in its existing order, preserving scope,
   protocol filtering, stable instance identity and priority overrides. The
   wrapper evaluates/reuses its PostAuth trigger at that instance's position;
   memoized false performs no capture, staging, reservation or external call.
   Undecided/missing state retains the existing fail-closed trigger semantics.
3. `prepare_rejection` is synchronous, with no async operation/first-poll adapter.
   It completes all raw reads and rewrites at that ordered position. Audit
   captures per instance at its position regardless of a pending limiter stage;
   capture enrollment, peer text precedence, binary framing and retained limits
   use the existing helpers with the reached-view and per-instance completion
   rules above. A partial final-hook chain cannot use another audit's shared
   flag to mark this instance complete. An authoritative terminal can suppress
   replacement without suppressing otherwise-authorized raw capture. This
   distinction is an explicit proposed behavior change, not an existing guarantee.
4. Prepare limiter reconciliation from its original instance/reservation/key,
   federation/backend status and usage facts; claim release/charge ownership
   once, but do not wait on Redis. Separate response-dependent decisions from
   raw-dependent capture. Stage any later sink decision with its record/permit
   identity and immutable method/framing facts, not with raw bytes or a context.
   Earlier asynchronous replacement/result patches must feed the later
   response/sink decision in order; a bulk preflight of all such decisions is
   insufficient. Preserve exactly-once OIDC cookie consumption, spec HEAD,
   compression negotiation/admission and route-header finalization.
5. Retire `request_body_bytes`, raw text and collector charge from every
   core-owned context and transport/replay owner **before the first await or
   task detachment**. A staged cleanup future may own only bounded typed state:
   limiter operation facts, audit staging/commit leases, closed response patches,
   trigger carrier and terminal/authorization plan. No `RequestContext`, raw
   Bytes, collector charge, unrestricted metadata clone or raw-view closure is
   admitted. The concrete admission/accounting requirements below cover both
   retained state and produced output before construction. New caps or refusal
   outcomes require explicit design/owner agreement.
6. Drive prepared operations in order on the response path under the existing
   deadline rules; after terminal selection continue only eligible cleanup on
   that same prepared operation. Never invoke or restart external work through
   a second `after_proxy` call. For charged terminals retain independent
   single-hook detachment, while later immediate decorators still decorate.
   For gateway deadline cleanup retain ordered continuation. Keep the earlier
   authorization/five-second cleanup bound, expiry-first polls and tie rules.
   No preparation/capture or protected cleanup starts after authorization
   expiry; no deadline extension or late full capture is proposed.
7. Apply allowed staged response patches only before commitment, preserving
   gateway provenance, terminal precedence, body/header re-decision and final
   method/status wire shape. Ignore detached response patches. Committed
   observers consume staged captures and the final selected response, never raw
   uploads. H3 still offers HEADERS before STOP_SENDING under its write grace.

This can express the inspected built-ins' raw dependencies, but is not yet an
implemented preservation proof. In particular result/header/sink decisions after
limiter I/O must remain ordered. Arbitrary post-await raw mutation, identity or
method/trigger mutation affecting later preparation cannot be represented by a
raw-free cleanup operation. A default method that delegates the old async hook
would reintroduce exactly that problem.

### State/output admission and ordered results to approve

The owner question includes these bounded representation requirements, not just
the name of a new hook. For a pinned chain of `N` eligible instances, allocate at
most one operation slot per instance and one current selected-response carrier;
never copy the remaining chain or response once per operation. At config load,
each conforming participant must declare finite control-state and result-output
byte ceilings, including owned string/vector/map capacity and fixed overhead.
The reservation is `carrier_bytes + N * slot_bytes + sum(control_i + output_i)`,
using checked arithmetic and counting capacities/overhead, not just string lengths.
Existing separately leased audit/response storage counts in its own budget and
must not be copied outside that lease. A shared finite preparation budget must
admit that reservation before materializing any new state. The owner must approve
its numeric aggregate cap and exhaustion disposition before implementation; no existing upload budget
or five-second timer supplies this missing admission contract. Unbounded or
undeclared participant ceilings make that composition unsupported at load time,
not implicitly trusted at runtime.

| Staged owner / output | Concrete bound and preservation requirement |
| --- | --- |
| Chain slots, trigger/completion carrier, terminal/authorization plan | Exactly `N` fixed slots; one private trigger decision and one capture/refutation outcome per instance. Closed enums and fixed identifiers; no metadata-map clone or raw-view closure. Slot storage and handles count in the preparation reservation. |
| Limiter operation and result | Freeze the exact rate key, reservation id/window/backend, token counts and original identity provenance once. Charge key/id capacity under the declared control ceiling before copying; do not truncate/hash into a different rate key. One external invocation and one bounded result containing numeric telemetry, enforcement disposition and closed patches. Existing rate-store entry limits do not bound this staged key. |
| Audit capture/commit state | Keep the existing instance staging permit and byte/commit leases rather than a second uncharged record copy. Preserve configured request/response excerpt ceilings, aggregate capture hard cap 2,097,152 bytes, model cap 256 bytes, tool-name cap 64 names / 128 bytes each / 4,096 aggregate bytes, and redaction scan cap at most 8,388,608 bytes. Existing `limits.buffer_max_bytes` (hard maximum 268,435,456 per instance) and `limits.max_entry_bytes` (hard maximum 16,777,216) still gate staging, serialization and queue/batch copies. Those leases are separate from the new control reservation and upload admission. |
| Response headers, cookies and deferred decisions | Declare a finite byte/entry ceiling for each patch, including Set-Cookie append values and all header-name/value capacities. Reserve before producing a patch; apply into one bounded response carrier. Preserve exact cookie consumption, CORS sanitation/decoration with Continue, compression votes and route finalizer position. No arbitrary metadata patch or identity/method/trigger rewrite is admitted after await. |
| Replacement body and sink serialization | Use the selected response's existing finite buffered ceiling/admission, with a finite fallback when that surface otherwise permits zero/unlimited, and the audit's exact bounded writer/queue reservation. Reserve output before construction, retain its charge through replacement/clones, and release discarded output once. Never stage full raw uploads as replacement state. Any new fallback/refusal requires owner approval, not silent adoption of 503/gRPC 14. |

An ordered result driver retains a cursor and applies operation `i`'s result to
the current selected status/headers/body before evaluating operation `i+1`'s
response-dependent action. Audit raw capture settles during preparation, but its
sink/replaceability decision consumes that current response and its own staged
capture/lease only when the cursor reaches it. Limiter unavailable/local-accounting
and exposed-header patches cannot be bulk-applied after later sink decisions.
The wrapper's private trigger decision and capture completion remain fixed; a
result cannot re-enroll, rehash or refute another instance after raw retirement.
Replacement follows existing provenance/terminal precedence and body/header
policy re-decision; CORS only sanitizes/decorates the selected response.

When a terminal is selected, the same once-started operation may continue as
eligible cleanup; it is not reconstructed or invoked again. Gateway cleanup
retains its ordered cursor. Charged-terminal independent detachment keeps a
bounded operation-local carrier and discards its response patches, while later
immediate decorators retain the selected terminal. Cancellation, authorization
expiry and the cleanup bound must release every control/output/commit lease
exactly once. This is a required algorithm and accounting proof for the future
implementation, not a claim about today's opaque detached futures.

## Minimal owner decision and exact affected cases

ROOT should ask the owner to approve a **plugin contract change for rejection
and charged terminals**:
all raw request access/mutation and preparation-visible facts must settle in
synchronous ordered preparation; async cleanup accepts only the bounded staged
state described above. Admit an effective HTTP-family chain only when every
potential rejection or charged-terminal participant declares and satisfies that
contract. Opaque
plugins cannot become trusted by reporting a built-in name or by wrapping an
inner plugin. A wrapper must propagate the actual inner declaration. There is
no silent legacy fallback, polling heuristic or narrowly settled-path exception.

The reviewable question is whether the owner approves that withdrawal of
post-await raw/preparation-fact access, the per-instance/reached-view completion
rule, finite declared state/output admission and the ordered result algorithm.
Before code is authorized, record the numeric shared preparation cap and exact
capacity outcome, inventory every migrated built-in/wrapper/custom example by
source symbol and declared ceilings, and identify affected opaque compositions.
Migration must implement distinct preparation/result operations; an adapter
that forwards the old mutable-context future is nonconforming. Approval of this
document alone is not evidence that any participant has migrated or P2 is fixed.

The affected custom/injected instances are those opting into
`applies_after_proxy_on_reject`, or non-replacers reachable in
`run_after_proxy_hooks` over a charged backend terminal, that read, rewrite,
clone or retain raw text, binary/charge owners, request headers/method/path/identity
or trigger/capture
inputs after suspension, or rely on an earlier peer doing so; also those that
require external I/O before choosing a raw rewrite or audit enrollment. They
must move that work into synchronous preparation with bounded staged cleanup,
or their affected HTTP/H2/native-H3/bridge/gRPC/gRPC-Web compositions
become unsupported. Priority-only and trigger wrappers do not exempt them.
Leaving rejection disabled alone is insufficient because of the ordinary
ladder's charged-terminal path. A custom hook outside both terminal invocation
sets, ordinary successful-backend behavior and successful WebSocket handshake
decorators are outside this narrow withdrawal. The synchronous configured-header
example needs no post-await raw behavior migration, but still needs an explicit
terminal preparation declaration where reachable. No change to unrelated
stream hooks is proposed.

If the owner keeps the unrestricted opaque contract, this architecture cannot
fully fix P2. That is a concrete design incompatibility requiring a chosen
profile, not an automatic external blocker. Keeping a bounded raw-retention
exception would leave P2 unresolved and cannot support complete-remediation
claims. The unresolved early-route selection profile in
`early_upload_policy.md` is a separate owner decision.

## Required preservation witnesses after owner approval

Hosted regression requirements for the future implementation:

- A real limiter operation held pending by a barrier, with audits both before
  and after it, multiple instances, priority overrides and true/false/undecided
  triggers. Audit capture must be complete and exact before that first await;
  a second actual charged upload must be admitted while cleanup is pending.
- Peer-redacted text versus non-UTF-8 native-gRPC fallback; client versus
  backend-effective enrolled/refuted method; staged framing/encoding, MCP
  classification, final-body-seen and one-capture guards. Retain the strict
  existing digest/excerpt witnesses in `ai_transcript_audit_tests.rs` and the
  functional native-gRPC short-circuit audit test.
- A partial final-request chain with request capture enabled, response capture
  disabled, two differently configured audit instances and a rejecting hook
  between them. A has completed its final capture and set the existing shared
  flag; B has provisional uncaptured staging and never entered its final hook.
  The future preparation must preserve A's exact keyed digest without rehashing
  and capture or refute B exactly once from the reached authoritative body,
  backend-effective method and finalized headers/framing. Exercise distinct
  audit keys/enrollment/redaction settings, enrolled-to-refuted method changes,
  non-UTF-8 gRPC versus peer-redacted HTTP text and strict sink full/unhealthy
  decisions over the ordered selected response. Assert each instance's digest,
  method, encoding/header witness, excerpt/discard and queue/commit lease outcome;
  count capture and sink invocations to forbid double capture. The shared flag
  alone and a response-body fallback must fail this control. Keep ordinary full
  final-chain backend capture as the companion preservation case.
- Limiter federation success/error, usage-known/unmetered, genuine backend
  2xx later rejected, non-2xx release, Redis unavailable/local accounting,
  independent instance leases and exposed headers. Count the external
  invocation and reservation reconciliation exactly once through cancellation
  and both detachment modes; never charge a provider call as free.
- Later response/sink decisions see earlier staged results in order, including
  fail-closed sink health/full queue, ignored nonreplaceable refusal, response
  replacers, rotated Set-Cookie, HEAD/spec, compression 406/permit ownership,
  route transforms and final response policy. Trigger/capture preparation must
  not be gated on reconcile completion or replacer eligibility.
- Expired-before-start, exact ties, mid-operation and delayed-wake RPC/route/
  authorization bounds; charged terminal independent detachment versus ordered
  gateway cleanup; pending/cancelled cleanup and final-owner release. No raw
  field/charge or full-context clone in any staged/detached object.
- Real H1/H2, native H3 and H3 bridge commitment/flow-control seams, with all
  existing timers, caps, trailers, protocol assertions and request-guard lifetime
  preserved. Unsupported opaque post-await examples must fail composition
  admission explicitly; conforming preparation plus cleanup runs once.
- Reserve-before-copy and reserve-before-output controls at each declared ceiling
  and aggregate exhaustion boundary, including oversized limiter keys/cookie
  patches, audit serialization expansion, cancellation and detached lease drop.
  Publish the migration inventory, reservation arithmetic, raw-owner/type audit
  and exact pushed-head hosted results for every invocation set and protocol.
  Structural scans supplement actual held-pending operations and second-upload
  admission witnesses; they cannot stand in for them.

Do not mark P2 fixed based on an empty original context, a lexical permit drop,
a future-size assertion or a bounded cleanup timer. No whole-process RSS bound,
published patched version or advisory qualification is claimed here. **P2 remains
open, and the HTTP 503/native-gRPC UNAVAILABLE (14) profile remains unqualified.**
Unrestricted opaque raw context access after await is still supported today.
Any future public hook/capability change also needs custom-plugin/lifecycle
documentation and the ferrum-contracts plugin-catalog handoff; ROOT owns the
release note.
