# Rejection preparation implementation status

PR #6011, issues #6008/#6009; continuation round 36 completes interrupted round 35,
preserving rounds 20–34.
**Draft subset only. P2 remains open; the whole approved contract is not implemented or qualified.**
The owner approved the complete 883-line round-17 contract identified by SHA-256
`641067eed12615706ff40f2ec81d5797bd379753e905b16ec265f02bedf60346`.
No further policy approval is requested. The separate unresolved-route HTTP 503 /
native-gRPC 14 profile remains pending. The capacity HTTP 503 / native-gRPC 8
profile is approved; interim refusals below are not final qualification of it.

## Implemented runtime boundary

- The actual protocol-filtered R/C union compiles into a generation-owned,
  exact-N out-of-line manifest (N at most 64). R includes reject delegates; C includes ordinary
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
  `TerminalResult` variants are Noop, Fields, EmptyBody, moved Cookie and sealed
  BodyValidator and AiStreamRouter response decisions. Their owner contains no
  plugin/context/raw body/collector/closure/future. The whole
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
- Field patches and cookies use allocation-backed action tables and exact-length
  copied blocks. The locked allocator's `nallocx` supplies each layout's backing
  class before the shared credit permits `mallocx`; native backing drops before
  credit. No `capacity * 64` collection-layout estimate remains in this path.
  Whole-patch occurrence/arena preflight finishes before the selected carrier
  mutates. Each value carries producer instance, policy contribution, section
  and epoch before copying; identical configured overrides have their own
  origin, override-false retains the prior origin, and rename preserves origin.
  Legacy input enters as Unknown. Duplicate opaque cookie occurrences remain
  separate in the carrier. The legacy String/map export remains unqualified.
- Failed frontend admission emits static HTTP 503 JSON (empty HEAD content),
  native gRPC HTTP 200 Trailers-Only status 8, or exact binary/base64 gRPC-Web
  status-8 trailer DATA profiles with canonical content type/expose/Vary fields.
  H1/H2 drop the request intake before return; H3 stops intake after its bounded
  terminal write. The wire values/body are static and invoke no plugin or
  recursive rejection chain. The HeaderMap constructor still allocates:
  pre-owned emergency backing and its independent 4,096-byte proof are pending.
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
| `rate_limiting` | Identity-field removal and three checked numeric telemetry fields; approved C 1,024 / O 4,096 restored. Valid long leading-zero values are retained when they fit actual O credit; no 20-digit input assumption. No new Redis operation here. |
| `security_headers` | Config-derived exact field/action output, at most 65,536; C 1,024. Oversize refuses the whole composition rather than omitting/quarantining this security participant. |
| `oidc_relying_party` | Check staged capacity, copy into charged exact-length backing, then retire the staged String once; C/O 16,384 each. Suppressed actions do not consume it. |
| `spec_expose` | Consume the HEAD marker once and emit EmptyBody; C/O 1,024 each. |
| `ai_semantic_cache` | Closed cache-status field; C/O 1,024 each. |
| `ExamplePlugin` | Custom two-field patch built with admitted credit; C 1,024 / O 16,384. |
| `cors` / `__cors_finalizer` | Borrow reached aggregate policy facts into a closed field patch; C/O 16,384 each, W 0. Direct instances and cache finalizers declare real configured output sizes; deferred wrappers retain inner declarations and wrapper credit. No raw context, policy-list clone or old-hook adapter escapes preparation. |
| `ai_stream_router` | Complete claim-owned terminal media/coding decision and representation repair; C 4,096 / O 8,192 / W 0 for all configurations. Private owner/provider facts prepare synchronously; current selected response fields decide at the cursor. HTTP-only C non-replacer; no new rejection eligibility. |
| `body_validator` | Complete terminal SSE refusal as a sealed response decision; C 1,024 / O 4,096 / W 0 for every configuration, including request-only protobuf. Current selected status/media and pristine origin evidence are cursor inputs; full-body validation is separate. |
| `mesh/workload_metrics` | Actual synchronous reject restamp and traceparent operation; C 16,384 / O 4,096 / W 0. Borrowed authenticated peer/header/config facts, composed CEL label requirements, sampling/B3/W3C state and capture-marker retirement; no cloned raw header map in the operation. |

The round-19 explicit no-op inventory remains. Pure candidate rows now delegate
to those same source-owned declarations. CORS candidate admission constructs the
actual policy, and its finalizer folds the complete configured sibling union.
Deferred wrappers return no response action while retaining the inner prepared
declaration; the mesh request-only sentinel remains a no-op.
No source-owned registry row trusts an arbitrary runtime `Plugin::name()`.

## Round-33 bounded production no-op declaration controls

This round reviews twelve concrete production implementations: `AdaptiveConcurrency`,
`AccessControl`, `IpRestriction`, `GrpcDeadline`, `StdoutLogging`, `RequestSizeLimiting`,
`BasicAuth`, `JwtAuth`, `KeyAuth`, `LdapAuth`, `MtlsAuth`, and `HmacAuth`. All twelve
already declared `PureNoop` at starting head
`8dd35e21d99c5ad306a59da5fb6f2631829eacf9`. The six auth types previously obtained
that declaration from a shared macro function. Each now owns its explicit source
declaration, passed as a required macro argument; sealed candidate admission uses
the same owning module. The macro grants no default no-op declaration to future
implementations. Existing request/auth/body/stream/WebSocket behavior is retained.
The other six declarations are unchanged.

New fixtures in the existing native `terminal_allocator_tests` hosted target
construct all twelve through production `PluginCache` with configured resource
IDs and priority wrappers. They check the exact no-op manifest charge, zero
workspace, measured native operation-slot backing, one-time execution, distinct
configured instances, and refusal of a foreign cache generation. A custom plugin
with an overridden side-effect hook and a reported `key_auth` name still refuses.
Actual `TransactionDebugger` and `AiRateLimiter` implementations still refuse,
including configured nonmatching triggers. These controls are **HOSTED UNVERIFIED**;
no local formatter, compiler, test, validator, generator, or project tool ran.

Old-head run `37361364307` at `e7835cbcb8d52f887afd67ac9330748b33af534f`
contains nine failed jobs. Its cited adaptive/auth/Redis startup failures include
active `BodyValidator`, `AiStreamRouter`, `AiFederation`, `TransactionDebugger`,
`AiTranscriptAudit`, and `AiRateLimiter` peers. Those implementations need real
bounded typed terminal operations; none receives a no-op declaration here. This
round does not claim to repair those startup failures or migrate all participants.
Assertion-only failures, including native-gRPC status 14 versus 8, remain **UNKNOWN** until their actual
request generation pins and lifecycle are traced. Unrelated fixtures and expected
statuses are unchanged. Internal composition views, trigger/priority wrappers,
deferred CORS, the CORS finalizer, mesh request dispatch, and WebSocket sessions
retain their previous declaration/identity behavior; they are outside this twelve
type review.

All ten original acceptance areas remain **OPEN/UNQUALIFIED**, P2 remains open,
and the separate unresolved-route HTTP 503/native-gRPC 14 profile remains pending.
Round 33 could not locate the proposal under its ambiguous supplied path. Round
34 read the entire exact 883-line approved artifact at
`/Volumes/JeremyStorage/Dev/repos/GitHub/ferrum-edge/orchestration/2026-10-04-root/work/artifacts/edge6011-worker17-decision/rejection-contract-proposal.md`
and verified SHA-256
`641067eed12615706ff40f2ec81d5797bd379753e905b16ec265f02bedf60346`.
The artifact is present in the authorized Ferrum tree. The historical design
document is not substituted for it. ROOT owns exact-head hosted qualification
and the cross-repository catalog handoff. The round-33 handoff must continue to
describe actual implementation declarations, availability, wrapper/trigger facts,
eligibility, bounds, and configured instance identity, never trust reported names.

## Round-34 complete BodyValidator terminal hook subset

`BodyValidator` now owns a Prepared declaration and synchronous preparer. The
sealed built-in candidate row delegates to that owning declaration; the pure
finalized-request-policy admission view therefore carries the actual terminal
bounds for all configurations. Runtime configured instances, generations,
priority wrappers, PostAuth trigger facts and R/C eligibility retain their
existing identity and composition checks. Reported names confer no trust.
C=1,024, O=4,096, W=0 are the approved row, with one 256-byte slot and the
existing 512-byte wrapper allowance when wrapped. No parser, schema, descriptor,
raw request owner, plugin handle, opaque metadata, closure or future escapes
preparation. Request-only configuration remains Prepared, with a statically
false response-policy vote, rather than becoming a trusted no-op type.

The complete original `after_proxy` predicate is preserved: a configured
response-policy vote, non-HEAD method, body-permitting selected status, and
original event-stream representation produce the fixed 502 JSON refusal;
otherwise Continue. The operation stages only the static vote and HEAD boolean
at its ordered preparation position. Its instance nonce and thin shared ticket
are validated with the operation. `execute` moves the sealed decision into the
cursor; `decide` consumes it once against a ticket-bound selected carrier and
current status, checking destination custody before reading fields. It allocates
nothing. The refusal outcome is a closed enum exposing static bytes, with no
JSON tree, String, header map, dynamic body or separate allocation. Actual
operation/result types fit the approved C/O; fixed slot backing is planned from
`Option<PreparedTerminalOp>`, and carrier tables/arena/inline ownership remain
under their existing checked native allowances.

The carrier holds a three-state bounded origin fact: pristine SSE, pristine
non-SSE/absent type, or unstamped synthetic response. Synthetic media is read
from current selected fields after preceding cursor patches; pristine evidence
survives header rewrites and uses the existing case-insensitive media essence
predicate. Core refreshes the origin fact before each cursor action, after any
replacement/expiry handling, so clearing a replaced backend stamp selects the
current synthetic representation. The existing crate-private legacy ingress may
construct the one bounded carrier; it remains unqualified for full raw-map/wire
custody. No public raw destination or unchecked copier was added.

BodyValidator still has default-false rejection participation and default-false
replacer capability: it belongs to C, not R. R preparation suppresses its action.
C evaluates its real decision and discards a refusal so the charged terminal
keeps its original status/body, matching the old charged hook behavior. Ordinary
successful `after_proxy`, response-body buffering/refinement/final validation,
request validation, descriptor admission and representation-security hooks are
unchanged. Other unmigrated active types, including AiRateLimiter and
TransactionDebugger, remain strictly Undeclared.

Four added native hosted fixtures exercise production PluginCache HTTP/gRPC
instances, sealed pure candidate admission, response/request-only/protobuf
configuration, exact ordinary hook status/body parity, HEAD and all no-content
statuses, pristine SSE/non-SSE/absent type, media cases/lookalikes, prior selected
header effects, once consumption, actual slot/native bounds, foreign generations
and reordered configured instances before allocation, foreign typed destinations
before allocation/mutation, replay refusal, true/false configured triggers, C
terminal preservation and R suppression. Last-owner cancellation checks exact
native root deallocation and zero residual ticket/ledger usage. External unit
controls pin the real declaration/effects and refuse an opaque implementation
reporting `body_validator`. Existing no-op, active limiter/debugger, hazard,
64/65 participant, 1,024/1,025 ticket, capacity, custody and lifetime controls are
retained without changing workloads, statuses, timeouts, filters or skips.

These are bounded source changes and unexecuted hosted fixtures. They remove the
specific BodyValidator Undeclared source cause in the old e783 adaptive descriptor
startup path; its existing workload is unchanged, and no hosted pass is claimed.
All original acceptance areas **1–10 remain OPEN/UNQUALIFIED**, and **P2 remains
OPEN**. Exact-head formatting, lint, compilation, native allocator and runtime
results remain HOSTED UNVERIFIED. The approved capacity HTTP 503/native-gRPC 8
profile is distinct from the separately pending unresolved-route 503/14 profile.
ROOT owns independent review, all current hosted failures and exact-head gates,
landing and the ferrum-contracts plugin-catalog handoff for the Prepared
BodyValidator row and sealed response-decision capability.

## Rounds 35–36 complete AiStreamRouter terminal hook subset

The actual AiStreamRouter owns its Prepared declaration, including disabled,
normalization-disabled and OpenAI pass-through configurations. The sealed
candidate registry delegates to that function; security candidate construction
still uses the real instance. HTTP-only protocol membership, configured resource
identity, cache generation, wrapper credit, priorities and PostAuth triggers
retain their actual checks. Default-false R and non-replacer capabilities remain:
C evaluates the hook and discards its closed 502 refusals, preserving the selected
charged terminal; R suppresses the action. Names cannot grant this declaration.

Preparation borrows the private claim only to establish owning instance,
normalization eligibility and closed provider kind. The operation owns that
bounded scalar witness, configured nonce, output allowance and shared ticket.
It carries no provider request, credential, model, claim, context, map, raw body,
plugin, closure or future. It does not freeze selected status or headers.
The ordered cursor reads the actual ticket-bound carrier after prior effects.
It preserves canonical lowercase Content-Type lookup, provider-specific
Normalize/PassThrough/refusal rules, successful 200..299 status gate, duplicate
case-insensitive encoding refusal, empty/identity behavior, parsing-error
precedence, four-layer coding cap and exact gzip/x-gzip/br canonical metadata.
The complete fixed OpenAI 502 bodies are static bytes, with no JSON allocation.

The repair uses the shared validator/digest/signature/range inventory and both
open-ended checksum families, removes encoding/length, scrubs Accept-Encoding
from all Vary case variants with the existing wildcard/dedup/order rules, and
stamps SSE only when no existing case variant already carries SSE. All patch
layouts, full dynamic Vary backing, canonical metadata copies and metadata
custody backing are planned together before allocation/copy; the
approved O=8,192 is not raised. Exact values that exceed it refuse without
truncation. Existing carrier occurrence/arena/provenance checks remain.
Pristine media facts are unaffected by these header-only repairs; normal body
producers, buffering, replay, caching/security policy and stream transforms
retain their separate lifecycle and lease domains.

Supported coding leaves the cursor only as a closed inline canonical projection.
Core checks the originating request ticket and private provider owner before
applying either identity or encoded repairs and copying the one fixed metadata
key/value under remaining O credit and existing metadata custody. It refuses foreign table growth; no public mutable context/map
adapter or raw access under suspension is introduced. The legacy response map
import/export is still private and **UNQUALIFIED** for complete wire backing and
mixed provenance, exactly as before. This participant does not qualify that
common foundation or implement a new stream producer.

Four native jemalloc fixtures compare the complete ordinary hook with real
PluginCache/candidate instances, all four providers and configuration modes,
media/coding/status/casing/duplicate/Vary/invalidation branches and exact refusal
bytes. They exercise genuine private claims, foreign owners/generations,
reordered instances, trigger outcomes, prior selected effects, C metadata/header
application and refusal discard, R suppression, custody before allocation,
dynamic O refusal before allocation, once consumption, cancellation and last
native ticket backing. External unit controls pin actual declarations and
refuse an opaque active implementation reporting the same name. Existing raw
custody, cookie, CORS, BodyValidator, capacity and lifetime controls are unchanged.

This removes AiStreamRouter's specific Undeclared source cause in the old
adaptive route-override workload without changing that workload. Native fixtures
are authored, **HOSTED UNVERIFIED**. No local project execution or formatter ran.
All ten acceptance areas **1–10 remain OPEN/UNQUALIFIED**, **P2 remains OPEN**,
and the separate unresolved-route HTTP 503/native-gRPC 14 decision remains
**PENDING**. ROOT owns independent review and all exact-head hosted gates. The
ferrum-contracts plugin-catalog handoff must include this source-owned Prepared
row, actual C-only/HTTP-only capabilities, ENROLLMENT preparation, response and
telemetry cursor effects, exact bounds, configured generation/wrapper/trigger
identity and closed cursor/output projection. No cross-repository publication
is performed in this round.

## Round-36 source parity repair and hosted formatting evidence

The independent review16 finding is accepted: BodyValidator's static refusal
used `details` before `error`, while the unchanged ordinary hook constructs
`error` before `details`. The normal MongoDB dependency graph includes BSON
2.15.0, whose published manifest enables `serde_json/preserve_order`. The static
constant now preserves that exact insertion order. The strict actual-cache
assertion still compares `outcome.body()` with `ordinary_body.as_bytes()`;
neither JSON parsing nor semantic comparison substitutes for bytes. This is a
source-established correction, not an executed parity result. C still discards
the non-replacer refusal and R remains ineligible.

The same source inspection completed all seven AiStreamRouter fixed envelopes
in ordinary `message`, `type`, `param`, `code` order. The closed outcome exposes
the ordinary fixed rejection media type as well as status/body. Native parity
retains complete header checks and counts every refusal branch, four canonical
coding layers and genuine Gemini JSON normalization. Additional controls retain
the actual active type for absent private claims despite forged public metadata,
exercise simultaneous coding/repair output refusal before allocation, and drive
the real R runner with a response that would normalize in C. No ordinary runtime
error content or JSON construction changed.

Native CI Plan job `111972339866` in run `37370810904` failed formatting for
`a352db8bf3b567c751a3f042dcefdb94565a0d87` (its GitHub merge ref included base
`8f63dfdd58f904644f43f1eeffb114d7d7ad38a4`). All six printed formatter regions
were applied manually: the allocator imports, BodyValidator candidate arguments,
Prepared destructure, no-op chain wrap, two configured cache calls, and the
gateway-core Undeclared assertion. New additions were formatted by hand.
Dependent compilation/lint/tests were skipped after planning failed. Cancelled
or runner-absent workflows and failed dependency aggregates provide no runtime
qualification; no historical green or rerun is borrowed.

The combined continuation preserves the interrupted source/tests/docs and the
round-32 public custody, round-33 authentication declarations, round-34 bounded
BodyValidator/pristine SSE facts and strict controls. No local project execution,
formatter, workflow edit, manual CI trigger or rerun occurred. The new pushed
head remains **HOSTED UNVERIFIED**, all ten acceptance areas remain
**OPEN/UNQUALIFIED**, and **P2 remains OPEN**. ROOT owns the complete final diff,
fresh independent review, exact-head hosted gates, protected landing and the
ferrum-contracts plugin-catalog handoff. The separate unresolved-route 503/14
decision remains **PENDING**, distinct from approved capacity 503/8.

## Round-24 storage boundary and exact gaps

`terminal_storage` executes plans against the locked prefixed jemalloc, including
when a non-Windows library uses System globally. `Layout` includes actual typed
padding/alignment; `nallocx` includes the allocator class. Every generation block,
shared header, exact-N slot table, patch field and carrier table/arena claims its
backing before native allocation. Growth keeps old and candidate backing charged
until the old backing drops. The process ledger owns no block or ticket, so
block → ticket → ledger ownership has no strong cycle. A thin shared owner keeps
its original header alive without another allocation until the last clone.
Generation tables/header use the same 128 MiB ledger without request tickets.
Frozen protocol/eligibility/declaration/source references are selected once at
compilation; preparation does not query them again. Prepared field operations
must carry the current ticket and configured instance nonce; cookies must carry
the current producer nonce before they can enter the cursor.

The scoped workspace API lends initialized fixed backing only for the synchronous
callback. A higher-ranked borrow and sealed allocation-free return types prevent
scratch-backed views, parser trees, closures or futures from escaping as callback
results; backing drops before W credit. This does **not**
prove arbitrary parser heap allocations, captured callback state, or custom Rust
code bounded. Those require the reviewed private codec implementation.

The selected carrier checks the actual field table, simultaneous projection
table and root against 32,768 bytes, and the single byte arena against 98,304.
It holds 256 real occurrences and compacts in place after complete preflight.
It is retained by the immediate chain rather than reconstructed for each patch.
The crate-private prepared-chain legacy adapter validates the source payload's
ticket before preflight, then exports through existing maps. A raw map carries
no immutable destination ticket: this adapter is **UNQUALIFIED** for destination
custody and allocation backing. Public application uses only the typed selected
carrier, which validates against its own immutable ticket. No second arena is allocated.

Workload metrics stages its real UDP source-scope restamp through C credit, then
checks authorization and completes all String adoption before changing metadata.
Adoption requires the binary's explicitly registered matching global jemalloc and
spare existing metadata-table capacity; a System-global library or required table
growth explicitly refuses. Ordinary admitted successful hooks are unchanged.
B3 validation now borrows validated identifiers; new terminal trace IDs use
fallible fixed-buffer randomness through the existing crypto-provider seam.
No baggage tree is parsed on the restamp branch: the existing authorization
marker unconditionally selects the authenticated attesting-peer fallback.

The **complete common foundation is not yet closed**. Remaining gaps include:

- Transport handoff still constructs legacy Strings, HashMaps, HeaderMaps and
  dynamic HeaderName/Bytes owners outside the new allocation API. The ordinary
  three-map provenance recorder remains. Core diagnostics, sticky cookies and
  native-gRPC encoded cells are not migrated producers. CORS now has mixed
  Vary append segments and explicit identical-token co-ownership; other dynamic
  append/merge producers and the legacy wire export remain unqualified.
- Pre-owned emergency backing is absent. No 4 KiB emergency or complete 128 KiB
  wire-handoff proof is claimed. Existing earlier-authoritative terminal handling
  is preserved; no unresolved-route/native-14 policy was introduced.
- Existing plugin/config objects are constructed before these generation tables;
  their complete candidate/old configuration construction overlap is not charged.
  Generic context clones still copy legacy metadata Strings without obtaining
  additional backing credit. Custody pins cover adopted originals only.
- Body/decode retirement retains prior repairs, but raw request headers and all
  collector/replay siblings still need complete retirement proof. There is no
  reviewed typed external executor/detach factory or custody cleanup variant.
- Windows has no qualified nonzero storage allocator and refuses. Non-Windows
  explicit blocks have source-backed plans, but hosted linkage/layout/FIPS and
  complete participant proof remain pending. This is no universal Rust allocator
  or process-RSS claim. Unknown custom implementations stay undeclared unless
  they supply an actual bounded typed preparation implementation.

All ten approved runtime acceptance areas remain **UNQUALIFIED**. This round
adds actual storage and the first active Mesh participant; it does not authorize
landing the original P2 or claim the whole foundation, audit or Redis complete.

## Round-27 CORS startup repair and remaining qualification

The actual hosted mesh client log at source `b4850ffb` reports five materialized
outbound routes, one synthesized VirtualService CORS plugin, then terminal
`Undeclared` and fatal cache startup refusal. The fixture's `svc-cors` policy
belongs to the client-side outbound `svc` route; no example/custom plugin or
infrastructure failure is substituted for this source path.

Both actual CORS implementations now synchronously copy only admitted response
fields from borrowed private aggregate facts. Token joins and decimal max age
write directly into bounded storage, with allocator-class admission before
allocation. Static policy sizes are checked during chain compilation; aggregate
methods/headers account the configured sibling union, while exposure accounts
its intersection ceiling. Dynamic reflection and merges still refuse exact
output overflow. No cap, matcher, credentials, request decision, status/body,
WebSocket behavior or mesh operator profile changes.

The narrow carrier extension preflights open-ended prefix removal, all field
writes, Vary occurrence/value/byte limits and token-storage capacity before any
selected mutation. It inserts missing CORS tokens in-place in the sole arena,
retains opaque cookie occurrences and backend Vary segments, records ensures
satisfied by unchanged backend tokens, and preserves those records on rename.
Token storage derives from actual class-sized layouts inside the existing
32,768-byte overhead allowance. A foreign request ticket cannot apply a CORS
merge. Native-gRPC and HTTP terminal normalization and deadline ownership remain
with their existing core paths.

Added fixtures cover actual direct and cached finalizer instances, real native
mesh synthesis and Istio projection followed by cache compilation, priorities and conservative
trigger refusal, reload rollback, ordinary/typed policy parity, originless and
unmatched native/Istio states, credentials, stale prefix fields, wildcard and
case-insensitive Vary tokens, duplicate opaque cookies, atomic overflow,
foreign-ticket refusal, native allocation witnesses, raw-owner drop and
operations surviving context/plugin/cache drop. The actual rejection runner is
covered with HTTP/native-gRPC normalization and an elapsed deadline. Existing
CORS functional suites and strict assertions are unchanged.

These are **unexecuted hosted fixtures**, not qualification. Legacy String/map
export and transport ownership remain outside the allocation proof; this round
adds no claim that those existing adapters or the whole generation/config
construction overlap are charged. All ten acceptance areas, the complete common
foundation and P2 remain OPEN. ROOT owns exact-head hosted execution, independent
review and the ferrum-contracts plugin-catalog handoff for the new trait fact.
The separate unresolved-route HTTP 503/native-gRPC 14 profile stays PENDING.

## Round-30 request custody repair and its destination gap

Every direct selected-carrier field patch now validates its exact request ticket
before allocating a projection table or changing carrier state. This applies to
ordinary Set/Remove/Prefix actions as well as CORS Vary actions. The prepared
chain checks the source payload against its own ticket before legacy input
preflight or first selected carrier construction. This does not bind an arbitrary
raw destination map to that ticket. Existing configured-instance and generation
validation at preparation remains strict.

The unchecked public cookie copier is private to the checked native chain.
The free public field adapter that constructed a destination carrier using the
source patch's ticket is removed. The remaining chain methods were still public
and accepted an arbitrary raw map: source chain A plus payload A could mutate
foreign map B. The round-30 legacy negative fixtures only supplied A's payload
through B's chain, so they did not exclude this public destination-custody escape.
Round 32 restricts those adapters. Direct cookie append
continues to validate custody and retain each opaque occurrence and its lineage.
This is terminal cookie custody only, not an ordinary OIDC replay claim.

New reachable fixtures prepare two requests from one compiled manifest with the
same configured producer nonce and distinct admitted tickets. Ordinary
request-derived Set/Remove patches refuse B's direct carrier without any native
allocation, occurrence/lineage mutation, backing claim or ledger change, then
remain valid for A. The last extracted patch retains A's reservation and returns
its exact native backing and logical ticket sum on drop. Checked legacy field
and cookie routes refuse before malformed input preflight, with both fresh and
already selected carriers; B's maps, capacity and backing remain unchanged,
while A's remaining operations succeed. Existing duplicate-cookie ordering,
non-UTF-8 compaction, same-ticket field capacity and CORS controls now use checked
custody. Compile-fail API examples record the removed/private unchecked helpers.
The exact formatter region printed by the d980 hosted planner is applied.

These fixtures have not been executed locally. Exact-head hosted formatting,
compilation, lint and runtime results remain UNVERIFIED and are owned by ROOT,
along with whole-diff inspection and fresh independent review. All ten original
acceptance areas, complete wire/export allocation proof and P2 remain
OPEN/UNQUALIFIED. The separate unresolved-route HTTP 503/native-gRPC 14 profile
remains PENDING; this bounded repair does not qualify the whole contract.

## Round-32 public destination-custody boundary

`PreparedTerminalChain::apply_fields` and `apply_cookie` are now crate-private.
There is no public wrapper that accepts a raw destination map. Public field and
cookie application uses `SelectedTerminalCarrier::apply` / `append_cookie`;
the destination owns an immutable admitted ticket and checks the payload against
it before projection allocation or mutation. `new_selected_carrier` retains the
prepared request's original ticket. Existing generation/configured-instance
checks, cookie copier privacy, native backing/refcounts, caps, retirement,
source ordering, CORS and suppression behavior are preserved.

Public compile-fail examples use valid source-chain/payload/raw-map types and
attempt the actual forbidden A-source/A-payload/B-map calls for fields and
cookies. A positive typed API example accompanies them. The existing
hosted gateway-core CI lane now runs these doctests; no local execution occurred.

All external application fixtures now use the valid public typed destination API.
The combined negative control constructs independently admitted A/B requests
from one manifest and tests both fields and cookies against empty and full B
carriers. Full B first rejects its own payload with ControlCapacity (field table)
or FieldCapacity (cookies), then rejects A's payload with PinnedGeneration before
any native allocation. B's occurrences, lineage, token contributions, context
maps and backing, plus the logical ledger, are checked unchanged; consumed A
payload backing is checked against its exact native release. A's next same-ticket
payload succeeds, and last-owner release
returns the exact logical ticket sum. Existing direct A/B native-allocation and
extracted-owner lifetime controls remain. The legacy oversize-input fixture now
exercises the actual rejection runner, asserting the capacity terminal and no
partial field application; no raw adapter is exposed merely for tests. CORS and
metrics parity compare every typed occurrence, including duplicate cookies.

The crate-private legacy raw-map adapters/exports remain **UNQUALIFIED** for
destination-map custody and complete allocation/wire backing. This bounded
restriction does not complete participant migration, audit, Redis, raw-owner P2
or any of the ten original acceptance areas: all ten remain OPEN/UNQUALIFIED.
Exact-head hosted formatting, compilation, lint, doctest and runtime results
remain UNVERIFIED. ROOT owns hosted validation and any required follow-up. No
ordinary OIDC replay, complete export/wire qualification, new owner decision or
separate unresolved-route HTTP 503/native-gRPC 14 approval is claimed.

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
| Other active hooks | `response_transformer`/core route-header finalizer, `compression`, `sse`, `a2a_gateway`, `ai_federation`, `openapi_validator`, `waf`, `ai_response_guard`, `response_size_limiting`, `response_caching`, `grpc_web`, `transaction_debugger`, and the audit/limiter rows above remain Undeclared/refused in their effective HTTP R/C union. There is no opaque fallback. Configuring a currently unmigrated participant can reject an otherwise valid proxy config. |
| External operations / cursor | Add reviewed typed I/O/result/cleanup variants, selected-response scope and replacement/result replay, authorization/deadline rechecks before every external poll, independent finite detach summary, held-operation cancellation and once/paid-state semantics. The immediate driver is not an implementation of these requirements. |
| Provenance / final policies | Migrate mixed backend/gateway provenance, exact authored-field/cookie occurrence ownership and route finalizers under finite cursor credit; preserve every admitted terminal's final header/body policy and HEAD/CORS/compression semantics. Current legacy-lineage refusal must be retired by the full migration. |
| Complete teardown proof | Context retirement and existing retained-upload handoffs are connected, but every raw caller/replay/decode/collector/request-view sibling and cancellation site still needs exact-head real ownership proof. Committed-response/logging observers keep their existing separate lifecycle; no claim is made that their opaque state is a conforming typed terminal operation. |
| Capacity details | Pre-owned emergency storage, foreign header/map/name/Bytes owner backing and wire conversion overlap remain unimplemented. New constants and a charged arena do not qualify those legacy allocations. All key/prefix/Redis encoder and active participant temporary bounds still need actual migration. |
| Config / governance | Hosted full/delta/global/custom/trigger/pure-CP/admin/DB/DP publication parity is pending. Config-dependent declarations for every active hook are pending. Root must publish the edge-owned plugin-catalog contract handoff; this branch does not claim ferrum-contracts publication. |

`mcp_gateway` is a distinct existing case: its default-false reject gate plus
explicit response-replacer capability puts it outside the current R/C union.
Its ordinary successful-response lifecycle remains unchanged; no new terminal
operation is claimed. Configuring future terminal eligibility without a real
declaration will refuse it. Enabled inactive audits still conservatively refuse
until their config-derived no-op declaration is implemented.

## Round-24 source and hosted fixture inventory

The locked published archives were read statically and SHA-256 verified:

| Crate | Version | SHA-256 |
| --- | --- | --- |
| `tikv-jemallocator` | 0.6.1 | `0359b4327f954e0567e69fb191cf1436617748813819c94b8cd4a431422d053a` |
| `tikv-jemalloc-ctl` | 0.6.1 | `661f1f6a57b3a36dc9174a2c10f19513b4866816e13425d3e418b11cc37bc24c` |
| `tikv-jemalloc-sys` | 0.6.1+5.3.0-1-ge13ca993e8ccb9ba9847cc330696e02839f328f7 | `cd8aa5b2ab86a2cefa406d889139c162cbb230092f7d1d7cbc1716405d852a3b` |
| `http` | 1.4.0 | `e3ba2a386d7f85a81f119ad7498ebe444d2e22c2af0b86b069416ace48b3311a` |
| `bytes` | 1.11.1 | `1e748733b7cbc798e1434b6ac524f0c1ff2ab456fe201501e6497c8417a4fc33` |
| `uuid` | 1.23.1 | `ddd74a9687298c6858e9b88ec8935ec45d22e8fd5e6394fa1bd4e99a87789c76` |

The sys API defines prefixed `nallocx`/`mallocx`/`sdallocx`, matching alignment
flags and the sized-deallocation range. The allocator's global String
allocation/deallocation has the matching align-1 exact-capacity layout. In
contrast, `http` owns private bucket/index/extra tables and dynamic names, and
`Bytes::from_owner` creates a boxed owner: neither is proved by logical capacity.
`Uuid::new_v4` can panic on entropy failure; the new terminal helper avoids it.
No dependency, lockfile, release history, version or chart is changed.

`terminal_allocator_tests` installs the production global jemalloc in its own
hosted target. Fixtures read jemalloc's native per-thread cumulative allocated
and deallocated bytes, including direct native calls. Production code contains no
fixture allocation counter. The gateway-core CI shard precompiles and
runs this target. Fixtures exercise pre-allocation refusal at byte/ticket and
per-request pressure, last-owner release, exact N slots and small inline root,
65-participant candidate refusal with the prior generation retained, duplicate
actual-instance rejection, scoped W reuse, huge-capacity/tiny-value input refusal,
whole-patch atomicity and legacy refusal before mutation, identical-value
override/rename origins, non-UTF-8 retention, duplicate opaque cookies with
independent value limits, 256/257 real occurrences, long numeric telemetry and actual metrics
restamp versus its ordinary hook. These fixtures have **not** run locally.

## Tests and qualification

Round 22 repairs the two retired H3 rejection-provenance calls using checked
typed terminal entry rather than the buffered snapshot recorder. The shared H3
reject delegate retires context raw/decode views, refuses unsupported carrier or
mixed lineage before any committed observer, clears its temporary synthetic
marker and leaves the selected immutable response intact on refusal. Direct
gateway terminals preserve admitted native-gRPC correlation and wire fields.
The rejection runner also preserves a captured early-upload terminal when later
authorization expires at entry; it retires raw views and skips preparation and
cursor work while the outer final-header closure still runs. Ordinary
authorization-terminal selection remains unchanged.

External regressions exercise both actual delegates, including over-capacity
backing with tiny header values, normalization crossing 256 field occurrences,
mixed lineage, zero refused committed observers,
raw-owner/request-budget release and decode retirement, and an admitted pinned
typed chain with ordered preparation, suppressed replacement actions and no
typed execution or protected observer after later credential expiry. The existing
late-wake refusal fixture retains both RPC/authorization arms and all assertions;
the existing canonical H3 deadline fixture retains all wire/context assertions.
These repairs do not complete any of the open migrations above. Hosted
formatting, compilation and execution for the repaired head are pending.

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
