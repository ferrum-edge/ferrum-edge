# Early retained uploads: DRAFT remediation and supported-profile proposal

This entire change is a draft for issues #6008 and #6009. Deterministic route-total
selection restores the configured receipt-anchored HTTPRoute budget. The refusal
policy below is a proposed change to supported released profiles: **no owner
approval exists**. Root must review this proposal, obtain a fresh independent
source review, qualify the exact candidate in hosted CI, and obtain the owner's
profile decision before adopting or releasing it. This document is not approval.

The inspected released v0.9.11 commit is
`c764084b3b51c3f7ffde268c039688d35e49c553`. Its distribution was independently
verified. It still has the SOAP early-collection and native-H3 admission gaps.
GHSA-gxfv-924p-wvx4 is the active draft SOAP total-deadline advisory; its package,
affected-range and patched-version fields remain blank. Redis #5998 is unrelated.
No affected-version range beyond this inspected head, patched release, exposure
threshold or complete advisory remediation is established here. Preserve the
immutable v0.9.11 binaries, images, OpenAPI artifact and ferrum-contracts handoff.

## Deterministic selection

Immediately before a fresh early body collection, a private witness reads the
request's pinned plugin-cache generation. Cache reload compiles the effective
scope/protocol/priority chain and conservative mutation topology once. The pure
selector reuses the compiled mesh rule matcher and canonical outbound query,
projects Host authority rewrites/restoration without changing the request, and
keeps first matching rule semantics. Across instances, a later matching untimed
rule clears earlier timing; a later nonmatch preserves it.
The result explicitly distinguishes no match, untimed match, timed match,
terminal-before-publication and unresolved dependence. No minimum of unrelated
route timers is applied. No `before_proxy` hook runs early, even on a clone.

Redirects, deterministic terminal faults and waypoint destination vetoes do not
publish the selected rule's timer. Stochastic or delayed fault outcomes are
unresolved. Reload also caches whether node- or service-waypoint authorization
can publish a destination stamp; its pure wrapper projection preserves known
false triggers. Authentication and completed authorization are
distinct collector boundaries: a pending stamp makes a matching nonempty
destination unresolved even before the active-scope metadata is published. After
authorization, an available destination veto is terminal. An existing private AI route claim keeps
its normal precedence; a possible intervening AI claim is unprojectable.
Memoized wrapper trigger decisions retain their normal meaning. An undecided
identity trigger remains unresolved before authentication; post-authentication
facts can resolve it. Unprojectable header/query/destination mutations before the
last mesh selector remain conservative dependencies, even when a particular
request might happen to be unaffected. Destination publishers after that selector
also remain unresolved because they can replace the final routing policy. No
unrelated timer is substituted. Deferred hooks and the normal later arm/rearm retain
their existing execution order.

The witness computes only receipt + selected total. It publishes no destination,
authorization or routing override and starts no gRPC attempt. Normal later
selection still arms/rearms from the same receipt instant. A later non-gRPC
matched untimed rule can clear the total, or a longer total can extend it;
gRPC total folding only shortens the RPC budget and attempt timing starts later.

## Proposed owner decision: refuse unresolved collection dependencies

**Proposed terminal:** before reading or dispatching the required body, return
plain HTTP **503**, `Content-Type: application/json`, with the fixed redacted body
`{"error":"Request body policy cannot be resolved"}`. This is a gateway-local
policy refusal, neutral to circuit breaker, passive health, load-balancer penalty
and adaptive concurrency. It neither claims a timeout nor failed authentication,
exposes no route/identity/body/credential facts, and introduces no new gateway
error-header vocabulary. Native gRPC uses the existing status normalizer to emit
UNAVAILABLE (14); gRPC-Web uses its equivalent terminal trailer frame. Cleanup/decorators cannot replace the selected payload.
Final header policy gets one immediate poll while authorization permits it. If
that policy refuses or stalls, or a later authorization bound has elapsed, all
optional decorations are removed and only the fixed core terminal headers
remain. A rejected header is never published, and a later authorization/RPC
bound does not relabel the captured collector owner. Protected cleanup and
committed observers are skipped after authorization expires. Root must qualify
this terminal precedence as part of the proposal.
Terminal transaction logging uses the existing bounded detached delivery rather
than retaining the response task behind a stalled logging hook. Native H3 offers
the response before STOP_SENDING and bounds a stalled terminal write by the
existing post-deadline grace.

**Affected released profiles:** an HTTP-family proxy with effective
`mesh_route_dispatch` and a required fresh authenticate, authorize or
pre-`before_proxy` retained-body collector, when the final applicable total
cannot be selected from currently authoritative facts. This includes SOAP
UsernameToken, X.509 and SAML identity establishment with consumer/auth-method/
SPIFFE trigger dependence; body-derived AI routing or provider claims; deferred
or intervening header/query/destination mutation; pending scoped waypoint
selection; and stochastic/delayed route faults. An unrepresentable positive
route total also refuses; an unrepresentable read window requires another finite
bound to cap collection.
The conservative mutation check
may also refuse timestamp-only SOAP, HMAC or other early-body consumers in such
chains. It applies to H1/H2 and native H3, and to gRPC-flavored early collectors
when they have the same unresolved mesh dependence. A transport-proven empty
H1/H2 fast path requires no collection dependency decision. WebSocket,
Extended CONNECT, HBONE CONNECT and CONNECT-UDP exclusions are preserved.

Approval would explicitly withdraw support for those unresolved early-collection
cycles unless the chain is made deterministically selectable. Root must verify
this exact scope, including conservative false positives. The proposed code is
present on the draft branch so the owner can review a concrete result, but must
not be represented as an approved routing-profile change. Rejecting this choice
requires another qualified policy design; simply treating unresolved as untimed
or applying a minimum of sibling route timers does not complete remediation.

## Collection bounds and retained ownership

Route, existing RPC/protocol, one whole-collection read window and a genuine
accepted authorization deadline compose into one captured earliest instant and
owner. An absolute bound wins a read tie; accepted authorization wins its ties;
RPC keeps a route tie. Read zero disables only the read window.
Route `request_timeout_ms: 0` remains invalid; omission is an untimed match. Deadline-first
polling refuses an expired-ready body without polling it, and delayed wakeups
retain the earlier read/route owner. Pre-authentication SOAP acquires no invented
authorization plan. A plain route expiry is the existing **504** /
`X-Gateway-Error: request_timeout`, recorded `before_dispatch`, with no backend
contact or health charge. It never enters the gRPC-only finalizer.

All seven retained native-H3 handler drains and the plain-mesh / buffered-gRPC
bridge drains use RequestBufferPermit admission before allocation and the finite
buffered fallback at effective zero. The actual
allocation capacity is bounded, all Buf runs are counted, and a partial body and
its charge drop inside the cancelled/failed future before rejection hooks.
Capacity refusal is the existing 503 / gRPC RESOURCE_EXHAUSTED retained-request
contract. Completed bytes share the charge across plugin metadata, reuse,
backend handoff and retry clones until the final owner drops. No second upload
reservation is taken. Body-transform growth and text/decoded plugin working
sets retain their existing separate contracts; this change is not a claim that
the upload budget covers every plugin allocation. Streaming zero remains
unlimited; QUIC flow control is not an aggregate retained-body cap. Trailers and
H2 open-DATA GET/HEAD/OPTIONS without Content-Length retain their transport
semantics. HMAC still requires valid header preverification; timestamp-only SOAP
remains in its later phase; native gRPC/gRPC-Web folding and attempt clocks,
WebSocket and CONNECT tunnels retain their protocol contracts.

## Qualification and contract handoff

External controlled-clock tests exercise shared selection, receipt anchoring,
expired-ready nonpolling, read zero, read/route order and ties, delayed wakeup,
pinned reload, effective scope/protocol/priority order, terminal actions,
deferred destination dependence and identity-trigger refusal. The actual H3
collector seam also proves unresolved refusal before admission/body polling and
receipt-anchored gRPC folding without early RPC/attempt publication. The real shared retained collector
is tested for partial cancellation, over-ceiling failure, read failure, admission
before source polling and successful final-clone ownership. Real ingress tests
exercise UsernameToken/X.509/SAML and timestamp-only SOAP stalls through H1
chunked/Content-Length, H2 open DATA without Content-Length (POST/GET/HEAD/OPTIONS)
and native H3 terminal HEADERS, with backend, circuit-breaker and health
snapshots. Existing HMAC/gRPC/untimed and trailer regressions
remain required siblings. Structural parity supplements those behavioral checks.
No local build, formatter or test was run; hosted exact-head CI is the only gate.

**ferrum-contracts parity required for the next qualified release:** this change
touches `src/plugins/mod.rs`. Carry the early collector witness/projection
contract, request-timeout before-dispatch attribution, native-H3 retained-request
admission and the finally approved unresolved-profile disposition into the next
qualified contracts handoff. Do not rewrite v0.9.11 contracts or invent digests.
