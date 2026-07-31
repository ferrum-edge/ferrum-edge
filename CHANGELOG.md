# Changelog

All notable changes to Ferrum Edge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- API-spec YAML ingestion now expands anchors and aliases through a bounded
  libyaml event graph (node, depth, alias-reference, expanded-byte, and work
  budgets) with cycle / undefined-alias / duplicate-anchor /
  duplicate-mapping-key detection before JSON conversion (#3307). The expanded
  byte budget is a fail-closed upper bound on the compact JSON representation,
  including string/key escaping. Merge keys are applied when present. JSON and
  YAML share the same expanded-node admission cap so autodetection cannot
  weaken checks. Expansion also fails closed on non-core/local YAML tags,
  non-finite numbers, and integers outside the exact JSON `i64`/`u64` range.
  Scalar number and boolean mapping keys keep the stringified spelling the
  previous `serde_json::to_value` conversion produced (`200:` → `"200"`), so
  YAML that leaves status codes unquoted still ingests and already-stored specs
  still restore.
- Istio Telemetry `accessLogging.filter.expression` now supports bounded boolean
  expressions with `||`, `&&`, parentheses, and the existing `response.code`,
  `response.status`, and `response.duration` comparison atoms. `duration` is
  accepted as the documented latency shorthand, and duration thresholds accept
  integer milliseconds by default or explicit `ms` / `s` suffixes with checked
  millisecond conversion. Pure conjunctions continue to compile into flat
  `AccessLogFilter` fields; expressions containing `||` compile into a
  pre-evaluated `expression` AST consumed by the injected `stdout_logging`
  plugin.
- Machine-readable vendored-patch lifecycle inventory at
  `docs/vendored-patch-lifecycle.json`, enforced on every PR and weekly
  `dependency-audit` run by `scripts/check_vendored_patch_lifecycle.py`. The
  inventory records owner, upstream filing state (or deliberate-fork staging ref),
  co-retirement groups, compatible-release test status, and the shared retirement
  checklist for all eleven current `[patch.crates-io]` logical patches. Unfiled
  deliberate forks are flagged for upstream filing or dated owner reaffirmation
  rather than tracked only in GitHub issue #3335. Because the `dependency-audit`
  job that runs the gate is required to stay on full CI, the PR planner now keeps
  `docs/dependency-policy.md`, `docs/vendored-patch-lifecycle.json`, and
  `docs/upstream-*-patches/` off the lightweight documentation path.

### Changed

- `proxy_alerts` / notification delivery now expose bounded-cardinality
  Prometheus delivery metrics (`attempted` / `succeeded` /
  `failed_transient` / `failed_permanent` / `backpressure_dropped` /
  `abandoned_at_deadline` / `in_flight`, labeled only by fixed
  `channel_type`), classify transport/HTTP outcomes into permanent vs
  transient failures with a bounded jittered retry budget, track dispatch
  tasks per plugin generation (reload stops admission and cooperatively
  cancels; process shutdown drains via the shared observability delivery
  budget), and commit Trigger/Resolve cooldown + incident state only after
  a defined delivery settle (`PendingTrigger` / `PendingResolve`). See
  `docs/proxy_alerts.md` and `docs/notifications.md` (#2448).
- Abandonment is now reported under a fixed, compiled-in reason taxonomy
  instead of one catch-all counter. New
  `ferrum_notification_delivery_rejected_total{channel_type,reason}`
  (`generation_closed`, `registry_rejected`) covers drops where the
  registry-owned delivery body never started — including the pre-`begin_task`
  generation rejection that previously incremented nothing at all — and new
  `ferrum_notification_delivery_abandoned_total{channel_type,reason}`
  (`generation_retired`, `shutdown_deadline`, `task_dropped`) covers bodies
  that started without a committed outcome (channel transport may or may not
  have been polled). `ferrum_notification_delivery_attempted_total` advances at
  that body-start boundary (not the first channel call) so hard-deadline drop
  classification and the accounting identity stay race-free; an admit-then-cancel
  race can therefore increment `attempted` with no bytes on the wire.
  `ferrum_notification_delivery_abandoned_at_deadline_total` increments
  **only** for the true hard abort at the global shutdown drain deadline; a
  rejected or reload-retired send no longer inflates it, and a pre-body
  rejection never inflates `attempted`. Every rejection path still runs the
  producer settle callback exactly once (#2448).
- `proxy_alerts` re-breach during an externally in-flight Resolve no longer
  silently suppresses the follow-up alert. The incident parks in
  `ResolveInFlightRebreached` (no notification that could overtake the Resolve
  on the wire), and the Resolve's settle — success, failure, or abandonment
  alike, because none of those proves the endpoint did not act — converges to
  `CompensatingTrigger`, so the next breaching sample re-alerts through the
  ordinary cooldown gate. A rule that recovered again in the meantime returns
  to `Healthy` with no phantom alert (#2448).
- Documented the best-effort endpoint delivery contract: bounded
  backpressure/failure paths can produce zero copies, while transport timeouts,
  connection errors after the request was written, and cancellation after bytes
  left the process can duplicate a delivery on retry or report an abandoned
  outcome despite endpoint action. Retries preserve `fired_at`, but later
  re-admission does not; Ferrum supplies no cross-admission idempotency key.
  Webhook/email consumers must be idempotent or duplicate-tolerant (#2448).

### Security

- `body_validator` and `openapi_validator` validation diagnostics no longer
  disclose the rejected representation (GHSA-5p2h-fq6q-gwh9). Both plugins used
  to format the offending instance value — or a payload-chosen JSON, XML, form,
  or multipart member name — into the string returned in the client-visible
  reject / problem body and stored in `openapi_validator.request_error` /
  `openapi_validator.response_error`, which every configured logging plugin
  exports. On the response side that republished exactly the upstream
  representation validation exists to withhold, letting a client that can
  trigger an invalid backend response read back a token, credential, or PII
  field; on the request side it copied caller credentials into gateway
  telemetry and every downstream sink. Diagnostics are now assembled under a
  centralized construction contract
  (`plugins::utils::validation_diagnostics`): a compiled-in failure category, an
  allowlisted JSON Schema keyword, and — request side only — a bounded instance
  location. Numeric JSON Pointer segments render as a fixed `#` marker (pointer
  text alone does not prove array shape); an object member name survives only
  when the *configured schema declares it as a JSON property*, and every other
  segment renders as `~`, so a hostile member name is replaced rather than
  sanitized after the fact. Segment count, segment length, and total diagnostic
  length are capped by compiled-in constants. Raw schema paths (including
  `$defs` / reference names), configured XML names and namespaces, and hostile
  `Content-Encoding` coding tokens are never formatted into diagnostics. No
  production path formats a rejected value, an expected `enum` / `const`
  constant, a raw `jsonschema` / `roxmltree` / `prost` rendering, a backend
  `Content-Type`, or the request target, so there is nothing left for truncation
  to protect and no raw-detail escape hatch in configuration or tracing.
  Response-side conversion and decode failures collapse further, to a single
  fixed sentence, because even the class of failure describes an upstream
  representation the client was never entitled to observe.
  `error_truncate_chars` is retained as a size bound and now only narrows
  (`min(configured, 256)`). JSON, XML, form, multipart, protobuf, and gRPC
  validation decisions, statuses, and fail-closed behavior are unchanged;
  `openapi_validator`'s unknown-operation detail no longer interpolates the
  request method and target.

- Updated the transitive `event-listener` dependency from 5.4.1 to 5.4.2,
  removing the `StackSlot` cross-thread unsoundness reported as
  RUSTSEC-2026-0221.

- `ai_rate_limiter` pre-dispatch prompt reservation no longer under-counts billed
  prompt text when a recognized field is present (GHSA-2r5g-438w-85hr). The
  estimator walks the already-parsed request JSON once and sums billable string
  values, visited object member names (including nested tool / function JSON
  Schema property names), and JSON scalar literals (`null` / booleans / numbers
  at serialized width), so sibling instructions, schema keys, and schema scalars
  cannot be omitted from the reservation. Exclusions are path/context aware —
  unsigned numeric output caps only at the exact paths also read for
  completion-budget reservation (negative/fractional values count fail-closed),
  and multimodal URL/base64/file leaves only inside matching provider
  content-part family and part `type` (member names and unrelated textual
  siblings still count; wrong-family / malformed parts count fail-closed).
  Ordinary strings, including well-formed `data:` URLs in `instructions` or
  schemas, always count; collision-shaped reserved spellings outside those
  contexts count fail-closed. The walk remains a conservative `chars/4`
  heuristic, not provider tokenizer parity.
- Irreversible request egress no longer precedes request-body transformation or
  final request policy (GHSA-4vr5-4wm3-x5xv). `request_mirror` and
  `serverless_function` previously ran their external dispatch in
  `before_proxy`, consuming the *pre-transform* metadata body: a mirror, a
  serverless function, or a pre-proxy authorization function could receive a
  field `request_transformer` was configured to remove or redact, and could be
  handed a request that WAF body rules, OpenAPI request-schema validation,
  request-body validation, or the post-transform `request_size_limiting`
  ceiling went on to reject — a disclosure or billable side effect that no
  later local rejection could retract. Both plugins now have no `before_proxy`
  hook at all and instead run in a new **finalized-request-egress** phase that
  the gateway reaches only after request-body collection, canonical
  `transform_request_body` rewrites, and every `on_final_request_body` policy
  hook have accepted the exact backend-visible representation. The phase hands
  plugins an immutable header/body snapshot; a `pre_proxy` `serverless_function`
  publishes its header injections through a backend header overlay that the
  proxy merges only after re-establishing gateway-owned assertions and the
  egress baggage policy. `ai_federation` also dispatches from this boundary
  rather than from inside the ordered final-body hook pass, so
  `priority_override` cannot move provider I/O ahead of a final request policy.
  The phase is wired on H1/H2 (HTTP, WebSocket handshakes, and native gRPC) and
  HTTP/3, runs at most once per request, and is therefore not repeated by
  retries, which replay the already-finalized body.

  Consequences worth reading before upgrading:
  - A body-forwarding `serverless_function` may now share a proxy with
    `request_transformer`; that composition was previously refused outright
    because the function saw different bytes than the backend. The refusal is
    retained — and widened to cover final request-body policy plugins — for
    registered custom plugins that still declare
    `egresses_request_body_before_finalization()`.
  - A buffered request on a proxy with an egress plugin now finalizes its body
    *before* the backend circuit-breaker gate rather than inside backend
    dispatch, so an open breaker is reported after the upload is read.
  - A mirrored body is now the transformed body and is metered against
    `max_mirrored_request_body_bytes` at its post-transform length; a transform
    that inflates the body past that ceiling drops the mirror instead of
    replaying a truncated payload.
  - Rejections produced by these plugins report
    `rejection_phase = "finalized_request_egress"` instead of `"before_proxy"`.
  - Egress plugins no longer run for HBONE `CONNECT` tunnels, which
    short-circuit the dispatch ladder before the phase boundary.
- Retained-response replay now follows one fail-closed partition contract across
  `response_caching`, `request_deduplication`, and `ai_semantic_cache`
  (GHSA-w27g-65rf-h7xm, GHSA-v4g3-2r4f-f6pc, GHSA-37gg-v9m4-8445). A new shared
  module, `plugins::utils::replay_partition`, defines it.
  - **Caller authorization, not a display subject.** Every key binds the
    authentication mechanism, resolved identity and consumer, peer SPIFFE
    identity, and SHA-256 digests of every credential presented, so two
    tokens that resolve to the same `sub` with different scopes, audiences, or
    tenancy claims can no longer share a retained result. `scope_by_consumer`
    and `cache_key_include_consumer` no longer gate caller isolation; they now
    only add the display identity to the digest. `request_deduplication` also
    stops excluding credential headers from the request fingerprint and binds
    their digests instead, so a same-subject/different-scope credential is a
    conflict rather than a replay. Both credential views are bound under separate
    provenance labels — the pristine inbound wire headers and the live
    backend-visible headers — because the post-routing caches run after
    `ai_stream_router`, which strips the client credential and injects the
    provider's; binding only the live view would collapse two distinct client
    tokens onto one partition. The route's precomputed credential registry now
    includes custom header locations configured by `key_auth`, `jwt_auth`,
    `jwks_auth`, and `oauth2_introspection`. Present credential-bearing query
    parameters are privately digested before authentication/transformer
    stripping and remain mandatory caller dimensions independently of the
    response cache's legacy `cache_key_include_query` setting.
  - **Every caller binds canonical caller context.** A new
    `anonymous_caller_scope` option (`caller_address` default, `shared` opt-out)
    binds the gateway-resolved canonical peer address, which the origin observes
    through Ferrum's regenerated `X-Forwarded-For`. Authenticated callers bind it
    too — the backend receives their regenerated forwarding identity as well and
    may vary policy or content by it — so the `shared` attestation applies to
    anonymous callers only. A caller whose canonical address cannot be derived is
    refused rather than keyed incompletely.
  - **Effective destination is part of the key.** `response_caching` and
    `ai_semantic_cache` run after every route-dispatch plugin and now bind the
    post-routing upstream / host / port / scheme / authority and rewritten path,
    so a header-selected tenant backend cannot replay another backend's result.
    `ai_semantic_cache` now uses that shared contract instead of a plugin-local
    encoding that omitted the proxy *namespace*, and additionally binds a
    length-framed backend-visible request-context digest (original client
    authority and `Host`, method, path, the effective outbound query, and every
    non-credential request header, with credential values digested), so
    cross-namespace and header/query-only tenant collisions are closed for both
    exact and semantic lookup scopes.
    `response_caching` now binds the same complete backend-visible request
    *target* unconditionally: the effective outbound query is a key dimension
    even when `cache_key_include_query` is `false`, which is retained only as a
    legacy keyspace toggle. Its request-header dimension stays the complete
    `Vary` tuple (backend-nominated dimensions, `vary_by_headers`, and the
    mandatory credential/session auto-Vary) rather than the raw header view.
    `Authorization`, `Proxy-Authorization`, and `Cookie` are now present as
    dimensions on every retained response, including anonymous responses, so
    the emitted `Vary` contract also protects downstream shared caches that
    cannot see Ferrum's private caller partition. Authorization storage
    admission checks both the pristine inbound and live backend-visible views,
    so a request transformer cannot erase the origin opt-in requirement.
    This tuple is used
    because RFC 9111 §4.1 selection is target + `Vary` and a conditional
    revalidation, a client `no-cache` refresh, and `Content-Length: 0` are
    addressed to a stored entry rather than selecting a different one.
  - **`ai_semantic_cache` lookup moved to the final-request-body stage**
    (priority `2996` → `4057`). It previously looked up in `before_proxy`,
    ahead of `request_transformer` (3000) and every `transform_request_body`
    hook, so the headers, query, and prompt bytes it called "backend-visible"
    were pre-transform, and a hit could bypass a fail-closed final-request-body
    validator — notably `ai_prompt_compressor`, which stages a
    marker-sanitization rejection in its transform and enforces it in its final
    hook at 4055. Lookup now runs in `on_final_request_body_with_context`, after
    that rejection boundary and after every request-body transform, and still
    before `ai_federation` (4060) performs provider I/O. Every `before_proxy`
    admission guardrail continues to run ahead of any hit, exact/semantic Redis
    behavior is unchanged, and store remains in `on_final_response_body`.
  - **Tracing and correlation request headers are bound, not excluded.** The
    request-context partition previously excluded `traceparent`, `tracestate`,
    `b3`, `X-B3-*`, `X-Request-Id`, `X-Correlation-Id` and related names by
    reusing the response-cache sanitation classifier and asserting they are
    fresh "by construction". That is not a valid request-side proof:
    `correlation_id` preserves a valid client-supplied identifier, the plugin
    may be absent entirely, and the value reaches the origin either way. They
    are now bound like any other backend-visible header. The separate
    response-header replay sanitation contract still strips trace identifiers
    from retained responses and is unchanged.
  - **A consumed credential no longer reads as an anonymous caller.** The
    authenticated/anonymous classification now treats a candidate credential
    present in *either* the pristine inbound wire headers or the live
    backend-visible headers as authentication. A credential that an earlier
    plugin removed was previously invisible to the classifier, so such a caller
    was labelled anonymous and `anonymous_caller_scope: shared` could drop its
    canonical-address binding — the one relaxation that is meant to apply only
    to callers who presented nothing.
  - **`request_deduplication` now witnesses routing and request shaping.** Its
    lookup moved from priority `2750` to `3010`, after route dispatch and
    request-transformer header/query rules but before terminate-mode serverless
    execution. Its logical key now binds the effective destination and its
    fingerprint binds the outbound query. Admission rejects every
    same-protocol header/query mutator at or after deduplication (including
    priority overrides), and rejects deferred request-body transformers whose
    final wire bytes were not already established by pre-`before_proxy`
    normalization.
  - **Body-bearing response caching is refused.** `cacheable_methods` now
    accepts only `GET` and `HEAD`; a body-bearing method is rejected at
    admission. At runtime the H1/H2/H3 transport must observe the complete
    upload and privately prove the final pre-`before_proxy` body is empty before
    lookup. Header heuristics cannot prove this for H2/H3 DATA without
    `Content-Length`. Non-empty or unproven bodies bypass lookup and storage,
    and composition admission rejects deferred body transformers that could
    synthesize bytes after lookup.
  - **Canonical length-framed key serialization replaces raw delimiters.**
    `ai_semantic_cache` no longer joins roles, content, and broader fields with
    literal `:`, `|`, and newline bytes, and `response_caching` no longer
    appends `name=value|name=value` Vary suffixes. Keys are digests over typed,
    length-framed fields with explicit sequence counts and presence flags, so a
    legal value containing a delimiter cannot reproduce another request's
    preimage. `response_caching` hashes the *complete* Vary tuple — every name,
    presence flag, and value — rather than only the subset classified as
    sensitive.
  - **Bounded cache maintenance.** `response_caching` overflow eviction now pops
    an insertion-ordered queue in amortized O(1) instead of cloning and sorting
    the entire cache under the accounting mutex for every admitted entry;
    unsafe-method invalidation is an indexed exact lookup plus one ordered range
    over the mutated path's descendants instead of a full-cache scan;
    `vary_index` mappings are reclaimed exactly when their last variant leaves
    instead of by a heuristic sweep; and the uncacheable predictor enforces its
    bound with a FIFO queue instead of a full clone + sort at capacity. Byte-cap
    pressure now evicts oldest-first rather than scanning for expiry.
  - Replay keys, credentials, caller identities, and authorization fingerprints
    are never logged; the remaining diagnostics carry only counts and static
    reasons.
  - **Breaking:** key derivation changed in all three plugins, so entries stored
    by a previous build are unreachable — the intended fail-closed outcome for
    anything keyed under the weaker partition. `response_caching` configs that
    listed a body-bearing `cacheable_methods` entry now fail admission.
    `request_deduplication` and `response_caching` priority overrides and
    deferred body-transform compositions that hide final backend-visible
    request state now fail admission; `mcp_gateway` remains incompatible
    because its response rewrite is derived from mutable live discovery state.
    `ai_semantic_cache` moves
    from priority `2996` to `4057`: a `before_proxy`
    short-circuit that previously lost to a cache hit (`serverless_function`,
    `response_mock`) now wins, and a priority override placing the cache at or
    before a co-located `ai_prompt_compressor` re-opens the bypass this change
    closes.
- Transformer RTDS gates are now bound to the mesh generation that supplied
  their rules (GHSA-83rc-23c9-3g9x). `request_transformer` and
  `response_transformer` read `ferrum.{request,response}_transformer.<scope>.enabled`
  from process-global stores that mesh swapped *after* `ProxyState::update_config`
  had already published the new `RequestEpoch`, and they re-read those stores at
  every request phase. That opened two windows: a plugin built from the new slice
  could read the previous gate during the publication gap, and an already-admitted
  request could read a newly published gate for its whole lifetime — unbounded for
  a slow upload or a slow backend. Scope, rules, defaults, and gate could combine
  into states that existed in neither accepted slice, and one request could
  observe different values at different phases: a request-side marker header
  could be added while its paired body removal was skipped, and a response whose
  buffering preflight answered `false` (selecting streaming) could then have
  header rules applied by a `true` header phase, shipping a response marked as
  sanitized whose body rules never ran.

  The accepted overlay's gate is now materialized into each candidate instance's
  own effective config on the mesh cold path — the same model `fault_injection`
  already used for RTDS fault percentages — as the reserved
  `runtime_overlay_resolved_enabled`. Gate and rules are therefore validated,
  built, and published as one indivisible generation, and each instance resolves
  one immutable decision at construction that every phase reads: buffering
  preflight, request headers/query/body, response streaming/buffering selection,
  response headers/body, retries, and synthetic responses, identically on
  H1/H2/H3. An in-flight request stays wholly on the generation it pinned; a
  rejected slice leaves the previous gate serving in full. Overlay-only changes
  publish as coherent new generations because the affected instances are
  re-stamped for rebuild. The request path no longer performs any overlay lookup,
  removing a per-request `ArcSwap` load. The gate stores are still published
  after acceptance as the provenance surface `response_caching` and
  `request_deduplication` bind retained representations to, and
  `GET /mesh/runtime-overlay` is unchanged. Because that publication lands
  *after* the request epoch, a request whose authenticate/authorize phase spans
  a slice apply keeps the plugin generation it pinned while pinning the newly
  published identity; `response_caching` therefore also binds each stored entry
  to its own generation's effective presentation-policy digest — which now
  covers the materialized gate — so an entry shaped by a superseded generation
  is refetched instead of replayed. An unprovable digest retains nothing.
  `request_deduplication` already bound both halves.
- Route-scoped request/response body ceilings are now enforced by the proxy core
  on every path, not just in body hooks (GHSA-xrfj-852f-645j). The `max_bytes` of
  `request_size_limiting` / `response_size_limiting` is published to the core
  through the plugin cache (precomputed per proxy/protocol) and folded into the
  effective bound of every H1/H2, direct-H2/SNI, native-H3 and H3
  cross-protocol, unary/streaming gRPC, retry, buffering, coalescing, mesh-mTLS,
  and HBONE path *before bytes are forwarded or retained*. Previously
  `request_size_limiting` could not bound an unbuffered chunked, H2/H3
  unknown-length, or streaming-gRPC upload at all — those streamed up to the
  generally larger global ceiling, and to no bound whatsoever when the global
  ceiling was disabled. Specific changes:
  - The effective bound is the strictest *active* (nonzero) value of the route
    ceiling and the applicable global knob, and a global limit of `0`
    ("unlimited") no longer disables an active route ceiling. Multiple instances
    (and a global composed with a proxy-scoped instance) compose to their
    minimum; a looser sibling never relaxes the strictest active bound.
  - Strict buffered response collection (`require_buffered_check: true`) now
    aborts at the route ceiling instead of retaining up to the global allowance
    and only then failing the lower final check, so concurrent requests can no
    longer amplify retained gateway memory toward the global allowance each.
  - Response-size policy now runs over every already-buffered synthetic body
    (mock, `serverless_function`, response/semantic cache, `ai_federation`, dedup
    replay) without depending on another plugin to activate the response
    body-hook gate. A default non-buffering instance previously had no hook on
    that path, so an oversized synthetic body crossed the client boundary.
  - Standards-valid repeated identical `Content-Length` values (RFC 9110 §8.6)
    are parsed per comma-folded member on both request and response fast paths
    via a shared canonical parser, so `Content-Length: 2048, 2048` is compared
    against the ceiling instead of failing a whole-list `parse()` and silently
    skipping the bound. Members are validated as `1*DIGIT` (so `+2048` is not
    honored as a length). A declared length that cannot be reduced to one agreed
    value now fails closed — HTTP 400 on the request side, HTTP 502 on the
    response side — rather than reading as an absent length. Bodyless semantics
    (`HEAD`, `1xx`, `204`/`205`/`304`) remain exempt.
  - Post-transform checks are preserved, and the effective ceiling additionally
    bounds the buffered-representation decode gate and compression admission, so
    a decoding or expanding transform cannot escape the route policy.
  This completes the advisory; [PR #3176](https://github.com/ferrum-edge/ferrum-edge/pull/3176)
  had previously closed only the direct-H2/SNI early-response timing window.
- `soap_ws_security` no longer trusts client media-type selection
  (GHSA-435h-f785-wmm4). Content types are parsed structurally (`type/subtype`
  plus RFC 9110 parameters) and matched by exact essence instead of
  case-insensitive substring search, and the new `content_type.mode` defaults to
  `strict`: every request on a SOAP-protected proxy is governed, so a SOAP
  envelope labelled `application/octet-stream`, `text/plain`, or with no
  `Content-Type` at all is rejected (415) before backend dispatch rather than
  streamed to a backend that routes by path or SOAPAction. `mixed_route` is the
  explicit pass-through opt-out. SOAP 1.1/1.2, `application/xml`,
  `application/xop+xml`, and MTOM/XOP `multipart/related` are supported;
  MTOM validates the root part's envelope (selected by `start`, else the first
  part) and refuses a root part that is mislabelled, re-encoded, or absent.
  A `multipart/form-data; boundary=application/xml` request is no longer
  raw-scanned as an envelope. MTOM package framing is now a strict MIME
  contract, because the parser decides which bytes are the envelope: delimiter
  *lines* are recognized only at the body start or immediately after a CRLF with
  exact CRLF framing and no transport padding (so a `--boundary` sequence inside
  a preamble, a header value, an attachment payload, or the envelope itself is
  inert payload rather than framing); exactly one close-delimiter is required
  and the epilogue after it must not contain the boundary token; part headers
  must be US-ASCII, unfolded, well-formed `token: value` pairs carrying at most
  one `Content-Type` / `Content-ID` / `Content-Transfer-Encoding` each;
  `Content-ID` values must be package-unique and nonblank, and with `start`
  supplied exactly one part may match; and the whole package is framed and every
  part parsed before a root is selected, so no later ambiguity is missed by an
  early return. Part, header, and boundary-candidate ceilings stay fail-closed.
  Previously an unanchored byte-substring search let an attacker plant a
  boundary-shaped sequence in a payload or preamble and have Ferrum validate a
  fabricated envelope — or a truncated one — while the backend executed the real
  root part.
- `soap_ws_security` now authenticates the signer before performing
  attacker-selected XML work (GHSA-9g4v-h9hm-846r). Both the X.509 and SAML
  paths settle certificate trust and `SignatureValue`-over-`SignedInfo`
  verification *before* the first `<Reference>` is resolved, canonicalized, or
  digested, so an untrusted or forged signature costs constant work. Duplicate
  Reference URIs are rejected, the X.509 Reference ceiling drops from 64 to 8,
  SAML accepts exactly one Reference, one bounded id index is built per message
  in place of a full-envelope scan per Reference, the raw-attribute uniqueness
  guard is a single pass for the whole `SignedInfo`, and every canonicalization
  is charged against an aggregate per-message byte budget derived from the body
  length. Previously 64 References to one large element could force well over a
  gigabyte of scanning and canonicalization per unauthenticated request.
- `soap_ws_security` now establishes SOAP identity before authorization
  (GHSA-gfrx-43w6-jq3c). A configuration that establishes a principal
  (`username_token`, `x509_signature`, or `saml`) is an authentication plugin:
  it buffers the body before the authenticate phase, validates there, and
  publishes `authenticated_identity` plus a namespace-correct
  `identified_consumer`, so `access_control`, consumer-scoped `rate_limiting`,
  logging, retries, and chargeback all observe one authoritative SOAP identity
  instead of running before it exists. A timestamp-only policy establishes no
  principal, stays out of the authentication chain, and keeps validating in
  `before_proxy`; the two phases are mutually exclusive by configuration, so no
  message is validated twice. **Breaking:** an identity-establishing instance
  must be the proxy's sole authentication mechanism in either auth mode, and
  composing one with `compression`'s `decompress_request` is rejected at config
  admission; for that identity-establishing form an `on_final_request_body`
  guard additionally refuses to dispatch a message whose bytes changed after
  validation. A timestamp-only instance authenticates nobody and claims no
  integrity over the Body, so it does not bind the representation and stays
  composable with request-body transformers. Also **breaking:** because an
  identity-establishing instance is the proxy's sole authentication mechanism,
  a request the SOAP policy passes through — a non-SOAP media type under
  `content_type.mode: mixed_route`, or a governed envelope with no
  `wsse:Security` header under `reject_missing_security_header: false` —
  reaches the authentication chain with no identity and is answered `401`
  rather than forwarded anonymously; pair those options with a timestamp-only
  instance, or separate anonymous and SOAP-authenticated traffic onto different
  proxies.
- `soap_ws_security` X.509 signatures must now protect the backend-visible SOAP
  Body (GHSA-3mwq-c8j6-9xhp). `Envelope`/`Header`/`Body`/`Security` selection is
  namespace-qualified and positional rather than by local name, duplicate
  namespace-correct envelope elements and misplaced `wsse:Security` headers are
  rejected, and a successful X.509 verification now requires a Reference that
  resolves uniquely to the actual Body. `require_signed_timestamp` rejects a
  message with no Timestamp instead of passing vacuously, and pairing it with
  `timestamp.require: false` is refused at admission. Previously a trusted
  signature over only the Timestamp authorized an arbitrary rewritten operation,
  and a signed lookalike `<Body>` under another namespace could be selected in
  place of the real one. **Breaking:** because Ferrum implements no WS-Security
  attachment-signature transform, an X.509 signature cannot cover the octets an
  `xop:Include` stands for; an enabled `x509_signature` therefore now refuses
  both MTOM/XOP `multipart/related` and bare `application/xop+xml` with `415`
  before dispatch, and an explicit `content_type.allow_mtom: true` alongside it
  is refused at config admission. `username_token` and `saml` keep accepting
  MTOM/XOP — they authenticate who sent the message and never claimed integrity
  over attachment octets. Separately, `reject_missing_security_header: false`
  now governs an *absent header only*: on a governed representation, malformed
  XML, unsupported or ambiguous envelope structure, and XML parsing-budget
  failures reject with `400` regardless of that setting, so a gateway/backend
  parser disagreement can no longer become a pass-through that skips
  authentication, integrity, freshness, and replay for a message the backend
  still executes.
- `soap_ws_security` SAML assertions are now bound and single-use
  (GHSA-f44p-hfqr-cvcc). **Breaking:** `saml.audience`, the new
  `saml.recipient`, and `nonce.replay_scope` are required when SAML is enabled.
  An accepted assertion must carry a mandatory `Conditions` window with both
  `NotBefore` and `NotOnOrAfter` inside the new
  `saml.max_assertion_lifetime_seconds` cap (default 300), must be admitted by
  every `AudienceRestriction`, must carry one supported `SubjectConfirmation`
  (bearer only; `holder-of-key` is refused at admission) whose
  `SubjectConfirmationData` names `saml.recipient`, carries its own bounded
  `NotOnOrAfter`, and omits `InResponseTo`, and its assertion id is claimed for
  single use in the declared replay scope for the same fixed 93 601-second
  horizon as PasswordDigest nonces. `OneTimeUse` needs no special case because
  every accepted assertion is claimed exactly once. `process` scope is a
  single-replica declaration and makes no cross-replica claim; multi-replica
  SAML deployments must use `shared`. Previously a captured signed assertion
  could be replayed indefinitely beside a freshly minted outer Timestamp, and in
  the default configuration an assertion issued for another service by the same
  trusted IdP was accepted. An accepted assertion must also resolve exactly one
  namespace-correct, nonblank Subject `NameID` — the documented SAML principal —
  and that resolution now happens *before* the single-use claim, so an assertion
  that satisfies every binding but authenticates nobody fails closed with `401`
  without consuming replay state. Previously such an assertion was accepted,
  burned its replay id, and returned no principal, silently degrading the
  request to unauthenticated while letting an attacker spend a legitimate
  assertion id.

- `mcp_gateway` aggregate-router mode now validates `tools/call` results against
  discovered tool `outputSchema` values when
  `validation.validate_tool_results` is enabled
  (#3296). Schemas are audited and compiled at catalog construction (local
  references only; depth/node budgets), invalid schemas are refused at admission
  with field-specific diagnostics, and bounded caller-visible results are checked
  before release or audit publication. `structuredContent` and JSON text
  `content` variants are covered without validating a different representation
  than the caller receives; tool `isError` results and well-formed, error-only
  upstream JSON-RPC errors are preserved; event-stream / non-JSON / oversized
  results fail closed with JSON-RPC `-32012`. Transparent mode rejects the
  option because it has no mediated tool catalog. Result bodies are never
  logged.
- Plugin egress no longer inherits ambient proxy configuration
  (GHSA-c4pj-vq6x-53rw). Backend dispatch `reqwest` clients (via
  `BackendTlsConfigBuilder::build_reqwest`), active health-check clients
  (primary, custom-TLS, and degraded DNS-cached fallbacks), the dedicated
  ClickHouse client built by `api_chargeback_sink` for custom CA / mTLS /
  relaxed-verification settings, and the dedicated `spec_expose` and
  `load_testing` clients now call `reqwest::ClientBuilder::no_proxy()` like the
  shared `PluginHttpClient` and its fallback builders. With a proxy selected
  from `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`, Ferrum resolved and screened
  the *proxy* while the proxy resolved and connected to the configured hostname,
  so the ultimate destination never passed `BackendEgressPolicy`. A CI guard
  now fails if any policy-governed `reqwest` builder drops `.no_proxy()`.
- `ws_logging` now enforces backend egress policy on the address it actually
  dials (GHSA-mp2j-gjfp-2vm8). Every connection and reconnection resolves the
  endpoint fresh (bypassing both DNS cache layers), rejects the complete A+AAAA
  answer if any candidate is denied, rechecks each candidate immediately before
  its socket is opened, and dials only screened addresses. The configured
  hostname is retained as the TLS SNI / certificate identity and the WebSocket
  `Host` authority. Previously the endpoint was handed to `tokio-tungstenite`,
  which resolved and dialed it outside the policy, so a hostname could rebind to
  a denied address between admission and any later reconnect.
- `kafka_logging` bootstrap parsing now matches the pinned librdkafka grammar
  (`[proto://]host[:port]`, URL-path truncation, bracketed-IPv6 port rules,
  empty host → `localhost`), so protocol-prefixed denied literals such as
  `PLAINTEXT://169.254.169.254:9092` are rejected instead of evading a
  `host:port`-only screen. Entries whose protocol prefix disagrees with
  `security_protocol` are rejected rather than silently truncating the broker
  list the way librdkafka would.
- ACME issuance and renewal now route every connection through a
  Ferrum-controlled, public-only fresh-DNS connector; reject mixed/private DNS
  answers, answers above 64 addresses, ambiguous legacy numeric IPv4 host
  spellings, endpoint origin drift, credential-directory mismatch, legacy
  credential URL sets, hostile order resource URLs, redirects, and response
  bodies above 1 MiB while preserving HTTPS hostname/certificate verification.
  Fresh DNS plus all TCP candidates share one 30-second wall-clock budget.
  **Breaking:** ACME servers that advertise endpoints on another host or port,
  and pre-0.4 `instant-acme` credentials with embedded `urls`, must be migrated
  to the configured directory origin (#2407).
- `body_validator` now enforces the validation it advertises on all four of its
  surfaces. Configured JSON Schemas are compiled once at plugin construction with
  the `jsonschema` crate under an explicit draft (`json_schema_draft`, default
  `draft2020-12`) instead of being interpreted by a partial handwritten
  evaluator, so `$ref`/`$defs`, union types, conditionals, and other standard
  keywords take effect and malformed schemas, invalid type names, non-local
  references, `$vocabulary` declarations, and over-budget schemas fail
  configuration closed; local JSON Pointer targets are policy-audited even under
  normally literal containers, and no external reference is ever retrieved. XML
  bodies are parsed exactly, without Unicode whitespace trimming, with
  `roxmltree` rather than scanned for balanced tags, so multiple roots, text
  outside the root, invalid names or characters, malformed/unquoted/duplicate
  attributes, and undeclared entity references are rejected. External
  `SYSTEM`/`PUBLIC` identifiers on either the DOCTYPE or an entity declaration
  are refused outright, and `required_xml_elements` matches parsed
  namespace-expanded names. Decoded gRPC protobuf messages must satisfy
  proto2 `required`-field initialization recursively, including inside present
  nested, repeated, map, and extension message values. Unknown top-level config
  keys and unknown keys inside a `protobuf_method_messages` entry are rejected
  before defaults, so a typo can no longer silently replace enforcement with a
  weaker policy. This is a breaking configuration change; see the
  [Safe Upgrade Guide](docs/upgrade_guide.md#body-validator-enforcement-hardening).
- **`request_deduplication` Redis ownership is now atomically fenced**
  (GHSA-f72h-jm2p-mc73). Ownership and completion share one versioned operation
  record per logical key. Completion is a compare-and-set on the owner's exact
  in-flight record, so an owner whose `inflight_ttl_seconds` lease expired can
  neither overwrite a successor's completed response nor publish while a
  successor owns the operation; such a completion is discarded locally too
  instead of being replayed as a non-authoritative result. Redis-mode logical
  keys move to `v4`, unconditionally include the matched proxy namespace even
  under an explicitly shared Redis prefix, and the record format is versioned,
  so a rolling upgrade reads and writes disjoint keys instead of mixing
  formats. Current-version records with missing ownership fences, impossible
  state fields, or mismatched inner/outer fingerprints fail closed. A new
  `on_redis_unavailable` field decides outage behavior and **defaults to
  `fail_closed` (HTTP 503)**; deployments that prefer the previous
  process-local fallback must set `on_redis_unavailable: "local_only"`.
- **`request_deduplication` rejects unknown configuration keys**
  (GHSA-h2c3-j3cm-7ghh). The runtime constructor and the OpenAPI
  `RequestDeduplicationConfig` schema now share one closed allowlist, so a
  misspelled `enforce_required` or `sync_mode` fails admission with a
  path-qualified diagnostic instead of silently reverting to a permissive
  default. Redis-only keys are additionally rejected outside
  `sync_mode: "redis"`. Existing configurations carrying stray keys, or
  `redis_*` fields in local mode, must be corrected before upgrade.
- **Completed external operations behind a synthetic response now leave a
  durable completion** (GHSA-8cr6-rw38-7j59). `serverless_function` terminate
  mode and `ai_federation` provider calls declare that their short-circuit
  performed the protected billable operation; deduplication publishes a
  non-replayable 409 completion tombstone — fenced in Redis mode — on buffered,
  empty/HEAD, streamed-fallthrough, and interrupted-delivery outcomes alike.
  Previously an interrupted delivery only held a bare in-flight marker, so an
  identical retry re-executed the operation once `inflight_ttl_seconds` elapsed.
  The tombstone is retained for `max(ttl_seconds, inflight_ttl_seconds)`: it
  replaces a marker that blocked duplicates for `inflight_ttl_seconds`, so a
  deployment configured with `inflight_ttl_seconds > ttl_seconds` never becomes
  re-executable sooner than it was before. Ordinary replayable completions keep
  `ttl_seconds`. The barrier also covers the case where the committed response
  itself cannot be retained as a replay — its request straddled a
  response-presentation-policy publication, or that policy is incomplete or
  `Dynamic` — instead of falling back to the bare in-flight lease. Local
  response-byte admission failure and later protected-completion eviction now
  use an explicit fixed-size execution barrier carrying the completion's own
  authoritative retention clock; neither path can silently restart a shorter
  `inflight_ttl_seconds` lease. Stale owner hooks cannot clear the barrier or a
  successor because every transition remains fingerprint/token fenced. Per-key
  execution barriers are hard-capped at `max_entries`; overflow extends one
  fixed process-global deadline that returns 503 for applicable idempotency-key
  requests, preserving fail-closed retention without unbounded key storage.
  Serverless responses with stable, complete policy provenance are still stored
  as ordinary replays. The provenance contract is documented in
  `docs/plugin_execution_order.md`.
- Versioned standard and `-ebpf` multi-architecture images are now keylessly
  signed in Docker Hub and GHCR and carry final-manifest SLSA provenance plus
  per-platform SPDX SBOM attestations. A fail-closed publication gate requires
  identity, signature, subject-digest, source-commit, provenance, and SBOM
  verification and retracts a GitHub Release if attestation does not succeed
  (compatible with the trusted Cross `create-release.needs` contract).
- `ai_semantic_cache` no longer discards Redis quarantine-`DEL` failures for
  malformed, oversized, empty, or otherwise inadmissible entries. Failed deletes
  are counted with rate-limited warnings that omit keys, payloads, credentials,
  and endpoints, and a bounded per-instance local suppressor (content fingerprint
  + 30s TTL, hard-capped, constant-work capacity eviction) prevents immediate
  re-download/parse/delete amplification of the same poisoned remote value while
  still reconsidering repaired replacements within that bound. Quarantine
  fingerprints are computed only after a Redis value fails admission, so valid
  hits are not hashed for poison markers. Invalid entries remain unserved;
  deletion failure cannot convert a miss into a hit (issue #3213).
- `response_caching` now applies RFC 9111 §3.5 shared-cache admission to the
  live request credential rather than only to a gateway-minted identity, so a
  gateway that forwards `Authorization` to a backend that validates it no longer
  retains the protected response without an explicit `public` /
  `must-revalidate` / `s-maxage` opt-in. `cache_key_include_consumer` remains a
  key-partition option but no longer overrides the origin's storage policy.
  Backend-side revocation, expiry, and scope changes are no longer masked for
  the entry's lifetime (GHSA-7f28-wh4x-5375).
- `Cache-Control` is parsed with quoted-string awareness, so the qualified
  `private="…"` and `no-cache="…"` field-name forms are understood. Named fields
  are removed from the retained entry instead of being replayed from the shared
  cache, and a malformed qualified argument fails closed to the bare directive.
  Connection-scoped and proxy-authentication response fields are also stripped
  before storage (GHSA-fpx2-5v4j-wqxq).
- `1xx`, `206`, and `304` can no longer be configured in
  `cacheable_status_codes`, are refused again at store time, and are never
  replayed; a response carrying `Content-Range` is likewise never stored. A
  caller can no longer poison a shared cache with a partial or validator-only
  representation (GHSA-v7fj-73gm-h625). **Breaking:** existing plugin rows
  containing those statuses must be repaired before upgrade — see the
  [Safe Upgrade Guide](docs/upgrade_guide.md#response-cache-shared-storage-hardening).

### Added

- `fault_injection` now supports UDP and DTLS. Session admission aborts run in
  isolated per-source / per-DTLS-client `on_stream_connect` tasks; per-datagram
  delays and silent abort drops run on `on_udp_datagram` (client→backend) inside
  the established-session hook-ingress worker — never the shared listener recv
  loop — so one peer's delay cannot stall another. UDP/DTLS stream connect skips
  delay so the first-datagram path cannot stack two waits. Delays share the
  existing one-minute ceiling, `FERRUM_MAX_CONCURRENT_FAULT_DELAYS` budget, and
  shutdown cancellation; queued follow-ups remain under the hook-ingress
  byte/datagram caps (#3293).

### Changed

- Kubernetes controller Gateway API and Istio status patch batches now have a
  60-second wall-clock ceiling. A stalled Kubernetes API request can no longer
  retain the reconcile loop indefinitely; unfinished status updates are
  cancelled and retried by a later watch event or periodic full sync.

- Kubernetes controller Gateway API and Istio status writers now share one
  immutable `Arc<[K8sObject]>` generation per reconcile instead of each
  deep-cloning the full unstructured object snapshot. Status semantics,
  bounded update plans, route-conflict handling, and per-writer failure
  isolation are unchanged; deployments with neither writer still pay no
  snapshot clone cost (#3281).

- Gateway API `GRPCRoute` predicates are now translated instead of dropped.
  A pathless `matches[]` entry (method-only, header-only, or a rule with no
  `matches` at all) previously disappeared during translation, so valid gRPC
  rules never routed and their traffic fell through or 404'd. gRPC predicates
  are now represented independently of HTTP paths: an `Exact` `method` with
  both `service` and `method` becomes an exact `=/{service}/{method}` listen
  path, a service-only match becomes a `/{service}/` prefix, and every
  remaining shape materializes on the `/` listener behind a
  `mesh_route_dispatch` URI regex. Every emitted GRPCRoute match — exact-path
  matches included — additionally carries a case-insensitive gRPC
  `content-type` predicate, so a GRPCRoute only ever selects gRPC calls and
  can never capture ordinary HTTP traffic sharing the same hostname and path.
  That gate is the regex transcription of Ferrum's canonical native-gRPC
  content-type contract (`proxy::backend_dispatch::is_native_grpc_content_type`),
  so `application/grpc-web`, `application/grpc-web-text`, and lookalikes such as
  `application/grpcfoo` are refused exactly as the proxy's own dispatcher
  refuses them — gRPC-Web is served by configuring the trusted `grpc_web`
  plugin, which rewrites a verified request to native `application/grpc` before
  backend dispatch. A route-authored `content-type` match still replaces the
  gate, but it is validated against the same native contract first, so an
  operator header can only narrow the protocol boundary. GRPCRoutes share
  HTTPRoute's same-`(hostname, listen path)` collapse **within their own kind**,
  so rule/match ordering and fall-through are preserved. Gateway API v1.5.1
  forbids merging rules between GRPCRoutes and HTTPRoutes: an HTTPRoute and a
  GRPCRoute attached to the same resolved listener with any intersecting
  hostname now resolve to exactly one accepted Route on that listener and
  hostname — oldest `metadata.creationTimestamp`,
  then `{namespace}/{name}`, then `kind` (the last only breaks a total tie: the
  two kinds may share a name and `creationTimestamp` has second granularity),
  independent of rule paths and of the order objects are observed in — and the losing Route materializes no proxy, upstream,
  plugin, or materialized-parent record and is reported `Accepted=False` with
  `reason: Conflicted`. "The same listener" is the *resolved* Gateway listener,
  not the literal `parentRefs[]` selector: a wildcard reference and a reference
  pinning that listener by `sectionName` or `port` contend with each other,
  while two wildcard references that `allowedRoutes.kinds` sends to different
  listeners do not. Ferrum's HTTP-family route representation is
  port-agnostic, so retaining any second parentRef or hostname claim after one
  loss would also retain the Route's proxy on the listener where it lost: the
  entire Route is conservatively withdrawn across every claim as soon as it
  loses on **any** listener. Whole-Route arbitration runs in the same total
  Gateway API order, so a withdrawn Route cannot displace a later valid Route
  elsewhere. Route status always echoes each parentRef the operator wrote.
  Cross-kind routes never collapse, including when separate listeners admit
  them: because the route table is port-agnostic, merging would make each
  backend reachable through the other kind's listener. An identical
  `(hosts, listen path)` therefore fails config validation closed.
  gRPC shapes Ferrum cannot represent exactly
  — `method.type: RegularExpression` (Ferrum cannot constrain a regex operand
  to a single gRPC path segment, so the predicate is refused rather than
  compiled into a matcher that could widen across service/method boundaries)
  or any other non-`Exact` `method.type`, a `method` block with neither
  `service` nor `method`, an `Exact` operand that is empty, over 1024 bytes
  (the CRD `MaxLength=1024`), present but not a string, or outside the v1.5.1
  CRD grammars, a non-native-gRPC `content-type` predicate, a non-`Exact`
  header match, a match entry carrying both `method` and Ferrum's hand-authored
  `path` extension (Ferrum cannot represent their conjunction, so honoring
  either half alone would widen the match), or an explicit
  `method: null` / `headers: null` (an explicit null is malformed input, not an
  omission, and must not widen into the any-gRPC-call or headerless match —
  omitting either field keeps its documented meaning) — are dropped fail
  closed with a field-specific translator warning that never echoes the
  operand.
  See
  [GRPCRoute predicate translation](docs/gateway_api_conformance.md#grpcroute-predicate-translation).

- **Breaking:** `kafka_logging` now fails closed under any restrictive backend
  egress policy, including the default posture. librdkafka resolves bootstrap
  hostnames itself and dials brokers advertised by cluster metadata, and the
  pinned `rdkafka 0.39` exposes no connect/resolve callback, so those addresses
  cannot be screened. The plugin is admitted only under a fully-open policy
  (`FERRUM_BACKEND_ALLOW_IPS=both`, no `FERRUM_BACKEND_DENY_CIDRS`,
  `FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES=false`). Deployments that need Kafka log
  shipping under a restrictive policy should ship through a policy-aware sink
  (`http_logging`, `tcp_logging`, `ws_logging`, `loki_logging`) and bridge to
  Kafka outside the gateway. See
  [Backend Egress / SSRF Protection](docs/configuration.md#kafka_logging-requires-a-fully-open-egress-policy).

- Authenticated `/metrics` now renders TLS certificate gauges from a cached,
  non-secret TLS inventory snapshot and performs no certificate, private-key,
  Kubernetes, HSM, or cloud-secret I/O on the scrape path. The snapshot is
  refreshed by a bounded single-flight background task governed by the new
  `FERRUM_TLS_INVENTORY_SNAPSHOT_TTL_SECONDS` (default 300, `0` disables it), its
  freshness is exported as `ferrum_tls_inventory_snapshot_timestamp_seconds` /
  `ferrum_tls_inventory_snapshot_max_age_seconds`, and certificate gauges are
  absent until the first snapshot is published. `GET /admin/tls/inventory` still
  collects live.
- Added release governance requiring version tags to match the package version and
  requiring build-out breaking changes to be recorded here.
- Hardened `tcp_connection_throttle` config loading to fail closed for
  unsupported-only global targets, non-TCP scoped attachments, unknown config
  fields, and cleanup intervals above 86400 seconds. Existing deployments must
  remediate these rows before upgrade; see the
  [Safe Upgrade Guide](docs/upgrade_guide.md#tcp-connection-throttle-validation-hardening).

## [0.9.0]

Ferrum Edge 0.9.0 represents the current build-out baseline: a multi-protocol
edge proxy with file, database, control-plane, data-plane, mesh, injector, and
node-agent modes plus its plugin and operational tooling. This entry is
intentionally coarse-grained rather than a reconstruction of unreleased history;
see [GitHub Releases](https://github.com/ferrum-edge/ferrum-edge/releases) for
published release notes.

[Unreleased]: https://github.com/ferrum-edge/ferrum-edge/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/ferrum-edge/ferrum-edge/releases/tag/v0.9.0
