# Plugin Execution Order

Ferrum Edge executes plugins in a deterministic order based on two dimensions: **lifecycle phases** and **priority within each phase**.

`transaction_log_schema` is a config-only exception to runtime ordering. Full
and delta cache builds construct its global instances first to stage named
schemas, then discard those instances after the registry owns the compiled
definitions. It is absent from global/per-proxy lifecycle lists and all
HTTP, gRPC, WebSocket, TCP, and UDP protocol snapshots, so it never runs a
request, summary, connection, or frame hook. It still appears in the complete
inventory at priority `9999` because schema registration has explicit ordering
semantics relative to every logger that may resolve `schema_ref` — the priority
documents that contract even though no request hook ever fires.

`__mesh_bpf_metrics` is a reserved, mesh-auto-injected plugin (NodeWaypoint
topology). Operators should not configure it directly; the mesh runtime injects
it so the BPF SOCK_OPS event consumer can expose TCP-layer Prometheus counters.
It declares all protocols so an accidental non-mesh attachment is not silently
dropped, but it implements no request/response/stream hooks.

## Lifecycle Phases

HTTP-family routing and per-proxy allowed-method admission occur before the
ordinary plugin lifecycle begins. Native gRPC requests also pass a POST-only
admission gate at this boundary. Admitted gRPC requests then run the synchronous
`grpc_deadline` policy preflight immediately after routing: it establishes one
receipt-anchored monotonic deadline before any plugin or body await. The normal
`before_proxy` hook later writes the relative remaining header for the backend;
it does not create or re-arm the gateway timer. Requests admitted by those
checks then pass through the request/header phases in strict order. Buffered
responses run the body phases before logging; streamed non-buffered responses
skip the buffered body phases and run a terminal stream hook before logging.
WebSocket connections optionally enter a frame phase after the HTTP upgrade
completes. Successful H1/H2/H3 WebSocket handshakes run a synchronous,
non-rejecting response-header decoration boundary in configured priority order
before transport-owned handshake fields are restored. Plugins only run in the
phases they implement:

```
Request In
    │
    ▼
┌─────────────────────────┐
│ Route + method admission│  Unmatched: 404; disallowed: 405; gRPC non-POST: reject
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 0. gRPC deadline policy │  Synchronous receipt-time budget preflight
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 1. on_request_received  │  Matched-request processing: CORS preflight
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 2. authenticate         │  Identity verification: mTLS, JWKS, JWT, API key, LDAP, Basic, HMAC
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 3. authorize            │  AuthZ, OPA decisions, consumer rate limiting, WAF metadata, request_mirror pre-buffer admission
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 3b. normalize body      │  Opt-in buffered request decompression before before_proxy
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 4. before_proxy         │  Route/header preparation before backend-path policy
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 5a. final path policy   │  Enforce selected method; charge state once
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 5b. routing-header hook │  Deferred enrichment with target pinned
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 5c. deferred hooks      │  Remaining external/synthetic work after policy
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 5d. final request body  │  Terminal body dispatch after selected-path policy
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 6. backend_admission    │  Target-aware backend admission after load balancing
└────────────┬────────────┘
             │
             ▼
       ┌───────────┐
       │  Backend   │  Actual HTTP call to upstream
       └─────┬─────┘
             │
             ▼
┌─────────────────────────┐
│ 7. after_proxy          │  Response headers, fast-path rejection, CORS
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 8. normalize_response_body │ Provider/protocol normalization
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 9. on_response_body     │  Normalized buffered body inspection
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 10. transform_response_body │ Buffered presentation rewrites
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 11. on_final_response_body │ Buffered body validation/storage
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 12. on_response_committed │ Observe final buffered response
└────────────┬────────────┘
             │
             │  Streamed non-buffered bodies skip phases 8-12 and call
             │  on_response_stream_terminated here when the body terminates.
             │
             ▼
┌─────────────────────────┐
│ 13. log                 │  Logging & observability (timing depends on body owner)
└─────────────────────────┘
```

`on_request_received` is therefore a post-route, post-allowed-method hook, not
a pre-routing receipt hook. Once it runs, `ctx.matched_proxy` is populated and
the plugin list is the resolved view for that proxy: applicable global plugins
plus proxy/proxy-group-scoped plugins. Unmatched 404 responses run neither
global nor scoped hooks because there is no proxy view to select. Matched 405
responses also return before either kind of ordinary request hook runs, but
they still emit one terminal transaction summary from the protocol-filtered
plugin-cache view (`metadata.rejection_phase = "allowed_methods"`) without
running authentication, transformation, mirroring, or other request-policy
hooks. Native gRPC requests must also use `POST` before this hook runs.

Stream-termination hooks ordinarily retain plugin priority order. Terminal
observers may explicitly defer only this final hook until ordinary peers have
finished, while retaining relative priority within the deferred group.
`ai_transcript_audit` uses that terminal-observer phase so a streaming record
sees the final `ai_tool_governor` decision before the transaction summary is
cloned; request, response, and stream-inspector ordering is unchanged.

A matched request using a different method is rejected at its protocol
admission gate before either kind of hook, even if `allowed_methods` permits
that method. H1, H2, and H3 share the ordinary-hook blind spots for unmatched
404 and gRPC non-POST admission; matched-proxy `allowed_methods` 405 responses
are included in transaction logs. Terminal transaction logging is separate from
ordinary request hooks; whether a terminal summary exists must not be inferred
from whether `on_request_received` ran.

Any plugin can short-circuit the pipeline by returning a `Reject` result. For example, a native direct CORS policy returns a `204` preflight response in phase 1 without ever reaching authentication (an Istio projection returns its source-compatible 200). Rate limiting returns `429` in the authorize phase (phase 3) after the consumer is identified.

`on_backend_path_resolved` is an opt-in, route-sensitive boundary after
route/header-shaping `before_proxy` hooks and load balancing, but before
circuit-breaker or backend dispatch. The gateway assembles the same path
segments used by the backend URL builder, including regex/exact/prefix match
length, the canonical policy path, `strip_listen_path`, `backend_path`, and
the selected target's path. `grpc_method_router` uses this phase so
allow/deny/rate policy and `grpc_*` metadata describe the method placed on the
backend wire. The selected target remains pinned across deferred external hooks,
so routing-header mutations cannot steer the request onto a different method.
The gateway enforces the selected path, including stateful per-method rate
limits, exactly once before invoking those hooks or a terminal final-request-
body dispatch such as `ai_federation`. Gateway-owned identity headers and
configured egress baggage filtering are reapplied after every deferred
mutation pass. The pre-filtered backend-path plugin list is built on reload;
proxies without an opt-in plugin do not scan the chain or allocate an
effective-path string. Once policy binds the
first target's path, retries may rotate host/port only when the candidate keeps
the same assembled effective backend path, including the proxy `backend_path`
fallback when a target has no explicit path. A candidate with a different path
aborts the retry instead of redialing the failed target or silently changing
the authorized method. This applies to HTTP, native and bridged gRPC/H3, and
WebSocket retry loops.

When backend-path policy is active, `before_proxy` hooks that can dispatch
external work or synthesize a terminal response opt into the deferred phases.
Ferrum runs them in their normal relative priority order only after path policy.
`fault_injection`, `request_mirror`, pre-proxy `serverless_function`,
`response_mock`, `grpc_deadline`, and `load_testing` use this boundary, so a
backend-effective gRPC deny cannot be delayed, faulted, mirrored, invoked,
mocked, deadline-rejected, or load-fanned-out before it is enforced. Proxies
without a backend-path policy retain the ordinary single `before_proxy` pass.
Deferred hooks generally observe the original client path, preserving their
normal request semantics even when mesh routing rewrote the backend path.
`request_mirror` is the route-parity exception: an unset `mirror_path` reads
the finalized mesh `route_override_path` without taking it from primary
dispatch, then falls back to the backend-effective authorized path and finally
the original client path.
Within that deferred transform band, `load_testing` (3070) runs before
`request_mirror` (3075) so the reserved `X-Loadtesting-Key` is stripped on both
matching and non-matching paths before mirror can copy it. As defense in depth,
`request_mirror` also excludes both load-testing control headers if priority
overrides reverse the order. Both plugins still require backend-path resolution
and pre-`before_proxy` body availability when they opt in. `request_mirror` is
also the security-sensitive path exception: when backend-path policy is active
and `mirror_path` is unset, it mirrors the exact effective path that passed
final authorization. An explicit operator-configured `mirror_path` still wins.
Each configured mirror instance appends its own bounded result receiver; result
logging is detached per instance, so later instances and mixed completion order
cannot overwrite an earlier destination's outcome.

A body-mirroring `request_mirror` instance additionally participates in the
`authorize` phase, purely to decide mirror admission before the gateway
collects a request body (advisory `GHSA-jv66-mq44-m9v3`). That hook never
rejects — mirroring stays fail-open for the primary request. It advances the
deterministic sampler once and, on selection, takes the instance's
`max_in_flight` permit plus a `max_retained_request_body_bytes` reservation
equal to the full positive `max_mirrored_request_body_bytes` ceiling (declared
`Content-Length` is used only to skip already-oversized bodies before sampling;
it never sizes the aggregate charge). `should_buffer_request_body` is then a
pure read of that decision, so a
`percentage: 0`, sampled-out, or saturated request keeps streaming and never
allocates a mirror body. Its built-in priority follows the built-in rejecting
authorization hooks. If an operator priority override or custom plugin places a
rejecting hook later, the proxy still waits for the complete authorization
phase before collecting the body; that rejection drops the staged permit and
reservation without reading the upload, though it may consume a sampling slot.
Instances with `mirror_request_body: false` or a zero-quantized `percentage`
declare no body capability at all and stay out of the authorize list. The staged
decision is left behind as a consumed marker after `before_proxy` takes the
lease, so the buffering predicate answers consistently for the whole request.

A deferred hook that can inject routing headers runs after the selected
target's single state-consuming enforcement, and that target is pinned across
the external call. After each deferred pass, the gateway removes every case
variant of the reserved `x-consumer-username` and `x-consumer-custom-id`
headers, restores only authenticated gateway values, and reapplies configured
egress baggage-key filtering. Plugin-returned headers therefore cannot spoof
backend identity, restore forbidden baggage, or steer this request to a
different unauthorized target.

Terminal final-request-body plugins run after the selected path is pinned and
authorized, and after both deferred `before_proxy` subphases, but before
backend-only admission, circuit breaking, pool, TLS, or transport work. This
keeps final transformed-body provider dispatch outside placeholder-backend
health accounting without allowing it to bypass backend-effective gRPC method
policy.

When a plugin returns a replacement body from `transform_response_body`, the core first removes representation metadata that can no longer describe the client-visible bytes: range fields, ETag/Last-Modified validators, content digests/checksums, and content-bound signatures. It then calls that plugin's `on_response_body_transformed` callback before the next transform, allowing the plugin to attach metadata it recomputed for the replacement representation. Neither step runs when the transform returns `None`, so unmodified responses retain their original semantics — with one exception: a body the representation gate **decoded** has already had its client-visible bytes changed (encoded in, identity out), so that same metadata invalidation is applied at the decode itself, whether or not a later rule matches. Otherwise a decoded body no rule happened to change would be served as identity bytes carrying the origin's validator for the encoded ones. `206 Partial Content` and `226 IM Used` responses that no configured body policy claims skip provider normalization and presentation transforms entirely: the buffered bytes are only a selected range or delta, so Ferrum cannot rewrite them into a truthful full representation merely by changing headers or status. When a configured body policy *does* claim such a response, skipping the transform would silently forward protected bytes, so the representation gate described below rejects it instead — see [Buffered response representation gate](#buffered-response-representation-gate). Transform-dependent header hooks also decline these statuses: compression does not attach `Content-Encoding`, gRPC-Web does not relabel native gRPC bytes or expose transformed trailers, and SSE does not force a non-SSE representation into event-stream headers when wrapping cannot run. Inspection hooks still run. If an enforcing policy detects content whose safe disposition requires redaction, it rejects the response instead of forwarding the original bytes with false redaction telemetry. This lifecycle rule is shared by buffered H1, H2, H3, gRPC, and synthetic/rejection response paths rather than delegated to individual transformer implementations.

Gateway-generated synthetic responses normally skip the body pipeline when they contain zero bytes. A validator whose contract distinguishes an empty representation from a valid one can opt into zero-byte processing; `openapi_validator` does so for matching response contracts, keeping empty synthetic and buffered backend responses under the same final-schema rule. HEAD and 1xx/204/205/304 responses retain their no-body semantics and do not enter this path.

### Buffered response representation gate

Before any buffered body transform runs, one shared gate decides whether a configured body policy — a plugin returning `true` from `enforces_response_body_policy`, such as a `response_transformer` with `body_rules` — can genuinely be applied to the representation the backend produced. The same gate runs on every path that publishes a buffered response: H1/H2, buffered gRPC, native H3, both H3 cross-protocol bridges, and the synthetic/replay short-circuit.

The gate answers one question and it is fail-closed:

- **No configured body policy claims the response.** Nothing changes. Unprotected traffic — range requests for media, encoded assets, non-JSON payloads, `226` deltas — is forwarded exactly as before, and the presentation rule above still keeps `206`/`226` bodies untouched.
- **A configured body policy claims the response.** The representation must be inspectable, or the response is rejected. It is never forwarded unchanged, because doing so would report a redaction that did not happen.

What is inspectable:

- **Content codings.** `gzip` (including `x-gzip`) and `br` are decoded in a bounded pre-transform phase, including stacked codings, which are undone in reverse order. The decoded body is capped at the smaller of 10 MiB and the configured `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`, and the coding list at 4 entries, so a decompression bomb is rejected rather than materialized. A deployment that sets the response-body limit below 10 MiB therefore rejects at that lower configured bound, not at 10 MiB: enabling a body policy must not buy a larger effective ceiling than the operator configured. (`0` is the usual "unlimited" spelling for that limit, and leaves the 10 MiB hard ceiling in force.) Any other coding (`zstd`, `deflate`, a private coding), a malformed or truncated stream, or output past the cap is a rejection. After a successful decode the response is served as identity: `Content-Encoding` is dropped and `Content-Length` recomputed, so the bytes every transform and the client see are the bytes the policy was evaluated against.
- **Partial and delta representations.** A `206` range slice or a `226` delta is only a fragment. Ferrum does not fetch the remaining ranges or apply the delta, so it cannot produce the complete resource — and it must not present a rewritten fragment as one. A claimed fragment is **rejected**; it is never relabeled as a complete `200`, which would misrepresent the resource and let downstream caches store a truncated body under the full resource's identity.
- **Document parseability.** A body whose media type the policy operates on must parse as a complete document. A JSON body that does not parse is a rejection, not a silent pass-through. A body that parses cleanly but that no configured rule happens to match is an ordinary no-op and is served unchanged.
- **Framed gRPC is not a document.** On a gRPC or gRPC-Web request whose response carries a framed media type, the frames are not a document a field rule could act on, so the policy declines them rather than rejecting a valid RPC reply. The backend's pristine `Content-Type` answers first. When the backend stamped none at all, the request's own representation selects exactly one framing grammar — DATA frames for native gRPC, DATA plus one FINAL trailer frame for gRPC-Web binary, and the base64 of that for gRPC-Web text — and the bytes must be a total parse against that one grammar; testing the union of all three would let a byte string that is framing in some *other* mode skip the fail-closed rejection. gRPC-Web text is decoded segment-wise, because a text-mode producer may flush (and therefore pad) at frame or chunk boundaries, so interior `=` padding is valid rather than a defect. A `Content-Type` an `after_proxy` hook *added* to a response the backend sent untyped does not override that parse: it describes nothing the backend proved, and letting it claim complete frames as JSON turned working replies into `502`s. Bytes that are not exactly a complete frame sequence stay claimed, so a genuine JSON document under a hook-added or hook-removed type is still inspected and redacted.
- **Provable origin state.** Encoding and range/delta state are read from a snapshot taken before any `after_proxy` hook can mutate the response headers, never from the live header map — a header-only rule that removes `Content-Encoding`, or a hook that rewrites a `206` to `200`, cannot hide the original representation. A backend response that reaches the body phase without that snapshot cannot prove its representation and is rejected. Gateway-generated bodies (mock, semantic-cache hit, serverless terminate, dedup replay) never took that snapshot, so their live headers are read directly.
- **Fragment evidence is status-semantic.** One rule decides whether a status and its headers are evidence that the body is a fragment, and both provenances apply it — a backend response applies it once to its pristine snapshot, gateway-generated bytes apply it to their live headers. A `206`/`226` is always a fragment. On any other `2xx`, a `Content-Range` or `IM` is still treated as one, since that is the shape a fragment whose status was rewritten would take, and over-detecting here only rejects. On a non-`2xx` it is not: a `1xx` carries no content at all, and `3xx`/`4xx`/`5xx` content describes the redirection or the error condition rather than a successfully delivered range or delta of the selected resource. `IM` is defined only for `226` (RFC 3229 §10.5.3). `Content-Range` is also defined on a `416`, in its unsatisfied-range form (RFC 9110 §14.4, §15.5.17), but there it reports the selected representation's current length rather than describing the response content — the `416` body is still a complete status document. On any other non-`2xx` the header is stale metadata with no defined meaning. Either way such a body is a complete, inspectable document: the policy is applied to it and the stale metadata is invalidated by the rewrite, rather than the response being rejected. Treating every marker as fragment evidence would fail closed on ordinary `416`/`429`/`503` replies while protecting nothing.
- **Earlier body rejections are preserved.** The gate runs after `on_response_body`, which may already have replaced the backend response with a plugin rejection. Those bytes are gateway-generated, and the gate treats them as such: it judges them on their own live headers instead of against the replaced backend response's snapshot, so a legitimate gateway `403` is never decoded as though it were the backend's gzip body or rejected as though it were the backend's `206` and overwritten with a generic `502`.

A rejection is served in the client's flavor: a trailers-only gRPC `INTERNAL` error for `application/grpc` and gRPC-Web, and a `502` JSON body otherwise. Native gRPC selection comes from the immutable inbound request classification, while gRPC-Web keeps its separately retained binary/text response flavor; an `after_proxy` policy that removes or relabels the response `Content-Type` cannot change either error shape. All three shapes follow the same header discipline as every other buffered terminal response: the map is rebuilt from provenance-known gateway output, so no header describing the rejected representation (`Set-Cookie`, validators, cache directives) survives onto the gateway-authored error, and the opt-in `applies_after_proxy_on_reject` decorators still run so CORS, correlation, and security headers are preserved exactly as they are for an ordinary body reject. The client-visible message states only that inspection failed; the specific reason (`unsupported_content_coding`, `malformed_content_coding`, `decoded_body_too_large`, `partial_representation`, `unparseable_document`, `unproven_origin_state`, `identity_coding_unacceptable`, `unenforceable_grpc_web_framing`) is recorded in transaction metadata for operators and is not echoed to the caller. `identity_coding_unacceptable` is the newest of these: inspecting a protected encoded body means publishing it as identity, so a client whose original `Accept-Encoding` forbids the identity coding (`identity;q=0`, or `*;q=0` with no explicit non-zero `identity`) cannot be served either representation, since the gateway does not re-encode. That acceptability is judged against the `Accept-Encoding` captured at request init, before any `before_proxy` hook can rewrite it. `unenforceable_grpc_web_framing` covers the one route where enforcement is structurally impossible: a TRANSLATED gRPC-Web request has its buffered body re-encoded by `grpc_web` (priority 260) before `response_transformer` (priority 4000) is handed it, so a claimed backend body that is not already native gRPC framing would be rewrapped and published unredacted no matter what the field rule did. Such a backend reply is broken regardless — the backend was spoken to as `application/grpc` — so it is rejected rather than admitted. Native gRPC and pass-through (retained-only) gRPC-Web routes run no re-encoder after the enforcer and are unaffected, as are gateway-generated bodies, whose own rejection response must survive. Deployments alerting or dashboarding on `ferrum:representation_rejected` should include these labels in the set they match.

A gRPC-Web rejection carries `grpc-status`/`grpc-message` in the body trailer
frame, and the wire trailers and initial terminal fields are cleared on purpose
because that is the shape the client must receive. Transaction metadata keeps
the synthesized status anyway, so logs, transaction summaries, and the
Prometheus status bucket report the `INTERNAL` the client actually got rather
than the `UNKNOWN` an empty header/trailer map would otherwise synthesize. A
status present in either map still wins, so a genuine response-hook edit is
never ignored.

That gateway-header provenance is captured before response hooks whenever a
configured body policy may reject, even when the request has no RPC deadline.
This keeps ordinary gRPC and gRPC-Web rejection decorators without widening the
trusted set to backend fields that happen to use the same header names.

Successful content decoding is itself a client-visible representation rewrite,
including when no later body rule matches. Native H3 therefore drops backend
trailers after a decode just as it does after an ordinary body transform.
Buffered gRPC retires application trailers and their merged compatibility
copies while preserving only reserved RPC completion metadata (`grpc-status`,
`grpc-message`, and status details) on the terminal channel. Unclaimed or
identity-coded responses that no body rule changes retain their original
trailers.

For gateway-generated rejection responses, a small set of header-only `after_proxy` plugins opt in to still run. This preserves headers such as `Access-Control-Allow-Origin`, `traceparent`, and request IDs on rejected responses without treating them as backend responses.

An RPC deadline discovered while buffering an upload is finalized through this same rejection path even when it occurs before authentication, authorization, `before_proxy`, or backend dispatch. Immediately-ready non-replacing decorators and committed observers run against the canonical status-4 result before it is emitted, gRPC-Web translation happens only after those synchronous headers are finalized, and the rejection is logged before the frontend returns. If a rejection or committed hook is still pending when the deadline wins, that exact invocation and the remaining eligible hooks continue once, in priority order, on owned response/context state under a bounded detached cleanup task. Their late mutations cannot race or delay the client-visible response. Response-replacing hooks cannot overwrite an already-selected terminal deadline.

For a deadline-bound buffered backend response, the core establishes a response-header provenance boundary before the first `after_proxy` hook. Backend fields begin outside the terminal-response set; each completed trusted hook records only fields it added, changed, removed, or explicitly owns (for example, the configured correlation-header name, a `response_transformer`/route-override `update` that overwrites with an operator-configured value, or the destination of a `response_transformer` `rename` rule that actually fired). Because ownership is declared rather than inferred from a value diff, a completed exact-value write is retained even when the backend pre-populated the identical key/value, so a backend cannot suppress a gateway decoration by echoing it first. A `rename` is included for the same reason: mutation tracking observes only the source removal, so a backend that also sent the destination key carrying the value the rename produces would otherwise suppress the transformer's write. Conversely, a change that merely APPENDS to a field is credited only for what it appended: a route-override response `add` rule extends an existing backend value with a comma, so the gateway-owned set records only the appended list elements and the backend's own portion is discarded rather than crossing onto the terminal response. Declared ownership is unaffected, because it is only ever declared for unconditional replacements, whose whole operator-configured value is gateway output even when it re-states an element the backend also sent. If a later normalizer, body transform, or committed observer exhausts the deadline, the terminal response is rebuilt from that gateway-owned set rather than from a header-name allowlist. Backend cookies, credentials, representation metadata, arbitrary fields, and spoofed decorator names are discarded, but a gateway hook's own `Set-Cookie` (for example `oidc_relying_party` rotating the session cookie so the client applies it, or the load balancer's sticky-affinity cookie injected by proxy core) is retained because it is gateway output, not backend metadata. `Set-Cookie` provenance is tracked per line and per OCCURRENCE: every occurrence the backend supplied is dropped, and only the surplus a trusted phase added crosses, so multiplicity is preserved exactly. One consequence is deliberate — a gateway phase that authors a line byte-identical to a backend line is credited with that copy, because the alternative (dropping every matching occurrence) silently destroys deterministic gateway cookies such as affinity cookies and session refreshes that reproduce the upstream value. Occurrence surplus is the defence against an APPENDING phase, so it does not govern a phase that declares ownership of `Set-Cookie` and REPLACES the field (a `response_transformer` `update` to `set-cookie`, or a `rename` whose destination is `set-cookie`): a replacement overwrites the whole field, so no backend line survives underneath it, its operator-configured value is retained even when the backend sent a byte-identical cookie, and the backend baseline it overwrote is retired unconditionally — including when a gateway append follows the replacement before the same provenance record, where both the replacement cookie and the appended one are gateway output. Ownership therefore means REPLACEMENT and is never declared by an appending phase: proxy core's sticky-affinity injection records its mutation without claiming the field, so a co-present backend cookie stays on the occurrence-partition branch and cannot ride the append onto the terminal response. A phase that appends a known operator-configured element set onto a list-valued field the backend may also have sent (`grpc_web` writing `access-control-expose-headers` from its configured `expose_headers`) uses a third form: it retires one backend baseline occurrence per element it authored, so the ordinary occurrence partition credits exactly its configured elements while backend-only tokens keep their baseline occurrence and are still discarded. The cookies such a replacement discarded do not return — only the value the trusted phase actually wrote crosses. Cache state, discarded-representation metadata, transport framing, and prior gRPC terminal fields remain owned by the terminal response and are removed even when a completed gateway hook wrote them; the narrow `Vary: Origin` compatibility contract and gateway-authored `Set-Cookie` cross independently. Protocol framing is then regenerated and deterministic initial-response policies are reapplied. A later generic sanitation pass never erases another completed trusted decorator, and when a completed decorator chain is followed by a later `after_proxy` hook that itself exhausts the deadline, the resulting terminal rejection preserves the gateway output those completed hooks already recorded instead of restarting from the deadline error headers. A pending or cancelled hook cannot publish partial mutations.

Post-routing method-filter responses and native-gRPC gateway errors also apply the resolved route's precomputed initial-response policy at the client HEADERS boundary. Pre-routing failures have no resolved plugin configuration. Protocol-owned gRPC terminal metadata and HTTP framing are restored after policy.

`after_proxy` rejections are also honored before anything is sent downstream. This matters for plugins like `response_size_limiting`, whose `Content-Length` fast path now replaces oversized backend responses instead of only logging a warning.

`on_response_committed` is buffered-only and observe-only. It receives mutable request context plus the final client-visible status, headers, and body after every `on_final_response_body` hook and any rejection replacement. It cannot mutate or reject the response. Exporters use it for record construction while retaining fail-closed sink admission in an earlier rejecting hook. Each opted-in hook is invoked at most once. If the gRPC deadline expires inside one committed hook, the gateway first replaces the outcome with the terminal `DEADLINE_EXCEEDED` representation, then transfers that pending invocation and the remaining committed hooks to owned state. They continue in order under a post-response timeout, so a blocked exporter cannot retain the H1/H2/H3 response writer indefinitely. The proxy uses a precomputed per-protocol committed-hook list, so normal buffered requests do not rescan the full plugin chain.

If `on_response_body`, the shared representation gate, or a body-transform deadline has already selected a gateway-authored terminal response, the remaining presentation/protocol transforms may still run to preserve the client's wire shape, but `on_final_response_body` is skipped. A final validator or storage hook must never reinterpret the gateway's error payload and replace the first fail-closed decision. `on_response_committed` still observes the response that will actually be sent.

`on_response_stream_terminated` is streaming-only. It receives mutable request context plus the terminal body outcome and response status, cannot replace the response or access a full body buffer, and fires before the final `TransactionSummary.metadata` snapshot and `log` from the same deferred terminal path used for streaming accounting. It is distinct from `ResponseStreamInspector` chunk inspection: this hook is for state cleanup, accounting, and aggregate metadata write-back after the stream ends. Plugins can key bounded shared inspector state by `ctx.response_stream_id()`, remove it here on every terminal outcome (including client disconnect), and write the aggregate into `ctx.metadata`; for example, `ai_tool_governor` writes streamed dry-run decisions before transaction logging. `request_deduplication` uses the same hook to release an ordinary non-buffered streamed marker on clean completion (`body_completed`) but intentionally retains it until `inflight_ttl_seconds` when the stream is interrupted (client disconnect or backend error). When the stream sits behind a declared completed external operation — a terminate-mode `serverless_function` that may already have executed before `on_error: continue` fell through to the stream, or a plugin that marked `ferrum:external_operation_completed` — the hook instead publishes a durable non-replayable 409 completion tombstone (locally, and in Redis through the fenced ownership transition) on both clean and interrupted terminations. That closes the gap where an already-charged operation became re-executable the moment the raw in-flight lease expired: a same-key retry is refused for `max(ttl_seconds, inflight_ttl_seconds)`, never merely for `inflight_ttl_seconds` and never for less.

### Synthetic-response completion contract

A plugin that short-circuits the chain with `Reject`/`RejectBinary` produces a
*synthetic* response. Ownership plugins such as `request_deduplication` cannot
tell from the response bytes whether that short-circuit merely fabricated a
representation or actually performed the protected operation, so the producing
plugin must declare it:

| Provenance | Declared by | Ownership outcome |
|---|---|---|
| Harmless synthetic response (`response_mock`, `fault_injection`, `request_termination`, `ai_semantic_cache` / `response_caching` hit) | nothing to declare; the shared reject finalizer records `ferrum:finalized_synthetic_response` for successful shapes | token-matched release on commit; the synthetic body is never stored under the idempotency key |
| Committed before any external operation could start (payload validation, unsupported-protocol refusal, DNS/egress denial, proven pre-wire transport failure) | `ferrum:release_dedup_inflight_on_commit`, or `serverless_function`'s pre-invocation rejection owners | token-matched release on commit, so a corrected retry proceeds immediately |
| The short-circuit performed the protected billable/side-effecting operation | `ferrum:external_operation_completed` (`ai_federation`), or `serverless_function` terminate-mode side-effect owners | ownership is **not** released; a durable non-replayable 409 completion tombstone is published for `max(ttl_seconds, inflight_ttl_seconds)`, fenced in Redis mode |

For the last row, a terminate-mode `serverless_function` response that *can* be
retained is published as an ordinary replayable completion for `ttl_seconds`, so
an identical retry receives the real function response instead of a conflict. The
non-replayable tombstone is what the key falls back to whenever that response
cannot be persisted as a replay — no safe representation exists, storage capacity
or the Redis payload cap rejects it, or its replay provenance is unusable because
the request straddled a response-presentation-policy publication or that policy
is incomplete/`Dynamic`. The completion barrier is never downgraded to the bare
in-flight lease in those cases: the same fenced ownership transition publishes the
409 barrier for `max(ttl_seconds, inflight_ttl_seconds)`. If response-byte
admission fails locally, the exact owner is atomically replaced by a fixed-size
execution barrier with that same retention. If later capacity pressure evicts a
protected completion, its barrier inherits the completion's original insertion
time and retention rather than starting a fresh `inflight_ttl_seconds` lease.
Redis publication remains compare-and-set fenced, and a stale hook cannot clear
either the barrier or a successor owner. Per-key barriers are hard-capped at
`max_entries`; overflow is collapsed into one fixed process-global deadline
that returns 503 for applicable idempotency-key requests until the longest
displaced completion deadline, rather than allocating unbounded key state or
failing open.

These markers are internal (`ferrum:`-prefixed) and cannot be set from public
request metadata or from a backend response header. A new plugin that spends
money or mutates remote state behind a short-circuit and declares nothing will
be treated as harmless, and identical idempotency-key retries will repeat the
operation — declare the provenance or define an equivalent completion contract.

The absolute gRPC response-deadline wrapper sits outside the response-inspector chain. Its partial-DATA decision therefore counts only bytes emitted by the final inspected body, not backend chunks an inspector consumed and buffered. If an inspector has emitted zero bytes when the deadline fires, the client still receives the clean status-4 terminal representation.

## Stream Proxy Lifecycle (TCP/UDP)

TCP and UDP stream proxies use a separate two-phase lifecycle. Since there is no HTTP request/response structure, only protocol-agnostic plugins (those declaring `ALL_PROTOCOLS`) and protocol-specific plugins (e.g., `tcp_connection_throttle` for TCP, `udp_rate_limiting` for UDP) participate.

```
Connection/Session In
    │
    ▼
┌─────────────────────────┐
│ 1. on_stream_connect    │  Gating: IP restriction, rate limiting, ID assignment
└────────────┬────────────┘
             │
             ▼
       ┌───────────┐
       │  Proxy     │  Bidirectional stream copy (TCP) or datagram forwarding (UDP)
       └─────┬─────┘
             │
             ▼
┌─────────────────────────┐
│ 2. on_stream_disconnect │  Logging, metrics, tracing (fire-and-forget)
└─────────────────────────┘
```

Body-aware plugins such as `graphql`, request-side `body_validator`, `openapi_validator`, `waf`, `ai_semantic_firewall`, `ai_request_guard`, `ai_prompt_shield`, and `ai_prompt_compressor` now pre-buffer only matching request bodies (for example JSON `POST` requests). Non-matching requests can continue on the faster streaming path.

`waf` request metadata inspection (path, query, headers, cookies, and method) runs in the `authorize` phase at priority 2930, after authentication and earlier authorization plugins such as `access_control`, `mesh_authz`, `opa`, and consumer-aware `rate_limiting`. Authenticated proxies that reject during auth/authz therefore avoid WAF scan cost, while public/no-auth proxies still run WAF before backend dispatch. WAF request-body inspection remains on the final backend-visible request body.

**Phase 1 — `on_stream_connect`**: Runs after the client connection is accepted (TCP) or the first datagram from a new client creates a session (UDP). For TCP+TLS and UDP+DTLS listeners it runs after the frontend TLS/DTLS handshake and before the backend connection/session is opened, so plugins can inspect the client certificate without spending upstream capacity first. Frontend TLS/DTLS handshake failures do not fire stream plugins; plugin rejects close the frontend connection/session immediately and do not dial the backend. Plugins can also insert metadata (e.g., trace IDs) into `ctx.metadata`, which is carried through to `on_stream_disconnect`. Built-in correlation IDs remain in private lifecycle state and are authoritatively projected into terminal metadata after plugin-writable merges. Built-in admission plugins can instead attach opaque connection permits; TCP runners release all permits in reverse order immediately when a later plugin rejects, and normal connection teardown releases any remaining permits exactly once.

**Phase 2 — `on_stream_disconnect`**: Runs after the stream completes (TCP connection closed, or a UDP/DTLS session expires, is cleaned up, or otherwise ends). Receives a `StreamTransactionSummary` with bytes transferred, duration, error info, and metadata from the connect phase. Fire-and-forget — does not block cleanup.

Captured Sidecar/Ambient raw-TCP and UDP **egress** bypasses the generic stream proxy because it is relayed through a mesh CONNECT tunnel. Those handlers run only the `workload_metrics` connect/disconnect lifecycle, once per logical captured session, to produce the source-side outbound CLIENT span with final duration, bytes, and error state. They do not run authentication, authorization, throttling, or other policy plugins a second time; destination-side mesh authorization remains the enforcement point.

### Stream Hook Implementations by Plugin

| Plugin | `on_stream_connect` | `on_stream_disconnect` | Behavior |
|--------|:-------------------:|:----------------------:|----------|
| `ip_restriction` | ✓ | | Rejects connections from denied IPs |
| `spiffe_identity` | ✓ | | Extracts peer SPIFFE IDs from TLS/DTLS client certificates |
| `mtls_auth` | ✓ | | Maps the client certificate to a Consumer on TCP+TLS or UDP+DTLS |
| `access_control` | ✓ | | Applies consumer and group allow/deny rules once a stream Consumer exists |
| `mesh_authz` | ✓ | | Applies Layer 2 mesh authorization policies from SPIFFE/HBONE identity |
| `tcp_connection_throttle` | ✓ | | Owns an opaque permit that caps process-local active TCP/TCP+TLS connections per Consumer, else canonical client IP; UDP/DTLS attachment is rejected |
| `geo_restriction` | ✓ | | Rejects connections from denied countries |
| `rate_limiting` | ✓ | | Consumer-aware rate limiting when a stream identity exists, else IP-based |
| `correlation_id` | ✓ | | Assigns a UUID request ID to metadata |
| `otel_tracing` | ✓ | ✓ | Generates trace/span IDs; emits structured trace log |
| `stdout_logging` | | ✓ | JSON access log for stream connections |
| `statsd_logging` | | ✓ | Sends stream connection and WebSocket session metrics to StatsD over UDP |
| `http_logging` | | ✓ | Sends stream connection logs to webhook endpoint |
| `tcp_logging` | | ✓ | Sends stream connection logs to TCP/TLS endpoint |
| `kafka_logging` | | ✓ | Sends stream connection logs to Kafka topic |
| `loki_logging` | | ✓ | Sends stream connection logs to Grafana Loki |
| `udp_logging` | | ✓ | Sends stream connection logs to UDP/DTLS endpoint |
| `ws_logging` | | ✓ | Sends stream connection logs to WebSocket endpoint |
| `prometheus_metrics` | | ✓ | Records `ferrum_stream_connections_total` counter and `ferrum_stream_duration_ms` histogram |
| `api_chargeback_sink` | | ✓ | Exports durable stream charge events or snapshot deltas to ClickHouse |
| `workload_metrics` | ✓ | ✓ | Adds direction-aware mesh source/destination labels to stream metadata and emits mesh spans when Telemetry providers are configured |
| `transaction_debugger` | | ✓ | Prints typed terminal diagnostics for stream connections |

### When Hooks Fire

| Protocol | `on_stream_connect` fires | `on_stream_disconnect` fires |
|----------|--------------------------|------------------------------|
| **TCP** | After `accept()`, before backend connection | After bidirectional copy completes |
| **TCP+TLS** | After TLS handshake, before backend connection | After bidirectional copy completes |
| **UDP** | On first datagram from new client (session creation) | When session is cleaned up (idle timeout) |
| **UDP+DTLS** | After DTLS `accept()`, before backend connection | When DTLS handler exits |

## WebSocket Frame Lifecycle (`on_ws_frame`)

WebSocket connections go through the normal HTTP plugin pipeline during the upgrade handshake — authentication, authorization, rate limiting, and all other HTTP phases execute before the connection is upgraded. Once the WebSocket upgrade completes, parser policies and message-level hooks kick in.

Successful upgrade responses do not run the general asynchronous `after_proxy`
chain. They run the ordered `apply_websocket_handshake_response_headers`
boundary instead, with status 101 for H1 and 200 for H2/H3. The hook cannot
reject or perform I/O after the backend has accepted the session. Ferrum then
strips connection/framing/WebSocket transport fields, adds the authoritative
H1 Upgrade fields or Extended CONNECT response, preserves the verified backend
subprotocol, and appends any gateway-owned sticky cookie. `correlation_id`
uses this boundary to echo generated and preserved IDs consistently.

Plugins that opt into `on_ws_disconnect` receive exactly one terminal callback
after both relay directions finish, including clean closes, typed errors, drain
timeouts, and upgrades that never establish frame flow. The disconnect-plugin
list is cloned from the same request-generation snapshot that accepted the
upgrade, so a configuration reload cannot mix plugin generations within a live
session. `transaction_debugger` emits the ordinary HTTP handshake terminal
diagnostic plus one WebSocket terminal diagnostic. Both expose the same
selected `request_id` / `trace_id` correlation metadata when present, after
central sensitivity classification; neither dumps raw metadata.

The `on_ws_frame` phase fires for every complete **Text**, **Binary**, **Ping**,
and **Pong** message yielded by tungstenite in both directions. Text/Binary
continuations are reassembled before this ordinary hook. Parser-level size
policy is the exception: `ws_message_size_limiting` installs the strictest
configured actual-frame and reassembled-message ceilings before either parser
reads, so continuation payloads are checked individually before allocation.

Physical fragments that produce no message — the initial non-final Text/Binary
frame and every intermediate continuation, including zero-length ones — are
metered inside the codec and charged through the separate
`on_ws_reassembly_frames` hook, which runs **before** the `on_ws_frame` chain
for the read that surfaced them (and also for an interleaved Ping/Pong that
arrives mid-reassembly). The completing frame is charged once by the ordinary
message hook, so each wire frame is counted exactly once. Observational plugins
are skipped for fragment batches and only a returned `Message::Close` is
honored. Independently, `FERRUM_WEBSOCKET_MAX_INCOMPLETE_MESSAGE_FRAMES` and
`FERRUM_WEBSOCKET_MAX_INCOMPLETE_MESSAGE_SECONDS` bound the in-flight
reassembly itself and close both peers with code 1008.

Peer-originated **Close** frames take a separate forward path: mutating
admission hooks are skipped so a later plugin cannot replace the peer's
code/reason, while observational delivery hooks (see below) still record the
successfully forwarded Close. Plugin-generated rejection Closes are visible to
observational `on_ws_frame` hooks inside the applicator as the final decision.

```
WebSocket Upgrade (HTTP pipeline: authenticate → authorize → before_proxy → ...)
    │
    ▼
┌─────────────────────────────────────┐
│  Frame Forwarding Loop              │
│                                     │
│  ┌───────────────────────────────┐  │
│  │ on_ws_frame (ClientToBackend) │──┼── For each Text/Binary/Ping/Pong from client
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │ control-frame guard           │──┼── Restore illegal Ping↔Pong flips
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │ destination send              │──┼── Success-only frame/byte counters
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │ emit_ws_frame_delivery        │──┼── Observational logs (final message)
│  └───────────────────────────────┘  │
│                                     │
│  ┌───────────────────────────────┐  │
│  │ on_ws_frame (BackendToClient) │──┼── For each Text/Binary/Ping/Pong from backend
│  └───────────────────────────────┘  │
│  … same guard → send → delivery …   │
│                                     │
│  Peer Close → forward → delivery    │── No mutating hooks; log after accept
└─────────────────────────────────────┘
```

Delivery-accurate observers prepare metadata before `send()` (so large payloads
are not cloned solely for logging) and emit only after the sink accepts the
write — the same success boundary as `frames_*` / `bytes_*`. Cancelled or failed
writes discard the prepared observation. `ws_frame_logging` uses this path for
ordinary frames and peer Close (`outcome=delivered`) and records plugin
rejection Closes separately (`outcome=policy_close`) when it observes the final
decision in the mutating chain.

### Connection Tracking

Each WebSocket connection is assigned a `connection_id` — a monotonic `u64` counter unique within a single gateway process. Plugins use this identifier for per-connection state tracking (e.g., per-connection rate limit buckets, per-connection frame counters). The same admission ID is passed to every `on_ws_frame` call and copied into `WsDisconnectContext` at teardown so frame and disconnect observers share one session key without a lookup map.

The identifier is **process-local**, not globally unique across gateway instances. Operators aggregating multi-instance logs must join on `(gateway_instance_id, proxy_id, connection_id)` (or an equivalent host/process identity + `proxy_id` + `connection_id` tuple).

### Frame Rejection

Plugins can return `Some(Message::Close(...))` to close the connection in both
directions. The first terminal Close from a priority-ordered admission/mutating
`on_ws_frame` hook is preserved for the rest of the chain: later mutating
plugins (including additional `ws_rate_limiting` instances) are not invoked for
that frame, so they neither charge local/Redis budget nor replace the Close
code/reason. Observational hooks that opt in via
`observes_ws_frame_decisions()` (today: `ws_frame_logging`) still receive the
already-final Close so they can record the decision. The relay then records the
first detailed policy Close, signals shared cancellation before any potentially
backpressured write, then attempts the same protocol-valid Close to both peers
under a short bound. Parser-level size rejections
(`ws_message_size_limiting` via `websocket_size_limits`) never enter the
post-reassembly hook chain and use the same dual-peer Close path with code 1009.

### Execution Order

Plugins execute in priority order (lower number runs first):

| # | Plugin | Priority | Behavior |
|---|--------|----------|----------|
| 1 | `ws_message_size_limiting` | 2810 | Pre-read actual-frame and bounded-reassembly policy; closes both peers with 1009 |
| 2 | `ws_rate_limiting` | 2910 | Per-connection token-bucket rate limiting, charged per physical frame (fragments batched via `on_ws_reassembly_frames`) |
| 3 | `ws_frame_logging` | 9050 | Logs final delivered frame metadata (and policy Close decisions); never mutates |

### Zero-Overhead Opt-In

When no plugin contributes parser policy or returns `true` from
`requires_ws_frame_hooks()`, tunnel mode may use raw copy and the parsed relay
otherwise forwards messages without entering plugin hooks. This aggregate
framing requirement is pre-computed per proxy in `PluginCache` at reload time.

## UDP Datagram Lifecycle (`on_udp_datagram`)

UDP proxies support per-datagram plugin hooks that fire before each client-to-backend and backend-to-client datagram is forwarded. This is separate from the `on_stream_connect`/`on_stream_disconnect` lifecycle, which fires once per session.

```
Session Established (on_stream_connect already ran)
    │
    ▼
┌─────────────────────────────────────┐
│  Datagram Forwarding Loop           │
│                                     │
│  ┌───────────────────────────────┐  │
│  │ on_udp_datagram               │──── For each datagram in either direction
│  │ (returns Forward or Drop)     │
│  └───────────────────────────────┘  │
│                                     │
└─────────────────────────────────────┘
```

### Execution Order

| # | Plugin | Priority | Behavior |
|---|--------|----------|----------|
| 1 | `udp_rate_limiting` | 2915 | Per-client-IP datagram and byte rate limiting |

### Silent Drop Semantics

Unlike HTTP plugins which return status codes and response bodies, UDP datagram plugins return `UdpDatagramVerdict::Drop` to silently discard the datagram. This is standard UDP behavior — there is no error response to send.

### Direction Handling

`UdpDatagramContext.direction` is `ClientToBackend` for inbound datagrams and `BackendToClient` for backend responses. Built-in `udp_rate_limiting` intentionally shares one per-client window across both directions; plugins that need asymmetric policy should branch on `ctx.direction`.

### Zero-Overhead Opt-In

When no plugins on a proxy return `true` from `requires_udp_datagram_hooks()`, the datagram forwarding loop has zero overhead — datagrams are forwarded directly without entering the plugin pipeline. The flag is checked once at listener startup.

Both plain UDP and DTLS frontend paths support per-datagram hooks.

## Priority Bands

Within each lifecycle phase, plugins are sorted by **priority** (lower number runs first). Each plugin has a built-in priority constant, but this can be overridden per plugin-config via the `priority_override` field (0–10000). When two plugins share the same effective priority, their relative order is stable (based on config order) but not explicitly controllable — use `priority_override` to guarantee ordering.

Multiple instances of the same plugin type are supported on a single proxy (e.g., two `http_logging` instances for different log destinations). When merging global, proxy-scoped, and proxy-group-scoped plugins, a scoped plugin replaces only the **global** plugin of the same name — other scoped instances of the same type are preserved. See [Plugin Scope](plugins.md#plugin-scope-merging) for the full merging rules and examples.

**Exception — `api_chargeback`:** merge still preserves scoped same-name instances, but admission then rejects any proxy whose effective list retains more than one `api_chargeback`. The shared `/charges` registry has no instance/ledger dimension, so multiple hooks would double-count one client transaction. Shared render/cleanup tunables must also agree across every enabled instance in the process. See [api_chargeback](plugins.md#api_chargeback).

Priority bands are spaced with gaps so future plugins can slot in without renumbering:

| Band | Priority Range | Purpose | Plugins |
|------|---------------|---------|---------|
| **Early** | 0–949 | Matched-request tracing, IDs, preflight, and short-circuiting before auth | `otel_tracing` (25), `correlation_id` (50), `cors` (100), `request_termination` (125), `mesh_outbound_registry` (130), `ip_restriction` (150), `geo_restriction` (175), `bot_detection` (200), `spec_expose` (210), `sse` (250), `grpc_web` (260), `grpc_method_router` (275), `spiffe_identity` (940) |
| **AuthN** | 950–1999 | Authentication / identity verification | `mtls_auth` (950), `jwks_auth` (1000), `oauth2_introspection` (1050), `oidc_relying_party` (1075), `jwt_auth` (1100), `key_auth` (1200), `ldap_auth` (1250), `basic_auth` (1300), `hmac_auth` (1400), `soap_ws_security` (1500) |
| **Admission** | 2000–2999 | Authorization, validation, and request admission control | `access_control` (2000), `tcp_connection_throttle` (2050), `mesh_authz` (2075), `opa` (2080), `adaptive_concurrency` (2090), `ai_transcript_audit` (2740), `request_deduplication` (2750), `request_size_limiting` (2800), `ws_message_size_limiting` (2810), `graphql` (2850), `rate_limiting` (2900), `ws_rate_limiting` (2910), `udp_rate_limiting` (2915), `ai_prompt_shield` (2925), `waf` (2930), `fault_injection` (2940), `body_validator` (2950), `openapi_validator` (2960), `ai_semantic_firewall` (2968), `ai_request_guard` (2975), `ai_tool_governor` (2978), `ai_stream_router` (2984), `mcp_gateway` (2992), `a2a_gateway` (2993), `mesh_route_dispatch` (2995), `ai_semantic_cache` (2996) |
| **Transform** | 3000–3999 | Request shaping and response buffering decisions | `request_transformer` (3000), `serverless_function` (3025), `response_mock` (3030), `grpc_deadline` (3050), `load_testing` (3070), `request_mirror` (3075), `response_size_limiting` (3490), `response_caching` (3500) |
| **Response** | 4000–4999 | Response transformation, compression, security headers, and AI accounting | `response_transformer` (4000), `compression` (4050), `ai_prompt_compressor` (4055), `ai_federation` (4060), `ai_response_guard` (4075), `security_headers` (4080), `ai_token_metrics` (4100), `ai_rate_limiter` (4200) |
| **Custom** | 5000 | Default for unrecognized/custom plugins | _(future plugins)_ |
| **Logging** | 9000–9999 | Observability and frame logging | `stdout_logging` (9000), `ws_frame_logging` (9050), `statsd_logging` (9075), `http_logging` (9100), `tcp_logging` (9125), `kafka_logging` (9150), `loki_logging` (9155), `udp_logging` (9160), `ws_logging` (9175), `transaction_debugger` (9200), `proxy_alerts` (9250), `prometheus_metrics` (9300), `api_chargeback` (9350), `api_chargeback_sink` (9351), `workload_metrics` (9360), `__mesh_bpf_metrics` (9365), `transaction_log_schema` (9999, config-only) |

`soap_ws_security` keeps AuthN-band priority 1500 for ordering, but validates SOAP bodies in `before_proxy` after request-body buffering is available.

`serverless_function` also runs in `before_proxy`. With `forward_body: true` it receives the exact lossless client representation before any request-body transform. Candidate admission and cache construction therefore reject a same-protocol chain that also contains a body transformer (including request decompression); the same capability-based validation covers registered custom body-egress plugins. Candidate admission derives the built-in serverless protocol, effective priority, `mode`, and `forward_body` capabilities without constructing its environment-bound HTTP/AWS client, so a CP can validate composition without requiring credentials that intentionally exist only on DPs. Runtime cache construction still resolves and validates those node-local values as a fail-closed backstop. Ferrum does not allow an external decision to govern bytes different from those ultimately dispatched. Non-identity encoded bodies fail closed before function egress. When a terminate-mode instance shares a protocol chain with `request_deduplication`, every deduplication instance must have a strictly lower effective priority so retry ownership exists before the function can execute; candidate admission and cache construction reject equal or reversed ordering.

`mcp_gateway` sits at priority 2992: generic admission/auth/body validation runs first, then MCP JSON-RPC metadata is extracted and aggregate-router calls can set `RequestContext.route_override_*` before final route-dispatch plugins and request transformers. It is HTTP-only and does not implement generic auth, rate limiting, retry, timeout, tracing, WAF, DLP, or semantic safety behavior; those remain separate Ferrum plugins that can consume emitted `mcp.*` metadata.

`a2a_gateway` sits at priority 2993: it runs after MCP handling and before final mesh route dispatch. It observes HTTP JSON-RPC, HTTP+JSON/REST, and gRPC A2A methods, applies optional method policy, rewrites HTTP Agent Card responses, and emits `a2a.*` metadata. It preserves SSE/gRPC streaming and does not own A2A task state.

`mesh_route_dispatch` intentionally sits at priority 2995: authentication, `mesh_authz`, and rate limiting evaluate the original public proxy identity, then route overrides apply before request transformers, mirror/serverless/caching plugins, and backend dispatch. For node-waypoint Service egress with scoped mesh policies, `mesh_authz` stamps the authorized Service upstream and `mesh_route_dispatch` rejects any matching rule that would rewrite that request to a different upstream or direct backend. When multiple instances are attached to the same proxy, each matching instance replaces the complete override destination and route-local timeout/retry policy from earlier instances; a non-matching later instance leaves any earlier match in place. Per-rule `backend_tls` is only valid for direct `backend_host`/`backend_port` destinations; `upstream_id` destinations use TLS from the referenced `Upstream`. For WebSockets, the override selects only the upgrade handshake backend; the upgraded connection is pinned to that backend and frame hooks do not re-route individual frames. HBONE CONNECT traffic flows through the standard `before_proxy` chain before the HBONE relay consumes route overrides; inner H2 frames are not re-classified per stream.

`reject_unmatched` is evaluated across all attached `mesh_route_dispatch`
instances: a local miss never short-circuits a later instance, and the request
returns 404 only after every instance has run, fail-closed behavior was requested,
and no instance matched or earlier route override exists.
All attached instances must remain a contiguous priority block so this
finalization runs before later short-circuit plugins. Cache construction rejects
priority overrides that interleave another plugin between dispatch instances.

When a `mesh_route_dispatch` rule matches on query params, the plugin opts the whole proxy into decoded query-param materialization for HTTP/3 so its `query_params` predicates see the same percent-decoded values as HTTP/1.1 and HTTP/2. That means every plugin on that proxy observes decoded `ctx.query_params` while the query-rule instance is configured.

A `mesh_route_dispatch` rule may also carry a per-rule `fault` action (`{delay, abort}`) that runs as soon as the rule matches and BEFORE any route override is applied. The fault uses the shared `FaultRoller` (`src/plugins/utils/fault_roll.rs`) so a static-percentage rule uses the same 64-bit threshold math as the proxy-scoped `fault_injection` plugin. When delay and abort both trigger, the delay runs first; the abort then short-circuits dispatch and the route override is skipped. An earlier proxy-scoped fault marks the request so the route-local surface does not stack; a route-local fault writes a private source marker so a priority-overridden later proxy-scoped fault also no-ops. Ordinary sibling `fault_injection` instances do not suppress one another: each independently decides until an abort short-circuits the chain.

## Complete Execution Order

Given all built-in plugins enabled, the execution order is:

| # | Plugin | Priority | Active Phases |
|---|--------|----------|---------------|
| 1 | `otel_tracing` | 25 | on_request_received, on_stream_connect, before_proxy, after_proxy, log, on_stream_disconnect |
| 2 | `correlation_id` | 50 | on_request_received, before_proxy, after_proxy, apply_websocket_handshake_response_headers, on_stream_connect |
| 3 | `cors` | 100 | on_request_received, after_proxy |
| 4 | `request_termination` | 125 | on_request_received |
| 5 | `mesh_outbound_registry` | 130 | on_request_received |
| 6 | `ip_restriction` | 150 | on_request_received, on_stream_connect |
| 7 | `geo_restriction` | 175 | on_request_received, on_stream_connect |
| 8 | `bot_detection` | 200 | on_request_received |
| 9 | `spec_expose` | 210 | on_request_received |
| 10 | `sse` | 250 | on_request_received, before_proxy, after_proxy, transform_response_body |
| 11 | `grpc_web` | 260 | on_request_received, before_proxy, transform_request_body, on_final_request_body, after_proxy, transform_response_body |
| 12 | `grpc_method_router` | 275 | on_request_received, on_backend_path_resolved |
| 13 | `spiffe_identity` | 940 | on_request_received, on_stream_connect |
| 14 | `mtls_auth` | 950 | authenticate, on_stream_connect |
| 15 | `jwks_auth` | 1000 | authenticate |
| 16 | `oauth2_introspection` | 1050 | authenticate, before_proxy |
| 17 | `oidc_relying_party` | 1075 | authenticate, before_proxy |
| 18 | `jwt_auth` | 1100 | authenticate |
| 19 | `key_auth` | 1200 | authenticate, before_proxy |
| 20 | `ldap_auth` | 1250 | authenticate |
| 21 | `basic_auth` | 1300 | authenticate |
| 22 | `hmac_auth` | 1400 | authenticate |
| 23 | `soap_ws_security` | 1500 | before_proxy |
| 24 | `access_control` | 2000 | authorize, on_stream_connect |
| 25 | `tcp_connection_throttle` | 2050 | on_stream_connect (opaque connection permit releases on rejection/teardown) |
| 26 | `mesh_authz` | 2075 | authorize, on_stream_connect |
| 27 | `opa` | 2080 | authorize |
| 28 | `adaptive_concurrency` | 2090 | backend_admission |
| 29 | `ai_transcript_audit` | 2740 | before_proxy, on_final_request_body, on_final_response_body, on_response_committed, response_stream_inspector, on_response_stream_terminated, log |
| 30 | `request_deduplication` | 2750 | before_proxy, on_final_response_body, on_response_stream_terminated |
| 31 | `request_size_limiting` | 2800 | on_request_received, before_proxy, on_final_request_body |
| 32 | `ws_message_size_limiting` | 2810 | parser-level frame/message limits |
| 33 | `graphql` | 2850 | before_proxy |
| 34 | `rate_limiting` | 2900 | on_request_received (IP mode), authorize (consumer mode), before_proxy, after_proxy, on_stream_connect |
| 35 | `ws_rate_limiting` | 2910 | on_ws_frame, on_ws_reassembly_frames |
| 36 | `udp_rate_limiting` | 2915 | on_udp_datagram |
| 37 | `ai_prompt_shield` | 2925 | before_proxy, transform_request_body, on_final_request_body |
| 38 | `waf` | 2930 | authorize, on_final_request_body, after_proxy, on_final_response_body, on_stream_connect, on_udp_datagram |
| 39 | `fault_injection` | 2940 | before_proxy, on_stream_connect, on_udp_datagram |
| 40 | `body_validator` | 2950 | before_proxy, on_final_request_body, after_proxy, on_final_response_body |
| 41 | `openapi_validator` | 2960 | before_proxy, on_final_request_body, after_proxy, on_final_response_body |
| 42 | `ai_semantic_firewall` | 2968 | before_proxy, on_final_request_body, on_response_body, on_final_response_body, response_stream_inspector, on_response_stream_terminated |
| 43 | `ai_request_guard` | 2975 | before_proxy, transform_request_body, on_final_request_body |
| 44 | `ai_tool_governor` | 2978 | before_proxy, on_final_request_body, on_response_body, transform_response_body, on_final_response_body, response_stream_inspector, on_response_stream_terminated |
| 45 | `ai_stream_router` | 2984 | before_proxy, transform_request_body, normalize_response_body, response_stream_inspector |
| 46 | `mcp_gateway` | 2992 | before_proxy, transform_request_body, transform_response_body |
| 47 | `a2a_gateway` | 2993 | before_proxy, after_proxy, on_response_body, response_stream_inspector |
| 48 | `mesh_route_dispatch` | 2995 | before_proxy |
| 49 | `ai_semantic_cache` | 2996 | before_proxy, after_proxy, on_final_response_body |
| 50 | `request_transformer` | 3000 | before_proxy, transform_request_body |
| 51 | `serverless_function` | 3025 | before_proxy |
| 52 | `response_mock` | 3030 | before_proxy |
| 53 | `grpc_deadline` | 3050 | receipt-time deadline preflight, before_proxy |
| 54 | `load_testing` | 3070 | before_proxy |
| 55 | `request_mirror` | 3075 | authorize (pre-buffer mirror admission; never rejects), before_proxy |
| 56 | `response_size_limiting` | 3490 | after_proxy, on_final_response_body |
| 57 | `response_caching` | 3500 | before_proxy, after_proxy, on_final_response_body |
| 58 | `response_transformer` | 4000 | after_proxy, transform_response_body |
| 59 | `compression` | 4050 | normalize_buffered_request_body_before_before_proxy, before_proxy, after_proxy, transform_request_body, transform_response_body |
| 60 | `ai_prompt_compressor` | 4055 | before_proxy, transform_request_body_with_context, on_final_request_body_with_context |
| 61 | `ai_federation` | 4060 | final request body (HTTP only) |
| 62 | `ai_response_guard` | 4075 | after_proxy, on_response_body, transform_response_body |
| 63 | `security_headers` | 4080 | after_proxy, initial response-header boundary |
| 64 | `ai_token_metrics` | 4100 | on_response_body |
| 65 | `ai_rate_limiter` | 4200 | before_proxy, after_proxy, on_response_body |
| 66 | `stdout_logging` | 9000 | log, on_stream_disconnect |
| 67 | `ws_frame_logging` | 9050 | on_ws_frame |
| 68 | `statsd_logging` | 9075 | log, on_stream_disconnect, on_ws_disconnect |
| 69 | `http_logging` | 9100 | log, on_stream_disconnect |
| 70 | `tcp_logging` | 9125 | log, on_stream_disconnect |
| 71 | `kafka_logging` | 9150 | log, on_stream_disconnect |
| 72 | `loki_logging` | 9155 | log, on_stream_disconnect |
| 73 | `udp_logging` | 9160 | log, on_stream_disconnect |
| 74 | `ws_logging` | 9175 | log, on_stream_disconnect |
| 75 | `transaction_debugger` | 9200 | on_request_received, before_proxy, on_final_request_body, after_proxy, on_final_response_body, log, on_stream_disconnect, on_ws_disconnect |
| 76 | `proxy_alerts` | 9250 | log, on_stream_disconnect, on_ws_disconnect |
| 77 | `prometheus_metrics` | 9300 | log, on_stream_disconnect, on_ws_disconnect |
| 78 | `api_chargeback` | 9350 | log, on_stream_disconnect, on_ws_disconnect |
| 79 | `api_chargeback_sink` | 9351 | log, on_stream_disconnect, on_ws_disconnect |
| 80 | `workload_metrics` | 9360 | on_request_received, before_proxy, after_proxy, log, on_stream_connect, on_stream_disconnect |
| 81 | `__mesh_bpf_metrics` | 9365 | (no lifecycle hooks; passive Prometheus surface populated by the BPF SOCK_OPS event consumer) |
| 82 | `transaction_log_schema` | 9999 | (config-only; no lifecycle hooks — priority retained for schema-registration inventory/order) |

### Config-only and reserved inventory rows

- `transaction_log_schema` (9999) is listed so the published inventory stays set-equal
  with the built-in registry. Cache rebuild still constructs it first (ahead of every
  other plugin) so named schemas exist before loggers resolve `schema_ref`; the
  priority value itself is not used for request-phase ordering because the instance
  is discarded after registry staging.
- `__mesh_bpf_metrics` (9365) is reserved for NodeWaypoint mesh auto-injection. It is
  a passive Prometheus surface fed by the BPF SOCK_OPS consumer and intentionally
  overrides no lifecycle hooks.


## Why This Order Matters

### Response caching runs after response size limiting (3490 -> 3500)

`response_size_limiting` gets the first chance to reject oversized backend payloads before anything is written into cache. `response_caching` then records the surviving final representation in `on_final_response_body`, after all response-body transforms have completed.

That ordering has a few practical effects:
- Cache entries include the final client-visible body and headers, not the raw backend response.
- A later `HIT`/`REVALIDATED` synthetic replay marks a private finalized-response capability so ordinary presentation transforms (including `response_transformer` body and header sequences) are not applied a second time, while inspectors, final-body validators, and reject-path observability hooks still run over the replayed bytes.
- Backend `Vary` headers are respected when building the cache key, so variants such as `Accept-Encoding: gzip` stay isolated from uncompressed responses.
- Fresh cached validators (`ETag`, `Last-Modified`) can satisfy conditional requests at the edge with a `304 Not Modified` response.
- The `compression` plugin (4050) generates gzip/brotli responses at the gateway during the response-body transform phase. `response_caching` stores the final encoded representation in `on_final_response_body` (which runs after all response-body transforms), so cache entries contain the gateway-compressed bytes and `Content-Encoding` header — not the uncompressed backend response. A cache `HIT` replays those stored bytes and headers directly from `response_caching::before_proxy` (3500), short-circuiting before `compression::before_proxy` (4050) runs, so no second compression pass occurs and compression-setting changes do not rewrite existing entries. `max_entry_size_bytes` compares the encoded body length; `max_total_size_bytes` and per-entry accounting use the stored entry's approximate footprint, including that body and its headers. The `body_validator` plugin separately decompresses gzip-compressed gRPC frames for protobuf validation — this is internal to the validation path and does not affect the forwarded body.

### OTel tracing runs first (priority 25)

OpenTelemetry tracing runs at priority 25 — the earliest of any plugin — so it can capture trace context before any other plugin runs. This ensures accurate timing: the gateway span's start time reflects the true moment the request was received, not the time after CORS/auth/etc. have executed. The `before_proxy` phase injects traceparent into backend requests, `after_proxy` echoes it to clients, and `log` exports the completed span to the OTLP collector.

### CORS runs next (priority 100)

Browser preflight (`OPTIONS`) requests must be answered before authentication. If an auth plugin ran first, it would reject the preflight with `401` and the browser would never complete the CORS handshake. CORS at priority 100 ensures preflight responses are returned immediately.

When a proxy has multiple CORS instances, the cache keeps their equal-priority
order stable, evaluates the whole contiguous CORS chain, and inserts one
internal finalizer after it. Actual requests compose origin, credentials, and
exposed-header policy; method/header lists and max age are preflight-only and
are not evaluated on actual traffic. Preflights additionally intersect the
requested-method/header policy and use the shortest max age, so an earlier
approval cannot bypass a later restriction. A priority override that places a
different HTTP/gRPC-capable plugin between CORS instances is rejected during
cache construction; non-overlapping stream-only plugins are ignored because
protocol filtering removes them from the CORS chain. This preserves the
phase-1 short-circuit boundary on H1, H2, H3, and the gRPC-Web request-policy
chain.

### Request termination runs immediately after CORS (priority 125)

`request_termination` still short-circuits before authentication, but it now sits behind CORS so maintenance and mock responses do not break browser preflight. That keeps browser clients functional while preserving the low-cost fast path for intentionally terminated requests.

### Mesh outbound registry runs before network gates (priority 130)

`mesh_outbound_registry` rejects unknown HTTP-family destinations for mesh `REGISTRY_ONLY` outbound policy before authentication, authorization, and backend dispatch. It runs after `request_termination` so deliberate maintenance/mock responses still win, and before IP/geo/bot gates so denied egress attempts are measured as mesh policy rejections instead of disappearing into later admission checks. The plugin is auto-injected only for topologies with an outbound capture listener unless operators configure it directly as a Host allowlist.

### Spec expose runs after IP restriction and bot detection (priority 210)

`spec_expose` intercepts `GET` and `HEAD` at the canonical `{listen_path}/specz` resource and returns the API specification without proxying. `HEAD` retains the GET representation until response-body transforms and guards establish the final status and headers, then suppresses the wire body. It runs at priority 210 — after IP restriction (150) and bot detection (200) so blocked IPs and bots cannot access spec endpoints, but before all authentication plugins (950+). This makes the `/specz` endpoint unauthenticated by design, allowing legitimate API consumers to discover contracts without credentials while still enforcing network-level security policies. Route-level `allowed_methods` admission still runs before the plugin.

### Authentication before authorization (1000s before 2000s)

Authentication plugins identify *who* the caller is (setting `ctx.identified_consumer` and/or `ctx.authenticated_identity`). Authorization plugins like `access_control` and `opa` then decide *whether* that identity is allowed — by consumer username, ACL group membership, or external policy. Running auth first is required — authorization checks are meaningless without a verified identity.

When `opa.include_body` is enabled, the request body is collected after the
authentication phase succeeds and before authorization callbacks run. This
keeps unauthenticated requests eligible for an immediate `401` without body
collection while still making the bounded body available to OPA's `authorize`
callback on HTTP/1.1, HTTP/2, and HTTP/3.

After all plugin phases complete, the gateway automatically injects `X-Consumer-Username` (and `X-Consumer-Custom-Id` when set) headers into the request forwarded to the backend, so upstream services can identify the authenticated caller. `X-Consumer-Username` uses the mapped Consumer username when available, otherwise an external auth header/display identity (for example from `jwks_auth`), otherwise the raw external authenticated identity.

### Rate limiting runs after auth (priority 2900)

Rate limiting sits at the end of the AuthZ band (priority 2900) so it can enforce limits by **authenticated identity**, not just by IP address. When `limit_by: "consumer"`, the plugin uses the mapped Consumer username when available, otherwise external `ctx.authenticated_identity`; those values only exist after the authenticate phase. When `limit_by: "spiffe_identity"`, the plugin uses `ctx.peer_spiffe_id`, populated earlier by the `spiffe_identity` plugin.

**Dual-phase behavior:**
- `limit_by: "ip"` — enforces IP-based limits in `on_request_received` (phase 1, before auth). This protects auth endpoints from brute-force attacks.
- `limit_by: "consumer"` — enforces identity-based limits in `authorize` (phase 3, after auth). Uses mapped Consumer username first, then external `authenticated_identity`, and falls back to IP-based keying only when no authenticated identity exists. `limits` must include one `scope: "default"` rule for generic consumers/IP fallback, and may include `scope: "consumers"` rules that apply one shared rate window to one or many named identities.
- `limit_by: "spiffe_identity"` — enforces SPIFFE-based limits in `authorize` (phase 3, after `spiffe_identity`). Uses the peer SPIFFE URI and falls back to IP-based keying when no SPIFFE identity exists. The shorter alias `spiffe` is accepted.

**Header exposure** (`expose_headers: true`): When enabled, the plugin injects `x-ratelimit-limit`, `x-ratelimit-remaining`, and `x-ratelimit-window` headers on both upstream requests (`before_proxy`) and downstream responses (`after_proxy`). This lets backends and clients see current rate-limit state without additional lookups. Disabled by default so gateway admins control whether limit details are exposed. The limiter key/identity is deliberately never injected as a header: for `limit_by: "consumer"`/`"spiffe_identity"` it would disclose the gateway's internal notion of the caller identity (consumer username) or the peer workload SVID to the downstream client.

**Redis mode** (`sync_mode: "redis"`): rate-limit counter plugins support only `local` and `redis` storage; database-backed counters are intentionally unsupported. `rate_limiting`, `ai_rate_limiter`, `graphql`, `grpc_method_router`, and `udp_rate_limiting` use Redis for coordinated counters across multiple gateway instances. `ws_rate_limiting` also supports Redis, but only to externalize its per-connection counters; because WebSocket connection IDs are process-local, it namespaces keys per gateway instance to avoid cross-instance collisions rather than sharing a portable connection budget across reconnects. When Redis is unavailable, behavior is governed by `redis_failure_policy`, which defaults to `fail_closed`: the plugin refuses with `503` rather than silently degrading to a per-process enforcement domain. `redis_failure_policy: "local_fallback"` is the explicit opt-in that falls back to local in-memory state and switches back when connectivity is restored. `request_deduplication` expresses the same choice through its own `on_redis_unavailable` field (also fail-closed by default) and does not accept `redis_failure_policy`; `ai_semantic_cache` keeps automatic local fallback because a cache miss carries no enforcement consequence. The shared client reconnects in the background under either policy. Redis Cluster is not supported and is screened rather than assumed: the client runs `INFO CLUSTER` on every newly established connection and reacts to `MOVED`/`ASK`/`CROSSSLOT`/`CLUSTERDOWN`/`TRYAGAIN`; a proven Cluster endpoint is refused terminally for the life of the client. The Redis backend uses native RESP protocol commands (no Lua scripts), so it works with Redis, Valkey, DragonflyDB, KeyDB, or Garnet.

### OpenAPI validation runs after body validation (priority 2960)

`openapi_validator` runs after the generic `body_validator` so explicit per-proxy body checks can fail first, then the generated OpenAPI contract can enforce operation-specific schemas. It runs before AI request policy and request transformation, which means contract mismatches are caught before the request body is reshaped or sent to an upstream.

### AI Plugins: audit → PII shield → semantic firewall → guard → tool governor → routing → metrics → rate limiter (2740–4200)

The AI plugins are ordered to compose correctly:

1. **`ai_transcript_audit` (2740)** runs after authentication/authorization and before `request_deduplication` (2750), so local and Redis replays cannot terminate the chain before audit staging. It also stages before reject-capable AI guardrails so blocked prompts can still be captured when `always_capture_on_guardrail` is enabled. Its final request-body hook reclassifies and refreshes the captured request after downstream redaction/transforms when traffic continues; priority overrides that reverse audit/dedup order are rejected.
2. **`ai_prompt_shield` (2925)** runs next in the pre-proxy body flow — PII must be detected/redacted before the request reaches the backend or later body validators. It sits right after audit staging and rate limiting so brute-force protection applies first. For encoded JSON bodies it defers inspection to `on_final_request_body`, after request decompression; enforcing actions fail closed if the body remains encoded, and compressed redaction rejects detected PII because that final hook cannot rewrite wire bytes. `waf` request metadata checks have already run in `authorize`; WAF request-body checks run on the final backend-visible body after request body transforms.
3. **`ai_semantic_firewall` (2968)** runs after body/OpenAPI validation and before request guard, semantic cache, and federation — semantically dangerous prompts, RAG content, tool calls, and responses are evaluated before they can reach semantic cache or a federated provider. Because request/response body transformers run after the initial semantic pass, the firewall uses instance-scoped body hashes and re-evaluates changed final backend-visible requests and client-visible responses; unchanged bodies avoid duplicate embedding calls. Encoded requests are deferred until the final request hook after optional decompression, while encoded governed responses fail closed unless a final gateway-compressed body can be decoded within the inspection bound.
4. **`ai_request_guard` (2975)** runs after semantic firewall — it validates model names, max_tokens, message counts, prompt size, and provider-native temperature fields. It revalidates the final backend-visible JSON after later request-body transforms, so a transformer cannot replace a protected field after admission; clamp/default caps that are undone after transformation fail closed.
5. **`ai_tool_governor` (2978)** runs after the request guard and before semantic cache and federation — it applies deterministic allow/deny/approval policy to concrete tool/function calls by name, arguments, JSON Schema, regex, identity, and an optional approval webhook. A disallowed tool schema in the request `tools[]`, a dangerous tool call in `choices[].message.tool_calls[]`, or a streamed SSE tool-call delta is screened before it reaches the client, semantic cache, or a federated provider. It complements `ai_semantic_firewall` (which catches intent); this plugin is purely deterministic (names, args, schema, regex, identity, approval). Because `request_transformer` (3000) and `response_transformer` (4000) run after the initial `before_proxy`/`on_response_body` inspection, the governor re-runs its deterministic request policy on the final backend-visible body (`on_final_request_body`) and its response policy on the final client-visible body (`on_final_response_body`), so a transform that rewrites an allowed body into a denied `tools/call` or injects a denied `choices[].message.tool_calls[]` is still fail-closed before dispatch or delivery.
6. **`ai_stream_router` (2984)** claims streaming OpenAI Chat Completions requests (`"stream": true`) before non-streaming federation. It rewrites the route for provider-native streaming and normalizes provider SSE where needed without full-response buffering.
7. **`ai_semantic_cache` (2996)** runs after guardrails and after route-dispatch plugins (`ai_stream_router`, `mcp_gateway`, `a2a_gateway`, `mesh_route_dispatch`), so exact and semantic cache hits observe the accepted backend-visible prompt and the effective destination/provider identity before short-circuiting outbound provider dispatch.
8. **`ai_prompt_compressor` (4055)** runs after the guard, semantic cache, and `compression` request decompression. It boundedly shortens prompt text only for admitted OpenAI Chat/Text Completions representations (`messages[].content` for configured roles, plus legacy `prompt`). In `auto`, standard operation paths and body shapes must agree; the original incoming classification path is kept in one private per-request snapshot so a later routing rewrite cannot change eligibility, while fixed-family config is the explicit custom-path opt-in. Its request-time buffering gate stages plaintext `ctx.metadata["request_body"]` rewrites for compatible direct dispatch, privately reuses transformed bodies of at most 65,536 bytes when the wire source is unchanged, and otherwise recomputes against the final pre-compressor wire representation (including opt-in decompression) under the same work budget. Larger prompts therefore retain no second transformed-body copy across provider latency. Final wire counters replace provisional counters and remain instance-scoped before aggregation. Matching-backtick code, URLs, Unicode numbers, common identifiers, nested preserve text, and negations survive; successful changes intentionally reserialize the complete JSON body. Configured preserve markers use a separate non-queuing bounded sanitation lane and representation-preserving fallback when statistical work is saturated/over budget or output would overflow; the context-aware final hook rejects decoded bodies that exceed the hard sanitation bound or cannot enter the sanitation lane. Federation consumes the same final transformed body.
9. **`ai_federation` (4060)** is HTTP-only and handles non-streaming provider routing from the final request body, after all request transforms and final request validators. It translates OpenAI-format requests to the matched provider, normalizes bounded non-streaming responses, and returns via `RejectBinary` before backend egress/admission/transport. Matched requests with `"stream": true` are rejected with `501` unless `ai_stream_router` already claimed the request via `ai_stream_router_claimed=true`. Successful synthetic federation responses pass through the response-side body hooks before the client receives them, including `ai_semantic_firewall`, `ai_response_guard`, response transforms, final-response hooks, and committed observers when configured. `ai_token_metrics` is the deliberate exception: it skips synthetic short-circuit bodies, so `ai_federation` writes token metadata and a trusted typed usage snapshot directly.
10. **`ai_token_metrics` (4100)** runs after the response comes back from the backend — it parses supported HTTP JSON/SSE provider usage (prompt, completion, total, model) and writes it to `ctx.metadata`. Native gRPC protobuf messages are explicitly unsupported because no generic method/schema contract exists. Provider normalization runs before inspection; origin `gzip`/`br` coding chains are decoded only into a bounded inspection copy, leaving the encoded client response and headers unchanged. Public metadata flows into `TransactionSummary` for downstream logging, while bounded-label `prometheus_metrics` token/cost counters consume a separate typed usage snapshot that backend/operator metadata cannot mint. When several token-metrics instances publish different prefixes, Prometheus selects one most-complete token snapshot and at most one independently selected trusted cost per request instead of summing duplicates. It is observability-only and never enforces budget policy. When `ai_federation` is active, `ai_federation` publishes the same authoritative usage representation directly, and `ai_rate_limiter` reconciles usage from the public metadata on the rejection path.
11. **`ai_rate_limiter` (4200)** reserves estimated token usage before proxying JSON `POST` requests, based on output-token caps plus estimated prompt tokens. It runs after `ai_token_metrics` on the response body path, reconciles the reservation to actual usage when usage metadata is available, and keeps/rejects/releases unmetered 2xx responses according to `on_unmetered_response`. Synthetic short-circuit bodies (cache/dedup/mock/etc.) are never charged or released — the limiter exempts them via the internal `ferrum:synthetic_short_circuit` marker. When `ai_federation` is active, the rate limiter uses `applies_after_proxy_on_reject()` to reconcile token usage from federation metadata on the rejection path (the sole federation charger, scoped per limiter instance).

### Streaming AI: ai_stream_router (2984) claims `stream: true`, ai_federation (4060) owns the rest

`ai_stream_router` runs before `ai_semantic_cache` (2996) and before `ai_federation` (4060), and is the streaming counterpart to `ai_federation`. Route overrides it writes are therefore visible to cache keying. It claims **only** OpenAI Chat Completions requests with `"stream": true`; non-streaming requests continue untouched to `ai_federation`.

Rather than the buffered "terminate and respond" pattern, it rewrites the routing decision via `RequestContext.route_override_*` (scheme/host/port/path/authority) so the **normal proxy dispatch path** streams the provider response straight back to the client — no full-response buffering. It strips the client's `Authorization`/API-key headers and injects the matched provider's credential.

- `openai` / `openai_compatible`: request and response SSE are already OpenAI-shaped, so the stream passes through unchanged (optional `stream_options.include_usage` injection only). No response-stream inspector runs, so these requests stay on the fast dispatch path.
- `anthropic`: the request is translated to the Anthropic Messages API streaming request, and a `ResponseStreamInspector` normalizes Anthropic SSE events (`content_block_delta` text/tool deltas, `message_delta` usage/stop) into OpenAI `chat.completion.chunk` SSE on the fly, emitting a final usage chunk and `data: [DONE]`. For these requests the plugin returns `true` from `forces_reqwest_dispatch` so the inspector is guaranteed to be wired.

Streaming inspectors have semantic stages: provider/protocol `Normalize` stages
run before policy/audit `Inspect` stages, while configured plugin priority and
config order remain stable within each stage. Buffered responses use the
matching `normalize_response_body` phase before `on_response_body`. This keeps
guardrails on the same client-visible representation across H1/H2 and every
buffered H3 path without changing `ai_stream_router`'s request-side priority
(which must remain after `ai_semantic_cache`).

Because `ai_stream_router` runs first, when it claims a request it sets `ctx.metadata["ai_stream_router_claimed"] = "true"`; `ai_federation` checks this at the top of its final request-body hook and immediately continues, so the two plugins compose cleanly on the same proxy. `ai_stream_router` does not implement provider fallback in any form, and a `fallback` config block is rejected at admission rather than stored inert (issue #3328): the plugin commits one provider route, credential set, backend TLS resolution, and translated request body in `before_proxy`, and the dispatch retry loop replays exactly those prepared bytes and headers against the same effective proxy. No `ai_stream_router.fallback_attempts` metadata is emitted.

### Transforms after auth (3000+)

Request transformers run after authentication and authorization, so they only modify requests that are already permitted. This prevents wasted transformation work on requests that will be rejected.

`request_size_limiting` participates again after request transforms on buffered requests, so transformed bodies are re-checked before backend dispatch.

### Compression runs after response transformation (4050)

The `compression` plugin runs at priority 4050 — after `response_transformer` (4000) so it compresses the final transformed response body, before `ai_prompt_compressor` (4055) so opt-in request decompression exposes plaintext prompt JSON before prompt compression, and before `ai_token_metrics` (4100) and `ai_rate_limiter` (4200). Gateway-owned compression therefore presents normalized bytes to the later AI hooks. If an origin nevertheless returns an encoded JSON/SSE body, `ai_token_metrics` performs its own bounded inspection-only decoding without normalizing the client-visible bytes or headers. Configured request decompression (`decompress_request`) additionally runs in the shared pre-`before_proxy` body-normalization phase on H1/H2 and native H3 so earlier `before_proxy` body consumers (including `soap_ws_security` at priority 1500) observe the same size-bounded plaintext that is forwarded upstream. In `before_proxy`, compression can strip `Accept-Encoding` from the backend request so the backend sends uncompressed responses for the gateway to compress. Response body buffering is required when this plugin is enabled.

### Logging runs last (9000+)

Logging plugins run in phase 13 (`log`) in priority/config order, but the hook
is not universally fire-and-forget. `log_with_mirror` awaits each primary
transaction hook sequentially:

- Buffered H1/H2/gRPC responses, synchronous rejection/error paths, and other
  buffered terminal paths normally await all log hooks before the response is
  returned. Direct network or filesystem I/O therefore adds client-visible
  handler latency, with multiple hooks adding that latency serially. When an
  absolute gRPC deadline is active, Ferrum moves the owned summary, context, and
  plugin list to a five-second detached cleanup task so a blocked log sink
  cannot delay the terminal RPC response.
- Hyper-owned streamed H1/H2 and gRPC bodies return from the handler first.
  Body completion fires a spawned task that awaits streaming terminal hooks and
  then log hooks sequentially. The task can be lost when no Tokio runtime is
  available during shutdown or when runtime shutdown cancels unfinished work.
- Native H3 drives the response body to completion inside its handler. It then
  synchronously awaits streaming terminal hooks and sequential log hooks before
  the handler finishes; it does not use the detached hyper-body logger.

Potentially slow sinks should use an explicitly bounded, plugin-owned handoff.
Own the queue, worker, cancellation state, and retry budget in the plugin;
stage the worker from `start_background_tasks()` (dormant until publication) and
release it from `commit_background_tasks()` after atomic cache installation;
define queue-full behavior; and signal intake closure when the plugin is
dropped. Do not spawn an unbounded task per transaction. Because `Drop` cannot
await and runtime shutdown can still cancel a worker, durable delivery needs
persistence or an external collector with an explicit drain protocol.

Relative ordering within the logging band (9000–9300) determines invocation
order but otherwise does not change lifecycle phase semantics.

All logging plugins receive the `TransactionSummary` struct which includes an `error_class` field for failed transactions. This field classifies gateway-level errors (e.g., `ConnectionTimeout`, `TlsError`, `DnsLookupError`) to help operators quickly identify root causes. See [docs/error_classification.md](error_classification.md) for the full list of error classes and debugging guidance.

## Adding a New Plugin

When implementing a new plugin, choose a priority that places it in the correct band:

```rust
impl Plugin for MyPlugin {
    fn name(&self) -> &str { "my_plugin" }

    fn priority(&self) -> u16 {
        // Pick a value in the appropriate band:
        // 0-999: pre-processing (before auth)
        // 1000-1999: authentication
        // 2000-2999: authorization / post-auth enforcement
        // 3000-3999: request transformation
        // 4000-4999: response transformation
        // 9000-9999: logging
        500  // Example: runs after CORS (100), before auth (1000+)
    }

    // Declare which protocols this plugin supports.
    // Default is HTTP_ONLY_PROTOCOLS. Use one of the predefined constants:
    //   ALL_PROTOCOLS           — HTTP, gRPC, WebSocket, TCP, UDP
    //   HTTP_FAMILY_PROTOCOLS   — HTTP, gRPC, WebSocket
    //   HTTP_GRPC_PROTOCOLS     — HTTP, gRPC
    //   HTTP_ONLY_PROTOCOLS     — HTTP only (default)
    //   GRPC_ONLY_PROTOCOLS     — gRPC only
    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS  // Example: this plugin works with all protocols
    }

    // If your plugin makes outbound HTTP calls to a configured endpoint,
    // override warmup_hostnames() so the endpoint is pre-resolved at startup
    // via the gateway's shared DNS cache:
    fn warmup_hostnames(&self) -> Vec<String> {
        vec!["my-endpoint.example.com".to_string()]
    }
}
```

### Response Body Buffering

If your plugin needs access to the full response body (e.g., for body-level transformation or inspection), override `requires_response_body_buffering()` to return `true`. This is the config-time upper bound — the gateway uses a two-tier check:

1. **Config-time**: `requires_response_body_buffering()` — pre-computed in `PluginCache` at config load time.
2. **Per-request**: `should_buffer_response_body(&RequestContext)` — lets plugins skip buffering when the request context makes it irrelevant (e.g., non-POST requests on an AI plugin, missing `Accept-Encoding` on compression).

```rust
impl Plugin for MyBodyPlugin {
    fn name(&self) -> &str { "my_body_plugin" }

    fn requires_response_body_buffering(&self) -> bool {
        true  // Config-time: this proxy MAY need response buffering
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        // Per-request: only buffer for POST+JSON (skip GET, static assets, etc.)
        ctx.method == "POST"
            && ctx.headers.get("content-type")
                .is_some_and(|ct| ct.to_ascii_lowercase().contains("json"))
    }
}
```

By default, `should_buffer_response_body()` returns `self.requires_response_body_buffering()` — plugins that don't override it behave as before. When `response_transformer` has body transformation rules configured (`target: "body"`), it automatically returns `true` from `requires_response_body_buffering()`, forcing conservative pre-header buffering so a client-controlled `Accept: text/event-stream` value cannot release an ordinary JSON backend response past the policy. Once backend headers arrive, the content-type refinement releases a response that actually declares `text/event-stream`; JSON, absent, and ambiguous types remain buffered. When only header rules are configured, it returns `false` and works with streaming mode. See [docs/response_body_streaming.md](response_body_streaming.md) for the full streaming architecture.

Add the constant to `src/plugins/mod.rs` in the `priority` module for discoverability:

```rust
pub mod priority {
    pub const MY_PLUGIN: u16 = 500;
    // ...
}
```

The default priority is `5000` (the Custom band), which runs after all transforms but before logging. This is a safe default for plugins that don't have strong ordering requirements.

## Protocol Support

Each plugin declares which proxy protocols it supports via `supported_protocols()`. The gateway skips plugins that don't support the current proxy's protocol — for example, CORS is never invoked for a TCP stream proxy.

Recognized H3 gRPC-Web requests retain the ordinary `Http` protocol view so HTTP-only validators, deduplication, and other guardrails keep running. At cache rebuild time the gateway composes `grpc_method_router` and `grpc_deadline` into that same priority-ordered view when those native-gRPC policies are configured. No other gRPC-only plugin is added, and each plugin instance appears at most once.

TLS/DTLS are transport-layer concerns, not separate protocols. A plugin that supports `Tcp` also supports TCP+TLS, and a plugin that supports `Udp` also supports UDP+DTLS.

| Protocol | Description |
|----------|-------------|
| `Http` | HTTP/1.1, HTTP/2, HTTP/3 (includes HTTPS) |
| `Grpc` | gRPC / gRPCs (HTTP/2-based RPC) |
| `WebSocket` | WS / WSS |
| `Tcp` | Raw TCP stream proxy (includes TLS termination/origination) |
| `Udp` | Raw UDP datagram proxy (includes DTLS termination/origination) |

### Per-Plugin Protocol Matrix

Every built-in from `BUILTIN_PLUGIN_REGISTRATIONS` has exactly one row. Config-only
plugins use `—` in every protocol column. Reserved/auto-injected plugins keep
ordinary checkmarks for their declared `supported_protocols()` surface and call
out the reservation in the rationale. CI enforces name/priority/protocol set
parity against runtime metadata in `src/plugins/builtin_parity.rs`.

| Plugin | Http | Grpc | WebSocket | Tcp | Udp | Rationale |
|--------|:----:|:----:|:---------:|:---:|:---:|-----------|
| `otel_tracing` | ✓ | ✓ | ✓ | ✓ | ✓ | Tracing for all protocols |
| `correlation_id` | ✓ | ✓ | ✓ | ✓ | ✓ | ID assignment is protocol-agnostic |
| `cors` | ✓ | ✓ | | | | Origin/ACAO enforcement includes browser gRPC-Web requests |
| `request_termination` | ✓ | ✓ | ✓ | | | Returns HTTP error response |
| `mesh_outbound_registry` | ✓ | ✓ | ✓ | | | Host-header outbound registry gating is HTTP-family only; raw streams use mesh connect/datagram enforcement |
| `ip_restriction` | ✓ | ✓ | ✓ | ✓ | ✓ | IP filtering is protocol-agnostic |
| `geo_restriction` | ✓ | ✓ | ✓ | ✓ | ✓ | GeoIP country allow/deny is protocol-agnostic |
| `bot_detection` | ✓ | ✓ | ✓ | | | Needs User-Agent header |
| `spec_expose` | ✓ | | | | | HTTP-only; requires prefix listen_path |
| `sse` | ✓ | | | | | SSE is HTTP-only (text/event-stream over chunked transfer) |
| `grpc_web` | ✓ | ✓ | | | | Translates gRPC-Web (browser) ↔ native gRPC (HTTP/2) |
| `grpc_method_router` | | ✓ | | | | gRPC method-level access control and rate limiting |
| `spiffe_identity` | ✓ | ✓ | ✓ | ✓ | ✓ | Extracts SPIFFE IDs from TLS/DTLS client certificates |
| `mtls_auth` | ✓ | ✓ | ✓ | ✓ | ✓ | Requires TLS/DTLS client certificate |
| `jwks_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers |
| `oauth2_introspection` | ✓ | ✓ | ✓ | | | Requires HTTP bearer token headers or query params |
| `oidc_relying_party` | ✓ | ✓ | ✓ | | | Browser-oriented HTTP authentication flow |
| `jwt_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers |
| `key_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers or query parameters |
| `ldap_auth` | ✓ | ✓ | ✓ | | | Requires HTTP Basic auth header; authenticates against LDAP directory |
| `basic_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers |
| `hmac_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers and a buffered request body; HBONE CONNECT fails closed as incompatible |
| `soap_ws_security` | ✓ | | | | | SOAP XML body parsing (text/xml, application/soap+xml) |
| `access_control` | ✓ | ✓ | ✓ | ✓ | ✓ | Needs authenticated identity from an auth plugin; supports consumer username and ACL group allow/deny lists |
| `tcp_connection_throttle` | | | | ✓ | | Tracks process-local active TCP/TCP+TLS connections per Consumer or canonical client IP; each replica enforces independently |
| `mesh_authz` | ✓ | ✓ | ✓ | ✓ | ✓ | Applies Layer 2 mesh policy using SPIFFE or HBONE identities |
| `opa` | ✓ | | | | | Delegates HTTP request authorization to an OPA Data API policy |
| `adaptive_concurrency` | ✓ | ✓ | ✓ | | | Target-aware backend admission for HTTP-family upstream survival |
| `request_deduplication` | ✓ | | | | | HTTP-only request deduplication and response replay |
| `request_size_limiting` | ✓ | ✓ | | | | Enforces per-proxy request body size limits |
| `ws_message_size_limiting` | | | ✓ | | | Enforces actual-frame and bounded-reassembly limits on WebSocket connections |
| `graphql` | ✓ | | ✓ | | | GraphQL JSON over HTTP and GraphQL subscriptions over WebSocket |
| `rate_limiting` | ✓ | ✓ | ✓ | ✓ | ✓ | Connection/session rate applies everywhere |
| `ws_rate_limiting` | | | ✓ | | | Per-connection frame rate limiting for WebSocket |
| `udp_rate_limiting` | | | | | ✓ | Per-client-IP datagram and byte rate limiting for UDP proxies |
| `ai_transcript_audit` | ✓ | | | | | HTTP-only AI transcript capture to a configured sink |
| `ai_prompt_shield` | ✓ | | | | | HTTP-only PII detection/redaction for bare JSON prompts; native gRPC unsupported (gRPC-Web framed bodies are skipped) |
| `waf` | ✓ | ✓ | ✓ | ✓ | ✓ | HTTP-family always; TCP/UDP first-bytes and datagram inspection when a `stream` block is configured |
| `fault_injection` | ✓ | ✓ | ✓ | ✓ | ✓ | Probabilistic aborts and delays across HTTP-family, TCP stream connect, and UDP/DTLS session + datagram hooks |
| `body_validator` | ✓ | ✓ | | | | Validates request and response bodies |
| `openapi_validator` | ✓ | | | | | Validates bodies against generated OpenAPI operation schemas |
| `ai_semantic_firewall` | ✓ | | | | | HTTP-only semantic inspection for LLM JSON request and response bodies |
| `ai_request_guard` | ✓ | ✓ | | | | Validates JSON request bodies |
| `ai_tool_governor` | ✓ | | | | | HTTP-only deterministic tool/function-call policy on JSON and SSE bodies |
| `ai_semantic_cache` | ✓ | | | | | HTTP-only exact/semantic cache for LLM JSON request and response bodies |
| `ai_stream_router` | ✓ | | | | | Claims `stream: true` OpenAI Chat Completions, route-overrides to a provider, normalizes provider SSE to OpenAI SSE |
| `mcp_gateway` | ✓ | | | | | HTTP-only MCP JSON-RPC parsing, metadata, and namespaced tool/resource/prompt routing |
| `a2a_gateway` | ✓ | ✓ | | | | Detects A2A HTTP/REST/gRPC methods, rewrites HTTP Agent Cards, applies method policy, and emits `a2a.*` metadata |
| `mesh_route_dispatch` | ✓ | ✓ | ✓ | | | Rewrites the routing decision per request via `RequestContext.route_override_*`; for WebSocket, selects the upgrade backend only, not per-frame routing |
| `request_transformer` | ✓ | ✓ | | | | Modifies HTTP headers/query/body |
| `serverless_function` | ✓ | ✓ | | | | Invokes cloud functions (AWS Lambda, Azure Functions, GCP Cloud Functions); terminate supports HTTP and native unary gRPC |
| `response_mock` | ✓ | | ✓ | | | Short-circuits HTTP and WebSocket upgrade handshakes; native gRPC unsupported by design — only the validated serverless_function terminate contract carries provenance-authorized framed unary Reject semantics |
| `grpc_deadline` | | ✓ | | | | gRPC timeout enforcement and propagation |
| `load_testing` | ✓ | | | | | On-demand load testing via header trigger with multi-node fan-out |
| `request_mirror` | ✓ | ✓ | | | | Duplicates traffic to a shadow destination for validation |
| `response_size_limiting` | ✓ | ✓ | | | | Enforces per-proxy response body size limits |
| `response_caching` | ✓ | | | | | HTTP-only response cache lookup and store |
| `response_transformer` | ✓ | ✓ | | | | Modifies HTTP response headers/body |
| `compression` | ✓ | | | | | HTTP response compression and request decompression (gzip, brotli) |
| `ai_prompt_compressor` | ✓ | | | | | HTTP-only JSON prompt compression; native gRPC wire frames are not rewritten |
| `ai_federation` | ✓ | | | | | HTTP-only; routes final OpenAI JSON bodies to providers and normalizes bounded responses |
| `ai_response_guard` | ✓ | ✓ | | | | HTTP JSON/SSE/text response inspection; native gRPC only for methods enrolled in the descriptor-based `grpc` block |
| `security_headers` | ✓ | ✓ | ✓ | | | HTTP-family response security headers and fingerprint stripping |
| `ai_token_metrics` | ✓ | | | | | HTTP JSON/SSE accounting only; native gRPC protobuf has no supported provider schema contract |
| `ai_rate_limiter` | ✓ | | | | | HTTP JSON/SSE token accounting only; native gRPC protobuf frames have no supported usage schema, so gRPC attachment would never charge |
| `stdout_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `ws_frame_logging` | | | ✓ | | | Logs WebSocket frame metadata |
| `statsd_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `http_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `tcp_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `kafka_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `loki_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `udp_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `ws_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `transaction_debugger` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `proxy_alerts` | ✓ | ✓ | ✓ | ✓ | ✓ | Anomaly notifications across all protocols |
| `prometheus_metrics` | ✓ | ✓ | ✓ | ✓ | ✓ | Metrics for all protocols |
| `api_chargeback` | ✓ | ✓ | ✓ | ✓ | ✓ | In-memory charge accumulator for HTTP-family, WebSocket bandwidth, and stream sessions |
| `api_chargeback_sink` | ✓ | ✓ | ✓ | ✓ | ✓ | Durable ClickHouse charge event/snapshot exporter |
| `workload_metrics` | ✓ | ✓ | ✓ | ✓ | ✓ | Adds Istio/GAMMA mesh identity labels to metadata |
| `__mesh_bpf_metrics` | ✓ | ✓ | ✓ | ✓ | ✓ | Reserved/auto-injected NodeWaypoint BPF SOCK_OPS Prometheus surface (counters + fixed latency histograms); no request hooks |
| `transaction_log_schema` | — | — | — | — | — | Config-only: registers named log schemas during cache rebuild; no protocol hooks (ordering priority 9999) |

Protocol-filtered plugin lists are pre-computed in `PluginCache` at config reload time, so there is zero filtering cost on the hot path.

## Body Transformation

Both `request_transformer` and `response_transformer` support JSON body field manipulation using dot-notation paths. Use `"target": "body"` in the rules array alongside existing header and query rules.

### Configuration

```json
{
  "rules": [
    {"operation": "rename", "target": "body", "key": "user.old_field", "new_key": "user.new_field"},
    {"operation": "remove", "target": "body", "key": "internal.debug_info"},
    {"operation": "add", "target": "body", "key": "metadata.version", "value": "v2"},
    {"operation": "update", "target": "body", "key": "user.role", "value": "admin"}
  ]
}
```

### Dot-Notation Paths

Fields are referenced using dot-delimited paths that navigate nested JSON objects:

| Path | Targets |
|------|---------|
| `name` | `{"name": "..."}` |
| `user.email` | `{"user": {"email": "..."}}` |
| `a.b.c.d` | `{"a": {"b": {"c": {"d": "..."}}}}` |

### Operations

| Operation | Behavior |
|-----------|----------|
| `add` | Insert field only if it doesn't already exist. Creates intermediate objects as needed. |
| `update` | Always set the field value (overwrites if exists, creates if not). |
| `remove` | Delete the field at the given path. |
| `rename` | Move the value from `key` path to `new_key` path (both use dot notation). |

### Value Parsing

String values in the `"value"` field are parsed as JSON when possible:
- `"42"` → number `42`
- `"true"` → boolean `true`
- `"{\"a\":1}"` → object `{"a": 1}`
- `"hello"` → string `"hello"` (not valid JSON, kept as string)

Non-string JSON values (numbers, booleans, objects, arrays) in the config are used directly.

### Content-Type Awareness

Body transformation only applies to JSON bodies (detected by `Content-Type` containing `application/json` or `+json`). A body whose `Content-Type` is present and non-JSON is passed through unchanged.

An **absent** `Content-Type` is treated as JSON, and the representation gate's claim predicate matches that exactly. The two must agree: if the gate declined untyped responses while the transform still tried to parse them, an untyped `gzip`, `206`, or malformed body would skip inspection, fail to parse inside the transform, and be forwarded with the protected field intact — the same `None`-conflation bypass the gate exists to close. The consequence is deliberate and fail-closed: with a body policy configured, an untyped response that is not parseable JSON is rejected rather than forwarded.

### Performance Notes

- Body rules are parsed once at config load time, not per-request.
- When `response_transformer` has body rules, it automatically enables conservative response body buffering for the proxy. Backend-declared `text/event-stream` responses are released after headers; request-side SSE intent alone never releases a JSON response. Without body rules, responses stream through with zero overhead.
- `request_transformer` body transformation runs after the request body is collected and before it is sent to the backend (HTTP/1.1 and HTTPS paths).
- Header, query, and body rules can be mixed in a single plugin configuration.

## gRPC Compatibility

All plugins in the execution pipeline work transparently with gRPC requests. gRPC metadata maps directly to HTTP/2 headers, so:

- **Authentication plugins** (JWKS, JWT, API key, Basic) inspect the `authorization` header, which gRPC clients send as metadata.
- **Rate limiting** works identically for gRPC — keyed by IP or consumer identity.
- **Request/Response transformers** can add, modify, or remove gRPC metadata (HTTP/2 headers).
- **Logging plugins** receive the same `TransactionSummary` with the gRPC path (e.g., `/my.Service/MyMethod`) and HTTP status. For gateway-generated gRPC errors, `metadata.grpc_status` and `metadata.grpc_message` are also populated so sinks can distinguish gRPC failures despite the HTTP `200`.
- **Plugin rejections** are translated into trailers-only gRPC errors (`HTTP 200` with `grpc-status` / `grpc-message`) unless a plugin already supplied explicit gRPC error metadata.

gRPC requests are detected by their `content-type: application/grpc` header and routed to the dedicated gRPC proxy path, which uses hyper's HTTP/2 client for trailer forwarding. The plugin pipeline runs before and after the gRPC backend call, just like HTTP requests.
