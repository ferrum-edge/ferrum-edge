# mesh_route_dispatch

Part of the [Plugin Reference](../plugins.md).

**Priority:** 2995 · **Phases:** `before_proxy` · **Protocols:** HTTP, gRPC, WebSocket · **Failure policy:** `FailClosed`

Applies per-request route overrides generated from mesh/Istio routing resources. It runs in `before_proxy` after authentication and admission plugins, so policy evaluates the original public proxy identity before the backend override is applied. For WebSockets, the override selects the upgrade backend only; individual frames are not re-routed.

**Strict config validation:** unknown keys are rejected at every security-relevant nesting level — top-level plugin config, each rule, match, destination, fault, rewrite, redirect, transform, route-local `retry`, nested retry backoff, and destination `backend_tls`. Misspellings such as `reject_unmtached`, `requires_node_waypoint_auth`, `retry.max_retry`, or `backend_tls.client_certpath` fail admission on native/file/admin/translated/CP-DP paths instead of silently disabling fail-closed controls. Shared gateway `RetryConfig` / `BackendTlsConfig` consumers keep their existing compatibility boundary; mesh route policy uses strict route-local wire shapes that convert into those runtime types after validation.

**Response header transform destinations:** `rules[].response_transform` publishes onto the same response write surface as [`response_transformer`](../plugins.md#response_transformer) and shares its closed destination set. `add`/`update` of a [protocol-managed response header name](../plugins.md#protocol-managed-response-header-names) is rejected at construction, so a VirtualService `http[].headers.response.{set,add}` modifier cannot reintroduce a framing field after the origin hop-by-hop strip. `remove` of those names remains allowed. `rules[].request_transform` `add`/`update` destinations in the gateway-owned `x-consumer-*` consumer assertion namespace or the router's `x-path-param-*` route-capture namespace (case-insensitive, `_` or `-`) are rejected at construction with an error naming `rules[N].request_transform[M]`, matching `request_transformer`; `remove` stays allowed.

An `upstream_id` destination resolves in the matched proxy's namespace. Scoped plugin references are validated in their resource namespace; a gateway-wide global reference must exist in every proxy namespace where that global is effective (excluding proxies that replace it with a scoped `mesh_route_dispatch` instance). A same-ID upstream in another namespace never satisfies the reference.

**Query predicates are fail-closed.** `match.query_params` compares against the canonical decoding of the backend-bound query representation available at the dispatch hook, after authentication-owned credential strips and any priority-overridden query transformer that already ran. Selecting a route is a security decision, so a request whose query cannot be decoded to one value is rejected with `400` **before any rule is evaluated**, using the same [classifications](../plugins.md#query-canonicalization-advisories-ghsa-j2j6-f9c7-hh85-ghsa-gr4p-3qw3-87r5) OPA applies: a repeated or percent-encoded duplicate name (`?tenant=victim&tenant=admin`, `?a=1&%61=2`, `?flag&flag=1`), a literal `+`, an unencoded `;` (`?tenant=admin&x=;tenant=victim`), malformed percent-encoding, or a non-UTF-8 decoding. `%20`, `%2B`, and `%3B` are unambiguous. Behavior is identical on HTTP/1.1, HTTP/2, and HTTP/3, because predicates do not read the protocol-dependent `ctx.query_params` map. A later route/request transform remains an intentional, separately ordered operation. A dispatch config that declares no `query_params` predicate is completely unaffected — no query is decoded and no request is rejected on this path.

## Standalone configuration

`mesh_route_dispatch` is auto-emitted by the mesh/Istio translators, but it is an
ordinary operator-configurable plugin: the table below is the complete accepted
shape, and the constructor is the source of truth for it (`openapi.yaml` →
`MeshRouteDispatchConfig` mirrors it, with the two runtime-only checks called out
below). Omitted keys take the listed default; `null` is accepted only where the
type column says so. Unknown keys are rejected at every level.

**Root**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `rules` | Object[] | — | Required, at least one entry. Ordered; **first match wins** and evaluation stops there |
| `reject_unmatched` | bool | `false` | `true` answers `404` when no rule matched instead of falling through to the proxy's own backend. The translator sets this; a hand-written soft override normally leaves it `false` |

**`rules[]`**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `name` | String \| null | omitted | Optional operator label, 1–128 printable ASCII characters without whitespace. Published as `mesh_route_dispatch.rule_name` match metadata (see [Match observability](#match-observability)) |
| `match` | Object | `{}` | Predicates, all-of across the fields below. An empty match is rejected **unless** the rule carries a route action (`request_transform`, `response_transform`, `fault`, `rewrite`, `redirect`, `timeout_ms`, `timeout_disabled: true`, `request_timeout_ms`, `attempt_timeout_ms`, `retry`, `retry_disabled: true`), which makes it the deliberate action-only catch-all; otherwise it would silently shadow every later rule |
| `destination` | Object | `{}` | Route override applied on match. At least one field must be set unless the rule carries a `redirect` |
| `timeout_ms` | u64 \| null | omitted | Route-local backend response/read timeout. `0` means "no timeout". Cannot be combined with `timeout_disabled: true` |
| `timeout_disabled` | bool | `false` | Clear the selected proxy's inherited backend read timeout for this route (resolves to `0`). Cannot be combined with `timeout_ms` |
| `request_timeout_ms` | u64 \| null | omitted | Route-local **total** request deadline in milliseconds from request receipt (Gateway API `timeouts.request`). Spans every backend attempt, retry backoff, and the streaming response body; never re-armed by a retry and never promoted onto the proxy. `0` is rejected — omit it for no deadline. See [Route request deadline](#route-request-deadline) |
| `attempt_timeout_ms` | u64 \| null | omitted | Route-local **total** bound on each backend attempt in milliseconds (Gateway API `timeouts.backendRequest`, which the translator also projects as `timeout_ms`). Starts when the attempt is handed to the backend and covers its response head and whole response body; every retry attempt gets a fresh budget, and `request_timeout_ms` still bounds the whole transaction. Independent of `timeout_ms` / `timeout_disabled`. Never promoted onto the proxy. `0` is rejected — omit it for no per-attempt total bound. See [Route attempt budget](#route-attempt-budget) |
| `retry` | Object \| null | omitted | Route-local retry policy (below), applied only to requests this rule matches (Istio `http[].retries`, Gateway API `HTTPRoute.rules[].retry`). Cannot be combined with `retry_disabled: true` |
| `retry_disabled` | bool | `false` | Clear the selected proxy's inherited retry policy for this route. Cannot be combined with `retry` |
| `request_transform` | Object[] | `[]` | Route-level request header transforms (below). Requires an eligible consumer — see [Route transforms need a consumer](#route-transforms-need-a-consumer) |
| `response_transform` | Object[] | `[]` | Route-level response header transforms. Same shape and same consumer requirement, plus the closed protocol-managed destination set described above. Applied exactly once to every response the matched rule produces — a proxied response and also the rule's own `redirect` or aborted `fault` answer. A matching rule always replaces the list an earlier dispatch instance published (clearing it when the rule declares none). A NodeWaypoint authorization `403` refusing the rule's destination is a security denial, not a rule response: it carries no route response headers, including an earlier instance's list |
| `fault` | Object \| null | omitted | Per-rule delay / abort, applied before any route override |
| `rewrite` | Object \| null | omitted | Per-rule URI / authority rewrite applied to the backend request |
| `redirect` | Object \| null | omitted | Per-rule 3xx answer. Highest precedence: the request never reaches a backend, so the rule needs no `destination` |

**`rules[].match`**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `methods` | (String \| Object)[] | `[]` | Any-of. A bare string is an `exact` match; the object form is an Istio `StringMatch` with **exactly one** of `exact` / `prefix` / `regex`. `exact` and `prefix` operands must be non-empty RFC 9110 method tokens — an empty value or one containing a space (`"GET POST"`) is rejected at load, because it could never match. `exact` preserves operator casing (`"get"` matches only `get`); `prefix` is ASCII-uppercased at load; `regex` is compiled verbatim between full-input anchors. Empty array = no method restriction |
| `headers` | Object | `{}` | All-of, keyed by header name. Names must be RFC 9110 tokens and are ASCII-lowercased at load; duplicates after normalization are rejected. Values take the same bare-string / `StringMatch` shapes as `methods`. An `exact: ""` predicate legitimately means "present and empty"; empty `prefix` / `regex` operands are rejected |
| `without_headers` | Object | `{}` | Negated header predicates (Istio `withoutHeaders`), keyed and normalized like `headers`, with the same value shapes. The rule fails when **any** listed header is present and its value satisfies the matcher; an absent header never vetoes it, so `{"x-legacy": {"regex": ".*"}}` requires the header to be absent (the translator's projection of Istio's presence-only `withoutHeaders: {x-legacy: {}}`) |
| `query_params` | Object | `{}` | All-of, keyed by exact parameter name, on the canonical decoded query — see the fail-closed contract above. A value is a bare string (`exact`) or a `StringMatch` with exactly one of `exact` / `prefix` / `regex`; `regex` must match the full decoded value, and empty `prefix` / `regex` operands are rejected |
| `authority` | String \| Object \| null | omitted | `Host` / `:authority` predicate, bare string or `StringMatch`. Case-sensitive for `exact` / `prefix`, including an explicit request port; write `(?i)` for a case-insensitive `regex`. All operands must be non-empty |
| `source_namespace` | String \| null | omitted | Source workload namespace, read from the peer SPIFFE ID. Exact and case-sensitive; empty or whitespace-bearing values are rejected. Fails closed (no match) when there is no resolved peer identity |
| `uri` | Object \| null | omitted | `StringMatch` on the request path. Normally omitted because the proxy's `listen_path` already gates URI selection; the translator emits it for `ignoreUriCase` routes and collapsed route-order fallbacks. `regex` must match the full path |
| `ignore_uri_case` | bool | `false` | Fold ASCII case for `uri.exact` / `uri.prefix` only. Rejected without a `uri` predicate, and it never affects `uri.regex`, headers, methods, or authority |
| `port` | 1–65535 \| null | omitted | Destination port the client addressed (Istio `match.port`), from trusted provenance only: the original destination when capture rewrote the accept socket, otherwise the frontend listener port — never `Host` or forwarding headers. A request with neither does not match |

**`rules[].destination`**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `upstream_id` | String \| null | omitted | Override the proxy's upstream. Resolved in the matched proxy's namespace. Mutually exclusive with every direct-backend field |
| `backend_host` | String \| null | omitted | Direct-backend host. A **bare host**: a DNS name, an IPv4 literal, or an IPv6 literal in either `::1` or `[::1]` form. The port belongs in `backend_port`; an embedded authority port, scheme, path, query, fragment, or userinfo is rejected at load rather than failing DNS resolution with a 502 on every matching request. Trimmed and ASCII-lowercased at load; max 255 characters |
| `backend_port` | 1–65535 \| null | omitted | Direct-backend port. Must be set together with `backend_host` |
| `backend_tls` | Object \| null | omitted | Route-local backend TLS (below). **Direct backends only** — an `upstream_id` destination inherits TLS from the referenced `Upstream` (including mesh `DestinationRule` projection), so per-canary TLS for an upstream override is modeled as a separate upstream resource |
| `requires_node_waypoint_authz` | bool | `false` | Trusted mesh-translator marker. Under scoped NodeWaypoint authorization, a matching destination carrying it fails closed without an authorized destination stamp. Not for hand-authored config |

**`rules[].fault`** — at least one of `delay` / `abort` is required.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `delay.duration_ms` | u64 | — | Required. `1`–`60000` |
| `delay.percentage` | f64 | — | Required. `(0.0, 100.0]`; `0.0` is rejected (omit the action instead). A positive value below one 64-bit sampler bucket rounds up so every accepted value can fire |
| `abort.status_code` | u16 | — | Required. `200`–`599` |
| `abort.percentage` | f64 | — | Required. Same `(0.0, 100.0]` range as the delay |
| `abort.grpc_status` | u32 \| null | omitted | `0`–`16`, emitted only when the immutable pre-plugin request flavor is native gRPC |
| `abort.body` | String \| null | omitted | Response body; empty when unset |

**`rules[].rewrite`** — at least one of `uri` / `authority` is required.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `uri` | String \| null | omitted | Replacement path. Must be a canonical absolute path with no query or fragment; percent escapes, dot segments, backslashes, and CRLF are rejected at load, and the composed path is re-checked before publication |
| `authority` | String \| null | omitted | Replacement `Host` / `:authority`. Must be exactly `host` or `host:port`: a DNS name or IPv4 literal (letters, digits, `-`, `.`, `_`) or a bracketed IPv6 literal, optionally followed by a decimal port `1`–`65535`. A path, query, fragment, userinfo, whitespace, or a bare (unbracketed) IPv6 literal is rejected at load |
| `match_prefix` | String \| null | omitted | The literal prefix to replace with `uri`. Replacement is literal: the unmatched suffix is appended **verbatim**, so `match_prefix: /prefix/old` + `uri: /new` forwards `/prefix/oldtail` as `/newtail`, never `/new/tail`. A doubled separator is collapsed when both sides carry a `/` (`match_prefix: /prefix` + `uri: /` forwards `/prefix/etc` as `/etc`). A suffix whose first complete segment is `.` or `..` keeps its boundary so the canonical-path check refuses it (`/prefix/old../admin` composes `/new/../admin` and returns `400`); other dot-leading suffixes remain literal (`/prefix/old.env` becomes `/new.env`, and `..hidden` becomes `/new..hidden`). An empty string strips nothing and prepends `uri` (`match_prefix: ""` + `uri: /v2` forwards `/users` as `/v2/users`); the Gateway API translator emits it for a `URLRewrite` / `RequestRedirect` `ReplacePrefixMatch` under the root `PathPrefix: /`. Omit the field for whole-path replacement. A `match_prefix` with no `uri` is inert and dropped |

**`rules[].redirect`** — every field is optional; a status-only redirect preserves the request URL.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `uri` | String \| null | omitted | Replacement `Location` path; the request path is preserved when unset. Must be an absolute path (leading `/`) whose path component is already canonical (no dot segments, backslashes, or escapes that decode differently), without a fragment, and printable ASCII only — query included, so a raw control byte or unencoded non-ASCII character is refused (percent-encode it); it may carry its own `?query` unless `match_prefix` is set, because the unmatched suffix is appended after `uri`. A relative value is rejected at load because it would be concatenated onto the authority (`uri: new` would have redirected `app.example.com` to the different host `app.example.comnew`). A Gateway API `ReplacePrefixMatch` with an empty `replacePrefixMatch` (strip the matched prefix) is translated to `uri: /`, which composes `/old` → `/`, `/old/` → `/`, and `/old/child` → `/child` under `match_prefix: /old`. The composed path is canonicalized, and a `.` or `..` segment is refused with `400` |
| `match_prefix` | String \| null | omitted | Prefix replaced by `uri`, with the same literal-substitution contract as `rewrite.match_prefix` |
| `authority` | String \| null | omitted | Replacement `Location` authority; the request authority is preserved when unset. Same `host` / `host:port` grammar as `rewrite.authority` |
| `port` | 1–65535 \| null | omitted | Replacement authority port. Mutually exclusive with `derive_port` |
| `derive_port` | String \| null | omitted | `FROM_PROTOCOL_DEFAULT` (80/http, 443/https) or `FROM_REQUEST_PORT` (original-destination port under capture, otherwise the frontend listener port — never `X-Forwarded-Port` / `Forwarded`). Mutually exclusive with `port` |
| `scheme` | String \| null | omitted | `http` or `https`, ASCII-lowercased before validation (so `HTTPS` is accepted). The request's frontend scheme is preserved when unset |
| `redirect_code` | u16 | `301` | `300`–`399` |

Scheme-default ports are omitted from the rendered authority, and the original query string is preserved unless the redirect `uri` supplies its own.

**`rules[].retry`** — a strict route-local wire shape that converts to the gateway `RetryConfig`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_retries` | u32 | `3` | `0`–`100` |
| `retryable_status_codes` | u16[] | `[]` | Each `100`–`599`; at most 500 entries |
| `retryable_methods` | String[] | `["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]` | One of GET / POST / PUT / PATCH / DELETE / HEAD / OPTIONS / TRACE / CONNECT, ASCII-uppercased before comparison (so `get` is accepted). At most 9 entries |
| `backoff` | Object | `{"fixed": {"delay_ms": 100}}` | Either `{"fixed": {"delay_ms": N}}` or `{"exponential": {"base_ms": N, "max_ms": M}}`. Each delay is `0`–`300000` ms and `base_ms` must not exceed `max_ms` |
| `retry_on_connect_failure` | bool | `true` | Retry connection failures |

**`rules[].destination.backend_tls`** — a strict route-local wire shape that converts to the gateway `BackendTlsConfig`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `client_cert_path` | String \| null | omitted | Client certificate PEM path. Non-empty, and must be set together with `client_key_path` |
| `client_key_path` | String \| null | omitted | Client key PEM path. Non-empty, and must be set together with `client_cert_path` |
| `server_ca_cert_path` | String \| null | omitted | Backend CA PEM path, or `system://` for the platform roots. Non-empty |
| `verify_server_cert` | bool | `true` | Verify the backend certificate. Cannot be `false` alongside a `system://` `server_ca_cert_path` |
| `sni` | String \| null | omitted | SNI override, max 253 characters, ASCII-lowercased at load |
| `san_allow_list` | String[] | `[]` | Accepted backend SAN entries, at most 256 |

**`rules[].{request,response}_transform[]`**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `operation` | String | — | Required. `add` (append with a comma separator, or insert), `update` (insert or replace), or `remove` |
| `target` | String | `header` | Only `header` is accepted for route-level transforms |
| `key` | String | — | Required. A valid HTTP header name |
| `value` | String \| null | omitted | Required and non-null for `add` / `update`; omitted or null for `remove`. Must parse as an HTTP `HeaderValue`; CRLF is rejected |

**Two admission rules the JSON Schema cannot express** and that only the constructor
enforces: `backoff.base_ms <= backoff.max_ms` (a comparison between two sibling
properties), and the `system://` CA versus `verify_server_cert: false`
contradiction (a value-prefix test combined with a sibling boolean). The
`backend_host` schema `pattern` is likewise a conservative approximation — a
colon-bearing value that is not a valid IPv6 literal passes the schema and is
still rejected at admission.

### Matching and dispatch semantics

- **Soft fallback is the default.** With `reject_unmatched: false`, a request that
  matches no rule is simply proxied to the matched proxy's own backend. That makes
  a broken predicate look like healthy traffic, so verify a new canary rule
  actually fires before relying on it.
- **Aggregate unmatched handling.** `reject_unmatched` is finalized across every
  attached instance: a local miss never short-circuits a later instance, and the
  `404` is returned only after all instances have run with no match and no earlier
  route override. All attached instances must stay a contiguous priority block.
- **Whole-destination replacement.** A matching instance replaces all four
  override fields (`upstream_id`, `backend_host`, `backend_port`, `backend_tls`);
  a non-matching instance leaves an earlier instance's override intact.
- **`Host` ownership.** A matching rule without `rewrite.authority` undoes only a
  `Host` rewrite an earlier dispatch instance made, restoring the value that was
  live just before that rewrite. A `Host` another plugin set before the dispatch
  block is the forwarded authority the rule inherits and is left untouched.
- **Protocol scope.** The plugin runs on HTTP, gRPC, and WebSocket at priority
  2995. A WebSocket override selects the upgrade backend only — frames are not
  re-routed after the upgrade — and an HBONE `CONNECT` is matched on the outer
  request before the relay branch, after which the tunnel is a transparent relay.
- **Clearing inherited policy.** `timeout_disabled` / `retry_disabled` are the only
  way to clear a timeout or retry policy the selected proxy carries; leaving the
  field unset inherits it, which is the opposite of the operator's intent for a
  collapsed route.

### Route request deadline

`timeout_ms` bounds ONE backend attempt: the wait for its response head and the
idle gap between response frames (a steadily trickling body is not cut by it;
`attempt_timeout_ms` is what bounds an attempt's total duration, see
[Route attempt budget](#route-attempt-budget)). `request_timeout_ms` is the
rule's TOTAL budget. Proxy core arms it once, after
`before_proxy` has selected the rule, as one absolute instant anchored to request
receipt, so request-phase time already spent counts against it and a retry can
never re-arm it. It is request-scoped: it never changes the selected proxy,
upstream, or pool key, and a request matching another rule (or none) is
unaffected.

| Request | Expiry before the response head | Expiry while the body streams |
|---|---|---|
| HTTP/1.1 / HTTP/2 / HTTP/3, not gRPC | The in-flight attempt or retry backoff is cancelled, no new attempt starts once the budget is spent, and the client gets `504` `{"error":"Request timeout"}`. It is never retried. Transaction-log metadata `route_request_timeout` names the phase, which also decides backend-health attribution (see below) and the `X-Gateway-Error` token: `dispatch` — the backend held the cancelled attempt — is error class `read_write_timeout`, charged to that backend, with `backend_timeout`; `before_dispatch` (the attempt had not been handed to a backend) and `retry_backoff` are the health-neutral `dispatch_policy_rejected`, with `request_timeout` | The body ends with a timeout error, never a clean end of message: the HTTP/2 stream is reset, the HTTP/1.1 connection is closed, and the HTTP/3 stream is reset with `H3_REQUEST_CANCELLED`. On HTTP/1.1 and HTTP/2 a backend `Content-Length` stays advertised, so the cut reads as a short body. `body_error_class` is `read_write_timeout`, but the cut is **not** charged to the backend (see below). Native HTTP/3 phase details: [docs/http3.md](../http3.md#route-request-deadline-request_timeout_ms-gateway-api-timeoutsrequest) |
| gRPC / gRPC-Web on any frontend | The budget is folded into the request's RPC deadline (the earlier of it and any client `grpc-timeout` / `grpc_deadline` budget wins), so the existing deadline machinery answers `DEADLINE_EXCEEDED` and forwards the remaining budget as `grpc-timeout` | `DEADLINE_EXCEEDED` trailers before response DATA; a stream reset after it |

**Backend-health attribution.** The deadline is charged to a backend (circuit
breaker, passive health / outlier detection, least-latency and adaptive
concurrency samples) only when that backend held the request. An attempt counts
as handed to the backend once every gateway- and client-side step is done —
buffered client-body collection, request-body hooks, DNS, and backend admission
— and the dial, stream open, or send has begun; it is the same point where the
attempt's latency sample starts. A retry attempt is handed over from its start,
because the retry planner has already admitted it and replays the retained,
already-transformed body. Expiry before that point — a client that stalls its
upload while the gateway buffers it, for example — is recorded
`before_dispatch` / `dispatch_policy_rejected` and feeds no failure and no
latency sample. A streaming (unbuffered) upload is relayed as part of the
backend exchange, so after the handoff it is attributed like the per-attempt
header wait (`backend_read_timeout_ms`) already is. A cut **after** the response
head is never charged: the backend has answered, and the total budget ends a
long healthy download or a slow-reading client exactly as it ends a slow
backend, so deferred accounting treats it like an expired client RPC deadline.

**Bodies collected before `before_proxy`.** A body a plugin
needs before `authenticate`, `authorize`, or `before_proxy` (SOAP WS-Security,
`hmac_auth`, `waf`) is collected before this rule is selected. Each such
collector previews the selection with the same compiled matchers from the
request's pinned plugin-cache generation. No hook runs, no override is
published, and no gRPC attempt clock starts. The collect is bounded by the
receipt-anchored total alongside `backend_read_timeout_ms` and any client RPC
deadline. An RPC deadline wins a tie with it, and it wins a tie with the read
timeout. An already-elapsed total refuses before a ready body is polled. Expiry
is the `before_dispatch` `504` above, and gRPC folds the total into
`DEADLINE_EXCEEDED`. Selection may not be decidable that early:

- A rule that matches on an input a plugin may still rewrite before the
  instance runs (headers or Host, query, path or destination), or on a
  gateway-owned identity header (`x-consumer-*`, `x-geo-country`), is a
  candidate rather than a decision. A plugin that rewrites inputs from
  `authenticate`, `authorize`, or the request-decompression normalizer counts
  whatever its priority, because those phases run before every instance's
  `before_proxy`; a plugin that rewrites only in `before_proxy` counts only when
  it runs ahead of the instance. Every custom plugin counts whatever its
  priority, and one that does not return `true` from
  `declares_request_input_mutations()` is treated as able to rewrite any input
  (see `CUSTOM_PLUGINS.md`). The gateway logs this at `info` once per proxy
  chain at startup and reload when that chain also runs `mesh_route_dispatch`
  and collects a body before `before_proxy`. A plugin is built-in by the type
  it was registered with, not by the name it reports: a custom plugin that
  reports a built-in name is still a custom plugin. `key_auth`
  with `hide_credentials` and a `query:` location counts as rewriting the
  query.
- Plugins that always write a fixed set of headers declare those names
  (`correlation_id` its `header_name`, `otel_tracing` `traceparent` /
  `tracestate`, `rate_limiting` its `x-ratelimit-*` set and
  `x-ratelimit-identity`, `grpc_deadline` `grpc-timeout`, `sse`
  `accept-encoding` / `last-event-id`, `compression` the `accept-encoding` /
  `cache-control` / `content-encoding` / `content-length` /
  `x-ferrum-original-content-encoding` set), so a rule on
  any other header stays decided alongside them. Auth plugins name the
  headers they strip or own: `basic_auth` and `ldap_auth`
  `authorization` when `hide_credentials` is set, `key_auth` its key header,
  `jwks_auth` and `oauth2_introspection` `authorization` and their header
  token locations when a provider does not forward the original token plus
  their claim-header destinations, and `oidc_relying_party` `cookie` when the
  session cookie is hidden plus its claim-header destinations. `Host` and every
  other header stay decidable.
- An instance whose trigger reads an identity that is not yet established, or
  any input that may still change, may or may not run. So may an instance a
  routing plugin may claim the request away from.
- The early bound is then the **largest** total among the rules that could
  still be selected. An outcome answered without dispatch arms no total and
  adds no candidate: a redirect, a fault that always aborts (unless a
  `fault_injection` instance, or an earlier `mesh_route_dispatch` instance with
  a rule fault, runs ahead and may inject first), a waypoint veto
  the request's authorization metadata already decides, and the `404` the
  cache's finalizer returns when no instance of a `reject_unmatched` chain
  matched. If any candidate is untimed (including "no rule matches" without
  `reject_unmatched`, or with a routing plugin that may publish its own
  override), there is no early route bound and only `backend_read_timeout_ms`
  and the RPC deadline apply. Set a finite `backend_read_timeout_ms` on such
  routes.
- The transaction log names an early route expiry
  `route_request_timeout_early_upload` on HTTP/1.1, HTTP/2, and HTTP/3.

**Candidate-max profile.** The early bound is a ceiling on the collect only.
Once `before_proxy` selects a rule, that rule's own total is armed as usual
for the rest of the request. The preview computes the bound per request, from
the generation the request was received on:

1. It walks the `mesh_route_dispatch` instances in chain order and each
   instance's rules in order. A rule is *decided* when no input it matches on
   may still change. A decided rule that does not match is skipped. The first
   decided match ends that instance's walk.
2. Each rule that cannot be decided, and the decided match that ends the walk
   after one, is a *candidate* if it reaches a backend. It contributes its
   `request_timeout_ms`, or "untimed" when it has none. A redirect, a certain
   fault abort, or a decided waypoint veto contributes nothing.
3. If the instance may still publish nothing, the unmatched outcome is a
   candidate too. Without `reject_unmatched`, the request goes to the proxy's
   own backend with no total, so the candidate is untimed. The deferred
   `reject_unmatched` `404` contributes nothing, unless a routing plugin may
   publish an override first.
4. The bound is the largest candidate total. There is no early route bound if
   any candidate is untimed, if an instance cannot be previewed, or if a
   decided rule reached before any undecided one answers the request itself (a
   redirect or a certain abort), because that request never arms a total.

| Rules that can still be selected when the body is collected | Early bound |
|---|---|
| A decided match with `request_timeout_ms: T` | `T` |
| An undecided rule `T1`, then a decided catch-all `T2` | the larger of `T1` and `T2` |
| An undecided rule `T1`, then a decided catch-all with no `request_timeout_ms` | none: `backend_read_timeout_ms` and the RPC deadline only |
| An undecided rule `T1` and no catch-all, without `reject_unmatched` | none: an unmatched request dispatches untimed |
| An undecided rule `T1` and no catch-all, with `reject_unmatched` | `T1`: the deferred `404` never dispatches |
| An undecided redirect, then a decided catch-all `T2` | `T2`: the redirect adds no candidate |

Three consequences follow:

- The bound can only be the longest possible total, never a shorter one the
  client picks. A client that sends `x-consumer-username` itself does not
  decide a rule on that header, so it cannot select a shorter sibling's total.
- An untimed sibling turns the early bound off. With
  `backend_read_timeout_ms: 0` on such a route, no time bound applies to the
  collect except a client RPC deadline. The read timeout is the operator's
  backstop.
- The bound is anchored at request receipt and pinned to the receiving
  generation. A reload that lands during the collect changes neither.

`tests/functional/functional_soap_preauth_deadline_matrix_test.rs` drives the
pre-authentication collect over real HTTP/1.1, HTTP/2, and HTTP/3 streams in
all three SOAP identity modes (a stalled upload each). With UsernameToken it
checks this profile, trickling and late-wake uploads, a ready upload whose
total elapses before dispatch, and a reload during collection.

Upgraded WebSocket and CONNECT-UDP tunnels are not HTTP response bodies and are
not bounded by `request_timeout_ms`. Gateway-local plugin hooks are not
cancelled mid-hook on a non-gRPC request: their time counts against the budget,
which is enforced when each backend attempt starts, while it is awaited, in
retry backoff, and while the response body streams. A client that stops reading
a streamed response is cut when the transport next polls the body on HTTP/1.1
and HTTP/2, and at the deadline itself on HTTP/3.

### Route attempt budget

`attempt_timeout_ms` bounds each backend attempt's TOTAL duration: from the
moment the attempt is handed to the backend (the same point that starts its
latency sample, described above) until its full response — head and body — has
been received. A retry attempt is handed over from its start, and every attempt
gets a fresh budget. `request_timeout_ms`, when set, still bounds the whole
transaction: the earlier instant wins, and when both expire together the total
deadline's terminal stands, so a spent transaction is never retried. Like the
total deadline it is request-scoped: it never changes the selected proxy,
upstream, or pool key. `timeout_ms` keeps bounding the header wait and idle
gaps independently.

| Request | Expiry before the response head | Expiry while the body streams |
|---|---|---|
| HTTP/1.1 / HTTP/2 / HTTP/3, not gRPC | The attempt is cancelled and answered with the ordinary backend-timeout `504` `{"error":"Backend timeout"}`, error class `read_write_timeout`, charged to the backend. Only the attempt ends: a route `retry` that lists `504` runs the next attempt under a fresh budget. An attempt still reading a buffered response body (a small `Content-Length` response, or one a response-body plugin buffers) ends the same way. The request body the attempt retained is published at the handoff, outside the cancelled attempt, so the retry replays it. The HTTP/3 bridge to HTTP/1.1 and HTTP/2 backends collects a buffered response body inside the attempt too, so an expiry there is retried the same way; `after_proxy` then runs once, after that body was read | The body ends with the same timeout error as a `request_timeout_ms` cut (HTTP/2 stream reset, HTTP/1.1 connection close with `Content-Length` kept advertised, HTTP/3 `H3_REQUEST_CANCELLED` stream reset, `body_error_class: read_write_timeout`, not charged to the backend). A response whose head reached the client is never retried |
| gRPC / gRPC-Web on any frontend | Folded into the RPC deadline when the rule is selected — earlier than the handoff, so a gRPC upload the gateway buffers counts against it — and the earliest of it, `request_timeout_ms`, and any client `grpc-timeout` / `grpc_deadline` budget wins. The backend is told the remaining budget in `grpc-timeout` and the client gets `DEADLINE_EXCEEDED`. When the attempt budget was the binding deadline and it expired after the request was sent (waiting for the response head, or collecting a buffered response body), the terminal is `Backend deadline exceeded`, charged to the backend like a stalled backend under `timeout_ms`; an expiry before that (buffered upload collection, DNS, admission, and on the native gRPC path connection acquisition) stays the health-neutral client-deadline terminal. The expiry is not retried: gRPC retries only connection failures. On every frontend — the HTTP/3 bridge's gRPC and gRPC-Web pass-through dispatch included — each retry attempt re-arms a fresh budget and retry backoff is bounded by the total alone | `DEADLINE_EXCEEDED` trailers before response DATA; a stream reset after it |

A streamed (unbuffered) upload travels with the backend exchange, so the upload
time after the handoff counts against the attempt budget, and an expiry while
the upload is still streaming is charged to the backend like any other expiry
after the handoff. Any response that takes longer than the budget to deliver is
cut — a large but fast download, a Server-Sent Events stream, a long poll, or a
server-streaming gRPC call, not only a trickled body — so size the budget for
the longest complete response the rule must serve.

With no `attempt_timeout_ms` the dispatch path is unchanged: no timer is armed
and nothing is allocated for it.

### Route transforms need a consumer

Route header transforms are published onto the request context and applied by
proxy core after the last **eligible** (enabled) `request_transformer` /
`response_transformer` in the chain. The request list is applied after the
LATER of that consumer and the last `mesh_route_dispatch` instance — every
instance, including one whose rules carry no `request_transform`, because a
matching rule replaces the whole route decision. A consumer that a
`priority_override` moves ahead of the dispatch block therefore still has the
winning rule's list applied once the block has decided, a superseded rule's
list is never applied, and no later dispatch predicate sees route headers early.

A WebSocket handshake gets the matched rule's route lists too, each applied
exactly once. `request_transformer` itself runs on WebSocket handshakes, so it
is the request list's consumer there exactly as on HTTP and the request list
reaches the backend handshake. `response_transformer` runs on HTTP and gRPC
only, so the WebSocket chain carries a cache-owned stand-in at its position
(route-header finalization only — never the transformer's static header rules),
and the response list decorates the successful upgrade response as well as a
redirect / fault / rejection answer.

A chain whose rules carry `request_transform` / `response_transform` but that has
no configured `request_transformer` / `response_transformer` respectively is
**refused** at plugin-cache construction and admin admission, naming the missing
consumer; without one the list would be silently dropped and, for example, a
route rule that strips a sensitive request header would forward it untouched.
The VirtualService and Gateway API translators auto-emit an
`apply_route_overrides: true` consumer; when configuring the plugin directly, add
one yourself (see the third example below). The check counts a configured
transformer whatever its RTDS gate: an instance an RTDS overlay disables is not
eligible at runtime and leaves the route list unused, exactly as before, so the
kill switch never wedges a reload.

### Match observability

Every matching rule — including one that answers with its own `redirect` or an
aborted `fault` — publishes transaction-log metadata
`mesh_route_dispatch.rule_index` (the rule's zero-based position in its
instance's `rules`) and, when the rule sets `name`, `mesh_route_dispatch.rule_name`.
A later matching instance overwrites both and removes a stale name when its own
rule is unnamed. A NodeWaypoint authorization `403` that refuses the matched
destination withdraws both keys, since the vetoed rule served nothing. Both keys
are on the built-in safe-metadata allowlist, so they are visible in every
logging sink by default.

### Examples

A minimal direct override — a `POST` carrying `x-canary: v2` goes to the canary
backend, everything else keeps the proxy's own backend:

```yaml
version: "1"
plugin_configs:
  - id: reviews-canary
    plugin_name: mesh_route_dispatch
    scope: proxy
    proxy_id: reviews
    enabled: true
    config:
      rules:
        - match:
            methods: ["POST"]
            headers:
              x-canary: v2
          destination:
            backend_host: reviews-v2.default.svc.cluster.local
            backend_port: 9080
          timeout_ms: 1500
proxies:
  - id: reviews
    listen_path: /reviews
    backend_scheme: http
    backend_host: reviews-v1.default.svc.cluster.local
    backend_port: 9080
    plugins:
      - plugin_config_id: reviews-canary
```

A redirect-only rule needs no `destination`. `/reviews/legacyitem` is answered
`301` with a `Location` path of `/reviews/v2item` — literal prefix substitution,
with no separator synthesized at the segment boundary:

```yaml
version: "1"
plugin_configs:
  - id: reviews-redirect
    plugin_name: mesh_route_dispatch
    scope: proxy
    proxy_id: reviews
    enabled: true
    config:
      rules:
        - match:
            uri:
              prefix: /reviews/legacy
          redirect:
            uri: /reviews/v2
            match_prefix: /reviews/legacy
            redirect_code: 301
proxies:
  - id: reviews
    listen_path: /reviews
    backend_scheme: http
    backend_host: reviews-v1.default.svc.cluster.local
    backend_port: 9080
    plugins:
      - plugin_config_id: reviews-redirect
```

Route header transforms with the eligible consumers they require. Without the two
transformer instances the rule still forwards to the backend, but neither header
change is applied:

```yaml
version: "1"
plugin_configs:
  - id: reviews-routing
    plugin_name: mesh_route_dispatch
    scope: proxy
    proxy_id: reviews
    enabled: true
    config:
      reject_unmatched: true
      rules:
        - match:
            uri:
              prefix: /reviews/api
          destination:
            backend_host: reviews-v2.default.svc.cluster.local
            backend_port: 9080
          rewrite:
            uri: /v2
            match_prefix: /reviews/api
          request_transform:
            - operation: update
              key: x-route
              value: reviews-v2
            - operation: remove
              key: x-internal-debug
          response_transform:
            - operation: add
              key: x-served-by
              value: edge
  - id: reviews-route-request-consumer
    plugin_name: request_transformer
    scope: proxy
    proxy_id: reviews
    enabled: true
    config:
      apply_route_overrides: true
      rules: []
  - id: reviews-route-response-consumer
    plugin_name: response_transformer
    scope: proxy
    proxy_id: reviews
    enabled: true
    config:
      apply_route_overrides: true
      rules: []
proxies:
  - id: reviews
    listen_path: /reviews
    backend_scheme: http
    backend_host: reviews-v1.default.svc.cluster.local
    backend_port: 9080
    plugins:
      - plugin_config_id: reviews-routing
      - plugin_config_id: reviews-route-request-consumer
      - plugin_config_id: reviews-route-response-consumer
```

With `reject_unmatched: true` in that last example, a request under `/reviews`
that does not start with `/reviews/api` is answered `404` rather than reaching
`reviews-v1`.

See [Mesh VirtualService translation](../mesh.md#virtualservice-translation) and [plugin execution order](../plugin_execution_order.md#why-this-order-matters) for route-collapse, fault, rewrite, redirect, and HBONE behavior.
