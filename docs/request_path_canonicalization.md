# Request Path Canonicalization

Ferrum Edge derives **one canonical policy path** for every HTTP-family
request, at the frontend boundary, before routing or any plugin runs. Routing,
WAF, `openapi_validator`, `request_termination`, authorization, cache and
replay keys, rewrites, `strip_listen_path`, and the request line placed on the
backend connection all read that single value.

Implementation: `src/policy_path.rs`. Boundary call sites:
`src/proxy/mod.rs` (HTTP/1.1 + HTTP/2) and `src/http3/server.rs` (HTTP/3).

## Why one representation

A percent-encoded request target has more than one plausible reading. If the
gateway evaluates policy on the raw target while the backend framework
percent-decodes path segments before dispatch, a client can pick a spelling
that misses an operator's rule and still reaches the protected handler:

| Client sends    | Operator rule | Old gateway reading | Backend dispatches |
| --------------- | ------------- | ------------------- | ------------------ |
| `/%61dmin`      | `/admin`      | `/%61dmin` — no hit | `/admin`           |
| `/api%2Fadmin`  | `/api/admin`  | one segment         | two segments       |

The fix is representational rather than per-plugin: canonicalize once, store
the result in `RequestContext::path`, and let every existing consumer keep
reading that one field. There is no second normalization model and no
per-plugin decoding.

## The contract

`canonicalize_policy_path()` returns either a canonical path or a rejection.

**Fast path.** The normal path is allocation-free but not unvalidated. A single
scan proves the target carries no percent escape, no literal `\`, and no literal
`.`/`..` segment; only then is it returned borrowed and unchanged. A target is
accepted because the scan cleared it, not because it happened to contain no `%`.
As soon as the scan reaches a `%` it hands off to the decoding pass, which
re-validates from the first byte, so the two cannot disagree about what is
accepted.

**Accepted and decoded.** An escape of a character that may appear literally in
a path — RFC 3986 `pchar`, i.e. `unreserved` / `sub-delims` / `:` / `@` — is
decoded to that character. `/%61dmin` becomes `/admin`, `/%40user` becomes
`/@user`.

**No escape survives.** An escape is either decoded to the byte it names or the
request is refused, so a canonical policy path never contains a `%`. That is
what makes the canonical path a single coordinate: the gateway cannot evaluate
one spelling while forwarding another that a decoding backend reads
differently.

**Rejected with `400`.** Each case is a target whose meaning depends on which
component decodes it, so there is no reading the gateway can adopt without
risking disagreement with the backend:

| Reason token             | Example          | Why |
| ------------------------ | ---------------- | --- |
| `invalid_escape`         | `/a%`, `/a%2`, `/a%zz` | A lenient parser and a strict one disagree about where the escape ends. |
| `double_encoding`        | `/a%25b`, `/a%252Fb` | An encoded `%` is the lead byte of any double encoding; a second decode could introduce structure. |
| `encoded_separator`      | `/a%2Fb`, `/a%3Fb`, `/a%23b` | Decoding would add a segment, a query, or a fragment the raw target did not have. |
| `encoded_backslash`      | `/a%5Cb`         | Several backend stacks treat `\` as a path separator. |
| `literal_backslash`      | `/a\b`           | The Rust `url` parser — which parses the backend URL on the reqwest dispatch paths — treats `\` as a path separator for special HTTP(S) URLs, as do several backend stacks. A literal `\` is the same route-structure mismatch an encoded one is. |
| `encoded_control`        | `/a%00`, `/a%0A` | A NUL truncates the path in several runtimes; other C0 controls and `DEL` are equally divergent. |
| `unrepresentable_escape` | `/a%20b`, `/a%7Bb`, `/caf%C3%A9`, `/caf%C3%28` | The escaped byte is outside the `pchar` decode set (space, `"`, `<`, `>`, `[`, `]`, `^`, `` ` ``, `{`, `\|`, `}`, and every non-ASCII byte, valid UTF-8 sequence or not). Keeping it escaped would put a different string on the wire than the one policy read; decoding it would emit a byte the backend URL parser cannot carry (space, controls) or percent-encodes again (`"`, `{`, `}`, non-ASCII), so the forwarded request line would not be the canonical string. Neither is a single coordinate, so the target is refused. This rule governs *escapes*; see [Literal non-`pchar` bytes](#literal-non-pchar-bytes) for the same bytes sent literally. |
| `ambiguous_dot_segment`  | `/a/%2e%2e/b`    | A percent escape produced a `.` or `..` segment. |
| `literal_dot_segment`    | `/a/../b`, `/a/./b`, `/a/..` | A `.` or `..` segment written literally. See below. |

Rejections carry a fixed JSON body and a fixed reason token. Neither echoes any
request bytes, and the reject is logged with the reason token only.

**Dot segments are rejected, literal as well as escaped — and never removed.**
A dot segment is not a single policy/backend coordinate. Ferrum's ordinary HTTP
dispatch hands a backend URL string to reqwest (`src/proxy/mod.rs` and
`src/http3/cross_protocol.rs`), which parses it with the Rust `url` crate; every
RFC 3986 / WHATWG normalizer removes dot segments. Policy would therefore
evaluate `/a/../protected` while the request line actually placed on the backend
connection resolves `/protected`. Removing the segment inside the gateway is not
a fix either — removal *is* a second reading, and it would change a request's
meaning. The target is refused instead. A `.` inside a segment is an ordinary
path character: `/v1.0/users` and `/a/.hidden/b` are unaffected; only a
*complete* `.` or `..` segment is a dot segment.

## Literal non-`pchar` bytes

The `unrepresentable_escape` rule above governs percent *escapes*, not literal
bytes, and the two sets are not the same. `http`'s request-target parser — used
by hyper for HTTP/1.1 and HTTP/2 and by the HTTP/3 frontend — permits several
non-`pchar` bytes literally in a path: `"`, `{`, `}`, `[`, `]`, `^`, `|`, and any
byte sequence that is valid UTF-8. Those arrive as ordinary path bytes and are
accepted. So a literal `/café` is served while `/caf%C3%A9` receives `400`, and
`/a{b` is served while `/a%7Bb` receives `400`.

That is deliberate — refusing an escape the gateway cannot forward as one
coordinate does not require also refusing a byte a client may legally send
literally — but it bounds what the invariants below claim. The `url` crate's
path percent-encode set covers controls, space, `"`, `<`, `>`, `` ` ``, `#`,
`?`, `{`, `}`, and every non-ASCII byte, so when a canonical path carrying a
literal one of those is parsed into the backend URL, the forwarded request line
carries the percent-encoded spelling rather than the canonical bytes.
Percent-encoding only ever expands one byte into `%XX`; it can never synthesize
a `/`, `?`, or `#`, and a decoding backend resolves it straight back to the
canonical byte. Segment structure is therefore still preserved and policy still
reads exactly what a decoding backend resolves — but the canonical path is not
always byte-for-byte identical to the forwarded request line.

## Invariants this buys

1. **Structure preservation.** Because every escape that could decode to a
   separator is rejected, and because `\` and dot segments — the two literal
   spellings a URL parser re-reads as structure — are rejected too, the
   canonical path has exactly the segment structure of the raw target, and the
   backend URL parser cannot change that structure either: the only edit it
   makes to a canonical path is percent-encoding a literal byte from its path
   encode set, which expands one byte into `%XX` and can never produce a `/`,
   `?`, or `#`. Routing, `openapi_validator` parameter segments (`[^/]+`), and
   the backend cannot disagree about how many segments a request has or which of
   them the request line ends up naming.
2. **Decode idempotence.** `canonicalize(canonicalize(p)) == canonicalize(p)`,
   and a further decode of a canonical path is a no-op — there is no escape
   left to decode.
3. **One coordinate system.** Only `pchar`-legal bytes are decoded and no
   escape survives, so the canonical path is itself a valid HTTP request target
   *and* is byte-identical to what a decoding backend resolves. Policy
   evaluation and backend forwarding start from the same string, and
   `strip_listen_path` offsets measured by the router are valid offsets into it.
   There is no spelling left on which a policy rule and the application can
   disagree. (The one edit the backend URL parser may still make — percent-
   encoding a literal byte from its path encode set — is reversed by the
   decoding backend, so both ends still read the canonical bytes.)

## Protocol parity

HTTP/1.1, HTTP/2, and HTTP/3 run the check at the same point in the request
ordering — after transport-level validation (URL length, query-parameter count,
`check_protocol_headers`, `check_host_authority_consistency`) and before
routing, every plugin phase, and backend dispatch. All three accept and reject
the same set of targets. Plain HTTP receives the fixed, non-echoing `400`;
native gRPC receives a trailers-only `INVALID_ARGUMENT`; and gRPC-Web receives
HTTP `200` with `INVALID_ARGUMENT` in its body trailer frame on every supported
frontend protocol.

## ACME HTTP-01 serving

ACME HTTP-01 key authorizations are answered ahead of overload admission, so
losing a domain validation to load shedding cannot cost a certificate. That
makes challenge serving the one handler that resolves a target before the check
above runs, so it resolves the *canonical* path too: an escaped-but-legal
spelling of a live challenge (`/%2Ewell-known/acme-challenge/<token>`,
`/.well-known/acme-challenge/tok%5FABC`) serves exactly what its literal
spelling serves, rather than missing the handler and falling through to ordinary
routing. Challenge serving never decides what an ambiguous path means: a target
the canonicalizer refuses resolves to no challenge and reaches the same fixed,
non-echoing `400` every other request does.

## Configured paths must be canonical too

Operator-authored path values are compared against the canonical request path,
so a non-canonical configured value can never match. A configured literal path
is canonical exactly when it contains no percent escape, no literal `\`, and no
literal `.`/`..` segment. Rather than silently never firing, non-canonical
values are rejected at admission using the same canonicalizer:

- `Proxy.listen_path` — rejected by `Proxy::validate_fields()` and by the
  dedicated `GatewayConfig::validate_listen_path_encodings()` that runs on
  every load and reload path, including SQL/DP loads where the catch-all
  validator is warn-only.
- `request_termination` `trigger.path_prefix` — rejected by the plugin
  constructor, and therefore by Admin API validation, file-mode startup, and DB
  admission.

A `~regex` `listen_path` is a *pattern*, not a literal path, so only the escape
half of the contract applies to it. `\` and `.` are regex syntax there —
`~^/v1\.0/.*` matches the entirely reachable canonical path `/v1.0/x` — and the
canonical request path a pattern is matched against already cannot contain a
backslash or a dot segment, so holding the pattern to the literal rules would
reject working routes without closing anything. Percent escapes are still
refused in a pattern, because no regex metacharacter makes `%2F` match a path
that can never contain a `%`.

WAF `conditions.paths`, `openapi_validator` path regexes, and other
regex-shaped path scopes are operator-authored patterns rather than literal
paths and are not canonicalized; write them against the canonical form.

## Raw target

The client's original target is retained on the request context only when
canonicalization changed it. The field has no general context accessor and its
contents are held in an opaque, debug-redacted wrapper whose single consumer is
a private helper inside `hmac_auth`. That signing string binds the literal bytes
the client signed and so cannot verify against a rewritten spelling. Nothing
else can consume or accidentally debug-log it: routing and every policy surface
run on the canonical path, so a raw spelling can never select a different
route, operation, or rule than the backend executes.

Canonicalization runs before any plugin, so a raw target that is refused never
reaches `hmac_auth` at all. The raw path it signs is therefore always one the
canonicalizer accepted, differing from the canonical form only in percent
escapes of `pchar`-legal characters — a client can still sign `/%61dmin`, and
`hmac_auth` still verifies against exactly those bytes.

Transaction logs record the canonical path.

## Operational impact

This is a behavior change for four shapes of traffic that previously succeeded:

- Targets with encoded separators (`%2F`, `%252F`) were folded into `/` for
  route lookup and now receive `400`. Folding changes segment structure, so a
  folded route decision could still disagree with a backend that does not
  decode; refusing cannot. APIs that carry an encoded `/` inside a path
  parameter must move that value into the query string or a header.
- Targets with a `.` or `..` segment now receive `400`, whether the segment was
  written literally (`/a/../b`, `literal_dot_segment`) or produced by a percent
  escape (`/a/%2e%2e/b`, `ambiguous_dot_segment`). Clients that relied on the
  gateway forwarding a relative target must send the resolved path. A `.` inside
  a segment (`/v1.0/users`, `/a/.hidden`) is unaffected.
- Targets with a literal backslash now receive `400` (`literal_backslash`),
  alongside the encoded `%5C` form.
- Targets carrying an escape of a byte outside the `pchar` decode set — `%20`
  for space, `%7B`/`%5B` for brackets, and any percent-encoded non-ASCII text
  such as `/caf%C3%A9` — now receive `400` (`unrepresentable_escape`). This is
  the broadest of the four: **percent-encoded spaces and percent-encoded
  non-ASCII path segments are no longer accepted at all.** The gateway will not
  retain the escape (policy would read a spelling the application resolves
  differently) and will not decode it (the decoded byte is one the backend URL
  parser cannot carry or re-encodes), so it refuses. APIs that need spaces or
  non-ASCII text in a resource identifier should carry that value in the query
  string, a header, or a body field, or use a `pchar`-legal identifier in the
  path. Note that this is a rule about escapes: a client that sends non-ASCII
  path bytes *literally* — `/café` rather than `/caf%C3%A9` — is still served,
  because `http`'s request-target parser accepts valid UTF-8 literally. See
  [Literal non-`pchar` bytes](#literal-non-pchar-bytes). Standard HTTP clients
  percent-encode such paths, so most callers will see the `400`.

There is no configuration switch for any of them. A per-deployment opt-out would
mean policy is computed differently depending on config, which is the class of
divergence this representation exists to eliminate.

## Related

- `docs/routing.md` — route matching and `strip_listen_path`
- `docs/plugins.md` — `waf`, `openapi_validator`, `request_termination`,
  `hmac_auth`
- `src/router_cache.rs` `normalize_encoded_slashes()` — the predecessor helper,
  retained only as an unreachable defense-in-depth residual for callers that do
  not enter through the frontend boundary
