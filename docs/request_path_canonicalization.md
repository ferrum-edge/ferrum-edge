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

| Client sends    | Operator rule | Raw-target reading  | Backend dispatches |
| --------------- | ------------- | ------------------- | ------------------ |
| `/%61dmin`      | `/admin`      | `/%61dmin` — no hit | `/admin`           |
| `/api%2Fadmin`  | `/api/admin`  | one segment         | two segments       |

The fix is representational rather than per-plugin: canonicalize once, store
the result in `RequestContext::path`, and let every existing consumer keep
reading that one field. There is no second normalization model and no
per-plugin decoding.

## The contract

`canonicalize_policy_path()` returns either a canonical path or a rejection.
The frontends call `canonicalize_request_path()`, which applies the same rules
and also reports whether the canonical path carries a `;` path parameter, so
the per-proxy rule in [Path parameters](#path-parameters-require-a-per-proxy-opt-in)
can be applied once the route is known.

**Fast path.** The normal path is allocation-free but not unvalidated. A single
scan proves the target carries no percent escape, no literal `\`, no literal
`.`/`..` segment, and no non-final empty segment; only then is it returned
borrowed and unchanged. Each segment is classified once, when its `/` or the
end of the target is reached, and noting a `;` is one more case of the same
byte match, not a second scan. A target is
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
| `ambiguous_dot_segment`  | `/a/%2e%2e/b`, `/a/%2e%2e;/b`, `/a/..%3B/b` | A percent escape produced a `.` or `..` segment, or the `;` that makes one a path-parameter dot segment. |
| `literal_dot_segment`    | `/a/../b`, `/a/./b`, `/a/..`, `/a/..;/b`, `/a/.;x/b` | A `.` or `..` segment written literally, with or without a `;` path parameter. See below. |
| `empty_segment`          | `//a`, `/a//b`, `/;x/a`, `/a/%3Bx/b` | A non-final empty segment, or a non-final segment that is empty before its first `;`. See below. |
| `path_parameter`         | `/a;x/b`, `/a%3Bx/b` | A `;` path parameter on a proxy that has not set `allow_path_parameters`, or whose parameter-stripped path belongs to a different proxy. Applied after route lookup and before any plugin runs. See below. |

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

**A `;` path parameter does not hide a dot segment.** A segment is a dot segment
when its text before the first `;` is `.` or `..`, so `..;`, `.;x`, and
`..;jsessionid=1` are refused exactly like `..` and `.`. `;` is a legal path
character, so the `url` crate forwards `/a/..;/b` unchanged, but servlet
containers and frameworks that strip path parameters before resolving dot
segments (Tomcat, Spring, some Jetty configurations) resolve it to `/b`. An
escaped `;` (`%3B`) is decoded like every other `pchar` escape, so `..%3B` is
the same segment after canonicalization and is refused as
`ambiguous_dot_segment`; because no escape survives canonicalization, a
decoding backend is never handed a `%3B` it could turn into `..;` after policy
ran. A dot segment is `ambiguous_dot_segment` when an escape produced one of
its dots or its `;` delimiter, and `literal_dot_segment` otherwise; an escape
inside the parameter itself (`..;%61`) does not change that. A `;` on an
ordinary segment (`/v1;version=2`, `/a;b`, `/..a;b`) is not a dot segment; it
falls under the per-proxy path-parameter rule below.

**Empty segments are rejected, except a trailing one.** A non-final empty
segment (`//admin`, `/a//b`) and a non-final segment that is empty before its
first `;` (`/;x/admin`, `/a/;/b`, and the escaped `/%3Bx/admin`) are refused as
`empty_segment`. Tomcat, Spring, and nginx (`merge_slashes`, on by default)
collapse `//`, and servlet stacks strip `;…` before doing so, so
`//admin/users` and `/;x/admin/users` execute `/admin/users` while routing and
policy would read a different path: segment-aware routing could pick a
catch-all over a protected `/admin` route, and even a bare prefix rule would
miss. Collapsing inside the gateway would be a second reading, so the target
is refused. A trailing slash (`/a/`) and the root path (`/`) are not empty
segments and are unaffected. A *final* parameter-only segment
(`/ctx/;jsessionid=abc`, which Tomcat emits for directory URLs) resolves to the
trailing-slash path rather than a collapsed one, so this rule admits it; its
`;` is still a path parameter under the per-proxy rule below. This applies on
every proxy, including one that opts in to path parameters.

## Path parameters require a per-proxy opt-in

Tomcat and Spring strip RFC 3986 path parameters (`;…`) from every segment
before dispatch, so `/admin;x/users`, `/admin;/users`, and `/admin%3Bx/users`
all execute `/admin/users`. The gateway evaluates policy on the literal
canonical path, so those spellings would miss an exact authorization rule, a
WAF `Exact` or `Regex` condition, a `Prefix` written with a trailing `/`, or a
`request_termination` prefix, and could route past a protected route to a
catch-all. The gateway also decodes `%3B` to a literal `;`, which such a
backend then strips.

Stripping the parameter from the policy path while forwarding the original
would reintroduce two coordinates, and stripping it from both would forward a
different request than the client sent. So a `;` in the canonical path —
literal, or decoded from `%3B` — is refused with `400` (`path_parameter`)
unless the proxy the request routes to sets `allow_path_parameters: true`.

**Ordering.** Whether a proxy allows parameters is only known once the request
is routed, and canonicalization runs before routing. The frontends therefore:

1. canonicalize the target, which records whether it contains a `;`;
2. run route lookup on the canonical path;
3. refuse the request if it contains a `;` and the matched proxy has not
   opted in;
4. on an opted-in proxy, re-resolve the route with every parameter removed
   (the path a parameter-stripping backend executes) and refuse the request
   when that path belongs to a different proxy (see below for which one
   counts);
5. only then run any plugin phase or backend dispatch.

Route lookup is a literal match on the canonical path and grants nothing on its
own, and steps 3 and 4 run before every policy surface, so no plugin ever
evaluates a path carrying a `;` on a proxy that has not opted in. A route miss
still answers `404` as before.

Step 4 is needed because the router splits only on `/`: `/admin;x/users` does
not match an `/admin` route, so on its own it would fall through to an opted-in
`/` or `/api` catch-all, whose parameter-stripping backend would then execute
`/admin/users` without the `/admin` proxy's plugins. The stripped path
`/admin/users` routes to `/admin`, a different proxy, so the request is
refused. A stripped path that routes to the same proxy, or to no proxy at all,
is accepted: neither can skip another proxy's policy. The re-resolve
allocates, but only for a request that carries a `;` and reached an opted-in
proxy.

**A literal `listen_path` with `;` is not shadowed by a catch-all.** A proxy
whose literal `listen_path` itself contains `;` (for example `/api;v=1`) only
ever receives requests whose stripped path starts with that `listen_path`
stripped (`/api`). If a catch-all `/` exists, that stripped path routes to the
catch-all, so refusing every different stripped route would make the proxy
unreachable. For a proxy with a literal `listen_path` (prefix or `=` exact),
the gateway therefore accepts a different stripped route when all of these
hold:

- the stripped route matched fewer bytes than the proxy's `listen_path` with
  its own parameters and any trailing `/` stripped (so `/api;v=1/` is measured
  as `/api`). The router matches prefixes only on `/` boundaries, so such a
  route is an ancestor of the whole space the proxy claims (`/` for
  `/api;v=1`). A host-only route matches zero bytes and counts as an ancestor
  too;
- the stripped route sits in a host tier no more specific than the one the
  proxy was found in (exact host, then a longer wildcard, then a shorter
  wildcard, then no hosts).

A direction-scoped mesh route counts like any other route here, because the
re-resolve repeats the request's own mesh resolution (see
[Mesh-materialised routes](#mesh-materialised-routes)).

Every other different stripped route is refused. A sibling at the stripped
prefix (`/api` next to `/api;v=1`), a more specific descendant
(`/api/private`, reached with `/api;v=1/private/x`), and any exact or regex
route, which always matches the whole path, stay refused. So does an exact-host
`/svc` against a catch-all `/svc;v=1/v2`: on that host the exact-host route
owns `/svc/v2/x` ahead of every catch-all route, even though its prefix is
shorter. A catch-all `/api/private` is refused against an exact-host
`/api;v=1` as well: on that host `/api/private/x` routes to it, and the
host-specific proxy does not claim that path. A proxy whose `listen_path` is a
regex, or that has none (host-only), keeps the plain rule: any different
stripped route is refused. The classic case is unchanged: an opted-in `/` has a
stripped prefix of one byte, so an `/admin` route always outranks it and
`/admin;x/users` is refused.

Trade-off: when the opted-in proxy and the ancestor it wins over share a
backend that strips path parameters, that backend serves the whole stripped
subtree (`/api/...` for `/api;v=1`) through the opted-in proxy and its plugins,
not the ancestor's. Configure the opted-in proxy's own authentication and
policy for that subtree, or give it a dedicated backend.

**With the opt-in.** On a proxy with `allow_path_parameters: true`, the `;` is
kept in the canonical path and forwarded unchanged, so routing, policy, and the
backend read the same string. That keeps the earlier behaviour for backends that use
matrix parameters. The dot-segment and empty-segment rules still apply
(`/a/..;/b` and `/;x/a` are refused), but policy on that proxy evaluates the
parameterised path: a rule for `/admin/users` does not match `/admin;x/users`.
Enable it only for backends that give `;` a meaning, and write policy for the
spellings those backends accept. Mesh authorization (`mesh_authz`) is the
exception: on an opted-in proxy it judges `AuthorizationPolicy` `paths:`,
`notPaths:`, and `request.headers[:path]` conditions on both the raw and the
parameter-stripped spelling (see
[Mesh authorization judges both spellings](#mesh-authorization-judges-both-spellings)). A literal `listen_path` that contains `;`
requires the opt-in on its proxy and is rejected at admission otherwise. A
`~regex` `listen_path` that contains `;` on a proxy without the opt-in is
loaded with a warning, since the part of the pattern that needs a parameter is
unreachable.

Gateway API routes whose literal path match itself contains `;` are translated
with `allow_path_parameters: true`, since the route declares the parameter
explicitly; every other translated route keeps the default. Mesh-materialised
routes follow their service's opt-in, described next.

### Mesh-materialised routes

Mesh mode builds its HTTP routes from the mesh slice, so it has no per-proxy
field to set. The opt-in is per service instead: `MeshService`
`allow_path_parameters: true`, or the Kubernetes Service annotation
`ferrum.io/allow-path-parameters: "true"`, sets `allow_path_parameters` on every
HTTP-family route mesh mode materialises for that service: the outbound routes
each client sidecar or node proxy builds to it (including direct Pod-IP
routes), its local Sidecar inbound routes, and the Sidecar `ingress[]`
listener routes it owns. Default `false`, so a service without it still
refuses `;` with `400 path_parameter`. Stock (non-Ferrum) xDS control planes
cannot carry the field, so their services stay refused. See
[mesh.md](mesh.md#path-parameters-and-the-per-service-opt-in).

The re-resolve of an opted-in request repeats the request's own resolution,
mesh steps included, before it compares routes:

1. the same host, frontend port, TLS class, and Gateway listener;
2. the same mesh direction filter: on a capture listener only the routes of
   that listener's direction count (outbound on the outbound listener, inbound
   and `ingress[]` on the inbound listener), and on every other listener, the
   HTTP/3 frontend included, no direction-scoped mesh route counts;
3. the same port-sibling selection: a multi-port service's routes share one
   representative in the route table, so the request's captured original
   destination or authority port picks the sibling again, and a dedicated
   Sidecar ingress bind route must match the accepted frontend port;
4. the direct Pod-IP HTTP egress decision is not repeated, because it reads
   only the captured original destination, never the path, so the stripped
   path takes the same route.

So an opted-in mesh route re-resolves to itself, and the request is served.
A stripped path that the mesh port selection would refuse (`502`) is refused
here too. Every mesh-materialised route is a `/` prefix on its service's own
hosts, so a different stripped route can only be a longer route on those
hosts, such as an explicit `/admin` route next to the service's `/`. That
route is never an ancestor of `/`, so `/admin;x/users` on the opted-in service
is still refused. A `;` never changes the `Host` or the port signals, so it
cannot move a request onto another service or another port sibling.

### Mesh authorization judges both spellings

On a proxy with `allow_path_parameters: true`, a `;` request has two
spellings: the raw path the gateway forwards (`/admin;x/users`), which a
backend that keeps parameters executes, and the parameter-stripped path
(`/admin/users`), which a Tomcat or Spring backend executes. The gateway cannot
tell which kind of backend it forwards to, so `mesh_authz` evaluates every
`AuthorizationPolicy` rule once per spelling and combines the two results by
the rule's action (issue #5948). Within one evaluation, `to:` `paths:` /
`notPaths:` and any `when: request.headers[:path]` condition all read the
same spelling, so the two halves of a rule are never judged on different
paths.

| Action | The rule matches when |
|--------|-----------------------|
| `DENY` | it matches on the raw spelling **or** on the stripped spelling |
| `CUSTOM` | it matches on the raw spelling **or** on the stripped spelling |
| `AUDIT` | it matches on the raw spelling **or** on the stripped spelling |
| `ALLOW` | it matches on the raw spelling **and** on the stripped spelling |

On one spelling, a `to:` entry matches when its `paths:` (if set) contain the
spelling and its `notPaths:` (if set) do not, and a `request.headers[:path]`
condition matches when its `values:` (if set) contain the spelling and its
`notValues:` (if set) do not. So:

- a DENY on `/admin/*` refuses `/admin;x/users`, and a DENY on `/api/admin/*`
  refuses `/api;x/admin/users`, whether written as `paths:` or as a
  `request.headers[:path]` condition;
- a `notPaths:` or `notValues:` exclusion lifts a DENY only when it holds for
  both spellings;
- an ALLOW on `*.png` does not admit `/admin/users;x.png`, because the stripped
  `/admin/users` is not a `.png`;
- an ALLOW on `/api/*` with `notPaths: /api/admin/*` (or a `:path` condition
  with `notValues: /api/admin/*`) does not admit `/api/admin;x/users`, because
  the stripped spelling is excluded;
- a prefix ALLOW such as `/app/*` still admits `/app/page;jsessionid=abc`, since
  both spellings match, and an exact ALLOW such as `/app/page` still does not
  match the raw `/app/page;jsessionid=abc`, as before. A presence pattern
  (`*`) matches both spellings.

DENY and CUSTOM restrict (a matched CUSTOM rule sends the request to its
external authorizer before anything else takes effect) and AUDIT only records,
so matching either spelling is the safe direction for them. ALLOW grants
access, so it must hold for both. The same rule decides which CUSTOM rules make
`mesh_authz` buffer a request body for a body-inspecting provider.

The combination is per rule, not per decision. The ALLOW implicit-deny floor is
met only by an ALLOW rule that matches on both spellings, so a request whose
raw spelling matches one ALLOW rule and whose stripped spelling matches a
different one is implicitly denied. Write one rule that covers both spellings,
for example a prefix pattern.

The second spelling is built whenever the canonical path carries a `;`. Only a
proxy with `allow_path_parameters` lets such a request reach a plugin (every
other proxy refuses it with `400 path_parameter` first), so authorization on
routes that have not opted in is unchanged. A path without a `;` has one
spelling and is evaluated exactly once.

**What a CUSTOM provider sees.** A CUSTOM (ext_authz) check is sent the raw
request path only, as the HTTP ext-authz protocol defines it. A provider that
makes its own path decisions on an opted-in service should apply the same rule
to the stripped spelling, or be scoped with a DENY-safe `paths:` rule on the
gateway side.

**VirtualService `uri` matches.** Ferrum compiles a VirtualService
`http[].match[].uri` into the `listen_path` of the proxy it emits for that
route (prefix, `=` exact, or `~` regex), and the `uri` that a
`mesh_route_dispatch` rule re-checks is evaluated on that same proxy.
VirtualService routes never inherit the service's opt-in. A route whose own
`uri` literal contains `;` opts in by itself, and `mesh_authz` judges both
spellings on it. Every other VirtualService route refuses a `;` request with
`400 path_parameter` before any plugin runs, so its `uri` matcher never sees a
parameterised path. A `;` request that reaches an opted-in mesh route, but
whose stripped path belongs to a VirtualService route on the same host, is
refused by the re-route check above. A VirtualService `/` route on the
service's host makes the mesh route yield to it, so the service's opt-in is not
applied there, and `;` stays refused (fail closed). VirtualService URI matching
therefore only selects routes, and the re-route check already covers it.

**Provider override queries are not canonicalized.** A plugin that rewrites
the backend path (`ai_stream_router`, `ai_federation`) may put the endpoint and
client query into the override. Only the path component of an override goes
through the canonicalizer; the query reaches the provider byte-identical, so an
encoded `%26` or `%3D` in a client value is never decoded into a new provider
parameter (GHSA-653r-wc8x-4fch).

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
routing, every plugin phase, and backend dispatch, and apply the per-proxy
path-parameter rule at the same point after route lookup. All three accept and
reject the same set of targets. Plain HTTP receives the fixed, non-echoing `400`;
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
is canonical exactly when it contains no percent escape, no literal `\`, no
literal `.`/`..` segment, and no non-final empty segment. Rather than silently
never firing, non-canonical values are rejected at admission using the same
canonicalizer:

- `Proxy.listen_path` — rejected by `Proxy::validate_fields()` and by the
  dedicated `GatewayConfig::validate_listen_path_encodings()` that runs on
  every load and reload path, including SQL/DP loads where the catch-all
  validator is warn-only.
  A literal `listen_path` containing `;` is also rejected unless the proxy
  sets `allow_path_parameters`, since no request carrying one could reach it.
- `request_termination` `trigger.path_prefix` — rejected by the plugin
  constructor, and therefore by Admin API validation, file-mode startup, and DB
  admission. Prefixes that cannot appear in a parsed `Uri::path()` (`?`, `#`,
  or a literal space) are also refused so the trigger cannot be a silent no-op.
- WAF `conditions.paths` (custom rules and `rule_overrides`) — rejected by the
  plugin constructor. An exact value and a `prefix*` value are held to the full
  contract; a `~regex` value is regex text and is not canonicalized. A
  condition that can never match would leave its rule silently inactive.
- OpenAPI server base paths (`servers[].url`, Swagger `basePath`) — every base
  segment must be one a canonical request path can contain, so an empty
  segment or a surviving escape is refused on import.

A `~regex` `listen_path` is a *pattern*, not a literal path, so only the escape
half of the contract applies to it. `\` and `.` are regex syntax there —
`~^/v1\.0/.*` matches the entirely reachable canonical path `/v1.0/x` — and the
canonical request path a pattern is matched against already cannot contain a
backslash or a dot segment, so holding the pattern to the literal rules would
reject working routes without closing anything. Percent escapes are still
refused in a pattern, because no regex metacharacter makes `%2F` match a path
that can never contain a `%`.

`openapi_validator` path regexes and other regex-shaped path scopes are
operator-authored patterns rather than literal paths and are not canonicalized;
write them against the canonical form.

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

Six shapes of traffic are refused with `400`. Clients and APIs that send them
must change:

- Targets with encoded separators (`%2F`, `%252F`). Folding them into `/` would
  change segment structure and could still disagree with a backend that does
  not decode; refusing cannot. APIs that carry an encoded `/` inside a path
  parameter must move that value into the query string or a header.
- Targets with a `.` or `..` segment, whether the segment was
  written literally (`/a/../b`, `literal_dot_segment`) or produced by a percent
  escape (`/a/%2e%2e/b`, `ambiguous_dot_segment`), and whether or not it carries
  a `;` path parameter (`/a/..;/b`, `/a/.;x/b`). Clients that relied on the
  gateway forwarding a relative target must send the resolved path. A `.` inside
  a segment (`/v1.0/users`, `/a/.hidden`) is unaffected.
- Targets with a literal backslash (`literal_backslash`), alongside the
  encoded `%5C` form.
- Targets carrying an escape of a byte outside the `pchar` decode set — `%20`
  for space, `%7B`/`%5B` for brackets, and any percent-encoded non-ASCII text
  such as `/caf%C3%A9` (`unrepresentable_escape`). This is the broadest of the
  four: **percent-encoded spaces and percent-encoded non-ASCII path segments
  are not accepted at all**, for the reasons given in the rejection table. APIs that need spaces or
  non-ASCII text in a resource identifier should carry that value in the query
  string, a header, or a body field, or use a `pchar`-legal identifier in the
  path. Note that this is a rule about escapes: a client that sends non-ASCII
  path bytes *literally* — `/café` rather than `/caf%C3%A9` — is still served,
  because `http`'s request-target parser accepts valid UTF-8 literally. See
  [Literal non-`pchar` bytes](#literal-non-pchar-bytes). Standard HTTP clients
  percent-encode such paths, so most callers will see the `400`.
- Targets with a non-final empty segment or a segment that is empty before its
  first `;` (`//a`, `/a//b`, `/;x/a`, `empty_segment`). Clients must send the
  collapsed path. A trailing slash is unaffected.
- Targets with a `;` path parameter (`/a;x/b`, `/a%3Bx/b`, `path_parameter`)
  on a proxy that has not set `allow_path_parameters: true` (in mesh mode, on
  a service that has not opted in). This is the only rule with a switch, and
  the switch is per proxy (or per mesh service) rather than per deployment:
  it keeps the `;` in the one canonical path instead of computing policy
  differently, and the structural rules above still apply with it on.

There is no configuration switch for the other five. A per-deployment opt-out
would mean policy is computed differently depending on config, which is the
class of divergence this representation exists to eliminate.

## Related

- `docs/routing.md` — route matching and `strip_listen_path`
- `docs/plugins.md` — `waf`, `openapi_validator`, `request_termination`,
  `hmac_auth`
- `docs/mesh.md` — Istio `AuthorizationPolicy` `paths:` / `notPaths:` matching,
  which runs on this canonical path. `mesh_authz`
  re-runs the canonicalizer before it evaluates a rule and denies with `403`
  rather than matching a target it cannot reduce to one reading.
- `src/router_cache.rs` `normalize_encoded_slashes()` — an older helper that is
  a no-op on canonical paths; it is kept so backend listen-path stripping uses
  the same offset coordinate system as the router
