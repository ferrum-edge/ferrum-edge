# CORS Plugin

This document explains how to configure the Cross-Origin Resource Sharing (CORS) plugin in Ferrum Edge.

## Overview

The CORS plugin handles the [CORS protocol](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) at the gateway level, so backend services do not need to implement CORS themselves. It intercepts preflight `OPTIONS` requests, validates their requested methods and headers, validates origins on actual requests, and injects the required `Access-Control-*` response headers on cross-origin HTTP and gRPC-Web responses.

### What the plugin does

1. **Preflight interception** -- When a browser sends an `OPTIONS` request with `Origin` and `Access-Control-Request-Method` headers, the native direct plugin validates the origin and requested method against the configured allow-lists. If both pass, it responds with `204 No Content` and all required CORS headers. If either fails, it responds with `403 Forbidden` and a descriptive error body. The request never reaches the backend unless `preflight_continue` is enabled.

2. **Actual-request origin enforcement** -- Non-preflight requests that carry an `Origin` header are checked against the allowed origins list. A native direct policy rejects disallowed origins with `403 Forbidden` and the body `CORS origin not allowed`; an Istio projection forwards unmatched actual requests while stripping every upstream `Access-Control-*` response field and adding no gateway CORS authorization fields. `allowed_methods` and `allowed_headers` are preflight policy only: they never reject an actual request or re-authorize headers on that phase.

3. **Response header injection** -- For allowed cross-origin requests that pass through to the backend, the plugin injects `Access-Control-Allow-Origin`, `Vary`, and optionally `Access-Control-Allow-Credentials` and `Access-Control-Expose-Headers` into the backend response before it reaches the client.

## Configuration

The CORS plugin is configured via the `plugin_configs` section in your YAML configuration file, or through the admin API when running in control-plane mode.

### Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_origins` | `(string \| object)[]` | required, max 64 entries | Origins permitted to make cross-origin requests. Use `"*"` only for intentional allow-all. **Plain strings are native syntax:** exact `scheme://host[:port]` values are URL-parsed and canonicalized once at config load (scheme/host case, default ports, IDNA, IPv4, and IPv6) and matched case-insensitively, and `"*.company.com"` matches subdomains; request matching remains a direct comparison with no per-request URL parse/allocation. **Istio-shaped objects carry exactly one of `exact` / `prefix` / `regex` and retain literal source semantics:** object `exact` is a byte-for-byte, case-sensitive comparison with no canonicalization and no wildcard interpretation (so `{exact: "*.example.com"}` matches only that literal string), except `{exact: "*"}` which is Istio allow-all. Each matcher value is bounded at 512 bytes; regexes are compiled once at config construction/reload under explicit complexity limits. |
| `allowed_methods` | `string[]` | `["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"]` | Preflight-only policy returned in `Access-Control-Allow-Methods`. Native preflights for unlisted methods are rejected with 403; the list is not evaluated against an actual request's method. |
| `allowed_headers` | `string[]` | `["Accept","Authorization","Content-Type","Origin","X-Requested-With"]` | Preflight-only policy returned in `Access-Control-Allow-Headers`. It is not evaluated against headers on the actual request. |
| `exposed_headers` | `string[]` | `[]` | Response headers the browser is allowed to access via JavaScript, returned in `Access-Control-Expose-Headers`. |
| `allow_credentials` | `bool` | `false` | When `true`, sends `Access-Control-Allow-Credentials: true`. Cannot be used with wildcard origins (see below). |
| `max_age` | `u64` | `86400` | Number of seconds browsers should cache preflight results (`Access-Control-Max-Age`). |
| `preflight_continue` | `bool` | `false` | When `true`, preflight requests are passed through to the backend instead of being short-circuited by the plugin. Useful if your backend needs to handle `OPTIONS` itself. |
| `unmatched_preflights` | `forward` or `ignore` | not set | Translation marker used for Istio policies. `forward` represents omitted/`UNSPECIFIED`/`FORWARD`; `ignore` answers unmatched preflights locally with 200 and no CORS authorization fields. Its presence also preserves empty method/header lists and absent max age. Do not combine it with `preflight_continue`. |

The config root must be an object. Unknown keys, explicit `null`, invalid or
whitespace-padded tokens, and an omitted/empty `allowed_origins` policy are
rejected during startup or reload. There is no implicit wildcard origin policy;
write `allowed_origins: ["*"]` when allow-all is intended.

### Credentials and Wildcard Origins

Per the CORS specification, `Access-Control-Allow-Origin: *` cannot be combined with `Access-Control-Allow-Credentials: true`. If you configure `allow_credentials: true` with wildcard origins, the plugin logs a warning and automatically disables credentials. To use credentials, specify explicit origins.

## Usage Examples

### Example 1: Global Wildcard CORS (Development)

Allow any origin to access all proxied routes. Suitable for local development.

```yaml
plugin_configs:
  - id: "cors-dev"
    plugin_name: "cors"
    config:
      allowed_origins: ["*"]
    scope: global
    enabled: true
```

This uses all defaults: any origin, all standard methods, common headers, 24-hour preflight cache.

### Example 2: Strict Production Configuration

Only allow specific front-end applications to access the API with credentials.

```yaml
plugin_configs:
  - id: "cors-prod"
    plugin_name: "cors"
    config:
      allowed_origins:
        - "https://app.example.com"
        - "https://admin.example.com"
      allowed_methods:
        - "GET"
        - "POST"
        - "PUT"
        - "DELETE"
        - "OPTIONS"
      allowed_headers:
        - "Authorization"
        - "Content-Type"
        - "X-Request-ID"
      exposed_headers:
        - "X-Request-ID"
        - "X-RateLimit-Remaining"
      allow_credentials: true
      max_age: 3600
    scope: global
    enabled: true
```

### Example 3: Per-Proxy CORS

Apply different CORS policies to different proxied services. Attach the plugin to a specific proxy rather than using global scope.

```yaml
proxies:
  - id: "public-api"
    listen_path: "/api/public"
    backend_host: "public-svc.internal"
    backend_port: 8080
    plugins:
      - "cors-permissive"

  - id: "admin-api"
    listen_path: "/api/admin"
    backend_host: "admin-svc.internal"
    backend_port: 8081
    plugins:
      - "cors-strict"

plugin_configs:
  - id: "cors-permissive"
    plugin_name: "cors"
    config:
      allowed_origins: ["*"]
    scope: proxy
    enabled: true

  - id: "cors-strict"
    plugin_name: "cors"
    config:
      allowed_origins: ["https://admin.example.com"]
      allow_credentials: true
      allowed_methods: ["GET", "POST"]
      max_age: 600
    scope: proxy
    enabled: true
```

### Example 4: Wildcard Subdomain Origins

Allow all subdomains of a domain, optionally mixed with exact origins.

```yaml
plugin_configs:
  - id: "cors-subdomain"
    plugin_name: "cors"
    config:
      allowed_origins:
        - "*.company.com"
        - "https://partner-app.example.com"
      allow_credentials: true
      max_age: 3600
    scope: global
    enabled: true
```

This allows:
- `https://app.company.com` ✅ (matches `*.company.com`)
- `https://staging.company.com` ✅ (matches `*.company.com`)
- `https://deep.sub.company.com` ✅ (matches `*.company.com`)
- `https://partner-app.example.com` ✅ (exact match)
- `https://company.com` ❌ (bare domain does not match `*.company.com`)
- `https://evil.com` ❌ (no match)

> **Note:** Wildcard subdomain patterns match the host portion of syntactically valid HTTP(S) origins only. `*.company.com` matches any origin whose host ends with `.company.com`, with an optional numeric port. The bare domain (`company.com` without a subdomain) does **not** match — add it as a separate exact entry if needed.

### Example 5: Exact / Prefix / Regex Origin Matchers (Istio `StringMatch`)

For finer-grained control — and for parity with Istio `VirtualService` `corsPolicy.allowOrigins[]`, which the mesh translator projects onto this plugin — `allowed_origins` entries may be `StringMatch`-shaped objects. Each object carries exactly one of `exact`, `prefix`, or `regex`.

> **The two entry families are different matcher semantics — this matters for security.** A plain STRING entry is *native* syntax: it is canonicalized at config load, compared case-insensitively, and a leading `*.` makes it a wildcard-subdomain pattern. An OBJECT `{ exact: … }` entry is *Istio* `StringMatch.exact`: a literal, byte-for-byte, case-sensitive comparison with no canonicalization and no wildcard interpretation.
>
> So `"*.example.com"` (string) allows every `*.example.com` subdomain, while `{ exact: "*.example.com" }` allows only an `Origin` header whose value is literally `*.example.com`. The literal form exists precisely so an Istio source matcher that *looks* like wildcard syntax is preserved rather than silently widened. The one exception is `{ exact: "*" }`, which Istio itself defines as allow-all.
>
> Likewise `{ exact: "https://Example.com:443" }` matches only that exact string; it is **not** normalized to `https://example.com`. Use the plain-string form when you want canonicalizing, case-insensitive origin matching.

```yaml
plugin_configs:
  - id: "cors-stringmatch"
    plugin_name: "cors"
    config:
      allowed_origins:
        - { exact: "https://app.example.com" }
        - { prefix: "https://preview-" }
        - { regex: "https://.*\\.api\\.example\\.com" }
    scope: global
    enabled: true
```

This allows:
- `https://app.example.com` ✅ (exact)
- `https://preview-pr-42.example.com` ✅ (starts with the literal prefix `https://preview-`)
- `https://v2.api.example.com` ✅ (full-matches the regex)
- `https://preview.example.com` ❌ (does not start with `https://preview-`)
- `https://app.example.com.evil.com` ❌ (regex is a **full** match, not a substring search)

> **Semantics:** `exact` is a literal, case-sensitive, byte-for-byte comparison with the request `Origin` header (see the note above). `prefix` is a literal, case-sensitive byte-prefix of the `Origin`. `regex` is an RE2 pattern (the `regex` crate) that must match the **entire** `Origin` — there is no implicit `.*` on either end — mirroring how Ferrum evaluates Istio `StringMatch` regex elsewhere. Use `(?i)` inside the pattern for case-insensitive regex matching.

#### Origin matcher limits

Origin matchers are admitted against explicit bounds on the cold config path. Every regex is compiled **once at config construction and reload**, never per request, and a matcher that exceeds a bound is a config error with a field-specific message — it is never dropped, truncated, or approximated:

| Bound | Value |
| --- | --- |
| `allowed_origins` entries | 64 |
| Bytes per matcher value (native string, `exact`, `prefix`, `regex` pattern) | 512 |
| Compiled regex program size | 64 KiB |
| Regex lazy-DFA cache | 64 KiB |
| Regex AST nesting depth | 24 |

The `regex` crate is finite-automaton based, so a hostile pattern cannot cause catastrophic backtracking; the bounds above additionally cap compile-time memory and per-match cache growth. An empty or whitespace-only `exact`, an empty `prefix` (which would match every origin), and an invalid or over-complex pattern are all rejected when the plugin is created. The same predicates gate the Istio VirtualService translator and native/file mesh validation, so an unrepresentable source policy is reported as a deferred field instead of failing plugin construction later.

### Example 6: Backend Handles OPTIONS

If your backend service implements its own preflight handling and you want it to
own the `OPTIONS` status/body, set `preflight_continue: true`. Ferrum removes
every backend `Access-Control-*` field and emits the complete configured gateway
policy (`Allow-Origin`, `Allow-Methods`, `Allow-Headers`, `Max-Age`, optional
credentials/exposed headers, and `Vary`). A backend therefore cannot widen the
gateway policy.

```yaml
plugin_configs:
  - id: "cors-passthrough"
    plugin_name: "cors"
    config:
      allowed_origins: ["https://app.example.com"]
      preflight_continue: true
    scope: global
    enabled: true
```

## Istio translation semantics

An Istio `VirtualService.http[].corsPolicy` is projected through the gateway and
mesh slice with its source request-handling behavior intact. Ferrum remains
authoritative over the browser-facing response fields:

- omitted, `UNSPECIFIED`, and `FORWARD` unmatched preflights go to the backend,
  preserving its status/body but stripping every upstream `Access-Control-*`
  response field;
- `IGNORE` unmatched preflights receive a local 200 without CORS authorization;
- unmatched actual requests go to the backend with its status/body preserved,
  every upstream `Access-Control-*` response field stripped, and no gateway
  CORS authorization fields added;
- a participating translated policy owns `Access-Control-*` response fields
  even when the request has no `Origin`; Ferrum strips those upstream fields
  while preserving unrelated response headers, preventing a shared-cache replay
  from widening the gateway policy;
- omitted/empty method and header lists stay empty, and omitted `maxAge` stays
  absent; and
- `StringMatch.exact: "*"` and legacy `allowOrigin: ["*"]` mean allow-all;
- every OTHER `StringMatch.exact` value (and every legacy `allowOrigin` entry) is
  projected onto this plugin's **literal** `{ exact: … }` matcher, byte-for-byte.
  A wildcard-shaped value such as `*.example.com` therefore keeps its upstream
  literal meaning and is never reinterpreted as this plugin's
  wildcard-subdomain syntax, and a non-canonical value such as
  `https://Example.com:443` is never widened to its browser serialization; and
- `prefix` / `regex` matchers project onto the matching object entries, with the
  regex compiled at config construction/reload under the limits above.

A policy Ferrum cannot represent faithfully is left **unprojected** — no route
CORS plugin is emitted, and the VirtualService's
`status.ferrum.translation.deferred_fields` names `http[].corsPolicy`. That
applies to a malformed or unknown origin matcher, a matcher value or list beyond
its bound, an un-compilable or over-complex regex, an unparseable `maxAge`, an
invalid method/header token, and credentialed exact `*` (which cannot emit the
concrete request origin credentialed CORS requires). Ferrum never approximates
or widens such a policy.

These rules do not alter operator-authored native direct-plugin behavior.

## Multiple instances

When multiple CORS instances attach to one proxy, Ferrum evaluates the complete
CORS execution chain and emits one phase-appropriate policy. On actual
requests, origins, exposed headers, and credentials compose restrictively;
method/header allow-lists and max age are neither intersected nor enforced
because they govern preflight only. On preflight, allowed methods and request
headers also intersect and the shortest max age wins, so an empty translated
Istio list cannot be widened by a permissive native instance. A permissive
earlier instance cannot short-circuit a stricter later preflight policy.

Priority overrides that interleave another HTTP/gRPC-capable plugin inside the
CORS block are rejected at cache construction. Stream-only and other plugins
whose supported protocols do not overlap CORS are ignored by this contiguity
check because protocol filtering removes them from every CORS execution chain.
The same rules apply when gRPC-Web requests use the gRPC request-policy chain.

## Request Flow

### Preflight Request (OPTIONS)

```
Browser                    Gateway (CORS Plugin)                Backend
  |                              |                                |
  |-- OPTIONS /api/users ------->|                                |
  |   Origin: https://app.com   |                                |
  |   Access-Control-Request-    |                                |
  |     Method: DELETE           |                                |
  |                              |-- Check origin: allowed? ---   |
  |                              |-- Check method: allowed? ---   |
  |                              |                                |
  |<---- 204 No Content --------|   (request never hits backend)  |
  |   Access-Control-Allow-      |                                |
  |     Origin: https://app.com |                                |
  |   Access-Control-Allow-      |                                |
  |     Methods: GET, POST, ...  |                                |
  |   Access-Control-Max-Age:    |                                |
  |     86400                    |                                |
```

### Preflight Rejected (Disallowed Origin)

```
Browser                    Gateway (CORS Plugin)
  |                              |
  |-- OPTIONS /api/users ------->|
  |   Origin: https://evil.com  |
  |   Access-Control-Request-    |
  |     Method: GET              |
  |                              |-- Check origin: NOT allowed ---
  |                              |
  |<---- 403 Forbidden ---------|
  |   Body: "CORS origin        |
  |          not allowed"        |
```

### Preflight Rejected (Disallowed Method)

```
Browser                    Gateway (CORS Plugin)
  |                              |
  |-- OPTIONS /api/users ------->|
  |   Origin: https://app.com   |
  |   Access-Control-Request-    |
  |     Method: TRACE            |
  |                              |-- Check origin: allowed ------
  |                              |-- Check method: NOT allowed --
  |                              |
  |<---- 403 Forbidden ---------|
  |   Body: "CORS method not    |
  |          allowed: TRACE"     |
```

### Actual Cross-Origin Request (Allowed)

```
Browser                    Gateway (CORS Plugin)                Backend
  |                              |                                |
  |-- GET /api/users ----------->|                                |
  |   Origin: https://app.com   |-- origin allowed, stash ----   |
  |                              |-- proxy to backend ----------->|
  |                              |                                |
  |                              |<--- 200 OK + body ------------|
  |                              |-- inject CORS headers ------   |
  |<---- 200 OK + body ---------|                                |
  |   Access-Control-Allow-      |                                |
  |     Origin: https://app.com |                                |
  |   Vary: Origin              |                                |
```

### Actual Cross-Origin Request (Disallowed Origin)

```
Browser                    Gateway (CORS Plugin)
  |                              |
  |-- GET /api/users ----------->|
  |   Origin: https://evil.com  |-- origin NOT allowed ----------
  |                              |
  |<---- 403 Forbidden ---------|
  |   Body: "CORS origin        |
  |          not allowed"        |
```

## Response Headers Reference

| Header | When Sent | Value |
|--------|-----------|-------|
| `Access-Control-Allow-Origin` | Allowed local/forwarded preflights and actual responses | `*` (wildcard) or the specific origin |
| `Access-Control-Allow-Methods` | Preflight only | Comma-separated list from `allowed_methods` |
| `Access-Control-Allow-Headers` | Preflight only | Comma-separated list from `allowed_headers` |
| `Access-Control-Max-Age` | Preflight only | Seconds from `max_age` |
| `Access-Control-Allow-Credentials` | When `allow_credentials: true` | `true` |
| `Access-Control-Expose-Headers` | When `exposed_headers` is non-empty | Comma-separated list |
| `Vary` | Always on allowed responses | Actual: `Origin`. Preflight: `Origin`, `Access-Control-Request-Method`, and `Access-Control-Request-Headers` (including when the last header is absent, so a cached headerless approval cannot satisfy a later header-bearing preflight). Existing backend `Vary` tokens are preserved. |

## Testing

### Run CORS Plugin Tests

```bash
# Run all CORS tests
cargo test --test unit_tests -- cors_tests

# Run a specific test
cargo test --test unit_tests -- cors_tests::test_preflight_with_allowed_origin -- --nocapture
```

### Manual Testing with curl

```bash
# Native direct-plugin preflight (should return 204 with CORS headers)
curl -v -X OPTIONS http://localhost:8000/api/users \
  -H "Origin: https://app.example.com" \
  -H "Access-Control-Request-Method: GET"

# Native direct-plugin preflight with disallowed origin (should return 403)
curl -v -X OPTIONS http://localhost:8000/api/users \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET"

# Preflight with disallowed method (should return 403)
curl -v -X OPTIONS http://localhost:8000/api/users \
  -H "Origin: https://app.example.com" \
  -H "Access-Control-Request-Method: TRACE"

# Actual request with allowed origin (should return backend response + CORS headers)
curl -v http://localhost:8000/api/users \
  -H "Origin: https://app.example.com"

# Native direct-plugin actual request with disallowed origin (should return 403)
curl -v http://localhost:8000/api/users \
  -H "Origin: https://evil.com"

# Request without Origin header (not a CORS request, passes through normally)
curl -v http://localhost:8000/api/users
```

## Troubleshooting

### Common Issues

1. **403 "CORS origin not allowed"**

   The `Origin` header value does not match any entry in `allowed_origins`. Exact origins must include the scheme (e.g., `https://example.com`, not `example.com`). Origin matching is case-insensitive. If using wildcard subdomain patterns (e.g., `*.company.com`), note that the bare domain (`https://company.com`) does not match — add it as a separate exact entry if needed.

2. **403 "CORS method not allowed: ..."**

   The `Access-Control-Request-Method` in the preflight request names a method not in `allowed_methods`. Add the method to the list or check the client request.

3. **Credentials not working with wildcard origins**

   `allow_credentials: true` requires explicit origins. The plugin logs a warning and disables credentials when wildcard origins are used. Specify exact origins to enable credentials.

4. **CORS headers missing on responses**

   The plugin only adds response headers when the request includes an `Origin` header. Requests without `Origin` (same-origin or non-browser clients) pass through without CORS headers.

5. **Preflight requests reaching the backend**

   If `preflight_continue: true` is set, preflight requests are forwarded to the backend. Remove this option to let the plugin handle preflights.

### Debug Tips

Enable debug logging to see CORS decisions:

```bash
RUST_LOG=debug ./ferrum-edge run
```

Look for log lines starting with `cors:` for preflight approvals, rejections, and origin checks.

## Security Considerations

1. **Avoid wildcard origins in production.** `allowed_origins: ["*"]` allows any website to make cross-origin requests to your API. Use explicit origins for production deployments.

2. **Be restrictive with methods.** Only allow the HTTP methods your API actually uses. Avoid allowing `TRACE` or other methods your backend does not handle.

3. **Limit exposed headers.** Only expose response headers that the front-end application actually needs access to via JavaScript.

4. **Use credentials carefully.** `allow_credentials: true` means cookies and authorization headers are sent on cross-origin requests. Only enable this when your front-end application requires it, and always pair it with explicit origins.

5. **Set a reasonable max_age.** The default of 86400 seconds (24 hours) means browsers cache preflight results for a day. Shorter values (e.g., 3600) provide more frequent revalidation at the cost of more preflight requests.
