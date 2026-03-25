# CORS Plugin

This document explains how to configure the Cross-Origin Resource Sharing (CORS) plugin in Ferrum Gateway.

## Overview

The CORS plugin handles the [CORS protocol](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) at the gateway level, so backend services do not need to implement CORS themselves. It intercepts preflight `OPTIONS` requests, validates origins and methods, and injects the required `Access-Control-*` response headers on actual cross-origin requests.

### What the plugin does

1. **Preflight interception** -- When a browser sends an `OPTIONS` request with `Origin` and `Access-Control-Request-Method` headers, the plugin validates the origin and requested method against the configured allow-lists. If both pass, it responds with `204 No Content` and all required CORS headers. If either fails, it responds with `403 Forbidden` and a descriptive error body. The request never reaches the backend.

2. **Origin and method enforcement** -- Non-preflight requests that carry an `Origin` header are checked against the allowed origins list. Requests from disallowed origins are rejected with `403 Forbidden` and the body `CORS origin not allowed`.

3. **Response header injection** -- For allowed cross-origin requests that pass through to the backend, the plugin injects `Access-Control-Allow-Origin`, `Vary`, and optionally `Access-Control-Allow-Credentials` and `Access-Control-Expose-Headers` into the backend response before it reaches the client.

## Configuration

The CORS plugin is configured via the `plugin_configs` section in your YAML configuration file, or through the admin API when running in control-plane mode.

### Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_origins` | `string[]` | `["*"]` | Origins permitted to make cross-origin requests. Use `["*"]` to allow any origin, list specific origins for exact matching, or use wildcard subdomain patterns like `"*.company.com"` to allow all subdomains. These can be mixed (see examples below). If `"*"` appears anywhere in the list, all origins are allowed. |
| `allowed_methods` | `string[]` | `["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"]` | HTTP methods returned in the `Access-Control-Allow-Methods` preflight header. Preflight requests for unlisted methods are rejected with 403. |
| `allowed_headers` | `string[]` | `["Accept","Authorization","Content-Type","Origin","X-Requested-With"]` | Request headers returned in the `Access-Control-Allow-Headers` preflight header. |
| `exposed_headers` | `string[]` | `[]` | Response headers the browser is allowed to access via JavaScript, returned in `Access-Control-Expose-Headers`. |
| `allow_credentials` | `bool` | `false` | When `true`, sends `Access-Control-Allow-Credentials: true`. Cannot be used with wildcard origins (see below). |
| `max_age` | `u64` | `86400` | Number of seconds browsers should cache preflight results (`Access-Control-Max-Age`). |
| `preflight_continue` | `bool` | `false` | When `true`, preflight requests are passed through to the backend instead of being short-circuited by the plugin. Useful if your backend needs to handle `OPTIONS` itself. |

### Credentials and Wildcard Origins

Per the CORS specification, `Access-Control-Allow-Origin: *` cannot be combined with `Access-Control-Allow-Credentials: true`. If you configure `allow_credentials: true` with wildcard origins, the plugin logs a warning and automatically disables credentials. To use credentials, specify explicit origins.

## Usage Examples

### Example 1: Global Wildcard CORS (Development)

Allow any origin to access all proxied routes. Suitable for local development.

```yaml
plugin_configs:
  - id: "cors-dev"
    plugin_name: "cors"
    config: {}
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

> **Note:** Wildcard subdomain patterns match the host portion of the origin only. `*.company.com` matches any origin whose host ends with `.company.com`, regardless of scheme or port. The bare domain (`company.com` without a subdomain) does **not** match — add it as a separate exact entry if needed.

### Example 5: Backend Handles OPTIONS

If your backend service implements its own preflight handling and you only want the gateway to add response headers, set `preflight_continue: true`.

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
| `Access-Control-Allow-Origin` | Preflight (204) and actual responses | `*` (wildcard) or the specific origin |
| `Access-Control-Allow-Methods` | Preflight only | Comma-separated list from `allowed_methods` |
| `Access-Control-Allow-Headers` | Preflight only | Comma-separated list from `allowed_headers` |
| `Access-Control-Max-Age` | Preflight only | Seconds from `max_age` |
| `Access-Control-Allow-Credentials` | When `allow_credentials: true` | `true` |
| `Access-Control-Expose-Headers` | When `exposed_headers` is non-empty | Comma-separated list |
| `Vary` | Always on allowed responses | `Origin` |

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
# Preflight request (should return 204 with CORS headers)
curl -v -X OPTIONS http://localhost:8000/api/users \
  -H "Origin: https://app.example.com" \
  -H "Access-Control-Request-Method: GET"

# Preflight with disallowed origin (should return 403)
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

# Actual request with disallowed origin (should return 403)
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
RUST_LOG=debug ./ferrum-gateway
```

Look for log lines starting with `cors:` for preflight approvals, rejections, and origin checks.

## Security Considerations

1. **Avoid wildcard origins in production.** `allowed_origins: ["*"]` allows any website to make cross-origin requests to your API. Use explicit origins for production deployments.

2. **Be restrictive with methods.** Only allow the HTTP methods your API actually uses. Avoid allowing `TRACE` or other methods your backend does not handle.

3. **Limit exposed headers.** Only expose response headers that the front-end application actually needs access to via JavaScript.

4. **Use credentials carefully.** `allow_credentials: true` means cookies and authorization headers are sent on cross-origin requests. Only enable this when your front-end application requires it, and always pair it with explicit origins.

5. **Set a reasonable max_age.** The default of 86400 seconds (24 hours) means browsers cache preflight results for a day. Shorter values (e.g., 3600) provide more frequent revalidation at the cost of more preflight requests.
