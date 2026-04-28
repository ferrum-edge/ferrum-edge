# API Spec Management

Ferrum Edge can ingest an OpenAPI 2.0 (Swagger), 3.0.x, 3.1.x, or 3.2.x specification document and atomically provision a proxy, optional upstream, and proxy-scoped plugins as a single transactional bundle. This document is the operator reference for the feature.

## Overview

When you submit a spec, Ferrum Edge:

1. Parses the document (JSON or YAML).
2. Extracts Ferrum resources from the `x-ferrum-*` extension fields.
3. Validates each resource against the same rules as the individual admin endpoints.
4. Persists everything atomically (SQL transaction / MongoDB best-effort).
5. Stores the compressed spec bytes with a SHA-256 content hash for later retrieval.

**Hot-path isolation**: the `api_specs` table is admin-only metadata. The gateway runtime never reads spec rows, never loads them into `GatewayConfig`, and never distributes them via gRPC. Submitting or updating a spec does not interrupt or affect in-flight requests.

## Supported OpenAPI versions

| Version string | Notes |
|---|---|
| `swagger: "2.0"` | Swagger / OpenAPI 2.0 |
| `openapi: "3.0.x"` | OpenAPI 3.0.x (any patch) |
| `openapi: "3.1.x"` | OpenAPI 3.1.x |
| `openapi: "3.2.x"` | OpenAPI 3.2.x |

Pre-release suffixes are supported: `openapi: "3.2.0-rc1"` is accepted.

Detection rule: `swagger: "2.0"` at the document root → Swagger 2.0. `openapi: "3.MINOR.PATCH[-suffix]"` → OpenAPI 3.x. Any other string (including `openapi: "4.0.0"`) → 400 `UnknownVersion`.

## Submission formats

Ferrum Edge accepts specs as JSON or YAML. The format is resolved in this order:

1. **`Content-Type` header**: `application/json` → JSON; `application/yaml`, `application/x-yaml`, `text/yaml`, or `text/x-yaml` → YAML.
2. **Autodetection** (when `Content-Type` is absent or unrecognised): first non-whitespace byte is `{` or `[` → JSON; anything else → YAML.

The autodetection heuristic is best-effort; the full parser produces a precise error if the bytes are actually invalid.

## Ferrum extension contract

The following canonical example shows all supported extension fields:

```yaml
openapi: 3.1.0
info:
  title: Orders API
  version: 1.4.0

x-ferrum-proxy:          # REQUIRED — exactly one
  id: orders-proxy
  hosts: [api.example.com]
  listen_path: /orders
  backend_host: orders.internal
  backend_port: 8080
  backend_scheme: https

x-ferrum-upstream:       # OPTIONAL — zero or one
  id: orders-pool
  targets:
    - host: backend1.internal
      port: 8080
    - host: backend2.internal
      port: 8080
  algorithm: round_robin

x-ferrum-plugins:        # OPTIONAL — array (all must be proxy-scoped)
  - id: rl-orders
    plugin_name: rate_limiting
    config:
      window_size: 60
      window_count: 100

paths:
  /orders:
    get: ...
```

### `x-ferrum-proxy` (required)

A single `Proxy` object. Fields follow the same schema as `POST /proxies` — see [admin_api.md](admin_api.md#proxies). The `namespace` field is always overridden by the `X-Ferrum-Namespace` request header; any `namespace` in the extension object is ignored.

At least one of `hosts` or `listen_path` must be set for HTTP-family proxies. The `(namespace, proxy_id)` pair must be unique — attempting to submit a second spec for the same proxy ID returns 409 Conflict.

### `x-ferrum-upstream` (optional)

A single `Upstream` object. Fields follow the same schema as `POST /upstreams` — see [admin_api.md](admin_api.md#upstreams). When present, the upstream is created and the proxy's `upstream_id` is automatically linked to it.

### `x-ferrum-plugins` (optional)

An array of `PluginConfig` objects. Fields follow the same schema as `POST /plugins/config` — see [admin_api.md](admin_api.md#plugin-configs). All plugins must be proxy-scoped:

- `scope` must be `proxy` or omitted (defaults to `proxy`). `global` and `proxy_group` are rejected.
- `proxy_id` must be omitted or match the spec's proxy ID.

## What is NOT allowed in specs

The following are rejected at parse time with a 400 error:

- **`x-ferrum-consumers`** — use `POST /consumers` directly. Credentials cannot be embedded in spec documents.
- **Plugin `scope: global` or `scope: proxy_group`** — only proxy-scoped plugins are allowed. A single shared plugin instance across multiple proxies cannot be expressed via a single-proxy spec bundle.
- **Plugin `proxy_id` mismatch** — if `proxy_id` is set on a plugin, it must match the spec's proxy ID.
- **Forbidden keys in plugin `config`** — the plugin `config` object is walked recursively. Any of the following keys at any nesting depth triggers a 400 `PluginContainsCredentials` error: `credentials`, `keyauth`, `basicauth`, `jwt`, `hmac`, `mtls`, `consumer`, `consumer_id`, `consumer_groups`, `consumers`.

  Note the distinction: a `plugin_name: "jwt"` plugin is fine — the check walks the plugin's `config` *value*, not the plugin metadata fields. A JWT plugin with `config: { secret_lookup: env, validation: { validate_exp: true } }` passes; one with `config: { jwt: { secret: "abc" } }` fails.

## Storage model

| Field | Type | Description |
|---|---|---|
| `id` | UUID string | Auto-generated |
| `proxy_id` | string | Links to `proxies(id)`; `ON DELETE CASCADE` |
| `namespace` | string | From `X-Ferrum-Namespace` header |
| `spec_version` | string | Detected version (`"2.0"`, `"3.1.0"`, etc.) |
| `spec_format` | enum | `json` or `yaml` |
| `spec_content` | bytes | gzip-compressed raw spec |
| `content_encoding` | string | Always `"gzip"` |
| `content_hash` | string | Lowercase SHA-256 hex of the uncompressed bytes |
| `uncompressed_size` | int64 | Byte count before compression |
| `title` | string? | `info.title` from the spec, if present |
| `info_version` | string? | `info.version` from the spec, if present |
| `description` | string? | `info.description`, truncated to 4096 bytes at a UTF-8 boundary |
| `contact_name` | string? | `info.contact.name` from the spec |
| `contact_email` | string? | `info.contact.email` from the spec |
| `license_name` | string? | `info.license.name` from the spec |
| `license_identifier` | string? | `info.license.identifier` (3.1+) or `info.license.url` fallback |
| `tags` | string[] | Top-level `tags[].name` entries, de-duplicated and sorted (3.x and 2.0) |
| `server_urls` | string[] | `servers[].url` for 3.x; `{scheme}://{host}{basePath}` for 2.0 |
| `operation_count` | uint32 | HTTP method keys summed across all `paths.*` entries |
| `resource_hash` | string | SHA-256 hex of the serialised bundle (internal; not returned in list) |
| `created_at` | timestamp | Set on POST; preserved on PUT |
| `updated_at` | timestamp | Set on POST and PUT |

**Uniqueness**: a `UNIQUE(namespace, proxy_id)` constraint ensures at most one spec per proxy per namespace.

**Body size limit**: controlled by `FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB` (default 25). Returns 413 when exceeded.

**MongoDB caveat**: the BSON document limit is 16 MiB. Since spec content is gzip-compressed before storage, a spec up to approximately 14–15 MiB compressed fits within the limit. Operators with larger specs should use a SQL backend (PostgreSQL, MySQL, or SQLite).

## Ownership semantics

All resources created by a spec submission are tagged with `api_spec_id = <spec UUID>`. Resources created via direct admin endpoints have `api_spec_id = null`. These IDs govern replacement and deletion behaviour:

| Operation | What happens |
|---|---|
| `POST /api-specs` | Resources tagged with the new `api_spec_id`. New proxy, optional upstream, and plugins are inserted. |
| `PUT /api-specs/{id}` | Idempotent if the bundle is unchanged (see "PUT semantics" below). When changed, all resources with `api_spec_id = {id}` are deleted and re-inserted from the new document. Resources on the same proxy with `api_spec_id = null` (manually added) are untouched. |
| `DELETE /api-specs/{id}` | Spec-owned proxy is deleted → FK cascade removes all of its plugins (including manually-added ones). Spec-owned upstream is deleted explicitly. Non-spec upstreams survive. The spec row is deleted. |
| `DELETE /proxies/{id}` | The database `ON DELETE CASCADE` on `api_specs.proxy_id → proxies(id)` removes the spec row automatically. The spec-owned upstream is NOT automatically cleaned up in this case. |

## Mode behaviour

| Mode | `POST`/`PUT`/`DELETE` | `GET` |
|---|---|---|
| `database` | Supported | Supported |
| `cp` (Control Plane) | Supported — proxy/upstream/plugins are distributed to DPs via gRPC; the spec row itself stays on the CP and is not distributed | Supported |
| `dp` (Data Plane) | 503 Service Unavailable (no database) | 503 Service Unavailable (no database) |
| `file` | 403 Forbidden (read-only mode) | 503 Service Unavailable (no database) |

## Atomicity and retries

**SQL backends (PostgreSQL, MySQL, SQLite)**: `POST /api-specs` and `PUT /api-specs/{id}` execute within a single database transaction. Either all resources are created/replaced or none are (full rollback on error).

**MongoDB without a replica set**: atomicity is limited to single-document operations. Multi-resource submissions use a best-effort approach with compensating deletes on failure. In the event of an infrastructure fault mid-submission, orphaned resources are possible. Use a MongoDB replica set for production deployments that require atomic multi-document writes.

## Listable metadata

At submit time, the gateway extracts the following fields from the spec document and stores them as indexed columns on the `api_specs` row. They appear in every `GET /api-specs` list item and can be used as search filters.

| Field | Source | Notes |
|---|---|---|
| `description` | `info.description` | Truncated to 4096 bytes at a UTF-8 char boundary |
| `contact_name` | `info.contact.name` | |
| `contact_email` | `info.contact.email` | |
| `license_name` | `info.license.name` | |
| `license_identifier` | `info.license.identifier` (3.1+) or `info.license.url` | |
| `tags` | `tags[].name` | De-duplicated and sorted; supported in both 2.0 and 3.x |
| `server_urls` | `servers[].url` (3.x) or `{scheme}://{host}{basePath}` (2.0) | |
| `operation_count` | Count of HTTP methods across all `paths.*` | `get`, `post`, `put`, `delete`, `options`, `head`, `patch`, `trace` |

These fields are stored at INSERT time and do not require re-parsing the spec for list queries.

## List filters

`GET /api-specs` supports the following query parameters in addition to `limit` and `offset`:

| Parameter | Type | Description |
|---|---|---|
| `proxy_id` | string | Exact match on `proxy_id` |
| `spec_version` | string | Prefix match (e.g. `3.1` matches `3.1.0`, `3.1.1`) |
| `title_contains` | string | Case-insensitive substring on `title` |
| `updated_since` | ISO-8601 | `updated_at >= ?` (e.g. `2026-04-01T00:00:00Z`) |
| `has_tag` | string | Exact tag name membership |
| `sort_by` | enum | `updated_at` (default), `title`, `operation_count`, `created_at` |
| `order` | enum | `desc` (default), `asc` |

Unknown `sort_by` or `order` values return HTTP 400.

```bash
# Filter examples
curl "https://gateway/api-specs?spec_version=3.1&sort_by=title&order=asc" \
  -H "Authorization: Bearer $JWT"

curl "https://gateway/api-specs?has_tag=public&updated_since=2026-04-01T00:00:00Z" \
  -H "Authorization: Bearer $JWT"

curl "https://gateway/api-specs?title_contains=orders&sort_by=operation_count&order=desc" \
  -H "Authorization: Bearer $JWT"
```

## PUT semantics

**Idempotent PUT (resource-hash short-circuit)**: At submit time, the gateway computes a SHA-256 hash over the serialised proxy, upstream, and plugin definitions (the "resource bundle"). On PUT, if the new bundle produces the same hash as the stored one — for example, when only `info.description` or other doc-only fields changed — the proxy, upstream, and plugin rows are left **untouched**:

- Their `updated_at` timestamps do **not** advance.
- The polling cycle sees no delta and skips router-cache and plugin-cache rebuilds.
- DP gRPC broadcast is not triggered.

The `api_specs` row is **always** updated: new `updated_at`, `content_hash`, spec content, and all extracted metadata fields.

This makes PUT safe to run on every CI/CD deploy cycle without causing unnecessary cache rebuilds or downstream configuration churn.

## Worked examples

### 1. Minimal spec — proxy only (JSON)

```json
{
  "swagger": "2.0",
  "info": { "title": "Ping API", "version": "1.0" },
  "x-ferrum-proxy": {
    "id": "ping-proxy",
    "listen_path": "/ping",
    "backend_host": "ping.internal",
    "backend_port": 8080
  }
}
```

```bash
curl -X POST https://gateway/api-specs \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d @ping.json
```

### 2. Proxy with plugins (YAML)

```yaml
openapi: 3.0.3
info:
  title: User API
  version: 2.0.0

x-ferrum-proxy:
  id: user-api
  listen_path: /users
  backend_host: users.internal
  backend_port: 8080
  backend_scheme: https
  hosts: [api.example.com]

x-ferrum-plugins:
  - id: user-api-auth
    plugin_name: key_auth
    config:
      key_names: [x-api-key]

  - id: user-api-rate
    plugin_name: rate_limiting
    config:
      limit_by: consumer
      minute: 1000
```

```bash
curl -X POST https://gateway/api-specs \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/yaml" \
  --data-binary @user-api.yaml
```

### 3. Proxy with upstream and plugins (multi-target)

```yaml
openapi: 3.1.0
info:
  title: Orders API
  version: 1.4.0

x-ferrum-proxy:
  id: orders-proxy
  listen_path: /orders
  backend_host: placeholder.internal  # overridden by upstream
  backend_port: 8080
  backend_scheme: https
  upstream_id: orders-pool

x-ferrum-upstream:
  id: orders-pool
  algorithm: least_connections
  targets:
    - host: orders-1.internal
      port: 8080
      weight: 2
    - host: orders-2.internal
      port: 8080
      weight: 2
    - host: orders-3.internal
      port: 8080
      weight: 1
  health_checks:
    active:
      http_path: /health
      interval_seconds: 10
      unhealthy_threshold: 3

x-ferrum-plugins:
  - id: orders-jwt
    plugin_name: jwt_auth
    config:
      uri_param_names: []
      header_names: [authorization]
```

### 4. Updating a spec via PUT — what survives

Assume the spec from example 3 was submitted. Then a plugin was added manually:

```bash
curl -X POST https://gateway/plugins/config \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"plugin_name":"stdout_logging","scope":"proxy","proxy_id":"orders-proxy","config":{}}'
```

Now replace the spec with a new version that removes `orders-jwt` and adds `rate_limiting`:

```bash
curl -X PUT "https://gateway/api-specs/$SPEC_ID" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/yaml" \
  --data-binary @orders-api-v2.yaml
```

After the PUT:

- `orders-proxy` is replaced (updated fields from new spec).
- `orders-pool` upstream is replaced (new target list, algorithm, etc.).
- `orders-jwt` plugin is removed (was spec-owned).
- New `rate_limiting` plugin from the updated spec is created.
- The manually-added `stdout_logging` plugin **survives** (it has `api_spec_id = null`).

## curl recipes

```bash
# Submit a spec (YAML)
curl -X POST https://gateway/api-specs \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/yaml" \
  --data-binary @myapi.yaml

# Submit a spec (JSON)
curl -X POST https://gateway/api-specs \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d @myapi.json

# List specs (first page)
curl "https://gateway/api-specs?limit=20" \
  -H "Authorization: Bearer $JWT"

# Retrieve spec document as YAML (regardless of stored format)
curl "https://gateway/api-specs/$SPEC_ID" \
  -H "Authorization: Bearer $JWT" \
  -H "Accept: application/yaml"

# Retrieve spec document as JSON
curl "https://gateway/api-specs/$SPEC_ID" \
  -H "Authorization: Bearer $JWT" \
  -H "Accept: application/json"

# Conditional GET (returns 304 if unchanged)
curl "https://gateway/api-specs/$SPEC_ID" \
  -H "Authorization: Bearer $JWT" \
  -H "If-None-Match: \"$CONTENT_HASH\""

# Look up spec by proxy ID
curl "https://gateway/api-specs/by-proxy/orders-proxy" \
  -H "Authorization: Bearer $JWT"

# Replace a spec
curl -X PUT "https://gateway/api-specs/$SPEC_ID" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/yaml" \
  --data-binary @myapi-v2.yaml

# Delete a spec (and cascade its proxy + plugins + upstream)
curl -X DELETE "https://gateway/api-specs/$SPEC_ID" \
  -H "Authorization: Bearer $JWT"
```
