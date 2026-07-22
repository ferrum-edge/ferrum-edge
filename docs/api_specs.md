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

### YAML type-coercion caution

YAML's implicit type coercion can produce surprising results when the gateway serialises the document to JSON for internal processing:

| YAML literal | JSON value | Why it matters |
|---|---|---|
| `010` | `8` | Octal integer — YAML 1.1 treats leading-zero integers as octal |
| `1:30` | `90` | Sexagesimal integer — YAML 1.1 treats `N:M` as `N*60 + M` |
| `yes`, `no`, `on`, `off`, `true`, `false` | boolean | YAML 1.1 boolean aliases; `yes` becomes JSON `true` |

**Recommendation**: quote strings that look like numbers or boolean words in YAML specs to preserve them as strings:

```yaml
info:
  version: "010"   # → JSON string "010", not integer 8
x-ferrum-proxy:
  backend_port: 443  # numeric — no quotes needed
```

Port numbers and version strings are the most common sources of accidental coercion. When in doubt, use `"..."` quoting.

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
      limits:
        - scope: default
          window_seconds: 60
          max_requests: 100

x-ferrum-validate: true  # OPTIONAL — auto-generate openapi_validator

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

### `x-ferrum-validate` (optional)

Set `x-ferrum-validate: true` to generate a proxy-scoped `openapi_validator` plugin from the spec's operation schemas. The generated plugin config embeds the resolved request and response schemas plus their media types; the gateway runtime never reads the `api_specs` row on the request path.

```yaml
x-ferrum-validate:
  mode: block
  request:
    enabled: true
    content_types:
      - application/json
      - application/xml
      - text/xml
      - application/x-www-form-urlencoded
      - multipart/form-data
      - text/plain
      - application/octet-stream
  response:
    enabled: true
    content_types:
      - application/json
      - application/xml
      - text/xml
      - application/x-www-form-urlencoded
      - multipart/form-data
      - text/plain
      - application/octet-stream
  fail_on_unknown_operation: true
  fail_on_missing_response_schema: false
  max_body_bytes: 1048576
  bypass:
    paths: ["^/orders/health$"]
    methods: [OPTIONS]
    consumers: [emergency-bypass]
    header_present:
      x-bypass-validator: null
```

`x-ferrum-validate` accepts:

- `true` — generate an `openapi_validator` plugin with defaults.
- `false` or `null` — do not generate the plugin.
- object — generate the plugin and apply the listed settings.

The importer walks `paths.{path}`, resolves local Path Item `$ref`s first, then enumerates HTTP methods and resolves local schema `$ref`s inside request/response content:

- **Path Item Objects** — local `$ref` targets such as `#/components/pathItems/Pets` (OpenAPI 3.1+) or `#/paths/~1shared` (Swagger 2.0 / OpenAPI 3.x) are expanded before method keys are read, so referenced operations enter the generated `openapi_validator` table.
- **Server / `basePath` bases** — generated `openapi_validator` operation matchers honor the effective request pathname from Swagger 2.0 `basePath` and OpenAPI 3.x Server Objects. OpenAPI precedence is operation `servers` → Path Item `servers` → root `servers`; absence at a narrower scope inherits the next outer scope. Each server URL contributes only its pathname (scheme, authority, query, and fragment are dropped). Absolute-path references (`/v1`), relative references (`v1`), and absolute URIs (`https://api.example.com/v1`) are supported; because uploaded specs have no document URL, relative references resolve from a synthetic document root. Server variables are substituted with declared `default` values only (enum members are not explored); missing defaults, defaults outside `enum`, malformed variables, empty `servers` arrays, and raw or percent-encoded `.` / `..` path segments fail closed. Empty path segments remain literal and safe because generated operation regexes are fully anchored. Multiple servers emit one operation matcher per distinct effective pathname in document order, deduplicating equivalents. Root-only / absent servers keep raw Paths-key matching. Bases join Paths keys with exactly one slash boundary (`/v1` + `/pets` → `/v1/pets`; `/v1` + `/` → `/v1`).
- OpenAPI 3.x request schemas from `requestBody.content.{mediaType}.schema`.
- OpenAPI 3.x response schemas from `responses.{status}.content.{mediaType}.schema`.
- Swagger 2.0 request schemas from `parameters[].in == "body"`.
- Swagger 2.0 response schemas from `responses.{status}.schema`, using `consumes`/`produces` media types.

Supported local `$ref` forms (same document only; never fetched):

- **Path Item `$ref`**: JSON Pointer fragments to Path Item Objects in the same document. OpenAPI leaves conflicts between `$ref` and adjacent Path Item fields undefined; Ferrum applies a deterministic sibling overlay — sibling fields override fields from the referenced Path Item after resolution.
- JSON Pointer fragments for schemas: `#/components/schemas/Order`, and percent-encoded pointer forms such as `#/components/schemas/Order%20Id`. Empty and `/`-prefixed fragments are pointers. An empty fragment (`#` or `https://example.com/schemas/order.json#`) resolves to the **schema resource root** — a Schema Object whose `$id` matches the reference URI. The OpenAPI document root is not a JSON Schema root, so bare `#` against the document (no matching Schema Object `$id` as the current resource) fails closed.
- Draft 2020-12 plain-name anchors (OpenAPI 3.1+): `#Order` resolves to the schema object that declares `"$anchor": "Order"` in the current schema resource. Nested anchors inside applicator / `$defs` subschemas and schemas under `components.pathItems` are included. `$anchor` / `$id` / `id` / `$ref` fields in non-schema OpenAPI data (for example `x-ferrum-plugins` config) or in schema annotation payloads (`default` / `examples` / `const` / `enum`) are not interpreted during schema indexing or expansion. Duplicate anchors in one resource and missing anchors fail closed.
- Draft 7 plain-name anchors (Swagger 2.0 / OpenAPI 3.0.x): `#Order` resolves via a fragment-only `"$id": "#Order"` (or Draft-4 `"id"`) in the current resource. Draft 7 names begin with a letter and may contain letters, digits, `-`, `_`, `.`, or `:`. The OpenAPI 3.1+ `$anchor` keyword is not consulted for 2.0 / 3.0.x documents.
- Local `$id` resource scope: an absolute or relative `$ref` whose URI (without fragment) matches an `$id` declared on a Schema Object in the same document resolves locally, including fragments such as `https://example.com/schemas/order.json#OrderBody`. Duplicate same-document resource `$id` URIs fail closed. URIs that are not declared in-document remain HTTP 422 `UnsupportedExternalRef`.

URI fragments are percent-decoded deterministically before classification; percent-escape hex case is canonicalized for resource identity, and malformed percent-escapes are rejected. Malformed, duplicated, or unresolved local references (including Path Item refs) return HTTP 422 `SchemaReference`; external `$ref`s (including external Path Item refs) return HTTP 422 `UnsupportedExternalRef`, and deeply recursive or cyclic refs return HTTP 422 `SchemaTooDeep`. Swagger 2.0 and OpenAPI 3.0 schemas are normalized for Draft 7 compatibility; OpenAPI 3.1+ schemas use Draft 2020-12.

For Swagger 2.0 and OpenAPI 3.0.x, request and response schemas are normalized with an explicit direction so OpenAPI `readOnly` / `writeOnly` required semantics are preserved: required `readOnly` properties are enforced only on responses, and required `writeOnly` properties (OpenAPI 3.0 only) are enforced only on requests. The rewrite applies through nested objects, arrays, local `$ref` expansion, and `allOf` / `oneOf` / `anyOf` members. OpenAPI 3.1+ leaves `required` unchanged because those keywords are JSON Schema annotations there; see [openapi_validator.md](openapi_validator.md).

Runtime validation supports JSON and `+json`, XML and `+xml` with OpenAPI `xml` metadata, `application/x-www-form-urlencoded`, `multipart/form-data` fields and file metadata, `text/*`, and binary payloads such as `application/octet-stream`, other non-JSON/XML `application/*`, `image/*`, `audio/*`, and `video/*`. OpenAPI response wildcard status keys such as `4XX` and `5XX` are preserved in the generated config and matched after exact status codes.

If `x-ferrum-plugins` already includes an `openapi_validator`, the importer merges it with the generated config: operator scalar fields win, `bypass.paths` / `bypass.methods` / `bypass.consumers` are unioned, `bypass.header_present` maps are merged with operator entries overriding spec entries on header-name conflicts, and `operations` is always regenerated from the spec. Malformed spec-side bypass shapes are rejected during extraction instead of being silently dropped.

For full runtime settings and metadata keys, see [openapi_validator.md](openapi_validator.md).

## What is NOT allowed in specs

The following are rejected at parse time with a 400 error:

- **`x-ferrum-consumers`** — use `POST /consumers` directly. Credentials cannot be embedded in spec documents.
- **Plugin `scope: global` or `scope: proxy_group`** — only proxy-scoped plugins are allowed. A single shared plugin instance across multiple proxies cannot be expressed via a single-proxy spec bundle.
- **Plugin `proxy_id` mismatch** — if `proxy_id` is set on a plugin, it must match the spec's proxy ID.
- **Forbidden keys in plugin `config`** — the plugin `config` object is walked recursively. Any of the following keys at any nesting depth triggers a 400 `PluginContainsCredentials` error: `credentials`, `keyauth`, `basicauth`, `jwt`, `hmac`, `mtls`, `consumer`, `consumer_id`, `consumer_groups`, `consumers`.
- **External `$ref`s in `x-ferrum-validate`** — only local document refs are resolved into generated plugin config. This covers Path Item `$ref`s as well as schema `$ref`s.

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

**YAML alias expansion**: Ferrum rejects parsed YAML documents that exceed the expanded node budget, but `serde_yaml` performs alias expansion while parsing. Keep YAML submissions to trusted operator workflows; use JSON for very large generated specs or when you need the tightest memory bound.

**MongoDB caveat**: the BSON document limit is 16 MiB. Since spec content is gzip-compressed before storage, a spec up to approximately 14–15 MiB compressed fits within the limit. Operators with larger specs should use a SQL backend (PostgreSQL, MySQL, or SQLite).

## Ownership semantics

All resources created by a spec submission are tagged with `api_spec_id = <spec UUID>`. The field is server-managed: clients must omit it from `x-ferrum-proxy`, `x-ferrum-upstream`, and `x-ferrum-plugins`, including when copying an exported resource into a POST or PUT document. A client-supplied ownership tag returns a 422 validation response consistently across database backends. Resources created via direct admin endpoints have `api_spec_id = null`. These IDs govern replacement and deletion behaviour:

| Operation | What happens |
|---|---|
| `POST /api-specs` | Resources tagged with the new `api_spec_id`. New proxy, optional upstream, and plugins are inserted. |
| `PUT /api-specs/{id}` | Idempotent if the bundle is unchanged (see "PUT semantics" below). When changed, all resources with `api_spec_id = {id}` are deleted and re-inserted from the new document. Resources on the same proxy with `api_spec_id = null` (manually added) are untouched. |
| `DELETE /api-specs/{id}` | Spec-owned proxy is deleted → FK cascade removes all of its plugins (including manually-added ones). Spec-owned upstream is deleted explicitly. Non-spec upstreams survive. The spec row is deleted. If the cascade would leave an invalid aggregate plugin graph, or the pre-delete snapshot contains foreign ownership or a plugin shape that atomic compensation cannot restore, the operation returns 422 without deleting anything. If namespace admission is lost after the delete commits, compensation revalidates the recovered proxy's current upstream existence, subset, and mesh-retry constraints and restores the complete prior graph atomically or leaves it deleted. |
| `DELETE /proxies/{id}` | The database `ON DELETE CASCADE` on `api_specs.proxy_id → proxies(id)` removes the spec row automatically. The spec-owned upstream is NOT automatically cleaned up in this case. |

## Mode behaviour

| Mode | `POST`/`PUT`/`DELETE` | `GET` |
|---|---|---|
| `database` | Supported | Supported |
| `cp` (Control Plane) | Supported — proxy/upstream/plugins are distributed to DPs via gRPC; the spec row itself stays on the CP and is not distributed | Supported |
| `dp` (Data Plane) | 503 Service Unavailable (no database) | 503 Service Unavailable (no database) |
| `file` | 403 Forbidden (read-only mode) | 503 Service Unavailable (no database) |

## Atomicity and retries

**SQL backends (PostgreSQL, MySQL, SQLite)**: `POST /api-specs` and `PUT /api-specs/{id}` execute within a single database transaction. Either all resources are created/replaced or none are (full rollback on error). Normal submissions retain the shared namespace admission contract used by ordinary resource writes, so unrelated invalid-but-present plugin associations do not block an otherwise valid spec submission needed for in-band repair. Late `DELETE` compensation uses the same transaction boundary for every upstream removed by the originating cascade (spec-owned upstreams and, for direct proxy deletion, an orphaned hand-owned upstream), the proxy, spec-owned plugins, hand-owned plugins removed by the proxy cascade, proxy/plugin junction rows, API-spec row, and every runtime config-change record. A hand-owned upstream retained because another proxy or mesh dispatch still references it is reused in place rather than inserted again, but only when its stable creation identity and ownership match the pre-delete snapshot. A same-ID replacement rejects and rolls back recovery. It additionally validates the recovered proxy/plugin graph before commit. This recovered-graph check includes raw associations, upstream/subset references, plugin composition, and named transaction-log schema dependencies for the restored proxy, its proxy-targeted rows, and effective global rows, while excluding unrelated proxy graphs so pre-existing repairable state elsewhere in the namespace cannot strand a valid recovery. Namespace-wide guarded TCP-throttle and mTLS identity checks still apply.

**MongoDB with a replica set**: late `DELETE` compensation uses one multi-document transaction with the same all-or-nothing graph and config-change boundary as SQL.

The same dedicated restore boundary is used when `DELETE /proxies/{id}` directly removes a proxy owned by an API spec and late compensation is required. Before that delete, Ferrum uses the namespace snapshot only to discover affected IDs, then re-reads the current upstream and every cascade plugin through ownership-preserving admin queries. Legitimate hand-owned rows retain `api_spec_id = null`; the authoritative API-spec snapshot supplies stamped bundle rows; foreign API-spec ownership, missing rows, or an ownership/scope shape the restore contract cannot reproduce returns 400 without deleting the proxy. The stamped spec-owned resources, any orphaned hand-owned upstream, and hand-owned plugins removed by the proxy cascade are restored through the compensation contract, not replayed as a normal client submission or separate writes. `DELETE /api-specs/{id}` also snapshots a current hand-owned upstream when the imported spec has no owned upstream or its proxy has drifted to one. A shared hand-owned upstream that survived either delete remains authoritative and is reused by the restored proxy after its stable identity is verified.

Because compensation follows a lost namespace-admission lease, another writer may have changed the namespace before recovery reacquires admission. SQL and replica-set MongoDB therefore reapply proxy route-uniqueness and upstream-reference admission inside the restore transaction. The recovered plugin-composition and named-schema checks reuse the configured admin validation HTTP client, including backend egress policy and the effective real-IP header, rather than a default client. An intervening overlapping route, a deleted hand-owned upstream, or a recovered plugin endpoint denied by current egress policy rejects and rolls back the complete restore instead of committing an invalid graph.

**MongoDB without a replica set**: atomicity is limited to single-document operations. Normal multi-resource submissions retain their best-effort approach with compensating deletes on failure. In the event of an infrastructure fault mid-submission, orphaned resources are possible. Late `DELETE` compensation is stricter: it fails closed before writing anything because a partially restored proxy could publish without its security plugins. The already-committed delete therefore remains in place until an operator retries on a replica-set deployment or re-submits the spec. Use a MongoDB replica set for production deployments that require atomic multi-document writes or automatic late-delete recovery.

Before deletion, Ferrum re-reads every plugin that the proxy cascade would remove through an ownership-preserving admin query and validates every other explicit association on the deleted proxy. Proxy-scoped configs remain valid without a reverse entry in `proxy.plugins`; compensation restores those configs in the same transaction while preserving their unattached state. The restore snapshot is validated before persistence: a cascade plugin tagged to another API spec, an explicitly associated global plugin, a proxy-scoped association targeting another proxy, a global plugin carrying the deleted proxy ID, a proxy-group plugin carrying a proxy ID, or an embedded `proxy.plugins` association naming a missing config returns a structured 422 `ApiSpecValidationError` for API-spec DELETE, or the equivalent 400 precondition response for direct proxy DELETE, without deleting anything. Recovery-time plugin construction uses the same configured backend egress policy and real-IP header as ordinary admin validation, so compensation cannot admit a plugin that normal CRUD rejects. This keeps categorically unrestorable or malformed persistent graphs available for operator repair instead of misreporting them as transient races or discovering them only during compensation.

### Detecting and cleaning up orphans (MongoDB non-RS)

If a non-RS deployment experiences a partial failure, the following queries identify orphaned documents. Run them in `mongosh` against the gateway database.

**Specs pointing to non-existent proxies** (the spec row survived but the proxy was never created or was already deleted):

```js
db.api_specs.aggregate([
  { $lookup: { from: "proxies", localField: "proxy_id", foreignField: "_id", as: "p" } },
  { $match: { p: { $size: 0 } } },
  { $project: { _id: 1, namespace: 1, proxy_id: 1 } }
])
// To delete: db.api_specs.deleteMany({ _id: { $in: [<ids from above>] } })
```

**Resources tagged with a non-existent spec** (the resource was created but the spec row was lost):

```js
// Proxies
db.proxies.aggregate([
  { $match: { api_spec_id: { $ne: null } } },
  { $lookup: { from: "api_specs", localField: "api_spec_id", foreignField: "_id", as: "s" } },
  { $match: { s: { $size: 0 } } },
  { $project: { _id: 1, namespace: 1, api_spec_id: 1 } }
])

// Same pattern for plugin_configs and upstreams — replace the collection name.
```

Orphaned resources with dangling `api_spec_id` tags are inert — they function as normal config entries and do not affect the gateway runtime. Cleanup is optional but recommended to keep the admin API consistent. To clear the tag without deleting the resource:

```js
db.proxies.updateMany(
  { api_spec_id: "<orphaned-spec-id>" },
  { $unset: { api_spec_id: "" } }
)
```

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

`GET /api-specs` uses a stricter pagination scheme than the other admin list
endpoints: `limit` defaults to 50 with a maximum of 200 (`0` means the default,
higher unsigned 64-bit values are capped), and `offset` is an unsigned 32-bit
value defaulting to 0. As everywhere else, malformed or negative
`limit`/`offset` values, limits beyond the unsigned 64-bit range, and offsets
above `2^32 - 1` are rejected with HTTP 400 rather than coerced to a default.
Percent-encoded query parameter names are decoded before matching, so encoding
`limit` or `offset` cannot bypass these bounds. Names are decoded before values:
a name that is not one of the recognized filters below — including one whose
percent-encoding is not valid UTF-8 — is ignored without decoding its value, so
unrelated third-party query parameters never break the request. Malformed
percent-encoding in the value of a *recognized* filter is still rejected with
HTTP 400.

It supports the following query parameters in addition to `limit` and `offset`:

| Parameter | Type | Description |
|---|---|---|
| `proxy_id` | string | Exact match on `proxy_id` |
| `spec_version` | string | Prefix match (e.g. `3.1` matches `3.1.0`, `3.1.1`) |
| `title_contains` | string | Case-insensitive substring on `title` |
| `updated_since` | ISO-8601 | `updated_at >= ?` (e.g. `2026-04-01T00:00:00Z`) |
| `has_tag` | string | Exact tag name membership |
| `sort_by` | enum | `updated_at` (default), `title`, `operation_count`, `created_at` |
| `order` | enum | `desc` (default), `asc` |

Unknown `sort_by` or `order` values, SQL `LIKE` wildcards in `spec_version` or
`title_contains`, and malformed `limit`/`offset` values all return HTTP 400.

### List response shape

```json
{
  "items": [ ... ],
  "limit": 50,
  "offset": 0,
  "next_offset": 50,
  "total": 327
}
```

- `items` — page of spec summaries (no `spec_content` or `resource_hash`).
- `limit` / `offset` — the pagination parameters that were applied.
- `next_offset` — set to `offset + items.len()` when that value is strictly greater than `offset`, remains below `total`, and fits in the 32-bit offset range; `null` on the last page or when the next cursor cannot be represented.
- `total` — count of all rows matching the filter (ignoring `limit`/`offset`). Use this to build "showing 1–50 of 327" pagination UI.

### Tag-name rules

Tag names are extracted from the OpenAPI `tags[].name` array and stored as a JSON text column. The `has_tag` filter uses a SQL `LIKE` pattern that embeds the tag name directly — no SQL `ESCAPE` clause is applied.

To keep the filter correct, tag names must not contain any of the following characters:

| Character | Why forbidden |
|---|---|
| `"` | Would close the JSON string literal early, producing false positives |
| `%` | SQL `LIKE` multi-character wildcard — would match unrelated tags |
| `_` | SQL `LIKE` single-character wildcard — `?has_tag=api_v1` would falsely match `apixv1` |
| `\` | Would act as a SQL escape character and corrupt the pattern |

Tags with forbidden characters are rejected at submit time with HTTP 422 `InvalidTagName`. MongoDB uses native array membership and is not affected by the `LIKE` limitation, but the same character restrictions apply for consistency.

**If you extend this whitelist in `src/admin/api_specs/extractor.rs`, you must also update the `has_tag` query in `src/config/db_loader.rs` to add an `ESCAPE` clause and pre-escape the tag value.**

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

When `x-ferrum-validate` is enabled, the generated `openapi_validator.config.operations` array is part of the resource hash. Schema-affecting spec changes replace the spec-owned plugin row and rebuild the affected plugin cache entry. Documentation-only changes that leave generated operations unchanged do not advance the plugin row's `updated_at`.

### OpenAPI validator override semantics

Persistent validator changes belong in `x-ferrum-validate` and should be applied with `PUT /api-specs/{id}`.

Emergency direct edits to the generated `openapi_validator` row via `PUT /plugins/config/{id}` are allowed for incident response, but they are ephemeral. The next spec `PUT` regenerates the spec-owned plugin and replaces direct edits.

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
      key_location: header:X-API-Key

  - id: user-api-rate
    plugin_name: rate_limiting
    config:
      limit_by: consumer
      limits:
        - scope: default
          requests_per_minute: 1000
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
      token_lookup: header:Authorization
      expected_issuer: https://identity.example.com
      audiences: [orders-api]
```

### 4. Proxy with generated OpenAPI validation

```yaml
openapi: 3.1.0
info:
  title: Orders API
  version: 1.0.0

x-ferrum-validate:
  mode: block
  bypass:
    paths: ["^/orders/health$"]

x-ferrum-proxy:
  id: orders-contract
  listen_path: /orders
  backend_host: orders.internal
  backend_port: 8080

paths:
  /orders:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [id]
              properties:
                id:
                  type: string
      responses:
        "201":
          description: created
          content:
            application/json:
              schema:
                type: object
                required: [created]
                properties:
                  created:
                    type: boolean
```

Submitting this spec creates one generated `openapi_validator` plugin attached to `orders-contract`. A request body missing `id` is rejected with HTTP 400 in `block` mode.

### 5. Updating a spec via PUT — what survives

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
