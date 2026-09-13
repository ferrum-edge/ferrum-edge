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

Ferrum follows the YAML scalar resolution used by `serde_yaml`: YAML 1.2-style
booleans and explicit base prefixes, while legacy YAML 1.1 spellings remain
strings:

| YAML literal | JSON value | Why it matters |
|---|---|---|
| `0o10` | `8` | Octal integers require the explicit `0o` prefix |
| `010`, `1:30` | string | Legacy octal and sexagesimal YAML 1.1 forms are not coerced |
| `yes`, `no`, `on`, `off` | string | Legacy YAML 1.1 boolean aliases are not coerced |
| `true`, `false` | boolean | YAML 1.2 boolean spellings are coerced |
| `200:` as a mapping key | `"200"` key | Number and boolean mapping keys take their JSON object-key spelling, so unquoted status codes are accepted |
| `18446744073709551616`, `1e400`, `.inf`, `.nan` | rejected (400) | Values outside the exact JSON `i64`/`u64` range, and non-finite numbers, are not silently rounded or restyled |

**Recommendation**: quote strings that look like numbers or boolean words in YAML specs to preserve them as strings:

```yaml
info:
  version: "010"   # Quoting remains the clearest way to state string intent
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
  /:
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

Operation matching uses the full canonical inbound path (`ctx.path`, without the query string), before backend listen-path stripping. Generated `path_template` / `path_regex` include the literal `x-ferrum-proxy.listen_path` prefix followed by the effective server/`basePath` pathname and Paths key. For example, listen path `/p2/oas2` plus Paths key `/items` matches `/p2/oas2/items`; a server pathname `/v1` makes that `/p2/oas2/v1/items`. Do not repeat the listen prefix in Paths keys or server/basePath unless the intended inbound path contains it twice.

Trailing slashes on the listen prefix are trimmed when joining non-root paths; `/p2/oas2/` plus `/items/{id}` generates `^/p2/oas2/items/[^/]+$`. With no server base, the Paths-key root `/` preserves the literal listen path so it matches the router's route key: `/p2/oas2` yields `^/p2/oas2$`, while `/p2/oas2/` yields `^/p2/oas2/$`. Any other Paths-key trailing slash is preserved (`/items/` is mounted as `/p2/oas2/items/`). Root (`/`), host-only, exact (`=...`), and regex (`~...`) listen routes add no prefix. For exact and regex routes, the spec must describe the full inbound paths. `strip_listen_path` affects forwarding only: generated matchers are the same whether it is `true` or `false`. Hand-authored plugin operations and `bypass.paths` retain full-path matching as written; bypass patterns are not prefixed. Unmatched requests still return HTTP 400 with the default blocking configuration.

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

The object form is a **closed** fixed-field object. Accepted keys are exactly `mode`, `request`, `response`, `validate_request`, `validate_response`, `bypass`, `fail_on_unknown_operation`, `fail_on_missing_response_schema`, `max_body_bytes`, `error_response`, and `error_truncate_chars`; `request` and `response` accept only `enabled` and `content_types`, and `bypass` accepts only `paths`, `methods`, `consumers`, and `header_present`. Any other key — including `operations`, which is always regenerated from the document — is rejected with HTTP 400 and a spelling suggestion. Unknown keys used to be copied verbatim into the generated plugin config, so a misspelled enforcement control deployed successfully with the weaker default still in force. The generated plugin config itself is closed the same way at construction; see [openapi_validator.md](openapi_validator.md#strict-config-admission).

The importer walks `paths.{path}`, resolves local Path Item `$ref`s first, then enumerates HTTP methods and resolves local schema `$ref`s inside request/response content:

- **Path Item Objects** — local `$ref` targets such as `#/components/pathItems/Pets` (OpenAPI 3.1+) or `#/paths/~1shared` (Swagger 2.0 / OpenAPI 3.x) are expanded before method keys are read, so referenced operations enter the generated `openapi_validator` table.
- **Server / `basePath` bases** — generated `openapi_validator` operation matchers honor the effective request pathname from Swagger 2.0 `basePath` and OpenAPI 3.x Server Objects. OpenAPI precedence is operation `servers` → Path Item `servers` → root `servers`; absence at a narrower scope inherits the next outer scope. Each server URL contributes only its pathname (scheme, authority, query, and fragment are dropped). Absolute-path references (`/v1`), relative references (`v1`), and absolute URIs (`https://api.example.com/v1`) are supported; because uploaded specs have no document URL, relative references resolve from a synthetic document root. Server variables are substituted with declared `default` values only (enum members are not explored); missing defaults, defaults outside `enum`, malformed variables, empty `servers` arrays, and raw or percent-encoded `.` / `..` path segments fail closed. Empty path segments remain literal and safe because generated operation regexes are fully anchored. Multiple servers emit one operation matcher per distinct effective pathname in document order, deduplicating equivalents. Root-only / absent servers add no server prefix; the listen prefix still applies. Bases join Paths keys with exactly one slash boundary (`/v1` + `/pets` → `/v1/pets`; `/v1` + `/` → `/v1`), before the listen prefix is prepended.
- OpenAPI 3.x request schemas from `requestBody.content.{mediaType}.schema`, preserving `encoding` for `application/x-www-form-urlencoded` and `multipart/form-data` in the strict generated `{schema, encoding}` shape (unsupported media types, unknown properties, invalid field types/styles, reserved headers, case-insensitive duplicate multipart encoding header names, Header Object `schema`/`content` exclusivity with closed per-form field sets, exactly one concrete content media type with full-key header-value validation, and other unsupported combinations fail closed).
- OpenAPI 3.x response schemas from `responses.{status}.content.{mediaType}.schema`.
- Swagger 2.0 request schemas from `parameters[].in == "body"`.
- Swagger 2.0 response schemas from `responses.{status}.schema`, using `consumes`/`produces` media types.

Supported `$ref` forms:

- **Path Item `$ref`**: JSON Pointer fragments to Path Item Objects in the same document, and — when external resolution is opted in — to Path Item Objects in other documents. OpenAPI leaves conflicts between `$ref` and adjacent Path Item fields undefined; Ferrum applies a deterministic sibling overlay — sibling fields override fields from the referenced Path Item after resolution. The same overlay applies to the other OpenAPI **Reference Object** positions (`requestBody`, response, parameter, header). It does **not** apply to Schema Objects.
- **Schema Object `$ref` siblings**: an adjacent keyword never replaces a referenced keyword. OpenAPI 3.1+ composes the pair as `allOf` per JSON Schema 2020-12; Swagger 2.0 / OpenAPI 3.0 reject an adjacent assertion keyword (including `nullable`) with HTTP 422 because JSON Reference gives it no meaning; `unevaluatedProperties`, `unevaluatedItems`, `$dynamicRef`, and legacy `$recursiveRef` adjacent to `$ref` are always rejected. See [openapi_validator.md](openapi_validator.md#schema-object-ref-siblings). Cross-document Schema Object `$ref` keeps these sibling/override rules.
- JSON Pointer fragments for schemas: `#/components/schemas/Order`, and percent-encoded pointer forms such as `#/components/schemas/Order%20Id`. Empty and `/`-prefixed fragments are pointers. An empty fragment (`#` or `https://example.com/schemas/order.json#`) resolves to the **schema resource root** — a Schema Object whose `$id` matches the reference URI. The OpenAPI document root is not a JSON Schema root, so bare `#` against the document (no matching Schema Object `$id` as the current resource) fails closed. Schema-only external documents treat the document root as the schema resource.
- Draft 2020-12 plain-name anchors (OpenAPI 3.1+): `#Order` resolves to the schema object that declares `"$anchor": "Order"` in the current schema resource. Nested anchors inside applicator / `$defs` subschemas and schemas under `components.pathItems` are included. `$anchor` / `$id` / `id` / `$ref` fields in non-schema OpenAPI data (for example `x-ferrum-plugins` config) or in schema annotation payloads (`default` / `examples` / `const` / `enum`) are not interpreted during schema indexing or expansion. Duplicate anchors in one resource and missing anchors fail closed.
- Draft 7 plain-name anchors (Swagger 2.0 / OpenAPI 3.0.x): `#Order` resolves via a fragment-only `"$id": "#Order"` (or Draft-4 `"id"`) in the current resource. Draft 7 names begin with a letter and may contain letters, digits, `-`, `_`, `.`, or `:`. The OpenAPI 3.1+ `$anchor` keyword is not consulted for 2.0 / 3.0.x documents.
- Local `$id` resource scope: an absolute or relative `$ref` whose URI (without fragment) matches an `$id` declared on a Schema Object in the same document resolves locally, including fragments such as `https://example.com/schemas/order.json#OrderBody`. Duplicate same-document resource `$id` URIs fail closed. `$id` also rebases the JSON Pointer fragments evaluated inside that resource, including a `$ref` in the *same* Schema Object: `{"$id": "https://example.com/wrapper.json", "$ref": "#/components/schemas/Order"}` addresses `/components/schemas/Order` within the wrapper, not within the OpenAPI document, and fails closed with an error naming the resource that was searched. Reference the target by its own `$id` (or move the `$id`) instead.
- **External / cross-document `$ref` (opt-in)**: relative and absolute references that leave the in-document resource set are resolved only when **both** `FERRUM_ADMIN_SPEC_EXTERNAL_REFS_ENABLED=true` and the per-spec `x-ferrum-external-refs` extension enable resolution. Each reference is resolved against the containing document's canonical base URI (not always the root). Absent either gate, external refs return HTTP 422 `UnsupportedExternalRef` (historical fail-closed default). See [External `$ref` policy](#external-ref-policy) below.

URI fragments are percent-decoded deterministically before classification; percent-escape hex case is canonicalized for resource identity, and malformed percent-escapes are rejected. Malformed, duplicated, or unresolved local references (including Path Item refs) return HTTP 422 `SchemaReference`; external `$ref`s that are not admitted by policy return HTTP 422 `UnsupportedExternalRef`; reference chains deeper than the documented ceiling return HTTP 422 `SchemaTooDeep`; a `$ref` chain that re-enters a target still being expanded returns HTTP 422 `SchemaReferenceCycle`; and a reference expansion that exceeds the per-expansion budget (500,000 materialized values / the generated-config byte ceiling) or the cumulative per-document budget (2,000,000 materialized values / twice the generated-config byte ceiling, across every expansion in the document) returns HTTP 422 `SchemaTooLarge`. Generated request/response media entries, multipart encoding headers, response statuses, and complete operations are charged against the byte budget before they can accumulate into an oversized table; JSON escaping is included in that accounting.

Reference expansion is bounded before allocation, not after (advisory GHSA-8jc7-c52g-85xr):

- **Cycles fail on re-entry.** Self-cycles, mutual cycles, and longer `$ref` loops are rejected the moment the chain re-enters a target that is still being expanded, rather than after the depth ceiling has expanded every sibling branch first. The error message carries the chain of `$ref` literals that closed the cycle. Those literals come from the submitted document and name document structure only.
- **Budgets are cumulative and charged before each clone.** One materialization account covers the whole document, so spreading expansion across many paths, operations, media types, or response statuses cannot reset it. Whole-subtree clones (opaque positions, Reference Objects, non-schema arrays) are charged their full weight, not just their container's.
- **Repeated acyclic references are expanded once.** Identical `(target, position kind, remaining depth)` expansions are memoized, so a high-branching acyclic DAG costs one expansion per distinct combination instead of re-expanding exponentially. Reuse is charged the same budget the original expansion was charged, so accounting is unchanged; legitimate repeated references keep working.
- **Both source formats are bounded identically.** JSON and YAML documents are both capped at 500,000 parsed source nodes (HTTP 400 `InvalidJson` / `InvalidYaml`) in addition to `FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB`, and post-parse expansion accounting is format-independent.
- **Concurrent imports are admitted in bounded numbers.** At most four API-spec extractions run at once process-wide; further submissions queue in FIFO order, so process peak resolution memory is a small constant multiple of one import's ceiling and no namespace can starve another. Waiter count is bounded upstream by the admin connection limiter and the advertised admin HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS`. Swagger 2.0 and OpenAPI 3.0 schemas are normalized for Draft 7 compatibility; OpenAPI 3.1+ schemas use Draft 2020-12.

For Swagger 2.0 and OpenAPI 3.0.x, request and response schemas are normalized with an explicit direction so OpenAPI `readOnly` / `writeOnly` required semantics are preserved: required `readOnly` properties are enforced only on responses, and required `writeOnly` properties (OpenAPI 3.0 only) are enforced only on requests. The rewrite applies through nested objects, arrays, local `$ref` expansion, and `allOf` / `oneOf` / `anyOf` members. OpenAPI 3.1+ leaves `required` unchanged because those keywords are JSON Schema annotations there; see [openapi_validator.md](openapi_validator.md).

Runtime validation supports JSON and `+json`, XML and `+xml` with OpenAPI `xml` metadata, `application/x-www-form-urlencoded` (including Encoding Object `style`/`explode`/`allowReserved`), `multipart/form-data` fields and file metadata (MIME boundary lines, quoted disposition parameters, bounded RFC 5987/8187 `filename*` decoding, and Encoding Object `contentType`/`headers`, including Header Object `content` with exactly one concrete RFC 9110 media type decoded under header-size limits), `text/*`, and binary payloads such as `application/octet-stream`, other non-JSON/XML `application/*`, `image/*`, `audio/*`, and `video/*`. Header-content media-type parameters require token names and token or quoted-string values; malformed suffixes fail closed instead of being discarded before decoding. OpenAPI response wildcard status keys such as `4XX` and `5XX` are preserved in the generated config and matched after exact status codes; a declared status always precludes range/`default` fallback, and declared statuses are emitted even when they carry no schema-bearing content so that rule holds. Form/multipart conversion honors composed schemas (`oneOf`/`anyOf`/`allOf`) without first-branch preselection.

If `x-ferrum-plugins` already includes an `openapi_validator`, the importer merges it with the generated config: operator scalar fields win, `bypass.paths` / `bypass.methods` / `bypass.consumers` are unioned, `bypass.header_present` maps are merged with operator entries overriding spec entries on header-name conflicts, and `operations` is always regenerated from the spec. Malformed spec-side bypass shapes are rejected during extraction instead of being silently dropped.

For full runtime settings and metadata keys, see [openapi_validator.md](openapi_validator.md).

## What is NOT allowed in specs

The following are rejected at parse time with a 400 error:

- **`x-ferrum-consumers`** — use `POST /consumers` directly. Credentials cannot be embedded in spec documents.
- **Plugin `scope: global` or `scope: proxy_group`** — only proxy-scoped plugins are allowed. A single shared plugin instance across multiple proxies cannot be expressed via a single-proxy spec bundle.
- **Plugin `proxy_id` mismatch** — if `proxy_id` is set on a plugin, it must match the spec's proxy ID.
- **Forbidden keys in plugin `config`** — the plugin `config` object is walked recursively. Any of the following keys at any nesting depth triggers a 400 `PluginContainsCredentials` error: `credentials`, `keyauth`, `basicauth`, `jwt`, `hmac`, `mtls`, `consumer`, `consumer_id`, `consumer_groups`, `consumers`.
- **External `$ref`s without opt-in policy** — when process policy or `x-ferrum-external-refs` leave resolution disabled, external Path Item and schema `$ref`s fail closed with HTTP 422 `UnsupportedExternalRef`.

  Note the distinction: a `plugin_name: "jwt"` plugin is fine — the check walks the plugin's `config` *value*, not the plugin metadata fields. A JWT plugin with `config: { secret_lookup: env, validation: { validate_exp: true } }` passes; one with `config: { jwt: { secret: "abc" } }` fails.

### External `$ref` policy {#external-ref-policy}

External and cross-document `$ref` resolution is **explicitly opt-in** and runs only at API-spec admission (POST/PUT). Runtime validation never performs network or filesystem I/O for `$ref`s: schemas and Path Items are materialized into the generated `openapi_validator` config, and an immutable external-document snapshot (plus digest) is stored on the `api_specs` row.

**Gates (both required):**

1. Process: `FERRUM_ADMIN_SPEC_EXTERNAL_REFS_ENABLED=true` (default `false`). See [configuration.md](configuration.md).
2. Per-spec: `x-ferrum-external-refs: true` or an object:

```yaml
x-ferrum-external-refs:
  enabled: true
  document_base: "file:///absolute/jail/root/openapi.yaml"   # optional
  allowed_origins: ["https://schemas.example.com"]          # optional intersect with process allowlist
```

**Containment:**

- **Files**: only under `FERRUM_ADMIN_SPEC_EXTERNAL_REFS_FILE_ROOT` (absolute). On Unix, each path component is opened relative to the already-open canonical jail descriptor with no-follow semantics, and bytes are read from the verified regular-file descriptor; symlink swaps and `..` traversal therefore fail closed without a check/reopen race. File refs are refused on platforms where this descriptor-relative containment primitive is unavailable. Client errors never echo raw host paths.
- **Network**: HTTPS origins listed in `FERRUM_ADMIN_SPEC_EXTERNAL_REFS_ALLOWED_ORIGINS` only (plus optional explicit HTTP fixture origins). Embedded credentials and query strings are rejected. HTTPS is always public-only, independently of `FERRUM_BACKEND_ALLOW_IPS`: localhost, private, link-local, metadata, multicast/broadcast, and unspecified addresses fail closed. The only non-public HTTP exception is loopback on an explicitly configured fixture/development origin. Every redirect hop is re-allowlisted, re-resolved, screened, and pinned into that hop's HTTP client, preserving hostname/SNI validation without an unchecked second DNS lookup. Redirects cannot downgrade HTTPS, and no ambient admin credentials, cookies, bearer tokens, or proxy credentials are forwarded.
- **Budgets and response media**: per-document and aggregate byte caps, document count, reference count, URI length, nesting depth, connect/request/total timeouts, and allowed Content-Types. A present response `Content-Type` must be valid UTF-8 and match the OpenAPI JSON/YAML/plain/octet-stream allowlist; malformed and unsupported values fail closed with the same generic redacted diagnostic. Only an absent `Content-Type` uses bounded first-byte JSON/YAML detection. `Content-Length` is preflighted without reserving from it, chunked/streamed bodies abort as soon as the cap is crossed, and the absolute total deadline covers DNS, connect/request, redirects, and every body read. Unknown, invalid, or oversized inputs fail closed with field-specific, redacted diagnostics.

**Snapshot / last-good:** successful admission persists a gzip-compressed normalized document set with per-document content digests and an aggregate `external_ref_digest`. The aggregate digest includes the canonical document values and effective-policy provenance: the process-policy digest, enabled state, canonical document base, and canonical sorted effective HTTPS/HTTP origin sets. Different per-spec narrowing therefore produces a different digest while ordering-equivalent allowlists remain stable. Every full SQL/Mongo/backup decode enforces the 64 MiB compressed / 128 MiB decompressed caps, revalidates each document digest, and requires the snapshot/digest fields to be present as a matching pair. Cache keys use the same effective-policy digest without rendering a file base, and serialized file-document identities are stable hashes rather than host paths. A failed PUT/extract retains the previously accepted generation (transactional replace / no write). Specs are admin-only metadata (not CP→DP published); `GET /api-specs` returns only the non-secret digest and never the snapshot bytes, and one tenant/namespace cannot read another's snapshot. Backup section version `2` carries optional snapshot bytes; version `1` backups remain restorable without them.

## Storage model

| Field | Type | Description |
|---|---|---|
| `id` | UUID string | Auto-generated; unique within the namespace (`PRIMARY KEY (namespace, id)`) |
| `proxy_id` | string | Links to `proxies(namespace, id)` via `(namespace, proxy_id)`; `ON DELETE CASCADE` |
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
| `external_ref_snapshot` | bytes? | gzip JSON snapshot of admitted external documents (private storage/backup only; never returned by list) |
| `external_ref_digest` | string? | Aggregate digest of the external-ref snapshot; returned by list, or `null` when absent |
| `created_at` | timestamp | Set on POST; preserved on PUT |
| `updated_at` | timestamp | Set on POST and PUT |

**Uniqueness**: a `UNIQUE(namespace, proxy_id)` constraint ensures at most one spec per proxy per namespace. Spec identity itself is `(namespace, id)`: the SQL primary key is composite and the MongoDB durable key is `_id = "{namespace}:{id}"`, so two tenants may hold specs with the same bare id and the foreign key can only ever reach a proxy in the spec's own namespace (issue #4627).

**Body size limit**: controlled by `FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB` (default 25). Returns 413 when exceeded.

**YAML alias expansion**: YAML anchors and aliases are composed through a libyaml event graph and expanded deterministically under shared budgets (expanded nodes, nesting depth, alias references, a 32 MiB fail-closed upper bound on the compact JSON representation including string/key escaping, and expansion work) with cycle, undefined-alias, duplicate-anchor, and duplicate-mapping-key detection. Expansion fails closed with field-specific diagnostics and never admits exponential alias bombs. JSON and YAML submissions share the same post-parse expanded-node cap so autodetection cannot weaken admission. Keep extremely large generated specs in JSON when you need the simplest wire form; modular YAML with finite alias reuse is supported. Expansion also fails closed on a non-core or local YAML tag, a non-finite number, an integer outside the exact JSON `i64`/`u64` range, and a mapping key that has no JSON object-key spelling (null, sequence, or mapping); scalar number and boolean keys keep their stringified spelling so unquoted status codes stay valid.

**MongoDB caveat**: the BSON document limit is 16 MiB. Since spec content is gzip-compressed before storage, a spec up to approximately 14–15 MiB compressed fits within the limit. Operators with larger specs should use a SQL backend (PostgreSQL, MySQL, or SQLite).

## Ownership semantics

All resources created by a spec submission are tagged with `api_spec_id = <spec UUID>`. The field is server-managed: clients must omit it from `x-ferrum-proxy`, `x-ferrum-upstream`, and `x-ferrum-plugins`, including when copying an exported resource into a POST or PUT document. A client-supplied ownership tag returns a 422 validation response consistently across database backends. Resources created via direct admin endpoints have `api_spec_id = null`. These IDs govern replacement and deletion behaviour:

| Operation | What happens |
|---|---|
| `POST /api-specs` | Resources tagged with the new `api_spec_id`. New proxy, optional upstream, and plugins are inserted. |
| `PUT /api-specs/{id}` | Idempotent if the bundle is unchanged (see "PUT semantics" below). When changed, all resources with `api_spec_id = {id}` are deleted and re-inserted from the new document. Resources on the same proxy with `api_spec_id = null` (manually added) are untouched. |
| `DELETE /api-specs/{id}` | Spec-owned proxy is deleted → FK cascade removes all of its plugins (including manually-added ones). Spec-owned upstream is deleted explicitly. Non-spec upstreams survive. The spec row is deleted. If the cascade would leave an invalid aggregate plugin graph, or the pre-delete snapshot contains foreign ownership or a plugin shape that atomic compensation cannot restore, the operation returns 422 without deleting anything. If namespace admission is lost after the delete commits, compensation revalidates the recovered proxy's current upstream existence, subset, and mesh-retry constraints and restores the complete prior graph atomically or leaves it deleted. |
| `DELETE /proxies/{id}` | SQL and replica-set MongoDB atomically remove the proxy, scoped plugins, owner spec, and spec-generated upstreams. Standalone MongoDB returns `501` before mutation. |
| `GET /backup` / `POST /restore` | Database-backed backups include a versioned `api_specs` section (gzip content as Base64 plus ownership metadata). Restore recreates documents after config resources and re-stamps `api_spec_id` without re-extracting. Failed restores roll specs back from the recovery snapshot. See [admin_backup_restore.md](admin_backup_restore.md). |

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

**MongoDB without a replica set**: atomicity is limited to single-document operations. Normal multi-resource submissions retain their best-effort approach with compensating deletes on failure. In the event of an infrastructure fault mid-submission, orphaned resources are possible. Direct `DELETE /proxies/{id}` refuses an API-spec-owned proxy with `501` before mutating the proxy, scoped plugins, owner metadata, generated upstreams, or config-change rows; hand-managed proxy deletion remains available. Late `DELETE` compensation is also strict: it fails closed before writing anything because a partially restored proxy could publish without its security plugins. An already-committed delete therefore remains in place until an operator retries on a replica-set deployment or re-submits the spec. Use a MongoDB replica set for production deployments that require atomic multi-document writes or automatic late-delete recovery.

Before deletion, Ferrum re-reads every plugin that the proxy cascade would remove through an ownership-preserving admin query and validates every other explicit association on the deleted proxy. Proxy-scoped configs remain valid without a reverse entry in `proxy.plugins`; compensation restores those configs in the same transaction while preserving their unattached state. The restore snapshot is validated before persistence: a cascade plugin tagged to another API spec, an explicitly associated global plugin, a proxy-scoped association targeting another proxy, a global plugin carrying the deleted proxy ID, a proxy-group plugin carrying a proxy ID, or an embedded `proxy.plugins` association naming a missing config returns a structured 422 `ApiSpecValidationError` for API-spec DELETE, or the equivalent 400 precondition response for direct proxy DELETE, without deleting anything. Recovery-time plugin construction uses the same configured backend egress policy and real-IP header as ordinary admin validation, so compensation cannot admit a plugin that normal CRUD rejects. This keeps categorically unrestorable or malformed persistent graphs available for operator repair instead of misreporting them as transient races or discovering them only during compensation.

### Detecting and cleaning up orphans (MongoDB non-RS)

If a non-RS deployment experiences a partial failure, the following queries identify orphaned documents. Run them in `mongosh` against the gateway database.

**Specs pointing to non-existent proxies** (the spec row survived but the proxy was never created or was already deleted):

```js
// `_id` is the composite "{namespace}:{id}" (issue #4627), so the join is on the
// plain `id` field plus the namespace.
db.api_specs.aggregate([
  { $lookup: {
      from: "proxies",
      let: { ns: "$namespace", pid: "$proxy_id" },
      pipeline: [
        { $match: { $expr: { $and: [
          { $eq: ["$namespace", "$$ns"] },
          { $eq: ["$id", "$$pid"] }
        ] } } },
        { $project: { _id: 1 } }
      ],
      as: "p"
  } },
  { $match: { p: { $size: 0 } } },
  { $project: { _id: 1, id: 1, namespace: 1, proxy_id: 1 } }
])
// To delete: db.api_specs.deleteMany({ _id: { $in: [<composite _ids from above>] } })
```

**Resources tagged with a non-existent spec** (the resource was created but the spec row was lost):

```js
// Proxies
db.proxies.aggregate([
  { $match: { api_spec_id: { $ne: null } } },
  { $lookup: {
      from: "api_specs",
      let: { ns: "$namespace", sid: "$api_spec_id" },
      pipeline: [
        { $match: { $expr: { $and: [
          { $eq: ["$namespace", "$$ns"] },
          { $eq: ["$id", "$$sid"] }
        ] } } },
        { $project: { _id: 1 } }
      ],
      as: "s"
  } },
  { $match: { s: { $size: 0 } } },
  { $project: { _id: 1, id: 1, namespace: 1, api_spec_id: 1 } }
])

// Same pattern for plugin_configs and upstreams — replace the collection name.
```

Orphaned resources with dangling `api_spec_id` tags are inert — they function as normal config entries and do not affect the gateway runtime. Cleanup is optional but recommended to keep the admin API consistent. To clear the tag without deleting the resource:

```js
db.proxies.updateMany(
  { namespace: "<namespace>", api_spec_id: "<orphaned-spec-id>" },
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
| `external_ref_digest` | External-ref admission snapshot | Lowercase SHA-256 hex when external refs were admitted; otherwise `null`. Snapshot bytes are never listed. |

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

- `items` — page of spec summaries (including nullable `external_ref_digest`, but never `spec_content`, `resource_hash`, or external snapshot bytes).
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

Resubmit an existing spec with `PUT /api-specs/{id}` to regenerate a validator whose stored paths omit the listen prefix. Runtime loading does not rewrite stored plugin configs.

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
  /:
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

Submitting this spec creates one generated `openapi_validator` plugin attached to `orders-contract` for `POST /orders`. A request body missing `id` is rejected with HTTP 400 in `block` mode.

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
