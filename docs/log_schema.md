# Customizing Transaction Log Output

Operators can shape the JSON / line-protocol output of every logging plugin
(`stdout_logging`, `http_logging`, `tcp_logging`, `udp_logging`,
`ws_logging`, `kafka_logging`, `loki_logging`, `statsd_logging`) through a
per-plugin `schema:` block. `api_chargeback`, `api_chargeback_sink`, and
`transaction_debugger` accept the same contract against their own record
families — see [Non-Summary Record Families](#non-summary-record-families). This lets you rename
keys, drop fields, reorder output, add static stamping, and inject a few
derived fields without forking the gateway.

The customization layer is purely a serialization-time wrapper. Existing
deployments are unaffected — when no `schema` / `schema_ref` is set, the
plugin emits native field names exactly as before.

HTTP-family schemas include `grpc_status` as a native numeric field. It is the
final gRPC application status and remains separate from
`response_status_code`; missing terminal status on a known gRPC transaction
normalizes to UNKNOWN (`2`), while malformed input retains the existing
`u32::MAX` invalid-status sentinel. It can be omitted, renamed, or placed in
`order` like any other HTTP native field.

## Quick Start

```yaml
plugin_configs:
  - id: stdout-customized
    plugin_name: stdout_logging
    scope: global
    config:
      schema:
        rename:
          proxy_id: route_id
          response_status_code: status
        omit: [request_user_agent, latency_plugin_external_io_ms]
        static_fields:
          env: production
          service: api-gateway
        derived_fields:
          - { name: status_class, kind: status_class }
          - { name: outcome, kind: outcome }
        metadata:
          mode: flatten
          prefix: "meta_"
        timestamp_format: epoch_ms
```

Output (HTTP request, redacted for brevity):

```json
{
  "namespace": "ferrum",
  "timestamp_received": 1778500800000,
  "client_ip": "10.0.0.1",
  "route_id": "things-api",
  "status": 200,
  "latency_total_ms": 12.5,
  "env": "production",
  "service": "api-gateway",
  "status_class": "2xx",
  "outcome": "ok",
  "meta_trace_id": "abc-123",
  "meta_authorization": "[REDACTED]"
}
```

## Where Schemas Live

Two equivalent forms:

### 1. Inline

Embed the schema directly under each logging plugin's `config:`. Simplest
when only one or two sinks need customization, or when each sink wants a
different schema.

### 2. Named (DRY)

Define a `transaction_log_schema` plugin once, reference it from any
number of logging plugins via `schema_ref:`:

```yaml
plugin_configs:
  - id: shared-log-schema
    plugin_name: transaction_log_schema
    scope: global             # required — schemas are process-global
    config:
      schemas:
        splunk_cim:
          summary_type: both
          rename: { proxy_id: route_id }
          metadata: { mode: flatten, prefix: "fields." }

  - id: my-stdout
    plugin_name: stdout_logging
    scope: global
    config:
      schema_ref: splunk_cim

  - id: my-loki
    plugin_name: loki_logging
    scope: global
    config:
      endpoint_url: http://loki:3100/loki/api/v1/push
      schema_ref: splunk_cim
```

The gateway loader processes `transaction_log_schema` plugins **before**
any plugin that uses `schema_ref:`, so reload ordering is automatic. The
named-schemas registry is fully replaced on every config reload — renamed
or removed schemas do not leak.

`schema:` and `schema_ref:` are mutually exclusive on a single plugin.

### Admin-API prospective graph validation

Every relevant `POST`, `PUT`, or `DELETE` under `/plugins/config` is
validated against the configuration that would exist after the mutation:
the authoritative current namespace snapshot, overlaid with the submitted
resource or with the deleted resource removed. Definitions are staged first
and enabled `schema_ref` consumers are validated second. The staging area is
discarded after validation and never changes the registry serving live traffic.

This rejects duplicate schema names and schema renames/deletes that would leave
an enabled logger dangling before anything is persisted. It also means a
logger submitted immediately after its schema definition resolves from the
database snapshot; validation does not depend on whether a runtime poll has
already refreshed the live registry.

Graph-relevant direct CRUD, batch, restore, and API-spec mutations for the same
namespace hold a renewable datastore lease from the authoritative snapshot read
through persistence. The process-local admission guard remains as a cheap first
tier, while the SQL/MongoDB lease also serializes writable gateway instances
that share persistence. Concurrent requests therefore cannot both validate
against snapshots that omit the other request's committed graph change.
If a write settles after its lease expires, Ferrum reacquires admission and
validates the authoritative graph before accepting or compensating that result.
Late restore clears use an additive, current-ID-wins recovery: the combined
current and pre-restore graph is validated before any missing snapshot resource
is replayed, so an intervening writer is neither erased nor combined into an
invalid schema graph.

Batch and restore payloads use the same definition-first graph pass, so a
payload can list referrers before definitions. Each namespace is validated in
isolation: the same schema name can be defined independently in separate
namespaces, while a referrer cannot resolve a definition from another
namespace. File reloads, DB poll cycles, and control-plane snapshots use the
same prospective graph rules before atomically publishing a new runtime cache.
SQL keeps every enabled graph participant in one batch transaction even when
an unrelated large plugin import would normally be split into bounded chunks.
API-spec `POST` validates extracted plugins against the same authoritative
namespace snapshot, and exact `PUT` first removes the plugins owned by the old
spec before overlaying the replacement bundle. API-spec `DELETE` validates the
same removal-only candidate and rejects deletion when retained referrers would
be left dangling.

Graph participation never bypasses backend-egress admission. Direct and batch
writes screen literal endpoints even for disabled configurations; disabled
configurations defer construction and graph validation until they are enabled.
Enabled `schema_ref` consumers also receive the policy-only checks that follow
prospective graph construction, including custom plugins and plugins that ignore
an unrecognized `schema_ref` key. SQL, MongoDB, and control-plane runtime
snapshots reject dangling/non-string references before cache publication, while
unrelated constructor failures on optional logging sinks retain their existing
fail-open warning behavior.

Upgrade note: every **enabled** plugin carrying a top-level `schema_ref`
participates in this fail-closed graph, even if that plugin does not otherwise
recognize the key. Remove accidental/stale `schema_ref` keys or add the named
definition before upgrading or reloading. Disabled entries remain inert until
they are enabled, at which point the same graph validation applies.

Inline `schema:` blocks have no registry dependency; they compile directly
against the static field metadata in `fields.rs`.

## Schema Fields

| Key | Type | Default | Description |
|---|---|---|---|
| `summary_type` | `http` / `stream` / `both` | `both` | Limits the schema to one summary type. Other summary types fall back to native output. |
| `omit` | `[String]` | `[]` | Native field names to drop. |
| `rename` | `{old: new}` | `{}` | Map native field names to output keys. |
| `order` | `[String]` | – | Explicit output order. May contain `"*"` once as a wildcard for "all unlisted entries in natural order." Without `"*"`, every field must be listed. |
| `static_fields` | `{key: value}` | `{}` | Literal JSON values injected at top level. Keys matching sensitive substrings (see [Sensitive substrings](#sensitive-substrings)) are rejected. String values that begin with an HTTP auth scheme token (`Bearer xxx`, `Basic xxx`, `AWS4-HMAC-SHA256 ...`, etc.) are also rejected as a defense-in-depth check against literal credential copy-paste. |
| `derived_fields` | `[{name, kind}]` | `[]` | Computed values; see [Derived Kinds](#derived-kinds). |
| `metadata` | object | `{mode: nested}` | How to render the `metadata` map: `nested` / `omit` / `flatten`. |
| `timestamp_format` | `rfc3339` / `epoch_ms` / `epoch_s` | `rfc3339` | Conversion for timestamp string fields. Parse failures fall back to the raw string. |

### WebSocket Disconnect Fields (`ws_logging` only)

These keys are scoped to the **`ws_logging`** plugin. `ws_logging` applies
`summary_type: http` and `summary_type: both` schemas to the record emitted
when a WebSocket session disconnects, and only there are the WebSocket-disconnect
keys valid. The native keys available to `omit`, `rename`, and `order` are:

`event`, `namespace`, `proxy_id`, `proxy_name`, `client_ip`,
`consumer_username`, `auth_method`, `backend_target`, `protocol`,
`listen_port`, `duration_ms`, `frames_client_to_backend`,
`frames_backend_to_client`, `bytes_client_to_backend`,
`bytes_backend_to_client`, `timestamp_connected`, `timestamp_disconnected`,
`direction`, `io_side`, `error_class`, and `metadata`.

The disconnect-specific keys are `event`, `frames_client_to_backend`,
`frames_backend_to_client`, `bytes_client_to_backend`,
`bytes_backend_to_client`, `timestamp_connected`, `timestamp_disconnected`,
`direction`, and `io_side`. Byte totals are the session payload volume already
computed by the relay (including H1/H2 tunnel mode, where frame counts stay
zero). Timestamps are RFC3339 wall-clock instants captured at upgrade and
teardown so delayed batch delivery does not replace event time with receipt
time; `timestamp_format` applies when a custom schema is configured. A
`summary_type: stream` schema remains limited to TCP, UDP, and DTLS entries;
WebSocket disconnects retain their native shape under that setting.

Every other logging plugin (`http_logging`, `kafka_logging`,
`loki_logging`, `stdout_logging`, `tcp_logging`, `udp_logging`,
`statsd_logging`) uses the shared compiler without this field family: these
WebSocket-disconnect names are **rejected** in `omit` / `rename` / `order`
and never reserve output keys, so a non-`ws_logging` schema is free to use
names like `event` for a `static_fields` entry or a flattened metadata key.

Named schemas defined via `transaction_log_schema` are process-global and are
registered without the WebSocket-disconnect family, so a portable definition
can never name a ws-only field. When `ws_logging` resolves such a schema via
`schema_ref:`, the named schema is recompiled under the `ws_logging`
capability, so the WebSocket-disconnect fields **do** apply to disconnect
entries (with their default names and order) — `schema_ref` reaches parity
with an inline `ws_logging` `schema:` rather than dropping the disconnect
fields. Because the named definition cannot reference ws-only field names, use
an inline `ws_logging` `schema:` when you need to `rename` / `omit` / `order`
the disconnect-specific keys themselves. (A `schema_ref` whose `static_fields`
key or rename target collides with a now-reserved WebSocket-disconnect field
name is rejected for `ws_logging` — the same error the equivalent inline
schema raises.)

### Derived Kinds

| `kind` | HTTP / WS summary | WebSocket disconnect | Stream summary |
|---|---|---|---|
| `status_class` | `"1xx"` / `"2xx"` / `"3xx"` / `"4xx"` / `"5xx"` / `"other"` from `response_status_code` | always `"none"` | always `"none"` |
| `backend_host` | hostname from `backend_target` (port stripped, IPv6 brackets honored) | hostname from `backend_target` (port stripped, IPv6 brackets honored) | hostname from `backend_target` (port stripped, IPv6 brackets honored) |
| `summary_kind` | `"http"` | `"websocket_disconnect"` | `"stream"` |
| `outcome` | `"error"` when `response_status_code >= 500` or the authoritative terminal predicate matches (dispatch/body/incomplete/disconnect/rejection/nonzero gRPC status); else `"ok"` | `"error"` when `error_class` is set; else `"ok"` | `"error"` when `connection_error`, `error_class`, or `disconnect_cause: backend_error` is set; else `"ok"` |

### Metadata Modes

- **`nested`** (default): emits `metadata: { ... }` as a single nested
  object. Sensitive keys are redacted to `"[REDACTED]"`.
- **`omit`**: drops the metadata entirely.
- **`flatten`**: promotes each metadata entry to a top-level key.
  Accepts:
  - `prefix:` (optional string prepended to every flattened key, e.g.
    `"meta_"` → `meta_trace_id`).
  - `on_collision:` — `skip` (default; existing key wins) or
    `overwrite` (metadata entry replaces — implemented as a duplicate
    key, which most JSON parsers resolve as "last wins").

Sensitive keys (`authorization`, `cookie`, credential tokens, API keys, etc.)
are **always** redacted, on every path — `nested`, `flatten`, even when the
operator renames the outer `metadata` field via `rename:`. There is no
way to bypass redaction through the schema. Request-private lifecycle keys
under the `_dedup_` prefix are **omitted entirely** (not redacted) from every
summary projection.

### Sensitive substrings

The full canonical list (`DEFAULT_SENSITIVE_METADATA_KEYS` in
`src/plugins/utils/metadata_redaction.rs`):

| Substring     | Matches (examples)                                       |
|---------------|----------------------------------------------------------|
| `authorization` | `authorization`, `request_authorization_header`, `downstream_authorization` |
| `cookie`      | `cookie`, `legacy.cookie.value`                          |
| `set-cookie`  | `set-cookie`                                             |
| `x-api-key`   | `x-api-key`, `X-API-KEY`                                 |
| `x-auth-token`| `x-auth-token`                                           |
| `x-csrf-token`| `x-csrf-token`                                           |
| `bearer`      | `bearer`, `auth.bearer.value`                            |
| `password`    | `password`, `user_password`                              |
| `secret`      | `secret`, `api_secret`, `secret_count` *(also matched — see below)* |

Matching is **case-insensitive substring**, not exact match. That means
operator-chosen rename targets / `static_fields` keys / `derived_fields`
names that *contain* one of these substrings will be rejected at compile
time — even if the operator's intent is benign. For example:

- `secret_count` is rejected because it contains `secret`.
- `secrets_loaded` is rejected for the same reason.
- `cookie_count_per_request` is rejected because it contains `cookie`.

This is **intentional defense-in-depth**: the read-path redactor uses
the same substring rule, so a benign-named field would be silently
replaced with `[REDACTED]` at every log sink. Erroring at compile time
is louder than letting the operator deploy a field that vanishes from
logs.

Workaround: rename the field to drop the substring (e.g.
`secret_count` → `total_credentials` or `credential_count`).

### Per-segment credential classifiers

Singular `token` keys and API-key spellings go through narrower per-segment
classifiers in `src/plugins/utils/metadata_redaction.rs` so the same decision
applies to native serialization, nested/flattened schema metadata, renamed
outer metadata fields, and explicitly selected `static_fields`:

| Concept | Sensitive examples | Not sensitive (controls) |
|---------|--------------------|--------------------------|
| Token | `token`, `access_token`, `refreshToken`, `id-token`, `APIToken`, `session_token` | `ai_total_tokens`, `ai_prompt_tokens`, `ai_completion_tokens`, `prompt_tokens` |
| API key | `api_key`, `api-key`, `apikey`, `APIKey`, `x-api-key`, `openai_api_key` | `cache_key`, `routing_key`, `api_response_count`, `ai_total_tokens` |

Segmentation splits on non-alphanumeric delimiters, camelCase boundaries, and
acronym→word boundaries (`APIKey` → `API` + `Key`, `APIToken` → `API` +
`Token`). Concatenated `apikey` is recognized as its own segment.

Operator-supplied extras may be added via the
`FERRUM_LOG_REDACT_METADATA_KEYS` env var (comma-separated, also
substring-matched). Those apply to the redaction path only — schema
compile-time rejection runs against the env-extras too, so adding a
substring there will start rejecting matching schema names on the next
reload.

### Internal-only lifecycle metadata

Keys in the reserved `_dedup_*` lifecycle namespace are **internal-only**.
Matching is fail-closed across ASCII case, delimiter (`-` / `.` / `_`), and
camelCase spellings: a leading `_` whose first alphanumeric segment is `dedup`
(for example `_dedup_key`, `_DEDUP_REDIS_LOCK_TOKEN`, `_dedup-redis-lock-token`,
`_DedupRedisLockToken`). They are stripped by `clone_log_metadata` and omitted
by every native / schema serializer. Names that merely contain `dedup`
(`request_dedup_key`, `_deduplication`) stay observable.
`request_deduplication` keeps ownership key, fingerprint, local inflight token,
and Redis lock token in typed non-serializable request state instead of public
metadata; the `_dedup_` filter is the shared fail-closed contract if any
producer still writes the legacy names (`_dedup_key`, `_dedup_fingerprint`,
`_dedup_local_inflight_token`, `_dedup_redis_lock_token`). Schema
`static_fields` / rename targets that match this namespace are rejected at
compile time.

## Per-Plugin Notes

| Plugin | Schema-aware output | Notes |
|---|---|---|
| `stdout_logging` | Full | Reserves bounded stdout queue capacity before serialization; independent of `FERRUM_LOG_LEVEL`. Optional flat filter (`status_code_min/max`, `min_latency_ms`, `errors_only`) or compiled `expression` tree runs before schema application. |
| `http_logging` | Full | Batched JSON array. |
| `tcp_logging` | Full | NDJSON, one line per entry. |
| `udp_logging` | Full | Batched JSON array per UDP datagram. Operators should keep per-summary size under MTU. |
| `ws_logging` | Full | HTTP / WebSocket entries use `summary_type: http`; TCP / UDP / DTLS entries use `summary_type: stream`. WebSocket disconnect fields and derived-value behavior are documented above. |
| `kafka_logging` | Full | One JSON message per summary. Partition key (`client_ip` / `proxy_id`) still reads typed fields, so partition keys are NOT affected by `rename:`. |
| `loki_logging` | Full | Schema-customized JSON appears inside the Loki log line. Loki **labels** (`build_http_labels` / `build_stream_labels`) keep reading typed fields, so labels are NOT affected by `rename:`. |
| `statsd_logging` | Tag rename / omit only | Static / derived / flatten / timestamp parts of a schema are no-ops here (statsd is line protocol, not JSON). When an inline `schema:` carries any of those keys, the plugin emits a `warn!` at construction time so operators don't ship a schema that silently throws fields away (per-referrer warnings would be noisy, so `schema_ref:` is not inspected — verify the shared schema's intent at the `transaction_log_schema` definition). The schema's `rename` and `omit` operate on the native field names backing the statsd tags. The supported mappings are: HTTP — `http_method`↔`method`, `response_status_code`↔`status`, `proxy_id`↔`proxy`. Stream — `protocol`↔`protocol`, `proxy_id`↔`proxy`, `disconnect_cause`↔`cause`, `disconnect_direction`↔`direction`. Computed statsd tags without native-field backing (`status_class`, `grpc_status`, `error`, `body_outcome`, `body_error`, `result`, `io_side`, `error_class`, and the authoritative `namespace`) are always emitted with their default names — `omit` and `rename` have no effect on them since they are derived at format time, not read from a summary field. `grpc_status` is emitted only for gRPC transactions and is bounded to `0`–`16` plus `OTHER`. Rename targets are fail-closed against a portable StatsD tag-key grammar (`[A-Za-z_][A-Za-z0-9_.-]*`) and cannot collide with reserved runtime tags; a schema that is valid for JSON loggers may still be rejected when attached to `statsd_logging` / `schema_ref`. |

`prometheus_metrics` rejects `schema:` and `schema_ref:` at construction
time: it exposes metrics with label names baked into the time-series store,
so there is no serialization boundary to project.

## Non-Summary Record Families

`api_chargeback`, `api_chargeback_sink`, and `transaction_debugger` do not
serialize `TransactionSummary` for shipping, but they each have an externally
emitted representation of their own. They accept the same `schema:` /
`schema_ref:` contract, compiled by the same resolver against their own field
inventory (a **record family**). Everything a family cannot express is rejected
at construction with a plugin- and field-specific diagnostic — never ignored.

| Plugin | Projected surface | Field inventory | Rejected for this family |
|---|---|---|---|
| `api_chargeback` | The per-proxy billing row inside `GET /charges` (`consumers.<consumer>.proxies.<key>`) | `proxy_id`, `namespace`, `proxy_name`, `currency`, `protocol_family`, `total_calls`, `total_charges`, `by_status`, `bandwidth`, `stream` | `summary_type`, `timestamp_format`, `metadata`, `order`, every derived kind except `summary_kind` |
| `api_chargeback_sink` | The exported charge event — the JSONEachRow row delivered to ClickHouse and the durable spool artifact that replays it | `event_id`, `received_at`, `node_id`, `namespace`, `consumer_id`, `consumer_name`, `proxy_id`, `proxy_name`, `route_id`, `status_code`, `http_status_code`, `grpc_status`, `protocol`, `call_count`, `charge_call`, `bytes_sent`, `bytes_received`, `charge_bytes_sent`, `charge_bytes_received`, `charge_total`, `currency`, `pricing_version`, `request_id`, `trace_id`, `snapshot_id` | `summary_type`, `timestamp_format`, `metadata`, the `backend_host` derived kind |
| `transaction_debugger` | The terminal diagnostic records on the `transaction_debug` tracing target (HTTP, stream, WebSocket disconnect) | its own diagnostic names — `outcome`, `method`, `path`, `status`, `rejection_phase`, `latency_plugin_ms`, `latency_gw_overhead_ms`, `metadata`, … — **not** the transaction-summary names | — (full contract, including `summary_type` and `metadata`) |

Shared rules for all three:

- **Nothing but the emitted representation moves.** Projection never touches
  billing identity, charge accounting, registry or accumulator keys, snapshot
  keys, Prometheus label sets, or spool ownership. Renaming `proxy_id` renames
  a JSON key, not the row it is accounted under.
- **Compiled once, never on the emit path.** `schema` compiles and `schema_ref`
  resolves at plugin construction / reload, exactly as for the log-shipping
  plugins, and `schema_ref` keeps the global-first lifecycle and fails closed
  for a missing definition.
- **Default output is unchanged.** With no `schema` / `schema_ref` configured
  every one of these surfaces emits its pre-existing bytes through its
  pre-existing path, with no projection machinery and no added allocation.
- **Named schemas are portable, so they are limited here.** A
  `transaction_log_schema` definition is authored and registered against the
  transaction-summary registry, so under another family it can only name the
  fields that family happens to share with the summary registry. Only
  `namespace`, `proxy_id`, and `proxy_name` are shared by all three families.
  `protocol`, `bytes_sent`, and `bytes_received` reach the charge event and the
  debugger diagnostics but **not** the chargeback billing row, which carries
  `protocol_family` and a nested `bandwidth` object instead. Recompiling a
  definition under a family that lacks one of its names fails closed on that
  name — use an inline `schema:` for family-specific fields.

Family-specific notes:

- **`api_chargeback`** governs one process-global render cache, so — exactly
  like `render_cache_ttl_seconds` and the registry budgets — every enabled
  `api_chargeback` instance must resolve to the same `schema` / `schema_ref`.
  A disagreement is rejected at admission. Changing the projection drops the
  cached `/charges` document. `order` is rejected because the row is a member
  of a `serde_json::Map`-backed document whose member order the projection does
  not control.
- **`api_chargeback_sink`** projects the ClickHouse INSERT row, so renaming a
  field renames the column the row inserts into — the target table must agree.
  The native (unprojected) JSONEachRow key set is gated against
  `migrations/clickhouse/0001_charges.sql` in CI (issue #4441); see
  `docs/plugins/api_chargeback_sink.md`.
  Mind the sort key in particular: the reference `ferrum.charges_raw` is a
  `ReplacingMergeTree` ordered by
  `(namespace, consumer_id, received_at, event_id)`, and that ordering is what
  makes at-least-once spool replay idempotent. Renaming or omitting one of
  those four without matching the destination table leaves its column at the
  default for every row, so distinct charges collapse onto one sort key and the
  `FINAL` reads behind the hourly/daily/monthly rollup views keep only one of
  them. Ferrum cannot inspect the remote table, so preserving the destination
  sort key is the operator's responsibility.
  `received_at` stays an epoch-nanosecond integer: its representation is fixed
  by the column it inserts into, so `timestamp_format` is rejected rather than
  silently changing a column's type. The durable spool artifact is a copy of the delivery body and is replayed
  verbatim, so a spool file written before a schema change replays under the
  schema in force when it was written. The retained-byte reservation for a
  batch adds a precomputed worst-case per-row surcharge for the projection, so
  the reservation still strictly precedes serialization.
- **`transaction_debugger`** emits one `record` field carrying the projected
  JSON document instead of the individual `tracing` fields when a schema is
  configured. The projected record is a faithful projection of the default
  one — same names, same values, same `"-"` placeholder for an absent optional
  — plus a `metadata` native field exposing the (redacted, `_dedup_*`-stripped)
  summary metadata map, so `nested` / `omit` / `flatten` work here as on any
  shipping sink. A schema whose `summary_type` excludes an entry kind leaves
  that record on its native diagnostic, matching every log-shipping plugin.

The transaction debugger's config is otherwise closed as well: only
`redacted_headers`, `log_request_body`, `log_response_body`,
`max_request_body_bytes`, `max_response_body_bytes`, `redacted_body_fields`,
`schema`, and `schema_ref` are accepted, and every other unsupported key is
rejected rather than ignored. Bounded body samples are emitted only on the
`transaction_debug` tracing target and are never projected into
`TransactionSummary` metadata, so no shipping sink can observe them — and they
are not part of the diagnostic field inventory either.

## Validation

`SummarySchema::compile` rejects (with a clear error and Levenshtein
suggestion where applicable):

1. Unknown keys in the fixed-shape outer `transaction_log_schema` config,
   each `derived_fields` entry, and the `metadata` policy. Errors identify the
   named schema and nested path. The operator-named `schemas` map and the
   `rename` and `static_fields` maps remain intentionally open.
2. Unknown field names in `omit`, `rename`, and `order`.
3. Renaming and omitting the same field.
4. Duplicate output keys (e.g. renaming two fields onto the same target).
5. `order` referencing unknown output keys.
6. `order` without `"*"` missing some fields.
7. `order` containing more than one `"*"`.
8. `summary_type: http` referring to stream-only fields, and vice versa.
9. `static_fields` keys that match sensitive substrings.
10. `static_fields` values containing nested keys with sensitive substrings.
11. `static_fields` string values that begin with an HTTP auth scheme token (`Bearer xxx`, `Basic xxx`, `Digest`, `Negotiate`, `NTLM`, `HOBA`, `Mutual`, `SCRAM-SHA-1`, `SCRAM-SHA-256`, `vapid`, `AWS4-HMAC-SHA256`). Defense-in-depth against literal credential copy-paste.
12. `static_fields` values that are `null`.
13. `metadata.prefix` containing control characters.
14. Unknown derived `kind`.
15. Unknown top-level schema keys (typo guard).
16. `schema:` and `schema_ref:` both present on the same plugin.
17. `schema_ref:` pointing at a name absent from the prospective namespace.

For named schemas:

18. `transaction_log_schema` with `scope: proxy` or `scope: proxy_group`
    is rejected at the admin write path (`PluginConfig::validate_fields`,
    returning a `400`) and by the runtime rejecting contract
    (`validate_plugin_references`). Both surfaces agree so an admitted write can
    never be rejected by a later full-config load (which would wedge the DB poll
    loop read-only — see issue #2158).
19. Two enabled `transaction_log_schema` instances in the same namespace
    defining the same name.

## Performance

- Schema parsing happens once at plugin construction. The compiled
  `Vec<FieldSpec>` lives behind an `Arc` and is shared cheaply.
- At log time, `SchemaView` walks the compiled vec and forwards each
  field through the typed HTTP, stream, or WebSocket-disconnect entry. No
  `serde_json::Value` is built; no per-request `HashMap` is allocated.
  Default-configured plugins (no schema) go through the identical
  pre-existing serde path with zero added cost.
- The named-schemas registry is read-only on the hot path; `schema_ref`
  resolution is a one-shot `Arc::clone` at plugin construction.
- `transaction_log_schema` instances are config-only: cache construction
  compiles and stages their definitions, then discards the instances instead
  of retaining them in global, per-proxy, capability, or HTTP/gRPC/WebSocket/
  TCP/UDP protocol lists. A schema-only configuration therefore leaves every
  runtime list empty and preserves the existing no-plugin transaction-summary
  fast path. Full- and delta-reload cache tests cover this invariant, including
  multiple schema instances; the schema-only test also pins repeated request
  views to the same precomputed `Arc` lists so a per-request list allocation
  regression fails deterministically without a wall-clock benchmark.

## Operator Cookbook

### Splunk-style "Common Information Model" output

```yaml
schema:
  summary_type: both
  rename:
    timestamp_received: time
    timestamp_connected: time
    proxy_id: route
    response_status_code: status
    client_ip: src
    backend_target: dest
    latency_total_ms: duration
  derived_fields:
    - { name: status_class, kind: status_class }
    - { name: outcome,      kind: outcome      }
  metadata: { mode: flatten, prefix: "fields." }
  timestamp_format: epoch_ms
```

### Datadog logs

```yaml
schema:
  summary_type: both
  static_fields:
    service: ferrum-edge
    ddsource: ferrum-edge
    env: production
  derived_fields:
    - { name: status_class, kind: status_class }
  rename:
    namespace: tenant
    response_status_code: http.status_code
    http_method: http.method
    backend_target: http.url
    request_path: http.url_details.path
  timestamp_format: rfc3339
```

### Strict JSON shape (minimal allowlist)

```yaml
schema:
  summary_type: http
  order:
    - timestamp_received
    - http_method
    - request_path
    - response_status_code
    - latency_total_ms
    - "*"
  omit:
    - latency_plugin_execution_ms
    - latency_plugin_external_io_ms
    - latency_gateway_overhead_ms
    - latency_gateway_processing_ms
    - latency_backend_ttfb_ms
    - latency_backend_total_ms
    - request_user_agent
    - mirror
```

### statsd tag rename for a Datadog migration

```yaml
schema:
  summary_type: http
  rename:
    http_method: verb
    proxy_id: route_id
    response_status_code: code
  omit:
    - proxy_id   # also valid if you want to drop the proxy tag entirely
```

Output line: `ferrum.request.count:1|c|#verb:GET,code:200,status_class:2xx,route_id:things-api`.

## Extending in Custom Plugins

Custom plugins authored under `custom_plugins/` can opt into the same
behavior by importing:

```rust
use ferrum_edge::plugins::utils::log_schema::{
    SchemaCapabilities, SchemaView, SummaryLogEntryView, SummarySchema, resolve_schema,
};
```

Store `Option<Arc<SummarySchema>>` on the plugin struct; call
`resolve_schema(config, "my_plugin", SchemaCapabilities::BASE)` in `new()`;
wrap each `serde_json::to_string(summary)` call site in a
`match self.schema { ... }` branch identical to the built-in plugins.

`resolve_schema` takes a `SchemaCapabilities` argument that gates optional
field families. Pass `SchemaCapabilities::BASE` unless your plugin serializes
WebSocket-disconnect entries (only the built-in `ws_logging` plugin does, via
`SchemaCapabilities::WS_LOGGING`). The capability is honored for both inline
`schema:` and `schema_ref:` — a named schema is recompiled under your
capability so `schema_ref` matches an inline schema.
