# Safe Upgrade Guide

This document describes how to safely upgrade Ferrum Edge between versions with zero data loss and a clear rollback path. The approach varies by operating mode, but the core principle is the same: **validate the new version against a copy of your data before cutting over production traffic.**

## Database Mode (`FERRUM_MODE=database`)

This is the most involved upgrade because schema migrations may alter your database. The strategy is: clone the database, migrate the clone, validate with the new binary, then cut over.

### Step-by-Step

#### 1. Backup Your Current Database

Create a full copy of the production database. This copy serves two purposes: it's the migration target for the new version, and it's your rollback safety net.

```bash
# PostgreSQL
pg_dump -Fc -h db-host -U ferrum ferrum_db > ferrum_backup_v1.dump
createdb -h db-host -U ferrum ferrum_db_upgrade
pg_restore -h db-host -U ferrum -d ferrum_db_upgrade ferrum_backup_v1.dump

# MySQL
mysqldump -h db-host -u ferrum -p ferrum_db > ferrum_backup_v1.sql
mysql -h db-host -u ferrum -p -e "CREATE DATABASE ferrum_db_upgrade"
mysql -h db-host -u ferrum -p ferrum_db_upgrade < ferrum_backup_v1.sql

# SQLite
cp ferrum.db ferrum_upgrade.db
```

Alternatively, use the Admin API backup endpoint to capture the logical config:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/backup > ferrum-config-backup.json
```

#### 2. Run Migrations Against the Cloned Database

Use the new Ferrum Edge binary in `migrate` mode to apply pending schema migrations to the clone. The original database is untouched.

```bash
# Dry run first — see what would change
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_MIGRATE_DRY_RUN=true \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db_upgrade \
  ./ferrum-edge-new

# Apply migrations
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db_upgrade \
  ./ferrum-edge-new
```

Check migration status to confirm everything applied cleanly:

```bash
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=status \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db_upgrade \
  ./ferrum-edge-new
```

#### 3. Validate the New Version Against the Upgraded Database

Start the new binary in `database` mode pointing at the cloned database. This lets you exercise the full proxy and admin API without touching production.

```bash
# Run new version against cloned DB on non-production ports
FERRUM_MODE=database \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db_upgrade \
  FERRUM_PROXY_HTTP_PORT=8100 \
  FERRUM_PROXY_HTTPS_PORT=8543 \
  FERRUM_ADMIN_HTTP_PORT=9100 \
  FERRUM_ADMIN_JWT_SECRET=change-me-to-a-32-character-admin-secret \
  ./ferrum-edge-new
```

Validate:

- **Health check**: `curl http://localhost:9100/health` — confirm `status: ok`
- **Config loaded**: `curl -H "Authorization: Bearer $TOKEN" http://localhost:9100/proxies` — verify all proxies are present and correctly configured
- **Proxy traffic**: send test requests through port 8100 to verify routing, plugin execution, and backend connectivity
- **Admin API**: test CRUD operations against the staging instance
- **Logs**: check for warnings or errors at `FERRUM_LOG_LEVEL=info`

### Protocol Hardening Checks

Recent proxy-boundary hardening intentionally rejects several malformed request
forms that older builds could tolerate:

- `Content-Length` lists with empty elements, such as `42,`, `,42`, or `4,,2`
- HTTP/2 or HTTP/3 `TE` lists with empty elements or values other than `trailers`
- HTTP/2 or HTTP/3 requests whose `Host` header disagrees with `:authority`
- unbracketed IPv6 literals in `Host` or `:authority`; use `[2001:db8::1]` form
- TLS or DTLS clients that do not complete the frontend handshake within `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` (default 10s)

During staged validation, scan access/error logs for unexpected 400s or frontend
TLS/DTLS handshake timeout warnings. Legacy clients that emit these malformed
headers should be fixed rather than allowlisted, since the stricter behavior
prevents request-smuggling and authority-confusion parser differentials.

The per-proxy `backend_connect_timeout_ms` budget also now covers the full
backend connection setup pipeline for direct TLS/H2/gRPC/H3 paths, including
TLS and HTTP/2 or HTTP/3 handshakes. Operators who previously sized this field
assuming it applied only to the TCP SYN phase should validate cold-connection
latency during rollout.

### TCP Connection Throttle Validation Hardening

Upgrades now fail closed when persisted `tcp_connection_throttle` configuration
would claim protection that the runtime cannot provide or contains an invalid
plugin shape. In particular, config load is rejected when:

- an enabled global throttle has a nonempty effective target set containing
  only HTTP-family, UDP, or DTLS proxies (a mixed target set remains valid when
  it includes at least one TCP/TCP+TLS proxy)
- a proxy- or proxy-group-scoped throttle is attached to a non-TCP protocol
- the plugin `config` contains fields other than `max_connections_per_key` and
  `cleanup_interval_seconds`
- `cleanup_interval_seconds` exceeds 86400 seconds

This is intentional fail-closed behavior; the upgrade does not ignore unknown
fields or preserve unsupported attachments through a compatibility shim.
Database, control-plane, and data-plane publication rejects invalid attachment
graphs, and a DP keeps its last accepted snapshot. Runtime plugin-cache staging
also rejects the invalid plugin shape or cleanup interval. File-mode startup or
reload likewise rejects the invalid file.

Before cutover, inspect every enabled `tcp_connection_throttle` in the cloned
database or staging config. Remove misspelled/obsolete fields, set the cleanup
interval to `0..=86400`, and either attach scoped policies only to TCP/TCP+TLS
proxies or add a supported TCP target for an enabled global policy. If the new
binary cannot accept the initial database snapshot, repair the row through the
old version's Admin API (preferably against the cloned database first), then
restart validation. For file mode, edit the YAML/JSON copy and run the staged
validation step again. Do not bypass the check by adding placeholder HTTP/UDP
targets; disable or remove a policy that has no TCP listener to protect.

### `kafka_logging` Fails Closed Under a Restrictive Egress Policy

`kafka_logging` is now refused at config admission whenever the backend egress
policy is able to deny any address — which includes the **default** posture
(`FERRUM_BACKEND_ALLOW_IPS=both` plus the dangerous-range baseline). librdkafka
resolves bootstrap hostnames itself and dials brokers advertised by cluster
metadata, and the pinned `rdkafka 0.39` exposes no connect/resolve callback, so
Ferrum cannot screen the addresses it actually connects to. The gateway refuses
the configuration rather than leaving an unenforced egress path.

Symptoms on upgrade: file mode fails startup; database/CP admin writes return
400; a data plane refuses the update and keeps its last accepted generation
(`kafka_logging` is `KeepLastKnownGood`).

Before cutover, inventory every enabled `kafka_logging` plugin row and choose
one of:

- **Recommended.** Move log shipping to a sink that dials through Ferrum's
  policy-aware path (`http_logging`, `tcp_logging`, `ws_logging`,
  `loki_logging`) and bridge to Kafka outside the gateway.
- Remove or disable the `kafka_logging` rows.
- Accept an unrestricted backend egress policy for the whole gateway
  (`FERRUM_BACKEND_ALLOW_IPS=both`, no `FERRUM_BACKEND_DENY_CIDRS`,
  `FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES=false`). This weakens every other
  outbound path — proxy backends, service discovery, and all other plugin
  endpoints — and the gateway logs an unrestricted-egress warning at startup.

Separately, `broker_list` is now parsed with librdkafka's exact
`[proto://]host[:port]` grammar. Two shapes that were previously accepted are
now rejected even under a fully-open policy: an unsupported or malformed
protocol prefix, and a protocol prefix that disagrees with `security_protocol`
(librdkafka would have discarded that entry and stopped parsing the rest of the
list, silently shrinking the broker set).

### Ambient Proxy Environment Is Ignored by Plugin Clients

Plugin outbound HTTP no longer honours `HTTP_PROXY`, `HTTPS_PROXY`,
`ALL_PROXY`, or `NO_PROXY` inherited from the process environment. Deployments
that relied on an ambient proxy to reach a log sink, AI provider, JWKS/OIDC
endpoint, webhook, or ClickHouse chargeback sink must point the plugin's
configured endpoint directly at the reachable destination instead.

### Body Validator Enforcement Hardening

`body_validator` now enforces the policy it advertises, which makes several
previously-accepted configurations fail closed. Because the plugin is
fail-closed, a rejected configuration keeps the last known-good generation:
database and control-plane publication rejects the row, a DP keeps its last
accepted snapshot, and file-mode startup or reload rejects the file. Audit every
`body_validator` config in the cloned database or staging config before cutover.

Configuration is now rejected when:

- an unknown top-level key is present (previously ignored), or a
  `protobuf_method_messages` entry contains any key other than `request` /
  `response`. Typos such as `response_json_scheam` or `respones` used to be
  silently dropped while the remaining valid rule kept admission succeeding.
- `json_schema` / `response_json_schema` is not a valid JSON Schema under the
  configured draft. Schemas are now compiled with the `jsonschema` crate at
  plugin construction instead of being interpreted by a partial evaluator, so
  malformed keyword shapes, invalid type names (`"type": "objcet"`), and invalid
  `pattern` regexes are configuration errors rather than no-ops.
- an actual schema position uses a non-local `$ref`/`$dynamicRef` (anything not
  starting with `#`), a non-fragment `$id` / `id`, a `$vocabulary` declaration,
  or a `$schema` naming a draft other than the configured one. Property and
  definition names with those spellings, and literal objects under `enum`,
  `const`, `default`, or `examples`, are not schema keywords unless a supported
  local URI-fragment JSON Pointer actually targets that object. Pointer targets
  are audited with percent-decoding and JSON Pointer escaping before compile,
  including targets under otherwise literal/unknown containers. No external
  reference is ever fetched: the dependency is built without HTTP or file
  retrievers.
- the complete supplied schema value nests deeper than 32 levels or contains
  more than 20000 JSON nodes. Literal and annotation data counts toward both
  budgets.
- `json_schema_draft` (new, default `draft2020-12`, also accepts `draft7`) has
  any other value. Draft-4 spellings such as a boolean `exclusiveMinimum` are
  rejected; convert them to the numeric draft-7/2020-12 form.

Runtime behavior also tightens:

- Standard keywords the old evaluator ignored are now enforced. `$ref`/`$defs`,
  array `type` unions, conditionals, and dependent keywords all take effect, so
  traffic a schema was always meant to reject now actually gets rejected.
  Draft 7 treats `definitions` as its ordinary definition container; `$defs`
  remains an unknown/literal value there unless a local pointer explicitly
  targets it. Draft 2020-12 follows both `$defs` and the validator library's
  compatible `definitions` map. `$dynamicRef` has reference semantics under
  Draft 2020-12 and remains an unknown, inert keyword under Draft 7.
- XML bodies are parsed by a real XML parser instead of a tag-balancing scan.
  Documents with multiple roots, text outside the root, invalid element or
  attribute names, unquoted or duplicated attributes, undeclared entity
  references, invalid characters, or non-XML Unicode whitespace outside the
  document are now rejected. The original body is parsed without trimming;
  legal XML space (`SP`, `TAB`, `CR`, `LF`) around the root remains accepted.
  `required_xml_elements` matches parsed element names: a bare name matches that
  local name in any namespace, `{uri}local` requires both, and `{}local`
  requires no namespace. A configured entry that previously relied on a raw
  `prefix:local` source match must be rewritten as `local` or `{uri}local`.
- External XML identifiers (`SYSTEM` / `PUBLIC`) on the DOCTYPE external subset
  or an entity declaration are always rejected. Internal DTD subsets remain
  supported under the entity count/nesting policy.
- Decoded gRPC protobuf messages must satisfy proto2 required-field
  initialization, recursively through present nested, repeated, map, and
  extension message values. proto3 descriptors are unaffected. Clients that
  relied on sending an uninitialized proto2 message must be fixed before
  upgrade.

### Retained-Response Replay Partition (breaking)

`response_caching`, `request_deduplication`, and `ai_semantic_cache` now share
one fail-closed replay-partition contract
(`plugins::utils::replay_partition`). Plan for four operational changes:

- **All three caches start cold after upgrade.** Key derivation changed in every
  plugin, so entries and idempotency records written by an earlier build are
  unreachable. That is deliberate: anything keyed under the weaker partition
  must not be replayable. Expect a transient origin-load spike proportional to
  your cache hit rate, and expect idempotency keys that were mid-flight across
  the upgrade to be re-executable exactly once.
- **`response_caching` accepts only bodyless retrieval methods.** A
  `cacheable_methods` list containing `POST`, `PUT`, `PATCH`, `DELETE`, or any
  other body-bearing method now fails admission in database, control-plane,
  data-plane, and file modes. Audit every enabled `response_caching` plugin row
  before cutover and reduce the list to `GET` / `HEAD`. At runtime, any request
  that declares a body (`Transfer-Encoding`, or a non-zero/unparsable
  `Content-Length`) bypasses lookup and storage.
- **Every caller is partitioned by canonical peer address.** The origin
  observes it through Ferrum's regenerated `X-Forwarded-For`, for authenticated
  callers as much as anonymous ones. The new `anonymous_caller_scope` option
  (default `caller_address`) lets you attest that a route's origin does not vary
  by caller address and restore the previous sharing with
  `anonymous_caller_scope: "shared"` — but that attestation covers **anonymous**
  callers only; authenticated callers always bind their address, and there is no
  opt-out. A caller whose canonical address cannot be derived bypasses the cache
  (and is not deduplicated).
- **`request_deduplication` moved from priority `2750` to `3010`.** It now runs
  after route dispatch and request-transformer header/query rules, so its
  logical key binds the effective destination and its fingerprint binds the
  outbound headers/query. It remains before terminate-mode
  `serverless_function`, preserving ownership before that external operation.
  Audit compositions and priority overrides: every same-protocol header/query
  mutator at or after deduplication is rejected. A deferred request-body
  transformer is also rejected because `before_proxy` cannot witness its final
  wire bytes; the exception is a transformer that proves its final output is
  exactly the body already produced by pre-`before_proxy` normalization. A
  plugin that still changes headers later remains incompatible even when its
  body normalization is observable. `mcp_gateway` remains incompatible because
  its skipped response rewrite depends on mutable live discovery state.
- **`ai_semantic_cache` lookup moved to the final-request-body stage, priority
  `2996` → `4057`.** Lookup previously ran in `before_proxy`, ahead of
  `request_transformer` (3000) and every `transform_request_body` hook, so the
  headers, query, and prompt bytes it keyed were *pre-transform* — not what the
  provider would receive — and a hit could bypass a fail-closed final-body
  validator. It now runs in `on_final_request_body_with_context`, after
  `ai_prompt_compressor` (4055) enforces its staged marker-sanitization
  rejection and before `ai_federation` (4060) performs provider I/O. Practical
  consequences:
  - keys change; every previously retained entry is unreachable (intended
    fail-closed outcome);
  - a request whose headers, query, or body a transform rewrites now keys on the
    rewritten form, so deployments running `request_transformer`,
    `compression` request decode, or `ai_prompt_compressor` alongside the cache
    will see a one-time key change and possibly a different hit distribution;
  - a `before_proxy` short-circuit that previously lost to a cache hit
    (`serverless_function` 3025, `response_mock` 3030) now wins, because it runs
    first;
  - a priority override that places an `ai_semantic_cache` instance at or before
    a co-located `ai_prompt_compressor` re-opens the bypass and should not be
    used.
- **`ai_semantic_cache` keys bind more of the request.** They now use the shared
  destination contract (which includes the proxy **namespace**, previously
  omitted) plus a backend-visible request-context digest covering the original
  client authority, the effective outbound query, and every non-credential
  request header. Deployments that varied only by header or query parameter and
  were previously sharing one completion will now miss. Only transport/hop-by-hop
  framing fields Ferrum provably regenerates for the backend hop are excluded;
  `Host`/authority is bound as its own field.
- **`response_caching` now binds the complete request context too.** The
  backend-effective query and every origin-visible request header are mandatory
  base-key dimensions, even when the origin omits a header from `Vary`.
  `cache_key_include_query: false` remains accepted only to rotate/partition
  legacy keyspaces; it no longer allows responses to be shared across
  origin-visible query values. The only header exemptions are operations this
  cache actually implements: `If-None-Match` / `If-Modified-Since`, zero-length
  `Content-Length`, and a pure bare, argument-free `no-cache` / `no-store`
  refresh while `respect_no_cache` is enabled. `Range`, unsupported
  preconditions, `Pragma`, mixed/arbitrary/argument-bearing request
  `Cache-Control`, and all request `Cache-Control` when `respect_no_cache` is
  disabled remain bound. The complete `Vary` tuple (backend-nominated
  dimensions, `vary_by_headers`, and mandatory credential/session auto-Vary)
  is an additional digest. Header/query priority overrides that run at or after
  `response_caching` and deferred request-body transformers now fail
  configuration admission. Expect a one-time key rotation and more conservative
  misses for requests whose headers previously shared one Vary-only partition.
  `Authorization`, `Proxy-Authorization`, and `Cookie` are mandatory Vary
  dimensions even when absent, so anonymous cache HITs now include those names
  in `Vary`; present values remain hashed.
  Authorization storage admission also checks both the pristine inbound and
  live backend-visible header views, so a transformer that removes or adds the
  field cannot bypass the origin shared-cache opt-in requirement.
- **GET/HEAD cache lookup now requires an observed empty upload.** Ferrum drains
  the complete H1/H2/H3 request body before cache lookup and bypasses when it is
  non-empty or cannot be proven empty. This closes H2/H3 GET-with-DATA replay
  even when no `Content-Length` is present. Expect those requests to reach the
  origin instead of receiving or populating a cached response.
- **Tracing and correlation request headers are now retained-cache key
  dimensions.** An earlier revision excluded `traceparent`, `tracestate`, `b3`,
  `X-B3-*`, `X-Request-Id`, `X-Correlation-Id` and friends from the shared
  request-header partition by reusing the *response*-cache sanitation classifier
  and arguing they are fresh "by construction". That proof does not hold on the
  request side: `correlation_id` preserves a valid client-supplied ID, the plugin
  may not be configured at all, and the value reaches the origin either way.
  Wherever that partition is used they are bound like any other backend-visible
  header, so a client that varies its trace header per request will now miss per
  request; `response_caching` now binds the same origin-visible fields directly
  in its base partition even when the origin does not nominate them in `Vary`.
  **Plan for this before enabling either retained cache alongside request
  tracing.** `otel_tracing` injects a `traceparent` carrying a freshly generated
  span ID into the backend-visible header map on *every* request (in both
  `trace_context_trust` modes, whenever `generate_trace_id` is `true`), and
  `correlation_id` injects a generated identifier whenever the client supplied
  none. Either one makes the response-cache base key and the semantic cache's
  exact/scope keys unique per request, so neither cache can hit; the semantic
  cache also pays for an embedding call and a store on every miss.
  `trace_context_trust: untrusted` does **not**
  help: it generates a fresh root rather than normalizing to a shared value. To
  keep either cache effective, run the cached route on a proxy that does not
  inject a per-request identifier (`otel_tracing` with
  `generate_trace_id: false` and no
  trusted inbound parent, or no `correlation_id` instance), or remove the
  identifier from the backend-visible view with a `request_transformer` header
  rule at priority `3000` — which also removes it from what the provider
  receives, so downstream propagation is lost. Response-header replay
  sanitation still strips trace identifiers from a retained response; that
  contract is unchanged.
- **`scope_by_consumer: false` and `cache_key_include_consumer` no longer
  disable caller isolation.** Every key now binds an authorization-context
  fingerprint (mechanism, identity, consumer, peer SPIFFE identity, and digests
  of the credentials presented), so two credentials that render as one display
  subject with different scopes never share a retained result. The credential
  registry includes configured custom header locations for `key_auth`,
  `jwt_auth`, `jwks_auth`, and `oauth2_introspection`; credential-bearing query
  parameters are privately digested before authentication or transformer
  stripping, even when `response_caching.cache_key_include_query` is `false`.
  Routes that intentionally shared entries across distinct credentials will see
  a lower hit rate; there is no opt-out, because that sharing was the
  vulnerability.

### Response Cache Shared-Storage Hardening

`response_caching` now applies RFC 9111 shared-cache rules that earlier
versions only applied partially. Three behaviors change:

- **Authorized requests need an explicit opt-in.** A request carrying an
  `Authorization` header is treated as authorized even when Ferrum itself
  performs no authentication (the common "forward the bearer token to a backend
  that validates it" topology). Such responses are stored only when the origin
  sends `Cache-Control: public`, `must-revalidate`, or `s-maxage`.
  `cache_key_include_consumer` no longer overrides this origin policy; it only
  changes cache-key partitioning. Deployments that relied on caching
  backend-authenticated responses under a plain `max-age` will see those routes
  go to the origin every time. Restore caching by adding an appropriate origin
  directive so backend revocation and scope changes remain authoritative.
- **Qualified `private` / `no-cache` field lists are enforced.** Fields named by
  `private="x-account"` / `no-cache="x-secret"` are dropped from the stored
  entry, and a malformed qualified argument (unquoted, unterminated, empty, or
  not a valid field name) refuses the whole response. Origins that emit such
  headers will see those routes become uncacheable until the header is
  well-formed.
- **`cacheable_status_codes` no longer accepts `1xx`, `206`, or `304`.** Config
  load fails closed on those values in database, control-plane, data-plane, and
  file modes. Before cutover, inspect every enabled `response_caching` plugin
  row and remove them; a `206` or `304` entry could previously be replayed to
  later unconditional requests as a truncated or empty representation. A `2xx`
  response carrying `Content-Range` is now refused at store time as well.

### Chargeback Scrape Authentication

`GET /charges` now requires an admin JWT. Update Prometheus or external billing
collectors that scrape this endpoint to send `Authorization: Bearer <token>`
(for example, Prometheus `bearer_token_file`) before upgrading. Observability
endpoints are also tiered by default now: `/metrics` returns `401` unless the
caller presents an admin JWT, a matching `FERRUM_METRICS_BEARER_TOKEN`, or a
source IP in `FERRUM_METRICS_ALLOWED_CIDRS`; `/health`, `/status`, and
`/overload` return only a coarse status/level summary unauthenticated and full
diagnostics only to an authenticated caller; `/live` stays unauthenticated and
minimal. Update any collector that scrapes `/metrics` (or that relies on full
`/health` / `/status` / `/overload` detail) to authenticate before upgrading.

#### 4. Cut Over Production

Once validation passes, stop the old binary and start the new one against the production database. The new binary will run any pending migrations automatically on startup (or you can run them explicitly first with `FERRUM_MODE=migrate`).

```bash
# Option A: Let the new binary auto-migrate on startup
# Stop old binary, then:
FERRUM_MODE=database \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db \
  ./ferrum-edge-new

# Option B: Explicit migration then start
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db \
  ./ferrum-edge-new

FERRUM_MODE=database \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db \
  ./ferrum-edge-new
```

#### 5. Rollback Path

If issues arise after cutting over:

1. **Stop** the new binary
2. **Restore** the original database from the backup taken in step 1:
   ```bash
   # PostgreSQL
   dropdb -h db-host -U ferrum ferrum_db
   createdb -h db-host -U ferrum ferrum_db
   pg_restore -h db-host -U ferrum -d ferrum_db ferrum_backup_v1.dump

   # MySQL
   mysql -h db-host -u ferrum -p -e "DROP DATABASE ferrum_db; CREATE DATABASE ferrum_db"
   mysql -h db-host -u ferrum -p ferrum_db < ferrum_backup_v1.sql

   # SQLite
   cp ferrum_original.db ferrum.db
   ```
3. **Restart** the old binary against the restored database

The old binary + old database is a fully consistent state. No data is lost.

> **Important**: Schema migrations are forward-only. You cannot run the old binary against a database that has been migrated to a newer schema. Always restore from the pre-migration backup when rolling back.

---

## Control Plane / Data Plane Mode (`FERRUM_MODE=cp` / `dp`)

CP/DP upgrades follow the same database strategy for the CP, with the added consideration of rolling out DP nodes. The key property that makes this safe: **DPs cache their config in memory and continue serving traffic even if the CP is temporarily unavailable.**

### Helm Chart Runtime Defaults

The `charts/ferrum-mesh` chart no longer enables CP, injector, or CA runtime
Deployments by default. A default install is scaffolding-only until you opt into
the desired component. This prevents a fresh default Helm install from rendering
a CP pod that immediately fails startup because `FERRUM_DB_TYPE`,
`FERRUM_DB_URL`, `FERRUM_ADMIN_JWT_SECRET`, and
`FERRUM_CP_DP_GRPC_JWT_SECRET` are absent.

Before upgrading an existing Helm install that relied on the old defaults, set
the component switches and move reserved CP settings into the new structured
values:

```yaml
controlPlane:
  enabled: true
  database:
    type: postgres
    existingSecret:
      name: ferrum-mesh-production-db
      urlKey: url
  credentials:
    adminJwtSecret:
      existingSecret:
        name: ferrum-mesh-production-credentials
        key: admin-jwt-secret
    cpDpGrpcJwtSecret:
      existingSecret:
        name: ferrum-mesh-production-credentials
        key: cp-dp-grpc-jwt-secret
```

Do not keep `FERRUM_DB_TYPE`, `FERRUM_DB_URL`, `FERRUM_ADMIN_JWT_SECRET`, or
`FERRUM_CP_DP_GRPC_JWT_SECRET` under `controlPlane.env`; Helm validation now
rejects those reserved entries with a template-time error.

### Version Negotiation (Built-In Safety Net)

Starting in v0.9.0, CP and DP nodes exchange their Ferrum Edge binary version during gRPC handshake. Versions are parsed as **SemVer**. The **major and minor** components must match — patch-level differences (e.g., `0.9.0` vs `0.9.1`) are allowed. **Prerelease policy:** prerelease (`-rc.1`) and build metadata (`+git`) are ignored for compatibility; only major.minor are compared, so `0.9.0-rc.1` is compatible with `0.9.0` and `0.9.3`. Empty or malformed versions are rejected on both CP admission (`FailedPrecondition`) and DP ConfigUpdate processing. Every ConfigUpdate envelope — FULL_SNAPSHOT, DELTA, or negotiated heartbeat — must carry a valid compatible CP version.

| CP Version | DP Version | Result |
|------------|------------|--------|
| `0.9.0` | `0.9.0` | Allowed |
| `0.9.0` | `0.9.3` | Allowed (patch difference) |
| `0.9.0` | `0.9.0-rc.1` | Allowed (prerelease ignored for major.minor gate) |
| `0.9.0` | `1` / `garbage` / `` | **Rejected** — missing or malformed SemVer |
| `0.9.0` | `0.10.0` | **Rejected** — DP Subscribe/GetFullConfig fails with `FAILED_PRECONDITION` |
| `1.0.0` | `0.9.0` | **Rejected** — major version mismatch |

What happens on rejection:
- The **CP** returns a gRPC `FAILED_PRECONDITION` status with a message identifying both versions and the required DP version.
- The **DP** logs the error, disconnects, and enters the standard exponential-backoff/failover loop. It will keep failing until upgraded to a compatible version.
- **No config is exchanged** — the DP continues serving traffic with whatever config it had cached before the connection attempt.

This prevents a scenario where a newer CP pushes config containing fields or structures that an older DP cannot deserialize, which could cause silent data loss or deserialization failures.

You can verify versions via the authenticated `GET /admin/metrics` endpoint on any node — the `gateway.ferrum_version` field reports the running binary version.

### Upgrade Order

Always upgrade in this order: **CP first, then DPs.** The CP manages the database and schema migrations. DPs are stateless proxies that receive config via gRPC. Version negotiation ensures that if you forget to upgrade a DP, it will refuse the incompatible config rather than silently applying a partial parse.

### Mixed-Version Wire Compatibility (Patch-Level Rollouts)

Because patch-level differences are allowed, a CP-first rollout necessarily runs
mixed CP/DP patch versions for a while. Two ConfigSync surfaces are explicitly
built to survive that window without config churn.

**ConfigSync heartbeats are negotiated, never assumed.** A DP advertises
`SubscribeRequest.supports_heartbeat`, and the CP confirms with
`ConfigUpdate.heartbeat_negotiated` on the first message of the stream. Both are
additive protobuf fields, so peers that predate them read `false` and safely
ignore them.

| CP | DP | Behavior |
|----|----|----------|
| New | New | CP sends heartbeat frames; DP arms the 150s application silence watchdog |
| New | Legacy | DP never advertises support, so the CP sends **no** heartbeat frames — the legacy DP never sees an empty envelope and never churns |
| Legacy | New | CP never confirms, so the DP does **not** arm the silence watchdog — no reconnect the legacy CP was never asked to prevent. HTTP/2 PING and TCP keepalive still cover the stream |

**Delta removal keys stay wire-compatible in both directions.** Incremental
DELTA bodies carry namespace-qualified removals (so a misrouted delta cannot
delete a same-ID resource in another namespace) without breaking older peers:
the historical `removed_proxy_ids` / `removed_plugin_config_ids` /
`removed_upstream_ids` arrays keep their bare-ID string shape, and the
namespace-qualified `(namespace, id)` objects travel in **additive**
`removed_*_keys` arrays that older DPs ignore. Decoding accepts either shape. A
delta from a CP that only sent bare IDs is scoped to the DP's own already
authorized subscription namespace, and the DP's namespace filter still drops
anything outside it — so the cross-namespace deletion guarantee holds on both
new/new and mixed pairs.

Neither surface requires operator configuration, and neither changes behavior
for new/new fleets. Still complete the CP-first, then DP rollout promptly.

### Step-by-Step

#### 1. Backup the CP Database

Same as database mode step 1 — clone the CP's database.

#### 2. Validate New CP Against Cloned Database

Run the new CP binary against the cloned database on staging ports:

```bash
FERRUM_MODE=cp \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db_upgrade \
  FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50052 \
  FERRUM_ADMIN_HTTP_PORT=9100 \
  FERRUM_ADMIN_JWT_SECRET=change-me-to-a-32-character-admin-secret \
  FERRUM_CP_DP_GRPC_JWT_SECRET=change-me-to-a-32-character-grpc-secret \
  ./ferrum-edge-new
```

Optionally connect a test DP to the staging CP to verify the full gRPC config sync pipeline:

```bash
FERRUM_MODE=dp \
  FERRUM_DP_CP_GRPC_URLS=http://cp-host:50052 \
  FERRUM_CP_DP_GRPC_JWT_SECRET=change-me-to-a-32-character-grpc-secret \
  FERRUM_PROXY_HTTP_PORT=8100 \
  FERRUM_ADMIN_HTTP_PORT=9200 \
  FERRUM_ADMIN_JWT_SECRET=change-me-to-a-32-character-admin-secret \
  ./ferrum-edge-new
```

Verify the test DP receives the full config snapshot and proxies traffic correctly.

#### 3. Upgrade the Production CP

Stop the old CP, run migrations against the production database, and start the new CP.

During the CP restart window, existing DPs continue serving traffic with their cached config. No downtime for API consumers.

```bash
# Stop old CP, then:
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=up \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db \
  ./ferrum-edge-new

FERRUM_MODE=cp \
  FERRUM_DB_TYPE=postgres \
  FERRUM_DB_URL=postgres://ferrum:pass@db-host/ferrum_db \
  FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051 \
  FERRUM_ADMIN_JWT_SECRET=change-me-to-a-32-character-admin-secret \
  FERRUM_CP_DP_GRPC_JWT_SECRET=change-me-to-a-32-character-grpc-secret \
  ./ferrum-edge-new
```

#### 4. Rolling Upgrade of DPs

Upgrade DP nodes one at a time (or in batches). Each DP reconnects to the CP on startup and receives a fresh config snapshot.

```bash
# On each DP node, stop old binary and start new:
FERRUM_MODE=dp \
  FERRUM_DP_CP_GRPC_URLS=http://cp-host:50051 \
  FERRUM_CP_DP_GRPC_JWT_SECRET=change-me-to-a-32-character-grpc-secret \
  FERRUM_ADMIN_JWT_SECRET=change-me-to-a-32-character-admin-secret \
  ./ferrum-edge-new
```

If a load balancer sits in front of the DP fleet, drain each node before restarting to avoid dropping in-flight requests.

#### Multi-CP Failover Deployments

When DPs are configured with `FERRUM_DP_CP_GRPC_URLS` (multiple CPs), upgrades are smoother:

1. Upgrade CP₁ first (DPs automatically fail over to CP₂ during the restart window)
2. Upgrade CP₂ (DPs fail back to CP₁ which is already running the new version)
3. Rolling upgrade DPs as above

This eliminates the read-only window during CP upgrades — DPs always have at least one CP available for config updates.

```bash
# DP configured for multi-CP failover:
FERRUM_MODE=dp \
  FERRUM_DP_CP_GRPC_URLS=https://cp1:50051,https://cp2:50051 \
  FERRUM_CP_DP_GRPC_JWT_SECRET=change-me-to-a-32-character-grpc-secret \
  FERRUM_ADMIN_JWT_SECRET=change-me-to-a-32-character-admin-secret \
  ./ferrum-edge-new
```

#### 5. Rollback Path

- **DP rollback**: Stop the new DP binary, restart the old one. It reconnects to the CP and gets the current config via gRPC. DPs are stateless — rollback is instant.
- **CP rollback**: Stop the new CP, restore the database from backup (step 1), restart the old CP. All DPs will reconnect and receive the old config. During the CP restart, DPs serve cached config.

> **Note**: If the new CP has already broadcast a migrated config to DPs, rolling back the CP means DPs will receive the old-schema config on reconnect. Since DPs are always overwritten by the CP's config on connect, this is safe — the old config format replaces whatever the DP had cached.

---

## File Mode (`FERRUM_MODE=file`)

File mode is the simplest to upgrade because there's no database. The config file is read at startup and on SIGHUP reload (Unix). Both reads require a stable regular-file snapshot (byte-identical consecutive probes with matching path identity) and fail closed on torn in-place writes; SIGHUP keeps the last known-good generation. Publish config updates with atomic rename (or ConfigMap symlink swap), not save-in-place / shell redirection onto the live path — see [configuration.md](configuration.md#file-mode). The risk on version upgrades is that a new Ferrum version might interpret existing config fields differently or require new fields.

### Step-by-Step

#### 1. Backup Your Config File

```bash
cp config.yaml config.yaml.backup-v1
```

#### 2. Run Config Migration (If Needed)

New Ferrum versions may introduce a new config file version. Use migrate mode to update your file:

```bash
# Dry run — see what would change
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=config \
  FERRUM_MIGRATE_DRY_RUN=true \
  FERRUM_FILE_CONFIG_PATH=./config.yaml \
  ./ferrum-edge-new

# Apply migration (creates a timestamped .backup automatically)
FERRUM_MODE=migrate \
  FERRUM_MIGRATE_ACTION=config \
  FERRUM_FILE_CONFIG_PATH=./config.yaml \
  ./ferrum-edge-new
```

Even if no version bump is required, the new binary will auto-migrate the config in memory on startup and log a warning if the on-disk version is behind.

#### 3. Validate the New Version

Start the new binary on non-production ports pointing at the (possibly migrated) config file:

```bash
FERRUM_MODE=file \
  FERRUM_FILE_CONFIG_PATH=./config.yaml \
  FERRUM_PROXY_HTTP_PORT=8100 \
  FERRUM_PROXY_HTTPS_PORT=8543 \
  FERRUM_ADMIN_HTTP_PORT=9100 \
  FERRUM_LOG_LEVEL=info \
  ./ferrum-edge-new
```

Validate:

- **Health check**: `curl http://localhost:9100/health`
- **Config loaded**: `curl http://localhost:9100/proxies` — verify all routes are present
- **Proxy traffic**: send test requests through port 8100
- **Logs**: look for deprecation warnings or config parsing errors

#### 4. Cut Over

Stop the old binary, start the new one on production ports:

```bash
FERRUM_MODE=file \
  FERRUM_FILE_CONFIG_PATH=./config.yaml \
  ./ferrum-edge-new
```

#### 5. Rollback Path

1. Stop the new binary
2. Restore the config backup: `cp config.yaml.backup-v1 config.yaml`
3. Restart the old binary

---

## General Recommendations

### Pre-Upgrade Checklist

- [ ] Read the release notes for breaking changes, deprecated fields, and new required fields
- [ ] Back up your database (database/CP modes) or config file (file mode)
- [ ] Back up your `ferrum.conf` if you use one — new versions may add env vars with different defaults
- [ ] Use `GET /backup` to capture a logical config snapshot (database/CP modes)
- [ ] Run migrations in dry-run mode before applying
- [ ] Validate the new version on non-production ports before cutting over

### Version Compatibility

| Component | Forward Compatible? | Backward Compatible? |
|-----------|-------------------|---------------------|
| Database schema | Yes (auto-migrates forward) | No (old binary cannot read new schema) |
| Config file format | Yes (auto-migrates in memory) | Depends on version gap |
| gRPC protocol (CP↔DP) | Same major.minor required (enforced at connect time) | Same major.minor required |
| Admin API | Generally stable | Check release notes |

### Downtime Expectations

| Mode | Upgrade Downtime | With Load Balancer |
|------|-----------------|-------------------|
| Database (single instance) | Brief (binary restart) | Near-zero (drain + restart) |
| CP/DP | Zero for API consumers | Zero (rolling DP restart) |
| File (single instance) | Brief (binary restart) | Near-zero (drain + restart) |

### Environment Variable Changes

New Ferrum versions may introduce new `FERRUM_*` environment variables. Review `ferrum.conf` in the release for new defaults.

### Process Logging Buffer Bounds

The process logging writer now defaults to 4,096 admitted records per sink
instead of the former 128,000-line channel and adds a 32 MiB aggregate byte
budget plus a 64 KiB per-record limit. Stdout runtime events and
`stdout_logging` access records share one sink; stderr has an independent sink
with the same bounds. Existing `FERRUM_LOG_BUFFER_CAPACITY=128000` settings are
applied as 65,536, the current maximum, and emit a startup warning rather than
being changed silently.

Admission still reserves the maximum record size before serializing untrusted
data. After serialization succeeds, the reservation shrinks to the actual
record length and remains charged until the worker finishes writing it. Size
`FERRUM_LOG_BUFFER_CAPACITY` and `FERRUM_LOG_BUFFER_BYTES` together: raising the
record limit is ineffective if actual outstanding bytes plus the provisional
maximum-record reservation reach the byte budget first. Monitor the
authenticated log-sink diagnostics and `ferrum_log_sink_*` metrics before and
after rollout for saturation, oversize, writer, flush, and drain failures.

### Logging Metadata Redaction

Transaction metadata is redacted at serialization time before any built-in logger sink writes it. Keys matching built-in sensitive substrings such as `authorization`, `cookie`, `password`, `secret`, or `token` now serialize as `[REDACTED]`; use `FERRUM_LOG_REDACT_METADATA_KEYS` to add operator-specific substrings. The in-memory metadata map is unchanged for plugin logic.
