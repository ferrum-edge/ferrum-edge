# API Chargeback Sink Plugin

`api_chargeback_sink` exports durable charge events to ClickHouse. It is a sibling
to `api_chargeback`: use either plugin independently, or run both when you want
the existing in-memory `/charges` view plus a durable event stream.

## Durability Contract

Durable (default) export treats a charge event as delivered only after ClickHouse
returns HTTP 200 or 204 **and** a complete, empty acknowledgement body with no
`X-ClickHouse-Exception-Code` header and no exception markers in the body.
HTTP status alone is never treated as proof of success: ClickHouse can return
200 with an exception in the body, and incomplete drains are ambiguous.

Recommended async-insert settings wait for persistence:

```json
"insert_query_params": { "async_insert": "1", "wait_for_async_insert": "1" }
```

When `async_insert` is enabled and `wait_for_async_insert` is omitted, the sink
pins `wait_for_async_insert=1` on the request instead of inheriting a potentially
lossy ClickHouse user/profile default.

### Credentials and `insert_query_params`

ClickHouse accepts `user`, `password`, and `access_token` as HTTP query
parameters. Ferrum does **not** support authenticating that way: parameter names
that carry a reusable credential are rejected at configuration time. The
rejected set is the exact names `user`, `password`, `access_token`, and
`session_id`, plus any name containing `apikey`, `api_key`, `credential`,
`passwd`, `secret`, or `token`.

Use `clickhouse.username` together with `clickhouse.password_ref` instead.
`password_ref` names a `FERRUM_*` environment variable; the resolved value is
sent as an HTTP Basic `Authorization` header, so it is never appended to a URL
and never rendered in diagnostics.

Parameter *values* remain arbitrary bounded strings (ClickHouse settings are
operator tuning), so the sink never renders the INSERT query string. Every
diagnostic path — literal-IP egress denial, DNS/TLS/connect failure, retry,
slow-call warning, custom-TLS client failure, and spool replay/flush errors —
records only a structurally redacted `scheme://host:port/redacted` form. The
complete INSERT URL is used solely to build the outbound request. `clickhouse.url`
also rejects userinfo credentials (`https://user:pass@host`), and the admin API's
audit projection redacts both `clickhouse.url` and every
`insert_query_params` value.

`wait_for_async_insert=0` (and equivalent falsy values `false` / `no` / `off`)
is rejected unless `clickhouse.allow_lossy_async_insert` is explicitly `true`.
That named opt-in is intentionally separate from durable mode: ClickHouse may
acknowledge a buffered async insert before it is persisted, so a later flush
failure or crash can lose rows that the sink already counted as exported and
removed from the spool. Use it only when that loss is acceptable.

Spool replay deletes a file only after an unambiguous persistence-aware success
result under the durable contract (or after the same complete empty ACK when the
lossy opt-in is enabled). Timeouts, incomplete acknowledgement drains, and other
ambiguous outcomes keep the spool file and retry with unchanged `event_id`
values so `ReplacingMergeTree` deduplicates duplicate-safe retries.

## Modes

`mode: per_event` emits one `ChargeEvent` for each chargeable HTTP-family
transaction, stream disconnect, or WebSocket disconnect. This preserves
transaction-level provenance and is the default.

`mode: snapshot` keeps a local accumulator whose **identity** is every
exported categorical field on the resulting `ChargeEvent`:

- `namespace`
- `consumer_id`
- `consumer_name` (empty segment when absent)
- `proxy_id`
- `proxy_name`
- `route_id` (empty segment when absent)
- billable `status_code`
- raw `http_status_code` (empty when absent, e.g. stream/WebSocket)
- final `grpc_status` (empty when absent; non-standard codes collapse to a
  bounded sentinel)
- `protocol` (`http`, `grpc`, `ws`, stream protocol labels, etc.)

**Identity fields are never prefix-truncated (GHSA-m28c-f3v5-26qg).** Every
field above is bounded, but a bound that kept only a prefix would merge two
distinct authenticated principals sharing that prefix into one accumulator entry
and one exported `consumer_id` — one invoice covering two customers. A verified
external identity above 512 bytes is rejected at authentication, and any value
that still needs bounding here (for example a long operator-configured Consumer
username or display name) is stored as a readable prefix plus a
domain-separated SHA-256 digest of the complete value: `<prefix>~sha256:<hex>`.
That mapping is injective, so two identities collide only on a SHA-256
collision. A within-bound value that itself contains the `~sha256:` marker is
also stored in digest form, so a representation cannot be replayed as a short
identity to land in another principal's row. The original of a digested value
must be resolved at the identity provider; the gateway does not retain
oversized credential-derived identities.

Delta emission, last-emitted bookkeeping, and stale-entry cleanup all use this
same key. Display-name changes (consumer or proxy rename on reload) and
distinct routes or protocols therefore produce separate snapshot rows instead of
silently labeling a mixed aggregate with the first record's metadata.
`request_id` and `trace_id` are omitted from snapshot events (they are
per-transaction only). Every `snapshot.interval_secs`, the sink emits deltas
since the last snapshot. Use this when event volume dominates ingest cost and
aggregate reconciliation is sufficient. Snapshot mode requires
`spool.enabled: true` because the accumulator advances only after a delta is
written to the spool; the queue is an additional low-latency delivery attempt,
not the durability boundary. Idle snapshot keys are eligible for eviction after
`snapshot.stale_entry_ttl_secs` (which must be `>= snapshot.interval_secs`) and
are checked every `snapshot.cleanup_interval_secs`, but cleanup never removes a
key whose current totals still exceed its last durable baseline. Pending or
never-emitted charges therefore survive first-tick races and prolonged spool
outages. Hard `snapshot.max_entries` and `snapshot.max_retained_bytes` budgets
bound accumulator memory; new identities beyond those budgets are spooled as
per-event rows through the bounded async spool delivery worker (never inline on
the terminal hook), or staged within the same retained-byte budget for the next
durable emission, rather than merged into unrelated keys. The overflow-spooled
counter advances only after the delivery worker's blocking write genuinely
lands; a full/closed delivery queue or a failed write re-stages the exact event
within the retained-byte budget. If both durable handoff and bounded staging are
exhausted, the sink records an explicit cardinality rejection counter instead of
growing memory without bound.

### Snapshot concurrency contract

Request-path `record`, periodic delta emission, and stale cleanup share the
accumulator without a global request-path lock (per-key DashMap shard locking
only):

- A new identity reserves one entry slot and its estimated retained bytes
  against the hard `max_entries`/`max_retained_bytes` ceilings (atomic CAS, no
  global lock) **before** the key is published. Retained bytes are a single
  combined counter shared with staged overflow, so concurrent identity admission
  and overflow staging can never exceed the byte ceiling. A losing same-key
  inserter releases its reservation and refreshes the winner exactly once, so a
  new-key/refresh race can never pin state above the configured ceilings or
  double-charge a slot.
- The same reservation is taken a second time against the **process-wide**
  retained-byte ceiling (`FERRUM_LOG_DELIVERY_MAX_RETAINED_BYTES`), in lockstep
  with the per-instance counter. `max_retained_bytes` bounds one accumulator;
  the process ceiling bounds the sum across every configured instance and every
  pending snapshot generation, so N instances cannot multiply past the
  advertised process total. Eviction, overflow drain, compaction clear, and drop
  each release exactly what they took; releases are saturating, so a double
  release cannot underflow the shared counter.
- Every projection built from the accumulator — the periodic delta emission, the
  final emission, and the Full→Compact compaction payload — reserves its own
  process-wide charge **before** it is allocated, because it coexists with the
  still-charged accumulator. A refusal is retryable: no baseline is advanced and
  no pending delta is discarded. Compaction transfers that reservation to the
  compact recovery entry, which holds it until the pending deltas are durably
  spooled or the entry is dropped. A compact retry takes ownership of the
  pending set rather than cloning it, and restores it unconditionally if the
  handoff fails; the recovery mutex is never held across filesystem work.
- Each accumulator slot has a stable **generation** (assigned at insert) and a
  **revision** that bumps on every refresh. Stale cleanup may scan candidates
  first, but eviction is a single conditional `remove_if`: the entry is removed
  only when generation, revision, `last_seen_at`, and a zero pending delta
  (current totals equal the last durable baseline for that generation) still
  match the stale observation. A same-key refresh that races after the stale
  check wins and remains available for the next snapshot. Unemitted or
  uncommitted totals are never TTL-evicted.
- `last_emitted` baselines are tagged with the entry generation. Cleanup drops a
  baseline only for the generation that was actually evicted, so a concurrent
  reinsert cannot lose a newer baseline. Delta emission ignores a baseline whose
  generation does not match the live entry (treats the live entry as starting
  from zero) and publishes a new baseline only while that generation is still
  present, so emission and cleanup cannot orphan or double-subtract totals
  across a remove/reinsert.
- Each accumulator has exactly one periodic snapshot task and therefore one
  delta emitter. Before that emitter advances a baseline, it writes the exact
  snapshot events to the required spool. It then enqueues the same event IDs as
  a low-latency ClickHouse attempt; spool replay remains the durable path and
  `ReplacingMergeTree` makes the duplicate-safe attempts idempotent. This
  single-emitter ownership prevents same-generation baseline publication from
  being reordered; request-path recorders remain concurrent with that emitter
  and cleanup.
- Unrelated keys never block each other on the request path.

### Snapshot generation shutdown

Every committed snapshot generation owns an explicit shutdown lifecycle. A
successful config replacement and graceful shutdown in database, file,
data-plane, and mesh modes stop admission to the old generation, wait for
already-entered record hooks, and then await its snapshot task. The task
computes the final delta and writes it directly to the required spool before
the accumulator baseline advances or the generation is released. This direct
handoff bypasses both the ClickHouse request path and the bounded in-memory
logger queue, so an unavailable endpoint or queue pressure cannot wedge reload
or shutdown.

Shutdown wins a simultaneous timer selection. If a periodic tick has already
durably spooled its events and advanced the baseline, the final handoff
observes a zero delta; if shutdown wins first, the final spool write advances
that same baseline. Thus one path, but never both, owns each pending delta.
The periodic queue attempt may still be in flight during reload, but it uses
the same event IDs as the durable spool rows, so aborting it cannot lose the
delta and successful duplicate delivery cannot double-charge it. Repeated
finalization is idempotent, and record hooks arriving after admission closes
are ignored.

Spool write failure leaves the generation unfinalized. After the bounded
finalization deadline the sink reduces failed generations to a compact recovery
payload (pending terminal deltas plus a spool handle) instead of retaining the
full accumulator/runtime indefinitely. Compaction never clears, replaces, or
unregisters a full generation until admission is closed and every already
admitted terminal hook has released its guard (`in_flight == 0`); until that
drain is observed the Full generation is retained untouched and a later
compaction pass retries, so an in-flight record can never race the accumulator
clear. Compaction also takes the generation's emission lock — the same lock the
periodic and final snapshot emitters hold across their prepare → durable spool →
advance-baseline sequence — and holds it from preparing the compact payload
through publishing Compact ownership and clearing Full state. Emission and
compaction are therefore mutually exclusive owners of the pending deltas, so a
still-running emitter cannot durably advance the baseline inside the window
where compaction has already snapshotted those deltas and the same charge cannot
be emitted twice. Every compaction refusal releases that lock, restores the
staged overflow it borrowed, and leaves the periodic emitter running. Once
mapped, Compact owns that
generation's recovery: later Full finalize/Drop paths must follow the registry
mapping and must not treat a cleared accumulator as an empty successful
finalization that unregisters Compact. Every later multi-threaded reload retries
all older retained full and compact recoveries concurrently with the generation
being retired, and graceful shutdown retries the complete registry. Pending
recovery count/bytes and oldest age are exposed on
`GET /charges/sink/status` and Prometheus, together with an explicit recovery
policy: restore spool writability; compact recoveries retry on reload/shutdown;
new snapshot generations fail closed while the pending recovery budget is
exhausted. The failure is also reported through the sink
failure/spool-availability metrics and status. Because snapshot mode requires
the spool, operators should treat an unwritable or exhausted spool as a
billing-durability incident and restore it before terminating the process.

Both modes use the same pricing fields as `api_chargeback`. At least one
nonempty pricing dimension is mandatory and matches
`PricingConfig::has_any_pricing`: a nonempty `pricing_tiers` list, bandwidth
pricing with at least one strictly positive per-byte rate, or
`stream_connection_pricing` with a strictly positive `price_per_connection`.

`request_mirror` shadow summaries (`mirror: true`) still reach the sink log
hook for observability/correlation with other logging plugins, but they are
never consumer-billable. Per-event and snapshot exports charge only the
primary client-facing HTTP summary; WebSocket and stream accounting are
unchanged.

Every unit price is an IEEE-754 binary64 value that must be finite,
non-negative, and at most `1e288`. Per-event mode multiplies each transaction's
`u64` quantities by those binary64 prices; snapshot mode accumulates the same
finite event charges and emits non-negative deltas. Integer quantities above
2^53 follow normal binary64 conversion rounding, and Ferrum applies no extra
decimal or currency-subunit rounding. The shared bound keeps every supported
per-event or snapshot counter state finite. As a final fail-closed guard,
JSONEachRow serialization rejects non-finite monetary fields, and snapshot
arithmetic reports a metered export failure instead of silently substituting a
zero delta.

- `pricing_tiers` for HTTP-family per-call pricing by billable status. Ordinary
  HTTP uses its wire status. Native gRPC and translated gRPC-Web use the final
  normalized `grpc-status` mapped to Ferrum's canonical effective HTTP status:
  `0→200`, `1→499`, `2→500`, `3→400`, `4→504`, `5→404`, `6→409`, `7→403`,
  `8→429`, `9→400`, `10→409`, `11→400`, `12→501`, `13→500`, `14→503`,
  `15→500`, and `16→401`. Missing, malformed, and unknown terminal statuses
  fail closed to the `500` billing bucket.
- `bandwidth_pricing` for client-to-backend and backend-to-client bytes.
- `stream_connection_pricing` for TCP, TCP+TLS, UDP, and DTLS sessions.

## Admission Layers

Admin, file-mode, and CP-DP admission share the OpenAPI
`ApiChargebackSinkConfig` contract plus the plugin constructor
(`ApiChargebackSink::new` / `validate_plugin_config`). OpenAPI requires
`config`, `clickhouse.url`, at least one valid pricing dimension, snapshot
mode with `spool.enabled=true`, and compatible `password_ref`/TLS settings.
Constructor validation additionally enforces relationships OpenAPI 3.1 cannot
express safely (notably `retry.max_delay_ms >= retry.initial_delay_ms` and the
600000 ms worst-case cumulative inter-attempt delay budget),
spool directory privacy, ClickHouse egress screening, that a nonempty
`password_ref` names a set `FERRUM_*` environment variable, and that
`wait_for_async_insert` falsy values require
`clickhouse.allow_lossy_async_insert=true`.

## ClickHouse Setup

Apply the reference DDL before enabling the plugin:

```bash
clickhouse-client < migrations/clickhouse/0001_charges.sql
```

The DDL creates `ferrum.charges_raw` with `ReplacingMergeTree` idempotency on
`event_id`, plus hourly, daily, and monthly views that read from
`charges_raw FINAL`. `call_count` is `UInt64` so snapshot deltas that exceed
`UInt32` capacity remain lossless. The views trade query cost for correctness:
duplicate raw events are deduplicated before rollup aggregation. Monetary
`charge` columns in those views are grouped by `currency` and `pricing_version`
(in addition to namespace/consumer/proxy/time) so mixed-currency or
multi-generation sinks never produce unitless rollups.

For HTTP-family events, `status_code` is the billable status used for pricing
and rollups. `http_status_code` preserves the transport status, and
`grpc_status` preserves the normalized final application code when the request
was native gRPC or translated gRPC-Web. Stream and WebSocket-disconnect events
leave both raw-status columns null. This keeps transport and application
outcomes auditable even when several gRPC codes share one effective billing
bucket.

## Example Config

```json
{
  "name": "api_chargeback_sink",
  "config": {
    "mode": "per_event",
    "pricing_tiers": [
      { "status_codes": [200, 201, 202], "price_per_call": 0.00001 }
    ],
    "bandwidth_pricing": {
      "price_per_byte_sent": 0.000000001,
      "price_per_byte_received": 0.000000002
    },
    "stream_connection_pricing": { "price_per_connection": 0.0001 },
    "clickhouse": {
      "url": "https://clickhouse.internal:8443",
      "database": "ferrum",
      "table": "charges_raw",
      "username": "ferrum_ingest",
      "password_ref": "FERRUM_CLICKHOUSE_PASSWORD",
      "insert_query_params": { "async_insert": "1", "wait_for_async_insert": "1" },
      "timeout_ms": 5000
    },
    "batch": { "size": 500, "flush_interval_ms": 2000, "buffer_capacity": 50000, "buffer_max_bytes": 16777216 },
    "retry": { "max_attempts": 5, "initial_delay_ms": 250, "max_delay_ms": 10000, "jitter": true },
    "spool": {
      "enabled": true,
      "dir": "/var/lib/ferrum/chargeback-spool",
      "max_bytes": 10737418240,
      "replay_interval_secs": 60,
      "delivery_queue_capacity": 4096,
      "compression": "zstd"
    },
    "snapshot": {
      "interval_secs": 30,
      "cleanup_interval_secs": 300,
      "stale_entry_ttl_secs": 3600,
      "max_entries": 100000,
      "max_retained_bytes": 67108864,
      "emit_zero_deltas": false
    },
    "pricing_version": "2026-01-rev3",
    "currency": "USD"
  }
}
```

Fire-and-forget (lossy) async inserts require an explicit opt-in that cannot be
confused with durable mode:

```json
"clickhouse": {
  "url": "https://clickhouse.internal:8443",
  "insert_query_params": { "async_insert": "1", "wait_for_async_insert": "0" },
  "allow_lossy_async_insert": true
}
```

Set `FERRUM_CLICKHOUSE_PASSWORD_FILE`, `FERRUM_CLICKHOUSE_PASSWORD_VAULT`, or
another supported secret suffix at startup, then reference the materialized base
variable (`FERRUM_CLICKHOUSE_PASSWORD`) from `password_ref`. `password_ref`
must name a `FERRUM_*` variable.

## Retry

A failed ClickHouse export uses `retry.max_attempts` total attempts (including
the initial try; valid range **1–32**). `0` is rejected rather than silently
rewritten. `clickhouse.timeout_ms` is bounded to **1–600000** ms per attempt so
the cross-process spool claim lease is finite and remains longer than the
accepted request/retry budget. Batch `size` is capped at **10000** and
`flush_interval_ms` at **600000** to match the shared `BatchingLogger` admission
limits. Each of
`retry.initial_delay_ms` and
`retry.max_delay_ms` is capped at **60000** ms. The inter-attempt delay uses
**bounded exponential backoff**: it starts at `retry.initial_delay_ms` and
doubles each attempt, capped at `retry.max_delay_ms` (which must be
`>= retry.initial_delay_ms`). The worst-case cumulative inter-attempt delay
(same exponential/capped schedule, excluding the initial try and ignoring
jitter reduction) must stay within **600000** ms (ten minutes); over-budget
configurations are rejected. When `retry.jitter` is `true` (default), each
delay is replaced with a uniformly random value in `[0, computed_delay]` (full
jitter) so a fleet of nodes does not synchronize a retry storm against a
struggling ClickHouse. After the attempt budget is exhausted the batch is
handed to the spool (when enabled) instead of being dropped.

## Spool And Replay

Spool files are written under a **managed namespace** owned by exactly one sink
identity:

```text
<spool.dir>/<safe_node>/<safe_plugin>/o<owner_digest>/spool.meta.json
<spool.dir>/<safe_node>/<safe_plugin>/o<owner_digest>/<YYYYMMDD>/<ULID>.<owner_tag>.ndjson.zst
```

### Spool ownership identity

The owner identity is the tuple

`(plugin config id, Ferrum namespace/ledger, sanitized ClickHouse endpoint,
database, table, node id)`.

`owner_digest` is a domain-separated, length-prefixed SHA-256 over that tuple
(first 32 hex characters in the path); `owner_tag` is its first 32 hex
characters and is embedded in **every** managed filename. The endpoint is the
credential-free configured base URL, including its configured path when present,
and the ClickHouse password is deliberately excluded, so neither the path, the
manifest, nor the digest is credential derived. `safe_node` and `safe_plugin`
stay human-readable when the source value is already a safe component; absolute
paths, parent segments, separators, NUL, drive letters, UNC, and Windows device
prefixes are hashed into one safe component instead of being joined, and NUL is
rejected outright.

Versioned `spool.meta.json` records the whole tuple plus `owner_digest`,
`owner_tag`, and the format version. It is written at prepare time and validated
before every replay listing. On mismatch the sink **fails closed**: nothing is
read, delivered, deleted, dead-lettered, or evicted, `spool.available` goes to
`false`, and `chargeback_sink_spool_prepare_failures_total` increments. The
per-file `owner_tag` binds each record individually, so a record moved between
directories is still attributable and is never replayed by a different owner.

The sink writes failed batches and queue high-water overflow to an async spool
delivery worker (bounded by `spool.delivery_queue_capacity`) **only when
`spool.enabled=true`**. That durable diversion hook is installed only when spool
delivery can take ownership of the event. With `spool.enabled=false`, the 80%
high-water mark is telemetry only (`high_water_hits_total` /
`chargeback_sink_queue_high_water_hits_total`); every configured
`batch.buffer_capacity` slot remains usable until the channel is actually full,
and true full-buffer losses increment `full_drops_total` /
`chargeback_sink_queue_full_drops_total` (never shutdown/unavailable
admission). High-water durable diversions increment
`high_water_diversions_total` /
`chargeback_sink_queue_high_water_diversions_total` only when the spool-delivery
handoff actually accepts the job; a saturated or closed delivery queue is
counted by `chargeback_sink_spool_jobs_lost_total` /
`chargeback_sink_spool_events_lost_total` instead (with rate-limited warnings)
and must not be reported as a successful diversion or enqueue.
`events_enqueued_total` / `chargeback_sink_events_enqueued_total` counts channel
admission or an overflow handoff that actually succeeded. Request and body
terminal hooks only enqueue to that worker; compression, directory scans,
writes, and fsync never run inline on those hooks. Files are
created with private permissions, written as process/generation-attributed
`*.write-<process_tag>-<generation>.tmp` temps, fsynced, renamed into place, then
directory-fsynced on Unix. The `spool.meta.json` ownership manifest uses the same
attributed temp name, so two generations or two processes sharing the volume can
never collide on one manifest temp and unlink each other's in-progress write. A
Unix parent-directory open or fsync failure is a **write failure**: Ferrum rolls
the attempt back, performs a second real parent-directory fsync, and returns the
error before any snapshot baseline commit.

Rollback is ownership-scoped, and ownership is decided by the name being
published rather than by inspecting the file on disk. It always removes this
attempt's own attributed temp. It also removes the **final** path when that name
belongs exclusively to the attempt — the ULID-derived `<ulid>.<owner_tag>.<ext>`
batch and its `<name>.rejected.meta` dead-letter record, which no other writer
can publish. It never removes `spool.meta.json`, the one final name every writer
of a namespace shares: an unlink acts on a path, and a peer's `rename` can
replace that path between any ownership check and the removal, so no
stat-then-unlink, content comparison, or timestamp comparison could keep such a
removal from deleting a peer's newer manifest.

A failed manifest publish therefore leaves the manifest entry in place, and
Ferrum does **not** treat that as success. The durability error is still
returned, live storage is not marked prepared, the batch is not accepted, and
`chargeback_sink_spool_prepare_failures_total` increments. What can survive is a
manifest whose directory entry was never fsynced (or whose bytes replaced a
peer's); the next prepare revalidates it against this sink's identity and
regenerates it or fails closed, so it is recoverable, whereas deleting another
writer's live manifest would not be. If rollback removal or its second fsync also
fails, that failure is included in the returned diagnostic rather than claiming a
guaranteed rollback.

On platforms that cannot fsync directories (notably Windows) a successful file
sync plus rename is the durability boundary this plugin can offer, and that limit
is stated rather than claimed away — there is no silent "best-effort" success
after a failed directory sync on Unix.

Spool enumeration never follows symlinks (scan, replay, eviction, quarantine,
and stale-temp cleanup use non-following metadata), proves the managed root
resolves under the canonical `spool.dir`, enforces containment for every path it
creates, renames, or unlinks, verifies that the namespace path still names its
original canonical directory before every walk/mutation, bounds traversal depth
and total directory-entry count, and skips directory cycles by device/inode
identity.

### Claim and lease protocol

The background replayer scans durable data files (`*.ndjson` / `*.ndjson.zst`)
carrying **its own** `owner_tag`, in lexicographic order, then **atomically
claims** each candidate by renaming it to

```text
<ULID>.<owner_tag>.ndjson.claim-<process_tag>-<generation>-<lease_deadline>.inflight
```

before any ClickHouse delivery. The rename is the mutual-exclusion primitive: on
a shared volume exactly one accepted generation or process can win it, and the
loser simply moves on to the next file. `process_tag` is a per-process nonce
drawn with 128 bits at startup, so a restart never mistakes a crashed run's claim
for live work. The lease deadline is derived from the configured worst-case
delivery budget (`clickhouse.timeout_ms` × `retry.max_attempts` plus the retry
backoff schedule, ×4, with a 300-second floor and no shorter ceiling).
Multi-chunk replay renews the claim before each chunk, so the aggregate delivery
of one file cannot outlive a lease sized for one bounded request/retry budget.

Claim disposition:

- **Delivered** — the claim is removed.
- **Retryable** — the claim is released back to its durable replayable name and
  the tick stops so ordering is preserved.
- **Permanent / 413 single row** — the claim is replaced by safe dead-letter
  metadata named after the durable data file.
- **Unreadable** — the claim is quarantined as `<data-name>.corrupt`.

In-flight claims count toward `spool.max_bytes` but are **never** eviction
candidates; when only claimed or foreign-owned files remain, an admission that
cannot fit fails closed instead of destroying them. Recovery at prepare time
returns a claim to its durable name only when this process demonstrably abandoned
it (same `process_tag`, no live lease) or when a peer's lease deadline has
passed.

Within one process the exclusion is absolute: a live claim holds an in-memory
lease, so no other accepted generation can recover it. Across processes sharing a
volume the exclusion is the atomic rename plus a *time* bound, not a proof that
the peer stopped: a peer stalled past its lease (host pause, `SIGSTOP`, or clock
skew between replicas) can still be delivering a claim another process has
recovered. The lease is sized at four times the accepted worst-case delivery
budget and renewed before every chunk so that window is not reachable by ordinary
slow delivery, and the residual case is a duplicate insert — not a lost or
misrouted record — which the stable `event_id` / `ReplacingMergeTree` idempotency
contract deduplicates. A claim is never delivered to a destination other than the
one its `owner_tag` names.

Queued export and spool-delivery events retain the same byte leases under
`batch.buffer_max_bytes`; transferring an event to the spool worker does not
escape or double-count that budget. The minimum admitted budget is 9312 bytes,
the conservative maximum retained size of one field-bounded charge event.

The contiguous JSONEachRow HTTP insert body is a second retained representation
and is charged to the process-wide retained-byte ceiling
(`FERRUM_LOG_DELIVERY_MAX_RETAINED_BYTES`), not a second time to
`buffer_max_bytes`. Admission reserves a provisional escaping/framing bound
before serialization, then shrinks to the exact retained buffer capacity for the
body's lifetime (including while a ClickHouse acknowledgement is held).

### Delivery outcomes

Replay classifies each ClickHouse HTTP attempt before deciding whether to keep,
split, or skip a file:

| Outcome | Status / cause | Replay behavior |
| --- | --- | --- |
| Delivered | HTTP 200 / 204 with a complete empty acknowledgement body and no exception header/markers | Remove the spool file after the accepted insert |
| Retryable | network / timeout / TLS transport errors, incomplete acknowledgement drains, ambiguous non-empty 2xx bodies, HTTP 401, 403, 408, 429, 5xx, and other non-4xx failures | Keep the file, stop the current replay tick (newer files wait so order is preserved across transient outages) |
| Payload too large | HTTP 413 | Deterministically split the JSONEachRow body (preferring `batch.size`, otherwise halving) and retry each part without rewriting row bytes, so each event keeps its stable `event_id` idempotency identity. A single row that still returns 413 is dead-lettered |
| Permanent | other HTTP 4xx (for example 400, 404, 409, 418, 422), or HTTP 200/204 whose body/`X-ClickHouse-Exception-Code` carries a ClickHouse exception | Replace the rejected payload with safe dead-letter metadata and continue with newer spool files so one poison batch cannot head-of-line block the spool |

Logs and error strings for these outcomes carry only safe metadata (plugin name,
HTTP status code, reason class, row count, acknowledgement byte length class,
and file path). Response bodies, ClickHouse credentials, and charge-record
fields are never logged.

### Quarantine and dead-letter

- Unreadable local spool files are renamed with a `.corrupt` suffix so newer
  files can continue to replay.
- Every encoded and decoded spool artifact is hard-capped at 256 MiB, matching
  the sink's maximum accepted retained-byte budget. The writer refuses a larger
  artifact, so it cannot publish a record this build will not replay. A `zstd`
  record written by this build records its decompressed size in the frame
  header, and that is the (tight) bound replay reserves before reading it; a
  foreign or hand-planted archive with no such header falls back to at most 200x
  its encoded size (floor 1 MiB). A planted large raw file or high-ratio archive
  inside the managed tree is quarantined as `.corrupt` without first being read
  or expanded without limit inside the billing process.
- Building a spool artifact is charged to the process-wide retained-byte
  ceiling. The JSONEachRow serialization and, under `zstd`, its compressed form
  are each reserved **before** they are allocated from a provisional
  escaping/framing (or compression) bound, then shrunk to the exact retained
  allocation — the queued charge events still hold their export leases at that
  point — and the compressed artifact's reservation is held across the blocking
  write, fsync, and rename. A ceiling refusal is reported through the existing
  spool-write failure accounting and publishes nothing.
- The writer additionally refuses any artifact whose *replay* would not fit
  under the same configured process ceiling. Replay retains, at its peak, one
  decoded text buffer, one `(start, end)` line index entry per row, a
  fixed-capacity 413-split worklist, and one request body for the chunk in
  flight. Because that peak is always below what writing the same artifact
  required, a file this build successfully spooled is never structurally
  unreplayable. Transient ceiling *pressure* is different and stays retryable:
  the claim is released and the artifact replays in order on a later tick — a
  busy ceiling never quarantines a healthy file.
- `spool.meta.json` is bounded separately at 64 KiB. It is the one managed file
  read *before* ownership is established — on every prepare and every replay
  listing — so it is reachable without first deriving this owner's tag. An
  oversized manifest fails the ownership check closed (`spool.available=false`,
  `chargeback_sink_spool_prepare_failures_total`) and mutates nothing.
- Permanently rejected rows (and single-row 413 failures) are discarded only
  after one deterministic sibling `.rejected.meta` JSON document has been
  durably written for the source file. The document contains the aggregate
  `rejected_rows`, safe `outcomes` (`reason`, optional `http_status`, and
  `row_count`), and `quarantined_at_unix`. Rejections are accumulated into a
  fixed-size per-status tally whose footprint is independent of the artifact's
  row count, so a hostile row count cannot grow an uncharged accumulator while
  the decoded artifact is still retained; per-status row counts stay exact. The
  document never retains the rejected payload, response bodies, credentials, or
  charge-record PII. If the metadata
  write fails, the original file remains replayable; successfully inserted
  rows may be retried with their unchanged `event_id` idempotency identity.
- Temps left by an interrupted atomic write are reconciled only when this process
  demonstrably owns them (matching `process_tag`) and no live writer holds the
  path, or when they are foreign/unattributable **and** older than the stale-temp
  age (300 s). A reloaded generation therefore cannot unlink the active temp of
  an older accepted generation or of a peer process sharing the volume.
- In-flight replay claims are recovered to durable replayable names during live
  prepare, subject to the lease rules above.

Dead-letter metadata, corrupt files, temps, and in-flight claims remain under
the managed namespace and count toward `spool.max_bytes` until eviction drops the
oldest **evictable** owned file. In-flight claims, temps still under an active
write, and records carrying another owner's tag are never evictable: eviction
applies the same ownership and stale-age test reconciliation does, so it can
reclaim a crash-left temp but never unlink a peer generation's in-progress
publish.

### Migration and destination changes

Ferrum never silently replays records it does not own to a newly configured
destination. Two shapes are recognized and reported instead:

- **Pre-namespace (legacy) records** written directly under
  `<spool.dir>/<node>/<YYYYMMDD>/`, which carry no ownership binding.
- **Orphaned namespaces**: a sibling `o<owner_digest>` directory left behind when
  the Ferrum namespace/ledger, ClickHouse endpoint, database, or table changed
  while the node id and plugin config id stayed the same.

Both are counted when the managed namespace is prepared (process start, or the
first tick after storage recovers) into `spool.unbound_files` /
`spool.unbound_namespaces` in the status JSON, exported as
`chargeback_sink_spool_unbound_files` and
`chargeback_sink_spool_unbound_namespaces`, and logged with a rate-limited
warning naming the counts and directories. The aggregate discovery pass shares
one 100,000-entry traversal budget across the legacy tree and every sibling
namespace; if that cap is reached, the warning sets `scan_truncated=true` and
the exported counts are explicit lower bounds rather than performing unbounded
work on a shared volume. They are **never** replayed, deleted, evicted, or
rerouted. Reconciling them is an explicit operator action: either re-point the
sink at the original destination so the records become owned again, or
export/remove them out of band. A record whose `owner_tag` names a different
identity but sits inside this namespace (only reachable by tampering or a
hand-moved file) is treated the same way: counted, reported, never touched.
Changing the node id or plugin config id moves records to a different parent
subtree, so the replacement instance cannot safely attribute or count them;
operators must inspect those previous subtrees explicitly.

Offline validation and candidate-generation staging do not create, chmod, or
probe `spool.dir`. After cache publication, the committed replayer prepares and
write-probes the private spool directories before replay or admission. A failed
probe is persistent operational evidence: status reports `spool.available=false`,
`chargeback_sink_spool_available` is `0`, and
`chargeback_sink_spool_prepare_failures_total` increments until storage recovers.

`spool.max_bytes` is a hard ceiling on **encoded** on-disk bytes owned by this
sink under its managed namespace (after compression when `compression` is
`zstd`). The budget and status/metrics count every retained file class:

- active data files (`*.ndjson` / `*.ndjson.zst`)
- in-progress atomic-write temps (`*.write-<process_tag>-<generation>.tmp` and
  dead-letter metadata `*.rejected.meta.tmp` files)
- in-flight replay claims (`*.inflight`)
- corrupt quarantine (`*.ndjson.corrupt` / `*.ndjson.zst.corrupt`)
- metadata-only dead letters (`*.ndjson.rejected.meta` /
  `*.ndjson.zst.rejected.meta`)

Pending writes are serialized/compressed and sized **before** quota admission.
Admission holds the spool write lock with eviction so concurrent writers cannot
over-admit. Existing owned bytes plus the incoming encoded file must stay within
`max_bytes`; when space is short, the oldest **evictable** owned file is dropped
and `chargeback_sink_spool_drops_total` is incremented. If a single encoded batch
still cannot fit after eviction (including on an empty spool, or when every
retained file is an in-flight claim, a temp under an active write, or owned by
another identity), the write is **rejected** and the batch/event follows the
existing spool-failure path (warned and not durably retained). The sink never
silently exceeds the ceiling and never reclaims bytes by destroying an in-flight,
actively written, or foreign-owned record.

Size `spool.max_bytes` for the longest ClickHouse outage you are willing to
absorb, using **encoded** average event size (and headroom for retained
`.corrupt` quarantine and `.rejected.meta` dead-letter files):

```text
max_bytes >= peak_events_per_second * average_encoded_event_bytes * outage_seconds
```

When `spool.dir` is backed by persistent storage, set `FERRUM_NODE_ID` to a
stable identity such as a StatefulSet ordinal (see
[configuration.md](../configuration.md) and `ferrum.conf`). The value is
length-bounded for charge-event provenance and encoded into a single safe path
component for the managed namespace (hostile absolute/parent/separator/NUL/drive
forms are hashed rather than joined raw). It is also part of the spool ownership
digest, so a node-identity change produces a fresh managed namespace. Resolution
order is `FERRUM_NODE_ID`, then `HOSTNAME`, then `/etc/hostname`, then
`unknown`. If the node identity changes across restarts, records under the
previous identity remain in the previous `<safe_node>` subtree and are never
replayed or deleted automatically. Because the replacement instance scans only
its own node/plugin subtree, node-id changes are not added to its unbound metric;
operators must inspect and reconcile the previous node subtree explicitly.

## Reconciliation Queries

Raw event count:

```sql
SELECT count(), sum(charge_total)
FROM ferrum.charges_raw FINAL
WHERE node_id = 'edge-a'
  AND received_at >= now() - INTERVAL 1 HOUR;
```

Consumer daily invoice rollup (partitioned by currency and pricing generation —
never sum `charge` across currencies or pricing versions):

```sql
SELECT namespace, consumer_id, currency, pricing_version, day, sum(calls), sum(charge)
FROM ferrum.charges_daily
WHERE day >= today() - 30
GROUP BY namespace, consumer_id, currency, pricing_version, day
ORDER BY day, namespace, consumer_id, currency, pricing_version;
```

The reference hourly/daily/monthly views group by `currency` and
`pricing_version` in addition to namespace/consumer/proxy/time so two sink
instances that share a table (or one sink that changes currency/pricing
generation on reload) cannot produce unitless USD+EUR-style rollups. Re-apply
`migrations/clickhouse/0001_charges.sql` to refresh those views (`CREATE OR
REPLACE VIEW`).

For snapshot mode, compare `/charges` totals to `sum(call_count)`,
`sum(bytes_sent)`, `sum(bytes_received)`, and `sum(charge_total)` over the same
node and time window.

## Status And Metrics

`GET /charges/sink/status` is JWT-authenticated and returns the current
accepted-generation observability for every stable `api_chargeback_sink`
plugin-config ID. Validation-only construction and uncommitted staged reloads
never publish into this view.

Response contract:

- `enabled` is `true` when at least one accepted instance is live.
- `instance_count` is the number of published instances.
- `snapshot_finalizations_pending` is the number of retired snapshot
  generations retaining an unspooled terminal delta for bounded retry.
- `totals` aggregates queue depth/capacity/high-water hits/high-water
  diversions/full-buffer drops, spool files/bytes/
  drops/prepare failures, and export counters across every current accepted
  instance.
  `totals.spool.available` is `true` only when every spool-enabled live instance
  is currently writable.
- `instances` lists the current accepted generation for each sink in ascending
  `plugin_config_id` order. Each entry includes its generation plus
  mode, pricing version, sanitized ClickHouse endpoint metadata, batch/retry
  settings, per-instance queue/spool/export counters, and timestamps.

Cardinality is bounded by the number of accepted plugin-config IDs. A newly
accepted generation replaces the prior status entry for the same stable ID;
dropping an older in-flight runtime removes nothing unless it is still the
published generation.

`/metrics` preserves the existing metric names as process-wide aggregates
across the current accepted sink generation for every stable plugin-config ID:

- `chargeback_sink_events_enqueued_total`
- `chargeback_sink_events_exported_total`
- `chargeback_sink_export_failures_total{reason}`
- `chargeback_sink_queue_depth`
- `chargeback_sink_queue_high_water_hits_total`
- `chargeback_sink_queue_high_water_diversions_total`
- `chargeback_sink_queue_full_drops_total`
- `chargeback_sink_snapshot_finalizations_pending`
- `chargeback_sink_spool_bytes` (owned encoded bytes: active, temp, in-flight claim, corrupt, and dead-lettered)
- `chargeback_sink_spool_files` (owned file count across those same classes)
- `chargeback_sink_spool_drops_total`
- `chargeback_sink_spool_available` (aggregate is `1` only while every spool-enabled live instance is writable)
- `chargeback_sink_spool_prepare_failures_total`
- `chargeback_sink_spool_unbound_files` (records not bound to a live destination identity; never replayed or deleted; a lower bound when the rate-limited warning reports `scan_truncated=true`)
- `chargeback_sink_spool_unbound_namespaces` (same bounded-scan lower-bound semantics)
- `chargeback_sink_export_latency_seconds`
- `chargeback_sink_snapshot_emits_total` in snapshot mode

Per-instance identity, generation, configuration, and counters are available
from the authenticated status endpoint. Prometheus deliberately does not add a
generation label: repeated reloads therefore cannot create an unbounded stream
of historical time series, and ordinary sums cannot double-count aggregate plus
component samples.

## Security Notes

Use HTTPS to ClickHouse. When `clickhouse.password_ref` is set, the plugin
requires an `https://` `clickhouse.url` and rejects configs that disable TLS
certificate or hostname verification, so Basic Auth credentials are never sent
over cleartext. Configure mTLS with `clickhouse.tls.client_cert_file`
and `clickhouse.tls.client_key_file` when ClickHouse requires client
authentication. Keep `password_ref` pointed at an environment variable resolved
by Ferrum's existing secret materialization; do not place credentials directly
in plugin config. The admin status response strips user-info and never returns
passwords or bearer material.
