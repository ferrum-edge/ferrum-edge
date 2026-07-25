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
clear. Once mapped, Compact owns that
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
rewritten. Batch `size` is capped at **10000** and `flush_interval_ms` at
**600000** to match the shared `BatchingLogger` admission limits. Each of
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

Spool files are written under:

```text
<spool.dir>/<node_id>/<YYYYMMDD>/<ULID>.ndjson.zst
```

The sink writes failed batches and queue high-water overflow to an async spool
delivery worker (bounded by `spool.delivery_queue_capacity`). Request and body
terminal hooks only enqueue to that worker; compression, directory scans, writes,
and fsync never run inline on those hooks. Saturation of the delivery queue is
counted (`chargeback_sink_spool_jobs_lost_total` /
`chargeback_sink_spool_events_lost_total`) with rate-limited warnings. Files are
created with private permissions, written as `*.tmp`, fsynced, and renamed into
place. The background replayer scans durable data files (`*.ndjson` /
`*.ndjson.zst`) in lexicographic order.

Queued export and spool-delivery events retain the same byte leases under
`batch.buffer_max_bytes`; transferring an event to the spool worker does not
escape or double-count that budget. The minimum admitted budget is 9312 bytes,
the conservative maximum retained size of one field-bounded charge event.

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
- Permanently rejected rows (and single-row 413 failures) are discarded only
  after one deterministic sibling `.rejected.meta` JSON document has been
  durably written for the source file. The document contains the aggregate
  `rejected_rows`, safe `outcomes` (`reason`, optional `http_status`, and
  `row_count`), and `quarantined_at_unix`. It never retains the rejected
  payload, response bodies, credentials, or charge-record PII. If the metadata
  write fails, the original file remains replayable; successfully inserted
  rows may be retried with their unchanged `event_id` idempotency identity.
- Stale `*.tmp` files left by an interrupted atomic write are deleted at spool
  startup and after a failed write/rename so they cannot accumulate indefinitely.

Dead-letter metadata and corrupt files remain under the node spool tree and
count toward `spool.max_bytes` until eviction drops the oldest owned file.

Offline validation and candidate-generation staging do not create, chmod, or
probe `spool.dir`. After cache publication, the committed replayer prepares and
write-probes the private spool directories before replay or admission. A failed
probe is persistent operational evidence: status reports `spool.available=false`,
`chargeback_sink_spool_available` is `0`, and
`chargeback_sink_spool_prepare_failures_total` increments until storage recovers.

`spool.max_bytes` is a hard ceiling on **encoded** on-disk bytes owned by this
sink under `<spool.dir>/<node_id>/` (after compression when `compression` is
`zstd`). The budget and status/metrics count every retained file class:

- active data files (`*.ndjson` / `*.ndjson.zst`)
- in-progress atomic-write temps (`*.ndjson.tmp`, `*.ndjson.zst.tmp`, and
  dead-letter metadata `*.rejected.meta.tmp` files)
- corrupt quarantine (`*.ndjson.corrupt` / `*.ndjson.zst.corrupt`)
- metadata-only dead letters (`*.ndjson.rejected.meta` /
  `*.ndjson.zst.rejected.meta`)

Pending writes are serialized/compressed and sized **before** quota admission.
Admission holds the spool write lock with eviction so concurrent writers cannot
over-admit. Existing owned bytes plus the incoming encoded file must stay within
`max_bytes`; when space is short, the oldest owned file is dropped and
`chargeback_sink_spool_drops_total` is incremented. If a single encoded batch
still cannot fit after eviction (including on an empty spool), the write is
**rejected** and the batch/event follows the existing spool-failure path
(warned and not durably retained). The sink never silently exceeds the ceiling.

Size `spool.max_bytes` for the longest ClickHouse outage you are willing to
absorb, using **encoded** average event size (and headroom for retained
`.corrupt` quarantine and `.rejected.meta` dead-letter files):

```text
max_bytes >= peak_events_per_second * average_encoded_event_bytes * outage_seconds
```

When `spool.dir` is backed by persistent storage, set `FERRUM_NODE_ID` to a
stable identity such as a StatefulSet ordinal (see
[configuration.md](../configuration.md) and `ferrum.conf`). Accepted values
are any non-empty trimmed string; whitespace-only is ignored and values longer
than 512 characters are truncated. Resolution order is `FERRUM_NODE_ID`, then
`HOSTNAME`, then `/etc/hostname`, then `unknown`. If the node ID changes
across restarts, the sink logs a warning when it finds sibling spool
directories that may contain events from an older identity.

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
- `totals` aggregates queue depth/capacity/high-water hits, spool files/bytes/
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
- `chargeback_sink_snapshot_finalizations_pending`
- `chargeback_sink_spool_bytes` (owned encoded bytes: active, temp, corrupt, and dead-lettered)
- `chargeback_sink_spool_files` (owned file count across those same classes)
- `chargeback_sink_spool_drops_total`
- `chargeback_sink_spool_available` (aggregate is `1` only while every spool-enabled live instance is writable)
- `chargeback_sink_spool_prepare_failures_total`
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
