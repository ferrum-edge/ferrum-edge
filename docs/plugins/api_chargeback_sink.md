# API Chargeback Sink Plugin

`api_chargeback_sink` exports durable charge events to ClickHouse. It is a sibling
to `api_chargeback`: use either plugin independently, or run both when you want
the existing in-memory `/charges` view plus a durable event stream.

## Modes

`mode: per_event` emits one `ChargeEvent` for each chargeable HTTP-family
transaction, stream disconnect, or WebSocket disconnect. This preserves
transaction-level provenance and is the default.

`mode: snapshot` keeps a local accumulator keyed by namespace, consumer, proxy,
billable status, raw HTTP status, final gRPC status, and protocol. Every
`snapshot.interval_secs`, it emits deltas since the last snapshot. Use this when
event volume dominates ingest cost and aggregate reconciliation is sufficient.
Snapshot mode requires `spool.enabled: true` because the accumulator advances
after a delta is handed to the sink queue; the spool is the durable path when
ClickHouse or the in-memory queue is unavailable. Idle snapshot keys are evicted
after `snapshot.stale_entry_ttl_secs` and checked every
`snapshot.cleanup_interval_secs`.

Both modes use the same pricing fields as `api_chargeback`. At least one
nonempty pricing dimension is mandatory and matches
`PricingConfig::has_any_pricing`: a nonempty `pricing_tiers` list, bandwidth
pricing with at least one strictly positive per-byte rate, or
`stream_connection_pricing` with a strictly positive `price_per_connection`.

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
express safely (notably `retry.max_delay_ms >= retry.initial_delay_ms`),
spool directory privacy, ClickHouse egress screening, and that a nonempty
`password_ref` names a set `FERRUM_*` environment variable.

## ClickHouse Setup

Apply the reference DDL before enabling the plugin:

```bash
clickhouse-client < migrations/clickhouse/0001_charges.sql
```

The DDL creates `ferrum.charges_raw` with `ReplacingMergeTree` idempotency on
`event_id`, plus hourly, daily, and monthly views that read from
`charges_raw FINAL`. The views trade query cost for correctness: duplicate raw
events are deduplicated before rollup aggregation.

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
      "insert_query_params": { "async_insert": "1", "wait_for_async_insert": "0" },
      "timeout_ms": 5000
    },
    "batch": { "size": 500, "flush_interval_ms": 2000, "buffer_capacity": 50000 },
    "retry": { "max_attempts": 5, "initial_delay_ms": 250, "max_delay_ms": 10000, "jitter": true },
    "spool": {
      "enabled": true,
      "dir": "/var/lib/ferrum/chargeback-spool",
      "max_bytes": 10737418240,
      "replay_interval_secs": 60,
      "compression": "zstd"
    },
    "snapshot": {
      "interval_secs": 30,
      "cleanup_interval_secs": 300,
      "stale_entry_ttl_secs": 3600,
      "emit_zero_deltas": false
    },
    "pricing_version": "2026-01-rev3",
    "currency": "USD"
  }
}
```

Set `FERRUM_CLICKHOUSE_PASSWORD_FILE`, `FERRUM_CLICKHOUSE_PASSWORD_VAULT`, or
another supported secret suffix at startup, then reference the materialized base
variable (`FERRUM_CLICKHOUSE_PASSWORD`) from `password_ref`. `password_ref`
must name a `FERRUM_*` variable.

## Retry

A failed ClickHouse export is retried up to `retry.max_attempts` times. The
inter-attempt delay uses **bounded exponential backoff**: it starts at
`retry.initial_delay_ms` and doubles each attempt, capped at `retry.max_delay_ms`
(which must be `>= retry.initial_delay_ms`). When `retry.jitter` is `true`
(default), each delay is replaced with a uniformly random value in
`[0, computed_delay]` (full jitter) so a fleet of nodes does not synchronize a
retry storm against a struggling ClickHouse. After the attempt budget is
exhausted the batch is handed to the spool (when enabled) instead of being
dropped.

## Spool And Replay

Spool files are written under:

```text
<spool.dir>/<node_id>/<YYYYMMDD>/<ULID>.ndjson.zst
```

The sink writes failed batches and queue high-water overflow to disk. Files are
created with private permissions, written as `*.tmp`, fsynced, and renamed into
place. The background replayer scans durable data files (`*.ndjson` /
`*.ndjson.zst`) in lexicographic order and removes a file only after ClickHouse
accepts the whole file as one insert. Unreadable spool files are renamed with a
`.corrupt` suffix so newer files can continue to replay. Stale `*.tmp` files left
by an interrupted atomic write are deleted at spool startup and after a failed
write/rename so they cannot accumulate indefinitely.

`spool.max_bytes` is a hard ceiling on **encoded** on-disk bytes owned by this
sink under `<spool.dir>/<node_id>/` (after compression when `compression` is
`zstd`). The budget and status/metrics count every retained file class:

- active data files (`*.ndjson` / `*.ndjson.zst`)
- in-progress atomic-write temps (`*.ndjson.tmp` / `*.ndjson.zst.tmp`)
- quarantined files (`*.ndjson.corrupt` / `*.ndjson.zst.corrupt`)

Pending writes are serialized/compressed and sized **before** quota admission.
Admission holds the spool write lock with eviction so concurrent writers cannot
over-admit. Existing owned bytes plus the incoming encoded file must stay within
`max_bytes`; when space is short, the oldest owned file is dropped and
`chargeback_sink_spool_drops_total` is incremented. If a single encoded batch
still cannot fit after eviction (including on an empty spool), the write is
**rejected** and the batch/event follows the existing spool-failure path
(warned and not durably retained). The sink never silently exceeds the ceiling.

Size `spool.max_bytes` for the longest ClickHouse outage you are willing to
absorb, using **encoded** average event size (and headroom for any retained
`.corrupt` quarantine files):

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

Consumer daily invoice rollup:

```sql
SELECT namespace, consumer_id, day, sum(calls), sum(charge)
FROM ferrum.charges_daily
WHERE day >= today() - 30
GROUP BY namespace, consumer_id, day
ORDER BY day, namespace, consumer_id;
```

For snapshot mode, compare `/charges` totals to `sum(call_count)`,
`sum(bytes_sent)`, `sum(bytes_received)`, and `sum(charge_total)` over the same
node and time window.

## Status And Metrics

`GET /charges/sink/status` is JWT-authenticated and returns queue depth, spool
size, replay timestamps, and export counters. `/metrics` includes:

- `chargeback_sink_events_enqueued_total`
- `chargeback_sink_events_exported_total`
- `chargeback_sink_export_failures_total{reason}`
- `chargeback_sink_queue_depth`
- `chargeback_sink_spool_bytes` (owned encoded bytes: active, temp, and quarantined)
- `chargeback_sink_spool_files` (owned file count across those same classes)
- `chargeback_sink_spool_drops_total`
- `chargeback_sink_export_latency_seconds`
- `chargeback_sink_snapshot_emits_total` in snapshot mode

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
