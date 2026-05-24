# API Chargeback Sink Plugin

`api_chargeback_sink` exports durable charge events to ClickHouse. It is a sibling
to `api_chargeback`: use either plugin independently, or run both when you want
the existing in-memory `/charges` view plus a durable event stream.

## Modes

`mode: per_event` emits one `ChargeEvent` for each chargeable HTTP-family
transaction, stream disconnect, or WebSocket disconnect. This preserves
transaction-level provenance and is the default.

`mode: snapshot` keeps a local accumulator keyed by namespace, consumer, proxy,
and status code. Every `snapshot.interval_secs`, it emits deltas since the last
snapshot. Use this when event volume dominates ingest cost and aggregate
reconciliation is sufficient. Snapshot mode requires `spool.enabled: true`
because the accumulator advances after a delta is handed to the sink queue; the
spool is the durable path when ClickHouse or the in-memory queue is unavailable.
Idle snapshot keys are evicted after `snapshot.stale_entry_ttl_secs` and checked
every `snapshot.cleanup_interval_secs`.

Both modes use the same pricing fields as `api_chargeback`:

- `pricing_tiers` for HTTP-family per-call pricing by status code.
- `bandwidth_pricing` for client-to-backend and backend-to-client bytes.
- `stream_connection_pricing` for TCP, TCP+TLS, UDP, and DTLS sessions.

## ClickHouse Setup

Apply the reference DDL before enabling the plugin:

```bash
clickhouse-client < migrations/clickhouse/0001_charges.sql
```

The DDL creates `ferrum.charges_raw` with `ReplacingMergeTree` idempotency on
`event_id`, plus hourly, daily, and monthly views that read from
`charges_raw FINAL`. The views trade query cost for correctness: duplicate raw
events are deduplicated before rollup aggregation.

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

## Spool And Replay

Spool files are written under:

```text
<spool.dir>/<node_id>/<YYYYMMDD>/<ULID>.ndjson.zst
```

The sink writes failed batches and queue high-water overflow to disk. Files are
created with private permissions, written as `*.tmp`, fsynced, and renamed into
place. The background replayer scans files in lexicographic order and removes a
file only after ClickHouse accepts the whole file as one insert. Unreadable
spool files are renamed with a `.corrupt` suffix so newer files can continue to
replay.

Size `spool.max_bytes` for the longest ClickHouse outage you are willing to
absorb:

```text
max_bytes >= peak_events_per_second * average_event_bytes * outage_seconds
```

When the spool is full, the oldest file is dropped and
`chargeback_sink_spool_drops_total` is incremented.

When `spool.dir` is backed by persistent storage, set `FERRUM_NODE_ID` to a
stable identity such as a StatefulSet ordinal. If the node ID changes across
restarts, the sink logs a warning when it finds sibling spool directories that
may contain events from an older identity.

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
- `chargeback_sink_spool_bytes`
- `chargeback_sink_spool_files`
- `chargeback_sink_spool_drops_total`
- `chargeback_sink_export_latency_seconds`
- `chargeback_sink_snapshot_emits_total` in snapshot mode

## Security Notes

Use HTTPS to ClickHouse. Configure mTLS with `clickhouse.tls.client_cert_file`
and `clickhouse.tls.client_key_file` when ClickHouse requires client
authentication. Keep `password_ref` pointed at an environment variable resolved
by Ferrum's existing secret materialization; do not place credentials directly
in plugin config. The admin status response strips user-info and never returns
passwords or bearer material.
