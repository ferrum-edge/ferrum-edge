CREATE DATABASE IF NOT EXISTS ferrum;

CREATE TABLE IF NOT EXISTS ferrum.charges_raw (
    event_id              String,
    received_at           DateTime64(9, 'UTC'),
    node_id               LowCardinality(String),
    namespace             LowCardinality(String),
    consumer_id           String,
    consumer_name         String,
    proxy_id              String,
    proxy_name            LowCardinality(String),
    route_id              String,
    status_code           UInt16,
    protocol              LowCardinality(String),
    call_count            UInt32,
    charge_call           Float64,
    bytes_sent            UInt64,
    bytes_received        UInt64,
    charge_bytes_sent     Float64,
    charge_bytes_received Float64,
    charge_total          Float64,
    currency              LowCardinality(String),
    pricing_version       LowCardinality(String),
    request_id            String,
    trace_id              String,
    snapshot_id           String
) ENGINE = ReplacingMergeTree(received_at)
ORDER BY (namespace, consumer_id, received_at, event_id)
PARTITION BY toYYYYMM(received_at)
TTL toDateTime(received_at) + INTERVAL 13 MONTH;

CREATE MATERIALIZED VIEW IF NOT EXISTS ferrum.charges_hourly
ENGINE = SummingMergeTree()
ORDER BY (namespace, consumer_id, proxy_id, status_code, hour)
PARTITION BY toYYYYMM(hour)
AS SELECT
    namespace, consumer_id, proxy_id, status_code,
    toStartOfHour(received_at) AS hour,
    sum(call_count)            AS calls,
    sum(charge_total)          AS charge,
    sum(bytes_sent)            AS bytes_sent,
    sum(bytes_received)        AS bytes_received
FROM ferrum.charges_raw
GROUP BY namespace, consumer_id, proxy_id, status_code, hour;

CREATE MATERIALIZED VIEW IF NOT EXISTS ferrum.charges_daily
ENGINE = SummingMergeTree()
ORDER BY (namespace, consumer_id, proxy_id, day)
AS SELECT
    namespace, consumer_id, proxy_id,
    toDate(hour)           AS day,
    sum(calls)             AS calls,
    sum(charge)            AS charge,
    sum(bytes_sent)        AS bytes_sent,
    sum(bytes_received)    AS bytes_received
FROM ferrum.charges_hourly
GROUP BY namespace, consumer_id, proxy_id, day;

CREATE MATERIALIZED VIEW IF NOT EXISTS ferrum.charges_monthly
ENGINE = SummingMergeTree()
ORDER BY (namespace, consumer_id, proxy_id, month)
AS SELECT
    namespace, consumer_id, proxy_id,
    toStartOfMonth(day)    AS month,
    sum(calls)             AS calls,
    sum(charge)            AS charge,
    sum(bytes_sent)        AS bytes_sent,
    sum(bytes_received)    AS bytes_received
FROM ferrum.charges_daily
GROUP BY namespace, consumer_id, proxy_id, month;
