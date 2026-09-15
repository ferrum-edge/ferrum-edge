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
    http_status_code      Nullable(UInt16),
    grpc_status           Nullable(UInt32),
    protocol              LowCardinality(String),
    call_count            UInt64,
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

-- Monetary rollups must stay partitioned by currency and pricing_version so
-- mixed-currency or multi-generation sinks never produce unitless charge sums
-- (issue #2569). CREATE OR REPLACE keeps re-applying the baseline DDL safe.
CREATE OR REPLACE VIEW ferrum.charges_hourly AS
SELECT
    namespace, consumer_id, proxy_id, status_code,
    currency, pricing_version,
    toStartOfHour(received_at) AS hour,
    sum(call_count)            AS calls,
    sum(charge_total)          AS charge,
    sum(bytes_sent)            AS bytes_sent,
    sum(bytes_received)        AS bytes_received
FROM ferrum.charges_raw FINAL
GROUP BY namespace, consumer_id, proxy_id, status_code, currency, pricing_version, hour;

CREATE OR REPLACE VIEW ferrum.charges_daily AS
SELECT
    namespace, consumer_id, proxy_id,
    currency, pricing_version,
    toDate(received_at)        AS day,
    sum(call_count)            AS calls,
    sum(charge_total)          AS charge,
    sum(bytes_sent)            AS bytes_sent,
    sum(bytes_received)        AS bytes_received
FROM ferrum.charges_raw FINAL
GROUP BY namespace, consumer_id, proxy_id, currency, pricing_version, day;

CREATE OR REPLACE VIEW ferrum.charges_monthly AS
SELECT
    namespace, consumer_id, proxy_id,
    currency, pricing_version,
    toStartOfMonth(received_at) AS month,
    sum(call_count)             AS calls,
    sum(charge_total)           AS charge,
    sum(bytes_sent)             AS bytes_sent,
    sum(bytes_received)         AS bytes_received
FROM ferrum.charges_raw FINAL
GROUP BY namespace, consumer_id, proxy_id, currency, pricing_version, month;
