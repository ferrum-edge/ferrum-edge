# Prometheus Metrics Contract (DOC-10)

This page is the checked-in operator reference for Ferrum Edge Prometheus families exported on authenticated `GET /metrics`, plus the `api_chargeback` billing families exported only by authenticated `GET /charges` in Prometheus format (see each row's `export_surface` in the inventory JSON).
The canonical machine-readable inventory is [`docs/prometheus_metric_contract.json`](prometheus_metric_contract.json).
Hosted CI and unit tests fail closed when exposition name/type/label drift is undocumented, when this reference diverges from the inventory, or when bundled PrometheusRule/Grafana queries reference unknown Ferrum families.

## Contract model

| Field | Meaning |
|-------|---------|
| `name` | Exact Prometheus metric family name. Histogram/summary samples use `_bucket`/`_sum`/`_count`; those suffixes are normalized to the base family only when the exact name is not itself an inventoried family and the stripped candidate is an inventoried histogram/summary. |
| `type` | Prometheus type: `counter`, `gauge`, `histogram`, or `summary` |
| `help` | HELP text emitted on scrape |
| `labels` | Stable label keys the family may emit (optional `namespace` / `gateway_namespace` appear when the gateway namespace is configured) |
| `subsystem` | Owning emitter / operational area |
| `export_surface` | Admin endpoint that renders the family: `/metrics`, or `/charges` for the `api_chargeback` billing families, which are never folded into `/metrics` |
| `bundled` | `alert`, `dashboard`, `alert_and_dashboard`, or `documented_only` (explicitly no bundled alert/dashboard yet) |
| `emission` | `always`, `conditional`, `when_series_present`, `when_plugin_enabled`, or `when_process_initialized` |

Dynamic families (AI token counters, mesh BPF prefix overrides, request_mirror lifecycle counters, chargeback sink series) are inventoried explicitly — CI does not rediscover them with brittle source regex alone. Hosted CI also scans production Rust string-literal `# TYPE` declarations and rejects any literal exported family absent from this inventory (or any type mismatch). The mesh BPF plugin defaults to prefix `ferrum_mesh_bpf`; inventory names use that default, and `name_template` records `{prefix}_…` for overrides.

Scrape rendering stays allocation-light: the inventory is a documentation/CI contract only and is **not** scanned on the `/metrics` hot path.

## Operator runbooks for newly documented families

### Database rejected-delta polling

| Family | Type | Labels | Guidance |
|--------|------|--------|----------|
| `ferrum_database_delta_rejections_total` | counter | `resource_category`, `namespace` | Rising rejections mean incremental DB deltas failed validation; last-known-good config keeps serving. Inspect Admin `/health` `database_polling` and the rejected resource category. |
| `ferrum_database_delta_consecutive_identical_rejections` | gauge | `namespace` | Counts identical rejected deltas currently being retried. Alert when this stays elevated: the poller is stuck on a bad delta and will eventually force a full reload. |
| `ferrum_database_delta_backoff_bucket` | gauge | `bucket`, `namespace` | Exactly one backoff bucket is `1`. Movement toward `gte_5m` / `max` indicates prolonged rejection pressure. |
| `ferrum_database_delta_forced_full_reloads_total` | counter | `namespace` | Authoritative full reloads triggered by repeated rejections. Correlate with recoveries. |
| `ferrum_database_delta_recoveries_total` | counter | `namespace` | Recovery after an accepted incremental apply or full reload. |
| `ferrum_database_poll_last_completed_timestamp_seconds` | gauge | `namespace` | Poll-task freshness (including empty success). Alert when `time() - metric` exceeds your poll SLO. |

**Suggested alert:** `ferrum_database_delta_consecutive_identical_rejections > 0` for 10m, or backoff bucket in `{gte_5m,max}` for 5m, while serving last-known-good. Mitigations: fix the rejected config mutation, confirm DB connectivity, and watch for a forced full reload + recovery.

### Mesh remote-cluster endpoint discovery

| Family | Type | Labels | Guidance |
|--------|------|--------|----------|
| `ferrum_mesh_remote_discovery_poll_failures_total` | counter | `cluster`, `trust_domain`, `control_plane`, `gateway_namespace` | Failures against a remote control plane. The `control_plane` label is redacted to a non-URL token (never a raw URL). |
| `ferrum_mesh_remote_discovery_poll_successes_total` | counter | `cluster`, `trust_domain`, `gateway_namespace` | Successful discovery polls. |
| `ferrum_mesh_remote_discovery_last_success_timestamp_seconds` | gauge | `cluster`, `trust_domain`, `gateway_namespace` | Unix timestamp of last successful poll. |
| `ferrum_mesh_remote_discovery_endpoint_age_seconds` | gauge | `cluster`, `trust_domain`, `gateway_namespace` | Age of cached remote endpoints. Increases while pollers preserve last-good data. |

**Poll-failure runbook:** on `increase(ferrum_mesh_remote_discovery_poll_failures_total[10m]) > 0`, check peer CP reachability, JWT/audience, and TLS trust for that `cluster`/`trust_domain`. Last-good endpoints remain until a successful poll or explicit withdrawal — confirm with authenticated `GET /mesh/remote-clusters`. See also [mesh_multicluster_federation_runbook.md](mesh_multicluster_federation_runbook.md).

**Endpoint-age runbook:** alert when `ferrum_mesh_remote_discovery_endpoint_age_seconds` exceeds your freshness window (for example 10–15m). Rising age with flat successes means polls are failing or stalled; rising age after cluster removal should resolve once metrics are withdrawn. Do not force-fail data-plane traffic solely on age — fail closed only when policy requires fresh endpoints.

### Raw-TCP mesh egress

| Family | Type | Labels | Guidance |
|--------|------|--------|----------|
| `ferrum_mesh_tcp_egress_connections_total` | counter | `transport`, `result`, `namespace` | Raw-TCP mesh egress relays by `transport` (`hbone` / `mtls`) and `result` (`success` / `failure`). |

**Suggested alert:** `sum(rate(ferrum_mesh_tcp_egress_connections_total{result="failure"}[5m]))` above baseline. Investigate orig-dst capture, outbound registry admits, and HBONE/mTLS dial failures for stream-family ports.

## Complete family inventory

Sorted by family name. Optional namespace labels are listed when the emitter supports them.

| Name | Type | Labels | Subsystem | Bundled | Emission | Help |
|------|------|--------|-----------|---------|----------|------|
| `chargeback_sink_events_enqueued_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink events admitted to the in-memory channel or accepted by a durable overflow handoff. |
| `chargeback_sink_events_exported_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink events successfully exported to ClickHouse. |
| `chargeback_sink_export_failures_total` | counter | `reason` | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink export failures by bounded reason. |
| `chargeback_sink_export_latency_seconds` | histogram | `le` | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink ClickHouse export latency in seconds. |
| `chargeback_sink_queue_byte_budget_exhausted_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink export admissions rejected by the retained-byte budget. |
| `chargeback_sink_queue_depth` | gauge | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink in-memory queue depth. |
| `chargeback_sink_queue_full_drops_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink events dropped because the bounded in-memory queue was full and no durable overflow path accepted ownership. Shutdown/unavailable admission is not counted here. |
| `chargeback_sink_queue_high_water_diversions_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink events whose high-water durable spool-delivery handoff was accepted. Spool delivery saturation/closure is counted by spool loss metrics, not this counter. |
| `chargeback_sink_queue_high_water_hits_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink enqueue attempts observed at or above the queue high-water mark (telemetry only). |
| `chargeback_sink_queue_retained_bytes` | gauge | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink retained export and spool-delivery bytes under the configured buffer_max_bytes budget. |
| `chargeback_sink_snapshot_cardinality_rejections_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Snapshot charges that could not be accumulated or overflow-spooled under hard budgets. |
| `chargeback_sink_snapshot_emits_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink snapshot delta events emitted. |
| `chargeback_sink_snapshot_entries` | gauge | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Snapshot accumulator identities retained in memory. |
| `chargeback_sink_snapshot_finalizations_oldest_age_seconds` | gauge | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Age in seconds of the oldest pending snapshot finalization recovery. |
| `chargeback_sink_snapshot_finalizations_pending` | gauge | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Snapshot generations retaining unspooled terminal deltas after admission closed. |
| `chargeback_sink_snapshot_finalizations_pending_bytes` | gauge | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Estimated retained bytes for pending snapshot finalization recovery state. |
| `chargeback_sink_snapshot_overflow_pending_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Snapshot overflow charges staged for the next durable emission when async spool handoff was unavailable or its write failed. |
| `chargeback_sink_snapshot_overflow_spooled_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Snapshot charges durably spooled through the bounded async delivery worker after accumulator cardinality or byte budget overflow. |
| `chargeback_sink_snapshot_retained_bytes` | gauge | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Estimated snapshot accumulator retained bytes under configured max_retained_bytes. |
| `chargeback_sink_spool_available` | gauge | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Whether committed spool storage is currently writable (1) or unavailable (0). Aggregate is 1 only when every spool-enabled live instance is available. |
| `chargeback_sink_spool_bytes` | gauge | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink on-disk owned spool bytes (active, temp, corrupt, and dead-lettered files). |
| `chargeback_sink_spool_drops_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink spool files dropped to enforce max_bytes. |
| `chargeback_sink_spool_events_lost_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink events lost with dropped spool delivery jobs. |
| `chargeback_sink_spool_files` | gauge | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink on-disk owned spool file count (active, temp, corrupt, and dead-lettered files). |
| `chargeback_sink_spool_jobs_enqueued_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink jobs accepted by the async spool delivery worker. |
| `chargeback_sink_spool_jobs_lost_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink spool delivery jobs dropped under saturation or write failure. |
| `chargeback_sink_spool_jobs_written_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink jobs successfully written by the async spool delivery worker. |
| `chargeback_sink_spool_prepare_failures_total` | counter | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Chargeback sink committed spool storage preparation failures. |
| `chargeback_sink_spool_unbound_files` | gauge | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Retained spool records not bound to a live destination identity. Never replayed or deleted; an observed lower bound when the bounded aggregate scan is truncated. |
| `chargeback_sink_spool_unbound_namespaces` | gauge | — | `api_chargeback_sink` | `documented_only` | `when_plugin_enabled` | Managed spool namespaces still holding records for a destination identity no live instance owns; an observed lower bound when the bounded aggregate scan is truncated. |
| `ferrum_admin_active_connections` | gauge | `namespace` | `admin` | `documented_only` | `conditional` | Admin/management-plane connections currently in flight. |
| `ferrum_admin_max_connections` | gauge | `namespace` | `admin` | `documented_only` | `conditional` | Configured admin connection cap (0 = unlimited). |
| `ferrum_admin_max_connections_per_ip` | gauge | `namespace` | `admin` | `documented_only` | `conditional` | Configured per-source-IP admin connection cap (0 = unlimited). |
| `ferrum_admin_rejected_connections_total` | counter | `reason`, `namespace` | `admin` | `documented_only` | `conditional` | Admin connections rejected by the connection limiter, by reason. |
| `ferrum_ai_completion_tokens_total` | counter | `proxy_id`, `provider`, `namespace` | `ai` | `documented_only` | `when_series_present` | Completion tokens reported by AI providers. |
| `ferrum_ai_estimated_cost_currency_units_total` | counter | `proxy_id`, `provider`, `namespace` | `ai` | `documented_only` | `when_series_present` | Estimated AI cost in the configured currency units, retaining sub-micro precision and rounding the aggregate to six decimals. |
| `ferrum_ai_federation_circuit_half_open_probes_total` | counter | `namespace` | `ai` | `documented_only` | `always` | ai_federation provider half-open probes admitted. |
| `ferrum_ai_federation_circuit_open_skips_total` | counter | `namespace` | `ai` | `documented_only` | `always` | ai_federation provider attempts skipped by an open circuit. |
| `ferrum_ai_federation_circuits_closed_total` | counter | `namespace` | `ai` | `documented_only` | `always` | ai_federation provider circuit half-open recoveries. |
| `ferrum_ai_federation_circuits_open` | gauge | `namespace` | `ai` | `documented_only` | `always` | Current ai_federation provider circuits in open or half-open recovery state. |
| `ferrum_ai_federation_circuits_opened_total` | counter | `namespace` | `ai` | `documented_only` | `always` | ai_federation provider circuit closed-to-open transitions. |
| `ferrum_ai_prompt_tokens_total` | counter | `proxy_id`, `provider`, `namespace` | `ai` | `documented_only` | `when_series_present` | Prompt tokens reported by AI providers. |
| `ferrum_ai_tokens_total` | counter | `proxy_id`, `provider`, `namespace` | `ai` | `documented_only` | `when_series_present` | Total tokens reported by AI providers. |
| `ferrum_api_bandwidth_charges_total` | counter | `consumer`, `proxy_id`, `proxy_name`, `direction`, `currency`, `protocol_family`, `namespace` | `api_chargeback` | `documented_only` | `when_plugin_enabled` | Total bandwidth charges per consumer, split by direction. |
| `ferrum_api_bytes_received_total` | counter | `consumer`, `proxy_id`, `proxy_name`, `currency`, `protocol_family`, `namespace` | `api_chargeback` | `documented_only` | `when_plugin_enabled` | Total bytes the gateway received backend->client and forwarded to this consumer. |
| `ferrum_api_bytes_sent_total` | counter | `consumer`, `proxy_id`, `proxy_name`, `currency`, `protocol_family`, `namespace` | `api_chargeback` | `documented_only` | `when_plugin_enabled` | Total bytes the gateway sent client->backend on this consumer's behalf. |
| `ferrum_api_chargeable_calls_total` | counter | `consumer`, `proxy_id`, `proxy_name`, `status_code`, `currency`, `namespace` | `api_chargeback` | `documented_only` | `when_plugin_enabled` | Total chargeable HTTP-family API calls per consumer by billable status. |
| `ferrum_api_chargeback_dropped_charges_total` | counter | — | `api_chargeback` | `documented_only` | `when_plugin_enabled` | Charges lost because neither an ordinary billing row nor the aggregate row could be admitted. |
| `ferrum_api_chargeback_identity_overflow_total` | counter | — | `api_chargeback` | `documented_only` | `when_plugin_enabled` | Charges folded into the aggregate overflow row because a new billing row could not be admitted under max_entries (per-identity attribution lost). |
| `ferrum_api_chargeback_registry_entries` | gauge | — | `api_chargeback` | `documented_only` | `when_plugin_enabled` | Billing rows (complete registry entry keys) currently retained against max_entries. |
| `ferrum_api_chargeback_registry_max_entries` | gauge | — | `api_chargeback` | `documented_only` | `when_plugin_enabled` | Configured ceiling on retained billing rows (complete registry entry keys). |
| `ferrum_api_chargeback_registry_max_retained_bytes` | gauge | — | `api_chargeback` | `documented_only` | `when_plugin_enabled` | Configured ceiling on retained registry bytes. |
| `ferrum_api_chargeback_registry_retained_bytes` | gauge | — | `api_chargeback` | `documented_only` | `when_plugin_enabled` | Estimated bytes retained by the shared registry. |
| `ferrum_api_charges_total` | counter | `consumer`, `proxy_id`, `proxy_name`, `status_code`, `currency`, `namespace` | `api_chargeback` | `documented_only` | `when_plugin_enabled` | Total per-call charges accumulated per consumer. |
| `ferrum_api_stream_connection_charges_total` | counter | `consumer`, `proxy_id`, `proxy_name`, `currency`, `namespace` | `api_chargeback` | `documented_only` | `when_plugin_enabled` | Total per-connection charges for stream sessions. |
| `ferrum_api_stream_connections_total` | counter | `consumer`, `proxy_id`, `proxy_name`, `currency`, `namespace` | `api_chargeback` | `documented_only` | `when_plugin_enabled` | Total stream sessions (TCP/UDP/DTLS) per consumer. |
| `ferrum_backend_duration_ms` | histogram | `proxy_id`, `le`, `namespace` | `prometheus_metrics` | `dashboard` | `always` | Backend response time in milliseconds. |
| `ferrum_client_disconnects_total` | counter | `proxy_id`, `namespace` | `prometheus_metrics` | `dashboard` | `conditional` | Requests where the client disconnected before receiving the full response. |
| `ferrum_compression_codec_admitted_total` | counter | `namespace` | `compression` | `documented_only` | `always` | Compression codec jobs admitted to the bounded spawn_blocking pool. |
| `ferrum_compression_codec_join_failures_total` | counter | `namespace` | `compression` | `documented_only` | `always` | Compression codec spawn_blocking tasks that failed to join. |
| `ferrum_compression_codec_saturated_total` | counter | `namespace` | `compression` | `documented_only` | `always` | Compression codec admission refusals when the bounded pool is saturated. |
| `ferrum_compression_codec_worker_failures_total` | counter | `namespace` | `compression` | `documented_only` | `always` | Compression codec worker errors (encode/decode failures inside spawn_blocking). |
| `ferrum_compression_response_buffer_admitted_total` | counter | `namespace` | `compression` | `documented_only` | `always` | Response-compression buffer admissions granted (bounds bodies collected for compression). |
| `ferrum_compression_response_buffer_saturated_total` | counter | `namespace` | `compression` | `documented_only` | `always` | Response-compression buffer admission refusals; the response streams identity (or 406) instead. |
| `ferrum_configsync_delta_rejections_total` | counter | `namespace` | `configsync` | `documented_only` | `conditional` | Non-empty ConfigSync deltas rejected by the DP, forcing an authoritative FULL_SNAPSHOT resync. |
| `ferrum_configsync_diverged` | gauge | `namespace` | `configsync` | `documented_only` | `conditional` | Whether the DP is currently sticky-diverged after a rejected ConfigSync delta (1) or converged (0). |
| `ferrum_configsync_divergence_recoveries_total` | counter | `namespace` | `configsync` | `documented_only` | `conditional` | ConfigSync divergence recoveries after an accepted authoritative FULL_SNAPSHOT. |
| `ferrum_configsync_fenced_full_snapshots_total` | counter | `namespace` | `configsync` | `documented_only` | `conditional` | ConfigSync FULL_SNAPSHOTs the DP fenced without applying (stale/older, unorderable/inconsistent, or an implausibly-future CP clock stamp); last-known-good config keeps serving. |
| `ferrum_cp_grpc_active_connections` | gauge | `namespace` | `cp_grpc` | `documented_only` | `conditional` | CP gRPC listener connections currently admitted (pre-handshake through served HTTP/2 session). |
| `ferrum_cp_grpc_max_connections` | gauge | `namespace` | `cp_grpc` | `documented_only` | `conditional` | Configured CP gRPC connection cap (0 = unlimited). |
| `ferrum_cp_grpc_max_connections_per_ip` | gauge | `namespace` | `cp_grpc` | `documented_only` | `conditional` | Configured per-source-IP CP gRPC connection cap (0 = unlimited). |
| `ferrum_cp_grpc_rejected_connections_total` | counter | `reason`, `namespace` | `cp_grpc` | `documented_only` | `conditional` | CP gRPC connections rejected before any handshake work was allocated, by reason. |
| `ferrum_database_change_stream_connected` | gauge | `namespace` | `database_polling` | `documented_only` | `conditional` | Whether the backend config-change watcher currently has an open stream (1) or is degraded (0). Periodic polling stays authoritative either way. |
| `ferrum_database_change_stream_degraded_reason` | gauge | `reason`, `namespace` | `database_polling` | `documented_only` | `conditional` | Current bounded degraded reason for the backend config-change watcher. Exactly one reason is 1. |
| `ferrum_database_change_stream_events_total` | counter | `namespace` | `database_polling` | `documented_only` | `conditional` | Config-change notifications observed by the backend watcher. Each one only triggers the authoritative cursor poll; it never advances the accepted sequence. |
| `ferrum_database_change_stream_history_losses_total` | counter | `namespace` | `database_polling` | `documented_only` | `conditional` | Times the retained watch resume point fell out of the backend's history and was dropped. |
| `ferrum_database_change_stream_invalidations_total` | counter | `namespace` | `database_polling` | `documented_only` | `conditional` | Backend config-change watch invalidations (watched collection dropped, renamed, or database dropped). |
| `ferrum_database_change_stream_reconnects_total` | counter | `namespace` | `database_polling` | `documented_only` | `conditional` | Times the backend config-change watcher (re)established a stream. |
| `ferrum_database_delta_backoff_bucket` | gauge | `bucket`, `namespace` | `database_polling` | `documented_only` | `conditional` | Current rejected-delta retry backoff bucket. Exactly one bucket is 1. |
| `ferrum_database_delta_consecutive_identical_rejections` | gauge | `namespace` | `database_polling` | `documented_only` | `conditional` | Consecutive identical rejected database deltas currently being retried. |
| `ferrum_database_delta_forced_full_reloads_total` | counter | `namespace` | `database_polling` | `documented_only` | `conditional` | Authoritative full reload attempts triggered by repeated rejected database deltas. |
| `ferrum_database_delta_recoveries_total` | counter | `namespace` | `database_polling` | `documented_only` | `conditional` | Rejected database delta recovery events after an accepted incremental apply or full reload. |
| `ferrum_database_delta_rejections_total` | counter | `resource_category`, `namespace` | `database_polling` | `documented_only` | `conditional` | Database incremental deltas rejected by validation, bucketed by bounded resource category. |
| `ferrum_database_poll_last_completed_timestamp_seconds` | gauge | `namespace` | `database_polling` | `documented_only` | `conditional` | Unix timestamp of the most recently completed database/CP config poll attempt (including empty success). |
| `ferrum_edge_overhead_ms` | histogram | `proxy_id`, `le`, `namespace` | `prometheus_metrics` | `dashboard` | `always` | Gateway overhead (excluding backend and plugins) in milliseconds. |
| `ferrum_kafka_logging_accepting` | gauge | `generation` | `kafka_logging` | `documented_only` | `when_plugin_enabled` | Whether the Kafka logging generation still admits new records. |
| `ferrum_kafka_logging_healthy` | gauge | `generation` | `kafka_logging` | `documented_only` | `when_plugin_enabled` | Whether the Kafka logging generation recovered from its latest failure. |
| `ferrum_kafka_logging_in_flight` | gauge | `generation` | `kafka_logging` | `documented_only` | `when_plugin_enabled` | Records waiting in librdkafka for terminal delivery. |
| `ferrum_kafka_logging_records_total` | counter | `generation`, `outcome` | `kafka_logging` | `documented_only` | `when_plugin_enabled` | Kafka logging record outcomes. |
| `ferrum_kafka_logging_retained_bytes` | gauge | `generation` | `kafka_logging` | `documented_only` | `when_plugin_enabled` | Ferrum userspace retained payload+key bytes awaiting librdkafka admission. |
| `ferrum_log_sink_accepted_records_total` | counter | `sink` | `logging` | `documented_only` | `when_process_initialized` | Records accepted by the bounded process log sink. |
| `ferrum_log_sink_dropped_records_total` | counter | `sink`, `reason` | `logging` | `documented_only` | `when_process_initialized` | Log records dropped by bounded admission. |
| `ferrum_log_sink_healthy` | gauge | `sink` | `logging` | `documented_only` | `when_process_initialized` | Whether the process log sink has recovered from its latest I/O or drain failure. |
| `ferrum_log_sink_io_failures_total` | counter | `sink`, `operation` | `logging` | `documented_only` | `when_process_initialized` | Underlying writer and flush failures. |
| `ferrum_log_sink_queued_bytes` | gauge | `sink` | `logging` | `documented_only` | `when_process_initialized` | Serialized bytes admitted but not yet completed. |
| `ferrum_log_sink_queued_records` | gauge | `sink` | `logging` | `documented_only` | `when_process_initialized` | Records admitted but not yet completed. |
| `ferrum_log_sink_reserved_bytes` | gauge | `sink` | `logging` | `documented_only` | `when_process_initialized` | Byte budget reserved by admitted records. |
| `ferrum_log_sink_shutdown_incomplete_records_total` | counter | `sink` | `logging` | `documented_only` | `when_process_initialized` | Records still outstanding when a bounded drain deadline was reached. |
| `ferrum_log_sink_shutdown_timeouts_total` | counter | `sink` | `logging` | `documented_only` | `when_process_initialized` | Bounded process log drain deadlines reached. |
| `ferrum_mesh_bpf_drop_reasons` | gauge | `reason` | `mesh_bpf` | `documented_only` | `when_plugin_enabled` | Well-known BPF drop reason labels (gauge=1 to make the label set self-documenting). |
| `ferrum_mesh_bpf_drops_total` | counter | `reason` | `mesh_bpf` | `documented_only` | `when_plugin_enabled` | Connection-bypass decisions by reason, produced by the connect4/connect6 capture hooks. |
| `ferrum_mesh_bpf_ringbuf_events_total` | counter | — | `mesh_bpf` | `documented_only` | `when_plugin_enabled` | Total events drained from the SOCK_OPS ringbuf. |
| `ferrum_mesh_bpf_ringbuf_in_overrun_regime` | gauge | — | `mesh_bpf` | `documented_only` | `when_plugin_enabled` | 1 while the consumer is in an overrun regime, 0 after recovery. Pair with `_overruns_total` for alerting. |
| `ferrum_mesh_bpf_ringbuf_overruns_total` | counter | — | `mesh_bpf` | `documented_only` | `when_plugin_enabled` | Ringbuf overrun episodes. Incremented when the kernel dropped-events counter advances between polls, and once when attaching (or re-attaching after pin rotation) to a map generation that already reports a nonzero dropped total. Non-zero = userspace fell behind and the kernel dropped events. Set FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES higher. |
| `ferrum_mesh_bpf_srtt_microseconds` | histogram | `le` | `mesh_bpf` | `documented_only` | `when_plugin_enabled` | TCP smoothed RTT samples in microseconds. Fixed le buckets plus sum/count; zero samples are ignored and sum overflow drops the sample. |
| `ferrum_mesh_bpf_syn_to_ack_microseconds` | histogram | `le` | `mesh_bpf` | `documented_only` | `when_plugin_enabled` | Time between SYN send and ACK observation in microseconds. Fixed le buckets plus sum/count; zero samples are ignored and sum overflow drops the sample. |
| `ferrum_mesh_bpf_tcp_events_total` | counter | `event` | `mesh_bpf` | `documented_only` | `when_plugin_enabled` | TCP-layer events captured by the BPF SOCK_OPS program. event="rst" counts abnormal ESTABLISHED→CLOSE transitions without sent/received attribution (SOCK_OPS state callbacks cannot distinguish direction). |
| `ferrum_mesh_ca_health` | gauge | `ca_type`, `gateway_namespace` | `mesh` | `alert_and_dashboard` | `conditional` | Mesh CA backend health, 1 healthy and 0 unhealthy. |
| `ferrum_mesh_cert_expiry_seconds` | gauge | `spiffe_id`, `source`, `gateway_namespace` | `mesh` | `alert_and_dashboard` | `conditional` | Seconds until mesh X.509-SVID expiry. |
| `ferrum_mesh_cert_rotation_failures_total` | counter | `spiffe_id`, `source`, `gateway_namespace` | `mesh` | `alert_and_dashboard` | `conditional` | Mesh certificate rotation failures. |
| `ferrum_mesh_config_last_received_timestamp_seconds` | gauge | `namespace`, `gateway_namespace` | `mesh` | `alert_and_dashboard` | `conditional` | Unix timestamp of the last installed mesh config slice. |
| `ferrum_mesh_config_revision_adoptions_total` | counter | `gateway_namespace` | `mesh` | `documented_only` | `always` | Foreign mesh config authorities adopted after the configured grace period. |
| `ferrum_mesh_config_revision_rejections_total` | counter | `reason`, `gateway_namespace` | `mesh` | `documented_only` | `conditional` | Mesh slices quarantined by the config-revision freshness gate before replacing live state, by reason. |
| `ferrum_mesh_config_update_rejections_total` | counter | `consumer`, `reason`, `gateway_namespace` | `mesh` | `documented_only` | `conditional` | MeshSubscribe responses refused before apply, by consumer and reason. |
| `ferrum_mesh_dns_upstream_id_exhaustions_total` | counter | `namespace` | `mesh` | `documented_only` | `always` | Mesh DNS upstream transaction ID exhaustion events. |
| `ferrum_mesh_federation_bundle_age_seconds` | gauge | `trust_domain`, `gateway_namespace` | `mesh_federation` | `alert_and_dashboard` | `conditional` | Age of the cached federated trust bundle, in seconds. |
| `ferrum_mesh_federation_last_success_timestamp_seconds` | gauge | `trust_domain`, `gateway_namespace` | `mesh_federation` | `documented_only` | `conditional` | Unix timestamp of last successful SPIFFE federation poll. |
| `ferrum_mesh_federation_poll_failures_total` | counter | `trust_domain`, `endpoint`, `gateway_namespace` | `mesh_federation` | `alert_and_dashboard` | `conditional` | SPIFFE federation trust-bundle poll failures. |
| `ferrum_mesh_hbone_relay_failures_total` | counter | `proxy_id`, `direction`, `error_class`, `namespace` | `mesh` | `documented_only` | `conditional` | HBONE CONNECT tunnel relay failures after the 200 response has been sent. |
| `ferrum_mesh_inbound_plaintext_allowed` | gauge | `gateway_namespace` | `mesh` | `documented_only` | `always` | 1 when the mesh inbound listener was allowed to come up without enforced mTLS (dev opt-out posture; production mode refuses this). 0 otherwise. |
| `ferrum_mesh_mtls_handshake_failures_total` | counter | `reason`, `gateway_namespace` | `mesh` | `alert_and_dashboard` | `conditional` | Frontend mesh TLS/mTLS handshake failures. |
| `ferrum_mesh_node_topology_degraded` | gauge | `reason`, `namespace` | `mesh` | `documented_only` | `conditional` | Node-agent detected missing eBPF prerequisites or a build without eBPF capture. 1 with a reason label means degraded, 0 with reason="none" means nominal. |
| `ferrum_mesh_node_waypoint_asserted_identity_total` | counter | `result`, `reason`, `gateway_namespace` | `mesh_node_waypoint` | `dashboard` | `conditional` | Asserted source-identity decisions on inbound NodeWaypoint HBONE. Rejection reasons are compile-time-bounded; SPIFFE IDs never appear as labels. |
| `ferrum_mesh_node_waypoint_destination_policy_rejections_total` | counter | `reason`, `gateway_namespace` | `mesh_node_waypoint` | `dashboard` | `conditional` | Destination-side AuthorizationPolicy / scope / open-relay rejections on NodeWaypoint. Distinct from asserted-identity rejections. |
| `ferrum_mesh_node_waypoint_hbone_handshakes_total` | counter | `phase`, `result`, `gateway_namespace` | `mesh_node_waypoint` | `alert_and_dashboard` | `conditional` | NodeWaypoint HBONE handshake outcomes by phase. One failed session increments exactly one phase (inbound_tls XOR inbound_connect on the destination; outbound_dial is independent on the source). |
| `ferrum_mesh_node_waypoint_missing_destination_metadata_total` | counter | `gateway_namespace` | `mesh_node_waypoint` | `dashboard` | `conditional` | Secured NodeWaypoint service targets skipped because Workload.node_waypoint metadata was absent. |
| `ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total` | counter | `gateway_namespace` | `mesh_node_waypoint` | `dashboard` | `conditional` | Prohibited plaintext fallback attempts blocked under identity-backed NodeWaypoint (fail-closed instead of retaining a plaintext backend). |
| `ferrum_mesh_outbound_registry_decisions_total` | counter | `mesh_namespace`, `host`, `decision`, `namespace` | `mesh` | `dashboard` | `conditional` | Mesh outbound registry decisions with bounded host buckets (<admit_explicit>, <admit_wildcard>, <denied>). |
| `ferrum_mesh_outbound_registry_stream_decisions_total` | counter | `mesh_namespace`, `protocol`, `decision`, `namespace` | `mesh` | `documented_only` | `conditional` | Mesh outbound registry decisions for stream-family egress (TCP/UDP/TCP+TLS/UDP+DTLS) by protocol. |
| `ferrum_mesh_remote_discovery_endpoint_age_seconds` | gauge | `cluster`, `trust_domain`, `gateway_namespace` | `mesh_remote_discovery` | `documented_only` | `conditional` | Age of the cached remote-cluster endpoints, in seconds. |
| `ferrum_mesh_remote_discovery_last_success_timestamp_seconds` | gauge | `cluster`, `trust_domain`, `gateway_namespace` | `mesh_remote_discovery` | `documented_only` | `conditional` | Unix timestamp of last successful remote-cluster endpoint discovery poll. |
| `ferrum_mesh_remote_discovery_poll_failures_total` | counter | `cluster`, `trust_domain`, `control_plane`, `gateway_namespace` | `mesh_remote_discovery` | `documented_only` | `conditional` | Remote-cluster endpoint discovery poll failures. |
| `ferrum_mesh_remote_discovery_poll_successes_total` | counter | `cluster`, `trust_domain`, `gateway_namespace` | `mesh_remote_discovery` | `documented_only` | `conditional` | Successful remote-cluster endpoint discovery polls. |
| `ferrum_mesh_request_duration_ms` | histogram | `source_workload`, `source_namespace`, `source_principal`, `source_app`, `source_service`, `destination_workload`, `destination_namespace`, `destination_principal`, `destination_app`, `destination_service`, `request_protocol`, `response_code`, `response_flags`, `connection_security_policy`, `gateway_namespace`, `le` | `mesh` | `dashboard` | `conditional` | Mesh request duration in milliseconds. |
| `ferrum_mesh_requests_total` | counter | `source_workload`, `source_namespace`, `source_principal`, `source_app`, `source_service`, `destination_workload`, `destination_namespace`, `destination_principal`, `destination_app`, `destination_service`, `request_protocol`, `response_code`, `response_flags`, `connection_security_policy`, `gateway_namespace` | `mesh` | `alert_and_dashboard` | `conditional` | Mesh requests by Istio/GAMMA identity labels. |
| `ferrum_mesh_subscribe_audience_rejections_total` | counter | `subscription`, `reason`, `gateway_namespace` | `mesh` | `documented_only` | `conditional` | MeshSubscribe subscriptions refused by the control plane because the bearer JWT audience does not match the required subscription purpose, by subscription class and reason. |
| `ferrum_mesh_tcp_egress_connections_total` | counter | `transport`, `result`, `namespace` | `mesh` | `documented_only` | `conditional` | Raw-TCP mesh egress relay connections by transport and outcome. |
| `ferrum_mesh_trust_bundle_version` | gauge | `trust_domain`, `source`, `gateway_namespace` | `mesh` | `dashboard` | `conditional` | Monotonic version of observed mesh trust bundles. |
| `ferrum_node_agent_attach_errors_total` | counter | `namespace` | `node_agent` | `documented_only` | `conditional` | Node-agent BPF attachment or map update errors. |
| `ferrum_node_agent_capture_state` | gauge | `state`, `namespace` | `node_agent` | `documented_only` | `conditional` | Node-agent capture backend condition. Exactly one state label is 1. |
| `ferrum_node_agent_cni_socket_lifecycle_total` | counter | `reason`, `namespace` | `node_agent` | `documented_only` | `conditional` | Node-agent CNI socket lifecycle failures by bounded reason. |
| `ferrum_node_agent_pod_annotation_updates_applied_total` | counter | `namespace` | `node_agent` | `documented_only` | `conditional` | Mid-life pod includeOutboundPorts annotation changes re-applied to the BPF map. |
| `ferrum_node_agent_pod_annotation_updates_failed_total` | counter | `namespace` | `node_agent` | `documented_only` | `conditional` | Mid-life pod includeOutboundPorts annotation changes that failed to re-apply (annotation parse error or BPF map write error). Cgroup-id-unavailable retries are intentionally not counted here because they are routinely observed during early pod startup and are retried on the next Apply event. |
| `ferrum_node_agent_pods_enrolled_total` | counter | `namespace` | `node_agent` | `documented_only` | `conditional` | Pods enrolled for node-agent capture. |
| `ferrum_node_agent_pods_unenrolled_total` | counter | `namespace` | `node_agent` | `documented_only` | `conditional` | Pods unenrolled from node-agent capture. |
| `ferrum_notification_delivery_abandoned_at_deadline_total` | counter | `channel_type` | `notifications` | `documented_only` | `always` | Notification deliveries hard-aborted because the global observability shutdown drain deadline expired; the shutdown_deadline slice of ferrum_notification_delivery_abandoned_total. |
| `ferrum_notification_delivery_abandoned_total` | counter | `channel_type`, `reason` | `notifications` | `documented_only` | `always` | Notification delivery tasks whose body started executing but settled without a committed outcome, by fixed reason (generation_retired = producer reload/Drop, shutdown_deadline = hard abort at the global drain deadline, task_dropped = dispatch task dropped without settling). |
| `ferrum_notification_delivery_attempted_total` | counter | `channel_type` | `notifications` | `documented_only` | `always` | Notification delivery tasks whose registry-owned delivery body started executing (counted once per admitted task, not once per bounded retry; may advance before any channel transport call). |
| `ferrum_notification_delivery_backpressure_dropped_total` | counter | `channel_type` | `notifications` | `documented_only` | `always` | Notification deliveries dropped because the bounded dispatch semaphore was exhausted. |
| `ferrum_notification_delivery_failed_permanent_total` | counter | `channel_type` | `notifications` | `documented_only` | `always` | Notification deliveries that failed with a permanent (non-retryable) outcome. |
| `ferrum_notification_delivery_failed_transient_total` | counter | `channel_type` | `notifications` | `documented_only` | `always` | Notification deliveries that exhausted retries on transient transport/HTTP failures. |
| `ferrum_notification_delivery_in_flight` | gauge | `channel_type` | `notifications` | `documented_only` | `always` | Notification deliveries currently executing (including bounded retry backoff). |
| `ferrum_notification_delivery_rejected_total` | counter | `channel_type`, `reason` | `notifications` | `documented_only` | `always` | Notification deliveries rejected before the registry-owned delivery body started, by fixed reason (generation_closed = producer reload/Drop closed admission, registry_rejected = process delivery registry refused the task). |
| `ferrum_notification_delivery_succeeded_total` | counter | `channel_type` | `notifications` | `documented_only` | `always` | Notification deliveries that completed successfully (after any bounded retries). |
| `ferrum_observability_batch_materialization_fallbacks_total` | counter | — | `observability_delivery` | `documented_only` | `always` | Batches delivered complete but in a degraded representation, such as uncompressed because the compressed copy could not be reserved. No record loss. |
| `ferrum_observability_batch_materialization_losses_total` | counter | — | `observability_delivery` | `documented_only` | `always` | Discard events, each of which lost one or more records. |
| `ferrum_observability_batch_materialization_lost_records_total` | counter | — | `observability_delivery` | `documented_only` | `always` | Log entries, spans, and rows discarded because their batch representation could not be materialized under the retained-byte ceiling. Counts records, not reservations. |
| `ferrum_observability_delivery_active_tasks` | gauge | — | `observability_delivery` | `documented_only` | `always` | Deferred observability tasks currently owned by the shutdown lifecycle. |
| `ferrum_observability_delivery_active_workers` | gauge | — | `observability_delivery` | `documented_only` | `always` | Queue workers currently owned by the shutdown lifecycle. |
| `ferrum_observability_delivery_admitted_tasks` | gauge | — | `observability_delivery` | `documented_only` | `always` | Deferred observability tasks holding an admission permit (registry plus in-flight spawn handoff). |
| `ferrum_observability_delivery_cancelled_tasks_total` | counter | — | `observability_delivery` | `documented_only` | `always` | Delivery tasks cancelled on shutdown-budget expiry or during spawn/cancel handoff races. |
| `ferrum_observability_delivery_capacity_rejected_tasks_total` | counter | — | `observability_delivery` | `documented_only` | `always` | Delivery tasks rejected specifically because the aggregate task budget was exhausted. |
| `ferrum_observability_delivery_drain_timeouts_total` | counter | — | `observability_delivery` | `documented_only` | `always` | Observability shutdown drains that exhausted their shared deadline. |
| `ferrum_observability_delivery_generation` | gauge | — | `observability_delivery` | `documented_only` | `always` | Current delivery lifecycle generation; increments when a serving cycle reopens delivery after a drain. |
| `ferrum_observability_delivery_lost_worker_records_total` | counter | — | `observability_delivery` | `documented_only` | `always` | Queued records abandoned when worker drain exceeded the shutdown budget. |
| `ferrum_observability_delivery_max_tasks` | gauge | — | `observability_delivery` | `documented_only` | `always` | Configured aggregate admission budget for terminal, mirror, and deadline-cleanup tasks. |
| `ferrum_observability_delivery_rejected_tasks_total` | counter | — | `observability_delivery` | `documented_only` | `always` | Delivery tasks rejected after lifecycle admission closed, task-budget exhaustion, or without a runtime. |
| `ferrum_observability_max_retained_bytes` | gauge | — | `observability_delivery` | `documented_only` | `always` | Configured process-wide retained-byte ceiling shared by all observability sink instances. |
| `ferrum_observability_process_ceiling_rejections_total` | counter | — | `observability_delivery` | `documented_only` | `always` | Sink admissions refused specifically by the process-wide retained-byte ceiling rather than a per-instance budget. |
| `ferrum_observability_retained_bytes` | gauge | — | `observability_delivery` | `documented_only` | `always` | Bytes currently retained across every observability sink instance in this process. |
| `ferrum_observability_retained_bytes_high_water` | gauge | — | `observability_delivery` | `documented_only` | `always` | Peak process-wide observability retention observed since startup. |
| `ferrum_rate_limit_exceeded_total` | counter | `namespace` | `prometheus_metrics` | `dashboard` | `always` | Total rate limit rejections. |
| `ferrum_request_duration_ms` | histogram | `proxy_id`, `le`, `namespace` | `prometheus_metrics` | `dashboard` | `always` | Request duration in milliseconds. |
| `ferrum_request_mirror_budget_drops_total` | counter | `namespace` | `request_mirror` | `documented_only` | `always` | request_mirror attempts dropped because max_retained_request_body_bytes was exhausted. |
| `ferrum_request_mirror_cancellations_total` | counter | `namespace` | `request_mirror` | `documented_only` | `always` | request_mirror tasks dropped before a terminal outcome (shutdown/panic/cancellation). |
| `ferrum_request_mirror_completed_total` | counter | `namespace` | `request_mirror` | `documented_only` | `always` | request_mirror tasks that fully drained a response within byte and time bounds. |
| `ferrum_request_mirror_concurrency_drops_total` | counter | `namespace` | `request_mirror` | `documented_only` | `always` | request_mirror attempts dropped because max_in_flight was saturated. |
| `ferrum_request_mirror_dispatched_total` | counter | `namespace` | `request_mirror` | `documented_only` | `always` | request_mirror detached tasks admitted past concurrency and retained-body budgets. |
| `ferrum_request_mirror_drain_failures_total` | counter | `namespace` | `request_mirror` | `documented_only` | `always` | request_mirror response-body drain transport failures. |
| `ferrum_request_mirror_drain_timeouts_total` | counter | `namespace` | `request_mirror` | `documented_only` | `always` | request_mirror response-body drain deadline expiries. |
| `ferrum_request_mirror_drain_truncations_total` | counter | `namespace` | `request_mirror` | `documented_only` | `always` | request_mirror responses truncated at max_response_body_bytes during bounded drain. |
| `ferrum_request_mirror_request_failures_total` | counter | `namespace` | `request_mirror` | `documented_only` | `always` | request_mirror pre-response transport failures (DNS, refused, reset, TLS, …). |
| `ferrum_request_mirror_request_timeouts_total` | counter | `namespace` | `request_mirror` | `documented_only` | `always` | request_mirror request-phase deadline expiries (connect/headers/body). |
| `ferrum_requests_total` | counter | `proxy_id`, `method`, `status_code`, `grpc_status`, `namespace` | `prometheus_metrics` | `dashboard` | `always` | Total number of requests processed. |
| `ferrum_stream_connections_total` | counter | `proxy_id`, `protocol`, `namespace` | `stream` | `dashboard` | `conditional` | Total stream connections (TCP/UDP). |
| `ferrum_stream_disconnects_total` | counter | `proxy_id`, `protocol`, `cause`, `direction`, `namespace` | `stream` | `dashboard` | `conditional` | Stream disconnects (TCP/UDP) by cause and direction. |
| `ferrum_stream_duration_ms` | histogram | `proxy_id`, `le`, `namespace` | `stream` | `documented_only` | `conditional` | Stream connection duration in milliseconds. |
| `ferrum_tls_cert_expiry_seconds` | gauge | `cert_id`, `surface`, `source_kind`, `namespace` | `tls` | `documented_only` | `conditional` | Seconds until the certificate leaf not_after timestamp. Negative means expired. |
| `ferrum_tls_cert_not_before_seconds` | gauge | `cert_id`, `surface`, `source_kind`, `namespace` | `tls` | `documented_only` | `conditional` | Certificate leaf not_before timestamp as Unix seconds. |
| `ferrum_tls_cert_rotations_total` | counter | `cert_id`, `reason`, `outcome`, `namespace` | `tls` | `documented_only` | `conditional` | TLS certificate rotation outcomes by cert ID, reason, and outcome. |
| `ferrum_tls_inventory_snapshot_max_age_seconds` | gauge | `namespace` | `tls` | `documented_only` | `conditional` | Configured maximum snapshot age (FERRUM_TLS_INVENTORY_SNAPSHOT_TTL_SECONDS) before a scrape schedules a background refresh. |
| `ferrum_tls_inventory_snapshot_timestamp_seconds` | gauge | `namespace` | `tls` | `documented_only` | `conditional` | Unix timestamp of the cached, non-secret TLS inventory snapshot backing the certificate gauges. |
| `ferrum_tls_source_fetch_duration_seconds` | histogram | `scheme`, `kind`, `le`, `namespace` | `tls` | `documented_only` | `conditional` | TLS material source fetch duration in seconds. |
| `ferrum_tls_source_fetch_failures_total` | counter | `scheme`, `kind`, `reason`, `namespace` | `tls` | `documented_only` | `conditional` | TLS material source fetch failures by scheme, kind, and bounded reason. |
| `ferrum_tls_source_refresh_total` | counter | `scheme`, `kind`, `surface`, `outcome`, `namespace` | `tls` | `documented_only` | `conditional` | TLS material source refresh attempts by scheme, kind, surface, and outcome. |
| `ferrum_websocket_bytes_total` | counter | `proxy_id`, `direction`, `namespace` | `websocket` | `documented_only` | `conditional` | WebSocket payload bytes relayed by direction. |
| `ferrum_websocket_frames_total` | counter | `proxy_id`, `direction`, `namespace` | `websocket` | `documented_only` | `conditional` | WebSocket frames relayed by direction. |
| `ferrum_websocket_session_duration_ms` | histogram | `proxy_id`, `result`, `direction`, `io_side`, `error_class`, `le`, `namespace` | `websocket` | `documented_only` | `conditional` | WebSocket session duration in milliseconds. |
| `ferrum_websocket_sessions_total` | counter | `proxy_id`, `result`, `direction`, `io_side`, `error_class`, `namespace` | `websocket` | `documented_only` | `conditional` | Completed WebSocket sessions by bounded terminal classification. |
| `ferrum_xds_first_slice_nacks_total` | counter | `namespace`, `type_url`, `gateway_namespace` | `mesh` | `documented_only` | `conditional` | NACKs of a required mesh-slice type while the data plane is still waiting for its first slice. |
| `ferrum_xds_streams_rejected_total` | counter | `gateway_namespace` | `mesh` | `documented_only` | `conditional` | ADS streams rejected for exceeding the per-node concurrent-stream ceiling. |
| `ferrum_xds_warming_partial_applies_total` | counter | `namespace`, `gateway_namespace` | `mesh` | `documented_only` | `conditional` | Mesh slices applied while marked as xDS required-version skewed. Normal coherent xDS apply should not increment this. |

## Bundled observability surfaces

- PrometheusRule: `charts/ferrum-mesh/templates/alerts-prometheusrule.yaml`
- Grafana dashboards: `charts/ferrum-mesh/dashboards/*.json`
- Families with `bundled: documented_only` are intentionally exported without a chart alert/dashboard yet; adding a query requires updating both the chart artifact and this inventory classification.

Chart-reference validation scans Ferrum-owned tokens (`ferrum_…`, `chargeback_sink_…`) plus an explicit allowlist of external (non-Ferrum) metrics referenced by bundled alerts — currently `apiserver_admission_webhook_rejection_count`. Allowlisted names are outside this inventory, and CI fails closed on a stale entry (allowlisted but no longer referenced by the charts) or on an entry that shadows an inventoried family. Other non-Ferrum metric names in bundled queries are not scanned; adding one requires an allowlist entry to keep this record complete.

Hosted CI validates chart metric references with `.github/scripts/validate_prometheus_metric_contract.py`, renders the enabled Helm `PrometheusRule`, extracts its rule groups, and runs `promtool check rules` against the exact rendered expressions. Operators may run the same check against a rendered PrometheusRule in their own cluster tooling.
