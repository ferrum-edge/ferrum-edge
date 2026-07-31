# proxy_alerts plugin

Watches primary proxy traffic and dispatches notifications when configured rules breach their thresholds. Hooks into the `log()`, `on_stream_disconnect()`, and selected WebSocket disconnect lifecycle phases (priority `9250`, after every logging sink). Works across all protocols (HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket, TCP, UDP/DTLS). Shadow summaries emitted by `request_mirror` are ignored so mirror-target failures do not page the live proxy owner.

The channel layer (Slack, Microsoft Teams, Discord, generic Webhook, SMTP email) lives in [`docs/notifications.md`](notifications.md) and is reusable from any subsystem.

## When to use it

This plugin is a lightweight in-gateway alerting surface — useful when you want each proxy/team to be paged on its own anomalies without having to set up separate Alertmanager / Datadog monitors. It is **not** a substitute for a real metrics-based alerting platform; use `prometheus_metrics` + a dedicated alerting stack for everything else.

## Configuration

```jsonc
{
  "enabled": true,
  "default_cooldown_seconds": 300,
  "default_min_request_count": 50,
  "default_window_seconds": 60,
  "default_resolved_window_seconds": 300,
  "max_concurrent_dispatches": 8,
  "max_delivery_retries": 2,
  "delivery_retry_base_ms": 100,
  "delivery_retry_max_ms": 2000,

  "quiet_hours_utc": [
    { "from": "23:00", "to": "06:00", "weekdays": [0, 6] }
  ],

  "channels": {
    "ops_slack": {
      "type": "slack",
      "webhook_url": "https://hooks.slack.com/services/T/B/X",
      "channel_override": "#alerts-prod",
      "username": "ferrum-edge",
      "icon_emoji": ":rotating_light:"
    },
    "ops_teams":   { "type": "teams",   "webhook_url": "https://outlook.office.com/webhook/..." },
    "ops_discord": { "type": "discord", "webhook_url": "https://discord.com/api/webhooks/..." },
    "pagerduty_v2": {
      "type": "webhook",
      "url": "https://events.pagerduty.com/v2/enqueue",
      "method": "POST",
      "headers": { "Content-Type": "application/json" },
      "body_template": "{\"routing_key\":\"$ROUTING_KEY\",\"event_action\":\"${event_action}\",\"payload\":{\"summary\":\"${rule_name}: ${reason}\",\"source\":\"${proxy_name}\",\"severity\":\"${severity}\"}}"
    }
  },

  "rules": [
    {
      "name": "proxy_5xx_spike",
      "enabled": true,
      "type": "error_rate",
      "status_codes": [500, 501, 502, 503, 504],
      "window_seconds": 60,
      "threshold_percent": 5.0,
      "min_request_count": 100,
      "channels": ["ops_slack", "pagerduty_v2"],
      "cooldown_seconds": 300,
      "recovery": { "resolved_window_seconds": 300 },
      "severity": "high"
    }
  ]
}
```

See [docs/notifications.md](notifications.md#channel-json-schema) for the full per-channel field reference (including `*_env` secret-resolver forms).

Unknown properties are rejected at the top level and within quiet-hours, recovery, each selected rule variant, and each selected notification channel. The `channels` map stays open for arbitrary channel names, and generic webhook `headers` stay open for arbitrary header names.

### Top-level options

| Field | Default | Notes |
|-------|---------|-------|
| `enabled` | `true` | Master runtime switch. Must be a boolean when present; strings/null are rejected. |
| `default_cooldown_seconds` | `300` | Per-rule fallback if `cooldown_seconds` is omitted; must be in `[1, 86400]`. Applied per `(rule, proxy, channel)` so one proxy's incident does not suppress another proxy that shares a global/group rule, while each channel still throttles independently. |
| `default_min_request_count` | `50` | Per-rule fallback for `min_request_count` (used by `error_rate`, `latency_percentile`, and `grpc_status_rate`); must be at least `1`. Avoids noisy alerts from low-traffic windows. |
| `default_window_seconds` | `60` | Per-rule fallback for `window_seconds`; must be in `[5, 3600]`. |
| `default_resolved_window_seconds` | `300` | Per-rule fallback for `recovery.resolved_window_seconds`; must be in `[5, 86400]`. |
| `max_concurrent_dispatches` | `8` | Bounded-concurrency semaphore for outbound notifications (`>= 1`). When exhausted, alerts are dropped with a `warn!` rather than queued. |
| `max_delivery_retries` | `2` | Re-attempts after the initial send for **transient** failures only (`0..=8`). Retries hold the dispatch permit and never enqueue extra work. |
| `delivery_retry_base_ms` | `100` | Initial jittered backoff between transient retries (`[10, 60000]`). |
| `delivery_retry_max_ms` | `2000` | Cap for exponential jittered backoff (`[10, 60000]`, must be `>= delivery_retry_base_ms`). |
| `quiet_hours_utc` | `[]` | Optional UTC time-of-day windows where `Trigger` alerts are suppressed (without consuming the cooldown). Omit the field for no quiet hours; `null` is rejected. `Resolve` events still fire so operators don't miss recovery during off hours. |

### Quiet hours

```json
"quiet_hours_utc": [
  { "from": "23:00", "to": "06:00", "weekdays": [0, 6] }
]
```

- `from` / `to` are `HH:MM` (UTC). `from > to` wraps past midnight.
- `weekdays` is `0..=6` with `0 = Sunday` … `6 = Saturday`. Empty/omitted = every day. For wrapped windows (`from > to`), the after-midnight segment belongs to the weekday on which the window started.

### Rule types

#### `error_rate`

```jsonc
{
  "name": "proxy_5xx_spike",
  "type": "error_rate",
  "status_codes": [500, 501, 502, 503, 504],
  "window_seconds": 60,
  "threshold_percent": 5.0,
  "min_request_count": 100,
  "channels": ["ops_slack"]
}
```

Fires when ≥ `threshold_percent` of the last `window_seconds` of HTTP requests had a status in `status_codes`, provided the window saw at least `min_request_count` requests. `threshold_percent` must be > 0 and ≤ 100. HTTP-only.

#### `status_code_count`

```jsonc
{
  "name": "auth_failures_spike",
  "type": "status_code_count",
  "status_codes": [401, 403],
  "window_seconds": 120,
  "threshold_count": 200,
  "channels": ["secops_teams"]
}
```

Fires when at least `threshold_count` requests with a status in `status_codes` occurred within `window_seconds`. HTTP-only. Useful for security signals (4xx auth-failure spikes). HTTP transport status stays independent of gRPC application outcome — use `grpc_status_count` / `grpc_status_rate` for terminal `grpc-status`.

#### `grpc_status_count`

```jsonc
{
  "name": "grpc_unavailable_burst",
  "type": "grpc_status_count",
  "grpc_statuses": [14, 13, "OTHER"],
  "window_seconds": 60,
  "threshold_count": 25,
  "channels": ["ops_slack"],
  "recovery": { "resolved_window_seconds": 300 },
  "severity": "high"
}
```

Fires when at least `threshold_count` completed gRPC transactions carried a terminal application status matching `grpc_statuses` within `window_seconds`. Entries are standard numeric codes `0..=16`, or the string `"OTHER"` for malformed / future out-of-range codes (the same bounded bucket used by StatsD/Prometheus). HTTP `response_status_code` is never consulted — an RPC that finishes HTTP 200 with `grpc-status: 14` counts as a match.

Evaluation runs from the terminal `log()` summary after buffered, trailers-only, and streamed bodies finish (including deferred trailer completion on H2/H3 native and bridge paths, plus gateway-generated gRPC rejections). Streaming RPCs therefore cannot trigger until the client-visible terminal status is known.

#### `grpc_status_rate`

```jsonc
{
  "name": "grpc_error_rate",
  "type": "grpc_status_rate",
  "grpc_statuses": [1, 2, 4, 8, 13, 14, 16, "OTHER"],
  "window_seconds": 60,
  "threshold_percent": 5.0,
  "min_request_count": 50,
  "channels": ["ops_slack"]
}
```

Fires when ≥ `threshold_percent` of gRPC transactions in the window matched `grpc_statuses`, provided the window saw at least `min_request_count` gRPC transactions. The denominator is gRPC-only (`TransactionSummary::grpc_status()` present); plain HTTP samples neither match nor dilute the rate, but still allow recovery/resolve observation against the existing window. Status `0` (OK) may be selected explicitly when operators want an inverted success-rate style signal.

#### `latency_percentile`

```jsonc
{
  "name": "p95_backend_latency",
  "type": "latency_percentile",
  "metric": "backend_total_ms",
  "percentile": 95,
  "threshold_ms": 1500,
  "window_seconds": 60,
  "min_request_count": 50,
  "channels": ["ops_slack"]
}
```

`metric` is one of:
- `backend_total_ms` — HTTP only; `latency_backend_total_ms` from the transaction summary
- `backend_ttfb_ms` — HTTP only
- `total_ms` — HTTP only
- `stream_duration_ms` — TCP/UDP/DTLS/WebSocket session summaries. Upstream producers measure elapsed duration on a process-monotonic clock (`Instant` / coarse monotonic counter), not UTC wall time. Connect/disconnect RFC3339 timestamps remain civil-clock values for human-readable logs and may diverge from `duration_ms` after NTP or administrator clock corrections. UDP/DTLS idle expiry uses the same monotonic base, so wall-clock jumps neither freeze nor prematurely expire sessions.

Percentiles are estimated with fixed log-scale buckets (boundaries 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000, 120000, 300000 ms). Alert messages display the upper bound of the bucket containing the percentile rank, and threshold comparisons fire when that upper bound is strictly greater than `threshold_ms`. This keeps thresholds exactly on a bucket boundary from firing on samples in the previous bucket, while non-boundary thresholds can still fire when the percentile lands in a bucket that spans the threshold. Adequate for alerting; not a substitute for a precise histogram. `threshold_ms` must be at most 300000 so only the overflow bucket can breach the largest finite threshold. Negative latency values (sentinel `-1.0` used during streaming responses) are ignored without clearing an already-breached latency window.

#### `error_class`

```jsonc
{
  "name": "backend_connect_errors",
  "type": "error_class",
  "classes": ["connection_refused", "connection_timeout", "dns_lookup_error", "tls_error"],
  "window_seconds": 60,
  "threshold_count": 25,
  "channels": ["ops_slack"]
}
```

Counts transactions whose `error_class` (or HTTP `body_error_class`) matches one of `classes`. Applies to both HTTP/gRPC/WebSocket and stream protocols (TCP/UDP) — both share the same `ErrorClass` enum (`src/retry.rs`). See [docs/error_classification.md](error_classification.md) for the full enum.

#### `stream_disconnect_cause`

```jsonc
{
  "name": "backend_disconnect_burst",
  "type": "stream_disconnect_cause",
  "causes": ["backend_error", "recv_error"],
  "window_seconds": 60,
  "threshold_count": 50,
  "channels": ["infra_discord"]
}
```

Counts stream disconnects whose `disconnect_cause` matches one of `causes`. Stream-only (TCP / UDP / DTLS / WebSocket). Causes: `idle_timeout`, `recv_error`, `backend_error`, `graceful_shutdown`. WebSocket sessions derive the cause from their disconnect summary: clean closes map to `graceful_shutdown`, drain/read-write timeouts map to `idle_timeout`, backend-to-client failures map to `backend_error`, and client-side/unknown failures map to `recv_error`.

### Cooldown and recovery

- Sliding-window aging, cooldowns, recovery durations, and background eviction use process-monotonic elapsed time. NTP synchronization, administrator wall-clock corrections, and daylight-saving changes therefore cannot freeze or prematurely advance alert lifecycle state. UTC wall time is used only for quiet-hour matching and rendered notification timestamps.
- The monotonic epoch is process-local. A process restart or full plugin-instance rebuild resets windows, cooldowns, and recovery state; ordinary in-process clock corrections do not. Incremental reload preservation follows the instance-ownership rules in [Operational notes](#operational-notes).
- **Cooldown** is per `(rule, proxy, channel)`. After a `Trigger` dispatch for proxy P on channel X, subsequent triggers from the same rule/proxy/channel are suppressed for `cooldown_seconds`. Other proxies and other channels remain free to fire.
- **Recovery** is opt-in via `recovery: { "resolved_window_seconds": N }`. After a rule transitions Active → Recovering (window dropped below threshold), the rule must remain below threshold for `resolved_window_seconds` before a single `Resolve` event is dispatched. A re-breach inside the window quietly returns to Active without re-firing.
- Without `recovery`, dropping below threshold immediately resets that proxy/rule incident; the next breach can fire a fresh `Trigger` subject to cooldown.
- `Resolve` dispatches are NOT subject to cooldown — they are always one-shot.
- Quiet hours suppress `Trigger` events without consuming the cooldown, so the next eligible window re-evaluates fresh. `Resolve` events still fire during quiet hours.

### Webhook template variables

In addition to the [generic notification template variables](notifications.md#template-variables-provided-by-the-notifications-layer), the proxy_alerts plugin exposes these to the operator-templated channels — the `webhook` channel's `body_template` and the `email` channel's `subject_template` / `body_template`:

| Variable | Value |
|----------|-------|
| `${rule_name}` | The rule's `name`. |
| `${proxy_id}` | Proxy id from the transaction summary. |
| `${proxy_name}` | Human-friendly proxy name. |
| `${namespace}` | Namespace from the transaction summary. |
| `${fired_at}` | RFC 3339 timestamp. |
| `${observed}` | Pre-formatted observed value, e.g. `"6.7%"`, `"1873ms"`, `"204"`. |
| `${threshold}` | Pre-formatted threshold value. |
| `${sample_count}` | Total samples in the window. |
| `${window_seconds}` | Rule window. |
| `${severity}` | `info` / `low` / `medium` / `high` / `critical`. |
| `${reason}` | Concise summary string suitable for a notification body. |
| `${event_action}` | `trigger` or `resolve`. |

Use `$$` for a literal `$`. Unknown placeholders are passed through unchanged.

## Scopes

`proxy_alerts` may be configured at any scope:
- `proxy` — the rule observes only that proxy's traffic.
- `proxy_group` — shared instance observes traffic across the group; per-proxy bucket keys ensure the alert identifies the offending proxy.
- `global` — observes traffic across every proxy; per-proxy bucket keys still apply (a global "5xx > 5%" rule alerts per offending proxy, never as one mashed aggregate).

## Operational notes

- Shared validation and Admin/file admission reject invalid configurations. At plugin-cache construction, `proxy_alerts` remains an optional fail-open observability plugin: a construction failure is logged and that instance is omitted instead of blocking cache publication.
- Plugin state (sliding-window counters, cooldown timestamps, recovery state machines) is per-instance. **Full rebuilds** (plugin definition changes, global rebuilds, or cascade-deleted proxy-group instances) construct a fresh instance and therefore reset state. **Incremental plugin-cache updates** deliberately preserve unchanged global and proxy-group instances so live counters survive unrelated proxy edits; after those commits, preserved instances publish per-proxy ownership generations and retire cooldown/recovery/window rows for proxies that left their active set or whose published generation advanced (deleted, renamed, removed from or rejoined to a proxy-group, or delete→recreate of the same ID). A continuously configured proxy also advances ownership whenever its effective set of `proxy_alerts` instances changes, so a pre-leave in-flight sample cannot write into a later rejoined group membership. Lifecycle rows are themselves keyed by that admission ownership generation, so a stale in-flight write that races past retain cannot populate or poison the replacement incarnation. Ownership generations are allocated from a persistent monotonic high-water mark on the plugin cache (surviving empty active maps) and captured at request/stream/WebSocket admission from the published RequestEpoch/plugin-cache snapshot into transaction summaries. A bare current-active-ID precheck alone is insufficient for those reuse races. Proxy-scoped instances are dropped with their proxy and do not need that retention pass.
- Rule IDs are assigned from rule order at config load and are therefore load-local; reordering or renaming rules rebuilds the instance and resets state rather than carrying cooldown/recovery across definitions. A full rebuild during an active anomaly may re-fire alerts immediately — this is acceptable today; cross-reload persistence is a v2 follow-up.
- Background eviction additionally bounds historical state inside a preserved instance: every sweep reapplies the published proxy-generation ownership map (serialized with commit-path retention under a cold-path lock, loading the latest map while that lock is held) so an isolated old-generation write that lands just after commit-time retention is removed on the next cadence without deleting current-generation rows; sliding-window samples and expired cooldown timestamps older than `max(1h, max rule window/cooldown/recovery)` are swept; and terminal `Healthy` recovery rows are dropped via resolved-row eviction. Active/Recovering incidents for the currently published generation remain owned by retention and are not TTL-reset. Ownership generations are pinned at request/stream/WebSocket admission from the published RequestEpoch/plugin-cache snapshot into transaction / stream / WebSocket summaries (not stamped later by `log_with_mirror`).
- Per-rule `enabled: false` entries are skipped before rule validation, so operators can keep draft/disabled rules alongside at least one active rule without breaking the active alert set. Configurations with no active rules are rejected. Present non-boolean `enabled` values (plugin or rule scope) and wrongly typed optional scalars such as `min_request_count` are rejected rather than coerced to active defaults.
- `*_env` channel fields read `std::env::var()` at construction so the gateway's secret resolver (`_FILE`, `_VAULT`, `_AWS`, `_AZURE`, `_GCP`) handles materialization without ever placing secrets in DB/file config. Reference the unsuffixed variable in plugin config: for example set `FERRUM_ALERTS_SLACK_WEBHOOK_VAULT=secret/data/ferrum/slack#url`, then configure `"webhook_url_env": "FERRUM_ALERTS_SLACK_WEBHOOK"` after startup materializes the base env var.
- Sensitive metadata (`Authorization`, `Cookie`, etc.) is auto-redacted at `TransactionSummary` serialize time per the standard logger redaction. Notification template variables only expose named scalars (`${observed}`, `${rule_name}`, …) — there is no raw `${metadata}` hook, so the redaction layer cannot be bypassed via a template.
- When the dispatch semaphore (`max_concurrent_dispatches`) is exhausted, alerts are dropped with a `warn!` rather than queued, the rule/proxy/channel cooldown is not consumed, and `ferrum_notification_delivery_backpressure_dropped_total{channel_type=…}` increments. Operators investigating a backpressure event should scrape that counter (or grep `plugin=proxy_alerts` in their logs).
- **Delivery outcomes**: each admitted send is classified as success, transient failure (408/429/5xx, connect/timeout), or permanent failure (other 4xx / config faults). Transient failures retry inside the same task with jittered exponential backoff up to `max_delivery_retries` while holding the semaphore permit — never an unbounded queue, never blocking the `log()` hook.
- **Cooldown / incident state**: Trigger and Resolve reserve a `PendingTrigger` / `PendingResolve` seat when a dispatch is admitted. Cooldown is armed at admission and **released on failure/abandon**; incident state commits to `Active` / `Healthy` only after at least one channel settles successfully. A failed Trigger therefore does not silently consume cooldown or permanently mark Active; a failed Resolve returns to `Recovering` so the next healthy sample can retry.
- **Re-breach while a Resolve is externally in flight**: a Resolve already on the wire cannot be unsent, and cancelling or retiring its local future is not a rollback — the endpoint may have received it and marked the incident closed. If observations breach again in that window the incident parks in `ResolveInFlightRebreached` and emits nothing yet, because a Trigger dispatched now could overtake the Resolve on the wire and leave "resolved" as the operator's last view. When the Resolve settles — **success, failure, or abandonment alike**, since none of those distinguishes "the peer acted on it" from "it never arrived" — the incident converges to `CompensatingTrigger`, and the next breaching sample re-alerts through the ordinary cooldown gate. A possibly-delivered Resolve therefore can never leave a genuinely breached incident silently suppressed. If the rule is no longer breaching by then, the Resolve was accurate and the state returns to `Healthy` with no phantom alert. The compensating Trigger is bounded by the same cooldown as any other Trigger and never queues: a cooldown-suppressed compensation stays pending and is retried on the next sample.
- **Generation drain**: every `proxy_alerts` instance owns a dispatch generation. Reload/`Drop` stops admitting and cooperatively cancels in-flight sends for that generation. Cancellation preempts the live transport attempt itself (not just the gaps around it), so a stalled channel endpoint cannot hold a retired generation open until the HTTP client timeout; already-transmitted bytes may still be delivered. A retired send cannot commit `Succeeded`/`FailedTransient`/`FailedPermanent` or incident state, cannot schedule another retry, or invoke a success/failure completion outcome; it settles exactly once as `Abandoned(generation_retired)`, with the exactly-once settlement edge invoking the producer callback once to roll back reserved/pending producer state. Tasks are also admitted into the process `observability_delivery` registry so graceful shutdown drains them under `FERRUM_LOG_SHUTDOWN_DRAIN_TIMEOUT_MS`; only sends hard-aborted when that deadline expires increment `ferrum_notification_delivery_abandoned_at_deadline_total`. Reload retirement, pre-task admission rejection, and registry rejection are reported under their own `reason` labels on `ferrum_notification_delivery_abandoned_total` / `ferrum_notification_delivery_rejected_total` instead — see `docs/notifications.md`.
- **Best-effort / duplicate delivery**: alert delivery is bounded and non-durable. Backpressure, permanent failure, or an exhausted retry budget can produce zero endpoint copies; transport timeouts, post-write connection errors, and cancellation after bytes left the process can instead produce duplicates because the endpoint may have acted before Ferrum observed failure/abandonment. **Webhook and email consumers must be idempotent or duplicate-tolerant.** Retries within one admitted task preserve `fired_at`, but rollback followed by re-admission creates a new timestamp and Ferrum supplies no cross-admission idempotency key. For incident-level deduplication, derive a receiver-owned stable key/window from rule + proxy + event action rather than relying on `fired_at` alone. Read `abandoned_total` as "delivery state unknown", not "not delivered". Full contract in `docs/notifications.md`.
- **Delivery SLO / alerting guidance**: treat notification delivery as a best-effort side channel with a soft SLO of “≥ 99% of admitted Trigger/Resolve sends succeed within the retry budget under healthy channel endpoints.” Alert when `rate(ferrum_notification_delivery_failed_transient_total[5m])` or `failed_permanent` stays elevated, when `backpressure_dropped` or `rejected_total{reason="registry_rejected"}` is non-zero during an incident window, or when `abandoned_at_deadline` increments on shutdown. A persistently non-zero `abandoned_total{reason="generation_retired"}` points at config churn retiring generations mid-send rather than at a broken endpoint. Prefer paging on the underlying proxy anomaly (`prometheus_metrics` / external Alertmanager) and use these counters to detect “alerting is itself broken.”
- **Tuning `max_concurrent_dispatches`**: default `8` is conservative — alert storms during a partial channel outage should be visible (drops trigger warnings) rather than buffered. Deployments fanning out to many channels (e.g., Slack + Teams + PagerDuty + Discord simultaneously breaching) may want to bump this to 16-32.
