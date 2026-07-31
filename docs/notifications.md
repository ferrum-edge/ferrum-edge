# Notifications

Reusable, plugin-agnostic notification infrastructure. Lives at `src/notifications/`. Today the only consumer is the [`proxy_alerts` plugin](proxy_alerts.md); future subsystems (overload manager, mesh policy enforcement, custom plugins) can dispatch notifications to the same channels without re-implementing the transports.

## What's in the module

| Item | Path | Purpose |
|------|------|---------|
| `Notification` | `src/notifications/notification.rs` | Generic payload: title, body, severity, k/v fields, lifecycle action. No alert-specific fields. |
| `NotificationChannel` | `src/notifications/channels/mod.rs` | Enum over Slack / Teams / Discord / Webhook / Email. Uniform `dispatch` surface. |
| `parse_channels(json)` | `src/notifications/channels/mod.rs` | JSON → typed channel map with validation. |
| `dispatch(...)` | `src/notifications/dispatch.rs` | Bounded-concurrency fan-out helper. |
| `templating::render_template` | `src/notifications/templating.rs` | `${var}` substitution + dry-run validation. |

## Channel JSON schema

`channels` is a `{ name -> definition }` map. Each definition picks a transport via `"type"` and supplies its required fields.

### Common rules
- Channel name matches `[A-Za-z0-9_-]+`.
- Unknown properties on a selected channel variant are rejected (including fields that belong only to a different channel type). Generic webhook `headers` remain an open string map.
- `webhook_url` (Slack/Teams/Discord) and `url` (generic webhook) MUST be `http://` or `https://` with a host and no `user:pass@` userinfo segment. The `email` channel takes a bare `smtp_host` instead — no scheme, port, path, or credentials in that field.
- For each URL field there is a sibling `*_env` form (`webhook_url_env: "MY_ENV"`) that resolves via `std::env::var()` at construction. Combine with the gateway's secret resolver (`_FILE`, `_VAULT`, `_AWS`, `_AZURE`, `_GCP` env-var suffixes) to keep credentials out of config files.
- Dispatch slow-call/error logs redact endpoint paths, query strings, and userinfo because incoming webhook credentials commonly live inside the URL.
- Response bodies are discarded after successful dispatches with a 1 MiB cap: responses advertising `Content-Length > 1 MiB` are rejected before any bytes are read, and otherwise the body is streamed and aborted once the running total crosses 1 MiB. Either path fails the send without buffering the whole body.
- Non-success responses are reported by status only, without surfacing or draining their bodies. Any drain bail-out (non-success status, advertised `Content-Length` over 1 MiB, streaming abort at 1 MiB, or transport error) drops the response without consuming the body; reqwest handles the protocol cleanup (HTTP/1.x closes the connection, HTTP/2 can reset the stream while keeping the connection reusable). This is acceptable for the typical alert cadence (up to a few notifications per second per channel) and avoids spending work on misbehaving endpoints.

### Slack (Incoming Webhook)

```json
{
  "type": "slack",
  "webhook_url": "https://hooks.slack.com/services/T/B/X",
  "channel_override": "#alerts",     // optional
  "username": "ferrum-edge",         // optional
  "icon_emoji": ":rotating_light:"   // optional
}
```

Posts a JSON payload using the legacy `attachments` schema (color side-bar + field grid). `Notification.fields` become `attachments[].fields` (`{title, value, short}`). `Notification.severity` maps to a hex color.

### Microsoft Teams (Office 365 connector)

```json
{
  "type": "teams",
  "webhook_url": "https://outlook.office.com/webhook/..."
}
```

Posts a `MessageCard` payload. `Notification.fields` become `sections[0].facts` (`{name, value}`). Teams `facts` always render full-width — `NotificationField.short` is ignored.

### Discord (webhook)

```json
{
  "type": "discord",
  "webhook_url": "https://discord.com/api/webhooks/...",
  "username": "ferrum-edge"          // optional
}
```

Posts an `embeds` payload. `Notification.fields` become `embeds[0].fields` (`{name, value, inline}`); `inline` mirrors `short`.

### Generic webhook

```json
{
  "type": "webhook",
  "url": "https://events.pagerduty.com/v2/enqueue",
  "method": "POST",                   // optional; one of POST | PUT | PATCH (default POST)
  "headers": {                        // optional
    "Content-Type": "application/json",
    "X-Auth-Token": "..."
  },
  "body_template": "{\"r\":\"${rule_name}\",\"sev\":\"${severity}\"}"
}
```

Renders `body_template` after `${var}` substitution and POSTs the result. The default `Content-Type: application/json` is added if the operator does not supply their own. For JSON content types (`application/json` or `*+json`), substituted values are escaped as JSON string content so quotes, backslashes, and control characters inside alert fields cannot break the body; place variables inside JSON strings unless the value is intentionally numeric/boolean text. Non-JSON content types keep raw substitution.

### Email (SMTP)

```json
{
  "type": "email",
  "smtp_host": "smtp.example.com",
  "smtp_port": 587,                    // optional; default 587 (starttls) / 465 (implicit_tls)
  "tls_mode": "starttls",              // optional; "starttls" | "implicit_tls" (default "starttls")
  "tls_server_name": "smtp.example.com", // optional; verified identity override, default smtp_host
  "username_env": "FERRUM_ALERT_SMTP_USERNAME",  // optional (inline "username" also accepted)
  "password_env": "FERRUM_ALERT_SMTP_PASSWORD",  // optional (inline "password" also accepted)
  "from": "ferrum@example.com",
  "to": ["oncall@example.com"],
  "subject_template": "[${severity}] ${title}",  // optional
  "body_template": "${body}\n\n${fields}",       // optional
  "helo_name": "example.com",          // optional; defaults to the domain of `from`
  "connect_timeout_ms": 5000,          // optional; 100..60000
  "command_timeout_ms": 10000          // optional; 100..120000
}
```

Sends a single-part `text/plain; charset=utf-8` message, base64 transfer-encoded, with `Date`, `From`, `To`, `Subject`, `Message-ID`, `MIME-Version`, `Auto-Submitted: auto-generated`, and `X-Ferrum-Notification-{Severity,Event-Action}` headers.

**TLS is mandatory and there is no downgrade path.**

- `starttls` connects in the clear, sends `EHLO`, requires an advertised `STARTTLS`, upgrades, and re-sends `EHLO` inside TLS (pre-TLS capabilities are discarded per RFC 3207 §4.2). A relay that does not advertise `STARTTLS` fails the send; the message is never delivered in cleartext. Any bytes the peer pipelines ahead of the handshake abort the session (command-injection defense).
- `implicit_tls` handshakes immediately after TCP connect (SMTPS, port 465).
- `AUTH` is only reachable inside a completed handshake — the authenticated phase requires a token minted at handshake completion, so credentials cannot precede TLS.
- Certificate verification is **always** enforced. Unlike the log-shipping sinks, this channel deliberately ignores `FERRUM_TLS_NO_VERIFY`: skipping verification here would hand the SMTP password to whatever answered the connect. Private CAs go through `FERRUM_TLS_CA_BUNDLE_PATH`, and `FERRUM_TLS_CRL_FILE_PATH` revocation applies. The rustls config is built once per channel on a blocking thread and reused.
- Plaintext SMTP is not offered at all; `tls_mode: "none"` is rejected at admission.
- Supported AUTH mechanisms are `PLAIN` and `LOGIN`. If credentials are configured and the server advertises neither, the send fails rather than proceeding unauthenticated.

Bounds (all enforced, all fail closed or truncate visibly):

| Bound | Value |
|-------|-------|
| Recipients (`to`) | 1–32, duplicates collapsed |
| Address length | 254 bytes; local part ≤ 64, domain ≤ 255, ASCII addr-spec only |
| `subject_template` / `body_template` | 1 KiB / 64 KiB |
| Rendered subject / body | 512 B / 32 KiB, enforced during template substitution; truncated with `...` / `[truncated]` |
| `${fields}` block | 8 KiB hard ceiling (names, values, separators, truncation marker); 512 B per value |
| SMTP reply | 1 KiB per line, 64 lines, 16 KiB total |
| Concurrent SMTP sessions per channel | 4 (further dispatches fail immediately rather than queue) |
| Timeouts | `connect_timeout_ms` applies independently to DNS resolution, TCP connect, and the TLS handshake (so a stalled connect can take up to 3× the configured value before it fails); `command_timeout_ms` bounds each command/reply exchange including `DATA` |

Security notes:

- Credentials resolve through the same inline / `*_env` convention as the other channels, so the gateway secret resolver (`_FILE`, `_VAULT`, `_AWS`, `_AZURE`, `_GCP`) materializes them. They are never logged, never `Debug`-printed (the channel has a hand-written `Debug` impl), and never appear in an error.
- Delivery errors are structured and carry only a phase plus the numeric SMTP reply code — server reply text is always withheld because it is untrusted and can be attacker-influenced. A reply that echoes the configured password, or either credential in its on-the-wire base64 form, aborts the session with a dedicated error. The plaintext AUTH username is deliberately not watched: it is usually the mailbox address and relays legitimately echo addresses in `MAIL FROM` / `RCPT TO` replies.
- Multiline replies are parsed strictly: every line must repeat the same 3-digit code with a `-`/space separator, and a malformed, oversized, or truncated reply fails the send.
- Every templated value that reaches a header has its control characters folded to spaces, and the body is base64-encoded, so neither header injection nor premature `DATA` termination is reachable from template variables.
- The resolved SMTP address is screened against `FERRUM_BACKEND_ALLOW_IPS` / `FERRUM_BACKEND_DENY_CIDRS` before connecting, so a hostname that resolves into a denied range is refused.
- `smtp_host` participates in startup warmup/preflight DNS resolution (`NotificationChannel::warmup_hostnames`).

### Template variables provided by the notifications layer

These are always available to the operator-templated channels (generic `webhook` body, `email` subject/body), derived from the supplied `Notification`:

- `${title}` — notification title
- `${body}` — notification body
- `${severity}` — `info` / `low` / `medium` / `high` / `critical`
- `${event_action}` — `trigger` / `resolve` / `info`
- `${fired_at}` — RFC 3339 timestamp
- `${source}` — caller-defined identifier (e.g., `proxy_alerts:proxy_5xx`)
- `${subject_id}` — caller-defined subject (e.g., proxy name)
- `${namespace}` — caller-defined namespace

The `email` channel adds one more: `${fields}` — the notification's key/value rows rendered as `Name: value` lines.

Callers can supply additional variables via `dispatch_with_vars`. The [`proxy_alerts` plugin](proxy_alerts.md#webhook-template-variables) adds `${rule_name}`, `${proxy_id}`, `${observed}`, `${threshold}`, etc. Extra variables are consumed only by the `webhook` and `email` channels because Slack, Teams, and Discord use fixed native payload shapes. Generic notification variables win on key collisions, so a caller cannot shadow `${title}` or `${severity}`.

Special characters:
- `${name}` — variable substitution.
- `$$` — literal `$`.
- Unknown variables are passed through unmodified (`${typo}` stays as `${typo}` in the output) so misconfigured templates remain auditable. Unbalanced `${` is rejected at construction.
- `${metadata}`-style raw map injection is NOT supported; this would bypass the gateway's metadata-redaction layer.

## Dispatch helper

```rust
use std::sync::Arc;
use tokio::sync::Semaphore;
use ferrum_edge::notifications::{dispatch, Notification, NotificationChannel};
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;

let sem = Arc::new(Semaphore::new(8));
dispatch(
    Arc::new(my_notification),
    &[Arc::clone(&channel)],
    &sem,
    &http_client,
    "my_subsystem",
);
```

`dispatch` is fire-and-forget: each channel send runs on a detached task admitted through the process observability delivery registry under the supplied semaphore. When permits are exhausted alerts are dropped with a `warn!` (and `ferrum_notification_delivery_backpressure_dropped_total`) rather than queued — alert storms during a partial channel outage should be visible, not buffered. Each caller owns its own `Semaphore` so dispatch budgets do not interact across subsystems.

Transient transport/HTTP failures (408/429/5xx, connect/timeout) retry inside the same task with a bounded, jittered backoff while holding the permit. Permanent failures (other 4xx, egress denials) fail immediately. Process shutdown drains in-flight sends under the shared observability budget; sends still outstanding when that deadline expires are hard-aborted and increment `ferrum_notification_delivery_abandoned_at_deadline_total{channel_type=…}`.

Retiring a generation (reload / `Drop`) cancels its sends promptly: the in-flight transport call and the backoff between attempts are both raced against the cancel signal, with cancellation deliberately given priority, so an endpoint that accepts a connection and then stalls cannot pin a retired generation until the 60s HTTP client timeout. Cancellation is a **commit boundary, not an undo** — bytes already written may still reach and be acted on by the endpoint, and Ferrum reports that send as abandoned regardless. What it does guarantee is that a retired generation cannot commit `Succeeded`, `FailedTransient`, or `FailedPermanent`; cannot schedule another retry or invoke a success/failure completion outcome; and settles exactly once as `Abandoned`, with the exactly-once settlement edge invoking the producer callback once with `Abandoned` to roll back reserved/pending producer state.

### Delivery metrics (bounded cardinality)

Authenticated `/metrics` exports these families, labeled only by the fixed `channel_type` set (`slack` / `teams` / `discord` / `webhook` / `email`) — never by operator channel name:

| Metric | Type | Meaning |
|--------|------|---------|
| `ferrum_notification_delivery_attempted_total` | counter | Tasks whose registry-owned delivery body started executing (one count per delivery task, not per retry). Advances at body start — before any channel transport call — so an admit-then-cancel race can increment it with no bytes on the wire. |
| `ferrum_notification_delivery_succeeded_total` | counter | Final success (after retries) |
| `ferrum_notification_delivery_failed_transient_total` | counter | Exhausted retries on transient failures |
| `ferrum_notification_delivery_failed_permanent_total` | counter | Permanent failures |
| `ferrum_notification_delivery_backpressure_dropped_total` | counter | Semaphore exhaustion drops (delivery body never started) |
| `ferrum_notification_delivery_rejected_total` | counter | Rejected before the delivery body started, by `reason` |
| `ferrum_notification_delivery_abandoned_total` | counter | Delivery body started but settled with no committed outcome, by `reason` (transport may or may not have been polled) |
| `ferrum_notification_delivery_abandoned_at_deadline_total` | counter | Hard-aborted at the global shutdown drain deadline |
| `ferrum_notification_delivery_in_flight` | gauge | Currently executing sends (including backoff) |

Two families carry a second label, `reason`. Its values are compiled-in discriminants — never a channel name, endpoint URL, or peer-supplied string — so total cardinality stays at 5 × 2 and 5 × 3 series respectively:

| Family | `reason` | Meaning |
|--------|----------|---------|
| `rejected_total` | `generation_closed` | The producer stopped admitting (reload / plugin `Drop`) before the dispatch task was created. |
| `rejected_total` | `registry_rejected` | The process delivery registry refused the task (shutting down, or `FERRUM_LOG_DELIVERY_MAX_TASKS` exhausted). |
| `abandoned_total` | `generation_retired` | Reload / `Drop` cancelled a delivery after its body started (before, during, or between transport calls). |
| `abandoned_total` | `shutdown_deadline` | Hard-aborted when the global observability drain deadline expired. |
| `abandoned_total` | `task_dropped` | The dispatch task was dropped without settling for any other reason. |

`abandoned_at_deadline_total` is exactly the `shutdown_deadline` slice of `abandoned_total`, kept as its own family because it is the signal operators page on. Nothing else increments it: an earlier revision charged reload retirement, registry rejection and dropped tasks to it as well, which made the metric operationally false.

The accounting identity, per `channel_type`, is:

```text
attempted == succeeded + failed_transient + failed_permanent
           + sum(abandoned_total) + in_flight
```

`backpressure_dropped_total` and `rejected_total` sit deliberately outside it: the delivery body never started, so counting them as attempts would understate the delivery success ratio. Every one of those paths still invokes the producer's settle callback exactly once, so reserved cooldown / pending incident state is always rolled back.

`attempted` is deliberately a **body-start** counter, not a transport-start counter. Moving the marker to the first channel call would open a window where a hard shutdown abort could drop a running task before `attempted` advanced and misclassify it as `registry_rejected`. The body-start boundary keeps hard-deadline classification, the accounting identity, and pre-body rejection visibility coherent.

### Best-effort delivery can produce zero, one, or multiple copies

Delivery is bounded and non-durable. Backpressure, permanent failure, or an exhausted retry budget can produce **zero** endpoint copies, while uncertain transport/cancellation boundaries can produce duplicates. Ferrum therefore guarantees neither at-most-once nor at-least-once endpoint delivery; settlement is exactly-once only in Ferrum's own accounting. Three boundaries are indistinguishable from inside the process:

1. **Transport timeout** — the peer may have received and acted on the request; only the response was lost. Classified transient and retried.
2. **Connection error after the request was written** — a reset or early EOF carries no proof the peer did not process the body. Classified transient and retried.
3. **Cancellation after bytes left the process** — reload retirement and the shutdown-deadline abort drop the in-flight transport future, which cannot unsend anything. The send is reported `Abandoned` and producer state is rolled back, so the same logical alert may be dispatched again later.

Conversely, a 2xx followed by a response-body drain failure is classified **permanent** for the mirror-image reason: the peer already committed, so retrying would only duplicate.

Operator expectations for webhook and email consumers:

- Make the receiver idempotent, or tolerant of duplicates. Retries inside one admitted task reuse the same notification (including `fired_at`), but rollback followed by a later re-admission creates a new timestamp and Ferrum does not emit a cross-admission idempotency key. For incident-level deduplication, derive a receiver-owned stable business key/window from rule + proxy + `event_action`; do not rely on `fired_at` alone across re-admission.
- Treat `abandoned_total{reason="shutdown_deadline"}` and `{reason="generation_retired"}` as **delivery state unknown**, not as "definitely not delivered".
- Setting `max_delivery_retries: 0` narrows duplicate windows 1 and 2, at the cost of dropping recoverable transient failures. It cannot close window 3.

## Reusing the layer from a non-plugin caller

```rust
use std::sync::Arc;
use chrono::Utc;
use tokio::sync::Semaphore;
use ferrum_edge::notifications::{
    dispatch, EventAction, Notification, NotificationField, Severity,
    channels::parse_channels,
};

let channels = parse_channels(&serde_json::json!({
    "ops": {
        "type": "slack",
        "webhook_url": "https://hooks.slack.com/services/T/B/X"
    }
}))?;

let sem = Arc::new(Semaphore::new(4));
let n = Notification::builder("Gateway entered draining state")
    .body("FD usage at 96% — overload manager has shed new connections")
    .severity(Severity::High)
    .event_action(EventAction::Trigger)
    .source("overload_manager")
    .fired_at(Utc::now())
    .field("FD %", "96")
    .build();

dispatch(
    Arc::new(n),
    &channels.values().cloned().collect::<Vec<_>>(),
    &sem,
    &http_client,
    "overload_manager",
);
```

## When to extend this module

Add a new channel under `src/notifications/channels/<name>.rs` with:
- A `NewName::new(name: &str, value: &serde_json::Value) -> Result<Self, String>` constructor.
- A `dispatch(&self, &Notification, &PluginHttpClient) -> Result<(), String>` method.
- A `name(&self) -> &str` accessor.
- A new `NotificationChannel` variant.
- A match arm in `build_channel()` in `src/notifications/channels/mod.rs`.
- Snapshot / parse tests in `tests/unit/notifications/channels_tests.rs`.

Email / SMTP ships natively (see [Email (SMTP)](#email-smtp)). PagerDuty and Opsgenie remain deferred follow-ups — the generic webhook covers both via `body_template` and `headers` today.
