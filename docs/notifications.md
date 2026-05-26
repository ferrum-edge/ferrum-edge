# Notifications

Reusable, plugin-agnostic notification infrastructure. Lives at `src/notifications/`. Today the only consumer is the [`proxy_alerts` plugin](proxy_alerts.md); future subsystems (overload manager, mesh policy enforcement, custom plugins) can dispatch notifications to the same channels without re-implementing the transports.

## What's in the module

| Item | Path | Purpose |
|------|------|---------|
| `Notification` | `src/notifications/notification.rs` | Generic payload: title, body, severity, k/v fields, lifecycle action. No alert-specific fields. |
| `NotificationChannel` | `src/notifications/channels/mod.rs` | Enum over Slack / Teams / Discord / Webhook. Uniform `dispatch` surface. |
| `parse_channels(json)` | `src/notifications/channels/mod.rs` | JSON → typed channel map with validation. |
| `dispatch(...)` | `src/notifications/dispatch.rs` | Bounded-concurrency fan-out helper. |
| `templating::render_template` | `src/notifications/templating.rs` | `${var}` substitution + dry-run validation. |

## Channel JSON schema

`channels` is a `{ name -> definition }` map. Each definition picks a transport via `"type"` and supplies its required fields.

### Common rules
- Channel name matches `[A-Za-z0-9_-]+`.
- `webhook_url` (Slack/Teams/Discord) and `url` (generic webhook) MUST be `http://` or `https://` with a host and no `user:pass@` userinfo segment.
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

#### Template variables provided by the notifications layer

These are always available for the generic webhook channel, derived from the supplied `Notification`:

- `${title}` — notification title
- `${body}` — notification body
- `${severity}` — `info` / `low` / `medium` / `high` / `critical`
- `${event_action}` — `trigger` / `resolve` / `info`
- `${fired_at}` — RFC 3339 timestamp
- `${source}` — caller-defined identifier (e.g., `proxy_alerts:proxy_5xx`)
- `${subject_id}` — caller-defined subject (e.g., proxy name)
- `${namespace}` — caller-defined namespace

Callers can supply additional variables via `dispatch_with_vars`. The [`proxy_alerts` plugin](proxy_alerts.md#webhook-template-variables) adds `${rule_name}`, `${proxy_id}`, `${observed}`, `${threshold}`, etc. Extra variables are consumed only by generic `webhook` channels because Slack, Teams, and Discord use fixed native payload shapes.

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

`dispatch` is fire-and-forget: each channel send runs on its own `tokio::spawn` under the supplied semaphore. When permits are exhausted alerts are dropped with a `warn!` rather than queued — alert storms during a partial channel outage should be visible, not buffered. Each caller owns its own `Semaphore` so dispatch budgets do not interact across subsystems.

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

Email / SMTP, PagerDuty, and Opsgenie are deferred follow-ups — the generic webhook covers the latter two via `body_template` and `headers` today.
