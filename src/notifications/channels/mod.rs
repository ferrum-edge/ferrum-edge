//! Notification channel implementations.
//!
//! Each channel takes a generic [`Notification`] and projects it into its own
//! payload shape. The [`NotificationChannel`] enum provides a uniform
//! `dispatch` surface so callers can hand a list of `Arc<NotificationChannel>`
//! to [`crate::notifications::dispatch::dispatch`] without caring which
//! transport each one uses.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use url::Url;

use crate::plugins::utils::http_client::PluginHttpClient;
use crate::plugins::utils::response_body::{BoundedReadError, measure_response_body_bounded};

use super::notification::Notification;

pub mod discord;
pub mod slack;
pub mod teams;
pub mod webhook;

/// Webhook acknowledgements are normally a few hundred bytes. The 1 MiB cap is
/// only a DoS guard so a misbehaving sink cannot make us stream an unbounded
/// body just to keep the keep-alive connection reusable. The drain path counts
/// and discards chunks instead of buffering them, so memory tracks the current
/// response chunk and transport buffers rather than this full cap. Intentionally
/// hardcoded rather than exposed as an env knob: it bounds adversarial behavior,
/// not legitimate payload sizes (webhook ACKs are <1 KiB across Slack, Teams,
/// Discord, and PagerDuty), so making it tunable would invite bikeshedding on a
/// value that has no operator-meaningful target.
const RESPONSE_BODY_DRAIN_LIMIT_BYTES_U64: u64 = 1024 * 1024;
const RESPONSE_BODY_DRAIN_LIMIT_BYTES: usize = RESPONSE_BODY_DRAIN_LIMIT_BYTES_U64 as usize;

#[allow(unused_imports)]
pub use discord::DiscordChannel;
#[allow(unused_imports)]
pub use slack::SlackChannel;
#[allow(unused_imports)]
pub use teams::TeamsChannel;
#[allow(unused_imports)]
pub use webhook::{HttpMethod, NOTIFICATION_TEMPLATE_VARS, WebhookChannel};

#[derive(Debug, Clone)]
pub enum NotificationChannel {
    Slack(SlackChannel),
    Teams(TeamsChannel),
    Discord(DiscordChannel),
    Webhook(WebhookChannel),
}

#[allow(dead_code)] // Public dispatch surface for non-plugin callers + tests.
impl NotificationChannel {
    pub fn name(&self) -> &str {
        match self {
            Self::Slack(c) => c.name(),
            Self::Teams(c) => c.name(),
            Self::Discord(c) => c.name(),
            Self::Webhook(c) => c.name(),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Slack(_) => "slack",
            Self::Teams(_) => "teams",
            Self::Discord(_) => "discord",
            Self::Webhook(_) => "webhook",
        }
    }

    pub fn warmup_hostnames(&self) -> Vec<String> {
        match self {
            Self::Slack(c) => hostname_from_url(c.webhook_url()),
            Self::Teams(c) => hostname_from_url(c.webhook_url()),
            Self::Discord(c) => hostname_from_url(c.webhook_url()),
            Self::Webhook(c) => hostname_from_url(c.url()),
        }
    }

    /// Dispatch with no extra template variables. Convenience for callers
    /// that don't need to inject domain-specific context (today: anything
    /// except the proxy_alerts plugin).
    pub async fn dispatch(
        &self,
        notification: &Notification,
        http: &PluginHttpClient,
    ) -> Result<(), String> {
        let extras: HashMap<String, String> = HashMap::new();
        self.dispatch_with_vars(notification, &extras, http).await
    }

    /// Dispatch with an extra template-variable map. Variables are only
    /// consumed by the [`WebhookChannel`] (other channels ignore them).
    pub async fn dispatch_with_vars(
        &self,
        notification: &Notification,
        extras: &HashMap<String, String>,
        http: &PluginHttpClient,
    ) -> Result<(), String> {
        match self {
            Self::Slack(c) => c.dispatch(notification, http).await,
            Self::Teams(c) => c.dispatch(notification, http).await,
            Self::Discord(c) => c.dispatch(notification, http).await,
            Self::Webhook(c) => c.dispatch_with_vars(notification, extras, http).await,
        }
    }
}

/// Parse a `{ name -> ChannelDef }` JSON object into typed channels.
///
/// Returns an error on:
/// - Empty map.
/// - Channel name not matching `[A-Za-z0-9_-]+`.
/// - Missing or unknown `"type"` discriminant.
/// - Per-channel validation failure (URL parse, missing required fields).
pub fn parse_channels(value: &Value) -> Result<HashMap<String, Arc<NotificationChannel>>, String> {
    let map = value
        .as_object()
        .ok_or_else(|| "'channels' must be an object".to_string())?;
    if map.is_empty() {
        return Err("'channels' must contain at least one channel".to_string());
    }
    let mut out = HashMap::with_capacity(map.len());
    for (name, def) in map {
        validate_channel_name(name)?;
        let channel = build_channel(name, def)?;
        out.insert(name.clone(), Arc::new(channel));
    }
    Ok(out)
}

fn validate_channel_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("channel name must not be empty".to_string());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "channel name '{name}' must match [A-Za-z0-9_-]+ (got disallowed characters)"
        ));
    }
    Ok(())
}

fn build_channel(name: &str, def: &Value) -> Result<NotificationChannel, String> {
    let obj = def
        .as_object()
        .ok_or_else(|| format!("channel '{name}': definition must be an object"))?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("channel '{name}': 'type' is required"))?;
    match kind {
        "slack" => Ok(NotificationChannel::Slack(SlackChannel::new(name, def)?)),
        "teams" => Ok(NotificationChannel::Teams(TeamsChannel::new(name, def)?)),
        "discord" => Ok(NotificationChannel::Discord(DiscordChannel::new(
            name, def,
        )?)),
        "webhook" => Ok(NotificationChannel::Webhook(WebhookChannel::new(
            name, def,
        )?)),
        other => Err(format!(
            "channel '{name}': unknown 'type' '{other}' (expected one of: slack, teams, discord, webhook)"
        )),
    }
}

/// Helper used by every channel that accepts either an inline value or a
/// `*_env`-suffixed env-var reference. Returns the resolved string when one
/// of the two is set; returns `Ok(None)` when neither is present.
///
/// Env-var resolution feeds through the gateway's existing secret resolver
/// (`src/secrets/`) — any `_FILE`/`_VAULT`/`_AWS`/`_AZURE`/`_GCP` suffix
/// applied at startup will already have populated the named env var by the
/// time channels are constructed.
pub(super) fn resolve_optional_string(
    value: &Value,
    key: &str,
    env_key: &str,
    channel: &str,
) -> Result<Option<String>, String> {
    if let Some(v) = value.get(key) {
        let s = v
            .as_str()
            .ok_or_else(|| format!("channel '{channel}': '{key}' must be a string"))?;
        if s.is_empty() {
            return Err(format!("channel '{channel}': '{key}' must not be empty"));
        }
        return Ok(Some(s.to_string()));
    }
    if let Some(v) = value.get(env_key) {
        let env_name = v
            .as_str()
            .ok_or_else(|| format!("channel '{channel}': '{env_key}' must be a string"))?;
        if env_name.is_empty() {
            return Err(format!(
                "channel '{channel}': '{env_key}' must not be empty"
            ));
        }
        let resolved = std::env::var(env_name).map_err(|_| {
            format!(
                "channel '{channel}': env var '{env_name}' (referenced by '{env_key}') is not set"
            )
        })?;
        if resolved.is_empty() {
            return Err(format!(
                "channel '{channel}': env var '{env_name}' resolved to empty string"
            ));
        }
        return Ok(Some(resolved));
    }
    Ok(None)
}

pub(super) fn validate_webhook_url(url: &str, channel: &str, kind: &str) -> Result<(), String> {
    validate_notification_url(url, channel, kind, "webhook_url")
}

pub(super) fn validate_notification_url(
    url: &str,
    channel: &str,
    kind: &str,
    field: &str,
) -> Result<(), String> {
    let parsed = Url::parse(url)
        .map_err(|e| format!("channel '{channel}' ({kind}): invalid '{field}': {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        s => {
            return Err(format!(
                "channel '{channel}' ({kind}): '{field}' must use http:// or https:// (got '{s}')"
            ));
        }
    }
    if parsed.host_str().is_none() {
        return Err(format!(
            "channel '{channel}' ({kind}): '{field}' must include a hostname"
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "channel '{channel}' ({kind}): '{field}' must not include username or password credentials"
        ));
    }
    Ok(())
}

/// Redact a webhook endpoint for logs/errors. Incoming webhook credentials
/// commonly live in the URL path or query string, so keep only scheme/host/port.
pub(super) fn redacted_endpoint_url(raw: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return "redacted-url".to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.set_path("/redacted");
    url.to_string()
}

pub(super) async fn dispatch_json_payload(
    webhook_url: &str,
    channel: &'static str,
    client_label: &'static str,
    payload: &Value,
    http: &PluginHttpClient,
) -> Result<(), String> {
    let redacted_url = redacted_endpoint_url(webhook_url);
    let req = http.get().post(webhook_url).json(payload);
    let resp = http
        .execute_redacted(req, client_label, &redacted_url)
        .await
        .map_err(|e| format!("{channel} dispatch failed: {e}"))?;
    finalize_dispatch_response(resp, channel, &redacted_url).await
}

async fn drain_response_body_redacted(
    resp: reqwest::Response,
    channel: &str,
    redacted_url: &str,
) -> Result<(), String> {
    // Best-effort early reject when the peer advertises an oversized
    // Content-Length: saves one chunk read and the connection-close cost
    // on HTTP/1.x. `content_length()` returns `None` for chunked / HTTP/2/3
    // responses without an explicit header, so the streaming check below
    // is the load-bearing backstop — not a duplicate.
    if let Some(content_length) = resp.content_length()
        && content_length > RESPONSE_BODY_DRAIN_LIMIT_BYTES_U64
    {
        // Keep this wording distinct from the streaming abort below; tests use
        // "before reading" vs. "after reading" to pin the intended path.
        return Err(format!(
            "{channel} dispatch response body exceeds drain limit {RESPONSE_BODY_DRAIN_LIMIT_BYTES} bytes before reading response advertising Content-Length {content_length} from {redacted_url}"
        ));
    }

    // Reached only from `finalize_dispatch_response` after a 2xx status check,
    // so this is the size-bounded drain on a successful response: it measures
    // chunk lengths and discards the bytes, never buffering anything we will
    // not inspect.
    measure_response_body_bounded(resp, RESPONSE_BODY_DRAIN_LIMIT_BYTES)
        .await
        .map(|_| ())
        .map_err(|e| match e {
            BoundedReadError::LimitExceeded {
                read_so_far,
                max_bytes,
            } => format!(
                "{channel} dispatch response body exceeds drain limit {max_bytes} bytes after reading {read_so_far} bytes from {redacted_url}"
            ),
            BoundedReadError::Stream(e) => {
                format!(
                    "{channel} dispatch body read failed: {} reading response from {redacted_url}",
                    reqwest_error_class(&e)
                )
            }
        })
}

pub(super) async fn finalize_dispatch_response(
    resp: reqwest::Response,
    channel: &str,
    redacted_url: &str,
) -> Result<(), String> {
    let status = resp.status();
    if !status.is_success() {
        // Keep non-success diagnostics status-only. Notification endpoint URLs
        // often contain credentials, and response bodies are untrusted and not
        // needed to identify a failed send.
        return Err(format!(
            "{channel} dispatch returned non-success status {status} from {redacted_url}"
        ));
    }
    // A 2xx with an abusive response body is still a dispatch failure: success
    // status does not buy an endpoint permission to make us read forever.
    drain_response_body_redacted(resp, channel, redacted_url).await
}

fn reqwest_error_class(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect error"
    } else if error.is_body() {
        "body error"
    } else if error.is_decode() {
        "decode error"
    } else if error.is_status() {
        "status error"
    } else if error.is_redirect() {
        "redirect error"
    } else if error.is_request() {
        "request error"
    } else {
        "error"
    }
}

fn hostname_from_url(raw: &str) -> Vec<String> {
    Url::parse(raw)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .into_iter()
        .collect()
}
