//! Slack Incoming Webhook channel.
//!
//! Posts a JSON payload using the legacy `attachments` schema. Slack still
//! supports it on Incoming Webhooks and it gives us colored side-bars + a
//! field grid — both useful for at-a-glance triage.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::plugins::utils::http_client::PluginHttpClient;

use super::super::notification::Notification;
use super::{dispatch_json_payload, resolve_optional_string, validate_webhook_url};

#[derive(Debug, Clone)]
pub struct SlackChannel {
    name: Arc<str>,
    webhook_url: Arc<str>,
    channel_override: Option<Arc<str>>,
    username: Option<Arc<str>>,
    icon_emoji: Option<Arc<str>>,
}

impl SlackChannel {
    pub fn new(name: &str, value: &Value) -> Result<Self, String> {
        let webhook_url =
            resolve_optional_string(value, "webhook_url", "webhook_url_env", name)?
                .ok_or_else(|| format!("channel '{name}' (slack): 'webhook_url' is required"))?;
        validate_webhook_url(&webhook_url, name, "slack")?;
        let channel_override = take_optional_string(value, "channel_override", name)?;
        let username = take_optional_string(value, "username", name)?;
        let icon_emoji = take_optional_string(value, "icon_emoji", name)?;
        Ok(Self {
            name: Arc::from(name),
            webhook_url: Arc::from(webhook_url),
            channel_override: channel_override.map(Arc::from),
            username: username.map(Arc::from),
            icon_emoji: icon_emoji.map(Arc::from),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn webhook_url(&self) -> &str {
        &self.webhook_url
    }

    pub fn build_payload(&self, n: &Notification) -> Value {
        let fields: Vec<Value> = n
            .fields
            .iter()
            .map(|f| {
                json!({
                    "title": f.name,
                    "value": f.value,
                    "short": f.short,
                })
            })
            .collect();
        let mut attachment = json!({
            "color": n.severity.slack_color(),
            "title": n.title,
            "text": n.body,
            "fields": fields,
            "ts": n.fired_at.timestamp(),
        });
        if let Some(source) = n.source.as_deref() {
            attachment["footer"] = json!(source);
        }
        let mut payload = json!({ "attachments": [attachment] });
        if let Some(ch) = self.channel_override.as_deref() {
            payload["channel"] = json!(ch);
        }
        if let Some(u) = self.username.as_deref() {
            payload["username"] = json!(u);
        }
        if let Some(emoji) = self.icon_emoji.as_deref() {
            payload["icon_emoji"] = json!(emoji);
        }
        payload
    }

    pub async fn dispatch(
        &self,
        notification: &Notification,
        http: &PluginHttpClient,
    ) -> Result<(), String> {
        let payload = self.build_payload(notification);
        dispatch_json_payload(
            &self.webhook_url,
            "slack",
            "notification_slack",
            &payload,
            http,
        )
        .await
    }
}

fn take_optional_string(value: &Value, key: &str, channel: &str) -> Result<Option<String>, String> {
    match value.get(key) {
        Some(v) => v
            .as_str()
            .map(|s| s.to_string())
            .map(Some)
            .ok_or_else(|| format!("channel '{channel}' (slack): '{key}' must be a string")),
        None => Ok(None),
    }
}
