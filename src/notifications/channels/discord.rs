//! Discord webhook channel.
//!
//! Posts an `embeds`-shaped JSON payload to a Discord-compatible webhook.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::plugins::utils::http_client::PluginHttpClient;

use super::super::notification::Notification;
use super::{dispatch_json_payload, resolve_optional_string, validate_webhook_url};

#[derive(Debug, Clone)]
pub struct DiscordChannel {
    name: Arc<str>,
    webhook_url: Arc<str>,
    username: Option<Arc<str>>,
}

impl DiscordChannel {
    pub fn new(name: &str, value: &Value) -> Result<Self, String> {
        let webhook_url =
            resolve_optional_string(value, "webhook_url", "webhook_url_env", name)?
                .ok_or_else(|| format!("channel '{name}' (discord): 'webhook_url' is required"))?;
        validate_webhook_url(&webhook_url, name, "discord")?;
        let username = take_optional_string(value, "username", name)?;
        Ok(Self {
            name: Arc::from(name),
            webhook_url: Arc::from(webhook_url),
            username: username.map(Arc::from),
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
                    "name": f.name,
                    "value": f.value,
                    "inline": f.short,
                })
            })
            .collect();
        let mut embed = json!({
            "title": n.title,
            "description": n.body,
            "color": n.severity.discord_color(),
            "timestamp": n.fired_at.to_rfc3339(),
            "fields": fields,
        });
        if let Some(source) = n.source.as_deref() {
            embed["footer"] = json!({ "text": source });
        }
        let mut payload = json!({ "embeds": [embed] });
        if let Some(u) = self.username.as_deref() {
            payload["username"] = json!(u);
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
            "discord",
            "notification_discord",
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
            .ok_or_else(|| format!("channel '{channel}' (discord): '{key}' must be a string")),
        None => Ok(None),
    }
}
