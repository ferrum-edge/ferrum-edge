//! Microsoft Teams Office 365 connector channel.
//!
//! Posts a `MessageCard` JSON payload. Teams `facts` always render
//! full-width, so [`NotificationField::short`] is ignored on this channel.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::plugins::utils::http_client::PluginHttpClient;

use super::super::notification::Notification;
use super::{dispatch_json_payload, resolve_optional_string, validate_webhook_url};

#[derive(Debug, Clone)]
pub struct TeamsChannel {
    name: Arc<str>,
    webhook_url: Arc<str>,
}

impl TeamsChannel {
    pub fn new(name: &str, value: &Value) -> Result<Self, String> {
        let webhook_url =
            resolve_optional_string(value, "webhook_url", "webhook_url_env", name)?
                .ok_or_else(|| format!("channel '{name}' (teams): 'webhook_url' is required"))?;
        validate_webhook_url(&webhook_url, name, "teams")?;
        Ok(Self {
            name: Arc::from(name),
            webhook_url: Arc::from(webhook_url),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn webhook_url(&self) -> &str {
        &self.webhook_url
    }

    pub fn build_payload(&self, n: &Notification) -> Value {
        let facts: Vec<Value> = n
            .fields
            .iter()
            .map(|f| {
                json!({
                    "name": f.name,
                    "value": f.value,
                })
            })
            .collect();
        let summary = n
            .source
            .as_deref()
            .map(|s| format!("ferrum-edge: {s}"))
            .unwrap_or_else(|| format!("ferrum-edge: {}", n.title));
        json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": n.severity.teams_color_hex(),
            "summary": summary,
            "title": n.title,
            "text": n.body,
            "sections": [{
                "facts": facts,
            }]
        })
    }

    pub async fn dispatch(
        &self,
        notification: &Notification,
        http: &PluginHttpClient,
    ) -> Result<(), String> {
        let payload = self.build_payload(notification);
        dispatch_json_payload(
            &self.webhook_url,
            "teams",
            "notification_teams",
            &payload,
            http,
        )
        .await
    }
}
