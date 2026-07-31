//! Generic HTTP webhook channel.
//!
//! Posts an operator-templated body to an arbitrary HTTP endpoint. Supports
//! `${var}` substitution against a caller-supplied variable map (the plugin
//! exposes its alert context vars; another caller can expose its own).

use std::collections::HashMap;
use std::sync::Arc;

use http::header::{HeaderName, HeaderValue};
use serde_json::Value;

use crate::plugins::utils::http_client::PluginHttpClient;

use super::super::notification::Notification;
use super::super::templating::{
    render_template, render_template_json_string_escaped, validate_template,
};
use super::{
    finalize_dispatch_response_classified, redacted_endpoint_url, resolve_optional_string,
    transport_failure, validate_notification_url,
};

/// Template variable names the webhook channel projects from a generic
/// [`Notification`]. Callers (the proxy_alerts plugin in particular) supply
/// additional variables via the [`WebhookChannel::dispatch_with_vars`]
/// surface.
pub const NOTIFICATION_TEMPLATE_VARS: &[&str] = &[
    "title",
    "body",
    "severity",
    "event_action",
    "fired_at",
    "source",
    "subject_id",
    "namespace",
];

#[derive(Debug, Clone)]
pub struct WebhookChannel {
    name: Arc<str>,
    url: Arc<str>,
    method: HttpMethod,
    headers: Vec<(HeaderName, HeaderValue)>,
    body_template: Arc<str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Post,
    Put,
    Patch,
}

impl HttpMethod {
    fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_uppercase().as_str() {
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "PATCH" => Ok(Self::Patch),
            other => Err(format!(
                "unsupported method '{other}'; only POST, PUT, PATCH are allowed"
            )),
        }
    }
}

#[allow(dead_code)] // Accessors and the no-extras dispatch are part of the
// reusable channel surface; not all of them are exercised by the plugin's
// dispatch path today.
impl WebhookChannel {
    pub fn new(name: &str, value: &Value) -> Result<Self, String> {
        let url = resolve_optional_string(value, "url", "url_env", name)?
            .ok_or_else(|| format!("channel '{name}' (webhook): 'url' is required"))?;
        validate_url(&url, name)?;

        let method = match value.get("method") {
            Some(v) => v
                .as_str()
                .ok_or_else(|| format!("channel '{name}' (webhook): 'method' must be a string"))
                .and_then(|s| {
                    HttpMethod::parse(s).map_err(|e| format!("channel '{name}' (webhook): {e}"))
                })?,
            None => HttpMethod::Post,
        };

        let mut headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
        let mut has_content_type = false;
        if let Some(headers_val) = value.get("headers") {
            let map = headers_val.as_object().ok_or_else(|| {
                format!("channel '{name}' (webhook): 'headers' must be an object")
            })?;
            for (k, v) in map {
                let s = v.as_str().ok_or_else(|| {
                    format!("channel '{name}' (webhook): headers['{k}'] must be a string")
                })?;
                let header_name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| {
                    format!("channel '{name}' (webhook): invalid header name '{k}': {e}")
                })?;
                let header_value = HeaderValue::from_str(s).map_err(|e| {
                    format!("channel '{name}' (webhook): invalid header value for '{k}': {e}")
                })?;
                if header_name.as_str().eq_ignore_ascii_case("content-type") {
                    has_content_type = true;
                }
                headers.retain(|(existing, _)| *existing != header_name);
                headers.push((header_name, header_value));
            }
        }

        let body_template = value
            .get("body_template")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("channel '{name}' (webhook): 'body_template' is required"))?
            .to_string();
        validate_template(&body_template)
            .map_err(|e| format!("channel '{name}' (webhook): invalid 'body_template': {e}"))?;

        if !has_content_type {
            headers.push((
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("application/json"),
            ));
        }

        Ok(Self {
            name: Arc::from(name),
            url: Arc::from(url),
            method,
            headers,
            body_template: Arc::from(body_template),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn body_template(&self) -> &str {
        &self.body_template
    }

    pub fn method(&self) -> HttpMethod {
        self.method
    }

    pub fn headers(&self) -> &[(HeaderName, HeaderValue)] {
        &self.headers
    }

    /// Render the body using only the generic [`Notification`] variables.
    /// Callers with extra context should use [`Self::render_body_with_vars`].
    pub fn render_body(&self, n: &Notification) -> Result<String, String> {
        let vars = base_vars(n);
        self.render_body_from_vars(&vars)
    }

    /// Render using caller-supplied variables plus generic notification variables.
    /// Generic notification variables win on key collisions so callers cannot
    /// accidentally override `${title}`, `${severity}`, etc.
    pub fn render_body_with_vars(
        &self,
        n: &Notification,
        extras: &HashMap<String, String>,
    ) -> Result<String, String> {
        let mut vars = extras.clone();
        vars.extend(base_vars(n));
        self.render_body_from_vars(&vars)
    }

    /// Dispatch with extra template variables supplied by the caller.
    pub async fn dispatch_with_vars(
        &self,
        notification: &Notification,
        extras: &HashMap<String, String>,
        http: &PluginHttpClient,
    ) -> Result<(), String> {
        match self
            .dispatch_with_vars_classified(notification, extras, http)
            .await
        {
            crate::notifications::outcome::DeliveryAttempt::Success => Ok(()),
            crate::notifications::outcome::DeliveryAttempt::Failed { message, .. } => Err(message),
        }
    }

    pub async fn dispatch_with_vars_classified(
        &self,
        notification: &Notification,
        extras: &HashMap<String, String>,
        http: &PluginHttpClient,
    ) -> crate::notifications::outcome::DeliveryAttempt {
        use crate::notifications::outcome::{DeliveryAttempt, FailureClass};

        let body = match self.render_body_with_vars(notification, extras) {
            Ok(body) => body,
            Err(message) => return DeliveryAttempt::failed(FailureClass::Permanent, message),
        };
        let mut req = match self.method {
            HttpMethod::Post => http.get().post(self.url.as_ref()),
            HttpMethod::Put => http.get().put(self.url.as_ref()),
            HttpMethod::Patch => http.get().patch(self.url.as_ref()),
        };
        for (k, v) in &self.headers {
            req = req.header(k.clone(), v.clone());
        }
        req = req.body(body);
        let redacted_url = redacted_endpoint_url(&self.url);
        let resp = match http
            .execute_with_redacted_url(req, "notification_webhook", &redacted_url)
            .await
        {
            Ok(response) => response,
            Err(error) => return transport_failure("webhook", &error, &redacted_url),
        };
        finalize_dispatch_response_classified(resp, "webhook", &redacted_url).await
    }

    pub async fn dispatch(
        &self,
        notification: &Notification,
        http: &PluginHttpClient,
    ) -> Result<(), String> {
        let extras: HashMap<String, String> = HashMap::new();
        self.dispatch_with_vars(notification, &extras, http).await
    }

    fn render_body_from_vars(&self, vars: &HashMap<String, String>) -> Result<String, String> {
        if self.body_template_uses_json_escaping() {
            render_template_json_string_escaped(&self.body_template, vars)
        } else {
            render_template(&self.body_template, vars)
        }
    }

    fn body_template_uses_json_escaping(&self) -> bool {
        self.headers.iter().any(|(name, value)| {
            name.as_str().eq_ignore_ascii_case("content-type") && header_value_is_json(value)
        })
    }
}

fn header_value_is_json(value: &HeaderValue) -> bool {
    let Ok(raw) = value.to_str() else {
        return false;
    };
    let media_type = raw.split(';').next().unwrap_or("").trim();
    if media_type.eq_ignore_ascii_case("application/json") {
        return true;
    }
    media_type.to_ascii_lowercase().ends_with("+json")
}

/// Project the generic [`Notification`] variables into a template map. Shared
/// with the email channel so both operator-templated transports expose exactly
/// the same variable names.
pub(super) fn base_vars(n: &Notification) -> HashMap<String, String> {
    let mut vars = HashMap::with_capacity(NOTIFICATION_TEMPLATE_VARS.len());
    vars.insert("title".to_string(), n.title.clone());
    vars.insert("body".to_string(), n.body.clone());
    vars.insert("severity".to_string(), n.severity.to_string());
    vars.insert("event_action".to_string(), n.event_action.to_string());
    vars.insert("fired_at".to_string(), n.fired_at.to_rfc3339());
    vars.insert(
        "source".to_string(),
        n.source
            .as_deref()
            .map(|s| s.to_string())
            .unwrap_or_default(),
    );
    vars.insert(
        "subject_id".to_string(),
        n.subject_id
            .as_deref()
            .map(|s| s.to_string())
            .unwrap_or_default(),
    );
    vars.insert(
        "namespace".to_string(),
        n.namespace
            .as_deref()
            .map(|s| s.to_string())
            .unwrap_or_default(),
    );
    vars
}

fn validate_url(url: &str, channel: &str) -> Result<(), String> {
    validate_notification_url(url, channel, "webhook", "url")
}
