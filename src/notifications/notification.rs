//! Generic, plugin-agnostic notification model.
//!
//! [`Notification`] is the unit of work the notification layer ships. Callers
//! (the `proxy_alerts` plugin today, future overload-manager / mesh-policy
//! callers tomorrow) build a `Notification` and hand it to
//! [`crate::notifications::dispatch`]; channel implementations format it into
//! their own JSON payload (Slack attachment, Teams MessageCard, Discord embed,
//! arbitrary webhook body).
//!
//! The struct intentionally carries no alert-specific fields (`observed`,
//! `threshold`, `sample_count`) so a non-alert caller doesn't have to fabricate
//! values. Per-domain context goes into [`NotificationField`] rows that all
//! channels render uniformly.

use std::sync::Arc;

use crate::time_compat::UtcTimestamp;

/// Severity level for a notification. Mapped to channel-native colors per
/// channel (Slack hex, Teams hex, Discord int) inside each channel's
/// `dispatch()` impl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Slack `attachments[].color` — hex color.
    pub const fn slack_color(&self) -> &'static str {
        match self {
            Self::Info => "#2196F3",
            Self::Low => "#8BC34A",
            Self::Medium => "#FFC107",
            Self::High => "#FF5722",
            Self::Critical => "#B71C1C",
        }
    }

    /// Teams `themeColor` — hex color without leading `#`.
    pub const fn teams_color_hex(&self) -> &'static str {
        match self {
            Self::Info => "2196F3",
            Self::Low => "8BC34A",
            Self::Medium => "FFC107",
            Self::High => "FF5722",
            Self::Critical => "B71C1C",
        }
    }

    /// Discord `embeds[].color` — 24-bit RGB integer.
    pub const fn discord_color(&self) -> u32 {
        match self {
            Self::Info => 0x2196F3,
            Self::Low => 0x8BC34A,
            Self::Medium => 0xFFC107,
            Self::High => 0xFF5722,
            Self::Critical => 0xB71C1C,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle action this notification represents.
///
/// `Trigger` and `Resolve` are paired (alert raised / cleared); `Info` is for
/// one-shot informational notifications that have no resolved counterpart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventAction {
    Trigger,
    Resolve,
    Info,
}

impl EventAction {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Trigger => "trigger",
            Self::Resolve => "resolve",
            Self::Info => "info",
        }
    }
}

impl std::fmt::Display for EventAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One key/value row rendered by every channel as part of the notification
/// body (Slack `attachments[].fields[]`, Teams `sections[].facts[]`, Discord
/// `embeds[].fields[]`).
#[derive(Debug, Clone)]
pub struct NotificationField {
    pub name: String,
    pub value: String,
    /// Hint to render side-by-side with the next field (Slack/Discord only;
    /// Teams `facts` always render full-width).
    pub short: bool,
}

#[allow(dead_code)] // Public builder surface; full_width is not used by
// proxy_alerts but exposed for future callers / channels.
impl NotificationField {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            short: true,
        }
    }

    pub fn full_width(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            short: false,
        }
    }
}

/// A generic notification ready to be dispatched to one or more channels.
///
/// Channel implementations consume this by reference and project it into
/// their own payload shape. Construct via [`Notification::builder`] for
/// readable call sites.
#[derive(Debug, Clone)]
pub struct Notification {
    pub title: String,
    pub body: String,
    pub severity: Severity,
    pub event_action: EventAction,
    /// Identifier of the producing subsystem (e.g.,
    /// `"proxy_alerts:proxy_5xx_spike"`). Surfaces in logs and is used by
    /// channels as a fallback subtitle.
    pub source: Option<Arc<str>>,
    /// Human-friendly subject the notification is about (e.g., proxy name).
    pub subject_id: Option<Arc<str>>,
    pub namespace: Option<Arc<str>>,
    pub fired_at: UtcTimestamp,
    pub fields: Vec<NotificationField>,
}

impl Notification {
    pub fn builder(title: impl Into<String>) -> NotificationBuilder {
        NotificationBuilder {
            title: title.into(),
            body: String::new(),
            severity: Severity::Medium,
            event_action: EventAction::Info,
            source: None,
            subject_id: None,
            namespace: None,
            fired_at: UtcTimestamp::now(),
            fields: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NotificationBuilder {
    title: String,
    body: String,
    severity: Severity,
    event_action: EventAction,
    source: Option<Arc<str>>,
    subject_id: Option<Arc<str>>,
    namespace: Option<Arc<str>>,
    fired_at: UtcTimestamp,
    fields: Vec<NotificationField>,
}

#[allow(dead_code)] // Public builder; not all setters are used by every caller.
impl NotificationBuilder {
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }
    pub fn severity(mut self, s: Severity) -> Self {
        self.severity = s;
        self
    }
    pub fn event_action(mut self, a: EventAction) -> Self {
        self.event_action = a;
        self
    }
    pub fn source(mut self, s: impl Into<Arc<str>>) -> Self {
        self.source = Some(s.into());
        self
    }
    pub fn subject_id(mut self, s: impl Into<Arc<str>>) -> Self {
        self.subject_id = Some(s.into());
        self
    }
    pub fn namespace(mut self, n: impl Into<Arc<str>>) -> Self {
        self.namespace = Some(n.into());
        self
    }
    pub fn fired_at(mut self, t: UtcTimestamp) -> Self {
        self.fired_at = t;
        self
    }
    pub fn field(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push(NotificationField::new(name, value));
        self
    }
    pub fn full_width_field(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push(NotificationField::full_width(name, value));
        self
    }
    pub fn fields(mut self, fields: Vec<NotificationField>) -> Self {
        self.fields = fields;
        self
    }
    pub fn build(self) -> Notification {
        Notification {
            title: self.title,
            body: self.body,
            severity: self.severity,
            event_action: self.event_action,
            source: self.source,
            subject_id: self.subject_id,
            namespace: self.namespace,
            fired_at: self.fired_at,
            fields: self.fields,
        }
    }
}
