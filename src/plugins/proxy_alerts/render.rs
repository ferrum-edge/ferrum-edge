//! Build a generic [`Notification`] (and webhook template-variable map) from
//! a fired rule observation.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::notifications::{EventAction, Notification, NotificationField};

use super::rules::{Rule, RuleObservation, SampleInput};

/// Proxy identity a notification is rendered for.
///
/// Built from the triggering sample on the traffic path, or from the identity
/// recorded when the incident was alerted when the background lifecycle
/// re-evaluation resolves an incident on a proxy that stopped producing
/// traffic.
#[derive(Debug, Clone, Copy)]
pub struct AlertSubject<'a> {
    pub namespace: &'a str,
    pub proxy_id: Option<&'a str>,
    pub proxy_name: Option<&'a str>,
}

impl<'a> AlertSubject<'a> {
    pub fn from_sample(sample: SampleInput<'a>) -> Self {
        Self {
            namespace: sample.namespace(),
            proxy_id: sample.proxy_id(),
            proxy_name: sample.proxy_name(),
        }
    }
}

/// Stable receiver-side incident key for one
/// `(plugin config, namespace, proxy, rule)`.
///
/// `policy_id` is the stable plugin-config resource id of the `proxy_alerts`
/// instance (rule names are unique only within one instance, and several
/// instances may apply to one proxy), so two instances that reuse a rule name
/// never share a receiver incident. It is the same on every replica and across
/// compatible reloads; directly constructed instances use
/// [`super::STANDALONE_POLICY_ID`].
///
/// Identical for the Trigger, every reminder, and the Resolve of the same
/// rule/proxy, so a receiver that correlates on it (PagerDuty `dedup_key`,
/// Opsgenie `alias`) closes the incident the Trigger opened. Fields are
/// length-prefixed before hashing so distinct identities cannot collide by
/// concatenation; the output is fixed-length ASCII (`pa1-` + 64 hex chars),
/// safe for any JSON string and well under PagerDuty's 255-character limit.
pub fn incident_key(policy_id: &str, namespace: &str, proxy_id: &str, rule_name: &str) -> String {
    use crate::fips::approved::Sha256;
    let mut hasher = Sha256::new();
    hasher.update(b"ferrum-edge/proxy_alerts/incident/v1");
    for part in [policy_id, namespace, proxy_id, rule_name] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    format!("pa1-{}", hex::encode(hasher.finalize()))
}

pub fn build_notification(
    rule: &Rule,
    observation: &RuleObservation,
    subject: AlertSubject<'_>,
    event_action: EventAction,
    now: DateTime<Utc>,
) -> Notification {
    let common = rule.common();
    let rendered = observation.render(rule);
    let proxy_label = subject
        .proxy_name
        .or(subject.proxy_id)
        .unwrap_or("(unknown proxy)");
    let title = match event_action {
        EventAction::Trigger => format!("[ALERT] {} on {}", common.name, proxy_label),
        EventAction::Resolve => format!("[RESOLVED] {} on {}", common.name, proxy_label),
        EventAction::Info => format!("{} on {}", common.name, proxy_label),
    };
    let mut fields: Vec<NotificationField> = vec![
        NotificationField::new("Rule", common.name.to_string()),
        NotificationField::new("Type", rule.type_str().to_string()),
        NotificationField::new("Severity", common.severity.as_str().to_string()),
        NotificationField::new("Proxy", proxy_label.to_string()),
        NotificationField::new("Observed", rendered.observed.clone()),
        NotificationField::new("Threshold", rendered.threshold.clone()),
        NotificationField::new("Window", format!("{}s", common.window_seconds)),
        NotificationField::new("Samples", observation.sample_count.to_string()),
    ];
    let ns = subject.namespace;
    if !ns.is_empty() {
        fields.push(NotificationField::new("Namespace", ns.to_string()));
    }
    if !common.channel_names.is_empty() {
        let names: Vec<&str> = common.channel_names.iter().map(|n| n.as_ref()).collect();
        fields.push(NotificationField::full_width("Channels", names.join(", ")));
    }
    let body = match event_action {
        EventAction::Resolve => {
            format!("Rule '{}' has recovered: {}", common.name, rendered.reason)
        }
        _ => rendered.reason,
    };
    let source: Arc<str> = Arc::from(format!("proxy_alerts:{}", common.name).as_str());
    let mut builder = Notification::builder(title)
        .body(body)
        .severity(common.severity)
        .event_action(event_action)
        .source(source)
        .fired_at(now)
        .fields(fields);
    if let Some(name) = subject.proxy_name {
        builder = builder.subject_id(Arc::from(name));
    } else if let Some(id) = subject.proxy_id {
        builder = builder.subject_id(Arc::from(id));
    }
    if !ns.is_empty() {
        builder = builder.namespace(Arc::from(ns));
    }
    builder.build()
}

/// `policy_id` is the instance's stable plugin-config id; see [`incident_key`].
pub fn build_webhook_vars(
    rule: &Rule,
    observation: &RuleObservation,
    subject: AlertSubject<'_>,
    policy_id: &str,
    event_action: EventAction,
    now: DateTime<Utc>,
) -> HashMap<String, String> {
    let common = rule.common();
    let rendered = observation.render(rule);
    let proxy_id = subject.proxy_id.unwrap_or("");
    let mut vars = HashMap::with_capacity(13);
    vars.insert("rule_name".to_string(), common.name.to_string());
    vars.insert("proxy_id".to_string(), proxy_id.to_string());
    vars.insert(
        "proxy_name".to_string(),
        subject.proxy_name.unwrap_or("").to_string(),
    );
    vars.insert("namespace".to_string(), subject.namespace.to_string());
    vars.insert(
        "incident_key".to_string(),
        incident_key(policy_id, subject.namespace, proxy_id, &common.name),
    );
    vars.insert("fired_at".to_string(), now.to_rfc3339());
    vars.insert("observed".to_string(), rendered.observed);
    vars.insert("threshold".to_string(), rendered.threshold);
    vars.insert(
        "sample_count".to_string(),
        observation.sample_count.to_string(),
    );
    vars.insert(
        "window_seconds".to_string(),
        common.window_seconds.to_string(),
    );
    vars.insert("severity".to_string(), common.severity.as_str().to_string());
    vars.insert("reason".to_string(), rendered.reason);
    vars.insert(
        "event_action".to_string(),
        event_action.as_str().to_string(),
    );
    vars
}
