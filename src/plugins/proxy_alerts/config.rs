//! Config parsing for the `proxy_alerts` plugin.
//!
//! Builds typed [`Rule`] / channel definitions from `serde_json::Value`,
//! validates ranges, resolves channel-name references to channel ids, and
//! collects parsed quiet-hours windows. All errors are surfaced as
//! `Result<_, String>` from `ProxyAlerts::new`: direct/Admin validation rejects
//! them, while serving-mode publication applies the plugin's documented
//! `OptionalFailOpen` policy and warns before omitting the invalid instance.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde_json::{Map, Value};

use crate::notifications::{NotificationChannel, Severity, channels::parse_channels};
use crate::plugins::DisconnectCause;
use crate::retry::ErrorClass;
use crate::util::unknown_keys::{near_miss_for_missing_key, reject_unknown_keys};

use super::rules::{
    ErrorClassRule, ErrorRateRule, LatencyMetric, LatencyPercentileRule, RecoveryConfig, Rule,
    RuleCommon, StatusCodeCountRule, StreamDisconnectCauseRule,
};
use super::windows::MAX_FINITE_LATENCY_BOUND_MS;

const MIN_WINDOW_SECONDS: u32 = 5;
const MAX_WINDOW_SECONDS: u32 = 3600;
const MIN_COOLDOWN_SECONDS: u32 = 1;
const MAX_COOLDOWN_SECONDS: u32 = 86_400;
const MIN_RESOLVED_WINDOW_SECONDS: u32 = 5;
const MAX_RESOLVED_WINDOW_SECONDS: u32 = 86_400;

const TOP_LEVEL_KEYS: &[&str] = &[
    "enabled",
    "default_cooldown_seconds",
    "default_min_request_count",
    "default_window_seconds",
    "default_resolved_window_seconds",
    "max_concurrent_dispatches",
    "quiet_hours_utc",
    "channels",
    "rules",
];

const QUIET_HOUR_KEYS: &[&str] = &["from", "to", "weekdays"];
const RECOVERY_KEYS: &[&str] = &["resolved_window_seconds"];
const ERROR_RATE_KEYS: &[&str] = &[
    "name",
    "enabled",
    "type",
    "window_seconds",
    "channels",
    "cooldown_seconds",
    "recovery",
    "severity",
    "status_codes",
    "threshold_percent",
    "min_request_count",
];
const STATUS_CODE_COUNT_KEYS: &[&str] = &[
    "name",
    "enabled",
    "type",
    "window_seconds",
    "channels",
    "cooldown_seconds",
    "recovery",
    "severity",
    "status_codes",
    "threshold_count",
];
const LATENCY_PERCENTILE_KEYS: &[&str] = &[
    "name",
    "enabled",
    "type",
    "window_seconds",
    "channels",
    "cooldown_seconds",
    "recovery",
    "severity",
    "metric",
    "percentile",
    "threshold_ms",
    "min_request_count",
];
const ERROR_CLASS_KEYS: &[&str] = &[
    "name",
    "enabled",
    "type",
    "window_seconds",
    "channels",
    "cooldown_seconds",
    "recovery",
    "severity",
    "classes",
    "threshold_count",
];
const STREAM_DISCONNECT_CAUSE_KEYS: &[&str] = &[
    "name",
    "enabled",
    "type",
    "window_seconds",
    "channels",
    "cooldown_seconds",
    "recovery",
    "severity",
    "causes",
    "threshold_count",
];

#[derive(Debug)]
pub struct ProxyAlertsConfig {
    pub enabled: bool,
    /// Bounded-concurrency semaphore size for outbound notification
    /// dispatches. Default `8` is intentionally conservative: alert storms
    /// during a partial channel outage should be VISIBLE (drops trigger
    /// `warn!` log lines) rather than silently BUFFERED behind a slow
    /// channel. Operators with wide fanout (e.g. Slack + Teams + PagerDuty +
    /// Discord all firing simultaneously) should bump this to 16-32; see
    /// `docs/proxy_alerts.md` for tuning guidance.
    pub max_concurrent_dispatches: usize,
    pub quiet_hours: Vec<QuietHourWindow>,
    /// Channels indexed by name; kept around for admin debug surfaces and
    /// future use cases (e.g., a `/proxy_alerts` admin endpoint that lists
    /// configured channels).
    #[allow(dead_code)]
    pub channels: Arc<HashMap<String, Arc<NotificationChannel>>>,
    pub channel_by_id: Arc<HashMap<u32, Arc<NotificationChannel>>>,
    pub rules: Arc<Vec<Rule>>,
}

#[derive(Debug, Clone)]
pub struct QuietHourWindow {
    /// Minutes from 00:00 UTC for the start of the quiet window.
    pub from_minute: u32,
    /// Minutes from 00:00 UTC for the end of the quiet window. May be less
    /// than `from_minute` (window wraps past midnight).
    pub to_minute: u32,
    /// Allowed weekdays (0 = Sunday … 6 = Saturday). Empty list means "every
    /// day"; explicit list means "only these days".
    pub weekdays: Vec<u32>,
}

impl QuietHourWindow {
    pub fn matches(&self, dt: DateTime<Utc>) -> bool {
        let now_minute = dt.hour() * 60 + dt.minute();
        if self.from_minute == self.to_minute {
            // Zero-length window matches nothing.
            return false;
        }
        let window_start_weekday = if self.from_minute < self.to_minute {
            if !(now_minute >= self.from_minute && now_minute < self.to_minute) {
                return false;
            }
            dt.weekday().num_days_from_sunday()
        } else if now_minute >= self.from_minute {
            dt.weekday().num_days_from_sunday()
        } else if now_minute < self.to_minute {
            // Wrapped overnight window: after-midnight minutes still belong
            // to the previous day's scheduled window.
            previous_weekday(dt.weekday().num_days_from_sunday())
        } else {
            return false;
        };

        self.weekdays.is_empty() || self.weekdays.contains(&window_start_weekday)
    }
}

fn previous_weekday(day_from_sunday: u32) -> u32 {
    if day_from_sunday == 0 {
        6
    } else {
        day_from_sunday - 1
    }
}

impl ProxyAlertsConfig {
    pub fn parse(config: &Value) -> Result<Self, String> {
        let obj = config
            .as_object()
            .ok_or_else(|| "proxy_alerts: config must be an object".to_string())?;
        reject_unknown_keys(obj, "config", TOP_LEVEL_KEYS, "proxy_alerts: ")?;

        let enabled = read_optional_bool(config, "enabled", "proxy_alerts")?.unwrap_or(true);
        let default_cooldown_seconds = read_u32_default(config, "default_cooldown_seconds", 300)?;
        let default_min_request_count = read_u64_default(config, "default_min_request_count", 50)?;
        let default_window_seconds = read_u32_default(config, "default_window_seconds", 60)?;
        let default_resolved_window_seconds =
            read_u32_default(config, "default_resolved_window_seconds", 300)?;
        validate_top_level_u32_range(
            "default_cooldown_seconds",
            default_cooldown_seconds,
            MIN_COOLDOWN_SECONDS,
            MAX_COOLDOWN_SECONDS,
        )?;
        if default_min_request_count == 0 {
            return Err("proxy_alerts: 'default_min_request_count' must be >= 1".to_string());
        }
        validate_top_level_u32_range(
            "default_window_seconds",
            default_window_seconds,
            MIN_WINDOW_SECONDS,
            MAX_WINDOW_SECONDS,
        )?;
        validate_top_level_u32_range(
            "default_resolved_window_seconds",
            default_resolved_window_seconds,
            MIN_RESOLVED_WINDOW_SECONDS,
            MAX_RESOLVED_WINDOW_SECONDS,
        )?;
        let max_concurrent_dispatches = {
            let n = read_u32_default(config, "max_concurrent_dispatches", 8)?;
            if n == 0 {
                return Err("proxy_alerts: 'max_concurrent_dispatches' must be >= 1".to_string());
            }
            n as usize
        };

        let quiet_hours = parse_quiet_hours(config.get("quiet_hours_utc"))?;

        let channels_value = config
            .get("channels")
            .ok_or_else(|| "proxy_alerts: 'channels' is required".to_string())?;
        let channels = parse_channels(channels_value).map_err(|e| format!("proxy_alerts: {e}"))?;

        // Assign deterministic channel ids in alphabetical order so test
        // snapshots and log output are stable across runs.
        let mut channel_names: Vec<&String> = channels.keys().collect();
        channel_names.sort();
        let mut channel_id_by_name: HashMap<String, u32> = HashMap::with_capacity(channels.len());
        let mut channel_by_id: HashMap<u32, Arc<NotificationChannel>> =
            HashMap::with_capacity(channels.len());
        for (idx, name) in channel_names.iter().enumerate() {
            let id = idx as u32;
            channel_id_by_name.insert((*name).clone(), id);
            channel_by_id.insert(id, Arc::clone(&channels[*name]));
        }

        let rules_value = config
            .get("rules")
            .ok_or_else(|| "proxy_alerts: 'rules' is required".to_string())?;
        let rules_array = rules_value
            .as_array()
            .ok_or_else(|| "proxy_alerts: 'rules' must be an array".to_string())?;
        if rules_array.is_empty() {
            return Err("proxy_alerts: 'rules' must contain at least one rule".to_string());
        }

        let mut seen_rule_names: HashSet<String> = HashSet::new();
        let mut rules: Vec<Rule> = Vec::with_capacity(rules_array.len());
        for (idx, raw_rule) in rules_array.iter().enumerate() {
            // Per-rule `enabled: false` skips the rule before validation so
            // operators can keep incomplete draft rules in config without
            // breaking the active alert set. Present non-boolean values fail
            // closed rather than defaulting to active.
            let rule_enabled = match raw_rule.get("enabled") {
                None => true,
                Some(v) => v.as_bool().ok_or_else(|| {
                    format!("proxy_alerts: rules[{idx}].enabled must be a boolean")
                })?,
            };
            if !rule_enabled {
                continue;
            }
            let rule_id = idx as u32;
            let rule = parse_rule(
                rule_id,
                raw_rule,
                &channel_id_by_name,
                &channels,
                RuleDefaults {
                    cooldown_seconds: default_cooldown_seconds,
                    window_seconds: default_window_seconds,
                    resolved_window_seconds: default_resolved_window_seconds,
                    min_request_count: default_min_request_count,
                },
            )?;
            let name = rule.common().name.to_string();
            if !seen_rule_names.insert(name.clone()) {
                return Err(format!(
                    "proxy_alerts: duplicate rule name '{name}' (rule names must be unique)"
                ));
            }
            rules.push(rule);
        }

        if rules.is_empty() {
            return Err(
                "proxy_alerts: every rule was 'enabled: false' — no rules left to evaluate"
                    .to_string(),
            );
        }

        Ok(Self {
            enabled,
            max_concurrent_dispatches,
            quiet_hours,
            channels: Arc::new(channels),
            channel_by_id: Arc::new(channel_by_id),
            rules: Arc::new(rules),
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct RuleDefaults {
    cooldown_seconds: u32,
    window_seconds: u32,
    resolved_window_seconds: u32,
    min_request_count: u64,
}

fn parse_rule(
    id: u32,
    raw: &Value,
    channel_id_by_name: &HashMap<String, u32>,
    channels: &HashMap<String, Arc<NotificationChannel>>,
    defaults: RuleDefaults,
) -> Result<Rule, String> {
    let obj = raw
        .as_object()
        .ok_or_else(|| format!("proxy_alerts: rule[{id}] must be an object"))?;
    let name = match obj.get("name") {
        Some(v) => {
            let s = v
                .as_str()
                .ok_or_else(|| format!("proxy_alerts: rule[{id}]: 'name' must be a string"))?;
            if s.is_empty() {
                return Err(format!(
                    "proxy_alerts: rule[{id}]: 'name' must not be empty"
                ));
            }
            s.to_string()
        }
        None => {
            return Err(missing_required_key_error(
                obj,
                &format!("proxy_alerts: rule[{id}]"),
                "name",
            ));
        }
    };
    let kind = match obj.get("type") {
        Some(v) => v
            .as_str()
            .ok_or_else(|| format!("proxy_alerts: rule '{name}': 'type' must be a string"))?,
        None => {
            return Err(missing_required_key_error(
                obj,
                &format!("proxy_alerts: rule '{name}'"),
                "type",
            ));
        }
    };
    let rule_path = format!("rules[{id}]");

    match kind {
        "error_rate" => {
            reject_unknown_keys(obj, &rule_path, ERROR_RATE_KEYS, "proxy_alerts: ")?;
            let common = build_rule_common(id, &name, raw, channel_id_by_name, channels, defaults)?;
            parse_error_rate(common, raw, defaults).map(Rule::ErrorRate)
        }
        "status_code_count" => {
            reject_unknown_keys(obj, &rule_path, STATUS_CODE_COUNT_KEYS, "proxy_alerts: ")?;
            let common = build_rule_common(id, &name, raw, channel_id_by_name, channels, defaults)?;
            parse_status_code_count(common, raw).map(Rule::StatusCodeCount)
        }
        "latency_percentile" => {
            reject_unknown_keys(obj, &rule_path, LATENCY_PERCENTILE_KEYS, "proxy_alerts: ")?;
            let common = build_rule_common(id, &name, raw, channel_id_by_name, channels, defaults)?;
            parse_latency_percentile(common, raw, defaults).map(Rule::LatencyPercentile)
        }
        "error_class" => {
            reject_unknown_keys(obj, &rule_path, ERROR_CLASS_KEYS, "proxy_alerts: ")?;
            let common = build_rule_common(id, &name, raw, channel_id_by_name, channels, defaults)?;
            parse_error_class(common, raw).map(Rule::ErrorClass)
        }
        "stream_disconnect_cause" => {
            reject_unknown_keys(
                obj,
                &rule_path,
                STREAM_DISCONNECT_CAUSE_KEYS,
                "proxy_alerts: ",
            )?;
            let common = build_rule_common(id, &name, raw, channel_id_by_name, channels, defaults)?;
            parse_stream_disconnect_cause(common, raw).map(Rule::StreamDisconnectCause)
        }
        other => Err(format!(
            "proxy_alerts: rule '{name}': unknown type '{other}' (expected one of: error_rate, status_code_count, latency_percentile, error_class, stream_disconnect_cause)"
        )),
    }
}

fn build_rule_common(
    id: u32,
    name: &str,
    raw: &Value,
    channel_id_by_name: &HashMap<String, u32>,
    channels: &HashMap<String, Arc<NotificationChannel>>,
    defaults: RuleDefaults,
) -> Result<RuleCommon, String> {
    let window_seconds = read_window_seconds(raw, name, defaults.window_seconds)?;
    let cooldown_ms = read_cooldown_ms(raw, name, defaults.cooldown_seconds)?;
    let recovery = read_recovery(raw, name, id, defaults.resolved_window_seconds)?;
    let severity = read_severity(raw, name)?;
    let (channel_ids, channel_names) = read_channels(raw, name, channel_id_by_name, channels)?;
    Ok(RuleCommon {
        id,
        name: Arc::from(name),
        window_seconds,
        cooldown_ms,
        recovery,
        severity,
        channel_ids,
        channel_names,
    })
}

fn missing_required_key_error(
    object: &Map<String, Value>,
    context: &str,
    required: &str,
) -> String {
    match near_miss_for_missing_key(object, required) {
        Some(typo) => format!(
            "{context}: '{required}' is required (did you mean '{required}' instead of '{typo}'?)"
        ),
        None => format!("{context}: '{required}' is required"),
    }
}

fn parse_error_rate(
    common: RuleCommon,
    raw: &Value,
    defaults: RuleDefaults,
) -> Result<ErrorRateRule, String> {
    let status_codes = read_status_codes(raw, &common.name)?;
    let threshold_percent = raw
        .get("threshold_percent")
        .and_then(Value::as_f64)
        .ok_or_else(|| {
            format!(
                "proxy_alerts: rule '{}': 'threshold_percent' is required",
                common.name
            )
        })?;
    if !(0.0 < threshold_percent && threshold_percent <= 100.0) {
        return Err(format!(
            "proxy_alerts: rule '{}': 'threshold_percent' must be in (0.0, 100.0] (got {threshold_percent})",
            common.name
        ));
    }
    let min_request_count = read_min_request_count(raw, &common.name, defaults.min_request_count)?;
    Ok(ErrorRateRule {
        common,
        status_codes,
        threshold_percent,
        min_request_count,
    })
}

fn parse_status_code_count(common: RuleCommon, raw: &Value) -> Result<StatusCodeCountRule, String> {
    let status_codes = read_status_codes(raw, &common.name)?;
    let threshold_count = read_threshold_count(raw, &common.name)?;
    Ok(StatusCodeCountRule {
        common,
        status_codes,
        threshold_count,
    })
}

fn parse_latency_percentile(
    common: RuleCommon,
    raw: &Value,
    defaults: RuleDefaults,
) -> Result<LatencyPercentileRule, String> {
    let metric_str = raw
        .get("metric")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!(
                "proxy_alerts: rule '{}': 'metric' is required (one of: backend_total_ms, backend_ttfb_ms, total_ms, stream_duration_ms)",
                common.name
            )
        })?;
    let metric = match metric_str {
        "backend_total_ms" => LatencyMetric::BackendTotalMs,
        "backend_ttfb_ms" => LatencyMetric::BackendTtfbMs,
        "total_ms" => LatencyMetric::TotalMs,
        "stream_duration_ms" => LatencyMetric::StreamDurationMs,
        other => {
            return Err(format!(
                "proxy_alerts: rule '{}': unknown 'metric' '{other}' (expected one of: backend_total_ms, backend_ttfb_ms, total_ms, stream_duration_ms)",
                common.name
            ));
        }
    };
    let percentile = raw
        .get("percentile")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            format!(
                "proxy_alerts: rule '{}': 'percentile' is required",
                common.name
            )
        })?;
    if !(1..=99).contains(&percentile) {
        return Err(format!(
            "proxy_alerts: rule '{}': 'percentile' must be in [1, 99] (got {percentile})",
            common.name
        ));
    }
    let threshold_ms = raw
        .get("threshold_ms")
        .and_then(Value::as_f64)
        .ok_or_else(|| {
            format!(
                "proxy_alerts: rule '{}': 'threshold_ms' is required",
                common.name
            )
        })?;
    if threshold_ms <= 0.0 {
        return Err(format!(
            "proxy_alerts: rule '{}': 'threshold_ms' must be > 0 (got {threshold_ms})",
            common.name
        ));
    }
    if threshold_ms > MAX_FINITE_LATENCY_BOUND_MS as f64 {
        return Err(format!(
            "proxy_alerts: rule '{}': 'threshold_ms' must be <= {} (largest finite histogram bucket; got {threshold_ms})",
            common.name, MAX_FINITE_LATENCY_BOUND_MS
        ));
    }
    let min_request_count = read_min_request_count(raw, &common.name, defaults.min_request_count)?;
    Ok(LatencyPercentileRule {
        common,
        metric,
        percentile: percentile as u8,
        threshold_ms,
        min_request_count,
    })
}

fn read_min_request_count(raw: &Value, rule_name: &str, default: u64) -> Result<u64, String> {
    let min_request_count = match raw.get("min_request_count") {
        None => default,
        Some(v) => v.as_u64().ok_or_else(|| {
            format!(
                "proxy_alerts: rule '{rule_name}': 'min_request_count' must be an unsigned integer"
            )
        })?,
    };
    if min_request_count == 0 {
        return Err(format!(
            "proxy_alerts: rule '{rule_name}': 'min_request_count' must be > 0"
        ));
    }
    Ok(min_request_count)
}

fn parse_error_class(common: RuleCommon, raw: &Value) -> Result<ErrorClassRule, String> {
    let arr = raw
        .get("classes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            format!(
                "proxy_alerts: rule '{}': 'classes' is required (array of error_class names)",
                common.name
            )
        })?;
    if arr.is_empty() {
        return Err(format!(
            "proxy_alerts: rule '{}': 'classes' must contain at least one entry",
            common.name
        ));
    }
    let mut classes = Vec::with_capacity(arr.len());
    for item in arr {
        let name = item.as_str().ok_or_else(|| {
            format!(
                "proxy_alerts: rule '{}': 'classes' entries must be strings",
                common.name
            )
        })?;
        // Deserialize through ErrorClass's authoritative serde contract so a
        // newly added runtime class cannot drift from proxy_alerts admission.
        let class = serde_json::from_value::<ErrorClass>(Value::String(name.to_string()))
            .map_err(|_| {
                format!(
                    "proxy_alerts: rule '{}': unknown error class '{name}'",
                    common.name
                )
            })?;
        if !classes.contains(&class) {
            classes.push(class);
        }
    }
    let threshold_count = read_threshold_count(raw, &common.name)?;
    Ok(ErrorClassRule {
        common,
        classes,
        threshold_count,
    })
}

fn parse_stream_disconnect_cause(
    common: RuleCommon,
    raw: &Value,
) -> Result<StreamDisconnectCauseRule, String> {
    let arr = raw.get("causes").and_then(Value::as_array).ok_or_else(|| {
        format!(
            "proxy_alerts: rule '{}': 'causes' is required (array of disconnect_cause names)",
            common.name
        )
    })?;
    if arr.is_empty() {
        return Err(format!(
            "proxy_alerts: rule '{}': 'causes' must contain at least one entry",
            common.name
        ));
    }
    let mut causes = Vec::with_capacity(arr.len());
    for item in arr {
        let name = item.as_str().ok_or_else(|| {
            format!(
                "proxy_alerts: rule '{}': 'causes' entries must be strings",
                common.name
            )
        })?;
        let cause = disconnect_cause_from_str(name).ok_or_else(|| {
            format!(
                "proxy_alerts: rule '{}': unknown disconnect cause '{name}'",
                common.name
            )
        })?;
        if !causes.contains(&cause) {
            causes.push(cause);
        }
    }
    let threshold_count = read_threshold_count(raw, &common.name)?;
    Ok(StreamDisconnectCauseRule {
        common,
        causes,
        threshold_count,
    })
}

fn read_status_codes(raw: &Value, rule_name: &str) -> Result<Vec<u16>, String> {
    let arr = raw
        .get("status_codes")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("proxy_alerts: rule '{rule_name}': 'status_codes' is required"))?;
    if arr.is_empty() {
        return Err(format!(
            "proxy_alerts: rule '{rule_name}': 'status_codes' must contain at least one entry"
        ));
    }
    let mut out = Vec::with_capacity(arr.len());
    for code in arr {
        let v = code.as_u64().ok_or_else(|| {
            format!(
                "proxy_alerts: rule '{rule_name}': 'status_codes' entries must be unsigned integers"
            )
        })?;
        if !(100..=599).contains(&v) {
            return Err(format!(
                "proxy_alerts: rule '{rule_name}': 'status_codes' entry {v} is not in [100, 599]"
            ));
        }
        let v16 = v as u16;
        if !out.contains(&v16) {
            out.push(v16);
        }
    }
    Ok(out)
}

fn read_threshold_count(raw: &Value, rule_name: &str) -> Result<u64, String> {
    let v = raw
        .get("threshold_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            format!("proxy_alerts: rule '{rule_name}': 'threshold_count' is required")
        })?;
    if v == 0 {
        return Err(format!(
            "proxy_alerts: rule '{rule_name}': 'threshold_count' must be > 0"
        ));
    }
    Ok(v)
}

fn read_window_seconds(raw: &Value, rule_name: &str, default: u32) -> Result<u32, String> {
    let v = read_rule_u32(raw, "window_seconds", rule_name)?.unwrap_or(default);
    if !(MIN_WINDOW_SECONDS..=MAX_WINDOW_SECONDS).contains(&v) {
        return Err(format!(
            "proxy_alerts: rule '{rule_name}': 'window_seconds' must be in [{MIN_WINDOW_SECONDS}, {MAX_WINDOW_SECONDS}] (got {v})"
        ));
    }
    Ok(v)
}

fn read_cooldown_ms(raw: &Value, rule_name: &str, default: u32) -> Result<u64, String> {
    let v = read_rule_u32(raw, "cooldown_seconds", rule_name)?.unwrap_or(default);
    if !(MIN_COOLDOWN_SECONDS..=MAX_COOLDOWN_SECONDS).contains(&v) {
        return Err(format!(
            "proxy_alerts: rule '{rule_name}': 'cooldown_seconds' must be in [{MIN_COOLDOWN_SECONDS}, {MAX_COOLDOWN_SECONDS}] (got {v})"
        ));
    }
    Ok(u64::from(v) * 1000)
}

fn read_recovery(
    raw: &Value,
    rule_name: &str,
    rule_id: u32,
    default_resolved_window_seconds: u32,
) -> Result<Option<RecoveryConfig>, String> {
    let Some(rec) = raw.get("recovery") else {
        return Ok(None);
    };
    if rec.is_null() {
        return Ok(None);
    }
    let rec_obj = rec
        .as_object()
        .ok_or_else(|| format!("proxy_alerts: rule '{rule_name}': 'recovery' must be an object"))?;
    reject_unknown_keys(
        rec_obj,
        &format!("rules[{rule_id}].recovery"),
        RECOVERY_KEYS,
        "proxy_alerts: ",
    )?;
    let resolved_window_seconds =
        read_object_u32(rec, "resolved_window_seconds", rule_name, "recovery")?
            .unwrap_or(default_resolved_window_seconds);
    if !(MIN_RESOLVED_WINDOW_SECONDS..=MAX_RESOLVED_WINDOW_SECONDS)
        .contains(&resolved_window_seconds)
    {
        return Err(format!(
            "proxy_alerts: rule '{rule_name}': 'recovery.resolved_window_seconds' must be in [{MIN_RESOLVED_WINDOW_SECONDS}, {MAX_RESOLVED_WINDOW_SECONDS}] (got {resolved_window_seconds})"
        ));
    }
    Ok(Some(RecoveryConfig {
        resolved_window_ms: u64::from(resolved_window_seconds) * 1000,
    }))
}

fn read_rule_u32(raw: &Value, key: &str, rule_name: &str) -> Result<Option<u32>, String> {
    let Some(v) = raw.get(key) else {
        return Ok(None);
    };
    let n = v.as_u64().ok_or_else(|| {
        format!("proxy_alerts: rule '{rule_name}': '{key}' must be an unsigned integer")
    })?;
    u32::try_from(n)
        .map(Some)
        .map_err(|_| format!("proxy_alerts: rule '{rule_name}': '{key}' is too large for u32"))
}

fn read_object_u32(
    raw: &Value,
    key: &str,
    rule_name: &str,
    object_name: &str,
) -> Result<Option<u32>, String> {
    let Some(v) = raw.get(key) else {
        return Ok(None);
    };
    let n = v.as_u64().ok_or_else(|| {
        format!(
            "proxy_alerts: rule '{rule_name}': '{object_name}.{key}' must be an unsigned integer"
        )
    })?;
    u32::try_from(n).map(Some).map_err(|_| {
        format!("proxy_alerts: rule '{rule_name}': '{object_name}.{key}' is too large for u32")
    })
}

fn read_severity(raw: &Value, rule_name: &str) -> Result<Severity, String> {
    let Some(v) = raw.get("severity") else {
        return Ok(Severity::Medium);
    };
    let s = v
        .as_str()
        .ok_or_else(|| format!("proxy_alerts: rule '{rule_name}': 'severity' must be a string"))?;
    match s {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(format!(
            "proxy_alerts: rule '{rule_name}': unknown severity '{other}' (expected one of: info, low, medium, high, critical)"
        )),
    }
}

fn read_channels(
    raw: &Value,
    rule_name: &str,
    channel_id_by_name: &HashMap<String, u32>,
    channels: &HashMap<String, Arc<NotificationChannel>>,
) -> Result<(Vec<u32>, Vec<Arc<str>>), String> {
    let arr = raw
        .get("channels")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("proxy_alerts: rule '{rule_name}': 'channels' is required"))?;
    if arr.is_empty() {
        return Err(format!(
            "proxy_alerts: rule '{rule_name}': 'channels' must contain at least one channel name"
        ));
    }
    let mut ids = Vec::with_capacity(arr.len());
    let mut names: Vec<Arc<str>> = Vec::with_capacity(arr.len());
    for item in arr {
        let name = item.as_str().ok_or_else(|| {
            format!("proxy_alerts: rule '{rule_name}': 'channels' entries must be strings")
        })?;
        let id = channel_id_by_name.get(name).ok_or_else(|| {
            format!("proxy_alerts: rule '{rule_name}': references unknown channel '{name}'")
        })?;
        // Defensive: ensure the channel actually parsed (e.g., not missing
        // from the resolved table).
        if !channels.contains_key(name) {
            return Err(format!(
                "proxy_alerts: rule '{rule_name}': channel '{name}' is registered but not in the channels table"
            ));
        }
        if !ids.contains(id) {
            ids.push(*id);
            names.push(Arc::from(name));
        }
    }
    Ok((ids, names))
}

fn parse_quiet_hours(value: Option<&Value>) -> Result<Vec<QuietHourWindow>, String> {
    let Some(v) = value else {
        return Ok(Vec::new());
    };
    // OpenAPI declares an array; present null is not the empty default.
    let arr = v
        .as_array()
        .ok_or_else(|| "proxy_alerts: 'quiet_hours_utc' must be an array".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for (idx, item) in arr.iter().enumerate() {
        let obj = item
            .as_object()
            .ok_or_else(|| format!("proxy_alerts: 'quiet_hours_utc'[{idx}] must be an object"))?;
        reject_unknown_keys(
            obj,
            &format!("quiet_hours_utc[{idx}]"),
            QUIET_HOUR_KEYS,
            "proxy_alerts: ",
        )?;
        let from_str = obj.get("from").and_then(Value::as_str).ok_or_else(|| {
            format!("proxy_alerts: 'quiet_hours_utc'[{idx}]: 'from' is required (HH:MM)")
        })?;
        let to_str = obj.get("to").and_then(Value::as_str).ok_or_else(|| {
            format!("proxy_alerts: 'quiet_hours_utc'[{idx}]: 'to' is required (HH:MM)")
        })?;
        let from_minute = parse_hh_mm(from_str)
            .map_err(|e| format!("proxy_alerts: 'quiet_hours_utc'[{idx}].from: {e}"))?;
        let to_minute = parse_hh_mm(to_str)
            .map_err(|e| format!("proxy_alerts: 'quiet_hours_utc'[{idx}].to: {e}"))?;
        let mut weekdays: Vec<u32> = Vec::new();
        if let Some(days) = obj.get("weekdays") {
            let days_arr = days.as_array().ok_or_else(|| {
                format!("proxy_alerts: 'quiet_hours_utc'[{idx}].weekdays must be an array")
            })?;
            for d in days_arr {
                let n = d.as_u64().ok_or_else(|| {
                    format!(
                        "proxy_alerts: 'quiet_hours_utc'[{idx}].weekdays entries must be 0..=6 integers"
                    )
                })?;
                if n > 6 {
                    return Err(format!(
                        "proxy_alerts: 'quiet_hours_utc'[{idx}].weekdays entry {n} is out of range 0..=6"
                    ));
                }
                let day = n as u32;
                if !weekdays.contains(&day) {
                    weekdays.push(day);
                }
            }
        }
        out.push(QuietHourWindow {
            from_minute,
            to_minute,
            weekdays,
        });
    }
    Ok(out)
}

fn parse_hh_mm(s: &str) -> Result<u32, String> {
    let (h, m) = s
        .split_once(':')
        .ok_or_else(|| format!("expected HH:MM, got '{s}'"))?;
    if h.len() != 2
        || m.len() != 2
        || !h.bytes().all(|b| b.is_ascii_digit())
        || !m.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!("expected HH:MM, got '{s}'"));
    }
    let hour: u32 = h.parse().map_err(|_| format!("invalid hour in '{s}'"))?;
    let minute: u32 = m.parse().map_err(|_| format!("invalid minute in '{s}'"))?;
    if hour > 23 {
        return Err(format!("hour {hour} out of range 0..=23 in '{s}'"));
    }
    if minute > 59 {
        return Err(format!("minute {minute} out of range 0..=59 in '{s}'"));
    }
    Ok(hour * 60 + minute)
}

fn read_u32_default(config: &Value, key: &str, default: u32) -> Result<u32, String> {
    match config.get(key) {
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| format!("proxy_alerts: '{key}' must be an unsigned integer"))?;
            u32::try_from(n).map_err(|_| format!("proxy_alerts: '{key}' is too large for u32"))
        }
        None => Ok(default),
    }
}

fn validate_top_level_u32_range(
    key: &str,
    value: u32,
    minimum: u32,
    maximum: u32,
) -> Result<(), String> {
    if !(minimum..=maximum).contains(&value) {
        return Err(format!(
            "proxy_alerts: '{key}' must be in [{minimum}, {maximum}] (got {value})"
        ));
    }
    Ok(())
}

fn read_u64_default(config: &Value, key: &str, default: u64) -> Result<u64, String> {
    match config.get(key) {
        Some(v) => v
            .as_u64()
            .ok_or_else(|| format!("proxy_alerts: '{key}' must be an unsigned integer")),
        None => Ok(default),
    }
}

fn read_optional_bool(config: &Value, key: &str, context: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("{context}: '{key}' must be a boolean")),
    }
}

fn disconnect_cause_from_str(s: &str) -> Option<DisconnectCause> {
    match s {
        "idle_timeout" => Some(DisconnectCause::IdleTimeout),
        "recv_error" => Some(DisconnectCause::RecvError),
        "backend_error" => Some(DisconnectCause::BackendError),
        "graceful_shutdown" => Some(DisconnectCause::GracefulShutdown),
        _ => None,
    }
}
