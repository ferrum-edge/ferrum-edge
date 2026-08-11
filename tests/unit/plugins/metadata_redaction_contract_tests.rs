//! GHSA-c95h-874g-fq5x: credential redaction + internal-only dedup metadata.
//!
//! Covers ordinary and schema-shaped log views, the four legacy dedup lifecycle
//! fields, API-key / API-token spellings, operator-extra keys, and non-secret
//! counter controls. All projections must share one sensitivity decision.

use ferrum_edge::_test_support::clone_log_metadata;
use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;
use ferrum_edge::plugins::utils::log_schema::{SchemaCapabilities, SchemaView, SummarySchema};
use ferrum_edge::plugins::utils::metadata_redaction::{
    INTERNAL_ONLY_METADATA_KEY_PREFIX, REDACTED_PLACEHOLDER, is_dedup_internal_metadata_key,
    is_internal_only_metadata_key, is_mesh_metrics_internal_metadata_key,
    is_sensitive_metadata_key_with_extras, parse_extras_list, strip_dedup_internal_metadata,
};
use ferrum_edge::plugins::{RequestContext, TransactionSummary};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

const LEGACY_DEDUP_FIELDS: &[&str] = &[
    "_dedup_key",
    "_dedup_fingerprint",
    "_dedup_local_inflight_token",
    "_dedup_redis_lock_token",
    "_DEDUP_REDIS_LOCK_TOKEN",
    "_DeDuP_Local_Inflight_Token",
    "_dedup-redis-lock-token",
    "_DedupRedisLockToken",
];

const NON_INTERNAL_DEDUP_CONTROLS: &[&str] = &[
    "dedup_key",
    "request_dedup_key",
    "_deduplication",
    "cache_key",
];

const API_CREDENTIAL_KEYS: &[&str] = &[
    "api_key",
    "api-key",
    "apikey",
    "APIKey",
    "APIToken",
    "openaiToken",
    "vendor_token",
];

const NON_SECRET_COUNTERS: &[&str] = &[
    "ai_total_tokens",
    "ai_prompt_tokens",
    "ai_completion_tokens",
    "cache_key",
    "routing_key",
];

const MESH_METRICS_DISABLED_METADATA: &str = "mesh.metrics.disabled";
const MESH_REQUEST_COUNT_OVERRIDES_METADATA: &str = "mesh.metrics.request_count.tag_overrides";

const MESH_METRICS_COORDINATION_KEYS: &[&str] = &[
    MESH_METRICS_DISABLED_METADATA,
    "mesh.metrics.prometheus_metrics_observed",
    MESH_REQUEST_COUNT_OVERRIDES_METADATA,
    "mesh.metrics.cel.request_host",
    "mesh.metrics.cel.request_method",
    "mesh.metrics.cel.destination_port",
    "Mesh.Metrics.Request_Duration.Tag_Overrides",
];

fn planted_metadata() -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    for (idx, key) in LEGACY_DEDUP_FIELDS.iter().enumerate() {
        metadata.insert(
            (*key).to_string(),
            format!("dedup-lifecycle-sentinel-{idx}"),
        );
    }
    for (idx, key) in API_CREDENTIAL_KEYS.iter().enumerate() {
        metadata.insert((*key).to_string(), format!("api-credential-sentinel-{idx}"));
    }
    for (idx, key) in NON_SECRET_COUNTERS.iter().enumerate() {
        metadata.insert((*key).to_string(), format!("counter-{idx}"));
    }
    metadata.insert("trace_id".to_string(), "trace-visible".to_string());
    metadata.insert("operator_canary".to_string(), "operator-secret".to_string());
    metadata
}

fn summary_with(metadata: HashMap<String, String>) -> TransactionSummary {
    TransactionSummary {
        metadata,
        ..TransactionSummary::default()
    }
}

fn serialize_native(summary: &TransactionSummary) -> Value {
    serde_json::to_value(summary).expect("native summary serializes")
}

fn serialize_schema(summary: &TransactionSummary, raw_schema: Value) -> Value {
    let schema = SummarySchema::compile(&raw_schema, "test", SchemaCapabilities::BASE)
        .expect("schema compiles");
    let view = SchemaView {
        summary,
        schema: &schema,
    };
    serde_json::to_value(view).expect("schema view serializes")
}

fn assert_no_lifecycle_leak(json: &str, parsed: &Value) {
    for key in LEGACY_DEDUP_FIELDS {
        assert!(
            parsed.pointer(&format!("/metadata/{key}")).is_none()
                && parsed.get(key).is_none()
                && parsed.get(format!("meta_{key}")).is_none(),
            "lifecycle key {key} must be omitted from projection: {json}"
        );
    }
    for idx in 0..LEGACY_DEDUP_FIELDS.len() {
        let sentinel = format!("dedup-lifecycle-sentinel-{idx}");
        assert!(
            !json.contains(&sentinel),
            "dedup lifecycle value leaked: {sentinel} in {json}"
        );
    }
}

fn assert_api_credentials_redacted(json: &str, md: &Map<String, Value>) {
    for (idx, key) in API_CREDENTIAL_KEYS.iter().enumerate() {
        let value = md
            .get(*key)
            .unwrap_or_else(|| panic!("missing projected key {key}: {json}"));
        assert_eq!(
            value.as_str(),
            Some(REDACTED_PLACEHOLDER),
            "{key} must redact, got {value} in {json}"
        );
        let sentinel = format!("api-credential-sentinel-{idx}");
        assert!(
            !json.contains(&sentinel),
            "API credential leaked for {key}: {json}"
        );
    }
}

fn assert_counters_visible(md: &Map<String, Value>) {
    for (idx, key) in NON_SECRET_COUNTERS.iter().enumerate() {
        let expected = format!("counter-{idx}");
        let value = md
            .get(*key)
            .unwrap_or_else(|| panic!("missing counter key {key}"));
        assert_eq!(value.as_str(), Some(expected.as_str()));
    }
}

#[test]
fn classifier_covers_api_key_spellings_and_non_secret_controls() {
    assert_eq!(INTERNAL_ONLY_METADATA_KEY_PREFIX, "_dedup_");
    let extras = parse_extras_list("operator_canary");
    for key in API_CREDENTIAL_KEYS {
        assert!(
            is_sensitive_metadata_key_with_extras(key, &extras),
            "{key} must be sensitive"
        );
    }
    for key in NON_SECRET_COUNTERS {
        assert!(
            !is_sensitive_metadata_key_with_extras(key, &extras),
            "{key} must remain visible"
        );
    }
    assert!(is_sensitive_metadata_key_with_extras(
        "operator_canary",
        &extras
    ));
    for key in LEGACY_DEDUP_FIELDS {
        assert!(
            is_internal_only_metadata_key(key)
                && is_sensitive_metadata_key_with_extras(key, &extras),
            "{key} must be internal-only and fail closed"
        );
    }
    for key in NON_INTERNAL_DEDUP_CONTROLS {
        assert!(
            !is_internal_only_metadata_key(key),
            "{key} must not be swept into the internal-only namespace"
        );
    }
}

#[test]
fn clone_log_metadata_strips_all_four_legacy_dedup_fields() {
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/pay".into());
    ctx.metadata = planted_metadata();

    let logged = clone_log_metadata(&ctx);
    for key in LEGACY_DEDUP_FIELDS {
        assert!(
            !logged.contains_key(*key),
            "{key} survived clone_log_metadata"
        );
    }
    assert_eq!(
        logged.get("trace_id").map(String::as_str),
        Some("trace-visible")
    );
    assert_eq!(
        logged.get("api_key").map(String::as_str),
        Some("api-credential-sentinel-0")
    );
}

#[test]
fn classifier_splits_dedup_strip_from_mesh_metrics_serialization() {
    for key in LEGACY_DEDUP_FIELDS {
        assert!(
            is_dedup_internal_metadata_key(key) && is_internal_only_metadata_key(key),
            "{key} must be dedup-internal and serialization-internal"
        );
        assert!(
            !is_mesh_metrics_internal_metadata_key(key),
            "{key} must not be classified as mesh.metrics internal"
        );
    }
    for key in MESH_METRICS_COORDINATION_KEYS {
        assert!(
            is_mesh_metrics_internal_metadata_key(key) && is_internal_only_metadata_key(key),
            "{key} must be mesh-metrics internal and serialization-internal"
        );
        assert!(
            !is_dedup_internal_metadata_key(key),
            "{key} must not be stripped before in-process summary"
        );
    }
    for key in NON_INTERNAL_DEDUP_CONTROLS {
        assert!(
            !is_dedup_internal_metadata_key(key) && !is_mesh_metrics_internal_metadata_key(key),
            "{key} must remain observable"
        );
    }
}

#[test]
fn clone_log_metadata_preserves_mesh_metrics_coordination_keys() {
    let mut ctx = RequestContext::new("203.0.113.10".into(), "POST".into(), "/orders".into());
    ctx.metadata = planted_metadata();
    for (idx, key) in MESH_METRICS_COORDINATION_KEYS.iter().enumerate() {
        ctx.metadata
            .insert((*key).to_string(), format!("mesh-plan-{idx}"));
    }

    let logged = clone_log_metadata(&ctx);
    for key in LEGACY_DEDUP_FIELDS {
        assert!(
            !logged.contains_key(*key),
            "{key} survived clone_log_metadata"
        );
    }
    for (idx, key) in MESH_METRICS_COORDINATION_KEYS.iter().enumerate() {
        assert_eq!(
            logged.get(*key).map(String::as_str),
            Some(format!("mesh-plan-{idx}").as_str()),
            "{key} must survive production summary projection"
        );
    }
}

#[test]
fn strip_dedup_internal_metadata_retains_mesh_metrics_plans() {
    let mut metadata = planted_metadata();
    for (idx, key) in MESH_METRICS_COORDINATION_KEYS.iter().enumerate() {
        metadata.insert((*key).to_string(), format!("mesh-plan-{idx}"));
    }
    strip_dedup_internal_metadata(&mut metadata);
    for key in LEGACY_DEDUP_FIELDS {
        assert!(!metadata.contains_key(*key));
    }
    for (idx, key) in MESH_METRICS_COORDINATION_KEYS.iter().enumerate() {
        assert_eq!(
            metadata.get(*key).map(String::as_str),
            Some(format!("mesh-plan-{idx}").as_str())
        );
    }
}

#[test]
fn native_summary_omits_mesh_metrics_coordination_keys() {
    let mut metadata = planted_metadata();
    for (idx, key) in MESH_METRICS_COORDINATION_KEYS.iter().enumerate() {
        metadata.insert((*key).to_string(), format!("mesh-plan-{idx}"));
    }
    let summary = summary_with(metadata);
    let parsed = serialize_native(&summary);
    let json = parsed.to_string();
    let md = parsed
        .get("metadata")
        .and_then(Value::as_object)
        .expect("native metadata object");

    for key in MESH_METRICS_COORDINATION_KEYS {
        assert!(
            md.get(*key).is_none(),
            "{key} must be omitted from serialized summary: {json}"
        );
    }
    for idx in 0..MESH_METRICS_COORDINATION_KEYS.len() {
        assert!(
            !json.contains(&format!("mesh-plan-{idx}")),
            "mesh coordination value leaked: {json}"
        );
    }
    assert_eq!(
        md.get("trace_id").and_then(Value::as_str),
        Some("trace-visible")
    );
}

#[test]
fn prometheus_consumes_disable_and_tag_override_from_clone_log_metadata_projection() {
    let mut ctx = RequestContext::new("10.0.0.1".into(), "GET".into(), "/orders".into());
    ctx.metadata.extend([
        ("mesh.source.workload".to_string(), "frontend".to_string()),
        ("mesh.source.namespace".to_string(), "default".to_string()),
        (
            "mesh.destination.workload".to_string(),
            "orders".to_string(),
        ),
        ("mesh.request_protocol".to_string(), "http".to_string()),
        (
            "mesh.connection_security_policy".to_string(),
            "mutual_tls".to_string(),
        ),
        (
            MESH_METRICS_DISABLED_METADATA.to_string(),
            "request_count".to_string(),
        ),
        (
            MESH_REQUEST_COUNT_OVERRIDES_METADATA.to_string(),
            "m0;s0,4:edge;r11;".to_string(),
        ),
    ]);

    let projected = clone_log_metadata(&ctx);
    assert_eq!(
        projected
            .get(MESH_METRICS_DISABLED_METADATA)
            .map(String::as_str),
        Some("request_count")
    );
    assert_eq!(
        projected
            .get(MESH_REQUEST_COUNT_OVERRIDES_METADATA)
            .map(String::as_str),
        Some("m0;s0,4:edge;r11;")
    );

    let mut summary = TransactionSummary {
        proxy_id: Some("orders".to_string()),
        proxy_name: Some("orders".to_string()),
        response_status_code: 200,
        latency_total_ms: 12.0,
        metadata: projected,
        ..TransactionSummary::default()
    };

    let registry = MetricsRegistry::new();
    registry.record(&summary);
    assert!(
        registry.mesh_request_counter.is_empty(),
        "disable plan from projected summary must suppress request_count"
    );
    assert_eq!(registry.mesh_request_duration_buckets.len(), 1);

    summary.metadata.remove(MESH_METRICS_DISABLED_METADATA);
    summary.metadata.insert(
        MESH_REQUEST_COUNT_OVERRIDES_METADATA.to_string(),
        "m0;s0,4:edge;r11;".to_string(),
    );
    let registry = MetricsRegistry::new();
    registry.record(&summary);
    let output = registry.render_uncached();
    let counter = output
        .lines()
        .find(|line| line.starts_with("ferrum_mesh_requests_total{"))
        .expect("mesh request counter");
    assert!(
        counter.contains("source_workload=\"edge\""),
        "tag override from projected summary must apply: {counter}"
    );
    assert!(!counter.contains("response_flags="), "{counter}");
}

#[test]
fn strip_dedup_internal_metadata_is_shared_fail_closed_filter() {
    let mut metadata = planted_metadata();
    strip_dedup_internal_metadata(&mut metadata);
    for key in LEGACY_DEDUP_FIELDS {
        assert!(!metadata.contains_key(*key));
    }
    assert!(metadata.contains_key("api_key"));
    assert!(metadata.contains_key("ai_total_tokens"));
}

#[test]
fn native_summary_omits_dedup_fields_and_redacts_api_credentials() {
    let summary = summary_with(planted_metadata());
    let parsed = serialize_native(&summary);
    let json = parsed.to_string();
    let md = parsed
        .get("metadata")
        .and_then(Value::as_object)
        .expect("native metadata object");

    assert_no_lifecycle_leak(&json, &parsed);
    assert_api_credentials_redacted(&json, md);
    assert_counters_visible(md);
    assert_eq!(
        md.get("trace_id").and_then(Value::as_str),
        Some("trace-visible")
    );
}

#[test]
fn nested_schema_view_matches_native_redaction_contract() {
    let summary = summary_with(planted_metadata());
    let parsed = serialize_schema(&summary, json!({ "summary_type": "http" }));
    let json = parsed.to_string();
    let md = parsed
        .get("metadata")
        .and_then(Value::as_object)
        .expect("nested metadata");

    assert_no_lifecycle_leak(&json, &parsed);
    assert_api_credentials_redacted(&json, md);
    assert_counters_visible(md);
}

#[test]
fn flattened_schema_view_redacts_and_omits_under_prefix() {
    let summary = summary_with(planted_metadata());
    let parsed = serialize_schema(
        &summary,
        json!({
            "summary_type": "http",
            "metadata": { "mode": "flatten", "prefix": "meta_" }
        }),
    );
    let json = parsed.to_string();

    assert!(parsed.get("metadata").is_none());
    for key in LEGACY_DEDUP_FIELDS {
        assert!(
            parsed.get(format!("meta_{key}")).is_none(),
            "flattened lifecycle key meta_{key} must be omitted"
        );
    }
    for idx in 0..LEGACY_DEDUP_FIELDS.len() {
        assert!(!json.contains(&format!("dedup-lifecycle-sentinel-{idx}")));
    }
    for (idx, key) in API_CREDENTIAL_KEYS.iter().enumerate() {
        assert_eq!(
            parsed.get(format!("meta_{key}")).and_then(Value::as_str),
            Some(REDACTED_PLACEHOLDER),
            "flattened {key} must redact"
        );
        assert!(!json.contains(&format!("api-credential-sentinel-{idx}")));
    }
    for (idx, key) in NON_SECRET_COUNTERS.iter().enumerate() {
        let expected = format!("counter-{idx}");
        assert_eq!(
            parsed.get(format!("meta_{key}")).and_then(Value::as_str),
            Some(expected.as_str())
        );
    }
}

#[test]
fn renamed_metadata_outer_field_still_redacts_inner_keys() {
    let summary = summary_with(planted_metadata());
    let parsed = serialize_schema(
        &summary,
        json!({
            "summary_type": "http",
            "rename": { "metadata": "attrs" }
        }),
    );
    let json = parsed.to_string();
    assert!(parsed.get("metadata").is_none());
    let attrs = parsed
        .get("attrs")
        .and_then(Value::as_object)
        .expect("renamed metadata object");

    for key in LEGACY_DEDUP_FIELDS {
        assert!(attrs.get(*key).is_none(), "{key} leaked under rename");
    }
    assert_api_credentials_redacted(&json, attrs);
    assert_counters_visible(attrs);
}

#[test]
fn static_fields_reject_api_key_spellings_and_dedup_lifecycle_names() {
    for key in API_CREDENTIAL_KEYS
        .iter()
        .chain(LEGACY_DEDUP_FIELDS.iter())
        .copied()
    {
        let err = SummarySchema::compile(
            &json!({
                "summary_type": "http",
                "static_fields": { key: "must-not-ship" }
            }),
            "test",
            SchemaCapabilities::BASE,
        )
        .expect_err("sensitive / internal-only static field must fail closed");
        assert!(
            err.contains("sensitive") || err.contains(key),
            "unexpected compile error for {key}: {err}"
        );
    }

    let ok = SummarySchema::compile(
        &json!({
            "summary_type": "http",
            "static_fields": { "deployment_region": "us-east-1" }
        }),
        "test",
        SchemaCapabilities::BASE,
    );
    assert!(ok.is_ok(), "benign static field rejected: {ok:?}");
}

#[test]
fn operator_extra_keys_redact_on_native_and_shaped_views() {
    let extras = parse_extras_list("operator_canary,tenant_secret");
    assert!(is_sensitive_metadata_key_with_extras(
        "operator_canary",
        &extras
    ));
    assert!(is_sensitive_metadata_key_with_extras(
        "tenant_secret",
        &extras
    ));
    assert!(!is_sensitive_metadata_key_with_extras(
        "ai_total_tokens",
        &extras
    ));
}
