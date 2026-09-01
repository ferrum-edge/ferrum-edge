//! Header, log, and metrics `error_class` vocabularies (issues #4396, #4399,
//! #4397).
//!
//! `X-Gateway-Error` stays on the coarse seven-token set. HTTP metrics and
//! access logs use granular [`ErrorClass::as_str`] when a class exists.

use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::_test_support::x_gateway_error_for_backend_failure_for_test;
use ferrum_edge::plugins::TransactionSummary;
use ferrum_edge::plugins::prometheus_metrics::{CounterKey, MetricsRegistry};
use ferrum_edge::retry::{
    ErrorClass, HTTP_METRICS_ERROR_CLASS_BOUND, HTTP_METRICS_GATEWAY_ERROR_CLASSES,
    HTTP_OBSERVABILITY_ERROR_CLASSES, OBS_BACKEND_ERROR, OBS_BACKEND_TIMEOUT,
    OBS_CIRCUIT_BREAKER_OPEN, OBS_CONCURRENCY_LIMIT, OBS_CONFIG_STALE, OBS_CONNECTION_FAILURE,
    OBS_OVERLOAD, http_log_error_class, http_metrics_error_class, intern_http_metrics_error_class,
    intern_http_observability_error_class, x_gateway_error_token_for_class,
};

fn http_summary(status: u16, class: Option<ErrorClass>, phase: Option<&str>) -> TransactionSummary {
    let mut metadata = HashMap::new();
    if let Some(phase) = phase {
        metadata.insert("rejection_phase".to_string(), phase.to_string());
    }
    TransactionSummary {
        plugin_trigger_decisions: Default::default(),
        namespace: "ferrum".to_string(),
        timestamp_received: "2026-08-31T00:00:00Z".to_string(),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: "/test".to_string(),
        proxy_id: Some("obs-corr".to_string()),
        proxy_name: Some("obs".to_string()),
        backend_target: Some("http://127.0.0.1:9".to_string()),
        backend_resolved_ip: None,
        response_status_code: status,
        latency_total_ms: 1.0,
        latency_gateway_processing_ms: 1.0,
        latency_backend_ttfb_ms: 0.0,
        latency_backend_total_ms: 0.0,
        latency_plugin_execution_ms: 0.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 1.0,
        request_user_agent: None,
        response_streamed: false,
        client_disconnected: false,
        error_class: class,
        body_error_class: None,
        body_completed: false,
        bytes_sent: 0,
        bytes_received: 0,
        grpc_request_messages: 0,
        grpc_response_messages: 0,
        mirror: false,
        metadata,
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

fn counter_key(status: u16, error_class: Option<&'static str>) -> CounterKey {
    CounterKey {
        proxy_id: Arc::from("obs-corr"),
        method: "GET",
        status_code: status,
        grpc_status: None,
        error_class,
    }
}

#[test]
fn header_stays_coarse_while_metrics_and_logs_stay_granular() {
    let registry = MetricsRegistry::new();

    let refused = http_summary(502, Some(ErrorClass::ConnectionRefused), None);
    assert_eq!(
        x_gateway_error_for_backend_failure_for_test(true, 502),
        Some(OBS_CONNECTION_FAILURE)
    );
    assert_eq!(
        x_gateway_error_token_for_class(ErrorClass::ConnectionRefused),
        OBS_CONNECTION_FAILURE
    );
    assert_eq!(
        http_metrics_error_class(Some(ErrorClass::ConnectionRefused), 502, None),
        Some("connection_refused")
    );
    assert_eq!(
        http_log_error_class(Some(ErrorClass::ConnectionRefused)),
        Some("connection_refused")
    );
    assert_eq!(refused.serialized_error_class(), Some("connection_refused"));
    assert_eq!(
        refused.metrics_error_class_label(),
        Some("connection_refused")
    );
    registry.record(&refused);

    let dns = http_summary(502, Some(ErrorClass::DnsLookupError), None);
    assert_eq!(
        x_gateway_error_token_for_class(ErrorClass::DnsLookupError),
        OBS_CONNECTION_FAILURE
    );
    assert_eq!(
        http_metrics_error_class(Some(ErrorClass::DnsLookupError), 502, None),
        Some("dns_lookup_error")
    );
    assert_eq!(
        http_log_error_class(Some(ErrorClass::DnsLookupError)),
        Some("dns_lookup_error")
    );
    assert_eq!(dns.serialized_error_class(), Some("dns_lookup_error"));
    assert_eq!(dns.metrics_error_class_label(), Some("dns_lookup_error"));
    registry.record(&dns);

    assert!(
        registry
            .request_counter
            .contains_key(&counter_key(502, Some("connection_refused")))
    );
    assert!(
        registry
            .request_counter
            .contains_key(&counter_key(502, Some("dns_lookup_error")))
    );
    assert!(
        !registry
            .request_counter
            .contains_key(&counter_key(502, Some(OBS_CONNECTION_FAILURE))),
        "HTTP metrics must not collapse DNS and refused onto connection_failure"
    );

    let timeout = http_summary(504, Some(ErrorClass::ReadWriteTimeout), None);
    assert_eq!(
        x_gateway_error_for_backend_failure_for_test(false, 504),
        Some(OBS_BACKEND_TIMEOUT)
    );
    assert_eq!(
        timeout.metrics_error_class_label(),
        Some("read_write_timeout")
    );
    assert_eq!(timeout.serialized_error_class(), Some("read_write_timeout"));
    registry.record(&timeout);

    let backend = http_summary(503, None, None);
    assert_eq!(
        x_gateway_error_for_backend_failure_for_test(false, 503),
        Some(OBS_BACKEND_ERROR)
    );
    // A backend 5xx the gateway never classified still carries the metrics
    // label its header advertises, so PromQL can select the series; the
    // access log stays granular and simply has nothing to report here.
    assert_eq!(backend.metrics_error_class_label(), Some(OBS_BACKEND_ERROR));
    assert_eq!(backend.serialized_error_class(), None);
    registry.record(&backend);
    assert!(
        registry
            .request_counter
            .contains_key(&counter_key(503, Some(OBS_BACKEND_ERROR)))
    );

    for (token, phase) in [
        (OBS_CIRCUIT_BREAKER_OPEN, "circuit_breaker_open"),
        (OBS_OVERLOAD, "overload"),
        (OBS_CONFIG_STALE, "config_stale"),
        (OBS_CONCURRENCY_LIMIT, "adaptive_concurrency"),
    ] {
        let summary = http_summary(503, None, Some(phase));
        assert_eq!(summary.metrics_error_class_label(), Some(token));
        assert_eq!(
            summary.serialized_error_class(),
            None,
            "gateway-authored 503s with no ErrorClass omit log error_class"
        );
        registry.record(&summary);
        assert!(
            registry
                .request_counter
                .contains_key(&counter_key(503, Some(token)))
        );
    }

    let ok = http_summary(200, None, None);
    registry.record(&ok);
    assert!(
        registry
            .request_counter
            .contains_key(&counter_key(200, None))
    );
    let output = registry.render_uncached();
    assert!(
        !output.contains(r#"status_code="200",error_class="#),
        "2xx must omit error_class: {output}"
    );
    assert!(output.contains(
        r#"ferrum_requests_total{proxy_id="obs-corr",method="GET",status_code="502",error_class="dns_lookup_error"} 1"#
    ));
    assert!(output.contains(
        r#"ferrum_requests_total{proxy_id="obs-corr",method="GET",status_code="502",error_class="connection_refused"} 1"#
    ));
}

#[test]
fn http_metrics_cardinality_is_error_class_all_plus_five_gateway_tokens() {
    assert_eq!(HTTP_OBSERVABILITY_ERROR_CLASSES.len(), 7);
    assert_eq!(HTTP_METRICS_GATEWAY_ERROR_CLASSES.len(), 5);
    assert_eq!(ErrorClass::ALL.len(), 19);
    assert_eq!(
        ErrorClass::ALL.len() + HTTP_METRICS_GATEWAY_ERROR_CLASSES.len(),
        HTTP_METRICS_ERROR_CLASS_BOUND
    );
    assert_eq!(HTTP_METRICS_ERROR_CLASS_BOUND, 24);

    let mut header_seen = std::collections::HashSet::new();
    for token in HTTP_OBSERVABILITY_ERROR_CLASSES {
        assert!(header_seen.insert(*token), "duplicate header token {token}");
        assert_eq!(intern_http_observability_error_class(token), Some(*token));
    }
    assert!(intern_http_observability_error_class("backend_down").is_none());
    assert!(intern_http_observability_error_class("Service overloaded").is_none());

    let mut metrics_seen = std::collections::HashSet::new();
    for class in ErrorClass::ALL {
        let token = class.as_str();
        assert!(metrics_seen.insert(token), "duplicate ErrorClass {}", token);
        assert_eq!(intern_http_metrics_error_class(token), Some(token));
        assert!(
            !HTTP_METRICS_GATEWAY_ERROR_CLASSES.contains(&token),
            "gateway tokens must not overlap ErrorClass: {token}"
        );
    }
    for token in HTTP_METRICS_GATEWAY_ERROR_CLASSES {
        assert!(
            metrics_seen.insert(*token),
            "duplicate metrics token {token}"
        );
        assert_eq!(intern_http_metrics_error_class(token), Some(*token));
    }
    assert_eq!(metrics_seen.len(), HTTP_METRICS_ERROR_CLASS_BOUND);
    assert!(intern_http_metrics_error_class("connection_failure").is_none());
    assert!(intern_http_metrics_error_class("backend_timeout").is_none());
    // `backend_error` IS a metrics token now: it is the label an unclassified
    // backend 5xx carries so the series matches its `X-Gateway-Error` header.
    assert!(intern_http_metrics_error_class("backend_error").is_some());
    assert!(intern_http_metrics_error_class("dns_lookup_error").is_some());
}

#[test]
fn gateway_authored_5xx_sites_set_the_new_tokens() {
    let proxy = include_str!("../../src/proxy/mod.rs");
    assert!(proxy.contains("X_GATEWAY_ERROR_OVERLOAD"));
    assert!(proxy.contains("X_GATEWAY_ERROR_CONFIG_STALE"));
    assert!(proxy.contains("build_response_with_gateway_error("));

    let h3 = include_str!("../../src/http3/server.rs");
    assert!(h3.contains("overload_reject_headers()"));
    assert!(h3.contains("config_stale_reject_headers()"));

    let ac = include_str!("../../src/plugins/adaptive_concurrency.rs");
    assert!(ac.contains("OBS_CONCURRENCY_LIMIT"));
    assert!(ac.contains("\"x-gateway-error\""));
}
