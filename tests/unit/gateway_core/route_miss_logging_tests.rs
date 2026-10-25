//! Source-contract coverage for route-miss (`404`) transaction logging.
//!
//! A request that matches no proxy runs no plugin hook, but a global
//! `stdout_logging` instance must still record it, on H1/H2 and H3 alike
//! (shared-invariant parity). Without such a logger the route miss must stay a
//! single pointer check, so the delivery is gated on the cache's precomputed
//! list and headers are materialized only inside that gate.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ferrum_edge::plugins::{Plugin, RequestContext, TransactionSummary};

const UNROUTED_GATE: &str = "epoch.plugin_cache.unrouted_transaction_log_plugins()";

/// The body of the route-miss arm from `start` to the `return Ok(...)` that
/// ends it.
fn route_miss_arm<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let begin = source.find(start).expect("route-miss arm start marker");
    let rest = &source[begin..];
    let len = rest.find(end).expect("route-miss arm end marker");
    &rest[..len + end.len()]
}

fn assert_gated_unrouted_delivery(arm: &str, surface: &str, after_head: &str) {
    let head = arm
        .find(after_head)
        .unwrap_or_else(|| panic!("{surface}: route-miss head marker missing"));
    let gate = arm
        .find(UNROUTED_GATE)
        .unwrap_or_else(|| panic!("{surface}: route miss must consult the unrouted log list"));
    let materialize = arm
        .find("ctx.materialize_headers();")
        .unwrap_or_else(|| panic!("{surface}: headers must be materialized for the log"));
    let log = arm
        .find("log_unrouted_request(")
        .unwrap_or_else(|| panic!("{surface}: route miss must deliver the unrouted summary"));
    assert!(
        head < gate,
        "{surface}: log after the routing diagnostic/head"
    );
    assert!(
        gate < materialize && materialize < log,
        "{surface}: header materialization must stay inside the logger gate"
    );
    assert!(
        arm[log..].contains("StatusCode::NOT_FOUND.as_u16()"),
        "{surface}: the summary records the routing status"
    );
    assert!(
        arm[log..].contains("&state.env_config.namespace,"),
        "{surface}: a route miss is attributed to the serving namespace"
    );
    // The logging future is boxed so its state never inflates the dispatcher's
    // request state machine (a debug-build H3 handler overflowed the worker
    // stack when it was inlined).
    assert!(
        arm[gate..log].contains("Box::pin("),
        "{surface}: the unrouted log future must be boxed"
    );
}

#[test]
fn h1_h2_route_miss_delivers_to_global_access_logs_only_when_configured() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let arm = route_miss_arm(
        source,
        "\"No route matched for request path\"",
        "return Ok(response);",
    );
    assert_gated_unrouted_delivery(
        arm,
        "H1/H2",
        "crate::diagnostic_ref::ROUTE_NOT_FOUND_PHASE,",
    );
}

#[test]
fn h3_route_miss_delivers_to_global_access_logs_only_when_configured() {
    let source = include_str!("../../../src/http3/server.rs");
    let arm = route_miss_arm(
        source,
        "crate::diagnostic_ref::ROUTE_NOT_FOUND_PHASE,",
        "return Ok(());",
    );
    assert_gated_unrouted_delivery(arm, "H3", "r#\"{\"error\":\"Not Found\"}\"#,");
    // The write result propagates only after delivery, so a peer that resets
    // or closes during the 404 still leaves its access record.
    let log = arm
        .find("log_unrouted_request(")
        .expect("H3 unrouted delivery");
    let propagate = arm.find("sent?;").expect("H3 send result propagation");
    assert!(
        log < propagate,
        "H3 must log before propagating the write result"
    );
    let send = arm
        .find("let sent = send_h3_error_flavor_aware(")
        .expect("H3 keeps the send result");
    assert!(
        !arm[send..log].contains(".await?"),
        "the 404 write must not return before the access record is delivered"
    );
}

#[test]
fn unrouted_summary_is_proxyless_and_names_the_routing_phase() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let start = source
        .find("pub async fn log_unrouted_request(")
        .expect("unrouted log helper");
    let body = &source[start..];
    let body = &body[..body.find("\n}\n").expect("helper end")];
    assert!(body.contains("crate::diagnostic_ref::ROUTE_NOT_FOUND_PHASE.to_string()"));
    assert!(
        !body.contains("default_namespace()"),
        "the resource-deserialization default is not the serving namespace"
    );
    assert!(body.contains("..TransactionSummary::default()"));
    for absent in ["proxy_id:", "backend_target:", "consumer_username:"] {
        assert!(
            !body.contains(absent),
            "a route miss has no `{absent}` to report"
        );
    }
    // The routing diagnostic was recorded by `record_route_miss`; the helper
    // must not record a second rejection through the rejection-log funnel.
    assert!(!body.contains("record_rejection("));
    assert!(body.contains("log_with_mirror_before_buffered_response(plugins, summary, ctx)"));
}

struct CapturingLogger {
    captured: Arc<Mutex<Vec<TransactionSummary>>>,
}

#[async_trait]
impl Plugin for CapturingLogger {
    fn name(&self) -> &str {
        "route-miss-capture"
    }

    fn priority(&self) -> u16 {
        9000
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.captured
            .lock()
            .expect("captured summaries")
            .push(summary.clone());
    }
}

/// The emitted record, not just the call site: one proxy-less summary in the
/// serving namespace (here non-default), carrying the routing phase.
#[tokio::test]
async fn unrouted_summary_is_attributed_to_the_serving_namespace() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(CapturingLogger {
        captured: Arc::clone(&captured),
    })];
    let ctx = RequestContext::new(
        "203.0.113.7".to_string(),
        "GET".to_string(),
        "/missing".to_string(),
    );

    ferrum_edge::proxy::log_unrouted_request(
        &plugins,
        &ctx,
        "payments",
        404,
        std::time::Instant::now(),
    )
    .await;

    let captured = captured.lock().expect("captured summaries");
    assert_eq!(captured.len(), 1, "exactly one access record");
    let summary = &captured[0];
    assert_eq!(summary.namespace, "payments");
    assert_ne!(
        summary.namespace,
        ferrum_edge::config::types::default_namespace()
    );
    assert_eq!(summary.response_status_code, 404);
    assert_eq!(summary.request_path, "/missing");
    assert_eq!(summary.client_ip, "203.0.113.7");
    assert!(summary.proxy_id.is_none());
    assert!(summary.backend_target.is_none());
    assert!(summary.consumer_username.is_none());
    assert_eq!(
        summary.metadata.get("rejection_phase").map(String::as_str),
        Some("route_not_found")
    );
}
