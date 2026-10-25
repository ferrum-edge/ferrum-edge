//! Source-contract coverage for route-miss (`404`) transaction logging.
//!
//! A request that matches no proxy runs no plugin hook, but a global
//! `stdout_logging` instance must still record it, on H1/H2 and H3 alike
//! (shared-invariant parity). Without such a logger the route miss must stay a
//! single pointer check, so the delivery is gated on the cache's precomputed
//! list and headers are materialized only inside that gate.

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
}

#[test]
fn unrouted_summary_is_proxyless_and_names_the_routing_phase() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let start = source
        .find("pub(crate) async fn log_unrouted_request(")
        .expect("unrouted log helper");
    let body = &source[start..];
    let body = &body[..body.find("\n}\n").expect("helper end")];
    assert!(body.contains("crate::diagnostic_ref::ROUTE_NOT_FOUND_PHASE.to_string()"));
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
