//! Unit coverage for NodeWaypoint ADR observability counters (issue #3334).

use async_trait::async_trait;
use ferrum_edge::_test_support;
use ferrum_edge::config::env_config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::modes::mesh::node_waypoint_observability::{
    self, NodeWaypointAssertedIdentityRejectReason, NodeWaypointDestinationPolicyRejectReason,
    NodeWaypointHboneHandshakePhase,
};
use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;
use ferrum_edge::plugins::{Plugin, RequestContext, TransactionSummary};
use ferrum_edge::proxy::ProxyState;
use http_body_util::BodyExt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

static OBSERVABILITY_TEST_LOCK: Mutex<()> = Mutex::new(());

fn observability_test_guard() -> MutexGuard<'static, ()> {
    OBSERVABILITY_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn reason_enums_expose_stable_label_strings() {
    assert_eq!(
        NodeWaypointHboneHandshakePhase::InboundTls.as_str(),
        "inbound_tls"
    );
    assert_eq!(
        NodeWaypointHboneHandshakePhase::InboundConnect.as_str(),
        "inbound_connect"
    );
    assert_eq!(
        NodeWaypointHboneHandshakePhase::OutboundDial.as_str(),
        "outbound_dial"
    );
    assert_eq!(
        NodeWaypointAssertedIdentityRejectReason::UntrustedAssertor.as_str(),
        "untrusted_assertor"
    );
    assert_eq!(
        NodeWaypointAssertedIdentityRejectReason::AssertionOutOfScope.as_str(),
        "assertion_out_of_scope"
    );
    assert_eq!(
        NodeWaypointDestinationPolicyRejectReason::AuthzDeny.as_str(),
        "authz_deny"
    );
}

#[test]
fn disabled_producers_do_not_increment() {
    let _guard = observability_test_guard();
    node_waypoint_observability::set_enabled(false);
    let before = node_waypoint_observability::snapshot();

    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundTls,
        false,
    );
    node_waypoint_observability::record_asserted_identity_accepted();
    node_waypoint_observability::record_missing_destination_metadata();
    node_waypoint_observability::record_plaintext_fallback_attempt();

    let after = node_waypoint_observability::snapshot();
    assert_eq!(after.hbone_handshakes, before.hbone_handshakes);
    assert_eq!(after.asserted_identity, before.asserted_identity);
    assert_eq!(
        after.missing_destination_metadata,
        before.missing_destination_metadata
    );
    assert_eq!(
        after.plaintext_fallback_attempts,
        before.plaintext_fallback_attempts
    );
    assert!(!after.enabled);
}

#[test]
fn enabled_producers_increment_and_render_bounded_labels() {
    let _guard = observability_test_guard();
    node_waypoint_observability::set_enabled(true);
    let before = node_waypoint_observability::snapshot();

    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundTls,
        true,
    );
    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundTls,
        false,
    );
    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundConnect,
        true,
    );
    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::OutboundDial,
        false,
    );
    node_waypoint_observability::record_asserted_identity_accepted();
    node_waypoint_observability::record_asserted_identity_rejected(
        NodeWaypointAssertedIdentityRejectReason::UntrustedAssertor,
    );
    node_waypoint_observability::record_destination_policy_rejection(
        NodeWaypointDestinationPolicyRejectReason::AuthzDeny,
    );
    node_waypoint_observability::record_missing_destination_metadata();
    node_waypoint_observability::record_plaintext_fallback_attempt();

    let after = node_waypoint_observability::snapshot();
    assert!(after.enabled);
    assert_eq!(
        after.hbone_handshakes.inbound_tls_success,
        before.hbone_handshakes.inbound_tls_success + 1
    );
    assert_eq!(
        after.hbone_handshakes.inbound_tls_failure,
        before.hbone_handshakes.inbound_tls_failure + 1
    );
    assert_eq!(
        after.hbone_handshakes.inbound_connect_success,
        before.hbone_handshakes.inbound_connect_success + 1
    );
    assert_eq!(
        after.hbone_handshakes.outbound_dial_failure,
        before.hbone_handshakes.outbound_dial_failure + 1
    );
    // `mesh_authz` is the production producer for the asserted-identity and
    // destination-policy counters, and `tests/unit/plugins/mesh_plugins_tests.rs`
    // drives `MeshAuthz` with `per_pod_policy_scoping: true` in THIS SAME test
    // binary. `OBSERVABILITY_TEST_LOCK` only serialises the observability tests
    // against each other, so a mesh_authz deny/honored-baggage case running on
    // another libtest thread while the producers are enabled adds its own
    // increments. Assert a lower bound for those three; the handshake, metadata,
    // and plaintext-fallback counters have no other producer in this binary and
    // stay exact.
    assert!(
        after.asserted_identity.accepted > before.asserted_identity.accepted,
        "asserted identity accept must move (was {}, now {})",
        before.asserted_identity.accepted,
        after.asserted_identity.accepted
    );
    assert!(
        after.asserted_identity.rejected_untrusted_assertor
            > before.asserted_identity.rejected_untrusted_assertor,
        "untrusted-assertor reject must move (was {}, now {})",
        before.asserted_identity.rejected_untrusted_assertor,
        after.asserted_identity.rejected_untrusted_assertor
    );
    assert!(
        after.destination_policy_rejections.authz_deny
            > before.destination_policy_rejections.authz_deny,
        "authz_deny must move (was {}, now {})",
        before.destination_policy_rejections.authz_deny,
        after.destination_policy_rejections.authz_deny
    );
    assert_eq!(
        after.missing_destination_metadata,
        before.missing_destination_metadata + 1
    );
    assert_eq!(
        after.plaintext_fallback_attempts,
        before.plaintext_fallback_attempts + 1
    );

    let registry = MetricsRegistry::new();
    let output = registry.render();
    assert!(output.contains("# TYPE ferrum_mesh_node_waypoint_hbone_handshakes_total counter"));
    assert!(output.contains(
        "ferrum_mesh_node_waypoint_hbone_handshakes_total{phase=\"inbound_tls\",result=\"failure\"}"
    ));
    assert!(output.contains("# TYPE ferrum_mesh_node_waypoint_asserted_identity_total counter"));
    assert!(output.contains(
        "ferrum_mesh_node_waypoint_asserted_identity_total{result=\"rejected\",reason=\"untrusted_assertor\"}"
    ));
    // Issue #4274: the out-of-scope refusal is a distinct, bounded reason so an
    // operator can tell "peer is not an assertor" from "assertor may not assert
    // THAT identity". It must keep a stable zero baseline in the exposition.
    assert!(output.contains(
        "ferrum_mesh_node_waypoint_asserted_identity_total{result=\"rejected\",reason=\"assertion_out_of_scope\"}"
    ));
    assert!(
        output.contains(
            "# TYPE ferrum_mesh_node_waypoint_destination_policy_rejections_total counter"
        )
    );
    assert!(
        output.contains(
            "# TYPE ferrum_mesh_node_waypoint_missing_destination_metadata_total counter"
        )
    );
    assert!(
        output
            .contains("# TYPE ferrum_mesh_node_waypoint_plaintext_fallback_attempts_total counter")
    );
    // Cardinality contract: no identity/IP/URL label keys.
    for forbidden in [
        "spiffe_id=",
        "pod=",
        "workload=",
        "service=",
        "node=",
        "url=",
        "remote=",
    ] {
        assert!(
            !output
                .lines()
                .filter(|line| line.contains("ferrum_mesh_node_waypoint_"))
                .any(|line| line.contains(forbidden)),
            "forbidden label key {forbidden} in NodeWaypoint ADR metrics"
        );
    }

    // Disable again before releasing the lock so unrelated suites in this
    // binary (notably the `MeshAuthz` per-pod tests) do not keep moving the
    // process-static counters while no observability test is running.
    node_waypoint_observability::set_enabled(false);
}

/// `/metrics` must observe NodeWaypoint ADR counter movement even when the
/// MetricsRegistry render cache would otherwise serve a body generated before
/// the increment (default TTL is 5s; the live harness scrapes before/after
/// within that window).
#[test]
fn node_waypoint_inbound_tls_failure_bypasses_metrics_render_cache() {
    let _guard = observability_test_guard();
    node_waypoint_observability::set_enabled(true);
    let registry = MetricsRegistry::new();
    // Keep the registry body cached across the producer increment. A non-empty
    // namespace also exercises gateway_namespace label append on the live series.
    registry.configure(5, 3600, 60_000, 10_000, "ferrum");

    // Live harness passes closed selectors; optional gateway_namespace may be
    // appended before the closing `}` when the Prometheus plugin is configured.
    const INBOUND_TLS_FAILURE: &str = "ferrum_mesh_node_waypoint_hbone_handshakes_total{phase=\"inbound_tls\",result=\"failure\"}";

    let before_output = registry.render();
    let before_failure = prometheus_counter_value(&before_output, INBOUND_TLS_FAILURE);
    let before_snap = node_waypoint_observability::snapshot()
        .hbone_handshakes
        .inbound_tls_failure;
    assert_eq!(
        before_failure, before_snap,
        "pre-increment /metrics must match the live process-static snapshot"
    );

    node_waypoint_observability::set_enabled(true);
    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundTls,
        false,
    );

    let after_snap = node_waypoint_observability::snapshot()
        .hbone_handshakes
        .inbound_tls_failure;
    assert!(
        after_snap > before_snap,
        "producer must increment inbound_tls failure (was {before_snap}, now {after_snap})"
    );

    let after_output = registry.render();
    let after_failure = prometheus_counter_value(&after_output, INBOUND_TLS_FAILURE);
    assert_eq!(
        after_failure, after_snap,
        "cached /metrics render must still reflect a fresh inbound_tls failure \
         (snapshot {after_snap}, rendered {after_failure})"
    );
    assert!(
        after_failure > before_failure,
        "cached /metrics render must still reflect a fresh inbound_tls failure \
         (was {before_failure}, now {after_failure})"
    );

    node_waypoint_observability::set_enabled(false);
}

/// Parse a Prometheus counter for an exact closed selector (`metric{…}`).
/// Matches the no-extra-label form and the same required labels with optional
/// `gateway_namespace` appended before `}` — the same contract as
/// `sum_ambient_metric_total` in the NodeWaypoint live harness.
fn prometheus_counter_value(output: &str, selector: &str) -> u64 {
    let Some(required_prefix) = selector.strip_suffix('}') else {
        return 0;
    };
    let mut total = 0u64;
    for line in output.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let Some(rest) = line.strip_prefix(required_prefix) else {
            continue;
        };
        let Some(sample) = match_optional_gateway_namespace_sample(rest) else {
            continue;
        };
        if let Ok(parsed) = sample.parse::<u64>() {
            total = total.saturating_add(parsed);
        }
    }
    total
}

/// After the required-label prefix, accept `} <n>` or
/// `,gateway_namespace="…"} <n>`. Reject other extra labels and malformed tails.
fn match_optional_gateway_namespace_sample(rest: &str) -> Option<&str> {
    let after_labels = if let Some(after) = rest.strip_prefix('}') {
        after
    } else {
        let after_key = rest.strip_prefix(",gateway_namespace=\"")?;
        let (_value, after_value) = after_key.split_once('"')?;
        after_value.strip_prefix('}')?
    };
    // Prometheus exposition requires whitespace between `}` and the sample.
    if after_labels.is_empty() || !after_labels.chars().next()?.is_whitespace() {
        return None;
    }
    let sample = after_labels.trim_start();
    if sample.is_empty() || sample.chars().any(char::is_whitespace) {
        return None;
    }
    Some(sample)
}

#[test]
fn closed_metric_selector_matches_both_gateway_namespace_shapes() {
    const SELECTOR: &str =
        r#"ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="inbound_tls",result="failure"}"#;

    let without_ns = concat!(
        "# HELP ferrum_mesh_node_waypoint_hbone_handshakes_total HBONE handshake outcomes\n",
        r#"ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="inbound_tls",result="failure"} 3"#,
        "\n",
        r#"ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="inbound_tls",result="success"} 9"#,
        "\n",
    );
    assert_eq!(prometheus_counter_value(without_ns, SELECTOR), 3);

    let with_ns = concat!(
        r#"ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="inbound_tls",result="failure",gateway_namespace="ferrum"} 4"#,
        "\n",
        r#"ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="inbound_tls",result="failure",gateway_namespace="other"} 1"#,
        "\n",
        // Wrong metric name / wrong required label must not contribute.
        r#"ferrum_mesh_node_waypoint_hbone_handshakes_total_extra{phase="inbound_tls",result="failure"} 100"#,
        "\n",
        r#"ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="inbound_tls",result="failure_extra"} 100"#,
        "\n",
        r#"ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="inbound_tls",result="failure",other="x"} 100"#,
        "\n",
        // Malformed sample (no value / non-numeric) fail closed.
        r#"ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="inbound_tls",result="failure"}"#,
        "\n",
        r#"ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="inbound_tls",result="failure"} not_a_number"#,
        "\n",
    );
    assert_eq!(prometheus_counter_value(with_ns, SELECTOR), 5);
}

#[test]
fn handshake_phase_ownership_is_independent() {
    let _guard = observability_test_guard();
    node_waypoint_observability::set_enabled(true);
    let before = node_waypoint_observability::snapshot();

    // One TLS failure must not also bump inbound_connect.
    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundTls,
        false,
    );
    let after_tls = node_waypoint_observability::snapshot();
    assert_eq!(
        after_tls.hbone_handshakes.inbound_tls_failure,
        before.hbone_handshakes.inbound_tls_failure + 1
    );
    assert_eq!(
        after_tls.hbone_handshakes.inbound_connect_failure,
        before.hbone_handshakes.inbound_connect_failure
    );

    // One CONNECT failure must not also bump inbound_tls.
    node_waypoint_observability::record_hbone_handshake(
        NodeWaypointHboneHandshakePhase::InboundConnect,
        false,
    );
    let after_connect = node_waypoint_observability::snapshot();
    assert_eq!(
        after_connect.hbone_handshakes.inbound_connect_failure,
        before.hbone_handshakes.inbound_connect_failure + 1
    );
    assert_eq!(
        after_connect.hbone_handshakes.inbound_tls_failure,
        after_tls.hbone_handshakes.inbound_tls_failure
    );

    node_waypoint_observability::set_enabled(false);
}

/// Captures every transaction line a refusal hands to the logging chain.
struct CapturingLogPlugin {
    captured: Arc<Mutex<Vec<TransactionSummary>>>,
}

#[async_trait]
impl Plugin for CapturingLogPlugin {
    fn name(&self) -> &str {
        "capturing_log"
    }

    fn priority(&self) -> u16 {
        9000
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(summary.clone());
    }
}

/// Whether the refused CONNECT arrived from an mTLS-authenticated peer.
#[derive(Clone, Copy)]
enum Peer {
    Authenticated,
    Peerless,
}

struct SynthesisRefusal {
    status: u16,
    body: String,
    summary: TransactionSummary,
}

async fn refuse_at_synthesis(
    state: &ProxyState,
    peer: Peer,
    reason: &'static str,
    destination: (&str, u16),
    is_udp_connect: bool,
) -> SynthesisRefusal {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let plugin = CapturingLogPlugin {
        captured: Arc::clone(&captured),
    };
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin)];
    let mut ctx = RequestContext::new(
        "10.0.0.2".to_string(),
        "CONNECT".to_string(),
        "/".to_string(),
    );
    ctx.mesh_inbound_terminator_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
    if matches!(peer, Peer::Authenticated) {
        // Synthesis runs before `spiffe_identity`, so a presented client
        // certificate is what marks the peer as not peerless there.
        ctx.tls_client_cert_der = Some(Arc::new(vec![0x30, 0x00]));
    }
    let response = _test_support::reject_inbound_connect_relay_synthesis_for_test(
        state,
        &plugins,
        &mut ctx,
        reason,
        Some(destination),
        is_udp_connect,
    )
    .await;
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("refusal body")
        .to_bytes();
    let mut lines = captured
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .split_off(0);
    assert_eq!(
        lines.len(),
        1,
        "a refusal writes exactly one transaction line"
    );
    SynthesisRefusal {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
        summary: lines.remove(0),
    }
}

fn metadata<'a>(summary: &'a TransactionSummary, key: &str) -> Option<&'a str> {
    summary.metadata.get(key).map(String::as_str)
}

/// Issue #5763: a relay-synthesis refusal answers one of three terminals and
/// writes one transaction line each. Only a real destination denial carries the
/// documented 403 body and counts as `relay_destination_denied`; `no_mesh_slice`
/// is a 503 readiness answer, and a peerless CONNECT gets the handlers'
/// unauthenticated-peer 403 with no `mesh.relay.*` audit metadata.
#[test]
fn inbound_connect_relay_synthesis_refusals_log_and_count_by_terminal() {
    let _guard = observability_test_guard();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    node_waypoint_observability::set_enabled(true);
    let before = node_waypoint_observability::snapshot();
    let (denied, udp_denied, not_ready, peerless, state) = runtime.block_on(async {
        let dns_cache = DnsCache::new(DnsConfig::default());
        let (state, _) = ProxyState::new(
            GatewayConfig::default(),
            dns_cache,
            EnvConfig::default(),
            None,
            None,
        )
        .expect("proxy state");
        let denied = refuse_at_synthesis(
            &state,
            Peer::Authenticated,
            "address_not_terminated_here",
            ("::1", 8080),
            false,
        )
        .await;
        let udp_denied = refuse_at_synthesis(
            &state,
            Peer::Authenticated,
            "port_not_declared",
            ("10.0.0.9", 5353),
            true,
        )
        .await;
        let not_ready = refuse_at_synthesis(
            &state,
            Peer::Authenticated,
            "no_mesh_slice",
            ("10.0.0.9", 5353),
            true,
        )
        .await;
        let peerless = refuse_at_synthesis(
            &state,
            Peer::Peerless,
            "address_not_terminated_here",
            ("10.0.0.9", 8080),
            false,
        )
        .await;
        (denied, udp_denied, not_ready, peerless, state)
    });
    let after = node_waypoint_observability::snapshot();
    node_waypoint_observability::set_enabled(false);

    // A real destination denial: the documented 403, its body, and the
    // `mesh.relay.*` audit trail on a transaction line with no `proxy_id`.
    assert_eq!(denied.status, 403);
    assert!(
        denied.body.contains("HBONE relay destination not allowed"),
        "body={}",
        denied.body
    );
    assert_eq!(denied.summary.response_status_code, 403);
    assert_eq!(denied.summary.proxy_id, None);
    assert_eq!(
        metadata(&denied.summary, "rejection_phase"),
        Some("hbone_relay_destination_denied")
    );
    assert_eq!(
        metadata(&denied.summary, "mesh_authz.deny_policy"),
        Some("hbone_relay_destination_denied")
    );
    assert_eq!(
        metadata(&denied.summary, "mesh.relay.denial_reason"),
        Some("address_not_terminated_here")
    );
    assert_eq!(
        metadata(&denied.summary, "mesh.relay.denied_destination"),
        Some("[::1]:8080"),
        "an IPv6 destination is bracketed so its port stays unambiguous"
    );
    assert_eq!(
        metadata(&denied.summary, "mesh.relay.terminator_ip"),
        Some("10.0.0.5")
    );

    // The datagram flavor of the same denial.
    assert_eq!(udp_denied.status, 403);
    assert!(
        udp_denied
            .body
            .contains("HBONE UDP relay destination not allowed"),
        "body={}",
        udp_denied.body
    );
    assert_eq!(
        metadata(&udp_denied.summary, "rejection_phase"),
        Some("hbone_udp_relay_destination_denied")
    );
    assert_eq!(
        metadata(&udp_denied.summary, "mesh.relay.denied_destination"),
        Some("10.0.0.9:5353")
    );

    // No slice yet: a readiness answer, still audited, never a 403.
    assert_eq!(not_ready.status, 503);
    assert!(
        not_ready.body.contains("HBONE UDP relay not ready"),
        "body={}",
        not_ready.body
    );
    assert_eq!(not_ready.summary.response_status_code, 503);
    assert_eq!(
        metadata(&not_ready.summary, "rejection_phase"),
        Some("hbone_udp_relay_not_ready")
    );
    assert_eq!(
        metadata(&not_ready.summary, "mesh.relay.denial_reason"),
        Some("no_mesh_slice")
    );

    // A peerless CONNECT learns nothing about the destination.
    assert_eq!(peerless.status, 403);
    assert!(
        peerless
            .body
            .contains("HBONE tunnel requires an authenticated mesh peer"),
        "body={}",
        peerless.body
    );
    assert_eq!(
        metadata(&peerless.summary, "rejection_phase"),
        Some("hbone_unauthenticated_peer")
    );
    assert_eq!(
        metadata(&peerless.summary, "mesh_authz.deny_policy"),
        Some("hbone_unauthenticated_peer")
    );
    assert!(
        peerless
            .summary
            .metadata
            .keys()
            .all(|key| !key.starts_with("mesh.relay.")),
        "a peerless refusal must carry no relay audit metadata: {:?}",
        peerless.summary.metadata
    );

    // Only the two real destination denials count.
    assert_eq!(
        after.destination_policy_rejections.relay_destination_denied,
        before.destination_policy_rejections.relay_destination_denied + 2
    );
    // Every refusal is accounted as a request with its status.
    assert_eq!(state.request_count.load(Ordering::Relaxed), 4);
    let status_count = |status: u16| {
        state
            .status_counts
            .get(&status)
            .map(|count| count.load(Ordering::Relaxed))
    };
    assert_eq!(status_count(403), Some(3));
    assert_eq!(status_count(503), Some(1));
}
