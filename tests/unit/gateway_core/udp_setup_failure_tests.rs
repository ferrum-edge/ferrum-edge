//! UDP session setup-failure summary ownership and attribution (issue #4049).
//!
//! A setup attempt that never publishes a session must still emit exactly one
//! `StreamTransactionSummary`, and a published session must own every summary
//! for its flow even when it is removed from the session map before the
//! spawned setup task observes the error. Both properties are driven through
//! the production `UdpSetupProgress` value the UDP listener threads through
//! `process_new_session_datagram` / `create_session`, so what is under test is
//! the shipped ownership rule rather than a re-implementation of it.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use ferrum_edge::_test_support::UdpSetupProgressForTest;
use ferrum_edge::config::types::{BackendScheme, GatewayConfig, Proxy};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::{
    DisconnectCause, Plugin, StreamConnectionContext, StreamTransactionSummary,
};
use ferrum_edge::retry::ErrorClass;

const NS: &str = "ferrum";
const PROXY_ID: &str = "u-dns";
const LISTEN_PORT: u16 = 20_273;

type CapturedSummaries = Arc<Mutex<Vec<StreamTransactionSummary>>>;
type CaptureFixture = (Vec<Arc<dyn Plugin>>, CapturedSummaries);

/// Records every `on_stream_disconnect` it receives so "exactly once" is a
/// count, not an absence-of-panic.
struct CaptureDisconnects {
    summaries: CapturedSummaries,
}

#[async_trait]
impl Plugin for CaptureDisconnects {
    fn name(&self) -> &str {
        "capture-udp-setup"
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.summaries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(summary.clone());
    }
}

fn capture() -> CaptureFixture {
    let summaries = Arc::new(Mutex::new(Vec::new()));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(CaptureDisconnects {
        summaries: Arc::clone(&summaries),
    })];
    (plugins, summaries)
}

/// A UDP proxy whose *configured* backend deliberately differs from the target
/// selection settles on, so "preserved the selected target" is distinguishable
/// from "reconstructed the proxy default".
fn udp_proxy() -> Proxy {
    let config: GatewayConfig = serde_json::from_value(serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": PROXY_ID,
            "name": "UDP DNS Proxy",
            "backend_scheme": "udp",
            "backend_host": "configured-default.local",
            "backend_port": 53,
            "listen_port": LISTEN_PORT
        }],
        "consumers": [],
        "plugin_configs": []
    }))
    .expect("gateway config should deserialize");
    config.proxies[0].clone()
}

fn admitted_ctx(generation: Option<u64>) -> StreamConnectionContext {
    let mut ctx = StreamConnectionContext::new(
        "198.51.100.4".to_string(),
        "198.51.100.4".to_string(),
        PROXY_ID.to_string(),
        Some("UDP DNS Proxy".to_string()),
        LISTEN_PORT,
        BackendScheme::Udp,
        Arc::new(ConsumerIndex::new(&[])),
    );
    ctx.proxy_namespace = NS.to_string();
    ctx.proxy_lifecycle_generation = generation;
    ctx.authenticated_identity = Some("spiffe://mesh/ns/ferrum/sa/dns-client".to_string());
    ctx.auth_method = Some("mtls_auth");
    ctx.sni_hostname = Some("dns.example".to_string());
    ctx
}

fn dns_setup_error() -> anyhow::Error {
    ferrum_edge::_test_support::stream_dns_setup_error_for_test(
        "backend.local",
        anyhow::anyhow!("DNS resolution returned no addresses for backend.local"),
    )
}

/// Pre-publication DNS failure: exactly one summary, classified as a DNS
/// lookup failure, carrying the epoch the attempt was ADMITTED under and the
/// backend that selection actually chose.
#[tokio::test]
async fn a_pre_publication_dns_failure_emits_exactly_one_attributed_summary() {
    let (plugins, captured) = capture();
    let proxy = udp_proxy();

    let mut progress = UdpSetupProgressForTest::new();
    progress.record_stream_admission(plugins.clone(), &proxy, &admitted_ctx(Some(7)));
    // The load balancer picked a member of the upstream, not the proxy default.
    progress.record_backend_selection("10.244.2.9", 5353);

    assert!(progress.owns_setup_failure());
    let error = dns_setup_error();
    let emitted = progress
        .emit_setup_failure_if_owner(NS, PROXY_ID, "198.51.100.4", LISTEN_PORT, &error)
        .await;
    assert!(emitted, "setup owns a failure that never published");

    let summaries = captured.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(summaries.len(), 1, "exactly one setup-failure summary");
    let summary = &summaries[0];
    assert_eq!(summary.error_class, Some(ErrorClass::DnsLookupError));
    assert_eq!(
        summary.disconnect_cause,
        Some(DisconnectCause::BackendError)
    );
    assert_eq!(summary.protocol, "udp");
    assert_eq!(summary.listen_port, LISTEN_PORT);
    assert_eq!(summary.bytes_sent, 0);
    assert_eq!(summary.bytes_received, 0);
    // The ADMITTED generation, never a later one re-read from the live epoch.
    assert_eq!(summary.proxy_lifecycle_generation, Some(7));
    assert_eq!(
        summary.backend_target, "10.244.2.9:5353",
        "the selected target must survive the failure, not the proxy default"
    );
    assert_eq!(summary.backend_resolved_ip, None, "DNS never resolved");
    assert_eq!(
        summary.consumer_username.as_deref(),
        Some("spiffe://mesh/ns/ferrum/sa/dns-client")
    );
    assert_eq!(summary.auth_method, Some("mtls_auth"));
    assert_eq!(summary.sni_hostname.as_deref(), Some("dns.example"));
    assert_eq!(summary.proxy_name.as_deref(), Some("UDP DNS Proxy"));
    assert!(
        summary
            .connection_error
            .as_deref()
            .is_some_and(|text| text.starts_with("DNS resolution failed for backend.local: ")),
        "legacy DNS wording is preserved: {:?}",
        summary.connection_error
    );
}

/// A failure observed after `sessions.insert` belongs to the session, even
/// though the session has already been removed by the time setup sees the
/// error. This is the race the old `sessions.contains_key` probe lost: the
/// map says "absent", and the pre-fix code emitted a second summary on top of
/// the session-owned disconnect summary.
#[tokio::test]
async fn a_post_publication_failure_emits_nothing_even_after_the_session_is_removed() {
    let (plugins, captured) = capture();
    let proxy = udp_proxy();

    let mut progress = UdpSetupProgressForTest::new();
    progress.record_stream_admission(plugins.clone(), &proxy, &admitted_ctx(Some(7)));
    progress.record_backend_selection("10.244.2.9", 5353);
    progress.record_backend_resolved_ip("10.244.2.9".parse::<IpAddr>().expect("addr"));

    // `create_session` published the session...
    progress.mark_published();
    // ...and it was concurrently removed (idle expiry / shutdown / reload)
    // before the spawned setup task observed the error. Ownership does not
    // move back to setup.
    assert!(!progress.owns_setup_failure());

    let emitted = progress
        .emit_setup_failure_if_owner(
            NS,
            PROXY_ID,
            "198.51.100.4",
            LISTEN_PORT,
            &anyhow::anyhow!("backend send failed after publication"),
        )
        .await;
    assert!(!emitted, "a published session owns its own disconnect");
    let summaries = captured.lock().unwrap_or_else(|p| p.into_inner());
    assert!(
        summaries.is_empty(),
        "no duplicate setup summary may reach on_stream_disconnect"
    );
}

/// A failure BEFORE any epoch view resolved has no admitted plugin slice and no
/// admitted generation. It must not borrow the current generation's plugins.
#[tokio::test]
async fn a_failure_before_admission_notifies_no_plugins_and_claims_no_generation() {
    let (_plugins, captured) = capture();

    let progress = UdpSetupProgressForTest::new();
    assert!(progress.owns_setup_failure());
    let emitted = progress
        .emit_setup_failure_if_owner(
            NS,
            PROXY_ID,
            "198.51.100.4",
            LISTEN_PORT,
            &anyhow::anyhow!("Proxy ferrum/u-dns not found"),
        )
        .await;
    assert!(emitted, "the transaction is still recorded for operators");
    let summaries = captured.lock().unwrap_or_else(|p| p.into_inner());
    assert!(
        summaries.is_empty(),
        "no plugin from a generation that never admitted this attempt may be notified"
    );
}

/// Frontend DTLS plugin reject (PR #6872 review): the accepted-DTLS handler
/// used to close and return before building any summary, so metadata the
/// rejecting chain wrote — `ip_restriction.reason` — never reached a log sink.
/// Exercise the production summary helper's zero-byte, client-side attribution;
/// the structural test below separately pins its listener call site.
#[tokio::test]
async fn a_frontend_dtls_plugin_rejection_emits_one_summary_with_the_rejection_reason() {
    use ferrum_edge::plugins::ip_restriction::{IpRestriction, REJECTION_REASON_METADATA_KEY};
    use ferrum_edge::plugins::{Direction, PluginResult, StreamFrontendTransport};

    let proxy = udp_proxy();
    for (config, expected) in [
        (
            serde_json::json!({"deny": ["198.51.100.0/24"]}),
            "ip_denied",
        ),
        (
            serde_json::json!({"allow": ["10.0.0.0/8"]}),
            "not_in_allow_list",
        ),
    ] {
        let (capture_plugins, captured) = capture();
        let restriction: Arc<dyn Plugin> =
            Arc::new(IpRestriction::new(&config).expect("valid ip_restriction config"));
        let mut plugins = vec![Arc::clone(&restriction)];
        plugins.extend(capture_plugins);

        let mut ctx = admitted_ctx(Some(7));
        ctx.frontend_transport = StreamFrontendTransport::Dtls;
        assert!(matches!(
            restriction.on_stream_connect(&mut ctx).await,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ));

        let emitted = ferrum_edge::_test_support::emit_dtls_plugin_rejection_summary_for_test(
            plugins,
            &proxy,
            &ctx,
            "198.51.100.4",
            LISTEN_PORT,
        )
        .await;
        assert!(emitted, "a rejected DTLS admission emits its summary");

        let summaries = captured.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(summaries.len(), 1, "exactly one rejection summary");
        let summary = &summaries[0];
        assert_eq!(
            summary
                .metadata
                .get(REJECTION_REASON_METADATA_KEY)
                .map(String::as_str),
            Some(expected)
        );
        assert_eq!(summary.client_ip, "198.51.100.4");
        assert_eq!(summary.listen_port, LISTEN_PORT);
        assert_eq!(summary.bytes_sent, 0);
        assert_eq!(summary.bytes_received, 0);
        assert_eq!(summary.proxy_lifecycle_generation, Some(7));
        assert_eq!(
            summary.disconnect_direction,
            Some(Direction::ClientToBackend)
        );
        assert_ne!(
            summary.disconnect_cause,
            Some(DisconnectCause::BackendError),
            "a plugin reject is client-side and backend-health neutral"
        );
    }
}

/// The helper test above cannot catch the listener dropping summary emission
/// (issue #6906). Scope this guard to the listener's rejection arm so the helper
/// definition or a call in another branch cannot satisfy it.
#[test]
fn frontend_dtls_listener_awaits_plugin_rejection_summary_before_returning() {
    let source = include_str!("../../../src/proxy/udp_proxy.rs");
    let listener = source
        .split_once("async fn start_dtls_frontend_listener(")
        .expect("frontend DTLS listener")
        .1
        .split_once("\n}\n")
        .expect("end of frontend DTLS listener")
        .0;
    let rejected = listener
        .split_once("DtlsStreamConnectOutcome::Rejected => {")
        .expect("listener plugin-rejection arm")
        .1
        .split_once("\n                        }\n")
        .expect("end of listener plugin-rejection arm")
        .0;
    let before_return = rejected
        .split_once("return;")
        .expect("plugin rejection returns before backend setup")
        .0;
    let snapshot = before_return
        .find("let progress = dtls_plugin_rejection_progress(")
        .expect("plugin rejection snapshots the admitting context before returning");
    let emit = before_return
        .find("emit_dtls_plugin_rejection_summary(")
        .expect("listener must emit the plugin-rejection summary before returning");
    assert!(snapshot < emit, "snapshot attribution before emitting");
    assert_eq!(
        rejected
            .matches("emit_dtls_plugin_rejection_summary(")
            .count(),
        1,
        "the listener must emit exactly one plugin-rejection summary"
    );

    // Ignore rustfmt whitespace, but require the real awaited call with the
    // rejection's attribution, rather than merely finding the helper's name.
    let call: String = before_return[emit..].split_whitespace().collect();
    assert!(
        call.starts_with(concat!(
            "emit_dtls_plugin_rejection_summary(progress,DtlsPluginRejection{",
            "namespace:&proxy_namespace,proxy_id:&resolved_proxy_id,",
            "client_ip:client_ip.as_ref(),listen_port:port,",
            "connected_wall_at:connected_at,",
            "duration_ms:connected_mono.elapsed().as_secs_f64()*1000.0,",
            "},).await;"
        )),
        "the listener must await summary emission with the rejected connection's attribution"
    );
}
