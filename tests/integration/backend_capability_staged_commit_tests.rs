//! Staged capability commit, driven through the real probes.
//!
//! An HTTPS target is classified by an HTTP/2-over-TLS probe and an HTTP/3
//! probe. Against a backend with no QUIC listener the HTTP/3 probe ends only
//! at its timeout, so a refresh that published one record after both probes
//! left the target `Unknown` — reqwest instead of the direct HTTP/2 or
//! HTTP/1.1 pools — for seconds after every start and reload.
//!
//! The refresh now publishes the HTTP/2 verdict as soon as that probe
//! answers and merges the HTTP/3 verdict in a second compare-and-commit
//! chained off the first (`StagedProbeCommit`). These tests hold the HTTP/3
//! probe open at a test-controlled barrier — the QUIC listener receives the
//! Initial and answers nothing until released — and assert what the registry
//! reports while it is held, after it is released, and when a request-path
//! downgrade lands in between.
//!
//! The registry-level rules of the chain itself are pinned without sockets in
//! `tests/unit/gateway_core/backend_capability_commit_tests.rs`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::types::{GatewayConfig, Proxy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::ProxyState;
use ferrum_edge::proxy::backend_capabilities::{
    BackendCapabilityRecord, ProtocolSupport, capability_key_for_proxy_target,
};
use serde_json::json;
use tokio::task::JoinHandle;

use crate::scaffolding::backends::{
    H2Step, H3Step, H3TlsConfig, MatchHeaders, ScriptedH2Backend, ScriptedH3Backend,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::reserve_colocated_tcp_udp;

const SUPPORTED: ProtocolSupport = ProtocolSupport::Supported;
const UNSUPPORTED: ProtocolSupport = ProtocolSupport::Unsupported;
const UNKNOWN: ProtocolSupport = ProtocolSupport::Unknown;

/// Bound for every wait on the fixture. The HTTP/3 probe itself gives up
/// after `backend_connect_timeout_ms` (capped at 5 s for probes), so each
/// test must reach its release well inside that; nothing here sleeps for a
/// fixed time.
const WAIT: Duration = Duration::from_secs(15);

/// One HTTPS target whose HTTP/2 side answers immediately and whose HTTP/3
/// side is held at a barrier, plus a `ProxyState` that has not probed it yet.
struct StagedProbeFixture {
    state: ProxyState,
    /// The proxy exactly as the request path reads it from the published
    /// config, so `registry.get(&proxy, None)` and the `mark_*` calls use the
    /// same key the probe target does.
    proxy: Proxy,
    h3_backend: ScriptedH3Backend,
    _h2_backend: ScriptedH2Backend,
    _health_checks: Vec<JoinHandle<()>>,
}

impl StagedProbeFixture {
    async fn start(name: &str) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = TestCa::new(name).expect("backend CA");
        let (cert, key) = ca.valid().expect("backend leaf");
        let (tcp, udp) = reserve_colocated_tcp_udp()
            .await
            .expect("co-located TCP/UDP backend port");
        let backend_port = tcp.port;

        // HTTP/2 over TLS: completes the handshake the probe needs and then
        // waits for a request that never comes, like an idle pooled peer.
        let h2_backend = ScriptedH2Backend::builder_tls(tcp.into_listener(), &cert, &key)
            .expect("HTTP/2 TLS backend builder")
            .repeat_script(true)
            .step(H2Step::ExpectHeaders(MatchHeaders::any()))
            .step(H2Step::RespondHeaders(vec![(":status", "200".into())]))
            .step(H2Step::RespondData {
                data: Bytes::from_static(b"ok"),
                end_stream: true,
            })
            .spawn()
            .expect("HTTP/2 TLS backend");

        // HTTP/3 on the same port: a real QUIC + H3 listener whose handshakes
        // stay un-accepted until `release_handshakes`.
        let h3_backend = ScriptedH3Backend::builder(udp.into_socket(), H3TlsConfig::new(cert, key))
            .hold_handshakes()
            .step(H3Step::StallFor(Duration::from_secs(60)))
            .spawn()
            .expect("gated HTTP/3 backend");

        let mut config: GatewayConfig = serde_json::from_value(json!({
            "version": "1",
            "proxies": [{
                "id": "staged-commit",
                "listen_path": "/staged",
                "backend_scheme": "https",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "backend_connect_timeout_ms": 5000,
                "backend_tls_verify_server_cert": false,
                // One QUIC connection per backend keeps the barrier to a
                // single held handshake.
                "pool_http3_connections_per_backend": 1
            }],
            "consumers": [],
            "upstreams": [],
            "plugin_configs": []
        }))
        .expect("staged-commit config");
        // What the loaders do after deserializing: derive `resolved_tls`,
        // dispatch kind and the other serde-skipped projections.
        config.normalize_fields();

        let env = EnvConfig {
            tls_no_verify: true,
            pool_warmup_enabled: false,
            ..EnvConfig::default()
        };
        // `ProxyState::new` starts no capability refresh; the test owns it.
        let (state, health_checks) =
            ProxyState::new(config, DnsCache::new(DnsConfig::default()), env, None, None)
                .expect("proxy state");
        let proxy = state.config.load().proxies[0].clone();

        Self {
            state,
            proxy,
            h3_backend,
            _h2_backend: h2_backend,
            _health_checks: health_checks,
        }
    }

    /// Run one refresh on its own task, as the background refresh does.
    fn spawn_refresh(&self) -> JoinHandle<()> {
        let state = self.state.clone();
        tokio::spawn(async move { state.refresh_backend_capabilities().await })
    }

    /// The published record, read the way dispatch reads it.
    fn record(&self) -> Option<Arc<BackendCapabilityRecord>> {
        self.state.backend_capabilities.get(&self.proxy, None)
    }

    async fn wait_for_record(
        &self,
        what: &str,
        ready: impl Fn(&BackendCapabilityRecord) -> bool,
    ) -> Arc<BackendCapabilityRecord> {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let record = self.record();
            if let Some(record) = &record
                && ready(record.as_ref())
            {
                return Arc::clone(record);
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {what}; published record: {record:?}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Wait until the registry reports the HTTP/2 verdict AND the HTTP/3
    /// probe's Initial is parked at the barrier. From then until
    /// `release_handshakes` the HTTP/3 probe cannot have a verdict, so any
    /// record read in that window is the early stage.
    async fn wait_for_h2_verdict_with_h3_held(&self) -> Arc<BackendCapabilityRecord> {
        let deadline = tokio::time::Instant::now() + WAIT;
        while self.h3_backend.held_handshakes() == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the HTTP/3 probe never reached the gated QUIC listener \
                 (connections seen: {})",
                self.h3_backend.accepted_connections()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let early = self
            .wait_for_record("the early HTTP/2 verdict", |record| {
                record.plain_http.h2_tls == SUPPORTED
            })
            .await;
        assert_eq!(
            self.h3_backend.accepted_handshakes(),
            0,
            "precondition: the HTTP/3 handshake must still be held"
        );
        early
    }

    /// Open the barrier, let the refresh finish, and prove the HTTP/3 probe
    /// really completed its handshake (so it had a `Supported` verdict to
    /// publish, whatever the registry then did with it).
    async fn release_h3_and_finish(&self, refresh: JoinHandle<()>) {
        self.h3_backend.release_handshakes();
        tokio::time::timeout(WAIT, refresh)
            .await
            .expect("refresh must finish once the HTTP/3 probe is released")
            .expect("refresh task");
        let deadline = tokio::time::Instant::now() + WAIT;
        while self.h3_backend.accepted_handshakes() == 0 {
            if tokio::time::Instant::now() >= deadline {
                let errors = self.h3_backend.step_errors().await;
                panic!(
                    "the released HTTP/3 probe never completed a handshake; fixture errors: {errors:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// First probe of a target: the HTTP/2 verdict is visible while the HTTP/3
/// probe is provably still open, HTTP/3 reads `Unknown` meanwhile, and the
/// HTTP/3 verdict is merged once its probe finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_verdict_is_published_while_the_h3_probe_is_still_open() {
    let fixture = StagedProbeFixture::start("staged-commit-first-probe").await;
    assert!(
        fixture.record().is_none(),
        "precondition: the registry has never classified this target"
    );

    let refresh = fixture.spawn_refresh();
    let early = fixture.wait_for_h2_verdict_with_h3_held().await;

    assert!(
        !refresh.is_finished(),
        "the refresh as a whole still waits for the HTTP/3 probe"
    );
    assert_eq!(early.plain_http.h2_tls, SUPPORTED);
    assert_eq!(
        early.grpc_transport.h2_tls, SUPPORTED,
        "the gRPC HTTP/2 bucket is published with the same verdict"
    );
    assert_eq!(
        early.plain_http.h3, UNKNOWN,
        "a first probe has no earlier HTTP/3 verdict to keep, so the early \
         stage must not claim one: native HTTP/3 dispatch stays off"
    );
    assert_eq!(
        early.last_probe_error, None,
        "a successful HTTP/2 probe publishes no error"
    );

    fixture.release_h3_and_finish(refresh).await;

    let merged = fixture.record().expect("published record");
    assert_eq!(
        merged.plain_http.h3, SUPPORTED,
        "the HTTP/3 verdict must be merged once its probe finishes"
    );
    assert_eq!(merged.plain_http.h2_tls, SUPPORTED);
    assert_eq!(merged.grpc_transport.h2_tls, SUPPORTED);
    assert_eq!(merged.last_probe_error, None);
    assert!(
        !Arc::ptr_eq(&early, &merged),
        "the merge is a second published version, not a mutation of the first"
    );
}

/// A re-probe of a target that already has a record: the early stage carries
/// the PREVIOUS HTTP/3 value forward untouched, then the fresh verdict
/// replaces it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn early_stage_keeps_the_previous_h3_value_until_the_h3_probe_finishes() {
    let fixture = StagedProbeFixture::start("staged-commit-reprobe").await;

    // An earlier refresh found no QUIC listener and no HTTP/2 verdict.
    let mut previous = BackendCapabilityRecord::default();
    previous.plain_http.h3 = UNSUPPORTED;
    fixture.state.backend_capabilities.upsert(
        capability_key_for_proxy_target(&fixture.proxy, None),
        previous,
    );
    let seeded = fixture
        .record()
        .expect("the seed must land on the key dispatch reads");
    assert_eq!(seeded.plain_http.h2_tls, UNKNOWN);

    let refresh = fixture.spawn_refresh();
    let early = fixture.wait_for_h2_verdict_with_h3_held().await;

    assert_eq!(early.plain_http.h2_tls, SUPPORTED);
    assert_eq!(
        early.plain_http.h3, UNSUPPORTED,
        "the early stage must leave HTTP/3 exactly as the previous record had it"
    );

    fixture.release_h3_and_finish(refresh).await;

    let merged = fixture.record().expect("published record");
    assert_eq!(
        merged.plain_http.h3, SUPPORTED,
        "a completed HTTP/3 probe replaces the carried-forward value"
    );
    assert_eq!(merged.plain_http.h2_tls, SUPPORTED);
}

/// `mark_h3_unsupported` lands after the HTTP/2 verdict was published and
/// before the HTTP/3 probe finishes. The probe then succeeds, but its
/// `Supported` verdict must lose to the newer request-path downgrade.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_downgrade_between_the_stages_is_not_overwritten_by_the_h3_verdict() {
    let fixture = StagedProbeFixture::start("staged-commit-h3-mark").await;
    let refresh = fixture.spawn_refresh();
    let early = fixture.wait_for_h2_verdict_with_h3_held().await;
    assert_eq!(early.plain_http.h3, UNKNOWN);

    fixture
        .state
        .backend_capabilities
        .mark_h3_unsupported(&fixture.proxy, None);
    let marked = fixture.record().expect("marked record");
    assert_eq!(
        marked.plain_http.h3, UNSUPPORTED,
        "precondition: the downgrade must actually mutate the early stage"
    );

    fixture.release_h3_and_finish(refresh).await;

    let after = fixture.record().expect("published record");
    assert!(
        Arc::ptr_eq(&marked, &after),
        "the HTTP/3 stage must be discarded: the downgraded record is still \
         the published version, got {after:?}"
    );
    assert_eq!(
        after.plain_http.h3, UNSUPPORTED,
        "a probe verdict must not resurrect native HTTP/3 dispatch over a newer downgrade"
    );
    assert_eq!(
        after.plain_http.h2_tls, SUPPORTED,
        "the HTTP/2 verdict published before the downgrade is kept under it"
    );

    // The discarded verdict is not lost for good: the next refresh merges
    // against the downgraded record and re-classifies from there.
    fixture.spawn_refresh().await.expect("second refresh");
    let reprobed = fixture.record().expect("published record");
    assert_eq!(reprobed.plain_http.h3, SUPPORTED);
    assert_eq!(reprobed.plain_http.h2_tls, SUPPORTED);
}

/// `mark_h2_tls_unsupported` lands between the stages. The downgrade — both
/// HTTP/2 buckets and the HTTP/1.1 note — must survive the HTTP/3 stage, and
/// the HTTP/3 verdict of this refresh is dropped with it: HTTP/3 stays at its
/// pre-probe value, which can only withhold native HTTP/3, never grant it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_downgrade_between_the_stages_survives_the_h3_stage() {
    let fixture = StagedProbeFixture::start("staged-commit-h2-mark").await;
    let refresh = fixture.spawn_refresh();
    let early = fixture.wait_for_h2_verdict_with_h3_held().await;
    assert_eq!(early.plain_http.h3, UNKNOWN);

    assert!(
        fixture
            .state
            .backend_capabilities
            .mark_h2_tls_unsupported(&fixture.proxy, None),
        "precondition: the downgrade must actually mutate the early stage"
    );
    let marked = fixture.record().expect("marked record");

    fixture.release_h3_and_finish(refresh).await;

    let after = fixture.record().expect("published record");
    assert!(
        Arc::ptr_eq(&marked, &after),
        "the HTTP/3 stage must be discarded: the downgraded record is still \
         the published version, got {after:?}"
    );
    assert_eq!(after.plain_http.h2_tls, UNSUPPORTED);
    assert_eq!(after.grpc_transport.h2_tls, UNSUPPORTED);
    assert_eq!(after.plain_http.h1, SUPPORTED);
    assert_eq!(
        after.plain_http.h3, UNKNOWN,
        "the superseded refresh must not publish its HTTP/3 verdict either"
    );
    assert!(
        after
            .last_probe_error
            .as_deref()
            .is_some_and(|error| error.contains("ALPN-negotiated HTTP/1.1")),
        "the surviving record keeps the request-path downgrade reason, got {:?}",
        after.last_probe_error
    );
}
