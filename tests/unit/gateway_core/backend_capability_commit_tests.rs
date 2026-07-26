//! External coverage for the capability-refresh compare-and-commit protocol.
//!
//! The periodic refresh reads a target's record, probes across an `await`, then
//! writes the result back. A request-path live-learning downgrade
//! (`mark_h3_unsupported` / `mark_h2_tls_unsupported` / `mark_hbone_unsupported`)
//! can land inside that window. A blind write-back would overwrite the newer
//! verdict with stale probe output — resurrecting native H3 dispatch (or direct
//! H2, or HBONE) against a backend the data path just proved broken, and
//! repeating the failure until the next refresh interval (default 24 h).
//!
//! `BackendCapabilityRegistry::snapshot_for_probe` + `commit_probe` close that
//! window: a probe result replaces the entry only while the entry is still the
//! exact version the probe was computed against.

use chrono::Utc;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, Proxy, ResponseBodyMode,
};
use ferrum_edge::proxy::backend_capabilities::{
    BackendCapabilityRecord, BackendCapabilityRegistry, BackendCapabilitySnapshot,
    CapabilityCommitOutcome, GrpcTransportCapabilities, PlainHttpCapabilities, ProtocolSupport,
    capability_key, merge_protocol_probe_classification,
};
use std::collections::HashSet;

const SUPPORTED: ProtocolSupport = ProtocolSupport::Supported;
const UNSUPPORTED: ProtocolSupport = ProtocolSupport::Unsupported;
const UNKNOWN: ProtocolSupport = ProtocolSupport::Unknown;

fn minimal_proxy() -> Proxy {
    let now = Utc::now();
    Proxy {
        id: "capability-commit".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Https),
        dispatch_kind: DispatchKind::from(BackendScheme::Https),
        backend_host: "backend.test".to_string(),
        backend_port: 443,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: BackendTlsConfig::default_verify(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        created_at: now,
        updated_at: now,
    }
}

/// Build a fully specified record.
///
/// `last_probe_at_unix_secs` is pinned instead of taken from the wall clock so
/// two records built from the same arguments are field-for-field identical —
/// `commit_probe_compares_arc_identity_not_field_equality` depends on that.
fn caps(
    h3: ProtocolSupport,
    h2_tls: ProtocolSupport,
    hbone: ProtocolSupport,
) -> BackendCapabilityRecord {
    BackendCapabilityRecord {
        plain_http: PlainHttpCapabilities {
            h1: UNKNOWN,
            h2_tls,
            h3,
        },
        grpc_transport: GrpcTransportCapabilities {
            h2_tls,
            h2c: UNKNOWN,
        },
        hbone,
        last_probe_at_unix_secs: 1,
        last_probe_error: None,
    }
}

fn registry_with(key: &str, seed: BackendCapabilityRecord) -> BackendCapabilityRegistry {
    let registry = BackendCapabilityRegistry::new();
    registry.upsert(key.to_string(), seed);
    registry
}

#[test]
fn commit_probe_accepts_an_unchanged_occupied_snapshot() {
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = registry_with(&key, caps(UNKNOWN, UNKNOWN, UNKNOWN));

    let snapshot = registry.snapshot_for_probe(&key);
    assert!(!snapshot.was_vacant());
    assert_eq!(
        snapshot.previous().map(|entry| entry.plain_http.h3),
        Some(UNKNOWN),
        "the snapshot must expose the observed record for probe merging"
    );

    let probed = caps(SUPPORTED, SUPPORTED, UNKNOWN);
    let outcome = registry.commit_probe(key, &snapshot, probed);
    assert!(
        outcome.is_committed(),
        "nothing raced the probe; commit rejected as {}",
        outcome.reason()
    );

    let fetched = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(fetched.plain_http.h3, SUPPORTED);
    assert_eq!(fetched.plain_http.h2_tls, SUPPORTED);
}

#[test]
fn concurrent_h3_downgrade_beats_a_stale_probe_commit() {
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = registry_with(&key, caps(SUPPORTED, SUPPORTED, UNKNOWN));

    // The refresh observes the proven-Supported record and starts probing.
    let snapshot = registry.snapshot_for_probe(&key);

    // A native-H3 request fails mid-probe; the data path downgrades H3.
    registry.mark_h3_unsupported(&proxy, None);

    // The probe finishes and still believes the backend speaks H3.
    let probed = caps(SUPPORTED, SUPPORTED, UNKNOWN);
    let outcome = registry.commit_probe(key, &snapshot, probed);
    assert!(
        matches!(outcome, CapabilityCommitOutcome::RejectedStale),
        "a probe computed against a superseded record must lose, got {}",
        outcome.reason()
    );

    let fetched = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(
        fetched.plain_http.h3, UNSUPPORTED,
        "the stale probe must not resurrect native H3 dispatch"
    );
    assert!(
        fetched.last_probe_error.is_some(),
        "the surviving record must keep the request-path downgrade reason"
    );
}

#[test]
fn concurrent_h2_tls_downgrade_beats_a_stale_probe_commit() {
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = registry_with(&key, caps(UNKNOWN, SUPPORTED, UNKNOWN));

    let snapshot = registry.snapshot_for_probe(&key);

    // ALPN-negotiated HTTP/1.1 on the request path downgrades both H2 buckets.
    assert!(
        registry.mark_h2_tls_unsupported(&proxy, None),
        "precondition: the live downgrade must actually mutate the entry"
    );

    let probed = caps(UNKNOWN, SUPPORTED, UNKNOWN);
    let outcome = registry.commit_probe(key, &snapshot, probed);
    assert!(matches!(outcome, CapabilityCommitOutcome::RejectedStale));

    let fetched = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(fetched.plain_http.h2_tls, UNSUPPORTED);
    assert_eq!(
        fetched.grpc_transport.h2_tls, UNSUPPORTED,
        "the gRPC H2 bucket learned on the request path must survive too"
    );
}

#[test]
fn concurrent_hbone_downgrade_beats_a_stale_probe_commit() {
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = registry_with(&key, caps(UNKNOWN, UNKNOWN, SUPPORTED));

    let snapshot = registry.snapshot_for_probe(&key);
    registry.mark_hbone_unsupported(&proxy, None);

    let probed = caps(UNKNOWN, UNKNOWN, SUPPORTED);
    let outcome = registry.commit_probe(key, &snapshot, probed);
    assert!(matches!(outcome, CapabilityCommitOutcome::RejectedStale));

    let fetched = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(fetched.hbone, UNSUPPORTED);
}

#[test]
fn a_stale_probe_cannot_clobber_a_downgrade_it_did_not_observe() {
    // The commit token is the whole record, not one protocol field. An H3
    // refresh finishing after a live HBONE downgrade must still lose, or the
    // gateway would redial an unavailable waypoint on every request.
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = registry_with(&key, caps(SUPPORTED, SUPPORTED, SUPPORTED));

    let snapshot = registry.snapshot_for_probe(&key);
    registry.mark_hbone_unsupported(&proxy, None);

    // The probe only re-learned H3, but its record still carries the stale
    // `hbone: Supported` it snapshotted before the tunnel failure.
    let probed = caps(UNSUPPORTED, SUPPORTED, SUPPORTED);
    let outcome = registry.commit_probe(key, &snapshot, probed);
    assert!(matches!(outcome, CapabilityCommitOutcome::RejectedStale));

    let fetched = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(fetched.hbone, UNSUPPORTED, "HBONE downgrade must survive");
    assert_eq!(
        fetched.plain_http.h3, SUPPORTED,
        "rejecting the whole probe preserves the pre-probe H3 verdict; the \
         next refresh re-classifies from the new baseline"
    );
}

#[test]
fn commit_probe_fills_a_key_that_is_still_vacant() {
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = BackendCapabilityRegistry::new();

    // Startup / first periodic refresh for a newly configured target.
    let snapshot = registry.snapshot_for_probe(&key);
    assert!(snapshot.was_vacant());
    assert!(snapshot.previous().is_none());

    let probed = caps(SUPPORTED, SUPPORTED, UNKNOWN);
    let outcome = registry.commit_probe(key, &snapshot, probed);
    assert!(
        outcome.is_committed(),
        "a vacant expectation onto a still-vacant key must land, got {}",
        outcome.reason()
    );

    let fetched = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(fetched.plain_http.h3, SUPPORTED);
}

#[test]
fn vacant_commit_loses_to_an_entry_inserted_during_the_probe() {
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = BackendCapabilityRegistry::new();

    let snapshot = registry.snapshot_for_probe(&key);
    assert!(snapshot.was_vacant());

    // A cold-start HBONE tunnel failure inserts an Unsupported record while
    // the first probe is still in flight.
    registry.mark_hbone_unsupported(&proxy, None);

    let probed = caps(SUPPORTED, SUPPORTED, SUPPORTED);
    let outcome = registry.commit_probe(key, &snapshot, probed);
    assert!(
        matches!(outcome, CapabilityCommitOutcome::RejectedStale),
        "a vacant expectation must not overwrite a concurrently inserted entry"
    );

    let fetched = registry
        .get(&proxy, None)
        .expect("live insert must survive");
    assert_eq!(fetched.hbone, UNSUPPORTED);
}

#[test]
fn vacant_commit_loses_to_a_live_h2_tls_downgrade_that_creates_the_entry() {
    // `mark_h2_tls_unsupported` creates an H1-only record from a vacant key
    // when a backend SNI override forces direct H2. That insert must beat a
    // first-probe commit computed against the vacant key.
    let mut proxy = minimal_proxy();
    proxy.resolved_tls.sni = Some("backend.mesh.internal".to_string());
    let key = capability_key(&proxy);
    let registry = BackendCapabilityRegistry::new();

    let snapshot = registry.snapshot_for_probe(&key);
    assert!(registry.mark_h2_tls_unsupported(&proxy, None));

    let probed = caps(UNKNOWN, SUPPORTED, UNKNOWN);
    let outcome = registry.commit_probe(key, &snapshot, probed);
    assert!(matches!(outcome, CapabilityCommitOutcome::RejectedStale));

    let fetched = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(fetched.plain_http.h2_tls, UNSUPPORTED);
    assert_eq!(fetched.plain_http.h1, SUPPORTED);
}

#[test]
fn commit_probe_does_not_resurrect_a_key_evicted_during_the_probe() {
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = registry_with(&key, caps(SUPPORTED, SUPPORTED, UNKNOWN));

    let snapshot = registry.snapshot_for_probe(&key);

    // A reload dropped this backend from the config; `retain_keys` pruned it.
    registry.retain_keys(&HashSet::new());

    let probed = caps(SUPPORTED, SUPPORTED, UNKNOWN);
    let outcome = registry.commit_probe(key, &snapshot, probed);
    assert!(
        matches!(outcome, CapabilityCommitOutcome::RejectedEvicted),
        "an evicted key must be reported distinctly from a superseded one, got {}",
        outcome.reason()
    );
    assert!(
        registry.get(&proxy, None).is_none(),
        "a probe must not re-add a target the config no longer references"
    );
}

#[test]
fn commit_probe_compares_arc_identity_not_field_equality() {
    // The version token is the published `Arc`, not the record's value. A
    // concurrent writer that republishes a field-identical record still
    // invalidates the in-flight probe; value equality would let a
    // downgrade-then-restore sequence slip through as "unchanged".
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = registry_with(&key, caps(SUPPORTED, SUPPORTED, UNKNOWN));

    let snapshot = registry.snapshot_for_probe(&key);

    // Byte-identical field values, freshly published `Arc`.
    registry.upsert(key.clone(), caps(SUPPORTED, SUPPORTED, UNKNOWN));

    let probed = caps(UNSUPPORTED, SUPPORTED, UNKNOWN);
    let outcome = registry.commit_probe(key, &snapshot, probed);
    assert!(
        matches!(outcome, CapabilityCommitOutcome::RejectedStale),
        "a republished record is a new version even when its fields match"
    );

    let fetched = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(fetched.plain_http.h3, SUPPORTED);
}

#[test]
fn a_no_op_live_downgrade_does_not_invalidate_the_probe_snapshot() {
    // `mark_h3_unsupported` on an already-Unsupported entry leaves the
    // published `Arc` in place. Nothing changed, so there is nothing for the
    // probe to clobber and the commit must land — otherwise a backend that
    // keeps failing H3 could never be re-probed back to Supported once it
    // recovers.
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = registry_with(&key, caps(UNSUPPORTED, UNSUPPORTED, UNSUPPORTED));

    let snapshot = registry.snapshot_for_probe(&key);

    registry.mark_h3_unsupported(&proxy, None);
    assert!(
        !registry.mark_h2_tls_unsupported(&proxy, None),
        "precondition: the H2 downgrade is already recorded, so it is a no-op"
    );
    registry.mark_hbone_unsupported(&proxy, None);

    let probed = caps(SUPPORTED, SUPPORTED, SUPPORTED);
    let outcome = registry.commit_probe(key, &snapshot, probed);
    assert!(
        outcome.is_committed(),
        "no-op live-learning calls must not strand a healthy re-probe, got {}",
        outcome.reason()
    );

    let fetched = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(fetched.plain_http.h3, SUPPORTED);
}

#[test]
fn a_default_snapshot_expects_a_vacant_key() {
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = BackendCapabilityRegistry::new();

    let snapshot = BackendCapabilitySnapshot::default();
    assert!(snapshot.was_vacant());

    let first = caps(SUPPORTED, UNKNOWN, UNKNOWN);
    let outcome = registry.commit_probe(key.clone(), &snapshot, first);
    assert!(outcome.is_committed());

    // The key is occupied now, so the same vacant expectation must lose.
    let second = caps(UNSUPPORTED, UNKNOWN, UNKNOWN);
    let outcome = registry.commit_probe(key, &snapshot, second);
    assert!(matches!(outcome, CapabilityCommitOutcome::RejectedStale));

    let fetched = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(fetched.plain_http.h3, SUPPORTED);
}

#[test]
fn one_snapshot_serves_both_the_merge_input_and_the_commit_expectation() {
    // The refresh takes exactly one pre-probe observation and uses it twice.
    // Two independent reads would leave the merge reasoning about one version
    // while the commit compared against another.
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = registry_with(&key, caps(SUPPORTED, SUPPORTED, UNKNOWN));

    let snapshot = registry.snapshot_for_probe(&key);

    // Merge role: a transient reachability failure preserves the snapshot's
    // proven verdict instead of wiping it for a whole refresh interval.
    let merged = merge_protocol_probe_classification(
        snapshot.previous().map(|entry| entry.plain_http.h3),
        UNSUPPORTED,
        true,
    );
    assert_eq!(merged, SUPPORTED);

    // Commit role: the same snapshot value is the compare expectation.
    let probed = caps(merged, SUPPORTED, UNKNOWN);
    let outcome = registry.commit_probe(key, &snapshot, probed);
    assert!(outcome.is_committed());

    let fetched = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(fetched.plain_http.h3, SUPPORTED);
}

#[test]
fn periodic_refresh_write_back_uses_compare_and_commit() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let refresh = source
        .split("pub(crate) async fn refresh_backend_capabilities_with_semaphore(")
        .nth(1)
        .expect("refresh_backend_capabilities_with_semaphore")
        .split("fn spawn_backend_capability_refresh(")
        .next()
        .expect("bounded refresh body");

    assert!(
        refresh.contains("snapshot_for_probe("),
        "the refresh must take a pre-probe snapshot"
    );
    assert!(
        refresh.contains("commit_probe("),
        "the refresh must write back through compare-and-commit"
    );
    assert!(
        !refresh.contains(".upsert("),
        "a blind upsert reopens the probe-window race: a request-path \
         downgrade landing mid-probe would be overwritten by stale output"
    );
    assert!(
        !refresh.contains("get_by_key("),
        "the refresh must reuse its single snapshot instead of re-reading the \
         registry, so the merge input and the commit expectation cannot diverge"
    );

    // Counters and the summary line must describe committed registry state,
    // never a probe result the commit discarded.
    assert!(
        refresh.contains("committed.plain_http.h3.is_supported()"),
        "protocol tallies must read the committed record"
    );
    assert!(
        !refresh.contains("record.plain_http.h3.is_supported()"),
        "protocol tallies must not read the discarded probe proposal"
    );
    assert!(
        refresh.contains("discarded"),
        "the summary line must report probes that lost the commit"
    );
}

#[test]
fn probe_merges_against_the_callers_snapshot_without_re_reading() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let probe = source
        .split("async fn probe_backend_capabilities(")
        .nth(1)
        .expect("probe_backend_capabilities")
        .split("async fn probe_h2c(")
        .next()
        .expect("bounded probe body");

    assert!(
        probe.contains("previous.previous()"),
        "the probe must merge against the snapshot the caller will commit with"
    );
    assert!(
        !probe.contains("get_by_key("),
        "a second pre-probe read would produce a merge input that no longer \
         matches the commit expectation"
    );
}
