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
//!
//! An HTTPS target is published in two stages — the HTTP/2 verdict as soon as
//! that probe answers, the HTTP/3 verdict when its (often much slower) probe
//! finishes — through `begin_probe_commit`, which chains the same
//! compare-and-commit: the second stage must replace exactly the record the
//! first one published. The `staged_*` tests below pin that chain;
//! `tests/integration/backend_capability_staged_commit_tests.rs` drives it
//! through the real probes with the HTTP/3 probe held open.

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
        labels: Default::default(),
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
        websocket_permessage_deflate: Default::default(),
        allow_path_parameters: false,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: now,
        updated_at: now,
        pending_limit_scope: None,
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
        refresh.contains("begin_probe_commit("),
        "the refresh must open the staged write-back, which takes the one \
         pre-probe snapshot"
    );
    assert!(
        refresh.contains("commit_capability_probe_stage("),
        "the refresh must write back through the compare-and-commit chain"
    );
    assert!(
        !refresh.contains("snapshot_for_probe(") && !refresh.contains(".commit_probe("),
        "the refresh must not pair its own snapshot with a bare commit: a \
         final commit compared against the pre-probe snapshot would lose to \
         the HTTP/2 verdict this same probe published early"
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
        probe.contains("commit.expected().previous()"),
        "the probe must merge against the snapshot its first commit is compared with"
    );
    assert!(
        !probe.contains("get_by_key(") && !probe.contains("snapshot_for_probe("),
        "a second pre-probe read would produce a merge input that no longer \
         matches the commit expectation"
    );
}

#[test]
fn https_probe_publishes_the_h2_verdict_before_awaiting_the_h3_probe() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let probe = source
        .split("async fn probe_backend_capabilities(")
        .nth(1)
        .expect("probe_backend_capabilities")
        .split("async fn probe_h2c(")
        .next()
        .expect("bounded probe body");

    assert!(
        !probe.contains("tokio::join!(h2_fut, h3_fut)"),
        "joining the two probes holds the HTTP/2 verdict until the HTTP/3 \
         probe finishes or times out"
    );
    let early = probe
        .find("commit_capability_probe_stage(target, commit, h2_verdict)")
        .expect("the HTTP/2 verdict must be published through the commit chain");
    let h3_wait = probe
        .find("h3_fut.await")
        .expect("the HTTP/3 probe must still be awaited to completion");
    assert!(
        early < h3_wait,
        "the HTTP/2 verdict must be published before the HTTP/3 probe is awaited"
    );
    assert!(
        probe.contains("h2_verdict.plain_http.h3 = previous_h3"),
        "the early stage must leave HTTP/3 at its pre-probe value, never at a \
         verdict the HTTP/3 probe has not produced yet"
    );
    assert!(
        !probe.contains(".upsert(") && !probe.contains(".commit_probe("),
        "the early stage must go through the chain, not a blind or unchained write"
    );
}

// ── Staged commit (`begin_probe_commit`) ────────────────────────────────────

/// The early-stage record a refresh publishes for an HTTPS target: the fresh
/// HTTP/2 verdict with HTTP/3 left at `h3_before`.
fn h2_stage(h2_tls: ProtocolSupport, h3_before: ProtocolSupport) -> BackendCapabilityRecord {
    caps(h3_before, h2_tls, UNKNOWN)
}

#[test]
fn staged_commit_publishes_each_stage_against_the_previous_one() {
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = BackendCapabilityRegistry::new();

    let mut commit = registry.begin_probe_commit(&key);
    assert!(
        commit.expected().was_vacant(),
        "the opening expectation is the pre-probe snapshot"
    );
    assert_eq!(commit.published_stages(), 0);

    // Stage 1: the HTTP/2 verdict, HTTP/3 not classified yet.
    let first = match commit.commit(h2_stage(SUPPORTED, UNKNOWN)) {
        CapabilityCommitOutcome::Committed(first) => first,
        rejected => panic!("nothing raced the first stage; got {}", rejected.reason()),
    };
    assert_eq!(commit.published_stages(), 1);
    let published = registry.get(&proxy, None).expect("stage 1 must be visible");
    assert!(std::sync::Arc::ptr_eq(&first, &published));
    assert_eq!(published.plain_http.h2_tls, SUPPORTED);
    assert_eq!(
        published.plain_http.h3, UNKNOWN,
        "stage 1 must not claim an HTTP/3 verdict"
    );
    assert!(
        commit
            .expected()
            .previous()
            .is_some_and(|expected| std::ptr::eq(expected, std::sync::Arc::as_ptr(&first))),
        "the next stage must be compared against the record stage 1 published"
    );

    // Stage 2: the HTTP/3 verdict merged onto the same classification.
    let second = commit.commit(caps(SUPPORTED, SUPPORTED, UNKNOWN));
    assert!(
        second.is_committed(),
        "an untouched stage 1 must accept stage 2, got {}",
        second.reason()
    );
    assert_eq!(commit.published_stages(), 2);
    let merged = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(merged.plain_http.h3, SUPPORTED);
    assert_eq!(merged.plain_http.h2_tls, SUPPORTED);
}

#[test]
fn staged_h3_downgrade_between_stages_beats_the_second_stage() {
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    // A re-probe: HTTP/3 was proven earlier and stays `Supported` in stage 1.
    let registry = registry_with(&key, caps(SUPPORTED, UNKNOWN, UNKNOWN));

    let mut commit = registry.begin_probe_commit(&key);
    assert!(commit.commit(h2_stage(SUPPORTED, SUPPORTED)).is_committed());

    // Native HTTP/3 dispatch fails while the HTTP/3 probe is still in flight.
    registry.mark_h3_unsupported(&proxy, None);

    // The probe finishes and still believes the backend speaks HTTP/3.
    let second = commit.commit(caps(SUPPORTED, SUPPORTED, UNKNOWN));
    assert!(
        matches!(second, CapabilityCommitOutcome::RejectedStale),
        "the HTTP/3 stage must lose to a downgrade recorded after stage 1, got {}",
        second.reason()
    );
    assert_eq!(commit.published_stages(), 1);

    let fetched = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(
        fetched.plain_http.h3, UNSUPPORTED,
        "the stale HTTP/3 verdict must not resurrect native H3 dispatch"
    );
    assert_eq!(
        fetched.plain_http.h2_tls, SUPPORTED,
        "the HTTP/2 verdict published in stage 1 stays under the downgrade"
    );
}

#[test]
fn staged_h2_tls_downgrade_between_stages_beats_the_second_stage() {
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = BackendCapabilityRegistry::new();

    let mut commit = registry.begin_probe_commit(&key);
    assert!(commit.commit(h2_stage(SUPPORTED, UNKNOWN)).is_committed());

    // Stage 1 made the key occupied, so the request-path downgrade now lands
    // even without a backend SNI override.
    assert!(
        registry.mark_h2_tls_unsupported(&proxy, None),
        "precondition: the live downgrade must mutate the stage-1 record"
    );

    // Stage 2 still carries the probe's `h2_tls: Supported`.
    let second = commit.commit(caps(SUPPORTED, SUPPORTED, UNKNOWN));
    assert!(matches!(second, CapabilityCommitOutcome::RejectedStale));

    let fetched = registry.get(&proxy, None).expect("entry must exist");
    assert_eq!(fetched.plain_http.h2_tls, UNSUPPORTED);
    assert_eq!(fetched.grpc_transport.h2_tls, UNSUPPORTED);
    assert_eq!(fetched.plain_http.h1, SUPPORTED);
    assert_eq!(
        fetched.plain_http.h3, UNKNOWN,
        "the whole second stage is dropped, so HTTP/3 keeps its stage-1 value \
         and native H3 dispatch stays off until the next refresh"
    );
}

#[test]
fn staged_first_stage_loses_to_a_downgrade_recorded_during_the_h2_probe() {
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = registry_with(&key, caps(SUPPORTED, SUPPORTED, UNKNOWN));

    let mut commit = registry.begin_probe_commit(&key);
    registry.mark_h3_unsupported(&proxy, None);

    let first = commit.commit(h2_stage(SUPPORTED, SUPPORTED));
    assert!(
        matches!(first, CapabilityCommitOutcome::RejectedStale),
        "stage 1 carries the pre-probe HTTP/3 value, so it must not overwrite \
         a downgrade it did not observe"
    );
    assert_eq!(commit.published_stages(), 0);
    assert_eq!(
        registry
            .get(&proxy, None)
            .expect("entry must exist")
            .plain_http
            .h3,
        UNSUPPORTED
    );
}

#[test]
fn a_lost_stage_closes_the_chain_even_if_the_key_is_vacant_again() {
    // First probe: the opening expectation is "vacant". A live insert beats
    // stage 1, then a reload prunes the key. A second stage compared against
    // "vacant" again would re-add a target the config no longer references.
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = BackendCapabilityRegistry::new();

    let mut commit = registry.begin_probe_commit(&key);
    registry.mark_hbone_unsupported(&proxy, None);

    let first = commit.commit(h2_stage(SUPPORTED, UNKNOWN));
    assert!(matches!(first, CapabilityCommitOutcome::RejectedStale));

    registry.retain_keys(&HashSet::new());
    assert!(registry.get(&proxy, None).is_none());

    let second = commit.commit(caps(SUPPORTED, SUPPORTED, UNKNOWN));
    assert!(
        matches!(second, CapabilityCommitOutcome::RejectedStale),
        "a closed chain must repeat its rejection, got {}",
        second.reason()
    );
    assert!(
        registry.get(&proxy, None).is_none(),
        "a closed chain must not write, even onto a key that matches its \
         opening expectation again"
    );
    assert_eq!(commit.published_stages(), 0);
}

#[test]
fn staged_eviction_between_stages_rejects_the_second_stage() {
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = BackendCapabilityRegistry::new();

    let mut commit = registry.begin_probe_commit(&key);
    assert!(commit.commit(h2_stage(SUPPORTED, UNKNOWN)).is_committed());

    // A reload dropped this backend from the config mid-probe.
    registry.retain_keys(&HashSet::new());

    let second = commit.commit(caps(SUPPORTED, SUPPORTED, UNKNOWN));
    assert!(
        matches!(second, CapabilityCommitOutcome::RejectedEvicted),
        "an evicted key must be reported distinctly, got {}",
        second.reason()
    );
    assert!(
        registry.get(&proxy, None).is_none(),
        "the HTTP/3 stage must not re-add a target the config no longer references"
    );

    // The rejection is sticky and keeps its kind.
    let third = commit.commit(caps(SUPPORTED, SUPPORTED, UNKNOWN));
    assert!(matches!(third, CapabilityCommitOutcome::RejectedEvicted));
    assert!(registry.get(&proxy, None).is_none());
}

#[test]
fn staged_second_stage_does_not_fall_back_to_the_pre_probe_snapshot() {
    // After stage 1 the pre-probe record is no longer published. A writer
    // that republishes a record field-identical to stage 1 still supersedes
    // it: the token is the published `Arc`, at every stage.
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = registry_with(&key, caps(UNKNOWN, UNKNOWN, UNKNOWN));

    let mut commit = registry.begin_probe_commit(&key);
    assert!(commit.commit(h2_stage(SUPPORTED, UNKNOWN)).is_committed());

    registry.upsert(key.clone(), h2_stage(SUPPORTED, UNKNOWN));

    let second = commit.commit(caps(SUPPORTED, SUPPORTED, UNKNOWN));
    assert!(
        matches!(second, CapabilityCommitOutcome::RejectedStale),
        "a republished record is a new version even when its fields match stage 1"
    );
    assert_eq!(
        registry
            .get(&proxy, None)
            .expect("entry must exist")
            .plain_http
            .h3,
        UNKNOWN
    );
}

#[test]
fn a_no_op_downgrade_between_stages_does_not_strand_the_second_stage() {
    // `mark_h3_unsupported` on an already-Unsupported entry republishes
    // nothing, so a backend that recovered can still be re-probed back to
    // `Supported` by the HTTP/3 stage.
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = registry_with(&key, caps(UNSUPPORTED, UNKNOWN, UNKNOWN));

    let mut commit = registry.begin_probe_commit(&key);
    assert!(
        commit
            .commit(h2_stage(SUPPORTED, UNSUPPORTED))
            .is_committed()
    );

    registry.mark_h3_unsupported(&proxy, None);

    let second = commit.commit(caps(SUPPORTED, SUPPORTED, UNKNOWN));
    assert!(
        second.is_committed(),
        "a no-op live-learning call must not invalidate the chain, got {}",
        second.reason()
    );
    assert_eq!(
        registry
            .get(&proxy, None)
            .expect("entry must exist")
            .plain_http
            .h3,
        SUPPORTED
    );
}

#[test]
fn a_single_stage_chain_behaves_like_commit_probe() {
    // Plain-HTTP targets (and an HTTPS target whose HTTP/3 probe answers
    // first) publish once, through the same chain.
    let proxy = minimal_proxy();
    let key = capability_key(&proxy);
    let registry = registry_with(&key, caps(SUPPORTED, SUPPORTED, UNKNOWN));

    let mut commit = registry.begin_probe_commit(&key);
    assert_eq!(
        commit
            .expected()
            .previous()
            .map(|entry| entry.plain_http.h3),
        Some(SUPPORTED),
        "the chain exposes the observed record for probe merging"
    );
    registry.mark_h3_unsupported(&proxy, None);

    let only = commit.commit(caps(SUPPORTED, SUPPORTED, UNKNOWN));
    assert!(matches!(only, CapabilityCommitOutcome::RejectedStale));
    assert_eq!(
        registry
            .get(&proxy, None)
            .expect("entry must exist")
            .plain_http
            .h3,
        UNSUPPORTED
    );
}
