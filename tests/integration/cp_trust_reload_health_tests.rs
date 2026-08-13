//! Bounded, observable CP/DP trust-bundle reload health (issue #3813).
//!
//! The reload worker deliberately retains the last accepted verifier when a
//! candidate is unreadable, malformed, times out, or fails scope validation.
//! These tests pin the contract that makes that policy safe rather than silent:
//!
//! * the first refusal marks trust reload degraded immediately, under one
//!   closed reason label;
//! * repeated refusals advance stamps and counters without inventing labels;
//! * a valid candidate — including a semantically unchanged one — clears the
//!   degraded state and records exactly one recovery;
//! * the configured bound is the boundary, with no grace period, and crossing
//!   it blocks admission and readiness;
//! * an unexpectedly dead worker fails readiness immediately, while a clean
//!   shutdown is never reported as a failure;
//! * nothing published in unauthenticated output, logs, or Prometheus carries
//!   a path, a `kid`, a namespace, key material, or the private configuration
//!   fingerprint. Authenticated `/health`/`/status` detail carries a keyed
//!   HMAC-SHA-256 generation identifier that is replica-stable under a shared
//!   HMAC key and is never an unkeyed digest.
//!
//! The five gRPC stream families' behaviour at the boundary is covered in
//! `cp_tenant_trust_binding_tests.rs`, which already owns the multi-surface
//! server harness.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use serde_json::{Value, json};
use tokio::time::{Duration, Instant, advance};

use ferrum_edge::grpc::cp_trust::{CpDpTrustBundle, CpDpVerifier};
use ferrum_edge::grpc::cp_trust_health::{
    CpDpTrustReloadStatus, STATUS_GENERATION_HMAC_DOMAIN, STATUS_HMAC_KEY_MIN_BYTES,
    TRUST_RELOAD_FAILURES, TrustReloadFailure, keyed_generation_id,
};
use ferrum_edge::plugins::prometheus_metrics::render_cp_dp_trust_reload_prometheus;

const KID: &str = "tenant-a-v1";
const NAMESPACE: &str = "tenant-a";
const SECRET: &str = "tenant-a-cp-dp-secret-2026-ferrum-edge";
const POLL_INTERVAL: Duration = Duration::from_secs(30);
const BOUND: Duration = Duration::from_secs(900);
const STATUS_HMAC_KEY: &[u8] = b"ferrum-test-status-hmac-key-32b!";
const OTHER_STATUS_HMAC_KEY: &[u8] = b"other-test-status-hmac-key-32byt";
const INITIAL_FINGERPRINT: [u8; 32] = [0x11; 32];
const ROTATED_FINGERPRINT: [u8; 32] = [0x22; 32];

fn bundle_document(kid: &str, namespace: &str, secret: &str) -> String {
    json!({
        "version": 1,
        "keys": [{
            "kid": kid,
            "algorithm": "HS256",
            "namespaces": [namespace],
            "secret": secret,
        }],
    })
    .to_string()
}

fn verifier(kid: &str, namespace: &str, secret: &str) -> CpDpVerifier {
    CpDpVerifier::TrustBundle(
        CpDpTrustBundle::from_document_str(
            &bundle_document(kid, namespace, secret),
            "trust-health-test",
            None,
        )
        .expect("test trust bundle must load"),
    )
}

fn status_at(now: Instant, max_stale: Duration) -> CpDpTrustReloadStatus {
    CpDpTrustReloadStatus::watching_at(
        max_stale,
        max_stale.is_zero(),
        POLL_INTERVAL,
        now,
        STATUS_HMAC_KEY,
        &INITIAL_FINGERPRINT,
    )
}

// ── Degraded state and the closed reason set ─────────────────────────────

#[tokio::test(start_paused = true)]
async fn first_rejected_candidate_marks_degraded_immediately() {
    let status = status_at(Instant::now(), BOUND);
    let healthy = status.snapshot();
    assert!(!healthy.degraded, "a fresh acceptance is not degraded");
    assert_eq!(healthy.reason, "ok");
    assert!(!healthy.stale);
    assert!(!healthy.admission_blocked);

    status.record_attempt();
    status.record_rejected(TrustReloadFailure::DocumentUnreadable);

    let snapshot = status.snapshot();
    assert!(snapshot.degraded, "the first refusal degrades immediately");
    assert_eq!(snapshot.reason, "document_unreadable");
    assert_eq!(snapshot.consecutive_failures, 1);
    assert_eq!(snapshot.rejections_total, 1);
    assert_eq!(
        snapshot.rejections_by_reason.get("document_unreadable"),
        Some(&1)
    );
    // Retaining the previous verifier is still the policy inside the bound.
    assert!(
        !snapshot.stale && !snapshot.admission_blocked && !snapshot.readiness_blocked,
        "a transient failure inside the bound keeps serving: {snapshot:?}"
    );
    assert_eq!(
        snapshot.acceptances_total, healthy.acceptances_total,
        "a refusal is not an acceptance"
    );
}

#[tokio::test(start_paused = true)]
async fn repeated_rejections_advance_counters_without_unbounded_labels() {
    let status = status_at(Instant::now(), BOUND);
    for round in 0..60usize {
        status.record_attempt();
        // Cycle the reasons so a changing failure mode is exercised too.
        let failure = TRUST_RELOAD_FAILURES[round % TRUST_RELOAD_FAILURES.len()];
        status.record_rejected(failure);
        advance(Duration::from_secs(1)).await;
    }

    let snapshot = status.snapshot();
    assert_eq!(snapshot.consecutive_failures, 60);
    assert_eq!(snapshot.attempts_total, 60);
    assert_eq!(snapshot.rejections_total, 60);
    // Exactly the closed set — no reason label is ever derived from a path, a
    // parser message, a `kid`, or any other unbounded input.
    let observed: Vec<&str> = snapshot.rejections_by_reason.keys().copied().collect();
    let mut expected: Vec<&str> = TRUST_RELOAD_FAILURES
        .iter()
        .map(|failure| failure.as_str())
        .collect();
    expected.sort_unstable();
    assert_eq!(observed, expected);
    assert_eq!(snapshot.recoveries_total, 0);
}

#[tokio::test(start_paused = true)]
async fn every_closed_reason_has_a_distinct_fixed_label() {
    let mut labels: Vec<&str> = TRUST_RELOAD_FAILURES
        .iter()
        .map(|failure| failure.as_str())
        .collect();
    let total = labels.len();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), total, "reason labels must be distinct");
    assert_eq!(
        labels,
        [
            "document_invalid",
            "document_unreadable",
            "material_integrity_malformed",
            "material_integrity_mismatch",
            "material_integrity_unbound",
            "material_unreadable",
            "reader_unavailable",
            "reload_read_timed_out",
            "reload_reader_failed",
            "scope_validation_failed",
            "source_generation_escape",
            "source_generation_unstable",
            "source_generation_unsupported",
            "worker_exited",
        ]
    );
}

// ── Recovery ────────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn unchanged_candidate_after_an_outage_clears_degraded_and_counts_one_recovery() {
    let status = status_at(Instant::now(), BOUND);
    let accepted_before = status.snapshot().acceptances_total;
    for _ in 0..3 {
        status.record_attempt();
        status.record_rejected(TrustReloadFailure::ReadTimedOut);
        advance(Duration::from_secs(30)).await;
    }
    assert!(status.snapshot().degraded);

    // Semantically identical candidate: no verifier swap is needed, but the
    // trust source was read coherently and revalidated, which is exactly the
    // question the bound asks.
    status.record_attempt();
    status.record_accepted(false, &INITIAL_FINGERPRINT);

    let snapshot = status.snapshot();
    assert!(!snapshot.degraded, "recovery clears degraded: {snapshot:?}");
    assert_eq!(snapshot.reason, "ok");
    assert_eq!(snapshot.consecutive_failures, 0);
    assert_eq!(snapshot.recoveries_total, 1);
    assert_eq!(snapshot.acceptances_total, accepted_before + 1);
    assert_eq!(snapshot.last_acceptance_age_seconds, Some(0));

    // A second healthy poll is not a second recovery.
    status.record_attempt();
    status.record_accepted(false, &INITIAL_FINGERPRINT);
    assert_eq!(status.snapshot().recoveries_total, 1);
}

#[tokio::test(start_paused = true)]
async fn changed_candidate_recovers_and_counts_one_recovery() {
    let status = status_at(Instant::now(), BOUND);
    let accepted_before = status.snapshot().acceptances_total;
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::DocumentInvalid);

    status.record_attempt();
    status.record_accepted(true, &ROTATED_FINGERPRINT);

    let snapshot = status.snapshot();
    assert!(!snapshot.degraded);
    assert_eq!(snapshot.recoveries_total, 1);
    assert_eq!(
        snapshot.acceptances_total,
        accepted_before + 1,
        "a rotation is one acceptance, and publishes no identifier of what was rotated"
    );
}

// ── The stale boundary ──────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn the_configured_bound_is_the_boundary_with_no_grace_period() {
    let bound = Duration::from_secs(120);
    let status = status_at(Instant::now(), bound);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::MaterialUnreadable);

    advance(bound - Duration::from_secs(1)).await;
    let inside = status.snapshot();
    assert!(
        !inside.stale && !inside.admission_blocked && !inside.readiness_blocked,
        "one second inside the bound still serves: {inside:?}"
    );
    assert!(inside.degraded);

    advance(Duration::from_secs(1)).await;
    let outside = status.snapshot();
    assert!(
        outside.stale,
        "the bound itself is the boundary: {outside:?}"
    );
    assert!(outside.admission_blocked);
    assert!(outside.readiness_blocked);
    assert_eq!(outside.reason, "material_unreadable");
    assert_eq!(outside.max_stale_seconds, 120);
    assert!(!outside.unbounded_stale_allowed);
}

#[tokio::test(start_paused = true)]
async fn a_later_valid_candidate_clears_stale_and_restores_admission() {
    let bound = Duration::from_secs(60);
    let status = status_at(Instant::now(), bound);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::SourceGenerationUnstable);
    advance(bound).await;
    assert!(status.admission_blocked());

    status.record_attempt();
    status.record_accepted(false, &INITIAL_FINGERPRINT);

    let snapshot = status.snapshot();
    assert!(!snapshot.stale, "acceptance clears the sticky bit");
    assert!(!snapshot.admission_blocked);
    assert!(!snapshot.readiness_blocked);
    assert!(!snapshot.degraded);
    assert_eq!(snapshot.recoveries_total, 1);
}

#[tokio::test(start_paused = true)]
async fn unbounded_retention_never_blocks_but_stays_visibly_degraded() {
    let status = status_at(Instant::now(), Duration::ZERO);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::DocumentUnreadable);
    advance(Duration::from_secs(86_400)).await;

    let snapshot = status.snapshot();
    assert!(
        !snapshot.stale && !snapshot.admission_blocked,
        "the explicit unsafe opt-in keeps admitting: {snapshot:?}"
    );
    assert!(
        snapshot.degraded,
        "unbounded retention is still an alertable state"
    );
    assert_eq!(snapshot.max_stale_seconds, 0);
    assert!(snapshot.unbounded_stale_allowed);
    assert!(
        snapshot
            .last_acceptance_age_seconds
            .is_some_and(|age| age >= 86_400)
    );
}

#[tokio::test(start_paused = true)]
async fn a_status_with_no_trust_bundle_never_blocks_anything() {
    let status = CpDpTrustReloadStatus::disabled();
    advance(Duration::from_secs(86_400)).await;
    assert!(!status.admission_blocked());
    assert!(!status.degraded());
    let snapshot = status.snapshot();
    assert!(!snapshot.readiness_blocked);
    assert!(!snapshot.configured);
    assert_eq!(snapshot.worker_state, "disabled");
    assert_eq!(snapshot.last_acceptance_age_seconds, None);
}

// ── Worker supervision ──────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn an_unexpected_worker_exit_fails_readiness_immediately() {
    let status = status_at(Instant::now(), BOUND);
    status.record_worker_stopped(false);

    let snapshot = status.snapshot();
    assert_eq!(snapshot.worker_state, "failed");
    assert!(!snapshot.worker_running);
    assert!(snapshot.degraded);
    assert_eq!(snapshot.reason, "worker_exited");
    assert!(
        snapshot.readiness_blocked,
        "a dead watcher can never publish another revocation, so the bound \
         must not be what decides: {snapshot:?}"
    );
    // Admission itself still follows the documented bound; only readiness is
    // immediate, so an operator's orchestrator replaces the replica rather
    // than the CP dropping every tenant at once.
    assert!(!snapshot.admission_blocked);
}

#[tokio::test(start_paused = true)]
async fn a_clean_shutdown_is_not_reported_as_a_reload_failure() {
    let status = status_at(Instant::now(), BOUND);
    status.record_worker_stopped(true);

    let snapshot = status.snapshot();
    assert_eq!(snapshot.worker_state, "stopped");
    assert!(
        !snapshot.degraded,
        "shutdown is not a failure: {snapshot:?}"
    );
    assert_eq!(snapshot.reason, "ok");
    assert!(!snapshot.readiness_blocked);
    assert_eq!(snapshot.rejections_total, 0);
    assert_eq!(snapshot.consecutive_failures, 0);
}

#[tokio::test(start_paused = true)]
async fn a_worker_whose_attempts_stop_landing_reads_as_stalled() {
    let status = status_at(Instant::now(), Duration::ZERO);
    assert_eq!(status.snapshot().worker_state, "running");
    // Well past three poll intervals with no completed attempt: the shape of a
    // read parked in the kernel on a stalled network filesystem.
    advance(POLL_INTERVAL * 10).await;
    let snapshot = status.snapshot();
    assert_eq!(snapshot.worker_state, "stalled");
    assert!(
        snapshot.worker_running,
        "a stalled worker is still alive, and is reported separately from a dead one"
    );
    assert!(
        snapshot.degraded,
        "stalled is immediately degraded so it is alertable: {snapshot:?}"
    );
    assert!(
        !snapshot.readiness_blocked && !snapshot.admission_blocked,
        "readiness still follows the stale bound: {snapshot:?}"
    );
    let coarse = status.coarse();
    assert!(coarse.degraded && coarse.worker_stalled && !coarse.readiness_blocked);
}

#[tokio::test(start_paused = true)]
async fn stall_is_strictly_after_the_configured_window() {
    let status = status_at(Instant::now(), BOUND);
    let stall_after = status.stall_after();
    assert_eq!(stall_after, POLL_INTERVAL * 3);

    advance(stall_after).await;
    let at_bound = status.snapshot();
    assert_eq!(
        at_bound.worker_state, "running",
        "the stall window is exclusive: {at_bound:?}"
    );
    assert!(!at_bound.degraded);

    advance(Duration::from_nanos(1)).await;
    let past = status.snapshot();
    assert_eq!(past.worker_state, "stalled");
    assert!(past.degraded);
    assert!(!past.readiness_blocked);
    assert!(past.worker_running);

    let mut metrics = String::new();
    render_cp_dp_trust_reload_prometheus(&mut metrics, "", Some(&past));
    assert!(
        metrics.contains("ferrum_cp_dp_trust_reload_worker_stalled 1\n"),
        "{metrics}"
    );
    assert!(
        metrics.contains("ferrum_cp_dp_trust_degraded 1\n"),
        "{metrics}"
    );
    assert!(metrics.contains("ferrum_cp_dp_trust_reload_worker_running 1\n"));
}

#[tokio::test(start_paused = true)]
async fn a_completed_valid_candidate_clears_stalled() {
    let status = status_at(Instant::now(), BOUND);
    advance(status.stall_after() + Duration::from_secs(1)).await;
    assert_eq!(status.snapshot().worker_state, "stalled");
    assert!(status.snapshot().degraded);

    status.record_attempt();
    status.record_accepted(false, &INITIAL_FINGERPRINT);

    let recovered = status.snapshot();
    assert_eq!(recovered.worker_state, "running");
    assert!(!recovered.degraded);
    assert_eq!(recovered.reason, "ok");
}

#[tokio::test(start_paused = true)]
async fn a_completed_rejection_clears_stall_but_stays_degraded() {
    let status = status_at(Instant::now(), BOUND);
    advance(status.stall_after() + Duration::from_secs(1)).await;
    assert_eq!(status.snapshot().worker_state, "stalled");

    status.record_attempt();
    status.record_rejected(TrustReloadFailure::ReadTimedOut);

    let snapshot = status.snapshot();
    assert_eq!(snapshot.worker_state, "running");
    assert!(snapshot.degraded);
    assert_eq!(snapshot.reason, "reload_read_timed_out");
    assert!(!snapshot.readiness_blocked);
}

#[tokio::test(start_paused = true)]
async fn attempts_count_starts_not_verdicts() {
    let status = status_at(Instant::now(), BOUND);
    let healthy = status.snapshot();
    assert_eq!(healthy.attempts_total, 0);
    assert_eq!(healthy.acceptances_total, 1, "startup seeds one acceptance");
    assert_eq!(healthy.rejections_total, 0);

    status.record_attempt();
    let in_flight = status.snapshot();
    assert_eq!(in_flight.attempts_total, 1);
    assert_eq!(
        in_flight.acceptances_total + in_flight.rejections_total,
        healthy.acceptances_total,
        "an in-flight attempt has no verdict yet: {in_flight:?}"
    );

    status.record_rejected(TrustReloadFailure::DocumentInvalid);
    let completed = status.snapshot();
    assert_eq!(completed.attempts_total, 1);
    assert_eq!(completed.rejections_total, 1);
    assert_eq!(completed.acceptances_total, 1);
}

// ── Disclosure boundary ─────────────────────────────────────────────────

/// The longest run of ASCII hex digits in `text`.
fn longest_hex_run(text: &str) -> usize {
    let mut longest = 0usize;
    let mut current = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_hexdigit() {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

#[tokio::test(start_paused = true)]
async fn the_keyed_generation_id_is_stable_across_replicas_and_changes_with_the_bundle() {
    let expected = keyed_generation_id(STATUS_HMAC_KEY, &INITIAL_FINGERPRINT)
        .expect("test HMAC key is 32 bytes");
    assert_eq!(expected.len(), 64);
    assert!(expected.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert_ne!(expected, hex::encode(INITIAL_FINGERPRINT));

    let replica_a = status_at(Instant::now(), BOUND);
    let replica_b = status_at(Instant::now(), BOUND);
    assert_eq!(
        replica_a.snapshot().active_generation.as_deref(),
        Some(expected.as_str())
    );
    assert_eq!(
        replica_a.snapshot().active_generation,
        replica_b.snapshot().active_generation,
        "replicas sharing a bundle and HMAC key must converge"
    );

    replica_a.record_attempt();
    replica_a.record_accepted(false, &INITIAL_FINGERPRINT);
    assert_eq!(
        replica_a.snapshot().active_generation.as_deref(),
        Some(expected.as_str()),
        "an unchanged acceptance must keep the identifier"
    );

    replica_a.record_attempt();
    replica_a.record_accepted(true, &ROTATED_FINGERPRINT);
    let rotated = replica_a.snapshot().active_generation.expect("rotated id");
    assert_ne!(
        rotated, expected,
        "a semantic change must mint a new identifier"
    );
    assert_eq!(
        rotated,
        keyed_generation_id(STATUS_HMAC_KEY, &ROTATED_FINGERPRINT).expect("key")
    );

    let other_key =
        keyed_generation_id(OTHER_STATUS_HMAC_KEY, &INITIAL_FINGERPRINT).expect("other key");
    assert_ne!(
        other_key, expected,
        "replicas with different HMAC keys are incomparable"
    );
}

#[tokio::test(start_paused = true)]
async fn a_short_hmac_key_does_not_fall_back_to_an_unkeyed_digest() {
    assert!(STATUS_HMAC_KEY.len() >= STATUS_HMAC_KEY_MIN_BYTES);
    assert!(keyed_generation_id(&STATUS_HMAC_KEY[..8], &INITIAL_FINGERPRINT).is_none());

    let status = CpDpTrustReloadStatus::watching_at(
        BOUND,
        false,
        POLL_INTERVAL,
        Instant::now(),
        &STATUS_HMAC_KEY[..8],
        &INITIAL_FINGERPRINT,
    );
    let snapshot = status.snapshot();
    assert!(
        snapshot.active_generation.is_none(),
        "a short key must not publish any identifier: {snapshot:?}"
    );
    let rendered = serde_json::to_string(&snapshot).expect("snapshot serializes");
    assert!(!rendered.contains(&hex::encode(INITIAL_FINGERPRINT)));
}

#[tokio::test(start_paused = true)]
async fn the_keyed_identifier_is_detailed_health_only() {
    let status = status_at(Instant::now(), BOUND);
    status.record_attempt();
    status.record_accepted(true, &ROTATED_FINGERPRINT);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::MaterialIntegrityMismatch);
    let snapshot = status.snapshot();
    let id = snapshot
        .active_generation
        .as_deref()
        .expect("watching status publishes a keyed identifier");
    assert_eq!(id.len(), 64);
    assert_eq!(
        id,
        keyed_generation_id(STATUS_HMAC_KEY, &ROTATED_FINGERPRINT).expect("key")
    );

    let rendered = serde_json::to_string(&snapshot).expect("snapshot serializes");
    let mut metrics = String::new();
    render_cp_dp_trust_reload_prometheus(&mut metrics, ",namespace=\"edge\"", Some(&snapshot));
    let domain = std::str::from_utf8(
        STATUS_GENERATION_HMAC_DOMAIN
            .strip_suffix(&[0])
            .unwrap_or(STATUS_GENERATION_HMAC_DOMAIN),
    )
    .expect("domain is ascii");
    assert!(
        !rendered.contains(domain) && !metrics.contains(domain),
        "the HMAC domain string must not appear on a published surface"
    );

    assert!(
        rendered.contains(id),
        "authorized detailed health JSON publishes the keyed identifier"
    );
    assert!(
        !metrics.contains(id),
        "Prometheus must not carry the keyed identifier: {metrics}"
    );
    assert!(
        !metrics.contains("active_generation"),
        "Prometheus must not name the identifier: {metrics}"
    );

    for forbidden in ["fingerprint", "digest", "sha256", SECRET, KID, NAMESPACE] {
        assert!(
            !rendered.contains(forbidden),
            "published trust health must not carry `{forbidden}`: {rendered}"
        );
        assert!(
            !metrics.contains(forbidden),
            "published trust metrics must not carry `{forbidden}`: {metrics}"
        );
    }

    let health_without_id = rendered.replace(id, "");
    assert!(
        longest_hex_run(&health_without_id) < 16,
        "aside from the keyed identifier, health JSON must not carry a digest: {health_without_id}"
    );
    assert!(
        longest_hex_run(&metrics) < 16,
        "metrics must not carry a generation identifier, fingerprint, or digest: {metrics}"
    );
}

#[tokio::test(start_paused = true)]
async fn the_published_projection_carries_no_path_credential_or_namespace() {
    let status = status_at(Instant::now(), BOUND);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::MaterialIntegrityMismatch);
    let rendered = serde_json::to_string(&status.snapshot()).expect("snapshot serializes");

    for forbidden in [
        SECRET,
        KID,
        NAMESPACE,
        "/etc/ferrum/trust-bundle.json",
        "public_key",
        "secret",
        "kid",
        "Bearer",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "published trust health must not carry `{forbidden}`: {rendered}"
        );
    }

    // And the same for the metric text.
    let mut metrics = String::new();
    let snapshot = status.snapshot();
    render_cp_dp_trust_reload_prometheus(&mut metrics, ",namespace=\"edge\"", Some(&snapshot));
    for forbidden in [SECRET, KID, NAMESPACE] {
        assert!(
            !metrics.contains(forbidden),
            "trust-reload metrics must not carry `{forbidden}`: {metrics}"
        );
    }
}

// ── Metric shape ────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn metric_labels_are_bounded_to_the_closed_reason_set() {
    let status = status_at(Instant::now(), BOUND);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::DocumentInvalid);
    advance(BOUND).await;
    let snapshot = status.snapshot();

    let mut output = String::new();
    render_cp_dp_trust_reload_prometheus(&mut output, "", Some(&snapshot));

    for family in [
        "ferrum_cp_dp_trust_reload_attempts_total",
        "ferrum_cp_dp_trust_reload_acceptances_total",
        "ferrum_cp_dp_trust_reload_rejections_total",
        "ferrum_cp_dp_trust_reload_recoveries_total",
        "ferrum_cp_dp_trust_reload_consecutive_failures",
        "ferrum_cp_dp_trust_last_acceptance_age_seconds",
        "ferrum_cp_dp_trust_max_stale_seconds",
        "ferrum_cp_dp_trust_degraded",
        "ferrum_cp_dp_trust_stale",
        "ferrum_cp_dp_trust_reload_worker_running",
        "ferrum_cp_dp_trust_reload_worker_stalled",
    ] {
        assert!(
            output.contains(&format!("# TYPE {family} ")),
            "missing family {family}: {output}"
        );
    }
    assert!(output.contains("ferrum_cp_dp_trust_stale 1\n"));
    assert!(output.contains("ferrum_cp_dp_trust_degraded 1\n"));
    let invalid_series =
        "ferrum_cp_dp_trust_reload_rejections_total{reason=\"document_invalid\"} 1";
    assert!(output.contains(invalid_series), "{output}");
    // Every reason series is emitted, and only the closed set of them.
    let series = output
        .lines()
        .filter(|line| line.starts_with("ferrum_cp_dp_trust_reload_rejections_total{"))
        .count();
    assert_eq!(series, TRUST_RELOAD_FAILURES.len());

    // Nothing at all outside a CP that watches a bundle.
    let mut empty = String::new();
    render_cp_dp_trust_reload_prometheus(&mut empty, "", None);
    assert!(empty.is_empty());
}

// ── The live worker ─────────────────────────────────────────────────────

/// Wait for the published status to satisfy `predicate`, or fail.
async fn wait_for_status(
    status: &Arc<CpDpTrustReloadStatus>,
    what: &str,
    predicate: impl Fn(&ferrum_edge::grpc::cp_trust_health::CpDpTrustReloadSnapshot) -> bool,
) {
    let deadline = std::time::Instant::now() + StdDuration::from_secs(20);
    loop {
        let snapshot = status.snapshot();
        if predicate(&snapshot) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}: {snapshot:?}"
        );
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
}

fn spawn_worker(
    path: &std::path::Path,
    status: Arc<CpDpTrustReloadStatus>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    ferrum_edge::grpc::cp_trust::spawn_trust_bundle_reload(
        path.to_string_lossy().to_string(),
        None,
        Arc::new(ferrum_edge::grpc::cp_trust::CpDpVerifierStore::new(
            verifier(KID, NAMESPACE, SECRET),
        )),
        false,
        StdDuration::from_millis(1),
        status,
        shutdown,
    )
}

fn live_status() -> Arc<CpDpTrustReloadStatus> {
    Arc::new(CpDpTrustReloadStatus::watching(
        Duration::from_secs(900),
        false,
        Duration::from_secs(1),
        STATUS_HMAC_KEY,
        &INITIAL_FINGERPRINT,
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_bundle_document_publishes_the_closed_unreadable_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("absent-bundle.json");
    let status = live_status();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = spawn_worker(&path, status.clone(), shutdown_rx);

    wait_for_status(&status, "a rejected reload", |snapshot| {
        snapshot.degraded && snapshot.reason == "document_unreadable"
    })
    .await;
    let snapshot = status.snapshot();
    assert!(snapshot.consecutive_failures >= 1);
    assert!(!snapshot.stale, "still inside the bound: {snapshot:?}");

    // Writing a valid document recovers without any restart.
    std::fs::write(&path, bundle_document(KID, NAMESPACE, SECRET)).expect("write bundle");
    wait_for_status(&status, "recovery", |snapshot| {
        !snapshot.degraded && snapshot.recoveries_total == 1
    })
    .await;

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(StdDuration::from_secs(5), handle).await;
    assert_eq!(status.snapshot().worker_state, "stopped");
    assert!(!status.snapshot().degraded);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_bundle_document_publishes_the_closed_unreadable_reason() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("denied-bundle.json");
    std::fs::write(&path, bundle_document(KID, NAMESPACE, SECRET)).expect("write bundle");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
        .expect("drop read permission");
    if std::fs::read(&path).is_ok() {
        // Running as root: the permission bit is not enforced, so there is no
        // read failure to observe.
        return;
    }
    let status = live_status();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = spawn_worker(&path, status.clone(), shutdown_rx);

    wait_for_status(&status, "a permission-denied reload", |snapshot| {
        snapshot.degraded && snapshot.reason == "document_unreadable"
    })
    .await;

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(StdDuration::from_secs(5), handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_candidate_retains_the_previous_verifier_and_degrades() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bundle.json");
    std::fs::write(&path, bundle_document(KID, NAMESPACE, SECRET)).expect("write bundle");
    let status = live_status();
    let accepted_before = status.snapshot().acceptances_total;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = spawn_worker(&path, status.clone(), shutdown_rx);

    std::fs::write(&path, "{ not json").expect("write malformed bundle");
    wait_for_status(&status, "a malformed candidate", |snapshot| {
        snapshot.degraded && snapshot.reason == "document_invalid"
    })
    .await;
    assert_eq!(
        status.snapshot().acceptances_total,
        accepted_before,
        "a malformed candidate must never be accepted, even partially"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(StdDuration::from_secs(5), handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rotated_bundle_is_accepted_and_publishes_a_keyed_identifier() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bundle.json");
    std::fs::write(&path, bundle_document(KID, NAMESPACE, SECRET)).expect("write bundle");
    let status = live_status();
    let accepted_before = status.snapshot().acceptances_total;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = spawn_worker(&path, status.clone(), shutdown_rx);

    std::fs::write(
        &path,
        bundle_document(
            "tenant-a-v2",
            NAMESPACE,
            "rotated-tenant-a-secret-2026-ferrum",
        ),
    )
    .expect("rotate bundle");
    wait_for_status(&status, "a rotated generation", |snapshot| {
        snapshot.acceptances_total > accepted_before
    })
    .await;
    let snapshot = status.snapshot();
    assert!(!snapshot.degraded);
    assert!(snapshot.acceptances_total >= 2);
    // The rotation is observable as an acceptance, a reset age, and a new keyed
    // identifier — never as the private fingerprint.
    assert_eq!(snapshot.reason, "ok");
    assert_ne!(
        snapshot.active_generation.as_deref(),
        keyed_generation_id(STATUS_HMAC_KEY, &INITIAL_FINGERPRINT).as_deref()
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(StdDuration::from_secs(5), handle).await;
}

// ── Authenticated / coarse health separation ────────────────────────────

/// The `/health` projection is authenticated-detail only, and readiness is the
/// only thing an unauthenticated probe learns. This asserts the projection
/// itself is fixed-cardinality and JSON-shaped as documented; the transport
/// tiering is exercised in `admin_observability_auth_tests.rs`.
#[tokio::test(start_paused = true)]
async fn the_health_projection_is_fixed_cardinality() {
    let status = status_at(Instant::now(), BOUND);
    status.record_attempt();
    status.record_rejected(TrustReloadFailure::ReaderUnavailable);
    let value: Value = serde_json::to_value(status.snapshot()).expect("snapshot serializes");
    let object = value.as_object().expect("object projection");

    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "acceptances_total",
            "active_generation",
            "admission_blocked",
            "attempts_total",
            "configured",
            "consecutive_failures",
            "degraded",
            "last_acceptance_age_seconds",
            "last_attempt_age_seconds",
            "max_stale_seconds",
            "readiness_blocked",
            "reason",
            "recoveries_total",
            "rejections_by_reason",
            "rejections_total",
            "stale",
            "unbounded_stale_allowed",
            "worker_running",
            "worker_state",
        ]
    );
    assert_eq!(object["reason"], json!("reader_unavailable"));
    assert_eq!(object["configured"], json!(true));
    assert!(
        object["active_generation"]
            .as_str()
            .is_some_and(|id| id.len() == 64)
    );
}

#[test]
fn coarse_health_projection_is_copy_and_has_no_reason_map() {
    fn assert_copy<T: Copy>(value: T) -> T {
        value
    }
    let status = CpDpTrustReloadStatus::watching(
        BOUND,
        false,
        POLL_INTERVAL,
        STATUS_HMAC_KEY,
        &INITIAL_FINGERPRINT,
    );
    let coarse = assert_copy(status.coarse());
    assert!(coarse.configured);
    assert!(!coarse.degraded);
    assert!(!coarse.worker_stalled);
    assert!(
        std::mem::size_of::<ferrum_edge::grpc::cp_trust_health::CpDpTrustCoarse>() <= 16,
        "coarse verdict must stay a handful of booleans, not a snapshot"
    );
}

#[test]
fn unauthenticated_health_path_must_not_allocate_a_full_trust_snapshot() {
    let admin = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/admin/mod.rs"));
    let start = admin
        .find("Bounded CP/DP trust-reload health (issue #3813)")
        .expect("trust-reload health comment");
    let block = &admin[start..];
    let end = block
        .find("if jwks_degraded")
        .expect("jwks degraded follows trust health");
    let block = &block[..end];
    assert!(
        block.contains("cp_trust_health::coarse()"),
        "unauthenticated /health must evaluate coarse trust state"
    );
    assert_eq!(
        block.matches("cp_trust_health::snapshot()").count(),
        1,
        "exactly one snapshot() call, for authenticated detail: {block}"
    );
    let snapshot_at = block
        .find("cp_trust_health::snapshot()")
        .expect("authenticated snapshot");
    let gate = block[..snapshot_at]
        .rfind("if detailed")
        .expect("snapshot must sit under an if detailed gate");
    assert!(
        !block[gate..snapshot_at].contains("cp_trust_coarse"),
        "coarse evaluation must not be inside the snapshot allocation gate"
    );
}
