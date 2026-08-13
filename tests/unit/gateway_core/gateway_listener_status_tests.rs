//! Bounded dynamic Gateway API listener realization status (issue #3810).
//!
//! The manager already refuses traffic fail-closed for an unbindable listener
//! port and retries it forever; these tests pin the *observability* contract
//! that turns that into an operator-visible, recoverable, fixed-cardinality
//! signal:
//!
//! * a failure appears with a bounded category, protocol half, and origin;
//! * a repeat observation ages the entry instead of re-counting a new failure;
//! * a recovery clears the entry and counts a recovery;
//! * a stale config generation cannot overwrite the current generation, even
//!   under concurrent publishers;
//! * the retained set and every detail string are hard-bounded, while the
//!   onset/recovery accounting stays exact for identities the detail cap
//!   dropped — and reports an honest overflow past its own hard bound;
//! * the Prometheus surface has fixed cardinality and never carries a port,
//!   config generation, or error text.

use std::sync::Arc;

use ferrum_edge::proxy::gateway_listener_status::{
    GatewayListenerFailureCategory, GatewayListenerFailureObservation,
    GatewayListenerFailureOrigin, GatewayListenerProtocolHalf, GatewayListenerStatus,
    GatewayListenerTransientEvent, MAX_ACTIVE_TRACKED_FAILURES, MAX_DETAIL_CHARS,
    MAX_TRACKED_FAILURES,
};

const NS_LABEL: &str = ",namespace=\"ferrum\"";

fn is_printable_ascii(text: &str) -> bool {
    text.chars().all(|ch| ch == ' ' || ch.is_ascii_graphic())
}

fn tcp_bind_failure(port: u16) -> GatewayListenerFailureObservation {
    GatewayListenerFailureObservation::new(
        port,
        GatewayListenerProtocolHalf::Tcp,
        GatewayListenerFailureCategory::BindFailed,
        format!("port {port} bind failed: Address already in use (os error 48)"),
    )
}

fn quic_bind_failure(port: u16) -> GatewayListenerFailureObservation {
    GatewayListenerFailureObservation::new(
        port,
        GatewayListenerProtocolHalf::Quic,
        GatewayListenerFailureCategory::BindFailed,
        format!("port {port} HTTP/3 listener bind failed"),
    )
}

fn cumulative_failures(
    status: &GatewayListenerStatus,
    protocol: GatewayListenerProtocolHalf,
    category: GatewayListenerFailureCategory,
) -> u64 {
    status
        .cumulative()
        .failures_total
        .iter()
        .find(|series| series.protocol == protocol && series.category == category)
        .map_or(0, |series| series.value)
}

fn cumulative_recoveries(
    status: &GatewayListenerStatus,
    protocol: GatewayListenerProtocolHalf,
    category: GatewayListenerFailureCategory,
) -> u64 {
    status
        .cumulative()
        .recoveries_total
        .iter()
        .find(|series| series.protocol == protocol && series.category == category)
        .map_or(0, |series| series.value)
}

/// An occupied TCP port must appear as one bounded, structured, active failure
/// while the healthy listeners on the same generation stay counted as active.
#[test]
fn an_occupied_tcp_port_is_published_as_a_bounded_active_failure() {
    let status = GatewayListenerStatus::new();
    assert!(status.publish(7, 3, 2, vec![tcp_bind_failure(8443)], 1_000));

    let snapshot = status.snapshot();
    assert_eq!(snapshot.config_generation, 7);
    assert_eq!(snapshot.desired_listeners, 3);
    assert_eq!(snapshot.active_listeners, 2);
    assert_eq!(snapshot.failed_ports, 1);
    assert_eq!(snapshot.active_failures, 1);
    assert_eq!(snapshot.retained_failures, 1);
    assert!(!snapshot.truncated);
    assert!(snapshot.degraded());

    let entry = &snapshot.failures[0];
    assert_eq!(entry.port, 8443);
    assert_eq!(entry.protocol, GatewayListenerProtocolHalf::Tcp);
    assert_eq!(entry.category, GatewayListenerFailureCategory::BindFailed);
    assert_eq!(entry.origin, GatewayListenerFailureOrigin::Runtime);
    assert_eq!(entry.config_generation, 7);
    assert_eq!(entry.first_observed_unix_ms, 1_000);
    assert_eq!(entry.last_observed_unix_ms, 1_000);
    assert_eq!(entry.observations, 1);

    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        1
    );
}

/// A retry that keeps failing is the SAME failure: it ages the entry rather
/// than inflating the cumulative failure counter, so an alert on
/// `increase(ferrum_gateway_listener_failures_total)` reports onsets, not the
/// 30s retry cadence.
#[test]
fn a_repeated_failure_ages_the_entry_without_recounting_the_onset() {
    let status = GatewayListenerStatus::new();
    assert!(status.publish(1, 1, 0, vec![tcp_bind_failure(8443)], 1_000));
    assert!(status.publish(1, 1, 0, vec![tcp_bind_failure(8443)], 31_000));
    assert!(status.publish(1, 1, 0, vec![tcp_bind_failure(8443)], 61_000));

    let snapshot = status.snapshot();
    assert_eq!(snapshot.active_failures, 1);
    let entry = &snapshot.failures[0];
    assert_eq!(entry.first_observed_unix_ms, 1_000);
    assert_eq!(entry.last_observed_unix_ms, 61_000);
    assert_eq!(entry.observations, 3);

    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        1,
        "a still-failing retry must not count as a new failure"
    );
    assert_eq!(
        cumulative_recoveries(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        0
    );
}

/// Releasing the port clears the active failure on the next reconcile and
/// counts a recovery. This is the whole reason the status is separate from the
/// sticky `serving_listener_failures` surface.
#[test]
fn a_recovered_listener_clears_the_active_failure_and_counts_a_recovery() {
    let status = GatewayListenerStatus::new();
    assert!(status.publish(1, 1, 0, vec![tcp_bind_failure(8443)], 1_000));
    assert!(status.snapshot().degraded());

    assert!(status.publish(1, 1, 1, Vec::new(), 31_000));

    let snapshot = status.snapshot();
    assert!(
        !snapshot.degraded(),
        "recovery must clear the active failure"
    );
    assert_eq!(snapshot.active_failures, 0);
    assert_eq!(snapshot.failed_ports, 0);
    assert_eq!(snapshot.active_listeners, 1);
    assert!(snapshot.failures.is_empty());
    assert!(snapshot.active_by_category.is_empty());

    assert_eq!(
        cumulative_recoveries(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        1
    );
    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        1,
        "the cumulative failure counter is monotonic across a recovery"
    );

    // A later relapse is a NEW onset.
    assert!(status.publish(1, 1, 0, vec![tcp_bind_failure(8443)], 61_000));
    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        2
    );
    assert_eq!(status.snapshot().failures[0].first_observed_unix_ms, 61_000);
}

/// A reconcile pass that awaited socket retirement can finish after a newer
/// config generation was published. Its decision must be dropped whole — no
/// snapshot replacement and no counter movement.
#[test]
fn a_stale_generation_cannot_overwrite_the_current_generation() {
    let status = GatewayListenerStatus::new();
    assert!(status.publish(9, 2, 2, Vec::new(), 1_000));

    let stale = status.publish(8, 1, 0, vec![tcp_bind_failure(8443)], 2_000);
    assert!(!stale, "a stale generation must be refused");

    let snapshot = status.snapshot();
    assert_eq!(snapshot.config_generation, 9);
    assert_eq!(snapshot.active_listeners, 2);
    assert!(!snapshot.degraded());
    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
        ),
        0,
        "a refused publication must not move any counter"
    );

    // The same generation is still accepted: the supervisor re-reconciles the
    // current generation on every retry tick, and that is how a recovery lands.
    assert!(status.publish(9, 1, 0, vec![tcp_bind_failure(8443)], 3_000));
    assert!(status.snapshot().degraded());
    // And a newer generation is accepted.
    assert!(status.publish(10, 1, 1, Vec::new(), 4_000));
    assert_eq!(status.snapshot().config_generation, 10);
}

/// The TCP and QUIC halves of one TLS-class listener fail independently. A
/// QUIC-only failure must never read as "this port is unavailable".
#[test]
fn a_quic_only_failure_is_distinguished_from_the_tcp_half() {
    let status = GatewayListenerStatus::new();
    assert!(status.publish(1, 2, 2, vec![quic_bind_failure(8443)], 1_000));

    let snapshot = status.snapshot();
    assert_eq!(
        snapshot.active_listeners, 2,
        "the TCP half is still serving"
    );
    assert_eq!(snapshot.active_failures, 1);
    assert_eq!(
        snapshot.failures[0].protocol,
        GatewayListenerProtocolHalf::Quic
    );
    assert_eq!(snapshot.active_by_category.len(), 1);
    assert_eq!(
        snapshot.active_by_category[0].protocol,
        GatewayListenerProtocolHalf::Quic
    );

    let rendered = render(&status);
    let quic_active = "ferrum_gateway_listener_failures_active{protocol=\"quic\",reason=\"bind_failed\",namespace=\"ferrum\"} 1";
    let tcp_active = "ferrum_gateway_listener_failures_active{protocol=\"tcp\",reason=\"bind_failed\",namespace=\"ferrum\"} 0";
    assert!(rendered.contains(quic_active), "{rendered}");
    assert!(rendered.contains(tcp_active), "{rendered}");
}

/// Both halves of the same port are tracked separately and both are reported.
#[test]
fn mixed_healthy_and_failed_listeners_preserve_the_healthy_count() {
    let status = GatewayListenerStatus::new();
    assert!(status.publish(
        4,
        4,
        3,
        vec![
            tcp_bind_failure(8080),
            quic_bind_failure(8443),
            GatewayListenerFailureObservation::new(
                9090,
                GatewayListenerProtocolHalf::Tcp,
                GatewayListenerFailureCategory::StreamPortCollision,
                "port 9090 is claimed by a TCP/TLS stream proxy in the same config",
            ),
        ],
        1_000,
    ));

    let snapshot = status.snapshot();
    assert_eq!(snapshot.active_listeners, 3);
    assert_eq!(snapshot.active_failures, 3);
    assert_eq!(snapshot.failed_ports, 3);
    // Ordered by (port, protocol, category) so the surface is stable.
    let ports: Vec<u16> = snapshot.failures.iter().map(|entry| entry.port).collect();
    assert_eq!(ports, vec![8080, 8443, 9090]);
    assert_eq!(
        snapshot.failures[2].origin,
        GatewayListenerFailureOrigin::Admission,
        "a stream-port collision is repaired in the configuration, not the environment"
    );
}

/// Retention is hard-bounded, but the counts and the fixed-cardinality
/// breakdown still account for everything observed — truncation loses per-port
/// detail, never the signal.
#[test]
fn the_retained_failure_set_is_hard_bounded() {
    let status = GatewayListenerStatus::new();
    let observations: Vec<_> = (0..(MAX_TRACKED_FAILURES as u16 + 25))
        .map(|index| tcp_bind_failure(20_000 + index))
        .collect();
    let total = observations.len();
    assert!(status.publish(1, total, 0, observations, 1_000));

    let snapshot = status.snapshot();
    assert_eq!(snapshot.active_failures, total);
    assert_eq!(snapshot.retained_failures, MAX_TRACKED_FAILURES);
    assert_eq!(snapshot.failures.len(), MAX_TRACKED_FAILURES);
    assert!(snapshot.truncated);
    assert_eq!(snapshot.active_by_category.len(), 1);
    assert_eq!(snapshot.active_by_category[0].count, total as u64);
}

/// A detail string is sanitized to printable ASCII and truncated, so a
/// pathological error can neither corrupt an operator's terminal nor grow the
/// snapshot.
#[test]
fn detail_is_sanitized_and_bounded() {
    let status = GatewayListenerStatus::new();
    let hostile = format!(
        "bind failed\n\r\tline two \u{1b}[31m red \u{202e}rtl {}",
        "A".repeat(400)
    );
    assert!(status.publish(
        1,
        1,
        0,
        vec![GatewayListenerFailureObservation::new(
            8443,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
            hostile,
        )],
        1_000,
    ));

    let snapshot = status.snapshot();
    let detail = &snapshot.failures[0].detail;
    assert!(
        detail.chars().count() <= MAX_DETAIL_CHARS + 3,
        "detail must be bounded, got {} chars",
        detail.chars().count()
    );
    assert!(
        is_printable_ascii(detail),
        "detail must be printable ASCII: {detail:?}"
    );
    assert!(detail.starts_with("bind failed line two"));
    assert!(detail.ends_with("..."), "truncation must be visible");
}

fn render(status: &GatewayListenerStatus) -> String {
    let mut out = String::new();
    ferrum_edge::proxy::gateway_listener_status::render_prometheus(
        &mut out,
        NS_LABEL,
        Some(status),
    );
    out
}

/// The Prometheus surface is fixed-cardinality: two protocol halves times
/// twelve bounded reasons, plus three unlabeled process gauges — regardless of
/// how many listener ports the configuration declares or how many of them fail.
#[test]
fn the_metric_surface_has_fixed_cardinality_and_leaks_no_listener_identity() {
    let status = GatewayListenerStatus::new();
    let observations: Vec<_> = (0..40u16)
        .map(|index| tcp_bind_failure(30_000 + index))
        .collect();
    assert!(status.publish(12_345, 41, 1, observations, 1_000));

    let rendered = render(&status);
    let sample_lines: Vec<&str> = rendered
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();
    let count = |name: &str| {
        sample_lines
            .iter()
            .filter(|line| line.starts_with(&format!("{name}{{")))
            .count()
    };
    assert_eq!(count("ferrum_gateway_listeners_desired"), 1);
    assert_eq!(count("ferrum_gateway_listeners_active"), 1);
    assert_eq!(count("ferrum_gateway_listener_failed_ports"), 1);
    assert_eq!(count("ferrum_gateway_listener_failures_active"), 24);
    assert_eq!(count("ferrum_gateway_listener_failures_total"), 24);
    assert_eq!(count("ferrum_gateway_listener_recoveries_total"), 24);
    assert_eq!(sample_lines.len(), 3 + 24 * 3);

    // No port, config generation, or error text may reach a label.
    for forbidden in [
        "30000",
        "30039",
        "12345",
        "Address already in use",
        "os error",
        "port=",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "metric exposition leaked {forbidden:?}:\n{rendered}"
        );
    }
    // Only the three closed label keys appear.
    for line in &sample_lines {
        let Some(open) = line.find('{') else {
            continue;
        };
        let close = line.rfind('}').expect("label block closes");
        for pair in line[open + 1..close].split(',') {
            let key = pair.split('=').next().expect("label key");
            assert!(
                matches!(key, "protocol" | "reason" | "namespace"),
                "unexpected label key {key:?} in {line}"
            );
        }
    }
}

/// A process that binds no dynamic Gateway listeners advertises nothing, so
/// modes without this manager do not grow an empty family set.
#[test]
fn no_installed_status_renders_no_families() {
    let mut out = String::new();
    ferrum_edge::proxy::gateway_listener_status::render_prometheus(&mut out, NS_LABEL, None);
    assert!(out.is_empty());
}

/// Every bounded category maps to a stable label token and a stable origin.
#[test]
fn every_category_has_a_stable_label_and_origin() {
    let expected = [
        ("port_reserved", GatewayListenerFailureOrigin::Admission),
        (
            "process_global_class_mismatch",
            GatewayListenerFailureOrigin::Admission,
        ),
        (
            "stream_port_collision",
            GatewayListenerFailureOrigin::Admission,
        ),
        (
            "udp_stream_collision",
            GatewayListenerFailureOrigin::Admission,
        ),
        ("class_conflict", GatewayListenerFailureOrigin::Admission),
        (
            "dedicated_bind_conflict",
            GatewayListenerFailureOrigin::Admission,
        ),
        (
            "dedicated_bind_tls_unsupported",
            GatewayListenerFailureOrigin::Admission,
        ),
        (
            "frontend_tls_missing",
            GatewayListenerFailureOrigin::Admission,
        ),
        ("bind_failed", GatewayListenerFailureOrigin::Runtime),
        ("listener_task_ended", GatewayListenerFailureOrigin::Runtime),
        ("class_flip_deferred", GatewayListenerFailureOrigin::Runtime),
        ("retirement_pending", GatewayListenerFailureOrigin::Runtime),
    ];
    let categories = GatewayListenerFailureCategory::ALL;
    assert_eq!(categories.len(), expected.len());
    for (category, (label, origin)) in categories.into_iter().zip(expected) {
        assert_eq!(category.as_str(), label);
        assert_eq!(category.origin(), origin);
        assert!(
            category
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_'),
            "a metric label value must stay a stable snake_case token"
        );
    }
    assert_eq!(GatewayListenerProtocolHalf::Tcp.as_str(), "tcp");
    assert_eq!(GatewayListenerProtocolHalf::Quic.as_str(), "quic");
}

// ---------------------------------------------------------------------------
// Identity/history ledger beyond the public detail cap
//
// The public `failures` vector is capped at `MAX_TRACKED_FAILURES` entries, but
// the onset/recovery accounting must not be. These tests pin the separation:
// an identity the detail cap dropped is still a known, aged identity, so a
// retry never re-counts its onset and its recovery is still counted exactly
// once.
// ---------------------------------------------------------------------------

/// Ports used by the >64-failure tests. Chosen so key order is plain numeric
/// port order: the retained detail set is the 64 lowest ports.
fn oversubscribed_ports() -> Vec<u16> {
    (9_000..9_100).collect()
}

fn oversubscribed_failures(
    ports: impl IntoIterator<Item = u16>,
) -> Vec<GatewayListenerFailureObservation> {
    ports.into_iter().map(tcp_bind_failure).collect()
}

fn tcp_bind_failures_total(status: &GatewayListenerStatus) -> u64 {
    cumulative_failures(
        status,
        GatewayListenerProtocolHalf::Tcp,
        GatewayListenerFailureCategory::BindFailed,
    )
}

fn tcp_bind_recoveries_total(status: &GatewayListenerStatus) -> u64 {
    cumulative_recoveries(
        status,
        GatewayListenerProtocolHalf::Tcp,
        GatewayListenerFailureCategory::BindFailed,
    )
}

/// 100 simultaneously failing listeners — well past the 64-entry detail cap —
/// must be counted once on onset, aged (not re-counted) on every equal-generation
/// retry, and recovered exactly once each, including the 36 identities that were
/// never published in `failures`.
#[test]
fn identities_beyond_the_detail_cap_are_aged_and_recovered_exactly_once() {
    let status = GatewayListenerStatus::new();
    let all = oversubscribed_ports();
    assert_eq!(all.len(), 100);
    assert!(all.len() > MAX_TRACKED_FAILURES);

    // Onset.
    assert!(status.publish(5, 120, 20, oversubscribed_failures(all.clone()), 1_000));
    let snapshot = status.snapshot();
    assert_eq!(snapshot.active_failures, 100, "every identity is tracked");
    assert_eq!(snapshot.retained_failures, MAX_TRACKED_FAILURES);
    assert!(snapshot.truncated);
    assert!(!snapshot.overflowed, "100 is far below the ledger bound");
    assert_eq!(snapshot.failed_ports, 100);
    assert_eq!(snapshot.active_by_category.len(), 1);
    assert_eq!(
        snapshot.active_by_category[0].count, 100,
        "the fixed-cardinality breakdown is never reduced by the detail cap"
    );
    assert_eq!(tcp_bind_failures_total(&status), 100);
    assert_eq!(tcp_bind_recoveries_total(&status), 0);
    // The retained detail set is the 64 lowest ports.
    let retained: Vec<u16> = snapshot.failures.iter().map(|entry| entry.port).collect();
    assert_eq!(retained, all[..MAX_TRACKED_FAILURES].to_vec());

    // Two equal-generation retries: the same 100 identities keep failing. This
    // is the case the pre-repair merge got wrong — it re-derived "what was
    // failing" from the truncated public vector, so the 36 omitted identities
    // looked brand new on every pass.
    assert!(status.publish(5, 120, 20, oversubscribed_failures(all.clone()), 2_000));
    assert!(status.publish(5, 120, 20, oversubscribed_failures(all.clone()), 3_000));
    assert_eq!(
        tcp_bind_failures_total(&status),
        100,
        "a retry ages an existing failure; it never re-counts an onset"
    );
    assert_eq!(tcp_bind_recoveries_total(&status), 0);
    let snapshot = status.snapshot();
    assert_eq!(snapshot.active_failures, 100);
    assert_eq!(snapshot.failures[0].observations, 3);
    assert_eq!(snapshot.failures[0].first_observed_unix_ms, 1_000);
    assert_eq!(snapshot.failures[0].last_observed_unix_ms, 3_000);

    // Partial recovery: the 50 lowest ports bind. The survivors are ports
    // 9050..9100, every one of which was outside the retained detail set on the
    // passes above — their history must still be intact.
    let survivors: Vec<u16> = all[50..].to_vec();
    assert!(status.publish(5, 120, 70, oversubscribed_failures(survivors), 4_000));
    assert_eq!(
        tcp_bind_recoveries_total(&status),
        50,
        "every cleared identity is counted once, retained or not"
    );
    assert_eq!(
        tcp_bind_failures_total(&status),
        100,
        "a partial recovery must not look like 50 new onsets"
    );
    let snapshot = status.snapshot();
    assert_eq!(snapshot.active_failures, 50);
    assert_eq!(snapshot.retained_failures, 50);
    assert!(!snapshot.truncated, "50 fits inside the detail cap");
    assert_eq!(snapshot.failed_ports, 50);
    assert_eq!(snapshot.active_by_category[0].count, 50);

    // A previously omitted identity is now retained: it must carry its ORIGINAL
    // first-seen time and its cumulative observation count, not a fresh one.
    let promoted = snapshot
        .failures
        .iter()
        .find(|entry| entry.port == 9_080)
        .expect("port 9080 is now inside the retained detail set");
    assert_eq!(
        promoted.first_observed_unix_ms, 1_000,
        "an identity promoted into the detail set keeps its original first-seen time"
    );
    assert_eq!(
        promoted.observations, 4,
        "and its cumulative observation count across all four passes"
    );
    assert_eq!(promoted.last_observed_unix_ms, 4_000);

    // Full recovery: the remaining 50 clear.
    assert!(status.publish(5, 120, 120, Vec::new(), 5_000));
    let snapshot = status.snapshot();
    assert!(!snapshot.degraded());
    assert_eq!(snapshot.active_failures, 0);
    assert_eq!(snapshot.failed_ports, 0);
    assert!(snapshot.active_by_category.is_empty());
    assert_eq!(
        tcp_bind_recoveries_total(&status),
        100,
        "recoveries balance onsets exactly, across the detail cap"
    );
    assert_eq!(tcp_bind_failures_total(&status), 100);
}

/// The same identity observed twice in one pass is one identity: one onset, one
/// observation increment, one entry.
#[test]
fn a_duplicate_observation_within_one_pass_is_not_double_counted() {
    let status = GatewayListenerStatus::new();
    let mut observations = oversubscribed_failures(oversubscribed_ports());
    observations.extend(oversubscribed_failures(oversubscribed_ports()));
    assert_eq!(observations.len(), 200);
    assert!(status.publish(2, 100, 0, observations, 1_000));

    let snapshot = status.snapshot();
    assert_eq!(snapshot.active_failures, 100);
    assert_eq!(snapshot.failed_ports, 100);
    assert_eq!(snapshot.active_by_category[0].count, 100);
    assert_eq!(tcp_bind_failures_total(&status), 100);
    assert_eq!(snapshot.failures[0].observations, 1);
}

/// A port whose failure changes category (or protocol half) is an honest
/// recovery of the old identity plus an onset of the new one — including when
/// both identities live beyond the detail cap.
#[test]
fn a_category_change_is_a_recovery_plus_a_new_failure() {
    let status = GatewayListenerStatus::new();
    let all = oversubscribed_ports();
    assert!(status.publish(1, 120, 20, oversubscribed_failures(all.clone()), 1_000));
    assert_eq!(tcp_bind_failures_total(&status), 100);

    // Port 9090 (outside the retained detail set) flips from a runtime bind
    // failure to an admission refusal; port 9091 flips to the QUIC half.
    let mut next: Vec<GatewayListenerFailureObservation> = all
        .iter()
        .filter(|port| **port != 9_090 && **port != 9_091)
        .map(|port| tcp_bind_failure(*port))
        .collect();
    next.push(GatewayListenerFailureObservation::new(
        9_090,
        GatewayListenerProtocolHalf::Tcp,
        GatewayListenerFailureCategory::PortReserved,
        "port 9090 is reserved by another Ferrum listener",
    ));
    next.push(quic_bind_failure(9_091));
    assert!(status.publish(1, 120, 20, next, 2_000));

    assert_eq!(
        tcp_bind_recoveries_total(&status),
        2,
        "both old identities cleared exactly once"
    );
    assert_eq!(
        tcp_bind_failures_total(&status),
        100,
        "the 98 unchanged identities were aged, not re-counted"
    );
    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::PortReserved,
        ),
        1
    );
    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Quic,
            GatewayListenerFailureCategory::BindFailed,
        ),
        1
    );

    let snapshot = status.snapshot();
    assert_eq!(snapshot.active_failures, 100);
    assert_eq!(
        snapshot.failed_ports, 100,
        "both halves of 9091 belong to one port"
    );
    let by_category: Vec<(
        GatewayListenerProtocolHalf,
        GatewayListenerFailureCategory,
        u64,
    )> = snapshot
        .active_by_category
        .iter()
        .map(|active| (active.protocol, active.category, active.count))
        .collect();
    assert_eq!(
        by_category,
        vec![
            (
                GatewayListenerProtocolHalf::Tcp,
                GatewayListenerFailureCategory::PortReserved,
                1
            ),
            (
                GatewayListenerProtocolHalf::Tcp,
                GatewayListenerFailureCategory::BindFailed,
                98
            ),
            (
                GatewayListenerProtocolHalf::Quic,
                GatewayListenerFailureCategory::BindFailed,
                1
            ),
        ]
    );
}

/// A stale generation must leave the *whole* ledger untouched — snapshot,
/// history, and both cumulative counters — even when the current state is a
/// large truncated failure set.
#[test]
fn a_stale_generation_changes_no_history_or_counter_beyond_the_detail_cap() {
    let status = GatewayListenerStatus::new();
    let all = oversubscribed_ports();
    assert!(status.publish(11, 120, 20, oversubscribed_failures(all.clone()), 1_000));
    let before = status.snapshot();
    let failures_before = tcp_bind_failures_total(&status);
    let recoveries_before = tcp_bind_recoveries_total(&status);

    // An older generation arriving late, carrying a completely different
    // observation set (which, if merged, would count 100 recoveries and one
    // onset).
    assert!(!status.publish(10, 1, 0, vec![tcp_bind_failure(7_777)], 2_000));

    let after = status.snapshot();
    assert_eq!(after.config_generation, 11);
    assert_eq!(*after, *before, "a refused publication replaces nothing");
    assert_eq!(tcp_bind_failures_total(&status), failures_before);
    assert_eq!(tcp_bind_recoveries_total(&status), recoveries_before);
    assert_eq!(status.published_generation(), Some(11));

    // The refused pass must not have aged the ledger either: the next accepted
    // retry is observation 2, not 3.
    assert!(status.publish(11, 120, 20, oversubscribed_failures(all), 3_000));
    assert_eq!(status.snapshot().failures[0].observations, 2);
    assert_eq!(tcp_bind_failures_total(&status), failures_before);
}

/// Beyond the hard ledger bound the snapshot reports an honest overflow rather
/// than silently mis-counting onsets and recoveries.
#[test]
fn exceeding_the_identity_ledger_bound_is_reported_not_silently_corrupted() {
    let status = GatewayListenerStatus::new();
    // Two halves per port, ordered so the dropped identities are deterministic.
    let mut observations = Vec::new();
    for port in 1..=2_100u16 {
        observations.push(tcp_bind_failure(port));
        observations.push(quic_bind_failure(port));
    }
    assert!(observations.len() > MAX_ACTIVE_TRACKED_FAILURES);
    assert!(status.publish(1, 2_100, 0, observations, 1_000));

    let snapshot = status.snapshot();
    assert!(snapshot.overflowed, "the input exceeded the ledger bound");
    assert!(snapshot.degraded());
    assert_eq!(snapshot.active_failures, MAX_ACTIVE_TRACKED_FAILURES);
    assert_eq!(snapshot.retained_failures, MAX_TRACKED_FAILURES);
    assert!(snapshot.truncated);
    let tracked: u64 = snapshot
        .active_by_category
        .iter()
        .map(|active| active.count)
        .sum();
    assert_eq!(tracked, MAX_ACTIVE_TRACKED_FAILURES as u64);
    assert_eq!(
        tcp_bind_failures_total(&status)
            + cumulative_failures(
                &status,
                GatewayListenerProtocolHalf::Quic,
                GatewayListenerFailureCategory::BindFailed,
            ),
        MAX_ACTIVE_TRACKED_FAILURES as u64,
        "onsets are counted for tracked identities only, and the snapshot says so"
    );

    // Clearing everything recovers exactly what was tracked — the counters stay
    // balanced instead of drifting.
    assert!(status.publish(1, 2_100, 2_100, Vec::new(), 2_000));
    assert!(!status.snapshot().overflowed);
    assert!(!status.snapshot().degraded());
    assert_eq!(
        tcp_bind_recoveries_total(&status)
            + cumulative_recoveries(
                &status,
                GatewayListenerProtocolHalf::Quic,
                GatewayListenerFailureCategory::BindFailed,
            ),
        MAX_ACTIVE_TRACKED_FAILURES as u64
    );
}

/// When the ledger is full, previously tracked identities that appear only after
/// a burst of brand-new keys in the observation stream must not be dropped and
/// counted as recoveries.
#[test]
fn overflow_prioritizes_ledger_keys_over_new_admissions_in_encounter_order() {
    let status = GatewayListenerStatus::new();
    let tracked_ports: Vec<u16> = (1..=MAX_ACTIVE_TRACKED_FAILURES as u16).collect();
    assert!(status.publish(
        1,
        tracked_ports.len(),
        0,
        oversubscribed_failures(tracked_ports.clone()),
        1_000,
    ));
    assert_eq!(
        tcp_bind_failures_total(&status),
        MAX_ACTIVE_TRACKED_FAILURES as u64
    );
    assert_eq!(
        status.snapshot().active_failures,
        MAX_ACTIVE_TRACKED_FAILURES
    );

    // Adversarial encounter order: brand-new keys first, every tracked key last.
    let mut observations = oversubscribed_failures((60_000..60_500).collect::<Vec<_>>());
    observations.extend(oversubscribed_failures(tracked_ports.clone()));
    assert!(status.publish(1, observations.len(), 0, observations, 2_000));

    let snapshot = status.snapshot();
    assert!(snapshot.overflowed);
    assert_eq!(snapshot.active_failures, MAX_ACTIVE_TRACKED_FAILURES);
    assert_eq!(
        tcp_bind_failures_total(&status),
        MAX_ACTIVE_TRACKED_FAILURES as u64,
        "tracked identities must not be false-recovered and re-counted as onsets"
    );
    assert_eq!(tcp_bind_recoveries_total(&status), 0);
    let entry = snapshot
        .failures
        .iter()
        .find(|entry| entry.port == tracked_ports[0])
        .expect("a tracked identity must remain active");
    assert_eq!(entry.observations, 2);
    assert_eq!(entry.first_observed_unix_ms, 1_000);
}

/// After an overflowing pass, a later pass whose distinct identities fit under
/// the ledger bound recovers only identities genuinely absent from the stream.
/// Brand-new identities that now fit are admitted (and counted as onsets);
/// survivors keep their history. The preceding overflow does not freeze the
/// next pass into overflow or suppress new admissions below the cap.
#[test]
fn partial_recovery_after_overflow_counts_only_absent_identities() {
    let status = GatewayListenerStatus::new();
    let tracked_ports: Vec<u16> = (1..=MAX_ACTIVE_TRACKED_FAILURES as u16).collect();
    assert!(status.publish(
        1,
        tracked_ports.len(),
        0,
        oversubscribed_failures(tracked_ports.clone()),
        1_000,
    ));

    let mut overflow_pass = oversubscribed_failures((61_000..61_500).collect::<Vec<_>>());
    overflow_pass.extend(oversubscribed_failures(tracked_ports.clone()));
    assert!(status.publish(1, overflow_pass.len(), 0, overflow_pass, 2_000));
    assert!(status.snapshot().overflowed);
    assert_eq!(
        tcp_bind_failures_total(&status),
        MAX_ACTIVE_TRACKED_FAILURES as u64
    );

    let survivors: Vec<u16> = tracked_ports[MAX_ACTIVE_TRACKED_FAILURES / 2..].to_vec();
    let new_keys: Vec<u16> = (62_000..62_500).collect();
    let mut partial = oversubscribed_failures(new_keys.clone());
    partial.extend(oversubscribed_failures(survivors.clone()));
    assert!(status.publish(1, partial.len(), 0, partial, 3_000));

    let recovered_priors = (MAX_ACTIVE_TRACKED_FAILURES / 2) as u64;
    let admitted_new = new_keys.len() as u64;
    assert_eq!(tcp_bind_recoveries_total(&status), recovered_priors);
    assert_eq!(
        tcp_bind_failures_total(&status),
        MAX_ACTIVE_TRACKED_FAILURES as u64 + admitted_new,
        "the 500 brand-new identities fit under the cap and each count one onset"
    );
    let snapshot = status.snapshot();
    assert!(
        !snapshot.overflowed,
        "2048 survivors plus 500 new identities are below the ledger bound"
    );
    assert_eq!(
        snapshot.active_failures,
        survivors.len() + new_keys.len(),
        "survivors keep their slots and every new identity that fits is admitted"
    );
    let survivor = snapshot
        .failures
        .iter()
        .find(|entry| entry.port == survivors[0])
        .expect("a surviving tracked identity");
    assert_eq!(survivor.observations, 3);
    assert_eq!(survivor.first_observed_unix_ms, 1_000);

    // The 500 new keys were selected: dropping them recovers exactly those
    // identities and does not re-count onsets or disturb survivor history.
    assert!(status.publish(
        1,
        survivors.len(),
        0,
        oversubscribed_failures(survivors.clone()),
        4_000,
    ));
    assert_eq!(
        tcp_bind_recoveries_total(&status),
        recovered_priors + admitted_new
    );
    assert_eq!(
        tcp_bind_failures_total(&status),
        MAX_ACTIVE_TRACKED_FAILURES as u64 + admitted_new
    );
    let snapshot = status.snapshot();
    assert!(!snapshot.overflowed);
    assert_eq!(snapshot.active_failures, survivors.len());
    let survivor = snapshot
        .failures
        .iter()
        .find(|entry| entry.port == survivors[0])
        .expect("survivor history must survive the new-key recovery");
    assert_eq!(survivor.observations, 4);
    assert_eq!(survivor.first_observed_unix_ms, 1_000);
}

/// Remaining ledger slots are not reserved for brand-new keys that arrived
/// first, and they are not left empty either. A previously tracked identity
/// that appears late in the stream keeps its slot; brand-new identities then
/// compete for the six leftover slots in deterministic key order.
///
/// A first-N-distinct or encounter-order cap would keep the earliest new keys,
/// drop the late prior identities, and count those drops as recoveries. A
/// "priors only" overflow policy would discard every new key and under-count
/// active failures below the bound.
#[test]
fn late_prior_identities_keep_slots_remaining_go_to_lowest_new_keys() {
    let status = GatewayListenerStatus::new();
    let prior_count = MAX_ACTIVE_TRACKED_FAILURES - 6;
    let prior: Vec<u16> = (1..=prior_count as u16).collect();
    let lowest_new: Vec<u16> = (60_000..60_006).collect();
    let overflowed_new: Vec<u16> = (60_006..60_100).collect();
    assert!(status.publish(
        1,
        prior.len(),
        0,
        oversubscribed_failures(prior.clone()),
        1_000,
    ));
    assert_eq!(tcp_bind_failures_total(&status), prior_count as u64);

    let mut observations = oversubscribed_failures(overflowed_new);
    observations.extend(oversubscribed_failures(lowest_new.clone()));
    observations.extend(oversubscribed_failures(prior.clone()));
    assert!(status.publish(1, observations.len(), 0, observations, 2_000));

    let snapshot = status.snapshot();
    assert!(snapshot.overflowed);
    assert_eq!(
        snapshot.active_failures, MAX_ACTIVE_TRACKED_FAILURES,
        "4090 late priors keep their slots; the six leftover slots admit the lowest new keys"
    );
    assert_eq!(
        tcp_bind_failures_total(&status),
        MAX_ACTIVE_TRACKED_FAILURES as u64,
        "the six lowest new keys each count one onset"
    );
    assert_eq!(
        tcp_bind_recoveries_total(&status),
        0,
        "a late prior identity must not be false-recovered"
    );
    let entry = snapshot
        .failures
        .iter()
        .find(|entry| entry.port == prior[0])
        .expect("a late prior identity must remain active");
    assert_eq!(entry.observations, 2);
    assert_eq!(entry.first_observed_unix_ms, 1_000);

    // Prove the six selected new keys were 60000..60005, not the higher keys
    // that filled an encounter-order view first: a follow-up of prior + those
    // six must age, not recover-and-reonset.
    let mut next = oversubscribed_failures(prior.clone());
    next.extend(oversubscribed_failures(lowest_new.clone()));
    assert!(status.publish(1, next.len(), 0, next, 3_000));
    assert_eq!(tcp_bind_recoveries_total(&status), 0);
    assert_eq!(
        tcp_bind_failures_total(&status),
        MAX_ACTIVE_TRACKED_FAILURES as u64
    );
    let snapshot = status.snapshot();
    assert!(!snapshot.overflowed);
    assert_eq!(snapshot.active_failures, MAX_ACTIVE_TRACKED_FAILURES);
    let prior_entry = snapshot
        .failures
        .iter()
        .find(|entry| entry.port == prior[0])
        .expect("prior history must keep ageing");
    assert_eq!(prior_entry.observations, 3);
    assert_eq!(prior_entry.first_observed_unix_ms, 1_000);

    assert!(status.publish(1, prior.len(), 0, oversubscribed_failures(prior), 4_000,));
    assert_eq!(
        tcp_bind_recoveries_total(&status),
        6,
        "clearing the six lowest new keys recovers exactly those selected identities"
    );
    assert_eq!(
        tcp_bind_failures_total(&status),
        MAX_ACTIVE_TRACKED_FAILURES as u64
    );
}

/// Brand-new identities compete for remaining slots in deterministic key order,
/// not encounter order. High-keyed new identities first vs low-keyed first must
/// select the same six lowest new ports.
#[test]
fn new_identities_compete_for_remaining_slots_in_key_order_not_encounter_order() {
    let prior_count = MAX_ACTIVE_TRACKED_FAILURES - 6;
    let prior: Vec<u16> = (1..=prior_count as u16).collect();
    let low_new: Vec<u16> = (50_000..50_006).collect();
    let high_new: Vec<u16> = (60_000..61_000).collect();

    let publish_with_order = |new_first: Vec<u16>, new_second: Vec<u16>| {
        let status = GatewayListenerStatus::new();
        assert!(status.publish(
            1,
            prior.len(),
            0,
            oversubscribed_failures(prior.clone()),
            1_000,
        ));
        let mut observations = oversubscribed_failures(new_first);
        observations.extend(oversubscribed_failures(new_second));
        observations.extend(oversubscribed_failures(prior.clone()));
        assert!(status.publish(1, observations.len(), 0, observations, 2_000));
        status
    };

    let high_then_low = publish_with_order(high_new.clone(), low_new.clone());
    let low_then_high = publish_with_order(low_new.clone(), high_new);

    for (label, status) in [
        ("high-then-low", &high_then_low),
        ("low-then-high", &low_then_high),
    ] {
        let snapshot = status.snapshot();
        assert!(snapshot.overflowed, "{label}");
        assert_eq!(
            snapshot.active_failures, MAX_ACTIVE_TRACKED_FAILURES,
            "{label}"
        );
        assert_eq!(
            tcp_bind_failures_total(status),
            MAX_ACTIVE_TRACKED_FAILURES as u64,
            "{label}: six lowest new keys onset once, independent of encounter order"
        );
        assert_eq!(tcp_bind_recoveries_total(status), 0, "{label}");
    }

    // Prove the six selected new keys were 50000..50005, not the high keys that
    // were encountered first: a follow-up pass of prior + low_new must age,
    // not recover-and-reonset.
    let mut next = oversubscribed_failures(prior.clone());
    next.extend(oversubscribed_failures(low_new.clone()));
    assert!(high_then_low.publish(1, next.len(), 0, next, 3_000));
    assert_eq!(
        tcp_bind_recoveries_total(&high_then_low),
        0,
        "encounter-order selection would have recovered the high keys and counted the low keys as new onsets"
    );
    assert_eq!(
        tcp_bind_failures_total(&high_then_low),
        MAX_ACTIVE_TRACKED_FAILURES as u64
    );

    assert!(high_then_low.publish(1, prior.len(), 0, oversubscribed_failures(prior), 4_000,));
    assert_eq!(
        tcp_bind_recoveries_total(&high_then_low),
        6,
        "clearing the six lowest new keys recovers exactly those selected identities"
    );
}

/// Duplicate sightings of an unretained new identity must not be stored or
/// counted as onsets, but overflow stays true.
#[test]
fn duplicate_unretained_new_identities_overflow_without_double_counting() {
    let status = GatewayListenerStatus::new();
    let tracked: Vec<u16> = (1..=MAX_ACTIVE_TRACKED_FAILURES as u16).collect();
    assert!(status.publish(
        1,
        tracked.len(),
        0,
        oversubscribed_failures(tracked.clone()),
        1_000,
    ));

    let mut observations = oversubscribed_failures((60_000..60_500).collect::<Vec<_>>());
    observations.push(tcp_bind_failure(60_000));
    observations.push(tcp_bind_failure(60_000));
    observations.extend(oversubscribed_failures(tracked));
    assert!(status.publish(1, observations.len(), 0, observations, 2_000));

    let snapshot = status.snapshot();
    assert!(snapshot.overflowed);
    assert_eq!(snapshot.active_failures, MAX_ACTIVE_TRACKED_FAILURES);
    assert_eq!(
        tcp_bind_failures_total(&status),
        MAX_ACTIVE_TRACKED_FAILURES as u64
    );
    assert_eq!(tcp_bind_recoveries_total(&status), 0);
}

/// A same-pass listener-task death that rebinds before publication is transient:
/// cumulative counters move once, but nothing stays active.
#[test]
fn a_transient_listener_task_death_does_not_enter_the_active_ledger() {
    let status = GatewayListenerStatus::new();
    assert!(status.publish_transients(
        4,
        2,
        2,
        Vec::new(),
        [GatewayListenerTransientEvent {
            port: 8443,
            protocol: GatewayListenerProtocolHalf::Tcp,
            category: GatewayListenerFailureCategory::ListenerTaskEnded,
        }],
        1_000,
    ));

    let snapshot = status.snapshot();
    assert!(!snapshot.degraded());
    assert_eq!(snapshot.active_failures, 0);
    assert!(snapshot.failures.is_empty());
    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::ListenerTaskEnded,
        ),
        1
    );
    assert_eq!(
        cumulative_recoveries(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::ListenerTaskEnded,
        ),
        1
    );

    assert!(status.publish_transients(4, 2, 2, Vec::new(), Vec::new(), 2_000));
    assert_eq!(
        cumulative_failures(
            &status,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::ListenerTaskEnded,
        ),
        1,
        "a later healthy pass must not double-count the transient death"
    );
}

/// Generation `0` and `u64::MAX` are exact published values with no sentinel
/// encoding. Readers Acquire-load the advertised generation, so both extremes
/// remain real values while still synchronizing with the snapshot store.
#[test]
fn generation_boundaries_publish_and_read_back_exactly() {
    let status = GatewayListenerStatus::new();
    assert_eq!(status.published_generation(), None);

    assert!(status.publish(0, 1, 1, Vec::new(), 1_000));
    assert_eq!(status.published_generation(), Some(0));
    assert_eq!(status.snapshot().config_generation, 0);

    let max = u64::MAX;
    assert!(status.publish(max, 1, 1, Vec::new(), 2_000));
    assert_eq!(status.published_generation(), Some(max));
    assert_eq!(status.snapshot().config_generation, max);
    assert!(!status.publish(max - 1, 1, 0, vec![tcp_bind_failure(8443)], 3_000));
    assert_eq!(status.published_generation(), Some(max));
}

// ---------------------------------------------------------------------------
// Generation fencing under concurrent publishers
//
// Acceptance and the snapshot/ledger/counter read-modify-write are one
// serialized decision. The earlier design advanced the generation fence with a
// CAS *before* taking the publish lock, which left two observable defects:
//
//   1. the fence advertised a generation whose snapshot had not been written
//      yet, and
//   2. a publisher that cleared the fence first could be overtaken by a newer
//      publisher and then overwrite the newer status with its own, because it
//      never re-checked the fence inside the serialized section.
//
// The first test pins (1) deterministically by holding one publisher inside the
// critical section for a controlled window; the second pins (2) by racing an
// older and a newer generation directly.
// ---------------------------------------------------------------------------

/// Observations that stall the publisher on the first item until released.
///
/// The status object consumes `observations` inside its critical section, so
/// this is a test-only synchronization seam that holds a publication open
/// without any production sleep, hook, or timing dependency.
struct StallingObservations {
    items: std::vec::IntoIter<GatewayListenerFailureObservation>,
    entered: Option<std::sync::mpsc::Sender<()>>,
    release: Option<std::sync::mpsc::Receiver<()>>,
}

impl Iterator for StallingObservations {
    type Item = GatewayListenerFailureObservation;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(entered) = self.entered.take() {
            let _ = entered.send(());
        }
        if let Some(release) = self.release.take() {
            let _ = release.recv();
        }
        self.items.next()
    }
}

/// While a publication is in flight, no generation may be advertised: the
/// lock-free `published_generation` mirror is a Release store written only
/// after the snapshot it describes is visible, and readers Acquire-load it.
///
/// This is the invariant the pre-repair design broke, and the seam makes the
/// breach hold for a test-controlled window rather than a race window: that
/// design advanced the fence with a CAS *before* taking the publish lock, so
/// the overtaking publisher would advertise generation 11 for the entire
/// duration of the first publisher's stall while the published snapshot was
/// still the empty initial one. Advertising a generation it has not committed
/// is exactly the state that let an older publisher win the fence and then
/// overwrite a newer snapshot.
#[test]
fn no_generation_is_advertised_before_its_snapshot_is_published() {
    use std::sync::mpsc;
    use std::time::Duration;

    let status = Arc::new(GatewayListenerStatus::new());
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let stalled = {
        let status = Arc::clone(&status);
        std::thread::spawn(move || {
            status.publish(
                10,
                2,
                1,
                StallingObservations {
                    items: vec![tcp_bind_failure(8443)].into_iter(),
                    entered: Some(entered_tx),
                    release: Some(release_rx),
                },
                1_000,
            )
        })
    };

    entered_rx
        .recv()
        .expect("the first publisher must reach its critical section");
    assert_eq!(status.published_generation(), None);

    let overtaking = {
        let status = Arc::clone(&status);
        std::thread::spawn(move || status.publish(11, 2, 2, Vec::new(), 2_000))
    };

    // The newer publisher is now contending for a publication that has not
    // committed. Nothing may become visible on either lock-free reader.
    for _ in 0..100 {
        assert_eq!(
            status.published_generation(),
            None,
            "a generation was advertised before any snapshot was published"
        );
        assert_eq!(status.snapshot().config_generation, 0);
        std::thread::sleep(Duration::from_millis(5));
    }

    release_tx.send(()).expect("release the stalled publisher");
    assert!(stalled.join().expect("stalled publisher"));
    assert!(overtaking.join().expect("overtaking publisher"));

    let snapshot = status.snapshot();
    assert_eq!(snapshot.config_generation, 11);
    assert_eq!(status.published_generation(), Some(11));
    assert!(
        !snapshot.degraded(),
        "the newer generation's clean status is the one that stands"
    );
}

/// After the initialized flag is already true, a later publication must still
/// not advertise its generation until its snapshot is visible. A Release store
/// of `initialized = true` does not synchronize readers that already observed
/// that flag; every advertised generation therefore carries its own
/// Release/Acquire ordering, including generation `0` and `u64::MAX`.
#[test]
fn a_later_generation_is_not_advertised_before_its_snapshot() {
    use std::sync::mpsc;
    use std::time::Duration;

    let status = Arc::new(GatewayListenerStatus::new());
    assert!(status.publish(10, 2, 2, Vec::new(), 1_000));
    assert_eq!(status.published_generation(), Some(10));
    assert_eq!(status.snapshot().config_generation, 10);

    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let stalled = {
        let status = Arc::clone(&status);
        std::thread::spawn(move || {
            status.publish(
                11,
                2,
                1,
                StallingObservations {
                    items: vec![tcp_bind_failure(8443)].into_iter(),
                    entered: Some(entered_tx),
                    release: Some(release_rx),
                },
                2_000,
            )
        })
    };

    entered_rx
        .recv()
        .expect("the later publisher must reach its critical section");
    for _ in 0..100 {
        assert_eq!(
            status.published_generation(),
            Some(10),
            "a later generation was advertised before its snapshot was published"
        );
        assert_eq!(status.snapshot().config_generation, 10);
        assert!(
            !status.snapshot().degraded(),
            "the in-flight generation must not replace the committed snapshot"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    release_tx.send(()).expect("release the stalled publisher");
    assert!(stalled.join().expect("stalled publisher"));
    assert_eq!(status.published_generation(), Some(11));
    assert_eq!(status.snapshot().config_generation, 11);
    assert!(status.snapshot().degraded());
}

/// Two publishers racing an older and a newer generation: the newer one always
/// stands. The older publication either lands first and is replaced, or is
/// refused outright — it can never be applied *after* the newer one.
///
/// The outcome is deterministic for the repaired design (both orderings end at
/// the newer generation), which is what makes it a usable assertion; against
/// the pre-repair design it is a direct reproducer of the lost update, since
/// that design's window sat between its fence CAS and its lock acquisition and
/// so cannot be pinned open from outside. The rounds are there to hit it.
#[test]
fn an_older_generation_never_overwrites_a_newer_published_one() {
    use std::sync::Barrier;

    for round in 0..200u64 {
        let older_generation = round * 2;
        let newer_generation = older_generation + 1;
        let status = Arc::new(GatewayListenerStatus::new());
        let barrier = Arc::new(Barrier::new(2));

        let older = {
            let status = Arc::clone(&status);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                status.publish(
                    older_generation,
                    2,
                    0,
                    vec![tcp_bind_failure(8443), quic_bind_failure(8443)],
                    1_000,
                )
            })
        };
        let newer = {
            let status = Arc::clone(&status);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                status.publish(newer_generation, 2, 2, Vec::new(), 2_000)
            })
        };

        let older_accepted = older.join().expect("older publisher");
        assert!(
            newer.join().expect("newer publisher"),
            "a strictly newer generation is always accepted"
        );

        let snapshot = status.snapshot();
        assert_eq!(
            snapshot.config_generation, newer_generation,
            "round {round}: an older generation overwrote a newer published status \
             (older_accepted={older_accepted})"
        );
        assert_eq!(status.published_generation(), Some(newer_generation));
        assert_eq!(
            snapshot.active_failures, 0,
            "round {round}: the newer generation reports both halves healthy"
        );
        assert!(!snapshot.degraded());
        assert_eq!(snapshot.active_listeners, 2);
    }
}
