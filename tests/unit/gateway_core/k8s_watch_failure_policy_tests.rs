//! Kubernetes watch failure policy and relist divergence (issue #4491).
//!
//! kube-rs's own backoff cannot space a failed initial list (every attempt
//! yields an `Init` first, which resets it), so the controller holds a scope
//! the API server refused with HTTP 403 for a long fixed interval, holds any
//! other failed list for a doubling interval, and logs the fault once per
//! state change rather than once per attempt. An idle
//! relist compares the retiring store with the authoritative list so a missed
//! `Delete`/`Apply` becomes visible instead of being silently repaired. These
//! tests pin the pure decisions; the watcher task itself is driven over
//! scripted generations in
//! `tests/integration/k8s_controller_watch_relist_tests.rs`.

use std::sync::atomic::AtomicU64;
use std::time::Duration;

use ferrum_edge::k8s_controller::metrics::{
    IDLE_RECONCILE_LOG_INTERVAL, should_log_idle_reconcile,
};
use ferrum_edge::k8s_controller::watcher::{
    FORBIDDEN_WATCH_HOLD, K8S_WATCH_IDLE_RELIST_SECS_DEFAULT, LIST_FAILURE_HOLD_CAP,
    LIST_FAILURE_HOLD_FLOOR, RELIST_DIVERGENCE_LOG_LIMIT, RelistDivergence, WatchErrorClass,
    WatchFailureStreak, WatchFailureTransition, classify_watch_error, list_failure_hold,
    relist_divergence, render_object_list,
};
use kube::core::Status;
use kube::runtime::watcher;

fn api_error(code: u16, reason: &str) -> kube::Error {
    let mut status = Status::failure("refused by the API server", reason);
    status.code = code;
    kube::Error::Api(Box::new(status))
}

fn forbidden_status() -> Status {
    Status::failure("forbidden mid-stream", "Forbidden")
}

fn identity(namespace: &str, name: &str) -> (String, String) {
    (namespace.to_string(), name.to_string())
}

#[test]
fn forbidden_status_is_classified_on_every_watch_error_shape() {
    for error in [
        watcher::Error::InitialListFailed(api_error(403, "Forbidden")),
        watcher::Error::WatchStartFailed(api_error(403, "Forbidden")),
        watcher::Error::WatchFailed(api_error(403, "Forbidden")),
        // The API server can also answer inside the watch stream itself.
        watcher::Error::WatchError(Box::new(forbidden_status())),
    ] {
        assert_eq!(
            classify_watch_error(&error),
            WatchErrorClass::Forbidden,
            "{error}"
        );
    }
    // A bare 403 code without the textual reason still counts.
    assert_eq!(
        classify_watch_error(&watcher::Error::InitialListFailed(api_error(403, ""))),
        WatchErrorClass::Forbidden
    );
}

/// kube-rs stays in its listed or watching state after these, so its own
/// backoff grows between attempts and the watcher adds nothing.
#[test]
fn other_failures_are_left_to_the_stream_backoff() {
    for error in [
        watcher::Error::WatchFailed(api_error(410, "Expired")),
        watcher::Error::WatchStartFailed(api_error(500, "InternalError")),
        watcher::Error::WatchFailed(kube::Error::LinesCodecMaxLineLengthExceeded),
        watcher::Error::WatchError(Box::new(Status::failure("expired", "Expired"))),
    ] {
        let class = classify_watch_error(&error);
        assert_eq!(class, WatchErrorClass::Other, "{error}");
        for attempts in [1, 2, 50] {
            assert_eq!(class.hold(attempts), None, "{error}");
        }
    }
    assert_eq!(WatchErrorClass::Other.as_str(), "other");
}

/// kube-rs returns to its empty state after a failed initial list (and after a
/// list carrying no `resourceVersion`) and yields `Init` before the next
/// attempt, which resets `StreamBackoff`; these are the failures it cannot
/// space on its own, so the watcher restores the intended doubling itself.
#[test]
fn failed_initial_lists_are_held_with_a_doubling_interval() {
    for error in [
        watcher::Error::InitialListFailed(api_error(404, "NotFound")),
        watcher::Error::InitialListFailed(api_error(500, "InternalError")),
        watcher::Error::InitialListFailed(kube::Error::LinesCodecMaxLineLengthExceeded),
        watcher::Error::NoResourceVersion,
    ] {
        let class = classify_watch_error(&error);
        assert_eq!(class, WatchErrorClass::ListFailed, "{error}");
        assert_eq!(class.hold(1), Some(LIST_FAILURE_HOLD_FLOOR), "{error}");
    }
    assert_eq!(WatchErrorClass::ListFailed.as_str(), "list_failed");

    assert_eq!(list_failure_hold(0), LIST_FAILURE_HOLD_FLOOR);
    assert_eq!(list_failure_hold(1), LIST_FAILURE_HOLD_FLOOR);
    assert_eq!(list_failure_hold(2), LIST_FAILURE_HOLD_FLOOR * 2);
    assert_eq!(list_failure_hold(3), LIST_FAILURE_HOLD_FLOOR * 4);
    assert_eq!(list_failure_hold(6), LIST_FAILURE_HOLD_FLOOR * 32);
    assert_eq!(list_failure_hold(7), LIST_FAILURE_HOLD_CAP);
    assert_eq!(list_failure_hold(u64::MAX), LIST_FAILURE_HOLD_CAP);
    assert_eq!(
        WatchErrorClass::ListFailed.hold(u64::MAX),
        Some(LIST_FAILURE_HOLD_CAP)
    );
    assert_eq!(
        LIST_FAILURE_HOLD_FLOOR,
        Duration::from_millis(800),
        "the floor is kube-rs's own, so a single blip recovers as fast as before"
    );
    assert!(
        LIST_FAILURE_HOLD_CAP < FORBIDDEN_WATCH_HOLD,
        "an RBAC gap is held longer than any transient list failure"
    );
}

#[test]
fn forbidden_hold_is_long_but_inside_the_default_relist_window() {
    for attempts in [1, 2, 50] {
        assert_eq!(
            WatchErrorClass::Forbidden.hold(attempts),
            Some(FORBIDDEN_WATCH_HOLD),
            "the refusal hold does not grow: it is already the long one"
        );
    }
    assert!(
        FORBIDDEN_WATCH_HOLD >= Duration::from_secs(60),
        "an RBAC gap must not be retried at kube-rs's 30s ceiling"
    );
    assert!(
        FORBIDDEN_WATCH_HOLD < Duration::from_secs(K8S_WATCH_IDLE_RELIST_SECS_DEFAULT),
        "the hold must not outlive the idle relist that would restart the scope anyway"
    );
    assert_eq!(WatchErrorClass::Forbidden.as_str(), "forbidden");
}

#[test]
fn failure_streak_logs_once_per_transition_and_once_on_recovery() {
    let mut streak = WatchFailureStreak::default();
    assert_eq!(streak.failures(), 0);
    assert_eq!(
        streak.record_success(),
        None,
        "a healthy scope has nothing to recover from"
    );

    assert_eq!(
        streak.record_failure(WatchErrorClass::Other),
        WatchFailureTransition::Entered(WatchErrorClass::Other)
    );
    assert_eq!(
        streak.record_failure(WatchErrorClass::Other),
        WatchFailureTransition::Repeated {
            class: WatchErrorClass::Other,
            attempts: 2,
        }
    );
    assert_eq!(
        streak.record_failure(WatchErrorClass::Forbidden),
        WatchFailureTransition::Changed {
            from: WatchErrorClass::Other,
            to: WatchErrorClass::Forbidden,
        }
    );
    assert_eq!(
        streak.record_failure(WatchErrorClass::Forbidden),
        WatchFailureTransition::Repeated {
            class: WatchErrorClass::Forbidden,
            attempts: 4,
        }
    );
    assert_eq!(streak.failures(), 4);

    assert_eq!(
        streak.record_success(),
        Some(4),
        "recovery reports the whole streak exactly once"
    );
    assert_eq!(streak.record_success(), None);
    assert_eq!(streak.failures(), 0);
    assert_eq!(
        streak.record_failure(WatchErrorClass::Forbidden),
        WatchFailureTransition::Entered(WatchErrorClass::Forbidden),
        "a fresh failure after recovery is announced again"
    );
}

#[test]
fn relist_divergence_names_vanished_and_appeared_objects_in_sorted_order() {
    let previous = [
        identity("gateway-conformance-infra", "blackbox-tls-delete"),
        identity("gateway-conformance-infra", "blackbox-tls-a"),
        identity("gateway-conformance-infra", "blackbox-tls-main"),
        identity("", "ferrum"),
    ];
    let relisted = [
        identity("gateway-conformance-infra", "blackbox-tls-main"),
        identity("gateway-conformance-infra", "blackbox-tls-late"),
        identity("", "ferrum"),
    ];

    let divergence = relist_divergence(&previous, &relisted);

    assert_eq!(
        divergence,
        RelistDivergence {
            vanished: vec![
                "gateway-conformance-infra/blackbox-tls-a".to_string(),
                "gateway-conformance-infra/blackbox-tls-delete".to_string(),
            ],
            appeared: vec!["gateway-conformance-infra/blackbox-tls-late".to_string()],
        }
    );
    assert!(!divergence.is_empty());
}

#[test]
fn identical_object_sets_are_not_a_divergence() {
    let objects = [
        identity("ns", "b"),
        identity("ns", "a"),
        identity("", "cluster"),
    ];
    let mut reordered = objects.to_vec();
    reordered.reverse();

    let divergence = relist_divergence(&objects, &reordered);

    assert!(divergence.is_empty(), "{divergence:?}");
    assert_eq!(divergence, RelistDivergence::default());
    assert!(relist_divergence(&[], &[]).is_empty());
}

#[test]
fn cluster_scoped_objects_render_without_a_namespace_separator() {
    let divergence = relist_divergence(&[identity("", "ferrum")], &[]);
    assert_eq!(divergence.vanished, vec!["ferrum".to_string()]);
}

#[test]
fn rendered_object_lists_are_bounded() {
    let names: Vec<String> = (0..RELIST_DIVERGENCE_LOG_LIMIT + 4)
        .map(|index| format!("ns/object-{index:02}"))
        .collect();

    let rendered = render_object_list(&names);

    assert!(rendered.ends_with(" (+4 more)"), "{rendered}");
    assert!(
        rendered.contains(&format!("ns/object-{:02}", RELIST_DIVERGENCE_LOG_LIMIT - 1)),
        "{rendered}"
    );
    assert!(
        !rendered.contains(&format!("ns/object-{RELIST_DIVERGENCE_LOG_LIMIT:02}")),
        "{rendered}"
    );

    let exact = render_object_list(&names[..RELIST_DIVERGENCE_LOG_LIMIT]);
    assert!(!exact.contains("more"), "{exact}");
    let separators = exact.matches(", ").count();
    assert_eq!(separators, RELIST_DIVERGENCE_LOG_LIMIT - 1);

    assert_eq!(render_object_list(&[]), "");
    assert_eq!(render_object_list(&["ns/a".to_string()]), "ns/a");
}

#[test]
fn idle_reconcile_log_is_rate_limited_and_claims_its_slot() {
    let stamp = AtomicU64::new(0);
    let interval_ms = u64::try_from(IDLE_RECONCILE_LOG_INTERVAL.as_millis()).expect("fits");

    assert!(
        should_log_idle_reconcile(&stamp, 5_000),
        "the first idle reconcile always logs"
    );
    assert!(
        !should_log_idle_reconcile(&stamp, 6_000),
        "inside the interval nothing logs"
    );
    assert!(
        !should_log_idle_reconcile(&stamp, 5_000 + interval_ms - 1),
        "one millisecond short is still inside"
    );
    assert!(
        should_log_idle_reconcile(&stamp, 5_000 + interval_ms),
        "the interval boundary logs again"
    );
    assert!(
        !should_log_idle_reconcile(&stamp, 5_000 + interval_ms + 10),
        "and claims the slot for the next interval"
    );

    // A clock that reads zero still records that a line was logged.
    let fresh = AtomicU64::new(0);
    assert!(should_log_idle_reconcile(&fresh, 0));
    assert!(!should_log_idle_reconcile(&fresh, 1));
}
