//! Bounded-staleness policy parsing and restart-backoff contracts for the
//! service-discovery lifecycle work (issues #3717 / #3721 / #3722).
//!
//! Pure surfaces only — supervision, reconcile keep/replace, and withdrawal are
//! covered in `tests/integration/service_discovery_lifecycle_tests.rs`.

use std::time::Duration;

use ferrum_edge::config::env_config::{
    DEFAULT_SERVICE_DISCOVERY_MAX_STALE_SECONDS, HARD_MAX_SERVICE_DISCOVERY_MAX_STALE_SECONDS,
    MIN_SERVICE_DISCOVERY_MAX_STALE_SECONDS, parse_discovery_staleness_policy,
};
use ferrum_edge::config::types::{SdStalePolicy, ServiceDiscoveryConfig};
use ferrum_edge::service_discovery::health::{
    DISCOVERY_MIN_STALE_POLL_INTERVALS, resolve_staleness, restart_backoff,
};
use ferrum_edge::util::backoff::{BACKOFF_INITIAL_SECS, BACKOFF_MAX_SECS};

// ── Env policy parsing (issue #3717) ──────────────────────────────────

#[test]
fn staleness_policy_defaults_to_a_bounded_withdraw_window() {
    let policy = parse_discovery_staleness_policy(None, None, None).expect("defaults parse");

    assert_eq!(
        policy.max_stale_seconds, DEFAULT_SERVICE_DISCOVERY_MAX_STALE_SECONDS,
        "the shipped default must be a bounded window, not unbounded retention"
    );
    assert_eq!(policy.policy, SdStalePolicy::Withdraw);
    assert!(!policy.allow_unbounded);
}

#[test]
fn unbounded_staleness_is_refused_without_the_explicit_opt_in() {
    let error = parse_discovery_staleness_policy(Some("0"), None, None)
        .expect_err("0 must not silently mean unlimited");

    assert!(
        error.contains("FERRUM_SERVICE_DISCOVERY_ALLOW_UNBOUNDED_STALE"),
        "the error must name the opt-in an operator needs: {error}"
    );
}

#[test]
fn unbounded_staleness_is_admitted_with_the_explicit_opt_in() {
    let policy = parse_discovery_staleness_policy(Some("0"), None, Some("true"))
        .expect("explicit opt-in admits unbounded retention");

    assert_eq!(policy.max_stale_seconds, 0);
    assert!(policy.allow_unbounded);
}

#[test]
fn staleness_window_clamps_to_the_documented_bounds() {
    let low = parse_discovery_staleness_policy(Some("1"), None, None).expect("low value parses");
    assert_eq!(
        low.max_stale_seconds,
        MIN_SERVICE_DISCOVERY_MAX_STALE_SECONDS
    );

    let high =
        parse_discovery_staleness_policy(Some("9999999"), None, None).expect("high value parses");
    assert_eq!(
        high.max_stale_seconds,
        HARD_MAX_SERVICE_DISCOVERY_MAX_STALE_SECONDS
    );
}

#[test]
fn staleness_policy_tokens_round_trip_and_reject_unknown_values() {
    for (token, expected) in [
        ("retain", SdStalePolicy::Retain),
        ("withdraw", SdStalePolicy::Withdraw),
        ("WITHDRAW", SdStalePolicy::Withdraw),
        ("fail_readiness", SdStalePolicy::FailReadiness),
    ] {
        let policy =
            parse_discovery_staleness_policy(None, Some(token), None).expect("token parses");
        assert_eq!(policy.policy, expected, "token {token}");
        assert_eq!(
            SdStalePolicy::parse_token(expected.as_str()),
            Some(expected)
        );
    }

    assert!(parse_discovery_staleness_policy(None, Some("drop_everything"), None).is_err());
    assert!(parse_discovery_staleness_policy(None, Some("withdraw_discovered"), None).is_err());
}

#[test]
fn malformed_staleness_inputs_fail_closed_instead_of_reverting_to_unbounded() {
    assert!(parse_discovery_staleness_policy(Some("soon"), None, None).is_err());
    assert!(parse_discovery_staleness_policy(None, None, Some("maybe")).is_err());
}

#[test]
fn stale_policy_actions_match_their_documented_semantics() {
    assert!(!SdStalePolicy::Retain.withdraws());
    assert!(!SdStalePolicy::Retain.fails_readiness());

    assert!(SdStalePolicy::Withdraw.withdraws());
    assert!(!SdStalePolicy::Withdraw.fails_readiness());

    assert!(SdStalePolicy::FailReadiness.withdraws());
    assert!(SdStalePolicy::FailReadiness.fails_readiness());
}

// ── Effective per-task window ─────────────────────────────────────────

#[test]
fn effective_window_is_floored_at_three_poll_intervals() {
    // A 600s poll interval with a 300s bound would report permanent staleness
    // between two perfectly healthy polls.
    let staleness = resolve_staleness(300, SdStalePolicy::Withdraw, 600);

    assert_eq!(
        staleness.max_stale,
        Some(Duration::from_secs(
            600 * DISCOVERY_MIN_STALE_POLL_INTERVALS
        )),
    );
}

#[test]
fn effective_window_keeps_a_configured_value_above_the_floor() {
    let staleness = resolve_staleness(300, SdStalePolicy::Withdraw, 10);

    assert_eq!(staleness.max_stale, Some(Duration::from_secs(300)));
    assert_eq!(staleness.max_stale_seconds(), 300);
}

#[test]
fn zero_seconds_resolves_to_unbounded_retention() {
    let staleness = resolve_staleness(0, SdStalePolicy::Retain, 30);

    assert_eq!(staleness.max_stale, None);
    assert_eq!(
        staleness.max_stale_seconds(),
        0,
        "status output reports unbounded as 0"
    );
}

// ── Restart backoff (issue #3721) ─────────────────────────────────────

#[test]
fn restart_backoff_grows_and_caps_so_repeated_crashes_cannot_hot_loop() {
    let first = restart_backoff(1);
    assert!(
        first >= Duration::from_millis(BACKOFF_INITIAL_SECS * 750),
        "first restart must still wait out the initial backoff: {first:?}"
    );

    let capped = restart_backoff(64);
    assert!(
        capped <= Duration::from_millis(BACKOFF_MAX_SECS * 1250),
        "backoff must stay bounded by the shared maximum: {capped:?}"
    );
    assert!(
        capped >= Duration::from_millis(BACKOFF_MAX_SECS * 750),
        "a persistent crash loop must settle at the capped interval, not spin: {capped:?}"
    );
}

// ── Config surface (issue #3717) ──────────────────────────────────────

#[test]
fn service_discovery_config_omits_absent_staleness_overrides() {
    let config: ServiceDiscoveryConfig = serde_json::from_str(
        r#"{"provider":"dns_sd","dns_sd":{"service_name":"_http._tcp.svc.local"}}"#,
    )
    .expect("config deserializes without staleness overrides");

    assert_eq!(config.max_stale_seconds, None);
    assert_eq!(config.stale_policy, None);

    let encoded = serde_json::to_value(&config).expect("config serializes");
    assert!(
        encoded.get("max_stale_seconds").is_none(),
        "absent overrides must not be emitted: {encoded}"
    );
    assert!(encoded.get("stale_policy").is_none(), "{encoded}");
}

#[test]
fn service_discovery_config_round_trips_staleness_overrides() {
    let config: ServiceDiscoveryConfig = serde_json::from_str(
        r#"{"provider":"consul","consul":{"address":"http://consul:8500","service_name":"api"},
            "max_stale_seconds":45,"stale_policy":"fail_readiness"}"#,
    )
    .expect("config deserializes with staleness overrides");

    assert_eq!(config.max_stale_seconds, Some(45));
    assert_eq!(config.stale_policy, Some(SdStalePolicy::FailReadiness));

    let encoded = serde_json::to_value(&config).expect("config serializes");
    assert_eq!(encoded["max_stale_seconds"], 45);
    assert_eq!(encoded["stale_policy"], "fail_readiness");
}

#[test]
fn per_upstream_staleness_window_rejects_values_outside_the_documented_bounds() {
    let mut config: ServiceDiscoveryConfig = serde_json::from_str(
        r#"{"provider":"dns_sd","dns_sd":{"service_name":"_http._tcp.example"}}"#,
    )
    .expect("service-discovery fixture");

    for invalid in [4, 86_401] {
        config.max_stale_seconds = Some(invalid);
        assert!(
            config.validate_fields("default").is_err_and(|errors| {
                errors
                    .iter()
                    .any(|error| error.contains("max_stale_seconds"))
            }),
            "out-of-range per-upstream staleness {invalid} must fail validation"
        );
    }

    config.max_stale_seconds = Some(0);
    assert!(
        config.validate_fields("default").is_ok(),
        "the process unsafe opt-in gates the explicit unbounded sentinel"
    );
}

#[test]
fn direct_staleness_resolution_clamps_hostile_values_before_deadline_arithmetic() {
    let resolved = resolve_staleness(u64::MAX, SdStalePolicy::Withdraw, u64::MAX);
    assert_eq!(
        resolved.max_stale,
        Some(Duration::from_secs(
            HARD_MAX_SERVICE_DISCOVERY_MAX_STALE_SECONDS
        ))
    );
}
