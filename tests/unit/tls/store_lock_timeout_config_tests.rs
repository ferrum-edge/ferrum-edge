//! Issue #2409: `FERRUM_TLS_STORE_LOCK_TIMEOUT_SECONDS` must not lie.
//!
//! The setting is the only bound between a wedged shared TLS volume and an
//! unbounded wait inside a store mutation, so it is an availability control an
//! operator is entitled to audit. Silently substituting the default for a value
//! the operator actually configured turns that control into a claim the gateway
//! does not honour: someone who writes `30s` or `sixty` is told nothing and
//! runs on a ten-second bound they never chose.
//!
//! The contract therefore has three distinct outcomes, and this file pins all
//! three. Absent is the default. A valid number outside the supported range is
//! clamped, because clamping a number the operator did express is the
//! documented behaviour of this setting. Anything else present is an error.
//!
//! # Why these assert on the parser rather than on the environment
//!
//! `tls_store_lock_timeout_from_env` is split into an environment read and
//! `parse_tls_store_lock_timeout`, and the tests drive the latter. That is not
//! a convenience: every shared-store open in this same test binary reads the
//! real `FERRUM_TLS_STORE_LOCK_TIMEOUT_SECONDS`, and `cargo test` runs those
//! tests concurrently. A test that parked a malformed value in the process
//! environment — however briefly, and however carefully locked on its own side
//! — would be visible to any store open that raced it, turning an unrelated
//! suite red at random. The environment read itself is a single
//! `resolve_ferrum_var` call with no logic in it; the logic is here.

use std::time::Duration;

use ferrum_edge::config::env_config::{
    DEFAULT_TLS_STORE_LOCK_TIMEOUT_SECONDS, TLS_STORE_LOCK_TIMEOUT_KEY,
    parse_tls_store_lock_timeout,
};

#[test]
fn an_absent_setting_selects_the_documented_default() {
    let timeout = parse_tls_store_lock_timeout(None).expect("an absent setting is not a failure");
    assert_eq!(
        timeout,
        Duration::from_secs(DEFAULT_TLS_STORE_LOCK_TIMEOUT_SECONDS),
        "unset must mean the documented default, not an arbitrary bound"
    );
}

#[test]
fn a_valid_value_inside_the_supported_range_is_honoured_verbatim() {
    for (raw, expected) in [("1", 1), ("10", 10), ("45", 45), ("120", 120), (" 45 ", 45)] {
        let timeout = parse_tls_store_lock_timeout(Some(raw))
            .unwrap_or_else(|error| panic!("'{raw}' is a valid bound: {error}"));
        assert_eq!(
            timeout,
            Duration::from_secs(expected),
            "'{raw}' must be honoured as {expected} seconds"
        );
    }
}

/// Clamping is deliberate and documented: the operator expressed a real number,
/// so the nearest supported bound is a defensible answer. This is the one place
/// a configured value is legitimately not used verbatim, and it applies only to
/// values that parsed.
#[test]
fn a_valid_value_outside_the_supported_range_is_clamped() {
    assert_eq!(
        parse_tls_store_lock_timeout(Some("0")).expect("zero is a number"),
        Duration::from_secs(1),
        "below the floor clamps up to the minimum supported bound"
    );
    assert_eq!(
        parse_tls_store_lock_timeout(Some("100000")).expect("a large number is still a number"),
        Duration::from_secs(120),
        "above the ceiling clamps down to the maximum supported bound"
    );
}

/// The regression this file exists for: a malformed value must be an error, not
/// a silent fallback to the default.
#[test]
fn a_malformed_value_is_an_error_rather_than_a_silent_default() {
    for malformed in ["30s", "sixty", "-5", "1.5", "10 20", "", "   ", "0x10"] {
        let error = parse_tls_store_lock_timeout(Some(malformed)).expect_err(
            "a value that is not a whole number of seconds must fail closed, not fall back",
        );
        assert!(
            error.contains(TLS_STORE_LOCK_TIMEOUT_KEY),
            "the diagnostic must name the setting so an operator can find it: {error}"
        );
    }
}

/// The diagnostic must not echo the configured value.
///
/// Every `FERRUM_*` key is externally sourceable (`_VAULT`, `_FILE`, …), so a
/// value that reaches a store-open error and from there a startup log must be
/// treated as potentially secret-derived. Naming the rule is enough to fix the
/// misconfiguration.
#[test]
fn a_malformed_value_is_never_echoed_back() {
    let error = parse_tls_store_lock_timeout(Some("supersecretvalue"))
        .expect_err("a non-numeric value fails closed");
    assert!(
        !error.contains("supersecretvalue"),
        "the diagnostic must not echo the configured value: {error}"
    );
}
