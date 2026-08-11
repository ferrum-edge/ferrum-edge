//! Issue #3736: `FERRUM_TLS_MAX_MATERIAL_SIZE_BYTES` parse/validation contract.
//!
//! Absent → default. Above the hard maximum clamps down. `0` and other values
//! below the minimum are rejected. Malformed values fail closed. Diagnostics
//! name the setting and never echo the configured value (every `FERRUM_*` key
//! is externally sourceable).

use ferrum_edge::config::env_config::{
    DEFAULT_TLS_MAX_MATERIAL_SIZE_BYTES, HARD_MAX_TLS_MAX_MATERIAL_SIZE_BYTES,
    MIN_TLS_MAX_MATERIAL_SIZE_BYTES, TLS_MAX_MATERIAL_SIZE_BYTES_KEY,
    parse_tls_max_material_size_bytes,
};
use ferrum_edge::config::public_env_inventory::PUBLIC_FERRUM_ENV_SETTINGS;

#[test]
fn absent_setting_selects_the_documented_default() {
    let value = parse_tls_max_material_size_bytes(None).expect("absent is not a failure");
    assert_eq!(value, DEFAULT_TLS_MAX_MATERIAL_SIZE_BYTES);
    assert_eq!(value, HARD_MAX_TLS_MAX_MATERIAL_SIZE_BYTES);
    assert!(
        value > 0,
        "the default must be a finite positive ceiling, never unlimited"
    );
}

#[test]
fn valid_values_inside_the_supported_range_are_honoured() {
    for (raw, expected) in [
        ("1", 1),
        ("1024", 1024),
        ("4194304", 4_194_304),
        (" 2048 ", 2048),
    ] {
        let value = parse_tls_max_material_size_bytes(Some(raw))
            .unwrap_or_else(|error| panic!("'{raw}' is valid: {error}"));
        assert_eq!(value, expected, "'{raw}' must parse as {expected}");
    }
}

#[test]
fn zero_is_rejected_and_oversized_values_clamp_down() {
    let error = parse_tls_max_material_size_bytes(Some("0")).expect_err("0 must fail closed");
    assert!(
        error.contains(TLS_MAX_MATERIAL_SIZE_BYTES_KEY),
        "diagnostic must name the setting: {error}"
    );
    assert!(
        error.contains("not unlimited"),
        "diagnostic must reject unlimited posture: {error}"
    );
    assert!(
        !error.contains("=0") && !error.ends_with(" 0"),
        "diagnostic must not echo the configured numeric value: {error}"
    );
    assert_eq!(
        parse_tls_max_material_size_bytes(Some("999999999")).expect("large number"),
        HARD_MAX_TLS_MAX_MATERIAL_SIZE_BYTES,
        "above the hard maximum clamps down"
    );
    assert_eq!(MIN_TLS_MAX_MATERIAL_SIZE_BYTES, 1);
}

#[test]
fn malformed_values_fail_closed_without_echoing_the_value() {
    for malformed in ["4MiB", "unlimited", "-1", "1.5", "", "   ", "0x1000"] {
        let error = parse_tls_max_material_size_bytes(Some(malformed))
            .expect_err("malformed values must fail closed");
        assert!(
            error.contains(TLS_MAX_MATERIAL_SIZE_BYTES_KEY),
            "diagnostic must name the setting: {error}"
        );
        assert!(
            !error.contains(malformed.trim()) || malformed.trim().is_empty(),
            "diagnostic must not echo the configured value: {error}"
        );
    }
}

#[test]
fn public_inventory_lists_the_canonical_setting() {
    assert!(
        PUBLIC_FERRUM_ENV_SETTINGS.contains(&TLS_MAX_MATERIAL_SIZE_BYTES_KEY),
        "public inventory must list {TLS_MAX_MATERIAL_SIZE_BYTES_KEY}"
    );
}

#[test]
fn hard_maximum_is_finite_and_equals_the_default() {
    assert_eq!(
        DEFAULT_TLS_MAX_MATERIAL_SIZE_BYTES, HARD_MAX_TLS_MAX_MATERIAL_SIZE_BYTES,
        "default and hard maximum stay aligned so operators cannot raise past PEM parse admission"
    );
    const { assert!(HARD_MAX_TLS_MAX_MATERIAL_SIZE_BYTES < usize::MAX / 2) };
}
