//! Mesh DNS capacity/TTL settings fail closed (issue #5699).
//!
//! `FERRUM_MESH_DNS_TTL_SECONDS`, `FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES`, and
//! `FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES` used to fall back to their
//! defaults on a malformed, zero, or overflowing value. Unset still selects the
//! default; a present value must be a whole number in `1..=max`, and mesh
//! runtime construction (shared by `run` and `validate`) reports the variable
//! and range without echoing the value.

use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::mesh::dns_proxy::DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES;
use ferrum_edge::modes::mesh::{
    DEFAULT_DNS_MAX_CONCURRENT_QUERIES, DEFAULT_DNS_TTL_SECONDS,
    HARD_MAX_DNS_MAX_CONCURRENT_QUERIES, HARD_MAX_DNS_RESPONSE_CACHE_MAX_ENTRIES,
    HARD_MAX_DNS_TTL_SECONDS, MeshRuntimeConfig, parse_mesh_dns_max_concurrent_queries,
    parse_mesh_dns_response_cache_max_entries, parse_mesh_dns_ttl_seconds,
};

use crate::unit::env_lock::EnvGuard;

const TTL_KEY: &str = "FERRUM_MESH_DNS_TTL_SECONDS";
const QUERIES_KEY: &str = "FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES";
const CACHE_KEY: &str = "FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES";

const TTL_ERROR: &str = "FERRUM_MESH_DNS_TTL_SECONDS must be a whole number between 1 and 86400";
const QUERIES_ERROR: &str =
    "FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES must be a whole number between 1 and 16384";
const CACHE_ERROR: &str =
    "FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES must be a whole number between 1 and 262144";

/// Present values refused by every setting: zero, malformed (including the
/// issue's `2048x` / `64x` typos), negative, fractional, blank, and past
/// `u64::MAX`.
const REJECTED_EVERYWHERE: &[&str] = &[
    "0",
    "abc",
    "2048x",
    "64x",
    "-1",
    "1.5",
    "",
    "   ",
    "18446744073709551616",
];

fn mesh_env_config() -> EnvConfig {
    EnvConfig {
        mode: OperatingMode::Mesh,
        dp_cp_grpc_urls: vec!["http://127.0.0.1:1".to_string()],
        ..EnvConfig::default()
    }
}

#[test]
fn documented_bounds_match_the_contract() {
    assert_eq!(DEFAULT_DNS_TTL_SECONDS, 60);
    assert_eq!(HARD_MAX_DNS_TTL_SECONDS, 86_400);
    assert_eq!(DEFAULT_DNS_MAX_CONCURRENT_QUERIES, 1024);
    assert_eq!(HARD_MAX_DNS_MAX_CONCURRENT_QUERIES, 16_384);
    assert_eq!(DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES, 4096);
    assert_eq!(HARD_MAX_DNS_RESPONSE_CACHE_MAX_ENTRIES, 262_144);
}

#[test]
fn unset_selects_each_default() {
    assert_eq!(parse_mesh_dns_ttl_seconds(None).unwrap(), 60);
    assert_eq!(parse_mesh_dns_max_concurrent_queries(None).unwrap(), 1024);
    assert_eq!(
        parse_mesh_dns_response_cache_max_entries(None).unwrap(),
        4096
    );
}

#[test]
fn valid_values_are_accepted_including_both_bounds() {
    for (raw, expected) in [("1", 1), ("300", 300), (" 120 ", 120), ("86400", 86_400)] {
        assert_eq!(parse_mesh_dns_ttl_seconds(Some(raw)).unwrap(), expected);
    }
    for (raw, expected) in [("1", 1), ("2048", 2048), ("16384", 16_384)] {
        assert_eq!(
            parse_mesh_dns_max_concurrent_queries(Some(raw)).unwrap(),
            expected
        );
    }
    for (raw, expected) in [("1", 1), ("64", 64), ("262144", 262_144)] {
        assert_eq!(
            parse_mesh_dns_response_cache_max_entries(Some(raw)).unwrap(),
            expected
        );
    }
}

#[test]
fn zero_malformed_and_overflow_are_rejected_without_echo() {
    for &raw in REJECTED_EVERYWHERE {
        assert_eq!(
            parse_mesh_dns_ttl_seconds(Some(raw)).unwrap_err(),
            TTL_ERROR,
            "{raw:?}"
        );
        assert_eq!(
            parse_mesh_dns_max_concurrent_queries(Some(raw)).unwrap_err(),
            QUERIES_ERROR,
            "{raw:?}"
        );
        assert_eq!(
            parse_mesh_dns_response_cache_max_entries(Some(raw)).unwrap_err(),
            CACHE_ERROR,
            "{raw:?}"
        );
    }
}

#[test]
fn values_above_each_hard_maximum_are_rejected() {
    // `4294967296` overflows the `u32` TTL; the capacity settings are `usize`.
    for raw in ["86401", "4294967295", "4294967296"] {
        assert_eq!(
            parse_mesh_dns_ttl_seconds(Some(raw)).unwrap_err(),
            TTL_ERROR,
            "{raw:?}"
        );
    }
    for raw in ["16385", "18446744073709551615"] {
        assert_eq!(
            parse_mesh_dns_max_concurrent_queries(Some(raw)).unwrap_err(),
            QUERIES_ERROR,
            "{raw:?}"
        );
    }
    for raw in ["262145", "18446744073709551615"] {
        assert_eq!(
            parse_mesh_dns_response_cache_max_entries(Some(raw)).unwrap_err(),
            CACHE_ERROR,
            "{raw:?}"
        );
    }
}

#[test]
fn mesh_runtime_uses_defaults_when_unset() {
    let _env = EnvGuard::new(&[]);
    let runtime = MeshRuntimeConfig::from_env_config(&mesh_env_config())
        .expect("unset mesh DNS settings select their defaults");
    assert_eq!(runtime.dns_ttl_seconds, DEFAULT_DNS_TTL_SECONDS);
    assert_eq!(
        runtime.dns_max_concurrent_queries,
        DEFAULT_DNS_MAX_CONCURRENT_QUERIES
    );
    assert_eq!(
        runtime.dns_response_cache_max_entries,
        DEFAULT_DNS_RESPONSE_CACHE_MAX_ENTRIES
    );
}

#[test]
fn mesh_runtime_applies_valid_overrides() {
    let env = EnvGuard::new(&[]);
    env.set(TTL_KEY, "120");
    env.set(QUERIES_KEY, "4096");
    env.set(CACHE_KEY, "65536");
    let runtime = MeshRuntimeConfig::from_env_config(&mesh_env_config())
        .expect("in-range mesh DNS settings are accepted");
    assert_eq!(runtime.dns_ttl_seconds, 120);
    assert_eq!(runtime.dns_max_concurrent_queries, 4096);
    assert_eq!(runtime.dns_response_cache_max_entries, 65_536);
}

#[test]
fn mesh_runtime_rejects_each_invalid_setting() {
    let env = EnvGuard::new(&[]);
    for (key, expected) in [
        (TTL_KEY, TTL_ERROR),
        (QUERIES_KEY, QUERIES_ERROR),
        (CACHE_KEY, CACHE_ERROR),
    ] {
        for &raw in REJECTED_EVERYWHERE {
            env.set(key, raw);
            let error = MeshRuntimeConfig::from_env_config(&mesh_env_config())
                .expect_err("an invalid mesh DNS setting must fail startup and validate");
            assert_eq!(error, expected, "{key}={raw:?}");
        }
        env.unset(key);
    }
}
