//! Tests for admin security-related EnvConfig fields:
//! - admin_allowed_cidrs
//! - max_concurrent_requests_per_ip
//! - backend_allow_ips
//!
//! These tests verify default values and type semantics. Env var parsing
//! of these fields is covered by env_config_tests.rs; these focus on the
//! domain model and defaults.

use ferrum_edge::config::{BackendAllowIps, EnvConfig};

// ── FERRUM_ADMIN_ALLOWED_CIDRS ──────────────────────────────────────────────

#[test]
fn test_admin_allowed_cidrs_default_is_empty() {
    let config = EnvConfig::default();
    assert!(
        config.admin_allowed_cidrs.is_empty(),
        "Default admin_allowed_cidrs should be empty (all IPs allowed)"
    );
}

#[test]
fn test_admin_allowed_cidrs_can_hold_single_cidr() {
    let config = EnvConfig {
        admin_allowed_cidrs: "10.0.0.0/24".to_string(),
        ..Default::default()
    };
    assert_eq!(config.admin_allowed_cidrs, "10.0.0.0/24");
}

#[test]
fn test_admin_allowed_cidrs_can_hold_multiple() {
    let config = EnvConfig {
        admin_allowed_cidrs: "10.0.100.0/24,10.0.200.5,::1".to_string(),
        ..Default::default()
    };
    assert!(config.admin_allowed_cidrs.contains("10.0.100.0/24"));
    assert!(config.admin_allowed_cidrs.contains("::1"));
}

// ── FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP ───────────────────────────────────

#[test]
fn test_max_concurrent_requests_per_ip_default_is_zero() {
    let config = EnvConfig::default();
    assert_eq!(
        config.max_concurrent_requests_per_ip, 0,
        "Default should be 0 (disabled)"
    );
}

#[test]
fn test_max_concurrent_requests_per_ip_can_be_set() {
    let config = EnvConfig {
        max_concurrent_requests_per_ip: 500,
        ..Default::default()
    };
    assert_eq!(config.max_concurrent_requests_per_ip, 500);
}

// ── FERRUM_BACKEND_ALLOW_IPS ────────────────────────────────────────────────

#[test]
fn test_backend_allow_ips_default_is_both() {
    let config = EnvConfig::default();
    assert_eq!(
        config.backend_allow_ips,
        BackendAllowIps::Both,
        "Default should be Both (no restriction)"
    );
}

#[test]
fn test_backend_allow_ips_variants() {
    let config_private = EnvConfig {
        backend_allow_ips: BackendAllowIps::Private,
        ..Default::default()
    };
    assert_eq!(config_private.backend_allow_ips, BackendAllowIps::Private);

    let config_public = EnvConfig {
        backend_allow_ips: BackendAllowIps::Public,
        ..Default::default()
    };
    assert_eq!(config_public.backend_allow_ips, BackendAllowIps::Public);

    let config_both = EnvConfig {
        backend_allow_ips: BackendAllowIps::Both,
        ..Default::default()
    };
    assert_eq!(config_both.backend_allow_ips, BackendAllowIps::Both);
}

#[test]
fn test_backend_allow_ips_equality() {
    assert_ne!(BackendAllowIps::Private, BackendAllowIps::Public);
    assert_ne!(BackendAllowIps::Private, BackendAllowIps::Both);
    assert_ne!(BackendAllowIps::Public, BackendAllowIps::Both);
}
