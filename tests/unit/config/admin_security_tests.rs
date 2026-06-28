//! Tests for admin security-related EnvConfig fields:
//! - admin_allowed_cidrs
//! - max_concurrent_requests_per_ip
//! - backend_allow_ips
//! - admin HTTP plaintext exposure classification + writable-mode hard-fail
//!
//! These tests verify default values and type semantics. Env var parsing
//! of these fields is covered by env_config_tests.rs; these focus on the
//! domain model and defaults.

use ferrum_edge::config::{AdminHttpExposure, BackendAllowIps, EnvConfig, OperatingMode};

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

// ── Admin plaintext HTTP exposure classification ────────────────────────────
//
// `admin_http_exposure()` classifies the plaintext admin HTTP listener
// (FERRUM_ADMIN_HTTP_PORT) independently of mode. The writable-mode hard-fail
// (`admin_insecure_plaintext_startup_error()`) is exercised separately below.

#[test]
fn test_admin_bind_and_port_defaults() {
    // Safe-by-default management plane: admin binds to loopback, plaintext port
    // enabled, no allowlist, dev escape hatch off.
    let config = EnvConfig::default();
    assert_eq!(config.admin_http_port, 9000, "default admin HTTP port");
    assert_eq!(
        config.admin_bind_address, "127.0.0.1",
        "default admin bind is loopback (safe by default)"
    );
    assert!(
        config.admin_allowed_cidrs.is_empty(),
        "default allowlist is empty"
    );
    assert!(
        !config.allow_insecure_admin_http,
        "insecure admin escape hatch defaults off"
    );
}

#[test]
fn test_admin_http_exposure_default_is_loopback() {
    // Default 127.0.0.1:9000 is not network-exposed.
    assert_eq!(
        EnvConfig::default().admin_http_exposure(),
        AdminHttpExposure::LoopbackOrPrivate
    );
}

#[test]
fn test_admin_http_exposure_disabled_when_port_zero() {
    let config = EnvConfig {
        admin_http_port: 0,
        admin_bind_address: "0.0.0.0".to_string(),
        ..Default::default()
    };
    assert_eq!(
        config.admin_http_exposure(),
        AdminHttpExposure::Disabled,
        "port 0 means no plaintext admin listener"
    );
}

#[test]
fn test_admin_http_exposure_loopback_and_private_are_safe() {
    for bind in [
        "127.0.0.1",
        "::1",
        "10.0.0.5",
        "192.168.1.10",
        "169.254.1.1",
    ] {
        let config = EnvConfig {
            admin_bind_address: bind.to_string(),
            ..Default::default()
        };
        assert_eq!(
            config.admin_http_exposure(),
            AdminHttpExposure::LoopbackOrPrivate,
            "{bind} should classify as loopback/private"
        );
    }
}

#[test]
fn test_admin_http_exposure_unspecified_bind_is_public() {
    // 0.0.0.0 / :: ("all interfaces") with no allowlist is the unrestricted-
    // public posture the writable-mode guard protects against.
    for bind in ["0.0.0.0", "::"] {
        let config = EnvConfig {
            admin_bind_address: bind.to_string(),
            ..Default::default()
        };
        assert_eq!(
            config.admin_http_exposure(),
            AdminHttpExposure::PublicUnrestricted,
            "{bind} should classify as unrestricted-public"
        );
    }
}

#[test]
fn test_admin_http_exposure_public_with_allowlist() {
    let config = EnvConfig {
        admin_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: "10.0.0.0/8".to_string(),
        ..Default::default()
    };
    assert_eq!(
        config.admin_http_exposure(),
        AdminHttpExposure::PublicAllowlisted,
        "an allowlist downgrades the public posture"
    );
}

#[test]
fn test_admin_http_exposure_public_routable_ip_no_allowlist() {
    let config = EnvConfig {
        admin_bind_address: "203.0.113.10".to_string(),
        ..Default::default()
    };
    assert_eq!(
        config.admin_http_exposure(),
        AdminHttpExposure::PublicUnrestricted
    );
}

// ── Writable-mode (database/cp) plaintext-admin hard-fail ───────────────────

#[test]
fn test_default_database_startup_is_safe() {
    // Done criterion: a fresh production-mode DB startup with only the defaults
    // cannot accidentally expose plaintext admin — the default loopback bind is
    // not network-reachable, so startup is permitted with no opt-in.
    let config = EnvConfig {
        mode: OperatingMode::Database,
        ..Default::default()
    };
    assert_eq!(
        config.admin_http_exposure(),
        AdminHttpExposure::LoopbackOrPrivate
    );
    assert!(
        config.admin_insecure_plaintext_startup_error().is_none(),
        "default (loopback) database admin must start without any opt-in"
    );
}

#[test]
fn test_database_mode_rejects_explicit_public_plaintext_admin() {
    // Operator explicitly moves admin to a public plaintext bind with no
    // allowlist / TLS / opt-in → must refuse to start.
    let config = EnvConfig {
        mode: OperatingMode::Database,
        admin_bind_address: "0.0.0.0".to_string(),
        ..Default::default()
    };
    let err = config
        .admin_insecure_plaintext_startup_error()
        .expect("explicit public plaintext admin in database mode must hard-fail");
    assert!(
        err.contains("FERRUM_ADMIN_ALLOWED_CIDRS"),
        "error should point at the allowlist remediation: {err}"
    );
    assert!(
        err.contains("FERRUM_ALLOW_INSECURE_ADMIN_HTTP"),
        "error should mention the dev escape hatch: {err}"
    );
    assert!(
        err.contains("FERRUM_ADMIN_HTTP_PORT=0"),
        "error should mention disabling plaintext: {err}"
    );
}

#[test]
fn test_cp_mode_rejects_explicit_public_plaintext_admin() {
    let config = EnvConfig {
        mode: OperatingMode::ControlPlane,
        admin_bind_address: "0.0.0.0".to_string(),
        ..Default::default()
    };
    assert!(
        config.admin_insecure_plaintext_startup_error().is_some(),
        "explicit public plaintext admin in cp mode must hard-fail"
    );
}

#[test]
fn test_escape_hatch_allows_public_plaintext_admin() {
    // FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true is the explicit dev opt-in: the
    // posture is still PublicUnrestricted, but startup is permitted.
    let config = EnvConfig {
        mode: OperatingMode::Database,
        admin_bind_address: "0.0.0.0".to_string(),
        allow_insecure_admin_http: true,
        ..Default::default()
    };
    assert_eq!(
        config.admin_http_exposure(),
        AdminHttpExposure::PublicUnrestricted,
        "escape hatch does not change the exposure classification"
    );
    assert!(
        config.admin_insecure_plaintext_startup_error().is_none(),
        "escape hatch permits startup"
    );
}

#[test]
fn test_loopback_bind_allows_database_startup() {
    let config = EnvConfig {
        mode: OperatingMode::Database,
        admin_bind_address: "127.0.0.1".to_string(),
        ..Default::default()
    };
    assert!(
        config.admin_insecure_plaintext_startup_error().is_none(),
        "loopback admin bind is safe without any opt-in"
    );
}

#[test]
fn test_allowlist_allows_public_database_startup() {
    let config = EnvConfig {
        mode: OperatingMode::Database,
        admin_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: "10.0.0.0/8,127.0.0.1".to_string(),
        ..Default::default()
    };
    assert!(
        config.admin_insecure_plaintext_startup_error().is_none(),
        "an allowlist satisfies the writable-mode guard"
    );
}

#[test]
fn test_admin_http_port_zero_allows_public_database_startup() {
    let config = EnvConfig {
        mode: OperatingMode::Database,
        admin_bind_address: "0.0.0.0".to_string(),
        admin_http_port: 0,
        ..Default::default()
    };
    assert!(
        config.admin_insecure_plaintext_startup_error().is_none(),
        "disabling the plaintext listener satisfies the guard"
    );
}

#[test]
fn test_readonly_modes_are_not_hard_failed_on_public_plaintext() {
    // file/dp/mesh admin surfaces are read-only; they are warned (in main.rs),
    // not failed, even with an explicit public plaintext posture.
    for mode in [
        OperatingMode::File,
        OperatingMode::DataPlane,
        OperatingMode::Mesh,
    ] {
        let config = EnvConfig {
            mode: mode.clone(),
            admin_bind_address: "0.0.0.0".to_string(),
            ..Default::default()
        };
        assert!(
            config.admin_insecure_plaintext_startup_error().is_none(),
            "{mode:?} is read-only and must not hard-fail on plaintext admin"
        );
    }
}
