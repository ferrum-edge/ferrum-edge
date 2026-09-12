//! EnvConfig admission: admin vs CP/DP JWT secrets must be distinct when both
//! are configured. Issuer defaults do not domain-separate identical HMAC keys.

use ferrum_edge::config::{EnvConfig, OperatingMode};

use crate::unit::env_lock::ENV_LOCK;

fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
    let _guard = ENV_LOCK.lock().unwrap();
    for (k, v) in vars {
        // SAFETY: We hold a mutex preventing concurrent access.
        unsafe {
            std::env::set_var(k, v);
        }
    }
    f();
    for (k, _) in vars {
        // SAFETY: We hold a mutex preventing concurrent access.
        unsafe {
            std::env::remove_var(k);
        }
    }
}

const SHARED_SECRET: &str = "shared-hmac-secret-32-chars-min!!";
const ADMIN_SECRET: &str = "admin-secret-padding-32-chars!!!";
const CP_DP_SECRET: &str = "grpc-secret-padding-32-char-min!";

fn assert_equal_secret_rejection(error: &str) {
    assert!(
        error.contains("FERRUM_ADMIN_JWT_SECRET"),
        "error must name FERRUM_ADMIN_JWT_SECRET: {error}"
    );
    assert!(
        error.contains("FERRUM_CP_DP_GRPC_JWT_SECRET"),
        "error must name FERRUM_CP_DP_GRPC_JWT_SECRET: {error}"
    );
    assert!(
        error.contains("distinct"),
        "error must require distinct secrets: {error}"
    );
    assert!(
        !error.contains(SHARED_SECRET),
        "error must not echo either secret value: {error}"
    );
}

#[test]
fn cp_mode_rejects_identical_admin_and_cp_dp_jwt_secrets() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "cp"),
            ("FERRUM_ADMIN_JWT_SECRET", SHARED_SECRET),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_CP_GRPC_LISTEN_ADDR", "0.0.0.0:50051"),
            ("FERRUM_CP_DP_GRPC_JWT_SECRET", SHARED_SECRET),
            ("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", "true"),
            ("FERRUM_K8S_CONTROLLER_ENABLED", "false"),
        ],
        || {
            let error = EnvConfig::from_env().expect_err("identical secrets must fail closed");
            assert_equal_secret_rejection(&error);
        },
    );
}

#[test]
fn cp_mode_accepts_distinct_admin_and_cp_dp_jwt_secrets() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "cp"),
            ("FERRUM_ADMIN_JWT_SECRET", ADMIN_SECRET),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_CP_GRPC_LISTEN_ADDR", "0.0.0.0:50051"),
            ("FERRUM_CP_DP_GRPC_JWT_SECRET", CP_DP_SECRET),
            ("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", "true"),
            ("FERRUM_K8S_CONTROLLER_ENABLED", "false"),
        ],
        || {
            let config = EnvConfig::from_env().expect("distinct secrets must be accepted");
            assert_eq!(config.mode, OperatingMode::ControlPlane);
            assert_eq!(config.admin_jwt_secret.as_deref(), Some(ADMIN_SECRET));
            assert_eq!(config.cp_dp_grpc_jwt_secret.as_deref(), Some(CP_DP_SECRET));
        },
    );
}

#[test]
fn dp_mode_rejects_identical_admin_and_cp_dp_jwt_secrets() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_ADMIN_JWT_SECRET", SHARED_SECRET),
            ("FERRUM_DP_CP_GRPC_URLS", "http://control-plane:50051"),
            ("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", "true"),
            ("FERRUM_CP_DP_GRPC_JWT_SECRET", SHARED_SECRET),
        ],
        || {
            let error = EnvConfig::from_env().expect_err("identical secrets must fail closed");
            assert_equal_secret_rejection(&error);
        },
    );
}

#[test]
fn dp_mode_rejects_cp_dp_secret_without_admin_secret() {
    // Admission must enforce the same admin credential requirement as DP startup.
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://control-plane:50051"),
            ("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", "true"),
            ("FERRUM_CP_DP_GRPC_JWT_SECRET", CP_DP_SECRET),
        ],
        || {
            unsafe {
                std::env::remove_var("FERRUM_ADMIN_JWT_SECRET");
            }
            let error = EnvConfig::from_env().expect_err("DP requires an admin secret");
            assert!(error.contains("FERRUM_ADMIN_JWT_SECRET"));
        },
    );
}

#[test]
fn database_mode_rejects_identical_admin_and_cp_dp_jwt_secrets() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_ADMIN_JWT_SECRET", SHARED_SECRET),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
            ("FERRUM_CP_DP_GRPC_JWT_SECRET", SHARED_SECRET),
        ],
        || {
            let error = EnvConfig::from_env().expect_err("identical secrets must fail closed");
            assert_equal_secret_rejection(&error);
        },
    );
}

#[test]
fn database_mode_accepts_admin_secret_without_cp_dp_secret() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_ADMIN_JWT_SECRET", ADMIN_SECRET),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
        ],
        || {
            unsafe {
                std::env::remove_var("FERRUM_CP_DP_GRPC_JWT_SECRET");
            }
            let config = EnvConfig::from_env().expect("database mode needs only admin secret");
            assert_eq!(config.mode, OperatingMode::Database);
            assert_eq!(config.admin_jwt_secret.as_deref(), Some(ADMIN_SECRET));
            assert!(config.cp_dp_grpc_jwt_secret.is_none());
        },
    );
}

#[test]
fn mesh_mode_rejects_identical_admin_and_cp_dp_jwt_secrets() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_ADMIN_JWT_SECRET", SHARED_SECRET),
            ("FERRUM_DP_CP_GRPC_URLS", "https://control-plane:50051"),
            ("FERRUM_CP_DP_GRPC_JWT_SECRET", SHARED_SECRET),
            ("FERRUM_MESH_CONFIG_PROTOCOL", "native"),
            ("FERRUM_MESH_ALLOW_NO_CA", "true"),
        ],
        || {
            let error = EnvConfig::from_env().expect_err("identical secrets must fail closed");
            assert_equal_secret_rejection(&error);
        },
    );
}

#[test]
fn equal_secret_error_never_includes_secret_material() {
    // Unique marker unlikely to appear in a static error string.
    let marker = "redaction-probe-jwt-secret-value-zzzz-32c!";
    assert!(marker.len() >= 32);
    with_env_vars(
        &[
            ("FERRUM_MODE", "cp"),
            ("FERRUM_ADMIN_JWT_SECRET", marker),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_CP_GRPC_LISTEN_ADDR", "127.0.0.1:50051"),
            ("FERRUM_CP_DP_GRPC_JWT_SECRET", marker),
            ("FERRUM_K8S_CONTROLLER_ENABLED", "false"),
        ],
        || {
            let error = EnvConfig::from_env().expect_err("identical secrets must fail closed");
            assert!(error.contains("FERRUM_ADMIN_JWT_SECRET"));
            assert!(error.contains("FERRUM_CP_DP_GRPC_JWT_SECRET"));
            assert!(
                !error.contains(marker),
                "startup error must never include secret material: {error}"
            );
            assert!(
                !error.contains("redaction-probe"),
                "startup error must never include secret substrings: {error}"
            );
        },
    );
}
