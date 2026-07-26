//! Tests for environment configuration loading and validation.
//!
//! These tests mutate process-global environment variables, so they MUST run serially.
//! We use `serial_test` via a simple mutex to enforce this.

use ferrum_edge::config::{DbTlsMode, EnvConfig, OperatingMode};
use ferrum_edge::ebpf::NodeAgentProxyMode;

// Shared process-wide env lock: serializes against the identity guardrail
// tests that also mutate `FERRUM_MESH_PRODUCTION_MODE` (see tests/unit/env_lock.rs).
use crate::unit::env_lock::ENV_LOCK;

/// Helper to set env vars, run a closure, then clean them up.
/// Holds a mutex to prevent concurrent env var mutations.
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

/// Helper to remove an env var (must be called inside with_env_vars or while holding ENV_LOCK).
fn remove_var(key: &str) {
    // SAFETY: Called within with_env_vars which holds ENV_LOCK.
    unsafe {
        std::env::remove_var(key);
    }
}

const RUNTIME_METRICS_ENV_VARS: &[&str] = &[
    "FERRUM_METRICS_SYSTEM_SAMPLE_INTERVAL_MS",
    "FERRUM_METRICS_WINDOW_1M_SECONDS",
    "FERRUM_METRICS_WINDOW_5M_SECONDS",
    "FERRUM_METRICS_LOG_COUNTER_ENABLED",
    "FERRUM_METRICS_RUNTIME_CACHE_MS",
    "FERRUM_METRICS_POOL_TRACKING_ENABLED",
    "FERRUM_METRICS_STATUS_TRACKING_ENABLED",
];

fn remove_runtime_metrics_env_vars() {
    for key in RUNTIME_METRICS_ENV_VARS {
        remove_var(key);
    }
}

#[test]
fn test_operating_mode_database() {
    with_env_vars(&[("FERRUM_MODE", "database")], || {
        let mode = OperatingMode::from_env().unwrap();
        assert_eq!(mode, OperatingMode::Database);
    });
}

#[test]
fn test_operating_mode_file() {
    with_env_vars(&[("FERRUM_MODE", "file")], || {
        let mode = OperatingMode::from_env().unwrap();
        assert_eq!(mode, OperatingMode::File);
    });
}

#[test]
fn test_operating_mode_cp() {
    with_env_vars(&[("FERRUM_MODE", "cp")], || {
        let mode = OperatingMode::from_env().unwrap();
        assert_eq!(mode, OperatingMode::ControlPlane);
    });
}

#[test]
fn test_operating_mode_dp() {
    with_env_vars(&[("FERRUM_MODE", "dp")], || {
        let mode = OperatingMode::from_env().unwrap();
        assert_eq!(mode, OperatingMode::DataPlane);
    });
}

#[test]
fn test_operating_mode_mesh() {
    with_env_vars(&[("FERRUM_MODE", "mesh")], || {
        let mode = OperatingMode::from_env().unwrap();
        assert_eq!(mode, OperatingMode::Mesh);
    });
}

#[test]
fn test_operating_mode_injector() {
    with_env_vars(&[("FERRUM_MODE", "injector")], || {
        let mode = OperatingMode::from_env().unwrap();
        assert_eq!(mode, OperatingMode::Injector);
    });
}

#[test]
fn test_operating_mode_invalid() {
    with_env_vars(&[("FERRUM_MODE", "invalid")], || {
        let result = OperatingMode::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid FERRUM_MODE"));
    });
}

#[test]
fn test_operating_mode_case_insensitive() {
    with_env_vars(&[("FERRUM_MODE", "DATABASE")], || {
        let mode = OperatingMode::from_env().unwrap();
        assert_eq!(mode, OperatingMode::Database);
    });
}

#[test]
fn test_env_config_file_mode_valid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::File);
            assert_eq!(
                config.file_config_path,
                Some("/path/to/config.yaml".to_string())
            );
        },
    );
}

#[test]
fn test_xds_enabled_defaults_false() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
        ],
        || {
            remove_var("FERRUM_XDS_ENABLED");
            remove_var("FERRUM_XDS_STREAM_CHANNEL_CAPACITY");
            remove_var("FERRUM_XDS_MAX_STREAMS_PER_NODE");
            let config = EnvConfig::from_env().unwrap();
            assert!(!config.xds_enabled);
            assert_eq!(config.xds_stream_channel_capacity, 32);
            assert_eq!(config.xds_max_streams_per_node, 4);
        },
    );
}

#[test]
fn test_xds_enabled_parsed_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
            ("FERRUM_XDS_ENABLED", "true"),
            ("FERRUM_XDS_STREAM_CHANNEL_CAPACITY", "64"),
            ("FERRUM_XDS_MAX_STREAMS_PER_NODE", "8"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.xds_enabled);
            assert_eq!(config.xds_stream_channel_capacity, 64);
            assert_eq!(config.xds_max_streams_per_node, 8);
        },
    );
}

#[test]
fn test_http3_websocket_enabled_defaults_true() {
    // RFC 9220 WebSocket-over-HTTP/3 Extended CONNECT defaults to enabled.
    // Operators who run an H3 listener want WebSocket-over-H3 to "just work"
    // out of the box, matching the H2 default
    // (`enable_connect_protocol()` is unconditionally called on the H2 builder).
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
        ],
        || {
            remove_var("FERRUM_HTTP3_WEBSOCKET_ENABLED");
            let config = EnvConfig::from_env().unwrap();
            assert!(
                config.http3_websocket_enabled,
                "Missing FERRUM_HTTP3_WEBSOCKET_ENABLED must default to true"
            );
        },
    );
}

#[test]
fn test_http3_websocket_enabled_parses_false() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
            ("FERRUM_HTTP3_WEBSOCKET_ENABLED", "false"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(
                !config.http3_websocket_enabled,
                "FERRUM_HTTP3_WEBSOCKET_ENABLED=false must disable the path"
            );
        },
    );
}

#[test]
fn test_http3_websocket_enabled_parses_true() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
            ("FERRUM_HTTP3_WEBSOCKET_ENABLED", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.http3_websocket_enabled);
        },
    );
}

#[test]
fn test_env_config_file_mode_missing_path() {
    with_env_vars(&[("FERRUM_MODE", "file")], || {
        remove_var("FERRUM_FILE_CONFIG_PATH");
        let result = EnvConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("FERRUM_FILE_CONFIG_PATH"));
    });
}

#[test]
fn test_env_config_database_mode_missing_jwt() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
        ],
        || {
            remove_var("FERRUM_ADMIN_JWT_SECRET");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_ADMIN_JWT_SECRET"));
        },
    );
}

#[test]
fn test_env_config_rejects_oversized_admin_jwt_max_ttl() {
    // `0` is the only documented way to disable the admin JWT lifetime cap.
    // A value that cannot be represented as an i64-second bound is a typo,
    // not a disable request, and must fail startup instead of degrading into
    // an effectively unlimited cap.
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
            ("FERRUM_ADMIN_JWT_MAX_TTL", "18446744073709551615"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result.unwrap_err().contains("FERRUM_ADMIN_JWT_MAX_TTL"),
                "startup must name the offending setting"
            );
        },
    );
}

#[test]
fn test_env_config_accepts_admin_jwt_max_ttl_disable_sentinel() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
            ("FERRUM_ADMIN_JWT_MAX_TTL", "0"),
        ],
        || {
            let config = EnvConfig::from_env().expect("0 is the documented disable sentinel");
            assert_eq!(config.admin_jwt_max_ttl, 0);
        },
    );
}

#[test]
fn test_env_config_database_mode_missing_db_type() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_URL", "sqlite::memory:"),
        ],
        || {
            remove_var("FERRUM_DB_TYPE");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_DB_TYPE"));
        },
    );
}

#[test]
fn test_env_config_database_mode_missing_db_url() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "sqlite"),
        ],
        || {
            remove_var("FERRUM_DB_URL");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_DB_URL"));
        },
    );
}

#[test]
fn test_env_config_dp_mode_missing_grpc_url() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            remove_var("FERRUM_DP_CP_GRPC_URLS");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_DP_CP_GRPC_URLS"));
        },
    );
}

#[test]
fn test_env_config_dp_mode_missing_jwt_secret() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
        ],
        || {
            remove_var("FERRUM_CP_DP_GRPC_JWT_SECRET");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_CP_DP_GRPC_JWT_SECRET"));
        },
    );
}

#[test]
fn test_env_config_mesh_mode_valid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            // The CA backend does not load a runtime SVID yet, so a valid mesh
            // config needs actual identity or the dev opt-out; the gate itself
            // is exercised by the tests below.
            ("FERRUM_MESH_ALLOW_NO_CA", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::Mesh);
            assert_eq!(
                config.resolved_dp_cp_grpc_urls(),
                vec!["http://cp:50051".to_string()]
            );
        },
    );
}

#[test]
fn test_env_config_injector_mode_valid() {
    with_env_vars(&[("FERRUM_MODE", "injector")], || {
        let config = EnvConfig::from_env().unwrap();
        assert_eq!(config.mode, OperatingMode::Injector);
    });
}

#[test]
fn test_env_config_mesh_mode_missing_grpc_url() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            remove_var("FERRUM_DP_CP_GRPC_URLS");
            remove_var("FERRUM_DP_CP_GRPC_URLS");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_DP_CP_GRPC_URLS"));
        },
    );
}

#[test]
fn test_env_config_mesh_mode_missing_jwt_secret() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
        ],
        || {
            remove_var("FERRUM_CP_DP_GRPC_JWT_SECRET");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_CP_DP_GRPC_JWT_SECRET"));
        },
    );
}

#[test]
fn test_env_config_mesh_mode_no_ca_backend_fails_closed() {
    // The default CA backend is `none`. A mesh with no CA cannot establish or
    // verify mTLS, so PeerAuthentication's PERMISSIVE default would silently
    // accept unauthenticated plaintext. Startup must fail closed.
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            remove_var("FERRUM_MESH_PRODUCTION_MODE");
            remove_var("FERRUM_MESH_CA_BACKEND");
            remove_var("FERRUM_MESH_ALLOW_NO_CA");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                err.contains("FERRUM_MESH_CA_BACKEND"),
                "error should name the CA backend var, got: {err}"
            );
            assert!(
                err.contains("FERRUM_MESH_ALLOW_NO_CA"),
                "error should name the opt-out var, got: {err}"
            );
        },
    );
}

#[test]
fn test_env_config_mesh_mode_no_ca_allowed_with_explicit_opt_out() {
    // Operators may explicitly acknowledge the insecure dev/test posture.
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_MESH_ALLOW_NO_CA", "true"),
        ],
        || {
            remove_var("FERRUM_MESH_PRODUCTION_MODE");
            remove_var("FERRUM_MESH_CA_BACKEND");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::Mesh);
        },
    );
}

#[test]
fn test_env_config_mesh_mode_ca_backend_requires_workload_spiffe_id() {
    // A CA backend can now supply runtime identity, but it needs the local
    // workload SPIFFE ID so the issued SVID matches mesh policy/materialization
    // identity.
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_MESH_CA_BACKEND", "internal"),
        ],
        || {
            remove_var("FERRUM_MESH_PRODUCTION_MODE");
            remove_var("FERRUM_MESH_ALLOW_NO_CA");
            remove_var("FERRUM_GATEWAY_SVID_CERT_PATH");
            remove_var("FERRUM_GATEWAY_SVID_KEY_PATH");
            remove_var("FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH");
            remove_var("FERRUM_MESH_WORKLOAD_SPIFFE_ID");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("FERRUM_MESH_WORKLOAD_SPIFFE_ID")
            );
        },
    );
}

#[test]
fn test_env_config_mesh_mode_spire_backend_satisfies_production_identity_gate() {
    // A configured SPIRE backend plus local workload identity now supplies
    // runtime SVID material, so production mode does not require file SVID paths.
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_MESH_CA_BACKEND", "spire"),
            ("FERRUM_MESH_PRODUCTION_MODE", "true"),
            (
                "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                "spiffe://cluster.local/ns/default/sa/reviews",
            ),
        ],
        || {
            remove_var("FERRUM_MESH_ALLOW_NO_CA");
            remove_var("FERRUM_GATEWAY_SVID_CERT_PATH");
            remove_var("FERRUM_GATEWAY_SVID_KEY_PATH");
            remove_var("FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::Mesh);
        },
    );
}

#[test]
fn test_env_config_non_mesh_mode_no_ca_backend_not_gated() {
    // The gate is mesh-mode specific: a non-mesh mode with no CA backend must
    // not be blocked by it.
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            (
                "FERRUM_FILE_CONFIG_PATH",
                "/tmp/ferrum-no-ca-gate-test.yaml",
            ),
            ("FERRUM_MESH_CA_BACKEND", "none"),
        ],
        || {
            remove_var("FERRUM_MESH_ALLOW_NO_CA");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::File);
        },
    );
}

#[test]
fn test_env_config_mesh_mode_no_ca_refused_in_production_mode() {
    // FERRUM_MESH_PRODUCTION_MODE=true refuses an identity-less mesh
    // unconditionally, mirroring the bootstrap / static-attestor guardrails.
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_MESH_PRODUCTION_MODE", "true"),
        ],
        || {
            remove_var("FERRUM_MESH_CA_BACKEND");
            remove_var("FERRUM_MESH_ALLOW_NO_CA");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result.unwrap_err().contains("FERRUM_MESH_PRODUCTION_MODE"),
                "production-mode refusal should name the guardrail var"
            );
        },
    );
}

#[test]
fn test_env_config_mesh_mode_production_mode_ignores_no_ca_opt_out() {
    // In production mode the dev opt-out must NOT re-open the no-CA posture.
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_MESH_PRODUCTION_MODE", "true"),
            ("FERRUM_MESH_ALLOW_NO_CA", "true"),
        ],
        || {
            remove_var("FERRUM_MESH_CA_BACKEND");
            let result = EnvConfig::from_env();
            assert!(
                result.is_err(),
                "production mode must refuse no-CA even with the opt-out set"
            );
            assert!(result.unwrap_err().contains("FERRUM_MESH_PRODUCTION_MODE"));
        },
    );
}

#[test]
fn test_env_config_mesh_mode_no_ca_with_gateway_svid_passes() {
    // File-based gateway SVID material is a workload identity independent of
    // the CA backend, so a CA=none mesh that supplies it is NOT identity-less
    // and must start without any opt-out — even though the CA backend is none.
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_GATEWAY_SVID_CERT_PATH", "/tmp/ferrum-svid.crt"),
            ("FERRUM_GATEWAY_SVID_KEY_PATH", "/tmp/ferrum-svid.key"),
            (
                "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                "/tmp/ferrum-svid-bundle.pem",
            ),
        ],
        || {
            remove_var("FERRUM_MESH_PRODUCTION_MODE");
            remove_var("FERRUM_MESH_CA_BACKEND");
            remove_var("FERRUM_MESH_ALLOW_NO_CA");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::Mesh);
        },
    );
}

#[test]
fn test_env_config_mesh_mode_gateway_svid_takes_precedence_over_ca_backend() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_MESH_CA_BACKEND", "spire"),
            ("FERRUM_GATEWAY_SVID_CERT_PATH", "/tmp/ferrum-svid.crt"),
            ("FERRUM_GATEWAY_SVID_KEY_PATH", "/tmp/ferrum-svid.key"),
            (
                "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                "/tmp/ferrum-svid-bundle.pem",
            ),
        ],
        || {
            remove_var("FERRUM_MESH_WORKLOAD_SPIFFE_ID");
            remove_var("FERRUM_MESH_PRODUCTION_MODE");
            remove_var("FERRUM_MESH_ALLOW_NO_CA");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::Mesh);
        },
    );
}

#[test]
fn test_env_config_mesh_mode_production_mode_accepts_numeric_one() {
    // FERRUM_MESH_PRODUCTION_MODE=1 must be honored (same truthy spelling as
    // EnvConfig bools), so the opt-out cannot re-open the no-identity posture.
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_MESH_PRODUCTION_MODE", "1"),
            ("FERRUM_MESH_ALLOW_NO_CA", "true"),
        ],
        || {
            remove_var("FERRUM_MESH_CA_BACKEND");
            remove_var("FERRUM_GATEWAY_SVID_CERT_PATH");
            remove_var("FERRUM_GATEWAY_SVID_KEY_PATH");
            remove_var("FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH");
            let result = EnvConfig::from_env();
            assert!(
                result.is_err(),
                "PRODUCTION_MODE=1 must be treated as production and ignore the opt-out"
            );
            assert!(result.unwrap_err().contains("FERRUM_MESH_PRODUCTION_MODE"));
        },
    );
}

#[test]
fn test_env_config_mesh_mode_rejects_malformed_production_mode() {
    // A typo in the production flag must fail loudly (matching EnvConfig bool
    // parsing), not silently fall through to the non-production posture.
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_MESH_PRODUCTION_MODE", "yes"),
            ("FERRUM_MESH_ALLOW_NO_CA", "true"),
        ],
        || {
            remove_var("FERRUM_MESH_CA_BACKEND");
            remove_var("FERRUM_GATEWAY_SVID_CERT_PATH");
            remove_var("FERRUM_GATEWAY_SVID_KEY_PATH");
            remove_var("FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result.unwrap_err().contains("FERRUM_MESH_PRODUCTION_MODE"),
                "a malformed production flag must be rejected loudly"
            );
        },
    );
}

#[test]
fn test_env_config_mesh_production_refuses_unbounded_federation_staleness() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "https://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_MESH_PRODUCTION_MODE", "true"),
            ("FERRUM_MESH_CA_BACKEND", "spire"),
            (
                "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                "spiffe://cluster.local/ns/default/sa/reviews",
            ),
            ("FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS", "30"),
            ("FERRUM_MESH_FEDERATION_MAX_STALE_SECONDS", "0"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("FERRUM_MESH_FEDERATION_MAX_STALE_SECONDS"));
        },
    );
}

#[test]
fn test_env_config_mesh_production_refuses_unbounded_remote_discovery_staleness() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "https://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_MESH_PRODUCTION_MODE", "true"),
            ("FERRUM_MESH_CA_BACKEND", "spire"),
            (
                "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                "spiffe://cluster.local/ns/default/sa/reviews",
            ),
            ("FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS", "30"),
            ("FERRUM_MESH_REMOTE_DISCOVERY_MAX_STALE_SECONDS", "0"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("FERRUM_MESH_REMOTE_DISCOVERY_MAX_STALE_SECONDS"));
        },
    );
}

#[test]
fn test_env_config_mesh_production_refuses_remote_discovery_tls_no_verify() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "https://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_MESH_PRODUCTION_MODE", "true"),
            ("FERRUM_MESH_CA_BACKEND", "spire"),
            (
                "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                "spiffe://cluster.local/ns/default/sa/reviews",
            ),
            ("FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS", "30"),
            ("FERRUM_DP_GRPC_TLS_NO_VERIFY", "true"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("FERRUM_DP_GRPC_TLS_NO_VERIFY"));
        },
    );
}

#[test]
fn test_env_config_mesh_mode_blank_gateway_svid_paths_are_not_identity() {
    // Empty / whitespace SVID paths (`Some("")`) provide no usable cert/key, so
    // they must NOT satisfy the identity check — production mode must still
    // refuse the identity-less posture.
    with_env_vars(
        &[
            ("FERRUM_MODE", "mesh"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_GATEWAY_SVID_CERT_PATH", ""),
            ("FERRUM_GATEWAY_SVID_KEY_PATH", "   "),
            ("FERRUM_MESH_PRODUCTION_MODE", "true"),
        ],
        || {
            remove_var("FERRUM_MESH_CA_BACKEND");
            remove_var("FERRUM_MESH_ALLOW_NO_CA");
            let result = EnvConfig::from_env();
            assert!(
                result.is_err(),
                "blank SVID paths must not count as identity; production mode must refuse"
            );
            assert!(result.unwrap_err().contains("FERRUM_MESH_PRODUCTION_MODE"));
        },
    );
}

#[test]
fn test_env_config_cp_mode_missing_grpc_listen() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "cp"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "grpc-secret-padding-32-char-min!",
            ),
            // Default 0.0.0.0:50051 plaintext bind requires the explicit opt-in
            // under the secure-by-default CP/DP transport policy.
            ("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", "true"),
        ],
        || {
            remove_var("FERRUM_CP_GRPC_LISTEN_ADDR");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.cp_grpc_listen_addr,
                Some("0.0.0.0:50051".to_string())
            );
        },
    );
}

#[test]
fn test_env_config_cp_mode_missing_grpc_jwt_secret() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "cp"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
            ("FERRUM_CP_GRPC_LISTEN_ADDR", "0.0.0.0:50051"),
        ],
        || {
            remove_var("FERRUM_CP_DP_GRPC_JWT_SECRET");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_CP_DP_GRPC_JWT_SECRET"));
        },
    );
}

#[test]
fn test_env_config_default_ports() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_PROXY_HTTP_PORT");
            remove_var("FERRUM_PROXY_HTTPS_PORT");
            remove_var("FERRUM_ADMIN_HTTP_PORT");
            remove_var("FERRUM_ADMIN_HTTPS_PORT");

            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.proxy_http_port, 8000);
            assert_eq!(config.proxy_https_port, 8443);
            assert_eq!(config.admin_http_port, 9000);
            assert_eq!(config.admin_https_port, 9443);
        },
    );
}

#[test]
fn test_env_config_custom_ports() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_PROXY_HTTP_PORT", "3000"),
            ("FERRUM_ADMIN_HTTP_PORT", "4000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.proxy_http_port, 3000);
            assert_eq!(config.admin_http_port, 4000);
        },
    );
}

#[test]
fn test_compression_algorithm_gates_default_enabled() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_COMPRESSION_GZIP_ENABLED");
            remove_var("FERRUM_COMPRESSION_BROTLI_ENABLED");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.compression_gzip_enabled);
            assert!(config.compression_brotli_enabled);
        },
    );
}

#[test]
fn test_compression_algorithm_gates_parse_independently() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_COMPRESSION_GZIP_ENABLED", "false"),
            ("FERRUM_COMPRESSION_BROTLI_ENABLED", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(!config.compression_gzip_enabled);
            assert!(config.compression_brotli_enabled);
        },
    );
}

#[test]
fn test_env_config_default_log_level() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_LOG_LEVEL");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.log_level, "warn");
        },
    );
}

#[test]
fn test_env_config_http3_defaults() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_ENABLE_HTTP3");
            remove_var("FERRUM_HTTP3_IDLE_TIMEOUT");
            remove_var("FERRUM_HTTP3_MAX_STREAMS");
            remove_var("FERRUM_HTTP3_STREAM_RECEIVE_WINDOW");
            remove_var("FERRUM_HTTP3_RECEIVE_WINDOW");
            remove_var("FERRUM_HTTP3_SEND_WINDOW");
            remove_var("FERRUM_FRONTEND_H2_INITIAL_STREAM_WINDOW_SIZE");
            remove_var("FERRUM_FRONTEND_H2_INITIAL_CONNECTION_WINDOW_SIZE");
            remove_var("FERRUM_FRONTEND_H2_MAX_FRAME_SIZE");

            let config = EnvConfig::from_env().unwrap();
            assert!(!config.enable_http3);
            assert_eq!(config.http3_idle_timeout, 30);
            assert_eq!(config.http3_max_streams, 1000);
            // Frontend H3 defaults (conservative for untrusted clients)
            assert_eq!(config.http3_stream_receive_window, 262_144);
            assert_eq!(config.http3_receive_window, 2_097_152);
            assert_eq!(config.http3_send_window, 2_097_152);
            assert_eq!(config.http3_connections_per_backend, 4);
            assert_eq!(config.http3_pool_idle_timeout_seconds, 120);
            assert_eq!(config.http3_request_body_channel_capacity, 32);
            // Frontend H2 defaults (conservative for untrusted clients)
            assert_eq!(config.frontend_h2_initial_stream_window_size, 262_144);
            assert_eq!(config.frontend_h2_initial_connection_window_size, 2_097_152);
            assert_eq!(config.frontend_h2_max_frame_size, 16_384);
            assert_eq!(config.server_http2_max_pending_accept_reset_streams, 64);
            assert_eq!(config.server_http2_max_local_error_reset_streams, 256);
            assert_eq!(config.websocket_max_connections, 20_000);
        },
    );
}

#[test]
fn test_http3_connections_per_backend_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_CONNECTIONS_PER_BACKEND", "8"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_connections_per_backend, 8);
        },
    );
}

#[test]
fn test_http3_connections_per_backend_clamps_zero() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_CONNECTIONS_PER_BACKEND", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_connections_per_backend, 1);
        },
    );
}

#[test]
fn test_http3_pool_idle_timeout_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS", "45"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_pool_idle_timeout_seconds, 45);
        },
    );
}

#[test]
fn test_http3_request_body_channel_capacity_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY", "64"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_request_body_channel_capacity, 64);
        },
    );
}

#[test]
fn test_http3_request_body_channel_capacity_clamped_below_min() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_request_body_channel_capacity, 1);
        },
    );
}

#[test]
fn test_http3_request_body_channel_capacity_clamped_above_max() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY", "2048"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_request_body_channel_capacity, 1024);
        },
    );
}

#[test]
fn test_http3_request_body_channel_capacity_non_numeric_rejected() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY", "many"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.err().unwrap();
            assert!(
                err.contains("FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY"),
                "unexpected error: {err}"
            );
        },
    );
}

#[test]
fn test_http3_coalesce_min_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_HTTP3_COALESCE_MIN_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_min_bytes, 32_768);
        },
    );
}

#[test]
fn test_http3_coalesce_min_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MIN_BYTES", "16384"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_min_bytes, 16_384);
        },
    );
}

#[test]
fn test_http3_coalesce_min_clamped_above_max() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MIN_BYTES", "262144"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_min_bytes, 32_768);
        },
    );
}

#[test]
fn test_http3_coalesce_min_clamped_below_floor() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MIN_BYTES", "512"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_min_bytes, 1024);
        },
    );
}

#[test]
fn test_http3_coalesce_max_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_HTTP3_COALESCE_MAX_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_max_bytes, 32_768);
        },
    );
}

#[test]
fn test_http3_coalesce_max_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MAX_BYTES", "131072"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_max_bytes, 131_072);
        },
    );
}

#[test]
fn test_http3_coalesce_max_clamped_above_cap() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MAX_BYTES", "2097152"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_max_bytes, 1_048_576);
        },
    );
}

#[test]
fn test_http3_coalesce_max_clamped_below_floor() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MAX_BYTES", "512"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_max_bytes, 1024);
        },
    );
}

#[test]
fn test_http3_coalesce_min_clamped_to_runtime_max() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MAX_BYTES", "16384"),
            ("FERRUM_HTTP3_COALESCE_MIN_BYTES", "65536"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_max_bytes, 16_384);
            assert_eq!(config.http3_coalesce_min_bytes, 16_384);
        },
    );
}

#[test]
fn test_http3_coalesce_min_allows_large_value_when_max_raised() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MAX_BYTES", "262144"),
            ("FERRUM_HTTP3_COALESCE_MIN_BYTES", "131072"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_max_bytes, 262_144);
            assert_eq!(config.http3_coalesce_min_bytes, 131_072);
        },
    );
}

#[test]
fn test_h3_request_body_drain_ms_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_H3_REQUEST_BODY_DRAIN_MS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.h3_request_body_drain_ms, 50);
        },
    );
}

#[test]
fn test_h3_request_body_drain_ms_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_H3_REQUEST_BODY_DRAIN_MS", "200"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.h3_request_body_drain_ms, 200);
        },
    );
}

#[test]
fn test_h3_request_body_drain_ms_zero_disables() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_H3_REQUEST_BODY_DRAIN_MS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.h3_request_body_drain_ms, 0);
        },
    );
}

#[test]
fn test_h3_request_body_drain_ms_clamped_above_cap() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_H3_REQUEST_BODY_DRAIN_MS", "5000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.h3_request_body_drain_ms, 1000);
        },
    );
}

#[test]
fn test_http3_coalesce_min_non_numeric_rejected() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MIN_BYTES", "abc"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.err().unwrap();
            assert!(
                err.contains("FERRUM_HTTP3_COALESCE_MIN_BYTES"),
                "unexpected error: {err}"
            );
        },
    );
}

#[test]
fn test_http3_flush_interval_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_HTTP3_FLUSH_INTERVAL_MICROS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_flush_interval_micros, 200);
        },
    );
}

#[test]
fn test_http3_flush_interval_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_FLUSH_INTERVAL_MICROS", "500"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_flush_interval_micros, 500);
        },
    );
}

#[test]
fn test_http3_flush_interval_floor() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_FLUSH_INTERVAL_MICROS", "10"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_flush_interval_micros, 50);
        },
    );
}

#[test]
fn test_http3_flush_interval_ceiling() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_FLUSH_INTERVAL_MICROS", "200000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_flush_interval_micros, 100_000);
        },
    );
}

#[test]
fn test_http3_initial_mtu_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_HTTP3_INITIAL_MTU");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_initial_mtu, 1500);
        },
    );
}

#[test]
fn test_http3_initial_mtu_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_INITIAL_MTU", "1350"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_initial_mtu, 1350);
        },
    );
}

#[test]
fn test_http3_initial_mtu_below_min_rejected() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_INITIAL_MTU", "1199"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.err().unwrap();
            assert!(
                err.contains("FERRUM_HTTP3_INITIAL_MTU"),
                "unexpected error: {err}"
            );
        },
    );
}

#[test]
fn test_http3_initial_mtu_above_max_rejected() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_INITIAL_MTU", "65528"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.err().unwrap();
            assert!(
                err.contains("FERRUM_HTTP3_INITIAL_MTU"),
                "unexpected error: {err}"
            );
        },
    );
}

#[test]
fn test_http3_initial_mtu_u16_overflow_rejected() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_INITIAL_MTU", "70000"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.err().unwrap();
            assert!(
                err.contains("FERRUM_HTTP3_INITIAL_MTU"),
                "unexpected error: {err}"
            );
        },
    );
}

#[test]
fn test_http3_initial_mtu_non_numeric_rejected() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_INITIAL_MTU", "abc"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.err().unwrap();
            assert!(
                err.contains("FERRUM_HTTP3_INITIAL_MTU"),
                "unexpected error: {err}"
            );
        },
    );
}

#[test]
fn test_env_config_http2_reset_and_websocket_limits_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_SERVER_HTTP2_MAX_PENDING_ACCEPT_RESET_STREAMS", "96"),
            ("FERRUM_SERVER_HTTP2_MAX_LOCAL_ERROR_RESET_STREAMS", "384"),
            ("FERRUM_WEBSOCKET_MAX_CONNECTIONS", "4000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.server_http2_max_pending_accept_reset_streams, 96);
            assert_eq!(config.server_http2_max_local_error_reset_streams, 384);
            assert_eq!(config.websocket_max_connections, 4000);
        },
    );
}

#[test]
fn test_env_config_dns_overrides_parsing() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            (
                "FERRUM_DNS_OVERRIDES",
                r#"{"myhost.local":"10.0.0.1","other.local":"10.0.0.2"}"#,
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_overrides.len(), 2);
            assert_eq!(
                config.dns_overrides.get("myhost.local").unwrap(),
                "10.0.0.1"
            );
            assert_eq!(config.dns_overrides.get("other.local").unwrap(), "10.0.0.2");
        },
    );
}

#[test]
fn test_env_config_dns_overrides_empty() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DNS_OVERRIDES");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.dns_overrides.is_empty());
        },
    );
}

#[test]
fn test_env_config_tls_flags() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_TLS_NO_VERIFY", "true"),
            ("FERRUM_ADMIN_TLS_NO_VERIFY", "true"),
            ("FERRUM_ADMIN_READ_ONLY", "true"),
            ("FERRUM_ADMIN_AUDIT_ENABLED", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.tls_no_verify);
            assert!(config.admin_tls_no_verify);
            assert!(config.admin_read_only);
            assert!(config.admin_audit_enabled);
        },
    );
}

#[test]
fn test_env_config_tls_flags_default_false() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_TLS_NO_VERIFY");
            remove_var("FERRUM_ADMIN_TLS_NO_VERIFY");
            remove_var("FERRUM_ADMIN_READ_ONLY");
            remove_var("FERRUM_ADMIN_AUDIT_ENABLED");

            let config = EnvConfig::from_env().unwrap();
            assert!(!config.tls_no_verify);
            assert!(!config.admin_tls_no_verify);
            assert!(!config.admin_read_only);
            assert!(!config.admin_audit_enabled);
        },
    );
}

#[test]
fn test_env_config_gateway_svid_paths() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            (
                "FERRUM_GATEWAY_SVID_CERT_PATH",
                "/etc/ferrum/svid/gateway-chain.pem",
            ),
            (
                "FERRUM_GATEWAY_SVID_KEY_PATH",
                "/etc/ferrum/svid/gateway-key.pem",
            ),
            (
                "FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH",
                "/etc/ferrum/svid/trust-bundle.pem",
            ),
            (
                "FERRUM_GATEWAY_SPIFFE_ID",
                "spiffe://corp.example/ns/gateway/sa/edge",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.gateway_svid_cert_path.as_deref(),
                Some("/etc/ferrum/svid/gateway-chain.pem")
            );
            assert_eq!(
                config.gateway_svid_key_path.as_deref(),
                Some("/etc/ferrum/svid/gateway-key.pem")
            );
            assert_eq!(
                config.gateway_svid_trust_bundle_path.as_deref(),
                Some("/etc/ferrum/svid/trust-bundle.pem")
            );
            assert_eq!(
                config.gateway_spiffe_id.as_deref(),
                Some("spiffe://corp.example/ns/gateway/sa/edge")
            );
        },
    );
}

#[test]
fn test_env_config_request_limits_defaults() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_HEADER_SIZE_BYTES");
            remove_var("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES");

            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_header_size_bytes, 32768);
            assert_eq!(config.max_single_header_size_bytes, 16384);
            assert_eq!(config.max_request_body_size_bytes, 10_485_760);
            assert_eq!(config.max_response_body_size_bytes, 10_485_760);
            assert_eq!(config.max_header_count, 100);
            assert_eq!(config.max_url_length_bytes, 8_192);
            assert_eq!(config.max_query_params, 100);
            assert_eq!(config.max_grpc_recv_size_bytes, 4_194_304);
            assert_eq!(config.max_websocket_frame_size_bytes, 16_777_216);
            assert_eq!(config.http_header_read_timeout_seconds, 10);
            assert_eq!(config.frontend_tls_handshake_timeout_seconds, 10);
            assert!(config.add_via_header);
            assert_eq!(config.via_pseudonym, "ferrum-edge");
            assert!(!config.add_forwarded_header);
        },
    );
}

#[test]
fn test_env_config_database_mode_valid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "my-secret-padding-for-32-chars!!!",
            ),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::Database);
            assert_eq!(config.db_type, Some("sqlite".to_string()));
            assert_eq!(config.db_url, Some("sqlite::memory:".to_string()));
            assert_eq!(
                config.admin_jwt_secret,
                Some("my-secret-padding-for-32-chars!!!".to_string())
            );
        },
    );
}

#[test]
fn test_env_config_dp_mode_valid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://control-plane:50051"),
            // Non-loopback http:// CP URL requires the explicit plaintext opt-in.
            ("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", "true"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "my-secret-padding-for-32-char-min!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::DataPlane);
            assert_eq!(
                config.dp_cp_grpc_urls,
                vec!["http://control-plane:50051".to_string()]
            );
            assert_eq!(
                config.cp_dp_grpc_jwt_secret,
                Some("my-secret-padding-for-32-char-min!".to_string())
            );
        },
    );
}

#[test]
fn test_env_config_cp_mode_valid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "cp"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "admin-secret-padding-32-chars!!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_CP_GRPC_LISTEN_ADDR", "0.0.0.0:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "grpc-secret-padding-32-char-min!",
            ),
            // Non-loopback plaintext bind requires the explicit plaintext opt-in.
            ("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::ControlPlane);
            assert_eq!(
                config.cp_grpc_listen_addr,
                Some("0.0.0.0:50051".to_string())
            );
            assert_eq!(
                config.cp_dp_grpc_jwt_secret,
                Some("grpc-secret-padding-32-char-min!".to_string())
            );
        },
    );
}

// ============================================================================
// DNS Enhanced Configuration Tests
// ============================================================================

#[test]
fn test_env_config_dns_resolver_address() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_RESOLVER_ADDRESS", "1.1.1.1,8.8.8.8"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.dns_resolver_address,
                Some("1.1.1.1,8.8.8.8".to_string())
            );
        },
    );
}

#[test]
fn test_env_config_dns_resolver_address_not_set() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DNS_RESOLVER_ADDRESS");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.dns_resolver_address.is_none());
        },
    );
}

#[test]
fn test_env_config_dns_resolver_hosts_file() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_RESOLVER_HOSTS_FILE", "/custom/hosts"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.dns_resolver_hosts_file,
                Some("/custom/hosts".to_string())
            );
        },
    );
}

#[test]
fn test_env_config_dns_order() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_ORDER", "A,AAAA,SRV"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_order, Some("A,AAAA,SRV".to_string()));
        },
    );
}

#[test]
fn test_env_config_dns_ttl_override() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_TTL_OVERRIDE_SECONDS", "120"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_ttl_override, Some(120));
        },
    );
}

#[test]
fn test_env_config_dns_ttl_override_not_set() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DNS_TTL_OVERRIDE_SECONDS");
            let config = EnvConfig::from_env().unwrap();
            assert!(
                config.dns_ttl_override.is_none(),
                "dns_ttl_override should be None when not set"
            );
        },
    );
}

#[test]
fn test_env_config_dns_stale_ttl_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DNS_STALE_TTL");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.dns_stale_ttl, 3600,
                "dns_stale_ttl should default to 3600"
            );
        },
    );
}

#[test]
fn test_env_config_dns_stale_ttl_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_STALE_TTL", "7200"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_stale_ttl, 7200);
        },
    );
}

#[test]
fn test_env_config_dns_error_ttl_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DNS_ERROR_TTL");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_error_ttl, 5, "dns_error_ttl should default to 5");
        },
    );
}

#[test]
fn test_env_config_dns_error_ttl_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_ERROR_TTL", "5"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_error_ttl, 5);
        },
    );
}

#[test]
fn test_env_config_dns_warmup_concurrency_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DNS_WARMUP_CONCURRENCY");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_warmup_concurrency, 500);
        },
    );
}

#[test]
fn test_env_config_dns_warmup_concurrency_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_WARMUP_CONCURRENCY", "128"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_warmup_concurrency, 128);
        },
    );
}

#[test]
fn test_env_config_dns_warmup_concurrency_clamps_zero() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_WARMUP_CONCURRENCY", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_warmup_concurrency, 1);
        },
    );
}

// --- Pool Warmup Tests ---

#[test]
fn test_env_config_pool_warmup_enabled_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_POOL_WARMUP_ENABLED");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.pool_warmup_enabled);
        },
    );
}

#[test]
fn test_env_config_pool_warmup_enabled_false() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_POOL_WARMUP_ENABLED", "false"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(!config.pool_warmup_enabled);
        },
    );
}

#[test]
fn test_env_config_pool_warmup_concurrency_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_POOL_WARMUP_CONCURRENCY");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.pool_warmup_concurrency, 500);
        },
    );
}

#[test]
fn test_env_config_pool_warmup_concurrency_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_POOL_WARMUP_CONCURRENCY", "128"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.pool_warmup_concurrency, 128);
        },
    );
}

#[test]
fn test_env_config_pool_warmup_concurrency_clamps_zero() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_POOL_WARMUP_CONCURRENCY", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.pool_warmup_concurrency, 1);
        },
    );
}

// --- Size Limit Tests ---

#[test]
fn test_env_config_max_single_header_size_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_single_header_size_bytes, 16384,
                "max_single_header_size_bytes should default to 16384"
            );
        },
    );
}

#[test]
fn test_env_config_max_single_header_size_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES", "4096"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_single_header_size_bytes, 4096);
        },
    );
}

#[test]
fn test_env_config_max_response_body_size_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_response_body_size_bytes, 10_485_760,
                "max_response_body_size_bytes should default to 10MB"
            );
        },
    );
}

#[test]
fn test_env_config_max_response_body_size_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "52428800"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_response_body_size_bytes, 52_428_800);
        },
    );
}

#[test]
fn test_env_config_max_header_size_updated_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_HEADER_SIZE_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_header_size_bytes, 32768,
                "max_header_size_bytes should default to 32KB"
            );
        },
    );
}

#[test]
fn test_env_config_max_header_count_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_HEADER_COUNT");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_header_count, 100,
                "max_header_count should default to 100"
            );
        },
    );
}

#[test]
fn test_env_config_max_header_count_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_HEADER_COUNT", "200"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_header_count, 200);
        },
    );
}

#[test]
fn test_env_config_max_url_length_bytes_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_URL_LENGTH_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_url_length_bytes, 8_192,
                "max_url_length_bytes should default to 8KB"
            );
        },
    );
}

#[test]
fn test_env_config_max_url_length_bytes_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_URL_LENGTH_BYTES", "16384"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_url_length_bytes, 16_384);
        },
    );
}

#[test]
fn test_env_config_max_query_params_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_QUERY_PARAMS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_query_params, 100,
                "max_query_params should default to 100"
            );
        },
    );
}

#[test]
fn test_env_config_max_query_params_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_QUERY_PARAMS", "50"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_query_params, 50);
        },
    );
}

#[test]
fn test_env_config_max_grpc_recv_size_bytes_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_GRPC_RECV_SIZE_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_grpc_recv_size_bytes, 4_194_304,
                "max_grpc_recv_size_bytes should default to 4MB"
            );
        },
    );
}

#[test]
fn test_env_config_max_grpc_recv_size_bytes_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_GRPC_RECV_SIZE_BYTES", "8388608"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_grpc_recv_size_bytes, 8_388_608);
        },
    );
}

#[test]
fn test_env_config_max_websocket_frame_size_bytes_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_websocket_frame_size_bytes, 16_777_216,
                "max_websocket_frame_size_bytes should default to 16MB"
            );
        },
    );
}

#[test]
fn test_env_config_max_websocket_frame_size_bytes_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES", "33554432"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_websocket_frame_size_bytes, 33_554_432);
        },
    );
}

#[test]
fn test_env_config_websocket_idle_timeout_seconds_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_WEBSOCKET_IDLE_TIMEOUT_SECONDS");
            let config = EnvConfig::from_env().unwrap();
            // Safe production default: bound idle WebSocket lifetime to 5 minutes.
            assert_eq!(config.websocket_idle_timeout_seconds, 300);
        },
    );
}

#[test]
fn test_env_config_websocket_idle_timeout_seconds_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_WEBSOCKET_IDLE_TIMEOUT_SECONDS", "45"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.websocket_idle_timeout_seconds, 45);
        },
    );
}

// ============================================================================
// HTTP Header Read Timeout Tests
// ============================================================================

#[test]
fn test_env_config_http_header_read_timeout_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.http_header_read_timeout_seconds, 10,
                "http_header_read_timeout_seconds should default to 10"
            );
        },
    );
}

#[test]
fn test_env_config_http_header_read_timeout_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS", "60"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http_header_read_timeout_seconds, 60);
        },
    );
}

#[test]
fn test_env_config_http_header_read_timeout_disabled() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.http_header_read_timeout_seconds, 0,
                "0 should disable the header read timeout"
            );
        },
    );
}

#[test]
fn test_env_config_frontend_tls_handshake_timeout_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.frontend_tls_handshake_timeout_seconds, 10,
                "frontend_tls_handshake_timeout_seconds should default to 10"
            );
        },
    );
}

#[test]
fn test_env_config_frontend_tls_handshake_timeout_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS", "30"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.frontend_tls_handshake_timeout_seconds, 30);
        },
    );
}

#[test]
fn test_env_config_frontend_tls_handshake_timeout_disabled() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.frontend_tls_handshake_timeout_seconds, 0,
                "0 should disable the frontend TLS handshake timeout"
            );
        },
    );
}

// ============================================================================
// Per-IP Concurrent Request Limit Tests
// ============================================================================

#[test]
fn test_env_config_max_concurrent_requests_per_ip_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_concurrent_requests_per_ip, 0,
                "max_concurrent_requests_per_ip should default to 0 (disabled)"
            );
        },
    );
}

#[test]
fn test_env_config_max_concurrent_requests_per_ip_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP", "100"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_concurrent_requests_per_ip, 100);
        },
    );
}

// ============================================================================
// Admin Allowed CIDRs Tests
// ============================================================================

#[test]
fn test_env_config_admin_allowed_cidrs_default_empty() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_ADMIN_ALLOWED_CIDRS");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.admin_allowed_cidrs.is_empty());
        },
    );
}

#[test]
fn test_env_config_admin_allowed_cidrs_set() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_ADMIN_ALLOWED_CIDRS", "10.0.100.0/24,127.0.0.1,::1"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.admin_allowed_cidrs, "10.0.100.0/24,127.0.0.1,::1");
        },
    );
}

// ============================================================================
// Via / Forwarded Header Tests
// ============================================================================

#[test]
fn test_env_config_add_via_header_enabled() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_ADD_VIA_HEADER", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.add_via_header);
        },
    );
}

#[test]
fn test_env_config_via_pseudonym_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_VIA_PSEUDONYM", "my-gateway"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.via_pseudonym, "my-gateway");
        },
    );
}

#[test]
fn test_env_config_add_forwarded_header_enabled() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_ADD_FORWARDED_HEADER", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.add_forwarded_header);
        },
    );
}

// ============================================================================
// Backend Allow IPs (SSRF Protection) Tests
// ============================================================================

#[test]
fn test_env_config_backend_allow_ips_default_both() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_BACKEND_ALLOW_IPS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.backend_allow_ips.allow_ips(), &BackendAllowIps::Both);
        },
    );
}

#[test]
fn test_env_config_backend_allow_ips_private() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_BACKEND_ALLOW_IPS", "private"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.backend_allow_ips.allow_ips(),
                &BackendAllowIps::Private
            );
        },
    );
}

#[test]
fn test_env_config_backend_allow_ips_public() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_BACKEND_ALLOW_IPS", "public"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.backend_allow_ips.allow_ips(),
                &BackendAllowIps::Public
            );
        },
    );
}

#[test]
fn test_env_config_backend_allow_ips_case_insensitive() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_BACKEND_ALLOW_IPS", "PRIVATE"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.backend_allow_ips.allow_ips(),
                &BackendAllowIps::Private
            );
        },
    );
}

#[test]
fn test_env_config_backend_allow_ips_invalid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_BACKEND_ALLOW_IPS", "invalid"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("Invalid FERRUM_BACKEND_ALLOW_IPS")
            );
        },
    );
}

// ============================================================================
// is_private_ip / check_backend_ip_allowed Tests
// ============================================================================

use ferrum_edge::config::{BackendAllowIps, check_backend_ip_allowed, is_private_ip};

#[test]
fn test_is_private_ip_loopback_v4() {
    assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
    assert!(is_private_ip(&"127.255.255.255".parse().unwrap()));
}

#[test]
fn test_is_private_ip_rfc1918() {
    assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
    assert!(is_private_ip(&"10.255.255.255".parse().unwrap()));
    assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
    assert!(is_private_ip(&"172.31.255.255".parse().unwrap()));
    assert!(is_private_ip(&"192.168.0.1".parse().unwrap()));
    assert!(is_private_ip(&"192.168.255.255".parse().unwrap()));
}

#[test]
fn test_is_private_ip_link_local_v4() {
    assert!(is_private_ip(&"169.254.0.1".parse().unwrap()));
    assert!(is_private_ip(&"169.254.169.254".parse().unwrap()));
}

#[test]
fn test_is_private_ip_unspecified_v4() {
    assert!(is_private_ip(&"0.0.0.0".parse().unwrap()));
    assert!(is_private_ip(&"0.1.2.3".parse().unwrap()));
}

#[test]
fn test_is_private_ip_cgnat() {
    assert!(is_private_ip(&"100.64.0.1".parse().unwrap()));
    assert!(is_private_ip(&"100.127.255.255".parse().unwrap()));
    // 100.128.x.x is NOT CGNAT
    assert!(!is_private_ip(&"100.128.0.1".parse().unwrap()));
}

#[test]
fn test_is_private_ip_special_use_v4() {
    assert!(is_private_ip(&"192.0.0.1".parse().unwrap()));
    assert!(is_private_ip(&"192.0.0.8".parse().unwrap()));
    assert!(!is_private_ip(&"192.0.0.9".parse().unwrap()));
    assert!(!is_private_ip(&"192.0.0.10".parse().unwrap()));
    assert!(is_private_ip(&"192.0.0.170".parse().unwrap()));
    assert!(is_private_ip(&"192.0.2.5".parse().unwrap()));
    assert!(is_private_ip(&"192.88.99.1".parse().unwrap()));
    assert!(is_private_ip(&"198.18.0.1".parse().unwrap()));
    assert!(is_private_ip(&"198.51.100.5".parse().unwrap()));
    assert!(is_private_ip(&"203.0.113.5".parse().unwrap()));
    assert!(is_private_ip(&"224.0.0.1".parse().unwrap()));
    assert!(is_private_ip(&"240.0.0.1".parse().unwrap()));
}

#[test]
fn test_is_private_ip_public_v4() {
    assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
    assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
    assert!(!is_private_ip(&"100.128.0.1".parse().unwrap()));
}

#[test]
fn test_is_private_ip_ipv4_boundary_ranges() {
    for ip in [
        "9.255.255.255",
        "11.0.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.169.0.0",
        "100.63.255.255",
        "100.128.0.0",
    ] {
        assert!(
            !is_private_ip(&ip.parse().unwrap()),
            "{ip} should be public"
        );
    }

    for ip in [
        "10.0.0.0",
        "10.255.255.255",
        "172.16.0.0",
        "172.31.255.255",
        "192.168.0.0",
        "192.168.255.255",
        "100.64.0.0",
        "100.127.255.255",
    ] {
        assert!(
            is_private_ip(&ip.parse().unwrap()),
            "{ip} should be private/reserved"
        );
    }
}

#[test]
fn test_is_private_ip_ipv6() {
    assert!(is_private_ip(&"::1".parse().unwrap()));
    assert!(is_private_ip(&"::".parse().unwrap()));
    assert!(is_private_ip(&"fe80::1".parse().unwrap()));
    assert!(is_private_ip(&"fc00::1".parse().unwrap()));
    assert!(is_private_ip(&"fd00::1".parse().unwrap()));
    assert!(is_private_ip(&"ff02::1".parse().unwrap()));
    assert!(is_private_ip(&"2001:db8::1".parse().unwrap()));
    assert!(is_private_ip(&"::ffff:127.0.0.1".parse().unwrap()));
    assert!(is_private_ip(&"::127.0.0.1".parse().unwrap()));
    assert!(is_private_ip(&"64:ff9b::192.168.0.1".parse().unwrap()));
    assert!(is_private_ip(&"100::1".parse().unwrap()));
    assert!(is_private_ip(&"100:0:0:1::1".parse().unwrap()));
    assert!(is_private_ip(&"2001::1".parse().unwrap()));
    assert!(is_private_ip(&"2001:1::4".parse().unwrap()));
    assert!(is_private_ip(&"2001:2::1".parse().unwrap()));
    assert!(is_private_ip(&"2001:10::1".parse().unwrap()));
    // Public IPv6
    assert!(!is_private_ip(&"2607:f8b0:4004:800::200e".parse().unwrap()));
    assert!(!is_private_ip(&"::8.8.8.8".parse().unwrap()));
    assert!(!is_private_ip(&"64:ff9b::8.8.8.8".parse().unwrap()));
    assert!(!is_private_ip(&"100:0:0:2::1".parse().unwrap()));
    assert!(!is_private_ip(&"2001:1::1".parse().unwrap()));
    assert!(!is_private_ip(&"2001:1::2".parse().unwrap()));
    assert!(!is_private_ip(&"2001:1::3".parse().unwrap()));
    assert!(!is_private_ip(&"2001:3::1".parse().unwrap()));
    assert!(!is_private_ip(&"2001:4:112::1".parse().unwrap()));
    assert!(!is_private_ip(&"2001:20::1".parse().unwrap()));
    assert!(!is_private_ip(&"2001:30::1".parse().unwrap()));
}

#[test]
fn test_is_private_ip_ipv6_embedded_ipv4_boundaries() {
    for ip in [
        "::ffff:10.0.0.1",
        "::ffff:100.64.0.1",
        "::ffff:169.254.169.254",
        "::ffff:192.0.2.1",
        "::10.0.0.1",
        "64:ff9b::10.0.0.1",
        "64:ff9b::100.64.0.1",
        "64:ff9b::169.254.169.254",
        "64:ff9b::192.0.2.1",
        "64:ff9b:1::8.8.8.8",
    ] {
        assert!(
            is_private_ip(&ip.parse().unwrap()),
            "{ip} should be private/reserved"
        );
    }

    for ip in [
        "::ffff:8.8.8.8",
        "::8.8.8.8",
        "64:ff9b::8.8.8.8",
        "64:ff9b::192.0.0.9",
        "64:ff9b::192.0.0.10",
    ] {
        assert!(
            !is_private_ip(&ip.parse().unwrap()),
            "{ip} should be public"
        );
    }
}

#[test]
fn test_check_backend_ip_allowed_both_allows_all() {
    let policy = BackendAllowIps::Both;
    assert!(check_backend_ip_allowed(
        &"10.0.0.1".parse().unwrap(),
        &policy
    ));
    assert!(check_backend_ip_allowed(
        &"8.8.8.8".parse().unwrap(),
        &policy
    ));
    assert!(check_backend_ip_allowed(
        &"169.254.169.254".parse().unwrap(),
        &policy
    ));
    assert!(check_backend_ip_allowed(
        &"64:ff9b::192.168.0.1".parse().unwrap(),
        &policy
    ));
}

#[test]
fn test_check_backend_ip_allowed_public_denies_private() {
    let policy = BackendAllowIps::Public;
    assert!(!check_backend_ip_allowed(
        &"10.0.0.1".parse().unwrap(),
        &policy
    ));
    assert!(!check_backend_ip_allowed(
        &"127.0.0.1".parse().unwrap(),
        &policy
    ));
    assert!(!check_backend_ip_allowed(
        &"169.254.169.254".parse().unwrap(),
        &policy
    ));
    assert!(!check_backend_ip_allowed(
        &"100.64.0.1".parse().unwrap(),
        &policy
    ));
    assert!(!check_backend_ip_allowed(
        &"::ffff:10.0.0.1".parse().unwrap(),
        &policy
    ));
    assert!(!check_backend_ip_allowed(
        &"64:ff9b::192.168.0.1".parse().unwrap(),
        &policy
    ));
    // Public allowed
    assert!(check_backend_ip_allowed(
        &"8.8.8.8".parse().unwrap(),
        &policy
    ));
    assert!(check_backend_ip_allowed(
        &"64:ff9b::8.8.8.8".parse().unwrap(),
        &policy
    ));
}

#[test]
fn test_check_backend_ip_allowed_private_denies_public() {
    let policy = BackendAllowIps::Private;
    assert!(!check_backend_ip_allowed(
        &"8.8.8.8".parse().unwrap(),
        &policy
    ));
    assert!(!check_backend_ip_allowed(
        &"1.1.1.1".parse().unwrap(),
        &policy
    ));
    assert!(!check_backend_ip_allowed(
        &"64:ff9b::8.8.8.8".parse().unwrap(),
        &policy
    ));
    // Private allowed
    assert!(check_backend_ip_allowed(
        &"10.0.0.1".parse().unwrap(),
        &policy
    ));
    assert!(check_backend_ip_allowed(
        &"127.0.0.1".parse().unwrap(),
        &policy
    ));
    assert!(check_backend_ip_allowed(
        &"169.254.169.254".parse().unwrap(),
        &policy
    ));
    assert!(check_backend_ip_allowed(
        &"::ffff:10.0.0.1".parse().unwrap(),
        &policy
    ));
    assert!(check_backend_ip_allowed(
        &"64:ff9b::192.168.0.1".parse().unwrap(),
        &policy
    ));
}

// ============================================================================
// Database TLS Configuration Tests
// ============================================================================

#[test]
fn test_env_config_db_tls_defaults_none() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DB_TLS_MODE");
            remove_var("FERRUM_DB_TLS_CA_CERT_PATH");
            remove_var("FERRUM_DB_TLS_CLIENT_CERT_PATH");
            remove_var("FERRUM_DB_TLS_CLIENT_KEY_PATH");
            remove_var("FERRUM_DB_SSL_MODE");
            remove_var("FERRUM_DB_TLS_ENABLED");
            remove_var("FERRUM_DB_TLS_INSECURE");
            remove_var("FERRUM_DB_SSL_ROOT_CERT");
            remove_var("FERRUM_DB_SSL_CLIENT_CERT");
            remove_var("FERRUM_DB_SSL_CLIENT_KEY");

            let config = EnvConfig::from_env().unwrap();
            assert!(config.db_tls_mode.is_none());
            assert!(config.db_tls_ca_cert_path.is_none());
            assert!(config.db_tls_client_cert_path.is_none());
            assert!(config.db_tls_client_key_path.is_none());
        },
    );
}

#[test]
fn test_env_config_db_tls_mode_parsed() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_DB_TLS_MODE", "require"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_tls_mode, Some(DbTlsMode::Require));
        },
    );
}

#[test]
fn test_env_config_rejects_removed_db_tls_aliases() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_DB_SSL_MODE", "verify-full"),
            ("FERRUM_DB_SSL_ROOT_CERT", "/certs/ca.pem"),
            ("FERRUM_DB_SSL_CLIENT_CERT", "/certs/client.pem"),
            ("FERRUM_DB_SSL_CLIENT_KEY", "/certs/client-key.pem"),
        ],
        || {
            remove_var("FERRUM_DB_TLS_MODE");
            remove_var("FERRUM_DB_TLS_CA_CERT_PATH");
            remove_var("FERRUM_DB_TLS_CLIENT_CERT_PATH");
            remove_var("FERRUM_DB_TLS_CLIENT_KEY_PATH");

            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("Deprecated database TLS environment variables"));
            assert!(err.contains("FERRUM_DB_SSL_MODE"));
        },
    );
}

#[test]
fn test_effective_db_url_no_tls_params() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
        ],
        || {
            remove_var("FERRUM_DB_TLS_MODE");
            remove_var("FERRUM_DB_TLS_CA_CERT_PATH");
            remove_var("FERRUM_DB_TLS_CLIENT_CERT_PATH");
            remove_var("FERRUM_DB_TLS_CLIENT_KEY_PATH");

            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap().unwrap(),
                "postgres://localhost/ferrum"
            );
        },
    );
}

#[test]
fn test_effective_db_url_postgres_tls_mode() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_DB_TLS_MODE", "require"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap().unwrap(),
                "postgres://localhost/ferrum?sslmode=require"
            );
        },
    );
}

#[test]
fn test_effective_db_url_postgres_disable_tls_mode() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_DB_TLS_MODE", "disable"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap().unwrap(),
                "postgres://localhost/ferrum?sslmode=disable"
            );
        },
    );
}

#[test]
fn test_effective_db_url_postgres_all_tls_params() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            (
                "FERRUM_DB_URL",
                "postgres://user:pass@db.example.com/ferrum",
            ),
            ("FERRUM_DB_TLS_MODE", "verify-full"),
            ("FERRUM_DB_TLS_CA_CERT_PATH", "/certs/ca.pem"),
            ("FERRUM_DB_TLS_CLIENT_CERT_PATH", "/certs/client.pem"),
            ("FERRUM_DB_TLS_CLIENT_KEY_PATH", "/certs/client-key.pem"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap().unwrap(),
                "postgres://user:pass@db.example.com/ferrum?sslmode=verify-full&sslrootcert=/certs/ca.pem&sslcert=/certs/client.pem&sslkey=/certs/client-key.pem"
            );
        },
    );
}

#[test]
fn test_effective_db_url_postgres_existing_query_params() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            (
                "FERRUM_DB_URL",
                "postgres://localhost/ferrum?connect_timeout=10",
            ),
            ("FERRUM_DB_TLS_MODE", "require"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap().unwrap(),
                "postgres://localhost/ferrum?connect_timeout=10&sslmode=require"
            );
        },
    );
}

#[test]
fn test_effective_db_url_mysql_tls_mode_mapping() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mysql"),
            ("FERRUM_DB_URL", "mysql://localhost/ferrum"),
            ("FERRUM_DB_TLS_MODE", "require"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap().unwrap(),
                "mysql://localhost/ferrum?ssl-mode=REQUIRED"
            );
        },
    );
}

#[test]
fn test_effective_db_url_mysql_disable_tls_mode() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mysql"),
            ("FERRUM_DB_URL", "mysql://localhost/ferrum"),
            ("FERRUM_DB_TLS_MODE", "disable"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap().unwrap(),
                "mysql://localhost/ferrum?ssl-mode=DISABLED"
            );
        },
    );
}

#[test]
fn test_effective_db_url_mysql_verify_ca() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mysql"),
            ("FERRUM_DB_URL", "mysql://localhost/ferrum"),
            ("FERRUM_DB_TLS_MODE", "verify-ca"),
            ("FERRUM_DB_TLS_CA_CERT_PATH", "/certs/ca.pem"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap().unwrap(),
                "mysql://localhost/ferrum?ssl-mode=VERIFY_CA&ssl-ca=/certs/ca.pem"
            );
        },
    );
}

#[test]
fn test_effective_db_url_mysql_all_tls_params() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mysql"),
            ("FERRUM_DB_URL", "mysql://user:pass@db.example.com/ferrum"),
            ("FERRUM_DB_TLS_MODE", "verify-full"),
            ("FERRUM_DB_TLS_CA_CERT_PATH", "/certs/ca.pem"),
            ("FERRUM_DB_TLS_CLIENT_CERT_PATH", "/certs/client.pem"),
            ("FERRUM_DB_TLS_CLIENT_KEY_PATH", "/certs/client-key.pem"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap().unwrap(),
                "mysql://user:pass@db.example.com/ferrum?ssl-mode=VERIFY_IDENTITY&ssl-ca=/certs/ca.pem&ssl-cert=/certs/client.pem&ssl-key=/certs/client-key.pem"
            );
        },
    );
}

#[test]
fn test_env_config_db_tls_rejects_sqlite() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite://ferrum.db?mode=rwc"),
            ("FERRUM_DB_TLS_MODE", "require"),
            ("FERRUM_DB_TLS_CA_CERT_PATH", "/certs/ca.pem"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("SQLite has no network TLS"));
        },
    );
}

#[test]
fn test_env_config_db_tls_accepts_sqlite_disable_mode_as_noop() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite://ferrum.db?mode=rwc"),
            ("FERRUM_DB_TLS_MODE", "disable"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_tls_mode, Some(DbTlsMode::Disable));
            assert!(!config.db_tls_enabled());
            assert_eq!(
                config.effective_db_url().unwrap().unwrap(),
                "sqlite://ferrum.db?mode=rwc"
            );
        },
    );
}

#[test]
fn test_env_config_db_tls_rejects_sqlite_disable_with_cert_paths() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite://ferrum.db?mode=rwc"),
            ("FERRUM_DB_TLS_MODE", "disable"),
            ("FERRUM_DB_TLS_CA_CERT_PATH", "/certs/ca.pem"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("cannot be set when FERRUM_DB_TLS_MODE=disable"));
        },
    );
}

#[test]
fn test_env_config_db_tls_rejects_mysql_allow_mode() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mysql"),
            ("FERRUM_DB_URL", "mysql://localhost/ferrum"),
            ("FERRUM_DB_TLS_MODE", "allow"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("PostgreSQL-only"));
        },
    );
}

#[test]
fn test_effective_db_url_mysql_allow_returns_error_if_validation_bypassed() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mysql"),
            ("FERRUM_DB_URL", "mysql://localhost/ferrum"),
        ],
        || {
            let mut config = EnvConfig::from_env().unwrap();
            config.db_tls_mode = Some(DbTlsMode::Allow);

            let err = config.effective_db_url().unwrap_err();
            assert!(err.contains("PostgreSQL-only"));
        },
    );
}

#[test]
fn test_env_config_db_tls_rejects_mongodb_unsupported_mode() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mongodb"),
            ("FERRUM_DB_URL", "mongodb://localhost:27017/ferrum"),
            ("FERRUM_DB_TLS_MODE", "verify-ca"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("disable, require, verify-full"));
        },
    );
}

#[test]
fn test_env_config_db_tls_accepts_mongodb_require_as_insecure_tls() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mongodb"),
            ("FERRUM_DB_URL", "mongodb://localhost:27017/ferrum"),
            ("FERRUM_DB_TLS_MODE", "require"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_tls_mode, Some(DbTlsMode::Require));
            assert!(config.db_tls_enabled());
            assert!(config.mongodb_tls_allows_invalid_certs());
        },
    );
}

#[test]
fn test_env_config_db_tls_accepts_mongodb_verify_full() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mongodb"),
            ("FERRUM_DB_URL", "mongodb://localhost:27017/ferrum"),
            ("FERRUM_DB_TLS_MODE", "verify-full"),
            ("FERRUM_DB_TLS_CA_CERT_PATH", "/certs/ca.pem"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_tls_mode, Some(DbTlsMode::VerifyFull));
            assert!(config.db_tls_enabled());
            assert!(!config.mongodb_tls_allows_invalid_certs());
        },
    );
}

#[test]
fn test_env_config_db_tls_rejects_mongodb_uri_tls_conflict() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mongodb"),
            (
                "FERRUM_DB_URL",
                "mongodb://localhost:27017/ferrum?tls=false",
            ),
            ("FERRUM_DB_TLS_MODE", "verify-full"),
        ],
        || {
            let error = EnvConfig::from_env().unwrap_err();
            assert!(error.contains("conflicts with MongoDB URI TLS settings"));
            assert!(error.contains("exactly one source"));
        },
    );
}

#[test]
fn test_env_config_db_tls_rejects_mongodb_srv_implicit_tls_conflict() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mongodb"),
            ("FERRUM_DB_URL", "mongodb+srv://cluster.example.test/ferrum"),
            ("FERRUM_DB_TLS_MODE", "disable"),
        ],
        || {
            let error = EnvConfig::from_env().unwrap_err();
            assert!(error.contains("mongodb+srv implicit TLS"));
        },
    );
}

#[test]
fn test_env_config_db_tls_rejects_mongodb_failover_uri_tls_conflict() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mongodb"),
            ("FERRUM_DB_URL", "mongodb://primary:27017/ferrum"),
            (
                "FERRUM_DB_FAILOVER_URLS",
                "mongodb://secondary:27017/ferrum?tls=true",
            ),
            ("FERRUM_DB_TLS_MODE", "require"),
        ],
        || {
            let error = EnvConfig::from_env().unwrap_err();
            assert!(error.contains("secondary:27017"));
            assert!(error.contains("conflicts with MongoDB URI TLS settings"));
        },
    );
}

#[test]
fn test_env_config_db_tls_rejects_mongodb_seed_list_uri_tls_conflict() {
    // Multi-host seed lists are unparseable by `url::Url`; the conflict must
    // still be caught by MongoDB-aware query parsing.
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mongodb"),
            (
                "FERRUM_DB_URL",
                "mongodb://db0:27017,db1:27017/ferrum?tls=true",
            ),
            ("FERRUM_DB_TLS_MODE", "disable"),
        ],
        || {
            let error = EnvConfig::from_env().unwrap_err();
            assert!(
                error.contains("conflicts with MongoDB URI TLS settings"),
                "seed-list TLS option was not detected: {error}"
            );
            assert!(error.contains("tls"));
            assert!(error.contains("exactly one source"));
        },
    );
}

#[test]
fn test_env_config_mongodb_ignores_read_replica_url_and_skips_tls_conflict() {
    // FERRUM_DB_READ_REPLICA_URL is SQL-only; the MongoDB config store forces
    // primary reads and never opens a replica pool. A stale/unused Mongo replica
    // URI carrying TLS options must therefore NOT trip the MongoDB URI-TLS
    // conflict check and fail startup — the value is simply ignored.
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mongodb"),
            ("FERRUM_DB_URL", "mongodb://primary:27017/ferrum"),
            (
                "FERRUM_DB_READ_REPLICA_URL",
                "mongodb://replica:27017/ferrum?tls=true",
            ),
            ("FERRUM_DB_TLS_MODE", "require"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            // The raw value is still parsed into the config...
            assert_eq!(
                config.db_read_replica_url.as_deref(),
                Some("mongodb://replica:27017/ferrum?tls=true")
            );
            // ...but the effective replica URL is None for MongoDB (ignored),
            // so the shared TLS-conflict path never runs for it.
            assert!(config.effective_db_read_replica_url().unwrap().is_none());
        },
    );
}

#[test]
fn test_env_config_db_tls_accepts_mongodb_combined_client_pem() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mongodb"),
            ("FERRUM_DB_URL", "mongodb://localhost:27017/ferrum"),
            ("FERRUM_DB_TLS_MODE", "verify-full"),
            (
                "FERRUM_DB_TLS_CLIENT_CERT_PATH",
                "/certs/client-combined.pem",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.db_tls_client_cert_path.as_deref(),
                Some("/certs/client-combined.pem")
            );
            assert!(config.db_tls_client_key_path.is_none());
        },
    );
}

#[test]
fn test_env_config_db_tls_rejects_mongodb_client_key_without_cert() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mongodb"),
            ("FERRUM_DB_URL", "mongodb://localhost:27017/ferrum"),
            ("FERRUM_DB_TLS_MODE", "verify-full"),
            ("FERRUM_DB_TLS_CLIENT_KEY_PATH", "/certs/client-key.pem"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("FERRUM_DB_TLS_CLIENT_CERT_PATH is missing"));
        },
    );
}

#[test]
fn test_env_config_db_tls_ca_requires_mode() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_DB_TLS_CA_CERT_PATH", "/certs/ca.pem"),
        ],
        || {
            remove_var("FERRUM_DB_TLS_MODE");
            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("FERRUM_DB_TLS_MODE is required"));
        },
    );
}

#[test]
fn test_env_config_db_tls_rejects_client_cert_without_key() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_DB_TLS_MODE", "verify-full"),
            ("FERRUM_DB_TLS_CLIENT_CERT_PATH", "/certs/client.pem"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("FERRUM_DB_TLS_CLIENT_KEY_PATH is missing"));
        },
    );
}

#[test]
fn test_env_config_db_tls_rejects_client_key_without_cert() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mysql"),
            ("FERRUM_DB_URL", "mysql://localhost/ferrum"),
            ("FERRUM_DB_TLS_MODE", "verify-full"),
            ("FERRUM_DB_TLS_CLIENT_KEY_PATH", "/certs/client-key.pem"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("FERRUM_DB_TLS_CLIENT_CERT_PATH is missing"));
        },
    );
}

#[test]
fn test_plugin_http_slow_threshold_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.plugin_http_slow_threshold_ms, 1000);
        },
    );
}

#[test]
fn test_plugin_http_slow_threshold_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS", "5000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.plugin_http_slow_threshold_ms, 5000);
        },
    );
}

#[test]
fn test_plugin_http_slow_threshold_zero() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.plugin_http_slow_threshold_ms, 0);
        },
    );
}

#[test]
fn test_plugin_http_slow_threshold_invalid_errors() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS", "not_a_number"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS")
            );
        },
    );
}

#[test]
fn test_plugin_http_retries_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_PLUGIN_HTTP_MAX_RETRIES");
            remove_var("FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.plugin_http_max_retries, 0);
            assert_eq!(config.plugin_http_retry_delay_ms, 100);
        },
    );
}

#[test]
fn test_plugin_http_retries_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_PLUGIN_HTTP_MAX_RETRIES", "4"),
            ("FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS", "250"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.plugin_http_max_retries, 4);
            assert_eq!(config.plugin_http_retry_delay_ms, 250);
        },
    );
}

#[test]
fn test_plugin_http_retries_invalid_error() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_PLUGIN_HTTP_MAX_RETRIES", "not_a_number"),
            ("FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS", "also_bad"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("FERRUM_PLUGIN_HTTP_MAX_RETRIES")
            );
        },
    );
}

#[test]
fn test_effective_db_url_none_when_no_db_url() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DB_URL");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.effective_db_url().unwrap().is_none());
        },
    );
}

// ============================================================================
// Database Failover URL Tests
// ============================================================================

#[test]
fn test_db_failover_urls_empty_by_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.db_failover_urls.is_empty());
            assert!(config.effective_db_failover_urls().unwrap().is_empty());
        },
    );
}

#[test]
fn test_db_failover_urls_parsed() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://primary/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            (
                "FERRUM_DB_FAILOVER_URLS",
                "postgres://secondary1/ferrum, postgres://secondary2/ferrum",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_failover_urls.len(), 2);
            assert_eq!(config.db_failover_urls[0], "postgres://secondary1/ferrum");
            assert_eq!(config.db_failover_urls[1], "postgres://secondary2/ferrum");
        },
    );
}

#[test]
fn test_db_failover_urls_filters_empty_entries() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://primary/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            ("FERRUM_DB_FAILOVER_URLS", "postgres://secondary/ferrum,,, "),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_failover_urls.len(), 1);
            assert_eq!(config.db_failover_urls[0], "postgres://secondary/ferrum");
        },
    );
}

#[test]
fn test_db_failover_urls_with_tls_params() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://primary/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            ("FERRUM_DB_FAILOVER_URLS", "postgres://secondary/ferrum"),
            ("FERRUM_DB_TLS_MODE", "verify-full"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let effective = config.effective_db_failover_urls().unwrap();
            assert_eq!(effective.len(), 1);
            assert!(effective[0].contains("sslmode=verify-full"));
        },
    );
}

// ============================================================================
// Database Read Replica URL Tests
// ============================================================================

#[test]
fn test_db_read_replica_url_none_by_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.db_read_replica_url.is_none());
            assert!(config.effective_db_read_replica_url().unwrap().is_none());
        },
    );
}

#[test]
fn test_db_read_replica_url_parsed() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://primary/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            ("FERRUM_DB_READ_REPLICA_URL", "postgres://replica/ferrum"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.db_read_replica_url.as_deref(),
                Some("postgres://replica/ferrum")
            );
            assert_eq!(
                config.effective_db_read_replica_url().unwrap().as_deref(),
                Some("postgres://replica/ferrum")
            );
        },
    );
}

#[test]
fn test_db_read_replica_url_with_tls_params() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://primary/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            ("FERRUM_DB_READ_REPLICA_URL", "postgres://replica/ferrum"),
            ("FERRUM_DB_TLS_MODE", "verify-ca"),
            ("FERRUM_DB_TLS_CA_CERT_PATH", "/path/to/ca.pem"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let effective = config.effective_db_read_replica_url().unwrap().unwrap();
            assert!(effective.contains("sslmode=verify-ca"));
            assert!(effective.contains("sslrootcert=/path/to/ca.pem"));
        },
    );
}

#[test]
fn test_db_read_replica_url_mysql_tls_mode_translation() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "mysql"),
            ("FERRUM_DB_URL", "mysql://primary/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            ("FERRUM_DB_READ_REPLICA_URL", "mysql://replica/ferrum"),
            ("FERRUM_DB_TLS_MODE", "verify-full"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let effective = config.effective_db_read_replica_url().unwrap().unwrap();
            assert!(effective.contains("ssl-mode=VERIFY_IDENTITY"));
        },
    );
}

#[test]
fn test_db_read_replica_url_sqlite_no_tls() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite://ferrum.db"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            ("FERRUM_DB_READ_REPLICA_URL", "sqlite://replica.db"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let effective = config.effective_db_read_replica_url().unwrap().unwrap();
            // SQLite should not get SSL params
            assert_eq!(effective, "sqlite://replica.db");
        },
    );
}

#[test]
fn test_env_config_tcp_idle_timeout_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_TCP_IDLE_TIMEOUT_SECONDS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tcp_idle_timeout_seconds, 300);
        },
    );
}

#[test]
fn test_env_config_tcp_idle_timeout_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_TCP_IDLE_TIMEOUT_SECONDS", "600"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tcp_idle_timeout_seconds, 600);
        },
    );
}

#[test]
fn test_env_config_tcp_idle_timeout_zero_disables() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_TCP_IDLE_TIMEOUT_SECONDS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tcp_idle_timeout_seconds, 0);
        },
    );
}

// ============================================================================
// Database Connection Pool Configuration Tests
// ============================================================================

#[test]
fn test_env_config_db_pool_defaults() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DB_POOL_MAX_CONNECTIONS");
            remove_var("FERRUM_DB_POOL_MIN_CONNECTIONS");
            remove_var("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS");
            remove_var("FERRUM_DB_POOL_IDLE_TIMEOUT_SECONDS");
            remove_var("FERRUM_DB_POOL_MAX_LIFETIME_SECONDS");
            remove_var("FERRUM_DB_POOL_CONNECT_TIMEOUT_SECONDS");
            remove_var("FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS");

            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_pool_max_connections, 32);
            assert_eq!(config.db_pool_min_connections, 1);
            assert_eq!(config.db_pool_acquire_timeout_seconds, 30);
            assert_eq!(config.db_pool_idle_timeout_seconds, 600);
            assert_eq!(config.db_pool_max_lifetime_seconds, 300);
            assert_eq!(config.db_pool_connect_timeout_seconds, 10);
            assert_eq!(config.db_pool_statement_timeout_seconds, 30);
        },
    );
}

#[test]
fn test_env_config_db_pool_custom_values() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_DB_POOL_MAX_CONNECTIONS", "50"),
            ("FERRUM_DB_POOL_MIN_CONNECTIONS", "5"),
            ("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "60"),
            ("FERRUM_DB_POOL_IDLE_TIMEOUT_SECONDS", "1200"),
            ("FERRUM_DB_POOL_MAX_LIFETIME_SECONDS", "600"),
            ("FERRUM_DB_POOL_CONNECT_TIMEOUT_SECONDS", "15"),
            ("FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS", "60"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_pool_max_connections, 50);
            assert_eq!(config.db_pool_min_connections, 5);
            assert_eq!(config.db_pool_acquire_timeout_seconds, 60);
            assert_eq!(config.db_pool_idle_timeout_seconds, 1200);
            assert_eq!(config.db_pool_max_lifetime_seconds, 600);
            assert_eq!(config.db_pool_connect_timeout_seconds, 15);
            assert_eq!(config.db_pool_statement_timeout_seconds, 60);
        },
    );
}

#[test]
fn test_env_config_grpc_pool_ready_wait_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_GRPC_POOL_READY_WAIT_MS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.grpc_pool_ready_wait_ms, 1);
        },
    );
}

#[test]
fn test_env_config_grpc_pool_ready_wait_custom_value() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_GRPC_POOL_READY_WAIT_MS", "7"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.grpc_pool_ready_wait_ms, 7);
        },
    );
}

#[test]
fn test_env_config_db_pool_max_connections_minimum_clamped() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_POOL_MAX_CONNECTIONS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.db_pool_max_connections, 1,
                "max_connections should be clamped to at least 1"
            );
        },
    );
}

#[test]
fn test_env_config_db_pool_min_connections_zero_allowed() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_POOL_MIN_CONNECTIONS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.db_pool_min_connections, 0,
                "min_connections=0 should be allowed (no eager warming)"
            );
        },
    );
}

#[test]
fn test_env_config_db_pool_statement_timeout_zero_disables() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.db_pool_statement_timeout_seconds, 0,
                "0 should disable statement timeout"
            );
        },
    );
}

#[test]
fn test_env_config_db_pool_statement_timeout_at_max() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS", "3600"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.db_pool_statement_timeout_seconds, 3600,
                "3600 should be accepted as-is (at the max boundary)"
            );
        },
    );
}

#[test]
fn test_env_config_db_pool_statement_timeout_above_max_clamped() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS", "3601"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.db_pool_statement_timeout_seconds, 3600,
                "values above 3600 should be clamped to 3600"
            );
        },
    );
}

#[test]
fn test_env_config_db_pool_invalid_values_error() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_POOL_MAX_CONNECTIONS", "not_a_number"),
            ("FERRUM_DB_POOL_MIN_CONNECTIONS", "abc"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("FERRUM_DB_POOL_MAX_CONNECTIONS")
            );
        },
    );
}

// --- reserved_gateway_ports tests ---

#[test]
fn test_reserved_gateway_ports_defaults() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/test.yaml"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let ports = config.reserved_gateway_ports();
            assert!(
                ports.contains(&8000),
                "should contain default proxy HTTP port"
            );
            assert!(
                ports.contains(&8443),
                "should contain default proxy HTTPS port"
            );
            assert!(
                ports.contains(&9000),
                "should contain default admin HTTP port"
            );
            assert!(
                ports.contains(&9443),
                "should contain default admin HTTPS port"
            );
        },
    );
}

#[test]
fn test_reserved_gateway_ports_custom_ports() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/test.yaml"),
            ("FERRUM_PROXY_HTTP_PORT", "3000"),
            ("FERRUM_ADMIN_HTTP_PORT", "4000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let ports = config.reserved_gateway_ports();
            assert!(ports.contains(&3000));
            assert!(ports.contains(&4000));
        },
    );
}

#[test]
fn test_reserved_gateway_ports_includes_grpc() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/test.yaml"),
            ("FERRUM_CP_GRPC_LISTEN_ADDR", "0.0.0.0:50051"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let ports = config.reserved_gateway_ports();
            assert!(ports.contains(&50051), "should contain CP gRPC port");
        },
    );
}

#[test]
fn test_reserved_gateway_ports_excludes_disabled_ports() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/test.yaml"),
            ("FERRUM_PROXY_HTTP_PORT", "0"),
            ("FERRUM_PROXY_HTTPS_PORT", "0"),
            ("FERRUM_ADMIN_HTTP_PORT", "0"),
            ("FERRUM_ADMIN_HTTPS_PORT", "0"),
            ("FERRUM_CP_GRPC_LISTEN_ADDR", "0.0.0.0:0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let ports = config.reserved_gateway_ports();
            assert!(
                !ports.contains(&0),
                "disabled listener port 0 must not be reserved"
            );
            assert!(ports.is_empty(), "all configured listeners are disabled");
        },
    );
}

#[test]
fn test_reserved_gateway_ports_extracts_ipv6_grpc_port() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/test.yaml"),
            ("FERRUM_CP_GRPC_LISTEN_ADDR", "[::]:50051"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let ports = config.reserved_gateway_ports();
            assert!(ports.contains(&50051), "should contain IPv6 CP gRPC port");
        },
    );
}

#[test]
fn test_db_slow_query_threshold_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DB_SLOW_QUERY_THRESHOLD_MS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_slow_query_threshold_ms, None);
        },
    );
}

#[test]
fn test_db_slow_query_threshold_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_SLOW_QUERY_THRESHOLD_MS", "500"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_slow_query_threshold_ms, Some(500));
        },
    );
}

#[test]
fn test_db_slow_query_threshold_invalid_errors() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_SLOW_QUERY_THRESHOLD_MS", "not_a_number"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("FERRUM_DB_SLOW_QUERY_THRESHOLD_MS")
            );
        },
    );
}

// ---------------------------------------------------------------------------
// MongoDB configuration tests
// ---------------------------------------------------------------------------

#[test]
fn test_mongo_database_defaults_to_ferrum() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mongo_database, "ferrum");
        },
    );
}

#[test]
fn test_mongo_database_custom_value() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MONGO_DATABASE", "my_gateway"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mongo_database, "my_gateway");
        },
    );
}

#[test]
fn test_mongo_app_name_optional() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MONGO_APP_NAME", "my-edge-proxy"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mongo_app_name, Some("my-edge-proxy".to_string()));
        },
    );
}

#[test]
fn test_mongo_replica_set_optional() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MONGO_REPLICA_SET", "rs0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mongo_replica_set, Some("rs0".to_string()));
        },
    );
}

#[test]
fn test_mongo_timeouts_custom_values() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS", "60"),
            ("FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS", "5"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mongo_server_selection_timeout_seconds, Some(60));
            assert_eq!(config.mongo_connect_timeout_seconds, Some(5));
        },
    );
}

#[test]
fn test_mongo_timeouts_default_values() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS");
            remove_var("FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.mongo_server_selection_timeout_seconds, None,
                "unset timeout env must stay None so URI values are preserved"
            );
            assert_eq!(
                config.mongo_connect_timeout_seconds, None,
                "unset timeout env must stay None so URI values are preserved"
            );
        },
    );
}

// ============================================================================
// Circuit Breaker Cache Max Entries Tests
// ============================================================================

#[test]
fn test_env_config_circuit_breaker_cache_max_entries_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_CIRCUIT_BREAKER_CACHE_MAX_ENTRIES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.circuit_breaker_cache_max_entries, 10_000,
                "circuit_breaker_cache_max_entries should default to 10000"
            );
        },
    );
}

#[test]
fn test_env_config_circuit_breaker_cache_max_entries_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_CIRCUIT_BREAKER_CACHE_MAX_ENTRIES", "500"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.circuit_breaker_cache_max_entries, 500);
        },
    );
}

// ============================================================================
// Status Counts Max Entries Tests
// ============================================================================

#[test]
fn test_env_config_status_counts_max_entries_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_STATUS_COUNTS_MAX_ENTRIES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.status_counts_max_entries, 200,
                "status_counts_max_entries should default to 200"
            );
        },
    );
}

#[test]
fn test_env_config_status_counts_max_entries_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_STATUS_COUNTS_MAX_ENTRIES", "50"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.status_counts_max_entries, 50);
        },
    );
}

// ============================================================================
// Status Metrics Window Seconds Tests
// ============================================================================

#[test]
fn test_env_config_status_metrics_window_seconds_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_STATUS_METRICS_WINDOW_SECONDS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.status_metrics_window_seconds, 30,
                "status_metrics_window_seconds should default to 30"
            );
        },
    );
}

#[test]
fn test_env_config_status_metrics_window_seconds_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_STATUS_METRICS_WINDOW_SECONDS", "60"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.status_metrics_window_seconds, 60);
        },
    );
}

#[test]
fn test_env_config_status_metrics_window_seconds_minimum_clamped() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_STATUS_METRICS_WINDOW_SECONDS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.status_metrics_window_seconds, 1,
                "status_metrics_window_seconds should be clamped to minimum of 1"
            );
        },
    );
}

// ============================================================================
// Runtime Metrics Config Tests
// ============================================================================

#[test]
fn test_env_config_runtime_metrics_defaults() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_runtime_metrics_env_vars();
            let config = EnvConfig::from_env().unwrap();

            assert_eq!(config.runtime_metrics_system_sample_interval_ms, 1000);
            assert_eq!(config.runtime_metrics_window_1m_seconds, 60);
            assert_eq!(config.runtime_metrics_window_5m_seconds, 300);
            assert!(config.runtime_metrics_log_counter_enabled);
            assert_eq!(config.runtime_metrics_cache_ttl_ms, 1000);
            assert!(config.runtime_metrics_pool_tracking_enabled);
            assert!(config.runtime_metrics_status_tracking_enabled);
        },
    );
}

#[test]
fn test_env_config_runtime_metrics_custom_values() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_METRICS_SYSTEM_SAMPLE_INTERVAL_MS", "250"),
            ("FERRUM_METRICS_WINDOW_1M_SECONDS", "15"),
            ("FERRUM_METRICS_WINDOW_5M_SECONDS", "120"),
            ("FERRUM_METRICS_LOG_COUNTER_ENABLED", "false"),
            ("FERRUM_METRICS_RUNTIME_CACHE_MS", "0"),
            ("FERRUM_METRICS_POOL_TRACKING_ENABLED", "false"),
            ("FERRUM_METRICS_STATUS_TRACKING_ENABLED", "false"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();

            assert_eq!(config.runtime_metrics_system_sample_interval_ms, 250);
            assert_eq!(config.runtime_metrics_window_1m_seconds, 15);
            assert_eq!(config.runtime_metrics_window_5m_seconds, 120);
            assert!(!config.runtime_metrics_log_counter_enabled);
            assert_eq!(config.runtime_metrics_cache_ttl_ms, 0);
            assert!(!config.runtime_metrics_pool_tracking_enabled);
            assert!(!config.runtime_metrics_status_tracking_enabled);
        },
    );
}

#[test]
fn test_env_config_runtime_metrics_minimums_are_clamped() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_METRICS_SYSTEM_SAMPLE_INTERVAL_MS", "1"),
            ("FERRUM_METRICS_WINDOW_1M_SECONDS", "0"),
            ("FERRUM_METRICS_WINDOW_5M_SECONDS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();

            assert_eq!(
                config.runtime_metrics_system_sample_interval_ms, 100,
                "system sampler interval should clamp to the documented minimum"
            );
            assert_eq!(
                config.runtime_metrics_window_1m_seconds, 1,
                "1m runtime metrics window should clamp away from zero"
            );
            assert_eq!(
                config.runtime_metrics_window_5m_seconds, 1,
                "5m runtime metrics window should clamp away from zero"
            );
        },
    );
}

#[test]
fn test_env_config_node_agent_contract_defaults() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "node_agent"),
            ("FERRUM_NODE_AGENT_NODE_NAME", "node-a"),
        ],
        || {
            remove_var("FERRUM_NODE_AGENT_PROXY_MODE");
            remove_var("FERRUM_NODE_AGENT_ADMIN_ENABLED");
            remove_var("FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.node_agent_proxy_mode, NodeAgentProxyMode::LocalPod);
            assert!(!config.node_agent_admin_enabled);
            assert_eq!(
                config.node_agent_hbone_redirect_port,
                ferrum_ebpf_common::INBOUND_HBONE_PORT
            );
        },
    );
}

#[test]
fn test_env_config_node_agent_contract_custom_values() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "node_agent"),
            ("FERRUM_NODE_AGENT_NODE_NAME", "node-a"),
            ("FERRUM_NODE_AGENT_PROXY_MODE", "node_waypoint"),
            ("FERRUM_NODE_AGENT_ADMIN_ENABLED", "true"),
            ("FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT", "16008"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.node_agent_proxy_mode,
                NodeAgentProxyMode::NodeWaypoint
            );
            assert!(config.node_agent_admin_enabled);
            assert_eq!(config.node_agent_hbone_redirect_port, 16008);
        },
    );
}

#[test]
fn test_env_config_node_agent_rejects_invalid_proxy_mode() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "node_agent"),
            ("FERRUM_NODE_AGENT_NODE_NAME", "node-a"),
            ("FERRUM_NODE_AGENT_PROXY_MODE", "bad"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("FERRUM_NODE_AGENT_PROXY_MODE"));
        },
    );
}

#[test]
fn test_env_config_node_agent_rejects_hbone_port_equal_to_outbound_capture() {
    let outbound_capture_port = ferrum_ebpf_common::OUTBOUND_CAPTURE_PORT.to_string();
    with_env_vars(
        &[
            ("FERRUM_MODE", "node_agent"),
            ("FERRUM_NODE_AGENT_NODE_NAME", "node-a"),
            (
                "FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT",
                outbound_capture_port.as_str(),
            ),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT"));
            assert!(err.contains("outbound capture port"));
        },
    );
}

// --- DP CP failover URL tests ---

#[test]
fn test_resolved_dp_cp_grpc_urls_single_entry() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp1:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            // Non-loopback http:// CP URL requires the explicit plaintext opt-in.
            ("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let urls = config.resolved_dp_cp_grpc_urls();
            assert_eq!(urls, vec!["http://cp1:50051"]);
        },
    );
}

#[test]
fn test_resolved_dp_cp_grpc_urls_multi_urls_only() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            (
                "FERRUM_DP_CP_GRPC_URLS",
                "https://cp1:50051,https://cp2:50051,https://cp3:50051",
            ),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let urls = config.resolved_dp_cp_grpc_urls();
            assert_eq!(
                urls,
                vec![
                    "https://cp1:50051",
                    "https://cp2:50051",
                    "https://cp3:50051",
                ]
            );
        },
    );
}

#[test]
fn test_resolved_dp_cp_grpc_urls_trims_whitespace() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            (
                "FERRUM_DP_CP_GRPC_URLS",
                " https://cp1:50051 , https://cp2:50051 ",
            ),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.dp_cp_grpc_urls,
                vec!["https://cp1:50051", "https://cp2:50051"]
            );
        },
    );
}

#[test]
fn test_resolved_dp_cp_grpc_urls_filters_empty() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            (
                "FERRUM_DP_CP_GRPC_URLS",
                "https://cp1:50051,,https://cp2:50051,",
            ),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.dp_cp_grpc_urls,
                vec!["https://cp1:50051", "https://cp2:50051"]
            );
        },
    );
}

#[test]
fn test_dp_mode_validation_accepts_urls() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URLS", "https://cp1:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.resolved_dp_cp_grpc_urls(), vec!["https://cp1:50051"]);
        },
    );
}

#[test]
fn test_dp_mode_validation_rejects_no_url() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                err.contains("FERRUM_DP_CP_GRPC_URLS"),
                "Error should mention required env var: {}",
                err
            );
        },
    );
}

#[test]
fn test_dp_cp_failover_primary_retry_secs_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            // Non-loopback http:// CP URL requires the explicit plaintext opt-in.
            ("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dp_cp_failover_primary_retry_secs, 300);
        },
    );
}

#[test]
fn test_dp_cp_failover_primary_retry_secs_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS", "60"),
            // Non-loopback http:// CP URL requires the explicit plaintext opt-in.
            ("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dp_cp_failover_primary_retry_secs, 60);
        },
    );
}

// ============================================================================
// TLS 1.3 0-RTT early data methods
// ============================================================================

#[test]
fn test_tls_early_data_methods_default_empty() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/r.yaml"),
        ],
        || {
            remove_var("FERRUM_TLS_EARLY_DATA_METHODS");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.tls_early_data_methods.is_empty());
        },
    );
}

#[test]
fn test_tls_early_data_methods_single() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/r.yaml"),
            ("FERRUM_TLS_EARLY_DATA_METHODS", "GET"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tls_early_data_methods.len(), 1);
            assert!(config.tls_early_data_methods.contains("GET"));
        },
    );
}

#[test]
fn test_tls_early_data_methods_multiple_comma_separated() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/r.yaml"),
            ("FERRUM_TLS_EARLY_DATA_METHODS", "GET, HEAD, OPTIONS"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tls_early_data_methods.len(), 3);
            assert!(config.tls_early_data_methods.contains("GET"));
            assert!(config.tls_early_data_methods.contains("HEAD"));
            assert!(config.tls_early_data_methods.contains("OPTIONS"));
        },
    );
}

#[test]
fn test_tls_early_data_methods_uppercased() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/r.yaml"),
            ("FERRUM_TLS_EARLY_DATA_METHODS", "get,head"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tls_early_data_methods.len(), 2);
            assert!(config.tls_early_data_methods.contains("GET"));
            assert!(config.tls_early_data_methods.contains("HEAD"));
        },
    );
}

#[test]
fn test_tls_early_data_methods_empty_entries_filtered() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/r.yaml"),
            ("FERRUM_TLS_EARLY_DATA_METHODS", "GET,,HEAD,"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tls_early_data_methods.len(), 2);
            assert!(config.tls_early_data_methods.contains("GET"));
            assert!(config.tls_early_data_methods.contains("HEAD"));
        },
    );
}

#[test]
fn test_db_full_load_page_size_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DB_FULL_LOAD_PAGE_SIZE");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_full_load_page_size, 10_000);
        },
    );
}

#[test]
fn test_db_full_load_page_size_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_FULL_LOAD_PAGE_SIZE", "20000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_full_load_page_size, 20_000);
        },
    );
}

#[test]
fn test_db_full_load_page_size_clamped_to_minimum() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_FULL_LOAD_PAGE_SIZE", "10"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.db_full_load_page_size, 100,
                "values below 100 should be clamped to the minimum"
            );
        },
    );
}

#[test]
fn test_db_full_load_page_size_clamped_to_maximum() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_FULL_LOAD_PAGE_SIZE", "999999"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.db_full_load_page_size, 100_000,
                "values above 100000 should be clamped to the maximum"
            );
        },
    );
}

// ── FERRUM_POOL_SHARD_AMOUNT ────────────────────────────────────────────────

#[test]
fn test_pool_shard_amount_default_is_zero() {
    let config = EnvConfig::default();
    assert_eq!(
        config.pool_shard_amount, 0,
        "Default 0 means auto-derive from CPU topology"
    );
}

#[test]
fn test_k8s_pod_discovery_default_disabled() {
    let config = EnvConfig::default();
    assert!(
        !config.k8s_pod_discovery_enabled,
        "Pod auto-discovery is opt-in for the first rollout"
    );
    assert!(
        !config.k8s_node_locality_enabled,
        "Node locality enrichment is a separate cluster-scoped opt-in"
    );
}

#[test]
fn test_mesh_peer_auth_live_reload_default_disabled() {
    let config = EnvConfig::default();
    assert!(
        !config.mesh_peer_auth_live_reload_enabled,
        "PeerAuthentication live reload is opt-in for the first rollout"
    );
    assert_eq!(
        config.mesh_svid_rotation_drain_seconds, 0,
        "Backend SVID rotation force-drain is disabled by default"
    );
}

#[test]
fn test_frontend_tls_live_reload_default_disabled() {
    let config = EnvConfig::default();
    assert!(
        !config.frontend_tls_live_reload_enabled,
        "Frontend TLS cert/key live reload is opt-in; defaults preserve the historic restart-required behavior"
    );
    assert_eq!(
        config.frontend_tls_watch_interval_seconds, 30,
        "Default frontend TLS watch interval should be 30 seconds when live reload is enabled"
    );
    assert_eq!(
        config.secret_refresh_interval_seconds, 300,
        "Default TLS provider source refresh interval should be 300 seconds"
    );
}

#[test]
fn test_frontend_tls_live_reload_parsed_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED", "true"),
            ("FERRUM_FRONTEND_TLS_WATCH_INTERVAL_SECONDS", "5"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.frontend_tls_live_reload_enabled);
            assert_eq!(config.frontend_tls_watch_interval_seconds, 5);
        },
    );
}

#[test]
fn test_db_tls_live_reload_default_disabled() {
    let config = EnvConfig::default();
    assert!(
        !config.db_tls_live_reload_enabled,
        "Database TLS live reload is opt-in"
    );
    assert_eq!(
        config.db_tls_watch_interval_seconds, 30,
        "Default database TLS watch interval should be 30 seconds"
    );
}

#[test]
fn test_db_tls_live_reload_parsed_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_TLS_LIVE_RELOAD_ENABLED", "true"),
            ("FERRUM_DB_TLS_WATCH_INTERVAL_SECONDS", "5"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.db_tls_live_reload_enabled);
            assert_eq!(config.db_tls_watch_interval_seconds, 5);
        },
    );
}

#[test]
fn test_db_tls_watch_interval_clamps_to_minimum() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_TLS_WATCH_INTERVAL_SECONDS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.db_tls_watch_interval_seconds, 1,
                "FERRUM_DB_TLS_WATCH_INTERVAL_SECONDS=0 should clamp up to 1"
            );
        },
    );
}

#[test]
fn test_tls_ocsp_response_sources_parse_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            (
                "FERRUM_FRONTEND_TLS_OCSP_RESPONSE_SOURCE",
                "file:///source/frontend.ocsp.der",
            ),
            (
                "FERRUM_ADMIN_TLS_OCSP_RESPONSE_SOURCE",
                "k8s://edge/admin-ocsp#ocsp.der",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.frontend_tls_ocsp_response_source.as_deref(),
                Some("file:///source/frontend.ocsp.der")
            );
            assert_eq!(
                config.admin_tls_ocsp_response_source.as_deref(),
                Some("k8s://edge/admin-ocsp#ocsp.der")
            );
        },
    );
}

#[test]
fn test_tls_source_env_overrides_path_env() {
    const INLINE_CERT: &str =
        "-----BEGIN CERTIFICATE-----\nsource-cert\n-----END CERTIFICATE-----\n";
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_FRONTEND_TLS_CERT_PATH", "/path/frontend.crt"),
            ("FERRUM_FRONTEND_TLS_CERT_SOURCE", INLINE_CERT),
            ("FERRUM_FRONTEND_TLS_KEY_PATH", "/path/frontend.key"),
            (
                "FERRUM_FRONTEND_TLS_KEY_SOURCE",
                "file:///source/frontend.key",
            ),
            ("FERRUM_ADMIN_TLS_CERT_PATH", "/path/admin.crt"),
            ("FERRUM_ADMIN_TLS_CERT_SOURCE", "file:///source/admin.crt"),
            ("FERRUM_ADMIN_TLS_KEY_PATH", "/path/admin.key"),
            ("FERRUM_ADMIN_TLS_KEY_SOURCE", "file:///source/admin.key"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.frontend_tls_cert_path.as_deref(), Some(INLINE_CERT));
            assert_eq!(
                config.frontend_tls_key_path.as_deref(),
                Some("file:///source/frontend.key")
            );
            assert_eq!(
                config.admin_tls_cert_path.as_deref(),
                Some("file:///source/admin.crt")
            );
            assert_eq!(
                config.admin_tls_key_path.as_deref(),
                Some("file:///source/admin.key")
            );
        },
    );
}

#[test]
fn test_frontend_tls_watch_interval_clamps_to_minimum() {
    // The watcher must not busy-loop the filesystem; an operator who sets 0
    // gets clamped up to 1 second.
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED", "true"),
            ("FERRUM_FRONTEND_TLS_WATCH_INTERVAL_SECONDS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.frontend_tls_watch_interval_seconds, 1,
                "FERRUM_FRONTEND_TLS_WATCH_INTERVAL_SECONDS=0 should clamp up to 1"
            );
        },
    );
}

#[test]
fn test_secret_refresh_interval_parsed_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_SECRET_REFRESH_INTERVAL_SECONDS", "60"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.secret_refresh_interval_seconds, 60);
        },
    );
}

#[test]
fn test_secret_refresh_interval_clamps_to_minimum() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_SECRET_REFRESH_INTERVAL_SECONDS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.secret_refresh_interval_seconds, 1,
                "FERRUM_SECRET_REFRESH_INTERVAL_SECONDS=0 should clamp up to 1"
            );
        },
    );
}

#[test]
fn test_mesh_peer_auth_live_reload_parsed_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.mesh_peer_auth_live_reload_enabled);
        },
    );
}

#[test]
fn test_mesh_svid_rotation_drain_seconds_parsed_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS", "15"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mesh_svid_rotation_drain_seconds, 15);
        },
    );
}

#[test]
fn test_mesh_remote_discovery_credentials_parsed_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            (
                "FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS",
                r#"{"credB":"secretB"}"#,
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.mesh_remote_discovery_credentials.as_deref(),
                Some(r#"{"credB":"secretB"}"#)
            );
        },
    );
}

#[test]
fn test_mesh_remote_discovery_credentials_blank_is_none() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS", "   "),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(
                config.mesh_remote_discovery_credentials.is_none(),
                "blank credential map normalizes to None (shared-secret fallback)"
            );
        },
    );
}

#[test]
fn test_k8s_pod_discovery_parsed_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_K8S_POD_DISCOVERY_ENABLED", "true"),
            ("FERRUM_K8S_NODE_LOCALITY_ENABLED", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.k8s_pod_discovery_enabled);
            assert!(config.k8s_node_locality_enabled);
        },
    );
}

#[test]
fn test_pool_shard_amount_parsed_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_POOL_SHARD_AMOUNT", "256"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.pool_shard_amount, 256,
                "operator-supplied override must be passed through verbatim; \
                 power-of-two rounding happens at the call site",
            );
        },
    );
}

#[test]
fn test_pool_shard_amount_zero_kept_as_auto_sentinel() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_POOL_SHARD_AMOUNT", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.pool_shard_amount, 0,
                "FERRUM_POOL_SHARD_AMOUNT=0 must remain 0 (auto sentinel) — \
                 the helper resolves it later, not the parser",
            );
        },
    );
}

#[test]
fn test_k8s_istio_root_namespace_defaults_to_istio_system() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_K8S_ISTIO_ROOT_NAMESPACE");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.k8s_istio_root_namespace, "istio-system");
        },
    );
}

#[test]
fn test_k8s_istio_root_namespace_parsed_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_K8S_ISTIO_ROOT_NAMESPACE", "istio-config"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.k8s_istio_root_namespace, "istio-config");
        },
    );
}

#[test]
fn test_k8s_istio_root_namespace_rejects_invalid_k8s_namespace() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_K8S_ISTIO_ROOT_NAMESPACE", "Istio_System"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(err.contains("FERRUM_K8S_ISTIO_ROOT_NAMESPACE"));
        },
    );
}

// ── FERRUM_CP_NAMESPACES / FERRUM_CP_REQUIRE_NAMESPACE_CLAIM (MESH-T2-A) ─

#[test]
fn test_cp_namespaces_defaults_to_empty_for_back_compat() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_CP_NAMESPACES");
            let config = EnvConfig::from_env().unwrap();
            assert!(
                config.cp_namespaces.is_empty(),
                "default cp_namespaces must be empty (back-compat single-namespace CP)"
            );
            assert!(
                !config.cp_require_namespace_claim,
                "default cp_require_namespace_claim must be false (back-compat)"
            );
        },
    );
}

#[test]
fn test_cp_namespaces_parses_star_for_cluster_wide() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_CP_NAMESPACES", "*"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.cp_namespaces, vec!["*".to_string()]);
        },
    );
}

#[test]
fn test_cp_namespaces_parses_csv() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_CP_NAMESPACES", "prod,staging,dev"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.cp_namespaces,
                vec!["prod".to_string(), "staging".to_string(), "dev".to_string()]
            );
        },
    );
}

#[test]
fn test_cp_namespaces_rejects_star_combined_with_explicit() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_CP_NAMESPACES", "*,prod"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(
                err.contains("FERRUM_CP_NAMESPACES") && err.contains("`*`"),
                "error should mention FERRUM_CP_NAMESPACES + `*` constraint, got: {err}"
            );
        },
    );
}

#[test]
fn test_cp_namespaces_rejects_invalid_namespace_entry() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_CP_NAMESPACES", "prod,Bad Namespace!"),
        ],
        || {
            let err = EnvConfig::from_env().unwrap_err();
            assert!(
                err.contains("FERRUM_CP_NAMESPACES"),
                "error should mention FERRUM_CP_NAMESPACES, got: {err}"
            );
        },
    );
}

#[test]
fn test_cp_require_namespace_claim_parses_true() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_CP_REQUIRE_NAMESPACE_CLAIM", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.cp_require_namespace_claim);
        },
    );
}

// ── T2-B: K8s controller / pod discovery default-on inside a pod ──────────
//
// `EnvConfig::from_env()` invokes the helper that's unit-tested in
// `src/config/env_config.rs::tests`; this layer exercises the
// end-to-end full-config path so a future refactor of the helper can't
// silently drop the integration with the K8s switches.

#[test]
fn test_k8s_controller_default_on_inside_kubernetes_pod() {
    // Pod-like environment: KUBERNETES_SERVICE_HOST set, FERRUM_K8S_* unset.
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("KUBERNETES_SERVICE_HOST", "10.96.0.1"),
        ],
        || {
            // Make sure neither switch is set, then load.
            remove_var("FERRUM_K8S_CONTROLLER_ENABLED");
            remove_var("FERRUM_K8S_POD_DISCOVERY_ENABLED");
            let config = EnvConfig::from_env().unwrap();
            assert!(
                config.k8s_controller_enabled,
                "in-cluster default should flip k8s_controller_enabled to true"
            );
            assert!(
                config.k8s_pod_discovery_enabled,
                "in-cluster default should flip k8s_pod_discovery_enabled to true"
            );
        },
    );
}

#[test]
fn test_k8s_controller_default_off_outside_pod() {
    // CLI / docker-style environment: KUBERNETES_SERVICE_HOST absent.
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("KUBERNETES_SERVICE_HOST");
            remove_var("FERRUM_K8S_CONTROLLER_ENABLED");
            remove_var("FERRUM_K8S_POD_DISCOVERY_ENABLED");
            let config = EnvConfig::from_env().unwrap();
            assert!(
                !config.k8s_controller_enabled,
                "outside-cluster default must remain false (back-compat)"
            );
            assert!(!config.k8s_pod_discovery_enabled);
        },
    );
}

#[test]
fn test_k8s_controller_explicit_false_overrides_in_cluster_default() {
    // Pod-like environment + operator explicitly opting OUT.
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("KUBERNETES_SERVICE_HOST", "10.96.0.1"),
            ("FERRUM_K8S_CONTROLLER_ENABLED", "false"),
            ("FERRUM_K8S_POD_DISCOVERY_ENABLED", "false"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(
                !config.k8s_controller_enabled,
                "explicit =false must win over the in-cluster default"
            );
            assert!(!config.k8s_pod_discovery_enabled);
        },
    );
}

// ── FERRUM_TRUSTED_PROXIES strict validation (GHSA-pvj7-hhqj-rpv5) ──────────

/// Parse `FERRUM_TRUSTED_PROXIES` through the full env pipeline so the assertion
/// covers `EnvConfig::validate()`, which is what `ferrum-edge validate` and every
/// serving mode run before a listener binds.
fn trusted_proxies_from_env(raw: &str) -> Result<EnvConfig, String> {
    let mut result = None;
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_TRUSTED_PROXIES", raw),
        ],
        || result = Some(EnvConfig::from_env()),
    );
    result.expect("closure ran")
}

#[test]
fn test_trusted_proxies_accepts_valid_mixed_list() {
    let raw = "10.0.0.0/8, 172.16.0.0/12, ::1, ::ffff:192.0.2.0/120";
    let config = trusted_proxies_from_env(raw).expect("a fully valid list must be accepted");
    assert_eq!(config.trusted_proxies, raw);
}

#[test]
fn test_trusted_proxies_empty_stays_valid_secure_default() {
    let config = trusted_proxies_from_env("").expect("empty is the secure default");
    assert!(config.trusted_proxies.is_empty());
}

/// A mistyped prefix in an otherwise valid list must fail configuration rather
/// than silently retain the valid entries — the dropped hop is exactly the one
/// whose forwarded client identity would stop being believed.
#[test]
fn test_trusted_proxies_rejects_invalid_prefix_in_mixed_list() {
    let err = trusted_proxies_from_env("10.0.0.0/8,192.168.0.0/33")
        .expect_err("a malformed prefix must fail configuration");
    assert!(err.contains("FERRUM_TRUSTED_PROXIES"), "got: {err}");
    assert!(err.contains("192.168.0.0/33"), "got: {err}");
}

#[test]
fn test_trusted_proxies_rejects_junk_and_empty_segments() {
    for raw in [
        "not-an-ip",
        "10.0.0.0/8,junk",
        "10.0.0.0/8,",
        ",10.0.0.0/8",
        "10.0.0.0/8,,172.16.0.0/12",
        ",",
    ] {
        assert!(
            trusted_proxies_from_env(raw).is_err(),
            "FERRUM_TRUSTED_PROXIES={raw:?} must fail configuration"
        );
    }
}
