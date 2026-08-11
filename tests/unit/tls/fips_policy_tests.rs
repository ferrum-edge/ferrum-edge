//! FIPS deployment-mode surface and fail-closed admission policy (issue #3510).
//!
//! These target the `_enforced` policy entry points rather than the gated
//! wrappers. Enforcement is established only by `install_crypto_provider`
//! during process bootstrap, which an external test binary never runs, so the
//! gated wrappers short-circuit to `Ok(())` here and testing through them would
//! assert nothing. The wrappers' own gate is covered by
//! `fips_policy_is_inert_when_mode_is_off`.
//!
//! Assertions that depend on which cryptographic backend this build linked are
//! `cfg`-gated on the `fips` feature, so the same file is meaningful under both
//! `--features crypto-ring` (the default) and
//! `--no-default-features --features fips` (the hosted FIPS lane).

use chrono::Utc;
use ferrum_edge::config::env_config::{DbTlsMode, EnvConfig};
use ferrum_edge::config::types::{Consumer, GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::fips;
use ferrum_edge::fips::policy;
use serde_json::json;

fn plugin(name: &str, config: serde_json::Value) -> PluginConfig {
    PluginConfig {
        id: format!("{name}-1"),
        plugin_name: name.to_string(),
        namespace: "ferrum".to_string(),
        config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn consumer_with(basicauth: serde_json::Value) -> Consumer {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert("basicauth".to_string(), basicauth);
    Consumer {
        id: "consumer-1".to_string(),
        username: "alice".to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn config_with(plugins: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        plugin_configs: plugins,
        ..GatewayConfig::default()
    }
}

// ── Mode parsing ────────────────────────────────────────────────────────────

#[test]
fn mode_parses_documented_spellings() {
    for raw in [
        "", "off", "OFF", " off ", "false", "0", "disabled", "disable",
    ] {
        assert_eq!(
            fips::FipsMode::parse(raw).expect("parses"),
            fips::FipsMode::Off,
            "expected {raw:?} to parse as off"
        );
    }
    for raw in [
        "enforce",
        "ENFORCE",
        " enforce ",
        "true",
        "1",
        "on",
        "enabled",
    ] {
        assert_eq!(
            fips::FipsMode::parse(raw).expect("parses"),
            fips::FipsMode::Enforce,
            "expected {raw:?} to parse as enforce"
        );
    }
}

#[test]
fn mode_rejects_unknown_value_rather_than_downgrading() {
    // A typo must not quietly run non-FIPS. This is the whole reason the
    // setting is not a plain bool parse.
    let err = fips::FipsMode::parse("enfroce").expect_err("unknown value is an error");
    assert!(err.contains("FERRUM_FIPS_MODE"), "names the setting: {err}");
    assert!(
        !err.contains("enfroce"),
        "the supplied value must not be echoed: {err}"
    );
}

#[test]
fn mode_default_is_off() {
    assert_eq!(fips::FipsMode::default(), fips::FipsMode::Off);
    assert!(!fips::FipsMode::default().is_enforcing());
    assert_eq!(fips::FipsMode::Off.as_str(), "off");
    assert_eq!(fips::FipsMode::Enforce.as_str(), "enforce");
}

// ── Fail-closed bootstrap ───────────────────────────────────────────────────

#[test]
fn build_capability_matches_the_selected_cryptographic_backend() {
    // `BUILD_CAPABLE` must be derived from the build, never hand-set. Read it
    // through the function form so the assertion is a runtime comparison rather
    // than an assertion on a constant.
    assert_eq!(
        fips::build_capable(),
        cfg!(feature = "fips"),
        "build capability must follow the selected cargo feature"
    );
    assert_eq!(fips::build_capable(), fips::BUILD_CAPABLE);
}

#[cfg(not(feature = "fips"))]
#[test]
fn enforce_request_fails_closed_on_a_build_without_the_module() {
    // The load-bearing assertion of this whole feature: an enforce request on a
    // build that cannot provide a validated module must be refused, never
    // downgraded to `ring`.
    let err = fips::verify_resolved_mode(fips::FipsMode::Enforce)
        .expect_err("enforce must fail closed without build capability");
    assert!(err.contains("aws-lc-fips"), "names the integration: {err}");
    assert!(err.contains("docs/fips.md"), "points at the boundary doc");

    // And the mode-off path stays inert.
    assert!(fips::verify_resolved_mode(fips::FipsMode::Off).is_ok());
}

#[cfg(feature = "fips")]
#[test]
fn late_enforce_request_is_refused_on_a_capable_build_too() {
    // The process-default provider is installed before `ferrum.conf` is
    // readable, so an enforce request that only appears in the settings file
    // arrives after provider selection. Even on a capable build that is refused
    // rather than silently applied, because the resolved mode — and therefore
    // every policy gate keyed on it — is immutable after bootstrap.
    let err = fips::verify_resolved_mode(fips::FipsMode::Enforce)
        .expect_err("a settings-file-only request must not silently enable enforcement");
    assert!(err.contains("FERRUM_FIPS_MODE"), "names the setting: {err}");
    assert!(err.contains("docs/fips.md"), "points at the boundary doc");
    assert!(fips::verify_resolved_mode(fips::FipsMode::Off).is_ok());
}

#[cfg(feature = "fips")]
#[test]
fn a_fips_build_supplies_an_approved_provider_and_passes_the_module_self_test() {
    // On the FIPS profile the linked module must report approved-mode
    // operation and rustls must classify the resulting provider as FIPS. If
    // either is false the build is mislabelled, and `install_crypto_provider`
    // would refuse to start — assert it here so the FIPS CI lane fails on the
    // build rather than on a deployment.
    let provider = fips::base_crypto_provider();
    assert!(
        provider.fips(),
        "the fips profile's rustls provider must be FIPS-approved"
    );
    assert!(
        provider.cipher_suites.iter().all(|suite| suite.fips()),
        "every compiled cipher suite must be approved"
    );
    assert!(
        provider.kx_groups.iter().all(|group| group.fips()),
        "every compiled key-exchange group must be approved"
    );
    // A constructed policy over that provider must therefore pass the last gate
    // before any listener or backend client is built.
    fips::policy::check_tls_policy_enforced(
        &ferrum_edge::tls::TlsPolicy::from_env_config(&EnvConfig::default())
            .expect("default TLS policy builds"),
    )
    .expect("the fips profile's default TLS policy is approved");
}

#[test]
fn bootstrap_error_text_is_bounded_and_makes_no_certification_claim() {
    let rendered = fips::BootstrapError::BuildNotCapable.to_string();
    assert!(rendered.len() < 1024, "diagnostic stays bounded");
    assert!(
        !rendered.to_lowercase().contains("certified"),
        "must not imply certification: {rendered}"
    );
    assert!(
        rendered.contains("will not fall back"),
        "states fail-closed"
    );
}

// ── Status metadata ─────────────────────────────────────────────────────────

#[test]
fn status_metadata_is_non_sensitive_and_denies_certification() {
    let value = fips::status_metadata();
    let object = value.as_object().expect("object");

    // `certified` must be present and false on EVERY build, including the FIPS
    // one. Ferrum Edge is not itself a validated cryptographic module and is
    // not independently certified; a status scraper must never be able to read
    // `enforcing` — or a FIPS build profile — as `certified`.
    assert_eq!(object.get("certified"), Some(&json!(false)));
    // Bootstrap never ran in this test binary, so the resolved mode is off.
    assert_eq!(object.get("mode"), Some(&json!("off")));
    assert_eq!(object.get("enforcing"), Some(&json!(false)));

    // The build-derived half must describe the build that is actually running.
    let expected_capable = cfg!(feature = "fips");
    assert_eq!(object.get("build_capable"), Some(&json!(expected_capable)));
    assert_eq!(
        object.get("build_profile"),
        Some(&json!(if expected_capable {
            "fips"
        } else {
            "crypto-ring"
        }))
    );
    assert_eq!(
        object.get("provider"),
        Some(&json!(if expected_capable {
            "aws-lc-fips"
        } else {
            "ring"
        }))
    );
    assert_eq!(
        object.get("boundary_documentation"),
        Some(&json!("docs/fips.md"))
    );

    // Every value is a boolean or a fixed-set string: no paths, no key
    // material, no operator-supplied text.
    for (key, field) in object {
        assert!(
            field.is_boolean() || field.is_string(),
            "field {key} must be a boolean or fixed-set string, got {field}"
        );
    }
}

// ── Process configuration policy ────────────────────────────────────────────

#[test]
fn env_policy_accepts_an_approved_default_configuration() {
    let env_config = EnvConfig::default();
    policy::check_env_config_enforced(&env_config).expect("defaults are FIPS-approved");
}

#[test]
fn env_policy_rejects_a_provider_pin_this_build_does_not_provide() {
    let env_config = EnvConfig {
        fips_required_provider: "some-other-module".to_string(),
        ..EnvConfig::default()
    };
    let err = policy::check_env_config_enforced(&env_config).expect_err("pin is rejected");
    assert!(err.contains("FERRUM_FIPS_REQUIRED_PROVIDER"));
    assert!(err.contains(fips::SUPPORTED_PROVIDER_ID));
    assert!(
        !err.contains("some-other-module"),
        "operator-supplied value must not be echoed: {err}"
    );
}

#[test]
fn env_policy_rejects_disabled_backend_certificate_verification() {
    let env_config = EnvConfig {
        tls_no_verify: true,
        ..EnvConfig::default()
    };
    let err = policy::check_env_config_enforced(&env_config).expect_err("no-verify is rejected");
    assert!(err.contains("FERRUM_TLS_NO_VERIFY"));
}

#[test]
fn env_policy_rejects_a_frontend_dtls_listener() {
    // DTLS is the one transport Ferrum terminates outside rustls. The vendored
    // `dimpl` stack routes suites and signatures onto the selected module but
    // draws the handshake `Random`, the HelloVerifyRequest cookie secret, and
    // the DTLS 1.2 explicit AES-GCM nonce from the `rand` crate rather than the
    // module DRBG, so the whole surface is refused instead of admitted under an
    // implicit claim. See docs/fips.md §"DTLS: why the whole transport is
    // refused".
    for env_config in [
        EnvConfig {
            dtls_cert_path: Some("/etc/ferrum/dtls.pem".to_string()),
            ..EnvConfig::default()
        },
        EnvConfig {
            dtls_key_path: Some("/etc/ferrum/dtls.key".to_string()),
            ..EnvConfig::default()
        },
    ] {
        let err = policy::check_env_config_enforced(&env_config).expect_err("refused");
        assert!(err.contains("FERRUM_DTLS_"), "{err}");
        assert!(err.contains("dimpl"), "{err}");
        assert!(
            !err.contains("/etc/ferrum/"),
            "the configured path must never be echoed: {err}"
        );
    }
}

#[test]
fn env_policy_ignores_a_blank_dtls_path() {
    // Blank means unset everywhere else in `EnvConfig`; a whitespace-only value
    // must not be read as a configured listener.
    let env_config = EnvConfig {
        dtls_cert_path: Some("   ".to_string()),
        ..EnvConfig::default()
    };
    policy::check_env_config_enforced(&env_config).expect("blank configures no listener");
}

#[test]
fn env_policy_rejects_every_mongodb_config_store_shape() {
    for db_url in [
        None,
        Some("mongodb://db.example/ferrum?tls=true"),
        Some("mongodb://user:secret@db.example/ferrum?tlsAllowInvalidCertificates=true"),
    ] {
        let env_config = EnvConfig {
            db_type: Some("mongodb".to_string()),
            db_url: db_url.map(str::to_string),
            ..EnvConfig::default()
        };
        let err = policy::check_env_config_enforced(&env_config).expect_err("MongoDB is refused");
        assert!(err.contains("FERRUM_DB_TYPE=mongodb"), "{err}");
        assert!(err.contains("database-driver cryptography"), "{err}");
        assert!(!err.contains("user:secret"), "database URL leaked: {err}");
    }
}

#[test]
fn env_policy_rejects_unverified_sql_config_database_tls_modes() {
    for (mode, mode_name) in [
        (DbTlsMode::Disable, "disable"),
        (DbTlsMode::Allow, "allow"),
        (DbTlsMode::Prefer, "prefer"),
        (DbTlsMode::Require, "require"),
    ] {
        for db_type in ["postgres", "mysql", "POSTGRES", "MYSQL"] {
            let env_config = EnvConfig {
                db_type: Some(db_type.to_string()),
                db_tls_mode: Some(mode),
                ..EnvConfig::default()
            };
            let err = policy::check_env_config_enforced(&env_config)
                .expect_err(&format!("{mode_name} for {db_type} is refused"));
            assert!(
                err.contains(&format!("FERRUM_DB_TLS_MODE={mode_name}")),
                "{err}"
            );
            assert!(
                err.contains("verify-ca") && err.contains("verify-full"),
                "{err}"
            );
        }
    }
}

#[test]
fn env_policy_accepts_verified_sql_tls_modes() {
    for db_tls_mode in [DbTlsMode::VerifyCa, DbTlsMode::VerifyFull] {
        for db_type in ["postgres", "mysql"] {
            let env_config = EnvConfig {
                db_type: Some(db_type.to_string()),
                db_tls_mode: Some(db_tls_mode),
                ..EnvConfig::default()
            };
            policy::check_env_config_enforced(&env_config).expect("verified SQL TLS is admitted");
        }
    }
}

#[test]
fn env_policy_rejects_unset_sql_db_tls_mode_without_verifying_url_params() {
    // Residual gap after #3564: omitting FERRUM_DB_TLS_MODE must not admit an
    // unauthenticated config-database peer. Absent or weaker URL-owned
    // parameters are refused for every configured SQL URL.
    for db_type in ["postgres", "mysql", "POSTGRES", "MYSQL"] {
        let dialect = if db_type.eq_ignore_ascii_case("postgres") {
            "postgres"
        } else {
            "mysql"
        };
        let (plain_url, weak_url, secret_url) = if dialect == "postgres" {
            (
                "postgres://db.example/ferrum",
                "postgres://db.example/ferrum?sslmode=require",
                "postgres://user:s3cret-pass@db.example/ferrum",
            )
        } else {
            (
                "mysql://db.example/ferrum",
                "mysql://db.example/ferrum?ssl-mode=REQUIRED",
                "mysql://user:s3cret-pass@db.example/ferrum",
            )
        };

        for db_url in [plain_url, weak_url, secret_url] {
            let env_config = EnvConfig {
                db_type: Some(db_type.to_string()),
                db_tls_mode: None,
                db_url: Some(db_url.to_string()),
                ..EnvConfig::default()
            };
            let err = policy::check_env_config_enforced(&env_config)
                .expect_err("unset mode without verifying URL params is refused");
            assert!(
                err.contains("FERRUM_DB_URL"),
                "diagnostic must name the setting: {err}"
            );
            assert!(err.contains("FERRUM_DB_TLS_MODE unset"), "{err}");
            assert!(
                !err.contains("s3cret-pass")
                    && !err.contains("user:")
                    && !err.contains("db.example"),
                "database URL must never leak: {err}"
            );
        }
    }
}

#[test]
fn env_policy_accepts_unset_sql_db_tls_mode_with_url_owned_verifying_params() {
    // docs/database_tls.md documents URL-owned TLS as a supported alternative
    // to FERRUM_DB_TLS_MODE; verifying URL parameters must keep working under
    // enforced FIPS when the env var is unset.
    for (db_type, db_url) in [
        (
            "postgres",
            "postgres://user:s3cret@db.example/ferrum?sslmode=verify-full",
        ),
        (
            "postgres",
            "postgres://db.example/ferrum?sslmode=verify-ca&sslrootcert=/certs/ca.pem",
        ),
        (
            "mysql",
            "mysql://user:s3cret@db.example/ferrum?ssl-mode=VERIFY_IDENTITY",
        ),
        ("mysql", "mysql://db.example/ferrum?ssl_mode=VERIFY_CA"),
        (
            "POSTGRES",
            "postgres://db.example/ferrum?SSLMode=verify-full",
        ),
        (
            "MYSQL",
            "mysql://db.example/ferrum?SSL-Mode=VERIFY_IDENTITY",
        ),
    ] {
        let env_config = EnvConfig {
            db_type: Some(db_type.to_string()),
            db_tls_mode: None,
            db_url: Some(db_url.to_string()),
            ..EnvConfig::default()
        };
        policy::check_env_config_enforced(&env_config)
            .expect("URL-owned verifying TLS is admitted when mode is unset");
    }
}

#[test]
fn env_policy_holds_failover_and_replica_urls_to_the_same_sql_tls_standard() {
    // A verified primary with an unverified failover or replica still admits
    // an unauthenticated peer — every configured SQL URL is checked.
    let verified_primary = "postgres://user:s3cret@primary.example/ferrum?sslmode=verify-full";
    let weak_failover = "postgres://user:failover-secret@standby.example/ferrum?sslmode=require";
    let plain_replica = "postgres://user:replica-secret@replica.example/ferrum";

    let failover_only = EnvConfig {
        db_type: Some("postgres".to_string()),
        db_tls_mode: None,
        db_url: Some(verified_primary.to_string()),
        db_failover_urls: vec![weak_failover.to_string()],
        ..EnvConfig::default()
    };
    let err = policy::check_env_config_enforced(&failover_only)
        .expect_err("unverified failover is refused");
    assert!(err.contains("FERRUM_DB_FAILOVER_URLS[#1]"), "{err}");
    assert!(err.contains("`sslmode`"), "{err}");
    assert!(
        !err.contains("failover-secret")
            && !err.contains("standby.example")
            && !err.contains(verified_primary),
        "URL material must never leak: {err}"
    );

    let replica_only = EnvConfig {
        db_type: Some("postgres".to_string()),
        db_tls_mode: None,
        db_url: Some(verified_primary.to_string()),
        db_read_replica_url: Some(plain_replica.to_string()),
        ..EnvConfig::default()
    };
    let err = policy::check_env_config_enforced(&replica_only)
        .expect_err("unverified replica is refused");
    assert!(err.contains("FERRUM_DB_READ_REPLICA_URL"), "{err}");
    assert!(
        !err.contains("replica-secret") && !err.contains("replica.example"),
        "URL material must never leak: {err}"
    );

    let all_verified = EnvConfig {
        db_type: Some("mysql".to_string()),
        db_tls_mode: None,
        db_url: Some(
            "mysql://user:s3cret@primary.example/ferrum?ssl-mode=VERIFY_IDENTITY".to_string(),
        ),
        db_failover_urls: vec!["mysql://standby.example/ferrum?ssl-mode=VERIFY_CA".to_string()],
        db_read_replica_url: Some(
            "mysql://replica.example/ferrum?ssl_mode=VERIFY_IDENTITY".to_string(),
        ),
        ..EnvConfig::default()
    };
    policy::check_env_config_enforced(&all_verified)
        .expect("verified primary, failover, and replica are admitted");
}

#[test]
fn env_policy_unset_sql_db_tls_mode_without_urls_has_no_peer_to_refuse() {
    // With no configured SQL URL there is no peer connection; the gate has
    // nothing to inspect and must not refuse on db_type alone.
    for db_type in ["postgres", "mysql"] {
        let env_config = EnvConfig {
            db_type: Some(db_type.to_string()),
            db_tls_mode: None,
            ..EnvConfig::default()
        };
        policy::check_env_config_enforced(&env_config)
            .expect("unset mode with no SQL URLs is not refused");
    }
}

#[test]
fn env_policy_sql_tls_check_does_not_apply_to_sqlite_or_mongodb() {
    for mode in [
        DbTlsMode::Disable,
        DbTlsMode::Allow,
        DbTlsMode::Prefer,
        DbTlsMode::Require,
    ] {
        let sqlite = EnvConfig {
            db_type: Some("sqlite".to_string()),
            db_tls_mode: Some(mode),
            ..EnvConfig::default()
        };
        policy::check_env_config_enforced(&sqlite)
            .expect("sqlite is outside the SQL network TLS admission check");

        let mongodb = EnvConfig {
            db_type: Some("mongodb".to_string()),
            db_tls_mode: Some(mode),
            ..EnvConfig::default()
        };
        let err = policy::check_env_config_enforced(&mongodb)
            .expect_err("mongodb is refused by its own config-store rule");
        assert!(err.contains("FERRUM_DB_TYPE=mongodb"), "{err}");
        assert!(
            !err.contains("FERRUM_DB_TLS_MODE"),
            "mongodb refusal must not double-report SQL TLS diagnostics: {err}"
        );
    }

    // Unset mode with a plain SQL-looking URL must still be the MongoDB
    // config-store refusal alone — never the SQL URL-parameter diagnostic.
    let mongodb_unset = EnvConfig {
        db_type: Some("mongodb".to_string()),
        db_tls_mode: None,
        db_url: Some("mongodb://user:s3cret@db.example/ferrum".to_string()),
        ..EnvConfig::default()
    };
    let err = policy::check_env_config_enforced(&mongodb_unset)
        .expect_err("mongodb is refused by its own config-store rule");
    assert!(err.contains("FERRUM_DB_TYPE=mongodb"), "{err}");
    assert!(
        !err.contains("sslmode")
            && !err.contains("ssl-mode")
            && !err.contains("FERRUM_DB_TLS_MODE unset"),
        "mongodb refusal must not double-report SQL URL TLS diagnostics: {err}"
    );
    assert!(!err.contains("s3cret"), "database URL leaked: {err}");

    // SQLite has no network TLS; an unset mode with a file URL is unaffected.
    let sqlite_unset = EnvConfig {
        db_type: Some("sqlite".to_string()),
        db_tls_mode: None,
        db_url: Some("sqlite:///tmp/ferrum.db".to_string()),
        ..EnvConfig::default()
    };
    policy::check_env_config_enforced(&sqlite_unset)
        .expect("sqlite is outside the SQL network TLS admission check");
}

#[test]
fn env_policy_floors_hmac_key_length() {
    let mut env_config = EnvConfig {
        admin_jwt_secret: Some("short".to_string()),
        ..EnvConfig::default()
    };
    let err = policy::check_env_config_enforced(&env_config).expect_err("short key is rejected");
    assert!(err.contains("FERRUM_ADMIN_JWT_SECRET"));
    assert!(
        !err.contains("short"),
        "the secret must never appear in the diagnostic: {err}"
    );

    env_config.admin_jwt_secret = Some("x".repeat(policy::MIN_HMAC_KEY_BYTES));
    policy::check_env_config_enforced(&env_config).expect("32-byte key is admitted");

    env_config.basic_auth_hmac_secret = Some("short".to_string());
    let err = policy::check_env_config_enforced(&env_config)
        .expect_err("short Basic-auth HMAC key is rejected");
    assert!(err.contains("FERRUM_BASIC_AUTH_HMAC_SECRET"));
    assert!(
        !err.contains("short"),
        "the secret must not be echoed: {err}"
    );
}

// ── Gateway configuration policy ────────────────────────────────────────────

#[test]
fn gateway_policy_rejects_plugins_outside_the_module_boundary() {
    let config = config_with(vec![plugin("kafka_logging", json!({}))]);
    let err = policy::check_gateway_config_enforced(&config).expect_err("kafka is rejected");
    assert!(err.contains("kafka_logging"), "{err}");
    assert!(err.contains("docs/fips.md"), "{err}");
}

#[test]
fn gateway_policy_ignores_a_disabled_non_approved_plugin() {
    // A disabled plugin performs no cryptography, so refusing it would be a
    // false rejection that blocks an otherwise compliant startup.
    let mut disabled = plugin("kafka_logging", json!({}));
    disabled.enabled = false;
    policy::check_gateway_config_enforced(&config_with(vec![disabled]))
        .expect("disabled plugin is not a violation");
}

#[test]
fn gateway_policy_rejects_non_approved_jwt_algorithms() {
    // `ES512` is in this list deliberately. ECDSA over P-521 is an approved
    // FIPS 186-5 scheme, but the `jsonwebtoken/aws_lc_rs` backend this profile
    // selects exposes no supportable P-521 JWS path — `jsonwebtoken`'s
    // `Algorithm` enum has no `ES512` variant at all, so every downstream
    // admission surface (including the CP/DP trust-bundle parser in
    // `src/grpc/cp_trust.rs`) would fail to construct a key for it. Admitting an
    // algorithm Ferrum cannot route is the failure mode this allow-list exists
    // to prevent, so it must be refused at admission with an actionable
    // diagnostic instead of at first use.
    for alg in ["none", "EdDSA", "HS999", "ES512"] {
        let config = config_with(vec![plugin("jwt_auth", json!({ "algorithm": alg }))]);
        let err = match policy::check_gateway_config_enforced(&config) {
            Err(err) => err,
            Ok(()) => panic!("{alg} must be rejected"),
        };
        assert!(err.contains(&alg.to_ascii_uppercase()), "{err}");
    }
}

#[test]
fn shared_jwt_algorithm_policy_covers_external_admission_surfaces() {
    for algorithm in ["HS256", "RS384", "PS512", "ES256"] {
        assert!(policy::is_approved_jwt_algorithm(algorithm), "{algorithm}");
    }
    for algorithm in ["none", "EdDSA", "HS999", "ES512", ""] {
        assert!(!policy::is_approved_jwt_algorithm(algorithm), "{algorithm}");
    }

    let cp_trust = include_str!("../../../src/grpc/cp_trust.rs");
    assert!(
        cp_trust.contains("crate::fips::is_enforcing()")
            && cp_trust.contains("crate::fips::policy::is_approved_jwt_algorithm("),
        "the environment-selected CP/DP trust bundle must enforce the shared algorithm policy"
    );
}

#[test]
fn approved_jwt_algorithms_are_all_routable_by_the_selected_backend() {
    // The whole point of the allow-list is that everything on it can actually
    // be routed. An entry the backend cannot construct would be admitted at
    // config time and fail at first use — which is exactly how `ES512` got in.
    //
    // `src/grpc/cp_trust.rs` is the surface that maps every admitted algorithm
    // onto a concrete `DecodingKey`, so its EC arm is the authoritative
    // statement of which ECDSA curves this build can serve. The selected
    // `jsonwebtoken` release has no `ES512` variant at all.
    assert_eq!(
        policy::APPROVED_JWT_ALGORITHMS,
        &[
            "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
            "ES256", "ES384",
        ],
        "the approved JWS set changed; every entry must be constructible by the selected backend"
    );

    let cp_trust = include_str!("../../../src/grpc/cp_trust.rs");
    assert!(
        cp_trust.contains("Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem"),
        "cp_trust's EC arm is the routable-curve statement this allow-list must agree with"
    );
    assert!(
        !cp_trust.contains("Algorithm::ES512"),
        "the selected jsonwebtoken backend exposes no ES512 variant; it must not be admitted"
    );
}

#[test]
fn gateway_policy_accepts_approved_jwt_algorithms_in_both_config_shapes() {
    let scalar = config_with(vec![plugin("jwt_auth", json!({ "algorithm": "RS256" }))]);
    policy::check_gateway_config_enforced(&scalar).expect("RS256 scalar is approved");

    let array = config_with(vec![plugin(
        "jwks_auth",
        json!({ "algorithms": ["RS256", "ES384", "PS512"] }),
    )]);
    policy::check_gateway_config_enforced(&array).expect("approved array is admitted");
}

#[test]
fn gateway_policy_checks_nested_private_key_jwt_algorithms() {
    for plugin_name in ["oidc_relying_party", "oauth2_introspection"] {
        let rejected = config_with(vec![plugin(
            plugin_name,
            json!({
                "providers": [{
                    "client_auth": { "private_key_jwt_alg": "EdDSA" }
                }]
            }),
        )]);
        let err = policy::check_gateway_config_enforced(&rejected)
            .expect_err("nested EdDSA client assertions are rejected");
        assert!(err.contains("EDDSA"), "{plugin_name}: {err}");

        let approved = config_with(vec![plugin(
            plugin_name,
            json!({
                "providers": [{
                    "client_auth": { "private_key_jwt_alg": "RS256" }
                }]
            }),
        )]);
        policy::check_gateway_config_enforced(&approved)
            .expect("nested RS256 client assertions are approved");
    }
}

#[test]
fn gateway_policy_does_not_misread_non_jws_algorithm_vocabularies() {
    // `hmac_auth` reuses the `algorithm` key for its own vocabulary. Screening
    // it against the JWS registry would be a false rejection of an algorithm
    // that is itself approved.
    let config = config_with(vec![plugin(
        "hmac_auth",
        json!({ "algorithm": "hmac-sha256" }),
    )]);
    policy::check_gateway_config_enforced(&config).expect("hmac-sha256 is not a JWS alg");
}

#[test]
fn gateway_policy_diagnostics_stay_bounded_under_a_large_configuration() {
    // A hostile or merely large configuration must not turn a startup failure
    // into an unbounded log record.
    let plugins: Vec<PluginConfig> = (0..200)
        .map(|i| plugin("jwt_auth", json!({ "algorithm": format!("HS{i:03}") })))
        .collect();
    let err = policy::check_gateway_config_enforced(&config_with(plugins))
        .expect_err("non-approved algorithms are rejected");
    assert!(err.contains("and "), "reports a residual count: {err}");
    assert!(
        err.len() < 2048,
        "diagnostic stays bounded: {} bytes",
        err.len()
    );
}

#[test]
fn remote_external_secret_uri_schemes_are_refused_when_enforced() {
    for scheme in ["vault", "aws", "azure", "gcp"] {
        let err = policy::check_external_secret_uri_scheme_enforced(scheme)
            .expect_err("remote provider URI must be rejected");
        assert!(
            err.contains(scheme),
            "names only the provider scheme: {err}"
        );
        assert!(err.contains("docs/fips.md"), "points to guidance: {err}");
    }

    for scheme in ["file", "k8s", "acme", "managed", "pkcs11"] {
        policy::check_external_secret_uri_scheme_enforced(scheme)
            .expect("local or internally routed source remains allowed");
    }
}

#[test]
fn tls_remote_secret_loader_enforces_fips_policy_before_resolution() {
    let source = include_str!("../../../src/tls/source/mod.rs");
    let loader = source
        .split("fn load_secret_material_with(")
        .nth(1)
        .expect("remote secret loader exists")
        .split("fn load_k8s_secret_material_with(")
        .next()
        .expect("remote secret loader has an end");
    let gate = loader
        .find("check_external_secret_uri_scheme")
        .expect("loader applies the FIPS URI gate");
    let resolve = loader
        .find("resolve_secret_reference_blocking")
        .expect("loader reaches the provider resolver");
    assert!(
        gate < resolve,
        "FIPS refusal must precede provider resolution"
    );
}

// ── The gate itself ─────────────────────────────────────────────────────────

#[test]
fn fips_policy_is_inert_when_mode_is_off() {
    // Ordinary deployments must be behaviourally unchanged. The gated wrappers
    // admit configurations the enforced policy refuses.
    assert!(!fips::is_enforcing());

    let env_config = EnvConfig {
        tls_no_verify: true,
        ..EnvConfig::default()
    };
    policy::check_env_config(&env_config).expect("gated wrapper is inert when mode is off");

    let config = config_with(vec![plugin("kafka_logging", json!({}))]);
    policy::check_gateway_config(&config).expect("gated wrapper is inert when mode is off");
}

// ── Crypto inventory ────────────────────────────────────────────────────────

#[test]
fn inventory_entries_are_all_classified_and_documented() {
    use ferrum_edge::fips::inventory::{self, Disposition};

    assert!(
        inventory::INVENTORY.len() >= 20,
        "the inventory must cover the full acceptance-criteria surface"
    );
    for entry in inventory::INVENTORY {
        assert!(!entry.operation.is_empty(), "every row names an operation");
        assert!(
            !entry.location.is_empty(),
            "every row names a source location"
        );
        assert!(
            !entry.implementation.is_empty(),
            "every row names an implementing library"
        );
        assert!(
            !entry.rationale.is_empty(),
            "every row states how its disposition is achieved or enforced: {}",
            entry.operation
        );
        // Exhaustive so a new variant cannot be added without deciding what it
        // means for the honesty invariants below.
        match entry.disposition {
            Disposition::ModuleRoutable
            | Disposition::PendingClassification
            | Disposition::Rejected
            | Disposition::OutsideBoundary => {}
        }
    }
}

#[test]
fn inventory_rejected_plugins_agree_with_the_admission_policy() {
    use ferrum_edge::fips::inventory;

    // The inventory is documentation; the policy is enforcement. If they drift,
    // the document is lying about what the gateway does.
    let rejected_kafka =
        inventory::rejected().any(|entry| entry.location.contains("kafka_logging"));
    assert_eq!(
        rejected_kafka,
        policy::NON_APPROVED_PLUGINS.contains(&"kafka_logging"),
        "inventory and NON_APPROVED_PLUGINS disagree about kafka_logging"
    );
}

#[test]
fn inventory_work_register_is_empty() {
    use ferrum_edge::fips::inventory;

    // `pending-classification` means "security-relevant and NOT routed through
    // the module". A non-empty register is Ferrum claiming a FIPS deployment
    // mode over a crypto surface it has not actually routed, which is the exact
    // failure this module exists to prevent. Anything genuinely outside the
    // module boundary belongs in `outside-boundary` or `rejected` with a stated
    // rationale, not in the register.
    let pending: Vec<&str> = inventory::pending_classification()
        .map(|entry| entry.operation)
        .collect();
    assert!(
        pending.is_empty(),
        "unrouted security-relevant crypto remains: {pending:?}"
    );
}

#[test]
fn inventory_rejected_rows_are_all_actually_refused_by_the_policy() {
    use ferrum_edge::fips::inventory;

    // Every `rejected` row must name a check that exists. Otherwise the table
    // is documenting a protection the gateway does not implement.
    for entry in inventory::rejected() {
        assert!(
            entry.rationale.contains("fips::policy"),
            "rejected row must name the enforcing check: {}",
            entry.operation
        );
    }
}

// ── Newly classified admission rules ────────────────────────────────────────

#[test]
fn gateway_policy_rejects_sha1_xml_signature_selections() {
    // SP 800-131A Rev. 2 disallows SHA-1 for signature generation and
    // verification. `soap_ws_security` lets an operator admit `rsa-sha1` for
    // XML-DSig interoperability; FIPS mode refuses the configuration rather
    // than computing it outside the approved set.
    let config = config_with(vec![plugin(
        "soap_ws_security",
        json!({
            "x509_signature": { "allowed_algorithms": ["rsa-sha256", "rsa-sha1"] }
        }),
    )]);
    let err = policy::check_gateway_config_enforced(&config).expect_err("rsa-sha1 is rejected");
    assert!(err.contains("rsa-sha1"), "{err}");
    assert!(err.contains("x509_signature.allowed_algorithms"), "{err}");

    let approved = config_with(vec![plugin(
        "soap_ws_security",
        json!({
            "x509_signature": {
                "allowed_algorithms": ["rsa-sha256"],
                "allowed_digest_algorithms": ["sha256"]
            }
        }),
    )]);
    policy::check_gateway_config_enforced(&approved).expect("sha256 selections are approved");
}

#[test]
fn gateway_policy_rejects_an_unclassified_stored_password_representation() {
    for value in [
        "argon2id$v=19$m=65536,t=3,p=4$abc$def".to_string(),
        "hmac_sha256:abc".to_string(),
        format!("hmac_sha256:{}", "A".repeat(64)),
        format!("hmac_sha256:{}g", "a".repeat(63)),
    ] {
        let consumer = consumer_with(json!({ "password_hash": value }));
        let config = GatewayConfig {
            consumers: vec![consumer],
            ..GatewayConfig::default()
        };
        let err = policy::check_gateway_config_enforced(&config)
            .expect_err("an unclassified or malformed stored hash is rejected");
        assert!(err.contains(policy::APPROVED_PASSWORD_HASH_PREFIX), "{err}");
        assert!(
            !err.contains("argon2id") && !err.contains("hmac_sha256:abc"),
            "the stored value must never be echoed: {err}"
        );
    }

    for malformed in [
        json!({ "password": "plaintext-must-not-be-stored" }),
        json!({ "password_hash": 7 }),
        json!("not-a-basic-auth-credential-object"),
    ] {
        let config = GatewayConfig {
            consumers: vec![consumer_with(malformed)],
            ..GatewayConfig::default()
        };
        let err = policy::check_gateway_config_enforced(&config)
            .expect_err("missing or non-string stored hashes are unclassified");
        assert!(err.contains(policy::APPROVED_PASSWORD_HASH_PREFIX), "{err}");
        assert!(
            !err.contains("plaintext-must-not-be-stored"),
            "the credential must not be echoed: {err}"
        );
    }
}

#[test]
fn gateway_policy_admits_the_approved_stored_password_representation() {
    // Multi-credential rotation stores an array; both shapes are walked.
    let consumer = consumer_with(json!([
        { "password_hash": format!("hmac_sha256:{}", "a".repeat(64)) }
    ]));
    let config = GatewayConfig {
        consumers: vec![consumer],
        ..GatewayConfig::default()
    };
    policy::check_gateway_config_enforced(&config).expect("HMAC-SHA256 hashes are approved");
}

#[test]
fn gateway_document_policy_is_wired_to_every_runtime_publication_boundary() {
    // A default-profile external test cannot establish global FIPS
    // enforcement, so pin the production wiring statically while the semantic
    // `_enforced` tests above exercise the policy itself.
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let incremental_start = proxy
        .find("pub async fn apply_incremental(")
        .expect("incremental apply boundary");
    let staging_start = proxy[incremental_start..]
        .find("let prospective_delta =")
        .map(|offset| incremental_start + offset)
        .expect("incremental cache staging boundary");
    assert!(
        proxy[incremental_start..staging_start]
            .contains("crate::fips::policy::check_gateway_config(&new_config)"),
        "database and CP/DP deltas must be rejected before request-epoch cache staging"
    );

    let validation = include_str!("../../../src/config/validation_pipeline.rs");
    assert!(
        validation.contains("crate::fips::policy::check_gateway_config(config)"),
        "database full loads and CP composition must share the FIPS document gate"
    );

    let mesh = include_str!("../../../src/grpc/mesh_server.rs");
    assert!(
        mesh.matches("crate::fips::policy::check_gateway_config(")
            .count()
            >= 3,
        "initial, full/recovery, and incremental mesh stream candidates must all be gated"
    );

    let reconciler = include_str!("../../../src/k8s_controller/reconciler.rs");
    let publish_start = reconciler
        .find("pub fn publish_k8s_reconcile(")
        .expect("Kubernetes publication boundary");
    let reconcile_start = reconciler[publish_start..]
        .find("async fn do_reconcile(")
        .map(|offset| publish_start + offset)
        .expect("end of Kubernetes publication boundary");
    let publish_body = &reconciler[publish_start..reconcile_start];
    let fips_gate = publish_body
        .find("crate::fips::policy::check_gateway_config(&candidate)")
        .expect("Kubernetes composed-candidate FIPS gate");
    let overlay_store = publish_body
        .find("store_accepted_k8s_overlay(")
        .expect("accepted Kubernetes overlay store");
    assert!(
        fips_gate < overlay_store,
        "a rejected Kubernetes candidate must not replace the last accepted overlay"
    );
}

#[test]
fn approved_primitives_agree_with_their_published_test_vectors() {
    use ferrum_edge::fips::approved::{HmacSha256, HmacSha512, Sha256, Sha512};

    // FIPS 180-4 / RFC 6234 "abc" vectors, and the RFC 4231 HMAC test case 1
    // vector. These pin the module-backed primitives against a published
    // answer, which is what makes the substitution for RustCrypto verifiable
    // rather than assumed — and they run identically on both build profiles.
    assert_eq!(
        hex::encode(Sha256::digest(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        &hex::encode(Sha512::digest(b"abc"))[..32],
        "ddaf35a193617abacc417349ae204131"
    );

    let mut incremental = Sha256::new();
    incremental.update(b"a");
    incremental.update(b"bc");
    assert_eq!(incremental.finalize(), Sha256::digest(b"abc"));

    let mut mac = HmacSha256::new_from_slice(&[0x0b; 20]).expect("any key length is accepted");
    mac.update(b"Hi There");
    assert_eq!(
        hex::encode(mac.finalize().into_bytes()),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );

    let mut mac512 = HmacSha512::new_from_slice(&[0x0b; 20]).expect("any key length is accepted");
    mac512.update(b"Hi There");
    assert_eq!(
        &hex::encode(mac512.finalize().into_bytes())[..32],
        "87aa7cdea5ef619d4ff0b4241a1d6cb0"
    );
}
