//! FIPS key-strength admission and the complete peer-verification gate
//! (issue #3510).
//!
//! Like `fips_policy_tests`, these target the `_enforced` entry points. FIPS
//! enforcement is established only by `install_crypto_provider` during process
//! bootstrap, which an external test binary never runs, so the gated wrappers
//! short-circuit to `Ok(())` and testing through them would assert nothing.
//! `gated_wrappers_are_inert_without_bootstrap` covers the gate itself, which
//! is also the proof that an ordinary non-FIPS deployment is behaviourally
//! unchanged by everything below.

use chrono::Utc;
use serde_json::json;

use ferrum_edge::config::env_config::{DbTlsMode, EnvConfig};
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope, Proxy, Upstream};
use ferrum_edge::fips::keys;
use ferrum_edge::fips::policy;

// ── Fixtures ────────────────────────────────────────────────────────────────

fn plugin(name: &str, config: serde_json::Value) -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
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

fn config_with_plugins(plugins: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        plugin_configs: plugins,
        ..GatewayConfig::default()
    }
}

/// Build an upstream, optionally with backend verification switched off.
fn upstream(id: &str, verify_server_cert: bool) -> Upstream {
    serde_json::from_value(json!({
        "id": id,
        "namespace": "ferrum",
        "name": format!("upstream-{id}"),
        "targets": [{"host": "10.0.0.10", "port": 8443, "weight": 100}],
        "backend_tls_verify_server_cert": verify_server_cert,
    }))
    .expect("upstream fixture")
}

/// Build a direct-backend HTTPS proxy, optionally with verification off.
fn proxy(id: &str, verify_server_cert: bool) -> Proxy {
    serde_json::from_value(json!({
        "id": id,
        "namespace": "ferrum",
        "name": format!("proxy-{id}"),
        "listen_path": format!("/{id}"),
        "backend_scheme": "https",
        "backend_host": "backend.internal",
        "backend_port": 8443,
        "backend_tls_verify_server_cert": verify_server_cert,
    }))
    .expect("proxy fixture")
}

/// Generate a self-signed certificate over a caller-chosen key.
///
/// `rcgen` is a dev-dependency here, so this mints real DER rather than
/// asserting against a hand-rolled encoding — a key-strength gate that only
/// ever sees fixtures its own author encoded proves very little.
fn self_signed_der(algorithm: &'static rcgen::SignatureAlgorithm) -> Vec<u8> {
    let key_pair = rcgen::KeyPair::generate_for(algorithm).expect("key pair");
    let params = rcgen::CertificateParams::new(vec!["fips-admission.test".to_string()])
        .expect("certificate params");
    params
        .self_signed(&key_pair)
        .expect("self-signed certificate")
        .der()
        .to_vec()
}

// ── Certificate key strength ────────────────────────────────────────────────

#[test]
fn approved_ec_certificates_are_admitted() {
    for algorithm in [
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &rcgen::PKCS_ECDSA_P384_SHA384,
    ] {
        let der = self_signed_der(algorithm);
        keys::check_certificate_public_key_enforced(&der, "frontend TLS certificate")
            .expect("an approved NIST prime curve must be admitted");
    }
}

#[test]
fn certificate_ec_admission_uses_the_named_curve_not_rounded_point_bits() {
    let mut p521_point = vec![0u8; 1 + 2 * 66];
    p521_point[0] = 0x04;
    p521_point[1] = 1;
    keys::check_ec_curve_oid_and_point_enforced(
        "1.3.132.0.35",
        &p521_point,
        "frontend TLS certificate",
    )
    .expect("a correctly sized P-521 point is admitted by its named curve");

    let mut same_size_unapproved = vec![0u8; 1 + 2 * 32];
    same_size_unapproved[0] = 0x04;
    same_size_unapproved[1] = 1;
    keys::check_ec_curve_oid_and_point_enforced(
        "1.3.132.0.10",
        &same_size_unapproved,
        "frontend TLS certificate",
    )
    .expect_err("secp256k1 must not be mistaken for P-256 by point length");

    keys::check_ec_curve_oid_and_point_enforced(
        "1.2.840.10045.3.1.7",
        &p521_point,
        "frontend TLS certificate",
    )
    .expect_err("a point whose encoding does not match the named curve must fail closed");
}

#[test]
fn ed25519_certificates_are_refused_with_an_actionable_diagnostic() {
    // Ed25519 is approved by FIPS 186-5 as an *algorithm*, but it is not in the
    // set Ferrum routes through the selected module — the same reasoning that
    // keeps `EdDSA` off the JWS allow-list. It must be refused at admission,
    // not left to fail opaquely inside a provider.
    let der = self_signed_der(&rcgen::PKCS_ED25519);

    let error = keys::check_certificate_public_key_enforced(&der, "frontend TLS certificate")
        .expect_err("Ed25519 must be refused");

    assert!(error.contains("frontend TLS certificate"), "{error}");
    assert!(error.contains("Ed25519"), "{error}");
    // The remedy has to be in the message, or the operator is guessing.
    assert!(error.contains("P-256"), "{error}");
}

#[test]
fn under_strength_rsa_is_refused_and_approved_rsa_is_admitted() {
    // SP 800-131A Rev. 2 disallowed RSA below 2048 bits in 2013. The rustls
    // FIPS provider rejects a non-approved *algorithm*, not uniformly an
    // approved algorithm under an under-strength key, which is why Ferrum
    // enforces this itself at admission.
    keys::check_rsa_modulus_bits(2048, "backend TLS CA bundle").expect("RSA-2048 is admitted");
    keys::check_rsa_modulus_bits(4096, "backend TLS CA bundle").expect("RSA-4096 is admitted");

    let error = keys::check_rsa_modulus_bits(1024, "backend TLS CA bundle")
        .expect_err("RSA-1024 must be refused");
    assert!(error.contains("1024"), "{error}");
    assert!(error.contains("2048"), "{error}");
    assert!(error.contains("backend TLS CA bundle"), "{error}");

    let unmeasurable = keys::check_rsa_modulus_bits(0, "backend TLS CA bundle")
        .expect_err("a modulus whose strength cannot be established must fail closed");
    assert!(
        unmeasurable.contains("could not be measured"),
        "{unmeasurable}"
    );
}

#[test]
fn oversized_rsa_is_refused_as_a_handshake_denial_of_service_bound() {
    let error = keys::check_rsa_modulus_bits(65_536, "admin TLS certificate")
        .expect_err("an absurd modulus must be bounded");
    assert!(
        error.contains(&keys::MAX_RSA_MODULUS_BITS.to_string()),
        "{error}"
    );
}

#[test]
fn a_real_rsa_certificate_is_measured_from_its_subject_public_key_info() {
    // The bit-level rule above is only meaningful if the certificate path
    // actually reaches it, so measure a genuine RSA certificate end to end
    // rather than trusting the unit rule alone.
    //
    // `rcgen` can only generate RSA through its aws-lc backend; when that arm is
    // not compiled it reports `KeyGenerationUnavailable`, which is a property of
    // the fixture generator and not of the gate under test. The EC and Ed25519
    // cases above already exercise the same certificate path end to end.
    let Ok(key_pair) = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256) else {
        return;
    };
    let params = rcgen::CertificateParams::new(vec!["fips-admission.test".to_string()])
        .expect("certificate params");
    let der = params
        .self_signed(&key_pair)
        .expect("self-signed certificate")
        .der()
        .to_vec();

    keys::check_certificate_public_key_enforced(&der, "frontend TLS certificate")
        .expect("rcgen mints 2048-bit RSA, which is approved");
}

#[test]
fn certificate_diagnostics_never_carry_a_path_or_key_material() {
    let der = self_signed_der(&rcgen::PKCS_ED25519);

    // A caller passing an over-long or control-character-bearing label must not
    // be able to turn one refusal into an unbounded or multi-line log record.
    let hostile_label = format!("{}\n/etc/ferrum/secret.key", "A".repeat(500));
    let error = keys::check_certificate_public_key_enforced(&der, &hostile_label)
        .expect_err("Ed25519 must be refused");

    assert!(!error.contains('\n'), "diagnostic must stay single-line");
    assert!(
        !error.contains("/etc/ferrum/secret.key"),
        "diagnostic must not carry a path: {error}"
    );
    let diagnostic_label = error
        .split_once(':')
        .map(|(label, _)| label)
        .expect("certificate admission diagnostic must carry a surface label");
    assert!(
        diagnostic_label.chars().count() <= keys::MAX_SURFACE_LABEL_CHARS,
        "label must be bounded to {} chars: {error}",
        keys::MAX_SURFACE_LABEL_CHARS
    );
}

#[test]
fn an_unparseable_certificate_fails_key_form_admission() {
    let error = keys::check_certificate_public_key_enforced(
        b"not a certificate",
        "frontend TLS certificate",
    )
    .expect_err("unparseable DER has no classifiable public-key form");
    assert!(error.contains("could not be parsed"), "{error}");
}

// ── JWK key strength ────────────────────────────────────────────────────────

#[test]
fn jwk_rsa_modulus_floor_is_enforced_and_padding_is_not_credited() {
    let weak = vec![0xFFu8; 128]; // 1024 bits
    let error = keys::check_jwk_rsa_modulus_enforced(&weak).expect_err("RSA-1024 JWK is refused");
    assert!(error.contains("1024"), "{error}");
    assert!(error.contains("2048"), "{error}");

    let strong = vec![0xFFu8; 256]; // 2048 bits
    keys::check_jwk_rsa_modulus_enforced(&strong).expect("RSA-2048 JWK is admitted");

    let rounded_up_weak = vec![0x01u8; 256]; // 2041 significant bits
    keys::check_jwk_rsa_modulus_enforced(&rounded_up_weak)
        .expect_err("a short top byte must not be rounded up to 2048 bits");

    // An issuer that pads `n` contrary to RFC 7518 §6.3.1.1 must not be
    // credited with the padding.
    let mut padded_weak = vec![0x00u8; 16];
    padded_weak.extend(std::iter::repeat_n(0xFFu8, 128));
    keys::check_jwk_rsa_modulus_enforced(&padded_weak)
        .expect_err("padding must not turn a 1024-bit modulus into an admitted one");
}

#[test]
fn jwk_rsa_public_exponent_form_is_enforced() {
    let modulus = vec![0xFFu8; 256];
    keys::check_jwk_rsa_public_key_enforced(&modulus, &[0x01, 0x00, 0x01])
        .expect("RSA exponent 65537 is admitted");
    keys::check_jwk_rsa_public_key_enforced(&modulus, &[0x03])
        .expect_err("legacy exponent 3 is outside the admitted FIPS form");
    keys::check_jwk_rsa_public_key_enforced(&modulus, &[0x01, 0x00, 0x02])
        .expect_err("an even RSA public exponent must be refused");
}

#[test]
fn jwk_ec_curves_outside_the_approved_set_are_refused() {
    for curve in ["P-256", "P-384"] {
        keys::check_jwk_ec_curve_enforced(curve).unwrap_or_else(|error| {
            panic!("{curve} is approved and must be admitted: {error}");
        });
    }
    for curve in [
        "P-521",
        "secp256k1",
        "Ed25519",
        "X25519",
        "p-256",
        " P-384 ",
        "",
    ] {
        assert!(
            keys::check_jwk_ec_curve_enforced(curve).is_err(),
            "{curve} must be refused"
        );
    }
}

#[test]
fn p521_jwks_are_refused_because_es512_is_refused() {
    // The two decisions have to agree, or the curve is admitted while every
    // algorithm that could use it is not — a failure moved later, not removed.
    let error = keys::check_jwk_ec_curve_enforced("P-521").expect_err("P-521 JWK must be refused");
    assert!(error.contains("P-256"), "{error}");
    assert!(
        !policy::APPROVED_JWT_ALGORITHMS.contains(&"ES512"),
        "the curve gate and the algorithm gate must agree"
    );
}

#[test]
fn jwk_ec_curve_and_coordinate_form_are_both_required() {
    let p256 = vec![1u8; 32];
    keys::check_jwk_ec_public_key_enforced(Some("P-256"), &p256, &p256)
        .expect("complete P-256 public components are admitted");
    keys::check_jwk_ec_public_key_enforced(None, &p256, &p256)
        .expect_err("a missing curve must not silently default under FIPS enforcement");
    keys::check_jwk_ec_public_key_enforced(Some("P-256"), &p256[..31], &p256)
        .expect_err("truncated coordinates must fail at key admission");
}

// ── Environment-level peer verification ─────────────────────────────────────

fn env_with(mutate: impl FnOnce(&mut EnvConfig)) -> EnvConfig {
    let mut env_config = EnvConfig::default();
    mutate(&mut env_config);
    env_config
}

#[test]
fn a_default_environment_is_admitted() {
    policy::check_env_config_enforced(&env_with(|_| {}))
        .expect("Ferrum's secure-by-default environment must pass its own FIPS gate");
}

#[test]
fn every_independently_configurable_env_verification_bypass_is_refused() {
    // The point here is coverage of the *set*, not of any single flag: a
    // global-only gate is precisely the hole a per-surface switch walks through.
    type EnvMutation = fn(&mut EnvConfig);
    let cases: [(&str, EnvMutation); 5] = [
        ("FERRUM_TLS_NO_VERIFY", |c| c.tls_no_verify = true),
        ("FERRUM_ADMIN_TLS_NO_VERIFY", |c| {
            c.admin_tls_no_verify = true
        }),
        ("FERRUM_ALLOW_INSECURE_ADMIN_HTTP", |c| {
            c.allow_insecure_admin_http = true
        }),
        ("FERRUM_MESH_EGRESS_STREAM_ALLOW_PLAINTEXT", |c| {
            c.mesh_egress_stream_allow_plaintext = true
        }),
        ("FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT", |c| {
            c.cp_dp_grpc_allow_plaintext = true
        }),
    ];

    for (name, mutate) in cases {
        let env_config = env_with(mutate);
        let error = policy::check_env_config_enforced(&env_config)
            .expect_err("an unauthenticated peer defeats the approved key exchange");
        assert!(
            error.contains(name),
            "the diagnostic must name the setting to change: {error}"
        );
    }
}

#[test]
fn injector_plaintext_escape_hatch_is_in_the_process_peer_bypass_inventory() {
    assert!(
        policy::PROCESS_PEER_BYPASS_ENV
            .iter()
            .any(|(name, _)| *name == "FERRUM_INJECTOR_ALLOW_PLAINTEXT"),
        "the injector webhook's dev-only plaintext transport must be refused in FIPS mode"
    );
}

#[test]
fn dp_grpc_no_verify_is_covered_by_the_ordinary_validator_not_by_fips() {
    // `FERRUM_DP_GRPC_TLS_NO_VERIFY` is deliberately absent from the FIPS rule
    // set because it is already refused unconditionally, on every build and in
    // every mode. This test is what makes that reasoning load-bearing: if the
    // ordinary rejection is ever relaxed, this fails and the FIPS gate has to
    // grow a rule of its own rather than silently leaving a bypass open.
    //
    // `EnvConfig::validate` is private, so the assertion is made over the source
    // of the rejection itself: the flag must be refused before any mode or
    // build-profile test, i.e. not inside a FIPS or production-mode branch.
    let env_config_source = include_str!("../../../src/config/env_config.rs");
    let rejection = env_config_source
        .find("if self.dp_grpc_tls_no_verify {")
        .expect("the unconditional DP gRPC no-verify rejection must still exist");
    let body = &env_config_source[rejection..rejection + 400];
    assert!(
        body.contains("return Err(")
            && body.contains("FERRUM_DP_GRPC_TLS_NO_VERIFY=true is not supported"),
        "the DP gRPC no-verify flag must stay refused unconditionally; if it is ever made \
         conditional, fips::policy::check_env_config_enforced needs a rule of its own"
    );
    assert!(
        !body.contains("is_enforcing") && !body.contains("fips"),
        "the rejection must not become FIPS-conditional without a matching FIPS rule"
    );

    // And the FIPS policy deliberately does not duplicate it.
    let policy_source = include_str!("../../../src/fips/policy.rs");
    assert!(
        policy_source.contains("FERRUM_DP_GRPC_TLS_NO_VERIFY` is deliberately absent"),
        "the omission must stay documented at the policy itself, not only here"
    );
}

#[test]
fn every_mongodb_tls_mode_is_refused_at_the_config_store_boundary() {
    for mode in [DbTlsMode::Require, DbTlsMode::VerifyFull] {
        let error = policy::check_env_config_enforced(&env_with(|config| {
            config.db_type = Some("MoNgOdB".to_string());
            config.db_tls_mode = Some(mode);
        }))
        .expect_err("every MongoDB config store must be refused");
        assert!(error.contains("FERRUM_DB_TYPE=mongodb"), "{error}");
        assert!(error.contains("database-driver cryptography"), "{error}");
    }
}

#[test]
fn blanket_mongodb_rejection_never_echoes_uri_or_credentials() {
    for url in [
        "mongodb://admin:sup3rs3cr3t@db.internal:27017/ferrum?tls=true&tlsInsecure=true",
        "mongodb://admin:explicit-false@db.internal:27017/ferrum?tlsAllowInvalidCertificates=false",
        "mongodb://admin:tlsInsecure@db.internal:27017/ferrum",
    ] {
        let error = policy::check_env_config_enforced(&env_with(|config| {
            config.db_type = Some("mongodb".to_string());
            config.db_url = Some(url.to_string());
        }))
        .expect_err("every MongoDB URI must be refused");

        assert!(error.contains("FERRUM_DB_TYPE=mongodb"), "{error}");
        assert!(!error.contains("sup3rs3cr3t"), "{error}");
        assert!(!error.contains("explicit-false"), "{error}");
        assert!(!error.contains("db.internal"), "{error}");
        assert!(!error.contains("tlsInsecure"), "{error}");
    }
}

// ── Gateway-document peer verification ──────────────────────────────────────

#[test]
fn a_declared_upstream_verification_opt_out_is_refused_even_when_dormant() {
    // Documented decision: `backend_tls_verify_server_cert: false` is refused
    // even where it is currently inert. An `Upstream` carries no scheme of its
    // own, so "inert" is a property of its targets and of every proxy that
    // references it — none of which is stable across the reload or CP
    // publication this gate is the backstop for. The remedy is free: `true` is
    // the schema default and a no-op on a plaintext backend.
    let config = GatewayConfig {
        upstreams: vec![upstream("billing", false)],
        ..GatewayConfig::default()
    };

    let error = policy::check_gateway_config_enforced(&config)
        .expect_err("a declared verification opt-out is refused even when dormant");
    assert!(error.contains("upstreams[#1]"), "{error}");
}

#[test]
fn a_verifying_document_is_admitted() {
    let config = GatewayConfig {
        upstreams: vec![upstream("billing", true)],
        proxies: vec![proxy("api", true)],
        ..GatewayConfig::default()
    };
    policy::check_gateway_config_enforced(&config)
        .expect("the schema defaults already verify every peer");
}

#[test]
fn gateway_verification_diagnostics_name_positions_not_operator_ids() {
    let config = GatewayConfig {
        upstreams: vec![upstream("prod-billing-cluster", false)],
        ..GatewayConfig::default()
    };

    let error = policy::check_gateway_config_enforced(&config).expect_err("refused");
    assert!(
        !error.contains("prod-billing-cluster"),
        "an id is operator free text and must not be echoed: {error}"
    );
    assert!(error.contains("#1"), "{error}");
}

#[test]
fn a_proxy_verification_opt_out_is_refused() {
    let config = GatewayConfig {
        proxies: vec![proxy("api", false)],
        ..GatewayConfig::default()
    };
    let error = policy::check_gateway_config_enforced(&config).expect_err("refused");
    assert!(error.contains("proxies[#1]"), "{error}");
}

#[test]
fn every_plugin_owned_verification_opt_out_is_refused() {
    let cases: &[(&str, serde_json::Value)] = &[
        ("spec_expose", json!({ "tls_no_verify": true })),
        (
            "udp_logging",
            json!({ "dtls": true, "dtls_no_verify": true }),
        ),
        (
            "api_chargeback_sink",
            json!({ "clickhouse": { "tls": { "insecure_skip_verify": true } } }),
        ),
        (
            "api_chargeback_sink",
            json!({ "clickhouse": { "tls": { "verify_hostname": false } } }),
        ),
        (
            "mesh_route_dispatch",
            json!({
                "rules": [
                    { "destination": { "backend_tls": { "verify_server_cert": true } } },
                    { "destination": { "backend_tls": { "verify_server_cert": false } } }
                ]
            }),
        ),
        (
            "ai_transcript_audit",
            json!({ "sink": { "allow_insecure_loopback": true } }),
        ),
        ("ldap_auth", json!({ "allow_plaintext": true })),
        (
            "ai_federation",
            json!({ "providers": [{ "allow_plaintext": true }] }),
        ),
        (
            "ai_stream_router",
            json!({ "providers": [{ "allow_plaintext": true }] }),
        ),
        (
            "rate_limiting",
            json!({
                "sync_mode": "redis",
                "redis_url": "rediss://cache.internal:6380/0#insecure",
            }),
        ),
    ];

    for (name, config) in cases {
        let document = config_with_plugins(vec![plugin(name, config.clone())]);
        match policy::check_gateway_config_enforced(&document) {
            Ok(()) => panic!("{name} with config {config} must be refused"),
            Err(error) => assert!(
                error.contains(name),
                "the diagnostic must name the plugin to edit: {error}"
            ),
        }
    }
}

// ── DTLS ────────────────────────────────────────────────────────────────────

/// Build a raw stream proxy on a caller-chosen backend scheme.
fn stream_proxy(id: &str, scheme: &str) -> Proxy {
    serde_json::from_value(json!({
        "id": id,
        "namespace": "ferrum",
        "name": format!("proxy-{id}"),
        // Stream proxies route on `listen_port` and must leave `listen_path`
        // unset.
        "listen_port": 6000,
        "backend_scheme": scheme,
        "backend_host": "backend.internal",
        "backend_port": 6001,
    }))
    .expect("stream proxy fixture")
}

#[test]
fn a_dtls_stream_proxy_is_refused() {
    // `dimpl` routes DTLS suites and signatures onto the selected module but
    // draws the handshake `Random`, the DTLS 1.2 HelloVerifyRequest cookie
    // secret, and the DTLS 1.2 explicit AES-GCM record nonce from the `rand`
    // crate rather than the module DRBG. docs/fips.md puts the DRBG inside the
    // boundary, so the transport is refused rather than admitted under an
    // implicit claim.
    let config = GatewayConfig {
        proxies: vec![stream_proxy("udp-edge", "dtls")],
        ..GatewayConfig::default()
    };
    let error = policy::check_gateway_config_enforced(&config).expect_err("DTLS is refused");
    assert!(error.contains("proxies[#1].backend_scheme=dtls"), "{error}");
    assert!(error.contains("dimpl"), "{error}");
    assert!(
        !error.contains("udp-edge"),
        "an id is operator free text and must not be echoed: {error}"
    );
}

#[test]
fn a_plaintext_udp_stream_proxy_is_admitted() {
    // The refusal is about the DTLS stack, not about UDP: a plaintext UDP
    // stream proxy performs no cryptography and stays supported.
    let config = GatewayConfig {
        proxies: vec![stream_proxy("udp-edge", "udp")],
        ..GatewayConfig::default()
    };
    policy::check_gateway_config_enforced(&config).expect("plaintext UDP has no crypto");
}

#[test]
fn a_dtls_udp_logging_sink_is_refused_but_a_plaintext_one_is_not() {
    let dtls_sink = config_with_plugins(vec![plugin(
        "udp_logging",
        json!({ "host": "collector.internal", "port": 9000, "dtls": true }),
    )]);
    let error = policy::check_gateway_config_enforced(&dtls_sink).expect_err("DTLS is refused");
    assert!(error.contains("udp_logging.dtls"), "{error}");
    assert!(error.contains("dimpl"), "{error}");

    let plaintext_sink = config_with_plugins(vec![plugin(
        "udp_logging",
        json!({ "host": "collector.internal", "port": 9000 }),
    )]);
    policy::check_gateway_config_enforced(&plaintext_sink)
        .expect("a plaintext UDP log sink performs no cryptography");
}

#[test]
fn the_dtls_inventory_row_and_the_dtls_refusal_agree() {
    use ferrum_edge::fips::inventory;

    // The inventory is documentation; the policy is enforcement. A row that
    // claimed DTLS was module-routable while the policy refused it — or the
    // reverse — is exactly the drift this table exists to prevent.
    let rejected_dtls = inventory::rejected().any(|entry| entry.location.contains("dimpl"));
    let policy_refuses_dtls = policy::check_gateway_config_enforced(&GatewayConfig {
        proxies: vec![stream_proxy("dtls-edge", "dtls")],
        ..GatewayConfig::default()
    })
    .is_err();
    assert_eq!(
        rejected_dtls, policy_refuses_dtls,
        "inventory and fips::policy disagree about DTLS"
    );
}

#[test]
fn an_approved_plugin_configuration_is_admitted() {
    // The verification keys are refused; the plugins that own them are not.
    let document = config_with_plugins(vec![
        plugin("spec_expose", json!({ "tls_no_verify": false })),
        plugin(
            "api_chargeback_sink",
            json!({ "clickhouse": { "tls": { "insecure_skip_verify": false,
                                             "verify_hostname": true } } }),
        ),
    ]);
    policy::check_gateway_config_enforced(&document)
        .expect("a plugin that verifies its peer is admitted");
}

#[test]
fn load_testing_insecure_default_is_refused_even_when_the_key_is_absent() {
    // The one insecure-by-default surface in the inventory: with `gateway_tls`
    // on, an absent `gateway_tls_no_verify` resolves to `true`. A gate that only
    // inspected present keys would wave that default straight through.
    let absent = config_with_plugins(vec![plugin("load_testing", json!({ "gateway_tls": true }))]);
    let error = policy::check_gateway_config_enforced(&absent)
        .expect_err("the open default must be refused");
    assert!(error.contains("gateway_tls_no_verify"), "{error}");

    let explicit = config_with_plugins(vec![plugin(
        "load_testing",
        json!({ "gateway_tls": true, "gateway_tls_no_verify": false }),
    )]);
    policy::check_gateway_config_enforced(&explicit)
        .expect("an explicit opt-in to verification must be admitted");

    // Without `gateway_tls` the key cannot bypass anything, and here the gate is
    // a value in the same document rather than an inference about another one.
    let no_tls = config_with_plugins(vec![plugin(
        "load_testing",
        json!({ "gateway_tls": false }),
    )]);
    policy::check_gateway_config_enforced(&no_tls)
        .expect("a disabled TLS client has no peer to leave unverified");
}

#[test]
fn a_disabled_plugin_instance_is_not_reported() {
    let mut disabled = plugin("spec_expose", json!({ "tls_no_verify": true }));
    disabled.enabled = false;
    policy::check_gateway_config_enforced(&config_with_plugins(vec![disabled]))
        .expect("a disabled plugin performs no cryptography");
}

#[test]
fn kafka_ssl_no_verify_needs_no_rule_because_the_plugin_itself_is_refused() {
    // Pins the reasoning behind `ssl_no_verify`'s absence from the plugin-key
    // table: if the plugin-level rejection were ever removed, this fails rather
    // than silently orphaning the key.
    assert!(
        policy::NON_APPROVED_PLUGINS.contains(&"kafka_logging"),
        "kafka_logging's own rejection is what covers its ssl_no_verify key"
    );
    let config = config_with_plugins(vec![plugin(
        "kafka_logging",
        json!({ "ssl_no_verify": true }),
    )]);
    policy::check_gateway_config_enforced(&config).expect_err("the whole plugin is refused");
}

#[test]
fn peer_verification_diagnostics_are_bounded() {
    let upstreams: Vec<Upstream> = (0..64)
        .map(|index| upstream(&format!("u{index}"), false))
        .collect();
    let config = GatewayConfig {
        upstreams,
        ..GatewayConfig::default()
    };

    let error = policy::check_gateway_config_enforced(&config).expect_err("refused");
    assert_eq!(
        error.matches("upstreams[#").count(),
        policy::MAX_REPORTED_VIOLATIONS,
        "a large document must not turn one refusal into an unbounded record: {error}"
    );
    assert!(
        error.contains(&format!(
            "and {} more",
            64 - policy::MAX_REPORTED_VIOLATIONS
        )),
        "the remainder must still be counted: {error}"
    );
}

// ── External secret providers ───────────────────────────────────────────────

#[test]
fn remote_external_secret_providers_are_refused_and_file_is_not() {
    for suffix in policy::REMOTE_SECRET_PROVIDER_SUFFIXES {
        assert!(
            policy::check_external_secret_sources_enforced(vec![*suffix]).is_err(),
            "{suffix} resolves secrets over an SDK TLS stack Ferrum cannot route"
        );
    }

    assert!(
        !policy::REMOTE_SECRET_PROVIDER_SUFFIXES.contains(&"_FILE"),
        "`_FILE` is a local read that reaches no network peer and stays supported"
    );
    policy::check_external_secret_sources_enforced(Vec::new())
        .expect("no configured remote provider means nothing to refuse");
}

#[test]
fn external_secret_refusal_names_the_alternative_but_not_the_settings() {
    let error = policy::check_external_secret_sources_enforced(vec!["_VAULT"])
        .expect_err("Vault is refused");
    assert!(error.contains("_VAULT"), "{error}");
    assert!(error.contains("_FILE"), "{error}");
    assert!(error.contains("docs/fips.md"), "{error}");
}

// ── The gate itself ─────────────────────────────────────────────────────────

#[test]
fn gated_wrappers_are_inert_without_bootstrap() {
    // Nothing in this binary calls `install_crypto_provider`, so enforcement is
    // never established and every gated wrapper must be a no-op. This is what
    // guarantees an ordinary (non-FIPS) deployment is behaviourally unchanged by
    // the existence of all of the above.
    assert!(!ferrum_edge::fips::is_enforcing());

    let der = self_signed_der(&rcgen::PKCS_ED25519);
    keys::check_certificate_public_key(&der, "frontend TLS certificate")
        .expect("inert when FIPS mode is off");
    keys::check_jwk_rsa_modulus(&[0xFFu8; 64]).expect("inert when FIPS mode is off");
    keys::check_jwk_ec_curve("secp256k1").expect("inert when FIPS mode is off");
    policy::check_external_secret_sources().expect("inert when FIPS mode is off");

    let config = GatewayConfig {
        upstreams: vec![upstream("billing", false)],
        ..GatewayConfig::default()
    };
    policy::check_gateway_config(&config).expect("inert when FIPS mode is off");
    policy::check_env_config(&env_with(|c| c.tls_no_verify = true))
        .expect("inert when FIPS mode is off");
}
