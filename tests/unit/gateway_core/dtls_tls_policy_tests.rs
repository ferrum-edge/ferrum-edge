//! The gateway TLS policy on DTLS surfaces (issue #4507).
//!
//! `FERRUM_TLS_MIN_VERSION`, `FERRUM_TLS_MAX_VERSION`, `FERRUM_TLS_CIPHER_SUITES`
//! and `FERRUM_TLS_KEY_EXCHANGE_GROUPS` are documented as applying "inbound + outbound".
//! Before #4507 the DTLS builders never received the parsed `TlsPolicy`, so a
//! `udp` + `dtls` proxy kept accepting DTLS 1.2 with the DTLS stack's full
//! default suite list under `FERRUM_TLS_MIN_VERSION=1.3`.
//!
//! These tests read the policy through `TlsPolicy::from_env_config` — the same
//! constructor every rustls listener uses — so the DTLS mapping can never drift
//! from what the rest of the gateway enforces. No process environment is read:
//! `EnvConfig` fields are set directly, so no env lock is required.

use dimpl::crypto::{Dtls12CipherSuite, Dtls13CipherSuite, NamedGroup};
use ferrum_edge::config::env_config::EnvConfig;
use ferrum_edge::dtls::{DtlsSuitePolicy, build_frontend_dtls_config};
use ferrum_edge::tls::TlsPolicy;

fn policy(min: &str, max: &str, suites: Option<&str>) -> TlsPolicy {
    let env = EnvConfig {
        tls_min_version: min.to_string(),
        tls_max_version: max.to_string(),
        tls_cipher_suites: suites.map(str::to_string),
        ..EnvConfig::default()
    };
    TlsPolicy::from_env_config(&env).expect("policy must parse")
}

fn map(min: &str, max: &str, suites: Option<&str>) -> DtlsSuitePolicy {
    DtlsSuitePolicy::from_tls_policy(&policy(min, max, suites), "frontend DTLS listener")
        .expect("policy must map onto the DTLS stack")
}

/// An ECDSA P-256 server identity written to disk, the only key type the DTLS
/// stack accepts.
struct DtlsIdentity {
    _dir: tempfile::TempDir,
    cert_path: String,
    key_path: String,
}

fn dtls_identity() -> DtlsIdentity {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate P-256 key");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("certificate params")
        .self_signed(&key_pair)
        .expect("self-sign");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    DtlsIdentity {
        cert_path: cert_path.to_string_lossy().into_owned(),
        key_path: key_path.to_string_lossy().into_owned(),
        _dir: dir,
    }
}

#[test]
fn default_policy_keeps_both_dtls_versions_with_the_ecdsa_aead_suites() {
    let mapped = map("1.2", "1.3", None);

    // The defaults name both ECDHE-ECDSA-* and ECDHE-RSA-* TLS 1.2 suites. The
    // RSA-authenticated ones have no DTLS counterpart (the DTLS stack
    // authenticates with ECDSA certificates only), so only the ECDSA ones
    // survive — and their presence is what keeps that exclusion from being a
    // capability loss.
    let mut dtls12: Vec<u16> = mapped
        .dtls12_cipher_suites()
        .iter()
        .map(Dtls12CipherSuite::as_u16)
        .collect();
    dtls12.sort_unstable();
    assert_eq!(
        dtls12,
        vec![0xC02B, 0xC02C, 0xCCA9],
        "the default policy must admit exactly the ECDSA AEAD DTLS 1.2 suites"
    );
    assert!(
        !mapped.dtls13_cipher_suites().is_empty(),
        "DTLS 1.3 must stay enabled under the default policy"
    );
    assert!(
        mapped.kx_groups().contains(&NamedGroup::X25519),
        "the default curve selection must reach the DTLS stack"
    );
}

#[test]
fn min_version_1_3_disables_dtls_1_2() {
    let mapped = map("1.3", "1.3", None);
    assert!(
        mapped.dtls12_cipher_suites().is_empty(),
        "FERRUM_TLS_MIN_VERSION=1.3 must leave no DTLS 1.2 suite"
    );
    assert!(
        !mapped.dtls13_cipher_suites().is_empty(),
        "DTLS 1.3 must remain usable"
    );
}

#[test]
fn max_version_1_2_disables_dtls_1_3() {
    let mapped = map("1.2", "1.2", None);
    assert!(
        mapped.dtls13_cipher_suites().is_empty(),
        "FERRUM_TLS_MAX_VERSION=1.2 must leave no DTLS 1.3 suite"
    );
    assert!(
        !mapped.dtls12_cipher_suites().is_empty(),
        "DTLS 1.2 must remain usable"
    );
}

#[test]
fn a_restricted_cipher_suite_list_maps_to_exactly_that_subset() {
    let mapped = map(
        "1.2",
        "1.3",
        Some("TLS_AES_128_GCM_SHA256,ECDHE-ECDSA-AES128-GCM-SHA256"),
    );
    assert_eq!(
        mapped.dtls12_cipher_suites().to_vec(),
        vec![Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256],
        "only the named DTLS 1.2 suite may be offered"
    );
    assert_eq!(
        mapped.dtls13_cipher_suites().to_vec(),
        vec![Dtls13CipherSuite::AES_128_GCM_SHA256],
        "only the named DTLS 1.3 suite may be offered"
    );
}

#[test]
fn an_rsa_only_tls12_selection_is_a_startup_error_not_a_silent_drop() {
    // `ECDHE-RSA-*` has no DTLS counterpart. Dropping it beside an ECDSA
    // sibling costs nothing, but a selection made ENTIRELY of RSA-auth TLS 1.2
    // suites would silently lose DTLS 1.2 altogether — so it is refused.
    let policy = policy(
        "1.2",
        "1.3",
        Some("TLS_AES_128_GCM_SHA256,ECDHE-RSA-AES128-GCM-SHA256"),
    );
    let error = DtlsSuitePolicy::from_tls_policy(&policy, "frontend DTLS listener")
        .expect_err("an RSA-only TLS 1.2 selection must be refused on a DTLS surface");
    let rendered = error.to_string();
    assert!(
        rendered.contains("ECDHE-RSA-AES128-GCM-SHA256"),
        "the refusal must name the suite: {rendered}"
    );
    assert!(
        rendered.contains("frontend DTLS listener"),
        "the refusal must name the DTLS surface: {rendered}"
    );
}

#[test]
fn an_rsa_suite_beside_its_ecdsa_sibling_is_admitted() {
    let mapped = map(
        "1.2",
        "1.2",
        Some("ECDHE-RSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES128-GCM-SHA256"),
    );
    assert_eq!(
        mapped.dtls12_cipher_suites().to_vec(),
        vec![Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256],
        "the ECDSA sibling carries the selection; the RSA name is inapplicable to DTLS"
    );
}

#[test]
fn a_tls13_only_suite_list_with_tls12_enabled_still_serves_dtls_13() {
    // Naming only TLS 1.3 suites leaves rustls with no TLS 1.2 suites either,
    // so DTLS mirrors it rather than refusing.
    let mapped = map("1.2", "1.3", Some("TLS_AES_256_GCM_SHA384"));
    assert!(mapped.dtls12_cipher_suites().is_empty());
    assert_eq!(
        mapped.dtls13_cipher_suites().to_vec(),
        vec![Dtls13CipherSuite::AES_256_GCM_SHA384]
    );
}

#[test]
fn a_policy_with_no_usable_dtls_suite_is_refused() {
    // TLS 1.3 only, but the only named suite is a TLS 1.2 one: nothing is left
    // for either DTLS version.
    let policy = policy("1.3", "1.3", Some("ECDHE-ECDSA-AES128-GCM-SHA256"));
    let error = DtlsSuitePolicy::from_tls_policy(&policy, "backend DTLS client for proxy 'p1'")
        .expect_err("a policy with no usable DTLS suite must be refused");
    assert!(
        error
            .to_string()
            .contains("backend DTLS client for proxy 'p1'"),
        "the refusal must name the DTLS surface: {error}"
    );
}

#[test]
fn the_built_frontend_config_reports_no_dtls_1_2_suites_under_min_version_1_3() {
    let identity = dtls_identity();
    let policy = policy("1.3", "1.3", None);
    let built = build_frontend_dtls_config(
        &identity.cert_path,
        &identity.key_path,
        None,
        &[],
        Some(&policy),
    )
    .expect("build frontend DTLS config under a 1.3-only policy");
    assert_eq!(
        built.dimpl_config.dtls12_cipher_suites().count(),
        0,
        "a 1.3-only policy must leave the listener with no negotiable DTLS 1.2 suite"
    );
    assert!(
        built.dimpl_config.dtls13_cipher_suites().count() > 0,
        "DTLS 1.3 must remain negotiable"
    );
}

#[test]
fn the_built_frontend_config_offers_only_the_selected_suites() {
    let identity = dtls_identity();
    let policy = policy(
        "1.2",
        "1.3",
        Some("TLS_AES_128_GCM_SHA256,ECDHE-ECDSA-AES128-GCM-SHA256"),
    );
    let built = build_frontend_dtls_config(
        &identity.cert_path,
        &identity.key_path,
        None,
        &[],
        Some(&policy),
    )
    .expect("build frontend DTLS config under a restricted suite policy");
    let dtls12: Vec<u16> = built
        .dimpl_config
        .dtls12_cipher_suites()
        .map(|cs| cs.suite().as_u16())
        .collect();
    assert_eq!(dtls12, vec![0xC02B], "only ECDHE-ECDSA-AES128-GCM-SHA256");
    let dtls13: Vec<u16> = built
        .dimpl_config
        .dtls13_cipher_suites()
        .map(|cs| cs.suite().as_u16())
        .collect();
    assert_eq!(dtls13, vec![0x1301], "only TLS_AES_128_GCM_SHA256");
}

#[test]
fn an_unpoliced_build_keeps_the_dtls_stack_defaults() {
    let identity = dtls_identity();
    let built =
        build_frontend_dtls_config(&identity.cert_path, &identity.key_path, None, &[], None)
            .expect("build frontend DTLS config without a policy");
    assert!(
        built.dimpl_config.dtls12_cipher_suites().count() > 0
            && built.dimpl_config.dtls13_cipher_suites().count() > 0,
        "no policy means the DTLS stack's own defaults, unchanged"
    );
}
