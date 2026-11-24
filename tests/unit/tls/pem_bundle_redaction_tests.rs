//! PEM bundle parse and trust-root admission diagnostics must not echo malformed
//! PEM lines, DER bytes, or rustls library error text.

use ferrum_edge::config::types::validate_pem_key_file;
use ferrum_edge::tls::source::{CertSource, MaterialKind};
use ferrum_edge::tls::{build_client_cert_verifier, check_cert_expiry, load_crls};
use rcgen::{CertificateParams, KeyPair};
use tempfile::TempDir;

const PEM_MARKER: &str = "SECRET_MARKER_DO_NOT_LEAK_12345";

fn assert_rendered_material_error(error: anyhow::Error, expected: &[&str], withheld: &[&str]) {
    let rendered = ferrum_edge::startup::render_startup_error(error, &[]);
    for &text in expected {
        assert!(rendered.contains(text), "missing {text:?}: {rendered}");
    }
    for &text in withheld {
        assert!(!rendered.contains(text), "leaked {text:?}: {rendered}");
    }
}

fn write_pem(dir: &TempDir, name: &str, data: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, data).unwrap();
    path.to_str().unwrap().to_string()
}

fn generate_self_signed_cert(sans: &[&str]) -> String {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let params = CertificateParams::new(san_strings).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    cert.pem()
}

#[test]
fn malformed_pem_record_error_withholds_marker_bearing_input() {
    let dir = TempDir::new().unwrap();
    let valid_pem = generate_self_signed_cert(&["localhost"]);
    let bundle = format!(
        "{valid_pem}-----BEGIN CERTIFICATE-----\n{PEM_MARKER}\n-----END CERTIFICATE-----\n"
    );
    let path = write_pem(&dir, "malformed-later.pem", &bundle);

    let error = check_cert_expiry(&path, "expiry bundle", 30)
        .expect_err("malformed later record must reject the bundle")
        .to_string();

    assert!(
        !error.contains(PEM_MARKER),
        "malformed PEM input must not echo in diagnostics: {error}"
    );
    assert!(error.contains("expiry bundle"), "got: {error}");
    assert!(error.contains("record #2"), "got: {error}");
    assert!(error.contains("malformed-later.pem"), "got: {error}");
    assert!(
        error.contains("malformed PEM certificate record"),
        "got: {error}"
    );
}

#[test]
fn malformed_pem_section_start_error_withholds_marker_bearing_line() {
    let dir = TempDir::new().unwrap();
    let valid_pem = generate_self_signed_cert(&["localhost"]);
    let bundle = format!("{valid_pem}-----BEGIN {PEM_MARKER}-----\n");
    let path = write_pem(&dir, "illegal-section.pem", &bundle);

    let error = check_cert_expiry(&path, "expiry bundle", 30)
        .expect_err("illegal section start must reject the bundle")
        .to_string();

    assert!(
        !error.contains(PEM_MARKER),
        "malformed PEM line must not echo in diagnostics: {error}"
    );
    assert!(error.contains("expiry bundle"), "got: {error}");
    assert!(error.contains("record #2"), "got: {error}");
    assert!(error.contains("illegal-section.pem"), "got: {error}");
    assert!(
        error.contains("malformed PEM certificate record"),
        "got: {error}"
    );
}

#[test]
fn malformed_private_key_error_withholds_marker_bearing_input() {
    let dir = TempDir::new().unwrap();
    let key = format!("-----BEGIN PRIVATE KEY-----\n{PEM_MARKER}\n-----END PRIVATE KEY-----\n");
    let path = write_pem(&dir, "malformed-key.pem", &key);

    let error = validate_pem_key_file("backend TLS client key", &path)
        .expect_err("malformed private key must fail admission");

    assert!(
        !error.contains(PEM_MARKER),
        "malformed key input must not echo in diagnostics: {error}"
    );
    assert!(error.contains("private key"), "got: {error}");
    assert!(error.contains("malformed-key.pem"), "got: {error}");
    assert!(error.contains("malformed"), "got: {error}");
}

#[test]
fn file_uri_credentials_are_rejected_without_echoing_them() {
    let source = format!("file://operator:{PEM_MARKER}@localhost/key.pem");
    let debug = format!("{:?}", CertSource::parse(&source, MaterialKind::Key));
    let error = validate_pem_key_file("backend TLS client key", &source)
        .expect_err("credential-bearing file URI must be rejected");

    assert!(!debug.contains(PEM_MARKER), "debug output leaked: {debug}");
    assert!(
        !error.contains(PEM_MARKER),
        "file URI credential must not echo in diagnostics: {error}"
    );
    assert!(error.contains("file URI credentials are not permitted"));
    assert!(error.contains("<redacted source reference>"));
}

#[test]
fn unusable_trust_root_error_withholds_rejected_certificate_material() {
    const UNUSABLE_CERT_BASE64: &str = "AQIDBA==";

    let dir = TempDir::new().unwrap();
    let bundle =
        format!("-----BEGIN CERTIFICATE-----\n{UNUSABLE_CERT_BASE64}\n-----END CERTIFICATE-----\n");
    let path = write_pem(&dir, "unusable-root.pem", &bundle);

    let error = build_client_cert_verifier(&path, &[])
        .expect_err("unusable PEM certificate must not be admitted as a trust root")
        .to_string();

    assert!(
        !error.contains(UNUSABLE_CERT_BASE64),
        "rejected certificate material must not echo in diagnostics: {error}"
    );
    assert!(error.contains("client CA bundle"), "got: {error}");
    assert!(error.contains("record #1"), "got: {error}");
    assert!(error.contains("unusable-root.pem"), "got: {error}");
    assert!(
        error.contains("certificate failed trust-anchor admission"),
        "got: {error}"
    );
}

#[test]
fn rendered_material_errors_keep_schema_index_and_reason_without_source_or_content() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let dir = TempDir::new().unwrap();
    let valid_pem = generate_self_signed_cert(&["localhost"]);
    let bundle = format!(
        "{valid_pem}-----BEGIN CERTIFICATE-----\n'{PEM_MARKER}\n-----END CERTIFICATE-----\n"
    );
    let path = write_pem(&dir, "'TLS_FILENAME_MARKER.pem", &bundle);
    for source in [&path, &bundle] {
        let error = check_cert_expiry(source, "backend_tls_client_cert_path", 0).unwrap_err();
        assert_rendered_material_error(
            error,
            &[
                "`backend_tls_client_cert_path`",
                "record #2",
                "malformed PEM certificate record",
            ],
            &["TLS_FILENAME_MARKER", PEM_MARKER, &path, &valid_pem],
        );
    }

    let key = format!("-----BEGIN PRIVATE KEY-----\n'{PEM_MARKER}\n-----END PRIVATE KEY-----\n");
    let path = write_pem(&dir, "'TLS_KEY_FILENAME_MARKER.pem", &key);
    let error = validate_pem_key_file("backend_tls_client_key_path", &path).unwrap_err();
    assert_rendered_material_error(
        anyhow::anyhow!(error),
        &[
            "`backend_tls_client_key_path`",
            "private key",
            "is malformed",
        ],
        &["TLS_KEY_FILENAME_MARKER", PEM_MARKER, &path],
    );

    let path = write_pem(
        &dir,
        "'TLS_ROOT_FILENAME_MARKER.pem",
        "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n",
    );
    let error = build_client_cert_verifier(&path, &[]).unwrap_err();
    assert_rendered_material_error(
        error,
        &[
            "`client CA bundle`",
            "record #1",
            "certificate failed trust-anchor admission",
        ],
        &["TLS_ROOT_FILENAME_MARKER", "AQIDBA==", &path],
    );
}

#[test]
fn rendered_expiry_error_withholds_caller_composed_label_and_source() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let dir = TempDir::new().unwrap();
    let path = write_pem(
        &dir,
        "'TLS_CONTEXT_FILENAME_MARKER.pem",
        "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n",
    );
    let label = "provider['TLS_LABEL_KEY_MARKER'].cert_pem: '\"\\\n927451 true";
    let error = check_cert_expiry(&path, label, 0).unwrap_err();
    assert_rendered_material_error(
        error,
        &["record #1", "failed X.509 validation"],
        &[
            "TLS_CONTEXT_FILENAME_MARKER",
            "TLS_LABEL_KEY_MARKER",
            "927451",
            "true",
            &path,
        ],
    );
}

#[test]
fn material_load_errors_discard_source_and_provider_chains() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("'TLS_MISSING_SOURCE_MARKER.pem");
    let missing = missing.to_str().unwrap();
    let error = check_cert_expiry(missing, "backend_tls_client_cert_path", 0).unwrap_err();
    assert_eq!(
        error.chain().count(),
        1,
        "raw I/O causes must not be retained"
    );
    assert_rendered_material_error(
        error,
        &[
            "`backend_tls_client_cert_path`",
            "failed to read TLS material",
            "io",
        ],
        &["TLS_MISSING_SOURCE_MARKER", missing],
    );

    let source = "file://operator:TLS_PROVIDER_MARKER@localhost/key.pem";
    let error = check_cert_expiry(source, "backend_tls_client_cert_path", 0).unwrap_err();
    assert_eq!(
        error.chain().count(),
        1,
        "raw provider causes must not be retained"
    );
    assert_rendered_material_error(
        error,
        &["`backend_tls_client_cert_path`", "invalid_source"],
        &["TLS_PROVIDER_MARKER", source],
    );
}

/// The multi-certificate Gateway loader labels unreadable material like the
/// single-certificate loader and keeps only the failure class, never the raw
/// I/O text or the source path (issue #7229).
#[test]
fn gateway_multi_cert_material_load_errors_keep_label_and_class_only() {
    use ferrum_edge::config::EnvConfig;
    use ferrum_edge::tls::TlsPolicy;
    use ferrum_edge::tls::multi_cert::{
        GatewayCertificateInput, load_gateway_multi_cert_tls_config,
    };

    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let dir = TempDir::new().unwrap();
    let policy = TlsPolicy::from_env_config(&EnvConfig::default()).unwrap();
    let cert = write_pem(
        &dir,
        "gateway.pem",
        &generate_self_signed_cert(&["localhost"]),
    );
    let missing = dir.path().join("'TLS_MISSING_SOURCE_MARKER.pem");
    let missing = missing.to_str().unwrap().to_string();

    for (cert_source, key_source, label) in [
        (&missing, &missing, "`Gateway server TLS cert`"),
        (&cert, &missing, "`Gateway server TLS private key`"),
    ] {
        let inputs = vec![GatewayCertificateInput {
            cert_source: cert_source.clone(),
            key_source: key_source.clone(),
            hostname: Some("localhost".to_string()),
            identity: "ns/gw/listener".to_string(),
            is_default: true,
        }];
        let error = load_gateway_multi_cert_tls_config(&inputs, None, None, &policy, 0, 0, &[])
            .expect_err("unreadable Gateway material must fail closed");
        assert_eq!(
            error.chain().count(),
            1,
            "raw I/O causes must not be retained"
        );
        assert_rendered_material_error(
            error,
            &[label, "failed to read TLS material", "io"],
            &["TLS_MISSING_SOURCE_MARKER", &missing],
        );
    }
}

#[test]
fn rendered_crl_parse_error_omits_malformed_pem_and_hostile_filename() {
    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let dir = TempDir::new().unwrap();
    let crl = format!("-----BEGIN X509 CRL-----\n'{PEM_MARKER}\n-----END X509 CRL-----\n");
    let path = write_pem(&dir, "'TLS_CRL_FILENAME_MARKER.pem", &crl);
    for source in [&path, &crl] {
        let error = load_crls(Some(source), 0).unwrap_err();
        assert_rendered_material_error(
            error,
            &["`FERRUM_TLS_CRL_FILE_PATH`", "malformed PEM CRL record"],
            &["TLS_CRL_FILENAME_MARKER", PEM_MARKER, &path],
        );
    }
}

#[test]
fn backend_constructor_errors_keep_material_context_without_paths_or_payloads() {
    use ferrum_edge::config::EnvConfig;
    use ferrum_edge::tls::TlsPolicy;
    use ferrum_edge::tls::backend::BackendTlsConfigBuilder;
    use std::path::Path;

    let _env = crate::unit::env_lock::EnvGuard::new(&[]);
    let policy = TlsPolicy::from_env_config(&EnvConfig::default()).unwrap();
    let proxy = serde_json::from_value(serde_json::json!({
        "id": "diagnostic-backend",
        "name": "diagnostic-backend",
        "listen_path": "/",
        "backend_scheme": "https",
        "backend_host": "localhost",
        "backend_port": 443,
    }))
    .unwrap();
    let build = |cert, key| {
        BackendTlsConfigBuilder {
            proxy: &proxy,
            policy: Some(&policy),
            global_ca: None,
            global_no_verify: false,
            global_client_cert: cert,
            global_client_key: key,
            crls: &[],
        }
        .build_rustls()
        .unwrap_err()
    };
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("'TLS_BACKEND_MISSING_MARKER.pem");
    assert_rendered_material_error(
        build(Some(&missing), Some(&missing)).into(),
        &["`backend TLS client certificate`", "Failed to read"],
        &["TLS_BACKEND_MISSING_MARKER"],
    );
    assert_rendered_material_error(
        build(Some(&missing), None).into(),
        &[
            "`backend TLS client certificate`",
            "the private key is missing",
        ],
        &["TLS_BACKEND_MISSING_MARKER"],
    );
    assert_rendered_material_error(
        build(None, Some(&missing)).into(),
        &[
            "`backend TLS client private key`",
            "the certificate is missing",
        ],
        &["TLS_BACKEND_MISSING_MARKER"],
    );

    let valid_pem = generate_self_signed_cert(&["localhost"]);
    let malformed_bundle = format!(
        "{valid_pem}-----BEGIN CERTIFICATE-----\n'{PEM_MARKER}\n-----END CERTIFICATE-----\n"
    );
    let malformed = write_pem(&dir, "'TLS_BACKEND_CERT_MARKER.pem", &malformed_bundle);
    assert_rendered_material_error(
        build(Some(Path::new(&malformed)), Some(&missing)).into(),
        &[
            "`backend TLS client certificate`",
            "record #2",
            "malformed PEM certificate record",
        ],
        &["TLS_BACKEND_CERT_MARKER", PEM_MARKER, &malformed],
    );
    let cert = write_pem(&dir, "'TLS_BACKEND_VALID_CERT_MARKER.pem", &valid_pem);
    let malformed_key =
        format!("-----BEGIN PRIVATE KEY-----\n'{PEM_MARKER}\n-----END PRIVATE KEY-----\n");
    let key = write_pem(&dir, "'TLS_BACKEND_KEY_MARKER.pem", &malformed_key);
    assert_rendered_material_error(
        build(Some(Path::new(&cert)), Some(Path::new(&key))).into(),
        &[
            "`backend TLS client private key`",
            "private key",
            "is malformed",
        ],
        &["TLS_BACKEND_KEY_MARKER", PEM_MARKER, &key],
    );
}
