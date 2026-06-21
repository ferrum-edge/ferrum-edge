use ferrum_edge::identity::file_loader::load_svid_bundle_from_files;
use ferrum_edge::identity::spiffe::{SpiffeId, spiffe_id_to_san};
use rcgen::SanType;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use tempfile::TempDir;

struct TestSvidFiles {
    _dir: TempDir,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    trust_bundle_path: std::path::PathBuf,
}

struct TestCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn test_ca() -> TestCa {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.distinguished_name = DistinguishedName::new();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    let cert = params.self_signed(&key).expect("ca cert");
    TestCa {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key),
    }
}

fn issue_intermediate_ca(
    ca: &TestCa,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> TestCa {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("intermediate key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("intermediate params");
    params.distinguished_name = DistinguishedName::new();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params
        .signed_by(&key, &ca.issuer)
        .expect("intermediate cert");
    TestCa {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key),
    }
}

fn issue_svid(
    ca: &TestCa,
    spiffe_id: Option<&str>,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> (String, String) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    if let Some(id) = spiffe_id {
        let id = SpiffeId::new(id).expect("test SPIFFE ID");
        params
            .subject_alt_names
            .push(spiffe_id_to_san(&id).expect("spiffe SAN"));
    }
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params.signed_by(&key, &ca.issuer).expect("leaf cert");
    (cert.pem(), key.serialize_pem())
}

fn issue_ca_cert_for_leaf_slot(ca: &TestCa) -> (String, String) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    let cert = params.signed_by(&key, &ca.issuer).expect("ca leaf cert");
    (cert.pem(), key.serialize_pem())
}

fn issue_svid_with_raw_uri_san(
    ca: &TestCa,
    uri: &str,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> (String, String) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.subject_alt_names.push(SanType::URI(
        Ia5String::try_from(uri.to_string()).expect("test URI is IA5"),
    ));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params.signed_by(&key, &ca.issuer).expect("leaf cert");
    (cert.pem(), key.serialize_pem())
}

fn write_svid_files(cert_pem: &str, key_pem: &str, trust_bundle_pem: &str) -> TestSvidFiles {
    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("svid-chain.pem");
    let key_path = dir.path().join("svid-key.pem");
    let trust_bundle_path = dir.path().join("trust-bundle.pem");
    std::fs::write(&cert_path, cert_pem).expect("write cert");
    std::fs::write(&key_path, key_pem).expect("write key");
    std::fs::write(&trust_bundle_path, trust_bundle_pem).expect("write trust bundle");
    TestSvidFiles {
        _dir: dir,
        cert_path,
        key_path,
        trust_bundle_path,
    }
}

#[test]
fn loads_svid_bundle_from_files() {
    let ca = test_ca();
    let now = time::OffsetDateTime::now_utc();
    let (cert_pem, key_pem) = issue_svid(
        &ca,
        Some("spiffe://corp.example/ns/gateway/sa/edge"),
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    );
    let files = write_svid_files(&cert_pem, &key_pem, &ca.cert_pem);

    let bundle = load_svid_bundle_from_files(
        &files.cert_path,
        &files.key_path,
        &files.trust_bundle_path,
        None,
    )
    .expect("bundle loads");

    assert_eq!(
        bundle.spiffe_id.as_str(),
        "spiffe://corp.example/ns/gateway/sa/edge"
    );
    assert_eq!(bundle.cert_chain_der.len(), 1);
    assert!(!bundle.private_key_pkcs8_der.is_empty());
    let debug = format!("{bundle:?}");
    assert!(debug.contains("private_key_pkcs8_der: <redacted>"));
    assert_eq!(
        bundle.trust_bundles.local.trust_domain.as_str(),
        "corp.example"
    );
    assert_eq!(bundle.trust_bundles.local.x509_authorities.len(), 1);
}

#[test]
fn uses_explicit_spiffe_id_when_leaf_has_no_uri_san() {
    let ca = test_ca();
    let now = time::OffsetDateTime::now_utc();
    let (cert_pem, key_pem) = issue_svid(
        &ca,
        None,
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    );
    let files = write_svid_files(&cert_pem, &key_pem, &ca.cert_pem);

    let bundle = load_svid_bundle_from_files(
        &files.cert_path,
        &files.key_path,
        &files.trust_bundle_path,
        Some("spiffe://corp.example/ns/gateway/sa/fallback"),
    )
    .expect("explicit id fallback works");

    assert_eq!(
        bundle.spiffe_id.as_str(),
        "spiffe://corp.example/ns/gateway/sa/fallback"
    );
}

#[test]
fn rejects_invalid_leaf_spiffe_san_even_with_explicit_fallback() {
    let ca = test_ca();
    let now = time::OffsetDateTime::now_utc();
    let (cert_pem, key_pem) = issue_svid_with_raw_uri_san(
        &ca,
        "spiffe://",
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    );
    let files = write_svid_files(&cert_pem, &key_pem, &ca.cert_pem);

    let err = load_svid_bundle_from_files(
        &files.cert_path,
        &files.key_path,
        &files.trust_bundle_path,
        Some("spiffe://corp.example/ns/gateway/sa/fallback"),
    )
    .expect_err("malformed in-cert SPIFFE ID is rejected")
    .to_string();

    assert!(err.contains("SPIFFE URI SAN is invalid"));
    assert!(err.contains("spiffe://"));
}

#[test]
fn rejects_ca_certificate_in_leaf_slot() {
    let ca = test_ca();
    let (cert_pem, key_pem) = issue_ca_cert_for_leaf_slot(&ca);
    let files = write_svid_files(&cert_pem, &key_pem, &ca.cert_pem);

    let err = load_svid_bundle_from_files(
        &files.cert_path,
        &files.key_path,
        &files.trust_bundle_path,
        Some("spiffe://corp.example/ns/gateway/sa/fallback"),
    )
    .expect_err("CA certificate in the leaf slot is rejected")
    .to_string();

    assert!(err.contains("must not be a CA certificate"));
}

#[test]
fn rejects_missing_file_with_clear_error() {
    let ca = test_ca();
    let now = time::OffsetDateTime::now_utc();
    let (cert_pem, key_pem) = issue_svid(
        &ca,
        Some("spiffe://corp.example/ns/gateway/sa/edge"),
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    );
    let files = write_svid_files(&cert_pem, &key_pem, &ca.cert_pem);
    let missing = files.cert_path.with_file_name("missing.pem");

    let err =
        load_svid_bundle_from_files(&missing, &files.key_path, &files.trust_bundle_path, None)
            .expect_err("missing cert file rejected")
            .to_string();

    assert!(err.contains("failed to read"));
    assert!(err.contains("missing.pem"));
}

#[test]
fn rejects_mismatched_leaf_key() {
    let ca = test_ca();
    let now = time::OffsetDateTime::now_utc();
    let (cert_pem, _key_pem) = issue_svid(
        &ca,
        Some("spiffe://corp.example/ns/gateway/sa/edge"),
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    );
    let (_other_cert_pem, other_key_pem) = issue_svid(
        &ca,
        Some("spiffe://corp.example/ns/gateway/sa/other"),
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    );
    let files = write_svid_files(&cert_pem, &other_key_pem, &ca.cert_pem);

    let err = load_svid_bundle_from_files(
        &files.cert_path,
        &files.key_path,
        &files.trust_bundle_path,
        None,
    )
    .expect_err("cert/key mismatch rejected")
    .to_string();

    assert!(err.contains("does not match"));
}

#[test]
fn rejects_expired_leaf_certificate() {
    let ca = test_ca();
    let now = time::OffsetDateTime::now_utc();
    let (cert_pem, key_pem) = issue_svid(
        &ca,
        Some("spiffe://corp.example/ns/gateway/sa/edge"),
        now - time::Duration::days(3),
        now - time::Duration::days(1),
    );
    let files = write_svid_files(&cert_pem, &key_pem, &ca.cert_pem);

    let err = load_svid_bundle_from_files(
        &files.cert_path,
        &files.key_path,
        &files.trust_bundle_path,
        None,
    )
    .expect_err("expired cert rejected")
    .to_string();

    assert!(err.contains("has expired"));
}

#[test]
fn rejects_expired_intermediate_certificate() {
    let root = test_ca();
    let now = time::OffsetDateTime::now_utc();
    let intermediate = issue_intermediate_ca(
        &root,
        now - time::Duration::days(3),
        now - time::Duration::days(1),
    );
    let (cert_pem, key_pem) = issue_svid(
        &intermediate,
        Some("spiffe://corp.example/ns/gateway/sa/edge"),
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
    );
    let cert_chain_pem = format!("{cert_pem}{}", intermediate.cert_pem);
    let files = write_svid_files(&cert_chain_pem, &key_pem, &root.cert_pem);

    let err = load_svid_bundle_from_files(
        &files.cert_path,
        &files.key_path,
        &files.trust_bundle_path,
        None,
    )
    .expect_err("expired intermediate cert rejected")
    .to_string();

    assert!(err.contains("gateway SVID intermediate certificate #1"));
    assert!(err.contains("has expired"));
}
