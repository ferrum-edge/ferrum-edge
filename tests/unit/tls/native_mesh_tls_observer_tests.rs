//! Trusted-verifier fixtures for native MeshSubscribe client TLS classification.
//!
//! These tests pin the observing WebPKI wrapper against the same exclusive-CA
//! verification Ferrum uses for MeshSubscribe: untrusted issuer vs wrong SAN,
//! flattened io/rustls chains, and the guarantee that generic handshake errors
//! are not relabeled.

use ferrum_edge::grpc::dp_client::DpGrpcTlsConfig;
use ferrum_edge::modes::mesh::config_consumer::native_tls::{
    NativeTlsClass, ObservingServerCertVerifier, annotate_connect_error, classify_native_tls_error,
    prepare_native_mesh_tls,
};
use rcgen::{
    BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
    string::Ia5String,
};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, Error as RustlsError};

const CP_DNS: &str = "ferrum-cp.ferrum.svc.cluster.local";
const WRONG_SAN_DNS: &str = "ferrum-cp-wrong-san.ferrum.svc.cluster.local";

struct GeneratedCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

struct GeneratedCert {
    cert_der: CertificateDer<'static>,
}

fn generate_ca(cn: &str) -> GeneratedCa {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    let cert = params.self_signed(&key_pair).expect("self-sign CA");
    GeneratedCa {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key_pair),
    }
}

fn generate_leaf(ca: &GeneratedCa, dns_san: &str) -> GeneratedCert {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dns_san);
    params.subject_alt_names.push(SanType::DnsName(
        Ia5String::try_from(dns_san.to_string()).expect("DNS SAN"),
    ));
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
    let cert_pem = cert.pem();
    let cert_der = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse leaf PEM")
        .into_iter()
        .next()
        .expect("leaf DER");
    GeneratedCert { cert_der }
}

fn verify(
    verifier: &ObservingServerCertVerifier,
    cert: &GeneratedCert,
    server_name: &str,
) -> Result<rustls::client::danger::ServerCertVerified, RustlsError> {
    verifier.verify_server_cert(
        &cert.cert_der,
        &[],
        &ServerName::try_from(server_name.to_string()).expect("server name"),
        &[],
        UnixTime::now(),
    )
}

#[test]
fn rustls_unknown_issuer_is_verify_and_expired_is_not() {
    assert_eq!(
        NativeTlsClass::from_rustls(&RustlsError::InvalidCertificate(
            CertificateError::UnknownIssuer
        )),
        Some(NativeTlsClass::Verify)
    );
    assert_eq!(
        NativeTlsClass::from_rustls(&RustlsError::InvalidCertificate(
            CertificateError::NotValidForName
        )),
        Some(NativeTlsClass::Name)
    );
    assert_eq!(
        NativeTlsClass::from_rustls(&RustlsError::InvalidCertificate(CertificateError::Expired)),
        None,
        "non-issuer, non-name certificate errors must not be relabeled"
    );
    assert_eq!(NativeTlsClass::Verify.as_str(), "client_tls_verify");
    assert_eq!(NativeTlsClass::Name.as_str(), "client_tls_name");
}

#[test]
fn flattened_io_error_preserves_unknown_issuer() {
    let rustls_err = RustlsError::InvalidCertificate(CertificateError::UnknownIssuer);
    let io_err = std::io::Error::new(std::io::ErrorKind::InvalidData, rustls_err);
    assert_eq!(
        classify_native_tls_error(&io_err),
        Some(NativeTlsClass::Verify)
    );
}

#[test]
fn flattened_io_error_preserves_not_valid_for_name() {
    let rustls_err = RustlsError::InvalidCertificate(CertificateError::NotValidForName);
    let io_err = std::io::Error::new(std::io::ErrorKind::InvalidData, rustls_err);
    assert_eq!(
        classify_native_tls_error(&io_err),
        Some(NativeTlsClass::Name)
    );
}

#[test]
fn generic_io_error_is_not_verify_or_name() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "connection closed");
    assert_eq!(classify_native_tls_error(&io_err), None);
}

#[test]
fn untrusted_server_ca_records_verify_and_still_returns_unknown_issuer() {
    let trusted = generate_ca("native-untrusted-ca-trust");
    let foreign = generate_ca("native-untrusted-ca-foreign");
    let leaf = generate_leaf(&foreign, CP_DNS);
    let verifier =
        ObservingServerCertVerifier::from_ca_pem(trusted.cert_pem.as_bytes()).expect("verifier");

    let err = verify(&verifier, &leaf, CP_DNS).expect_err("foreign CA must be rejected");
    assert_eq!(
        NativeTlsClass::from_rustls(&err),
        Some(NativeTlsClass::Verify),
        "rejection must be issuer verification, got {err:?}"
    );
    assert_eq!(verifier.observed(), Some(NativeTlsClass::Verify));
}

#[test]
fn wrong_san_records_name_while_signing_ca_is_trusted() {
    let ca = generate_ca("native-wrong-san-trust");
    let leaf = generate_leaf(&ca, CP_DNS);
    let verifier =
        ObservingServerCertVerifier::from_ca_pem(ca.cert_pem.as_bytes()).expect("verifier");

    let err = verify(&verifier, &leaf, WRONG_SAN_DNS).expect_err("wrong SAN must be rejected");
    assert_eq!(
        NativeTlsClass::from_rustls(&err),
        Some(NativeTlsClass::Name),
        "rejection must be name verification, got {err:?}"
    );
    assert_eq!(verifier.observed(), Some(NativeTlsClass::Name));
}

#[test]
fn trusted_matching_name_clears_observation() {
    let ca = generate_ca("native-matching-san-trust");
    let leaf = generate_leaf(&ca, CP_DNS);
    let verifier =
        ObservingServerCertVerifier::from_ca_pem(ca.cert_pem.as_bytes()).expect("verifier");

    verify(&verifier, &leaf, CP_DNS).expect("trusted matching SAN must verify");
    assert_eq!(verifier.observed(), None);
}

#[test]
fn debug_does_not_include_pem() {
    let ca = generate_ca("native-debug-ca");
    let verifier =
        ObservingServerCertVerifier::from_ca_pem(ca.cert_pem.as_bytes()).expect("verifier");
    let rendered = format!("{verifier:?}");
    assert!(
        !rendered.contains("BEGIN"),
        "observer Debug must not include PEM: {rendered}"
    );
    assert!(
        !ca.cert_pem.is_empty() && rendered.contains("ObservingServerCertVerifier"),
        "debug should name the type without material"
    );
}

#[test]
fn prepare_with_ca_installs_observer_and_without_ca_does_not() {
    let ca = generate_ca("native-prepare-ca");
    let with_ca = prepare_native_mesh_tls(
        &DpGrpcTlsConfig {
            ca_cert_pem: Some(ca.cert_pem.into_bytes()),
            client_cert_pem: None,
            client_key_pem: None,
        },
        Some(CP_DNS),
    )
    .expect("prepare with CA");
    assert!(with_ca.observer().is_some());

    let without_ca = prepare_native_mesh_tls(&DpGrpcTlsConfig::default(), Some(CP_DNS))
        .expect("prepare without CA");
    assert!(without_ca.observer().is_none());
}

#[test]
fn annotate_connect_error_uses_observer_over_generic_transport() {
    let ca = generate_ca("native-annotate-ca");
    let foreign = generate_ca("native-annotate-foreign");
    let leaf = generate_leaf(&foreign, CP_DNS);
    let verifier =
        ObservingServerCertVerifier::from_ca_pem(ca.cert_pem.as_bytes()).expect("verifier");
    verify(&verifier, &leaf, CP_DNS).expect_err("foreign CA must be rejected");

    let err = annotate_connect_error(
        anyhow::anyhow!("error trying to connect: connection closed"),
        Some(&verifier),
    );
    let rendered = format!("{err}");
    assert!(
        rendered.contains("error trying to connect"),
        "annotated error must keep the transport Display, got {rendered}"
    );
    assert!(
        !rendered.contains("BEGIN"),
        "annotated error must not include PEM"
    );
    assert_eq!(
        ferrum_edge::modes::mesh::config_consumer::native_tls::observed_class_from_error(&err),
        Some(NativeTlsClass::Verify)
    );
}
