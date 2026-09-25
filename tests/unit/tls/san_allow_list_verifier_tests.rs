use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use ferrum_edge::tls::backend::{SanAllowListVerifier, build_root_cert_store};
use ferrum_edge::tls::build_server_verifier_with_crls;
use rcgen::{
    BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
    string::Ia5String,
};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tempfile::TempDir;

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

fn generate_leaf(
    ca: &GeneratedCa,
    cn: &str,
    dns_sans: &[&str],
    uri_sans: &[&str],
    ip_sans: &[IpAddr],
) -> GeneratedCert {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    for dns in dns_sans {
        params.subject_alt_names.push(SanType::DnsName(
            Ia5String::try_from((*dns).to_string()).expect("DNS SAN"),
        ));
    }
    for uri in uri_sans {
        params.subject_alt_names.push(SanType::URI(
            Ia5String::try_from((*uri).to_string()).expect("URI SAN"),
        ));
    }
    for ip in ip_sans {
        params.subject_alt_names.push(SanType::IpAddress(*ip));
    }
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

fn write_ca(dir: &TempDir, ca: &GeneratedCa) -> PathBuf {
    let path = dir.path().join("ca.pem");
    std::fs::write(&path, &ca.cert_pem).expect("write CA");
    path
}

fn verifier_for_ca(ca: &GeneratedCa, allowed_sans: &[&str]) -> SanAllowListVerifier {
    let temp_dir = TempDir::new().expect("temp dir");
    let ca_path = write_ca(&temp_dir, ca);
    let root_store = build_root_cert_store(Some(&ca_path), None).expect("root store");
    let inner = build_server_verifier_with_crls(root_store, &[]).expect("inner verifier");
    SanAllowListVerifier::new(
        inner,
        allowed_sans.iter().map(|san| (*san).to_string()).collect(),
    )
    .expect("SAN allow-list verifier")
}

fn verify(
    verifier: &SanAllowListVerifier,
    cert: &GeneratedCert,
    server_name: &str,
) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
    verifier.verify_server_cert(
        &cert.cert_der,
        &[],
        &ServerName::try_from(server_name.to_string()).expect("server name"),
        &[],
        UnixTime::now(),
    )
}

#[test]
fn dns_san_match_is_accepted() {
    let ca = generate_ca("dns-match-ca");
    let leaf = generate_leaf(&ca, "backend.test", &["backend.test"], &[], &[]);
    let verifier = verifier_for_ca(&ca, &["backend.test"]);

    verify(&verifier, &leaf, "backend.test").expect("DNS SAN should match");
}

#[test]
fn dns_san_match_is_case_insensitive() {
    let ca = generate_ca("dns-case-ca");
    let leaf = generate_leaf(&ca, "Backend.Test", &["Backend.Test"], &[], &[]);
    let verifier = verifier_for_ca(&ca, &["backend.test"]);

    verify(&verifier, &leaf, "backend.test").expect("DNS SAN case should not matter");
}

#[test]
fn dns_san_mismatch_is_rejected() {
    let ca = generate_ca("dns-mismatch-ca");
    let leaf = generate_leaf(&ca, "backend.test", &["backend.test"], &[], &[]);
    let verifier = verifier_for_ca(&ca, &["other.test"]);

    let err = verify(&verifier, &leaf, "backend.test").expect_err("SAN mismatch should reject");
    assert!(
        format!("{err:?}").contains("SAN allow-list"),
        "expected SAN allow-list rejection, got {err:?}"
    );
}

#[test]
fn multiple_sans_accept_any_match() {
    let ca = generate_ca("multi-san-ca");
    let leaf = generate_leaf(
        &ca,
        "backend.test",
        &["backend.test", "alternate.test"],
        &[],
        &[],
    );
    let verifier = verifier_for_ca(&ca, &["alternate.test"]);

    verify(&verifier, &leaf, "backend.test").expect("any matching SAN should pass");
}

#[test]
fn uri_spiffe_san_match_is_accepted() {
    let ca = generate_ca("spiffe-ca");
    let spiffe = "spiffe://cluster.local/ns/default/sa/backend";
    let leaf = generate_leaf(&ca, "backend.test", &["backend.test"], &[spiffe], &[]);
    let verifier = verifier_for_ca(&ca, &[spiffe]);

    verify(&verifier, &leaf, "backend.test").expect("SPIFFE URI SAN should match");
}

#[test]
fn spiffe_uri_trust_domain_match_is_case_insensitive() {
    let ca = generate_ca("spiffe-case-ca");
    let cert_spiffe = "SPIFFE://Cluster.Local/ns/default/sa/backend";
    let allow_spiffe = "spiffe://cluster.local/ns/default/sa/backend";
    let leaf = generate_leaf(&ca, "backend.test", &["backend.test"], &[cert_spiffe], &[]);
    let verifier = verifier_for_ca(&ca, &[allow_spiffe]);

    verify(&verifier, &leaf, "backend.test").expect("SPIFFE trust domain case should not matter");
}

#[test]
fn ip_san_match_is_accepted() {
    let ca = generate_ca("ip-ca");
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let leaf = generate_leaf(&ca, "localhost", &["localhost"], &[], &[ip]);
    let verifier = verifier_for_ca(&ca, &["127.0.0.1"]);

    verify(&verifier, &leaf, "localhost").expect("IP SAN should match");
}

#[test]
fn ipv6_san_match_is_accepted() {
    let ca = generate_ca("ipv6-ca");
    let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let leaf = generate_leaf(&ca, "localhost", &["localhost"], &[], &[ip]);
    let verifier = verifier_for_ca(&ca, &["::1"]);

    verify(&verifier, &leaf, "localhost").expect("IPv6 SAN should match");
}

#[test]
fn ip_allow_list_does_not_match_dns_san_text() {
    let ca = generate_ca("cross-type-ca");
    let leaf = generate_leaf(
        &ca,
        "backend.test",
        &["backend.test", "127.0.0.1"],
        &[],
        &[],
    );
    let verifier = verifier_for_ca(&ca, &["127.0.0.1"]);

    let err = verify(&verifier, &leaf, "backend.test")
        .expect_err("IP allow-list entry should not match a DNS SAN string");
    assert!(
        format!("{err:?}").contains("SAN allow-list"),
        "expected SAN allow-list rejection, got {err:?}"
    );
}

#[test]
fn mixed_allow_list_accepts_any_matching_type() {
    let ca = generate_ca("mixed-ca");
    let leaf = generate_leaf(&ca, "backend.test", &["backend.test"], &[], &[]);
    let verifier = verifier_for_ca(
        &ca,
        &[
            "spiffe://cluster.local/ns/default/sa/other",
            "127.0.0.1",
            "backend.test",
        ],
    );

    verify(&verifier, &leaf, "backend.test").expect("matching DNS entry should pass");
}

#[test]
fn invalid_allow_list_entries_are_rejected() {
    let ca = generate_ca("invalid-allow-list-ca");
    let temp_dir = TempDir::new().expect("temp dir");
    let ca_path = write_ca(&temp_dir, &ca);
    let root_store = build_root_cert_store(Some(&ca_path), None).expect("root store");
    let inner = build_server_verifier_with_crls(root_store, &[]).expect("inner verifier");

    for invalid in [
        "*.example.com",
        "spiffe://cluster.local",
        "https://example.com/id",
    ] {
        let err = SanAllowListVerifier::new(inner.clone(), vec![invalid.to_string()])
            .expect_err("invalid SAN allow-list entry should be rejected");
        assert!(
            format!("{err:?}").contains("SAN allow-list"),
            "expected SAN allow-list parse error for {invalid}, got {err:?}"
        );
    }
}

#[test]
fn chain_failure_is_rejected_before_san_check() {
    let trusted_ca = generate_ca("trusted-ca");
    let untrusted_ca = generate_ca("untrusted-ca");
    let leaf = generate_leaf(&untrusted_ca, "backend.test", &["backend.test"], &[], &[]);
    let verifier = verifier_for_ca(&trusted_ca, &["backend.test"]);

    let err = verify(&verifier, &leaf, "backend.test").expect_err("untrusted chain should reject");
    assert!(
        !format!("{err:?}").contains("SAN allow-list"),
        "chain failure should come from webpki before SAN allow-list enforcement: {err:?}"
    );
}
