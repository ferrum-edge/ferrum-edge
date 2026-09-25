//! Canonical SAN strings on TLS certificate summaries (issue #5543).
//!
//! Managed, ACME, and inventory admin responses share [`ferrum_edge::tls::san`].
//! These tests pin the exact strings those endpoints return for IPv4, IPv6,
//! DNS, URI, and email SANs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ferrum_edge::config::EnvConfig;
use ferrum_edge::tls::acme::{AcmeCertificateRecord, AcmeIssuedCertificateInput};
use ferrum_edge::tls::inventory::{TlsInventory, TlsInventoryState};
use ferrum_edge::tls::managed::ManagedTlsRecord;
use ferrum_edge::tls::san::{certificate_san_strings, format_general_name};
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

const SERVER_CRT: &str = include_str!("../../certs/server.crt");

const EXPECTED_SERVER_CRT_SANS: [&str; 3] = ["127.0.0.1", "host.docker.internal", "localhost"];

const MIXED_DNS: &str = "localhost";
const MIXED_IPV4: &str = "127.0.0.1";
const MIXED_IPV6: &str = "2001:db8::1";
const MIXED_URI: &str = "spiffe://example.test/ns/default/sa/api";
const MIXED_EMAIL: &str = "ops@example.test";

fn expected_mixed_sans() -> Vec<String> {
    let mut sans = vec![
        MIXED_DNS.to_string(),
        MIXED_IPV4.to_string(),
        MIXED_IPV6.to_string(),
        MIXED_URI.to_string(),
        MIXED_EMAIL.to_string(),
    ];
    sans.sort();
    sans
}

fn generate_mixed_san_cert() -> (String, String) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("cert params");
    params
        .distinguished_name
        .push(DnType::CommonName, "san-summary");
    params.subject_alt_names = vec![
        SanType::DnsName(Ia5String::try_from(MIXED_DNS.to_string()).expect("DNS SAN")),
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        SanType::IpAddress(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        SanType::URI(Ia5String::try_from(MIXED_URI.to_string()).expect("URI SAN")),
        SanType::Rfc822Name(Ia5String::try_from(MIXED_EMAIL.to_string()).expect("email SAN")),
    ];
    let cert = params.self_signed(&key_pair).expect("self-sign cert");
    (cert.pem(), key_pair.serialize_pem())
}

fn sans_from_pem(pem: &str) -> Vec<String> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse PEM");
    let der = certs.first().expect("leaf certificate");
    let (_, parsed) = X509Certificate::from_der(der.as_ref()).expect("parse DER");
    certificate_san_strings(&parsed)
}

fn inventory_sans(cert_pem: &str) -> Vec<String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("leaf.pem");
    std::fs::write(&cert_path, cert_pem).expect("write cert");
    let env = EnvConfig {
        frontend_tls_cert_path: Some(cert_path.to_string_lossy().into_owned()),
        ..EnvConfig::default()
    };
    let inventory = TlsInventory::collect_public_metadata(Some(&env), None);
    let cert = inventory
        .entries
        .iter()
        .find(|entry| entry.material_kind == "certificate")
        .expect("inventory certificate entry");
    assert_eq!(
        cert.state,
        TlsInventoryState::Loaded,
        "inventory must load the fixture: {:?}",
        cert.error
    );
    cert.sans.clone()
}

fn managed_ca_bundle_sans(cert_pem: &str) -> Vec<String> {
    ManagedTlsRecord::new_ca_bundle(
        "audit-ca".to_string(),
        "audit-ca".to_string(),
        None,
        cert_pem.to_string(),
    )
    .summary()
    .sans
}

fn acme_summary_sans(cert_pem: &str, key_pem: &str) -> Vec<String> {
    AcmeCertificateRecord::new_issued(AcmeIssuedCertificateInput {
        id: "edge-cert".to_string(),
        domains: vec!["localhost".to_string()],
        directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
        account_id: None,
        order_url: None,
        cert_pem: cert_pem.to_string(),
        key_pem: key_pem.to_string(),
        chain_pem: None,
    })
    .expect("acme record")
    .summary()
    .sans
}

#[test]
fn format_general_name_uses_plain_canonical_values() {
    assert_eq!(
        format_general_name(&GeneralName::DNSName("localhost")),
        "localhost"
    );
    assert_eq!(
        format_general_name(&GeneralName::RFC822Name(MIXED_EMAIL)),
        MIXED_EMAIL
    );
    assert_eq!(format_general_name(&GeneralName::URI(MIXED_URI)), MIXED_URI);

    let ipv4 = [127_u8, 0, 0, 1];
    assert_eq!(
        format_general_name(&GeneralName::IPAddress(&ipv4)),
        MIXED_IPV4
    );

    let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
    assert_eq!(
        format_general_name(&GeneralName::IPAddress(&ipv6)),
        MIXED_IPV6
    );

    let truncated = [1_u8, 2, 3];
    assert_eq!(
        format_general_name(&GeneralName::IPAddress(&truncated)),
        "invalid-ip:010203"
    );
}

#[test]
fn repository_server_crt_renders_ipv4_and_dns_sans_canonically() {
    let expected: Vec<String> = EXPECTED_SERVER_CRT_SANS
        .iter()
        .map(|san| (*san).to_string())
        .collect();
    assert_eq!(sans_from_pem(SERVER_CRT), expected);
    assert_eq!(managed_ca_bundle_sans(SERVER_CRT), expected);
    assert_eq!(inventory_sans(SERVER_CRT), expected);
}

#[test]
fn mixed_sans_match_across_managed_acme_and_inventory() {
    let (cert_pem, key_pem) = generate_mixed_san_cert();
    let expected = expected_mixed_sans();

    assert_eq!(sans_from_pem(&cert_pem), expected);
    assert_eq!(managed_ca_bundle_sans(&cert_pem), expected);
    assert_eq!(
        ManagedTlsRecord::new_certificate(
            "edge-cert".to_string(),
            "edge-cert".to_string(),
            None,
            cert_pem.clone(),
            key_pem.clone(),
            None,
        )
        .summary()
        .sans,
        expected
    );
    assert_eq!(acme_summary_sans(&cert_pem, &key_pem), expected);
    assert_eq!(inventory_sans(&cert_pem), expected);
}

#[test]
fn managed_acme_and_inventory_call_the_shared_san_helper() {
    const SITES: &[&str] = &[
        "src/tls/managed.rs",
        "src/tls/acme.rs",
        "src/tls/inventory.rs",
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in SITES {
        let text = std::fs::read_to_string(root.join(relative))
            .unwrap_or_else(|error| panic!("{relative} must be readable: {error}"));
        assert!(
            text.contains("certificate_san_strings("),
            "{relative} must render SANs through tls::san::certificate_san_strings"
        );
        assert!(
            !text.contains("{bytes:?}"),
            "{relative} must not debug-format IP SAN bytes"
        );
    }
}
