//! Live TLS coverage for Gateway multi-certificate SNI selection (#3267/#3268).
//!
//! These drive real rustls handshakes over a real socket against the same
//! `ServerConfig` the data plane installs, and assert on the leaf certificate
//! the server actually presented. Translation-side decisions (which
//! certificates exist, who wins a hostname collision) are covered by
//! `tests/unit/config/gateway_api_frontend_tls_tests.rs`.

use ferrum_edge::config::EnvConfig;
use ferrum_edge::tls::TlsPolicy;
use ferrum_edge::tls::multi_cert::{
    GatewayCertificateInput, MAX_SNI_INDEX_ENTRIES, load_gateway_multi_cert_tls_config,
};
use rustls::pki_types::ServerName;
use std::sync::{Arc, Once};
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

static INIT_CRYPTO: Once = Once::new();

fn ensure_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A self-signed leaf written to disk, plus its DER so a handshake result can
/// be compared against the exact certificate that was installed.
struct TestCertificate {
    cert_path: String,
    key_path: String,
    der: Vec<u8>,
}

fn write_certificate(dir: &TempDir, name: &str, sans: &[&str]) -> TestCertificate {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key pair");
    let mut params =
        rcgen::CertificateParams::new(sans.iter().map(|san| san.to_string()).collect::<Vec<_>>())
            .expect("certificate params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let certificate = params.self_signed(&key_pair).expect("self-signed cert");

    let cert_path = dir.path().join(format!("{name}.crt"));
    let key_path = dir.path().join(format!("{name}.key"));
    std::fs::write(&cert_path, certificate.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");

    TestCertificate {
        cert_path: cert_path.to_string_lossy().into_owned(),
        key_path: key_path.to_string_lossy().into_owned(),
        der: certificate.der().to_vec(),
    }
}

fn input(
    certificate: &TestCertificate,
    identity: &str,
    hostname: Option<&str>,
    is_default: bool,
) -> GatewayCertificateInput {
    GatewayCertificateInput {
        cert_source: certificate.cert_path.clone(),
        key_source: certificate.key_path.clone(),
        hostname: hostname.map(str::to_string),
        identity: identity.to_string(),
        is_default,
    }
}

fn tls_policy() -> TlsPolicy {
    TlsPolicy::from_env_config(&EnvConfig::default()).expect("default TLS policy")
}

fn server_config(certificates: &[GatewayCertificateInput]) -> Arc<rustls::ServerConfig> {
    load_gateway_multi_cert_tls_config(certificates, None, None, &tls_policy(), 30, &[])
        .expect("multi-certificate server config")
}

/// Complete one real handshake with the given SNI and return the leaf the
/// server presented.
async fn presented_leaf(server_config: Arc<rustls::ServerConfig>, server_name: &str) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = TlsAcceptor::from(server_config);

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        // The handshake is all this test needs; the client drops right after.
        let _ = acceptor.accept(stream).await;
    });

    let mut client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ferrum_edge::tls::NoVerifier))
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = TcpStream::connect(addr).await.expect("connect");
    let name = ServerName::try_from(server_name.to_string()).expect("server name");
    let tls_stream = connector.connect(name, stream).await.expect("handshake");

    let leaf = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .map(|cert| cert.as_ref().to_vec())
        .expect("server presented a certificate");
    drop(tls_stream);
    let _ = server.await;
    leaf
}

/// The certificate set most cases here share. Callers that destructure must
/// bind `_dir` (not only `..`) so TempDir outlives path reads and handshakes.
struct Fixture {
    _dir: TempDir,
    alpha: TestCertificate,
    beta: TestCertificate,
    wildcard: TestCertificate,
    fallback: TestCertificate,
}

fn fixture() -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let alpha = write_certificate(&dir, "alpha", &["a.example.com"]);
    let beta = write_certificate(&dir, "beta", &["b.example.com"]);
    let wildcard = write_certificate(&dir, "wildcard", &["*.wild.example.com"]);
    let fallback = write_certificate(&dir, "fallback", &["fallback.example.com"]);
    Fixture {
        _dir: dir,
        alpha,
        beta,
        wildcard,
        fallback,
    }
}

#[tokio::test]
async fn sni_selects_the_certificate_that_names_the_requested_host() {
    ensure_crypto_provider();
    // Bind `_dir` explicitly: `..` would drop TempDir before path reads.
    let Fixture {
        _dir,
        alpha,
        beta,
        fallback,
        ..
    } = fixture();
    let config = server_config(&[
        input(&fallback, "ferrum/edge/catch-all", None, true),
        input(&alpha, "ferrum/edge-a/https", Some("a.example.com"), false),
        input(&beta, "ferrum/edge-b/https", Some("b.example.com"), false),
    ]);

    assert_eq!(
        presented_leaf(config.clone(), "a.example.com").await,
        alpha.der,
        "SNI a.example.com must be answered by its own Gateway's certificate"
    );
    assert_eq!(
        presented_leaf(config, "b.example.com").await,
        beta.der,
        "a second Gateway in the same namespace serves its own certificate (#3268)"
    );
}

#[tokio::test]
async fn certificate_san_selects_even_without_a_listener_hostname() {
    ensure_crypto_provider();
    let Fixture {
        _dir, alpha, beta, ..
    } = fixture();
    // Both listeners are catch-all: selection has to come from each leaf's own
    // SANs, which is the shape a Gateway with no `hostname` produces.
    let config = server_config(&[
        input(&alpha, "ferrum/edge-a/https", None, true),
        input(&beta, "ferrum/edge-b/https", None, false),
    ]);

    assert_eq!(
        presented_leaf(config.clone(), "b.example.com").await,
        beta.der
    );
    assert_eq!(presented_leaf(config, "a.example.com").await, alpha.der);
}

#[tokio::test]
async fn wildcard_matches_one_label_only() {
    ensure_crypto_provider();
    let Fixture {
        _dir,
        wildcard,
        fallback,
        ..
    } = fixture();
    let config = server_config(&[
        input(&fallback, "ferrum/edge/catch-all", None, true),
        input(
            &wildcard,
            "ferrum/edge/wild",
            Some("*.wild.example.com"),
            false,
        ),
    ]);

    assert_eq!(
        presented_leaf(config.clone(), "shop.wild.example.com").await,
        wildcard.der,
        "one label under the wildcard matches"
    );
    assert_eq!(
        presented_leaf(config.clone(), "deep.shop.wild.example.com").await,
        fallback.der,
        "two labels must NOT match a single-label wildcard (RFC 6125)"
    );
    assert_eq!(
        presented_leaf(config, "wild.example.com").await,
        fallback.der,
        "a wildcard does not cover its own parent domain"
    );
}

#[tokio::test]
async fn exact_match_beats_a_covering_wildcard() {
    ensure_crypto_provider();
    let dir = TempDir::new().expect("temp dir");
    let wildcard = write_certificate(&dir, "wildcard", &["*.example.com"]);
    let exact = write_certificate(&dir, "exact", &["shop.example.com"]);
    let config = server_config(&[
        input(&wildcard, "ferrum/edge/wild", Some("*.example.com"), true),
        input(&exact, "ferrum/edge/shop", Some("shop.example.com"), false),
    ]);

    assert_eq!(
        presented_leaf(config, "shop.example.com").await,
        exact.der,
        "a certificate that names the host outright wins over one that only covers it"
    );
}

#[tokio::test]
async fn unmatched_sni_falls_back_to_the_marked_default() {
    ensure_crypto_provider();
    let Fixture {
        _dir,
        alpha,
        beta,
        fallback,
        ..
    } = fixture();
    let config = server_config(&[
        input(&alpha, "ferrum/edge-a/https", Some("a.example.com"), false),
        input(&beta, "ferrum/edge-b/https", Some("b.example.com"), false),
        input(&fallback, "ferrum/edge/catch-all", None, true),
    ]);

    assert_eq!(
        presented_leaf(config, "unknown.example.org").await,
        fallback.der,
        "an unmatched SNI is answered with the fallback, not a handshake failure"
    );
}

/// SANs per saturating certificate.
///
/// rustls pairs a leaf through webpki, which reads the certificate's top-level
/// DER SEQUENCE with a two-byte length limit (65535 bytes). All
/// `MAX_SNI_INDEX_ENTRIES` names on ONE leaf is roughly 120 KiB and is rejected
/// at load as `BadEncoding` — no resolver would ever see it, and no product
/// change could accept it. Spreading the names over several certificates keeps
/// every leaf servable and models what an alias-heavy catch-all listener with
/// multiple `certificateRefs` actually looks like. 512 names is about 15 KiB.
const SATURATION_SANS_PER_CERTIFICATE: usize = 512;

#[tokio::test]
async fn declared_listener_hostname_survives_certificate_san_index_saturation() {
    ensure_crypto_provider();
    let dir = TempDir::new().expect("temp dir");
    let san_names: Vec<String> = (0..MAX_SNI_INDEX_ENTRIES)
        .map(|index| format!("san-{index}.saturation.example"))
        .collect();
    let saturating: Vec<TestCertificate> = san_names
        .chunks(SATURATION_SANS_PER_CERTIFICATE)
        .enumerate()
        .map(|(part, names)| {
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            write_certificate(&dir, &format!("saturated-{part}"), &refs)
        })
        .collect();
    let declared = write_certificate(&dir, "declared", &["certificate-only.example.net"]);

    // One catch-all listener carrying every saturating certificate, so the
    // SAN pass alone would exhaust the index before the declared hostname.
    let mut certificates: Vec<GatewayCertificateInput> = Vec::new();
    for certificate in &saturating {
        certificates.push(input(certificate, "ferrum/edge/catch-all", None, true));
    }
    let declared_listener = input(
        &declared,
        "ferrum/edge/declared",
        Some("PRIORITY.Example.COM."),
        false,
    );
    certificates.push(declared_listener);
    let config = server_config(&certificates);

    assert_eq!(
        presented_leaf(config, "priority.example.com").await,
        declared.der,
        "certificate SAN aliases must never consume the slot for a later listener's explicit, canonically equivalent hostname"
    );
}

#[tokio::test]
async fn rotating_one_certificate_leaves_the_others_serving() {
    ensure_crypto_provider();
    let dir = TempDir::new().expect("temp dir");
    let alpha = write_certificate(&dir, "alpha", &["a.example.com"]);
    let beta = write_certificate(&dir, "beta", &["b.example.com"]);
    let before = server_config(&[
        input(&alpha, "ferrum/edge-a/https", Some("a.example.com"), true),
        input(&beta, "ferrum/edge-b/https", Some("b.example.com"), false),
    ]);
    assert_eq!(
        presented_leaf(before.clone(), "b.example.com").await,
        beta.der
    );

    // A rotation replaces the Secret behind one listener only. The data plane
    // rebuilds the whole resolver, so assert the untouched listener is
    // unaffected and the rotated one now presents the new leaf.
    let rotated_beta = write_certificate(&dir, "beta-rotated", &["b.example.com"]);
    let after = server_config(&[
        input(&alpha, "ferrum/edge-a/https", Some("a.example.com"), true),
        input(
            &rotated_beta,
            "ferrum/edge-b/https",
            Some("b.example.com"),
            false,
        ),
    ]);

    assert_ne!(rotated_beta.der, beta.der);
    assert_eq!(
        presented_leaf(after.clone(), "b.example.com").await,
        rotated_beta.der,
        "the rotated listener presents its new leaf"
    );
    assert_eq!(
        presented_leaf(after, "a.example.com").await,
        alpha.der,
        "an untouched listener keeps serving its own certificate across a sibling's rotation"
    );
    // In-flight config objects are immutable: the pre-rotation snapshot still
    // presents the old leaf, mirroring sessions that negotiated against it.
    assert_eq!(presented_leaf(before, "b.example.com").await, beta.der);
}

#[test]
fn one_unloadable_certificate_fails_the_whole_set_closed() {
    ensure_crypto_provider();
    let Fixture {
        _dir,
        alpha,
        fallback,
        ..
    } = fixture();
    let mut broken = input(&alpha, "ferrum/edge-a/https", Some("a.example.com"), false);
    broken.cert_source = "/nonexistent/gateway-cert.pem".to_string();

    let result = load_gateway_multi_cert_tls_config(
        &[
            input(&fallback, "ferrum/edge/catch-all", None, true),
            broken,
        ],
        None,
        None,
        &tls_policy(),
        30,
        &[],
    );

    assert!(
        result.is_err(),
        "a certificate that cannot be loaded must reject the whole snapshot rather than \
         silently answering its hostname with the fallback certificate"
    );
}

#[test]
fn an_invalid_explicit_listener_hostname_fails_the_whole_set_closed() {
    ensure_crypto_provider();
    let Fixture {
        _dir,
        alpha,
        fallback,
        ..
    } = fixture();
    let malformed = input(
        &alpha,
        "ferrum/edge-a/https",
        Some("bad host.example.com"),
        false,
    );

    let error = load_gateway_multi_cert_tls_config(
        &[
            input(&fallback, "ferrum/edge/catch-all", None, true),
            malformed,
        ],
        None,
        None,
        &tls_policy(),
        30,
        &[],
    )
    .expect_err("a malformed declared hostname must reject the whole snapshot");

    assert!(
        error
            .to_string()
            .contains("invalid explicit listener hostname")
    );
    assert!(!error.to_string().contains("bad host.example.com"));
}

#[test]
fn conflicting_explicit_listener_claims_fail_the_runtime_snapshot_closed() {
    ensure_crypto_provider();
    let Fixture {
        _dir, alpha, beta, ..
    } = fixture();

    let error = load_gateway_multi_cert_tls_config(
        &[
            input(
                &alpha,
                "ferrum/edge-a/https",
                Some("shop.example.com"),
                true,
            ),
            input(
                &beta,
                "ferrum/edge-b/https",
                Some("shop.example.com"),
                false,
            ),
        ],
        None,
        None,
        &tls_policy(),
        30,
        &[],
    )
    .expect_err("a ConfigSync collision must not bypass translator withdrawal");

    assert!(error.to_string().contains("conflicting certificate sets"));
}

#[test]
fn one_listener_identity_cannot_carry_inconsistent_hostnames() {
    ensure_crypto_provider();
    let Fixture {
        _dir, alpha, beta, ..
    } = fixture();

    let error = load_gateway_multi_cert_tls_config(
        &[
            input(&alpha, "ferrum/edge/https", Some("a.example.com"), true),
            input(&beta, "ferrum/edge/https", Some("b.example.com"), false),
        ],
        None,
        None,
        &tls_policy(),
        30,
        &[],
    )
    .expect_err("one listener must have one consistent hostname claim");

    assert!(error.to_string().contains("inconsistent hostname claims"));
}

#[test]
fn a_mismatched_certificate_and_key_pair_is_refused() {
    ensure_crypto_provider();
    let Fixture {
        _dir,
        alpha,
        beta,
        fallback,
        ..
    } = fixture();
    let mut mismatched = input(&alpha, "ferrum/edge-a/https", Some("a.example.com"), false);
    mismatched.key_source = beta.key_path.clone();

    let result = load_gateway_multi_cert_tls_config(
        &[
            input(&fallback, "ferrum/edge/catch-all", None, true),
            mismatched,
        ],
        None,
        None,
        &tls_policy(),
        30,
        &[],
    );

    assert!(result.is_err(), "cert/key mismatch must fail closed");
}

#[test]
fn an_empty_certificate_set_is_refused() {
    ensure_crypto_provider();
    let result = load_gateway_multi_cert_tls_config(&[], None, None, &tls_policy(), 30, &[]);
    assert!(result.is_err());
}

#[tokio::test]
async fn an_unmarked_set_still_produces_a_fallback() {
    ensure_crypto_provider();
    let Fixture {
        _dir, alpha, beta, ..
    } = fixture();
    // No entry carries the default marker (an older control plane): the first
    // certificate in the delivered order must take the fallback slot rather
    // than leaving the listener without a credential.
    let config = server_config(&[
        input(&alpha, "ferrum/edge-a/https", Some("a.example.com"), false),
        input(&beta, "ferrum/edge-b/https", Some("b.example.com"), false),
    ]);

    assert_eq!(
        presented_leaf(config, "unknown.example.org").await,
        alpha.der
    );
}

#[test]
fn runtime_refuses_a_hand_built_certificate_set_over_the_admission_bound() {
    let certificates: Vec<GatewayCertificateInput> = (0
        ..ferrum_edge::config::types::MAX_FRONTEND_TLS_CERTIFICATE_SOURCES + 1)
        .map(|index| GatewayCertificateInput {
            cert_source: format!("/not-loaded/{index}.crt"),
            key_source: format!("/not-loaded/{index}.key"),
            hostname: None,
            identity: format!("ferrum/edge/listener-{index}"),
            is_default: index == 0,
        })
        .collect();

    let error =
        load_gateway_multi_cert_tls_config(&certificates, None, None, &tls_policy(), 30, &[])
            .expect_err("the runtime must enforce the same resident certificate bound");
    assert!(error.to_string().contains("certificate set exceeds"));
}
