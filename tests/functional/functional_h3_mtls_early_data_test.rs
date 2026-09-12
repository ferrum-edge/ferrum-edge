//! Functional regression coverage for issue #2938 — enabling HTTP/3 0-RTT must
//! not break HTTP/3 frontend mTLS.
//!
//! Before the fix, a non-empty `FERRUM_TLS_EARLY_DATA_METHODS` made the H3
//! listener accept **every** connection through quinn's `into_0rtt()`, which
//! materializes the connection at 0.5-RTT — before the client's
//! `Certificate`/`Finished` flight arrives. `peer_identity()` was snapshotted
//! right there and pinned for the connection's life, so `mtls_auth` (950) and
//! `spiffe_identity` (940) saw no client certificate on *every* request,
//! including fully handshaken 1-RTT ones. Fail-closed, but a total silent
//! availability regression presenting as universal 401s.
//!
//! Tests:
//!   1. A normal 1-RTT H3 request presenting a valid client cert succeeds (200)
//!      with early-data methods configured, and an unmapped cert still gets 401
//!      — so the certificate really is being evaluated, not bypassed.
//!   2. `spiffe_identity` sees the same peer certificate: a cert with two URI
//!      SANs (invalid per SPIFFE X.509-SVID §4.1) is rejected 403. Pre-fix this
//!      returned 401 from `mtls_auth`, because the plugin never saw a cert at
//!      all.
//!   3. Non-mTLS H3 early data is unchanged: a listener with early-data methods
//!      and no client CA still serves ordinary H3 requests.
//!
//! Run with:
//!   cargo build --bin ferrum-edge && \
//!     cargo test --test functional_tests -- functional_h3_mtls_early_data --ignored --nocapture

use crate::scaffolding::port_registry::TestSocket;

use crate::common::TestGateway;
use crate::scaffolding::clients::Http3Client;

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Certificate generation
// ============================================================================

struct GeneratedCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

struct GeneratedCert {
    cert_pem: String,
    key_pem: String,
}

fn generate_ca(cn: &str) -> GeneratedCa {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let cert = params.self_signed(&key_pair).expect("self-sign CA");
    GeneratedCa {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key_pair),
    }
}

fn generate_server_cert(ca: &GeneratedCa) -> GeneratedCert {
    let key_pair =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate server key");
    let sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let mut params = CertificateParams::new(sans).expect("server params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ferrum-h3-gw");
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

/// Client leaf with the given subject CN and zero or more URI SANs. Two URI
/// SANs make the leaf invalid per SPIFFE X.509-SVID §4.1, which is how test 2
/// observes that `spiffe_identity` actually parsed the peer certificate.
fn generate_client_cert(ca: &GeneratedCa, cn: &str, uri_sans: &[&str]) -> GeneratedCert {
    let key_pair =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate client key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("client params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    for uri in uri_sans {
        let ia5 = rcgen::string::Ia5String::try_from(uri.to_string()).expect("URI SAN is IA5");
        params.subject_alt_names.push(SanType::URI(ia5));
    }
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign cert");
    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

fn write_pem(dir: &TempDir, name: &str, data: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, data).expect("write PEM");
    path.to_str().expect("PEM path is UTF-8").to_string()
}

// ============================================================================
// Backend
// ============================================================================

fn start_counting_http_backend_on(
    listener: TcpListener,
    accepted: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let accepted = Arc::clone(&accepted);
            tokio::spawn(async move {
                let mut request_prefix = [0u8; 9];
                // Count only the proxied HTTP/1.1 GET for this fixture's path.
                // With `FERRUM_POOL_WARMUP_ENABLED=false`, the binary gateway still
                // runs an initial backend-capability refresh that dials plaintext
                // backends with h2c prior-knowledge (`PRI * HTTP/2.0`). Counting
                // bare TCP accepts would attribute that probe to a plugin-rejected
                // request and falsely fail the fail-closed security assertion. An
                // exact read avoids missing a real GET when TCP fragments its prefix.
                if stream.read_exact(&mut request_prefix).await.is_ok()
                    && request_prefix == *b"GET /test"
                {
                    accepted.fetch_add(1, Ordering::Relaxed);
                }
                let body = r#"{"status":"ok"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    })
}

// ============================================================================
// Gateway harness
// ============================================================================

async fn alloc_port() -> u16 {
    crate::scaffolding::ports::unbound_port()
        .await
        .expect("lease test port")
}

/// Start a gateway with fresh ports on each attempt. Port allocation races with
/// other parallel functional tests, so every retry gets a brand-new port.
async fn start_gateway_with_retry<F>(config: &str, build_envs: F) -> (TestGateway, u16)
where
    F: Fn(u16) -> Vec<(String, String)>,
{
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let https_port = alloc_port().await;
        let mut builder = TestGateway::builder()
            .mode_file(config.to_string())
            // The outer loop allocates fresh ports, so each harness attempt
            // intentionally gets one gateway spawn.
            .max_attempts(1)
            .log_level("warn")
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string());
        for (key, value) in build_envs(https_port) {
            builder = builder.env(key, value);
        }
        match builder.spawn().await {
            Ok(gateway) => return (gateway, https_port),
            Err(err) => {
                last_err = err.to_string();
                eprintln!("Gateway startup attempt {attempt}/{MAX_ATTEMPTS} failed: {last_err}");
            }
        }
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {MAX_ATTEMPTS} attempts: {last_err}");
}

/// Fire an H3 GET, retrying while the QUIC listener is still coming up.
/// Returns the response status.
async fn h3_get_status(client: &Http3Client, url: &str) -> u16 {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut last_err = String::new();
    loop {
        match client.get(url).await {
            Ok(response) => return response.status.as_u16(),
            Err(err) if std::time::Instant::now() < deadline => {
                last_err = err.to_string();
                sleep(Duration::from_millis(150)).await;
            }
            Err(err) => panic!("H3 request never completed: last={last_err}; final={err}"),
        }
    }
}

const MTLS_CONFIG: &str = r#"
version: "1"
proxies:
  - id: "h3-mtls"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: BACKEND_PORT
    strip_listen_path: true
    plugins:
      - plugin_config_id: "p-spiffe"
      - plugin_config_id: "p-mtls"

consumers:
  - id: "alice"
    username: "alice"
    credentials:
      mtls_auth:
        - identity: "alice.h3.local"

plugin_configs:
  - id: "p-spiffe"
    proxy_id: "h3-mtls"
    plugin_name: "spiffe_identity"
    scope: "proxy"
    enabled: true
    config: {}
  - id: "p-mtls"
    proxy_id: "h3-mtls"
    plugin_name: "mtls_auth"
    scope: "proxy"
    enabled: true
    config:
      cert_field: "subject_cn"
"#;

// ============================================================================
// Test 1 — normal 1-RTT H3 mTLS with early-data methods configured
// ============================================================================

#[ignore]
#[tokio::test]
async fn functional_h3_mtls_early_data_normal_request_is_authenticated() {
    let dir = TempDir::new().expect("temp dir");
    let ca = generate_ca("H3-MTLS-EARLY-DATA-CA");
    let server = generate_server_cert(&ca);
    let alice = generate_client_cert(
        &ca,
        "alice.h3.local",
        &["spiffe://ferrum.test/ns/default/sa/alice"],
    );
    let stranger = generate_client_cert(&ca, "stranger.h3.local", &[]);

    let ca_p = write_pem(&dir, "ca.pem", &ca.cert_pem);
    let cert_p = write_pem(&dir, "server.crt", &server.cert_pem);
    let key_p = write_pem(&dir, "server.key", &server.key_pem);

    let backend_listener = TcpListener::bind_test("127.0.0.1:0").await.expect("bind");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    let backend = start_counting_http_backend_on(backend_listener, Arc::clone(&backend_hits));
    sleep(Duration::from_millis(150)).await;

    let config = MTLS_CONFIG.replace("BACKEND_PORT", &backend_port.to_string());
    let (mut gateway, https_port) = start_gateway_with_retry(&config, |_port| {
        vec![
            ("FERRUM_FRONTEND_TLS_CERT_PATH".into(), cert_p.clone()),
            ("FERRUM_FRONTEND_TLS_KEY_PATH".into(), key_p.clone()),
            (
                "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH".into(),
                ca_p.clone(),
            ),
            // The knob that used to break H3 mTLS entirely.
            ("FERRUM_TLS_EARLY_DATA_METHODS".into(), "GET".into()),
            ("FERRUM_TLS_NO_VERIFY".into(), "false".into()),
            ("FERRUM_POOL_WARMUP_ENABLED".into(), "false".into()),
        ]
    })
    .await;

    let url = format!("https://localhost:{https_port}/api/test");

    let alice_client = Http3Client::insecure_with_client_auth(&alice.cert_pem, &alice.key_pem)
        .expect("alice H3 client");
    let status = h3_get_status(&alice_client, &url).await;
    assert_eq!(
        status, 200,
        "a fully handshaken H3 client presenting a valid client certificate must be \
         authenticated even with FERRUM_TLS_EARLY_DATA_METHODS configured (issue #2938 \
         regressed this to a universal 401)"
    );
    assert!(
        backend_hits.load(Ordering::Relaxed) >= 1,
        "the authenticated H3 request must actually reach the backend"
    );

    // The certificate is genuinely being evaluated — a CA-signed cert whose CN
    // maps to no consumer still fails closed.
    let stranger_client =
        Http3Client::insecure_with_client_auth(&stranger.cert_pem, &stranger.key_pem)
            .expect("stranger H3 client");
    let status = h3_get_status(&stranger_client, &url).await;
    assert_eq!(
        status, 401,
        "a client cert with no consumer mapping must still fail closed"
    );

    gateway.shutdown();
    backend.abort();
}

// ============================================================================
// Test 2 — SPIFFE metadata is derived from the post-handshake peer certificate
// ============================================================================

#[ignore]
#[tokio::test]
async fn functional_h3_mtls_early_data_spiffe_identity_sees_the_peer_certificate() {
    let dir = TempDir::new().expect("temp dir");
    let ca = generate_ca("H3-MTLS-EARLY-DATA-SPIFFE-CA");
    let server = generate_server_cert(&ca);
    // CN maps to the "alice" consumer, so `mtls_auth` alone would answer 200.
    // Two URI SANs make the leaf an invalid X.509-SVID, so `spiffe_identity`
    // (priority 940, ahead of mtls_auth's 950) rejects it 403 — but only if it
    // actually received the peer certificate.
    let double_uri = generate_client_cert(
        &ca,
        "alice.h3.local",
        &[
            "spiffe://ferrum.test/ns/default/sa/alice",
            "spiffe://ferrum.test/ns/default/sa/imposter",
        ],
    );

    let ca_p = write_pem(&dir, "ca.pem", &ca.cert_pem);
    let cert_p = write_pem(&dir, "server.crt", &server.cert_pem);
    let key_p = write_pem(&dir, "server.key", &server.key_pem);

    let backend_listener = TcpListener::bind_test("127.0.0.1:0").await.expect("bind");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    let backend = start_counting_http_backend_on(backend_listener, Arc::clone(&backend_hits));
    sleep(Duration::from_millis(150)).await;

    let config = MTLS_CONFIG.replace("BACKEND_PORT", &backend_port.to_string());
    let (mut gateway, https_port) = start_gateway_with_retry(&config, |_port| {
        vec![
            ("FERRUM_FRONTEND_TLS_CERT_PATH".into(), cert_p.clone()),
            ("FERRUM_FRONTEND_TLS_KEY_PATH".into(), key_p.clone()),
            (
                "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH".into(),
                ca_p.clone(),
            ),
            ("FERRUM_TLS_EARLY_DATA_METHODS".into(), "GET".into()),
            ("FERRUM_TLS_NO_VERIFY".into(), "false".into()),
            ("FERRUM_POOL_WARMUP_ENABLED".into(), "false".into()),
        ]
    })
    .await;

    let url = format!("https://localhost:{https_port}/api/test");
    let client = Http3Client::insecure_with_client_auth(&double_uri.cert_pem, &double_uri.key_pem)
        .expect("double-URI H3 client");
    let status = h3_get_status(&client, &url).await;

    assert_eq!(
        status, 403,
        "spiffe_identity must derive SPIFFE metadata from the post-handshake peer \
         certificate and reject an invalid X.509-SVID; a 401 here means the plugin never \
         saw a certificate (issue #2938)"
    );
    assert_eq!(
        backend_hits.load(Ordering::Relaxed),
        0,
        "a SPIFFE-rejected request must never reach the backend"
    );

    gateway.shutdown();
    backend.abort();
}

// ============================================================================
// Test 3 — non-mTLS H3 early data is unchanged
// ============================================================================

const PLAIN_CONFIG: &str = r#"
version: "1"
proxies:
  - id: "h3-plain"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: BACKEND_PORT
    strip_listen_path: true

consumers: []
plugin_configs: []
"#;

#[ignore]
#[tokio::test]
async fn functional_h3_early_data_without_client_ca_is_unchanged() {
    let dir = TempDir::new().expect("temp dir");
    let ca = generate_ca("H3-EARLY-DATA-PLAIN-CA");
    let server = generate_server_cert(&ca);
    let cert_p = write_pem(&dir, "server.crt", &server.cert_pem);
    let key_p = write_pem(&dir, "server.key", &server.key_pem);

    let backend_listener = TcpListener::bind_test("127.0.0.1:0").await.expect("bind");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    let backend = start_counting_http_backend_on(backend_listener, Arc::clone(&backend_hits));
    sleep(Duration::from_millis(150)).await;

    let config = PLAIN_CONFIG.replace("BACKEND_PORT", &backend_port.to_string());
    let (mut gateway, https_port) = start_gateway_with_retry(&config, |_port| {
        vec![
            ("FERRUM_FRONTEND_TLS_CERT_PATH".into(), cert_p.clone()),
            ("FERRUM_FRONTEND_TLS_KEY_PATH".into(), key_p.clone()),
            // No client CA — the 0-RTT accept path stays enabled here.
            ("FERRUM_TLS_EARLY_DATA_METHODS".into(), "GET".into()),
            ("FERRUM_POOL_WARMUP_ENABLED".into(), "false".into()),
        ]
    })
    .await;

    let url = format!("https://localhost:{https_port}/api/test");
    let client = Http3Client::insecure().expect("plain H3 client");
    let status = h3_get_status(&client, &url).await;

    assert_eq!(
        status, 200,
        "a non-mTLS H3 listener with early-data methods configured must keep serving \
         ordinary requests exactly as before"
    );
    assert!(backend_hits.load(Ordering::Relaxed) >= 1);

    gateway.shutdown();
    backend.abort();
}
