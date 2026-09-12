//! Functional tests for TLS certificate lifecycle:
//!
//! 1. Expired frontend TLS cert → hard failure at startup (exit non-zero, stderr
//!    mentions "expired").
//! 2. Cert expiring within `FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS` window → gateway
//!    starts successfully but emits a warn log mentioning the days remaining.
//! 3. `FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS=0` disables warnings → gateway starts,
//!    stderr has no expiry warning line.
//! 4. CRL revocation: backend cert is revoked by CRL → backend connection fails
//!    (status != 200 or transport error).
//! 5. CRL with unrelated issuer: revocation policy is `allow_unknown_revocation_status`
//!    so requests succeed.
//! 6. No hot reload on frontend cert: overwriting the cert file post-startup does
//!    not change the cert served to new TLS clients (invariant by design).
//!
//! Certificates are generated with `rcgen` at test time with custom validity
//! windows. For tests 4/5, CRLs are generated in-memory via
//! `rcgen::CertificateRevocationListParams::signed_by` and written to disk as
//! PEM.
//!
//! Run with:
//!   cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests -- --ignored functional_tls_lifecycle --nocapture

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child as TokioChild, Command as TokioCommand};
use tokio::time::sleep;

// ============================================================================
// Certificate / CRL Generation Helpers
// ============================================================================

struct GeneratedCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn generate_ca(cn: &str) -> GeneratedCa {
    let key_pair =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("Failed to generate CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    // CAs that sign CRLs must have KeyCertSign AND CrlSign key usages
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    let cert = params.self_signed(&key_pair).expect("self-sign CA");
    let cert_pem = cert.pem();
    GeneratedCa {
        cert_pem,
        issuer: Issuer::new(params, key_pair),
    }
}

/// A signed leaf certificate plus the serial number used to sign it (needed if
/// we want to revoke it later).
struct GeneratedCert {
    cert_pem: String,
    key_pem: String,
    serial: SerialNumber,
}

fn generate_signed_cert(ca: &GeneratedCa, cn: &str, sans: &[&str]) -> GeneratedCert {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("gen leaf key");
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(san_strings).expect("leaf params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    // Assign a deterministic, non-zero serial so revocation can reference it.
    let serial_bytes: Vec<u8> = (1..=20).collect();
    let serial = SerialNumber::from_slice(&serial_bytes);
    params.serial_number = Some(serial.clone());
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        serial,
    }
}

/// Generate a self-signed certificate with custom not_before / not_after.
fn generate_self_signed_cert_with_window(
    cn: &str,
    sans: &[&str],
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> (String, String) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(san_strings).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params.self_signed(&key_pair).expect("self-sign cert");
    (cert.pem(), key_pair.serialize_pem())
}

/// Create a CRL signed by `ca` that revokes `revoked_serial` (optional).
fn generate_crl_pem(ca: &GeneratedCa, revoked_serials: &[SerialNumber]) -> String {
    let now = time::OffsetDateTime::now_utc();
    let revoked_certs: Vec<RevokedCertParams> = revoked_serials
        .iter()
        .map(|s| RevokedCertParams {
            serial_number: s.clone(),
            revocation_time: now,
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        })
        .collect();
    let params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + time::Duration::days(30),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    params
        .signed_by(&ca.issuer)
        .expect("sign CRL")
        .pem()
        .expect("CRL to PEM")
}

fn write_file(dir: &TempDir, name: &str, data: &str) -> String {
    let p = dir.path().join(name);
    std::fs::write(&p, data).unwrap();
    p.to_str().unwrap().to_string()
}

// ============================================================================
// Gateway Helpers
// ============================================================================

fn gw_bin() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else if std::path::Path::new("./target/release/ferrum-edge").exists() {
        "./target/release/ferrum-edge"
    } else {
        panic!("ferrum-edge binary not found. Run `cargo build --bin ferrum-edge` first.");
    }
}

/// Allocate an ephemeral port by binding to port 0 and returning the assigned port.
async fn alloc_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Wait for the gateway admin HTTP health endpoint. Returns `true` if healthy
/// within timeout.
async fn wait_for_gateway(admin_http_port: u16, max_attempts: u32) -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    for _ in 0..max_attempts {
        if let Ok(resp) = client
            .get(format!("http://127.0.0.1:{}/health", admin_http_port))
            .send()
            .await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

#[derive(Clone)]
struct Ports {
    proxy_http: u16,
    proxy_https: u16,
    admin_http: u16,
    /// TCP+TLS stream listener port (issue #3857 retirement coverage).
    stream_tcp: u16,
    /// UDP+DTLS stream listener port (issue #3857 retirement coverage).
    stream_udp: u16,
}

async fn alloc_ports() -> Ports {
    Ports {
        proxy_http: alloc_port().await,
        proxy_https: alloc_port().await,
        admin_http: alloc_port().await,
        stream_tcp: alloc_port().await,
        stream_udp: alloc_port().await,
    }
}

/// Captures stdout + stderr from the gateway child process. The gateway writes
/// JSON-formatted tracing events to stdout and early startup errors (crypto
/// init, validate path) to stderr via `eprintln!`. Both must be drained into a
/// shared Vec to prevent pipe-buffer deadlock on verbose log output.
struct OutputCapture {
    buf: Arc<Mutex<Vec<String>>>,
    _stdout_task: tokio::task::JoinHandle<()>,
    _stderr_task: tokio::task::JoinHandle<()>,
}

impl OutputCapture {
    fn new(stdout: tokio::process::ChildStdout, stderr: tokio::process::ChildStderr) -> Self {
        let buf = Arc::new(Mutex::new(Vec::<String>::new()));
        let stdout_task = spawn_line_drain(stdout, buf.clone());
        let stderr_task = spawn_line_drain(stderr, buf.clone());
        Self {
            buf,
            _stdout_task: stdout_task,
            _stderr_task: stderr_task,
        }
    }

    fn snapshot(&self) -> Vec<String> {
        self.buf.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

fn spawn_line_drain<R>(reader: R, buf: Arc<Mutex<Vec<String>>>) -> tokio::task::JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    if let Ok(mut g) = buf.lock() {
                        g.push(line.trim_end().to_string());
                    }
                }
                Err(_) => break,
            }
        }
    })
}

/// Start the gateway in file mode with piped stdout + stderr. Returns the child
/// plus a capture handle that tests can inspect via `.snapshot()`.
fn spawn_gateway_piped(
    config_path: &str,
    ports: &Ports,
    envs: &[(&str, &str)],
) -> (TokioChild, OutputCapture) {
    let mut cmd = TokioCommand::new(gw_bin());
    cmd.arg("run");
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", ports.proxy_http.to_string())
        .env("FERRUM_PROXY_HTTPS_PORT", ports.proxy_https.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", ports.admin_http.to_string())
        .env("FERRUM_LOG_LEVEL", "warn")
        .env("RUST_LOG", "ferrum_edge=warn,warn")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn gateway");
    let stdout = child.stdout.take().expect("child stdout should be piped");
    let stderr = child.stderr.take().expect("child stderr should be piped");
    let capture = OutputCapture::new(stdout, stderr);
    (child, capture)
}

/// Write a minimal config file with no proxies (no backend needed for startup tests).
fn write_empty_config(dir: &TempDir) -> String {
    let p = dir.path().join("cfg.yaml");
    std::fs::write(
        &p,
        "version: \"1\"\nproxies: []\nconsumers: []\nupstreams: []\nplugin_configs: []\n",
    )
    .unwrap();
    p.to_str().unwrap().to_string()
}

// ============================================================================
// HTTPS echo backend (for CRL tests)
// ============================================================================

async fn start_https_echo_on(
    listener: TcpListener,
    cert_pem: &str,
    key_pem: &str,
) -> tokio::task::JoinHandle<()> {
    let cert = cert_pem.to_string();
    let key = key_pem.to_string();
    let h = tokio::spawn(async move {
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
        let pk = rustls_pemfile::private_key(&mut key.as_bytes())
            .unwrap()
            .unwrap();
        let provider = rustls::crypto::ring::default_provider();
        let builder = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap();
        let mut cfg = builder
            .with_no_client_auth()
            .with_single_cert(certs, pk)
            .unwrap();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        while let Ok((tcp, _)) = listener.accept().await {
            let acc = acceptor.clone();
            tokio::spawn(async move {
                let mut s = match acc.accept(tcp).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let mut buf = vec![0u8; 4096];
                let _ = s.read(&mut buf).await;
                let body = r#"{"status":"ok"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    sleep(Duration::from_millis(100)).await;
    h
}

// ============================================================================
// Test 1: Expired frontend cert → hard failure at startup
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_expired_frontend_cert_hard_fails_startup() {
    let td = TempDir::new().unwrap();
    // Cert already expired (notAfter in the past)
    let now = time::OffsetDateTime::now_utc();
    let (cert_pem, key_pem) = generate_self_signed_cert_with_window(
        "expired.local",
        &["localhost", "127.0.0.1"],
        now - time::Duration::days(60),
        now - time::Duration::days(1),
    );
    let cert_path = write_file(&td, "expired.crt", &cert_pem);
    let key_path = write_file(&td, "expired.key", &key_pem);
    let cfg = write_empty_config(&td);

    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let ports = alloc_ports().await;
        let (mut child, capture) = spawn_gateway_piped(
            &cfg,
            &ports,
            &[
                ("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path.as_str()),
                ("FERRUM_FRONTEND_TLS_KEY_PATH", key_path.as_str()),
            ],
        );

        // Gateway must NOT become healthy — either exits quickly or never listens.
        let healthy = wait_for_gateway(ports.admin_http, 10).await;
        if healthy {
            // Unexpected: gateway accepted an expired cert. Clean up and retry —
            // but if we see this on the last attempt, fail loudly.
            let _ = child.kill().await;
            if attempt == MAX_ATTEMPTS {
                panic!("Gateway unexpectedly became healthy with an expired frontend cert");
            }
            continue;
        }

        // Wait for the child to exit (give it up to 10s — the startup TLS check is
        // synchronous and fails fast, usually within a few hundred ms).
        let status_result = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
        let output = capture.snapshot().join("\n");

        match status_result {
            Ok(Ok(status)) => {
                assert!(
                    !status.success(),
                    "Expected non-zero exit for expired cert, got {:?}\nstderr:\n{}",
                    status,
                    output
                );
                let lower = output.to_lowercase();
                assert!(
                    lower.contains("expired")
                        || lower.contains("not after")
                        || lower.contains("notafter"),
                    "Expected stderr to mention 'expired' or 'notAfter'.\nstderr:\n{}",
                    output
                );
                return;
            }
            Ok(Err(e)) => {
                eprintln!(
                    "attempt {}/{}: failed to wait for child: {} (stderr so far:\n{})",
                    attempt, MAX_ATTEMPTS, e, output
                );
            }
            Err(_) => {
                // Child hung without exiting — kill and retry.
                eprintln!(
                    "attempt {}/{}: gateway did not exit within 10s. stderr:\n{}",
                    attempt, MAX_ATTEMPTS, output
                );
                let _ = child.kill().await;
            }
        }

        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not exit cleanly with expired cert after {} attempts",
        MAX_ATTEMPTS
    );
}

// ============================================================================
// Test 2: Near-expiry cert → warn log + successful startup
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_near_expiry_cert_warns_but_starts() {
    let td = TempDir::new().unwrap();
    let now = time::OffsetDateTime::now_utc();
    let (cert_pem, key_pem) = generate_self_signed_cert_with_window(
        "nearexpiry.local",
        &["localhost", "127.0.0.1"],
        now - time::Duration::days(30),
        now + time::Duration::days(7), // expires in 7 days
    );
    let cert_path = write_file(&td, "near.crt", &cert_pem);
    let key_path = write_file(&td, "near.key", &key_pem);
    let cfg = write_empty_config(&td);

    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let ports = alloc_ports().await;
        let (mut child, capture) = spawn_gateway_piped(
            &cfg,
            &ports,
            &[
                ("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path.as_str()),
                ("FERRUM_FRONTEND_TLS_KEY_PATH", key_path.as_str()),
                ("FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS", "30"),
            ],
        );

        if !wait_for_gateway(ports.admin_http, 60).await {
            eprintln!(
                "attempt {}/{}: gateway with near-expiry cert did not become healthy. stderr:\n{}",
                attempt,
                MAX_ATTEMPTS,
                capture.snapshot().join("\n")
            );
            let _ = child.kill().await;
            let _ = child.wait().await;
            if attempt < MAX_ATTEMPTS {
                sleep(Duration::from_secs(1)).await;
                continue;
            }
            panic!(
                "gateway with near-expiry cert did not become healthy after {} attempts",
                MAX_ATTEMPTS
            );
        }

        // Give the log writer a moment to flush the warning through the async
        // bounded process-log worker.
        sleep(Duration::from_millis(500)).await;
        let output = capture.snapshot().join("\n");
        let lower = output.to_lowercase();
        let has_warning =
            lower.contains("expires in") || (lower.contains("days") && lower.contains("notafter"));

        // Clean up first
        let _ = child.kill().await;
        let _ = child.wait().await;

        assert!(
            has_warning,
            "Expected a near-expiry warning in stderr mentioning 'expires in' or 'days'/'notAfter'.\nstderr:\n{}",
            output
        );
        return;
    }
}

// ============================================================================
// Test 3: FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS=0 disables warnings
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_expiry_warning_days_zero_disables_warning() {
    let td = TempDir::new().unwrap();
    let now = time::OffsetDateTime::now_utc();
    let (cert_pem, key_pem) = generate_self_signed_cert_with_window(
        "nearexpiry2.local",
        &["localhost", "127.0.0.1"],
        now - time::Duration::days(30),
        now + time::Duration::days(7),
    );
    let cert_path = write_file(&td, "near2.crt", &cert_pem);
    let key_path = write_file(&td, "near2.key", &key_pem);
    let cfg = write_empty_config(&td);

    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let ports = alloc_ports().await;
        let (mut child, capture) = spawn_gateway_piped(
            &cfg,
            &ports,
            &[
                ("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path.as_str()),
                ("FERRUM_FRONTEND_TLS_KEY_PATH", key_path.as_str()),
                ("FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS", "0"),
            ],
        );

        if !wait_for_gateway(ports.admin_http, 60).await {
            let _ = child.kill().await;
            let _ = child.wait().await;
            if attempt < MAX_ATTEMPTS {
                sleep(Duration::from_secs(1)).await;
                continue;
            }
            panic!("gateway with warning-disabled near-expiry cert did not become healthy");
        }

        sleep(Duration::from_millis(500)).await;
        let output = capture.snapshot().join("\n");
        let lower = output.to_lowercase();
        let has_expiry_warn_line = output.lines().any(|l| {
            let ll = l.to_lowercase();
            // Only match the specific "expires in N days" warning from check_cert_expiry.
            ll.contains("expires in") && ll.contains("day")
        });

        let _ = child.kill().await;
        let _ = child.wait().await;

        assert!(
            !has_expiry_warn_line,
            "Expected no expiry warning when FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS=0.\nstderr:\n{}",
            output
        );
        // Sanity: still should NOT contain "has expired" either (cert is valid).
        assert!(
            !lower.contains("has expired"),
            "Valid near-expiry cert should not produce 'has expired' error.\nstderr:\n{}",
            output
        );
        return;
    }
}

// ============================================================================
// Test 4: CRL revocation — backend cert is on a CRL → backend connection fails
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_crl_revoked_backend_cert_rejected() {
    let td = TempDir::new().unwrap();
    // CA issues backend cert, then revokes it.
    let ca = generate_ca("CRL-Test-CA");
    let backend = generate_signed_cert(&ca, "backend.local", &["localhost", "127.0.0.1"]);
    let crl_pem = generate_crl_pem(&ca, std::slice::from_ref(&backend.serial));

    let ca_path = write_file(&td, "ca.pem", &ca.cert_pem);
    let crl_path = write_file(&td, "revoked.crl", &crl_pem);
    let cfg_path = td.path().join("cfg.yaml");

    // Start HTTPS backend
    let be_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bp = be_listener.local_addr().unwrap().port();
    let echo = start_https_echo_on(be_listener, &backend.cert_pem, &backend.key_pem).await;

    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let ports = alloc_ports().await;
        let config_yaml = format!(
            r#"
version: "1"
proxies:
  - id: "crl-test"
    listen_path: "/api"
    backend_scheme: https
    backend_host: "localhost"
    backend_port: {bp}
    strip_listen_path: true
    backend_tls_verify_server_cert: true
    backend_tls_server_ca_cert_path: "{ca_path}"
    pool_enable_http2: false
    dns_override: "127.0.0.1"
consumers: []
upstreams: []
plugin_configs: []
"#
        );
        std::fs::write(&cfg_path, &config_yaml).unwrap();

        let (mut child, capture) = spawn_gateway_piped(
            cfg_path.to_str().unwrap(),
            &ports,
            &[("FERRUM_TLS_CRL_FILE_PATH", crl_path.as_str())],
        );

        if !wait_for_gateway(ports.admin_http, 60).await {
            let _ = child.kill().await;
            let _ = child.wait().await;
            if attempt < MAX_ATTEMPTS {
                sleep(Duration::from_secs(1)).await;
                continue;
            }
            eprintln!("stderr:\n{}", capture.snapshot().join("\n"));
            panic!("gateway with CRL config did not become healthy");
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let result = client
            .get(format!("http://127.0.0.1:{}/api/test", ports.proxy_http))
            .send()
            .await;

        let _ = child.kill().await;
        let _ = child.wait().await;

        // Expect either a transport error or a 5xx response. Status 200 means
        // the revocation was NOT honored, which is the bug this test catches.
        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                assert!(
                    status >= 500,
                    "Expected 5xx for revoked backend cert, got {}. Revocation may not have been enforced.",
                    status
                );
                echo.abort();
                return;
            }
            Err(_) => {
                // Transport error — perfectly acceptable (upstream unreachable due
                // to TLS verification failure).
                echo.abort();
                return;
            }
        }
    }
}

// ============================================================================
// Test 5: CRL from unrelated issuer → `allow_unknown_revocation_status` lets the
// request succeed (the CRL has no entries for this backend's issuer).
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_crl_unrelated_issuer_allows_request() {
    let td = TempDir::new().unwrap();
    let backend_ca = generate_ca("Backend-CA");
    let unrelated_ca = generate_ca("Unrelated-CA"); // issues CRL but not the backend cert
    let backend = generate_signed_cert(&backend_ca, "backend2.local", &["localhost", "127.0.0.1"]);
    // CRL is signed by `unrelated_ca` and revokes some random serial that has no
    // bearing on the backend cert (which was signed by `backend_ca`).
    let unrelated_serial = SerialNumber::from(99_999u64);
    let crl_pem = generate_crl_pem(&unrelated_ca, &[unrelated_serial]);

    let ca_path = write_file(&td, "backend_ca.pem", &backend_ca.cert_pem);
    let crl_path = write_file(&td, "unrelated.crl", &crl_pem);
    let cfg_path = td.path().join("cfg.yaml");

    let be_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bp = be_listener.local_addr().unwrap().port();
    let echo = start_https_echo_on(be_listener, &backend.cert_pem, &backend.key_pem).await;

    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let ports = alloc_ports().await;
        let config_yaml = format!(
            r#"
version: "1"
proxies:
  - id: "crl-unrelated"
    listen_path: "/api"
    backend_scheme: https
    backend_host: "localhost"
    backend_port: {bp}
    strip_listen_path: true
    backend_tls_verify_server_cert: true
    backend_tls_server_ca_cert_path: "{ca_path}"
    pool_enable_http2: false
    dns_override: "127.0.0.1"
consumers: []
upstreams: []
plugin_configs: []
"#
        );
        std::fs::write(&cfg_path, &config_yaml).unwrap();

        let (mut child, capture) = spawn_gateway_piped(
            cfg_path.to_str().unwrap(),
            &ports,
            &[("FERRUM_TLS_CRL_FILE_PATH", crl_path.as_str())],
        );

        if !wait_for_gateway(ports.admin_http, 60).await {
            let _ = child.kill().await;
            let _ = child.wait().await;
            if attempt < MAX_ATTEMPTS {
                sleep(Duration::from_secs(1)).await;
                continue;
            }
            eprintln!("stderr:\n{}", capture.snapshot().join("\n"));
            panic!("gateway with unrelated-CRL config did not become healthy");
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let result = client
            .get(format!("http://127.0.0.1:{}/api/test", ports.proxy_http))
            .send()
            .await;

        let _ = child.kill().await;
        let _ = child.wait().await;

        match result {
            Ok(resp) => {
                assert_eq!(
                    resp.status().as_u16(),
                    200,
                    "Unrelated CRL should not affect requests (policy: allow_unknown_revocation_status)"
                );
                echo.abort();
                return;
            }
            Err(e) => {
                if attempt < MAX_ATTEMPTS {
                    eprintln!(
                        "attempt {}/{}: request error with unrelated CRL: {}. Retrying.",
                        attempt, MAX_ATTEMPTS, e
                    );
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
                echo.abort();
                panic!("request failed with unrelated CRL: {}", e);
            }
        }
    }
}

// ============================================================================
// Test 6: No hot reload on frontend cert — overwriting the cert file does not
// change the cert served to new TLS clients (invariant by design).
// ============================================================================

#[ignore]
#[tokio::test]
async fn test_frontend_cert_no_hot_reload() {
    let td = TempDir::new().unwrap();
    let now = time::OffsetDateTime::now_utc();

    // Initial cert with CN "initial.local"
    let (cert_a_pem, key_a_pem) = generate_self_signed_cert_with_window(
        "initial.local",
        &["localhost", "127.0.0.1", "initial.local"],
        now - time::Duration::days(1),
        now + time::Duration::days(365),
    );
    // Replacement cert with CN "replaced.local" — a different identity.
    let (cert_b_pem, key_b_pem) = generate_self_signed_cert_with_window(
        "replaced.local",
        &["localhost", "127.0.0.1", "replaced.local"],
        now - time::Duration::days(1),
        now + time::Duration::days(365),
    );

    let cert_path = write_file(&td, "fe.crt", &cert_a_pem);
    let key_path = write_file(&td, "fe.key", &key_a_pem);
    let cfg = write_empty_config(&td);

    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let ports = alloc_ports().await;
        let (mut child, capture) = spawn_gateway_piped(
            &cfg,
            &ports,
            &[
                ("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path.as_str()),
                ("FERRUM_FRONTEND_TLS_KEY_PATH", key_path.as_str()),
            ],
        );

        if !wait_for_gateway(ports.admin_http, 60).await {
            let _ = child.kill().await;
            let _ = child.wait().await;
            if attempt < MAX_ATTEMPTS {
                sleep(Duration::from_secs(1)).await;
                continue;
            }
            eprintln!("stderr:\n{}", capture.snapshot().join("\n"));
            panic!("gateway did not become healthy for no-hot-reload test");
        }

        // First handshake — should see the initial cert.
        let initial_cn = fetch_server_cert_cn(ports.proxy_https).await;

        // Overwrite cert+key files with the replacement.
        std::fs::write(&cert_path, &cert_b_pem).unwrap();
        std::fs::write(&key_path, &key_b_pem).unwrap();

        // Give the filesystem a moment; also make several new TLS handshakes so
        // we're not tripping over any in-flight session resumption.
        sleep(Duration::from_millis(500)).await;
        let post_cn = fetch_server_cert_cn(ports.proxy_https).await;

        let _ = child.kill().await;
        let _ = child.wait().await;

        match (initial_cn, post_cn) {
            (Some(a), Some(b)) => {
                assert_eq!(
                    a, b,
                    "Frontend cert hot-reload was triggered (CN changed from '{}' to '{}'). This invariant must hold.",
                    a, b
                );
                assert!(
                    a.contains("initial"),
                    "First handshake expected 'initial.local' CN, got '{}'",
                    a
                );
                return;
            }
            (initial, post) => {
                // Couldn't read certs on this attempt — retry.
                if attempt < MAX_ATTEMPTS {
                    eprintln!(
                        "attempt {}/{}: cert CN fetch returned initial={:?}, post={:?}",
                        attempt, MAX_ATTEMPTS, initial, post
                    );
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
                panic!(
                    "unable to fetch server cert CN to verify no-hot-reload invariant (initial={:?}, post={:?})",
                    initial, post
                );
            }
        }
    }
}

// ----------------------------------------------------------------------------
// TLS introspection helper
// ----------------------------------------------------------------------------

/// Dangerous verifier that captures the first server cert presented.
#[derive(Debug)]
struct CertCapturingVerifier {
    captured: Arc<Mutex<Option<Vec<u8>>>>,
}

impl rustls::client::danger::ServerCertVerifier for CertCapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Ok(mut g) = self.captured.lock() {
            *g = Some(end_entity.as_ref().to_vec());
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Perform a TLS handshake and return the server cert's Common Name (as found in
/// the Subject DN). Returns `None` on any error.
async fn fetch_server_cert_cn(port: u16) -> Option<String> {
    let captured = Arc::new(Mutex::new(None::<Vec<u8>>));
    let verifier = Arc::new(CertCapturingVerifier {
        captured: captured.clone(),
    });
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .ok()?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost")
        .ok()?
        .to_owned();
    let _ = connector.connect(server_name, stream).await.ok()?;
    let der = captured.lock().ok()?.clone()?;
    extract_cn_from_der(&der)
}

/// Best-effort Common Name extraction from a DER-encoded certificate using
/// x509-parser (already a dependency of the main crate and in Cargo.lock).
fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string()))
}

// ============================================================================
// Issue #3857 — live retirement of established frontend mTLS transports when
// CRL or client-CA trust is withdrawn.
//
// These are deliberately NOT bookkeeping tests. Each case establishes a REAL
// TLS connection to a REAL gateway process with a REAL client certificate,
// proves the connection is usable, then changes the operator's CRL or
// client-CA bundle on disk and proves the ORIGINAL transport loses
// authorization WITHOUT the client reconnecting.
// ============================================================================

/// Bound for "the accepted live reload has been observed". The watcher polls at
/// 1s in these tests; this is generous enough for a loaded CI runner while still
/// failing rather than hanging if retirement never happens.
const RETIREMENT_DEADLINE: Duration = Duration::from_secs(45);

/// Client certificate with a caller-chosen serial so a CRL can revoke exactly
/// this leaf. `generate_signed_cert` pins one fixed serial for every leaf, which
/// would make "revoke the client" indistinguishable from "revoke the server".
fn generate_client_cert_with_serial(ca: &GeneratedCa, cn: &str, serial: u64) -> GeneratedCert {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("gen client key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("client params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let serial = SerialNumber::from(serial);
    params.serial_number = Some(serial.clone());
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let cert = params
        .signed_by(&key_pair, &ca.issuer)
        .expect("sign client");
    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        serial,
    }
}

/// Minimal plaintext HTTP/1.1 backend: answers every request with 200 and a
/// fixed JSON body, keeping the connection alive.
fn start_plain_echo_on(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                    let body = r#"{"status":"ok"}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    if sock.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    })
}

/// Build a client `rustls::ClientConfig` that verifies the gateway against
/// `server_ca_pem` and presents `client` as its certificate.
fn mtls_client_config(
    server_ca_pem: &str,
    client: &GeneratedCert,
    alpn: &[&[u8]],
) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut server_ca_pem.as_bytes()) {
        roots.add(cert.expect("parse server CA")).expect("add root");
    }
    let client_chain: Vec<_> = rustls_pemfile::certs(&mut client.cert_pem.as_bytes())
        .map(|c| c.expect("parse client cert"))
        .collect();
    let client_key = rustls_pemfile::private_key(&mut client.key_pem.as_bytes())
        .expect("read client key")
        .expect("client key present");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .with_root_certificates(roots)
        .with_client_auth_cert(client_chain, client_key)
        .expect("client auth cert");
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.resumption = rustls::client::Resumption::disabled();
    config
}

async fn connect_mtls(
    port: u16,
    config: rustls::ClientConfig,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost")
        .expect("server name")
        .to_owned();
    connector.connect(server_name, tcp).await
}

/// Outcome of one request attempt on an already-established transport.
#[derive(Debug, PartialEq, Eq)]
enum AttemptOutcome {
    Status(u16),
    TransportFailed,
}

impl AttemptOutcome {
    fn is_authorized(&self) -> bool {
        matches!(self, AttemptOutcome::Status(200))
    }
}

/// A multiplexed / keep-alive transport that can issue further requests without
/// a new handshake — which is exactly the property under test.
struct EstablishedTransport {
    sender: EstablishedSender,
    _driver: tokio::task::JoinHandle<()>,
}

enum EstablishedSender {
    H1(hyper::client::conn::http1::SendRequest<http_body_util::Empty<bytes::Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<http_body_util::Empty<bytes::Bytes>>),
}

impl EstablishedTransport {
    async fn request(&mut self, authority: &str) -> AttemptOutcome {
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/api/test")
            .header("host", authority)
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .expect("build request");
        let result = match &mut self.sender {
            EstablishedSender::H1(sender) => sender.send_request(req).await,
            EstablishedSender::H2(sender) => {
                let req = hyper::Request::builder()
                    .method("GET")
                    .uri(format!("https://{authority}/api/test"))
                    .body(http_body_util::Empty::<bytes::Bytes>::new())
                    .expect("build h2 request");
                sender.send_request(req).await
            }
        };
        match result {
            Ok(resp) => AttemptOutcome::Status(resp.status().as_u16()),
            Err(_) => AttemptOutcome::TransportFailed,
        }
    }

    /// Poll the SAME transport until it stops being authorized, or the deadline
    /// elapses. Returns the final outcome.
    async fn wait_until_unauthorized(&mut self, authority: &str) -> AttemptOutcome {
        let deadline = tokio::time::Instant::now() + RETIREMENT_DEADLINE;
        let mut last = AttemptOutcome::Status(200);
        while tokio::time::Instant::now() < deadline {
            last = self.request(authority).await;
            if !last.is_authorized() {
                return last;
            }
            sleep(Duration::from_millis(250)).await;
        }
        last
    }
}

async fn establish_h1(
    port: u16,
    config: rustls::ClientConfig,
) -> std::io::Result<EstablishedTransport> {
    let tls = connect_mtls(port, config).await?;
    let io = hyper_util::rt::TokioIo::new(tls);
    let (sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(EstablishedTransport {
        sender: EstablishedSender::H1(sender),
        _driver: driver,
    })
}

async fn establish_h2(
    port: u16,
    config: rustls::ClientConfig,
) -> std::io::Result<EstablishedTransport> {
    let tls = connect_mtls(port, config).await?;
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "the gateway must negotiate HTTP/2 for this case"
    );
    let io = hyper_util::rt::TokioIo::new(tls);
    let (sender, conn) =
        hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(EstablishedTransport {
        sender: EstablishedSender::H2(sender),
        _driver: driver,
    })
}

/// Which frontend listener families a fixture brings up beyond proxy HTTPS.
///
/// Each live test enables only the surface it observes, so a failure in one
/// transport cannot mask or perturb another and teardown stays simple.
#[derive(Clone, Copy, Default)]
struct FixtureSurfaces {
    /// QUIC / HTTP-3 on the same port number as proxy HTTPS.
    http3: bool,
    /// A `/ws` route reaching a WebSocket echo backend, reached over frontend
    /// TLS.
    websocket: bool,
    /// A raw TCP stream listener terminating frontend TLS.
    tcp_tls: bool,
    /// A UDP stream listener terminating frontend DTLS.
    dtls: bool,
}

/// A running gateway with frontend mTLS and client-trust live reload armed.
struct TrustRetirementFixture {
    _dir: TempDir,
    gateway: crate::common::TestGateway,
    ports: Ports,
    client_ca: GeneratedCa,
    client_ca_path: String,
    crl_path: String,
    server_ca_pem: String,
    client_cert: GeneratedCert,
    /// The fixture's client certificate/key on disk, for transports whose
    /// client stack loads PEM files (frontend DTLS).
    client_cert_path: String,
    client_key_path: String,
    revoked_serial: u64,
    metrics_token: String,
    _backends: Vec<tokio::task::JoinHandle<()>>,
}

#[derive(Clone, Copy, Debug, Default)]
enum GlobalCrlFixture {
    #[default]
    Baseline,
    OutsideWithAki,
    OutsideWithoutAki,
    AnchoredWithoutAki,
    UnarmedWithoutAki,
}

impl TrustRetirementFixture {
    async fn try_new_with(surfaces: FixtureSurfaces) -> Option<Self> {
        Self::try_new_with_crl(surfaces, GlobalCrlFixture::Baseline).await
    }

    async fn try_new_with_crl(
        surfaces: FixtureSurfaces,
        crl_case: GlobalCrlFixture,
    ) -> Option<Self> {
        let dir = TempDir::new().unwrap();
        let server_ca = generate_ca("Retirement-Server-CA");
        let server = generate_signed_cert(&server_ca, "localhost", &["localhost", "127.0.0.1"]);
        let client_ca = generate_ca("Retirement-Client-CA");
        let revoked_serial = 0x3857u64;
        let client_cert =
            generate_client_cert_with_serial(&client_ca, "retirement-client", revoked_serial);

        // A baseline CRL revoking an unrelated serial: the file exists and
        // parses, so the first accepted generation is a genuine one and a later
        // rewrite is a real semantic delta rather than "a CRL appeared".
        let outside_ca = generate_ca("Outside-Client-Trust-CA");
        let crl_signer = match crl_case {
            GlobalCrlFixture::Baseline | GlobalCrlFixture::AnchoredWithoutAki => &client_ca,
            _ => &outside_ca,
        };
        let baseline_crl = generate_crl_pem(crl_signer, &[SerialNumber::from(1u64)]);
        let baseline_crl = if matches!(
            crl_case,
            GlobalCrlFixture::OutsideWithoutAki
                | GlobalCrlFixture::AnchoredWithoutAki
                | GlobalCrlFixture::UnarmedWithoutAki
        ) {
            crate::common::crl_fixtures::without_authority_key_identifier(
                &baseline_crl,
                crl_signer.issuer.key(),
                &crl_signer.cert_pem,
            )
        } else {
            baseline_crl
        };

        let cert_path = write_file(&dir, "server.crt", &server.cert_pem);
        let key_path = write_file(&dir, "server.key", &server.key_pem);
        let client_ca_path = write_file(&dir, "client-ca.pem", &client_ca.cert_pem);
        let client_cert_path = write_file(&dir, "client.crt", &client_cert.cert_pem);
        let client_key_path = write_file(&dir, "client.key", &client_cert.key_pem);
        let crl_path = write_file(&dir, "revocations.crl", &baseline_crl);
        // Keep promised listener ports bound while fixture backends start.
        // Only the subprocess bind requires releasing these reservations.
        let https = crate::scaffolding::ports::reserve_port().await.unwrap();
        let stream_tcp = crate::scaffolding::ports::reserve_port().await.unwrap();
        let stream_udp = crate::scaffolding::ports::reserve_udp_port().await.unwrap();
        let mut ports = Ports {
            proxy_http: 0,
            proxy_https: https.port,
            admin_http: 0,
            stream_tcp: stream_tcp.port,
            stream_udp: stream_udp.port,
        };
        let mut backends = Vec::new();
        let mut proxies = String::new();

        let be_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_port = be_listener.local_addr().unwrap().port();
        backends.push(start_plain_echo_on(be_listener));
        proxies.push_str(&format!(
            r#"
  - id: "trust-retirement"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true"#
        ));

        if surfaces.websocket {
            let ws_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let ws_port = ws_listener.local_addr().unwrap().port();
            backends.push(start_ws_echo_on(ws_listener));
            // WebSocket is a runtime flavor, not a backend scheme: an ordinary
            // `http` route carries the Upgrade to a WebSocket backend.
            proxies.push_str(&format!(
                r#"
  - id: "trust-retirement-ws"
    listen_path: "/ws"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {ws_port}
    strip_listen_path: true"#
            ));
        }

        if surfaces.tcp_tls {
            let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tcp_port = tcp_listener.local_addr().unwrap().port();
            backends.push(start_tcp_echo_on(tcp_listener));
            let listen_port = ports.stream_tcp;
            proxies.push_str(&format!(
                r#"
  - id: "trust-retirement-tcp"
    listen_port: {listen_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {tcp_port}
    frontend_tls: true"#
            ));
        }

        if surfaces.dtls {
            let (udp_backend_port, udp_backend) = start_udp_echo().await;
            backends.push(udp_backend);
            let listen_port = ports.stream_udp;
            proxies.push_str(&format!(
                r#"
  - id: "trust-retirement-dtls"
    listen_port: {listen_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {udp_backend_port}
    frontend_tls: true"#
            ));
        }

        let mut config_yaml = String::from("version: \"1\"\nproxies:");
        config_yaml.push_str(&proxies);
        config_yaml.push_str("\nconsumers: []\nupstreams: []\nplugin_configs: []\n");
        let mut envs: Vec<(&str, &str)> = vec![
            ("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path.as_str()),
            ("FERRUM_FRONTEND_TLS_KEY_PATH", key_path.as_str()),
            (
                "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH",
                client_ca_path.as_str(),
            ),
            ("FERRUM_TLS_CRL_FILE_PATH", crl_path.as_str()),
            ("FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED", "true"),
            ("FERRUM_FRONTEND_TLS_WATCH_INTERVAL_SECONDS", "1"),
            ("FERRUM_POOL_WARMUP_ENABLED", "false"),
        ];
        if matches!(crl_case, GlobalCrlFixture::UnarmedWithoutAki) {
            envs.retain(|(name, _)| *name != "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH");
        }
        if surfaces.http3 {
            envs.push(("FERRUM_ENABLE_HTTP3", "true"));
        }
        if surfaces.dtls {
            // The DTLS listener needs its own ECDSA identity and its own
            // client-CA source; the CRL source is the shared one, so one CRL
            // rewrite is a withdrawal for both the TLS and DTLS trust domains.
            envs.push(("FERRUM_DTLS_CERT_PATH", cert_path.as_str()));
            envs.push(("FERRUM_DTLS_KEY_PATH", key_path.as_str()));
            envs.push(("FERRUM_DTLS_CLIENT_CA_CERT_PATH", client_ca_path.as_str()));
        }
        // Shared startup proves authenticated readiness, JWT-only admin
        // ownership and child liveness. A foreign /health cannot admit this
        // fixture (#4740). It does not create an extra mTLS session that could
        // perturb the exactly-one retirement metric asserted below.
        let mut builder = crate::common::TestGateway::builder()
            .mode_file(config_yaml)
            .skip_auto_build()
            .capture_output()
            .log_level("warn")
            .env("RUST_LOG", "ferrum_edge=warn,warn")
            .env("FERRUM_PROXY_HTTPS_PORT", ports.proxy_https.to_string())
            .reserve_listener_port(ports.stream_tcp)
            .reserve_listener_port(ports.stream_udp)
            .health_timeout(Duration::from_secs(15));
        for (key, value) in envs {
            builder = builder.env(key, value);
        }
        https.drop_and_take_port();
        stream_tcp.drop_and_take_port();
        stream_udp.drop_and_take_port();
        let gateway = match builder.spawn_classified().await {
            Ok(gateway) => gateway,
            Err(error) => {
                eprintln!("owned trust-retirement gateway did not start: {error}");
                for backend in backends {
                    backend.abort();
                    let _ = backend.await;
                }
                assert!(
                    error.listener_addr_in_use,
                    "trust-retirement startup failed without a retryable bind race: {error}"
                );
                return None;
            }
        };
        ports.proxy_http = gateway.proxy_port;
        ports.admin_http = gateway.admin_port;
        let metrics_token = gateway.observability_token.clone();

        Some(Self {
            _dir: dir,
            gateway,
            ports,
            client_ca,
            client_ca_path,
            crl_path,
            server_ca_pem: server_ca.cert_pem.clone(),
            client_cert,
            client_cert_path,
            client_key_path,
            revoked_serial,
            metrics_token,
            _backends: backends,
        })
    }

    async fn shutdown(&mut self) {
        self.gateway.shutdown();
        for backend in self._backends.drain(..) {
            backend.abort();
            let _ = backend.await;
        }
    }

    /// Prove the gateway is still the process that refused the request.
    ///
    /// `AttemptOutcome::TransportFailed` is the correct outcome for a retired
    /// transport, but it is also what a dead gateway produces. Asserting the
    /// child has not exited turns "the connection failed" into "the running
    /// gateway closed the connection".
    fn assert_still_running(&mut self, context: &str) {
        assert!(
            self.gateway.is_running(),
            "{context}: the gateway is not confirmed alive after transport refusal; output:\n{}",
            self.gateway.diagnostic_captured_output()
        );
    }

    fn h1_config(&self) -> rustls::ClientConfig {
        mtls_client_config(&self.server_ca_pem, &self.client_cert, &[b"http/1.1"])
    }

    fn h2_config(&self) -> rustls::ClientConfig {
        mtls_client_config(&self.server_ca_pem, &self.client_cert, &[b"h2"])
    }

    /// Publish a CRL that revokes the fixture's client certificate.
    fn revoke_client_certificate(&self) {
        let updated = generate_crl_pem(
            &self.client_ca,
            &[
                SerialNumber::from(1u64),
                SerialNumber::from(self.revoked_serial),
            ],
        );
        std::fs::write(&self.crl_path, updated).expect("rewrite CRL");
    }

    /// Re-issue the SAME revocation set under a new CRL number and validity
    /// window — the shape a scheduled CRL refresh produces.
    fn reissue_same_crl(&self) {
        let mut params = CertificateRevocationListParams {
            this_update: time::OffsetDateTime::now_utc(),
            next_update: time::OffsetDateTime::now_utc() + time::Duration::days(60),
            crl_number: SerialNumber::from(999u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        params.revoked_certs.push(RevokedCertParams {
            serial_number: SerialNumber::from(1u64),
            revocation_time: time::OffsetDateTime::now_utc(),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        });
        let pem = params
            .signed_by(&self.client_ca.issuer)
            .expect("sign re-issued CRL")
            .pem()
            .expect("CRL PEM");
        std::fs::write(&self.crl_path, pem).expect("rewrite CRL");
    }

    /// Replace the client-CA bundle with a completely different CA — the
    /// withdrawal shape that invalidates every chain terminating at the old one.
    fn withdraw_client_ca(&self) {
        let replacement = generate_ca("Replacement-Client-CA");
        std::fs::write(&self.client_ca_path, replacement.cert_pem).expect("rewrite client CA");
    }

    /// Append a second, unrelated CA to the bundle. Additive overlap: the old
    /// anchor is still trusted, so nothing may be retired.
    fn add_overlapping_client_ca(&self) {
        let extra = generate_ca("Additional-Client-CA");
        let bundle = format!("{}{}", self.client_ca.cert_pem, extra.cert_pem);
        std::fs::write(&self.client_ca_path, bundle).expect("rewrite client CA");
    }

    /// Replace the CRL with a well-framed but undecodable PEM record. The
    /// candidate must be refused outright — never summarized into an empty
    /// revocation set, which would look like a widening — and the whole previous
    /// generation retained.
    fn corrupt_crl(&self) {
        std::fs::write(
            &self.crl_path,
            "-----BEGIN X509 CRL-----\n!!! not base64 at all !!!\n-----END X509 CRL-----\n",
        )
        .expect("write malformed CRL");
    }

    async fn scrape_metrics(&self) -> String {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        client
            .get(format!(
                "http://127.0.0.1:{}/metrics",
                self.ports.admin_http
            ))
            .header("Authorization", format!("Bearer {}", self.metrics_token))
            .send()
            .await
            .expect("scrape /metrics")
            .text()
            .await
            .expect("metrics body")
    }
}

impl Drop for TrustRetirementFixture {
    fn drop(&mut self) {
        self.gateway.shutdown();
        for backend in &self._backends {
            backend.abort();
        }
    }
}

/// Spawn the fixture, retrying on port races (never on an observation).
async fn trust_retirement_fixture() -> TrustRetirementFixture {
    trust_retirement_fixture_with(FixtureSurfaces::default()).await
}

async fn trust_retirement_fixture_with(surfaces: FixtureSurfaces) -> TrustRetirementFixture {
    for _ in 0..3u32 {
        if let Some(fixture) = TrustRetirementFixture::try_new_with(surfaces).await {
            return fixture;
        }
        sleep(Duration::from_secs(1)).await;
    }
    panic!("gateway with frontend mTLS + client-trust live reload did not become healthy");
}

/// Minimal WebSocket echo backend: replies `Echo: <text>` and forwards nothing
/// else, so the only reason a client session ends is the gateway ending it.
fn start_ws_echo_on(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::protocol::Message;

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut sink, mut source) = ws.split();
                while let Some(Ok(message)) = source.next().await {
                    if let Message::Text(text) = message {
                        let echo = format!("Echo: {text}");
                        if sink.send(Message::Text(echo.into())).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    })
}

/// Minimal TCP echo backend for the raw TCP+TLS relay.
fn start_tcp_echo_on(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    })
}

/// Minimal UDP echo backend for the frontend DTLS relay. Binds first and
/// reports its own port so there is no reserve-then-rebind race.
async fn start_udp_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp echo backend");
    let port = socket.local_addr().expect("udp echo addr").port();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    let _ = socket.send_to(&buf[..n], peer).await;
                }
                Err(_) => return,
            }
        }
    });
    (port, handle)
}

// ----------------------------------------------------------------------------
// Test 7: an established HTTP/2 connection stops admitting new streams once its
// client certificate is revoked — with no reconnect.
// ----------------------------------------------------------------------------

#[ignore]
#[tokio::test]
async fn test_h2_streams_are_refused_after_crl_revocation_without_reconnect() {
    let mut fixture = trust_retirement_fixture().await;

    let mut transport = establish_h2(fixture.ports.proxy_https, fixture.h2_config())
        .await
        .expect("establish H2 mTLS transport");
    assert_eq!(
        transport.request("localhost").await,
        AttemptOutcome::Status(200),
        "the transport must be usable before the revocation"
    );

    fixture.revoke_client_certificate();

    let outcome = transport.wait_until_unauthorized("localhost").await;
    assert!(
        !outcome.is_authorized(),
        "a NEW stream on the ORIGINAL H2 connection must not be authorized after revocation, got {outcome:?}"
    );
    fixture.assert_still_running("H2 stream refusal after CRL revocation");
    assert!(
        matches!(
            outcome,
            AttemptOutcome::TransportFailed | AttemptOutcome::Status(401)
        ),
        "expected a fixed 401 or a closed transport, got {outcome:?}"
    );

    // The bounded, fixed-cardinality series must show exactly one retirement
    // under the closed CRL reason, and must not carry a serial or a subject.
    let metrics = fixture.scrape_metrics().await;
    assert!(
        metrics.contains(
            "ferrum_frontend_client_trust_retired_connections_total{scope=\"proxy_frontend\",reason=\"crl_changed\"} 1"
        ),
        "expected exactly one CRL-reason retirement in /metrics:\n{metrics}"
    );
    assert!(
        !metrics.contains("retirement-client") && !metrics.contains("14423"),
        "client-trust series must never carry a certificate subject or serial"
    );

    fixture.shutdown().await;
}

// ----------------------------------------------------------------------------
// Test 8: the same for an HTTP/1.1 keep-alive connection.
// ----------------------------------------------------------------------------

#[ignore]
#[tokio::test]
async fn test_h1_keepalive_is_refused_after_crl_revocation_without_reconnect() {
    let mut fixture = trust_retirement_fixture().await;

    let mut transport = establish_h1(fixture.ports.proxy_https, fixture.h1_config())
        .await
        .unwrap_or_else(|error| {
            panic!(
                "establish H1 mTLS transport: {error}; gateway output:\n{}",
                fixture.gateway.diagnostic_captured_output()
            )
        });
    assert_eq!(
        transport.request("localhost").await,
        AttemptOutcome::Status(200),
        "the keep-alive connection must be usable before the revocation"
    );

    fixture.revoke_client_certificate();

    let outcome = transport.wait_until_unauthorized("localhost").await;
    fixture.assert_still_running("H1 keep-alive refusal after CRL revocation");
    assert!(
        !outcome.is_authorized(),
        "a reused H1 keep-alive connection must not be authorized after revocation, got {outcome:?}"
    );
    assert!(
        matches!(
            outcome,
            AttemptOutcome::TransportFailed | AttemptOutcome::Status(401)
        ),
        "expected a fixed 401 or a closed transport, got {outcome:?}"
    );

    // Same bounded, fixed-cardinality proof the H2 sibling makes: without it
    // `TransportFailed` alone does not distinguish "retired by the CRL
    // publication" from "the connection broke for some other reason".
    let metrics = fixture.scrape_metrics().await;
    assert!(
        metrics.contains(
            "ferrum_frontend_client_trust_retired_connections_total{scope=\"proxy_frontend\",reason=\"crl_changed\"} 1"
        ),
        "expected exactly one CRL-reason retirement in /metrics:\n{metrics}"
    );
    assert!(
        !metrics.contains("retirement-client") && !metrics.contains("14423"),
        "client-trust series must never carry a certificate subject or serial"
    );

    fixture.shutdown().await;
}

// ----------------------------------------------------------------------------
// Test 9: removing the issuing CA from the client-CA bundle retires the
// established transport, and a fresh handshake with the same certificate is
// refused outright by the new verifier.
// ----------------------------------------------------------------------------

#[ignore]
#[tokio::test]
async fn test_client_ca_withdrawal_retires_established_transport_and_new_handshakes() {
    let mut fixture = trust_retirement_fixture().await;

    let mut transport = establish_h2(fixture.ports.proxy_https, fixture.h2_config())
        .await
        .expect("establish H2 mTLS transport");
    assert_eq!(
        transport.request("localhost").await,
        AttemptOutcome::Status(200)
    );

    fixture.withdraw_client_ca();

    let outcome = transport.wait_until_unauthorized("localhost").await;
    assert!(
        !outcome.is_authorized(),
        "removing the issuing CA must retire the established transport, got {outcome:?}"
    );
    fixture.wait_for_accepted_withdrawal("proxy_frontend").await;

    // A brand-new connection must meet the new verifier only. The old client
    // certificate no longer chains to any trusted anchor. Session resumption is
    // disabled on this client so a ticket issued under the withdrawn generation
    // cannot masquerade as a new handshake.
    //
    // The refusal is observed by DRIVING the fresh transport, not by the
    // handshake call returning an error. A TLS 1.3 client finishes its own
    // handshake before the server has even parsed its Certificate message
    // (tokio-rustls returns as soon as `is_handshaking()` clears), and hyper's
    // HTTP/2 client handshake only writes the connection preface — it never
    // reads from the peer. Both therefore report success against an accepting
    // *and* a refusing gateway, so `establish_h2(..).is_err()` alone can
    // neither pass here nor fail on a real regression. Requiring the fresh
    // transport to be unable to carry an authorized request is the strictly
    // stronger property: a gateway that still served the withdrawn credential
    // answers 200 and fails this loop.
    let deadline = tokio::time::Instant::now() + RETIREMENT_DEADLINE;
    let mut refused = false;
    while tokio::time::Instant::now() < deadline {
        refused = match establish_h2(fixture.ports.proxy_https, fixture.h2_config()).await {
            // Refused outright at the transport — the handshake or the h2
            // preface exchange failed.
            Err(_) => true,
            // Established at the wire level: the credential must still buy
            // nothing. A retired/refused transport fails, and the pre-routing
            // fence answers a fixed 401; only a 200 is authorization.
            Ok(mut fresh) => !fresh.request("localhost").await.is_authorized(),
        };
        if refused {
            break;
        }
        sleep(Duration::from_millis(250)).await;
    }
    assert!(
        refused,
        "a connection established after the accepted reload must use ONLY the new verifier"
    );

    let metrics = fixture.scrape_metrics().await;
    assert!(
        metrics.contains(
            "ferrum_frontend_client_trust_retired_connections_total{scope=\"proxy_frontend\",reason=\"client_ca_withdrawn\"} 1"
        ),
        "expected exactly one CA-withdrawal retirement in /metrics:\n{metrics}"
    );

    fixture.shutdown().await;
}

// ----------------------------------------------------------------------------
// Test 10: a malformed replacement CRL retains the prior verifier, generation,
// and live sessions; and a routine CRL re-issue over the same revocation set
// does not churn anything either.
// ----------------------------------------------------------------------------

#[ignore]
#[tokio::test]
async fn test_malformed_and_noop_candidates_retain_established_transports() {
    let mut fixture = trust_retirement_fixture().await;

    let mut transport = establish_h2(fixture.ports.proxy_https, fixture.h2_config())
        .await
        .expect("establish H2 mTLS transport");
    assert_eq!(
        transport.request("localhost").await,
        AttemptOutcome::Status(200)
    );

    // (a) Truncated CRL — refused candidate.
    fixture.corrupt_crl();
    sleep(Duration::from_secs(6)).await;
    assert_eq!(
        transport.request("localhost").await,
        AttemptOutcome::Status(200),
        "a malformed CRL candidate must retain the prior verifier and live sessions"
    );

    // (b) Same revocation set, new CRL number and validity window.
    fixture.reissue_same_crl();
    sleep(Duration::from_secs(6)).await;
    assert_eq!(
        transport.request("localhost").await,
        AttemptOutcome::Status(200),
        "a routine CRL re-issue must not retire an unaffected session"
    );

    let metrics = fixture.scrape_metrics().await;
    assert!(
        metrics.contains(
            "ferrum_frontend_client_trust_retired_connections_total{scope=\"proxy_frontend\",reason=\"crl_changed\"} 0"
        ) && metrics.contains(
            "ferrum_frontend_client_trust_retired_connections_total{scope=\"proxy_frontend\",reason=\"client_ca_withdrawn\"} 0"
        ),
        "no retirement may be recorded for a refused or no-op candidate:\n{metrics}"
    );
    assert!(
        metrics.contains(concat!(
            "ferrum_frontend_client_trust_rejected_candidates_total",
            "{scope=\"proxy_frontend\"}"
        )),
        "the rejected-candidate series must be exported so a refused reload is observable:\n{metrics}"
    );
    assert!(
        metrics.contains(
            "ferrum_frontend_client_trust_publications_total{scope=\"proxy_frontend\",outcome=\"withdrawn\"} 0"
        ),
        "neither a refused nor a no-op candidate may publish a withdrawal:\n{metrics}"
    );

    fixture.shutdown().await;
}

// ----------------------------------------------------------------------------
// Test 11: an additive, overlapping client-CA rotation does not retire an
// unaffected established transport.
// ----------------------------------------------------------------------------

#[ignore]
#[tokio::test]
async fn test_additive_client_ca_overlap_does_not_retire_unaffected_transports() {
    let mut fixture = trust_retirement_fixture().await;

    let mut transport = establish_h2(fixture.ports.proxy_https, fixture.h2_config())
        .await
        .expect("establish H2 mTLS transport");
    assert_eq!(
        transport.request("localhost").await,
        AttemptOutcome::Status(200)
    );

    fixture.add_overlapping_client_ca();
    sleep(Duration::from_secs(8)).await;

    assert_eq!(
        transport.request("localhost").await,
        AttemptOutcome::Status(200),
        "an overlap rotation that only ADDS an anchor must leave established sessions alone"
    );

    let metrics = fixture.scrape_metrics().await;
    assert!(
        metrics.contains(
            "ferrum_frontend_client_trust_publications_total{scope=\"proxy_frontend\",outcome=\"advanced\"} 1"
        ),
        "the additive rotation must advance the generation without withdrawing:\n{metrics}"
    );
    assert!(
        metrics.contains(
            "ferrum_frontend_client_trust_publications_total{scope=\"proxy_frontend\",outcome=\"withdrawn\"} 0"
        ),
        "no withdrawal may be recorded for an additive rotation:\n{metrics}"
    );

    fixture.shutdown().await;
}

// ============================================================================
// Issue #3857 — live retirement of the remaining established authenticated
// transports: HTTP/3, WebSocket over frontend TLS, raw TCP+TLS, and frontend
// DTLS.
//
// Each case brings up only the listener family it observes, establishes a REAL
// authenticated session through a REAL gateway process, proves that session is
// usable, then rewrites the operator's CRL and proves the ORIGINAL session
// loses authorization — bounded, and without the client reconnecting.
// ============================================================================

impl TrustRetirementFixture {
    /// Client config with no ALPN, for the raw TCP+TLS relay where no
    /// application protocol is negotiated.
    fn raw_stream_config(&self) -> rustls::ClientConfig {
        mtls_client_config(&self.server_ca_pem, &self.client_cert, &[])
    }

    /// Block until the gateway has ACCEPTED a withdrawal on `scope`, so a later
    /// observation cannot be a false positive taken before the reload landed.
    ///
    /// The publication counter is the gateway's own record that the candidate
    /// was accepted and narrowed authority — not a sleep, and not the outcome
    /// under test.
    async fn wait_for_accepted_withdrawal(&self, scope: &str) {
        let needle = format!(
            "ferrum_frontend_client_trust_publications_total{{scope=\"{scope}\",outcome=\"withdrawn\"}} 1"
        );
        let deadline = tokio::time::Instant::now() + RETIREMENT_DEADLINE;
        while tokio::time::Instant::now() < deadline {
            if self.scrape_metrics().await.contains(&needle) {
                return;
            }
            sleep(Duration::from_millis(250)).await;
        }
        panic!("the gateway never accepted a client-trust withdrawal on scope '{scope}'");
    }

    /// A DTLS client presenting this fixture's client certificate.
    async fn connect_dtls(&self) -> Result<ferrum_edge::dtls::DtlsConnection, anyhow::Error> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        socket
            .connect(format!("127.0.0.1:{}", self.ports.stream_udp))
            .await?;
        let params = ferrum_edge::dtls::BackendDtlsParams {
            config: Arc::new(dimpl::Config::default()),
            certificate: ferrum_edge::dtls::load_dtls_certificate(
                &self.client_cert_path,
                &self.client_key_path,
            )?,
            // The gateway identity is not what this test is about; the client
            // certificate the gateway verifies is.
            server_name: None,
            server_cert_verifier: None,
            connect_timeout_ms: 5_000,
        };
        ferrum_edge::dtls::DtlsConnection::connect(socket, params).await
    }
}

// ----------------------------------------------------------------------------
// Test 12: a new request stream on the ORIGINAL client-certificate-authenticated
// QUIC/HTTP-3 connection is refused (or the connection closes) after the
// revocation is accepted, and a fresh handshake meets only the new verifier.
// ----------------------------------------------------------------------------

#[ignore]
#[tokio::test]
async fn test_h3_streams_are_refused_after_crl_revocation_without_reconnect() {
    let mut fixture = trust_retirement_fixture_with(FixtureSurfaces {
        http3: true,
        ..FixtureSurfaces::default()
    })
    .await;
    let url = format!("https://localhost:{}/api/test", fixture.ports.proxy_https);

    let client = crate::scaffolding::Http3Client::insecure_with_client_auth(
        &fixture.client_cert.cert_pem,
        &fixture.client_cert.key_pem,
    )
    .expect("build an H3 mTLS client");

    // A QUIC/H3 connection that survives across requests — the property under
    // test is that a LATER stream on THIS connection stops being authorized.
    let mut connection = None;
    let deadline = tokio::time::Instant::now() + RETIREMENT_DEADLINE;
    while tokio::time::Instant::now() < deadline {
        if let Ok(established) = client.connect(&url).await {
            connection = Some(established);
            break;
        }
        sleep(Duration::from_millis(250)).await;
    }
    let mut connection = connection.expect("establish an H3 mTLS connection to the gateway");
    assert_eq!(
        connection
            .get(&url)
            .await
            .expect("first H3 request on the established connection")
            .status
            .as_u16(),
        200,
        "the H3 connection must be usable before the revocation"
    );

    fixture.revoke_client_certificate();

    // Poll the SAME QUIC connection. The gateway either refuses the new stream
    // before routing or closes the connection outright; both are the retirement
    // taking effect on the ORIGINAL transport, and neither is a reconnect.
    let deadline = tokio::time::Instant::now() + RETIREMENT_DEADLINE;
    let mut retirement = None;
    while tokio::time::Instant::now() < deadline {
        match connection.get(&url).await {
            Ok(response) if response.status.as_u16() == 200 => {
                sleep(Duration::from_millis(250)).await;
            }
            Ok(response) => {
                retirement = Some(format!("refused with status {}", response.status));
                break;
            }
            Err(_) => {
                retirement = Some("connection closed".to_string());
                break;
            }
        }
    }
    assert!(
        retirement.is_some(),
        "a NEW stream on the ORIGINAL H3 connection must not be authorized after the accepted revocation"
    );
    fixture.wait_for_accepted_withdrawal("proxy_h3").await;

    // A brand-new QUIC connection must meet ONLY the accepted verifier: the
    // revoked client certificate no longer passes revocation checking. This is
    // what proves the endpoint installed the same generation it published,
    // rather than only tearing the old one down.
    //
    // As on the H1/H2 side, the refusal is observed by DRIVING the fresh
    // connection. quinn signals `Connected` to the client the moment its own
    // TLS handshake stops handshaking — before the server has processed the
    // client's Certificate — and `h3::client::new` only opens a local
    // unidirectional stream and buffers SETTINGS, so neither call reads the
    // server's rejection. A request on the fresh connection is what the
    // withdrawn credential must not be able to buy.
    let fresh = crate::scaffolding::Http3Client::insecure_with_client_auth(
        &fixture.client_cert.cert_pem,
        &fixture.client_cert.key_pem,
    )
    .expect("build a second H3 mTLS client");
    let deadline = tokio::time::Instant::now() + RETIREMENT_DEADLINE;
    let mut refused_handshake = false;
    while tokio::time::Instant::now() < deadline {
        refused_handshake = match fresh.connect(&url).await {
            // Refused outright: the QUIC connection was closed before H3 setup
            // completed.
            Err(_) => true,
            // Established at the wire level: the revoked credential must still
            // buy nothing. The connection closes, or the stream-admission fence
            // refuses before routing; only a 200 is authorization.
            Ok(mut established) => match established.get(&url).await {
                Ok(response) => response.status.as_u16() != 200,
                Err(_) => true,
            },
        };
        if refused_handshake {
            break;
        }
        sleep(Duration::from_millis(250)).await;
    }
    assert!(
        refused_handshake,
        "a connection established after the accepted reload must use ONLY the new H3 verifier"
    );

    let metrics = fixture.scrape_metrics().await;
    assert!(
        metrics.contains(
            "ferrum_frontend_client_trust_retired_connections_total{scope=\"proxy_h3\",reason=\"crl_changed\"} 1"
        ),
        "the H3 scope must record exactly one CRL-reason retirement:\n{metrics}"
    );
    assert!(
        !metrics.contains("retirement-client"),
        "client-trust series must never carry a certificate subject"
    );

    fixture.shutdown().await;
}

// ----------------------------------------------------------------------------
// Test 13: an established WebSocket session over frontend TLS terminates
// through its ordinary bounded relay teardown after the withdrawal.
// ----------------------------------------------------------------------------

#[ignore]
#[tokio::test]
async fn test_websocket_over_frontend_tls_terminates_after_crl_revocation() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::protocol::Message;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    let mut fixture = trust_retirement_fixture_with(FixtureSurfaces {
        websocket: true,
        ..FixtureSurfaces::default()
    })
    .await;

    let tls = connect_mtls(fixture.ports.proxy_https, fixture.h1_config())
        .await
        .expect("establish the frontend mTLS transport the WebSocket rides on");
    let ws_url = format!("wss://localhost:{}/ws", fixture.ports.proxy_https);
    let request = ws_url
        .as_str()
        .into_client_request()
        .expect("build the WebSocket upgrade request");
    let (mut ws, response) = tokio_tungstenite::client_async(request, tls)
        .await
        .expect("WebSocket upgrade over frontend mTLS");
    assert_eq!(
        response.status().as_u16(),
        101,
        "the upgrade must complete before the revocation"
    );

    ws.send(Message::Text("hello".to_string().into()))
        .await
        .expect("send the pre-revocation frame");
    let echo = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .expect("pre-revocation echo timed out")
        .expect("the WebSocket session must be open")
        .expect("the pre-revocation echo must arrive");
    assert_eq!(
        echo,
        Message::Text("Echo: hello".to_string().into()),
        "the established WebSocket session must be usable before the revocation"
    );

    fixture.revoke_client_certificate();

    // The session must end. A frame-parsed relay delivers the bounded policy
    // Close first; a tunnel relay drops the upgraded sockets. Either way the
    // ORIGINAL session stops — and if a Close frame is delivered it must carry
    // the bounded policy code, never a certificate field.
    let deadline = tokio::time::Instant::now() + RETIREMENT_DEADLINE;
    let mut terminated = false;
    while tokio::time::Instant::now() < deadline {
        // Hoisted out of the `match` scrutinee: the borrow of `ws` must end
        // before an arm can drive the session again.
        let polled = tokio::time::timeout(Duration::from_secs(2), ws.next()).await;
        match polled {
            Ok(None) | Ok(Some(Err(_))) => {
                terminated = true;
                break;
            }
            Ok(Some(Ok(Message::Close(frame)))) => {
                if let Some(frame) = frame {
                    assert_eq!(
                        frame.code,
                        CloseCode::Policy,
                        "a gateway-initiated trust close must use the bounded policy code"
                    );
                    assert!(
                        !frame.reason.contains("retirement-client")
                            && !frame.reason.contains("14423"),
                        "the close reason must not carry a certificate subject or serial"
                    );
                }
                terminated = true;
                break;
            }
            Ok(Some(Ok(_))) => {}
            Err(_) => {
                // No frame within this window: keep driving the session so a
                // terminated tunnel surfaces as a write/read failure rather
                // than as silence.
                if ws
                    .send(Message::Text("still-there".to_string().into()))
                    .await
                    .is_err()
                {
                    terminated = true;
                    break;
                }
            }
        }
    }
    assert!(
        terminated,
        "the ESTABLISHED WebSocket session must terminate after its client certificate is revoked"
    );

    let metrics = fixture.scrape_metrics().await;
    assert!(
        metrics.contains(
            "ferrum_frontend_client_trust_retired_connections_total{scope=\"proxy_frontend\",reason=\"crl_changed\"} 1"
        ),
        "the WebSocket's underlying frontend transport must be recorded as retired once:\n{metrics}"
    );

    fixture.shutdown().await;
}

// ----------------------------------------------------------------------------
// Test 14: an established raw TCP+TLS relay terminates through its ordinary
// bounded teardown after the withdrawal.
// ----------------------------------------------------------------------------

#[ignore]
#[tokio::test]
async fn test_tcp_tls_relay_terminates_after_crl_revocation() {
    let mut fixture = trust_retirement_fixture_with(FixtureSurfaces {
        tcp_tls: true,
        ..FixtureSurfaces::default()
    })
    .await;

    let mut relay = None;
    let deadline = tokio::time::Instant::now() + RETIREMENT_DEADLINE;
    while tokio::time::Instant::now() < deadline {
        let attempt = connect_mtls(fixture.ports.stream_tcp, fixture.raw_stream_config()).await;
        if let Ok(stream) = attempt {
            relay = Some(stream);
            break;
        }
        sleep(Duration::from_millis(250)).await;
    }
    let mut relay = relay.expect("establish a TCP+TLS mTLS relay through the gateway");

    relay
        .write_all(b"ping")
        .await
        .expect("write through the established relay");
    let mut echo = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), relay.read_exact(&mut echo))
        .await
        .expect("pre-revocation echo timed out")
        .expect("the relay must be usable before the revocation");
    assert_eq!(
        &echo, b"ping",
        "the established TCP+TLS relay must round-trip before the revocation"
    );

    fixture.revoke_client_certificate();

    // The client leg fails through the relay's ordinary error path, so the
    // socket closes. Reading is the bounded observation: a retired relay ends
    // in EOF or a transport error, never in another echo.
    let deadline = tokio::time::Instant::now() + RETIREMENT_DEADLINE;
    let mut terminated = false;
    let mut buf = [0u8; 64];
    while tokio::time::Instant::now() < deadline {
        // Keep the relay active so a terminated session surfaces promptly
        // rather than waiting on an idle timer.
        if relay.write_all(b"ping").await.is_err() {
            terminated = true;
            break;
        }
        match tokio::time::timeout(Duration::from_secs(2), relay.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {
                terminated = true;
                break;
            }
            Ok(Ok(_)) | Err(_) => {}
        }
    }
    assert!(
        terminated,
        "the ESTABLISHED TCP+TLS relay must terminate after its client certificate is revoked"
    );

    let metrics = fixture.scrape_metrics().await;
    assert!(
        metrics.contains(
            "ferrum_frontend_client_trust_retired_connections_total{scope=\"proxy_frontend\",reason=\"crl_changed\"} 1"
        ),
        "the TCP+TLS relay must be recorded as retired exactly once:\n{metrics}"
    );

    fixture.shutdown().await;
}

// ----------------------------------------------------------------------------
// Test 15: an established frontend DTLS session terminates after the
// withdrawal, and a reconnect under the withdrawn credential is refused.
// ----------------------------------------------------------------------------

#[ignore]
#[tokio::test]
async fn test_frontend_dtls_session_is_retired_and_reconnect_refused_after_crl_revocation() {
    let mut fixture = trust_retirement_fixture_with(FixtureSurfaces {
        dtls: true,
        ..FixtureSurfaces::default()
    })
    .await;

    let mut session = None;
    let deadline = tokio::time::Instant::now() + RETIREMENT_DEADLINE;
    while tokio::time::Instant::now() < deadline {
        if let Ok(conn) = fixture.connect_dtls().await {
            session = Some(conn);
            break;
        }
        sleep(Duration::from_millis(250)).await;
    }
    let session = session.expect("establish a client-certificate-authenticated DTLS session");

    session
        .send(b"dtls-ping")
        .await
        .expect("send on the established DTLS session");
    let reply = tokio::time::timeout(Duration::from_secs(10), session.recv())
        .await
        .expect("pre-revocation DTLS echo timed out")
        .expect("pre-revocation DTLS echo failed");
    assert_eq!(
        reply.as_slice(),
        b"dtls-ping".as_slice(),
        "the established DTLS session must relay before the revocation"
    );

    fixture.revoke_client_certificate();
    // Gate on the gateway's own record that the candidate was ACCEPTED and
    // narrowed authority, so "no echo came back" below cannot be a false
    // positive observed before the reload landed.
    fixture.wait_for_accepted_withdrawal("frontend_dtls").await;

    // The DTLS session driver breaks through the same path the shutdown arm
    // uses, so the gateway stops relaying for THIS peer. The bounded
    // observation is that a datagram on the ORIGINAL session is no longer
    // echoed, where moments ago it round-tripped in microseconds.
    let deadline = tokio::time::Instant::now() + RETIREMENT_DEADLINE;
    let mut retired = false;
    while tokio::time::Instant::now() < deadline {
        if session.send(b"dtls-ping").await.is_err() {
            retired = true;
            break;
        }
        let polled = tokio::time::timeout(Duration::from_secs(2), session.recv()).await;
        match polled {
            // A relayed echo means the session is still authorized.
            Ok(Ok(_)) => sleep(Duration::from_millis(250)).await,
            // The session ended, or stopped being relayed for two whole
            // seconds while the backend echoes in microseconds.
            Ok(Err(_)) | Err(_) => {
                retired = true;
                break;
            }
        }
    }
    assert!(
        retired,
        "the ESTABLISHED DTLS session must stop being relayed after its client certificate is revoked"
    );

    // ...and the withdrawn credential cannot come back through a new handshake.
    // dimpl may emit local `Connected` before the server has refused the
    // certificate, so `connect()` Ok is not admission: a handshake the
    // accepted verifier refused cannot relay.
    let deadline = tokio::time::Instant::now() + RETIREMENT_DEADLINE;
    let mut reconnect_refused = false;
    while tokio::time::Instant::now() < deadline {
        match fixture.connect_dtls().await {
            Err(_) => {
                reconnect_refused = true;
                break;
            }
            Ok(conn) => {
                if conn.send(b"dtls-ping").await.is_err() {
                    reconnect_refused = true;
                    break;
                }
                match tokio::time::timeout(Duration::from_secs(2), conn.recv()).await {
                    Ok(Ok(_)) => sleep(Duration::from_millis(250)).await,
                    Ok(Err(_)) | Err(_) => {
                        reconnect_refused = true;
                        break;
                    }
                }
            }
        }
    }
    assert!(
        reconnect_refused,
        "a DTLS handshake presenting the revoked client certificate must be refused by the accepted verifier"
    );

    let metrics = fixture.scrape_metrics().await;
    assert!(
        metrics.contains(
            "ferrum_frontend_client_trust_retired_connections_total{scope=\"frontend_dtls\",reason=\"crl_changed\"} 1"
        ),
        "the frontend DTLS scope must record exactly one CRL-reason retirement:\n{metrics}"
    );
    assert!(
        !metrics.contains("retirement-client"),
        "client-trust series must never carry a certificate subject"
    );

    session.close().await;
    fixture.shutdown().await;
}

#[ignore]
#[tokio::test]
async fn test_global_crl_without_aki_allows_frontend_mtls_startup() {
    for crl_case in [
        GlobalCrlFixture::OutsideWithoutAki,
        GlobalCrlFixture::OutsideWithAki,
        GlobalCrlFixture::AnchoredWithoutAki,
        GlobalCrlFixture::UnarmedWithoutAki,
    ] {
        let mut started = None;
        for _ in 0..3 {
            started =
                TrustRetirementFixture::try_new_with_crl(FixtureSurfaces::default(), crl_case)
                    .await;
            if started.is_some() {
                break;
            }
            // Only the classified bind-race return reaches this retry.
            sleep(Duration::from_secs(1)).await;
        }
        let mut fixture = started.unwrap_or_else(|| panic!("CRL startup case {crl_case:?}"));
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut transport = establish_h1(fixture.ports.proxy_https, fixture.h1_config())
                .await
                .unwrap_or_else(|error| panic!("CRL {crl_case:?} mTLS handshake: {error}"));
            assert_eq!(
                transport.request("localhost").await,
                AttemptOutcome::Status(200),
                "CRL startup case {crl_case:?} must serve"
            );
        })
        .await
        .expect("CRL startup case must complete a real frontend request");
        fixture.assert_still_running("global CRL startup control");
        fixture.shutdown().await;
    }
}
