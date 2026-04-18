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
}

async fn alloc_ports() -> Ports {
    Ports {
        proxy_http: alloc_port().await,
        proxy_https: alloc_port().await,
        admin_http: alloc_port().await,
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
        "proxies: []\nconsumers: []\nupstreams: []\nplugin_configs: []\n",
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
        // tracing-appender buffer.
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
proxies:
  - id: "crl-test"
    listen_path: "/api"
    backend_protocol: https
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
proxies:
  - id: "crl-unrelated"
    listen_path: "/api"
    backend_protocol: https
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
