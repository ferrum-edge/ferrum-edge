//! Live HTTP/3 acceptance coverage for the authenticated-stream authorization
//! lifetime (issues #3815 / #3816).
//!
//! These tests spawn the real `ferrum-edge` binary with a real QUIC/HTTP/3
//! frontend and real backends, authenticate with a real short-lived HS256 JWT
//! through the production `jwt_auth` plugin, and then hold each admitted stream
//! open past the credential's authoritative `exp` while the backend keeps
//! producing. Nothing here inspects source text, and nothing exercises a
//! standalone helper: every assertion is made on the QUIC wire through the
//! production listener and the production relay loops.
//!
//! Production paths covered:
//!
//! * `http3::server` — the inline native-H3 → native-H3 streaming response
//!   relay (`FERRUM_ENABLE_HTTP3` frontend, `h3=supported` backend).
//! * `http3::cross_protocol::dispatch_plain` — the streaming request-upload
//!   bridge, whose expiry is pre-commitment and therefore a fixed `401`.
//! * `http3::cross_protocol::stream_hyper_incoming` — native gRPC (clean
//!   `grpc-status: 16` before DATA, deterministic reset after DATA) and the
//!   gRPC-Web translation of the same terminal into a bounded trailer frame.
//! * The shared downstream-write seam
//!   (`http3::stream_util::await_authorized_response_write`) on a client that
//!   stops reading: `send_data`/`finish` park in QUIC flow control, so the
//!   relay never returns to its own `select!` and only a deadline raced around
//!   the WRITE can end the stream. Covered for native gRPC, for the plain/SSE
//!   native-H3 relay, and for the plain/SSE cross-protocol relay, each with a
//!   4 KiB per-stream receive window so the very first downstream write
//!   provably parks.
//! * The same native-H3 streaming relay stalled specifically at response
//!   HEADERS (`stream_util::commit_authorized_streaming_response_headers`):
//!   a non-reading client plus an oversized HEADERS block that exceeds the
//!   4 KiB stream window parks `send_response` itself, so no protected head
//!   can commit after the credential expires.
//! * The request direction under CONTINUOUS activity as well as under a stall,
//!   proving relayed request DATA cannot buy extra authorized lifetime.
//!
//! Every test asserts the stream is *usable before* the deadline, terminates
//! within a bounded grace *at* the deadline despite continued backend activity,
//! and that the bounded, fixed-cardinality `credential_expired` counter for the
//! right protocol family incremented **exactly once** on a freshly spawned
//! gateway process — which is also the proof that the terminal accounting fired
//! once rather than per frame.
//!
//! Run with:
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests h3_auth_lifetime -- --ignored --nocapture
//! ```

use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};

use crate::scaffolding::backends::{
    GrpcStep, H2Step, H3Step, H3TlsConfig, MatchHeaders, MatchRpc, ScriptedGrpcBackend,
    ScriptedH2Backend, ScriptedH3Backend, ScriptedTlsBackend, TcpStep, TlsConfig,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::{reserve_colocated_tcp_udp, reserve_port};

/// Consumer identity and shared HMAC secret used by every test in this file.
const CONSUMER: &str = "h3-lifetime-alice";
const JWT_SECRET: &str = "h3-auth-lifetime-shared-hmac-secret-2026";

/// Seconds of credential validity granted to each stream.
///
/// `credential_deadline_from_unix_seconds` floors `exp - now` to whole seconds,
/// so the effective monotonic deadline lands `TOKEN_TTL_SECS - 1 ..= TOKEN_TTL_SECS`
/// after the request. Large enough to establish the stream and prove it usable,
/// small enough that the test finishes quickly.
const TOKEN_TTL_SECS: i64 = 6;

/// Bounded grace allowed between the credential deadline and the observed
/// termination. Generous enough for a loaded CI runner, far below the
/// multi-minute lifetime the backends in this file would otherwise keep alive.
const TERMINATION_GRACE: Duration = Duration::from_secs(12);

/// Mint a real HS256 JWT for `CONSUMER` whose `exp` is `TOKEN_TTL_SECS` in the
/// future. The gateway's `jwt_auth` plugin validates it and publishes the
/// authoritative deadline onto the request.
fn mint_short_lived_token() -> String {
    let now = Utc::now();
    let claims = json!({
        "sub": CONSUMER,
        "iat": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(TOKEN_TTL_SECS)).timestamp(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .expect("encode short-lived consumer JWT")
}

/// File-mode YAML for one `jwt_auth`-protected HTTPS proxy at `/api`.
///
/// `backend_read_timeout_ms` is deliberately far larger than the credential
/// TTL so the authorization deadline — not a backend watchdog — is provably
/// the bound that terminates each stream.
fn protected_proxy_yaml(backend_port: u16) -> String {
    protected_proxy_yaml_with_read_timeout(backend_port, 60000)
}

/// [`protected_proxy_yaml`] with an explicit `backend_read_timeout_ms`.
///
/// `0` disables the operator fallback entirely, which — combined with a client
/// that sends no `grpc-timeout` — leaves the authorization deadline as the only
/// bound on a dispatch phase.
fn protected_proxy_yaml_with_read_timeout(backend_port: u16, read_timeout_ms: u64) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h3-auth-lifetime",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 5000,
            "backend_read_timeout_ms": read_timeout_ms,
            "backend_write_timeout_ms": 60000,
            "backend_tls_verify_server_cert": false,
            "plugins": [{"plugin_config_id": "h3-auth-lifetime-jwt"}],
        }],
        "consumers": [{
            "id": CONSUMER,
            "username": CONSUMER,
            "credentials": {"jwt": [{"secret": JWT_SECRET}]},
        }],
        "upstreams": [],
        "plugin_configs": [{
            "id": "h3-auth-lifetime-jwt",
            "plugin_name": "jwt_auth",
            "scope": "proxy",
            "proxy_id": "h3-auth-lifetime",
            "enabled": true,
            "config": {
                "token_lookup": "header:Authorization",
                "consumer_claim_field": "sub",
            },
        }],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

/// [`protected_proxy_yaml`] with the `grpc_web` translator enabled.
///
/// The shared wire classifier deliberately leaves `application/grpc-web*` as a
/// pass-through representation: the gateway promotes the request to effective
/// gRPC for policy, but the BACKEND transport is promoted — and the response
/// body translated — only once the `grpc_web` plugin stamps its trusted
/// translation marker. Without it, a plugin-free deployment relays the backend's
/// native `application/grpc` response untouched, which is a different contract
/// from the one the gRPC-Web terminal test asserts.
fn grpc_web_protected_proxy_yaml(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h3-auth-lifetime",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 5000,
            "backend_read_timeout_ms": 60000,
            "backend_write_timeout_ms": 60000,
            "backend_tls_verify_server_cert": false,
            "plugins": [
                {"plugin_config_id": "h3-auth-lifetime-jwt"},
                {"plugin_config_id": "h3-auth-lifetime-grpc-web"},
            ],
        }],
        "consumers": [{
            "id": CONSUMER,
            "username": CONSUMER,
            "credentials": {"jwt": [{"secret": JWT_SECRET}]},
        }],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "h3-auth-lifetime-jwt",
                "plugin_name": "jwt_auth",
                "scope": "proxy",
                "proxy_id": "h3-auth-lifetime",
                "enabled": true,
                "config": {
                    "token_lookup": "header:Authorization",
                    "consumer_claim_field": "sub",
                },
            },
            {
                "id": "h3-auth-lifetime-grpc-web",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "h3-auth-lifetime",
                "enabled": true,
                "config": {},
            },
        ],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("h3-auth-lifetime-gw").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let cert_path = scratch.join("gw.cert.pem");
    let key_path = scratch.join("gw.key.pem");
    std::fs::write(&cert_path, &cert).expect("write cert");
    std::fs::write(&key_path, &key).expect("write key");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

/// Spawn a gateway with an HTTP/3 frontend on an explicit, retried QUIC port.
/// Mirrors `scripted_backend_h3_tests::spawn_h3_harness_with_explicit_https_port`:
/// an env-pinned QUIC port cannot be reused after a failed startup, so every
/// attempt takes a fresh port and a fresh scratch directory.
async fn spawn_h3_gateway(yaml: String, pool_warmup: bool) -> (GatewayHarness, u16) {
    const STARTUP_ATTEMPTS: u32 = 3;
    let mut last_error = None;
    for attempt in 1..=STARTUP_ATTEMPTS {
        let reservation = reserve_port().await.expect("reserve https port");
        let https_port = reservation.port;
        drop(reservation);

        let scratch = tempfile::tempdir().expect("scratch");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());
        let builder = GatewayHarness::builder()
            .file_config(yaml.clone())
            .log_level("info")
            .capture_output()
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .env("FERRUM_TLS_NO_VERIFY", "true")
            .env(
                "FERRUM_POOL_WARMUP_ENABLED",
                if pool_warmup { "true" } else { "false" },
            );

        match builder.spawn().await {
            Ok(harness) => {
                Box::leak(Box::new(scratch));
                return (harness, https_port);
            }
            Err(error) => {
                eprintln!(
                    "H3 auth-lifetime harness attempt {attempt}/{STARTUP_ATTEMPTS} failed: {error}"
                );
                last_error = Some(error.to_string());
                if attempt < STARTUP_ATTEMPTS {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!(
        "H3 auth-lifetime harness failed after {STARTUP_ATTEMPTS} attempts: {}",
        last_error.unwrap_or_else(|| "no startup error recorded".to_string())
    );
}

fn proxy_url(https_port: u16, path: &str) -> String {
    format!("https://127.0.0.1:{https_port}{path}")
}

/// Read the bounded authorization-lifetime counter for one protocol family from
/// the authenticated `GET /metrics/runtime` snapshot.
async fn credential_expired_count(harness: &GatewayHarness, family: &str) -> u64 {
    let body: Value = harness
        .get_admin_json("/metrics/runtime")
        .await
        .expect("GET /metrics/runtime");
    body["authorization_lifetime"]["credential_expired"][family]
        .as_u64()
        .unwrap_or_else(|| {
            panic!(
                "runtime snapshot must expose authorization_lifetime.credential_expired.{family}; \
                 got {body:#?}"
            )
        })
}

/// Poll the runtime snapshot until the family's `credential_expired` counter
/// reaches `expected`, then assert it does not go higher. The snapshot is
/// cached for `FERRUM_METRICS_RUNTIME_CACHE_MS` (1s by default), so this polls
/// rather than sampling once.
async fn assert_credential_expired_exactly(harness: &GatewayHarness, family: &str, expected: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let observed = loop {
        let value = credential_expired_count(harness, family).await;
        if value >= expected || std::time::Instant::now() >= deadline {
            break value;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        observed,
        expected,
        "expected exactly {expected} credential_expired termination(s) for family {family} on a \
         freshly spawned gateway; observed {observed}. Logs:\n{}",
        harness.captured_combined().unwrap_or_default()
    );
    // A second read after the cache window proves the terminal accounting fired
    // once for the stream rather than once per relayed frame.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        credential_expired_count(harness, family).await,
        expected,
        "credential_expired must not keep incrementing after the stream ended"
    );
}

async fn fetch_capability_entry(harness: &GatewayHarness) -> Option<Value> {
    let body = harness.get_admin_json("/backend-capabilities").await.ok()?;
    body["entries"].as_array().cloned()?.into_iter().next()
}

async fn wait_for_h3_supported(harness: &GatewayHarness, timeout: Duration) -> Option<Value> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(entry) = fetch_capability_entry(harness).await
            && entry["plain_http"]["h3"].as_str() == Some("supported")
        {
            return Some(entry);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// A backend script that keeps producing response DATA for `count` rounds
/// spaced by `gap`. Activity must never extend the authorization deadline.
fn h3_chatty_stream(count: usize, gap: Duration) -> Vec<H3Step> {
    let mut steps = vec![
        H3Step::AcceptStream,
        H3Step::RespondHeaders(vec![
            (":status", "200".to_string()),
            ("content-type", "text/event-stream".to_string()),
            ("cache-control", "no-cache".to_string()),
        ]),
    ];
    for _ in 0..count {
        steps.push(H3Step::RespondData(Bytes::from_static(b"event: tick\n\n")));
        steps.push(H3Step::StallFor(gap));
    }
    steps
}

// ────────────────────────────────────────────────────────────────────────────
// 1. Native HTTP/3 frontend → native HTTP/3 backend streaming response.
//    Production path: `http3::server`'s inline streaming relay.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_auth_lifetime_native_h3_streaming_response_ends_at_credential_expiry() {
    let ca = TestCa::new("h3-auth-lifetime-native").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    // The capability probe uses the colocated TCP+TLS side; the streaming
    // request itself must land on the native-H3 backend once h3=supported.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls probe backend");

    // 60 rounds x 500ms = 30s of continuous backend activity, five times the
    // credential lifetime.
    let backend_tls = H3TlsConfig::new(cert.clone(), key.clone());
    let _h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), backend_tls)
        .steps(h3_chatty_stream(60, Duration::from_millis(500)))
        .spawn()
        .expect("spawn h3 backend");

    let (harness, https_port) = spawn_h3_gateway(protected_proxy_yaml(backend_port), false).await;
    let entry = wait_for_h3_supported(&harness, Duration::from_secs(20)).await;
    assert!(
        entry.is_some(),
        "capability registry must classify the backend h3=supported so the request takes the \
         native-H3 relay; logs:\n{}",
        harness.captured_combined().unwrap_or_default()
    );

    let client = Http3Client::insecure().expect("H3 client");
    let token = mint_short_lived_token();
    let mut stream = client
        .open_response_stream(
            &proxy_url(https_port, "/api/events"),
            GetOptions::default().header("authorization", format!("Bearer {token}")),
        )
        .await
        .expect("open native-H3 streaming response");

    let (status, _headers) = stream.recv_response().await.expect("response headers");
    assert_eq!(
        status.as_u16(),
        200,
        "the stream must be admitted and usable while the credential is valid"
    );

    // Usable BEFORE the deadline: at least one relayed event arrives.
    let first = stream
        .recv_data()
        .await
        .expect("first event must relay before the credential deadline")
        .expect("first event must be a DATA frame, not EOF");
    assert!(!first.is_empty());

    // The backend keeps producing for 30s. The credential deadline is ~6s.
    let started = std::time::Instant::now();
    let outcome = loop {
        match stream.recv_data().await {
            Ok(Some(_)) => {
                assert!(
                    started.elapsed() < TERMINATION_GRACE,
                    "the native-H3 streaming response outlived its credential deadline: still \
                     relaying after {:?}",
                    started.elapsed()
                );
            }
            Ok(None) => break Err("clean EOF"),
            Err(error) => break Ok(error.to_string()),
        }
    };
    let error = outcome.expect(
        "post-commitment expiry must terminate the H3 stream with a reset, never a clean, \
         successful end of body",
    );
    assert!(
        started.elapsed() < TERMINATION_GRACE,
        "termination must land inside the bounded grace; took {:?} ({error})",
        started.elapsed()
    );

    assert_credential_expired_exactly(&harness, "http", 1).await;
}

// ────────────────────────────────────────────────────────────────────────────
// 2. HTTP/3 streaming request upload. The deadline fires BEFORE any response
//    header is committed, so the terminal is a fixed `401`.
//    Production path: `http3::cross_protocol::dispatch_plain`'s upload bridge.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_auth_lifetime_streaming_upload_expiry_is_a_fixed_401() {
    let ca = TestCa::new("h3-auth-lifetime-upload").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;

    // Accept the request and never answer: only the authorization deadline can
    // end this exchange (`backend_read_timeout_ms` is 60s).
    let _backend = ScriptedH2Backend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("h2 tls builder")
        .repeat_script(true)
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::Sleep(Duration::from_secs(45)))
        .spawn()
        .expect("spawn stalling h2 backend");

    let (harness, https_port) = spawn_h3_gateway(protected_proxy_yaml(backend_port), false).await;

    let client = Http3Client::insecure().expect("H3 client");
    let token = mint_short_lived_token();
    let mut stream = client
        .open_request_stream_with_content_type(
            &proxy_url(https_port, "/api/upload"),
            "application/octet-stream",
            &[("authorization", &format!("Bearer {token}"))],
        )
        .await
        .expect("open H3 streaming upload");

    // Usable BEFORE the deadline: the admitted upload reaches the backend
    // application layer while the credential is still valid.
    stream
        .send_raw_data(Bytes::from_static(b"chunk"))
        .await
        .expect("the route must accept an authenticated upload while the credential is valid");
    let admitted = {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if _backend.received_stream_count() > 0 {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    assert!(
        admitted,
        "the streaming upload must be dispatched to the backend before the credential deadline; \
         logs:\n{}",
        harness.captured_combined().unwrap_or_default()
    );

    // Continuous upload activity across the deadline. Activity must not extend
    // it, and the client never half-closes.
    let started = std::time::Instant::now();
    while started.elapsed() < TERMINATION_GRACE {
        if stream
            .send_raw_data(Bytes::from_static(b"chunk"))
            .await
            .is_err()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let (status, _headers) = tokio::time::timeout(TERMINATION_GRACE, stream.recv_response())
        .await
        .expect("the upload bridge must terminate inside the bounded grace")
        .expect("terminal response headers");
    assert_eq!(
        status.as_u16(),
        401,
        "a pre-commitment authorization expiry must be a fixed 401; logs:\n{}",
        harness.captured_combined().unwrap_or_default()
    );
    let (body, _trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("terminal 401 body");
    assert_eq!(
        std::str::from_utf8(&body).unwrap_or_default(),
        r#"{"error":"Unauthorized"}"#,
        "the 401 body must be the compiled-in literal — no expiry, claim, subject, or provider \
         detail may reach the client"
    );

    assert_credential_expired_exactly(&harness, "http", 1).await;
}

// ────────────────────────────────────────────────────────────────────────────
// 3. H3 cross-protocol native gRPC, expiry BEFORE any response DATA.
//    Protocol state permits a clean terminal, so the gateway emits
//    `grpc-status: 16` (UNAUTHENTICATED) trailers.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_auth_lifetime_grpc_expiry_before_data_emits_unauthenticated_trailers() {
    let ca = TestCa::new("h3-auth-lifetime-grpc-pre").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;

    // Headers, then silence: the response is committed but no gRPC message is
    // ever client-visible, which is the only state that permits a clean status.
    let _backend = ScriptedGrpcBackend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("grpc tls builder")
        .step(GrpcStep::AcceptStreamingRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::Sleep(Duration::from_secs(45)))
        .spawn()
        .expect("spawn stalling grpc backend");

    let (harness, https_port) = spawn_h3_gateway(protected_proxy_yaml(backend_port), false).await;

    let client = Http3Client::insecure().expect("H3 client");
    let token = mint_short_lived_token();
    let mut stream = client
        .open_grpc_stream_with_headers(
            &proxy_url(https_port, "/api/pkg.Svc/Stream"),
            &[("authorization", &format!("Bearer {token}"))],
        )
        .await
        .expect("open H3 native gRPC stream");
    stream
        .send_message(b"hello")
        .await
        .expect("the RPC must accept a request message while the credential is valid");
    stream.finish().await.expect("half-close the request");

    let (status, headers) = stream.recv_response().await.expect("response headers");
    assert_eq!(status.as_u16(), 200, "gRPC responses are HTTP 200");
    assert!(
        headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .starts_with("application/grpc"),
        "the stream must be a live native-gRPC response before the deadline"
    );

    let started = std::time::Instant::now();
    let terminal = tokio::time::timeout(TERMINATION_GRACE, stream.recv_body_and_trailers()).await;
    let (body, trailers) = terminal
        .expect("the gRPC relay must terminate inside the bounded grace")
        .expect("terminal trailers");
    assert!(
        body.is_empty(),
        "the backend committed no message, so no DATA may reach the client"
    );
    assert_eq!(
        trailers.get("grpc-status").and_then(|v| v.to_str().ok()),
        Some("16"),
        "a pre-DATA authorization expiry must be UNAUTHENTICATED, never a fabricated success; \
         elapsed {:?}; logs:\n{}",
        started.elapsed(),
        harness.captured_combined().unwrap_or_default()
    );
    assert_eq!(
        trailers.get("grpc-message").and_then(|v| v.to_str().ok()),
        Some("credential expired"),
        "the grpc-message must be the compiled-in literal with no credential or expiry detail"
    );

    assert_credential_expired_exactly(&harness, "grpc", 1).await;
}

// ────────────────────────────────────────────────────────────────────────────
// 4. H3 cross-protocol native gRPC, expiry AFTER response DATA is committed.
//    A length-prefixed message may be mid-frame, so the stream is RESET and no
//    successful terminal status is fabricated.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_auth_lifetime_grpc_expiry_after_data_resets_without_fabricated_status() {
    let ca = TestCa::new("h3-auth-lifetime-grpc-post").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;

    // A server-streaming RPC that keeps producing messages for 40s.
    let mut steps = vec![
        GrpcStep::AcceptStreamingRpc(MatchRpc::any()),
        GrpcStep::SendInitialHeaders,
    ];
    for _ in 0..80 {
        steps.push(GrpcStep::RespondMessage(Bytes::from_static(b"tick")));
        steps.push(GrpcStep::Sleep(Duration::from_millis(500)));
    }
    let _backend = ScriptedGrpcBackend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("grpc tls builder")
        .steps(steps)
        .spawn()
        .expect("spawn server-streaming grpc backend");

    let (harness, https_port) = spawn_h3_gateway(protected_proxy_yaml(backend_port), false).await;

    let client = Http3Client::insecure().expect("H3 client");
    let token = mint_short_lived_token();
    let mut stream = client
        .open_grpc_stream_with_headers(
            &proxy_url(https_port, "/api/pkg.Svc/ServerStream"),
            &[("authorization", &format!("Bearer {token}"))],
        )
        .await
        .expect("open H3 native gRPC stream");
    stream.send_message(b"go").await.expect("request message");
    stream.finish().await.expect("half-close the request");

    let (status, _headers) = stream.recv_response().await.expect("response headers");
    assert_eq!(status.as_u16(), 200);

    // Usable BEFORE the deadline: at least one gRPC message is committed.
    let first = stream
        .recv_data()
        .await
        .expect("first message must relay before the deadline")
        .expect("first message must be DATA, not EOF");
    assert!(!first.is_empty());

    let started = std::time::Instant::now();
    let outcome = loop {
        match stream.recv_data().await {
            Ok(Some(_)) => {
                assert!(
                    started.elapsed() < TERMINATION_GRACE,
                    "the gRPC stream outlived its credential deadline: still relaying after {:?}",
                    started.elapsed()
                );
            }
            Ok(None) => break Err(stream.recv_trailers().await),
            Err(error) => break Ok(error.to_string()),
        }
    };
    match outcome {
        Ok(_reset) => {}
        Err(trailers) => panic!(
            "post-DATA authorization expiry must RESET the H3 stream rather than close it with \
             synthesized trailers; observed {trailers:?}; logs:\n{}",
            harness.captured_combined().unwrap_or_default()
        ),
    }
    assert!(
        started.elapsed() < TERMINATION_GRACE,
        "termination must land inside the bounded grace; took {:?}",
        started.elapsed()
    );

    assert_credential_expired_exactly(&harness, "grpc", 1).await;
}

// ────────────────────────────────────────────────────────────────────────────
// 5. H3 cross-protocol gRPC-Web. The same pre-DATA terminal is translated into
//    the bounded body-framed trailer frame gRPC-Web requires.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_auth_lifetime_grpc_web_expiry_emits_bounded_trailer_frame() {
    let ca = TestCa::new("h3-auth-lifetime-grpc-web").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;

    let _backend = ScriptedGrpcBackend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("grpc tls builder")
        .step(GrpcStep::AcceptStreamingRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::Sleep(Duration::from_secs(45)))
        .spawn()
        .expect("spawn stalling grpc backend");

    // The `grpc_web` translator is what makes this a gRPC-Web stream rather than
    // a pass-through of the backend's native gRPC framing.
    let (harness, https_port) =
        spawn_h3_gateway(grpc_web_protected_proxy_yaml(backend_port), false).await;

    let client = Http3Client::insecure().expect("H3 client");
    let token = mint_short_lived_token();
    let mut stream = client
        .open_request_stream_with_content_type(
            &proxy_url(https_port, "/api/pkg.Svc/WebStream"),
            "application/grpc-web",
            &[("authorization", &format!("Bearer {token}"))],
        )
        .await
        .expect("open H3 gRPC-Web stream");
    stream
        .send_message(b"hello")
        .await
        .expect("the gRPC-Web RPC must accept a request message while the credential is valid");
    stream.finish().await.expect("half-close the request");

    let (status, headers) = stream.recv_response().await.expect("response headers");
    assert_eq!(status.as_u16(), 200);
    assert!(
        headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .starts_with("application/grpc-web"),
        "the response must be a live gRPC-Web stream before the deadline"
    );

    let started = std::time::Instant::now();
    let mut relayed = Vec::new();
    loop {
        match tokio::time::timeout(TERMINATION_GRACE, stream.recv_data()).await {
            Ok(Ok(Some(chunk))) => relayed.extend_from_slice(&chunk),
            Ok(Ok(None)) => break,
            Ok(Err(error)) => panic!(
                "a pre-DATA gRPC-Web expiry must deliver the bounded trailer frame, not a reset: \
                 {error}; logs:\n{}",
                harness.captured_combined().unwrap_or_default()
            ),
            Err(_) => panic!(
                "the gRPC-Web relay outlived its credential deadline by more than the bounded \
                 grace ({:?})",
                started.elapsed()
            ),
        }
    }
    assert!(
        started.elapsed() < TERMINATION_GRACE,
        "termination must land inside the bounded grace; took {:?}",
        started.elapsed()
    );
    assert!(
        !relayed.is_empty() && (relayed[0] & 0x80) != 0,
        "the terminal must be a gRPC-Web trailer frame (0x80 flag); got {relayed:?}"
    );
    let trailer_text = String::from_utf8_lossy(&relayed[5..]).to_ascii_lowercase();
    assert!(
        trailer_text.contains("grpc-status:16") || trailer_text.contains("grpc-status: 16"),
        "the gRPC-Web trailer frame must carry UNAUTHENTICATED; got {trailer_text:?}"
    );
    assert!(
        trailer_text.contains("credential expired"),
        "the gRPC-Web trailer frame must carry the compiled-in message; got {trailer_text:?}"
    );

    assert_credential_expired_exactly(&harness, "grpc_web", 1).await;
}

// ────────────────────────────────────────────────────────────────────────────
// 6. Regression: a client that stops consuming must not be able to hold an
//    admitted stream past the credential deadline.
//
//    `RequestStream::send_data` parks until QUIC flow-control credit arrives,
//    so a downstream that never reads keeps the relay loop out of its own
//    `select!` and its timer is never polled. The relay therefore races the
//    EARLIEST of the client `grpc-timeout` and the authorization deadline
//    around every downstream write — and this test sets no `grpc-timeout` at
//    all, so the authorization bound is the only one that can fire.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_auth_lifetime_stalled_downstream_cannot_outlive_the_credential() {
    let ca = TestCa::new("h3-auth-lifetime-stalled").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;

    // Each message is far larger than the client's receive window below, so the
    // gateway's very first downstream `send_data` parks in flow control.
    let big = Bytes::from(vec![b'x'; 64 * 1024]);
    let mut steps = vec![
        GrpcStep::AcceptStreamingRpc(MatchRpc::any()),
        GrpcStep::SendInitialHeaders,
    ];
    for _ in 0..40 {
        steps.push(GrpcStep::RespondMessage(big.clone()));
    }
    steps.push(GrpcStep::Sleep(Duration::from_secs(45)));
    let _backend = ScriptedGrpcBackend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("grpc tls builder")
        .steps(steps)
        .spawn()
        .expect("spawn bulk grpc backend");

    let (harness, https_port) = spawn_h3_gateway(protected_proxy_yaml(backend_port), false).await;

    // A deliberately tiny per-stream receive window makes the backpressure
    // deterministic instead of depending on Quinn's default.
    let client = Http3Client::insecure_with_stream_receive_window(4 * 1024).expect("H3 client");
    let token = mint_short_lived_token();
    let mut stream = client
        .open_grpc_stream_with_headers(
            &proxy_url(https_port, "/api/pkg.Svc/Bulk"),
            &[("authorization", &format!("Bearer {token}"))],
        )
        .await
        .expect("open H3 native gRPC stream");
    stream.send_message(b"go").await.expect("request message");
    stream.finish().await.expect("half-close the request");

    // Usable BEFORE the deadline: the response is committed.
    let (status, _headers) = stream.recv_response().await.expect("response headers");
    assert_eq!(status.as_u16(), 200);

    // From here the client NEVER reads a DATA frame. The gateway's downstream
    // write parks, and only the authorization bound can end the exchange.
    assert_credential_expired_exactly(&harness, "grpc", 1).await;

    // The stream must be terminated on the wire too, not merely counted.
    match tokio::time::timeout(TERMINATION_GRACE, stream.recv_data()).await {
        Ok(Err(_)) => {}
        Ok(Ok(other)) => {
            // Buffered credit may release a bounded prefix before the reset is
            // observed; drain until the reset surfaces.
            let _ = other;
            let started = std::time::Instant::now();
            loop {
                match stream.recv_data().await {
                    Ok(Some(_)) => assert!(
                        started.elapsed() < TERMINATION_GRACE,
                        "a stalled downstream kept receiving past the credential deadline"
                    ),
                    Ok(None) => panic!(
                        "a stalled-downstream expiry must reset the stream, never close it \
                         cleanly; logs:\n{}",
                        harness.captured_combined().unwrap_or_default()
                    ),
                    Err(_) => break,
                }
            }
        }
        Err(_) => panic!(
            "the stalled downstream was not terminated within the bounded grace; logs:\n{}",
            harness.captured_combined().unwrap_or_default()
        ),
    }
}

/// A backend script that keeps producing LARGE response DATA frames.
///
/// Each chunk is far bigger than the stalled client's per-stream receive window
/// below, so the gateway's very first downstream `send_data` parks in QUIC flow
/// control and the relay never returns to its own `select!` timer. That is
/// exactly the shape the write seam has to bound.
fn h3_bulk_sse_stream(count: usize, chunk_len: usize) -> Vec<H3Step> {
    let chunk = Bytes::from(vec![b'x'; chunk_len]);
    let mut steps = vec![
        H3Step::AcceptStream,
        H3Step::RespondHeaders(vec![
            (":status", "200".to_string()),
            ("content-type", "text/event-stream".to_string()),
            ("cache-control", "no-cache".to_string()),
        ]),
    ];
    for _ in 0..count {
        steps.push(H3Step::RespondData(chunk.clone()));
    }
    // Keep the connection alive far past the credential lifetime so only the
    // authorization bound can end the exchange.
    steps.push(H3Step::StallFor(Duration::from_secs(45)));
    steps
}

// ────────────────────────────────────────────────────────────────────────────
// 7. Regression: a NON-READING client on a PLAIN HTTP/SSE response must not be
//    able to hold an admitted native-H3 stream past the credential deadline.
//
//    This is the plain-relay counterpart of test 6. `select!` alone does not
//    cover it: a client that stops reading parks the relay inside
//    `RequestStream::send_data`, so the authorization arm is never polled and
//    only a deadline raced around the WRITE itself can terminate the stream.
//    Unlike gRPC there is no `grpc-timeout` at all on this path, so the
//    authorization bound is the only bound in existence.
//
//    Production path: `http3::server`'s inline native-H3 streaming relay
//    (`stream.send_data` / `finish` through
//    `stream_util::await_authorized_response_write`).
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_auth_lifetime_stalled_plain_sse_response_cannot_outlive_the_credential() {
    let ca = TestCa::new("h3-auth-lifetime-stalled-plain").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    // Colocated TCP+TLS side answers the capability probe; the SSE request
    // itself must land on the native-H3 relay once h3=supported.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls probe backend");

    let backend_tls = H3TlsConfig::new(cert.clone(), key.clone());
    let _h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), backend_tls)
        .steps(h3_bulk_sse_stream(40, 64 * 1024))
        .spawn()
        .expect("spawn bulk h3 backend");

    let (harness, https_port) = spawn_h3_gateway(protected_proxy_yaml(backend_port), false).await;
    let entry = wait_for_h3_supported(&harness, Duration::from_secs(20)).await;
    assert!(
        entry.is_some(),
        "capability registry must classify the backend h3=supported so the request takes the \
         native-H3 relay; logs:\n{}",
        harness.captured_combined().unwrap_or_default()
    );

    // A deliberately tiny per-stream receive window makes the backpressure
    // deterministic instead of depending on Quinn's default.
    let client = Http3Client::insecure_with_stream_receive_window(4 * 1024).expect("H3 client");
    let token = mint_short_lived_token();
    let mut stream = client
        .open_response_stream(
            &proxy_url(https_port, "/api/events"),
            GetOptions::default().header("authorization", format!("Bearer {token}")),
        )
        .await
        .expect("open native-H3 streaming response");

    // Usable BEFORE the deadline: the response is committed.
    let (status, headers) = stream.recv_response().await.expect("response headers");
    assert_eq!(status.as_u16(), 200);
    assert_eq!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream"),
        "the relay under test must be the streaming SSE one"
    );

    // From here the client NEVER reads a DATA frame. The gateway's downstream
    // write parks in flow control, and only the authorization bound can end it.
    assert_credential_expired_exactly(&harness, "http", 1).await;

    // The stream must be terminated on the wire too, not merely counted, and a
    // post-commitment expiry must RESET rather than fabricate a clean EOF.
    let started = std::time::Instant::now();
    loop {
        match tokio::time::timeout(TERMINATION_GRACE, stream.recv_data()).await {
            Ok(Err(_)) => break,
            Ok(Ok(Some(_))) => assert!(
                started.elapsed() < TERMINATION_GRACE,
                "a stalled downstream kept receiving past the credential deadline"
            ),
            Ok(Ok(None)) => panic!(
                "a stalled-downstream expiry must reset the stream, never close it cleanly; \
                 logs:\n{}",
                harness.captured_combined().unwrap_or_default()
            ),
            Err(_) => panic!(
                "the stalled plain/SSE downstream was not terminated within the bounded grace; \
                 logs:\n{}",
                harness.captured_combined().unwrap_or_default()
            ),
        }
    }
}

/// Backend script that answers with an oversized streaming HEADERS block and
/// then stalls. The pad is larger than the stalled client's 4 KiB per-stream
/// receive window so `send_response` itself parks in QUIC flow control — the
/// HEADERS write, not a later DATA frame, is the bound under test.
fn h3_oversized_sse_headers() -> Vec<H3Step> {
    let pad: String = (0..24_000)
        .map(|i| char::from(b'!' + (i % 90) as u8))
        .collect();
    vec![
        H3Step::AcceptStream,
        H3Step::RespondHeaders(vec![
            (":status", "200".to_string()),
            ("content-type", "text/event-stream".to_string()),
            ("cache-control", "no-cache".to_string()),
            ("x-auth-lifetime-pad", pad),
        ]),
        H3Step::StallFor(Duration::from_secs(45)),
    ]
}

// ────────────────────────────────────────────────────────────────────────────
// 7b. Regression: a NON-READING client stalled at streaming response HEADERS
//     must not observe a protected head after the credential expires.
//
//     Test 7 parks a later DATA write. This one parks `send_response` itself:
//     the backend HEADERS block is larger than the client's 4 KiB stream
//     window, and the client never calls `recv_response`. Only the
//     authorization bound around the HEADERS write can end the stream, and
//     no 200 / `text/event-stream` head may commit afterwards.
//
//     Production path: `http3::stream_util::commit_authorized_streaming_response_headers`
//     from `handle_h3_request`'s inline native-H3 streaming relay.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_auth_lifetime_stalled_plain_sse_headers_cannot_outlive_the_credential() {
    let ca = TestCa::new("h3-auth-lifetime-stalled-headers").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls probe backend");

    let backend_tls = H3TlsConfig::new(cert.clone(), key.clone());
    let _h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), backend_tls)
        .steps(h3_oversized_sse_headers())
        .spawn()
        .expect("spawn oversized-headers h3 backend");

    let (harness, https_port) = spawn_h3_gateway(protected_proxy_yaml(backend_port), false).await;
    let entry = wait_for_h3_supported(&harness, Duration::from_secs(20)).await;
    assert!(
        entry.is_some(),
        "capability registry must classify the backend h3=supported so the request takes the \
         native-H3 relay; logs:\n{}",
        harness.captured_combined().unwrap_or_default()
    );

    let client = Http3Client::insecure_with_stream_receive_window(4 * 1024).expect("H3 client");
    let token = mint_short_lived_token();
    let mut stream = client
        .open_response_stream(
            &proxy_url(https_port, "/api/events"),
            GetOptions::default().header("authorization", format!("Bearer {token}")),
        )
        .await
        .expect("open native-H3 streaming response");

    // Never recv_response: HEADERS must not become a committed protected head.
    assert_credential_expired_exactly(&harness, "http", 1).await;

    match tokio::time::timeout(TERMINATION_GRACE, stream.recv_response()).await {
        Ok(Ok((status, headers))) => panic!(
            "protected streaming response HEADERS committed after authorization expiry \
             (status={status}, content-type={:?}); logs:\n{}",
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            harness.captured_combined().unwrap_or_default()
        ),
        Ok(Err(_)) => {}
        Err(_) => panic!(
            "the stalled HEADERS write was not reset within the bounded grace; logs:\n{}",
            harness.captured_combined().unwrap_or_default()
        ),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 8. The same non-reading-client regression on the CROSS-PROTOCOL plain bridge
//    (H3 frontend → HTTP/2 backend), which is a different relay with its own
//    coalescer and its own writes (`cross_protocol::stream_reqwest_response`).
//    No `grpc-timeout` exists here either, so the authorization deadline is
//    again the only bound.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_auth_lifetime_stalled_cross_protocol_plain_response_cannot_outlive_the_credential() {
    let ca = TestCa::new("h3-auth-lifetime-stalled-xproto").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;

    let big = Bytes::from(vec![b'x'; 64 * 1024]);
    let mut steps = vec![
        H2Step::ExpectHeaders(MatchHeaders::any()),
        H2Step::RespondHeaders(vec![
            (":status", "200".to_string()),
            ("content-type", "text/event-stream".to_string()),
            ("cache-control", "no-cache".to_string()),
        ]),
    ];
    for _ in 0..40 {
        steps.push(H2Step::RespondData {
            data: big.clone(),
            end_stream: false,
        });
    }
    steps.push(H2Step::Sleep(Duration::from_secs(45)));
    let _backend = ScriptedH2Backend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("h2 tls builder")
        .steps(steps)
        .spawn()
        .expect("spawn bulk h2 backend");

    let (harness, https_port) = spawn_h3_gateway(protected_proxy_yaml(backend_port), false).await;

    let client = Http3Client::insecure_with_stream_receive_window(4 * 1024).expect("H3 client");
    let token = mint_short_lived_token();
    let mut stream = client
        .open_response_stream(
            &proxy_url(https_port, "/api/events"),
            GetOptions::default().header("authorization", format!("Bearer {token}")),
        )
        .await
        .expect("open cross-protocol streaming response");

    let (status, headers) = stream.recv_response().await.expect("response headers");
    assert_eq!(status.as_u16(), 200);
    assert_eq!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream"),
        "the relay under test must be the streaming SSE one"
    );

    // Stop reading. Only the authorization bound can end this exchange.
    assert_credential_expired_exactly(&harness, "http", 1).await;

    let started = std::time::Instant::now();
    loop {
        match tokio::time::timeout(TERMINATION_GRACE, stream.recv_data()).await {
            Ok(Err(_)) => break,
            Ok(Ok(Some(_))) => assert!(
                started.elapsed() < TERMINATION_GRACE,
                "a stalled downstream kept receiving past the credential deadline"
            ),
            Ok(Ok(None)) => panic!(
                "a stalled-downstream expiry must reset the stream, never close it cleanly; \
                 logs:\n{}",
                harness.captured_combined().unwrap_or_default()
            ),
            Err(_) => panic!(
                "the stalled cross-protocol downstream was not terminated within the bounded \
                 grace; logs:\n{}",
                harness.captured_combined().unwrap_or_default()
            ),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 9. Request direction under CONTINUOUS ACTIVITY. Test 2 proves a STALLED
//    upload is bounded; this one proves relayed request DATA cannot buy extra
//    authorized lifetime either. A per-read operator timeout never fires for a
//    client that trickles a frame before every deadline, and a plain HTTP
//    upload has no `grpc-timeout` at all, so the absolute authorization bound
//    is the only bound in existence. Response headers are not committed at this
//    point, so the terminal is the fixed redacted `401`.
//
//    Production path: `http3::cross_protocol::dispatch_plain`'s upload bridge,
//    whose absolute plan is anchored once at credential acceptance and is never
//    refreshed by a relayed DATA frame.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_auth_lifetime_continuously_active_upload_is_a_fixed_401() {
    let ca = TestCa::new("h3-auth-lifetime-active-upload").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;

    // Accept and never answer: only the authorization deadline can end this
    // exchange (`backend_read_timeout_ms` is 60s and is refreshed per read).
    let _backend = ScriptedH2Backend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("h2 tls builder")
        .repeat_script(true)
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::Sleep(Duration::from_secs(45)))
        .spawn()
        .expect("spawn silent h2 backend");

    let (harness, https_port) = spawn_h3_gateway(protected_proxy_yaml(backend_port), false).await;

    let client = Http3Client::insecure().expect("H3 client");
    let token = mint_short_lived_token();
    let mut stream = client
        .open_request_stream_with_content_type(
            &proxy_url(https_port, "/api/upload"),
            "application/octet-stream",
            &[("authorization", &format!("Bearer {token}"))],
        )
        .await
        .expect("open H3 request-upload stream");

    // Keep the upload CONTINUOUSLY active. Every frame is well inside the
    // per-read operator timeout, so nothing but the absolute authorization
    // bound can stop it. The write loop ends as soon as the gateway resets or
    // answers the request stream.
    let pump = async {
        loop {
            if stream
                .send_raw_data(Bytes::from_static(b"chunk"))
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let _ = tokio::time::timeout(TERMINATION_GRACE * 2, pump).await;

    // Pre-commitment expiry: the fixed redacted 401, and exactly one
    // fixed-cardinality termination for the `http` family.
    let response = tokio::time::timeout(TERMINATION_GRACE, stream.recv_response())
        .await
        .expect("the continuously active upload was not bounded within the grace")
        .expect("terminal response");
    assert_eq!(
        response.0.as_u16(),
        401,
        "a pre-commitment authorization expiry must be the fixed 401 contract; logs:\n{}",
        harness.captured_combined().unwrap_or_default()
    );

    assert_credential_expired_exactly(&harness, "http", 1).await;
}

// ────────────────────────────────────────────────────────────────────────────
// 10. NATIVE HTTP/3 gRPC, PRE-COMMITMENT. `dispatch_grpc_native_h3` opens the
//     backend stream and then races the request-upload pump against the
//     backend's response head. Both of that race's protocol bounds can be
//     absent at once — the client sets no `grpc-timeout` and the operator sets
//     `backend_read_timeout_ms: 0` — and a continuously active upload keeps the
//     pump making progress forever, so before the authorization deadline was
//     composed into the dispatch bound an admitted credential could stay
//     authorized indefinitely while NO response head existed.
//
//     Nothing is client-visible at expiry, so the terminal is the fixed
//     pre-commitment trailers-only `grpc-status: 16`, the backend's proven H3
//     capability is not downgraded, and the termination is counted exactly once
//     for the `grpc` family.
//
//     Production path: `http3::server::dispatch_grpc_native_h3` phases 1–3.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_auth_lifetime_native_h3_grpc_withheld_head_is_a_precommit_unauthenticated_terminal() {
    let ca = TestCa::new("h3-auth-lifetime-native-grpc").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    // The capability probe uses the colocated TCP+TLS side; once the registry
    // classifies the target `h3=supported`, the gRPC request itself takes the
    // native-H3 gRPC dispatch rather than the cross-protocol H2 bridge.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls probe backend");

    // The H3 backend accepts the request stream and keeps CONSUMING request
    // DATA — proving the upload is live and the backend is healthy — while
    // never sending a response head, for far longer than the credential lives.
    let mut steps = vec![H3Step::AcceptStream];
    for _ in 0..40 {
        steps.push(H3Step::ReadRequestData);
    }
    steps.push(H3Step::StallFor(Duration::from_secs(45)));
    let _h3_backend = ScriptedH3Backend::builder(
        udp_res.into_socket(),
        H3TlsConfig::new(cert.clone(), key.clone()),
    )
    .steps(steps)
    .spawn()
    .expect("spawn head-withholding h3 backend");

    // `backend_read_timeout_ms: 0` removes the operator fallback, and the
    // client sends no `grpc-timeout`, so the authorization deadline is the ONLY
    // bound in existence for the open + header race.
    let (harness, https_port) = spawn_h3_gateway(
        protected_proxy_yaml_with_read_timeout(backend_port, 0),
        false,
    )
    .await;
    let entry = wait_for_h3_supported(&harness, Duration::from_secs(20)).await;
    assert!(
        entry.is_some(),
        "capability registry must classify the backend h3=supported so the gRPC request takes \
         the native-H3 dispatch; logs:\n{}",
        harness.captured_combined().unwrap_or_default()
    );

    let client = Http3Client::insecure().expect("H3 client");
    let token = mint_short_lived_token();
    let mut stream = client
        .open_grpc_stream_with_headers(
            &proxy_url(https_port, "/api/pkg.Svc/Upload"),
            &[("authorization", &format!("Bearer {token}"))],
        )
        .await
        .expect("open H3 native gRPC stream");

    // Usable BEFORE the deadline: the first request message is accepted and
    // relayed while the credential is valid.
    stream
        .send_message(b"hello")
        .await
        .expect("the RPC must accept a request message while the credential is valid");

    // Then keep the upload CONTINUOUSLY active across the deadline. Relayed
    // request messages must never buy extra authorized lifetime, and the client
    // never half-closes.
    let started = std::time::Instant::now();
    let pump = async {
        loop {
            if stream.send_message(b"more").await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let _ = tokio::time::timeout(TERMINATION_GRACE * 2, pump).await;

    let (status, headers) = tokio::time::timeout(TERMINATION_GRACE, stream.recv_response())
        .await
        .expect("the native-H3 gRPC dispatch must terminate inside the bounded grace")
        .expect("terminal response headers");
    assert_eq!(status.as_u16(), 200, "gRPC terminals ride on HTTP 200");
    assert_eq!(
        headers.get("grpc-status").and_then(|v| v.to_str().ok()),
        Some("16"),
        "a pre-commitment authorization expiry must be a trailers-only UNAUTHENTICATED terminal, \
         never a backend UNAVAILABLE or DEADLINE_EXCEEDED; elapsed {:?}; logs:\n{}",
        started.elapsed(),
        harness.captured_combined().unwrap_or_default()
    );
    assert_eq!(
        headers.get("grpc-message").and_then(|v| v.to_str().ok()),
        Some("credential expired"),
        "the grpc-message must be the compiled-in literal with no credential or expiry detail"
    );

    // The backend never failed, so its proven H3 capability must survive: an
    // authorization expiry is a gateway policy decision, not a transport fault.
    let after = fetch_capability_entry(&harness).await;
    assert_eq!(
        after
            .as_ref()
            .and_then(|entry| entry["plain_http"]["h3"].as_str()),
        Some("supported"),
        "an authorization expiry must not downgrade the backend's proven H3 capability; entry: \
         {after:#?}"
    );

    assert_credential_expired_exactly(&harness, "grpc", 1).await;
}
