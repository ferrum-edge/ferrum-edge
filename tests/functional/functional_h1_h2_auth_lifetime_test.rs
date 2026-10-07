//! Live HTTP/1.1 and HTTP/2 acceptance coverage for the authenticated-stream
//! authorization lifetime under a downstream that will not consume the response
//! (issues #3815 / #3816).
//!
//! These are the two cases a response-body adapter alone provably cannot cover,
//! because hyper does not poll a response body in either of them:
//!
//! * **HTTP/2 with zero stream flow-control credit.** hyper's
//!   `PipeToSendStream` reserves stream send capacity and awaits
//!   `SendStream::poll_capacity` BEFORE it polls the body. A client that
//!   advertises `SETTINGS_INITIAL_WINDOW_SIZE: 0` parks that pipe indefinitely,
//!   so an in-body `Sleep` is never observed.
//! * **HTTP/1.1 with a client that never reads.** the dispatcher flushes a
//!   connection that can no longer buffer before it polls the body, so the
//!   write parks on socket writability and the body is never polled either.
//!
//! Both are client-controlled. What must hold anyway, and what these tests
//! assert on the wire and on the gateway's own fixed-cardinality counters:
//!
//! * the admitted stream IS usable while the credential is valid;
//! * at the credential deadline the gateway releases the backend body from its
//!   own task — the backend observes its connection torn down — even though the
//!   client polled nothing;
//! * within a bounded grace the client connection is terminated, which is what
//!   releases the request guard, per-IP guard, admission permits, and
//!   load-balancer accounting the response body holds;
//! * the HTTP/1.1 body ends WITHOUT its terminating chunk, so an authorization
//!   termination is distinguishable from a complete response;
//! * exactly one `credential_expired` termination is counted for the `http`
//!   family on a freshly spawned gateway.
//!
//! A further case covers the window BEFORE the backend request exists
//! (GHSA-xcg4-wj3x-gjj2): a direct HTTP/1.1 pool checkout whose TLS handshake
//! stalls past the credential deadline must end at that deadline with the
//! authorization terminal, and the backend must never receive the request —
//! not even once its stalled handshake would have completed. Two more cases
//! cover the same window on native gRPC (the buffered, replayable dispatch
//! and the fully-streamed one): an h2c sender acquisition whose peer preface
//! stalls past the credential deadline ends with `grpc-status: 16`, and the
//! backend never receives the RPC.
//!
//! The HTTP/1.1 case runs twice, against an integer and a fractional `exp`
//! (issue #5521). Both are conforming RFC 7519 §2 NumericDates and the JWT
//! layer validates both, but only the integer one used to publish a credential
//! deadline — so the fractional token authenticated and then held the admitted
//! stream open indefinitely. The paired runs are the live-wire proof that the
//! two shapes bound the stream identically.
//!
//! Run with:
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests h1_h2_auth_lifetime -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::scaffolding::backends::{ScriptedTcpBackend, TcpStep};
use crate::scaffolding::clients::raw_h2::join_idle_h2_driver;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;

const CONSUMER: &str = "h1h2-lifetime-alice";
const JWT_SECRET: &str = "h1h2-auth-lifetime-shared-hmac-secret-2026";

/// Seconds of credential validity granted to each stream. Matches the H3 suite:
/// long enough to establish the stream and prove it usable, short enough that
/// the test finishes quickly.
const TOKEN_TTL_SECS: i64 = 6;

/// Bounded grace allowed between the credential deadline and the observed
/// termination. Generous enough for a loaded CI runner, and far below the
/// multi-minute lifetime the backend script below would otherwise keep alive.
const TERMINATION_GRACE: Duration = Duration::from_secs(20);

/// Which RFC 7519 §2 NumericDate shape the minted `exp` carries.
///
/// A NumericDate is a JSON *number*, not an integer, so both shapes are equally
/// conforming and `jsonwebtoken` validates both. Issue #5521: only the integer
/// one used to publish a credential deadline, so a fractional `exp` left the
/// admitted stream unbounded on the live wire.
#[derive(Clone, Copy)]
enum ExpShape {
    /// Whole seconds — the pre-existing positive control.
    Integer,
    /// The same instant plus a quarter second. Ferrum truncates an `exp` toward
    /// the past, so the enforced deadline is the SAME second as the integer
    /// control: the two cases are directly comparable, and nothing in the
    /// assertions below depends on sub-second timing.
    Fractional,
}

fn mint_short_lived_token(exp_shape: ExpShape) -> String {
    mint_token_with_ttl(exp_shape, TOKEN_TTL_SECS)
}

fn mint_token_with_ttl(exp_shape: ExpShape, ttl_secs: i64) -> String {
    let now = Utc::now();
    let exp_seconds = (now + chrono::Duration::seconds(ttl_secs)).timestamp();
    let exp = match exp_shape {
        ExpShape::Integer => json!(exp_seconds),
        ExpShape::Fractional => json!(exp_seconds as f64 + 0.25),
    };
    let claims = json!({
        "sub": CONSUMER,
        "iat": now.timestamp(),
        "exp": exp,
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .expect("encode short-lived consumer JWT")
}

/// File-mode YAML for one `jwt_auth`-protected plaintext proxy at `/api`.
///
/// Every operator bound that could otherwise end the stream is disabled or set
/// far beyond the credential TTL, so the authorization deadline is provably the
/// only thing that can terminate it.
fn protected_proxy_yaml(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h1h2-auth-lifetime",
            "listen_path": "/api",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 5000,
            "backend_read_timeout_ms": 0,
            "backend_write_timeout_ms": 0,
            "plugins": [{"plugin_config_id": "h1h2-auth-lifetime-jwt"}],
        }],
        "consumers": [{
            "id": CONSUMER,
            "username": CONSUMER,
            "credentials": {"jwt": [{"secret": JWT_SECRET}]},
        }],
        "upstreams": [],
        "plugin_configs": [{
            "id": "h1h2-auth-lifetime-jwt",
            "plugin_name": "jwt_auth",
            "scope": "proxy",
            "proxy_id": "h1h2-auth-lifetime",
            "enabled": true,
            "config": {
                "token_lookup": "header:Authorization",
                "consumer_claim_field": "sub",
            },
        }],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

/// A chunked SSE response that keeps producing for far longer than the
/// credential lives, in chunks large enough to fill a downstream socket buffer.
///
/// The chunk size matters for the HTTP/1.1 case: the gateway's write must park
/// on a non-reading client for the "hyper never polls the body" state to exist
/// at all.
fn chatty_sse_script(rounds: usize, chunk_bytes: usize, gap: Duration) -> Vec<TcpStep> {
    let mut steps = vec![
        TcpStep::ReadUntil(b"\r\n\r\n".to_vec()),
        TcpStep::Write(
            b"HTTP/1.1 200 OK\r\n\
              Content-Type: text/event-stream\r\n\
              Cache-Control: no-cache\r\n\
              Transfer-Encoding: chunked\r\n\r\n"
                .to_vec(),
        ),
    ];
    let payload = vec![b'x'; chunk_bytes];
    let mut chunk = format!("{:x}\r\ndata: ", chunk_bytes + 8).into_bytes();
    chunk.extend_from_slice(&payload);
    chunk.extend_from_slice(b"\n\n\r\n");
    for _ in 0..rounds {
        steps.push(TcpStep::Write(chunk.clone()));
        steps.push(TcpStep::Sleep(gap));
    }
    // Deliberately no terminating `0\r\n\r\n`: this backend never finishes.
    steps
}

/// Read the bounded authorization-lifetime counter for one protocol family.
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

/// Poll until the family's `credential_expired` counter reaches `expected`, then
/// assert it does not go higher. The snapshot is cached for
/// `FERRUM_METRICS_RUNTIME_CACHE_MS`, so this polls rather than sampling once.
async fn assert_credential_expired_exactly(harness: &GatewayHarness, family: &str, expected: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
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
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        credential_expired_count(harness, family).await,
        expected,
        "credential_expired must not keep incrementing after the stream ended"
    );
}

async fn spawn_gateway(backend_port: u16) -> GatewayHarness {
    GatewayHarness::builder()
        .file_config(protected_proxy_yaml(backend_port))
        .log_level("info")
        .capture_output()
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway")
}

fn proxy_authority(harness: &GatewayHarness) -> String {
    harness
        .proxy_base_url()
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string()
}

// ────────────────────────────────────────────────────────────────────────────
// 1. HTTP/2 client holding ZERO stream flow-control credit.
//
//    `SETTINGS_INITIAL_WINDOW_SIZE: 0` means hyper's `PipeToSendStream` parks in
//    `poll_capacity` and never polls the response body, so ONLY a gateway-owned
//    mechanism can end the admitted stream.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h1_h2_auth_lifetime_zero_flow_credit_h2_client_cannot_outlive_the_credential() {
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .steps(chatty_sse_script(
            120,
            16 * 1024,
            Duration::from_millis(250),
        ))
        .spawn()
        .expect("spawn chatty sse backend");

    let harness = spawn_gateway(backend_port).await;
    let authority = proxy_authority(&harness);
    let token = mint_short_lived_token(ExpShape::Integer);

    let tcp = tokio::net::TcpStream::connect(authority.as_str())
        .await
        .expect("connect to the gateway plaintext port");
    // h2c prior knowledge, with a ZERO stream window. Connection-level credit is
    // left at its default so the response HEAD still arrives — it is DATA that
    // can never flow.
    let (send_request, connection) = h2::client::Builder::new()
        .initial_window_size(0)
        .handshake::<_, Bytes>(tcp)
        .await
        .expect("h2c handshake with the gateway");

    let connection_closed = Arc::new(AtomicBool::new(false));
    let closed_flag = Arc::clone(&connection_closed);
    tokio::spawn(async move {
        let _ = connection.await;
        closed_flag.store(true, Ordering::SeqCst);
    });

    let request = http::Request::builder()
        .method("GET")
        .uri(format!("http://{authority}/api/events"))
        .header("authorization", format!("Bearer {token}"))
        .body(())
        .expect("build h2 request");
    let mut send_request = send_request
        .ready()
        .await
        .expect("the h2 connection must accept a new stream");
    let (response, _send_body) = send_request
        .send_request(request, true)
        .expect("send the authenticated h2 request");

    // Usable BEFORE the deadline: the stream is admitted and the response head
    // is committed while the credential is valid.
    let response = tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .expect("the gateway must commit the response head while the credential is valid")
        .expect("response head");
    assert_eq!(
        response.status().as_u16(),
        200,
        "the SSE stream must be admitted before the credential deadline; logs:\n{}",
        harness.captured_combined().unwrap_or_default()
    );

    // From here the client NEVER releases capacity, so hyper never polls the
    // response body. `_body` is retained deliberately: dropping it would reset
    // the stream and defeat the whole point of the test.
    let _body = response.into_body();

    let started = std::time::Instant::now();
    while !connection_closed.load(Ordering::SeqCst) && started.elapsed() < TERMINATION_GRACE {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        connection_closed.load(Ordering::SeqCst),
        "a client withholding HTTP/2 flow-control credit must not be able to hold an admitted \
         authenticated stream — and the request guard, admission permit, and load-balancer \
         accounting it owns — past the credential deadline. Waited {:?}; logs:\n{}",
        started.elapsed(),
        harness.captured_combined().unwrap_or_default()
    );

    assert_credential_expired_exactly(&harness, "http", 1).await;
}

// ────────────────────────────────────────────────────────────────────────────
// 2. HTTP/1.1 client that never reads.
//
//    The gateway's write parks on socket writability once the client's receive
//    buffer fills, so hyper stops polling the response body. The stream must
//    still end at the credential deadline, and it must end WITHOUT the
//    terminating chunk so the client can tell an authorization termination from
//    a complete response.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h1_h2_auth_lifetime_non_reading_h1_client_cannot_outlive_the_credential() {
    assert_non_reading_h1_client_cannot_outlive_the_credential(ExpShape::Integer).await;
}

// ────────────────────────────────────────────────────────────────────────────
// 3. The same HTTP/1.1 case with a FRACTIONAL `exp` (issue #5521).
//
//    RFC 7519 §2 makes a NumericDate a JSON number, so `exp = <secs>.25` is an
//    ordinary conforming claim that the JWT layer validates exactly like the
//    integer control above. Ferrum used to read only `as_i64()`/`as_u64()` when
//    extracting the credential deadline, so this token authenticated and then
//    published NO bound: the admitted stream outlived its own credential on the
//    live wire, which is the state the integer control cannot observe.
//
//    Everything else is byte-identical to case 2, including the deadline: the
//    truncation is toward the past, so `<secs>.25` lands on `<secs>`.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h1_h2_auth_lifetime_fractional_exp_h1_client_cannot_outlive_the_credential() {
    assert_non_reading_h1_client_cannot_outlive_the_credential(ExpShape::Fractional).await;
}

async fn assert_non_reading_h1_client_cannot_outlive_the_credential(exp_shape: ExpShape) {
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .steps(chatty_sse_script(200, 32 * 1024, Duration::from_millis(50)))
        .spawn()
        .expect("spawn chatty sse backend");

    let harness = spawn_gateway(backend_port).await;
    let authority = proxy_authority(&harness);
    let token = mint_short_lived_token(exp_shape);

    let mut tcp = tokio::net::TcpStream::connect(authority.as_str())
        .await
        .expect("connect to the gateway plaintext port");
    // A small receive buffer makes the gateway's downstream write park quickly.
    // Best effort: the assertions below hold whether or not the kernel honors it.
    {
        let socket = socket2::SockRef::from(&tcp);
        let _ = socket.set_recv_buffer_size(8 * 1024);
    }
    let request = format!(
        "GET /api/events HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {token}\r\n\
         Accept: text/event-stream\r\nConnection: keep-alive\r\n\r\n"
    );
    tcp.write_all(request.as_bytes())
        .await
        .expect("write the authenticated request");
    tcp.flush().await.expect("flush");

    // Read NOTHING while the credential is valid and for a while after it
    // expires: this is the state in which hyper cannot poll the response body.
    tokio::time::sleep(Duration::from_secs(TOKEN_TTL_SECS as u64) + Duration::from_secs(6)).await;

    // Now drain whatever the kernel buffered and observe how the stream ended.
    let started = std::time::Instant::now();
    let mut received = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match tokio::time::timeout(TERMINATION_GRACE, tcp.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => received.extend_from_slice(&buf[..n]),
            // A reset is an equally valid "not a complete response" ending.
            Ok(Err(_)) => break,
            Err(_) => panic!(
                "the non-reading HTTP/1.1 client's connection was still open {:?} after the \
                 credential deadline; logs:\n{}",
                started.elapsed(),
                harness.captured_combined().unwrap_or_default()
            ),
        }
    }

    let text = String::from_utf8_lossy(&received);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "the stream must have been admitted and committed while the credential was valid; got \
         {:?}; logs:\n{}",
        text.chars().take(120).collect::<String>(),
        harness.captured_combined().unwrap_or_default()
    );
    assert!(
        !received.ends_with(b"0\r\n\r\n"),
        "an authorization termination must NOT look like a complete chunked response: the body \
         ended with a terminating chunk"
    );

    assert_credential_expired_exactly(&harness, "http", 1).await;
}

// ────────────────────────────────────────────────────────────────────────────
// 4. A direct HTTP/1.1 pool checkout that stalls past the credential deadline
//    (GHSA-xcg4-wj3x-gjj2).
//
//    The backend accepts TCP but holds its TLS handshake for longer than the
//    credential lives, so the direct pool's checkout is still in flight when
//    the credential expires. Every operator bound that could otherwise end the
//    checkout is disabled or set far beyond the stall, so the authorization
//    deadline is provably the bound that ends it.
// ────────────────────────────────────────────────────────────────────────────

/// How long the backend withholds its TLS handshake on every accepted
/// connection: far longer than the credential lives.
const CHECKOUT_STALL: Duration = Duration::from_secs(16);

/// The request path the backend counts. Nothing else the gateway sends (its
/// capability refresh included) uses it.
const STALLED_CHECKOUT_PATH: &str = "/stalled-checkout";

/// Logged (at debug) by the direct HTTP/1.1 pool once its TCP connect
/// completes and before the TLS handshake, and by no other transport: proof
/// that the stalled checkout was the direct pool's.
const DIRECT_H1_DIAL_MARKER: &str = "direct HTTP/1.1 pool dialed a backend connection";

/// File-mode YAML for one `jwt_auth`-protected route to an HTTP/1.1-only TLS
/// backend, which the direct HTTP/1.1 pool serves.
fn stalled_checkout_proxy_yaml(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h1-direct-stalled-checkout",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            // The dial budget outlives the stall, and neither the response
            // header read bound nor the write watermark is armed.
            "backend_connect_timeout_ms": 60_000,
            "backend_read_timeout_ms": 0,
            "backend_write_timeout_ms": 0,
            "pool_enable_http2": false,
            "backend_tls_verify_server_cert": false,
            "plugins": [{"plugin_config_id": "h1-direct-stalled-checkout-jwt"}],
        }],
        "consumers": [{
            "id": CONSUMER,
            "username": CONSUMER,
            "credentials": {"jwt": [{"secret": JWT_SECRET}]},
        }],
        "upstreams": [],
        "plugin_configs": [{
            "id": "h1-direct-stalled-checkout-jwt",
            "plugin_name": "jwt_auth",
            "scope": "proxy",
            "proxy_id": "h1-direct-stalled-checkout",
            "enabled": true,
            "config": {
                "token_lookup": "header:Authorization",
                "consumer_claim_field": "sub",
            },
        }],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

/// HTTP/1.1-only TLS backend that sleeps `stall` on every accepted connection
/// before it runs the TLS handshake, then serves HTTP/1.1. Returns the TCP
/// accept count and the number of requests for [`STALLED_CHECKOUT_PATH`] it
/// received.
fn spawn_stalled_handshake_backend(
    listener: tokio::net::TcpListener,
    cert_pem: &str,
    key_pem: &str,
    stall: Duration,
) -> (Arc<AtomicU32>, Arc<AtomicU32>) {
    use rustls::pki_types::pem::PemObject;
    let chain: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .filter_map(|c| c.ok())
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("key");
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .expect("cert");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let accepts = Arc::new(AtomicU32::new(0));
    let requests = Arc::new(AtomicU32::new(0));
    let (accept_count, request_count) = (Arc::clone(&accepts), Arc::clone(&requests));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            accept_count.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let request_count = Arc::clone(&request_count);
            tokio::spawn(async move {
                tokio::time::sleep(stall).await;
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        if req.uri().path() == STALLED_CHECKOUT_PATH {
                            request_count.fetch_add(1, Ordering::SeqCst);
                        }
                        async {
                            let body = http_body_util::Full::new(Bytes::from_static(b"reached"));
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(body))
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (accepts, requests)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h1_h2_auth_lifetime_direct_h1_stalled_checkout_never_reaches_the_backend() {
    let ca = crate::scaffolding::certs::TestCa::new("h1-direct-stalled-root").expect("ca");
    let (cert_pem, key_pem) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;
    let (accepts, requests) = spawn_stalled_handshake_backend(
        reservation.into_listener(),
        &cert_pem,
        &key_pem,
        CHECKOUT_STALL,
    );

    let harness = GatewayHarness::builder()
        .file_config(stalled_checkout_proxy_yaml(backend_port))
        .log_level("debug")
        .capture_output()
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let authority = proxy_authority(&harness);
    let token = mint_short_lived_token(ExpShape::Integer);

    let sent_at = std::time::Instant::now();
    let mut tcp = tokio::net::TcpStream::connect(authority.as_str())
        .await
        .expect("connect to the gateway plaintext port");
    let request = format!(
        "GET /api{STALLED_CHECKOUT_PATH} HTTP/1.1\r\nHost: {authority}\r\n\
         Authorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    tcp.write_all(request.as_bytes())
        .await
        .expect("write the authenticated request");
    tcp.flush().await.expect("flush");

    // Read the whole response. Without the fix the checkout is unbounded by
    // the credential, so the gateway would not answer before the stall ends.
    let mut received = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match tokio::time::timeout(CHECKOUT_STALL + TERMINATION_GRACE, tcp.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => received.extend_from_slice(&buf[..n]),
            Err(_) => panic!(
                "the gateway never answered the stalled-checkout request; logs:\n{}",
                harness.captured_combined().unwrap_or_default()
            ),
        }
    }
    let answered_after = sent_at.elapsed();
    let text = String::from_utf8_lossy(&received);
    assert!(
        text.starts_with("HTTP/1.1 401"),
        "a credential that expires while the direct HTTP/1.1 checkout is stalled must end \
         with the fixed authorization terminal; got {:?} after {answered_after:?}; logs:\n{}",
        text.chars().take(160).collect::<String>(),
        harness.captured_combined().unwrap_or_default()
    );
    assert!(
        answered_after < CHECKOUT_STALL,
        "the stalled checkout must be cut short at the credential deadline, not held until \
         the backend's handshake completes; answered after {answered_after:?}"
    );
    assert!(
        accepts.load(Ordering::SeqCst) >= 1,
        "the stalled backend must have accepted the gateway's dial"
    );
    let logs = harness
        .wait_for_log_contains(
            |logs| logs.contains(DIRECT_H1_DIAL_MARKER),
            Duration::from_secs(5),
        )
        .await;
    assert!(
        logs.contains(DIRECT_H1_DIAL_MARKER),
        "the stalled checkout must have been the direct HTTP/1.1 pool's dial"
    );

    // Let every stalled handshake run out, then prove the backend never saw the
    // request: the cancelled checkout took its connection down with it, and
    // nothing was ever handed to a connection driver.
    let settle_until = sent_at + CHECKOUT_STALL + Duration::from_secs(4);
    tokio::time::sleep(settle_until.saturating_duration_since(std::time::Instant::now())).await;
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "a request whose credential expired during connection checkout must never reach the \
         backend; logs:\n{}",
        harness.captured_combined().unwrap_or_default()
    );

    assert_credential_expired_exactly(&harness, "http", 1).await;
}

// ────────────────────────────────────────────────────────────────────────────
// 5. A native gRPC sender acquisition that stalls past the credential deadline
//    (GHSA-xcg4-wj3x-gjj2, native gRPC sibling; part of #5990).
//
//    The h2c backend accepts TCP but withholds its HTTP/2 connection preface
//    until the gateway closes that acquisition. The gRPC pool admits a sender
//    only once the peer's SETTINGS arrive, so the acquisition is still in flight
//    when the credential expires. The cold in-process harness excludes the
//    binary's 5s startup probe, which can own a coalesced create with a shorter
//    budget than this route's 60s connect timeout (issue #6006).
// ────────────────────────────────────────────────────────────────────────────

/// The gRPC method path the stalled h2c backend counts. Nothing else the
/// gateway sends (its capability probe included) uses it.
const STALLED_GRPC_PATH: &str = "/stalled.Acquisition/Call";
const HEALTHY_GRPC_PATH: &str = "/healthy.Acquisition/Call";

/// File-mode YAML for one `jwt_auth`-protected route to an h2c gRPC backend.
///
/// `buffered` adds a connect-failure retry policy, which makes the request
/// replayable and so selects the buffered dispatch (`proxy_grpc_request_core`).
/// Without it, the upload takes the fully-streamed dispatch.
fn stalled_grpc_proxy_yaml(backend_port: u16, buffered: bool) -> String {
    let mut proxy = json!({
        "id": "grpc-stalled-acquisition",
        "listen_path": "/grpc",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
        // The dial budget outlives the credential. Neither the response-header
        // read bound nor the write watermark is armed.
        "backend_connect_timeout_ms": 60_000,
        "backend_read_timeout_ms": 0,
        "backend_write_timeout_ms": 0,
        "plugins": [{"plugin_config_id": "grpc-stalled-acquisition-jwt"}],
    });
    if buffered {
        proxy["retry"] = json!({"max_retries": 1, "retry_on_connect_failure": true});
    }
    let config = json!({
        "version": "1",
        "proxies": [proxy],
        "consumers": [{
            "id": CONSUMER,
            "username": CONSUMER,
            "credentials": {"jwt": [{"secret": JWT_SECRET}]},
        }],
        "upstreams": [],
        "plugin_configs": [{
            "id": "grpc-stalled-acquisition-jwt",
            "plugin_name": "jwt_auth",
            "scope": "proxy",
            "proxy_id": "grpc-stalled-acquisition",
            "enabled": true,
            "config": {
                "token_lookup": "header:Authorization",
                "consumer_claim_field": "sub",
            },
        }],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

/// The first connection receives no peer SETTINGS. Its complete client bytes
/// are returned only after EOF/reset, positively proving cancelled acquisition.
/// Later connections serve real RPCs, so recovery also proves the pending pool
/// create was released. The fixture owns its accept loop and connection tasks.
struct GatedGrpcBackend {
    preface_received: tokio::sync::oneshot::Receiver<()>,
    acquisition_closed: tokio::sync::oneshot::Receiver<Vec<u8>>,
    accepts: Arc<AtomicU32>,
    expired_requests: Arc<AtomicU32>,
    healthy_requests: Arc<AtomicU32>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for GatedGrpcBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn spawn_gated_preface_h2c_backend(listener: tokio::net::TcpListener) -> GatedGrpcBackend {
    let (preface_tx, preface_received) = tokio::sync::oneshot::channel();
    let (closed_tx, acquisition_closed) = tokio::sync::oneshot::channel();
    let accepts = Arc::new(AtomicU32::new(0));
    let expired_requests = Arc::new(AtomicU32::new(0));
    let healthy_requests = Arc::new(AtomicU32::new(0));
    let accept_count = Arc::clone(&accepts);
    let expired_count = Arc::clone(&expired_requests);
    let healthy_count = Arc::clone(&healthy_requests);
    let task = tokio::spawn(async move {
        let (mut stalled, _) = listener.accept().await.expect("stalled acquisition TCP");
        accept_count.fetch_add(1, Ordering::SeqCst);
        let mut preface = [0u8; 24];
        stalled
            .read_exact(&mut preface)
            .await
            .expect("client preface");
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        preface_tx.send(()).expect("publish stalled preface");
        let mut frames = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match stalled.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    frames.extend_from_slice(&buffer[..n]);
                    assert!(
                        frames.len() <= 64 * 1024,
                        "unadmitted client bytes must be bounded"
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("stalled acquisition read: {error}"),
            }
        }
        drop(stalled);
        assert!(
            closed_tx.send(frames).is_ok(),
            "publish acquisition closure"
        );

        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted.expect("recovery acquisition TCP");
                    accept_count.fetch_add(1, Ordering::SeqCst);
                    let expired_count = Arc::clone(&expired_count);
                    let healthy_count = Arc::clone(&healthy_count);
                    connections.spawn(async move {
                        let service = hyper::service::service_fn(
                            move |req: hyper::Request<hyper::body::Incoming>| {
                                if req.uri().path() == STALLED_GRPC_PATH {
                                    expired_count.fetch_add(1, Ordering::SeqCst);
                                } else if req.uri().path() == HEALTHY_GRPC_PATH {
                                    healthy_count.fetch_add(1, Ordering::SeqCst);
                                }
                                async {
                                    let response = hyper::Response::builder()
                                        .header("content-type", "application/grpc")
                                        .header("grpc-status", "0")
                                        .body(http_body_util::Full::new(Bytes::new()))
                                        .expect("trailers-only gRPC response");
                                    Ok::<_, std::convert::Infallible>(response)
                                }
                            },
                        );
                        let executor = hyper_util::rt::TokioExecutor::new();
                        let builder = hyper::server::conn::http2::Builder::new(executor);
                        let io = hyper_util::rt::TokioIo::new(stream);
                        let _ = builder.serve_connection(io, service).await;
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    result.expect("recovery connection task");
                }
            }
        }
    });
    GatedGrpcBackend {
        preface_received,
        acquisition_closed,
        accepts,
        expired_requests,
        healthy_requests,
        task,
    }
}

/// Only connection-control frames may precede peer SETTINGS. Checking the raw
/// frame types makes zero backend requests non-vacuous even on the cancelled
/// socket that never became an HTTP/2 server connection.
fn assert_no_rpc_frames(mut frames: &[u8]) {
    assert!(
        !frames.is_empty(),
        "the client must have started HTTP/2 setup"
    );
    while !frames.is_empty() {
        assert!(frames.len() >= 9, "complete HTTP/2 frame header");
        let len =
            (usize::from(frames[0]) << 16) | (usize::from(frames[1]) << 8) | usize::from(frames[2]);
        assert!(frames.len() >= 9 + len, "complete HTTP/2 frame payload");
        assert!(
            matches!(frames[3], 4 | 6 | 7 | 8),
            "no RPC HEADERS, DATA, or CONTINUATION may be sent before admission: type={}",
            frames[3]
        );
        assert_eq!(&frames[5..9], &[0, 0, 0, 0], "connection control only");
        frames = &frames[9 + len..];
    }
}

/// The terminal `grpc-status` of a gRPC response: from a trailers-only head,
/// or else from the trailers after the body. Always finish the body first.
async fn grpc_status_of(response: http::Response<h2::RecvStream>) -> Option<String> {
    let (head, mut body) = response.into_parts();
    let head_status = head
        .headers
        .get("grpc-status")
        .and_then(|status| status.to_str().ok())
        .map(str::to_owned);
    while let Some(chunk) = body.data().await {
        let chunk = chunk.ok()?;
        body.flow_control().release_capacity(chunk.len()).ok()?;
    }
    let trailers = body.trailers().await.ok()?;
    if let Some(status) = head_status {
        return Some(status);
    }
    trailers?
        .get("grpc-status")?
        .to_str()
        .ok()
        .map(str::to_owned)
}

async fn assert_stalled_grpc_acquisition_never_reaches_the_backend(buffered: bool) {
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;
    let mut backend = spawn_gated_preface_h2c_backend(reservation.into_listener());
    let mut config: Value =
        serde_yaml::from_str(&stalled_grpc_proxy_yaml(backend_port, buffered)).expect("config");
    config["proxies"][0]["circuit_breaker"] = json!({"failure_threshold": 1});

    let harness = GatewayHarness::builder()
        // Binary startup probes share the pool but clamp their creator budget
        // to 5s, earlier than this 6s JWT. Own the cold acquisition instead.
        .mode_in_process()
        .file_config(serde_yaml::to_string(&config).expect("yaml"))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let authority = proxy_authority(&harness);
    assert_eq!(
        ferrum_edge::proxy::auth_lifetime::counters().credential_expired["grpc"],
        0
    );
    let mut frontend_driver = tokio::task::JoinSet::new();
    let (frontend_ping, mut send_request) = tokio::time::timeout(TERMINATION_GRACE, async {
        let tcp = tokio::net::TcpStream::connect(authority.as_str())
            .await
            .expect("connect to the gateway plaintext port");
        let (send_request, mut connection) = h2::client::handshake(tcp)
            .await
            .expect("h2c handshake with the gateway");
        // Taken before the driver is spawned: cleanup uses it to wake the driver.
        let ping_pong = connection.ping_pong().expect("fresh connection PingPong");
        frontend_driver.spawn(connection);
        let send_request = send_request
            .ready()
            .await
            .expect("the h2 connection must accept a new stream");
        (ping_pong, send_request)
    })
    .await
    .expect("bounded frontend readiness");
    let wait = Duration::from_secs(TOKEN_TTL_SECS as u64) + TERMINATION_GRACE;
    let (http_status, grpc_status) = tokio::time::timeout(wait, async {
        // Mint after frontend readiness, so startup cannot consume the validity
        // needed to reach the backend's explicit preface barrier.
        let token = mint_short_lived_token(ExpShape::Integer);
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("http://{authority}/grpc{STALLED_GRPC_PATH}"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .expect("build gRPC request");
        let (response, mut upload) = send_request
            .send_request(request, false)
            .expect("send the authenticated gRPC request");
        // One empty, uncompressed gRPC message, then end of stream.
        upload
            .send_data(Bytes::from_static(&[0, 0, 0, 0, 0]), true)
            .expect("send the gRPC message");
        (&mut backend.preface_received)
            .await
            .expect("the backend must read the client's preface");
        assert_eq!(backend.accepts.load(Ordering::SeqCst), 1);
        // No peer SETTINGS are released. The credential must cancel acquisition
        // before the 60s operator timeout, rather than waiting for fixture time.
        // The same watchdog includes terminal body/trailer parsing.
        let response = response.await.expect("gRPC response head");
        let http_status = response.status().as_u16();
        (http_status, grpc_status_of(response).await)
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the gateway never completed the stalled-acquisition RPC; logs:\n{}",
            harness.captured_combined().unwrap_or_default()
        )
    });
    assert_eq!(
        (http_status, grpc_status.as_deref()),
        (200, Some("16")),
        "a credential that expires while the gRPC sender acquisition is stalled must end with \
         the fixed UNAUTHENTICATED terminal, never DEADLINE_EXCEEDED or UNAVAILABLE; logs:\n{}",
        harness.captured_combined().unwrap_or_default()
    );
    let frames = tokio::time::timeout(TERMINATION_GRACE, &mut backend.acquisition_closed)
        .await
        .expect("expiry must close the acquisition socket")
        .expect("observe actual backend EOF/reset");
    assert_no_rpc_frames(&frames);
    assert_eq!(
        backend.expired_requests.load(Ordering::SeqCst),
        0,
        "a gRPC request whose credential expired during sender acquisition must never reach \
         the backend; logs:\n{}",
        harness.captured_combined().unwrap_or_default()
    );

    // In-process counters are uncached: sample after the terminal and socket
    // closure, then again after a real successful follow-up, without sleeps.
    assert_eq!(
        ferrum_edge::proxy::auth_lifetime::counters().credential_expired["grpc"],
        1
    );
    assert_eq!(
        backend.accepts.load(Ordering::SeqCst),
        1,
        "expiry must not retry"
    );
    let (send_request, http_status, grpc_status) = tokio::time::timeout(TERMINATION_GRACE, async {
        let token = mint_token_with_ttl(ExpShape::Integer, 60);
        let mut send_request = send_request.ready().await.expect("recovery frontend ready");
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("http://{authority}/grpc{HEALTHY_GRPC_PATH}"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .expect("recovery request");
        let (response, mut upload) = send_request
            .send_request(request, false)
            .expect("recovery send");
        upload
            .send_data(Bytes::from_static(&[0, 0, 0, 0, 0]), true)
            .expect("recovery message");
        let response = response.await.expect("recovery response");
        let http_status = response.status().as_u16();
        (send_request, http_status, grpc_status_of(response).await)
    })
    .await
    .expect("the pool and threshold-one breaker must complete recovery");
    assert_eq!(http_status, 200);
    assert_eq!(grpc_status.as_deref(), Some("0"));
    assert_eq!(backend.accepts.load(Ordering::SeqCst), 2);
    assert_eq!(backend.expired_requests.load(Ordering::SeqCst), 0);
    assert_eq!(backend.healthy_requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        ferrum_edge::proxy::auth_lifetime::counters().credential_expired["grpc"],
        1,
        "successful recovery must not recount the cancelled RPC"
    );
    // Every request handle is gone, so the client must close the connection.
    // Joining the driver alone can hang on an h2 lost wakeup (see `raw_h2`).
    drop(send_request);
    tokio::time::timeout(
        TERMINATION_GRACE,
        join_idle_h2_driver(frontend_ping, &mut frontend_driver),
    )
    .await
    .expect("bounded frontend cleanup")
    .expect("owned frontend driver")
    .expect("join frontend driver")
    .expect("frontend closed cleanly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h1_h2_auth_lifetime_buffered_grpc_stalled_acquisition_never_reaches_the_backend() {
    assert_stalled_grpc_acquisition_never_reaches_the_backend(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h1_h2_auth_lifetime_streamed_grpc_stalled_acquisition_never_reaches_the_backend() {
    assert_stalled_grpc_acquisition_never_reaches_the_backend(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h1_h2_auth_lifetime_buffered_grpc_response_collect_commits_only_the_expiry_terminal() {
    use crate::scaffolding::backends::{GrpcStep, MatchRpc, ScriptedGrpcBackend};

    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::Sleep(Duration::from_secs(45)))
        .spawn()
        .expect("stalling buffered gRPC backend");
    let mut config: Value =
        serde_yaml::from_str(&stalled_grpc_proxy_yaml(backend_port, true)).expect("base config");
    config["proxies"][0]["response_body_mode"] = json!("buffer");
    let harness = GatewayHarness::builder()
        .file_config(serde_yaml::to_string(&config).expect("config"))
        .capture_output()
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("gateway");
    let authority = proxy_authority(&harness);
    let token = mint_short_lived_token(ExpShape::Integer);
    let tcp = tokio::net::TcpStream::connect(authority.as_str())
        .await
        .expect("gateway TCP");
    let (sender, connection) = h2::client::handshake(tcp).await.expect("h2 client");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut sender = sender.ready().await.expect("sender ready");
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("http://{authority}/grpc/buffered.Response/Call"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .expect("request");
    let (response, mut upload) = sender.send_request(request, false).expect("send");
    upload
        .send_data(Bytes::from_static(&[0, 0, 0, 0, 0]), true)
        .expect("message");
    let response = tokio::time::timeout(
        Duration::from_secs(TOKEN_TTL_SECS as u64) + TERMINATION_GRACE,
        response,
    )
    .await
    .expect("collect must stop at expiry")
    .expect("response");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response
            .headers()
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("16"),
        "no backend head may commit while the buffered collect is still pending"
    );
    let grpc_status = tokio::time::timeout(TERMINATION_GRACE, grpc_status_of(response))
        .await
        .expect("bounded expiry terminal body and trailers");
    assert_eq!(grpc_status.as_deref(), Some("16"));
    assert_eq!(
        backend.received_stream_count(),
        1,
        "expiry must never retry the RPC"
    );
    assert_credential_expired_exactly(&harness, "grpc", 1).await;
}
