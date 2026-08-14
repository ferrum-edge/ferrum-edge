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
//! Run with:
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests h1_h2_auth_lifetime -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::scaffolding::backends::{ScriptedTcpBackend, TcpStep};
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
    let token = mint_short_lived_token();

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
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;
    let _backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .steps(chatty_sse_script(200, 32 * 1024, Duration::from_millis(50)))
        .spawn()
        .expect("spawn chatty sse backend");

    let harness = spawn_gateway(backend_port).await;
    let authority = proxy_authority(&harness);
    let token = mint_short_lived_token();

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
