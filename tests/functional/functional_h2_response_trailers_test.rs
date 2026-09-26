//! Plain HTTP/2 response trailers across dispatch paths and body modes
//! (issue #5760).
//!
//! An HTTPS backend that answers over HTTP/2 can be reached through the direct
//! HTTP/2 pool (once the capability registry proves `h2_tls`) or through
//! reqwest (an `Unknown` backend, or any route whose retry policy retains the
//! request body). Its trailer section used to survive only the streamed
//! direct-H2 relay: the reqwest relay read `bytes_stream()`, which discards
//! trailer frames, and every buffered collection kept the body only. Each case
//! below sends a `TE: trailers` HTTP/2 request and expects the backend's
//! trailers on the client wire.
//!
//! Run with: `cargo build --bin ferrum-edge && cargo test --test
//! functional_tests functional_h2_response_trailers -- --ignored --nocapture`.

use crate::scaffolding::backends::{H2Step, MatchHeaders, ScriptedH2Backend};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::Http2Client;
use crate::scaffolding::file_mode_yaml_for_backend_with;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

const BODY: &[u8] = b"hello, trailers";

#[derive(Clone, Copy)]
enum Dispatch {
    /// Retry policy retains the request body, which keeps the request off the
    /// direct HTTP/2 pool regardless of the backend's capability record.
    Reqwest,
    /// Warmup classifies `h2_tls = supported` before traffic.
    DirectH2,
    /// No warmup and no wait: the first request races the initial capability
    /// probe, so it may take either path. Trailers must survive both.
    ColdStart,
}

struct TrailerCase {
    name: &'static str,
    dispatch: Dispatch,
    buffer_response: bool,
    /// Declare `content-length` so the reqwest streaming path eagerly buffers
    /// the small body instead of streaming it.
    declare_content_length: bool,
}

fn backend_script(declare_content_length: bool) -> Vec<H2Step> {
    let mut headers = vec![
        (":status", "200".to_string()),
        ("content-type", "text/plain".to_string()),
    ];
    if declare_content_length {
        headers.push(("content-length", BODY.len().to_string()));
    }
    vec![
        H2Step::ExpectHeaders(MatchHeaders::any()),
        H2Step::RespondHeaders(headers),
        H2Step::RespondData {
            data: Bytes::from_static(BODY),
            end_stream: false,
        },
        H2Step::RespondTrailers(vec![
            ("x-checksum", "abc123".to_string()),
            ("x-timing", "12ms".to_string()),
        ]),
    ]
}

async fn wait_for_h2_tls_supported(harness: &GatewayHarness, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let body = harness
            .get_admin_json("/backend-capabilities")
            .await
            .expect("backend capability registry");
        let h2_tls = body["entries"]
            .as_array()
            .and_then(|entries| entries.first())
            .and_then(|entry| entry["plain_http"]["h2_tls"].as_str());
        if h2_tls == Some("supported") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for h2_tls=supported; latest={body:#?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn run_case(case: TrailerCase) {
    let ca = TestCa::new(&format!("h2-trailers-{}", case.name)).expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let _backend = ScriptedH2Backend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("h2 tls backend")
        .steps(backend_script(case.declare_content_length))
        // Warmup, the capability probe and the request under test may all
        // share pooled connections; serve every stream like a real server.
        .repeat_script(true)
        .spawn()
        .expect("spawn backend");

    let mut overrides = json!({
        "backend_scheme": "https",
        "backend_host": "localhost",
        "backend_tls_verify_server_cert": false,
        "pool_enable_http2": true,
    });
    if case.buffer_response {
        overrides["response_body_mode"] = Value::from("buffer");
    }
    if matches!(case.dispatch, Dispatch::Reqwest) {
        overrides["retry"] = json!({
            "max_retries": 1,
            "retryable_status_codes": [503],
            "retryable_methods": ["GET"],
            "retry_on_connect_failure": false,
        });
    }
    let harness = GatewayHarness::builder()
        .file_config(file_mode_yaml_for_backend_with(backend_port, overrides))
        .log_level("warn")
        .pool_warmup_enabled(matches!(case.dispatch, Dispatch::DirectH2))
        .spawn()
        .await
        .expect("spawn gateway");
    harness
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");
    if matches!(case.dispatch, Dispatch::DirectH2) {
        wait_for_h2_tls_supported(&harness, Duration::from_secs(15)).await;
    }

    let client = Http2Client::h2c_prior_knowledge().expect("h2c client");
    let response = client
        .as_reqwest()
        .get(format!("{}/api/trailers", harness.proxy_base_url()))
        .header("te", "trailers")
        .send()
        .await
        .expect("response");
    let version = response.version();
    assert_eq!(version, reqwest::Version::HTTP_2, "{}", case.name);
    assert_eq!(response.status(), reqwest::StatusCode::OK, "{}", case.name);

    // Read real frames: `bytes()` would discard the trailer section exactly
    // the way the gateway's reqwest relay used to.
    let collected = http::Response::<reqwest::Body>::from(response)
        .into_body()
        .collect()
        .await
        .expect("response body");
    let trailers = collected.trailers().cloned();
    assert_eq!(&collected.to_bytes()[..], BODY, "{}", case.name);
    let Some(trailers) = trailers else {
        panic!("{}: backend trailers were dropped", case.name);
    };
    let checksum = trailers.get("x-checksum").and_then(|v| v.to_str().ok());
    let timing = trailers.get("x-timing").and_then(|v| v.to_str().ok());
    assert_eq!(checksum, Some("abc123"), "{}: {trailers:?}", case.name);
    assert_eq!(timing, Some("12ms"), "{}: {trailers:?}", case.name);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn reqwest_streaming_response_relays_backend_trailers() {
    run_case(TrailerCase {
        name: "reqwest-stream",
        dispatch: Dispatch::Reqwest,
        buffer_response: false,
        declare_content_length: false,
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn reqwest_eagerly_buffered_small_response_relays_backend_trailers() {
    run_case(TrailerCase {
        name: "reqwest-eager",
        dispatch: Dispatch::Reqwest,
        buffer_response: false,
        declare_content_length: true,
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn reqwest_buffered_response_relays_backend_trailers() {
    run_case(TrailerCase {
        name: "reqwest-buffer",
        dispatch: Dispatch::Reqwest,
        buffer_response: true,
        declare_content_length: false,
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn direct_h2_streaming_response_relays_backend_trailers() {
    run_case(TrailerCase {
        name: "direct-h2-stream",
        dispatch: Dispatch::DirectH2,
        buffer_response: false,
        declare_content_length: false,
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn direct_h2_buffered_response_relays_backend_trailers() {
    run_case(TrailerCase {
        name: "direct-h2-buffer",
        dispatch: Dispatch::DirectH2,
        buffer_response: true,
        declare_content_length: false,
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn cold_start_first_response_relays_backend_trailers() {
    run_case(TrailerCase {
        name: "cold-start",
        dispatch: Dispatch::ColdStart,
        buffer_response: false,
        declare_content_length: false,
    })
    .await;
}
