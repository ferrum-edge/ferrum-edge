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

use crate::scaffolding::backends::{
    H2Step, HttpStep, MatchHeaders, RequestMatcher, ScriptedH2Backend, ScriptedHttp1Backend,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::Http2Client;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use crate::scaffolding::{file_mode_yaml_for_backend_with, to_file_mode_yaml};
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

fn backend_script(
    body: &'static [u8],
    content_type: &str,
    declare_content_length: bool,
) -> Vec<H2Step> {
    let mut headers = vec![
        (":status", "200".to_string()),
        ("content-type", content_type.to_string()),
    ];
    if declare_content_length {
        headers.push(("content-length", body.len().to_string()));
    }
    vec![
        H2Step::ExpectHeaders(MatchHeaders::any()),
        H2Step::RespondHeaders(headers),
        H2Step::RespondData {
            data: Bytes::from_static(body),
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

/// Spawn a TLS HTTP/2 backend that answers every stream with `body` under
/// `content_type`, followed by the two-field trailer section.
async fn spawn_h2_trailer_backend(
    name: &str,
    body: &'static [u8],
    content_type: &str,
    declare_content_length: bool,
) -> (ScriptedH2Backend, u16) {
    let ca = TestCa::new(&format!("h2-trailers-{name}")).expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedH2Backend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("h2 tls backend")
        .steps(backend_script(body, content_type, declare_content_length))
        // Warmup, the capability probe and the request under test may all
        // share pooled connections; serve every stream like a real server.
        .repeat_script(true)
        .spawn()
        .expect("spawn backend");
    (backend, backend_port)
}

/// Proxy overrides for the TLS HTTP/2 backend above.
fn h2_backend_overrides() -> Value {
    json!({
        "backend_scheme": "https",
        "backend_host": "localhost",
        "backend_tls_verify_server_cert": false,
        "pool_enable_http2": true,
    })
}

/// A retry policy retains the request body, which keeps the request on the
/// reqwest path regardless of the backend's capability record.
fn reqwest_dispatch_retry() -> Value {
    json!({
        "max_retries": 1,
        "retryable_status_codes": [503],
        "retryable_methods": ["GET"],
        "retry_on_connect_failure": false,
    })
}

async fn spawn_gateway(yaml: String, pool_warmup: bool) -> GatewayHarness {
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("warn")
        .pool_warmup_enabled(pool_warmup)
        .spawn()
        .await
        .expect("spawn gateway");
    harness
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");
    harness
}

/// Read real frames: `bytes()` would discard the trailer section exactly the
/// way the gateway's reqwest relay used to.
async fn body_and_trailers(response: reqwest::Response) -> (Bytes, Option<http::HeaderMap>) {
    let collected = http::Response::<reqwest::Body>::from(response)
        .into_body()
        .collect()
        .await
        .expect("response body");
    let trailers = collected.trailers().cloned();
    (collected.to_bytes(), trailers)
}

fn assert_backend_trailers(name: &str, trailers: Option<http::HeaderMap>) {
    let Some(trailers) = trailers else {
        panic!("{name}: backend trailers were dropped");
    };
    let checksum = trailers.get("x-checksum").and_then(|v| v.to_str().ok());
    let timing = trailers.get("x-timing").and_then(|v| v.to_str().ok());
    assert_eq!(checksum, Some("abc123"), "{name}: {trailers:?}");
    assert_eq!(timing, Some("12ms"), "{name}: {trailers:?}");
}

async fn run_case(case: TrailerCase) {
    let declare_length = case.declare_content_length;
    let (_backend, backend_port) =
        spawn_h2_trailer_backend(case.name, BODY, "text/plain", declare_length).await;

    let mut overrides = h2_backend_overrides();
    if case.buffer_response {
        overrides["response_body_mode"] = Value::from("buffer");
    }
    if matches!(case.dispatch, Dispatch::Reqwest) {
        overrides["retry"] = reqwest_dispatch_retry();
    }
    let yaml = file_mode_yaml_for_backend_with(backend_port, overrides);
    let harness = spawn_gateway(yaml, matches!(case.dispatch, Dispatch::DirectH2)).await;
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

    let (body, trailers) = body_and_trailers(response).await;
    assert_eq!(&body[..], BODY, "{}", case.name);
    assert_backend_trailers(case.name, trailers);
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

/// An HTTP/1.1 client never receives a trailer section from the gateway, on
/// either body mode, even when it offers `TE: trailers` and the backend sent
/// one: the response carries no `Trailer` declaration for hyper to honor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn http1_client_receives_no_backend_trailers() {
    for buffer_response in [false, true] {
        let name = if buffer_response {
            "http1-client-buffer"
        } else {
            "http1-client-stream"
        };
        let (_backend, backend_port) =
            spawn_h2_trailer_backend(name, BODY, "text/plain", false).await;
        let mut overrides = h2_backend_overrides();
        overrides["retry"] = reqwest_dispatch_retry();
        if buffer_response {
            overrides["response_body_mode"] = Value::from("buffer");
        }
        let yaml = file_mode_yaml_for_backend_with(backend_port, overrides);
        let harness = spawn_gateway(yaml, false).await;

        let client = reqwest::Client::builder()
            .http1_only()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("http1 client");
        let response = client
            .get(format!("{}/api/trailers", harness.proxy_base_url()))
            .header("te", "trailers")
            .send()
            .await
            .expect("response");
        assert_eq!(response.version(), reqwest::Version::HTTP_11, "{name}");
        assert_eq!(response.status(), reqwest::StatusCode::OK, "{name}");
        let (body, trailers) = body_and_trailers(response).await;
        assert_eq!(&body[..], BODY, "{name}");
        assert!(
            trailers.is_none(),
            "{name}: unexpected trailers {trailers:?}"
        );
    }
}

/// An HTTP/1.1 backend that frames its body with chunked transfer-coding can
/// end it with a trailer section. The reqwest relay forwards that section to
/// an HTTP/2 client just like an HTTP/2 backend's TRAILERS frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn reqwest_relays_chunked_trailers_from_http1_backend() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let mut chunked = format!("{:x}\r\n", BODY.len()).into_bytes();
    chunked.extend_from_slice(BODY);
    chunked.extend_from_slice(b"\r\n0\r\nx-checksum: abc123\r\nx-timing: 12ms\r\n\r\n");
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .steps([
            HttpStep::ExpectRequest(RequestMatcher::any()),
            HttpStep::RespondStatus {
                status: 200,
                reason: "OK".into(),
            },
            HttpStep::RespondHeader {
                name: "Content-Type".into(),
                value: "text/plain".into(),
            },
            HttpStep::RespondHeader {
                name: "Transfer-Encoding".into(),
                value: "chunked".into(),
            },
            HttpStep::RespondBodyChunk(chunked),
            HttpStep::RespondBodyEnd,
        ])
        .spawn()
        .expect("spawn http1 backend");
    let overrides = json!({"pool_enable_http2": false});
    let yaml = file_mode_yaml_for_backend_with(backend_port, overrides);
    let harness = spawn_gateway(yaml, false).await;

    let client = Http2Client::h2c_prior_knowledge().expect("h2c client");
    let response = client
        .as_reqwest()
        .get(format!("{}/api/trailers", harness.proxy_base_url()))
        .header("te", "trailers")
        .send()
        .await
        .expect("response");
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let (body, trailers) = body_and_trailers(response).await;
    assert_eq!(&body[..], BODY);
    assert_backend_trailers("http1-chunked-backend", trailers);
}

/// A buffered backend body that a response-body policy replaces with a
/// gateway-authored rejection carries none of the backend's trailers; the
/// same route relays them when the body passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn gateway_replaced_buffered_body_drops_backend_trailers() {
    for (name, backend_body, expected_status) in [
        (
            "validator-pass",
            &br#"{"id":1}"#[..],
            reqwest::StatusCode::OK,
        ),
        (
            "validator-reject",
            &br#"{"x":1}"#[..],
            reqwest::StatusCode::BAD_GATEWAY,
        ),
    ] {
        let (_backend, backend_port) =
            spawn_h2_trailer_backend(name, backend_body, "application/json", false).await;
        let mut proxy = h2_backend_overrides();
        proxy["id"] = Value::from("validated");
        proxy["listen_path"] = Value::from("/api");
        proxy["backend_port"] = Value::from(backend_port);
        proxy["strip_listen_path"] = Value::from(true);
        proxy["response_body_mode"] = Value::from("buffer");
        proxy["retry"] = reqwest_dispatch_retry();
        proxy["plugins"] = json!([{"plugin_config_id": "validated-body"}]);
        let config = json!({
            "version": "1",
            "proxies": [proxy],
            "consumers": [],
            "upstreams": [],
            "plugin_configs": [{
                "id": "validated-body",
                "proxy_id": "validated",
                "plugin_name": "body_validator",
                "scope": "proxy",
                "enabled": true,
                "config": {
                    "response_json_schema": {"type": "object", "required": ["id"]}
                }
            }],
        });
        let harness = spawn_gateway(to_file_mode_yaml(&config), false).await;

        let client = Http2Client::h2c_prior_knowledge().expect("h2c client");
        let response = client
            .as_reqwest()
            .get(format!("{}/api/trailers", harness.proxy_base_url()))
            .header("te", "trailers")
            .send()
            .await
            .expect("response");
        assert_eq!(response.version(), reqwest::Version::HTTP_2, "{name}");
        assert_eq!(response.status(), expected_status, "{name}");
        let (body, trailers) = body_and_trailers(response).await;
        if expected_status == reqwest::StatusCode::OK {
            assert_eq!(&body[..], backend_body, "{name}");
            assert_backend_trailers(name, trailers);
        } else {
            assert_ne!(&body[..], backend_body, "{name}: backend body leaked");
            assert!(
                trailers.is_none(),
                "{name}: unexpected trailers {trailers:?}"
            );
        }
    }
}
