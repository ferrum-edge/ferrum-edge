//! HTTP/1.1 keep-alive and bounded-drain coverage for the shared batch-response
//! helper used by `http_logging`, `loki_logging`, and `ai_transcript_audit`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ferrum_edge::plugins::utils::{
    HTTP_BATCH_RESPONSE_BODY_LIMIT_BYTES, HTTP_BATCH_RESPONSE_DRAIN_TIMEOUT, HttpBatchDrainOutcome,
    PluginHttpClient, drain_http_batch_response_body, handle_http_batch_response,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::plugin_utils::read_http11_request_headers;

/// HTTP/1.1 keep-alive receiver that answers each POST with a delayed body.
///
/// `responses` is cycled per accepted request on a connection. Connection and
/// request counters let callers assert reuse after bounded drains.
async fn spawn_keepalive_body_server(
    responses: Vec<(u16, &'static [u8], Duration)>,
) -> (
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    JoinHandle<()>,
) {
    assert!(!responses.is_empty());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let connections_task = Arc::clone(&connections);
    let requests_task = Arc::clone(&requests);

    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            connections_task.fetch_add(1, Ordering::SeqCst);
            let responses = responses.clone();
            let requests = Arc::clone(&requests_task);
            tokio::spawn(async move {
                let mut index = 0usize;
                loop {
                    if !read_http11_request_headers(&mut socket).await {
                        break;
                    }
                    let req_n = requests.fetch_add(1, Ordering::SeqCst);
                    let (status, body, delay) = responses[index % responses.len()];
                    index = index.saturating_add(1);
                    let reason = match status {
                        200 => "OK",
                        204 => "No Content",
                        429 => "Too Many Requests",
                        503 => "Service Unavailable",
                        _ => "Status",
                    };
                    let headers = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                        body.len()
                    );
                    if socket.write_all(headers.as_bytes()).await.is_err() {
                        break;
                    }
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    if socket.write_all(body).await.is_err() {
                        break;
                    }
                    // Cap requests on this connection so abandoned tests do not
                    // leave a keep-alive task spinning forever.
                    if req_n + 1 >= 16 {
                        break;
                    }
                }
            });
        }
    });

    (addr, connections, requests, task)
}

async fn spawn_stalled_body_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let _ = read_http11_request_headers(&mut socket).await;
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n";
        let _ = socket.write_all(headers).await;
        // Never send the body — the drain timeout must win.
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    (addr, task)
}

async fn spawn_oversized_content_length_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let _ = read_http11_request_headers(&mut socket).await;
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            HTTP_BATCH_RESPONSE_BODY_LIMIT_BYTES + 1
        );
        let _ = socket.write_all(headers.as_bytes()).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    (addr, task)
}

async fn spawn_oversized_chunked_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let _ = read_http11_request_headers(&mut socket).await;
        let _ = socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await;
        let chunk = vec![b'x'; 64 * 1024];
        let chunk_header = format!("{:x}\r\n", chunk.len());
        for _ in 0..((HTTP_BATCH_RESPONSE_BODY_LIMIT_BYTES / chunk.len()) + 2) {
            if socket.write_all(chunk_header.as_bytes()).await.is_err() {
                break;
            }
            if socket.write_all(&chunk).await.is_err() {
                break;
            }
            if socket.write_all(b"\r\n").await.is_err() {
                break;
            }
        }
    });
    (addr, task)
}

#[tokio::test(flavor = "current_thread")]
async fn shared_helper_reuses_http11_connection_across_successful_batches() {
    let (addr, connections, requests, server) =
        spawn_keepalive_body_server(vec![(200, b"OK", Duration::from_millis(20))]).await;
    let client = PluginHttpClient::default();
    let url = format!("http://{addr}/ingest");

    for _ in 0..2 {
        let req = client
            .get()
            .expect("plugin HTTP client")
            .post(&url)
            .body("[]");
        let result = client.execute(req, "http_batch_drain_test").await;
        handle_http_batch_response("http_batch_drain_test", "", 1, result)
            .await
            .expect("2xx with drained ACK must succeed");
    }

    for _ in 0..50 {
        if requests.load(Ordering::SeqCst) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "drained keep-alive ACKs must reuse one HTTP/1.1 connection"
    );
    server.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn shared_helper_reuses_http11_connection_across_retryable_then_success() {
    let (addr, connections, requests, server) = spawn_keepalive_body_server(vec![
        (503, b"no", Duration::from_millis(15)),
        (200, b"OK", Duration::from_millis(15)),
    ])
    .await;
    let client = PluginHttpClient::default();
    let url = format!("http://{addr}/ingest");

    let first = client
        .execute(
            client
                .get()
                .expect("plugin HTTP client")
                .post(&url)
                .body("[]"),
            "http_batch_drain_retry",
        )
        .await;
    let err = handle_http_batch_response("http_batch_drain_retry", "", 1, first)
        .await
        .expect_err("503 must remain retryable");
    assert!(err.contains("503"), "{err}");
    assert!(err.contains("response body drained"), "{err}");

    let second = client
        .execute(
            client
                .get()
                .expect("plugin HTTP client")
                .post(&url)
                .body("[]"),
            "http_batch_drain_retry",
        )
        .await;
    handle_http_batch_response("http_batch_drain_retry", "", 1, second)
        .await
        .expect("follow-up 200 must succeed");

    for _ in 0..50 {
        if requests.load(Ordering::SeqCst) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "retryable response bodies must be drained so the pooled connection is reusable"
    );
    server.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn shared_helper_drain_timeout_bounds_stalled_ack_body() {
    let (addr, server) = spawn_stalled_body_server().await;
    let client = PluginHttpClient::default();
    let started = Instant::now();
    let result = client
        .execute(
            client
                .get()
                .expect("plugin HTTP client")
                .post(format!("http://{addr}/stall"))
                .body("[]"),
            "http_batch_drain_timeout",
        )
        .await
        .expect("headers must arrive");
    let outcome = drain_http_batch_response_body(result).await;
    let elapsed = started.elapsed();
    assert_eq!(outcome, HttpBatchDrainOutcome::Timeout);
    assert!(
        elapsed >= HTTP_BATCH_RESPONSE_DRAIN_TIMEOUT,
        "elapsed {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "stalled ACK must not consume the full request timeout; elapsed {elapsed:?}"
    );
    server.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn shared_helper_rejects_oversized_advertised_content_length_without_blocking() {
    let (addr, server) = spawn_oversized_content_length_server().await;
    let client = PluginHttpClient::default();
    let started = Instant::now();
    let live = client
        .execute(
            client
                .get()
                .expect("plugin HTTP client")
                .post(format!("http://{addr}/oversized"))
                .body("[]"),
            "http_batch_drain_cl",
        )
        .await;
    handle_http_batch_response("http_batch_drain_cl", "", 1, live)
        .await
        .expect("2xx remains success even when the ACK body is oversized");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "oversized Content-Length must fail closed before streaming the body"
    );
    server.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn shared_helper_aborts_oversized_chunked_ack_body() {
    let (addr, server) = spawn_oversized_chunked_server().await;
    let client = PluginHttpClient::default();
    let started = Instant::now();
    let result = client
        .execute(
            client
                .get()
                .expect("plugin HTTP client")
                .post(format!("http://{addr}/chunked"))
                .body("[]"),
            "http_batch_drain_chunked",
        )
        .await
        .expect("headers must arrive");
    let outcome = drain_http_batch_response_body(result).await;
    assert_eq!(outcome, HttpBatchDrainOutcome::LimitExceeded);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "chunked oversize drain must abort at the hard cap"
    );
    server.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn shared_helper_transport_failure_is_classified_without_logging_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let _ = read_http11_request_headers(&mut socket).await;
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nshort")
            .await;
        // Close before the advertised body completes → transport/malformed drain.
    });

    let client = PluginHttpClient::default();
    let result = client
        .execute(
            client
                .get()
                .expect("plugin HTTP client")
                .post(format!("http://{addr}/truncated"))
                .body("[]"),
            "http_batch_drain_truncated",
        )
        .await
        .expect("headers must arrive");
    let outcome = drain_http_batch_response_body(result).await;
    assert_eq!(outcome, HttpBatchDrainOutcome::TransportFailure);
    assert_eq!(
        outcome.diagnostic(),
        "response body drain had a transport failure"
    );
    server.abort();
}
