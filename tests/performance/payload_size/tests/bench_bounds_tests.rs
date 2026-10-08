//! `payload_bench` completion contract against controlled HTTP/2 peers
//! (issues #6071 and #6072): a stalled setup, response header, or response
//! body ends as a timed-out invalid run instead of hanging, and a failed
//! connection group is an invalid run instead of a clean zero-work result. A
//! normal echo peer is the control that every peer setup works.

use std::convert::Infallible;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::Value;
use tokio::net::TcpListener;

/// What a peer does with each accepted connection.
#[derive(Clone, Copy)]
enum Peer {
    /// Echo every request body.
    Echo,
    /// Send `200` headers, then never send DATA or END_STREAM.
    HeadersThenStall,
    /// Read the request, then never send response headers.
    NoHeaders,
    /// Accept TCP, then close before the TLS handshake.
    CloseOnAccept,
    /// Accept TCP, then never speak.
    Silent,
    /// Echo on the first connection; close every later one on accept.
    EchoFirstConnectionOnly,
}

type PeerBody = BoxBody<Bytes, Infallible>;

async fn respond(peer: Peer, req: Request<Incoming>) -> Result<Response<PeerBody>, Infallible> {
    let body = req
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();
    match peer {
        Peer::HeadersThenStall => {
            let never = futures_util::stream::pending::<Result<Frame<Bytes>, Infallible>>();
            Ok(Response::new(BodyExt::boxed(StreamBody::new(never))))
        }
        Peer::NoHeaders => std::future::pending().await,
        _ => Ok(Response::new(BodyExt::boxed(Full::new(body)))),
    }
}

fn cert_dir() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    std::env::temp_dir().join(format!(
        "payload-bench-bounds-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Start a TLS/ALPN-h2 peer and return its `https://` echo URL.
async fn start_peer(peer: Peer) -> String {
    let dir = cert_dir();
    let (cert, key) = payload_size_perf::tls_utils::generate_self_signed_certs(&dir).unwrap();
    let tls = payload_size_perf::tls_utils::make_server_tls_config(&cert, &key).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut accepted = 0usize;
        let mut held = Vec::new();
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            accepted += 1;
            match peer {
                Peer::CloseOnAccept => continue,
                Peer::EchoFirstConnectionOnly if accepted > 1 => continue,
                Peer::Silent => {
                    held.push(tcp);
                    continue;
                }
                _ => {}
            }
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = hyper::service::service_fn(move |req| respond(peer, req));
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    format!("https://{addr}/echo")
}

struct Run {
    exit_code: Option<i32>,
    report: Value,
    elapsed: Duration,
}

/// Run the bench for one second with a two-second request timeout. The outer
/// limit is far above the bench's own bound, so a hang fails the test.
async fn run_bench(url: &str, concurrency: u32) -> Run {
    let started = Instant::now();
    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_payload_bench"))
        .args([
            "octet-stream",
            "--http2",
            "--target",
            url,
            "--size",
            "64",
            "--json",
        ])
        .args(["--duration", "1", "--request-timeout", "2"])
        .args(["--concurrency", &concurrency.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .expect("payload_bench must finish within its own bounds")
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    Run {
        exit_code: output.status.code(),
        report: serde_json::from_str(stdout.trim())
            .unwrap_or_else(|error| panic!("JSON report expected, got {stdout:?}: {error}")),
        elapsed: started.elapsed(),
    }
}

fn count(report: &Value, field: &str) -> u64 {
    report[field]
        .as_u64()
        .unwrap_or_else(|| panic!("{field} missing from {report}"))
}

fn assert_invalid(run: &Run) {
    assert_eq!(
        run.exit_code,
        Some(2),
        "invalid runs exit 2: {}",
        run.report
    );
    assert_eq!(run.report["valid"], false, "{}", run.report);
    assert!(
        !run.report["invalid_reasons"].as_array().unwrap().is_empty(),
        "{}",
        run.report
    );
}

#[tokio::test]
async fn echo_peer_is_a_valid_run() {
    let run = run_bench(&start_peer(Peer::Echo).await, 4).await;
    assert_eq!(run.exit_code, Some(0), "{}", run.report);
    assert_eq!(run.report["valid"], true, "{}", run.report);
    assert!(count(&run.report, "total_requests") > 0);
    assert_eq!(count(&run.report, "total_errors"), 0);
    assert_eq!(count(&run.report, "workers_measured"), 4);
}

#[tokio::test]
async fn a_response_body_that_never_ends_times_out() {
    let run = run_bench(&start_peer(Peer::HeadersThenStall).await, 2).await;
    assert_invalid(&run);
    assert!(count(&run.report, "timeouts") >= 2, "{}", run.report);
    assert_eq!(count(&run.report, "total_requests"), 0);
    assert_eq!(count(&run.report, "workers_measured"), 2);
    // Duration 1 s plus one 2 s request timeout plus process startup.
    assert!(run.elapsed < Duration::from_secs(10), "{:?}", run.elapsed);
}

#[tokio::test]
async fn response_headers_that_never_arrive_time_out() {
    let run = run_bench(&start_peer(Peer::NoHeaders).await, 2).await;
    assert_invalid(&run);
    assert!(count(&run.report, "timeouts") >= 2, "{}", run.report);
    assert_eq!(count(&run.report, "total_requests"), 0);
}

#[tokio::test]
async fn a_tls_setup_failure_is_reported() {
    let run = run_bench(&start_peer(Peer::CloseOnAccept).await, 1).await;
    assert_invalid(&run);
    assert_eq!(count(&run.report, "setup_errors"), 1);
    assert_eq!(count(&run.report, "total_errors"), 1);
    assert_eq!(count(&run.report, "workers_measured"), 0);
}

#[tokio::test]
async fn a_stalled_handshake_times_out() {
    let run = run_bench(&start_peer(Peer::Silent).await, 1).await;
    assert_invalid(&run);
    assert_eq!(count(&run.report, "setup_errors"), 1);
    assert_eq!(count(&run.report, "timeouts"), 1);
    assert_eq!(count(&run.report, "workers_measured"), 0);
}

#[tokio::test]
async fn one_failed_connection_group_invalidates_the_run() {
    // Concurrency 20 is two connection groups of ten streams; the peer serves
    // only the first connection.
    let run = run_bench(&start_peer(Peer::EchoFirstConnectionOnly).await, 20).await;
    assert_invalid(&run);
    assert_eq!(count(&run.report, "setup_errors"), 1);
    assert_eq!(count(&run.report, "workers_expected"), 20);
    assert_eq!(count(&run.report, "workers_measured"), 10);
    assert!(count(&run.report, "total_requests") > 0, "{}", run.report);
}
