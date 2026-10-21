//! Binary-level checks for common-window accounting and retained warmup
//! connections. Like loadgen_exchange_timeout, fixtures keep their
//! kernel-assigned loopback listener bound for the entire child process.

use std::convert::Infallible;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};

const TEST_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone)]
enum ResponseMode {
    Echo,
    Held(Arc<Semaphore>),
    WrongBody,
    WrongStatus,
}

struct EchoPeer {
    target: String,
    requests: Arc<AtomicU64>,
    connections: Arc<AtomicU64>,
    task: JoinHandle<()>,
}

impl Drop for EchoPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl EchoPeer {
    async fn new(mode: ResponseMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind peer");
        let addr = listener.local_addr().expect("peer address");
        let requests = Arc::new(AtomicU64::new(0));
        let connections = Arc::new(AtomicU64::new(0));
        let request_count = requests.clone();
        let connection_count = connections.clone();
        let task = tokio::spawn(async move {
            // Dropping this set when the fixture is aborted closes every
            // accepted connection, as well as the listener.
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.expect("accept loadgen connection");
                        connection_count.fetch_add(1, Ordering::SeqCst);
                        let requests = request_count.clone();
                        let mode = mode.clone();
                        tasks.spawn(async move {
                            let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                                let requests = requests.clone();
                                let mode = mode.clone();
                                async move {
                                    let body = request.into_body().collect().await.expect("request body").to_bytes();
                                    requests.fetch_add(1, Ordering::SeqCst);
                                    if let ResponseMode::Held(gate) = &mode {
                                        gate.acquire().await.expect("response gate").forget();
                                    } else {
                                        tokio::time::sleep(Duration::from_millis(10)).await;
                                    }
                                    let status = if matches!(mode, ResponseMode::WrongStatus) {
                                        StatusCode::BAD_GATEWAY
                                    } else {
                                        StatusCode::OK
                                    };
                                    let body = if matches!(mode, ResponseMode::WrongBody) {
                                        Bytes::from(vec![b'y'; body.len()])
                                    } else {
                                        body
                                    };
                                    Ok::<_, Infallible>(Response::builder().status(status).body(Full::new(body)).expect("echo response"))
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        });
                    }
                    Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                        result.expect("echo connection task");
                    }
                }
            }
        });
        Self {
            target: format!("http://{addr}/echo"),
            requests,
            connections,
            task,
        }
    }

    fn spawn_loadgen(&self, warmup: &str, concurrency: &str) -> Child {
        Command::new(env!("CARGO_BIN_EXE_mesh_loadgen"))
            .kill_on_drop(true)
            .args([
                "--target",
                self.target.as_str(),
                "--duration",
                "1",
                "--warmup",
                warmup,
                "--concurrency",
                concurrency,
                "--payload-size",
                "16",
                "--exchange-timeout-secs",
                "5",
                "--json",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run mesh_loadgen")
    }
}

async fn report(child: Child) -> serde_json::Value {
    let output: Output = tokio::time::timeout(TEST_DEADLINE, child.wait_with_output())
        .await
        .expect("loadgen must finish within the test deadline")
        .expect("read loadgen output");
    assert!(output.status.success(), "loadgen failed: {output:?}");
    serde_json::from_slice(&output.stdout).expect("loadgen JSON report")
}

#[tokio::test]
async fn late_echo_is_drained_after_end_marker_and_excluded_from_useful_rps() {
    let gate = Arc::new(Semaphore::new(0));
    let peer = EchoPeer::new(ResponseMode::Held(gate.clone())).await;
    let mut child = peer.spawn_loadgen("0", "1");
    let mut stderr = BufReader::new(child.stderr.take().expect("loadgen stderr")).lines();
    for expected in ["MESH_BENCH_MEASUREMENT_START", "MESH_BENCH_MEASUREMENT_END"] {
        let marker = tokio::time::timeout(TEST_DEADLINE, stderr.next_line())
            .await
            .expect("phase marker must not wait for the held response")
            .expect("read phase marker")
            .expect("phase marker line");
        assert_eq!(marker, expected);
    }
    assert!(child.try_wait().expect("check loadgen process").is_none());
    assert_eq!(peer.requests.load(Ordering::SeqCst), 1);
    gate.add_permits(1);

    let report = report(child).await;
    assert_eq!(report["total_requests"], 0);
    assert_eq!(report["total_bytes"], 0);
    assert_eq!(report["rps"], 0.0);
    assert_eq!(report["latency_avg_us"], 0);
    assert_eq!(report["drained_requests"], 1);
    assert_eq!(report["drained_bytes"], 16);
    assert_eq!(report["total_errors"], 0);
    assert_eq!(
        peer.requests.load(Ordering::SeqCst),
        1,
        "no postdeadline request"
    );
}

#[tokio::test]
async fn warmup_and_measurement_reuse_each_workers_connection() {
    let peer = EchoPeer::new(ResponseMode::Echo).await;
    let report = report(peer.spawn_loadgen("1", "2")).await;
    let warmup = report["warmup_requests"].as_u64().expect("warmup count");
    let useful = report["total_requests"].as_u64().expect("useful count");
    let drained = report["drained_requests"].as_u64().expect("drained count");
    assert!(warmup >= 2, "each connection must be exercised in warmup");
    assert!(useful >= 2, "each connection must serve measured traffic");
    assert_eq!(report["warmup_errors"], 0);
    assert_eq!(report["total_errors"], 0);
    assert_eq!(
        peer.connections.load(Ordering::SeqCst),
        2,
        "retain both warmed connections"
    );
    assert_eq!(
        peer.requests.load(Ordering::SeqCst),
        warmup + useful + drained
    );
    assert_eq!(report["total_bytes"], useful * 16);
    assert_eq!(
        report["rps"], useful as f64,
        "warmup and drain do not inflate RPS"
    );
}

#[tokio::test]
async fn wrong_status_or_equal_length_wrong_body_is_an_error() {
    for mode in [ResponseMode::WrongStatus, ResponseMode::WrongBody] {
        let peer = EchoPeer::new(mode).await;
        let report = report(peer.spawn_loadgen("0", "1")).await;
        assert_eq!(report["total_requests"], 0);
        assert_eq!(report["drained_requests"], 0);
        assert!(report["total_errors"].as_u64().expect("errors") > 0);
    }
}
