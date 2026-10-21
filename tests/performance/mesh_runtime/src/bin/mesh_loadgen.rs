//! HTTP/1.1 closed-loop load generator for the mesh-runtime benchmark.
//!
//! One keep-alive connection per worker, fixed payload, explicit
//! `--host-header` so mesh outbound (host-routed) listeners can be driven
//! through an IP-literal dial. A response only counts when the status is
//! 200 AND the echoed body bytes equal the request payload bytes.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use mesh_runtime_perf::{BenchMetrics, MeasurementWindow};
use tokio::net::TcpStream;
use tokio::sync::watch;

#[derive(Parser)]
struct Cli {
    /// Target URL, e.g. http://127.0.0.1:15101/echo
    #[arg(long)]
    target: String,
    /// Host header to send (mesh service FQDN for host-routed outbound).
    #[arg(long, default_value = "svc.ferrum.svc.cluster.local")]
    host_header: String,
    /// Mesh arm name stamped into the JSON report.
    #[arg(long, default_value = "direct")]
    mesh: String,
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    duration: u64,
    /// Discarded traffic on each worker's retained connection before the
    /// coordinator starts the shared measurement window.
    #[arg(long, default_value_t = 0)]
    warmup: u64,
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..))]
    concurrency: u64,
    #[arg(long, default_value_t = 1024)]
    payload_size: usize,
    /// Deadline for one complete request/response exchange: sending the
    /// request and reading the whole response body share it. An expired
    /// exchange is recorded as a cell error and the connection is dropped.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
    exchange_timeout_secs: u64,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let args = Cli::parse();

    let url: http::Uri = args.target.parse().context("invalid target URL")?;
    let host = url.host().context("no host in URL")?.to_string();
    let port = url.port_u16().unwrap_or(80);
    let path = if url.path().is_empty() {
        "/echo".to_string()
    } else {
        url.path().to_string()
    };

    let payload = Bytes::from(vec![b'x'; args.payload_size]);

    // Workers retain their warmed connections while waiting. Only the
    // coordinator chooses the epoch, after every worker has become ready.
    // A watch channel distributes that exact window even to workers which
    // are scheduled later; they never create their own relative deadlines.
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(args.concurrency as usize + 1));
    let (window_tx, window_rx) = watch::channel(None);
    let duration = Duration::from_secs(args.duration);
    let warmup = Duration::from_secs(args.warmup);
    let target = ExchangeTarget {
        host,
        port,
        path,
        host_header: args.host_header.clone(),
        payload,
        exchange_timeout: Duration::from_secs(args.exchange_timeout_secs),
    };
    let mut handles = Vec::with_capacity(args.concurrency as usize);
    for _ in 0..args.concurrency {
        let target = target.clone();
        let barrier = barrier.clone();
        let window_rx = window_rx.clone();
        handles.push(tokio::spawn(async move {
            worker(target, barrier, window_rx, warmup).await
        }));
    }
    barrier.wait().await;
    let epoch = Instant::now();
    eprintln!("MESH_BENCH_MEASUREMENT_START");
    window_tx.send_replace(Some(MeasurementWindow::new(epoch, duration)));
    // Emit the end marker at the accounting deadline, independently of
    // worker drains. Host CPU samplers can exclude both warmup and drain.
    tokio::time::sleep_until(tokio::time::Instant::from_std(epoch + duration)).await;
    eprintln!("MESH_BENCH_MEASUREMENT_END");

    let mut combined = BenchMetrics::new();
    let mut worker_join_failed = false;
    for h in handles {
        match h.await {
            Ok(m) => combined.merge(&m),
            Err(e) => {
                eprintln!("join error: {e}");
                worker_join_failed = true;
            }
        }
    }
    if worker_join_failed {
        return Err(anyhow::anyhow!("one or more load-generator workers failed"));
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&combined.json(
                &args.mesh,
                &args.target,
                args.concurrency,
                args.duration,
                args.payload_size,
            ))
            .unwrap_or_default()
        );
    } else {
        let r = combined.json(
            &args.mesh,
            &args.target,
            args.concurrency,
            args.duration,
            args.payload_size,
        );
        println!(
            "  {} target={} concurrency={}\n  Latency avg {}us p50 {}us p95 {}us p99 {}us max {}us\n  {} requests, {} errors, {} drained after window\n  {} warmup requests, {} warmup errors\nRequests/sec: {:.2}",
            r.mesh,
            r.target,
            r.concurrency,
            r.latency_avg_us,
            r.p50_us,
            r.p95_us,
            r.p99_us,
            r.latency_max_us,
            r.total_requests,
            r.total_errors,
            r.drained_requests,
            r.warmup_requests,
            r.warmup_errors,
            r.rps
        );
    }
    Ok(())
}

async fn worker(
    target: ExchangeTarget,
    barrier: std::sync::Arc<tokio::sync::Barrier>,
    mut window_rx: watch::Receiver<Option<MeasurementWindow>>,
    warmup: Duration,
) -> BenchMetrics {
    let mut metrics = BenchMetrics::new();
    // Setup and optional warmup are excluded from throughput and latency.
    // Their errors still invalidate the cell; workers join readiness even
    // after a failure so a refused connection cannot strand their peers.
    let mut sender = match open_conn(&target.host, target.port).await {
        Ok(s) => Some(s),
        Err(_) => {
            if warmup.is_zero() {
                metrics.record_error();
            } else {
                metrics.record_warmup_error();
            }
            None
        }
    };
    if !warmup.is_zero() {
        run_phase(
            &target,
            &mut sender,
            MeasurementWindow::new(Instant::now(), warmup),
            Phase::Warmup,
            &mut metrics,
        )
        .await;
    }
    barrier.wait().await;
    if window_rx.changed().await.is_err() {
        metrics.record_error();
        return metrics;
    }
    let window = *window_rx.borrow_and_update();
    if let Some(window) = window {
        run_phase(&target, &mut sender, window, Phase::Measured, &mut metrics).await;
    } else {
        metrics.record_error();
    }
    metrics
}

#[derive(Clone)]
struct ExchangeTarget {
    host: String,
    port: u16,
    path: String,
    host_header: String,
    payload: Bytes,
    exchange_timeout: Duration,
}

#[derive(Clone, Copy)]
enum Phase {
    Warmup,
    Measured,
}

impl Phase {
    fn record_error(self, metrics: &mut BenchMetrics) {
        match self {
            Self::Warmup => metrics.record_warmup_error(),
            Self::Measured => metrics.record_error(),
        }
    }
}

async fn run_phase(
    target: &ExchangeTarget,
    sender: &mut Option<SendRequest<Full<Bytes>>>,
    window: MeasurementWindow,
    phase: Phase,
    metrics: &mut BenchMetrics,
) {
    while window.contains(Instant::now()) {
        let send = match sender.take() {
            // A temporarily unready keep-alive connection can become ready
            // in the bounded exchange. Reopening it would discard warmup.
            Some(s) if !s.is_closed() => s,
            _ => match open_conn(&target.host, target.port).await {
                Ok(s) => s,
                Err(_) => {
                    phase.record_error(metrics);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            },
        };

        // A reconnect may have consumed the remaining window. Never admit
        // another exchange after the common deadline just because it began
        // opening its connection earlier.
        let start = Instant::now();
        if !window.contains(start) {
            *sender = Some(send);
            break;
        }
        match complete_exchange(send, target).await {
            Ok((send, bytes)) => {
                let completed_at = Instant::now();
                match phase {
                    Phase::Warmup => metrics.record_warmup_success(),
                    Phase::Measured => metrics.record_completion(
                        window,
                        completed_at,
                        completed_at.duration_since(start).as_micros() as u64,
                        bytes,
                    ),
                }
                *sender = Some(send);
            }
            Err(_) => phase.record_error(metrics),
        }
    }
}

async fn complete_exchange(
    mut send: SendRequest<Full<Bytes>>,
    target: &ExchangeTarget,
) -> Result<(SendRequest<Full<Bytes>>, usize)> {
    // Readiness, sending, and the entire response body share one deadline.
    // Failure drops the sender and its connection; a successful late echo
    // is drained and reported separately by the measurement phase.
    tokio::time::timeout(target.exchange_timeout, async {
        let req = Request::builder()
            .method("POST")
            .uri(&target.path)
            .header("host", &target.host_header)
            .header("content-length", target.payload.len().to_string())
            .body(Full::new(target.payload.clone()))?;

        send.ready().await?;
        let resp = send.send_request(req).await?;
        let status = resp.status();
        let bytes = resp.into_body().collect().await?.to_bytes();
        anyhow::ensure!(
            status == StatusCode::OK && bytes == target.payload,
            "response must be a status-200 byte-exact echo"
        );
        Ok((send, bytes.len()))
    })
    .await
    .context("request/response exchange timed out")?
}

async fn open_conn(host: &str, port: u16) -> Result<SendRequest<Full<Bytes>>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let tcp = TcpStream::connect((host, port)).await?;
        tcp.set_nodelay(true)?;
        let (send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(send)
    })
    .await
    .context("connection setup timed out")?
}
