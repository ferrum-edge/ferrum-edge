//! HTTP/1.1 load generator for the mesh-runtime benchmark.
//!
//! One keep-alive connection per worker, fixed payload, explicit
//! `--host-header` so mesh outbound (host-routed) listeners can be driven
//! through an IP-literal dial. A response only counts when the status is
//! 200 AND the echoed body bytes equal the request payload bytes.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use mesh_runtime_perf::header_diagnostic::{
    HeaderDiagnostic, HeaderDiagnosticArgs, HeaderDiagnosticMetadata,
};
use mesh_runtime_perf::{BenchMetrics, FixedRateSchedule, MeasurementWindow};
use tokio::net::TcpStream;
use tokio::sync::watch;

// Only failures touch this process-wide budget. Diagnostic text contains
// static classifications/numeric metadata, never Display of peer/IO errors.
static ERROR_LINES: AtomicUsize = AtomicUsize::new(0);
const MAX_ERROR_LINES: usize = 16;

fn report_error(
    phase: &'static str,
    window: Option<MeasurementWindow>,
    slot: Option<u64>,
    error: &anyhow::Error,
) {
    if ERROR_LINES
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < MAX_ERROR_LINES).then_some(count + 1)
        })
        .is_err()
    {
        return;
    }
    let elapsed = window
        .map(|window| {
            Instant::now()
                .saturating_duration_since(window.start())
                .as_micros()
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());
    let slot = slot
        .map(|slot| slot.to_string())
        .unwrap_or_else(|| "none".to_string());
    eprintln!("MESH_LOADGEN_ERROR phase={phase} elapsed_us={elapsed} slot={slot} {error}");
}

fn hyper_error(stage: &'static str, error: hyper::Error) -> anyhow::Error {
    let mut io_kind = None;
    let mut os_error = None;
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(cause) = source {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            io_kind = Some(io.kind());
            os_error = io.raw_os_error();
            break;
        }
        source = cause.source();
    }
    anyhow::anyhow!(
        "stage={stage} cause=hyper closed={} canceled={} parse={} incomplete={} timeout={} io_kind={io_kind:?} os_error={os_error:?}",
        error.is_closed(),
        error.is_canceled(),
        error.is_parse(),
        error.is_incomplete_message(),
        error.is_timeout(),
    )
}

fn io_error(stage: &'static str, error: std::io::Error) -> anyhow::Error {
    anyhow::anyhow!(
        "stage={stage} cause=io io_kind={:?} os_error={:?}",
        error.kind(),
        error.raw_os_error()
    )
}

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
    /// Aggregate scheduled requests/sec across all workers. Zero keeps the
    /// saturated closed-loop mode. Late requests retain their original due
    /// time; slots not admitted by the common deadline are reported missed.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=1_000_000_000))]
    rate: u64,
    #[arg(long, default_value_t = 1024)]
    payload_size: usize,
    /// Deadline for one complete request/response exchange: sending the
    /// request and reading the whole response body share it. An expired
    /// exchange is recorded as a cell error and the connection is dropped.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
    exchange_timeout_secs: u64,
    /// Keep the process available for resource sampling until this many
    /// milliseconds after the END marker. The wait follows worker drains
    /// and is outside the measured interval; duration and RPS are unchanged.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=1000))]
    resource_end_grace_ms: u64,
    #[command(flatten)]
    diagnostic_headers: HeaderDiagnosticArgs,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let args = Cli::parse();
    let diagnostic_headers = args.diagnostic_headers.profile()?.map(Arc::new);

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
    let schedule = if args.rate == 0 {
        None
    } else {
        Some(Arc::new(FixedRateSchedule::new(args.rate, args.duration)?))
    };
    let target = ExchangeTarget {
        host,
        port,
        path,
        host_header: args.host_header.clone(),
        payload,
        exchange_timeout: Duration::from_secs(args.exchange_timeout_secs),
        diagnostic_headers: diagnostic_headers.clone(),
    };
    let mut handles = Vec::with_capacity(args.concurrency as usize);
    for _ in 0..args.concurrency {
        let target = target.clone();
        let barrier = barrier.clone();
        let window_rx = window_rx.clone();
        let schedule = schedule.clone();
        handles.push(tokio::spawn(async move {
            worker(target, barrier, window_rx, warmup, schedule).await
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
    let resource_end_grace_deadline =
        Instant::now() + Duration::from_millis(args.resource_end_grace_ms);

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
    // Host observers may receive END after every worker has already finished.
    // Preserve the process for their final /proc sample without adding time
    // to the common measurement window or delaying in-flight worker drains.
    if args.resource_end_grace_ms > 0 {
        tokio::time::sleep_until(tokio::time::Instant::from_std(resource_end_grace_deadline)).await;
    }
    if worker_join_failed {
        return Err(anyhow::anyhow!("one or more load-generator workers failed"));
    }
    if let Some(schedule) = &schedule {
        combined.configure_fixed_rate(schedule);
    }

    if args.json {
        let report = combined.json(
            &args.mesh,
            &args.target,
            args.concurrency,
            args.duration,
            args.payload_size,
        );
        if let Some(diagnostic) = &diagnostic_headers {
            #[derive(serde::Serialize)]
            struct DiagnosticReport<T> {
                #[serde(flatten)]
                report: T,
                diagnostic_headers: HeaderDiagnosticMetadata,
            }
            let validated_exchanges = combined
                .warmup_requests
                .saturating_add(combined.total_requests)
                .saturating_add(combined.drained_requests);
            println!(
                "{}",
                serde_json::to_string_pretty(&DiagnosticReport {
                    report,
                    diagnostic_headers: diagnostic.metadata(validated_exchanges),
                })?
            );
        } else {
            // Keep the default report fields and serialization unchanged.
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
        }
    } else {
        let r = combined.json(
            &args.mesh,
            &args.target,
            args.concurrency,
            args.duration,
            args.payload_size,
        );
        println!(
            "  {} target={} concurrency={}\n  In-window latency avg {}us p50 {}us p95 {}us p99 {}us max {}us\n  Successful cohort {} requests: p50 {}us p95 {}us p99 {}us max {}us\n  {} requests, {} errors, {} drained after window\n  {} warmup requests, {} warmup errors\nRequests/sec: {:.2}",
            r.mesh,
            r.target,
            r.concurrency,
            r.latency_avg_us,
            r.p50_us,
            r.p95_us,
            r.p99_us,
            r.latency_max_us,
            r.cohort_requests,
            r.cohort_p50_us,
            r.cohort_p95_us,
            r.cohort_p99_us,
            r.cohort_latency_max_us,
            r.total_requests,
            r.total_errors,
            r.drained_requests,
            r.warmup_requests,
            r.warmup_errors,
            r.rps
        );
        if args.rate > 0 {
            println!(
                "  Scheduled {} req/s: {} offered, {} admitted, {} missed\n  Scheduled latency p50 {}us p95 {}us p99 {}us max {}us\n  Scheduled successful cohort {} requests: p50 {}us p95 {}us p99 {}us max {}us\n  Admission delay p99 {}us max {}us",
                r.rate,
                r.offered_requests,
                r.admitted_requests,
                r.missed_requests,
                r.scheduled_p50_us,
                r.scheduled_p95_us,
                r.scheduled_p99_us,
                r.scheduled_latency_max_us,
                r.cohort_scheduled_requests,
                r.cohort_scheduled_p50_us,
                r.cohort_scheduled_p95_us,
                r.cohort_scheduled_p99_us,
                r.cohort_scheduled_latency_max_us,
                r.admission_delay_p99_us,
                r.admission_delay_max_us,
            );
        }
    }
    Ok(())
}

async fn worker(
    target: ExchangeTarget,
    barrier: std::sync::Arc<tokio::sync::Barrier>,
    mut window_rx: watch::Receiver<Option<MeasurementWindow>>,
    warmup: Duration,
    schedule: Option<Arc<FixedRateSchedule>>,
) -> BenchMetrics {
    let mut metrics = BenchMetrics::new();
    // Setup and optional warmup are excluded from throughput and latency.
    // Their errors still invalidate the cell; workers join readiness even
    // after a failure so a refused connection cannot strand their peers.
    let mut sender = match open_conn(&target.host, target.port).await {
        Ok(s) => Some(s),
        Err(error) => {
            report_error("setup", None, None, &error);
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
        report_error(
            "setup",
            None,
            None,
            &anyhow::anyhow!("stage=measurement_window cause=coordinator_closed"),
        );
        metrics.record_error();
        return metrics;
    }
    let window = *window_rx.borrow_and_update();
    if let Some(window) = window {
        if let Some(schedule) = schedule {
            run_scheduled_phase(&target, &mut sender, window, &schedule, &mut metrics).await;
        } else {
            run_phase(&target, &mut sender, window, Phase::Measured, &mut metrics).await;
        }
    } else {
        report_error(
            "setup",
            None,
            None,
            &anyhow::anyhow!("stage=measurement_window cause=missing_epoch"),
        );
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
    diagnostic_headers: Option<Arc<HeaderDiagnostic>>,
}

#[derive(Clone, Copy)]
enum Phase {
    Warmup,
    Measured,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::Warmup => "warmup",
            Self::Measured => "measured",
        }
    }

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
                Err(error) => {
                    report_error(phase.label(), Some(window), None, &error);
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
        if matches!(phase, Phase::Measured) {
            metrics.record_admission();
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
            Err(error) => {
                report_error(phase.label(), Some(window), None, &error);
                match phase {
                    Phase::Warmup => metrics.record_warmup_error(),
                    Phase::Measured => metrics.record_admitted_error(),
                }
            }
        }
    }
}

async fn run_scheduled_phase(
    target: &ExchangeTarget,
    sender: &mut Option<SendRequest<Full<Bytes>>>,
    window: MeasurementWindow,
    schedule: &FixedRateSchedule,
    metrics: &mut BenchMetrics,
) {
    while window.contains(Instant::now()) {
        let Some(slot) = schedule.claim_slot() else {
            break;
        };
        let due = window.start() + slot.offset;
        // One future reservation per worker spreads low aggregate rates
        // across the exact same global schedule regardless of concurrency.
        // No busy wait and no relative sleep that drifts with service time.
        tokio::time::sleep_until(tokio::time::Instant::from_std(due)).await;
        if !window.contains(Instant::now()) {
            metrics.record_missed_reservation(slot.index);
            break;
        }

        let send = match sender.take() {
            Some(s) if !s.is_closed() => s,
            _ => {
                // Connection admission also ends at the shared deadline.
                // The exchange deadline starts only after admission, and
                // bounds any successful or failed postdeadline drain.
                let connection = match tokio::time::timeout_at(
                    tokio::time::Instant::from_std(window.deadline()),
                    open_conn(&target.host, target.port),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(anyhow::anyhow!(
                        "stage=connection_admission cause=measurement_deadline"
                    )),
                };
                match connection {
                    Ok(s) => s,
                    Err(error) => {
                        report_error("measured", Some(window), Some(slot.index), &error);
                        metrics.record_missed_reservation(slot.index);
                        metrics.record_error();
                        // Refused connects may complete immediately; retain
                        // the saturated path's bounded retry backoff.
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        continue;
                    }
                }
            }
        };

        let admitted_at = Instant::now();
        if !window.contains(admitted_at) {
            metrics.record_missed_reservation(slot.index);
            *sender = Some(send);
            break;
        }
        metrics.record_scheduled_admission(due, admitted_at);
        match complete_exchange(send, target).await {
            Ok((send, bytes)) => {
                metrics.record_scheduled_completion(
                    window,
                    due,
                    admitted_at,
                    Instant::now(),
                    bytes,
                );
                *sender = Some(send);
            }
            Err(error) => {
                report_error("measured", Some(window), Some(slot.index), &error);
                metrics.record_admitted_error();
            }
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
    let mut stage = "request_build";
    let mut response_status = None;
    match tokio::time::timeout(target.exchange_timeout, async {
        let mut req = Request::builder()
            .method("POST")
            .uri(&target.path)
            .header("host", &target.host_header)
            .header("content-length", target.payload.len().to_string())
            .body(Full::new(target.payload.clone()))
            .map_err(|_| anyhow::anyhow!("stage=request_build cause=invalid_request"))?;
        if let Some(diagnostic) = &target.diagnostic_headers {
            diagnostic.append_request_headers(req.headers_mut());
        }

        stage = "sender_ready";
        send.ready().await.map_err(|error| hyper_error("sender_ready", error))?;
        stage = "response_head";
        let resp = send.send_request(req).await.map_err(|error| hyper_error("response_head", error))?;
        let status = resp.status();
        let receipt_valid = target
            .diagnostic_headers
            .as_ref()
            .is_none_or(|diagnostic| diagnostic.validate_response_headers(resp.headers()));
        response_status = Some(status.as_u16());
        stage = "response_body";
        let bytes = resp.into_body().collect().await.map_err(|error| {
            let error = hyper_error("response_body", error);
            anyhow::anyhow!("{error} status={} expected_body_bytes={} actual_body_bytes=unknown", status.as_u16(), target.payload.len())
        })?.to_bytes();
        anyhow::ensure!(
            status == StatusCode::OK,
            "stage=response_validation cause=unexpected_status status={} expected_status=200 expected_body_bytes={} actual_body_bytes={}",
            status.as_u16(), target.payload.len(), bytes.len()
        );
        anyhow::ensure!(
            bytes == target.payload,
            "stage=response_validation cause=body_mismatch status={} expected_status=200 expected_body_bytes={} actual_body_bytes={}",
            status.as_u16(), target.payload.len(), bytes.len()
        );
        anyhow::ensure!(
            receipt_valid,
            "stage=response_validation cause=diagnostic_receipt_mismatch"
        );
        Ok((send, bytes.len()))
    })
    .await {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!(
            "stage={stage} cause=exchange_timeout timeout_secs={} status={response_status:?} expected_body_bytes={} actual_body_bytes=unknown",
            target.exchange_timeout.as_secs(), target.payload.len()
        )),
    }
}

async fn open_conn(host: &str, port: u16) -> Result<SendRequest<Full<Bytes>>> {
    let mut stage = "tcp_connect";
    match tokio::time::timeout(Duration::from_secs(5), async {
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|error| io_error("tcp_connect", error))?;
        tcp.set_nodelay(true)
            .map_err(|error| io_error("tcp_nodelay", error))?;
        stage = "http1_handshake";
        let (send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|error| hyper_error("http1_handshake", error))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(send)
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!(
            "stage={stage} cause=connection_setup_timeout timeout_secs=5"
        )),
    }
}
