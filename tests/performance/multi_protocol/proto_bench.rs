//! Multi-protocol load testing tool for Ferrum Edge performance testing.
//!
//! Generates load for HTTP/2, HTTP/3, WebSocket, gRPC, TCP, and UDP protocols
//! and reports metrics in a wrk-like format.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use multi_protocol_perf::h2_observation::{Observer, error_chain, escaped_snippet};

use bytes::Buf;
use multi_protocol_perf::h1_diagnostic::{
    DRIVER_BOUND, Diagnostic, DiagnosticBody, Drivers, Observation, error_class as h1_error_class,
};
use multi_protocol_perf::h1_profile::{Counters, ObservedTls};
use multi_protocol_perf::metrics::BenchMetrics;
use multi_protocol_perf::phases::{Connections, Phases, TransportEvent};
use multi_protocol_perf::tls_utils;
use multi_protocol_perf::transport::{ObservedBody, ObservedChannel, echo_exchange, request_body};

// ── gRPC proto ───────────────────────────────────────────────────────────────

pub mod bench_proto {
    tonic::include_proto!("bench");
}

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "proto_bench", about = "Multi-protocol load testing tool")]
struct Cli {
    #[command(subcommand)]
    command: Protocol,
}

#[derive(Subcommand)]
enum Protocol {
    /// HTTP/1.1 load test
    Http1(BenchArgs),
    /// HTTP/2 load test
    Http2(BenchArgs),
    /// HTTP/3 (QUIC) load test
    Http3(BenchArgs),
    /// WebSocket load test
    Ws(BenchArgs),
    /// gRPC load test
    Grpc(BenchArgs),
    /// TCP load test
    Tcp(BenchArgs),
    /// UDP load test
    Udp(BenchArgs),
    /// Concurrent-connection saturation test (HTTP/1.1, plain or TLS)
    ///
    /// Holds N long-lived keep-alive connections against the target,
    /// each sending a small heartbeat request at a configurable interval.
    /// Reports connect/heartbeat success rates, peak alive connections, and
    /// a per-class failure breakdown so the caller can locate the breaking
    /// point. Use `run_connection_saturation_bench.sh` to ramp N across
    /// multiple invocations and find the ceiling.
    Saturate(SaturateArgs),
}

#[derive(Parser, Clone)]
struct BenchArgs {
    /// Target URL or address
    #[arg(long)]
    target: String,

    /// Test duration in seconds
    #[arg(long, default_value = "30")]
    duration: u64,

    /// Number of concurrent connections/tasks
    #[arg(long, default_value = "100")]
    concurrency: u64,

    /// Payload size in bytes for echo tests
    #[arg(long, default_value = "64")]
    payload_size: usize,

    /// Enable TLS (for TCP/UDP variants)
    #[arg(long, default_value = "false")]
    tls: bool,

    /// Path to a PEM-encoded CA certificate used to validate the server's
    /// certificate. Required for gRPC-over-TLS when targeting a self-signed
    /// backend. Also enables CA/name verification for HTTP/2; required for its
    /// observation campaign. HTTP/1, HTTP/3 and WS ignore this option.
    #[arg(long)]
    ca_cert: Option<std::path::PathBuf>,

    /// Output JSON instead of text
    #[arg(long, default_value = "false")]
    json: bool,

    /// Bounded H2/gRPC transport observations; identical overhead in every arm.
    #[arg(long, default_value = "false")]
    h2_observe: bool,

    /// Bounded H1 last-state snapshots and separate driver retirement (diagnostic only).
    #[arg(long, default_value = "false")]
    h1_diagnostic: bool,
}

#[derive(Parser, Clone)]
struct SaturateArgs {
    /// Target URL (http:// or https://) — HTTP/1.1 only
    #[arg(long)]
    target: String,

    /// Target number of concurrent connections to hold open
    #[arg(long, default_value = "10000")]
    connections: u64,

    /// Seconds to spread connection attempts over (avoids client-side SYN flood)
    #[arg(long, default_value = "30")]
    ramp_seconds: u64,

    /// Seconds to hold connections open after the ramp completes
    #[arg(long, default_value = "30")]
    hold_seconds: u64,

    /// Per-connection heartbeat interval in milliseconds (one small request per interval)
    #[arg(long, default_value = "1000")]
    heartbeat_interval_ms: u64,

    /// Heartbeat payload size in bytes
    #[arg(long, default_value = "64")]
    payload_size: usize,

    /// Per-attempt connect timeout in milliseconds
    #[arg(long, default_value = "10000")]
    connect_timeout_ms: u64,

    /// Output JSON instead of human-readable text
    #[arg(long, default_value = "false")]
    json: bool,
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install rustls crypto provider (needed for TLS operations)
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let cli = Cli::parse();
    match cli.command {
        Protocol::Http1(args) => run_http1(&args).await,
        Protocol::Http2(args) => run_http2(&args).await,
        Protocol::Http3(args) => run_http3(&args).await,
        Protocol::Ws(args) => run_ws(&args).await,
        Protocol::Grpc(args) => run_grpc(&args).await,
        Protocol::Tcp(args) => run_tcp(&args).await,
        Protocol::Udp(args) => run_udp(&args).await,
        Protocol::Saturate(args) => run_saturate(&args).await,
    }
}

// ── Reporting helper ─────────────────────────────────────────────────────────

/// Process-wide cap on transport-failure stderr lines (tracker #5588 section 3).
///
/// Transport failures used to be discarded (`Err(_) => metrics.record_error()`),
/// so a sample could report 159 gRPC errors with an empty stderr file and no way
/// to tell a backend refusal from a stream reset. Every worker retires on its
/// first transport failure, so the natural bound is one line per worker; the
/// response-body branch does not retire, so an explicit cap keeps a persistently
/// failing read from flooding the artifact. Reporting happens only on the error
/// path and cannot touch a successful request.
static REPORTED_TRANSPORT_ERRORS: AtomicUsize = AtomicUsize::new(0);
const MAX_REPORTED_TRANSPORT_ERRORS: usize = 512;

fn report_transport_error(
    protocol: &str,
    operation: &str,
    error: &(dyn std::error::Error + 'static),
) {
    let reported = REPORTED_TRANSPORT_ERRORS.fetch_add(1, Ordering::Relaxed);
    if reported < MAX_REPORTED_TRANSPORT_ERRORS {
        eprintln!("  {protocol} {operation} error: {}", error_chain(error));
    } else if reported == MAX_REPORTED_TRANSPORT_ERRORS {
        eprintln!("  {protocol} further transport errors suppressed");
    }
}

fn print_results(metrics: &BenchMetrics, protocol: &str, args: &BenchArgs) {
    if args.json {
        let report =
            metrics.to_json_report(protocol, &args.target, args.concurrency, args.duration);
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        println!(
            "{}",
            metrics.report(protocol, &args.target, args.concurrency, args.duration)
        );
    }
}

/// `error_body` is echoed back on an unexpected status so the gateway's own
/// refusal is identifiable. Three distinct Ferrum 502 bodies
/// (`Backend unavailable`, `Client disconnected`, `Invalid backend URL`) are all
/// exactly 31 bytes, so the length alone names no cause. Pass an empty slice
/// where the body was streamed and not retained.
#[allow(clippy::too_many_arguments)]
fn record_http_echo_result(
    metrics: &mut BenchMetrics,
    protocol: &str,
    status: http::StatusCode,
    body_len: usize,
    expected_len: usize,
    body_matches: bool,
    latency_us: u64,
    error_body: &[u8],
) -> bool {
    if status != http::StatusCode::OK {
        let snippet = escaped_snippet(error_body);
        eprintln!("  {protocol} unexpected status {status} (body {body_len} bytes): {snippet}");
        metrics.record_error();
        return false;
    }

    record_echo_match(
        metrics,
        protocol,
        body_len,
        expected_len,
        body_matches,
        latency_us,
    )
}

fn record_echo_result(
    metrics: &mut BenchMetrics,
    protocol: &str,
    actual: &[u8],
    expected: &[u8],
    latency_us: u64,
) -> bool {
    record_echo_match(
        metrics,
        protocol,
        actual.len(),
        expected.len(),
        actual == expected,
        latency_us,
    )
}

fn record_echo_match(
    metrics: &mut BenchMetrics,
    protocol: &str,
    body_len: usize,
    expected_len: usize,
    body_matches: bool,
    latency_us: u64,
) -> bool {
    if body_len != expected_len {
        eprintln!(
            "  {protocol} echo length mismatch: got {body_len} bytes, expected {expected_len}"
        );
        metrics.record_error();
        return false;
    }
    if !body_matches {
        eprintln!("  {protocol} echo payload mismatch: {body_len} bytes had wrong content");
        metrics.record_error();
        return false;
    }
    metrics.record(latency_us, body_len);
    true
}

fn make_payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(0xAB))
        .collect()
}

// ── HTTP/1.1 ─────────────────────────────────────────────────────────────────

async fn run_http1(args: &BenchArgs) -> anyhow::Result<()> {
    let combined = run_http1_metrics(args).await?;
    let protocol = if args.target.starts_with("https://") {
        "HTTP/1.1+TLS"
    } else {
        "HTTP/1.1"
    };
    print_results(&combined, protocol, args);
    Ok(())
}

#[cfg(test)]
pub(crate) async fn h1_diagnostic_test_run(
    target: String,
    enabled: bool,
    seconds: u64,
) -> BenchMetrics {
    let duration = seconds.to_string();
    let mut arguments = vec![
        "proto_bench",
        "http1",
        "--target",
        &target,
        "--duration",
        &duration,
        "--concurrency",
        "1",
        "--payload-size",
        "4",
    ];
    if enabled {
        arguments.push("--h1-diagnostic");
    }
    let Protocol::Http1(args) = Cli::try_parse_from(arguments).unwrap().command else {
        panic!("H1 test arguments selected another protocol");
    };
    run_http1_metrics(&args).await.unwrap()
}

async fn run_http1_metrics(args: &BenchArgs) -> anyhow::Result<BenchMetrics> {
    let is_tls = args.target.starts_with("https://");
    let url: http::Uri = args.target.parse().context("invalid target URL")?;
    let host = url.host().context("no host in URL")?;
    let port = url.port_u16().unwrap_or(if is_tls { 443 } else { 80 });
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .context("invalid address")?;
    let path = url.path().to_string();
    let authority = format!("{host}:{port}");

    let tls_connector = if is_tls {
        let mut tls_cfg = tls_utils::make_client_tls_config_insecure();
        // Force HTTP/1.1 via ALPN so TLS doesn't negotiate h2
        tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Some((
            tokio_rustls::TlsConnector::from(Arc::new(tls_cfg)),
            rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?,
        ))
    } else {
        None
    };

    let diagnostic = Diagnostic::new(args.h1_diagnostic);
    let drivers = Drivers::default();
    let mut phases = Phases::new(Duration::from_secs(args.duration))
        .with_payload(args.payload_size)
        .with_h1_diagnostic(diagnostic.clone());
    let connections = phases.connections();
    let protocol_label = if is_tls { "HTTP/1.1+TLS" } else { "HTTP/1.1" };
    let payload = Bytes::from(make_payload(args.payload_size));

    let mut handles = Vec::new();
    for worker_id in 0..args.concurrency {
        let path = path.clone();
        let authority = authority.clone();
        let tls_connector = tls_connector.clone();
        let payload = payload.clone();
        let h1_counters = phases.h1_counters();
        let mut metrics = phases.worker();
        let connections = connections.clone();
        let mut trace = diagnostic.worker(worker_id as usize);
        let observation = trace.observation.clone();
        let diagnostic = diagnostic.clone();
        let drivers = drivers.clone();
        handles.push(tokio::spawn(async move {
            let result = async {
                // Helper to create a connection (plain or TLS)
                async fn connect_h1(
                    addr: SocketAddr,
                    connections: &Connections,
                    counters: &Arc<Counters>,
                    diagnostic: &Diagnostic,
                    observation: &Observation,
                    drivers: &Drivers,
                    tls: &Option<(
                        tokio_rustls::TlsConnector,
                        rustls::pki_types::ServerName<'static>,
                    )>,
                ) -> anyhow::Result<
                    hyper::client::conn::http1::SendRequest<DiagnosticBody<ObservedBody>>,
                > {
                    observation.connecting();
                    let tcp = tokio::net::TcpStream::connect(addr)
                        .await
                        .inspect_err(|_| observation.error("tcp_connect"))?;
                    let id = observation.socket(tcp.local_addr().ok(), tcp.peer_addr().ok());
                    let _ = tcp.set_nodelay(true);
                    if let Some((connector, server_name)) = tls {
                        let tcp = ObservedTls::new(tcp, counters.clone());
                        observation.stage("tls_handshake");
                        let tls_stream = connector
                            .connect(server_name.clone(), tcp)
                            .await
                            .inspect_err(|_| observation.error("tls_handshake"))?;
                        let io = hyper_util::rt::TokioIo::new(tls_stream);
                        observation.stage("http_handshake");
                        let (sr, conn) = hyper::client::conn::http1::handshake(io)
                            .await
                            .inspect_err(|error| observation.error(h1_error_class(error)))?;
                        let connection = connections.opened();
                        drivers
                            .spawn(diagnostic, id, async move {
                                let _connection = connection;
                                conn.await
                            })
                            .inspect_err(|_| observation.error("driver_registration"))?;
                        Ok(sr)
                    } else {
                        let io = hyper_util::rt::TokioIo::new(tcp);
                        observation.stage("http_handshake");
                        let (sr, conn) = hyper::client::conn::http1::handshake(io)
                            .await
                            .inspect_err(|error| observation.error(h1_error_class(error)))?;
                        let connection = connections.opened();
                        drivers
                            .spawn(diagnostic, id, async move {
                                let _connection = connection;
                                conn.await
                            })
                            .inspect_err(|_| observation.error("driver_registration"))?;
                        Ok(sr)
                    }
                }

                let mut send_req = connect_h1(
                    addr,
                    &connections,
                    &h1_counters,
                    &diagnostic,
                    &observation,
                    &drivers,
                    &tls_connector,
                )
                .await?;
                let mut reconnects: u64 = 0;

                observation.stage("next_request");
                while metrics.next_request().await {
                    let request_observation = observation.request();
                    // Reconnect if the connection was closed
                    if send_req.is_closed() {
                        reconnects += 1;
                        send_req = connect_h1(
                            addr,
                            &connections,
                            &h1_counters,
                            &diagnostic,
                            &observation,
                            &drivers,
                            &tls_connector,
                        )
                        .await?;
                    }

                    let req = hyper::Request::post(&path)
                        .header("host", &authority)
                        .body(DiagnosticBody::new(
                            request_body(payload.clone(), metrics.admission()),
                            request_observation.clone(),
                            true,
                        ))
                        .unwrap();
                    let start = Instant::now();
                    observation.stage("send_request");
                    match send_req.send_request(req).await {
                        Ok(resp) => {
                            use http_body_util::BodyExt;
                            let status = resp.status();
                            h1_counters.response_headers(resp.headers());
                            request_observation.headers(status, resp.version(), resp.headers());
                            let counters = h1_counters.clone();
                            let body = DiagnosticBody::new(
                                resp.into_body(),
                                request_observation.clone(),
                                false,
                            )
                            .map_frame(move |frame| {
                                if let Some(data) = frame.data_ref() {
                                    counters.data_frame(data.len());
                                }
                                frame
                            });
                            match body.collect().await {
                                Ok(body) => {
                                    let bytes = body.to_bytes();
                                    let latency = start.elapsed().as_micros() as u64;
                                    let valid = record_http_echo_result(
                                        &mut metrics,
                                        protocol_label,
                                        status,
                                        bytes.len(),
                                        payload.len(),
                                        bytes.as_ref() == payload.as_ref(),
                                        latency,
                                        if diagnostic.enabled() {
                                            &[]
                                        } else {
                                            bytes.as_ref()
                                        },
                                    );
                                    request_observation.complete(valid);
                                    if !valid {
                                        break;
                                    }
                                }
                                Err(error) => {
                                    request_observation.error(h1_error_class(&error));
                                    report_transport_error(protocol_label, "response body", &error);
                                    metrics.record_error();
                                }
                            }
                        }
                        Err(error) => {
                            // Break out of the per-task loop on connection-level
                            // send errors (matches run_http2 / run_grpc). Without
                            // the break, a broken connection that reports fast
                            // errors without flipping is_closed() can spin the
                            // loop ~millions of times per second, inflating
                            // total_errors into the tens of millions at large
                            // payload sizes. Dropping the task is preferable —
                            // the other N-1 workers continue producing clean
                            // throughput data.
                            request_observation.error(h1_error_class(&error));
                            report_transport_error(protocol_label, "send_request", &error);
                            metrics.record_error();
                            break;
                        }
                    }
                    observation.stage("next_request");
                }
                if reconnects > 0 {
                    eprintln!(
                        "[http1] task reconnected {reconnects} times over {} requests",
                        metrics.total_requests
                    );
                }
                Ok(metrics.finish_worker())
            }
            .await;
            trace.returned(result.is_ok());
            result
        }));
    }

    let mut combined = phases.finish(handles).await;
    drivers.retire(&diagnostic, DRIVER_BOUND).await;
    if let Some(phases) = combined.phases.as_mut() {
        phases.h1_diagnostic = diagnostic.report();
    }
    Ok(combined)
}

// ── HTTP/2 ───────────────────────────────────────────────────────────────────

async fn run_http2(args: &BenchArgs) -> anyhow::Result<()> {
    use http_body_util::BodyExt;
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioTimer};
    let observer = Observer::new(args.h2_observe, "client_h2", false);
    if args.h2_observe && args.target.starts_with("https://") && args.ca_cert.is_none() {
        anyhow::bail!("H2 observation over TLS requires --ca-cert");
    }

    let is_tls = args.target.starts_with("https://");
    let url: http::Uri = args.target.parse().context("invalid target URL")?;
    let host = url.host().context("no host in URL")?;
    let port = url.port_u16().unwrap_or(if is_tls { 443 } else { 80 });
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .context("invalid address")?;
    // HTTP/2 requires requests built with a full absolute URI so hyper can
    // populate the mandatory `:authority` pseudo-header. Using only the path
    // (e.g. "/echo") emits a HEADERS frame with no `:authority`, which
    // strict HTTP/2 servers (Envoy) reject as a "Violation in HTTP
    // messaging rule" protocol error — GOAWAY + broken pipe on every
    // stream, 0 RPS. See RFC 9113 §8.3.1.
    let authority = format!("{host}:{port}");
    let request_uri = format!(
        "{}://{}{}",
        if is_tls { "https" } else { "http" },
        authority,
        url.path()
    );

    let mut phases =
        Phases::new(Duration::from_secs(args.duration)).with_payload(args.payload_size);
    let connections = phases.connections();

    let tls_cfg = if is_tls {
        // Force ALPN to h2-only on the client side. The shared
        // `make_client_tls_config_insecure()` helper defaults to
        // `["h2", "http/1.1"]`; against a strict server that ONLY advertises
        // `["h2"]` (e.g. Envoy with the h2 route config), some TLS stacks
        // have been observed to negotiate http/1.1 when both sides offer
        // the protocol in different orders — the downstream hyper h2
        // handshake then fails on the first send_request, producing the
        // classic 0 RPS / 100 errors pattern. Offering only h2 guarantees
        // we either get h2 or fail the TLS handshake cleanly.
        let mut cfg = if let Some(path) = &args.ca_cert {
            let pem = std::fs::read(path).context("reading H2 CA")?;
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(pem.as_slice()) {
                roots.add(cert?)?;
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        } else {
            tls_utils::make_client_tls_config_insecure()
        };
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        Some(Arc::new(cfg))
    } else {
        None
    };

    // Build an HTTP/2 client builder with optimized flow-control settings.
    // The default 64 KB stream window throttles throughput on modern networks;
    // 8 MiB stream + 32 MiB connection windows match the gateway's tuned defaults.
    let make_h2_builder = || {
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder
            .timer(TokioTimer::new())
            .initial_stream_window_size(8_388_608) // 8 MiB
            .initial_connection_window_size(33_554_432) // 32 MiB
            .adaptive_window(true) // BDP-based adaptive flow control
            .max_frame_size(1_048_576); // 1 MiB
        builder
    };

    // HTTP/2 multiplexes many streams over fewer connections. Use a
    // connection pool sized to balance multiplexing benefit vs contention.
    // ~10 streams per connection is a good balance for throughput.
    let num_conns = std::cmp::max(
        1,
        std::cmp::min(
            args.concurrency as usize,
            args.concurrency as usize / 10 + 1,
        ),
    );
    let mut senders = Vec::with_capacity(num_conns);
    let mut drivers = Vec::with_capacity(num_conns);

    for connection_id in 1..=num_conns {
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        tcp.set_nodelay(true)?;
        let host_str = host.to_string();

        let send_req = if let Some(ref tls_cfg) = tls_cfg {
            let connector = tokio_rustls::TlsConnector::from(tls_cfg.clone());
            let server_name = rustls::pki_types::ServerName::try_from(host_str)
                .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?;
            let tls_stream = connector.connect(server_name, tcp).await?;
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let (sr, conn) = make_h2_builder().handshake(io).await?;
            let connection = connections.opened();
            let events = observer.clone();
            drivers.push(tokio::spawn(async move {
                let _connection = connection;
                let result = conn.await;
                events.record(
                    connection_id,
                    None,
                    None,
                    "driver_terminated",
                    result.as_ref().err().map(|e| e as &dyn std::error::Error),
                );
            }));
            sr
        } else {
            let io = hyper_util::rt::TokioIo::new(tcp);
            let (sr, conn) = make_h2_builder().handshake(io).await?;
            let connection = connections.opened();
            let events = observer.clone();
            drivers.push(tokio::spawn(async move {
                let _connection = connection;
                let result = conn.await;
                events.record(
                    connection_id,
                    None,
                    None,
                    "driver_terminated",
                    result.as_ref().err().map(|e| e as &dyn std::error::Error),
                );
            }));
            sr
        };
        senders.push(send_req);
        observer.record(connection_id, None, None, "connection_opened", None);
    }

    let payload = Bytes::from(make_payload(args.payload_size));

    // Distribute concurrent tasks across the connection pool.
    // hyper's http2 SendRequest is Clone and supports concurrent streams.
    let mut handles = Vec::new();
    for i in 0..args.concurrency {
        let mut send_req = senders[i as usize % num_conns].clone();
        let connection_id = i as usize % num_conns + 1;
        let events = observer.clone();
        let uri = request_uri.clone();
        let payload = payload.clone();
        let mut metrics = phases.worker();
        handles.push(tokio::spawn(async move {
            while metrics.next_request().await {
                let req = hyper::Request::post(&uri)
                    .body(request_body(payload.clone(), metrics.admission()))
                    .unwrap();
                let start = Instant::now();
                match send_req.send_request(req).await {
                    Ok(resp) => {
                        let status = resp.status();
                        match resp.into_body().collect().await {
                            Ok(body) => {
                                let bytes = body.to_bytes();
                                let latency = start.elapsed().as_micros() as u64;
                                if !record_http_echo_result(
                                    &mut metrics,
                                    "HTTP/2",
                                    status,
                                    bytes.len(),
                                    payload.len(),
                                    bytes.as_ref() == payload.as_ref(),
                                    latency,
                                    bytes.as_ref(),
                                ) {
                                    events.record(
                                        connection_id,
                                        Some(i as usize),
                                        None,
                                        "response_validation_failed",
                                        None,
                                    );
                                    break;
                                }
                            }
                            Err(error) => {
                                report_transport_error("HTTP/2", "response body", &error);
                                events.record(
                                    connection_id,
                                    Some(i as usize),
                                    None,
                                    "response_body_error",
                                    Some(&error),
                                );
                                metrics.record_error();
                            }
                        }
                    }
                    Err(error) => {
                        report_transport_error("HTTP/2", "send_request", &error);
                        events.record(
                            connection_id,
                            Some(i as usize),
                            None,
                            "send_request_error",
                            Some(&error),
                        );
                        metrics.record_error();
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(metrics.finish_worker())
        }));
    }

    let mut combined = phases.finish(handles).await;
    if args.h2_observe {
        let close = Instant::now();
        if let Some(phases) = &mut combined.phases {
            phases.transport_close_start_monotonic_secs =
                Some(multi_protocol_perf::phases::monotonic_secs());
        }
        observer.record(0, None, None, "senders_dropped", None);
        drop(senders);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        for (index, mut driver) in drivers.into_iter().enumerate() {
            match tokio::time::timeout_at(deadline, &mut driver).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    observer.record(index + 1, None, None, "driver_join_failed", Some(&error));
                    combined.record_error();
                }
                Err(error) => {
                    observer.record(
                        index + 1,
                        None,
                        None,
                        "driver_observation_timeout",
                        Some(&error),
                    );
                    driver.abort();
                    let _ = driver.await;
                    if let Some(phases) = &mut combined.phases {
                        phases.transport_close_timed_out = true;
                    }
                }
            }
        }
        if let Some(phases) = &mut combined.phases {
            phases.transport_close_secs = close.elapsed().as_secs_f64();
            observer.attach(phases);
        }
    }
    print_results(&combined, "HTTP/2", args);
    Ok(())
}

// ── HTTP/3 ───────────────────────────────────────────────────────────────────

async fn run_http3(args: &BenchArgs) -> anyhow::Result<()> {
    let url: http::Uri = args.target.parse().context("invalid target URL")?;
    let host = url.host().context("no host in URL")?;
    let port = url.port_u16().unwrap_or(443);
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .context("invalid address")?;
    let path = url.path().to_string();

    let mut phases = Phases::new(Duration::from_secs(args.duration))
        .with_payload(args.payload_size)
        .with_observation_settle(Duration::from_millis(750));
    let connections = phases.connections();
    let client_cfg = tls_utils::make_h3_client_config_insecure();

    // HTTP/3 multiplexes streams over QUIC connections. Use a connection pool
    // similar to HTTP/2: ~10 streams per connection for good throughput balance.
    let num_conns = std::cmp::max(
        1,
        std::cmp::min(
            args.concurrency as usize,
            args.concurrency as usize / 10 + 1,
        ),
    );
    let host_str = host.to_string();
    let full_uri = format!("https://{host_str}:{port}{path}");

    // Create a pool of QUIC connections with shared endpoints
    let mut senders: Vec<h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>> =
        Vec::with_capacity(num_conns);

    let mut endpoints = Vec::with_capacity(num_conns);
    let mut drivers = Vec::with_capacity(num_conns);
    let mut transports = Vec::with_capacity(num_conns);
    let mut events = Vec::new();
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    for connection_id in 0..num_conns {
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        endpoint.set_default_client_config(client_cfg.clone());

        let conn = endpoint
            .connect(addr, &host_str)
            .map_err(|e| anyhow::anyhow!("quinn connect: {e}"))?
            .await
            .map_err(|e| anyhow::anyhow!("quinn connect: {e}"))?;
        events.push(TransportEvent::new(
            connection_id,
            "connected",
            format!(
                "local={} peer={}",
                endpoint.local_addr()?,
                conn.remote_address()
            ),
        ));
        transports.push(conn.clone());
        let (mut driver, send_req) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(|e| anyhow::anyhow!("h3 handshake: {e}"))?;
        endpoints.push(endpoint);
        let connection = connections.opened();
        // h3 driver must be polled concurrently to process connection frames
        drivers.push(tokio::spawn(async move {
            let _connection = connection;
            let result = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
            TransportEvent::new(
                connection_id,
                "driver_closed",
                format!("h3={result:?}; quic={:?}", conn.close_reason()),
            )
        }));
        senders.push(send_req);
    }

    let payload = Bytes::from(make_payload(args.payload_size));

    // Distribute concurrent tasks across the connection pool
    let mut handles = Vec::new();
    for i in 0..args.concurrency {
        let event_tx = event_tx.clone();
        let connection_id = i as usize % num_conns;
        let mut send_req = senders[i as usize % num_conns].clone();
        let full_uri = full_uri.clone();
        let payload = payload.clone();
        let mut metrics = phases.worker();
        handles.push(tokio::spawn(async move {
            while metrics.next_request().await {
                let req = http::Request::builder()
                    .method("POST")
                    .uri(&full_uri)
                    .body(())
                    .unwrap();
                let start = Instant::now();
                match send_req.send_request(req).await {
                    Ok(mut stream) => {
                        metrics.admitted();
                        if let Err(e) = stream.send_data(payload.clone()).await {
                            eprintln!("  h3 send_data error: {e}");
                            let _ = event_tx.send(TransportEvent::new(
                                connection_id,
                                "send_data_failed",
                                e.to_string(),
                            ));
                            metrics.record_error();
                            break;
                        }
                        if let Err(e) = stream.finish().await {
                            eprintln!("  h3 finish error: {e}");
                            let _ = event_tx.send(TransportEvent::new(
                                connection_id,
                                "finish_failed",
                                e.to_string(),
                            ));
                            metrics.record_error();
                            break;
                        }
                        match stream.recv_response().await {
                            Ok(resp) => {
                                let status = resp.status();
                                let mut body_bytes = 0usize;
                                let mut body_matches = true;
                                let mut recv_err: Option<String> = None;
                                loop {
                                    match stream.recv_data().await {
                                        Ok(Some(mut chunk)) => {
                                            let chunk_len = chunk.remaining();
                                            if body_matches {
                                                if body_bytes + chunk_len > payload.len() {
                                                    body_matches = false;
                                                } else {
                                                    let chunk_bytes =
                                                        chunk.copy_to_bytes(chunk_len);
                                                    let expected = &payload
                                                        [body_bytes..body_bytes + chunk_len];
                                                    body_matches = chunk_bytes.as_ref() == expected;
                                                }
                                            }
                                            body_bytes += chunk_len;
                                        }
                                        Ok(None) => break,
                                        Err(e) => {
                                            recv_err = Some(e.to_string());
                                            break;
                                        }
                                    }
                                }
                                if let Some(e) = recv_err {
                                    let _ = event_tx.send(TransportEvent::new(
                                        connection_id,
                                        "recv_data_failed",
                                        e.clone(),
                                    ));
                                    eprintln!(
                                        "  h3 recv_data error after {} bytes (expected {}): {}",
                                        body_bytes,
                                        payload.len(),
                                        e
                                    );
                                    // Treat H3 receive errors like H1/H2
                                    // connection-level failures: retire this
                                    // worker because the pooled QUIC connection
                                    // may be wedged.
                                    metrics.record_error();
                                    break;
                                } else {
                                    let latency = start.elapsed().as_micros() as u64;
                                    if !record_http_echo_result(
                                        &mut metrics,
                                        "HTTP/3",
                                        status,
                                        body_bytes,
                                        payload.len(),
                                        body_matches,
                                        latency,
                                        &[],
                                    ) {
                                        let _ = event_tx.send(TransportEvent::new(
                                            connection_id,
                                            "echo_validation_failed",
                                            format!("status={status} bytes={body_bytes}"),
                                        ));
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("  h3 recv_response error: {e}");
                                let _ = event_tx.send(TransportEvent::new(
                                    connection_id,
                                    "recv_response_failed",
                                    e.to_string(),
                                ));
                                metrics.record_error();
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("  h3 send_request error: {e}");
                        let _ = event_tx.send(TransportEvent::new(
                            connection_id,
                            "send_request_failed",
                            e.to_string(),
                        ));
                        metrics.record_error();
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(metrics.finish_worker())
        }));
    }

    let mut combined = phases.finish(handles).await;
    while let Ok(event) = event_rx.try_recv() {
        events.push(event);
    }
    // Preserve live sockets for an ending passive observation. No requests are
    // offered here, and this time is excluded from measured work and drain.
    let observation_started = Instant::now();
    tokio::time::sleep(Duration::from_millis(750)).await;
    if let Some(phases) = &mut combined.phases {
        phases.observation_hold_secs = observation_started.elapsed().as_secs_f64();
    }
    let close_started = Instant::now();
    events.push(TransportEvent::new(0, "retirement_started", String::new()));
    drop(senders);
    for (connection_id, endpoint) in endpoints.iter().enumerate() {
        events.push(TransportEvent::new(
            connection_id,
            "local_close_requested",
            format!(
                "benchmark drained; stats={:?}",
                transports[connection_id].stats()
            ),
        ));
        endpoint.close(0u32.into(), b"benchmark drained");
    }
    let close_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    for (connection_id, endpoint) in endpoints.into_iter().enumerate() {
        if tokio::time::timeout_at(close_deadline, endpoint.wait_idle())
            .await
            .is_err()
        {
            eprintln!("H3 endpoint close timed out");
            if let Some(phases) = &mut combined.phases {
                phases.transport_close_timed_out = true;
            }
            events.push(TransportEvent::new(
                connection_id,
                "idle_timeout",
                String::new(),
            ));
        } else {
            events.push(TransportEvent::new(
                connection_id,
                "endpoint_idle",
                String::new(),
            ));
        }
    }
    for (connection_id, mut driver) in drivers.into_iter().enumerate() {
        match tokio::time::timeout_at(close_deadline, &mut driver).await {
            Ok(Ok(event)) => events.push(event),
            Ok(Err(error)) => {
                events.push(TransportEvent::new(
                    connection_id,
                    "driver_join_failed",
                    error.to_string(),
                ));
                if let Some(phases) = &mut combined.phases {
                    phases.transport_close_timed_out = true;
                }
            }
            Err(error) => {
                driver.abort();
                let _ = driver.await;
                events.push(TransportEvent::new(
                    connection_id,
                    "driver_join_failed",
                    error.to_string(),
                ));
                if let Some(phases) = &mut combined.phases {
                    phases.transport_close_timed_out = true;
                }
            }
        }
    }
    if let Some(phases) = &mut combined.phases {
        phases.transport_close_secs = close_started.elapsed().as_secs_f64();
        phases.transport_close_start_unix_secs = events
            .iter()
            .find(|event| event.event == "retirement_started")
            .map(|event| event.unix_secs);
        phases.transport_close_start_monotonic_secs = events
            .iter()
            .find(|event| event.event == "retirement_started")
            .and_then(|event| event.monotonic_secs);
        phases.set_transport_events(events);
    }
    print_results(&combined, "HTTP/3", args);
    Ok(())
}

// ── WebSocket ────────────────────────────────────────────────────────────────

async fn run_ws(args: &BenchArgs) -> anyhow::Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::Connector;
    use tokio_tungstenite::tungstenite::Message;

    let mut phases =
        Phases::new(Duration::from_secs(args.duration)).with_payload(args.payload_size);
    let connections = phases.connections();
    let mut handles = Vec::new();
    let payload = make_payload(args.payload_size);

    // For wss://, plug our insecure rustls ClientConfig so tungstenite doesn't
    // reject proto_backend's self-signed cert. For ws://, pass None so the
    // default plaintext path is used.
    //
    // ALPN is restricted to `http/1.1` only: the shared helper advertises
    // `h2` first by default, which HTTP/2-capable gateways (Ferrum defaults,
    // Tyk with enable_http2, Kong with http2 listen flag) will happily
    // negotiate — and then the WebSocket upgrade (an HTTP/1.1-only
    // mechanism) fails at handshake time, producing 0 RPS. WSS clients
    // must explicitly offer only http/1.1 to force the gateway down the
    // WebSocket-upgradeable path.
    let connector: Option<Connector> = if args.target.starts_with("wss://") {
        let mut tls_cfg = tls_utils::make_client_tls_config_insecure();
        tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Some(Connector::Rustls(Arc::new(tls_cfg)))
    } else {
        None
    };

    // Keep this below the harness wall-clock kill switch. The current matrix
    // tops out at 5 MiB payloads; tune if substantially larger frames are added.
    let read_timeout = Duration::from_secs(30);
    for _ in 0..args.concurrency {
        let target = args.target.clone();
        let payload = payload.clone();
        let connector = connector.clone();
        let mut metrics = phases.worker();
        let connections = connections.clone();
        handles.push(tokio::spawn(async move {
            // Count connect failures as errors in the JSON report rather than
            // propagating via `?`. Otherwise the task returns Err, collect_results
            // prints a stderr line, and the aggregated metrics show 0 errors /
            // 0 requests — indistinguishable from "bench didn't run" and
            // suppressed by the aggregator's all-zero scenario filter.
            let ws = match tokio_tungstenite::connect_async_tls_with_config(
                &target, None, false, connector,
            )
            .await
            {
                Ok((ws, _)) => ws,
                Err(e) => {
                    eprintln!("  task error: ws connect: {e}");
                    metrics.record_error();
                    return Ok::<_, anyhow::Error>(metrics.finish_worker());
                }
            };
            let _connection = connections.opened();
            let (mut write, mut read) = ws.split();

            while metrics.next_request().await {
                let start = Instant::now();
                metrics.admitted();
                if let Err(error) = write.send(Message::Binary(payload.clone())).await {
                    report_transport_error("ws", "send", &error);
                    metrics.record_error();
                    break;
                }
                // Only count full binary echoes as successes. Gateway close
                // frames, such as Kong's default 1009 payload-limit close, are
                // failures for this echo benchmark.
                let echoed_len = match tokio::time::timeout(read_timeout, async {
                    loop {
                        match read.next().await {
                            Some(Ok(Message::Binary(data))) => {
                                let len = data.len();
                                if len != payload.len() {
                                    break Err(format!(
                                        "echo length mismatch: got {len} bytes, expected {}",
                                        payload.len()
                                    ));
                                }
                                if data.as_slice() != payload.as_slice() {
                                    break Err(format!(
                                        "echo payload mismatch: {len} bytes had wrong content"
                                    ));
                                }
                                break Ok(len);
                            }
                            Some(Ok(Message::Text(data))) => {
                                break Err(format!(
                                    "unexpected text frame of {} bytes",
                                    data.len()
                                ));
                            }
                            Some(Ok(Message::Close(frame))) => {
                                break Err(format!("close frame received: {frame:?}"));
                            }
                            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                            Some(Ok(other)) => break Err(format!("unexpected frame: {other:?}")),
                            Some(Err(e)) => break Err(e.to_string()),
                            None => break Err("connection closed before echo".to_string()),
                        }
                    }
                })
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(format!(
                        "timed out waiting {}s for echo",
                        read_timeout.as_secs()
                    )),
                };
                match echoed_len {
                    Ok(len) => {
                        let latency = start.elapsed().as_micros() as u64;
                        metrics.record(latency, len);
                    }
                    Err(e) => {
                        eprintln!("  ws echo error: {e}");
                        metrics.record_error();
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(metrics.finish_worker())
        }));
    }

    let combined = phases.finish(handles).await;
    print_results(&combined, "WebSocket", args);
    Ok(())
}

// ── gRPC ─────────────────────────────────────────────────────────────────────

async fn run_grpc(args: &BenchArgs) -> anyhow::Result<()> {
    use bench_proto::EchoRequest;
    use bench_proto::bench_service_client::BenchServiceClient;
    use multi_protocol_perf::transport::{GrpcConnectionIdentity, GrpcConnector};

    let observer = Observer::new(args.h2_observe, "client_grpc", false);

    let mut phases =
        Phases::new(Duration::from_secs(args.duration)).with_payload(args.payload_size);
    let connections = phases.connections();
    let payload = make_payload(args.payload_size);

    // gRPC TLS requires explicit trust configuration — tonic 0.14 has no
    // "accept invalid certs" toggle, so without --ca-cert the handshake
    // against the self-signed benchmark backend would fail and every bench
    // would emit rps=0. Read the CA once here and reuse for every channel.
    let is_tls = args.target.starts_with("https://");
    let ca_pem =
        if is_tls {
            let ca_path = args
                .ca_cert
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("gRPC over TLS requires --ca-cert <path-to-pem>"))?;
            Some(std::fs::read(ca_path).with_context(|| {
                format!("reading gRPC CA certificate from {}", ca_path.display())
            })?)
        } else {
            None
        };

    // gRPC uses HTTP/2 multiplexing. Share a pool of channels across tasks
    // (~10 streams per channel) instead of one channel per task.
    let num_conns = std::cmp::max(
        1,
        std::cmp::min(
            args.concurrency as usize,
            args.concurrency as usize / 10 + 1,
        ),
    );
    let mut channels = Vec::with_capacity(num_conns);

    for channel_id in 1..=num_conns {
        let mut endpoint = tonic::transport::Channel::from_shared(args.target.clone())
            .map_err(|e| anyhow::anyhow!("invalid gRPC target: {e}"))?
            .initial_stream_window_size(8_388_608) // 8 MiB (vs 64 KB default)
            .initial_connection_window_size(33_554_432) // 32 MiB
            .tcp_nodelay(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_while_idle(true);

        if let Some(pem) = &ca_pem {
            let ca = tonic::transport::Certificate::from_pem(pem);
            let tls = tonic::transport::ClientTlsConfig::new()
                .ca_certificate(ca)
                // Benchmark certs are issued for "localhost"; force SNI/name
                // check to match regardless of the numeric host in the URI.
                .domain_name("localhost");
            endpoint = endpoint
                .tls_config(tls)
                .map_err(|e| anyhow::anyhow!("gRPC TLS config for {}: {e}", args.target))?;
        }

        let current_connection = Arc::new(GrpcConnectionIdentity::default());
        let channel = endpoint
            .connect_with_connector(GrpcConnector {
                connections: connections.clone(),
                observer: observer.clone(),
                channel_id,
                current_connection: current_connection.clone(),
            })
            .await
            .map_err(|e| anyhow::anyhow!("gRPC connect to {}: {e}", args.target))?;
        channels.push((channel, current_connection));
    }

    let mut handles = Vec::new();
    for i in 0..args.concurrency {
        let (channel, current_connection) = channels[i as usize % num_conns].clone();
        let channel_id = i as usize % num_conns + 1;
        let events = observer.clone();
        let payload = payload.clone();
        let mut metrics = phases.worker();
        handles.push(tokio::spawn(async move {
            // tonic defaults to a 4 MiB cap on request + response message
            // size; the bench sweeps payloads up to 5 MiB. Without raising
            // both caps, every 5 MiB RPC fails with OutOfRange on the
            // encode side (client) or RESOURCE_EXHAUSTED on the decode
            // side (server). Must match proto_backend's cap.
            // Admission shares the worker's atomics; next_request refreshes it.
            let mut client = BenchServiceClient::new(ObservedChannel {
                inner: channel,
                admission: metrics.admission(),
            })
            .max_decoding_message_size(8 * 1024 * 1024)
            .max_encoding_message_size(8 * 1024 * 1024);
            while metrics.next_request().await {
                let connection_before = current_connection.snapshot();
                let req = tonic::Request::new(EchoRequest {
                    payload: payload.clone(),
                });
                let start = Instant::now();
                match client.unary_echo(req).await {
                    Ok(resp) => {
                        let latency = start.elapsed().as_micros() as u64;
                        let response = resp.into_inner().payload;
                        if !record_echo_result(&mut metrics, "gRPC", &response, &payload, latency) {
                            events.record(
                                0,
                                Some(i as usize),
                                Some(channel_id),
                                "response_validation_failed",
                                None,
                            );
                            break;
                        }
                    }
                    Err(status) => {
                        report_transport_error("gRPC", "unary_echo", &status);
                        // Includes failed/cancelled reconnects and retirement.
                        // Zero means unknown, never a channel index.
                        let connection_id =
                            current_connection.connection_id_since(connection_before);
                        events.record(
                            connection_id,
                            Some(i as usize),
                            Some(channel_id),
                            "unary_echo_error",
                            Some(&status),
                        );
                        metrics.record_error();
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(metrics.finish_worker())
        }));
    }

    let mut combined = phases.finish(handles).await;
    if args.h2_observe {
        // Dropping a Channel does not expose tonic's detached driver result.
        // Capture already observed socket events; do not claim graceful close.
        drop(channels);
        if let Some(phases) = &mut combined.phases {
            observer.attach(phases);
        }
    }
    print_results(&combined, "gRPC", args);
    Ok(())
}

// ── TCP ──────────────────────────────────────────────────────────────────────

// TCP echoes are closed-loop like the other protocols: one payload per worker.
// Read concurrently with chunked writes so large TLS echoes cannot deadlock on
// full socket buffers. The yield releases the split TLS stream between chunks.
async fn tcp_echo<S>(
    stream: S,
    payload: Vec<u8>,
    mut metrics: BenchMetrics,
    connections: Connections,
    label: &str,
) -> anyhow::Result<BenchMetrics>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let _connection = connections.opened();
    let (mut read, mut write) = tokio::io::split(stream);
    let mut response = vec![0; payload.len()];
    while metrics.next_request().await {
        let start = Instant::now();
        metrics.admitted();
        let exchange = echo_exchange(&mut read, &mut write, &payload, &mut response);
        match tokio::time::timeout(Duration::from_secs(15), exchange).await {
            Ok(Ok(_)) => {
                if !record_echo_result(
                    &mut metrics,
                    label,
                    &response,
                    &payload,
                    start.elapsed().as_micros() as u64,
                ) {
                    break;
                }
            }
            error => {
                eprintln!("{label} echo failed: {error:?}");
                metrics.record_error();
                break;
            }
        }
    }
    match tokio::time::timeout(Duration::from_secs(5), write.shutdown()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("{label} shutdown failed: {error}"),
        Err(_) => {
            eprintln!("{label} shutdown timed out");
            metrics.transport_close_timed_out = true;
        }
    }
    Ok(metrics.finish_worker())
}

#[cfg(test)]
#[path = "tests/support/tcp_echo_tests.rs"]
mod tcp_echo_tests;

async fn run_tcp(args: &BenchArgs) -> anyhow::Result<()> {
    let addr: SocketAddr = args.target.parse().context("invalid TCP target address")?;
    let mut phases =
        Phases::new(Duration::from_secs(args.duration)).with_payload(args.payload_size);
    let connections = phases.connections();
    let payload = make_payload(args.payload_size);
    let tls_cfg = args
        .tls
        .then(|| Arc::new(tls_utils::make_client_tls_config_insecure_raw()));
    let mut handles = Vec::new();
    for _ in 0..args.concurrency {
        let payload = payload.clone();
        let tls_cfg = tls_cfg.clone();
        let metrics = phases.worker();
        let connections = connections.clone();
        handles.push(tokio::spawn(async move {
            let tcp = tokio::net::TcpStream::connect(addr).await?;
            tcp.set_nodelay(true)?;
            if let Some(tls_cfg) = tls_cfg {
                let connector = tokio_rustls::TlsConnector::from(tls_cfg);
                let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string())?;
                let stream = connector.connect(server_name, tcp).await?;
                tcp_echo(stream, payload, metrics, connections, "TCP+TLS").await
            } else {
                tcp_echo(tcp, payload, metrics, connections, "TCP").await
            }
        }));
    }
    let combined = phases.finish(handles).await;
    let label = if args.tls { "TCP+TLS" } else { "TCP" };
    print_results(&combined, label, args);
    Ok(())
}

// ── UDP ──────────────────────────────────────────────────────────────────────

#[allow(unused_assignments)] // next_timeout assignments are defensive — drain loop may not always produce Timeout
async fn run_udp(args: &BenchArgs) -> anyhow::Result<()> {
    let addr: SocketAddr = args.target.parse().context("invalid UDP target address")?;
    let mut phases =
        Phases::new(Duration::from_secs(args.duration)).with_payload(args.payload_size);
    let connections = phases.connections();
    let mut handles = Vec::new();
    let payload = make_payload(args.payload_size);
    let use_dtls = args.tls;

    // Generate one cert for all DTLS connections (key gen is CPU-intensive)
    let shared_cert = if use_dtls {
        Some(
            dimpl::certificate::generate_self_signed_certificate()
                .map_err(|e| anyhow::anyhow!("cert gen: {e}"))?,
        )
    } else {
        None
    };

    for _ in 0..args.concurrency {
        let payload = payload.clone();
        let shared_cert = shared_cert.clone();
        let mut metrics = phases.worker();
        let connections = connections.clone();
        handles.push(tokio::spawn(async move {
            if use_dtls {
                use dimpl::{Config, Dtls, Output};

                let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
                    .await
                    .map_err(|e| anyhow::anyhow!("udp bind: {e}"))?;
                sock.connect(addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("udp connect: {e}"))?;

                let cert = shared_cert.unwrap();
                let config = Arc::new(Config::default());
                let mut dtls = Dtls::new_auto(config, cert, std::time::Instant::now());
                dtls.set_active(true); // client

                // Drive handshake
                let mut out_buf = vec![0u8; 65536];
                let mut recv_buf = vec![0u8; 65536];
                let hs_deadline = std::time::Instant::now() + Duration::from_secs(10);
                let mut next_timeout: Option<std::time::Instant>;
                let mut connected = false;

                // Kick off handshake — drain until Timeout
                loop {
                    match dtls.poll_output(&mut out_buf) {
                        Output::Packet(d) => { sock.send(d).await.map_err(|e| anyhow::anyhow!("hs send: {e}"))?; }
                        Output::Timeout(t) => { next_timeout = Some(t); break; }
                        _ => {} // PeerCert, KeyingMaterial, etc. — continue
                    }
                }

                while !connected {
                    if std::time::Instant::now() > hs_deadline {
                        return Err(anyhow::anyhow!("dtls handshake timed out after 10s"));
                    }
                    let sleep_dur = next_timeout
                        .map(|t| t.saturating_duration_since(std::time::Instant::now()))
                        .unwrap_or(Duration::from_secs(5));
                    tokio::select! {
                        Ok(len) = sock.recv(&mut recv_buf) => {
                            dtls.handle_packet(&recv_buf[..len]).map_err(|e| anyhow::anyhow!("hs pkt: {e}"))?;
                        }
                        _ = tokio::time::sleep(sleep_dur) => {
                            if let Some(t) = next_timeout
                                && std::time::Instant::now() >= t
                            {
                                dtls.handle_timeout(std::time::Instant::now()).map_err(|e| anyhow::anyhow!("hs timeout: {e}"))?;
                                next_timeout = None;
                            }
                        }
                    }
                    // Drain all outputs until Timeout (dimpl docs: Timeout
                    // is always the last variant in a poll cycle).
                    let mut just_connected = false;
                    loop {
                        match dtls.poll_output(&mut out_buf) {
                            Output::Packet(d) => { let _ = sock.send(d).await; }
                            Output::Timeout(t) => {
                                next_timeout = Some(t);
                                if just_connected {
                                    just_connected = false;
                                    continue;
                                }
                                break;
                            }
                            Output::Connected => {
                                just_connected = true;
                                connected = true;
                            }
                            _ => {} // PeerCert, KeyingMaterial, etc.
                        }
                    }
                }

                let _connection = connections.opened();
                // Connected — run echo benchmark using Sans-IO loop
                'benchmark: while metrics.next_request().await {
                    let start = Instant::now();
                    metrics.admitted();
                    dtls.send_application_data(&payload).map_err(|e| anyhow::anyhow!("dtls send: {e}"))?;

                    // Drain encrypted packets until Timeout
                    loop {
                        match dtls.poll_output(&mut out_buf) {
                            Output::Packet(d) => { sock.send(d).await.map_err(|e| anyhow::anyhow!("send: {e}"))?; }
                            Output::Timeout(t) => { next_timeout = Some(t); break; }
                            _ => {} // continue draining
                        }
                    }

                    // Wait for reply
                    let mut got_reply = false;
                    while !got_reply {
                        let sleep_dur = next_timeout
                            .map(|t| t.saturating_duration_since(std::time::Instant::now()))
                            .unwrap_or(Duration::from_secs(5));
                        tokio::select! {
                            result = sock.recv(&mut recv_buf) => {
                                match result {
                                    Ok(len) => {
                                        dtls.handle_packet(&recv_buf[..len]).map_err(|e| anyhow::anyhow!("pkt: {e}"))?;
                                    }
                                    Err(e) => {
                                        eprintln!("  dtls recv error: {e}");
                                        got_reply = true; // exit
                                    }
                                }
                            }
                            _ = tokio::time::sleep(sleep_dur) => {
                                if let Some(t) = next_timeout
                                    && std::time::Instant::now() >= t
                                {
                                    let _ = dtls.handle_timeout(std::time::Instant::now());
                                    next_timeout = None;
                                }
                            }
                        }
                        loop {
                            match dtls.poll_output(&mut out_buf) {
                                Output::Packet(d) => { let _ = sock.send(d).await; }
                                Output::Timeout(t) => { next_timeout = Some(t); break; }
                                Output::ApplicationData(d) => {
                                    let latency = start.elapsed().as_micros() as u64;
                                    if !record_echo_result(
                                        &mut metrics,
                                        "UDP+DTLS",
                                        d,
                                        &payload,
                                        latency,
                                    ) {
                                        break 'benchmark;
                                    }
                                    got_reply = true;
                                    break;
                                }
                                _ => {} // PeerCert, KeyingMaterial, etc.
                            }
                        }
                    }
                }
            } else {
                let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                sock.connect(addr).await?;
                let _connection = connections.opened();
                let mut buf = vec![0u8; 65535];
                // UDP is lossy by nature, and a misconfigured gateway (e.g.
                // stream proxy that accepts datagrams but never forwards a
                // reply) can leave `sock.recv` blocked forever. Without a
                // recv timeout, every task in the bench hangs past the
                // outer deadline and the workflow's 75-minute step budget
                // fires. Cap each round-trip at 1s; on timeout, count an
                // error and continue so legitimate packet loss doesn't
                // kill the task but a total backend silence still lets the
                // deadline check terminate the loop.
                let recv_timeout = Duration::from_secs(1);
                while metrics.next_request().await {
                    let start = Instant::now();
                    metrics.admitted();
                    if sock.send(&payload).await.is_err() {
                        metrics.record_error();
                        break;
                    }
                    match tokio::time::timeout(recv_timeout, sock.recv(&mut buf)).await {
                        Ok(Ok(n)) => {
                            let latency = start.elapsed().as_micros() as u64;
                            if !record_echo_result(
                                &mut metrics,
                                "UDP",
                                &buf[..n],
                                &payload,
                                latency,
                            ) {
                                break;
                            }
                        }
                        Ok(Err(_)) => {
                            metrics.record_error();
                            break;
                        }
                        Err(_) => {
                            metrics.record_error();
                            // Don't break — UDP loss is expected; let the
                            // outer deadline stop us if it's permanent.
                        }
                    }
                }
            }
            Ok::<_, anyhow::Error>(metrics.finish_worker())
        }));
    }

    let combined = phases.finish(handles).await;
    let proto_name = if args.tls { "UDP+DTLS" } else { "UDP" };
    print_results(&combined, proto_name, args);
    Ok(())
}

// ── Saturation (concurrent-connection breaking-point test) ───────────────────
//
// The shape of this test is deliberately different from the per-protocol
// throughput benches above. Throughput benches keep N connections busy and
// measure RPS. Saturation opens N keep-alive connections, sends one tiny
// heartbeat per connection per `heartbeat_interval_ms`, and watches for the
// gateway to start refusing connects, RST'ing established conns, or stalling
// the request loop. The metric of interest is "max N before breakage", not
// "RPS at fixed N".
//
// Connect failures are classified into refused / timeout / reset / TLS / other
// because the failure mode is itself the answer when comparing gateways:
// a Kong/nginx that exhausts `worker_connections` typically RSTs new connects;
// an Envoy at FD ceiling typically returns ECONNREFUSED; a TLS-terminating
// gateway that runs out of session memory tends to fail mid-handshake.
//
// `run_connection_saturation_bench.sh` invokes this with a series of N values
// (1K, 5K, 10K, ...) and walks the JSON breakdown to find the first N at
// which connect_success_rate drops below a threshold.

#[derive(Default)]
struct SaturateCounters {
    connect_attempts: AtomicU64,
    connect_successes: AtomicU64,
    connect_refused: AtomicU64,
    connect_timeout: AtomicU64,
    connect_reset: AtomicU64,
    connect_tls_error: AtomicU64,
    connect_other: AtomicU64,
    alive: AtomicI64,
    peak_alive: AtomicU64,
    heartbeats_attempted: AtomicU64,
    heartbeats_succeeded: AtomicU64,
    heartbeats_failed: AtomicU64,
    disconnects_during_hold: AtomicU64,
}

#[derive(serde::Serialize)]
struct SaturateReport {
    target: String,
    target_connections: u64,
    ramp_seconds: u64,
    hold_seconds: u64,
    heartbeat_interval_ms: u64,
    payload_size: usize,
    connect_attempts: u64,
    connect_successes: u64,
    connect_success_rate: f64,
    connect_refused: u64,
    connect_timeout: u64,
    connect_reset: u64,
    connect_tls_error: u64,
    connect_other: u64,
    peak_alive_connections: u64,
    alive_at_end: i64,
    heartbeats_attempted: u64,
    heartbeats_succeeded: u64,
    heartbeats_failed: u64,
    heartbeat_success_rate: f64,
    disconnects_during_hold: u64,
    p50_connect_us: u64,
    p99_connect_us: u64,
    p50_heartbeat_us: u64,
    p99_heartbeat_us: u64,
    /// (connect_successes - disconnects_during_hold) / connect_successes.
    /// 1.0 if every established connection survived the entire hold window.
    /// Required by the verdict because `peak_alive` + heartbeat success rate
    /// can BOTH be satisfied transiently while the gateway RSTs every conn
    /// after a single heartbeat — the case sustained-capacity benchmarks
    /// must catch.
    survivorship_rate: f64,
    /// heartbeats_attempted / expected_heartbeats_min. Diagnostic-only — not
    /// gating the verdict (timing variance during ramp can knock it under
    /// 1.0 even on healthy runs). Operators read this to spot cases where
    /// the gateway is up but starving the request loop.
    heartbeat_coverage: f64,
    /// "ok" if connect_success_rate ≥ 99% AND heartbeat_success_rate ≥ 99%
    /// AND peak_alive ≥ 99% × N AND survivorship_rate ≥ 99%; "broken"
    /// otherwise. Caller (run_connection_saturation_bench.sh) uses this as
    /// the binary "did this N succeed?" signal.
    verdict: &'static str,
}

fn classify_connect_error(err: &anyhow::Error) -> &'static str {
    let msg = format!("{err:?}").to_ascii_lowercase();
    // Order matters — TLS errors often also mention "reset"/"closed" in source chains.
    if msg.contains("invalid certificate")
        || msg.contains("tls")
        || msg.contains("handshake")
        || msg.contains("certificateverify")
        || msg.contains("badcertificate")
    {
        "tls"
    } else if msg.contains("connection refused") || msg.contains("econnrefused") {
        "refused"
    } else if msg.contains("timed out") || msg.contains("deadline") || msg.contains("timeout") {
        "timeout"
    } else if msg.contains("connection reset") || msg.contains("econnreset") {
        "reset"
    } else {
        "other"
    }
}

async fn connect_h1_saturate(
    addr: SocketAddr,
    tls: &Option<(
        tokio_rustls::TlsConnector,
        rustls::pki_types::ServerName<'static>,
    )>,
) -> anyhow::Result<hyper::client::conn::http1::SendRequest<http_body_util::Full<Bytes>>> {
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let _ = tcp.set_nodelay(true);
    if let Some((connector, server_name)) = tls {
        let tls_stream = connector.connect(server_name.clone(), tcp).await?;
        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let (sr, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sr)
    } else {
        let io = hyper_util::rt::TokioIo::new(tcp);
        let (sr, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sr)
    }
}

async fn run_saturate(args: &SaturateArgs) -> anyhow::Result<()> {
    use hdrhistogram::Histogram;
    use std::sync::Mutex;

    // A zero interval makes `next_beat += 0` produce a busy-spin loop that
    // pegs CPU until the test deadline, with garbage results. Enforce a
    // floor here rather than at parse-time because the workflow_dispatch
    // input is a free-form string — clap defaulting won't catch operators
    // typing 0.
    if args.heartbeat_interval_ms == 0 {
        anyhow::bail!("--heartbeat-interval-ms must be greater than 0");
    }

    let is_tls = args.target.starts_with("https://");
    let url: http::Uri = args.target.parse().context("invalid target URL")?;
    let host = url.host().context("no host in URL")?.to_string();
    let port = url.port_u16().unwrap_or(if is_tls { 443 } else { 80 });
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .context("invalid address")?;
    let path = url.path().to_string();
    let authority = format!("{host}:{port}");

    let tls_connector = if is_tls {
        let mut tls_cfg = tls_utils::make_client_tls_config_insecure();
        tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Some((
            tokio_rustls::TlsConnector::from(Arc::new(tls_cfg)),
            rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?,
        ))
    } else {
        None
    };

    let payload = Bytes::from(make_payload(args.payload_size));
    let counters = Arc::new(SaturateCounters::default());
    let connect_hist = Arc::new(Mutex::new(
        Histogram::<u64>::new_with_max(60_000_000, 3).context("histogram alloc")?,
    ));
    let heartbeat_hist = Arc::new(Mutex::new(
        Histogram::<u64>::new_with_max(60_000_000, 3).context("histogram alloc")?,
    ));

    let connect_timeout = Duration::from_millis(args.connect_timeout_ms);
    let heartbeat_interval = Duration::from_millis(args.heartbeat_interval_ms);
    let ramp = Duration::from_secs(args.ramp_seconds.max(1));
    let hold = Duration::from_secs(args.hold_seconds);
    let test_start = Instant::now();
    // Heartbeats only run during the [ramp_end, ramp_end + hold] window.
    // Without this gating, early-ramp connections would beat for ~ramp+hold
    // seconds while late-ramp connections beat for ~hold seconds, so total
    // request load varied with ramp_seconds and shifted the breaking point
    // independently of connection count. Keeping every connection's beat
    // window pinned to the same hold-after-ramp interval makes load
    // comparable across runs that tune ramp.
    let beat_window_start = test_start + ramp;
    let hold_until = beat_window_start + hold;

    if !args.json {
        eprintln!(
            "[saturate] target={} N={} ramp={}s hold={}s heartbeat={}ms{}",
            args.target,
            args.connections,
            args.ramp_seconds,
            args.hold_seconds,
            args.heartbeat_interval_ms,
            if is_tls { " (TLS)" } else { "" },
        );
    }

    // Spread connection attempts evenly over the ramp window. With N=50K and
    // ramp=30s that's ~1666 connects/sec — high but well within typical
    // client-side capacity given proper ulimit.
    let inter_connect = if args.connections > 1 {
        ramp / (args.connections as u32)
    } else {
        Duration::from_millis(0)
    };

    // Capture the scalar args used inside the spawned task as locals — the
    // task body needs a 'static closure, and `args: &SaturateArgs` doesn't
    // have a 'static lifetime. Cheap u64 copies, no per-task overhead.
    let total_connections = args.connections;
    let heartbeat_interval_ms = args.heartbeat_interval_ms;

    let mut handles = Vec::with_capacity(args.connections as usize);
    for i in 0..args.connections {
        let counters = counters.clone();
        let connect_hist = connect_hist.clone();
        let heartbeat_hist = heartbeat_hist.clone();
        let tls_connector = tls_connector.clone();
        let payload = payload.clone();
        let path = path.clone();
        let authority = authority.clone();
        let stagger = inter_connect.saturating_mul(i as u32);

        handles.push(tokio::spawn(async move {
            // Stagger so we don't all SYN at once.
            tokio::time::sleep(stagger).await;

            counters.connect_attempts.fetch_add(1, Ordering::Relaxed);
            let connect_start = Instant::now();
            let connect_result =
                tokio::time::timeout(connect_timeout, connect_h1_saturate(addr, &tls_connector))
                    .await;

            let mut send_req = match connect_result {
                Ok(Ok(s)) => {
                    let elapsed = connect_start.elapsed().as_micros() as u64;
                    let _ = connect_hist.lock().map(|mut h| {
                        let _ = h.record(elapsed);
                    });
                    counters.connect_successes.fetch_add(1, Ordering::Relaxed);
                    let now_alive = counters.alive.fetch_add(1, Ordering::Relaxed) + 1;
                    if now_alive > 0 {
                        let prev = counters.peak_alive.load(Ordering::Relaxed);
                        if (now_alive as u64) > prev {
                            counters
                                .peak_alive
                                .fetch_max(now_alive as u64, Ordering::Relaxed);
                        }
                    }
                    s
                }
                Ok(Err(e)) => {
                    match classify_connect_error(&e) {
                        "refused" => &counters.connect_refused,
                        "timeout" => &counters.connect_timeout,
                        "reset" => &counters.connect_reset,
                        "tls" => &counters.connect_tls_error,
                        _ => &counters.connect_other,
                    }
                    .fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(_) => {
                    counters.connect_timeout.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };

            // Hold connection idle until the ramp window completes, then enter
            // the heartbeat phase. A small per-connection phase offset spreads
            // the first heartbeat across [beat_window_start, beat_window_start
            // + heartbeat_interval] so we don't get an N-wide thundering herd
            // the moment ramp ends.
            let phase_offset = Duration::from_millis(
                i.saturating_mul(heartbeat_interval_ms) / total_connections.max(1),
            );
            let beat_start = beat_window_start + phase_offset;
            let now_pre_beat = Instant::now();
            if now_pre_beat < beat_start {
                tokio::time::sleep(beat_start - now_pre_beat).await;
            }

            // Heartbeat loop: one small POST per `heartbeat_interval_ms` until
            // hold window elapses. We send POST not GET because all the bench
            // backends expect /echo to receive a body matching the configured
            // payload size.
            let mut next_beat = Instant::now();
            let task_lost = loop {
                let now = Instant::now();
                if now >= hold_until {
                    break false;
                }
                if now < next_beat {
                    tokio::time::sleep(next_beat - now).await;
                    continue;
                }
                next_beat += heartbeat_interval;

                if send_req.is_closed() {
                    break true;
                }

                counters
                    .heartbeats_attempted
                    .fetch_add(1, Ordering::Relaxed);
                let req_start = Instant::now();
                let req = match hyper::Request::post(&path)
                    .header("host", &authority)
                    .body(http_body_util::Full::new(payload.clone()))
                {
                    Ok(r) => r,
                    Err(_) => {
                        counters.heartbeats_failed.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                match send_req.send_request(req).await {
                    Ok(resp) => {
                        use http_body_util::BodyExt;
                        let status = resp.status();
                        match resp.into_body().collect().await {
                            Ok(body) if status == http::StatusCode::OK => {
                                // Mirror the throughput-bench echo validation:
                                // a misrouted gateway, a degraded handler that
                                // 200s with an empty/mock body, or a stale
                                // health-check responder would all otherwise
                                // count as healthy heartbeats. Comparing bytes
                                // is the cheapest way to confirm /echo is
                                // genuinely round-tripping the payload.
                                let bytes = body.to_bytes();
                                if bytes.as_ref() == payload.as_ref() {
                                    let elapsed = req_start.elapsed().as_micros() as u64;
                                    let _ = heartbeat_hist.lock().map(|mut h| {
                                        let _ = h.record(elapsed);
                                    });
                                    counters
                                        .heartbeats_succeeded
                                        .fetch_add(1, Ordering::Relaxed);
                                } else {
                                    counters.heartbeats_failed.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            _ => {
                                counters.heartbeats_failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(_) => {
                        counters.heartbeats_failed.fetch_add(1, Ordering::Relaxed);
                        // Connection broken mid-hold — task is done.
                        break true;
                    }
                }
            };

            counters.alive.fetch_sub(1, Ordering::Relaxed);
            if task_lost {
                counters
                    .disconnects_during_hold
                    .fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // Wait for ramp + hold + small grace.
    let total = ramp + hold + Duration::from_secs(2);
    let _ = tokio::time::timeout(total + Duration::from_secs(15), async {
        for h in handles {
            let _ = h.await;
        }
    })
    .await;

    // Snapshot and report.
    let connect_attempts = counters.connect_attempts.load(Ordering::Relaxed);
    let connect_successes = counters.connect_successes.load(Ordering::Relaxed);
    let heartbeats_attempted = counters.heartbeats_attempted.load(Ordering::Relaxed);
    let heartbeats_succeeded = counters.heartbeats_succeeded.load(Ordering::Relaxed);
    let peak_alive = counters.peak_alive.load(Ordering::Relaxed);
    let alive_at_end = counters.alive.load(Ordering::Relaxed);
    let disconnects_during_hold = counters.disconnects_during_hold.load(Ordering::Relaxed);

    let connect_success_rate = if connect_attempts > 0 {
        connect_successes as f64 / connect_attempts as f64
    } else {
        0.0
    };
    let heartbeat_success_rate = if heartbeats_attempted > 0 {
        heartbeats_succeeded as f64 / heartbeats_attempted as f64
    } else {
        0.0
    };

    // Survivorship: of the connections that established, how many made it
    // through the hold window without being dropped? Without this signal,
    // a gateway that accepts N conns + processes one heartbeat each + then
    // RSTs them all gets connect_success=100% AND heartbeat_success=100%
    // (over a tiny denominator), which the older verdict scored "ok".
    let survivorship_rate = if connect_successes > 0 {
        let survived = connect_successes.saturating_sub(disconnects_during_hold);
        survived as f64 / connect_successes as f64
    } else {
        0.0
    };

    // Diagnostic: how close did we get to the heartbeat volume that a
    // healthy run *should* produce? Lower bound assumes every conn opened
    // at the END of ramp (worst stagger), so each gets only `hold_seconds /
    // heartbeat_interval` beats. Real coverage on a healthy run will be
    // somewhat higher than this floor because early-ramp conns get more
    // beats. Not gating — operators eyeball this to spot starved request
    // loops.
    let expected_heartbeats_per_conn = (args.hold_seconds * 1_000)
        .checked_div(args.heartbeat_interval_ms)
        .unwrap_or(0);
    let expected_heartbeats_min = connect_successes * expected_heartbeats_per_conn;
    let heartbeat_coverage = if expected_heartbeats_min > 0 {
        heartbeats_attempted as f64 / expected_heartbeats_min as f64
    } else {
        1.0
    };

    let (p50_connect, p99_connect) = connect_hist
        .lock()
        .map(|h| (h.value_at_quantile(0.50), h.value_at_quantile(0.99)))
        .unwrap_or((0, 0));
    let (p50_heartbeat, p99_heartbeat) = heartbeat_hist
        .lock()
        .map(|h| (h.value_at_quantile(0.50), h.value_at_quantile(0.99)))
        .unwrap_or((0, 0));

    // Verdict: a level is "ok" only if essentially every connection both
    // established AND survived the entire hold window. Tightening below 99%
    // lets a gateway look healthy while quietly RST'ing 5–10% of conns
    // under load — exactly the breakage we want to detect.
    let verdict = if connect_success_rate >= 0.99
        && heartbeat_success_rate >= 0.99
        && peak_alive >= ((args.connections as f64) * 0.99) as u64
        && survivorship_rate >= 0.99
    {
        "ok"
    } else {
        "broken"
    };

    let report = SaturateReport {
        target: args.target.clone(),
        target_connections: args.connections,
        ramp_seconds: args.ramp_seconds,
        hold_seconds: args.hold_seconds,
        heartbeat_interval_ms: args.heartbeat_interval_ms,
        payload_size: args.payload_size,
        connect_attempts,
        connect_successes,
        connect_success_rate,
        connect_refused: counters.connect_refused.load(Ordering::Relaxed),
        connect_timeout: counters.connect_timeout.load(Ordering::Relaxed),
        connect_reset: counters.connect_reset.load(Ordering::Relaxed),
        connect_tls_error: counters.connect_tls_error.load(Ordering::Relaxed),
        connect_other: counters.connect_other.load(Ordering::Relaxed),
        peak_alive_connections: peak_alive,
        alive_at_end,
        heartbeats_attempted,
        heartbeats_succeeded,
        heartbeats_failed: counters.heartbeats_failed.load(Ordering::Relaxed),
        heartbeat_success_rate,
        disconnects_during_hold,
        p50_connect_us: p50_connect,
        p99_connect_us: p99_connect,
        p50_heartbeat_us: p50_heartbeat,
        p99_heartbeat_us: p99_heartbeat,
        survivorship_rate,
        heartbeat_coverage,
        verdict,
    };

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        let pct_connect = connect_success_rate * 100.0;
        let pct_heartbeat = heartbeat_success_rate * 100.0;
        let pct_survive = survivorship_rate * 100.0;
        let pct_coverage = heartbeat_coverage * 100.0;
        println!(
            "saturate {} N={} ramp={}s hold={}s\n  connect: {}/{} ({:.2}%) — refused={} timeout={} reset={} tls={} other={}\n  peak_alive={} alive_at_end={} disconnects_during_hold={} survivorship={:.2}%\n  heartbeats: {}/{} ({:.2}%) coverage={:.2}%\n  connect p50={}us p99={}us  heartbeat p50={}us p99={}us\n  verdict: {}",
            args.target,
            args.connections,
            args.ramp_seconds,
            args.hold_seconds,
            connect_successes,
            connect_attempts,
            pct_connect,
            report.connect_refused,
            report.connect_timeout,
            report.connect_reset,
            report.connect_tls_error,
            report.connect_other,
            peak_alive,
            alive_at_end,
            disconnects_during_hold,
            pct_survive,
            heartbeats_succeeded,
            heartbeats_attempted,
            pct_heartbeat,
            pct_coverage,
            p50_connect,
            p99_connect,
            p50_heartbeat,
            p99_heartbeat,
            verdict,
        );
    }

    Ok(())
}
