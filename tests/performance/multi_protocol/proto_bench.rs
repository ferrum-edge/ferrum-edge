//! Multi-protocol load testing tool for Ferrum Edge performance testing.
//!
//! Generates load for HTTP/2, HTTP/3, WebSocket, gRPC, TCP, and UDP protocols
//! and reports metrics in a wrk-like format.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use clap::{Parser, Subcommand};

use bytes::Buf;
use multi_protocol_perf::metrics::BenchMetrics;
use multi_protocol_perf::tls_utils;

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
    /// backend — tonic 0.14 does not expose an "accept invalid" toggle, so we
    /// must explicitly trust the benchmark backend's cert. HTTP/1, HTTP/2,
    /// HTTP/3, and WS use an in-process insecure verifier and ignore this.
    #[arg(long)]
    ca_cert: Option<std::path::PathBuf>,

    /// Output JSON instead of text
    #[arg(long, default_value = "false")]
    json: bool,
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

async fn collect_results(
    handles: Vec<tokio::task::JoinHandle<anyhow::Result<BenchMetrics>>>,
) -> BenchMetrics {
    let mut combined = BenchMetrics::new();
    for handle in handles {
        match handle.await {
            Ok(Ok(m)) => combined.merge(&m),
            Ok(Err(e)) => eprintln!("  task error: {e}"),
            Err(e) => eprintln!("  join error: {e}"),
        }
    }
    combined
}

fn record_http_echo_result(
    metrics: &mut BenchMetrics,
    protocol: &str,
    status: http::StatusCode,
    body_len: usize,
    expected_len: usize,
    body_matches: bool,
    latency_us: u64,
) -> bool {
    if status != http::StatusCode::OK {
        eprintln!("  {protocol} unexpected status {status} (body {body_len} bytes)");
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

    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let protocol_label = if is_tls { "HTTP/1.1+TLS" } else { "HTTP/1.1" };
    let payload = Bytes::from(make_payload(args.payload_size));

    let mut handles = Vec::new();
    for _ in 0..args.concurrency {
        let path = path.clone();
        let authority = authority.clone();
        let tls_connector = tls_connector.clone();
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

            // Helper to create a connection (plain or TLS)
            async fn connect_h1(
                addr: SocketAddr,
                tls: &Option<(
                    tokio_rustls::TlsConnector,
                    rustls::pki_types::ServerName<'static>,
                )>,
            ) -> anyhow::Result<hyper::client::conn::http1::SendRequest<http_body_util::Full<Bytes>>>
            {
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

            let mut send_req = connect_h1(addr, &tls_connector).await?;
            let mut reconnects: u64 = 0;

            while Instant::now() < deadline {
                // Reconnect if the connection was closed
                if send_req.is_closed() {
                    reconnects += 1;
                    send_req = connect_h1(addr, &tls_connector).await?;
                }

                let req = hyper::Request::post(&path)
                    .header("host", &authority)
                    .body(http_body_util::Full::new(payload.clone()))
                    .unwrap();
                let start = Instant::now();
                match send_req.send_request(req).await {
                    Ok(resp) => {
                        use http_body_util::BodyExt;
                        let status = resp.status();
                        match resp.into_body().collect().await {
                            Ok(body) => {
                                let bytes = body.to_bytes();
                                let latency = start.elapsed().as_micros() as u64;
                                if !record_http_echo_result(
                                    &mut metrics,
                                    protocol_label,
                                    status,
                                    bytes.len(),
                                    payload.len(),
                                    bytes.as_ref() == payload.as_ref(),
                                    latency,
                                ) {
                                    break;
                                }
                            }
                            Err(_) => metrics.record_error(),
                        }
                    }
                    Err(_) => {
                        // Break out of the per-task loop on connection-level
                        // send errors (matches run_http2 / run_grpc). Without
                        // the break, a broken connection that reports fast
                        // errors without flipping is_closed() can spin the
                        // loop ~millions of times per second, inflating
                        // total_errors into the tens of millions at large
                        // payload sizes. Dropping the task is preferable —
                        // the other N-1 workers continue producing clean
                        // throughput data.
                        metrics.record_error();
                        break;
                    }
                }
            }
            if reconnects > 0 {
                eprintln!(
                    "[http1] task reconnected {reconnects} times over {} requests",
                    metrics.total_requests
                );
            }
            Ok(metrics)
        }));
    }

    let combined = collect_results(handles).await;
    print_results(&combined, protocol_label, args);
    Ok(())
}

// ── HTTP/2 ───────────────────────────────────────────────────────────────────

async fn run_http2(args: &BenchArgs) -> anyhow::Result<()> {
    use http_body_util::BodyExt;
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioTimer};

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

    let deadline = Instant::now() + Duration::from_secs(args.duration);

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
        let mut cfg = tls_utils::make_client_tls_config_insecure();
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

    for _ in 0..num_conns {
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
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sr
        } else {
            let io = hyper_util::rt::TokioIo::new(tcp);
            let (sr, conn) = make_h2_builder().handshake(io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sr
        };
        senders.push(send_req);
    }

    let payload = Bytes::from(make_payload(args.payload_size));

    // Distribute concurrent tasks across the connection pool.
    // hyper's http2 SendRequest is Clone and supports concurrent streams.
    let mut handles = Vec::new();
    for i in 0..args.concurrency {
        let mut send_req = senders[i as usize % num_conns].clone();
        let uri = request_uri.clone();
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();
            while Instant::now() < deadline {
                let req = hyper::Request::post(&uri)
                    .body(http_body_util::Full::new(payload.clone()))
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
                                ) {
                                    break;
                                }
                            }
                            Err(_) => metrics.record_error(),
                        }
                    }
                    Err(_) => {
                        metrics.record_error();
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(metrics)
        }));
    }

    let combined = collect_results(handles).await;
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

    let deadline = Instant::now() + Duration::from_secs(args.duration);
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

    for _ in 0..num_conns {
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        endpoint.set_default_client_config(client_cfg.clone());

        let conn = endpoint
            .connect(addr, &host_str)
            .map_err(|e| anyhow::anyhow!("quinn connect: {e}"))?
            .await
            .map_err(|e| anyhow::anyhow!("quinn connect: {e}"))?;
        let (mut driver, send_req) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .map_err(|e| anyhow::anyhow!("h3 handshake: {e}"))?;
        // h3 driver must be polled concurrently to process connection frames
        tokio::spawn(async move {
            let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        senders.push(send_req);
    }

    let payload = Bytes::from(make_payload(args.payload_size));

    // Distribute concurrent tasks across the connection pool
    let mut handles = Vec::new();
    for i in 0..args.concurrency {
        let mut send_req = senders[i as usize % num_conns].clone();
        let full_uri = full_uri.clone();
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();
            while Instant::now() < deadline {
                let req = http::Request::builder()
                    .method("POST")
                    .uri(&full_uri)
                    .body(())
                    .unwrap();
                let start = Instant::now();
                match send_req.send_request(req).await {
                    Ok(mut stream) => {
                        if let Err(e) = stream.send_data(payload.clone()).await {
                            eprintln!("  h3 send_data error: {e}");
                            metrics.record_error();
                            break;
                        }
                        let _ = stream.finish().await;
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
                                    ) {
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("  h3 recv_response error: {e}");
                                metrics.record_error();
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("  h3 send_request error: {e}");
                        metrics.record_error();
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(metrics)
        }));
    }

    let combined = collect_results(handles).await;
    print_results(&combined, "HTTP/3", args);
    Ok(())
}

// ── WebSocket ────────────────────────────────────────────────────────────────

async fn run_ws(args: &BenchArgs) -> anyhow::Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::Connector;
    use tokio_tungstenite::tungstenite::Message;

    let deadline = Instant::now() + Duration::from_secs(args.duration);
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
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

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
                    return Ok::<_, anyhow::Error>(metrics);
                }
            };
            let (mut write, mut read) = ws.split();

            while Instant::now() < deadline {
                let start = Instant::now();
                if write.send(Message::Binary(payload.clone())).await.is_err() {
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
            Ok::<_, anyhow::Error>(metrics)
        }));
    }

    let combined = collect_results(handles).await;
    print_results(&combined, "WebSocket", args);
    Ok(())
}

// ── gRPC ─────────────────────────────────────────────────────────────────────

async fn run_grpc(args: &BenchArgs) -> anyhow::Result<()> {
    use bench_proto::EchoRequest;
    use bench_proto::bench_service_client::BenchServiceClient;

    let deadline = Instant::now() + Duration::from_secs(args.duration);
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

    for _ in 0..num_conns {
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

        let channel = endpoint
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("gRPC connect to {}: {e}", args.target))?;
        channels.push(channel);
    }

    let mut handles = Vec::new();
    for i in 0..args.concurrency {
        let channel = channels[i as usize % num_conns].clone();
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();
            // tonic defaults to a 4 MiB cap on request + response message
            // size; the bench sweeps payloads up to 5 MiB. Without raising
            // both caps, every 5 MiB RPC fails with OutOfRange on the
            // encode side (client) or RESOURCE_EXHAUSTED on the decode
            // side (server). Must match proto_backend's cap.
            let mut client = BenchServiceClient::new(channel)
                .max_decoding_message_size(8 * 1024 * 1024)
                .max_encoding_message_size(8 * 1024 * 1024);

            while Instant::now() < deadline {
                let req = tonic::Request::new(EchoRequest {
                    payload: payload.clone(),
                });
                let start = Instant::now();
                match client.unary_echo(req).await {
                    Ok(resp) => {
                        let latency = start.elapsed().as_micros() as u64;
                        let response = resp.into_inner().payload;
                        if !record_echo_result(&mut metrics, "gRPC", &response, &payload, latency) {
                            break;
                        }
                    }
                    Err(_) => {
                        metrics.record_error();
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(metrics)
        }));
    }

    let combined = collect_results(handles).await;
    print_results(&combined, "gRPC", args);
    Ok(())
}

// ── TCP ──────────────────────────────────────────────────────────────────────

// A reader must only wait for a payload the writer has admitted. Independent
// deadline loops can otherwise ask for one extra echo just as the writer sends
// close_notify. Counters preserve the existing pipelined byte stream without an
// unbounded per-request queue. Notify has a single reader and stores a permit.
#[derive(Default)]
struct TcpWriteProgress {
    admitted: AtomicU64,
    finished: AtomicBool,
    changed: tokio::sync::Notify,
}

impl TcpWriteProgress {
    fn admit(&self) {
        self.admitted.fetch_add(1, Ordering::Release);
        self.changed.notify_one();
    }

    fn finish(&self) {
        self.finished.store(true, Ordering::Release);
        self.changed.notify_one();
    }

    async fn wait_for_request(&self, received: u64) -> bool {
        loop {
            if received < self.admitted.load(Ordering::Acquire) {
                return true;
            }
            if self.finished.load(Ordering::Acquire) {
                // The first load can precede the final admission. Observing
                // finished synchronizes with every admission before it.
                return received < self.admitted.load(Ordering::Acquire);
            }
            self.changed.notified().await;
        }
    }
}

struct FinishTcpWrites(Arc<TcpWriteProgress>);

impl Drop for FinishTcpWrites {
    fn drop(&mut self) {
        self.0.finish();
    }
}

async fn run_tcp(args: &BenchArgs) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr: SocketAddr = args.target.parse().context("invalid TCP target address")?;
    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let mut handles = Vec::new();
    let payload = make_payload(args.payload_size);
    let use_tls = args.tls;

    let tls_cfg = if use_tls {
        Some(Arc::new(tls_utils::make_client_tls_config_insecure_raw()))
    } else {
        None
    };

    for _ in 0..args.concurrency {
        let payload = payload.clone();
        let tls_cfg = tls_cfg.clone();
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();
            let tcp = tokio::net::TcpStream::connect(addr).await?;
            let _ = tcp.set_nodelay(true);

            // Run write_all and read_exact CONCURRENTLY via split + try_join.
            // The previous sequential `write_all(N); read_exact(N)` pattern
            // symmetric-deadlocks when N exceeds the kernel socket buffers
            // (~212 KB default) and both peers try to push at once: each
            // side's SNDBUF fills before the other drains, neither can
            // progress. Reproduced locally at payload=1 MiB / concurrency>=10
            // against proto_backend's TCP+TLS echo — every task stalled
            // indefinitely and ran out the workflow's 75-min step budget.
            //
            // With full-duplex I/O the writer pushes bytes while the reader
            // simultaneously drains the echo, so 50 conns × 1 MiB completes
            // well inside DURATION.
            if let Some(tls_cfg) = tls_cfg {
                let connector = tokio_rustls::TlsConnector::from(tls_cfg);
                let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string())
                    .map_err(|e| anyhow::anyhow!("server name: {e}"))?;
                let stream = connector.connect(server_name, tcp).await?;
                // Spawn writer and reader on SEPARATE tasks. A single-task
                // `try_join!` over `tokio::io::split(tls_stream)` shares
                // a BiLock between halves and still deadlocks the TLS
                // case — confirmed locally at 1 MiB × 50 conns. With
                // two tasks the reader half can run on a different worker
                // while the writer is holding the BiLock between chunks.
                let (mut rd, mut wr) = tokio::io::split(stream);
                let payload_bytes = payload.clone();
                let write_deadline = deadline;
                let progress = Arc::new(TcpWriteProgress::default());
                let write_progress = progress.clone();
                let write_task = tokio::spawn(async move {
                    let _finished = FinishTcpWrites(write_progress.clone());
                    // Chunk the write + yield_now() between chunks.
                    // tokio::io::split over tokio_rustls::TlsStream shares a
                    // BiLock between the read and write halves. poll_write
                    // on the TLS stream produces Ready synchronously as
                    // long as the underlying TCP has buffer space — which
                    // means a naive `wr.write_all(5 MiB)` can complete
                    // without ever returning Pending, never releases the
                    // BiLock, and the reader on the other half is starved.
                    // Reproduced locally at 5 MiB × 25 conns: the writer
                    // task ran hot while read_exact never got scheduled.
                    //
                    // Chunked writes with explicit yield_now() between
                    // chunks force cooperative yielding so the reader
                    // can acquire the BiLock and drain the echo stream.
                    const CHUNK: usize = 65_536;
                    while Instant::now() < write_deadline {
                        // Publish before writing so large payloads retain
                        // full-duplex progress even when socket buffers fill.
                        write_progress.admit();
                        let mut offset = 0;
                        while offset < payload_bytes.len() {
                            let end = (offset + CHUNK).min(payload_bytes.len());
                            if wr.write_all(&payload_bytes[offset..end]).await.is_err() {
                                return Err::<(), ()>(());
                            }
                            offset = end;
                            tokio::task::yield_now().await;
                        }
                    }
                    // Shut down the write half cleanly so the peer sees EOF
                    // and stops echoing. Without this, the writer task drops
                    // `wr` at deadline in the middle of a repeated payload
                    // cycle — the LAST payload is only partially sent, the
                    // reader is mid-way through a `read_exact(payload.len())`
                    // that will never complete (the remaining bytes will
                    // never arrive because we're no longer writing), and the
                    // TCP FIN is never issued because `rd` on the other task
                    // still keeps the TlsStream alive. Reader hangs forever
                    // until the process wallclock-kills. Reproduced locally
                    // at 500 KiB × 100 conns: ~6/100 connections wedge in
                    // ESTABLISHED with half-received payloads.
                    wr.shutdown().await.map_err(|_| ())?;
                    Ok(())
                });

                // Read with a per-attempt timeout so a stalled backend or
                // partial echo cannot wedge the task indefinitely. 15s is
                // generous — well above the observed CI-runner worst case
                // (~5-8s under heavy scheduler contention at 200 concurrent
                // TLS connections on shared runners). The previous 5s caused
                // false-positive errors on every run.
                let mut buf = vec![0u8; payload.len()];
                let mut received = 0;
                let mut read_failed = false;
                while Instant::now() < deadline {
                    let start = Instant::now();
                    let read_timeout = Duration::from_secs(15);
                    let response = async {
                        if !progress.wait_for_request(received).await {
                            return Ok(None);
                        }
                        rd.read_exact(&mut buf).await?;
                        Ok::<_, std::io::Error>(Some(()))
                    };
                    match tokio::time::timeout(read_timeout, response).await {
                        Ok(Ok(None)) => break,
                        Ok(Ok(Some(()))) => {
                            received += 1;
                            let latency = start.elapsed().as_micros() as u64;
                            if !record_echo_result(&mut metrics, "TCP+TLS", &buf, &payload, latency)
                            {
                                read_failed = true;
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            eprintln!(
                                "[tcp-tls] read error after {} requests: {e}",
                                metrics.total_requests
                            );
                            metrics.record_error();
                            read_failed = true;
                            break;
                        }
                        Err(_) => {
                            eprintln!(
                                "[tcp-tls] read timeout (15s) after {} requests",
                                metrics.total_requests
                            );
                            metrics.record_error();
                            read_failed = true;
                            break;
                        }
                    }
                }
                // Abort the writer in case the reader exited first (deadline
                // or error) — otherwise it could keep writing into a dropped
                // socket until the write fails.
                write_task.abort();
                match write_task.await {
                    Ok(Err(())) if !read_failed => {
                        eprintln!("[tcp-tls] writer failed before clean shutdown");
                        metrics.record_error();
                    }
                    Err(error) if !error.is_cancelled() && !read_failed => {
                        eprintln!("[tcp-tls] writer task failed: {error}");
                        metrics.record_error();
                    }
                    _ => {}
                }
            } else {
                let (mut rd, mut wr) = tcp.into_split();
                let mut buf = vec![0u8; payload.len()];
                while Instant::now() < deadline {
                    let start = Instant::now();
                    let res = tokio::try_join!(async { wr.write_all(&payload).await }, async {
                        rd.read_exact(&mut buf).await.map(|_| ())
                    },);
                    match res {
                        Ok(_) => {
                            let latency = start.elapsed().as_micros() as u64;
                            if !record_echo_result(&mut metrics, "TCP", &buf, &payload, latency) {
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "[tcp] i/o error after {} requests: {e}",
                                metrics.total_requests
                            );
                            metrics.record_error();
                            break;
                        }
                    }
                }
            }
            Ok::<_, anyhow::Error>(metrics)
        }));
    }

    let combined = collect_results(handles).await;
    let proto_name = if args.tls { "TCP+TLS" } else { "TCP" };
    print_results(&combined, proto_name, args);
    Ok(())
}

// ── UDP ──────────────────────────────────────────────────────────────────────

#[allow(unused_assignments)] // next_timeout assignments are defensive — drain loop may not always produce Timeout
async fn run_udp(args: &BenchArgs) -> anyhow::Result<()> {
    let addr: SocketAddr = args.target.parse().context("invalid UDP target address")?;
    let deadline = Instant::now() + Duration::from_secs(args.duration);
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
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

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

                // Connected — run echo benchmark using Sans-IO loop
                'benchmark: while Instant::now() < deadline {
                    let start = Instant::now();
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
                while Instant::now() < deadline {
                    let start = Instant::now();
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
            Ok::<_, anyhow::Error>(metrics)
        }));
    }

    let combined = collect_results(handles).await;
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

#[cfg(test)]
mod tcp_admission_tests {
    use super::{FinishTcpWrites, TcpWriteProgress};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn completed_writer_does_not_admit_an_extra_eof_read() {
        let progress = TcpWriteProgress::default();
        progress.admit();
        progress.finish();
        assert!(progress.wait_for_request(0).await);
        assert!(!progress.wait_for_request(1).await);
    }

    #[tokio::test]
    async fn completion_before_wait_and_coalesced_notifications_keep_all_requests() {
        let progress = Arc::new(TcpWriteProgress::default());
        {
            let _finished = FinishTcpWrites(progress.clone());
            progress.admit();
            progress.admit();
        }
        assert!(progress.wait_for_request(0).await);
        assert!(progress.wait_for_request(1).await);
        assert!(!progress.wait_for_request(2).await);
    }

    #[tokio::test]
    async fn pending_reader_wakes_when_writer_finishes_without_a_request() {
        let progress = TcpWriteProgress::default();
        let reader = progress.wait_for_request(0);
        tokio::pin!(reader);
        assert!(futures_util::poll!(&mut reader).is_pending());
        progress.finish();
        assert!(
            !tokio::time::timeout(Duration::from_secs(1), reader)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn admitted_partial_payload_is_still_an_io_failure() {
        let progress = TcpWriteProgress::default();
        let (mut reader, mut writer) = tokio::io::duplex(4);
        progress.admit();
        writer.write_all(b"ab").await.unwrap();
        drop(writer);
        progress.finish();
        assert!(progress.wait_for_request(0).await);
        let mut payload = [0; 4];
        assert!(reader.read_exact(&mut payload).await.is_err());
    }
}
