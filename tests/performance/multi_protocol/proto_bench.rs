//! Multi-protocol load testing tool for Ferrum Edge performance testing.
//!
//! Generates load for HTTP/2, HTTP/3, WebSocket, gRPC, TCP, and UDP protocols
//! and reports metrics in a wrk-like format.

use std::net::SocketAddr;
use std::sync::Arc;
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
    let payload = Bytes::from(vec![0xABu8; args.payload_size]);

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

            while Instant::now() < deadline {
                // Reconnect if the connection was closed
                if send_req.is_closed() {
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
                        match resp.into_body().collect().await {
                            Ok(body) => {
                                let bytes = body.to_bytes();
                                let latency = start.elapsed().as_micros() as u64;
                                metrics.record(latency, bytes.len());
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

    let payload = Bytes::from(vec![0xABu8; args.payload_size]);

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
                    Ok(resp) => match resp.into_body().collect().await {
                        Ok(body) => {
                            let bytes = body.to_bytes();
                            let latency = start.elapsed().as_micros() as u64;
                            metrics.record(latency, bytes.len());
                        }
                        Err(_) => metrics.record_error(),
                    },
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

    let payload = Bytes::from(vec![0xABu8; args.payload_size]);

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
                            Ok(_resp) => {
                                let mut body_bytes = 0usize;
                                while let Ok(Some(chunk)) = stream.recv_data().await {
                                    body_bytes += chunk.remaining();
                                }
                                let latency = start.elapsed().as_micros() as u64;
                                metrics.record(latency, body_bytes);
                            }
                            Err(e) => {
                                eprintln!("  h3 recv_response error: {e}");
                                metrics.record_error();
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
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::Connector;

    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let mut handles = Vec::new();
    let payload = vec![0xABu8; args.payload_size];

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
                match read.next().await {
                    Some(Ok(msg)) => {
                        let latency = start.elapsed().as_micros() as u64;
                        let len = msg.into_data().len();
                        metrics.record(latency, len);
                    }
                    _ => {
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
    let payload = vec![0xABu8; args.payload_size];

    // gRPC TLS requires explicit trust configuration — tonic 0.14 has no
    // "accept invalid certs" toggle, so without --ca-cert the handshake
    // against the self-signed benchmark backend would fail and every bench
    // would emit rps=0. Read the CA once here and reuse for every channel.
    let is_tls = args.target.starts_with("https://");
    let ca_pem = if is_tls {
        let ca_path = args.ca_cert.as_ref().ok_or_else(|| {
            anyhow::anyhow!("gRPC over TLS requires --ca-cert <path-to-pem>")
        })?;
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
            endpoint = endpoint.tls_config(tls).map_err(|e| {
                anyhow::anyhow!("gRPC TLS config for {}: {e}", args.target)
            })?;
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
                        let bytes = resp.into_inner().payload.len();
                        metrics.record(latency, bytes);
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

async fn run_tcp(args: &BenchArgs) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr: SocketAddr = args.target.parse().context("invalid TCP target address")?;
    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let mut handles = Vec::new();
    let payload = vec![0xABu8; args.payload_size];
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
                let write_task = tokio::spawn(async move {
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
                    let _ = wr.shutdown().await;
                    Ok(())
                });

                // Read with a short per-attempt timeout so a stalled backend
                // or partial echo cannot wedge the task indefinitely. 5s is
                // generous — a healthy 5 MiB read at concurrency 25 completes
                // in <250ms on localhost, so any stall beyond that is a real
                // failure that should be surfaced, not papered over.
                let mut buf = vec![0u8; payload.len()];
                while Instant::now() < deadline {
                    let start = Instant::now();
                    let read_timeout = Duration::from_secs(5);
                    match tokio::time::timeout(read_timeout, rd.read_exact(&mut buf)).await {
                        Ok(Ok(_)) => {
                            let latency = start.elapsed().as_micros() as u64;
                            metrics.record(latency, buf.len());
                        }
                        Ok(Err(_)) => {
                            metrics.record_error();
                            break;
                        }
                        Err(_) => {
                            // Read timeout — no bytes flowing. Record as an
                            // error and bail so the bench doesn't wallclock
                            // itself into oblivion on a wedged connection.
                            metrics.record_error();
                            break;
                        }
                    }
                }
                // Abort the writer in case the reader exited first (deadline
                // or error) — otherwise it could keep writing into a dropped
                // socket until the write fails.
                write_task.abort();
                let _ = write_task.await;
            } else {
                let (mut rd, mut wr) = tcp.into_split();
                let mut buf = vec![0u8; payload.len()];
                while Instant::now() < deadline {
                    let start = Instant::now();
                    let res = tokio::try_join!(
                        async { wr.write_all(&payload).await },
                        async { rd.read_exact(&mut buf).await.map(|_| ()) },
                    );
                    match res {
                        Ok(_) => {
                            let latency = start.elapsed().as_micros() as u64;
                            metrics.record(latency, buf.len());
                        }
                        Err(_) => {
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
    let payload = vec![0xABu8; args.payload_size];
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
                while Instant::now() < deadline {
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
                                    metrics.record(latency, d.len());
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
                            metrics.record(latency, n);
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
