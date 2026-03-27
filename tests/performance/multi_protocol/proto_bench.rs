//! Multi-protocol load testing tool for Ferrum Gateway performance testing.
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

    let mut handles = Vec::new();
    for _ in 0..args.concurrency {
        let path = path.clone();
        let authority = authority.clone();
        let tls_connector = tls_connector.clone();
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

                let req = hyper::Request::get(&path)
                    .header("host", &authority)
                    .body(http_body_util::Full::new(Bytes::new()))
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
                        metrics.record_error();
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
    let path = url.path().to_string();

    let deadline = Instant::now() + Duration::from_secs(args.duration);

    let tls_cfg = if is_tls {
        Some(Arc::new(tls_utils::make_client_tls_config_insecure()))
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
            .initial_stream_window_size(8_388_608)         // 8 MiB
            .initial_connection_window_size(33_554_432)     // 32 MiB
            .adaptive_window(false)                         // Fixed windows
            .max_frame_size(65_535);                        // Max frame size
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

    // Distribute concurrent tasks across the connection pool.
    // hyper's http2 SendRequest is Clone and supports concurrent streams.
    let mut handles = Vec::new();
    for i in 0..args.concurrency {
        let mut send_req = senders[i as usize % num_conns].clone();
        let path = path.clone();
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();
            while Instant::now() < deadline {
                let req = hyper::Request::get(&path)
                    .body(http_body_util::Full::new(Bytes::new()))
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
    let num_conns = std::cmp::max(1, std::cmp::min(args.concurrency as usize, args.concurrency as usize / 10 + 1));
    let host_str = host.to_string();
    let full_uri = format!("https://{host_str}:{port}{path}");

    // Create a pool of QUIC connections with shared endpoints
    let mut senders: Vec<h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>> = Vec::with_capacity(num_conns);

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

    // Distribute concurrent tasks across the connection pool
    let mut handles = Vec::new();
    for i in 0..args.concurrency {
        let mut send_req = senders[i as usize % num_conns].clone();
        let full_uri = full_uri.clone();
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();
            while Instant::now() < deadline {
                let req = http::Request::builder()
                    .method("GET")
                    .uri(&full_uri)
                    .body(())
                    .unwrap();
                let start = Instant::now();
                match send_req.send_request(req).await {
                    Ok(mut stream) => {
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

    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let mut handles = Vec::new();
    let payload = vec![0xABu8; args.payload_size];

    for _ in 0..args.concurrency {
        let target = args.target.clone();
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

            let (ws, _) = tokio_tungstenite::connect_async(&target)
                .await
                .map_err(|e| anyhow::anyhow!("ws connect: {e}"))?;
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

    // gRPC uses HTTP/2 multiplexing. Share a pool of channels across tasks
    // (~10 streams per channel) instead of one channel per task.
    let num_conns = std::cmp::max(1, std::cmp::min(args.concurrency as usize, args.concurrency as usize / 10 + 1));
    let mut channels = Vec::with_capacity(num_conns);

    for _ in 0..num_conns {
        let channel = tonic::transport::Channel::from_shared(args.target.clone())
            .map_err(|e| anyhow::anyhow!("invalid gRPC target: {e}"))?
            .initial_stream_window_size(8_388_608)         // 8 MiB (vs 64 KB default)
            .initial_connection_window_size(33_554_432)     // 32 MiB
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
            let mut client = BenchServiceClient::new(channel);

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
        Some(Arc::new(tls_utils::make_client_tls_config_insecure()))
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

            if let Some(tls_cfg) = tls_cfg {
                let connector = tokio_rustls::TlsConnector::from(tls_cfg);
                let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string())
                    .map_err(|e| anyhow::anyhow!("server name: {e}"))?;
                let mut stream = connector.connect(server_name, tcp).await?;
                let mut buf = vec![0u8; payload.len()];
                while Instant::now() < deadline {
                    let start = Instant::now();
                    stream.write_all(&payload).await?;
                    stream.read_exact(&mut buf).await?;
                    let latency = start.elapsed().as_micros() as u64;
                    metrics.record(latency, buf.len());
                }
            } else {
                let mut stream = tcp;
                let mut buf = vec![0u8; payload.len()];
                while Instant::now() < deadline {
                    let start = Instant::now();
                    stream.write_all(&payload).await?;
                    stream.read_exact(&mut buf).await?;
                    let latency = start.elapsed().as_micros() as u64;
                    metrics.record(latency, buf.len());
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

async fn run_udp(args: &BenchArgs) -> anyhow::Result<()> {
    let addr: SocketAddr = args.target.parse().context("invalid UDP target address")?;
    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let mut handles = Vec::new();
    let payload = vec![0xABu8; args.payload_size];
    let use_dtls = args.tls;

    for _ in 0..args.concurrency {
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

            if use_dtls {
                use webrtc_dtls::config::Config as DtlsConfig;
                use webrtc_dtls::conn::DTLSConn;
                use webrtc_util::Conn;

                let cfg = DtlsConfig {
                    insecure_skip_verify: true,
                    ..Default::default()
                };

                let sock = Arc::new(
                    tokio::net::UdpSocket::bind("0.0.0.0:0")
                        .await
                        .map_err(|e| anyhow::anyhow!("udp bind: {e}"))?,
                );
                sock.connect(addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("udp connect: {e}"))?;

                let dtls_conn = tokio::time::timeout(
                    Duration::from_secs(10),
                    DTLSConn::new(
                        Arc::clone(&sock) as Arc<dyn webrtc_util::Conn + Send + Sync>,
                        cfg,
                        true, // is_client
                        None, // no existing state
                    ),
                )
                .await
                .map_err(|_| anyhow::anyhow!("dtls handshake timed out after 10s"))?
                .map_err(|e| anyhow::anyhow!("dtls connect: {e}"))?;

                let mut buf = vec![0u8; 65535];
                while Instant::now() < deadline {
                    let start = Instant::now();
                    dtls_conn
                        .send(&payload)
                        .await
                        .map_err(|e| anyhow::anyhow!("dtls send: {e}"))?;
                    match tokio::time::timeout(Duration::from_secs(5), dtls_conn.recv(&mut buf))
                        .await
                    {
                        Ok(Ok(n)) => {
                            let latency = start.elapsed().as_micros() as u64;
                            metrics.record(latency, n);
                        }
                        Ok(Err(e)) => {
                            eprintln!("  dtls recv error: {e}");
                            break;
                        }
                        Err(_) => {
                            eprintln!("  dtls recv timeout");
                            break;
                        }
                    }
                }
            } else {
                let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                sock.connect(addr).await?;
                let mut buf = vec![0u8; 65535];
                while Instant::now() < deadline {
                    let start = Instant::now();
                    sock.send(&payload).await?;
                    let n = sock.recv(&mut buf).await?;
                    let latency = start.elapsed().as_micros() as u64;
                    metrics.record(latency, n);
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
