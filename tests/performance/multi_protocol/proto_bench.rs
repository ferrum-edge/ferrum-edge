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
    let cli = Cli::parse();
    match cli.command {
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
        let report = metrics.to_json_report(protocol, &args.target, args.concurrency, args.duration);
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

fn collect_results(
    handles: Vec<tokio::task::JoinHandle<anyhow::Result<BenchMetrics>>>,
) -> BenchMetrics {
    let rt = tokio::runtime::Handle::current();
    let mut combined = BenchMetrics::new();
    for handle in handles {
        match rt.block_on(handle) {
            Ok(Ok(m)) => combined.merge(&m),
            Ok(Err(e)) => eprintln!("  task error: {e}"),
            Err(e) => eprintln!("  join error: {e}"),
        }
    }
    combined
}

// ── HTTP/2 ───────────────────────────────────────────────────────────────────

async fn run_http2(args: &BenchArgs) -> anyhow::Result<()> {
    use http_body_util::BodyExt;
    use hyper::client::conn::http2;
    use hyper_util::rt::TokioExecutor;

    let is_tls = args.target.starts_with("https://");
    let url: http::Uri = args.target.parse().context("invalid target URL")?;
    let host = url.host().context("no host in URL")?;
    let port = url.port_u16().unwrap_or(if is_tls { 443 } else { 80 });
    let addr: SocketAddr = format!("{host}:{port}").parse().context("invalid address")?;
    let path = url.path().to_string();

    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let mut handles = Vec::new();

    let tls_cfg = if is_tls {
        Some(Arc::new(tls_utils::make_client_tls_config_insecure()))
    } else {
        None
    };

    for _ in 0..args.concurrency {
        let path = path.clone();
        let tls_cfg = tls_cfg.clone();
        let host_str = host.to_string();
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

            let tcp = tokio::net::TcpStream::connect(addr).await?;

            let send_req = if let Some(tls_cfg) = tls_cfg {
                let connector = tokio_rustls::TlsConnector::from(tls_cfg);
                let server_name = rustls::pki_types::ServerName::try_from(host_str)
                    .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?;
                let tls_stream = connector.connect(server_name, tcp).await?;
                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let (sr, conn) =
                    http2::handshake(TokioExecutor::new(), io).await?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                sr
            } else {
                let io = hyper_util::rt::TokioIo::new(tcp);
                let (sr, conn) =
                    http2::handshake(TokioExecutor::new(), io).await?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                sr
            };

            let mut send_req = send_req;
            while Instant::now() < deadline {
                let req = hyper::Request::get(&path)
                    .body(http_body_util::Full::new(Bytes::new()))
                    .unwrap();
                let start = Instant::now();
                match send_req.send_request(req).await {
                    Ok(resp) => {
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
                        break; // Connection broken, exit
                    }
                }
            }
            Ok::<_, anyhow::Error>(metrics)
        }));
    }

    let combined = collect_results(handles);
    print_results(&combined, "HTTP/2", args);
    Ok(())
}

// ── HTTP/3 ───────────────────────────────────────────────────────────────────

async fn run_http3(args: &BenchArgs) -> anyhow::Result<()> {
    let url: http::Uri = args.target.parse().context("invalid target URL")?;
    let host = url.host().context("no host in URL")?;
    let port = url.port_u16().unwrap_or(443);
    let addr: SocketAddr = format!("{host}:{port}").parse().context("invalid address")?;
    let path = url.path().to_string();

    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let mut handles = Vec::new();
    let client_cfg = tls_utils::make_h3_client_config_insecure();

    for _ in 0..args.concurrency {
        let path = path.clone();
        let client_cfg = client_cfg.clone();
        let host_str = host.to_string();
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

            let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
            endpoint.set_default_client_config(client_cfg);

            let conn = endpoint.connect(addr, &host_str)?.await?;
            let (driver, mut send_req) =
                h3::client::new(h3_quinn::Connection::new(conn)).await?;
            // h3 driver needs to run but isn't a bare Future; drop it to let the
            // connection proceed (requests drive it).
            drop(driver);

            while Instant::now() < deadline {
                let req = http::Request::get(&path).body(()).unwrap();
                let start = Instant::now();
                match send_req.send_request(req).await {
                    Ok(mut stream) => {
                        let _ = stream.finish().await;
                        match stream.recv_response().await {
                            Ok(_resp) => {
                                let mut body_bytes = 0usize;
                                while let Ok(Some(chunk)) = stream.recv_data().await {
                                    body_bytes += chunk.remaining();
                                    // consume
                                }
                                let latency = start.elapsed().as_micros() as u64;
                                metrics.record(latency, body_bytes);
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

    let combined = collect_results(handles);
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
                if write
                    .send(Message::Binary(payload.clone().into()))
                    .await
                    .is_err()
                {
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

    let combined = collect_results(handles);
    print_results(&combined, "WebSocket", args);
    Ok(())
}

// ── gRPC ─────────────────────────────────────────────────────────────────────

async fn run_grpc(args: &BenchArgs) -> anyhow::Result<()> {
    use bench_proto::bench_service_client::BenchServiceClient;
    use bench_proto::EchoRequest;

    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let mut handles = Vec::new();
    let payload = vec![0xABu8; args.payload_size];

    for _ in 0..args.concurrency {
        let target = args.target.clone();
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

            let channel = tonic::transport::Channel::from_shared(target.clone())
                .map_err(|e| anyhow::anyhow!("invalid gRPC target: {e}"))?
                .connect()
                .await
                .map_err(|e| anyhow::anyhow!("gRPC connect to {target}: {e}"))?;
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
                        // Try reconnecting
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        let Ok(ch) =
                            tonic::transport::Channel::from_shared(target.clone())
                                .map_err(|e| anyhow::anyhow!("{e}"))
                                .and_then(|c| Ok(c))
                        else {
                            break;
                        };
                        match ch.connect().await {
                            Ok(new_ch) => client = BenchServiceClient::new(new_ch),
                            Err(_) => break,
                        }
                    }
                }
            }
            Ok::<_, anyhow::Error>(metrics)
        }));
    }

    let combined = collect_results(handles);
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

            if let Some(tls_cfg) = tls_cfg {
                let connector = tokio_rustls::TlsConnector::from(tls_cfg);
                let server_name =
                    rustls::pki_types::ServerName::try_from("localhost".to_string())
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

    let combined = collect_results(handles);
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

                let dtls_conn = DTLSConn::new(
                    Arc::clone(&sock) as Arc<dyn webrtc_util::Conn + Send + Sync>,
                    cfg,
                    true,  // is_client
                    None,  // no existing state
                )
                .await
                .map_err(|e| anyhow::anyhow!("dtls connect: {e}"))?;

                let mut buf = vec![0u8; 65535];
                while Instant::now() < deadline {
                    let start = Instant::now();
                    dtls_conn
                        .send(&payload)
                        .await
                        .map_err(|e| anyhow::anyhow!("dtls send: {e}"))?;
                    let n = dtls_conn
                        .recv(&mut buf)
                        .await
                        .map_err(|e| anyhow::anyhow!("dtls recv: {e}"))?;
                    let latency = start.elapsed().as_micros() as u64;
                    metrics.record(latency, n);
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

    let combined = collect_results(handles);
    let proto_name = if args.tls { "UDP+DTLS" } else { "UDP" };
    print_results(&combined, proto_name, args);
    Ok(())
}
