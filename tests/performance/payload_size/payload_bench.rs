//! Load generator for payload size benchmarks.
//!
//! Generates realistic payloads of specific content types and sizes, sends them
//! through the target (gateway or direct backend), and collects latency/throughput
//! metrics with HDR histogram precision.
//!
//! Usage:
//!   payload_bench <CONTENT_TYPE> --target <URL> --size <SIZE> [OPTIONS]
//!
//! Content types: json, xml, form-urlencoded, multipart, octet-stream, grpc,
//!                sse, ndjson, soap-xml, graphql, ws-binary, tcp, udp
//!
//! Sizes: 10kb, 50kb, 100kb, 1mb, 5mb, 9mb (or exact byte count)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use payload_size_perf::metrics::BenchMetrics;
use payload_size_perf::payload_gen::{self, ContentType, Transport};

mod bench_proto {
    tonic::include_proto!("bench");
}

use bench_proto::bench_service_client::BenchServiceClient;
use bench_proto::EchoRequest;

// -- CLI ----------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "payload_bench", about = "Payload size benchmark tool")]
struct Cli {
    /// Content type to test
    #[arg(value_parser = parse_content_type)]
    content_type: ContentType,

    /// Target URL or address (e.g., http://127.0.0.1:8000/echo or 127.0.0.1:5010)
    #[arg(short, long)]
    target: String,

    /// Payload size (e.g., 10kb, 50kb, 100kb, 1mb, 5mb, 9mb)
    #[arg(short, long, default_value = "10kb")]
    size: String,

    /// Test duration in seconds
    #[arg(short, long, default_value = "30")]
    duration: u64,

    /// Number of concurrent connections/tasks
    #[arg(short, long, default_value = "100")]
    concurrency: u64,

    /// Use HTTP/2 (TLS + ALPN) instead of HTTP/1.1
    #[arg(long)]
    http2: bool,

    /// Use HTTP/3 (QUIC)
    #[arg(long)]
    http3: bool,

    /// Use TLS
    #[arg(long)]
    tls: bool,

    /// Output results as JSON
    #[arg(long)]
    json: bool,

    /// Label for the payload size in reports
    #[arg(long)]
    size_label: Option<String>,
}

fn parse_content_type(s: &str) -> Result<ContentType, String> {
    ContentType::from_arg(s).ok_or_else(|| {
        format!(
            "Unknown content type '{s}'. Valid: json, xml, form-urlencoded, multipart, \
             octet-stream, grpc, sse, ndjson, soap-xml, graphql, ws-binary, tcp, udp"
        )
    })
}

// -- Main ---------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());

    let cli = Cli::parse();

    let target_size = payload_gen::parse_size(&cli.size)
        .ok_or_else(|| anyhow::anyhow!("Invalid size: {}", cli.size))?;

    let size_label = cli
        .size_label
        .clone()
        .unwrap_or_else(|| payload_gen::format_size(target_size));

    // Generate the payload once, share across all tasks
    let payload = payload_gen::generate_payload(cli.content_type, target_size);
    let payload = Arc::new(payload);

    let transport = if cli.http3 {
        Transport::Http3
    } else {
        cli.content_type.transport()
    };

    let protocol_name = if cli.http3 {
        "HTTP/3"
    } else if cli.http2 {
        "HTTP/2"
    } else {
        match transport {
            Transport::Http => "HTTP/1.1",
            Transport::Http3 => "HTTP/3",
            Transport::Grpc => "gRPC",
            Transport::WebSocket => "WebSocket",
            Transport::Tcp => "TCP",
            Transport::Udp => "UDP",
        }
    };

    let display_name = format!(
        "{} ({}, {})",
        protocol_name,
        cli.content_type.display_name(),
        size_label
    );

    if !cli.json {
        eprintln!(
            "[bench] {} | target={} | concurrency={} | duration={}s | payload={}B",
            display_name,
            cli.target,
            cli.concurrency,
            cli.duration,
            payload.len()
        );
    }

    let metrics = match transport {
        Transport::Http => {
            if cli.http2 || cli.tls {
                run_http2(&cli, &payload).await?
            } else {
                run_http1(&cli, &payload).await?
            }
        }
        Transport::Http3 => run_http3(&cli, &payload).await?,
        Transport::Grpc => run_grpc(&cli, &payload).await?,
        Transport::WebSocket => run_websocket(&cli, &payload).await?,
        Transport::Tcp => run_tcp(&cli, &payload).await?,
        Transport::Udp => run_udp(&cli, &payload).await?,
    };

    // Output results
    if cli.json {
        let mut report =
            metrics.to_json_report(&display_name, &cli.target, cli.concurrency, cli.duration);
        report.content_type = cli.content_type.display_name().to_string();
        report.payload_size = size_label;
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!(
            "{}",
            metrics.report(&display_name, &cli.target, cli.concurrency, cli.duration)
        );
    }

    Ok(())
}

// -- HTTP/1.1 Runner ----------------------------------------------------------

async fn run_http1(cli: &Cli, payload: &Arc<Vec<u8>>) -> anyhow::Result<BenchMetrics> {
    let deadline = Instant::now() + Duration::from_secs(cli.duration);
    let concurrency = cli.concurrency as usize;
    let content_type = cli.content_type.header_value().to_string();

    let uri: hyper::Uri = cli.target.parse()?;
    let host = uri.host().unwrap_or("127.0.0.1").to_string();
    let port = uri.port_u16().unwrap_or(80);
    let path = uri.path().to_string();

    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let payload = Arc::clone(payload);
        let content_type = content_type.clone();
        let host = host.clone();
        let path = path.clone();

        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();
            let addr = format!("{host}:{port}");

            let mut sender_opt: Option<hyper::client::conn::http1::SendRequest<Full<Bytes>>> =
                None;

            while Instant::now() < deadline {
                if sender_opt.is_none() || sender_opt.as_ref().is_some_and(|s| !s.is_ready()) {
                    match TcpStream::connect(&addr).await {
                        Ok(stream) => {
                            stream.set_nodelay(true).ok();
                            let io = TokioIo::new(stream);
                            match hyper::client::conn::http1::handshake(io).await {
                                Ok((sender, conn)) => {
                                    tokio::spawn(async move {
                                        let _ = conn.await;
                                    });
                                    sender_opt = Some(sender);
                                }
                                Err(_) => {
                                    metrics.record_error();
                                    continue;
                                }
                            }
                        }
                        Err(_) => {
                            metrics.record_error();
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                    }
                }

                let sender = sender_opt.as_mut().unwrap();
                let body = Full::new(Bytes::copy_from_slice(&payload));
                let req = Request::builder()
                    .method("POST")
                    .uri(&path)
                    .header("host", &host)
                    .header("content-type", &content_type)
                    .header("content-length", payload.len().to_string())
                    .body(body)
                    .unwrap();

                let start = Instant::now();
                match sender.send_request(req).await {
                    Ok(resp) => {
                        if resp.status() == StatusCode::OK {
                            match read_response_body(resp).await {
                                Ok(n) => {
                                    let elapsed = start.elapsed().as_micros() as u64;
                                    metrics.record(elapsed, n);
                                }
                                Err(_) => {
                                    metrics.record_error();
                                    sender_opt = None;
                                }
                            }
                        } else {
                            let _ = read_response_body(resp).await;
                            metrics.record_error();
                        }
                    }
                    Err(_) => {
                        metrics.record_error();
                        sender_opt = None;
                    }
                }
            }
            metrics
        }));
    }

    collect_metrics(handles).await
}

// -- HTTP/2 Runner (via TLS + ALPN) -------------------------------------------

async fn run_http2(cli: &Cli, payload: &Arc<Vec<u8>>) -> anyhow::Result<BenchMetrics> {
    let deadline = Instant::now() + Duration::from_secs(cli.duration);
    let concurrency = cli.concurrency as usize;
    let content_type = cli.content_type.header_value().to_string();

    let uri: hyper::Uri = cli.target.parse()?;
    let host = uri.host().unwrap_or("127.0.0.1").to_string();
    let port = uri.port_u16().unwrap_or(8443);
    let path = uri.path().to_string();

    let tls_config = payload_size_perf::tls_utils::make_client_tls_config_insecure();
    let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    let num_conns = (concurrency / 10).max(1);
    let streams_per_conn = (concurrency / num_conns).max(1);

    let mut handles = Vec::with_capacity(concurrency);

    for conn_idx in 0..num_conns {
        let tls_connector = tls_connector.clone();
        let host = host.clone();
        let path = path.clone();
        let content_type = content_type.clone();
        let payload = Arc::clone(payload);
        let tasks_for_conn = if conn_idx == num_conns - 1 {
            concurrency - (num_conns - 1) * streams_per_conn
        } else {
            streams_per_conn
        };

        let addr = format!("{host}:{port}");
        let host_clone = host.clone();

        handles.push(tokio::spawn(async move {
            let mut combined = BenchMetrics::new();

            let stream = match TcpStream::connect(&addr).await {
                Ok(s) => s,
                Err(_) => return combined,
            };
            stream.set_nodelay(true).ok();

            let server_name =
                rustls::pki_types::ServerName::try_from(host_clone.clone())
                    .unwrap_or(rustls::pki_types::ServerName::IpAddress(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
                    ));

            let tls_stream = match tls_connector.connect(server_name, stream).await {
                Ok(s) => s,
                Err(_) => return combined,
            };

            let io = TokioIo::new(tls_stream);
            let (sender, conn) = match hyper::client::conn::http2::handshake(
                hyper_util::rt::TokioExecutor::new(),
                io,
            )
            .await
            {
                Ok(pair) => pair,
                Err(_) => return combined,
            };

            tokio::spawn(async move {
                let _ = conn.await;
            });

            let mut stream_handles = Vec::with_capacity(tasks_for_conn);
            for _ in 0..tasks_for_conn {
                let mut sender = sender.clone();
                let path = path.clone();
                let host = host.clone();
                let content_type = content_type.clone();
                let payload = Arc::clone(&payload);

                stream_handles.push(tokio::spawn(async move {
                    let mut metrics = BenchMetrics::new();
                    while Instant::now() < deadline {
                        let body = Full::new(Bytes::copy_from_slice(&payload));
                        let req = Request::builder()
                            .method("POST")
                            .uri(&path)
                            .header("host", &host)
                            .header("content-type", &content_type)
                            .header("content-length", payload.len().to_string())
                            .body(body)
                            .unwrap();

                        let start = Instant::now();
                        match sender.send_request(req).await {
                            Ok(resp) => {
                                if resp.status() == StatusCode::OK {
                                    match read_response_body(resp).await {
                                        Ok(n) => {
                                            let elapsed = start.elapsed().as_micros() as u64;
                                            metrics.record(elapsed, n);
                                        }
                                        Err(_) => metrics.record_error(),
                                    }
                                } else {
                                    let _ = read_response_body(resp).await;
                                    metrics.record_error();
                                }
                            }
                            Err(_) => {
                                metrics.record_error();
                                break;
                            }
                        }
                    }
                    metrics
                }));
            }

            for h in stream_handles {
                if let Ok(m) = h.await {
                    combined.merge(&m);
                }
            }
            combined
        }));
    }

    collect_metrics(handles).await
}

// -- HTTP/3 Runner (QUIC) -----------------------------------------------------

async fn run_http3(cli: &Cli, payload: &Arc<Vec<u8>>) -> anyhow::Result<BenchMetrics> {
    let uri: http::Uri = cli.target.parse()?;
    let host = uri.host().unwrap_or("127.0.0.1").to_string();
    let port = uri.port_u16().unwrap_or(8443);
    let path = uri.path().to_string();
    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    let content_type = cli.content_type.header_value().to_string();

    let deadline = Instant::now() + Duration::from_secs(cli.duration);
    let concurrency = cli.concurrency as usize;
    let client_cfg = payload_size_perf::tls_utils::make_h3_client_config_insecure();

    // Pool of QUIC connections (~10 streams per connection)
    let num_conns = (concurrency / 10).max(1).min(concurrency);
    let full_uri = format!("https://{host}:{port}{path}");

    let mut senders: Vec<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>> =
        Vec::with_capacity(num_conns);

    for _ in 0..num_conns {
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        endpoint.set_default_client_config(client_cfg.clone());

        let conn = endpoint
            .connect(addr, &host)
            .map_err(|e| anyhow::anyhow!("quinn connect: {e}"))?
            .await
            .map_err(|e| anyhow::anyhow!("quinn connect: {e}"))?;
        let (mut driver, send_req) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .map_err(|e| anyhow::anyhow!("h3 handshake: {e}"))?;
        tokio::spawn(async move {
            let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        senders.push(send_req);
    }

    let mut handles = Vec::with_capacity(concurrency);
    for i in 0..concurrency {
        let mut send_req = senders[i % num_conns].clone();
        let full_uri = full_uri.clone();
        let content_type = content_type.clone();
        let payload = Arc::clone(payload);

        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();
            while Instant::now() < deadline {
                let req = http::Request::builder()
                    .method("POST")
                    .uri(&full_uri)
                    .header("content-type", &content_type)
                    .body(())
                    .unwrap();

                let start = Instant::now();
                match send_req.send_request(req).await {
                    Ok(mut stream) => {
                        // Send request body
                        let _ = stream
                            .send_data(Bytes::copy_from_slice(&payload))
                            .await;
                        let _ = stream.finish().await;

                        match stream.recv_response().await {
                            Ok(_resp) => {
                                use bytes::Buf;
                                let mut body_bytes = 0usize;
                                while let Ok(Some(chunk)) = stream.recv_data().await {
                                    body_bytes += chunk.remaining();
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
            metrics
        }));
    }

    collect_metrics(handles).await
}

// -- gRPC Runner --------------------------------------------------------------

async fn run_grpc(cli: &Cli, payload: &Arc<Vec<u8>>) -> anyhow::Result<BenchMetrics> {
    let deadline = Instant::now() + Duration::from_secs(cli.duration);
    let concurrency = cli.concurrency as usize;

    let channel = tonic::transport::Channel::from_shared(cli.target.clone())?
        .http2_keep_alive_interval(Duration::from_secs(30))
        .initial_stream_window_size(8 * 1024 * 1024)
        .initial_connection_window_size(32 * 1024 * 1024)
        .connect()
        .await?;

    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let channel = channel.clone();
        let payload = Arc::clone(payload);

        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();
            let mut client = BenchServiceClient::new(channel)
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024);

            while Instant::now() < deadline {
                let req = EchoRequest {
                    payload: payload.to_vec(),
                };

                let start = Instant::now();
                match client.unary_echo(req).await {
                    Ok(resp) => {
                        let elapsed = start.elapsed().as_micros() as u64;
                        let resp_size = resp.into_inner().payload.len();
                        metrics.record(elapsed, resp_size);
                    }
                    Err(_) => {
                        metrics.record_error();
                    }
                }
            }
            metrics
        }));
    }

    collect_metrics(handles).await
}

// -- WebSocket Runner ---------------------------------------------------------

async fn run_websocket(cli: &Cli, payload: &Arc<Vec<u8>>) -> anyhow::Result<BenchMetrics> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let deadline = Instant::now() + Duration::from_secs(cli.duration);
    let concurrency = cli.concurrency as usize;

    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let target = cli.target.clone();
        let payload = Arc::clone(payload);

        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

            let (ws_stream, _) = match tokio_tungstenite::connect_async(&target).await {
                Ok(pair) => pair,
                Err(_) => return metrics,
            };

            let (mut writer, mut reader) = ws_stream.split();

            while Instant::now() < deadline {
                let msg = Message::Binary(payload.to_vec());
                let start = Instant::now();

                if writer.send(msg).await.is_err() {
                    metrics.record_error();
                    break;
                }

                match reader.next().await {
                    Some(Ok(Message::Binary(data))) => {
                        let elapsed = start.elapsed().as_micros() as u64;
                        metrics.record(elapsed, data.len());
                    }
                    Some(Ok(_)) => {
                        let elapsed = start.elapsed().as_micros() as u64;
                        metrics.record(elapsed, 0);
                    }
                    _ => {
                        metrics.record_error();
                        break;
                    }
                }
            }
            metrics
        }));
    }

    collect_metrics(handles).await
}

// -- TCP Runner ---------------------------------------------------------------

async fn run_tcp(cli: &Cli, payload: &Arc<Vec<u8>>) -> anyhow::Result<BenchMetrics> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr: SocketAddr = cli.target.parse().map_err(|_| {
        anyhow::anyhow!(
            "Invalid TCP target address '{}'. Expected format: 127.0.0.1:5010",
            cli.target
        )
    })?;
    let deadline = Instant::now() + Duration::from_secs(cli.duration);
    let concurrency = cli.concurrency as usize;

    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let payload = Arc::clone(payload);

        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

            let tcp = match TcpStream::connect(addr).await {
                Ok(s) => s,
                Err(_) => return metrics,
            };
            let _ = tcp.set_nodelay(true);

            let mut stream = tcp;
            let mut buf = vec![0u8; payload.len()];

            while Instant::now() < deadline {
                let start = Instant::now();
                if stream.write_all(&payload).await.is_err() {
                    metrics.record_error();
                    break;
                }
                if stream.read_exact(&mut buf).await.is_err() {
                    metrics.record_error();
                    break;
                }
                let latency = start.elapsed().as_micros() as u64;
                metrics.record(latency, buf.len());
            }
            metrics
        }));
    }

    collect_metrics(handles).await
}

// -- UDP Runner ---------------------------------------------------------------

async fn run_udp(cli: &Cli, payload: &Arc<Vec<u8>>) -> anyhow::Result<BenchMetrics> {
    let addr: SocketAddr = cli.target.parse().map_err(|_| {
        anyhow::anyhow!(
            "Invalid UDP target address '{}'. Expected format: 127.0.0.1:5003",
            cli.target
        )
    })?;
    let deadline = Instant::now() + Duration::from_secs(cli.duration);
    let concurrency = cli.concurrency as usize;

    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let payload = Arc::clone(payload);

        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

            let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => return metrics,
            };
            if sock.connect(addr).await.is_err() {
                return metrics;
            }

            let mut buf = vec![0u8; 65535];

            while Instant::now() < deadline {
                let start = Instant::now();
                if sock.send(&payload).await.is_err() {
                    metrics.record_error();
                    continue;
                }
                match sock.recv(&mut buf).await {
                    Ok(n) => {
                        let latency = start.elapsed().as_micros() as u64;
                        metrics.record(latency, n);
                    }
                    Err(_) => metrics.record_error(),
                }
            }
            metrics
        }));
    }

    collect_metrics(handles).await
}

// -- Helpers ------------------------------------------------------------------

async fn read_response_body(resp: Response<Incoming>) -> anyhow::Result<usize> {
    let body = BodyExt::collect(resp.into_body()).await?.to_bytes();
    Ok(body.len())
}

async fn collect_metrics(
    handles: Vec<tokio::task::JoinHandle<BenchMetrics>>,
) -> anyhow::Result<BenchMetrics> {
    let mut combined = BenchMetrics::new();
    for h in handles {
        if let Ok(m) = h.await {
            combined.merge(&m);
        }
    }
    Ok(combined)
}
