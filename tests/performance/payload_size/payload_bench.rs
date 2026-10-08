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

use bench_proto::EchoRequest;
use bench_proto::bench_service_client::BenchServiceClient;

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

    /// Upper bound in seconds on each connection setup and each request,
    /// including its response body. A request still running when the
    /// duration ends gets this long to finish; anything slower is recorded as
    /// a timeout and makes the run invalid instead of hanging it.
    #[arg(long, default_value = "30", value_parser = clap::value_parser!(u64).range(1..))]
    request_timeout: u64,

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

    let invalid_reasons = metrics.invalid_reasons(cli.concurrency);

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

    if !invalid_reasons.is_empty() {
        // The report above is still printed so callers keep the diagnostic.
        eprintln!("[bench] invalid run: {}", invalid_reasons.join("; "));
        std::process::exit(INVALID_RUN_EXIT_CODE);
    }

    Ok(())
}

/// Exit status of a run that completed but cannot stand as a measurement.
const INVALID_RUN_EXIT_CODE: i32 = 2;

/// Extra time `collect_metrics` waits past the last bounded operation before
/// cancelling a worker and counting it as failed.
const JOIN_GRACE: Duration = Duration::from_secs(2);

/// The run's time limits, shared by every worker.
#[derive(Clone, Copy)]
struct Bounds {
    /// Workers start no new request after this.
    deadline: Instant,
    /// Each setup step or request gets at most this long.
    request_timeout: Duration,
    /// No operation runs past this: `deadline` plus one request timeout.
    hard_deadline: Instant,
}

impl Bounds {
    fn new(cli: &Cli) -> Self {
        let deadline = Instant::now() + Duration::from_secs(cli.duration);
        let request_timeout = Duration::from_secs(cli.request_timeout);
        Self {
            deadline,
            request_timeout,
            hard_deadline: deadline + request_timeout,
        }
    }

    fn measuring(&self) -> bool {
        Instant::now() < self.deadline
    }

    /// Run one setup step or request within the request timeout and the hard
    /// deadline; `None` when it ran out of time (the future is dropped).
    async fn op<F: std::future::Future>(&self, fut: F) -> Option<F::Output> {
        let limit = (Instant::now() + self.request_timeout).min(self.hard_deadline);
        tokio::time::timeout_at(tokio::time::Instant::from_std(limit), fut)
            .await
            .ok()
    }
}

// -- HTTP/1.1 Runner ----------------------------------------------------------

async fn run_http1(cli: &Cli, payload: &Arc<Vec<u8>>) -> anyhow::Result<BenchMetrics> {
    let bounds = Bounds::new(cli);
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
            let mut measuring = false;

            let mut sender_opt: Option<hyper::client::conn::http1::SendRequest<Full<Bytes>>> = None;

            while bounds.measuring() {
                if sender_opt.is_none() || sender_opt.as_ref().is_some_and(|s| !s.is_ready()) {
                    match bounds.op(connect_http1(&addr)).await {
                        Some(Ok(sender)) => {
                            if !measuring {
                                measuring = true;
                                metrics.mark_measuring();
                            }
                            sender_opt = Some(sender);
                        }
                        Some(Err(_)) => {
                            metrics.record_setup_error();
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                        None => {
                            metrics.record_setup_timeout();
                            continue;
                        }
                    }
                }

                let Some(sender) = sender_opt.as_mut() else {
                    continue;
                };
                let req = post_request(&path, &host, &content_type, &payload);

                let start = Instant::now();
                match bounds.op(exchange(sender.send_request(req))).await {
                    Some(Ok((StatusCode::OK, n))) => {
                        metrics.record(start.elapsed().as_micros() as u64, n);
                    }
                    Some(Ok(_)) => metrics.record_error(),
                    Some(Err(_)) => {
                        metrics.record_error();
                        sender_opt = None;
                    }
                    None => {
                        metrics.record_timeout();
                        sender_opt = None;
                    }
                }
            }
            metrics
        }));
    }

    collect_metrics(handles, bounds).await
}

async fn connect_http1(
    addr: &str,
) -> anyhow::Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true).ok();
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender)
}

// -- HTTP/2 Runner (via TLS + ALPN) -------------------------------------------

async fn run_http2(cli: &Cli, payload: &Arc<Vec<u8>>) -> anyhow::Result<BenchMetrics> {
    let bounds = Bounds::new(cli);
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

        handles.push(tokio::spawn(async move {
            let mut combined = BenchMetrics::new();

            // A failed group's workers never reach measurement, so the run
            // reports fewer measured workers than its concurrency.
            let sender = match bounds.op(connect_http2(&addr, &host, tls_connector)).await {
                Some(Ok(sender)) => sender,
                Some(Err(_)) => {
                    combined.record_setup_error();
                    return combined;
                }
                None => {
                    combined.record_setup_timeout();
                    return combined;
                }
            };

            let mut stream_handles = Vec::with_capacity(tasks_for_conn);
            for _ in 0..tasks_for_conn {
                let mut sender = sender.clone();
                let path = path.clone();
                let host = host.clone();
                let content_type = content_type.clone();
                let payload = Arc::clone(&payload);

                stream_handles.push(tokio::spawn(async move {
                    let mut metrics = BenchMetrics::new();
                    metrics.mark_measuring();
                    while bounds.measuring() {
                        let req = post_request(&path, &host, &content_type, &payload);
                        let start = Instant::now();
                        // A timed-out stream is reset when its future drops;
                        // the connection's other streams carry on.
                        match bounds.op(exchange(sender.send_request(req))).await {
                            Some(Ok((StatusCode::OK, n))) => {
                                metrics.record(start.elapsed().as_micros() as u64, n);
                            }
                            Some(Ok(_)) => metrics.record_error(),
                            Some(Err(_)) => {
                                metrics.record_error();
                                if sender.is_closed() {
                                    break;
                                }
                            }
                            None => metrics.record_timeout(),
                        }
                    }
                    metrics
                }));
            }

            for h in stream_handles {
                match h.await {
                    Ok(m) => combined.merge(&m),
                    Err(_) => combined.record_worker_failure(),
                }
            }
            combined
        }));
    }

    collect_metrics(handles, bounds).await
}

async fn connect_http2(
    addr: &str,
    host: &str,
    tls_connector: tokio_rustls::TlsConnector,
) -> anyhow::Result<hyper::client::conn::http2::SendRequest<Full<Bytes>>> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true).ok();

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap_or(
        rustls::pki_types::ServerName::IpAddress(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
        ),
    );
    let tls_stream = tls_connector.connect(server_name, stream).await?;

    // Keep these windows fixed. hyper's `adaptive_window(true)` silently
    // resets both to 65,535 and grows them with BDP pings; in that mode the
    // multi-protocol bench client intermittently stalled single streams
    // for 10-30 s (see `run_http2` in multi_protocol/proto_bench.rs).
    let mut h2_builder =
        hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
    h2_builder
        .initial_stream_window_size(8 * 1024 * 1024) // 8 MiB
        .initial_connection_window_size(32 * 1024 * 1024) // 32 MiB
        .max_frame_size(1_048_576); // 1 MiB
    let (sender, conn) = h2_builder.handshake(TokioIo::new(tls_stream)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender)
}

fn post_request(
    path: &str,
    host: &str,
    content_type: &str,
    payload: &[u8],
) -> Request<Full<Bytes>> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("host", host)
        .header("content-type", content_type)
        .header("content-length", payload.len().to_string())
        .body(Full::new(Bytes::copy_from_slice(payload)))
        .unwrap()
}

/// Send one request and read its whole response body.
async fn exchange(
    response: impl std::future::Future<Output = hyper::Result<Response<Incoming>>>,
) -> anyhow::Result<(StatusCode, usize)> {
    let resp = response.await?;
    let status = resp.status();
    let n = read_response_body(resp).await?;
    Ok((status, n))
}

// -- HTTP/3 Runner (QUIC) -----------------------------------------------------

async fn run_http3(cli: &Cli, payload: &Arc<Vec<u8>>) -> anyhow::Result<BenchMetrics> {
    let uri: http::Uri = cli.target.parse()?;
    let host = uri.host().unwrap_or("127.0.0.1").to_string();
    let port = uri.port_u16().unwrap_or(8443);
    let path = uri.path().to_string();
    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    let content_type = cli.content_type.header_value().to_string();

    let bounds = Bounds::new(cli);
    let concurrency = cli.concurrency as usize;
    let client_cfg = payload_size_perf::tls_utils::make_h3_client_config_insecure();

    // Pool of QUIC connections (~10 streams per connection)
    let num_conns = (concurrency / 10).max(1).min(concurrency);
    let full_uri = format!("https://{host}:{port}{path}");

    let mut senders: Vec<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>> =
        Vec::with_capacity(num_conns);

    // A failed or stalled QUIC setup fails the whole run with an error.
    for _ in 0..num_conns {
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        endpoint.set_default_client_config(client_cfg.clone());

        let setup = async {
            let conn = endpoint
                .connect(addr, &host)
                .map_err(|e| anyhow::anyhow!("quinn connect: {e}"))?
                .await
                .map_err(|e| anyhow::anyhow!("quinn connect: {e}"))?;
            h3::client::new(h3_quinn::Connection::new(conn))
                .await
                .map_err(|e| anyhow::anyhow!("h3 handshake: {e}"))
        };
        let (mut driver, send_req) = bounds
            .op(setup)
            .await
            .ok_or_else(|| anyhow::anyhow!("QUIC/h3 setup exceeded the request timeout"))??;
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
            metrics.mark_measuring();
            while bounds.measuring() {
                let req = http::Request::builder()
                    .method("POST")
                    .uri(&full_uri)
                    .header("content-type", &content_type)
                    .body(())
                    .unwrap();

                let start = Instant::now();
                let exchange = async {
                    let mut stream = send_req
                        .send_request(req)
                        .await
                        .map_err(|_| H3Failure::Open)?;
                    stream
                        .send_data(Bytes::copy_from_slice(&payload))
                        .await
                        .map_err(|_| H3Failure::Exchange)?;
                    stream.finish().await.map_err(|_| H3Failure::Exchange)?;
                    stream
                        .recv_response()
                        .await
                        .map_err(|_| H3Failure::Exchange)?;
                    use bytes::Buf;
                    let mut body_bytes = 0usize;
                    while let Some(chunk) =
                        stream.recv_data().await.map_err(|_| H3Failure::Exchange)?
                    {
                        body_bytes += chunk.remaining();
                    }
                    Ok::<usize, H3Failure>(body_bytes)
                };
                match bounds.op(exchange).await {
                    Some(Ok(body_bytes)) => {
                        metrics.record(start.elapsed().as_micros() as u64, body_bytes);
                    }
                    Some(Err(H3Failure::Exchange)) => metrics.record_error(),
                    Some(Err(H3Failure::Open)) => {
                        metrics.record_error();
                        break;
                    }
                    None => metrics.record_timeout(),
                }
            }
            metrics
        }));
    }

    collect_metrics(handles, bounds).await
}

/// How one HTTP/3 request failed: opening the stream ends the worker, as the
/// connection is gone; a failure after that is one failed request.
enum H3Failure {
    Open,
    Exchange,
}

// -- gRPC Runner --------------------------------------------------------------

async fn run_grpc(cli: &Cli, payload: &Arc<Vec<u8>>) -> anyhow::Result<BenchMetrics> {
    let bounds = Bounds::new(cli);
    let concurrency = cli.concurrency as usize;

    // A failed or stalled channel setup fails the whole run with an error.
    let channel = tonic::transport::Channel::from_shared(cli.target.clone())?
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_while_idle(true)
        .tcp_nodelay(true)
        .initial_stream_window_size(8 * 1024 * 1024)
        .initial_connection_window_size(32 * 1024 * 1024)
        .connect_timeout(bounds.request_timeout)
        .connect()
        .await?;

    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let channel = channel.clone();
        let payload = Arc::clone(payload);

        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();
            metrics.mark_measuring();
            let mut client = BenchServiceClient::new(channel)
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024);

            while bounds.measuring() {
                let req = EchoRequest {
                    payload: payload.to_vec(),
                };

                let start = Instant::now();
                match bounds.op(client.unary_echo(req)).await {
                    Some(Ok(resp)) => {
                        let elapsed = start.elapsed().as_micros() as u64;
                        let resp_size = resp.into_inner().payload.len();
                        metrics.record(elapsed, resp_size);
                    }
                    Some(Err(_)) => metrics.record_error(),
                    None => metrics.record_timeout(),
                }
            }
            metrics
        }));
    }

    collect_metrics(handles, bounds).await
}

// -- WebSocket Runner ---------------------------------------------------------

async fn run_websocket(cli: &Cli, payload: &Arc<Vec<u8>>) -> anyhow::Result<BenchMetrics> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let bounds = Bounds::new(cli);
    let concurrency = cli.concurrency as usize;

    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let target = cli.target.clone();
        let payload = Arc::clone(payload);

        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

            let ws_stream = match bounds.op(tokio_tungstenite::connect_async(&target)).await {
                Some(Ok((ws_stream, _))) => ws_stream,
                Some(Err(_)) => {
                    metrics.record_setup_error();
                    return metrics;
                }
                None => {
                    metrics.record_setup_timeout();
                    return metrics;
                }
            };
            metrics.mark_measuring();

            let (mut writer, mut reader) = ws_stream.split();

            while bounds.measuring() {
                let msg = Message::Binary(payload.to_vec());
                let start = Instant::now();

                let echo = async {
                    writer.send(msg).await.ok()?;
                    reader.next().await
                };
                match bounds.op(echo).await {
                    Some(Some(Ok(Message::Binary(data)))) => {
                        let elapsed = start.elapsed().as_micros() as u64;
                        metrics.record(elapsed, data.len());
                    }
                    Some(Some(Ok(_))) => {
                        let elapsed = start.elapsed().as_micros() as u64;
                        metrics.record(elapsed, 0);
                    }
                    Some(_) => {
                        metrics.record_error();
                        break;
                    }
                    None => {
                        // A half-finished echo leaves the socket out of step.
                        metrics.record_timeout();
                        break;
                    }
                }
            }
            metrics
        }));
    }

    collect_metrics(handles, bounds).await
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
    let bounds = Bounds::new(cli);
    let concurrency = cli.concurrency as usize;

    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let payload = Arc::clone(payload);

        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

            let mut stream = match bounds.op(TcpStream::connect(addr)).await {
                Some(Ok(s)) => s,
                Some(Err(_)) => {
                    metrics.record_setup_error();
                    return metrics;
                }
                None => {
                    metrics.record_setup_timeout();
                    return metrics;
                }
            };
            let _ = stream.set_nodelay(true);
            metrics.mark_measuring();

            let mut buf = vec![0u8; payload.len()];

            while bounds.measuring() {
                let start = Instant::now();
                let echo = async {
                    stream.write_all(&payload).await?;
                    stream.read_exact(&mut buf).await
                };
                match bounds.op(echo).await {
                    Some(Ok(_)) => {
                        let latency = start.elapsed().as_micros() as u64;
                        metrics.record(latency, buf.len());
                    }
                    Some(Err(_)) => {
                        metrics.record_error();
                        break;
                    }
                    None => {
                        // A half-finished echo leaves the stream out of step.
                        metrics.record_timeout();
                        break;
                    }
                }
            }
            metrics
        }));
    }

    collect_metrics(handles, bounds).await
}

// -- UDP Runner ---------------------------------------------------------------

async fn run_udp(cli: &Cli, payload: &Arc<Vec<u8>>) -> anyhow::Result<BenchMetrics> {
    let addr: SocketAddr = cli.target.parse().map_err(|_| {
        anyhow::anyhow!(
            "Invalid UDP target address '{}'. Expected format: 127.0.0.1:5003",
            cli.target
        )
    })?;
    let bounds = Bounds::new(cli);
    let concurrency = cli.concurrency as usize;

    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let payload = Arc::clone(payload);

        handles.push(tokio::spawn(async move {
            let mut metrics = BenchMetrics::new();

            let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => {
                    metrics.record_setup_error();
                    return metrics;
                }
            };
            if sock.connect(addr).await.is_err() {
                metrics.record_setup_error();
                return metrics;
            }
            metrics.mark_measuring();

            let mut buf = vec![0u8; 65535];
            // A lost datagram is an ordinary UDP error, not a stalled run.
            let recv_timeout = Duration::from_secs(2).min(bounds.request_timeout);

            while bounds.measuring() {
                let start = Instant::now();
                if sock.send(&payload).await.is_err() {
                    metrics.record_error();
                    continue;
                }
                match tokio::time::timeout(recv_timeout, sock.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        let latency = start.elapsed().as_micros() as u64;
                        metrics.record(latency, n);
                    }
                    _ => metrics.record_error(),
                }
            }
            metrics
        }));
    }

    collect_metrics(handles, bounds).await
}

// -- Helpers ------------------------------------------------------------------

async fn read_response_body(resp: Response<Incoming>) -> anyhow::Result<usize> {
    let body = BodyExt::collect(resp.into_body()).await?.to_bytes();
    Ok(body.len())
}

/// Join every worker by the run's hard deadline (plus a short grace). A worker
/// that panicked, or is still running then and is cancelled, counts as a
/// worker failure, so its lost samples invalidate the run rather than vanish.
async fn collect_metrics(
    handles: Vec<tokio::task::JoinHandle<BenchMetrics>>,
    bounds: Bounds,
) -> anyhow::Result<BenchMetrics> {
    let join_deadline = tokio::time::Instant::from_std(bounds.hard_deadline + JOIN_GRACE);
    let mut combined = BenchMetrics::new();
    for mut h in handles {
        match tokio::time::timeout_at(join_deadline, &mut h).await {
            Ok(Ok(m)) => combined.merge(&m),
            Ok(Err(_)) => combined.record_worker_failure(),
            Err(_) => {
                h.abort();
                combined.record_worker_failure();
            }
        }
    }
    Ok(combined)
}
