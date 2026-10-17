//! HTTP/1.1 closed-loop load generator for the mesh-runtime benchmark.
//!
//! One keep-alive connection per worker, fixed payload, explicit
//! `--host-header` so mesh outbound (host-routed) listeners can be driven
//! through an IP-literal dial. A response only counts when the status is
//! 200 AND the echoed body length equals the request payload length.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use mesh_runtime_perf::BenchMetrics;
use tokio::net::TcpStream;

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
    #[arg(long, default_value_t = 10)]
    duration: u64,
    #[arg(long, default_value_t = 100)]
    concurrency: u64,
    #[arg(long, default_value_t = 1024)]
    payload_size: usize,
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

    let deadline = Instant::now() + Duration::from_secs(args.duration);
    let payload = Bytes::from(vec![b'x'; args.payload_size]);

    let mut handles = Vec::with_capacity(args.concurrency as usize);
    for _ in 0..args.concurrency {
        let host = host.clone();
        let path = path.clone();
        let host_header = args.host_header.clone();
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            worker(host, port, path, host_header, payload, deadline).await
        }));
    }

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
            "  {} target={} concurrency={}\n  Latency avg {}us p50 {}us p95 {}us p99 {}us max {}us\n  {} requests, {} errors\nRequests/sec: {:.2}",
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
            r.rps
        );
    }
    Ok(())
}

async fn worker(
    host: String,
    port: u16,
    path: String,
    host_header: String,
    payload: Bytes,
    deadline: Instant,
) -> BenchMetrics {
    let mut metrics = BenchMetrics::new();
    let mut sender: Option<SendRequest<Full<Bytes>>> = None;

    while Instant::now() < deadline {
        let mut send = match sender.take() {
            Some(s) if s.is_ready() => s,
            _ => match open_conn(&host, port).await {
                Ok(s) => s,
                Err(_) => {
                    metrics.record_error();
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            },
        };

        let req = match Request::builder()
            .method("POST")
            .uri(&path)
            .header("host", &host_header)
            .header("content-length", payload.len().to_string())
            .body(Full::new(payload.clone()))
        {
            Ok(r) => r,
            Err(_) => {
                metrics.record_error();
                continue;
            }
        };

        let start = Instant::now();
        let send_result = send.send_request(req).await;

        match send_result {
            Ok(resp) => {
                let status = resp.status();
                match resp.into_body().collect().await {
                    Ok(body) if status == StatusCode::OK => {
                        let bytes = body.to_bytes();
                        if bytes.len() == payload.len() {
                            let elapsed = start.elapsed().as_micros() as u64;
                            metrics.record(elapsed, bytes.len());
                            sender = Some(send);
                        } else {
                            metrics.record_error();
                        }
                    }
                    _ => {
                        metrics.record_error();
                    }
                }
            }
            Err(_) => {
                metrics.record_error();
            }
        }
    }
    metrics
}

async fn open_conn(host: &str, port: u16) -> Result<SendRequest<Full<Bytes>>> {
    let tcp = TcpStream::connect((host, port)).await?;
    let _ = tcp.set_nodelay(true);
    let (send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(send)
}
