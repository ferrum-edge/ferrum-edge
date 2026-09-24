//! HBONE E2E load generator. Also hosts a `generate-certs` subcommand the
//! harness uses to lay down the SPIFFE-shaped material under `runtime/certs/`.
//!
//! `run` issues HTTP/1.1 POST requests against the supplied URL with a fixed
//! payload size, counts latency in microseconds via `hdrhistogram`, and prints
//! either a text report or a `BenchReport` JSON blob.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use mesh_hbone_e2e_perf::certs::{generate, write_to_dir};
use mesh_hbone_e2e_perf::metrics::BenchMetrics;
use tokio::net::TcpStream;

#[derive(Parser)]
#[command(name = "hbone_loadgen")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    GenerateCerts(CertArgs),
    Run(RunArgs),
}

#[derive(Parser)]
struct CertArgs {
    #[arg(long)]
    out_dir: PathBuf,
    #[arg(long, default_value = "cluster.local")]
    trust_domain: String,
}

#[derive(Parser, Clone)]
struct RunArgs {
    #[arg(long)]
    target: String,

    #[arg(long, default_value = "edge.local")]
    host_header: String,

    #[arg(long, default_value = "30")]
    duration: u64,

    #[arg(long, default_value = "50")]
    concurrency: u64,

    #[arg(long, default_value = "1024")]
    payload_size: usize,

    #[arg(long, default_value_t = false)]
    json: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::GenerateCerts(a) => generate_certs(&a),
        Cmd::Run(a) => run(&a).await,
    }
}

fn generate_certs(args: &CertArgs) -> Result<()> {
    let certs = generate(&args.trust_domain)?;
    write_to_dir(&certs, &args.out_dir)?;
    println!(
        "wrote ca.pem + gateway-{{cert,key}}.pem + sidecar-{{cert,key}}.pem to {}",
        args.out_dir.display()
    );
    println!("gateway SPIFFE ID: {}", certs.gateway_spiffe_id);
    println!("sidecar SPIFFE ID: {}", certs.sidecar_spiffe_id);
    Ok(())
}

async fn run(args: &RunArgs) -> Result<()> {
    let url = args
        .target
        .parse::<http::Uri>()
        .context("parsing --target URL")?;
    let host: String = url
        .host()
        .ok_or_else(|| anyhow::anyhow!("target URL missing host"))?
        .to_string();
    let port = url.port_u16().unwrap_or(80);
    let path = if url.path().is_empty() {
        "/".to_string()
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
        return Err(anyhow::anyhow!(
            "one or more HBONE load-generator workers failed"
        ));
    }

    let label = "hbone_e2e";
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&combined.json(
                label,
                &args.target,
                args.concurrency,
                args.duration,
                args.payload_size,
            ))
            .unwrap_or_default()
        );
    } else {
        println!(
            "{}",
            combined.report(label, &args.target, args.concurrency, args.duration)
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
    // Each worker owns its own HTTP/1.1 sender. Hyper 1.x's SendRequest is
    // not Clone; we keep the live sender across iterations to exercise
    // keep-alive and re-open on transport errors.
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
        let elapsed = start.elapsed().as_micros() as u64;

        match send_result {
            Ok(resp) => {
                let status = resp.status();
                match resp.into_body().collect().await {
                    Ok(body) if status == StatusCode::OK => {
                        let bytes = body.to_bytes();
                        metrics.record(elapsed, bytes.len());
                        // Connection still alive — reuse for the next request.
                        sender = Some(send);
                    }
                    _ => {
                        metrics.record_error();
                        // Drop the sender; next iteration will open a fresh
                        // connection.
                    }
                }
            }
            Err(_) => {
                metrics.record_error();
                // Drop the sender; next iteration will reopen.
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
        let _ = conn.with_upgrades().await;
    });
    Ok(send)
}
