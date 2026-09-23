//! Low-rate streaming latency profile for the response-aggregation window.
//!
//! The throughput benchmark cannot answer whether
//! `FERRUM_RESPONSE_COALESCE_FLUSH_MS` costs anything, because at saturation a
//! millisecond hold is invisible against a p50 of hundreds of milliseconds.
//! The workload that a hold actually penalises is the opposite one: a server
//! sent event or long poll whose frames are small and far apart, where the
//! aggregator waits for a sibling frame that is not coming and every frame
//! reaches the client late by up to the whole window.
//!
//! Each `/trickle` frame opens with the backend's own emission timestamp, so
//! frame latency is measured directly rather than inferred from the nominal
//! schedule. That distinction matters: subtracting `k * gap_ms` measures the
//! accumulated overshoot of the backend's `sleep` calls, a residual that grows
//! linearly with frame index and buries a hold of a millisecond or two.
//!
//! A gateway that aggregates will also MERGE frames, so arrivals are not frames.
//! Frames are recovered by fixed-size framing out of a running buffer, which
//! survives both merging and TLS-record splitting; `reads` versus `frames`
//! then says how much merging happened, independently of the latency figures.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use http_body_util::BodyExt;
use hyper::{Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Serialize;
use tokio::net::TcpStream;

use multi_protocol_perf::tls_utils;

#[derive(Parser, Debug, Clone)]
#[command(about = "Low-rate streaming latency profile (SSE / long-poll shape)")]
struct Args {
    /// host:port of the gateway (or backend, for a direct control)
    #[arg(long)]
    target: String,
    /// Frames the backend emits per response
    #[arg(long, default_value_t = 20)]
    frames: u64,
    /// Bytes per frame. Keep well under the coalescing target so the window,
    /// not the size trigger, decides when a frame is released.
    #[arg(long, default_value_t = 1024)]
    size: u64,
    /// Milliseconds between frames at the backend
    #[arg(long, default_value_t = 10)]
    gap_ms: u64,
    /// Sequential requests per connection slot
    #[arg(long, default_value_t = 30)]
    requests: u64,
    /// Concurrent connection slots. Deliberately small: this measures latency
    /// on an idle proxy, not throughput under contention.
    #[arg(long, default_value_t = 4)]
    concurrency: u64,
    /// ALPN to offer: h1 or h2
    #[arg(long, default_value = "h1")]
    alpn: String,
    /// Where to write the JSON result
    #[arg(long)]
    out: Option<String>,
}

#[derive(Serialize)]
struct Report {
    target: String,
    alpn: String,
    frames_requested: u64,
    frame_size: u64,
    gap_ms: u64,
    requests_completed: u64,
    requests_failed: u64,
    concurrency: u64,
    /// Backend frames recovered per response; should equal `frames_requested`.
    frames_received_mean: f64,
    /// Body reads per response. Fewer reads than frames is aggregation, which
    /// is the mechanism under test made visible.
    reads_mean: f64,
    ttfb_us: Quantiles,
    /// Arrival minus the backend's stamped emission time, per frame. This is
    /// the number a holding window moves, and it is drift-free.
    frame_delay_us: Quantiles,
    /// Gap between consecutive arrivals at the client.
    inter_frame_us: Quantiles,
}

#[derive(Serialize)]
struct Quantiles {
    n: u64,
    mean: f64,
    p50: u64,
    p90: u64,
    p99: u64,
    max: u64,
}

fn quantiles(mut values: Vec<u64>) -> Quantiles {
    values.sort_unstable();
    let n = values.len() as u64;
    if n == 0 {
        return Quantiles {
            n: 0,
            mean: 0.0,
            p50: 0,
            p90: 0,
            p99: 0,
            max: 0,
        };
    }
    let at = |q: f64| {
        let index = ((values.len() as f64 - 1.0) * q).round() as usize;
        values[index]
    };
    Quantiles {
        n,
        mean: values.iter().sum::<u64>() as f64 / n as f64,
        p50: at(0.50),
        p90: at(0.90),
        p99: at(0.99),
        max: *values.last().unwrap_or(&0),
    }
}

struct Sample {
    ttfb_us: u64,
    frames: u64,
    reads: u64,
    /// arrival-minus-stamped-emission, per recovered frame
    delays_us: Vec<u64>,
    inter_us: Vec<u64>,
}

/// Bytes the backend reserves for `TS:<16 digits>;` at the head of each frame.
const STAMP_LEN: usize = 20;

fn stamped_micros(frame: &[u8]) -> Option<u64> {
    let head = frame.get(..STAMP_LEN)?;
    if !head.starts_with(b"TS:") || !head.ends_with(b";") {
        return None;
    }
    std::str::from_utf8(&head[3..STAMP_LEN - 1])
        .ok()?
        .parse()
        .ok()
}

async fn one_request(args: &Args, tls: Arc<rustls::ClientConfig>) -> Result<Sample> {
    let stream = TcpStream::connect(&args.target).await.context("connect")?;
    stream.set_nodelay(true).ok();
    let connector = tokio_rustls::TlsConnector::from(tls);
    let server_name = rustls::pki_types::ServerName::try_from("localhost")
        .context("server name")?
        .to_owned();
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .context("tls")?;
    let io = TokioIo::new(tls_stream);

    let path = format!(
        "/trickle?frames={}&size={}&gap_ms={}",
        args.frames, args.size, args.gap_ms
    );
    // HTTP/2 derives `:authority` from the URI, so it needs absolute form;
    // HTTP/1.1 wants origin form against an origin server and carries the
    // authority in `host`.
    //
    // Do NOT also send `host` on h2: RFC 9113 8.3.1 requires it to agree with
    // `:authority`, and a gateway is right to reject the pair when they differ.
    // The authority is built from the TLS server name rather than the dial
    // address so it matches SNI and the certificate.
    let port = args.target.rsplit(':').next().unwrap_or("443");
    let request = if args.alpn == "h2" {
        Request::builder()
            .uri(format!("https://localhost:{port}{path}"))
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .context("request")?
    } else {
        Request::builder()
            .uri(&path)
            .header("host", "localhost")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .context("request")?
    };

    // Send, then time every frame off the same origin.
    let start = Instant::now();
    let mut response = if args.alpn == "h2" {
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .context("h2 handshake")?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender.send_request(request).await.context("h2 send")?
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("h1 handshake")?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender.send_request(request).await.context("h1 send")?
    };

    if response.status() != StatusCode::OK {
        anyhow::bail!("unexpected status {}", response.status());
    }

    let mut ttfb_us = 0u64;
    let mut frames = 0u64;
    let mut reads = 0u64;
    let mut delays = Vec::new();
    let mut inter = Vec::new();
    let mut previous: Option<Instant> = None;
    let frame_len = (args.size as usize).max(STAMP_LEN);
    let mut buffer: Vec<u8> = Vec::with_capacity(frame_len * 2);

    while let Some(next) = response.frame().await {
        let frame = next.context("frame")?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let now = Instant::now();
        if reads == 0 {
            ttfb_us = now.duration_since(start).as_micros() as u64;
        }
        reads += 1;
        if let Some(mark) = previous {
            inter.push(now.duration_since(mark).as_micros() as u64);
        }
        previous = Some(now);

        // Recover whole backend frames regardless of how the gateway packed
        // them: aggregation merges several into one read, TLS can split one
        // across two, and fixed-size framing out of a running buffer is
        // correct under both.
        buffer.extend_from_slice(&data);
        let arrival = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        let mut consumed = 0usize;
        while buffer.len() - consumed >= frame_len {
            let slice = &buffer[consumed..consumed + frame_len];
            if let Some(sent) = stamped_micros(slice) {
                delays.push(arrival.saturating_sub(sent));
                frames += 1;
            }
            consumed += frame_len;
        }
        buffer.drain(..consumed);
    }

    Ok(Sample {
        ttfb_us,
        frames,
        reads,
        delays_us: delays,
        inter_us: inter,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        // Already installed by another entry point; not fatal.
    }

    let mut config = tls_utils::make_client_tls_config_insecure();
    config.alpn_protocols = if args.alpn == "h2" {
        vec![b"h2".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    let tls = Arc::new(config);

    let mut tasks = Vec::new();
    for _ in 0..args.concurrency {
        let args = args.clone();
        let tls = Arc::clone(&tls);
        tasks.push(tokio::spawn(async move {
            let mut samples = Vec::new();
            let mut failed = 0u64;
            for _ in 0..args.requests {
                match one_request(&args, Arc::clone(&tls)).await {
                    Ok(sample) => samples.push(sample),
                    Err(error) => {
                        failed += 1;
                        if failed <= 3 {
                            eprintln!("request failed: {error:#}");
                        }
                    }
                }
            }
            (samples, failed)
        }));
    }

    let mut ttfb = Vec::new();
    let mut delays = Vec::new();
    let mut inter = Vec::new();
    let mut frame_counts = Vec::new();
    let mut read_counts = Vec::new();
    let mut completed = 0u64;
    let mut failed = 0u64;
    for task in tasks {
        let (samples, task_failed) = task.await.context("worker")?;
        failed += task_failed;
        for sample in samples {
            completed += 1;
            ttfb.push(sample.ttfb_us);
            frame_counts.push(sample.frames);
            read_counts.push(sample.reads);
            delays.extend(sample.delays_us);
            inter.extend(sample.inter_us);
        }
    }

    let report = Report {
        target: args.target.clone(),
        alpn: args.alpn.clone(),
        frames_requested: args.frames,
        frame_size: args.size,
        gap_ms: args.gap_ms,
        requests_completed: completed,
        requests_failed: failed,
        concurrency: args.concurrency,
        frames_received_mean: if frame_counts.is_empty() {
            0.0
        } else {
            frame_counts.iter().sum::<u64>() as f64 / frame_counts.len() as f64
        },
        reads_mean: if read_counts.is_empty() {
            0.0
        } else {
            read_counts.iter().sum::<u64>() as f64 / read_counts.len() as f64
        },
        ttfb_us: quantiles(ttfb),
        frame_delay_us: quantiles(delays),
        inter_frame_us: quantiles(inter),
    };

    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = &args.out {
        std::fs::write(path, format!("{json}\n")).context("writing report")?;
    }
    println!("{json}");
    if completed == 0 {
        anyhow::bail!("no requests completed");
    }
    Ok(())
}
