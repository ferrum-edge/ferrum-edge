//! DNS load generator for the mesh DNS proxy E2E perf harness.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use clap::{Parser, ValueEnum};
use mesh_dns_e2e_perf::dns_wire::{
    QTYPE_A, build_query, build_query_with_edns, decode_tcp_dns_length, frame_for_tcp,
    parse_response,
};
use mesh_dns_e2e_perf::metrics::{
    ClassMetrics, ClassReport, NameClass, RunReport, Transport, print_text_report,
    selected_reports_failure,
};
use mesh_dns_e2e_perf::slice::workload_names;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

#[derive(Parser, Debug, Clone)]
#[command(about = "DNS load generator for the mesh DNS proxy perf harness")]
struct Args {
    /// Resolver address (host:port). For "via gateway" runs, the gateway DNS
    /// proxy address (default 127.0.0.1:15053). For baseline runs, point at
    /// `dns_upstream_stub`'s address.
    #[arg(long, default_value = "127.0.0.1:15053")]
    target: String,

    /// Test duration in seconds.
    #[arg(long, default_value_t = 30)]
    duration: u64,

    /// Concurrent in-flight queries (parallel workers).
    #[arg(long, default_value_t = 100)]
    concurrency: u64,

    /// Transport mix.
    #[arg(long, value_enum, default_value_t = ProtocolMode::Both)]
    protocol: ProtocolMode,

    /// Set an EDNS(0) OPT record advertising this UDP payload size.
    /// 0 = no OPT record, otherwise must be in 512..=4096.
    #[arg(long, default_value_t = 0, value_parser = parse_edns)]
    edns: u16,

    /// Per-query timeout in milliseconds.
    #[arg(long, default_value_t = 2_000)]
    query_timeout_ms: u64,

    /// Skip mesh-internal queries (use for `--baseline` against the upstream
    /// stub; mesh-internal names only resolve through the gateway).
    #[arg(long, default_value_t = false)]
    skip_mesh: bool,

    /// Emit JSON instead of a text table.
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ProtocolMode {
    Udp,
    Tcp,
    Both,
}

fn parse_edns(raw: &str) -> Result<u16, String> {
    let value: u16 = raw
        .parse()
        .map_err(|e| format!("--edns must be a u16: {e}"))?;
    if value == 0 || (512..=4096).contains(&value) {
        Ok(value)
    } else {
        Err(format!(
            "--edns must be 0 (disabled) or in 512..=4096, got {value}"
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    let target: SocketAddr = args
        .target
        .parse()
        .with_context(|| format!("invalid target '{}'", args.target))?;

    // Filter workload names per --skip-mesh.
    let names: Vec<(&str, NameClass)> = workload_names()
        .iter()
        .copied()
        .filter(|(_, class)| !args.skip_mesh || matches!(class, NameClass::UpstreamForward))
        .collect();
    if names.is_empty() {
        return Err(anyhow!("no name classes selected; check --skip-mesh"));
    }

    // Run one transport at a time. UDP first, then TCP if requested.
    let transports: Vec<Transport> = match args.protocol {
        ProtocolMode::Udp => vec![Transport::Udp],
        ProtocolMode::Tcp => vec![Transport::Tcp],
        ProtocolMode::Both => vec![Transport::Udp, Transport::Tcp],
    };
    let selected_classes: Vec<NameClass> = NameClass::ALL
        .iter()
        .copied()
        .filter(|class| names.iter().any(|(_, selected)| selected == class))
        .collect();

    let mut all_reports: Vec<ClassReport> = Vec::new();
    for &transport in &transports {
        let reports = run_phase(&args, target, transport, &names).await?;
        all_reports.extend(reports);
    }

    // Emit the machine-readable (or text) report before failing so hosted
    // artifacts still contain the partial blob for diagnosis. A selected
    // protocol or row with zero successes or nonzero query errors must not
    // look like a clean run.
    if args.json {
        let run = RunReport {
            target: args.target.clone(),
            concurrency: args.concurrency,
            duration_secs: args.duration,
            reports: all_reports.clone(),
        };
        println!("{}", serde_json::to_string_pretty(&run)?);
    } else {
        print_text_report(&all_reports, &args.target, args.concurrency);
    }

    if let Some(reason) = selected_reports_failure(&all_reports, &selected_classes, &transports) {
        eprintln!("[dns_loadgen] {reason}");
        return Err(anyhow!(reason));
    }
    Ok(())
}

async fn run_phase(
    args: &Args,
    target: SocketAddr,
    transport: Transport,
    names: &[(&str, NameClass)],
) -> Result<Vec<ClassReport>, anyhow::Error> {
    let stop = Arc::new(AtomicBool::new(false));
    let txid_seq = Arc::new(AtomicU16::new(1));
    let deadline = Instant::now() + Duration::from_secs(args.duration);

    let stop_signal = stop.clone();
    let timer = tokio::spawn(async move {
        let now = Instant::now();
        if let Some(remaining) = deadline.checked_duration_since(now) {
            tokio::time::sleep(remaining).await;
        }
        stop_signal.store(true, Ordering::Relaxed);
    });

    let workers: Vec<_> = (0..args.concurrency)
        .map(|worker_id| {
            let args = args.clone();
            let stop = stop.clone();
            let txid_seq = txid_seq.clone();
            let names: Vec<(String, NameClass)> =
                names.iter().map(|(n, c)| ((*n).to_string(), *c)).collect();
            tokio::spawn(async move {
                worker_loop(worker_id, args, target, transport, names, stop, txid_seq).await
            })
        })
        .collect();

    let mut per_class: HashMap<NameClass, ClassMetrics> = HashMap::new();
    let mut worker_join_failed = false;
    for w in workers {
        match w.await {
            Ok(metrics) => {
                for (class, m) in metrics {
                    per_class.entry(class).or_default().merge(&m);
                }
            }
            Err(e) => {
                eprintln!("[dns_loadgen] worker join error: {e}");
                worker_join_failed = true;
            }
        }
    }
    let _ = timer.await;
    if worker_join_failed {
        return Err(anyhow!("one or more DNS load-generator workers failed"));
    }

    let mut reports = Vec::with_capacity(per_class.len());
    for class in NameClass::ALL {
        if let Some(m) = per_class.get(class) {
            reports.push(m.to_report(*class, transport, args.duration));
        }
    }
    Ok(reports)
}

async fn worker_loop(
    worker_id: u64,
    args: Args,
    target: SocketAddr,
    transport: Transport,
    names: Vec<(String, NameClass)>,
    stop: Arc<AtomicBool>,
    txid_seq: Arc<AtomicU16>,
) -> HashMap<NameClass, ClassMetrics> {
    let mut metrics: HashMap<NameClass, ClassMetrics> = HashMap::new();
    let mut local_idx: usize = worker_id as usize;
    let socket = if matches!(transport, Transport::Udp) {
        match UdpSocket::bind("127.0.0.1:0").await {
            Ok(s) => {
                if let Err(e) = s.connect(target).await {
                    eprintln!("[dns_loadgen] udp connect error: {e}");
                    return metrics;
                }
                Some(s)
            }
            Err(e) => {
                eprintln!("[dns_loadgen] udp bind error: {e}");
                return metrics;
            }
        }
    } else {
        None
    };

    while !stop.load(Ordering::Relaxed) {
        let (name, class) = &names[local_idx % names.len()];
        local_idx = local_idx.wrapping_add(1);

        let txid = next_txid(&txid_seq);
        let packet = if args.edns != 0 {
            build_query_with_edns(name, QTYPE_A, txid, args.edns)
        } else {
            build_query(name, QTYPE_A, txid)
        };

        let entry = metrics.entry(*class).or_default();
        let start = Instant::now();
        let result = match transport {
            Transport::Udp => {
                udp_query(socket.as_ref().unwrap(), &packet, args.query_timeout_ms).await
            }
            Transport::Tcp => tcp_query(target, &packet, args.query_timeout_ms).await,
        };
        let elapsed = start.elapsed();
        let elapsed_us = elapsed.as_micros().min(u64::MAX as u128) as u64;

        match result {
            Ok(bytes) => match parse_response(&bytes) {
                Some(parsed) if parsed.is_response && parsed.txid == txid => match parsed.rcode {
                    0 if parsed.answer_count > 0 => {
                        entry.record(elapsed_us, bytes.len());
                    }
                    0 => {
                        entry.record_error();
                    }
                    3 => entry.record_nxdomain(),
                    _ => entry.record_error(),
                },
                _ => entry.record_error(),
            },
            Err(_) => entry.record_error(),
        }
    }

    metrics
}

fn next_txid(seq: &AtomicU16) -> u16 {
    seq.fetch_add(1, Ordering::Relaxed)
}

async fn udp_query(
    socket: &UdpSocket,
    packet: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>, anyhow::Error> {
    socket.send(packet).await?;
    let mut buf = vec![0u8; 4096];
    let len = match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(anyhow!("udp query timed out")),
    };
    buf.truncate(len);
    Ok(buf)
}

async fn tcp_query(
    target: SocketAddr,
    packet: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut stream = timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(target),
    )
    .await
    .map_err(|_| anyhow!("tcp connect timed out"))??;
    stream.set_nodelay(true)?;
    let framed = frame_for_tcp(packet)
        .ok_or_else(|| anyhow!("DNS TCP query cannot be represented by a u16 length prefix"))?;
    stream.write_all(&framed).await?;
    let mut len_buf = [0u8; 2];
    timeout(
        Duration::from_millis(timeout_ms),
        stream.read_exact(&mut len_buf),
    )
    .await
    .map_err(|_| anyhow!("tcp read length timed out"))??;
    let len = decode_tcp_dns_length(len_buf)
        .map_err(|_| anyhow!("tcp DNS rejected empty length prefix"))?;
    let mut buf = vec![0u8; len];
    timeout(
        Duration::from_millis(timeout_ms),
        stream.read_exact(&mut buf),
    )
    .await
    .map_err(|_| anyhow!("tcp read payload timed out"))??;
    Ok(buf)
}
