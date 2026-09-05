//! Socket-level admission on the mesh application-probe listener (issue #4625).
//!
//! The unit suite pins the accounting; this pins the listener's real behaviour
//! against real sockets, because the whole point of the fix is *where* the
//! decision happens. A partial-header flood must be bounded by the connection
//! ceiling even though every one of those sockets is unauthenticated and
//! pre-HTTP, and a flood of perfectly valid probe requests must be bounded by
//! the active-probe budget, measured where it matters: the number of
//! simultaneous loopback connections reaching the application container.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::modes::mesh::app_probe::{
    AppProbeAdmission, AppProbeServer, parse_app_probes, run_app_probe_server,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Poll `condition` until it holds or the budget elapses. Wall-clock waits are
/// unavoidable here (the listener is a real accept loop) but they are bounded
/// and the failure message carries the last observed value.
async fn wait_for(label: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {label}");
}

/// A loopback stand-in for the application container that ACCEPTS and then
/// holds, so an in-flight probe stays in flight while we measure. Returns its
/// port, the live-connection gauge, and the high-water mark.
fn spawn_slow_application() -> (
    u16,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind slow application");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let listener = TcpListener::from_std(listener).expect("adopt listener");
    let live = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let task_live = Arc::clone(&live);
    let task_peak = Arc::clone(&peak);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let live = Arc::clone(&task_live);
            let peak = Arc::clone(&task_peak);
            tokio::spawn(async move {
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                // Never answer: the probe's own `timeoutSeconds` retires it,
                // which is exactly the slow-handler shape the issue describes.
                let mut stream = stream;
                let mut sink = [0_u8; 64];
                loop {
                    match stream.read(&mut sink).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (port, live, peak, handle)
}

struct RunningProbeServer {
    port: u16,
    shutdown: tokio::sync::watch::Sender<bool>,
    server: tokio::task::JoinHandle<()>,
}

impl RunningProbeServer {
    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.server).await;
    }
}

async fn start_probe_server(
    admission: Arc<AppProbeAdmission>,
    probes_json: &str,
) -> RunningProbeServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe listener");
    let port = listener.local_addr().expect("addr").port();
    let targets = parse_app_probes(probes_json).expect("probe targets parse");
    let server = Arc::new(AppProbeServer::with_admission(
        targets,
        Arc::clone(&admission),
    ));
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move {
        run_app_probe_server(listener, server, shutdown_rx).await;
    });
    RunningProbeServer {
        port,
        shutdown,
        server: handle,
    }
}

/// A partial-header flood cannot exceed the connection ceiling.
///
/// Before the fix each of these sockets bought a task and an HTTP state machine
/// that lived until the 5s header timer, with no maximum active count. Now the
/// permit is taken between `accept()` and `spawn`, so occupancy is pinned at
/// the ceiling and the surplus is closed in the accept loop.
#[tokio::test]
async fn a_partial_header_flood_cannot_exceed_the_connection_ceiling() {
    const CEILING: usize = 4;
    const FLOOD: usize = 24;

    // Per-IP disabled: every client here is 127.0.0.1, so the global cap has to
    // be the dimension under test.
    let admission = Arc::new(AppProbeAdmission::new(CEILING, 0, 0, None));
    let running = start_probe_server(
        Arc::clone(&admission),
        r#"{"app/livenessProbe":{"httpGet":{"path":"/livez","port":1,"scheme":"HTTP"},"timeoutSeconds":1}}"#,
    )
    .await;

    // Incomplete request headers — no terminating blank line — held open.
    let mut held = Vec::new();
    for _ in 0..FLOOD {
        let Ok(mut stream) = TcpStream::connect(("127.0.0.1", running.port)).await else {
            continue;
        };
        let _ = stream
            .write_all(b"GET /app-probe/app/livenessProbe HTTP/1.1\r\nHost:")
            .await;
        held.push(stream);
    }

    let occupancy = Arc::clone(&admission);
    wait_for("the listener to fill to its ceiling", move || {
        occupancy.limiter_snapshot().active_connections as usize == CEILING
    })
    .await;

    let snapshot = admission.limiter_snapshot();
    assert_eq!(
        snapshot.active_connections as usize, CEILING,
        "occupancy is pinned at the ceiling, not at the flood size"
    );
    assert!(
        snapshot.rejected_max_connections > 0,
        "the surplus was refused by the global cap, not silently accepted"
    );
    assert_eq!(
        snapshot.rejected_max_connections_per_ip, 0,
        "the per-IP dimension is disabled in this case"
    );

    // Releasing the flood frees the permits: the ceiling is a concurrency
    // bound, not a one-way latch.
    drop(held);
    let drained = Arc::clone(&admission);
    wait_for("the permits to drain", move || {
        drained.limiter_snapshot().active_connections == 0
    })
    .await;

    running.stop().await;
}

/// A flood of *valid* probe requests cannot exceed the active-probe budget,
/// measured at the application container.
///
/// This is the amplification half of the issue: every accepted request opens a
/// fresh loopback connection into the application that lives for the probe's
/// own timeout. Connection capacity alone does not bound it — here the
/// connection cap is deliberately disabled so only the probe budget can.
#[tokio::test]
async fn a_valid_probe_flood_cannot_exceed_the_active_probe_budget() {
    const BUDGET: usize = 2;
    const FLOOD: usize = 10;

    let (app_port, app_live, app_peak, app_task) = spawn_slow_application();

    // Connection caps off; only the probe budget is under test. A 3s probe
    // timeout keeps the first probes in flight for the whole measurement.
    let admission = Arc::new(AppProbeAdmission::new(0, 0, BUDGET, None));
    let running = start_probe_server(
        Arc::clone(&admission),
        &format!(
            r#"{{"app/livenessProbe":{{"httpGet":{{"path":"/livez","port":{app_port},"scheme":"HTTP"}},"timeoutSeconds":3}}}}"#
        ),
    )
    .await;

    // Prime the budget first so the surplus below is measured against a full
    // budget rather than racing the first acquisitions.
    let mut priming = Vec::new();
    for _ in 0..BUDGET {
        let mut stream = TcpStream::connect(("127.0.0.1", running.port))
            .await
            .expect("connect to probe listener");
        stream
            .write_all(b"GET /app-probe/app/livenessProbe HTTP/1.1\r\nHost: probe\r\n\r\n")
            .await
            .expect("send probe request");
        priming.push(stream);
    }
    let live = Arc::clone(&app_live);
    wait_for("the probe budget to fill", move || {
        live.load(Ordering::SeqCst) == BUDGET
    })
    .await;

    // Now the flood. Each of these is a perfectly valid, unauthenticated GET.
    let mut shed = 0_usize;
    for _ in 0..FLOOD {
        let mut stream = TcpStream::connect(("127.0.0.1", running.port))
            .await
            .expect("connect to probe listener");
        stream
            .write_all(b"GET /app-probe/app/livenessProbe HTTP/1.1\r\nHost: probe\r\n\r\n")
            .await
            .expect("send probe request");
        let mut response = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(2), async {
            let mut buf = [0_u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        response.extend_from_slice(&buf[..n]);
                        if response.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
        })
        .await;
        assert!(
            read.is_ok(),
            "an over-budget refusal is immediate, not queued"
        );
        let text = String::from_utf8_lossy(&response);
        assert!(
            text.starts_with("HTTP/1.1 503 "),
            "an over-budget probe request is refused with 503, got: {text}"
        );
        assert!(
            text.contains("app probe budget exhausted"),
            "the refusal is the bounded budget body, not a probe outcome: {text}"
        );
        assert!(
            text.to_ascii_lowercase().contains("connection: close"),
            "an over-budget refusal retires the socket: {text}"
        );
        shed += 1;
    }

    assert_eq!(shed, FLOOD, "every over-budget request was shed");
    assert_eq!(
        app_peak.load(Ordering::SeqCst),
        BUDGET,
        "the application container never saw more concurrent loopback probes than the budget"
    );
    assert_eq!(
        admission.budget().rejected() as usize,
        FLOOD,
        "each shed request is counted exactly once"
    );

    drop(priming);
    running.stop().await;
    app_task.abort();
}
