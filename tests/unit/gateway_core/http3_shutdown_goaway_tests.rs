//! HTTP/3 graceful-shutdown GOAWAY and connection-accounting contracts
//! (issue #4429).
//!
//! Production `ConnectionGuard` / `RequestGuard` Drop is the decrement. These
//! tests prove the H3 listener constructs the connection counter **once** per
//! spawned Incoming, never decrements it by hand, and uses the canonical
//! HTTP/3 no-error close after drain.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use ferrum_edge::overload::{ConnectionGuard, OverloadState, RequestGuard};

fn compact(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

fn server_src() -> &'static str {
    include_str!("../../../src/http3/server.rs")
}

fn websocket_src() -> &'static str {
    include_str!("../../../src/http3/websocket.rs")
}

#[test]
fn h3_no_error_close_code_is_rfc_9114_value() {
    let src = server_src();
    assert!(
        src.contains("pub(crate) const H3_NO_ERROR_CLOSE_CODE: u32 = 0x0100;"),
        "H3_NO_ERROR must be RFC 9114 §8.1 0x0100, not QUIC application code 0"
    );
    assert!(src.contains("pub(crate) const H3_NO_ERROR_CLOSE_REASON: &[u8] = b\"shutdown\";"));
}

#[test]
fn listener_force_close_uses_h3_no_error_not_quic_zero() {
    let src = server_src();
    let close = src
        .split("HTTP/3 drain timeout — forcing endpoint close")
        .nth(1)
        .expect("H3 drain-timeout close must remain present")
        .split("endpoint.wait_idle()")
        .next()
        .expect("bounded endpoint.close after drain");
    assert!(
        close.contains("H3_NO_ERROR_CLOSE_CODE") && close.contains("H3_NO_ERROR_CLOSE_REASON"),
        "deadline/drain endpoint.close must use H3_NO_ERROR, got:\n{close}"
    );
    assert!(
        !close.contains("from_u32(0)"),
        "QUIC application code 0 resets remaining H3 work; GOAWAY drain must close with 0x100"
    );
}

#[test]
fn connection_guard_is_constructed_once_in_the_spawn_wrapper() {
    let src = server_src();
    // Count the HTTP/3 `ConnectionGuard` itself, not identifiers that merely
    // end in it (for example `LoadBalancerConnectionGuard::new`).
    let bytes = src.as_bytes();
    let guard_constructions = src
        .match_indices("ConnectionGuard::new")
        .filter(|(at, _)| {
            *at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_')
        })
        .count();
    assert_eq!(
        guard_constructions, 1,
        "exactly one ConnectionGuard::new in server.rs, inside run_h3_connection_with_guard"
    );
    let helper = src
        .split("pub(crate) async fn run_h3_connection_with_guard")
        .nth(1)
        .expect("run_h3_connection_with_guard must exist")
        .split("async fn complete_h3_handshake")
        .next()
        .expect("bounded guard helper");
    assert!(helper.contains("ConnectionGuard::new(&overload)"));
    assert!(
        !helper.contains("fetch_sub"),
        "the helper must not decrement by hand; Drop is the only release"
    );

    let handler = src
        .split("async fn handle_h3_connection(")
        .nth(1)
        .expect("handle_h3_connection must exist")
        .split("async fn handle_h3_request(")
        .next()
        .expect("bounded handle_h3_connection");
    assert!(
        !handler.contains("ConnectionGuard::new"),
        "handle_h3_connection must not construct a second ConnectionGuard"
    );
    assert!(
        !handler.contains("fetch_sub"),
        "handle_h3_connection must not decrement active_connections by hand"
    );
}

#[test]
fn shutdown_watch_is_cloned_into_each_connection_and_request() {
    let src = compact(server_src());
    assert!(
        src.contains("letconn_shutdown=shutdown_rx.clone();"),
        "accept loop must clone the process shutdown watch into each connection task"
    );
    assert!(
        src.contains("letstream_shutdown=shutdown_rx.clone();"),
        "each accepted request stream must clone the connection shutdown watch"
    );
    assert!(
        src.contains("ctx.websocket_shutdown_rx=Some(shutdown_rx);"),
        "H3 requests must stamp websocket_shutdown_rx so RFC 9220 drain can emit Close 1001"
    );
}

#[test]
fn accept_loop_sends_goaway_and_keeps_polling_accept() {
    let src = server_src();
    let accept_loop = src
        .split("let mut h3_goaway_sent = false;")
        .nth(1)
        .expect("GOAWAY latch must remain present")
        .split("/// Peer-gone watch backed by QUIC connection close.")
        .next()
        .expect("bounded H3 accept loop");
    assert!(
        accept_loop.contains("send_h3_goaway(") && src.contains("h3_conn.shutdown(0)"),
        "drain must call the vendored shutdown(0) GOAWAY API"
    );
    assert!(
        accept_loop.contains("h3_conn.accept()"),
        "after GOAWAY the loop must keep polling accept so in-flight streams finish"
    );
    assert!(
        accept_loop.contains("continue;"),
        "successful GOAWAY must continue the accept loop, not drop h3_conn"
    );
}

#[test]
fn h3_websocket_uses_process_shutdown_watch_for_close_frame() {
    let src = websocket_src();
    assert!(
        src.contains("ctx.websocket_shutdown_rx") && src.contains("ws_shutdown_rx.clone()"),
        "H3 WebSocket must pass the process shutdown watch into run_websocket_proxy"
    );
    let relay = src
        .split("let relay_result = match backend_handshake")
        .nth(1)
        .expect("H3 WS relay match must remain present")
        .split("if let Err(e) = relay_result")
        .next()
        .expect("bounded H3 WS relay");
    assert!(
        !relay.contains("state.health_check_shutdown_rx.clone()"),
        "the relay must not ignore process shutdown in favor of the health-check watch"
    );
}

#[test]
fn request_guard_is_constructed_once_after_admission() {
    let src = server_src();
    let handler = src
        .split("async fn handle_h3_request(")
        .nth(1)
        .expect("handle_h3_request must exist")
        .split("\nfn build_h3_backend_url_for_flavor")
        .next()
        .expect("bounded handle_h3_request");
    assert_eq!(
        handler.matches("RequestGuard::new").count(),
        1,
        "handle_h3_request must construct RequestGuard exactly once after admission"
    );
    assert!(
        !handler.contains("fetch_sub"),
        "handle_h3_request must not decrement active_requests by hand"
    );
}

#[tokio::test]
async fn spawn_wrapper_pattern_releases_exactly_once_on_ok() {
    let state = Arc::new(OverloadState::new());
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
    {
        let _conn_guard = ConnectionGuard::new(&state);
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);
        let _: Result<(), anyhow::Error> = Ok(());
    }
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn spawn_wrapper_pattern_releases_exactly_once_on_err() {
    let state = Arc::new(OverloadState::new());
    {
        let _conn_guard = ConnectionGuard::new(&state);
        let result: Result<(), anyhow::Error> = Err(anyhow::anyhow!("peer reset"));
        let _ = result;
    }
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn spawn_wrapper_pattern_releases_exactly_once_on_handshake_cancel() {
    let state = Arc::new(OverloadState::new());
    {
        let _conn_guard = ConnectionGuard::new(&state);
        let result: Result<(), anyhow::Error> = Err(anyhow::anyhow!(
            "HTTP/3 handshake cancelled: gateway is draining"
        ));
        let _ = result;
    }
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn nested_request_guard_does_not_double_decrement_connections() {
    let state = Arc::new(OverloadState::new());
    {
        let _conn_guard = ConnectionGuard::new(&state);
        let _request = RequestGuard::new(&state);
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);
        assert_eq!(state.active_requests.load(Ordering::Relaxed), 1);
    }
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
    assert_eq!(state.active_requests.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn deadline_force_close_path_still_drops_one_connection_guard() {
    // Models listener `endpoint.close(H3_NO_ERROR)` aborting accept(): the
    // connection task returns Err and the spawn wrapper drops the guard once.
    let state = Arc::new(OverloadState::new());
    {
        let _conn_guard = ConnectionGuard::new(&state);
        assert_eq!(state.active_connections.load(Ordering::Relaxed), 1);
        let result: Result<(), anyhow::Error> =
            Err(anyhow::anyhow!("HTTP/3 connection error from peer"));
        let _ = result;
    }
    assert_eq!(state.active_connections.load(Ordering::Relaxed), 0);
}

#[test]
fn connect_udp_is_not_rewritten_for_shutdown() {
    // Issue #4429 scope: CONNECT-UDP already-accepted tunnels keep relaying
    // while the H3 accept loop stays alive after GOAWAY. New streams are
    // refused by vendored `H3_REQUEST_REJECTED`. Do not abort tunnels from
    // this change.
    let src = include_str!("../../../src/http3/connect_udp.rs");
    assert!(src.contains("SessionEnd::Draining"));
    assert!(src.contains("wait_for_drain_start()"));
}

// ---------------------------------------------------------------------------
// Issue #4542 — the overload keepalive tier reaches HTTP/3 as a one-shot GOAWAY
// ---------------------------------------------------------------------------

/// A fresh subscriber must start with the current value already marked seen, so
/// the accept-loop arm only ever fires on a transition. A `false` publication is
/// not a transition worth waking for and must never arm a GOAWAY.
#[tokio::test]
async fn keepalive_pressure_watch_only_wakes_on_a_real_transition() {
    let state = Arc::new(OverloadState::new());
    let mut rx = state.subscribe_keepalive_pressure();

    // Nothing published yet: the arm must stay parked.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            ferrum_edge::http3::server::h3_keepalive_pressure_raised(&mut rx),
        )
        .await
        .is_err(),
        "an unpublished watch must not arm a GOAWAY"
    );

    // Republishing the same `false` value is not a transition.
    state.publish_keepalive_pressure(false);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            ferrum_edge::http3::server::h3_keepalive_pressure_raised(&mut rx),
        )
        .await
        .is_err(),
        "re-publishing `false` must not arm a GOAWAY"
    );

    // The rising edge is the only thing that arms it.
    state.publish_keepalive_pressure(true);
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        ferrum_edge::http3::server::h3_keepalive_pressure_raised(&mut rx),
    )
    .await
    .expect("the rising edge must arm a GOAWAY");
}

/// The recovery edge (`true -> false`) also wakes `changed()`. It must not be
/// mistaken for pressure: a GOAWAY is terminal and cannot be withdrawn.
#[tokio::test]
async fn keepalive_pressure_recovery_edge_does_not_arm_a_goaway() {
    let state = Arc::new(OverloadState::new());
    state.publish_keepalive_pressure(true);

    // Subscribe AFTER the rise, so this receiver has only the fall ahead of it.
    let mut rx = state.subscribe_keepalive_pressure();
    state.publish_keepalive_pressure(false);

    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            ferrum_edge::http3::server::h3_keepalive_pressure_raised(&mut rx),
        )
        .await
        .is_err(),
        "the `true -> false` recovery edge must not arm a GOAWAY"
    );
}

/// The RED sampler is deliberately not consulted on the HTTP/3 path: it is a
/// per-response probability and a GOAWAY is per-connection and terminal.
#[test]
fn h3_accept_loop_reads_only_the_binary_keepalive_tier() {
    let src = server_src();
    let accept_loop = src
        .split("let mut h3_goaway_sent = false;")
        .nth(1)
        .expect("GOAWAY latch must remain present")
        .split("/// Peer-gone watch backed by QUIC connection close.")
        .next()
        .expect("bounded H3 accept loop");
    assert!(
        accept_loop.contains("subscribe_keepalive_pressure()"),
        "the accept loop must observe the overload keepalive tier (issue #4542)"
    );
    assert!(
        accept_loop.contains("h3_keepalive_pressure_raised(&mut keepalive_pressure_rx)"),
        "the keepalive tier must be observed by parking on the watch, not by a per-connection timer"
    );
    assert!(
        !accept_loop.contains("should_disable_keepalive_red"),
        "RED sampling must never drive a terminal per-connection GOAWAY"
    );
    assert!(
        !accept_loop.contains("tokio::time::interval"),
        "the keepalive tier must not cost a per-connection timer"
    );
    assert!(
        accept_loop.contains("H3GoawayTrigger::KeepalivePressure"),
        "the pressure-driven GOAWAY must be distinguishable from the shutdown-driven one"
    );
}

/// The single accept-loop `select!` (shared by 0-RTT and full-handshake
/// connections) must carry the arm exactly once, and it must stay after the
/// shutdown arm so `biased;` ordering keeps process shutdown first.
#[test]
fn accept_loop_select_observes_keepalive_pressure_after_shutdown() {
    let src = compact(server_src());
    let shutdown_arm = "_=shutdown_rx.changed(),if!h3_goaway_sent";
    let pressure_arm = "h3_keepalive_pressure_raised(&mutkeepalive_pressure_rx),if!h3_goaway_sent";
    let shutdown = src
        .match_indices(shutdown_arm)
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    let pressure = src
        .match_indices(pressure_arm)
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    assert_eq!(
        shutdown.len(),
        1,
        "the single accept-loop select must have exactly one shutdown arm"
    );
    assert_eq!(
        pressure.len(),
        1,
        "the single accept-loop select must observe the keepalive tier exactly once"
    );
    assert!(
        shutdown[0] < pressure[0],
        "the shutdown arm must precede the pressure arm under `biased;`"
    );
}

// ---------------------------------------------------------------------------
// Issue #4537 — the request-header arrival deadline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn header_arrival_deadline_elapses_and_drops_the_resolver() {
    let (drop_tx, drop_rx) = tokio::sync::oneshot::channel::<()>();
    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }
    let sentinel = DropSignal(Some(drop_tx));
    let never = async move {
        let _held = sentinel;
        std::future::pending::<u8>().await
    };

    let resolved = ferrum_edge::http3::server::await_h3_request_headers(never, 1).await;
    assert!(
        resolved.is_none(),
        "a stream that never sends HEADERS must elapse"
    );
    assert!(
        drop_rx.await.is_ok(),
        "the elapsed resolver must be dropped — the drop is what reclaims the QUIC stream slot"
    );
}

#[tokio::test]
async fn header_arrival_deadline_passes_a_resolved_request_through() {
    let resolved =
        ferrum_edge::http3::server::await_h3_request_headers(std::future::ready(7u8), 30).await;
    assert_eq!(resolved, Some(7u8));
}

#[tokio::test]
async fn zero_disables_the_header_arrival_deadline() {
    // Opt-out parity with hyper's `header_read_timeout` and the H2
    // `wait_pre_request_deadline`: `0` must never resolve on its own.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(150),
            ferrum_edge::http3::server::await_h3_request_headers(std::future::pending::<u8>(), 0),
        )
        .await
        .is_err(),
        "FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0 must disable the H3 bound"
    );
    // …while still passing a completed resolution straight through.
    assert_eq!(
        ferrum_edge::http3::server::await_h3_request_headers(std::future::ready(3u8), 0).await,
        Some(3u8)
    );
}

#[test]
fn h3_header_arrival_elapse_logs_at_debug_and_never_unwraps() {
    let src = server_src();
    let no_ws: String = src.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        no_ws.contains(
            "letSome(resolved)=await_h3_request_headers(resolver.resolve_request(),header_deadline_seconds,)"
        ),
        "the per-stream resolve must be bounded by the hoisted deadline (issue #4537)"
    );
    let spawn = src
        .split("let Some(resolved) = await_h3_request_headers(")
        .nth(1)
        .expect("the per-stream resolve must be bounded (issue #4537)")
        .split("Ok((req, stream)) =>")
        .next()
        .expect("bounded resolve arm");
    assert!(
        spawn.contains("debug!("),
        "an unauthenticated peer must not drive warn/error logging one stream at a time"
    );
    assert!(
        !spawn.contains("warn!(") && !spawn.contains("error!("),
        "the elapse arm must not raise log severity: {spawn}"
    );
    assert!(
        !spawn.contains(".unwrap()") && !spawn.contains(".expect("),
        "no unwrap/expect on the H3 accept path: {spawn}"
    );
    assert!(
        src.contains(
            "let header_deadline_seconds = state.env_config.http_header_read_timeout_seconds;"
        ),
        "the deadline must be hoisted once per connection, not read per stream"
    );
}
