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
    assert_eq!(
        src.matches("ConnectionGuard::new").count(),
        1,
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
