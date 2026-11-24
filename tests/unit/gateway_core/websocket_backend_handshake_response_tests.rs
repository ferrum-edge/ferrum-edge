//! Backend WebSocket handshake responses (issues #7391 / #7392,
//! GHSA-7x2j-3389-2h35) and backend response header obs-text
//! (GHSA-j26x-88q2-wq5m).
//!
//! * A successful backend `101` keeps its end-to-end headers (`Set-Cookie`
//!   included) for the client handshake response, with hop-by-hop,
//!   `Connection`-listed and gateway-owned diagnostic names stripped.
//! * `preserve_host_header` sends the validated client Host on a direct dial;
//!   an invalid Host falls back to the backend authority.
//! * A backend's own `3xx`-`5xx` refusal of the upgrade is typed, with its
//!   status, headers and complete body, so the bridges relay it instead of a
//!   synthetic `502`. A `2xx` non-`101` answer is not a refusal.
//! * Every backend-response collector keeps UTF-8 obs-text byte for byte and
//!   counts what it must drop.

use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::_test_support::{
    collect_backend_response_headers_for_test, collect_buffered_grpc_trailers_for_test,
    collect_h3_backend_response_headers_for_test,
    collect_h3_bridge_backend_response_headers_for_test,
    connect_websocket_backend_headers_for_test, websocket_backend_refusal_for_test,
    websocket_backend_refusal_response_for_test, websocket_preserved_backend_host_for_test,
};
use ferrum_edge::config::types::Proxy;
use ferrum_edge::plugins::Plugin;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// What the backend answers once it has read the upgrade request head.
enum BackendAnswer {
    /// A valid `101` carrying these extra header lines.
    Upgrade(&'static str),
    /// These raw response bytes, written in one call.
    Raw(Vec<u8>),
}

/// A one-shot raw backend: reads the upgrade request head, reports the `Host`
/// it carried, then answers. The socket is held open until the client closes,
/// so the handshake result never depends on an early EOF.
async fn spawn_backend(
    answer: BackendAnswer,
) -> (
    std::net::SocketAddr,
    oneshot::Receiver<String>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let (host_tx, host_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let Ok(read) = stream.read(&mut buf).await else {
                return;
            };
            if read == 0 {
                return;
            }
            head.extend_from_slice(&buf[..read]);
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        let header = |name: &str| {
            head.lines()
                .find_map(|line| {
                    let (field, value) = line.split_once(':')?;
                    field
                        .trim()
                        .eq_ignore_ascii_case(name)
                        .then(|| value.trim().to_string())
                })
                .unwrap_or_default()
        };
        let _ = host_tx.send(header("host"));
        let response = match answer {
            BackendAnswer::Upgrade(extra) => {
                let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(
                    header("sec-websocket-key").as_bytes(),
                );
                format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                     Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{extra}\r\n"
                )
                .into_bytes()
            }
            BackendAnswer::Raw(bytes) => bytes,
        };
        if stream.write_all(&response).await.is_err() {
            return;
        }
        let _ = stream.read(&mut buf).await;
    });
    (addr, host_rx, task)
}

fn direct_proxy(addr: std::net::SocketAddr) -> Proxy {
    serde_json::from_value(json!({
        "backend_host": addr.ip().to_string(),
        "backend_port": addr.port(),
        "backend_scheme": "http",
        "backend_connect_timeout_ms": 2000u64,
    }))
    .expect("proxy deserialize")
}

#[tokio::test]
async fn successful_upgrade_keeps_backend_end_to_end_headers() {
    let (addr, _host, server) = spawn_backend(BackendAnswer::Upgrade(
        "Set-Cookie: sid=abc; Path=/\r\nSet-Cookie: theme=dark\r\nX-Backend-Upgrade: yes\r\n\
         X-Gateway-Error: forged\r\nKeep-Alive: timeout=5\r\n",
    ))
    .await;

    let headers = connect_websocket_backend_headers_for_test(
        &format!("ws://{addr}/chat"),
        &direct_proxy(addr),
        None,
    )
    .await
    .expect("backend upgrade succeeds");

    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some("sid=abc; Path=/\ntheme=dark"),
        "every backend Set-Cookie on the 101 must survive as its own line"
    );
    assert_eq!(
        headers.get("x-backend-upgrade").map(String::as_str),
        Some("yes")
    );
    for stripped in ["x-gateway-error", "keep-alive", "connection", "upgrade"] {
        assert!(
            !headers.contains_key(stripped),
            "{stripped} must not cross the backend handshake boundary: {headers:?}"
        );
    }
    server.abort();
}

#[tokio::test]
async fn direct_dial_sends_preserved_client_host_and_defaults_to_backend_authority() {
    let (addr, host, server) = spawn_backend(BackendAnswer::Upgrade("")).await;
    connect_websocket_backend_headers_for_test(
        &format!("ws://{addr}/chat"),
        &direct_proxy(addr),
        Some("tenant.example.com:8443"),
    )
    .await
    .expect("backend upgrade succeeds");
    assert_eq!(
        host.await.expect("backend saw the request"),
        "tenant.example.com:8443",
        "preserve_host_header must reach the direct WebSocket backend handshake"
    );
    server.abort();

    let (addr, host, server) = spawn_backend(BackendAnswer::Upgrade("")).await;
    connect_websocket_backend_headers_for_test(
        &format!("ws://{addr}/chat"),
        &direct_proxy(addr),
        None,
    )
    .await
    .expect("backend upgrade succeeds");
    assert_eq!(
        host.await.expect("backend saw the request"),
        addr.to_string(),
        "without preserve_host_header the backend authority stays the Host"
    );
    server.abort();
}

#[test]
fn preserved_websocket_host_uses_the_http_path_validation() {
    assert_eq!(
        websocket_preserved_backend_host_for_test(true, Some("tenant.example.com:8443")).as_deref(),
        Some("tenant.example.com:8443")
    );
    assert_eq!(
        websocket_preserved_backend_host_for_test(true, Some("  [::1]:9443 ")).as_deref(),
        Some("[::1]:9443")
    );
    assert_eq!(
        websocket_preserved_backend_host_for_test(false, Some("tenant.example.com")),
        None,
        "preserve_host_header off keeps the backend authority"
    );
    for invalid in [
        "user@tenant.example.com",
        "::1",
        "",
        "tenant.example.com:99999",
    ] {
        assert_eq!(
            websocket_preserved_backend_host_for_test(true, Some(invalid)),
            None,
            "an invalid client Host {invalid:?} must fall back to the backend authority"
        );
    }
    assert_eq!(websocket_preserved_backend_host_for_test(true, None), None);
}

const REFUSAL_BODY: &str = r#"{"error":"backend-auth"}"#;

fn refusal_bytes(status_line: &str, extra: &str, body: &str, declared_len: usize) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status_line}\r\n{extra}Content-Length: {declared_len}\r\n\
         X-Gateway-Error: forged\r\nConnection: close\r\n\r\n{body}"
    )
    .into_bytes()
}

#[tokio::test]
async fn backend_refusal_is_relayed_with_its_status_headers_and_body() {
    let (addr, _host, server) = spawn_backend(BackendAnswer::Raw(refusal_bytes(
        "401 Unauthorized",
        "WWW-Authenticate: Bearer realm=\"ws\"\r\nContent-Type: application/json\r\n",
        REFUSAL_BODY,
        REFUSAL_BODY.len(),
    )))
    .await;

    let error = connect_websocket_backend_headers_for_test(
        &format!("ws://{addr}/chat"),
        &direct_proxy(addr),
        None,
    )
    .await
    .expect_err("a 401 is not an upgrade");
    let (status, headers, body) =
        websocket_backend_refusal_for_test(error.as_ref()).expect("a 401 is a backend refusal");
    assert_eq!(status, 401);
    assert_eq!(
        headers.get("www-authenticate").map(String::as_str),
        Some("Bearer realm=\"ws\"")
    );
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert!(!headers.contains_key("x-gateway-error"));
    assert!(!headers.contains_key("connection"));
    assert_eq!(body.as_ref(), REFUSAL_BODY.as_bytes());

    let plugins: Vec<Arc<dyn Plugin>> = Vec::new();
    let response = websocket_backend_refusal_response_for_test(error.as_ref(), &plugins)
        .expect("refusal response");
    assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    let wire = response.headers();
    assert_eq!(
        wire.get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer realm=\"ws\"")
    );
    assert_eq!(
        wire.get("content-length")
            .and_then(|value| value.to_str().ok()),
        Some(REFUSAL_BODY.len().to_string().as_str())
    );
    assert!(
        wire.get("x-gateway-error").is_none(),
        "a relayed backend answer carries no gateway error token"
    );
    server.abort();
}

#[tokio::test]
async fn incomplete_refusal_body_relays_status_without_its_representation() {
    // Declares more body than it sends: the relay keeps the status and the
    // challenge but cannot claim a representation it does not have.
    let (addr, _host, server) = spawn_backend(BackendAnswer::Raw(refusal_bytes(
        "429 Too Many Requests",
        "Retry-After: 7\r\nContent-Type: application/json\r\n",
        "{\"err",
        4096,
    )))
    .await;
    let error = connect_websocket_backend_headers_for_test(
        &format!("ws://{addr}/chat"),
        &direct_proxy(addr),
        None,
    )
    .await
    .expect_err("a 429 is not an upgrade");
    let (status, headers, body) =
        websocket_backend_refusal_for_test(error.as_ref()).expect("a 429 is a backend refusal");
    assert_eq!(status, 429);
    assert_eq!(headers.get("retry-after").map(String::as_str), Some("7"));
    assert!(!headers.contains_key("content-type"));
    assert!(body.is_empty());
    server.abort();
}

#[tokio::test]
async fn success_status_other_than_101_is_not_a_relayable_refusal() {
    // Relaying a 2xx would tell an Extended CONNECT client its tunnel is open.
    let (addr, _host, server) =
        spawn_backend(BackendAnswer::Raw(refusal_bytes("200 OK", "", "", 0))).await;
    let error = connect_websocket_backend_headers_for_test(
        &format!("ws://{addr}/chat"),
        &direct_proxy(addr),
        None,
    )
    .await
    .expect_err("a 200 is not an upgrade");
    assert!(websocket_backend_refusal_for_test(error.as_ref()).is_none());
    server.abort();
}

#[test]
fn backend_response_collectors_keep_utf8_obs_text_and_count_drops() {
    let filename = "attachment; filename=\"résumé.pdf\"";
    let cookie = "pref=café; Path=/";
    let mut source = http::HeaderMap::new();
    source.insert(
        "content-disposition",
        http::HeaderValue::from_bytes(filename.as_bytes()).expect("UTF-8 obs-text value"),
    );
    source.append("set-cookie", http::HeaderValue::from_static("sid=abc"));
    source.append(
        "set-cookie",
        http::HeaderValue::from_bytes(cookie.as_bytes()).expect("UTF-8 obs-text value"),
    );
    // ISO-8859-1 `é`: valid obs-text on the wire, not representable as UTF-8.
    source.insert(
        "x-latin1",
        http::HeaderValue::from_bytes(b"caf\xe9").expect("Latin-1 obs-text value"),
    );

    let bridge_response = {
        let mut builder = http::Response::builder().status(200);
        for (name, value) in &source {
            builder = builder.header(name, value);
        }
        reqwest::Response::from(builder.body("ok").expect("bridge response"))
    };

    let before = ferrum_edge::proxy::backend_response_non_utf8_field_drops_total();
    let collected: [(&str, HashMap<String, String>); 3] = [
        (
            "H1/H2 reqwest and direct hyper",
            collect_backend_response_headers_for_test(&source),
        ),
        (
            "native HTTP/3",
            collect_h3_backend_response_headers_for_test(&source),
        ),
        (
            "HTTP/3 bridge",
            collect_h3_bridge_backend_response_headers_for_test(&bridge_response),
        ),
    ];
    for (path, headers) in &collected {
        assert_eq!(
            headers.get("content-disposition").map(String::as_str),
            Some(filename),
            "{path}: a UTF-8 Content-Disposition must be forwarded byte for byte"
        );
        assert_eq!(
            headers.get("set-cookie").map(String::as_str),
            Some(format!("sid=abc\n{cookie}").as_str()),
            "{path}: every Set-Cookie line must survive"
        );
        assert!(
            !headers.contains_key("x-latin1"),
            "{path}: a non-UTF-8 value cannot be carried"
        );

        // The downstream builder emits the exact backend bytes.
        let response = ferrum_edge::proxy::headers::apply_response_headers(
            http::Response::builder().status(200),
            headers,
        )
        .body(())
        .expect("client response");
        assert_eq!(
            response
                .headers()
                .get("content-disposition")
                .map(http::HeaderValue::as_bytes),
            Some(filename.as_bytes()),
            "{path}: client response bytes"
        );
        let cookies: Vec<&[u8]> = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(http::HeaderValue::as_bytes)
            .collect();
        assert_eq!(cookies, [b"sid=abc".as_slice(), cookie.as_bytes()]);
    }

    let mut trailers = http::HeaderMap::new();
    trailers.insert(
        "x-app-detail",
        http::HeaderValue::from_bytes("détail".as_bytes()).expect("UTF-8 trailer"),
    );
    trailers.insert(
        "x-latin1",
        http::HeaderValue::from_bytes(b"caf\xe9").expect("Latin-1 trailer"),
    );
    let collected_trailers = collect_buffered_grpc_trailers_for_test(&trailers);
    assert_eq!(
        collected_trailers.get("x-app-detail").map(String::as_str),
        Some("détail")
    );
    assert!(!collected_trailers.contains_key("x-latin1"));

    // Three header collectors plus the trailer collector each dropped one
    // Latin-1 value. Other tests may run concurrently, so this is a floor.
    assert!(
        ferrum_edge::proxy::backend_response_non_utf8_field_drops_total() >= before + 4,
        "every non-UTF-8 drop must be counted"
    );
}

/// Drop full-line `//` comments and all whitespace so source-shape checks
/// survive rustfmt reflows and explanatory comments inside a block.
fn squeeze(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(str::chars)
        .filter(|ch| !ch.is_whitespace())
        .collect()
}

/// Every WebSocket backend transport that can carry a backend's refusal of the
/// upgrade must feed the ONE shared relay (GHSA-7x2j-3389-2h35): the H1 upgrade
/// transports (direct TCP/TLS, Unix socket, inner HBONE handshake) through
/// tungstenite's `Error::Http`, and the Sidecar mesh-mTLS Extended CONNECT
/// through `HbonePoolError::WebSocketUpgradeRefused`. Both frontends' failure
/// tails must consult that relay and charge the breaker by the backend status.
#[test]
fn every_websocket_transport_refusal_feeds_the_shared_relay() {
    let proxy = squeeze(include_str!("../../../src/proxy/mod.rs"));
    let relay = proxy
        .find("pub(crate)fnwebsocket_backend_refusal(")
        .expect("shared refusal extractor");
    let relay_body = &proxy[relay..relay + 1200];
    assert!(
        relay_body.contains("tokio_tungstenite::tungstenite::Error::Http(response)"),
        "the H1 upgrade transports' refusal must reach the relay"
    );
    assert!(
        relay_body.contains("HbonePoolError::WebSocketUpgradeRefused{refusal,..}"),
        "the Sidecar mesh-mTLS Extended CONNECT refusal must reach the relay"
    );

    let hbone = squeeze(include_str!("../../../src/proxy/hbone_pool.rs"));
    let head = hbone
        .find("asyncfnopen_h2_ws_connect_stream_head(")
        .expect("Sidecar WebSocket Extended CONNECT head opener");
    let head_body = &hbone[head..];
    let refused = head_body
        .find("returnOk(WsConnectHead::Refused{")
        .expect("the opener must hand back a 3xx-5xx refusal head");
    let rejected = head_body
        .find("returnErr(HbonePoolError::ConnectRejected{")
        .expect("other non-200 answers stay ConnectRejected");
    assert!(
        refused < rejected,
        "the refusal must be carried before the ConnectRejected fallback"
    );
    let finish = hbone
        .find("asyncfnfinish_ws_connect_head(")
        .expect("refusal finisher");
    let finish_body = &hbone[finish..finish + 1500];
    assert!(finish_body.contains("WebSocketBackendRefusal::from_response_parts("));
    assert!(finish_body.contains("Err(HbonePoolError::WebSocketUpgradeRefused{"));
    // The production deadline bounds the response head only, so an in-time
    // refusal head is never erased by its optional body read.
    let within = hbone
        .find("asyncfnopen_h2_ws_connect_stream_within(")
        .expect("timed Extended CONNECT opener");
    let within_body = &hbone[within..within + 1500];
    let timed_head = within_body
        .find("tokio::time::timeout(head_timeout,open_h2_ws_connect_stream_head(")
        .expect("the head deadline wraps only the head opener");
    let finished = within_body
        .find("finish_ws_connect_head(head).await")
        .expect("the refusal is finished after the head deadline");
    assert!(timed_head < finished);
    let mesh_mtls = squeeze(include_str!("../../../src/proxy/mesh_mtls_pool.rs"));
    assert!(
        mesh_mtls.contains("open_h2_ws_connect_stream_within(Duration::from_millis(proxy.backend_connect_timeout_ms),"),
        "the Sidecar WebSocket dial must use the head-bounded opener"
    );

    let h3 = squeeze(include_str!("../../../src/http3/websocket.rs"));
    for (label, source, extractor, breaker_path) in [
        (
            "H1/H2",
            proxy.as_str(),
            "websocket_backend_refusal(e.as_ref())",
            "backend_dispatch::",
        ),
        (
            "H3",
            h3.as_str(),
            "crate::proxy::websocket_backend_refusal(e.as_ref())",
            "crate::proxy::backend_dispatch::",
        ),
    ] {
        let at = source
            .find(extractor)
            .unwrap_or_else(|| panic!("{label}: failure tail must consult the shared relay"));
        let tail = &source[at..];
        // The breaker block itself (not the earlier refusal log branch) must
        // open with the refusal arm settling by the backend's status, ahead of
        // the egress-denied and failure arms.
        let breaker = tail
            .find("if!cb_failure_already_recorded&&letSome(cb)=cb_probe.current_breaker(")
            .unwrap_or_else(|| panic!("{label}: terminal breaker settlement block"));
        let block = &tail[breaker..breaker + 1500];
        let refusal_arm = block
            .find(&format!(
                "{{ifws_backend_refusal.is_some(){{{breaker_path}apply_circuit_breaker_outcome(&cb,ws_failure_status.as_u16(),false,None,"
            ))
            .unwrap_or_else(|| panic!("{label}: the breaker block must open with the refusal arm"));
        let egress_arm = block
            .find("}elseifws_egress_denied{")
            .unwrap_or_else(|| panic!("{label}: egress-denied arm"));
        assert!(
            refusal_arm < egress_arm,
            "{label}: a refusal must settle by status before any failure arm"
        );
    }

    // The H3 refusal writer is polled inside `handle_h3_request`'s stack
    // budget: box a trampoline so its future is built in the heap block.
    assert!(
        h3.contains("Box::pin(async{send_h3_backend_refusal("),
        "H3: box the refusal writer through a trampoline, not Box::pin(writer(..))"
    );
}
