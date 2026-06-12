use ferrum_edge::_test_support::{
    connect_websocket_backend_for_test, connect_websocket_backend_with_subprotocol_for_test,
};
use ferrum_edge::config::types::Proxy;
use serde_json::json;

#[tokio::test]
async fn connect_websocket_backend_sets_tcp_nodelay() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");

    let server = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = tokio_tungstenite::accept_async(stream).await;
        }
    });

    let proxy: Proxy = serde_json::from_value(json!({
        "backend_host": addr.ip().to_string(),
        "backend_port": addr.port(),
        "backend_scheme": "http",
        "backend_connect_timeout_ms": 2000u64,
    }))
    .expect("proxy deserialize");

    let url = format!("ws://{addr}/");
    let ws_stream = connect_websocket_backend_for_test(&url, &proxy)
        .await
        .expect("backend connect succeeds");

    match ws_stream.get_ref() {
        tokio_tungstenite::MaybeTlsStream::Plain(io) => {
            let tcp = io.get_ref();
            assert!(
                tcp.nodelay().expect("nodelay getsockopt"),
                "backend WS TcpStream must have TCP_NODELAY set"
            );
            assert!(
                socket2::SockRef::from(tcp)
                    .keepalive()
                    .expect("keepalive getsockopt"),
                "backend WS TcpStream must have TCP keepalive set"
            );
        }
        _ => panic!("expected plain TCP backend"),
    }

    drop(ws_stream);
    let _ = server.await;
}

// ============================================================================
// Negotiated subprotocol capture (RFC 6455 §11.3.4 / RFC 8441 §5.2 / RFC 9220)
//
// `connect_websocket_backend` must surface the backend's selected
// `Sec-WebSocket-Protocol` so the H1/H2 and H3 frontends can forward it to
// the client. Dropping it (the pre-fix behaviour) breaks subprotocol-based
// application dispatch — the client offers a list, the backend picks one,
// and the gateway hid the choice from the client.
// ============================================================================

/// Accept a single WebSocket connection with a tungstenite response callback
/// that selects the first offered subprotocol. Returns the picked value so
/// the caller can assert the gateway forwarded the same one.
async fn spawn_subprotocol_echo_server(
    listener: tokio::net::TcpListener,
    pick: &'static str,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            #[allow(clippy::result_large_err)]
            let callback =
                |_req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                 mut resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    resp.headers_mut().insert(
                        hyper::header::SEC_WEBSOCKET_PROTOCOL,
                        hyper::header::HeaderValue::from_static(pick),
                    );
                    Ok(resp)
                };
            let _ = tokio_tungstenite::accept_hdr_async(stream, callback).await;
        }
    })
}

#[tokio::test]
async fn connect_websocket_backend_captures_negotiated_subprotocol() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");

    let server = spawn_subprotocol_echo_server(listener, "mqtt").await;

    let proxy: Proxy = serde_json::from_value(json!({
        "backend_host": addr.ip().to_string(),
        "backend_port": addr.port(),
        "backend_scheme": "http",
        "backend_connect_timeout_ms": 2000u64,
    }))
    .expect("proxy deserialize");

    let url = format!("ws://{addr}/");
    let (ws_stream, negotiated) =
        connect_websocket_backend_with_subprotocol_for_test(&url, &proxy, &["mqtt", "wamp"])
            .await
            .expect("backend connect succeeds");

    assert_eq!(
        negotiated.as_deref(),
        Some("mqtt"),
        "BackendWsHandshake.negotiated_subprotocol must surface the backend's \
         Sec-WebSocket-Protocol so the frontend can forward it on the upgrade \
         response (RFC 6455 §11.3.4)"
    );

    drop(ws_stream);
    let _ = server.await;
}

#[tokio::test]
async fn connect_websocket_backend_subprotocol_none_when_backend_omits() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");

    // Default accept_async — never sets Sec-WebSocket-Protocol on the response.
    let server = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = tokio_tungstenite::accept_async(stream).await;
        }
    });

    let proxy: Proxy = serde_json::from_value(json!({
        "backend_host": addr.ip().to_string(),
        "backend_port": addr.port(),
        "backend_scheme": "http",
        "backend_connect_timeout_ms": 2000u64,
    }))
    .expect("proxy deserialize");

    let url = format!("ws://{addr}/");
    let (ws_stream, negotiated) =
        connect_websocket_backend_with_subprotocol_for_test(&url, &proxy, &[])
            .await
            .expect("backend connect succeeds");

    assert!(
        negotiated.is_none(),
        "Without a backend-supplied Sec-WebSocket-Protocol, the handshake \
         struct must report `None` so the frontend does not forward an \
         empty / fabricated subprotocol header"
    );

    drop(ws_stream);
    let _ = server.await;
}
