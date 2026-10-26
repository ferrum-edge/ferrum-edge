//! Exercise admission timing and settlement through the real dispatch ladders.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::_test_support::{
    adaptive_concurrency_snapshots_for_test, prepend_proxy_plugin_for_test,
};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::file::{ServeHandles, ServeOptions};
use ferrum_edge::plugins::{
    BackendAdmissionContext, BackendAdmissionDecision, BackendAdmissionOutcome,
    BackendAdmissionPermit, HTTP_FAMILY_PROTOCOLS, Plugin, ProxyProtocol, RequestContext,
    TransactionSummary,
};
use ferrum_edge::proxy::ProxyState;
use http::StatusCode;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::scaffolding::backends::{H2Step, MatchHeaders, ScriptedH2Backend};
use crate::scaffolding::clients::{Http3Client, WebSocketOptions};
use crate::scaffolding::{reserve_colocated_tcp_udp, reserve_port};

const WAIT: Duration = Duration::from_secs(15);

struct DispatchGateway {
    http_port: u16,
    https_port: u16,
    state: ProxyState,
    shutdown: ferrum_edge::overload::ShutdownSender,
    handles: Option<ServeHandles>,
}

impl DispatchGateway {
    async fn start(config: GatewayConfig, probe: Option<Arc<dyn Plugin>>) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reserve_port().await.expect("HTTP reservation");
        let (https, udp) = reserve_colocated_tcp_udp()
            .await
            .expect("HTTPS/H3 reservation");
        let http_port = http.port;
        let https_port = https.port;
        let env = EnvConfig {
            mode: OperatingMode::File,
            proxy_http_port: http_port,
            proxy_https_port: https_port,
            admin_http_port: 0,
            admin_https_port: 0,
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            enable_http3: true,
            pool_warmup_enabled: false,
            shutdown_drain_seconds: 0,
            max_connections: 0,
            ..EnvConfig::default()
        };
        let options = ServeOptions {
            proxy_http: Some(http.into_listener()),
            proxy_https: Some(https.into_listener()),
            skip_initial_capability_refresh: true,
            ..ServeOptions::default()
        };
        drop(udp);
        let (shutdown, _) = ferrum_edge::overload::ShutdownSender::channel(Duration::ZERO);
        let handles =
            ferrum_edge::modes::file::serve(env, config.clone(), options, shutdown.clone())
                .await
                .expect("in-process dispatch gateway");
        let state = handles.proxy_state.clone();
        if let Some(probe) = probe {
            prepend_proxy_plugin_for_test(&state.plugin_cache, "default", "dispatch", probe)
                .expect("inject dispatch observer");
            state
                .request_epoch
                .republish_from_runtime_parts_for_test(
                    config,
                    &state.plugin_cache,
                    &state.consumer_index,
                    &state.load_balancer_cache,
                )
                .expect("publish the observer before sending traffic");
        }
        Self {
            http_port,
            https_port,
            state,
            shutdown,
            handles: Some(handles),
        }
    }

    async fn shutdown(mut self) {
        self.shutdown.shutdown();
        tokio::time::timeout(WAIT, self.handles.take().expect("handles").join())
            .await
            .expect("gateway shutdown deadline")
            .expect("gateway tasks");
    }
}

impl Drop for DispatchGateway {
    fn drop(&mut self) {
        self.shutdown.shutdown();
        if let Some(handles) = self.handles.take() {
            tokio::spawn(async move {
                let _ = handles.join().await;
            });
        }
    }
}

fn config(backend_port: u16, adaptive: bool) -> GatewayConfig {
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "dispatch", "namespace": "default", "listen_path": "/",
            "backend_scheme": "http", "backend_host": "127.0.0.1",
            "backend_port": backend_port, "websocket_permessage_deflate": "terminate"
        }],
        "consumers": [], "upstreams": [],
        "plugin_configs": if adaptive { json!([{
            "id": "adaptive-dispatch", "namespace": "default",
            "plugin_name": "adaptive_concurrency", "enabled": true, "scope": "global",
            "config": { "min_limit": 1, "initial_limit": 8, "max_limit": 8,
                        "min_samples": 1, "decrease_ratio": 0.5 }
        }]) } else { json!([]) }
    }))
    .expect("dispatch config")
}

struct AdmissionProbe {
    live: Arc<AtomicUsize>,
    outcomes: mpsc::UnboundedSender<BackendAdmissionOutcome>,
    summaries: mpsc::UnboundedSender<f64>,
}

struct ProbePermit {
    live: Arc<AtomicUsize>,
    outcomes: mpsc::UnboundedSender<BackendAdmissionOutcome>,
}

impl BackendAdmissionPermit for ProbePermit {
    fn record_backend_outcome(&self, outcome: BackendAdmissionOutcome) {
        self.outcomes.send(outcome).expect("outcome receiver");
    }
}

impl Drop for ProbePermit {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Plugin for AdmissionProbe {
    fn name(&self) -> &str {
        "dispatch_probe"
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        HTTP_FAMILY_PROTOCOLS
    }

    fn is_backend_admission_plugin(&self) -> bool {
        true
    }

    fn try_backend_admission(
        &self,
        _ctx: &RequestContext,
        admission: &BackendAdmissionContext<'_>,
    ) -> BackendAdmissionDecision {
        assert_eq!(admission.protocol, ProxyProtocol::Grpc);
        self.live.fetch_add(1, Ordering::SeqCst);
        BackendAdmissionDecision::Admit(Arc::new(ProbePermit {
            live: Arc::clone(&self.live),
            outcomes: self.outcomes.clone(),
        }))
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.summaries
            .send(summary.latency_backend_ttfb_ms)
            .expect("summary receiver");
    }
}

/// Headers reach the client while the backend is held at a barrier. Settlement
/// waits for terminal trailers, but must use exactly the TTFB capture the
/// dispatcher logs. This catches re-reading the clock at any later settlement.
#[tokio::test]
async fn h3_grpc_bridge_records_captured_latency_only_after_terminal_trailers() {
    for buffered_request in [false, true] {
        let listener = reserve_port().await.expect("H2 backend reservation");
        let backend_port = listener.port;
        let backend = ScriptedH2Backend::builder_plain(listener.into_listener())
            .steps([
                H2Step::ExpectHeaders(MatchHeaders::path("/grpc.Service/Call")),
                H2Step::DrainRequestBody,
                H2Step::RespondHeaders(vec![
                    (":status", "200".to_string()),
                    ("content-type", "application/grpc".to_string()),
                ]),
                H2Step::AwaitTestSignal,
                H2Step::RespondData {
                    data: Bytes::from_static(b"\0\0\0\0\x01x"),
                    end_stream: false,
                },
                H2Step::RespondTrailers(vec![("grpc-status", "0".to_string())]),
            ])
            .spawn()
            .expect("gated H2 backend");
        let (outcome_tx, mut outcomes) = mpsc::unbounded_channel();
        let (summary_tx, mut summaries) = mpsc::unbounded_channel();
        let live = Arc::new(AtomicUsize::new(0));
        let probe = Arc::new(AdmissionProbe {
            live: Arc::clone(&live),
            outcomes: outcome_tx,
            summaries: summary_tx,
        });
        let mut config = config(backend_port, false);
        if buffered_request {
            config.proxies[0].retry = Some(ferrum_edge::config::types::RetryConfig::default());
        }
        let gateway = DispatchGateway::start(config, Some(probe)).await;
        let client = Http3Client::insecure().expect("H3 client");
        let mut stream = client
            .open_grpc_stream(&format!(
                "https://localhost:{}/grpc.Service/Call",
                gateway.https_port
            ))
            .await
            .expect("open gRPC stream");
        stream.send_message(b"request").await.expect("request DATA");
        stream.finish().await.expect("request FIN");
        let (status, _) = stream
            .recv_response()
            .await
            .expect("early response headers");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(live.load(Ordering::SeqCst), 1, "body must hold the permit");
        assert!(matches!(
            outcomes.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        backend.release_test_signal();
        let (body, trailers) = stream
            .recv_body_and_trailers()
            .await
            .expect("response terminal");
        assert_eq!(body.as_ref(), b"\0\0\0\0\x01x");
        assert_eq!(trailers.get("grpc-status").expect("status trailer"), "0");
        let outcome = tokio::time::timeout(WAIT, outcomes.recv())
            .await
            .expect("settlement deadline")
            .expect("settlement");
        let ttfb_ms = tokio::time::timeout(WAIT, summaries.recv())
            .await
            .expect("summary deadline")
            .expect("summary");
        assert_eq!(outcome.response_status, 200);
        assert!(!outcome.connection_error);
        assert!(outcome.error_class.is_none());
        assert_eq!(outcome.backend_elapsed.as_secs_f64() * 1000.0, ttfb_ms);
        assert_eq!(
            live.load(Ordering::SeqCst),
            0,
            "terminal releases the permit"
        );
        assert!(matches!(
            outcomes.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(backend.matcher_mismatches(), 0);
        gateway.shutdown().await;
    }
}

/// A valid 101 with an invalid RFC 7692 answer must reach extension validation,
/// then settle the real limiter as a backend fault before returning its 502.
#[tokio::test]
async fn websocket_invalid_deflate_answer_backs_off_admission_on_h1_h2_and_h3() {
    let listener = reserve_port().await.expect("WebSocket backend reservation");
    let backend_port = listener.port;
    let listener = listener.into_listener();
    let backend = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0];
                while !head.ends_with(b"\r\n\r\n") {
                    stream
                        .read_exact(&mut byte)
                        .await
                        .expect("backend request head");
                    head.push(byte[0]);
                    assert!(head.len() <= 16 * 1024);
                }
                let head = String::from_utf8(head).expect("request text");
                let key = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("sec-websocket-key")
                            .then_some(value.trim())
                    })
                    .expect("backend WebSocket key");
                let accept =
                    tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
                stream.write_all(format!(
                    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=7\r\n\r\n"
                ).as_bytes()).await.expect("invalid extension answer");
                let _ = stream.read(&mut byte).await;
            });
        }
    });
    let gateway = DispatchGateway::start(config(backend_port, true), None).await;
    let client = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("H1 client");
    let response = client
        .get(format!("http://127.0.0.1:{}/ws", gateway.http_port))
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .send()
        .await
        .expect("H1 rejection");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(
        response
            .text()
            .await
            .expect("H1 body")
            .contains("Backend WebSocket extension negotiation failed")
    );
    assert_adaptive_limit(&gateway.state, 4).await;

    let socket = tokio::net::TcpStream::connect(("127.0.0.1", gateway.http_port))
        .await
        .expect("H2 connect");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(socket))
            .await
            .expect("H2 handshake");
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method("CONNECT")
        .version(http::Version::HTTP_2)
        .uri(format!("http://127.0.0.1:{}/ws", gateway.http_port))
        .header("sec-websocket-version", "13")
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())
        .expect("Extended CONNECT");
    let response = sender.send_request(request).await.expect("H2 rejection");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("H2 body")
        .to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("Backend WebSocket extension negotiation failed")
    );
    assert_adaptive_limit(&gateway.state, 2).await;
    connection.abort();

    let client = Http3Client::insecure().expect("H3 client");
    let mut response = client
        .websocket(
            &format!("https://localhost:{}/ws", gateway.https_port),
            WebSocketOptions::default(),
        )
        .await
        .expect("H3 rejection");
    assert_eq!(response.status, StatusCode::BAD_GATEWAY);
    assert!(
        response
            .recv_body_text()
            .await
            .expect("H3 body")
            .contains("Backend WebSocket extension negotiation failed")
    );
    assert_adaptive_limit(&gateway.state, 1).await;
    gateway.shutdown().await;
    backend.abort();
}

async fn assert_adaptive_limit(state: &ProxyState, expected: u64) {
    tokio::time::timeout(WAIT, async {
        loop {
            let snapshots = adaptive_concurrency_snapshots_for_test(state);
            if let [target] = snapshots.as_slice() {
                assert_eq!(
                    target.limit, expected,
                    "backend protocol fault must halve the limit"
                );
                if target.in_flight == 0 {
                    break;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("admission release");
}
