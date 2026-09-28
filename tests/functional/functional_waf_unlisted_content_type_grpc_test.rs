//! `waf` `on_unlisted_content_type` end to end on native gRPC.
//!
//! `application/grpc` is outside the default WAF scan scope, and every gRPC
//! call carries a non-empty body (each message has a 5-byte frame header). So
//! `block`, and `fail_closed` wherever an enforcing request-body policy
//! applies, must refuse the RPC before it reaches the backend, and the client
//! must see the rejection as `PERMISSION_DENIED`. Listing `application/grpc`
//! in `body_content_types` scans the call instead, and a clean one is
//! forwarded.
//!
//! Run with:
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests waf_unlisted_content_type_grpc -- --ignored --nocapture
//! ```

use crate::scaffolding::backends::{GrpcStep, MatchRpc, ScriptedGrpcBackend};
use crate::scaffolding::clients::GrpcClient;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use serde_json::{Value, json};

const RPC_PATH: &str = "/helloworld.Greeter/SayHello";
const BACKEND_OK_MSG: &[u8] = b"backend-ok-payload";
/// gRPC `PERMISSION_DENIED`, the mapping of the WAF's default `403`.
const PERMISSION_DENIED: u32 = 7;

fn proxy(id: &str, backend_port: u16) -> Value {
    json!({
        "id": id,
        "listen_path": format!("/{id}"),
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "backend_connect_timeout_ms": 2000,
        "backend_read_timeout_ms": 5000,
        "backend_write_timeout_ms": 5000,
        "plugins": [{ "plugin_config_id": format!("{id}-waf") }],
    })
}

fn waf_plugin(id: &str, config: Value) -> Value {
    json!({
        "id": format!("{id}-waf"),
        "plugin_name": "waf",
        "scope": "proxy",
        "proxy_id": id,
        "enabled": true,
        "config": config,
    })
}

fn file_config(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [
            proxy("blocked", backend_port),
            proxy("failclosed", backend_port),
            proxy("listed", backend_port),
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            waf_plugin("blocked", json!({
                "mode": "enforce",
                "default_rule_action": "enforce",
                "on_unlisted_content_type": "block",
            })),
            waf_plugin("failclosed", json!({
                "mode": "enforce",
                "default_rule_action": "enforce",
                "on_unlisted_content_type": "fail_closed",
            })),
            waf_plugin("listed", json!({
                "mode": "enforce",
                "default_rule_action": "enforce",
                "on_unlisted_content_type": "block",
                "body_content_types": ["application/json", "application/grpc"],
            })),
        ],
    });
    serde_yaml::to_string(&config).expect("serialize yaml")
}

fn gateway_http_port(harness: &GatewayHarness) -> u16 {
    harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .expect("gateway http port")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_unlisted_content_type_is_refused_unless_listed() {
    let reservation = reserve_port().await.expect("reserve backend");
    let backend_port = reservation.port;
    // One scripted RPC: only the listed route may reach the backend.
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::method(RPC_PATH)))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(BACKEND_OK_MSG)))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "OK",
        })
        .spawn()
        .expect("spawn backend");

    // In-process with warmup off skips the startup capability probe, whose h2c
    // connection would otherwise run the one-shot backend script and break
    // the stream-count and matcher assertions below.
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(file_config(backend_port))
        .log_level("warn")
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let client = GrpcClient::h2c(format!("127.0.0.1:{}", gateway_http_port(&harness)));

    for route in ["blocked", "failclosed"] {
        let response = client
            .unary(&format!("/{route}{RPC_PATH}"), Bytes::from_static(b"ping"))
            .await
            .expect("unary rpc");
        assert_eq!(
            response.effective_grpc_status(),
            PERMISSION_DENIED,
            "{route}: an unlisted gRPC body must be refused; got {response:?}"
        );
        assert!(
            response.messages.is_empty(),
            "{route}: a refused RPC carries no backend message"
        );
        assert_eq!(
            backend.received_stream_count(),
            0,
            "{route}: a refused RPC must not reach the backend"
        );
    }

    let response = client
        .unary(&format!("/listed{RPC_PATH}"), Bytes::from_static(b"ping"))
        .await
        .expect("unary rpc");
    assert_eq!(
        response.grpc_status(),
        Some(0),
        "a listed gRPC body is scanned and forwarded; got {response:?}"
    );
    assert_eq!(
        response.messages.as_slice(),
        &[Bytes::from_static(BACKEND_OK_MSG)]
    );
    assert_eq!(backend.received_stream_count(), 1);
    backend.assert_no_matcher_mismatches().await;
}
