//! HTTP Agent Card partial-representation refusal through the live gateway.

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use serde_json::{Value, json};
use std::time::Duration;

use crate::scaffolding::backends::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
use crate::scaffolding::clients::{Http1Client, Http2Client};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;

pub(super) const MULTIPART_TYPE: &str = "multipart/byteranges; boundary=card-parts";
pub(super) const CARD_PATH: &str = "/.well-known/agent-card.json";

/// Two disjoint ranges omit only a space between JSON fields. Concatenating
/// their payloads therefore reconstructs a card advertising the backend URL.
pub(super) fn multipart_card_body() -> Bytes {
    let card = r#"{"name":"planner", "url":"https://planner.internal/a2a"}"#;
    let gap = card.find(" \"url\"").expect("card field separator");
    Bytes::from(format!(
        "--card-parts\r\nContent-Type: application/json\r\nContent-Range: bytes 0-{}/{}\r\n\r\n{}\r\n\
         --card-parts\r\nContent-Type: application/json\r\nContent-Range: bytes {}-{}/{}\r\n\r\n{}\r\n\
         --card-parts--\r\n",
        gap - 1,
        card.len(),
        &card[..gap],
        gap + 1,
        card.len() - 1,
        card.len(),
        &card[gap + 1..],
    ))
}

pub(super) fn card_gateway_config(backend_port: u16, rewrite: bool) -> Value {
    json!({
        "version": "1",
        "proxies": [{
            "id": "a2a-http-card",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": [{"plugin_config_id": "a2a-card"}]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "a2a-card",
            "proxy_id": "a2a-http-card",
            "plugin_name": "a2a_gateway",
            "scope": "proxy",
            "enabled": true,
            "config": {
                "discovery": {
                    "public_base_url": "https://gateway.example.com",
                    "rewrite_agent_card_urls": rewrite
                }
            }
        }]
    })
}

pub(super) fn assert_partial_card_refused(status: StatusCode, headers: &HeaderMap, body: &[u8]) {
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(headers["content-type"], "application/json");
    assert!(!headers.contains_key("content-range"));
    assert!(!headers.contains_key("etag"));
    let error = String::from_utf8_lossy(body);
    assert!(!error.contains("planner.internal"), "{error}");
    assert!(!error.contains("card-parts"), "{error}");
    assert!(serde_json::from_slice::<Value>(body).is_ok());
}

#[tokio::test]
#[ignore]
async fn multipart_partial_agent_card_is_refused_on_http1_and_http2() {
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;
    let body = multipart_card_body();
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 206,
            reason: "Partial Content".to_string(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Type".to_string(),
            value: MULTIPART_TYPE.to_string(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".to_string(),
            value: body.len().to_string(),
        })
        .step(HttpStep::RespondHeader {
            name: "ETag".to_string(),
            value: "\"card-v1\"".to_string(),
        })
        .step(HttpStep::RespondBodyChunk(body.to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("multipart backend");
    let clients = [
        (
            Http1Client::insecure()
                .expect("HTTP/1 client")
                .as_reqwest()
                .clone(),
            reqwest::Version::HTTP_11,
        ),
        (
            Http2Client::h2c_prior_knowledge()
                .expect("HTTP/2 client")
                .as_reqwest()
                .clone(),
            reqwest::Version::HTTP_2,
        ),
    ];
    for rewrite in [true, false] {
        let config = serde_yaml::to_string(&card_gateway_config(backend_port, rewrite))
            .expect("config YAML");
        let gateway = GatewayHarness::builder()
            .file_config(config)
            .log_level("warn")
            .pool_warmup_enabled(false)
            .spawn()
            .await
            .expect("card gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(5))
            .await
            .expect("proxy ready");
        for (client, version) in &clients {
            let response = client
                .get(gateway.proxy_url(CARD_PATH))
                .header("range", "bytes=0-17,19-")
                .send()
                .await
                .expect("card response");
            assert_eq!(response.version(), *version);
            let status = response.status();
            let headers = response.headers().clone();
            let received = response.bytes().await.expect("card body");
            if rewrite {
                assert_partial_card_refused(status, &headers, &received);
            } else {
                assert_eq!(status, StatusCode::PARTIAL_CONTENT);
                assert_eq!(received, body);
                assert_eq!(headers["content-type"], MULTIPART_TYPE);
            }
        }
    }
    assert!(
        backend
            .received_requests()
            .await
            .iter()
            .any(|request| request.path == CARD_PATH)
    );
}
