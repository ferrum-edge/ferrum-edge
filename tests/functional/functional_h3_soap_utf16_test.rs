//! End-to-end HTTP/3 coverage for UTF-16 SOAP WS-Security decoding.

use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, StatusCode};
use serde_json::json;

use crate::scaffolding::backends::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;

fn encode_utf16_le(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn encode_utf16_be(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xFE, 0xFF];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    bytes
}

fn username_token_envelope() -> String {
    r#"<?xml version="1.0" encoding="UTF-16"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
 <soap:Header><wsse:Security><wsse:UsernameToken>
  <wsse:Username>testuser</wsse:Username>
  <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">testpass</wsse:Password>
 </wsse:UsernameToken></wsse:Security></soap:Header>
 <soap:Body><GetData xmlns="http://example.com"><id>123</id></GetData></soap:Body>
</soap:Envelope>"#
        .to_string()
}

fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("h3-soap-utf16-gateway").expect("gateway CA");
    let (cert, key) = ca.valid().expect("gateway leaf");
    let cert_path = scratch.join("gateway.cert.pem");
    let key_path = scratch.join("gateway.key.pem");
    std::fs::write(&cert_path, cert).expect("write gateway cert");
    std::fs::write(&key_path, key).expect("write gateway key");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

async fn spawn_gateway(backend_port: u16) -> (GatewayHarness, u16, tempfile::TempDir) {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h3-soap-utf16",
            "listen_path": "/soap",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "response_body_mode": "buffer",
            "plugins": [{"plugin_config_id": "soap-utf16-security"}]
        }],
        "upstreams": [],
        "plugin_configs": [{
            "id": "soap-utf16-security",
            "plugin_name": "soap_ws_security",
            "scope": "proxy",
            "proxy_id": "h3-soap-utf16",
            "enabled": true,
            "config": {
                "username_token": {
                    "enabled": true,
                    "password_type": "PasswordText",
                    "credentials": [{"username": "testuser", "password": "testpass"}]
                },
                "timestamp": {"require": false}
            }
        }]
    });
    let yaml = serde_yaml::to_string(&config).expect("serialize config");
    let mut last_error = String::new();
    for _ in 0..5 {
        let reservation = reserve_port().await.expect("reserve H3 port");
        let https_port = reservation.port;
        drop(reservation);
        let scratch = tempfile::tempdir().expect("gateway scratch dir");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());
        match GatewayHarness::builder()
            .file_config(yaml.clone())
            .log_level("warn")
            .capture_output()
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await
        {
            Ok(gateway) => return (gateway, https_port, scratch),
            Err(error) => last_error = error.to_string(),
        }
    }
    panic!("failed to spawn H3 SOAP gateway: {last_error}");
}

async fn request_with_retry(client: &Http3Client, url: &str, options: GetOptions) -> Http3Response {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match client.get_with_options(url, options.clone()).await {
            Ok(response) => return response,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            Err(error) => panic!("H3 SOAP request never completed: {error}"),
        }
    }
}

#[tokio::test]
#[ignore]
async fn h3_soap_encodings_validate_and_hostile_metadata_fails_closed() {
    let backend_reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = backend_reservation.port;
    let _backend = ScriptedHttp1Backend::builder(backend_reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
            "POST", "/service",
        )))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".to_string(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".to_string(),
            value: "2".to_string(),
        })
        .step(HttpStep::RespondBodyChunk(b"ok".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
            "POST", "/service",
        )))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".to_string(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".to_string(),
            value: "2".to_string(),
        })
        .step(HttpStep::RespondBodyChunk(b"ok".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
            "POST", "/service",
        )))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".to_string(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".to_string(),
            value: "2".to_string(),
        })
        .step(HttpStep::RespondBodyChunk(b"ok".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn HTTP backend");

    let (_gateway, https_port, _scratch) = spawn_gateway(backend_port).await;
    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://127.0.0.1:{https_port}/soap/service");
    let body = encode_utf16_le(&username_token_envelope());

    let accepted = request_with_retry(
        &client,
        &url,
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/soap+xml; charset=utf-16")
            .body(Bytes::copy_from_slice(&body)),
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK);
    assert_eq!(accepted.body_bytes.as_ref(), b"ok");

    let accepted_be = request_with_retry(
        &client,
        &url,
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "text/xml; charset=utf-16be")
            .body(Bytes::from(encode_utf16_be(&username_token_envelope()))),
    )
    .await;
    assert_eq!(accepted_be.status, StatusCode::OK);
    assert_eq!(accepted_be.body_bytes.as_ref(), b"ok");

    let utf8 = username_token_envelope().replace("encoding=\"UTF-16\"", "encoding=\"UTF-8\"");
    let accepted_utf8 = request_with_retry(
        &client,
        &url,
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/soap+xml; charset=utf-8")
            .body(Bytes::from(utf8)),
    )
    .await;
    assert_eq!(accepted_utf8.status, StatusCode::OK);
    assert_eq!(accepted_utf8.body_bytes.as_ref(), b"ok");

    let conflict = request_with_retry(
        &client,
        &url,
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "text/xml; charset=utf-8")
            .body(Bytes::from(body)),
    )
    .await;
    assert_eq!(conflict.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(String::from_utf8_lossy(&conflict.body_bytes).contains("conflicting"));

    let malformed = request_with_retry(
        &client,
        &url,
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "text/xml; charset=utf-16")
            .body(Bytes::from_static(&[0xFF, 0xFE, 0x3C])),
    )
    .await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&malformed.body_bytes).contains("not valid"));
}
