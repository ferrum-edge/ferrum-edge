//! Comprehensive Functional Tests for Authentication, ACL, and Multi-Auth
//!
//! This test verifies end-to-end authentication and authorization flows:
//! - Key Auth: API key in header and query param
//! - Basic Auth: username:password with HMAC-SHA256 password hashes
//! - JWT Auth: HS256-signed tokens with consumer-specific secrets
//! - HMAC Auth: HMAC-signed requests with replay protection
//! - Access Control (ACL): Consumer allow/deny lists
//! - Multi-Auth mode: First-success-wins across multiple auth plugins
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_auth_acl

use crate::scaffolding::port_registry::TestSocket;

use crate::common::{
    TestGateway, content_digest_sha256_header, empty_digest_header, generate_hmac_signature,
    generate_hmac_signature_with_digest, hmac_authority_from_url,
};

use base64::Engine;
use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(super) fn create_rs256_token(claims: &serde_json::Value, private_key_pem: &[u8]) -> String {
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(private_key_pem).expect("Failed to parse RSA private key"),
    )
    .expect("Failed to encode RS256 token")
}

pub(super) fn build_rsa_jwks_from_pem(public_key_pem: &[u8]) -> serde_json::Value {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let pem_str = std::str::from_utf8(public_key_pem).expect("Invalid public key PEM");
    let der = extract_der_from_pem(pem_str);
    let (n, e) = parse_rsa_public_key_der(&der);

    json!({
        "keys": [{
            "kty": "RSA",
            "kid": "test-key-1",
            "use": "sig",
            "alg": "RS256",
            "n": URL_SAFE_NO_PAD.encode(&n),
            "e": URL_SAFE_NO_PAD.encode(&e)
        }]
    })
}

fn extract_der_from_pem(pem: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;

    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(&b64).expect("Invalid PEM base64")
}

fn parse_rsa_public_key_der(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut pos = 0;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (_outer_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (algo_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    pos += algo_len;
    assert_eq!(der[pos], 0x03);
    pos += 1;
    let (_bs_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    pos += 1;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (_inner_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (n_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    let mut n = der[pos..pos + n_len].to_vec();
    pos += n_len;
    if !n.is_empty() && n[0] == 0 {
        n.remove(0);
    }
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (e_len, consumed) = parse_asn1_length(&der[pos..]);
    pos += consumed;
    let e = der[pos..pos + e_len].to_vec();
    (n, e)
}

fn parse_asn1_length(data: &[u8]) -> (usize, usize) {
    if data[0] < 0x80 {
        (data[0] as usize, 1)
    } else {
        let num_bytes = (data[0] & 0x7f) as usize;
        let mut length = 0usize;
        for &byte in &data[1..=num_bytes] {
            length = (length << 8) | byte as usize;
        }
        (length, 1 + num_bytes)
    }
}

async fn start_jwks_server(
    public_key_pem: &[u8],
) -> Result<(tokio::task::JoinHandle<()>, String), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0").await?;
    let jwks_url = format!(
        "http://127.0.0.1:{}/.well-known/jwks.json",
        listener.local_addr()?.port()
    );
    let jwks_json = build_rsa_jwks_from_pem(public_key_pem).to_string();

    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let jwks_json = jwks_json.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
                let (reader, mut writer) = socket.into_split();
                let mut buf_reader = tokio::io::BufReader::new(reader);
                let mut request_line = String::new();
                if buf_reader.read_line(&mut request_line).await.is_err() {
                    return;
                }

                loop {
                    let mut line = String::new();
                    if buf_reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }

                let (status_line, body) = if request_line.starts_with("GET /.well-known/jwks.json ")
                {
                    ("HTTP/1.1 200 OK", jwks_json)
                } else {
                    (
                        "HTTP/1.1 404 Not Found",
                        r#"{"error":"not found"}"#.to_string(),
                    )
                };

                let response = format!(
                    "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status_line,
                    body.len(),
                    body
                );
                let _ = writer.write_all(response.as_bytes()).await;
            });
        }
    });

    Ok((handle, jwks_url))
}

/// Test harness for auth/ACL functional testing
struct AuthTestHarness {
    _gw: TestGateway,
    proxy_base_url: String,
    admin_base_url: String,
}

impl AuthTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let gw = TestGateway::builder()
            .jwt_secret("test-admin-jwt-secret-key-1234567890")
            .jwt_issuer("ferrum-edge-auth-test")
            .basic_auth_hmac_secret("test-hmac-server-secret-0123456789abcdef")
            .log_level("info")
            .spawn()
            .await?;

        Ok(Self {
            proxy_base_url: gw.proxy_base_url.clone(),
            admin_base_url: gw.admin_base_url.clone(),
            _gw: gw,
        })
    }

    fn generate_admin_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(self._gw.admin_token())
    }
}

fn content_digest_sha256(body: &[u8]) -> String {
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body))
    )
}

fn hmac_authorization_for_digest(
    method: &str,
    path: &str,
    date: &str,
    authority: &str,
    digest: &str,
) -> String {
    let signature = generate_hmac_signature_with_digest(
        method,
        path,
        date,
        "alice",
        authority,
        "alice-hmac-shared-secret-at-least-32-bytes",
        digest,
    );
    format!(r#"hmac username="alice", algorithm="hmac-sha256", signature="{signature}""#)
}

async fn send_raw_h1_hmac_request(
    proxy_port: u16,
    method: &str,
    digest: &str,
    framing_headers: &str,
    wire_body: &[u8],
) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let authority = format!("127.0.0.1:{proxy_port}");
    let date = Utc::now().to_rfc2822();
    let authorization =
        hmac_authorization_for_digest(method, "/hmacauth", &date, &authority, digest);
    let request = format!(
        "{method} /hmacauth HTTP/1.1\r\nHost: {authority}\r\nAuthorization: {authorization}\r\nDate: {date}\r\nContent-Digest: {digest}\r\n{framing_headers}Connection: close\r\n\r\n"
    );

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect raw H1 HMAC request");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write raw H1 HMAC headers");
    stream
        .write_all(wire_body)
        .await
        .expect("write raw H1 HMAC body");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read raw H1 HMAC response");
    let response = String::from_utf8_lossy(&response);
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .expect("raw H1 HMAC response status")
}

async fn send_declared_oversized_invalid_h1_hmac_request(
    proxy_port: u16,
    date: &str,
    username: &str,
    signing_secret: &str,
) -> (u16, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let authority = format!("127.0.0.1:{proxy_port}");
    let digest = empty_digest_header();
    let signature = generate_hmac_signature(
        "POST",
        "/hmacauth",
        date,
        username,
        &authority,
        signing_secret,
    );
    let authorization =
        format!(r#"hmac username="{username}", algorithm="hmac-sha256", signature="{signature}""#);
    let request = format!(
        "POST /hmacauth HTTP/1.1\r\nHost: {authority}\r\nAuthorization: {authorization}\r\nDate: {date}\r\nDigest: {digest}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        10 * 1024 * 1024 + 1
    );

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect declared-oversized HMAC request");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write declared-oversized HMAC headers");

    // An invalid credential must be rejected from headers alone. Sending the
    // advertised body would race the early response and can surface a client-
    // side BrokenPipe even when the gateway behaves correctly.
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("timed out waiting for early HMAC rejection")
        .expect("read early HMAC rejection");

    let header_end = response
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
        .expect("raw H1 HMAC response headers");
    let status = String::from_utf8_lossy(&response[..header_end])
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .expect("raw H1 HMAC response status");
    (status, response[header_end + 4..].to_vec())
}

async fn send_h2_hmac_request(
    proxy_port: u16,
    method: &str,
    digest: &str,
    content_length: Option<&str>,
    body_after_headers: Option<&[u8]>,
) -> u16 {
    let authority = format!("127.0.0.1:{proxy_port}");
    let date = Utc::now().to_rfc2822();
    let authorization =
        hmac_authorization_for_digest(method, "/hmacauth", &date, &authority, digest);
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect H2 HMAC request");
    let _ = stream.set_nodelay(true);
    let (mut sender, connection) = h2::client::handshake(stream)
        .await
        .expect("H2 HMAC handshake");
    let connection_task = tokio::spawn(connection);
    let mut request = hyper::Request::builder()
        .method(method)
        .uri(format!("http://{authority}/hmacauth"))
        .header("authorization", authorization)
        .header("date", date)
        .header("content-digest", digest);
    if let Some(content_length) = content_length {
        request = request.header("content-length", content_length);
    }
    let request = request.body(()).expect("build H2 HMAC request");
    let end_stream_on_headers = body_after_headers.is_none();
    let (response, mut request_body) = sender
        .send_request(request, end_stream_on_headers)
        .expect("send H2 HMAC headers");
    if let Some(body) = body_after_headers {
        request_body
            .send_data(bytes::Bytes::copy_from_slice(body), true)
            .expect("send H2 HMAC DATA");
    }
    let response = response.await.expect("receive H2 HMAC response");
    let status = response.status().as_u16();
    // HEAD may legally advertise the corresponding GET payload length while
    // sending no DATA. The low-level h2 client does not apply Hyper's
    // method-aware response-body semantics, so driving its generic body
    // validator can turn that valid response into a local PROTOCOL_ERROR.
    if method != "HEAD" {
        let mut response_body = response.into_body();
        while let Some(data) = response_body.data().await {
            data.expect("read H2 HMAC response DATA");
        }
    }
    drop(sender);
    connection_task.abort();
    status
}

async fn assert_empty_body_hmac_regressions(proxy_port: u16) {
    let empty_digest = content_digest_sha256(&[]);
    let incorrect_empty_digest = content_digest_sha256(b"not empty");

    // In H1, absent framing proves an empty request body for every method.
    // These methods cover the traditional bodyless set, DELETE, and a body
    // method without framing.
    for method in ["GET", "HEAD", "OPTIONS", "DELETE", "POST"] {
        assert_eq!(
            send_raw_h1_hmac_request(proxy_port, method, &empty_digest, "", &[]).await,
            200,
            "H1 {method} without framing should accept the empty-body digest"
        );
        assert_eq!(
            send_raw_h1_hmac_request(proxy_port, method, &incorrect_empty_digest, "", &[]).await,
            401,
            "H1 {method} without framing must reject a signed non-empty digest"
        );
    }

    for (framing_headers, wire_body, label) in [
        ("Content-Length: 0\r\n", &[][..], "Content-Length: 0"),
        (
            "Transfer-Encoding: chunked\r\n",
            &b"0\r\n\r\n"[..],
            "empty chunked body",
        ),
    ] {
        assert_eq!(
            send_raw_h1_hmac_request(
                proxy_port,
                "POST",
                &empty_digest,
                framing_headers,
                wire_body,
            )
            .await,
            200,
            "H1 POST with {label} should accept the empty-body digest"
        );
        assert_eq!(
            send_raw_h1_hmac_request(
                proxy_port,
                "POST",
                &incorrect_empty_digest,
                framing_headers,
                wire_body,
            )
            .await,
            401,
            "H1 POST with {label} must reject a signed non-empty digest"
        );
    }

    // H2 relies on END_STREAM, not method or framing headers. An END_STREAM on
    // the request headers proves emptiness even for body methods.
    for method in ["GET", "HEAD", "OPTIONS", "DELETE", "POST"] {
        assert_eq!(
            send_h2_hmac_request(proxy_port, method, &empty_digest, None, None).await,
            200,
            "H2 {method} with header END_STREAM should accept the empty-body digest"
        );
        assert_eq!(
            send_h2_hmac_request(proxy_port, method, &incorrect_empty_digest, None, None).await,
            401,
            "H2 {method} with header END_STREAM must reject a signed non-empty digest"
        );
    }

    assert_eq!(
        send_h2_hmac_request(proxy_port, "POST", &empty_digest, Some("0"), None).await,
        200,
        "H2 Content-Length: 0 should accept the empty-body digest"
    );
    assert_eq!(
        send_h2_hmac_request(proxy_port, "POST", &incorrect_empty_digest, Some("0"), None,).await,
        401,
        "H2 Content-Length: 0 must reject a signed non-empty digest"
    );

    // Keep the H2 request open at header time, then finish with empty DATA.
    // The proxy must collect through END_STREAM rather than infer emptiness
    // from GET plus absent Content-Length.
    assert_eq!(
        send_h2_hmac_request(proxy_port, "GET", &empty_digest, None, Some(&[])).await,
        200,
        "open H2 GET ending with empty DATA should authenticate"
    );
    assert_eq!(
        send_h2_hmac_request(proxy_port, "GET", &incorrect_empty_digest, None, Some(&[]),).await,
        401,
        "open H2 GET ending with empty DATA must verify the final empty digest"
    );

    let one_byte_digest = content_digest_sha256(b"x");
    assert_eq!(
        send_h2_hmac_request(proxy_port, "GET", &one_byte_digest, None, Some(b"x")).await,
        200,
        "open H2 GET must collect and verify DATA without Content-Length"
    );
    assert_eq!(
        send_h2_hmac_request(proxy_port, "GET", &empty_digest, None, Some(b"x")).await,
        401,
        "open H2 GET must never infer empty while DATA can still arrive"
    );
}

/// Simple echo HTTP server that returns request info.
///
/// Prefer [`start_echo_backend_on`] for new tests so callers can pass a
/// pre-bound listener and avoid the bind-drop-rebind race that triggers
/// intermittent EADDRINUSE under parallel functional runs.
async fn start_echo_backend(
    port: u16,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind_test(format!("127.0.0.1:{}", port)).await?;
    Ok(start_echo_backend_on(listener))
}

/// Like [`start_echo_backend`] but accepts a caller-owned listener so the
/// port stays bound continuously (no drop+rebind window).
fn start_echo_backend_on(listener: tokio::net::TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
                let (reader, mut writer) = socket.into_split();
                let mut buf_reader = tokio::io::BufReader::new(reader);
                let mut line = String::new();

                if buf_reader.read_line(&mut line).await.is_err() {
                    return;
                }

                let mut headers = String::new();
                loop {
                    line.clear();
                    if buf_reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                    headers.push_str(&line);
                }

                let body = r#"{"status":"ok","echo":true}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = writer.write_all(response.as_bytes()).await;
            });
        }
    })
}

/// Shared slot holding the last mutating request body the capturing backend
/// saw, or `None` if it has not seen one yet.
type CapturedBody = Arc<Mutex<Option<Vec<u8>>>>;

/// Capture the last mutating HTTP/1.1 request body. Health probes and
/// `GET`/`HEAD` warmup must not overwrite application POSTs.
fn start_capturing_backend(
    listener: tokio::net::TcpListener,
) -> (tokio::task::JoinHandle<()>, CapturedBody) {
    let captured = Arc::new(Mutex::new(None));
    let captured_for_task = Arc::clone(&captured);
    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let captured = Arc::clone(&captured_for_task);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = Vec::new();
                loop {
                    let mut tmp = [0u8; 1024];
                    let n = match socket.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    let Some(header_end) = buf.windows(4).position(|window| window == b"\r\n\r\n")
                    else {
                        if buf.len() > 64 * 1024 {
                            break;
                        }
                        continue;
                    };
                    // Own everything parsed out of the header before the body
                    // loop below extends `buf`: `header_text` borrows `buf`, and
                    // `method` / `path` borrow `header_text`, so holding either
                    // across `buf.extend_from_slice` is a borrow conflict.
                    let (method, path, content_length) = {
                        let header_text = String::from_utf8_lossy(&buf[..header_end]);
                        let mut lines = header_text.lines();
                        let request_line = lines.next().unwrap_or_default();
                        let mut parts = request_line.split_whitespace();
                        let method = parts.next().unwrap_or("").to_string();
                        let path = parts.next().unwrap_or("/").to_string();
                        let mut content_length = 0usize;
                        for line in header_text.lines().skip(1) {
                            let Some((name, value)) = line.split_once(':') else {
                                continue;
                            };
                            if name.eq_ignore_ascii_case("content-length") {
                                content_length = value.trim().parse().unwrap_or(0);
                            }
                        }
                        (method, path, content_length)
                    };
                    let body_start = header_end + 4;
                    while buf.len() < body_start + content_length {
                        let mut tmp = [0u8; 1024];
                        let n = match socket.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let body_end = (body_start + content_length).min(buf.len());
                    let body = buf[body_start..body_end].to_vec();
                    let mutating = method.eq_ignore_ascii_case("POST")
                        || method.eq_ignore_ascii_case("PUT")
                        || method.eq_ignore_ascii_case("PATCH")
                        || method.eq_ignore_ascii_case("DELETE");
                    if mutating
                        && path != "/health"
                        && let Ok(mut slot) = captured.lock()
                    {
                        *slot = Some(body);
                    }
                    let response_body = r#"{"status":"ok","echo":true}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        response_body.len(),
                        response_body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    break;
                }
            });
        }
    });
    (handle, captured)
}

/// Helper: create a consumer via admin API
async fn create_consumer(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    id: &str,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = json!({
        "id": id,
        "username": username,
        "custom_id": format!("{}-custom", username),
    });
    let resp = client
        .post(format!("{}/consumers", admin_url))
        .header("Authorization", auth_header)
        .json(&data)
        .send()
        .await?;
    assert!(
        resp.status().is_success(),
        "Failed to create consumer {}: {} - {}",
        id,
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
    Ok(())
}

/// Helper: add credentials to a consumer
async fn add_credential(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    consumer_id: &str,
    cred_type: &str,
    cred_data: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let credential_set = serde_json::Value::Array(vec![cred_data.clone()]);
    let resp = client
        .put(format!(
            "{}/consumers/{}/credentials/{}",
            admin_url, consumer_id, cred_type
        ))
        .header("Authorization", auth_header)
        .json(&credential_set)
        .send()
        .await?;
    assert!(
        resp.status().is_success(),
        "Failed to add {} credential to {}: {} - {}",
        cred_type,
        consumer_id,
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
    Ok(())
}

/// Helper: create a proxy via admin API
async fn create_proxy(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    proxy_data: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .post(format!("{}/proxies", admin_url))
        .header("Authorization", auth_header)
        .json(proxy_data)
        .send()
        .await?;
    assert!(
        resp.status().is_success(),
        "Failed to create proxy: {} - {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
    Ok(())
}

/// Helper: create a plugin config via admin API
async fn create_plugin_config(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    plugin_data: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .post(format!("{}/plugins/config", admin_url))
        .header("Authorization", auth_header)
        .json(plugin_data)
        .send()
        .await?;
    assert!(
        resp.status().is_success(),
        "Failed to create plugin config: {} - {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
    Ok(())
}

async fn update_proxy(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    proxy_data: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let proxy_id = proxy_data["id"].as_str().unwrap_or("<missing-id>");
    let resp = client
        .put(format!("{}/proxies/{}", admin_url, proxy_id))
        .header("Authorization", auth_header)
        .json(proxy_data)
        .send()
        .await?;
    assert!(
        resp.status().is_success(),
        "Failed to update proxy {}: {} - {}",
        proxy_id,
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
    Ok(())
}

/// Generate a consumer JWT token signed with the consumer's secret
fn generate_consumer_jwt(consumer_username: &str, secret: &str, exp_offset_secs: i64) -> String {
    let now = Utc::now();
    let claims = json!({
        "sub": consumer_username,
        "iat": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(exp_offset_secs)).timestamp(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());
    encode(&header, &claims, &key).expect("Failed to encode JWT")
}

#[tokio::test]
#[ignore]
async fn test_access_control_allows_jwks_authenticated_identity_when_enabled() {
    let harness = AuthTestHarness::new()
        .await
        .expect("Failed to create test harness");

    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port)
        .await
        .expect("Failed to start echo backend");

    let client = reqwest::Client::new();
    let admin_token = harness
        .generate_admin_token()
        .expect("Failed to generate admin token");
    let auth_header = format!("Bearer {}", admin_token);
    let admin_url = &harness.admin_base_url;
    let proxy_url = &harness.proxy_base_url;

    let private_key_pem = include_bytes!("../fixtures/test_rsa_private.pem");
    let public_key_pem = include_bytes!("../fixtures/test_rsa_public.pem");
    let (_jwks_server, jwks_uri) = start_jwks_server(public_key_pem)
        .await
        .expect("Failed to start JWKS server");

    for (id, path) in [
        ("proxy-jwks-acl-external-allow", "/jwks-acl-external-allow"),
        ("proxy-jwks-acl-external-deny", "/jwks-acl-external-deny"),
    ] {
        create_proxy(
            &client,
            admin_url,
            &auth_header,
            &json!({
                "id": id,
                "listen_path": path,
                "backend_scheme": "http",
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "auth_mode": "single",
            }),
        )
        .await
        .unwrap();
    }

    for plugin in [
        json!({
            "id": "plugin-jwks-acl-external-allow",
            "plugin_name": "jwks_auth",
            "scope": "proxy",
            "proxy_id": "proxy-jwks-acl-external-allow",
            "enabled": true,
            "config": {
                "providers": [{
                    "jwks_uri": jwks_uri,
                    "required_scopes": ["gateway:access"]
                }]
            }
        }),
        json!({
            "id": "plugin-acl-external-allow",
            "plugin_name": "access_control",
            "scope": "proxy",
            "proxy_id": "proxy-jwks-acl-external-allow",
            "enabled": true,
            // `allow_authenticated_identity` admits the unmapped external identity.
            // It cannot be combined with an allow-list (`allowed_consumers`), which
            // is rejected at config validation, so this config uses the flag alone.
            "config": {
                "allow_authenticated_identity": true
            }
        }),
        json!({
            "id": "plugin-jwks-acl-external-deny",
            "plugin_name": "jwks_auth",
            "scope": "proxy",
            "proxy_id": "proxy-jwks-acl-external-deny",
            "enabled": true,
            "config": {
                "providers": [{
                    "jwks_uri": jwks_uri,
                    "required_scopes": ["gateway:access"]
                }]
            }
        }),
        json!({
            "id": "plugin-acl-external-deny",
            "plugin_name": "access_control",
            "scope": "proxy",
            "proxy_id": "proxy-jwks-acl-external-deny",
            "enabled": true,
            "config": {
                "allowed_consumers": ["alice"]
            }
        }),
    ] {
        create_plugin_config(&client, admin_url, &auth_header, &plugin)
            .await
            .unwrap();
    }

    update_proxy(
        &client,
        admin_url,
        &auth_header,
        &json!({
            "id": "proxy-jwks-acl-external-allow",
            "listen_path": "/jwks-acl-external-allow",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "auth_mode": "single",
            "plugins": [
                {"plugin_config_id": "plugin-jwks-acl-external-allow"},
                {"plugin_config_id": "plugin-acl-external-allow"}
            ]
        }),
    )
    .await
    .unwrap();

    update_proxy(
        &client,
        admin_url,
        &auth_header,
        &json!({
            "id": "proxy-jwks-acl-external-deny",
            "listen_path": "/jwks-acl-external-deny",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "auth_mode": "single",
            "plugins": [
                {"plugin_config_id": "plugin-jwks-acl-external-deny"},
                {"plugin_config_id": "plugin-acl-external-deny"}
            ]
        }),
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_secs(4)).await;

    let now = Utc::now();
    let token = create_rs256_token(
        &json!({
            "sub": "oidc-user-123",
            "scope": "gateway:access",
            "iat": now.timestamp(),
            "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        }),
        private_key_pem,
    );

    let allowed = client
        .get(format!("{}/jwks-acl-external-allow", proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Allowed external identity request failed");
    assert_eq!(
        allowed.status().as_u16(),
        200,
        "access_control should permit authenticated_identity when enabled"
    );

    let denied = client
        .get(format!("{}/jwks-acl-external-deny", proxy_url))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Denied external identity request failed");
    assert_eq!(
        denied.status().as_u16(),
        403,
        "an authenticated external identity outside the Consumer allow-list is forbidden"
    );
}

#[tokio::test]
#[ignore]
async fn test_auth_acl_comprehensive() {
    println!("\n=== Starting Auth/ACL Functional Test ===\n");

    // --- Setup ---
    let harness = AuthTestHarness::new()
        .await
        .expect("Failed to create test harness");

    // Start echo backend
    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port)
        .await
        .expect("Failed to start echo backend");

    let client = reqwest::Client::new();
    let admin_token = harness
        .generate_admin_token()
        .expect("Failed to generate admin token");
    let auth_header = format!("Bearer {}", admin_token);
    let admin_url = &harness.admin_base_url;
    let proxy_url = &harness.proxy_base_url;

    // ==========================================
    // Create consumers with various credentials
    // ==========================================

    println!("\n--- Setup: Creating Consumers ---");

    // Consumer: alice (key_auth + jwt + basic_auth + hmac_auth — multi-credential consumer)
    create_consumer(&client, admin_url, &auth_header, "consumer-alice", "alice")
        .await
        .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-alice",
        "keyauth",
        &json!({"key": "alice-api-key-secret-12345"}),
    )
    .await
    .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-alice",
        "jwt",
        &json!({"secret": "alice-jwt-secret-key-9991234567890"}),
    )
    .await
    .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-alice",
        "basicauth",
        &json!({"password": "alice-password-123"}),
    )
    .await
    .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-alice",
        "hmac_auth",
        &json!({"secret": "alice-hmac-shared-secret-at-least-32-bytes"}),
    )
    .await
    .unwrap();

    // Consumer: bob (key_auth only — limited credentials)
    create_consumer(&client, admin_url, &auth_header, "consumer-bob", "bob")
        .await
        .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-bob",
        "keyauth",
        &json!({"key": "bob-api-key-unique-67890"}),
    )
    .await
    .unwrap();

    // Consumer: charlie (jwt only — for ACL deny list testing)
    create_consumer(
        &client,
        admin_url,
        &auth_header,
        "consumer-charlie",
        "charlie",
    )
    .await
    .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-charlie",
        "keyauth",
        &json!({"key": "charlie-api-key-blocked-11111"}),
    )
    .await
    .unwrap();

    println!(
        "✓ Consumers created: alice (keyauth+jwt+basic+hmac), bob (keyauth), charlie (keyauth)"
    );

    // ==========================================
    // Create proxies with various auth configs
    // ==========================================

    println!("\n--- Setup: Creating Proxies and Plugin Configs ---");

    // Step 1: Create all proxies first (without plugins)
    // Step 2: Create plugin configs (with proxy_id referencing existing proxies)
    // Step 3: Update proxies to add plugin references (populates junction table)
    //
    // This avoids the FK chicken-and-egg: proxy_plugins junction needs both
    // proxy and plugin_config to exist, and plugin_configs.proxy_id references proxies.

    // Create bare proxies
    for (id, path, auth_mode) in [
        ("proxy-keyauth", "/keyauth", "single"),
        ("proxy-basicauth", "/basicauth", "single"),
        ("proxy-jwtauth", "/jwtauth", "single"),
        ("proxy-hmacauth", "/hmacauth", "single"),
        ("proxy-keyauth-acl-allow", "/keyauth-acl-allow", "single"),
        ("proxy-keyauth-acl-deny", "/keyauth-acl-deny", "single"),
        ("proxy-multiauth", "/multiauth", "multi"),
        ("proxy-keyauth-query", "/keyauth-query", "single"),
        ("proxy-multiauth-acl", "/multiauth-acl", "multi"),
    ] {
        create_proxy(
            &client,
            admin_url,
            &auth_header,
            &json!({
                "id": id,
                "listen_path": path,
                "backend_scheme": "http",
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "auth_mode": auth_mode,
            }),
        )
        .await
        .unwrap();
    }

    // Create all plugin configs (with proxy_id FK)
    let plugin_configs = vec![
        json!({
            "id": "plugin-keyauth",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "proxy-keyauth",
            "enabled": true,
            "config": {"key_location": "header:X-API-Key"}
        }),
        json!({
            "id": "plugin-basicauth",
            "plugin_name": "basic_auth",
            "scope": "proxy",
            "proxy_id": "proxy-basicauth",
            "enabled": true,
            "config": {}
        }),
        json!({
            "id": "plugin-jwtauth",
            "plugin_name": "jwt_auth",
            "scope": "proxy",
            "proxy_id": "proxy-jwtauth",
            "enabled": true,
            "config": {
                "token_lookup": "header:Authorization",
                "consumer_claim_field": "sub"
            }
        }),
        json!({
            "id": "plugin-hmacauth",
            "plugin_name": "hmac_auth",
            "scope": "proxy",
            "proxy_id": "proxy-hmacauth",
            "enabled": true,
            "config": {
                "clock_skew_seconds": 300,
                "signing_profile": "ferrum-hmac-v1",
                "allow_unsafe_replayable_v1": true
            }
        }),
        json!({
            "id": "plugin-keyauth-acl-allow",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "proxy-keyauth-acl-allow",
            "enabled": true,
            "config": {"key_location": "header:X-API-Key"}
        }),
        json!({
            "id": "plugin-acl-allow",
            "plugin_name": "access_control",
            "scope": "proxy",
            "proxy_id": "proxy-keyauth-acl-allow",
            "enabled": true,
            "config": {
                "allowed_consumers": ["alice", "bob"]
            }
        }),
        json!({
            "id": "plugin-keyauth-acl-deny",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "proxy-keyauth-acl-deny",
            "enabled": true,
            "config": {"key_location": "header:X-API-Key"}
        }),
        json!({
            "id": "plugin-acl-deny",
            "plugin_name": "access_control",
            "scope": "proxy",
            "proxy_id": "proxy-keyauth-acl-deny",
            "enabled": true,
            "config": {
                "disallowed_consumers": ["charlie"]
            }
        }),
        json!({
            "id": "plugin-multiauth-jwt",
            "plugin_name": "jwt_auth",
            "scope": "proxy",
            "proxy_id": "proxy-multiauth",
            "enabled": true,
            "config": {
                "token_lookup": "header:Authorization",
                "consumer_claim_field": "sub"
            }
        }),
        json!({
            "id": "plugin-multiauth-key",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "proxy-multiauth",
            "enabled": true,
            "config": {"key_location": "header:X-API-Key"}
        }),
        json!({
            "id": "plugin-keyauth-query",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "proxy-keyauth-query",
            "enabled": true,
            "config": {"key_location": "query:apikey"}
        }),
        json!({
            "id": "plugin-multiauth-acl-jwt",
            "plugin_name": "jwt_auth",
            "scope": "proxy",
            "proxy_id": "proxy-multiauth-acl",
            "enabled": true,
            "config": {
                "token_lookup": "header:Authorization",
                "consumer_claim_field": "sub"
            }
        }),
        json!({
            "id": "plugin-multiauth-acl-key",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "proxy-multiauth-acl",
            "enabled": true,
            "config": {"key_location": "header:X-API-Key"}
        }),
        json!({
            "id": "plugin-multiauth-acl",
            "plugin_name": "access_control",
            "scope": "proxy",
            "proxy_id": "proxy-multiauth-acl",
            "enabled": true,
            "config": {
                "allowed_consumers": ["alice"]
            }
        }),
    ];

    for pc in &plugin_configs {
        create_plugin_config(&client, admin_url, &auth_header, pc)
            .await
            .unwrap();
    }

    // Update proxies to add plugin references (populates proxy_plugins junction table)
    let proxy_plugin_map: Vec<(&str, &str, serde_json::Value)> = vec![
        (
            "proxy-keyauth",
            "/keyauth",
            json!([{"plugin_config_id": "plugin-keyauth"}]),
        ),
        (
            "proxy-basicauth",
            "/basicauth",
            json!([{"plugin_config_id": "plugin-basicauth"}]),
        ),
        (
            "proxy-jwtauth",
            "/jwtauth",
            json!([{"plugin_config_id": "plugin-jwtauth"}]),
        ),
        (
            "proxy-hmacauth",
            "/hmacauth",
            json!([{"plugin_config_id": "plugin-hmacauth"}]),
        ),
        (
            "proxy-keyauth-acl-allow",
            "/keyauth-acl-allow",
            json!([
                {"plugin_config_id": "plugin-keyauth-acl-allow"},
                {"plugin_config_id": "plugin-acl-allow"}
            ]),
        ),
        (
            "proxy-keyauth-acl-deny",
            "/keyauth-acl-deny",
            json!([
                {"plugin_config_id": "plugin-keyauth-acl-deny"},
                {"plugin_config_id": "plugin-acl-deny"}
            ]),
        ),
        (
            "proxy-keyauth-query",
            "/keyauth-query",
            json!([{"plugin_config_id": "plugin-keyauth-query"}]),
        ),
    ];

    for (id, path, plugins) in &proxy_plugin_map {
        let resp = client
            .put(format!("{}/proxies/{}", admin_url, id))
            .header("Authorization", &auth_header)
            .json(&json!({
                "id": id,
                "listen_path": path,
                "backend_scheme": "http",
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "plugins": plugins,
            }))
            .send()
            .await
            .expect("Failed to update proxy");
        assert!(
            resp.status().is_success(),
            "Failed to update proxy {}: {} - {}",
            id,
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    // Multi-auth proxies need auth_mode set
    for (id, path, plugins) in [
        (
            "proxy-multiauth",
            "/multiauth",
            json!([
                {"plugin_config_id": "plugin-multiauth-jwt"},
                {"plugin_config_id": "plugin-multiauth-key"}
            ]),
        ),
        (
            "proxy-multiauth-acl",
            "/multiauth-acl",
            json!([
                {"plugin_config_id": "plugin-multiauth-acl-jwt"},
                {"plugin_config_id": "plugin-multiauth-acl-key"},
                {"plugin_config_id": "plugin-multiauth-acl"}
            ]),
        ),
    ] {
        let resp = client
            .put(format!("{}/proxies/{}", admin_url, id))
            .header("Authorization", &auth_header)
            .json(&json!({
                "id": id,
                "listen_path": path,
                "backend_scheme": "http",
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "auth_mode": "multi",
                "plugins": plugins,
            }))
            .send()
            .await
            .expect("Failed to update proxy");
        assert!(
            resp.status().is_success(),
            "Failed to update proxy {}: {} - {}",
            id,
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    println!("✓ All proxies and plugin configs created");

    // Wait for DB poll to pick up all config
    println!("\nWaiting for config to be loaded from database...");
    tokio::time::sleep(Duration::from_secs(4)).await;

    // ==========================================
    // KEY AUTH TESTS
    // ==========================================

    println!("\n=== KEY AUTH TESTS ===");

    // Test 1: Key Auth — valid API key in header
    println!("\n--- Test 1: Key Auth — Valid API Key (header) ---");
    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .header("X-API-Key", "alice-api-key-secret-12345")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Key auth with valid key should succeed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["echo"].as_bool().unwrap_or(false));
    println!("✓ Valid API key accepted");

    // Test 2: Key Auth — invalid API key
    println!("\n--- Test 2: Key Auth — Invalid API Key ---");
    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .header("X-API-Key", "wrong-key-does-not-exist")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status(), 401, "Invalid API key should return 401");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("Invalid API key"));
    println!("✓ Invalid API key rejected with 401");

    // Test 3: Key Auth — missing API key
    println!("\n--- Test 3: Key Auth — Missing API Key ---");
    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status(), 401, "Missing API key should return 401");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|err| err.contains("Authentication required"))
    );
    println!("✓ Missing API key rejected with 401");

    // Test 4: Key Auth — different consumer (bob)
    println!("\n--- Test 4: Key Auth — Bob's API Key ---");
    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .header("X-API-Key", "bob-api-key-unique-67890")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Bob's key auth should succeed: {}",
        resp.status()
    );
    println!("✓ Bob's API key accepted");

    // Test 5: Key Auth — query param lookup
    println!("\n--- Test 5: Key Auth — Query Param Lookup ---");
    let resp = client
        .get(format!(
            "{}/keyauth-query?apikey=alice-api-key-secret-12345",
            proxy_url
        ))
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Key auth via query param should succeed: {}",
        resp.status()
    );
    println!("✓ API key accepted via query parameter");

    // ==========================================
    // BASIC AUTH TESTS
    // ==========================================

    println!("\n=== BASIC AUTH TESTS ===");

    // Test 6: Basic Auth — valid credentials
    println!("\n--- Test 6: Basic Auth — Valid Credentials ---");
    let basic_cred = base64::engine::general_purpose::STANDARD.encode("alice:alice-password-123");
    let resp = client
        .get(format!("{}/basicauth", proxy_url))
        .header("Authorization", format!("Basic {}", basic_cred))
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Basic auth with valid creds should succeed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["echo"].as_bool().unwrap_or(false));
    println!("✓ Valid basic auth credentials accepted");

    // Test 7: Basic Auth — wrong password
    println!("\n--- Test 7: Basic Auth — Wrong Password ---");
    let bad_cred = base64::engine::general_purpose::STANDARD.encode("alice:wrong-password");
    let resp = client
        .get(format!("{}/basicauth", proxy_url))
        .header("Authorization", format!("Basic {}", bad_cred))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Basic auth with wrong password should return 401"
    );
    println!("✓ Wrong password rejected with 401");

    // Test 8: Basic Auth — unknown user
    println!("\n--- Test 8: Basic Auth — Unknown User ---");
    let unknown_cred =
        base64::engine::general_purpose::STANDARD.encode("unknownuser:some-password");
    let resp = client
        .get(format!("{}/basicauth", proxy_url))
        .header("Authorization", format!("Basic {}", unknown_cred))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Basic auth with unknown user should return 401"
    );
    println!("✓ Unknown user rejected with 401");

    // Test 9: Basic Auth — missing Authorization header
    println!("\n--- Test 9: Basic Auth — Missing Auth Header ---");
    let resp = client
        .get(format!("{}/basicauth", proxy_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Basic auth without header should return 401"
    );
    println!("✓ Missing auth header rejected with 401");

    // Test 10: Basic Auth — malformed header (not Basic scheme)
    println!("\n--- Test 10: Basic Auth — Malformed Header ---");
    let resp = client
        .get(format!("{}/basicauth", proxy_url))
        .header("Authorization", "Bearer some-token")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Basic auth with Bearer scheme should return 401"
    );
    println!("✓ Non-Basic scheme rejected with 401");

    // ==========================================
    // JWT AUTH TESTS
    // ==========================================

    println!("\n=== JWT AUTH TESTS ===");

    // Test 11: JWT Auth — valid token
    println!("\n--- Test 11: JWT Auth — Valid Token ---");
    let jwt_token = generate_consumer_jwt("alice", "alice-jwt-secret-key-9991234567890", 3600);
    let resp = client
        .get(format!("{}/jwtauth", proxy_url))
        .header("Authorization", format!("Bearer {}", jwt_token))
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "JWT auth with valid token should succeed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["echo"].as_bool().unwrap_or(false));
    println!("✓ Valid JWT token accepted");

    // Test 12: JWT Auth — expired token
    println!("\n--- Test 12: JWT Auth — Expired Token ---");
    let expired_token = generate_consumer_jwt("alice", "alice-jwt-secret-key-9991234567890", -300);
    let resp = client
        .get(format!("{}/jwtauth", proxy_url))
        .header("Authorization", format!("Bearer {}", expired_token))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status(), 401, "Expired JWT should return 401");
    println!("✓ Expired JWT token rejected with 401");

    // Test 13: JWT Auth — wrong secret (signed with different key)
    println!("\n--- Test 13: JWT Auth — Wrong Secret ---");
    let bad_jwt = generate_consumer_jwt("alice", "wrong-secret-not-matching", 3600);
    let resp = client
        .get(format!("{}/jwtauth", proxy_url))
        .header("Authorization", format!("Bearer {}", bad_jwt))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "JWT with wrong secret should return 401"
    );
    println!("✓ JWT with wrong secret rejected with 401");

    // Test 14: JWT Auth — unknown consumer (sub claim doesn't match anyone)
    println!("\n--- Test 14: JWT Auth — Unknown Consumer ---");
    let unknown_jwt = generate_consumer_jwt("nonexistent-user", "some-secret", 3600);
    let resp = client
        .get(format!("{}/jwtauth", proxy_url))
        .header("Authorization", format!("Bearer {}", unknown_jwt))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "JWT for unknown consumer should return 401"
    );
    println!("✓ JWT for unknown consumer rejected with 401");

    // Test 15: JWT Auth — missing token
    println!("\n--- Test 15: JWT Auth — Missing Token ---");
    let resp = client
        .get(format!("{}/jwtauth", proxy_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status(), 401, "Missing JWT should return 401");
    println!("✓ Missing JWT token rejected with 401");

    // Test 16: JWT Auth — malformed token
    println!("\n--- Test 16: JWT Auth — Malformed Token ---");
    let resp = client
        .get(format!("{}/jwtauth", proxy_url))
        .header("Authorization", "Bearer not.a.valid.jwt")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status(), 401, "Malformed JWT should return 401");
    println!("✓ Malformed JWT token rejected with 401");

    // ==========================================
    // HMAC AUTH TESTS
    // ==========================================

    println!("\n=== HMAC AUTH TESTS ===");
    let hmac_authority = hmac_authority_from_url(proxy_url);

    // Test 17: HMAC Auth — valid signature
    println!("\n--- Test 17: HMAC Auth — Valid Signature ---");
    let date = Utc::now().to_rfc2822();
    let signature = generate_hmac_signature(
        "GET",
        "/hmacauth",
        &date,
        "alice",
        &hmac_authority,
        "alice-hmac-shared-secret-at-least-32-bytes",
    );
    let hmac_header = format!(
        "hmac username=\"alice\", algorithm=\"hmac-sha256\", signature=\"{}\"",
        signature
    );
    let resp = client
        .get(format!("{}/hmacauth", proxy_url))
        .header("Authorization", &hmac_header)
        .header("Date", &date)
        .header("Digest", empty_digest_header())
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "HMAC auth with valid signature should succeed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["echo"].as_bool().unwrap_or(false));
    println!("✓ Valid HMAC signature accepted");

    // Focused regression coverage for the preverified HMAC cache and the
    // shared H1/H2 request-body classification boundary.
    assert_empty_body_hmac_regressions(harness._gw.proxy_port).await;

    // Test 18: HMAC Auth — wrong secret (bad signature)
    println!("\n--- Test 18: HMAC Auth — Wrong Secret ---");
    let date = Utc::now().to_rfc2822();
    let bad_sig = generate_hmac_signature(
        "GET",
        "/hmacauth",
        &date,
        "alice",
        &hmac_authority,
        "wrong-secret",
    );
    let hmac_header = format!(
        "hmac username=\"alice\", algorithm=\"hmac-sha256\", signature=\"{}\"",
        bad_sig
    );
    let resp = client
        .get(format!("{}/hmacauth", proxy_url))
        .header("Authorization", &hmac_header)
        .header("Date", &date)
        .header("Digest", empty_digest_header())
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "HMAC with wrong secret should return 401"
    );
    println!("✓ HMAC with wrong secret rejected with 401");

    // Test 19: HMAC Auth — missing Date header (replay protection)
    println!("\n--- Test 19: HMAC Auth — Missing Date Header ---");
    let sig_no_date = generate_hmac_signature(
        "GET",
        "/hmacauth",
        "",
        "alice",
        &hmac_authority,
        "alice-hmac-shared-secret-at-least-32-bytes",
    );
    let hmac_header = format!(
        "hmac username=\"alice\", algorithm=\"hmac-sha256\", signature=\"{}\"",
        sig_no_date
    );
    let resp = client
        .get(format!("{}/hmacauth", proxy_url))
        .header("Authorization", &hmac_header)
        .header("Digest", empty_digest_header())
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "HMAC without Date header should return 401"
    );
    println!("✓ HMAC without Date header rejected with 401");

    // Test 20: HMAC Auth — unknown consumer
    println!("\n--- Test 20: HMAC Auth — Unknown Consumer ---");
    let date = Utc::now().to_rfc2822();
    let sig = generate_hmac_signature(
        "GET",
        "/hmacauth",
        &date,
        "nonexistent",
        &hmac_authority,
        "some-secret",
    );
    let hmac_header = format!(
        "hmac username=\"nonexistent\", algorithm=\"hmac-sha256\", signature=\"{}\"",
        sig
    );
    let resp = client
        .get(format!("{}/hmacauth", proxy_url))
        .header("Authorization", &hmac_header)
        .header("Date", &date)
        .header("Digest", empty_digest_header())
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "HMAC for unknown consumer should return 401"
    );
    println!("✓ HMAC for unknown consumer rejected with 401");

    // Regression: wrong and unknown credentials must reject before an oversized
    // body reaches the HMAC plug-in's 10 MiB collection limit. Exact response
    // parity prevents the former 413-vs-401 username-enumeration oracle.
    println!("\n--- HMAC Auth — Oversized Invalid Credential Parity ---");
    let oversized_date = Utc::now().to_rfc2822();
    let (known_wrong_status, known_wrong_body) = send_declared_oversized_invalid_h1_hmac_request(
        harness._gw.proxy_port,
        &oversized_date,
        "alice",
        "wrong-secret-that-cannot-authenticate-alice",
    )
    .await;
    let (unknown_status, unknown_body) = send_declared_oversized_invalid_h1_hmac_request(
        harness._gw.proxy_port,
        &oversized_date,
        "nonexistent",
        "wrong-secret-that-cannot-authenticate-anyone",
    )
    .await;

    assert_eq!(known_wrong_status, 401);
    assert_eq!(unknown_status, known_wrong_status);
    assert_eq!(unknown_body, known_wrong_body);
    println!("✓ Oversized known-invalid and unknown HMAC credentials return identical 401s");

    // Test 21: HMAC Auth — missing Authorization header
    println!("\n--- Test 21: HMAC Auth — Missing Auth Header ---");
    let resp = client
        .get(format!("{}/hmacauth", proxy_url))
        .header("Date", Utc::now().to_rfc2822())
        .header("Digest", empty_digest_header())
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "HMAC without auth header should return 401"
    );
    println!("✓ Missing HMAC auth header rejected with 401");

    // ==========================================
    // ACCESS CONTROL (ACL) TESTS
    // ==========================================

    println!("\n=== ACCESS CONTROL (ACL) TESTS ===");

    // Test 22: ACL allow list — allowed consumer (alice)
    println!("\n--- Test 22: ACL Allow List — Allowed Consumer (alice) ---");
    let resp = client
        .get(format!("{}/keyauth-acl-allow", proxy_url))
        .header("X-API-Key", "alice-api-key-secret-12345")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Alice should be allowed by ACL: {}",
        resp.status()
    );
    println!("✓ Alice allowed through ACL allow list");

    // Test 23: ACL allow list — allowed consumer (bob)
    println!("\n--- Test 23: ACL Allow List — Allowed Consumer (bob) ---");
    let resp = client
        .get(format!("{}/keyauth-acl-allow", proxy_url))
        .header("X-API-Key", "bob-api-key-unique-67890")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Bob should be allowed by ACL: {}",
        resp.status()
    );
    println!("✓ Bob allowed through ACL allow list");

    // Test 24: ACL allow list — disallowed consumer (charlie not in allow list)
    println!("\n--- Test 24: ACL Allow List — Disallowed Consumer (charlie) ---");
    let resp = client
        .get(format!("{}/keyauth-acl-allow", proxy_url))
        .header("X-API-Key", "charlie-api-key-blocked-11111")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        403,
        "Charlie should be blocked by ACL allow list: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("not allowed"));
    println!("✓ Charlie blocked by ACL allow list (403)");

    // Test 25: ACL deny list — allowed consumer (alice, not in deny list)
    println!("\n--- Test 25: ACL Deny List — Allowed Consumer (alice) ---");
    let resp = client
        .get(format!("{}/keyauth-acl-deny", proxy_url))
        .header("X-API-Key", "alice-api-key-secret-12345")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Alice should not be blocked by deny list: {}",
        resp.status()
    );
    println!("✓ Alice allowed (not in deny list)");

    // Test 26: ACL deny list — denied consumer (charlie in deny list)
    println!("\n--- Test 26: ACL Deny List — Denied Consumer (charlie) ---");
    let resp = client
        .get(format!("{}/keyauth-acl-deny", proxy_url))
        .header("X-API-Key", "charlie-api-key-blocked-11111")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        403,
        "Charlie should be blocked by ACL deny list: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("not allowed"));
    println!("✓ Charlie blocked by ACL deny list (403)");

    // Test 27: ACL deny list — bob is allowed (not in deny list)
    println!("\n--- Test 27: ACL Deny List — Bob Allowed ---");
    let resp = client
        .get(format!("{}/keyauth-acl-deny", proxy_url))
        .header("X-API-Key", "bob-api-key-unique-67890")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Bob should not be blocked by deny list: {}",
        resp.status()
    );
    println!("✓ Bob allowed (not in deny list)");

    // ==========================================
    // MULTI-AUTH MODE TESTS
    // ==========================================

    println!("\n=== MULTI-AUTH MODE TESTS ===");

    // Test 28: Multi-Auth — authenticate via JWT (first-success wins)
    println!("\n--- Test 28: Multi-Auth — JWT Authentication ---");
    let jwt_token = generate_consumer_jwt("alice", "alice-jwt-secret-key-9991234567890", 3600);
    let resp = client
        .get(format!("{}/multiauth", proxy_url))
        .header("Authorization", format!("Bearer {}", jwt_token))
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Multi-auth via JWT should succeed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["echo"].as_bool().unwrap_or(false));
    println!("✓ Multi-auth succeeded via JWT");

    // Test 29: Multi-Auth — authenticate via API key (fallback)
    println!("\n--- Test 29: Multi-Auth — API Key Authentication ---");
    let resp = client
        .get(format!("{}/multiauth", proxy_url))
        .header("X-API-Key", "alice-api-key-secret-12345")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Multi-auth via API key should succeed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["echo"].as_bool().unwrap_or(false));
    println!("✓ Multi-auth succeeded via API key (fallback)");

    // Test 30: Multi-Auth — bob authenticates via API key (no JWT creds)
    println!("\n--- Test 30: Multi-Auth — Bob via API Key Only ---");
    let resp = client
        .get(format!("{}/multiauth", proxy_url))
        .header("X-API-Key", "bob-api-key-unique-67890")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Multi-auth for bob via API key should succeed: {}",
        resp.status()
    );
    println!("✓ Bob authenticated via API key in multi-auth mode");

    // Test 31: Multi-Auth — no credentials at all (all plugins fail)
    println!("\n--- Test 31: Multi-Auth — No Credentials ---");
    let resp = client
        .get(format!("{}/multiauth", proxy_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Multi-auth with no credentials should return 401"
    );
    println!("✓ Multi-auth with no credentials rejected with 401");

    // Test 32: Multi-Auth — invalid credentials for all methods
    println!("\n--- Test 32: Multi-Auth — All Invalid Credentials ---");
    let bad_jwt = generate_consumer_jwt("alice", "wrong-secret", 3600);
    let resp = client
        .get(format!("{}/multiauth", proxy_url))
        .header("Authorization", format!("Bearer {}", bad_jwt))
        .header("X-API-Key", "wrong-key-12345")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Multi-auth with all invalid creds should return 401"
    );
    println!("✓ Multi-auth with all invalid credentials rejected with 401");

    // ==========================================
    // MULTI-AUTH + ACL COMBINED TESTS
    // ==========================================

    println!("\n=== MULTI-AUTH + ACL COMBINED TESTS ===");

    // Test 33: Multi-Auth + ACL — alice via JWT (allowed)
    println!("\n--- Test 33: Multi-Auth + ACL — Alice via JWT (allowed) ---");
    let jwt_token = generate_consumer_jwt("alice", "alice-jwt-secret-key-9991234567890", 3600);
    let resp = client
        .get(format!("{}/multiauth-acl", proxy_url))
        .header("Authorization", format!("Bearer {}", jwt_token))
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Alice should be allowed via JWT + ACL: {}",
        resp.status()
    );
    println!("✓ Alice allowed via JWT through multi-auth + ACL");

    // Test 34: Multi-Auth + ACL — alice via API key (allowed)
    println!("\n--- Test 34: Multi-Auth + ACL — Alice via API Key (allowed) ---");
    let resp = client
        .get(format!("{}/multiauth-acl", proxy_url))
        .header("X-API-Key", "alice-api-key-secret-12345")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Alice should be allowed via API key + ACL: {}",
        resp.status()
    );
    println!("✓ Alice allowed via API key through multi-auth + ACL");

    // Test 35: Multi-Auth + ACL — bob via API key (blocked by ACL — not in allowed list)
    println!("\n--- Test 35: Multi-Auth + ACL — Bob Blocked by ACL ---");
    let resp = client
        .get(format!("{}/multiauth-acl", proxy_url))
        .header("X-API-Key", "bob-api-key-unique-67890")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        403,
        "Bob should be blocked by ACL in multi-auth: {}",
        resp.status()
    );
    println!("✓ Bob blocked by ACL allow list (403) despite valid auth");

    // ==========================================
    // CONSUMER CRUD VERIFICATION
    // ==========================================

    println!("\n=== CONSUMER CRUD VERIFICATION ===");

    // Test 36: Verify consumer credentials are redacted in API responses
    println!("\n--- Test 36: Consumer Credentials Redacted ---");
    let resp = client
        .get(format!("{}/consumers/consumer-alice", admin_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Request failed");
    assert!(resp.status().is_success());
    let consumer_json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(consumer_json["username"], "alice");
    assert!(
        consumer_json["credentials"].get("basicauth").is_none(),
        "Basic-auth credentials should be omitted from API responses"
    );
    println!("✓ Consumer credentials properly redacted");

    // Test 37: List consumers
    println!("\n--- Test 37: List Consumers ---");
    let resp = client
        .get(format!("{}/consumers", admin_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Request failed");
    assert!(resp.status().is_success());
    let consumers: serde_json::Value = resp.json().await.unwrap();
    let consumers_arr = consumers["data"]
        .as_array()
        .expect("consumer list response should include data array");
    assert!(
        consumers_arr.len() >= 3,
        "Should have at least 3 consumers (alice, bob, charlie)"
    );
    println!(
        "✓ Consumer listing works ({} consumers)",
        consumers_arr.len()
    );

    // Test 38: Delete credential and verify auth fails
    println!("\n--- Test 38: Delete Credential — Auth Should Fail ---");
    let resp = client
        .delete(format!(
            "{}/consumers/consumer-bob/credentials/keyauth",
            admin_url
        ))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Failed to delete credential: {}",
        resp.status()
    );

    // Wait for DB poll
    tokio::time::sleep(Duration::from_secs(4)).await;

    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .header("X-API-Key", "bob-api-key-unique-67890")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Bob's deleted key should no longer work: {}",
        resp.status()
    );
    println!("✓ Deleted credential correctly rejected");

    // Test 39: Re-add credential and verify auth works again
    println!("\n--- Test 39: Re-add Credential — Auth Should Work ---");
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-bob",
        "keyauth",
        &json!({"key": "bob-new-api-key-99999"}),
    )
    .await
    .unwrap();

    // Wait for DB poll
    tokio::time::sleep(Duration::from_secs(4)).await;

    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .header("X-API-Key", "bob-new-api-key-99999")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Bob's new key should work: {}",
        resp.status()
    );
    println!("✓ Re-added credential works correctly");

    // Test 40: Delete consumer and verify all auth fails. An
    // `access_control` plugin still listing the username in
    // `allowed_consumers` must 409; drop the username first, then delete.
    println!("\n--- Test 40: Delete Consumer — All Auth Should Fail ---");
    let resp = client
        .delete(format!("{}/consumers/consumer-bob", admin_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CONFLICT,
        "DELETE must 409 while access_control.allowed_consumers still names bob: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("409 body");
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "Consumer is referenced by one or more access_control plugin_configs and cannot be deleted"
    );

    let resp = client
        .put(format!("{}/plugins/config/plugin-acl-allow", admin_url))
        .header("Authorization", &auth_header)
        .json(&json!({
            "id": "plugin-acl-allow",
            "plugin_name": "access_control",
            "scope": "proxy",
            "proxy_id": "proxy-keyauth-acl-allow",
            "enabled": true,
            "config": {
                "allowed_consumers": ["alice"]
            }
        }))
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Failed to drop bob from allowed_consumers: {} - {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );

    let resp = client
        .delete(format!("{}/consumers/consumer-bob", admin_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Failed to delete consumer: {}",
        resp.status()
    );

    // Wait for DB poll
    tokio::time::sleep(Duration::from_secs(4)).await;

    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .header("X-API-Key", "bob-new-api-key-99999")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Deleted consumer's key should not work: {}",
        resp.status()
    );
    println!("✓ Deleted consumer's credentials correctly invalidated");

    // Verify consumer is gone via admin API
    let resp = client
        .get(format!("{}/consumers/consumer-bob", admin_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status(), 404, "Deleted consumer should return 404");
    println!("✓ Deleted consumer returns 404 from admin API");

    println!("\n=== All Auth/ACL Tests Passed ===\n");
}

// ============================================================================
// Per-auth-type ACL pairings
//
// `test_auth_acl_comprehensive` exercises key_auth + ACL and multi-auth + ACL.
// The tests below verify that allow/deny lists on the access_control plugin
// fire correctly when the authenticating plugin is basic_auth, jwt_auth, or
// hmac_auth. Each test stands alone so a regression in one auth type does not
// silently mask another (the comprehensive test bails on the first assert).
// ============================================================================

/// Parameters for [`setup_auth_plus_acl_proxy`]. Bundled into a struct so the
/// helper stays under clippy's `too_many_arguments` threshold and so the
/// per-test call sites read like a config block rather than a long positional
/// argument list.
struct AuthAclProxySetup<'a> {
    proxy_id: &'a str,
    listen_path: &'a str,
    backend_port: u16,
    auth_plugin_id: &'a str,
    auth_plugin: serde_json::Value,
    acl_plugin_id: &'a str,
    acl_config: serde_json::Value,
}

/// Helper: configure a single proxy that authenticates via `auth_plugin_id` and
/// then runs `access_control` with the supplied config. Used by the per-auth
/// ACL tests below.
async fn setup_auth_plus_acl_proxy(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    setup: AuthAclProxySetup<'_>,
) {
    let AuthAclProxySetup {
        proxy_id,
        listen_path,
        backend_port,
        auth_plugin_id,
        auth_plugin,
        acl_plugin_id,
        acl_config,
    } = setup;

    // Bare proxy (FK target for plugin_configs.proxy_id)
    create_proxy(
        client,
        admin_url,
        auth_header,
        &json!({
            "id": proxy_id,
            "listen_path": listen_path,
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "auth_mode": "single",
        }),
    )
    .await
    .unwrap();

    create_plugin_config(client, admin_url, auth_header, &auth_plugin)
        .await
        .unwrap();

    create_plugin_config(
        client,
        admin_url,
        auth_header,
        &json!({
            "id": acl_plugin_id,
            "plugin_name": "access_control",
            "scope": "proxy",
            "proxy_id": proxy_id,
            "enabled": true,
            "config": acl_config,
        }),
    )
    .await
    .unwrap();

    update_proxy(
        client,
        admin_url,
        auth_header,
        &json!({
            "id": proxy_id,
            "listen_path": listen_path,
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "auth_mode": "single",
            "plugins": [
                {"plugin_config_id": auth_plugin_id},
                {"plugin_config_id": acl_plugin_id}
            ]
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore]
async fn test_basic_auth_plus_acl() {
    let harness = AuthTestHarness::new()
        .await
        .expect("Failed to create test harness");

    // Pre-bound listener stays owned across the handoff to start_echo_backend_on
    // — avoids the bind-drop-rebind window that races with other parallel tests.
    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let _backend = start_echo_backend_on(backend_listener);

    let client = reqwest::Client::new();
    let admin_token = harness.generate_admin_token().unwrap();
    let auth_header = format!("Bearer {}", admin_token);
    let admin_url = &harness.admin_base_url;
    let proxy_url = &harness.proxy_base_url;

    // Two consumers: alice (allowed) and dave (blocked)
    create_consumer(&client, admin_url, &auth_header, "ba-alice", "ba-alice")
        .await
        .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "ba-alice",
        "basicauth",
        &json!({"password": "alice-basic-pass"}),
    )
    .await
    .unwrap();

    create_consumer(&client, admin_url, &auth_header, "ba-dave", "ba-dave")
        .await
        .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "ba-dave",
        "basicauth",
        &json!({"password": "dave-basic-pass"}),
    )
    .await
    .unwrap();

    // Allow-list proxy: only alice may pass
    setup_auth_plus_acl_proxy(
        &client,
        admin_url,
        &auth_header,
        AuthAclProxySetup {
            proxy_id: "proxy-basic-allow",
            listen_path: "/basic-acl-allow",
            backend_port,
            auth_plugin_id: "plugin-basic-allow-auth",
            auth_plugin: json!({
                "id": "plugin-basic-allow-auth",
                "plugin_name": "basic_auth",
                "scope": "proxy",
                "proxy_id": "proxy-basic-allow",
                "enabled": true,
                "config": {}
            }),
            acl_plugin_id: "plugin-basic-allow-acl",
            acl_config: json!({"allowed_consumers": ["ba-alice"]}),
        },
    )
    .await;

    // Deny-list proxy: dave is rejected, others pass
    setup_auth_plus_acl_proxy(
        &client,
        admin_url,
        &auth_header,
        AuthAclProxySetup {
            proxy_id: "proxy-basic-deny",
            listen_path: "/basic-acl-deny",
            backend_port,
            auth_plugin_id: "plugin-basic-deny-auth",
            auth_plugin: json!({
                "id": "plugin-basic-deny-auth",
                "plugin_name": "basic_auth",
                "scope": "proxy",
                "proxy_id": "proxy-basic-deny",
                "enabled": true,
                "config": {}
            }),
            acl_plugin_id: "plugin-basic-deny-acl",
            acl_config: json!({"disallowed_consumers": ["ba-dave"]}),
        },
    )
    .await;

    tokio::time::sleep(Duration::from_secs(4)).await;

    let alice_cred = base64::engine::general_purpose::STANDARD.encode("ba-alice:alice-basic-pass");
    let dave_cred = base64::engine::general_purpose::STANDARD.encode("ba-dave:dave-basic-pass");

    // Allow list: alice → 200
    let resp = client
        .get(format!("{}/basic-acl-allow", proxy_url))
        .header("Authorization", format!("Basic {}", alice_cred))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "alice should be allowed: {}",
        resp.status()
    );

    // Allow list: dave authenticates but is not in allow list → 403
    let resp = client
        .get(format!("{}/basic-acl-allow", proxy_url))
        .header("Authorization", format!("Basic {}", dave_cred))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "dave should be blocked by allow list (got {})",
        resp.status()
    );

    // Allow list: missing creds → 401 (auth fires before ACL)
    let resp = client
        .get(format!("{}/basic-acl-allow", proxy_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "missing creds should be 401");

    // Deny list: dave → 403, alice → 200
    let resp = client
        .get(format!("{}/basic-acl-deny", proxy_url))
        .header("Authorization", format!("Basic {}", dave_cred))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "dave should be blocked by deny list (got {})",
        resp.status()
    );

    let resp = client
        .get(format!("{}/basic-acl-deny", proxy_url))
        .header("Authorization", format!("Basic {}", alice_cred))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "alice should pass deny list: {}",
        resp.status()
    );
}

#[tokio::test]
#[ignore]
async fn test_jwt_auth_plus_acl() {
    let harness = AuthTestHarness::new()
        .await
        .expect("Failed to create test harness");

    // See test_basic_auth_plus_acl for the rationale on holding the listener.
    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let _backend = start_echo_backend_on(backend_listener);

    let client = reqwest::Client::new();
    let admin_token = harness.generate_admin_token().unwrap();
    let auth_header = format!("Bearer {}", admin_token);
    let admin_url = &harness.admin_base_url;
    let proxy_url = &harness.proxy_base_url;

    create_consumer(&client, admin_url, &auth_header, "jwt-alice", "jwt-alice")
        .await
        .unwrap();
    let alice_secret = "jwt-alice-shared-hmac-secret-2026";
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "jwt-alice",
        "jwt",
        &json!({"secret": alice_secret}),
    )
    .await
    .unwrap();

    create_consumer(&client, admin_url, &auth_header, "jwt-eve", "jwt-eve")
        .await
        .unwrap();
    let eve_secret = "jwt-eve-shared-hmac-secret-2026-aaa";
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "jwt-eve",
        "jwt",
        &json!({"secret": eve_secret}),
    )
    .await
    .unwrap();

    setup_auth_plus_acl_proxy(
        &client,
        admin_url,
        &auth_header,
        AuthAclProxySetup {
            proxy_id: "proxy-jwt-allow",
            listen_path: "/jwt-acl-allow",
            backend_port,
            auth_plugin_id: "plugin-jwt-allow-auth",
            auth_plugin: json!({
                "id": "plugin-jwt-allow-auth",
                "plugin_name": "jwt_auth",
                "scope": "proxy",
                "proxy_id": "proxy-jwt-allow",
                "enabled": true,
                "config": {
                    "token_lookup": "header:Authorization",
                    "consumer_claim_field": "sub"
                }
            }),
            acl_plugin_id: "plugin-jwt-allow-acl",
            acl_config: json!({"allowed_consumers": ["jwt-alice"]}),
        },
    )
    .await;

    setup_auth_plus_acl_proxy(
        &client,
        admin_url,
        &auth_header,
        AuthAclProxySetup {
            proxy_id: "proxy-jwt-deny",
            listen_path: "/jwt-acl-deny",
            backend_port,
            auth_plugin_id: "plugin-jwt-deny-auth",
            auth_plugin: json!({
                "id": "plugin-jwt-deny-auth",
                "plugin_name": "jwt_auth",
                "scope": "proxy",
                "proxy_id": "proxy-jwt-deny",
                "enabled": true,
                "config": {
                    "token_lookup": "header:Authorization",
                    "consumer_claim_field": "sub"
                }
            }),
            acl_plugin_id: "plugin-jwt-deny-acl",
            acl_config: json!({"disallowed_consumers": ["jwt-eve"]}),
        },
    )
    .await;

    tokio::time::sleep(Duration::from_secs(4)).await;

    let alice_token = generate_consumer_jwt("jwt-alice", alice_secret, 3600);
    let eve_token = generate_consumer_jwt("jwt-eve", eve_secret, 3600);

    // Allow list — alice OK, eve forbidden
    let resp = client
        .get(format!("{}/jwt-acl-allow", proxy_url))
        .header("Authorization", format!("Bearer {}", alice_token))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "alice should be allowed: {}",
        resp.status()
    );

    let resp = client
        .get(format!("{}/jwt-acl-allow", proxy_url))
        .header("Authorization", format!("Bearer {}", eve_token))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "eve should be blocked by allow list (got {})",
        resp.status()
    );

    // Allow list — bogus signature must still return 401, not 403
    let bogus = generate_consumer_jwt("jwt-alice", "totally-wrong-secret-xxx", 3600);
    let resp = client
        .get(format!("{}/jwt-acl-allow", proxy_url))
        .header("Authorization", format!("Bearer {}", bogus))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "invalid JWT must surface as 401 before ACL fires (got {})",
        resp.status()
    );

    // Deny list — eve forbidden, alice OK
    let resp = client
        .get(format!("{}/jwt-acl-deny", proxy_url))
        .header("Authorization", format!("Bearer {}", eve_token))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "eve should be blocked by deny list (got {})",
        resp.status()
    );

    let resp = client
        .get(format!("{}/jwt-acl-deny", proxy_url))
        .header("Authorization", format!("Bearer {}", alice_token))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "alice should pass deny list: {}",
        resp.status()
    );
}

#[tokio::test]
#[ignore]
async fn test_hmac_auth_plus_acl() {
    let harness = AuthTestHarness::new()
        .await
        .expect("Failed to create test harness");

    // See test_basic_auth_plus_acl for the rationale on holding the listener.
    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let _backend = start_echo_backend_on(backend_listener);

    let client = reqwest::Client::new();
    let admin_token = harness.generate_admin_token().unwrap();
    let auth_header = format!("Bearer {}", admin_token);
    let admin_url = &harness.admin_base_url;
    let proxy_url = &harness.proxy_base_url;

    let alice_hmac = "hmac-alice-shared-secret-aaa-0001";
    let mallory_hmac = "hmac-mallory-shared-secret-zzz-0002";

    create_consumer(&client, admin_url, &auth_header, "hmac-alice", "hmac-alice")
        .await
        .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "hmac-alice",
        "hmac_auth",
        &json!({"secret": alice_hmac}),
    )
    .await
    .unwrap();

    create_consumer(
        &client,
        admin_url,
        &auth_header,
        "hmac-mallory",
        "hmac-mallory",
    )
    .await
    .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "hmac-mallory",
        "hmac_auth",
        &json!({"secret": mallory_hmac}),
    )
    .await
    .unwrap();

    setup_auth_plus_acl_proxy(
        &client,
        admin_url,
        &auth_header,
        AuthAclProxySetup {
            proxy_id: "proxy-hmac-allow",
            listen_path: "/hmac-acl-allow",
            backend_port,
            auth_plugin_id: "plugin-hmac-allow-auth",
            auth_plugin: json!({
                "id": "plugin-hmac-allow-auth",
                "plugin_name": "hmac_auth",
                "scope": "proxy",
                "proxy_id": "proxy-hmac-allow",
                "enabled": true,
                "config": {
                    "clock_skew_seconds": 300,
                    "signing_profile": "ferrum-hmac-v1",
                    "allow_unsafe_replayable_v1": true
                }
            }),
            acl_plugin_id: "plugin-hmac-allow-acl",
            acl_config: json!({"allowed_consumers": ["hmac-alice"]}),
        },
    )
    .await;

    setup_auth_plus_acl_proxy(
        &client,
        admin_url,
        &auth_header,
        AuthAclProxySetup {
            proxy_id: "proxy-hmac-deny",
            listen_path: "/hmac-acl-deny",
            backend_port,
            auth_plugin_id: "plugin-hmac-deny-auth",
            auth_plugin: json!({
                "id": "plugin-hmac-deny-auth",
                "plugin_name": "hmac_auth",
                "scope": "proxy",
                "proxy_id": "proxy-hmac-deny",
                "enabled": true,
                "config": {
                    "clock_skew_seconds": 300,
                    "signing_profile": "ferrum-hmac-v1",
                    "allow_unsafe_replayable_v1": true
                }
            }),
            acl_plugin_id: "plugin-hmac-deny-acl",
            acl_config: json!({"disallowed_consumers": ["hmac-mallory"]}),
        },
    )
    .await;

    tokio::time::sleep(Duration::from_secs(4)).await;

    fn signed_request(
        path: &str,
        username: &str,
        authority: &str,
        secret: &str,
    ) -> (String, String) {
        let date = Utc::now().to_rfc2822();
        let signature = generate_hmac_signature("GET", path, &date, username, authority, secret);
        let header = format!(
            "hmac username=\"{}\", algorithm=\"hmac-sha256\", signature=\"{}\"",
            username, signature
        );
        (header, date)
    }

    // Allow list — alice OK, mallory blocked
    let hmac_authority = hmac_authority_from_url(proxy_url);
    let (header, date) =
        signed_request("/hmac-acl-allow", "hmac-alice", &hmac_authority, alice_hmac);
    let resp = client
        .get(format!("{}/hmac-acl-allow", proxy_url))
        .header("Authorization", header)
        .header("Date", date)
        .header("Digest", empty_digest_header())
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "alice should be allowed: {}",
        resp.status()
    );

    let (header, date) = signed_request(
        "/hmac-acl-allow",
        "hmac-mallory",
        &hmac_authority,
        mallory_hmac,
    );
    let resp = client
        .get(format!("{}/hmac-acl-allow", proxy_url))
        .header("Authorization", header)
        .header("Date", date)
        .header("Digest", empty_digest_header())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "mallory should be blocked by allow list (got {})",
        resp.status()
    );

    // Allow list — bad signature still returns 401, not 403
    let (header, date) = signed_request(
        "/hmac-acl-allow",
        "hmac-alice",
        &hmac_authority,
        "totally-wrong-secret",
    );
    let resp = client
        .get(format!("{}/hmac-acl-allow", proxy_url))
        .header("Authorization", header)
        .header("Date", date)
        .header("Digest", empty_digest_header())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "bad HMAC signature must surface as 401 before ACL fires (got {})",
        resp.status()
    );

    // Deny list — mallory blocked, alice OK
    let (header, date) = signed_request(
        "/hmac-acl-deny",
        "hmac-mallory",
        &hmac_authority,
        mallory_hmac,
    );
    let resp = client
        .get(format!("{}/hmac-acl-deny", proxy_url))
        .header("Authorization", header)
        .header("Date", date)
        .header("Digest", empty_digest_header())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "mallory should be blocked by deny list (got {})",
        resp.status()
    );

    let (header, date) =
        signed_request("/hmac-acl-deny", "hmac-alice", &hmac_authority, alice_hmac);
    let resp = client
        .get(format!("{}/hmac-acl-deny", proxy_url))
        .header("Authorization", header)
        .header("Date", date)
        .header("Digest", empty_digest_header())
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "alice should pass deny list: {}",
        resp.status()
    );
}

// ────────────────────────────────────────────────────────────────────
// Issue #3837 — `ferrum-hmac-v2` single-use signed requests, end to end
// ────────────────────────────────────────────────────────────────────

/// One accepted `ferrum-hmac-v2` request reaches the backend; its verbatim
/// replay does not.
///
/// The load-bearing assertion is the **backend mutation count**, not the
/// gateway status: "the gateway answered 401" is weaker than "the origin was
/// contacted exactly once", because only the second rules out a duplicate side
/// effect. The counting backend excludes `/health` and non-mutating methods
/// (`HEAD`/`GET`) so a readiness probe, pool warmup, or capability `HEAD /`
/// cannot be mistaken for application traffic.
/// Send one `ferrum-hmac-v2` request with the supplied Authorization header.
async fn send_hmac_v2(
    client: &reqwest::Client,
    url: &str,
    authorization: &str,
    date: &str,
    digest: &str,
) -> reqwest::Response {
    client
        .post(url)
        .header("Authorization", authorization)
        .header("Date", date)
        .header("Digest", digest)
        .send()
        .await
        .expect("hmac v2 request should complete")
}

/// Wait until the `/hmacv2` route is present **and** `hmac_auth` is enforcing.
///
/// A first 200 on a signed POST only proves the route/backend exist. If the
/// plugin has not reached the proxy snapshot, that POST is unauthenticated and
/// cannot seed a replay marker. An unsigned GET is excluded from
/// [`crate::common::spawn_http_counting_mutations`], so it neither consumes a
/// nonce nor increments the mutation count. 401 is the activation proof:
/// missing route is 404; route without the plugin is 200 from the backend.
async fn wait_until_hmac_v2_route_and_plugin_active(client: &reqwest::Client, url: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    const PER_ATTEMPT: Duration = Duration::from_secs(2);
    loop {
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "hmac v2 route and plugin did not become active within 15s: \
                 unsigned GET {url} must converge to 401 (route present and \
                 hmac_auth enforcing) before the first signed POST; last \
                 observation: activation deadline elapsed before any successful probe"
            );
        }
        let attempt_deadline = std::cmp::min(deadline, tokio::time::Instant::now() + PER_ATTEMPT);
        let last = match tokio::time::timeout_at(attempt_deadline, client.get(url).send()).await {
            Ok(Ok(resp)) => {
                let status = resp.status().as_u16();
                if status == 401 {
                    return;
                }
                format!("HTTP {status}")
            }
            Ok(Err(err)) => format!("request error: {err}"),
            Err(_) => String::from("request timed out on this probe"),
        };
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "hmac v2 route and plugin did not become active within 15s: \
                 unsigned GET {url} must converge to 401 (route present and \
                 hmac_auth enforcing) before the first signed POST; last \
                 observation: {last}"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
#[ignore]
async fn test_hmac_v2_backend_sees_exactly_one_mutation_for_a_replayed_request() {
    let harness = AuthTestHarness::new()
        .await
        .expect("Failed to create test harness");

    let (backend, mutations) = crate::common::spawn_http_counting_mutations()
        .await
        .expect("Failed to start counting backend");
    let backend_port = backend.port;

    let client = reqwest::Client::new();
    let admin_token = harness
        .generate_admin_token()
        .expect("Failed to generate admin token");
    let auth_header = format!("Bearer {}", admin_token);
    let admin_url = &harness.admin_base_url;
    let proxy_url = &harness.proxy_base_url;

    const SECRET: &str = "v2-hmac-shared-secret-at-least-32-bytes";
    create_consumer(&client, admin_url, &auth_header, "v2-consumer", "v2user")
        .await
        .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "v2-consumer",
        "hmac_auth",
        &json!({"secret": SECRET}),
    )
    .await
    .unwrap();

    create_proxy(
        &client,
        admin_url,
        &auth_header,
        &json!({
            "id": "proxy-hmac-v2",
            "listen_path": "/hmacv2",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "auth_mode": "single",
        }),
    )
    .await
    .unwrap();
    create_plugin_config(
        &client,
        admin_url,
        &auth_header,
        &json!({
            "id": "plugin-hmac-v2",
            "plugin_name": "hmac_auth",
            "scope": "proxy",
            "proxy_id": "proxy-hmac-v2",
            "enabled": true,
            // No `signing_profile`: `ferrum-hmac-v2` is the default. The replay
            // scope has no default and must be declared.
            "config": {
                "clock_skew_seconds": 300,
                "replay_scope": "process"
            }
        }),
    )
    .await
    .unwrap();

    // Populate proxy_plugins so the runtime snapshot attaches hmac_auth.
    update_proxy(
        &client,
        admin_url,
        &auth_header,
        &json!({
            "id": "proxy-hmac-v2",
            "listen_path": "/hmacv2",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "auth_mode": "single",
            "plugins": [{"plugin_config_id": "plugin-hmac-v2"}]
        }),
    )
    .await
    .unwrap();

    let url = format!("{}/hmacv2", proxy_url);
    wait_until_hmac_v2_route_and_plugin_active(&client, &url).await;

    let authority = hmac_authority_from_url(&url);
    let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    let digest = empty_digest_header();
    let nonce = crate::common::hmac_v2_nonce(0x5eed_0001);
    let request = crate::common::HmacV2Request {
        method: "POST",
        path: "/hmacv2",
        date: &date,
        username: "v2user",
        authority: &authority,
        secret: SECRET,
        digest_header: &digest,
        nonce: &nonce,
    };
    let authorization = crate::common::hmac_v2_authorization_header(&request, None);

    let first = send_hmac_v2(&client, &url, &authorization, &date, &digest).await;
    assert_eq!(
        first.status().as_u16(),
        200,
        "a valid ferrum-hmac-v2 request must be accepted"
    );
    assert_eq!(
        mutations.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the backend must have seen the one accepted mutation"
    );

    // Byte-for-byte replay — a verbatim transport retry is a replay.
    let replay = send_hmac_v2(&client, &url, &authorization, &date, &digest).await;
    assert_eq!(
        replay.status().as_u16(),
        401,
        "the exact replay must be rejected"
    );
    let replay_again = send_hmac_v2(&client, &url, &authorization, &date, &digest).await;
    assert_eq!(replay_again.status().as_u16(), 401);
    assert_eq!(
        mutations.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "replays must not reach the backend at all"
    );

    // A fresh nonce with a recomputed signature is a new request and succeeds.
    let fresh_nonce = crate::common::hmac_v2_nonce(0x5eed_0002);
    let fresh_request = crate::common::HmacV2Request {
        nonce: &fresh_nonce,
        ..request
    };
    let fresh_authorization = crate::common::hmac_v2_authorization_header(&fresh_request, None);
    let fresh = send_hmac_v2(&client, &url, &fresh_authorization, &date, &digest).await;
    assert_eq!(
        fresh.status().as_u16(),
        200,
        "a fresh nonce with a recomputed signature must be accepted"
    );
    assert_eq!(
        mutations.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "exactly one additional mutation reached the backend"
    );

    // A new nonce declared on the wire WITHOUT recomputing the signature must
    // fail authentication and must not reach the backend.
    let unsigned_nonce = crate::common::hmac_v2_nonce(0x5eed_0003);
    let mutated_authorization =
        crate::common::hmac_v2_authorization_header(&fresh_request, Some(&unsigned_nonce));
    let mutated = send_hmac_v2(&client, &url, &mutated_authorization, &date, &digest).await;
    assert_eq!(
        mutated.status().as_u16(),
        401,
        "swapping the nonce without re-signing must fail authentication"
    );
    assert_eq!(
        mutations.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "an unauthenticated request must never reach the backend"
    );

    // A malformed nonce is refused before any credential work.
    let malformed_authorization =
        r#"hmac username="v2user", algorithm="hmac-sha256", nonce="short", signature="AAAA""#;
    let malformed = send_hmac_v2(&client, &url, malformed_authorization, &date, &digest).await;
    assert_eq!(malformed.status().as_u16(), 401);
    assert_eq!(
        mutations.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "a malformed nonce must never reach the backend"
    );
}

async fn send_hmac_v2_content_digest(
    client: &reqwest::Client,
    url: &str,
    authorization: &str,
    date: &str,
    digest: &str,
    body: &[u8],
) -> reqwest::Response {
    client
        .post(url)
        .header("Authorization", authorization)
        .header("Date", date)
        .header("Content-Digest", digest)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .expect("hmac v2 Content-Digest request should complete")
}

/// Issue #3932 — a correctly signed nonempty RFC 9530 `Content-Digest`
/// request authenticates and the backend sees the original client bytes.
#[tokio::test]
#[ignore]
async fn test_hmac_v2_content_digest_forwards_original_body() {
    let harness = AuthTestHarness::new()
        .await
        .expect("Failed to create test harness");

    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind capturing HMAC backend");
    let backend_port = listener
        .local_addr()
        .expect("capturing HMAC backend addr")
        .port();
    let (_backend, captured) = start_capturing_backend(listener);

    let client = reqwest::Client::new();
    let admin_token = harness
        .generate_admin_token()
        .expect("Failed to generate admin token");
    let auth_header = format!("Bearer {}", admin_token);
    let admin_url = &harness.admin_base_url;
    let proxy_url = &harness.proxy_base_url;

    const SECRET: &str = "v2-hmac-content-digest-secret-32b";
    create_consumer(
        &client,
        admin_url,
        &auth_header,
        "v2-cd-consumer",
        "v2cduser",
    )
    .await
    .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "v2-cd-consumer",
        "hmac_auth",
        &json!({"secret": SECRET}),
    )
    .await
    .unwrap();

    create_proxy(
        &client,
        admin_url,
        &auth_header,
        &json!({
            "id": "proxy-hmac-v2-cd",
            "listen_path": "/hmacv2cd",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "auth_mode": "single",
        }),
    )
    .await
    .unwrap();
    create_plugin_config(
        &client,
        admin_url,
        &auth_header,
        &json!({
            "id": "plugin-hmac-v2-cd",
            "plugin_name": "hmac_auth",
            "scope": "proxy",
            "proxy_id": "proxy-hmac-v2-cd",
            "enabled": true,
            "config": {
                "clock_skew_seconds": 300,
                "replay_scope": "process"
            }
        }),
    )
    .await
    .unwrap();
    update_proxy(
        &client,
        admin_url,
        &auth_header,
        &json!({
            "id": "proxy-hmac-v2-cd",
            "listen_path": "/hmacv2cd",
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "auth_mode": "single",
            "plugins": [{"plugin_config_id": "plugin-hmac-v2-cd"}]
        }),
    )
    .await
    .unwrap();

    let url = format!("{}/hmacv2cd", proxy_url);
    wait_until_hmac_v2_route_and_plugin_active(&client, &url).await;

    let authority = hmac_authority_from_url(&url);
    let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    let nonempty = br#"{"ping":1}"#;
    let nonempty_digest = content_digest_sha256_header(nonempty);
    let nonce = crate::common::hmac_v2_nonce(0x3932_0001);
    let request = crate::common::HmacV2Request {
        method: "POST",
        path: "/hmacv2cd",
        date: &date,
        username: "v2cduser",
        authority: &authority,
        secret: SECRET,
        digest_header: &nonempty_digest,
        nonce: &nonce,
    };
    let authorization = crate::common::hmac_v2_authorization_header(&request, None);

    let first = send_hmac_v2_content_digest(
        &client,
        &url,
        &authorization,
        &date,
        &nonempty_digest,
        nonempty,
    )
    .await;
    assert_eq!(
        first.status().as_u16(),
        200,
        "a valid nonempty Content-Digest v2 request must be accepted: {}",
        first.status()
    );
    assert_eq!(
        captured.lock().unwrap().as_deref(),
        Some(nonempty.as_slice()),
        "the backend must receive the original client body bytes"
    );

    let replay = send_hmac_v2_content_digest(
        &client,
        &url,
        &authorization,
        &date,
        &nonempty_digest,
        nonempty,
    )
    .await;
    assert_eq!(replay.status().as_u16(), 401, "verbatim replay must be 401");
    assert_eq!(
        captured.lock().unwrap().as_deref(),
        Some(nonempty.as_slice()),
        "a replay must not replace the captured body"
    );

    let empty_digest = content_digest_sha256_header(&[]);
    let empty_nonce = crate::common::hmac_v2_nonce(0x3932_0002);
    let empty_request = crate::common::HmacV2Request {
        digest_header: &empty_digest,
        nonce: &empty_nonce,
        ..request
    };
    let empty_authorization = crate::common::hmac_v2_authorization_header(&empty_request, None);
    let empty = send_hmac_v2_content_digest(
        &client,
        &url,
        &empty_authorization,
        &date,
        &empty_digest,
        &[],
    )
    .await;
    assert_eq!(
        empty.status().as_u16(),
        200,
        "a valid empty-body Content-Digest v2 request must be accepted"
    );
    assert_eq!(
        captured.lock().unwrap().as_deref(),
        Some(&[][..]),
        "the backend must receive the empty body"
    );

    let wrong_digest = content_digest_sha256_header(b"not-the-body");
    let wrong_nonce = crate::common::hmac_v2_nonce(0x3932_0003);
    let wrong_request = crate::common::HmacV2Request {
        digest_header: &wrong_digest,
        nonce: &wrong_nonce,
        ..request
    };
    let wrong_authorization = crate::common::hmac_v2_authorization_header(&wrong_request, None);
    let mismatched = send_hmac_v2_content_digest(
        &client,
        &url,
        &wrong_authorization,
        &date,
        &wrong_digest,
        nonempty,
    )
    .await;
    assert_eq!(
        mismatched.status().as_u16(),
        401,
        "a digest that does not match the body must be rejected"
    );
    assert_eq!(
        captured.lock().unwrap().as_deref(),
        Some(&[][..]),
        "a digest mismatch must not reach the backend"
    );
}
