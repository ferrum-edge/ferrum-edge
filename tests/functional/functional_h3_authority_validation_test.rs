//! Functional tests for HTTP/3 authority validation.
//!
//! Unit tests cover the validator directly; this module verifies the live H3
//! listener rejects conflicting `Host` and `:authority` values before routing.

use crate::common::TestGateway;

use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

fn build_config(backend_port: u16) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "h3-authority-proxy"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: false
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
"#
    )
}

fn start_counting_http_backend_on(
    listener: TcpListener,
    accepted: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let accepted = Arc::clone(&accepted);
            tokio::spawn(async move {
                accepted.fetch_add(1, Ordering::Relaxed);
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let body = b"backend-ok";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    String::from_utf8_lossy(body)
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    })
}

#[derive(Debug)]
enum RawH3Outcome {
    Response(Vec<u8>),
    StreamError(String),
}

async fn send_mismatched_host_h3_request(
    url: &str,
    host_header: &str,
) -> Result<RawH3Outcome, Box<dyn std::error::Error + Send + Sync>> {
    let parsed: http::Uri = url.parse()?;
    let host = parsed.host().ok_or("missing host in url")?.to_string();
    let port = parsed.port_u16().unwrap_or(443);
    let authority = parsed
        .authority()
        .ok_or("missing authority in url")?
        .as_str()
        .to_string();
    let path = parsed.path_and_query().map_or("/", |pq| pq.as_str());

    let endpoint = insecure_h3_endpoint()?;
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let conn = tokio::time::timeout(
        Duration::from_secs(3),
        endpoint.connect(addr, host.as_str())?,
    )
    .await
    .map_err(|_| "QUIC handshake timed out")??;

    // Client control stream: stream type 0x00 followed by an empty SETTINGS
    // frame (0x04, length 0). Keep it open for the connection lifetime.
    let mut control = conn.open_uni().await?;
    control.write_all(&[0x00, 0x04, 0x00]).await?;

    // QPACK encoder/decoder streams are empty because this request uses a
    // stateless header block, but opening them mirrors a normal H3 client.
    let mut encoder = conn.open_uni().await?;
    encoder.write_all(&[0x02]).await?;
    let mut decoder = conn.open_uni().await?;
    decoder.write_all(&[0x03]).await?;

    let (mut send, mut recv) = conn.open_bi().await?;
    let header_block = encode_qpack_h3_get_headers(&authority, path, host_header);
    let mut request = Vec::with_capacity(header_block.len() + 8);
    encode_h3_varint(0x01, &mut request);
    encode_h3_varint(header_block.len() as u64, &mut request);
    request.extend_from_slice(&header_block);
    send.write_all(&request).await?;
    send.finish()?;

    let outcome =
        match tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024)).await {
            Ok(Ok(bytes)) => RawH3Outcome::Response(bytes),
            Ok(Err(err)) => RawH3Outcome::StreamError(err.to_string()),
            Err(_) => return Err("timed out waiting for H3 response/reset".into()),
        };

    drop((control, encoder, decoder));
    conn.close(0u32.into(), b"test complete");
    endpoint.close(0u32.into(), b"test complete");

    Ok(outcome)
}

fn insecure_h3_endpoint() -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    let provider = rustls::crypto::ring::default_provider();
    let verifier = Arc::new(DangerousAcceptAnyServer);
    let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
        .map_err(|e| format!("QuicClientConfig build failed: {e}"))?;
    let client_config = ClientConfig::new(Arc::new(quic_config));

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn encode_qpack_h3_get_headers(authority: &str, path: &str, host: &str) -> Vec<u8> {
    let mut block = vec![0x00, 0x00]; // Required Insert Count = 0, Delta Base = 0.
    encode_qpack_literal(&mut block, b":method", b"GET");
    encode_qpack_literal(&mut block, b":scheme", b"https");
    encode_qpack_literal(&mut block, b":authority", authority.as_bytes());
    encode_qpack_literal(&mut block, b":path", path.as_bytes());
    encode_qpack_literal(&mut block, b"host", host.as_bytes());
    block
}

fn encode_qpack_literal(buf: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    encode_qpack_string(buf, 4, 0b0010, name);
    encode_qpack_string(buf, 8, 0, value);
}

fn encode_qpack_string(buf: &mut Vec<u8>, size: u8, flags: u8, value: &[u8]) {
    encode_prefixed_int(buf, size - 1, flags << 1, value.len() as u64);
    buf.extend_from_slice(value);
}

fn encode_prefixed_int(buf: &mut Vec<u8>, size: u8, flags: u8, value: u64) {
    let mask = !(0xffu8 << size);
    let flags = flags << size;
    if value < u64::from(mask) {
        buf.push(flags | value as u8);
        return;
    }

    buf.push(flags | mask);
    let mut remaining = value - u64::from(mask);
    while remaining >= 128 {
        buf.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    buf.push(remaining as u8);
}

fn encode_h3_varint(value: u64, buf: &mut Vec<u8>) {
    if value < 64 {
        buf.push(value as u8);
    } else if value < 16_384 {
        buf.extend_from_slice(&((0b01u16 << 14) | value as u16).to_be_bytes());
    } else if value < 1_073_741_824 {
        buf.extend_from_slice(&((0b10u32 << 30) | value as u32).to_be_bytes());
    } else {
        buf.extend_from_slice(&((0b11u64 << 62) | value).to_be_bytes());
    }
}

fn h3_data_payload(raw: &[u8]) -> Vec<u8> {
    let mut offset = 0usize;
    let mut body = Vec::new();
    while offset < raw.len() {
        let Some(frame_type) = decode_h3_varint(raw, &mut offset) else {
            break;
        };
        let Some(len) = decode_h3_varint(raw, &mut offset) else {
            break;
        };
        let len = len as usize;
        if raw.len().saturating_sub(offset) < len {
            break;
        }
        let payload = &raw[offset..offset + len];
        if frame_type == 0x00 {
            body.extend_from_slice(payload);
        }
        offset += len;
    }
    body
}

fn decode_h3_varint(raw: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *raw.get(*offset)?;
    let width = 1usize << (first >> 6);
    if raw.len().saturating_sub(*offset) < width {
        return None;
    }
    let value = match width {
        1 => u64::from(first & 0x3f),
        2 => u64::from(u16::from_be_bytes([raw[*offset] & 0x3f, raw[*offset + 1]])),
        4 => u64::from(u32::from_be_bytes([
            raw[*offset] & 0x3f,
            raw[*offset + 1],
            raw[*offset + 2],
            raw[*offset + 3],
        ])),
        8 => u64::from_be_bytes([
            raw[*offset] & 0x3f,
            raw[*offset + 1],
            raw[*offset + 2],
            raw[*offset + 3],
            raw[*offset + 4],
            raw[*offset + 5],
            raw[*offset + 6],
            raw[*offset + 7],
        ]),
        _ => return None,
    };
    *offset += width;
    Some(value)
}

#[derive(Debug)]
struct DangerousAcceptAnyServer;

impl rustls::client::danger::ServerCertVerifier for DangerousAcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

/// H3 requests that carry a Host header disagreeing with `:authority` must be
/// rejected before route matching or backend connection.
#[ignore]
#[tokio::test]
async fn functional_h3_host_authority_mismatch_rejected_before_backend() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_accepts = Arc::new(AtomicUsize::new(0));
    let backend_task =
        start_counting_http_backend_on(backend_listener, Arc::clone(&backend_accepts));
    sleep(Duration::from_millis(150)).await;

    let https_reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let https_port = https_reservation.local_addr().unwrap().port();
    drop(https_reservation);

    let mut gateway = TestGateway::builder()
        .mode_file(build_config(backend_port))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start gateway with h3");

    sleep(Duration::from_millis(250)).await;
    backend_accepts.store(0, Ordering::Relaxed);

    let url = format!("https://localhost:{https_port}/");

    let mut last_err = None;
    let outcome = {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match send_mismatched_host_h3_request(&url, "evil.example:443").await {
                Ok(outcome) => break outcome,
                Err(err) if std::time::Instant::now() < deadline => {
                    last_err = Some(err.to_string());
                    sleep(Duration::from_millis(100)).await;
                }
                Err(err) => {
                    panic!(
                        "H3 Host/:authority mismatch request did not complete; last startup error={last_err:?}; final error={err}"
                    );
                }
            }
        }
    };

    match outcome {
        RawH3Outcome::StreamError(err) => {
            assert!(
                err.to_ascii_lowercase().contains("reset"),
                "unexpected raw H3 stream error: {err}"
            );
        }
        RawH3Outcome::Response(raw) => {
            let body = String::from_utf8_lossy(&h3_data_payload(&raw)).to_string();
            assert!(
                body.contains("authority disagree"),
                "unexpected raw H3 response bytes: {raw:?}, body: {body}"
            );
        }
    }
    assert_eq!(
        backend_accepts.load(Ordering::Relaxed),
        0,
        "mismatched Host/:authority request must be rejected before backend connect"
    );

    gateway.shutdown();
    backend_task.abort();
}
