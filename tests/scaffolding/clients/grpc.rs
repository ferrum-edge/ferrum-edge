//! gRPC client for scripted-backend tests.
//!
//! Built on the `h2` crate's raw client so the test can speak gRPC without
//! a `.proto` codegen step. The client sends:
//!
//! 1. HTTP/2 HEADERS with `:method = POST`, `:path = /pkg.Service/Method`,
//!    `content-type: application/grpc`, `te: trailers`.
//! 2. A 5-byte gRPC length-prefix + the message bytes as a DATA frame.
//! 3. End-of-stream.
//!
//! It returns the parsed response: HTTP status, message bytes (demarshaled
//! from the 5-byte gRPC header), trailers, and any intermediate error.
//!
//! ## Transport
//!
//! - [`GrpcClient::h2c`] — plaintext h2c, for the gateway routing to a
//!   plain HTTP backend that the gateway's own gRPC pool would reach via
//!   h2c. Rare in production but common for tests.
//! - [`GrpcClient::tls`] — h2 over TLS, for the gateway's typical
//!   `backend_scheme: https` gRPC flow.

use bytes::{BufMut, Bytes, BytesMut};
use h2::client as h2_client;
use http::{HeaderMap, Request, Response};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

/// A buffered gRPC response, captured eagerly.
#[derive(Debug, Clone)]
pub struct GrpcResponse {
    /// HTTP status. gRPC always uses 200 on the happy path; gateway
    /// rejections on input can surface as non-200.
    pub http_status: u16,
    /// Initial response headers (excluding trailers).
    pub headers: HeaderMap,
    /// Concatenated message bodies with gRPC 5-byte prefix stripped. If the
    /// server emitted multiple messages, they're concatenated in order —
    /// tests that care about individual messages should inspect
    /// `raw_body_frames`.
    pub messages: Vec<Bytes>,
    /// Raw DATA frames as delivered by h2. Useful when a test wants to
    /// assert on framing (e.g. that two messages weren't coalesced).
    pub raw_body_frames: Vec<Bytes>,
    /// Response trailers, if any. `grpc-status` lives here on the happy
    /// path.
    pub trailers: Option<HeaderMap>,
    /// Stream-level error if the response failed mid-stream.
    pub stream_error: Option<String>,
}

impl GrpcResponse {
    /// Shorthand: parse `grpc-status` from the trailers, falling back to
    /// initial response headers for the gRPC "Trailers-Only" response
    /// shape (where the HEADERS frame carries `grpc-status` + `grpc-message`
    /// and the stream ends immediately — used for error responses without
    /// a message body).
    pub fn grpc_status(&self) -> Option<u32> {
        if let Some(trailers) = self.trailers.as_ref()
            && let Some(raw) = trailers.get("grpc-status")
            && let Ok(s) = raw.to_str()
            && let Ok(n) = s.parse()
        {
            return Some(n);
        }
        let raw = self.headers.get("grpc-status")?.to_str().ok()?;
        raw.parse().ok()
    }

    /// Returns the effective gRPC status for the response, applying the
    /// gRPC wire-protocol rule that a missing `grpc-status` (in neither
    /// trailers nor Trailers-Only headers) is treated as `INTERNAL` (13)
    /// by compliant gRPC stacks (tonic, grpc-go).
    ///
    /// Use this in tests that care about the *semantic* outcome of an RPC
    /// rather than the literal bytes on the wire. [`Self::grpc_status`]
    /// returns `None` when the status header/trailer is absent;
    /// `effective_grpc_status` fills in the synthetic `INTERNAL` that a
    /// real client would observe.
    pub fn effective_grpc_status(&self) -> u32 {
        self.grpc_status().unwrap_or(13 /* INTERNAL */)
    }

    /// Shorthand: parse `grpc-message` from trailers, falling back to
    /// initial headers (Trailers-Only response).
    pub fn grpc_message(&self) -> Option<&str> {
        if let Some(t) = self.trailers.as_ref()
            && let Some(v) = t.get("grpc-message").and_then(|v| v.to_str().ok())
        {
            return Some(v);
        }
        self.headers.get("grpc-message")?.to_str().ok()
    }
}

/// A simple gRPC client.
pub struct GrpcClient {
    target: String,
    transport: Transport,
}

enum Transport {
    H2c,
    Tls {
        root_pem: Option<String>,
        insecure: bool,
    },
}

impl GrpcClient {
    /// Plaintext h2c client against `target` (`host:port`).
    pub fn h2c(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            transport: Transport::H2c,
        }
    }

    /// h2-over-TLS client. `root_pem` is an optional CA PEM the client
    /// will trust; if `None`, the system roots plus webpki defaults are
    /// used.
    pub fn tls(target: impl Into<String>, root_pem: Option<String>) -> Self {
        Self {
            target: target.into(),
            transport: Transport::Tls {
                root_pem,
                insecure: false,
            },
        }
    }

    /// h2-over-TLS client that accepts any server cert. Use for tests
    /// pointing at self-signed backends.
    pub fn tls_insecure(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            transport: Transport::Tls {
                root_pem: None,
                insecure: true,
            },
        }
    }

    /// Send a unary RPC at `path` with `body` as the single gRPC message.
    /// `body` is raw bytes — the client adds the 5-byte gRPC frame header.
    pub async fn unary(
        &self,
        path: &str,
        body: Bytes,
    ) -> Result<GrpcResponse, Box<dyn std::error::Error + Send + Sync>> {
        self.unary_with_headers(path, body, &[]).await
    }

    /// Like [`Self::unary`] but allows passing extra request headers.
    pub async fn unary_with_headers(
        &self,
        path: &str,
        body: Bytes,
        extra_headers: &[(&str, String)],
    ) -> Result<GrpcResponse, Box<dyn std::error::Error + Send + Sync>> {
        let (host, port) = parse_target(&self.target)?;
        let response = match &self.transport {
            Transport::H2c => {
                let tcp = TcpStream::connect((host.as_str(), port)).await?;
                self.send_over_io(tcp, &host, port, path, body, extra_headers, false)
                    .await?
            }
            Transport::Tls { root_pem, insecure } => {
                let tls = tls_connect(&host, port, root_pem.as_deref(), *insecure).await?;
                self.send_over_io(tls, &host, port, path, body, extra_headers, true)
                    .await?
            }
        };
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_over_io<T>(
        &self,
        io: T,
        host: &str,
        port: u16,
        path: &str,
        body: Bytes,
        extra_headers: &[(&str, String)],
        tls: bool,
    ) -> Result<GrpcResponse, Box<dyn std::error::Error + Send + Sync>>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut send_req, connection) = h2_client::handshake(io).await?;
        let conn_task = tokio::spawn(connection);

        let scheme = if tls { "https" } else { "http" };
        let mut req_builder = Request::builder()
            .method("POST")
            .uri(format!("{scheme}://{host}:{port}{path}"))
            .header("content-type", "application/grpc")
            .header("te", "trailers");
        for (k, v) in extra_headers {
            req_builder = req_builder.header(*k, v);
        }
        let request = req_builder.body(())?;

        let (response_fut, mut req_body) = send_req.send_request(request, false)?;

        // Frame the gRPC message: 1-byte compressed flag + 4-byte BE length + body.
        let mut framed = BytesMut::with_capacity(body.len() + 5);
        framed.put_u8(0);
        framed.put_u32(body.len() as u32);
        framed.extend_from_slice(&body);
        req_body.send_data(framed.freeze(), true)?;

        let response_result = tokio::time::timeout(Duration::from_secs(20), response_fut).await;
        let response: Response<h2::RecvStream> = match response_result {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                // Stream-level error before headers arrived. Synthesize a
                // response so the caller can inspect it.
                conn_task.abort();
                return Ok(GrpcResponse {
                    http_status: 0,
                    headers: HeaderMap::new(),
                    messages: Vec::new(),
                    raw_body_frames: Vec::new(),
                    trailers: None,
                    stream_error: Some(format!("response error: {e}")),
                });
            }
            Err(_) => {
                conn_task.abort();
                return Ok(GrpcResponse {
                    http_status: 0,
                    headers: HeaderMap::new(),
                    messages: Vec::new(),
                    raw_body_frames: Vec::new(),
                    trailers: None,
                    stream_error: Some("response timed out".into()),
                });
            }
        };

        let http_status = response.status().as_u16();
        let headers = response.headers().clone();
        let (_parts, mut body_stream) = response.into_parts();

        let mut raw_frames = Vec::new();
        let mut stream_error = None;
        loop {
            match body_stream.data().await {
                Some(Ok(chunk)) => {
                    let _ = body_stream.flow_control().release_capacity(chunk.len());
                    raw_frames.push(chunk);
                }
                Some(Err(e)) => {
                    stream_error = Some(format!("body error: {e}"));
                    break;
                }
                None => break,
            }
        }

        let trailers = if stream_error.is_none() {
            match body_stream.trailers().await {
                Ok(t) => t,
                Err(e) => {
                    stream_error = Some(format!("trailers error: {e}"));
                    None
                }
            }
        } else {
            None
        };

        let messages = decode_grpc_messages(&raw_frames);
        // Don't care if conn_task errors; the important state is above.
        conn_task.abort();

        Ok(GrpcResponse {
            http_status,
            headers,
            messages,
            raw_body_frames: raw_frames,
            trailers,
            stream_error,
        })
    }
}

/// Decode the length-prefixed gRPC messages out of a concatenation of DATA
/// frames. A single message may span multiple DATA frames, so we concat
/// first and then walk the 5-byte headers.
fn decode_grpc_messages(frames: &[Bytes]) -> Vec<Bytes> {
    let mut joined = BytesMut::new();
    for f in frames {
        joined.extend_from_slice(f);
    }
    let buf = joined.freeze();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 5 <= buf.len() {
        // 1-byte flag, 4-byte BE length. We don't bother with compression
        // semantics; just validate the length fits.
        let len = u32::from_be_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]) as usize;
        if i + 5 + len > buf.len() {
            break;
        }
        out.push(buf.slice(i + 5..i + 5 + len));
        i += 5 + len;
    }
    out
}

fn parse_target(t: &str) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    let (host, port) = t
        .rsplit_once(':')
        .ok_or_else(|| format!("bad target {t:?}: expected host:port"))?;
    let port = port.parse::<u16>()?;
    Ok((host.to_string(), port))
}

async fn tls_connect(
    host: &str,
    port: u16,
    root_pem: Option<&str>,
    insecure: bool,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::RootCertStore;
    use rustls_pemfile::certs;

    let provider = rustls::crypto::ring::default_provider();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?;
    let mut config = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier))
            .with_no_client_auth()
    } else {
        let mut root = RootCertStore::empty();
        if let Some(pem) = root_pem {
            let mut reader = pem.as_bytes();
            for cert in certs(&mut reader).filter_map(|c| c.ok()) {
                root.add(cert)?;
            }
        }
        builder.with_root_certificates(root).with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h2".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect((host, port)).await?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
    let stream = connector.connect(name, tcp).await?;
    Ok(stream)
}

/// Dangerous cert verifier: accepts every server cert. Used only when
/// `tls_insecure()` is requested.
#[derive(Debug)]
struct AcceptAnyVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parsing() {
        let (h, p) = parse_target("127.0.0.1:8080").expect("parse");
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 8080);
    }

    #[test]
    fn decode_grpc_messages_single_frame() {
        // 1-byte flag + 4-byte len + "hi"
        let frame = Bytes::from_static(b"\x00\x00\x00\x00\x02hi");
        let msgs = decode_grpc_messages(&[frame]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(&msgs[0][..], b"hi");
    }

    #[test]
    fn decode_grpc_messages_split_across_frames() {
        let a = Bytes::from_static(b"\x00\x00\x00\x00\x03ab");
        let b = Bytes::from_static(b"c");
        let msgs = decode_grpc_messages(&[a, b]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(&msgs[0][..], b"abc");
    }
}
