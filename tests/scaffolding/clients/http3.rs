//! HTTP/3 client tailored for scripted-backend tests.
//!
//! Wraps `quinn` + `h3` with a TLS-verify-off knob and buffered response
//! capture. Mirrors [`super::http1::Http1Client`] for the H3 frontend path
//! so tests can fire requests at the gateway's QUIC listener without
//! hand-rolling the QUIC + H3 handshake each time.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// An H3 client that skips TLS verification. Symmetric with Phase 1's
/// [`Http1Client::insecure`].
pub struct Http3Client {
    endpoint: Endpoint,
}

impl Http3Client {
    /// Build a client that accepts any TLS certificate.
    pub fn insecure() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let provider = rustls::crypto::ring::default_provider();
        let verifier = Arc::new(DangerousAcceptAnyServer);
        let client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Self::from_rustls(client_tls)
    }

    fn from_rustls(
        mut client_tls: rustls::ClientConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
            .map_err(|e| format!("QuicClientConfig build failed: {e}"))?;
        let client_config = ClientConfig::new(Arc::new(quic_config));

        // Bind ephemeral local UDP. quinn picks an IPv4 endpoint by default
        // which matches the gateway's IPv4 bind in test mode.
        let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint })
    }

    /// Fire a single `GET <url>` via QUIC. `url` must be `https://host:port/path`.
    /// Returns the buffered response.
    pub async fn get(
        &self,
        url: &str,
    ) -> Result<Http3Response, Box<dyn std::error::Error + Send + Sync>> {
        self.get_with_options(url, GetOptions::default()).await
    }

    /// Fire a single `GET` with caller-controlled header overrides. Used by
    /// host-header tests that need to force "only `:authority`" or
    /// "explicit Host that contradicts `:authority`" wire shapes.
    pub async fn get_with_options(
        &self,
        url: &str,
        options: GetOptions,
    ) -> Result<Http3Response, Box<dyn std::error::Error + Send + Sync>> {
        let parsed: http::Uri = url.parse()?;
        let host = parsed.host().ok_or("missing host in url")?.to_string();
        let port = parsed.port_u16().unwrap_or(443);
        let addr = resolve_loopback(&host, port)?;

        let server_name = match parsed.host() {
            Some(h) => h.to_string(),
            None => "localhost".to_string(),
        };
        // Timeout the whole request so a hung backend doesn't wedge the test.
        let conn = tokio::time::timeout(
            Duration::from_secs(15),
            self.endpoint.connect(addr, &server_name)?,
        )
        .await
        .map_err(|_| "QUIC handshake timed out")??;
        let h3_conn = h3_quinn::Connection::new(conn);
        let (mut driver, mut send_request) = h3::client::new(h3_conn)
            .await
            .map_err(|e| format!("h3 new: {e}"))?;
        let driver_task = tokio::spawn(async move {
            // The driver must be polled to make progress; ignore its final
            // result since we don't need the connection-level error for
            // client-side assertions.
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let mut req_builder = Request::builder().method(http::Method::GET).uri(url);
        match &options.host_header {
            HostHeader::Auto => {
                // Mirror what production H3 clients (curl, Chromium, Firefox)
                // typically send — only `:authority`, no explicit Host. The
                // gateway must synthesize Host from `:authority` for the
                // forwarded request.
            }
            HostHeader::Explicit(value) => {
                req_builder = req_builder.header(http::header::HOST, value.as_str());
            }
            HostHeader::SameAsAuthority => {
                let host_header = format!("{host}:{port}");
                req_builder = req_builder.header(http::header::HOST, host_header);
            }
        }
        let req = req_builder
            .body(())
            .map_err(|e| format!("build request: {e}"))?;
        let mut stream =
            tokio::time::timeout(Duration::from_secs(15), send_request.send_request(req))
                .await
                .map_err(|_| "send_request timed out")?
                .map_err(|e| format!("send_request: {e}"))?;
        stream
            .finish()
            .await
            .map_err(|e| format!("finish request body: {e}"))?;

        let resp = tokio::time::timeout(Duration::from_secs(15), stream.recv_response())
            .await
            .map_err(|_| "recv_response timed out")?
            .map_err(|e| format!("recv_response: {e}"))?;
        let status = resp.status();
        let headers = resp.headers().clone();

        let mut body_bytes = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(15), stream.recv_data()).await {
                Ok(Ok(Some(mut chunk))) => {
                    while chunk.has_remaining() {
                        let take = chunk.chunk().to_vec();
                        body_bytes.extend_from_slice(&take);
                        chunk.advance(take.len());
                    }
                }
                Ok(Ok(None)) => break,
                Ok(Err(_)) | Err(_) => break,
            }
        }

        // Best-effort drain of any trailers (we don't expose them but
        // need to advance the stream to a clean shutdown).
        let _ = stream.recv_trailers().await;
        drop(send_request);
        driver_task.abort();

        Ok(Http3Response {
            status,
            headers,
            body_bytes: Bytes::from(body_bytes),
        })
    }
}

/// Resolve a host into a `SocketAddr`, pinning it to loopback for test use.
/// We deliberately side-step `tokio::net::lookup_host` because the gateway's
/// listener binds `127.0.0.1` and we want deterministic routing regardless
/// of the host's actual resolver state.
fn resolve_loopback(
    host: &str,
    port: u16,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    if host == "localhost" || host == "127.0.0.1" {
        return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    }
    // Fall back to parsing the host as an IP literal. Arbitrary DNS is not
    // supported by the test client; tests should target loopback.
    let ip: std::net::IpAddr = host.parse()?;
    Ok(SocketAddr::new(ip, port))
}

/// Buffered H3 response captured after body drain.
#[derive(Debug)]
pub struct Http3Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body_bytes: Bytes,
}

impl Http3Response {
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body_bytes).to_string()
    }
}

/// Per-request overrides for `Http3Client::get_with_options`.
#[derive(Debug, Default, Clone)]
pub struct GetOptions {
    pub host_header: HostHeader,
}

/// Controls how the H3 client emits the inbound `Host` header alongside
/// the URI's `:authority` pseudo-header.
#[derive(Debug, Default, Clone)]
pub enum HostHeader {
    /// No explicit Host header — only `:authority`. This is what curl,
    /// Chromium, and Firefox typically emit on H3 requests.
    #[default]
    Auto,
    /// Send an explicit Host header equal to the URI's authority.
    SameAsAuthority,
    /// Send an explicit Host header with a caller-supplied value.
    Explicit(String),
}

use bytes::Buf;

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
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn insecure_client_builds() {
        Http3Client::insecure().expect("client");
    }
}
