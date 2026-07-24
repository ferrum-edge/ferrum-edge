//! HTTP/3 client tailored for scripted-backend tests.
//!
//! Wraps `quinn` + `h3` with a TLS-verify-off knob and buffered response
//! capture. Mirrors [`super::http1::Http1Client`] for the H3 frontend path
//! so tests can fire requests at the gateway's QUIC listener without
//! hand-rolling the QUIC + H3 handshake each time.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{HeaderMap, Method, Request, StatusCode};
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::task::JoinHandle;

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
        Self::from_rustls(client_tls, None)
    }

    /// Build an insecure client with an explicit per-stream receive window.
    ///
    /// Slow-client tests use this to create deterministic QUIC backpressure
    /// without relying on Quinn's substantially larger default window.
    pub fn insecure_with_stream_receive_window(
        stream_receive_window: u32,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let provider = rustls::crypto::ring::default_provider();
        let verifier = Arc::new(DangerousAcceptAnyServer);
        let client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Self::from_rustls(client_tls, Some(stream_receive_window))
    }

    fn from_rustls(
        mut client_tls: rustls::ClientConfig,
        stream_receive_window: Option<u32>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
            .map_err(|e| format!("QuicClientConfig build failed: {e}"))?;
        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        if let Some(window) = stream_receive_window {
            let mut transport = quinn::TransportConfig::default();
            transport.stream_receive_window(quinn::VarInt::from_u32(window));
            // Leave enough connection-level credit for the response stream
            // plus H3 control/QPACK streams while the response itself stalls.
            transport.receive_window(quinn::VarInt::from_u32(
                window.saturating_mul(64).max(1_048_576),
            ));
            client_config.transport_config(Arc::new(transport));
        }

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

    /// Fire a single request with caller-controlled method/header overrides.
    /// Used by protocol validation tests that need to force non-default
    /// request shapes without hand-rolling the QUIC/H3 handshake.
    /// Fire a single request with caller-controlled header overrides. Used by
    /// host-header tests that need to force "only `:authority`" or
    /// "explicit Host that contradicts `:authority`" wire shapes.
    pub async fn get_with_options(
        &self,
        url: &str,
        options: GetOptions,
    ) -> Result<Http3Response, Box<dyn std::error::Error + Send + Sync>> {
        self.request_with_body(url, options, Bytes::new()).await
    }

    /// Fire a single `POST <url>` via QUIC with DATA bytes and no explicit
    /// `Content-Length`. This exercises H3 streaming request-body paths.
    pub async fn post_bytes(
        &self,
        url: &str,
        body: impl Into<Bytes>,
    ) -> Result<Http3Response, Box<dyn std::error::Error + Send + Sync>> {
        let options = GetOptions::default().method(http::Method::POST);
        self.request_with_body(url, options, body.into()).await
    }

    async fn request_with_body(
        &self,
        url: &str,
        options: GetOptions,
        body: Bytes,
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

        let mut req_builder = Request::builder().method(options.method.clone()).uri(url);
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
        for (name, value) in &options.headers {
            req_builder = req_builder.header(name.as_str(), value.as_str());
        }
        let req = req_builder
            .body(())
            .map_err(|e| format!("build request: {e}"))?;
        let mut stream =
            tokio::time::timeout(Duration::from_secs(15), send_request.send_request(req))
                .await
                .map_err(|_| "send_request timed out")?
                .map_err(|e| format!("send_request: {e}"))?;
        if !body.is_empty() {
            tokio::time::timeout(Duration::from_secs(15), stream.send_data(body))
                .await
                .map_err(|_| "send request body timed out")?
                .map_err(|e| format!("send request body: {e}"))?;
        }
        if !options.body.is_empty() {
            stream
                .send_data(options.body.clone())
                .await
                .map_err(|e| format!("send request body: {e}"))?;
        }
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
        let mut body_error = None;
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
                Ok(Err(error)) => {
                    body_error = Some(error.to_string());
                    break;
                }
                Err(_) => {
                    body_error = Some("response body read timed out".to_string());
                    break;
                }
            }
        }

        // Capture any terminal trailers (e.g. gRPC `grpc-status` / `grpc-message`)
        // so trailer-preservation tests can assert on them; draining also
        // advances the stream to a clean shutdown.
        let trailers = tokio::time::timeout(Duration::from_secs(15), stream.recv_trailers())
            .await
            .ok()
            .and_then(|r| r.ok())
            .flatten();
        drop(send_request);
        driver_task.abort();

        Ok(Http3Response {
            status,
            headers,
            body_bytes: Bytes::from(body_bytes),
            trailers,
            body_error,
        })
    }

    /// Send an HTTP/3 Extended CONNECT request with a caller-selected
    /// `:protocol` value and buffer the regular response body. This is for
    /// negative protocol tests such as unsupported CONNECT-UDP rejection; use
    /// [`Self::websocket`] for successful RFC 9220 WebSocket sessions.
    pub async fn extended_connect(
        &self,
        url: &str,
        protocol: h3::ext::Protocol,
    ) -> Result<Http3Response, Box<dyn std::error::Error + Send + Sync>> {
        let parsed: http::Uri = url.parse()?;
        let host = parsed.host().ok_or("missing host in url")?.to_string();
        let port = parsed.port_u16().unwrap_or(443);
        let addr = resolve_loopback(&host, port)?;

        let server_name = parsed.host().unwrap_or("localhost").to_string();
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
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let mut req = Request::builder()
            .method(http::Method::CONNECT)
            .version(http::Version::HTTP_3)
            .uri(url)
            .body(())
            .map_err(|e| format!("build request: {e}"))?;
        req.extensions_mut().insert(protocol);

        let mut stream =
            tokio::time::timeout(Duration::from_secs(15), send_request.send_request(req))
                .await
                .map_err(|_| "send_request timed out")?
                .map_err(|e| format!("send_request: {e}"))?;

        let resp = tokio::time::timeout(Duration::from_secs(15), stream.recv_response())
            .await
            .map_err(|_| "recv_response timed out")?
            .map_err(|e| format!("recv_response: {e}"))?;
        let status = resp.status();
        let headers = resp.headers().clone();

        let mut body_bytes = Vec::new();
        let mut body_error = None;
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
                Ok(Err(error)) => {
                    body_error = Some(error.to_string());
                    break;
                }
                Err(_) => {
                    body_error = Some("response body read timed out".to_string());
                    break;
                }
            }
        }

        drop(send_request);
        driver_task.abort();

        Ok(Http3Response {
            status,
            headers,
            body_bytes: Bytes::from(body_bytes),
            trailers: None,
            body_error,
        })
    }

    /// Open an H3 gRPC request stream (POST, `content-type: application/grpc`)
    /// WITHOUT sending the request body or END_STREAM. The caller drives
    /// [`Http3GrpcStream::send_message`] / `finish` / `recv_response` /
    /// `recv_body_and_trailers` to exercise client-streaming and bidirectional
    /// gRPC over the HTTP/3 frontend — in particular, to send a request message
    /// and receive the server's response BEFORE half-closing the request.
    pub async fn open_grpc_stream(
        &self,
        url: &str,
    ) -> Result<Http3GrpcStream, Box<dyn std::error::Error + Send + Sync>> {
        self.open_grpc_stream_with_content_type(url, "application/grpc")
            .await
    }

    /// Open an H3 gRPC-Web request stream whose response can be consumed one
    /// DATA chunk at a time. Functional cadence/cancellation tests use this
    /// instead of the ordinary buffered [`Self::get_with_options`] helper.
    pub async fn open_grpc_web_stream(
        &self,
        url: &str,
        content_type: &str,
    ) -> Result<Http3GrpcStream, Box<dyn std::error::Error + Send + Sync>> {
        self.open_grpc_stream_with_content_type(url, content_type)
            .await
    }

    async fn open_grpc_stream_with_content_type(
        &self,
        url: &str,
        content_type: &str,
    ) -> Result<Http3GrpcStream, Box<dyn std::error::Error + Send + Sync>> {
        let parsed: http::Uri = url.parse()?;
        let host = parsed.host().ok_or("missing host in url")?.to_string();
        let port = parsed.port_u16().unwrap_or(443);
        let addr = resolve_loopback(&host, port)?;
        let server_name = parsed.host().unwrap_or("localhost").to_string();
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
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        // The gateway synthesizes `te: trailers` toward the backend itself, so
        // the client only needs the selected native/gRPC-Web content type.
        let req = Request::builder()
            .method(http::Method::POST)
            .uri(url)
            .header(http::header::CONTENT_TYPE, content_type)
            .body(())
            .map_err(|e| format!("build request: {e}"))?;
        let stream = tokio::time::timeout(Duration::from_secs(15), send_request.send_request(req))
            .await
            .map_err(|_| "send_request timed out")?
            .map_err(|e| format!("send_request: {e}"))?;
        Ok(Http3GrpcStream {
            stream,
            _send_request: send_request,
            driver_task,
        })
    }

    /// Open a plain HTTP/3 request stream and return it before response body
    /// drain. Used by slow-client / disconnect latency tests that must hold
    /// QUIC flow-control credit instead of buffering the full body eagerly.
    pub async fn open_response_stream(
        &self,
        url: &str,
        options: GetOptions,
    ) -> Result<Http3ResponseStream, Box<dyn std::error::Error + Send + Sync>> {
        let parsed: http::Uri = url.parse()?;
        let host = parsed.host().ok_or("missing host in url")?.to_string();
        let port = parsed.port_u16().unwrap_or(443);
        let addr = resolve_loopback(&host, port)?;
        let server_name = parsed.host().unwrap_or("localhost").to_string();
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
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let mut req_builder = Request::builder().method(options.method.clone()).uri(url);
        match &options.host_header {
            HostHeader::Auto => {}
            HostHeader::Explicit(value) => {
                req_builder = req_builder.header(http::header::HOST, value.as_str());
            }
            HostHeader::SameAsAuthority => {
                let host_header = format!("{host}:{port}");
                req_builder = req_builder.header(http::header::HOST, host_header);
            }
        }
        for (name, value) in &options.headers {
            req_builder = req_builder.header(name.as_str(), value.as_str());
        }
        let req = req_builder
            .body(())
            .map_err(|e| format!("build request: {e}"))?;
        let mut stream =
            tokio::time::timeout(Duration::from_secs(15), send_request.send_request(req))
                .await
                .map_err(|_| "send_request timed out")?
                .map_err(|e| format!("send_request: {e}"))?;
        if !options.body.is_empty() {
            stream
                .send_data(options.body.clone())
                .await
                .map_err(|e| format!("send request body: {e}"))?;
        }
        stream
            .finish()
            .await
            .map_err(|e| format!("finish request body: {e}"))?;
        Ok(Http3ResponseStream {
            stream,
            _send_request: send_request,
            driver_task,
        })
    }

    /// Open an RFC 9220 WebSocket-over-HTTP/3 Extended CONNECT stream.
    ///
    /// The returned stream works with raw WebSocket frames in HTTP/3 DATA
    /// frames. Test helpers below encode client frames unmasked by default,
    /// matching RFC 9220 §5.
    pub async fn websocket(
        &self,
        url: &str,
        options: WebSocketOptions,
    ) -> Result<Http3WebSocket, Box<dyn std::error::Error + Send + Sync>> {
        let parsed: http::Uri = url.parse()?;
        let host = parsed.host().ok_or("missing host in url")?.to_string();
        let port = parsed.port_u16().unwrap_or(443);
        let addr = resolve_loopback(&host, port)?;

        let server_name = parsed.host().unwrap_or("localhost").to_string();
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
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let mut req_builder = Request::builder()
            .method(http::Method::CONNECT)
            .version(http::Version::HTTP_3)
            .uri(url)
            .header("sec-websocket-version", "13")
            .header("user-agent", "ferrum-test-h3-ws/1.0");
        if !options.subprotocols.is_empty() {
            req_builder =
                req_builder.header("sec-websocket-protocol", options.subprotocols.join(", "));
        }
        for (name, value) in &options.headers {
            req_builder = req_builder.header(name.as_str(), value.as_str());
        }

        let mut req = req_builder
            .body(())
            .map_err(|e| format!("build request: {e}"))?;
        req.extensions_mut().insert(h3::ext::Protocol::WEB_SOCKET);

        let mut stream =
            tokio::time::timeout(Duration::from_secs(15), send_request.send_request(req))
                .await
                .map_err(|_| "send_request timed out")?
                .map_err(|e| format!("send_request: {e}"))?;

        let resp = tokio::time::timeout(Duration::from_secs(15), stream.recv_response())
            .await
            .map_err(|_| "recv_response timed out")?
            .map_err(|e| format!("recv_response: {e}"))?;
        let status = resp.status();
        let headers = resp.headers().clone();

        Ok(Http3WebSocket {
            stream,
            _send_request: send_request,
            driver_task,
            read_buf: Vec::new(),
            status,
            headers,
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
    /// Terminal H3 trailers (e.g. gRPC `grpc-status` / `grpc-message`), if the
    /// backend/gateway sent a TRAILERS frame. `None` for a trailers-only or
    /// no-trailer response.
    pub trailers: Option<HeaderMap>,
    /// Terminal response-body error, kept separate from the response head so
    /// tests can distinguish a clean short response from RESET_STREAM or a
    /// bounded body-read timeout.
    pub body_error: Option<String>,
}

impl Http3Response {
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body_bytes).to_string()
    }

    /// Read a terminal trailer value (TRAILERS frame) by name.
    pub fn trailer(&self, name: &str) -> Option<&str> {
        self.trailers
            .as_ref()
            .and_then(|t| t.get(name))
            .and_then(|v| v.to_str().ok())
    }

    /// gRPC terminal status, read from the TRAILERS frame first (normal gRPC
    /// responses) then the initial headers (Trailers-Only responses). `None`
    /// when neither carries `grpc-status`.
    pub fn grpc_status(&self) -> Option<i32> {
        self.trailer("grpc-status")
            .or_else(|| {
                self.headers
                    .get("grpc-status")
                    .and_then(|v| v.to_str().ok())
            })
            .and_then(|s| s.trim().parse::<i32>().ok())
    }

    /// gRPC status message (`grpc-message`), from trailers then initial headers.
    pub fn grpc_message(&self) -> Option<String> {
        self.trailer("grpc-message")
            .or_else(|| {
                self.headers
                    .get("grpc-message")
                    .and_then(|v| v.to_str().ok())
            })
            .map(|s| s.to_string())
    }
}

/// A client-driven H3 gRPC request stream for exercising client-streaming and
/// bidirectional RPCs: send request messages, receive the response, and control
/// exactly when the request half-closes. Returned by
/// [`Http3Client::open_grpc_stream`].
pub struct Http3GrpcStream {
    stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver_task: JoinHandle<()>,
}

impl Http3GrpcStream {
    /// Send caller-supplied request DATA without closing the request stream.
    pub async fn send_raw_data(
        &mut self,
        data: impl Into<Bytes>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tokio::time::timeout(Duration::from_secs(15), self.stream.send_data(data.into()))
            .await
            .map_err(|_| "send_data timed out")?
            .map_err(|e| format!("send_data: {e}"))?;
        Ok(())
    }

    /// Send one length-prefixed gRPC message as a DATA frame WITHOUT closing the
    /// request stream (no END_STREAM), so a backend can be observed reacting to
    /// it before the client half-closes.
    pub async fn send_message(
        &mut self,
        message: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut framed = Vec::with_capacity(message.len() + 5);
        framed.push(0); // uncompressed flag
        framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
        framed.extend_from_slice(message);
        tokio::time::timeout(
            Duration::from_secs(15),
            self.stream.send_data(Bytes::from(framed)),
        )
        .await
        .map_err(|_| "send_data timed out")?
        .map_err(|e| format!("send_data: {e}"))?;
        Ok(())
    }

    /// Half-close the request stream (send END_STREAM).
    pub async fn finish(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tokio::time::timeout(Duration::from_secs(15), self.stream.finish())
            .await
            .map_err(|_| "finish timed out")?
            .map_err(|e| format!("finish: {e}"))?;
        Ok(())
    }

    /// Await the response headers (status + header map). Used to prove the
    /// backend responded BEFORE the client half-closed.
    pub async fn recv_response(
        &mut self,
    ) -> Result<(StatusCode, HeaderMap), Box<dyn std::error::Error + Send + Sync>> {
        let resp = tokio::time::timeout(Duration::from_secs(15), self.stream.recv_response())
            .await
            .map_err(|_| "recv_response timed out")?
            .map_err(|e| format!("recv_response: {e}"))?;
        Ok((resp.status(), resp.headers().clone()))
    }

    /// Receive the next response DATA chunk without draining to EOF.
    pub async fn recv_data(
        &mut self,
    ) -> Result<Option<Bytes>, Box<dyn std::error::Error + Send + Sync>> {
        let Some(mut chunk) =
            tokio::time::timeout(Duration::from_secs(15), self.stream.recv_data())
                .await
                .map_err(|_| "recv_data timed out")?
                .map_err(|e| format!("recv_data: {e}"))?
        else {
            return Ok(None);
        };
        let mut data = Vec::new();
        while chunk.has_remaining() {
            let take = chunk.chunk().to_vec();
            data.extend_from_slice(&take);
            chunk.advance(take.len());
        }
        Ok(Some(Bytes::from(data)))
    }

    /// Receive terminal HTTP/3 trailers after response DATA reaches EOF.
    pub async fn recv_trailers(
        &mut self,
    ) -> Result<Option<HeaderMap>, Box<dyn std::error::Error + Send + Sync>> {
        let trailers = tokio::time::timeout(Duration::from_secs(15), self.stream.recv_trailers())
            .await
            .map_err(|_| "recv_trailers timed out")?
            .map_err(|e| format!("recv_trailers: {e}"))?;
        Ok(trailers)
    }

    /// Drain the response body (concatenated DATA) and the gRPC trailers.
    pub async fn recv_body_and_trailers(
        &mut self,
    ) -> Result<(Bytes, HeaderMap), Box<dyn std::error::Error + Send + Sync>> {
        let mut body = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(15), self.stream.recv_data()).await {
                Ok(Ok(Some(mut chunk))) => {
                    while chunk.has_remaining() {
                        let take = chunk.chunk().to_vec();
                        body.extend_from_slice(&take);
                        chunk.advance(take.len());
                    }
                }
                Ok(Ok(None)) => break,
                Ok(Err(e)) => return Err(format!("recv_data: {e}").into()),
                Err(_) => return Err("recv_data timed out".into()),
            }
        }
        let trailers = tokio::time::timeout(Duration::from_secs(15), self.stream.recv_trailers())
            .await
            .map_err(|_| "recv_trailers timed out")?
            .map_err(|e| format!("recv_trailers: {e}"))?
            .unwrap_or_default();
        Ok((Bytes::from(body), trailers))
    }
}

impl Drop for Http3GrpcStream {
    fn drop(&mut self) {
        self.driver_task.abort();
    }
}

/// A client-driven plain HTTP/3 response stream for slow-client and disconnect
/// tests. Returned by [`Http3Client::open_response_stream`].
pub struct Http3ResponseStream {
    stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver_task: JoinHandle<()>,
}

impl Http3ResponseStream {
    /// Await response headers.
    pub async fn recv_response(
        &mut self,
    ) -> Result<(StatusCode, HeaderMap), Box<dyn std::error::Error + Send + Sync>> {
        let resp = tokio::time::timeout(Duration::from_secs(15), self.stream.recv_response())
            .await
            .map_err(|_| "recv_response timed out")?
            .map_err(|e| format!("recv_response: {e}"))?;
        Ok((resp.status(), resp.headers().clone()))
    }

    /// Receive the next response DATA chunk without draining to EOF.
    pub async fn recv_data(
        &mut self,
    ) -> Result<Option<Bytes>, Box<dyn std::error::Error + Send + Sync>> {
        let Some(mut chunk) =
            tokio::time::timeout(Duration::from_secs(15), self.stream.recv_data())
                .await
                .map_err(|_| "recv_data timed out")?
                .map_err(|e| format!("recv_data: {e}"))?
        else {
            return Ok(None);
        };
        let mut data = Vec::new();
        while chunk.has_remaining() {
            let take = chunk.chunk().to_vec();
            data.extend_from_slice(&take);
            chunk.advance(take.len());
        }
        Ok(Some(Bytes::from(data)))
    }

    /// Drain remaining DATA frames to EOF.
    pub async fn drain_body(&mut self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let mut total = 0usize;
        loop {
            match self.recv_data().await? {
                Some(chunk) => total = total.saturating_add(chunk.len()),
                None => return Ok(total),
            }
        }
    }
}

impl Drop for Http3ResponseStream {
    fn drop(&mut self) {
        self.driver_task.abort();
    }
}

/// Options for [`Http3Client::websocket`].
#[derive(Debug, Default, Clone)]
pub struct WebSocketOptions {
    pub subprotocols: Vec<String>,
    pub headers: Vec<(String, String)>,
}

impl WebSocketOptions {
    pub fn subprotocols<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.subprotocols = values.into_iter().map(Into::into).collect();
        self
    }
}

/// Minimal RFC 9220 WebSocket stream over HTTP/3 DATA frames.
pub struct Http3WebSocket {
    stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver_task: JoinHandle<()>,
    read_buf: Vec<u8>,
    pub status: StatusCode,
    pub headers: HeaderMap,
}

impl Http3WebSocket {
    pub async fn send_text(
        &mut self,
        text: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_frame(0x1, text.as_bytes(), false).await
    }

    pub async fn send_masked_text(
        &mut self,
        text: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_frame(0x1, text.as_bytes(), true).await
    }

    pub async fn send_binary(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_frame(0x2, bytes, false).await
    }

    /// Send one unmasked RFC 9220 data/control frame with an explicit FIN bit.
    /// Test callers use opcode `0x1`/`0x2` for the first fragment, `0x0` for a
    /// continuation, and `0x9`/`0xA` for interleaved Ping/Pong frames.
    pub async fn send_fragment(
        &mut self,
        opcode: u8,
        payload: &[u8],
        is_final: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_frame_with_fin(opcode, payload, false, is_final)
            .await
    }

    pub async fn send_close(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_frame(0x8, &[], false).await?;
        let _ = self.stream.finish().await;
        Ok(())
    }

    pub async fn recv_text(&mut self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        match self.recv_frame().await? {
            H3WebSocketFrame::Text(text) => Ok(text),
            other => Err(format!("expected text frame, got {other:?}").into()),
        }
    }

    /// Drain a non-101/non-200 response body from a WebSocket CONNECT attempt.
    /// Failed H3 upgrades return regular DATA bytes, not WebSocket frames.
    pub async fn recv_body_bytes(
        &mut self,
    ) -> Result<Bytes, Box<dyn std::error::Error + Send + Sync>> {
        let mut body = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(15), self.stream.recv_data()).await {
                Ok(Ok(Some(mut chunk))) => {
                    while chunk.has_remaining() {
                        let take = chunk.chunk().to_vec();
                        body.extend_from_slice(&take);
                        chunk.advance(take.len());
                    }
                }
                Ok(Ok(None)) => break,
                Ok(Err(e)) => return Err(format!("websocket response body recv_data: {e}").into()),
                Err(_) => return Err("websocket response body recv_data timed out".into()),
            }
        }
        Ok(Bytes::from(body))
    }

    pub async fn recv_body_text(
        &mut self,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let body = self.recv_body_bytes().await?;
        Ok(String::from_utf8_lossy(&body).to_string())
    }

    pub async fn recv_frame(
        &mut self,
    ) -> Result<H3WebSocketFrame, Box<dyn std::error::Error + Send + Sync>> {
        loop {
            if let Some(frame) = try_parse_ws_frame(&mut self.read_buf)? {
                return Ok(frame);
            }
            let mut chunk = tokio::time::timeout(Duration::from_secs(15), self.stream.recv_data())
                .await
                .map_err(|_| "websocket recv_data timed out")?
                .map_err(|e| format!("websocket recv_data: {e}"))?
                .ok_or("websocket stream ended before next frame")?;
            while chunk.has_remaining() {
                let bytes = chunk.copy_to_bytes(chunk.remaining());
                self.read_buf.extend_from_slice(&bytes);
            }
        }
    }

    async fn send_frame(
        &mut self,
        opcode: u8,
        payload: &[u8],
        masked: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_frame_with_fin(opcode, payload, masked, true)
            .await
    }

    async fn send_frame_with_fin(
        &mut self,
        opcode: u8,
        payload: &[u8],
        masked: bool,
        is_final: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let frame = encode_ws_frame(opcode, payload, masked, is_final);
        tokio::time::timeout(
            Duration::from_secs(15),
            self.stream.send_data(Bytes::from(frame)),
        )
        .await
        .map_err(|_| "websocket send_data timed out")?
        .map_err(|e| format!("websocket send_data: {e}"))?;
        Ok(())
    }
}

impl Drop for Http3WebSocket {
    fn drop(&mut self) {
        self.driver_task.abort();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3WebSocketFrame {
    Text(String),
    Binary(Vec<u8>),
    Close(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Other { opcode: u8, payload: Vec<u8> },
}

fn encode_ws_frame(opcode: u8, payload: &[u8], masked: bool, is_final: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + payload.len());
    out.push((if is_final { 0x80 } else { 0 }) | (opcode & 0x0f));
    let mask_bit = if masked { 0x80 } else { 0 };
    match payload.len() {
        len @ 0..=125 => out.push(mask_bit | len as u8),
        len @ 126..=65_535 => {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    if masked {
        let mask = [0x12, 0x34, 0x56, 0x78];
        out.extend_from_slice(&mask);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    } else {
        out.extend_from_slice(payload);
    }
    out
}

fn try_parse_ws_frame(
    buf: &mut Vec<u8>,
) -> Result<Option<H3WebSocketFrame>, Box<dyn std::error::Error + Send + Sync>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let opcode = buf[0] & 0x0f;
    let masked = (buf[1] & 0x80) != 0;
    let len7 = buf[1] & 0x7f;
    let mut offset = 2usize;
    let payload_len = match len7 {
        0..=125 => len7 as usize,
        126 => {
            if buf.len() < offset + 2 {
                return Ok(None);
            }
            let len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
            offset += 2;
            len
        }
        127 => {
            if buf.len() < offset + 8 {
                return Ok(None);
            }
            let len = u64::from_be_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ]);
            offset += 8;
            usize::try_from(len).map_err(|_| "websocket frame too large for test client")?
        }
        _ => unreachable!(),
    };

    let mask = if masked {
        if buf.len() < offset + 4 {
            return Ok(None);
        }
        let mask = [
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ];
        offset += 4;
        Some(mask)
    } else {
        None
    };

    if buf.len() < offset + payload_len {
        return Ok(None);
    }
    let mut payload = buf[offset..offset + payload_len].to_vec();
    if let Some(mask) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    buf.drain(..offset + payload_len);

    let frame = match opcode {
        0x1 => H3WebSocketFrame::Text(String::from_utf8(payload)?),
        0x2 => H3WebSocketFrame::Binary(payload),
        0x8 => H3WebSocketFrame::Close(payload),
        0x9 => H3WebSocketFrame::Ping(payload),
        0xA => H3WebSocketFrame::Pong(payload),
        _ => H3WebSocketFrame::Other { opcode, payload },
    };
    Ok(Some(frame))
}

/// Per-request overrides for `Http3Client::get_with_options`.
#[derive(Debug, Clone)]
pub struct GetOptions {
    pub method: Method,
    pub host_header: HostHeader,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl Default for GetOptions {
    fn default() -> Self {
        Self {
            method: Method::GET,
            host_header: HostHeader::Auto,
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }
}

impl GetOptions {
    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body(mut self, body: Bytes) -> Self {
        self.body = body;
        self
    }
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

    #[test]
    fn websocket_frame_encoder_uses_unmasked_h3_shape_by_default() {
        let frame = encode_ws_frame(0x1, b"hi", false, true);
        assert_eq!(frame, vec![0x81, 0x02, b'h', b'i']);
    }

    #[test]
    fn websocket_frame_parser_unmasks_client_frames_for_gap_test() {
        let mut frame = encode_ws_frame(0x1, b"masked", true, true);
        let parsed = try_parse_ws_frame(&mut frame)
            .expect("parse")
            .expect("frame");
        assert_eq!(parsed, H3WebSocketFrame::Text("masked".to_string()));
        assert!(frame.is_empty());
    }
}
