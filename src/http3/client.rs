//! HTTP/3 client for proxying requests to HTTP/3 backends

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Buf;
use http::Request;
use quinn::crypto::rustls::QuicClientConfig;
use tracing::debug;

use crate::config::types::Proxy;

/// HTTP/3 client for connecting to backend services over QUIC.
#[derive(Clone)]
pub struct Http3Client {
    endpoint: quinn::Endpoint,
}

impl Http3Client {
    /// Create a new HTTP/3 client with the given TLS configuration.
    ///
    /// The `tls_config` must have ALPN protocols set (typically `b"h3"` for HTTP/3).
    /// The crypto provider must be installed before calling this function
    /// (typically once at application startup via `rustls::crypto::ring::default_provider().install_default()`).
    pub fn new(tls_config: Arc<rustls::ClientConfig>) -> Result<Self, anyhow::Error> {
        // Convert rustls config to QUIC-compatible config.
        // This validates that the config has TLS 1.3 support with an appropriate
        // initial cipher suite (AES-128-GCM-SHA256).
        let quic_client_config = QuicClientConfig::try_from(tls_config)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC client config (ensure TLS 1.3 cipher suites are available): {}", e))?;

        let client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

        // Bind to any available local UDP port
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    /// Send an HTTP/3 request to the specified backend.
    pub async fn request(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: Vec<(http::header::HeaderName, http::header::HeaderValue)>,
        body: bytes::Bytes,
    ) -> Result<(u16, Vec<u8>, std::collections::HashMap<String, String>), anyhow::Error> {
        // Parse URL to get host and port
        let uri: http::Uri = backend_url.parse()
            .map_err(|e| anyhow::anyhow!("Invalid backend URL: {}", e))?;

        let host = uri.host().unwrap_or(&proxy.backend_host);
        let port = uri.port_u16().unwrap_or(proxy.backend_port);
        let path_and_query = uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        // Resolve the backend address
        let addr = resolve_backend_addr(host, port).await?;

        debug!(
            "HTTP/3 client connecting to {}:{} (resolved: {})",
            host, port, addr
        );

        // Establish QUIC connection
        let connection = self
            .endpoint
            .connect(addr, host)?
            .await
            .map_err(|e| anyhow::anyhow!("QUIC connection failed: {}", e))?;

        // Create HTTP/3 connection
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;

        // Drive the connection in background. The driver future completes when
        // the connection is closed, so we spawn it and let it clean up naturally.
        tokio::spawn(async move {
            let err = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
            debug!("HTTP/3 connection driver closed: {}", err);
        });

        // Build the request with the correct URI (path only, not full URL)
        let req_method: http::Method = method.parse().unwrap_or(http::Method::GET);

        let mut req_builder = Request::builder()
            .method(req_method)
            .uri(path_and_query);

        // Add headers, skipping connection-level headers not valid in HTTP/3
        for (name, value) in &headers {
            match name.as_str() {
                // These are hop-by-hop headers from HTTP/1.1, not valid in HTTP/3
                "connection" | "transfer-encoding" | "keep-alive" | "upgrade" => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(())?;

        // Send request
        let mut stream = send_request.send_request(req).await?;

        // Send body if present
        if !body.is_empty() {
            stream.send_data(body).await?;
        }
        stream.finish().await?;

        // Receive response
        let response = stream.recv_response().await?;
        let status = response.status().as_u16();

        // Collect response headers
        let mut response_headers = std::collections::HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                response_headers.insert(name.as_str().to_string(), value_str.to_string());
            }
        }

        // Collect response body
        let mut response_body = Vec::new();
        while let Some(chunk) = stream.recv_data().await? {
            response_body.extend_from_slice(chunk.chunk());
        }

        Ok((status, response_body, response_headers))
    }
}

/// Resolve a hostname:port to a SocketAddr.
async fn resolve_backend_addr(host: &str, port: u16) -> Result<SocketAddr, anyhow::Error> {
    // First try parsing as an IP address directly (no DNS needed)
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    // DNS lookup
    let addr = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .map_err(|e| anyhow::anyhow!("DNS resolution failed for {}:{}: {}", host, port, e))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("DNS resolution returned no addresses for {}:{}", host, port))?;

    Ok(addr)
}
