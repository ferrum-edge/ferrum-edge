//! HTTP/1.1 client tailored for scripted-backend tests.
//!
//! Wraps `reqwest` with a TLS-verify-off knob and a short default timeout.
//! `ClientResponse` captures status + headers + body so callers can assert
//! without chaining `await`s.

use reqwest::{Client, ClientBuilder};
use std::time::Duration;

/// A test HTTP/1.1 client. Wrap a `reqwest::Client` so call sites don't
/// need to pick between `Client::new`, `Client::builder`, tls settings, etc.
pub struct Http1Client {
    inner: Client,
}

impl Http1Client {
    /// Build a client that accepts **any** TLS certificate. Use for pointing
    /// at the gateway with the harness's self-signed frontend cert.
    pub fn insecure() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let inner = ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .http1_only()
            // Default timeout keeps a hung test from blocking forever.
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { inner })
    }

    /// Build a client that trusts only the given CA PEM.
    pub fn with_ca(ca_pem: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let cert = reqwest::Certificate::from_pem(ca_pem.as_bytes())?;
        let inner = ClientBuilder::new()
            .add_root_certificate(cert)
            .http1_only()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { inner })
    }

    /// Access the underlying reqwest client (for advanced uses).
    pub fn as_reqwest(&self) -> &Client {
        &self.inner
    }

    /// `GET <url>`.
    pub async fn get(&self, url: &str) -> Result<ClientResponse, reqwest::Error> {
        let resp = self.inner.get(url).send().await?;
        ClientResponse::from(resp).await
    }

    /// `POST <url>` with a JSON body.
    pub async fn post_json<B: serde::Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<ClientResponse, reqwest::Error> {
        let resp = self.inner.post(url).json(body).send().await?;
        ClientResponse::from(resp).await
    }

    /// Generic builder escape hatch.
    pub fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        self.inner.request(method, url)
    }
}

/// A buffered HTTP response captured eagerly.
#[derive(Debug, Clone)]
pub struct ClientResponse {
    pub status: reqwest::StatusCode,
    pub headers: reqwest::header::HeaderMap,
    pub body_bytes: bytes::Bytes,
}

impl ClientResponse {
    async fn from(resp: reqwest::Response) -> Result<Self, reqwest::Error> {
        let status = resp.status();
        let headers = resp.headers().clone();
        let body_bytes = resp.bytes().await?;
        Ok(Self {
            status,
            headers,
            body_bytes,
        })
    }

    /// Decode the body as UTF-8 (lossy).
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body_bytes).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_client_builds() {
        Http1Client::insecure().expect("client");
    }
}
