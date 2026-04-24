//! HTTP/2 client for scripted-backend tests.
//!
//! Wraps `reqwest` in h2-over-TLS mode. Reqwest's HTTP/2 stack negotiates
//! via ALPN, so this client must be used against a TLS frontend; for h2c
//! (plain HTTP/2 with prior knowledge) use
//! [`Http2Client::h2c_prior_knowledge`] or the `h2` crate's raw client
//! directly (see the integration smoke tests for examples).

use super::http1::ClientResponse;
use reqwest::{Client, ClientBuilder};
use std::time::Duration;

/// A test HTTP/2 client. Like `Http1Client` but negotiates HTTP/2 via ALPN
/// when talking to a TLS frontend, or via prior-knowledge against a plain
/// h2c backend.
pub struct Http2Client {
    inner: Client,
}

impl Http2Client {
    /// Build a client that accepts **any** TLS certificate and lets ALPN
    /// pick HTTP/2 when the server advertises it.
    pub fn insecure() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let inner = ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { inner })
    }

    /// Build a client that uses h2c (plain HTTP/2 with prior knowledge)
    /// against a plaintext listener.
    pub fn h2c_prior_knowledge() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let inner = ClientBuilder::new()
            .http2_prior_knowledge()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { inner })
    }

    /// Access the underlying reqwest client.
    pub fn as_reqwest(&self) -> &Client {
        &self.inner
    }

    /// `GET <url>`.
    pub async fn get(&self, url: &str) -> Result<ClientResponse, reqwest::Error> {
        let resp = self.inner.get(url).send().await?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body_bytes = resp.bytes().await?;
        Ok(ClientResponse {
            status,
            headers,
            body_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_h2_client_builds() {
        Http2Client::insecure().expect("client");
    }
}
