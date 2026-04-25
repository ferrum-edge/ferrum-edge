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
    /// Build a client that accepts **any** TLS certificate and *requires*
    /// HTTP/2.
    ///
    /// Reqwest's default builder lets ALPN downgrade to HTTP/1.1 when the
    /// server doesn't advertise `h2`, which would silently mask H2-only
    /// protocol regressions in tests using this helper. Calling
    /// `http2_prior_knowledge()` disables HTTP/1 entirely on this client,
    /// so any path that ends up speaking H1 fails the connection
    /// instead of completing as H1 — the behavior the PR-486 review
    /// asked for ("require HTTP/2 so protocol regressions fail fast
    /// instead of downgrading").
    pub fn insecure() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let inner = ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .http2_prior_knowledge()
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
    ///
    /// Asserts the response actually came back over HTTP/2. The
    /// `http2_prior_knowledge()` flag on the client builder is supposed
    /// to make this impossible to violate at the wire level, but the
    /// runtime check is cheap insurance against a future builder edit
    /// that would silently let H1 through (the downgrade-mask scenario
    /// flagged in the PR-486 review).
    pub async fn get(&self, url: &str) -> Result<ClientResponse, reqwest::Error> {
        let resp = self.inner.get(url).send().await?;
        assert_eq!(
            resp.version(),
            reqwest::Version::HTTP_2,
            "Http2Client downgraded to {:?} — `http2_prior_knowledge()` \
             should have prevented this; a regression that lets H1 through \
             would mask H2-only protocol bugs",
            resp.version()
        );
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
