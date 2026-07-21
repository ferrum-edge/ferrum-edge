//! In-process fake HTTP servers for the GCP Secret Manager and Azure Key Vault
//! data planes, built on `wiremock`. No Docker, no real cloud — the real
//! provider SDK clients make real HTTP calls to these fakes.
//!
//! GCP has no official Secret Manager emulator and Azure Key Vault has no
//! local emulator that the SDK can target, so deterministic `wiremock` fakes
//! that speak each provider's exact wire shape are the right tool here.

#![allow(dead_code)] // helpers are used selectively per feature-gated module

#[cfg(feature = "secrets-gcp")]
pub use gcp::GcpSecretManagerFake;

#[cfg(feature = "secrets-azure")]
pub use azure::AzureKeyVaultFake;

// ---------------------------------------------------------------------------
// GCP Secret Manager fake (REST: `GET /v1/{name}:access`)
// ---------------------------------------------------------------------------
#[cfg(feature = "secrets-gcp")]
mod gcp {
    use base64::Engine;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A fake GCP Secret Manager REST endpoint. Point the real client at it via
    /// `FERRUM_GCP_SECRET_MANAGER_ENDPOINT = fake.endpoint()`.
    pub struct GcpSecretManagerFake {
        pub server: MockServer,
    }

    impl GcpSecretManagerFake {
        pub async fn start() -> Self {
            Self {
                server: MockServer::start().await,
            }
        }

        /// Base URL for `FERRUM_GCP_SECRET_MANAGER_ENDPOINT`.
        pub fn endpoint(&self) -> String {
            self.server.uri()
        }

        fn access_path_regex(resource_name: &str) -> String {
            format!("^/v1/{}:access$", regex::escape(resource_name))
        }

        /// `accessSecretVersion(resource_name)` returns `value` bytes. The bytes
        /// are base64-encoded (standard, padded) exactly as Google's REST/JSON
        /// mapping serializes proto `bytes`.
        pub async fn mock_access_success(&self, resource_name: &str, value: &[u8]) {
            let body = serde_json::json!({
                "name": resource_name,
                "payload": {
                    "data": base64::engine::general_purpose::STANDARD.encode(value),
                },
            });
            Mock::given(method("GET"))
                .and(path_regex(Self::access_path_regex(resource_name)))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&self.server)
                .await;
        }

        /// Success response with no `payload` field (drives the "no payload"
        /// production error).
        pub async fn mock_access_no_payload(&self, resource_name: &str) {
            let body = serde_json::json!({ "name": resource_name });
            Mock::given(method("GET"))
                .and(path_regex(Self::access_path_regex(resource_name)))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&self.server)
                .await;
        }

        /// Success response whose payload bytes are not valid UTF-8.
        pub async fn mock_access_invalid_utf8(&self, resource_name: &str) {
            let invalid_utf8: &[u8] = &[0xff, 0xfe, 0xfd, 0x80];
            self.mock_access_with_raw_payload(resource_name, invalid_utf8)
                .await;
        }

        /// Success response whose payload `data` is the base64 of `raw_bytes`.
        pub async fn mock_access_with_raw_payload(&self, resource_name: &str, raw_bytes: &[u8]) {
            let body = serde_json::json!({
                "name": resource_name,
                "payload": {
                    "data": base64::engine::general_purpose::STANDARD.encode(raw_bytes),
                },
            });
            Mock::given(method("GET"))
                .and(path_regex(Self::access_path_regex(resource_name)))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&self.server)
                .await;
        }

        /// Error status (e.g. 404 NOT_FOUND, 403 PERMISSION_DENIED) with a
        /// Google-style error envelope.
        pub async fn mock_access_status(
            &self,
            resource_name: &str,
            status: u16,
            grpc_status: &str,
        ) {
            let body = serde_json::json!({
                "error": {
                    "code": status,
                    "message": format!("{grpc_status} for {resource_name}"),
                    "status": grpc_status,
                },
            });
            Mock::given(method("GET"))
                .and(path_regex(Self::access_path_regex(resource_name)))
                .respond_with(ResponseTemplate::new(status).set_body_json(body))
                .mount(&self.server)
                .await;
        }

        /// Successful response delayed by `delay` (drives the fetch-timeout
        /// path without ever completing within a 1s budget).
        pub async fn mock_access_delayed(
            &self,
            resource_name: &str,
            value: &[u8],
            delay: std::time::Duration,
        ) {
            let body = serde_json::json!({
                "name": resource_name,
                "payload": {
                    "data": base64::engine::general_purpose::STANDARD.encode(value),
                },
            });
            Mock::given(method("GET"))
                .and(path_regex(Self::access_path_regex(resource_name)))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(body)
                        .set_delay(delay),
                )
                .mount(&self.server)
                .await;
        }

        /// The exact request paths the client sent (path + query), for asserting
        /// the configured resource name is forwarded unchanged.
        pub async fn recorded_paths(&self) -> Vec<String> {
            self.server
                .received_requests()
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|r| {
                    let mut p = r.url.path().to_string();
                    if let Some(q) = r.url.query() {
                        p.push('?');
                        p.push_str(q);
                    }
                    p
                })
                .collect()
        }
    }
}

// ---------------------------------------------------------------------------
// Azure Key Vault fake (`GET /secrets/{name}/?api-version=...`)
// ---------------------------------------------------------------------------
#[cfg(feature = "secrets-azure")]
mod azure {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A fake Azure Key Vault secrets data plane. Build a secret reference URL
    /// with [`AzureKeyVaultFake::secret_url`] and resolve it via
    /// `AzureCredentials::from_static_token(..)`.
    pub struct AzureKeyVaultFake {
        pub server: MockServer,
    }

    impl AzureKeyVaultFake {
        pub async fn start() -> Self {
            Self {
                server: MockServer::start().await,
            }
        }

        /// Reference URL for `FERRUM_<KEY>_AZURE` / direct fetch. Uses the fake's
        /// real host:port (so the port-preservation fix is exercised end to end).
        pub fn secret_url(&self, name: &str) -> String {
            format!("{}/secrets/{}", self.server.uri(), name)
        }

        /// Versioned reference URL (`/secrets/<name>/<version>`).
        pub fn secret_version_url(&self, name: &str, version: &str) -> String {
            format!("{}/secrets/{}/{}", self.server.uri(), name, version)
        }

        fn secret_path_regex(name: &str) -> String {
            // The SDK requests `/secrets/{name}/` (empty version segment) plus an
            // `?api-version=` query, which `path_regex` ignores.
            format!("^/secrets/{}/?$", regex::escape(name))
        }

        fn secret_version_path_regex(name: &str, version: &str) -> String {
            format!(
                "^/secrets/{}/{}/?$",
                regex::escape(name),
                regex::escape(version)
            )
        }

        /// Simple success: returns the secret on the first request regardless of
        /// auth. Robust and sufficient for the URL-parse / port / value paths.
        pub async fn mock_secret(&self, name: &str, value: &str) {
            Mock::given(method("GET"))
                .and(path_regex(Self::secret_path_regex(name)))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(self.secret_body(name, value)),
                )
                .mount(&self.server)
                .await;
        }

        /// Success for a pinned version request. Only matches
        /// `/secrets/{name}/{version}` so a latest-only mock cannot satisfy it.
        pub async fn mock_secret_version(&self, name: &str, version: &str, value: &str) {
            Mock::given(method("GET"))
                .and(path_regex(Self::secret_version_path_regex(name, version)))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(self.secret_body_versioned(name, version, value)),
                )
                .mount(&self.server)
                .await;
        }

        /// 200 response whose body has no `value` field.
        pub async fn mock_secret_no_value(&self, name: &str) {
            let body =
                serde_json::json!({ "id": format!("{}/secrets/{}/v1", self.server.uri(), name) });
            Mock::given(method("GET"))
                .and(path_regex(Self::secret_path_regex(name)))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&self.server)
                .await;
        }

        /// 200 response with a non-JSON body (drives the parse error).
        pub async fn mock_secret_malformed(&self, name: &str) {
            Mock::given(method("GET"))
                .and(path_regex(Self::secret_path_regex(name)))
                .respond_with(ResponseTemplate::new(200).set_body_string("this is not json"))
                .mount(&self.server)
                .await;
        }

        /// Arbitrary error status (e.g. 404).
        pub async fn mock_secret_status(&self, name: &str, status: u16) {
            Mock::given(method("GET"))
                .and(path_regex(Self::secret_path_regex(name)))
                .respond_with(
                    ResponseTemplate::new(status).set_body_json(serde_json::json!({
                        "error": { "code": "SecretNotFound", "message": "secret not found" },
                    })),
                )
                .mount(&self.server)
                .await;
        }

        /// Successful response delayed by `delay` (drives the fetch-timeout path).
        pub async fn mock_secret_delayed(
            &self,
            name: &str,
            value: &str,
            delay: std::time::Duration,
        ) {
            Mock::given(method("GET"))
                .and(path_regex(Self::secret_path_regex(name)))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(self.secret_body(name, value))
                        .set_delay(delay),
                )
                .mount(&self.server)
                .await;
        }

        fn secret_body(&self, name: &str, value: &str) -> serde_json::Value {
            self.secret_body_versioned(name, "0123456789abcdef", value)
        }

        fn secret_body_versioned(
            &self,
            name: &str,
            version: &str,
            value: &str,
        ) -> serde_json::Value {
            serde_json::json!({
                "value": value,
                "id": format!("{}/secrets/{}/{}", self.server.uri(), name, version),
                "attributes": { "enabled": true },
            })
        }
    }
}
