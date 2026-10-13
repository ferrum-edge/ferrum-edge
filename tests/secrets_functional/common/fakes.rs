//! In-process fake HTTP servers for the GCP Secret Manager and Azure Key Vault
//! data planes, built on `wiremock`. No Docker, no real cloud — the real
//! provider SDK clients make real HTTP calls to these fakes.
//!
//! GCP has no official Secret Manager emulator and Azure Key Vault has no
//! local emulator that the SDK can target, so deterministic `wiremock` fakes
//! that speak each provider's exact wire shape are the right tool here.
//!
//! The Azure fake is served over TLS: the 1.x Azure SDK refuses bearer auth on
//! non-`https` URLs, and Ferrum refuses `http://` Key Vault references. A
//! per-fake CA and `127.0.0.1` leaf are generated at test time and the client
//! trusts the CA through `FERRUM_TLS_CA_BUNDLE_PATH` (see
//! [`AzureKeyVaultFake::trust_ca`]).

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
// Azure Key Vault fake (`GET /secrets/{name}/?api-version=...`) behind TLS
// ---------------------------------------------------------------------------
#[cfg(feature = "secrets-azure")]
mod azure {
    use std::io::Write;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::common::env::EnvGuard;

    /// A fake Azure Key Vault secrets data plane. `wiremock` serves the wire
    /// shape on plain HTTP; an in-process TLS terminator in front of it is the
    /// endpoint the SDK talks to. Build a secret reference URL with
    /// [`AzureKeyVaultFake::secret_url`], call [`AzureKeyVaultFake::trust_ca`],
    /// and resolve it via `AzureCredentials::from_static_token(..)`.
    pub struct AzureKeyVaultFake {
        /// The plain-HTTP mock behind the TLS terminator. Use it to mount mocks
        /// and to inspect `received_requests()`.
        pub server: MockServer,
        /// `https://127.0.0.1:<port>` of the TLS terminator.
        https_base: String,
        /// PEM file holding this fake's CA certificate.
        ca_bundle: tempfile::NamedTempFile,
        terminator: tokio::task::JoinHandle<()>,
    }

    impl Drop for AzureKeyVaultFake {
        fn drop(&mut self) {
            self.terminator.abort();
        }
    }

    impl AzureKeyVaultFake {
        pub async fn start() -> Self {
            let server = MockServer::start().await;

            // Test CA plus a leaf for 127.0.0.1 / localhost, generated per fake.
            let ca_key =
                KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("fake CA key");
            let mut ca_params =
                CertificateParams::new(Vec::<String>::new()).expect("fake CA params");
            ca_params
                .distinguished_name
                .push(DnType::CommonName, "ferrum azure key vault fake CA");
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca_cert = ca_params.self_signed(&ca_key).expect("fake CA cert");
            let issuer = Issuer::new(ca_params, ca_key);

            let leaf_key =
                KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("fake leaf key");
            // `CertificateParams::new` maps `127.0.0.1` to an IP-address SAN.
            let mut leaf_params =
                CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
                    .expect("fake leaf params");
            leaf_params
                .distinguished_name
                .push(DnType::CommonName, "127.0.0.1");
            leaf_params.is_ca = IsCa::ExplicitNoCa;
            let leaf_cert = leaf_params
                .signed_by(&leaf_key, &issuer)
                .expect("fake leaf cert");

            let mut ca_bundle = tempfile::NamedTempFile::new().expect("fake CA bundle file");
            ca_bundle
                .write_all(ca_cert.pem().as_bytes())
                .expect("write fake CA bundle");
            ca_bundle.flush().expect("flush fake CA bundle");

            let certs: Vec<CertificateDer<'static>> = vec![leaf_cert.der().clone()];
            let key = PrivateKeyDer::from_pem_slice(leaf_key.serialize_pem().as_bytes())
                .expect("parse fake leaf key");
            let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("fake TLS protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("fake TLS server config");
            server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let acceptor = TlsAcceptor::from(Arc::new(server_config));

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind fake TLS terminator");
            let port = listener
                .local_addr()
                .expect("fake TLS terminator addr")
                .port();
            let backend: SocketAddr = *server.address();
            let terminator = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        continue;
                    };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        let Ok(mut upstream) = TcpStream::connect(backend).await else {
                            return;
                        };
                        let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
                    });
                }
            });

            Self {
                server,
                https_base: format!("https://127.0.0.1:{port}"),
                ca_bundle,
                terminator,
            }
        }

        /// Trust this fake's CA for Key Vault TLS by pointing
        /// `FERRUM_TLS_CA_BUNDLE_PATH` at it for the guard's lifetime. Call it
        /// before constructing `AzureCredentials`, which loads the bundle.
        pub fn trust_ca(&self, guard: &EnvGuard) {
            guard.set(
                "FERRUM_TLS_CA_BUNDLE_PATH",
                self.ca_bundle.path().to_string_lossy(),
            );
        }

        /// `https://127.0.0.1:<port>` of the TLS endpoint.
        pub fn uri(&self) -> &str {
            &self.https_base
        }

        /// Reference URL for `FERRUM_<KEY>_AZURE` / direct fetch. Uses the fake's
        /// real host:port (so the port-preservation fix is exercised end to end).
        pub fn secret_url(&self, name: &str) -> String {
            format!("{}/secrets/{}", self.https_base, name)
        }

        /// Versioned reference URL (`/secrets/<name>/<version>`).
        pub fn secret_version_url(&self, name: &str, version: &str) -> String {
            format!("{}/secrets/{}/{}", self.https_base, name, version)
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
                serde_json::json!({ "id": format!("{}/secrets/{}/v1", self.https_base, name) });
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
                "id": format!("{}/secrets/{}/{}", self.https_base, name, version),
                "attributes": { "enabled": true },
            })
        }
    }
}
