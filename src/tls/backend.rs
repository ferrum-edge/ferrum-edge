use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use reqwest::ClientBuilder;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use thiserror::Error;

use crate::config::types::Proxy;
use crate::tls::{
    NoVerifier, TlsPolicy, backend_client_config_builder, build_server_verifier_with_crls,
};

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("TLS file I/O: {0}")]
    Io(String),
    #[error("TLS PEM parse: {0}")]
    Pem(String),
    #[error("rustls: {0}")]
    Rustls(String),
}

/// Build the backend trust store using the CA chain resolution from CLAUDE.md:
/// proxy CA, else global CA, else webpki roots. Custom CAs are exclusive.
pub fn build_root_cert_store(
    proxy_ca: Option<&Path>,
    global_ca: Option<&Path>,
    _crls: &[CertificateRevocationListDer<'static>],
) -> Result<RootCertStore, TlsError> {
    let ca_path = proxy_ca.or(global_ca);
    let mut root_store = if ca_path.is_some() {
        RootCertStore::empty()
    } else {
        RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
    };

    if let Some(ca_path) = ca_path {
        let certs = load_cert_chain(ca_path)?;
        let (added, ignored) = root_store.add_parsable_certificates(certs);
        if added == 0 {
            return Err(TlsError::Rustls(format!(
                "No valid CA certificates found in {}",
                ca_path.display()
            )));
        }
        if ignored > 0 {
            tracing::warn!(
                "Ignored {} invalid CA certificate(s) while loading {}",
                ignored,
                ca_path.display()
            );
        }
    }

    Ok(root_store)
}

pub struct BackendTlsConfigBuilder<'a> {
    pub proxy: &'a Proxy,
    pub policy: Option<&'a TlsPolicy>,
    pub global_ca: Option<&'a Path>,
    pub global_no_verify: bool,
    pub global_client_cert: Option<&'a Path>,
    pub global_client_key: Option<&'a Path>,
    pub crls: &'a [CertificateRevocationListDer<'static>],
}

impl<'a> BackendTlsConfigBuilder<'a> {
    pub fn build_rustls(&self) -> Result<ClientConfig, TlsError> {
        let builder = backend_client_config_builder(self.policy)
            .map_err(|e| TlsError::Rustls(format!("Failed to apply backend TLS policy: {}", e)))?;
        let client_auth = self.load_client_auth()?;
        let verifier = self.build_server_verifier()?;
        let builder = builder.with_webpki_verifier(verifier);
        let mut client_config = match client_auth {
            Some((certs, key)) => builder.with_client_auth_cert(certs, key).map_err(|e| {
                TlsError::Rustls(format!("Invalid client certificate/key pair: {}", e))
            }),
            None => Ok(builder.with_no_client_auth()),
        }?;

        if self.skip_verification() {
            client_config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifier));
        }

        Ok(client_config)
    }

    pub fn build_rustls_quic(&self) -> Result<ClientConfig, TlsError> {
        let builder = backend_client_config_builder(self.policy)
            .map_err(|e| TlsError::Rustls(format!("Failed to apply backend TLS policy: {}", e)))?;
        let client_auth = self.load_client_auth()?;
        let skip_verification = self.skip_verification();
        let ca_path = self.custom_ca_path();
        let mut root_store = if ca_path.is_some() {
            RootCertStore::empty()
        } else {
            RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
        };

        if !skip_verification && let Some(ca_path) = ca_path {
            let certs = load_cert_chain(ca_path)?;
            let (added, ignored) = root_store.add_parsable_certificates(certs);
            if added == 0 {
                return Err(TlsError::Rustls(format!(
                    "No valid CA certificates found in {}",
                    ca_path.display()
                )));
            }
            if ignored > 0 {
                tracing::warn!(
                    "Ignored {} invalid CA certificate(s) while loading {}",
                    ignored,
                    ca_path.display()
                );
            }
        }

        let verifier = build_server_verifier_with_crls(root_store, self.crls)
            .map_err(|e| TlsError::Rustls(format!("Failed to build server verifier: {}", e)))?;
        let builder = builder.with_webpki_verifier(verifier);
        let mut client_config = match client_auth {
            Some((certs, key)) => builder.with_client_auth_cert(certs, key).map_err(|e| {
                TlsError::Rustls(format!("Invalid client certificate/key pair: {}", e))
            }),
            None => Ok(builder.with_no_client_auth()),
        }?;

        if skip_verification {
            client_config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifier));
        }

        Ok(client_config)
    }

    pub fn build_reqwest(&self) -> Result<ClientBuilder, TlsError> {
        let mut builder = reqwest::Client::builder();
        if self.custom_ca_path().is_some() {
            builder = builder.tls_built_in_root_certs(false);
        }
        if self.skip_verification() {
            builder = builder.danger_accept_invalid_certs(true);
        }
        Ok(builder.use_preconfigured_tls(self.build_rustls()?))
    }

    fn build_server_verifier(&self) -> Result<Arc<WebPkiServerVerifier>, TlsError> {
        let root_store = build_root_cert_store(self.custom_ca_path(), self.global_ca, self.crls)?;
        build_server_verifier_with_crls(root_store, self.crls)
            .map_err(|e| TlsError::Rustls(format!("Failed to build server verifier: {}", e)))
    }

    fn skip_verification(&self) -> bool {
        !self.proxy.resolved_tls.verify_server_cert || self.global_no_verify
    }

    fn custom_ca_path(&self) -> Option<&Path> {
        self.proxy
            .resolved_tls
            .server_ca_cert_path
            .as_deref()
            .map(Path::new)
            .or(self.global_ca)
    }

    fn load_client_auth(
        &self,
    ) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>, TlsError> {
        let cert_path = self
            .proxy
            .resolved_tls
            .client_cert_path
            .as_deref()
            .map(Path::new)
            .or(self.global_client_cert);
        let key_path = self
            .proxy
            .resolved_tls
            .client_key_path
            .as_deref()
            .map(Path::new)
            .or(self.global_client_key);

        match (cert_path, key_path) {
            (Some(_), None) => Err(TlsError::Pem(
                "backend TLS client certificate is set but the private key is missing".to_string(),
            )),
            (None, Some(_)) => Err(TlsError::Pem(
                "backend TLS client private key is set but the certificate is missing".to_string(),
            )),
            (None, None) => Ok(None),
            (Some(cert_path), Some(key_path)) => {
                let certs = load_cert_chain(cert_path)?;
                let key = load_private_key(key_path)?;
                Ok(Some((certs, key)))
            }
        }
    }
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let pem = fs::read(path)
        .map_err(|e| TlsError::Io(format!("Failed to read {}: {}", path.display(), e)))?;
    let certs = rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            TlsError::Pem(format!(
                "Failed to parse PEM certificates from {}: {}",
                path.display(),
                e
            ))
        })?;

    if certs.is_empty() {
        return Err(TlsError::Pem(format!(
            "No PEM certificates found in {}",
            path.display()
        )));
    }

    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let pem = fs::read(path)
        .map_err(|e| TlsError::Io(format!("Failed to read {}: {}", path.display(), e)))?;
    rustls_pemfile::private_key(&mut Cursor::new(pem))
        .map_err(|e| {
            TlsError::Pem(format!(
                "Failed to parse PEM private key from {}: {}",
                path.display(),
                e
            ))
        })?
        .ok_or_else(|| TlsError::Pem(format!("No private key found in {}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::Once;

    use chrono::Utc;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
    };
    use rustls::client::danger::ServerCertVerifier;
    use tempfile::TempDir;

    use crate::config::types::{AuthMode, BackendProtocol, BackendTlsConfig, Proxy};

    static INIT_CRYPTO: Once = Once::new();

    struct GeneratedCa {
        cert_pem: String,
        issuer: Issuer<'static, KeyPair>,
    }

    struct GeneratedCert {
        cert_pem: String,
        key_pem: String,
        cert_der: CertificateDer<'static>,
        serial: SerialNumber,
    }

    fn ensure_crypto_provider() {
        INIT_CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn generate_ca(cn: &str) -> GeneratedCa {
        let key_pair =
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate CA key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        let cert = params.self_signed(&key_pair).expect("self-sign CA");
        GeneratedCa {
            cert_pem: cert.pem(),
            issuer: Issuer::new(params, key_pair),
        }
    }

    fn generate_signed_cert(ca: &GeneratedCa, cn: &str, sans: &[&str]) -> GeneratedCert {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut params =
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .expect("leaf params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let serial = SerialNumber::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        params.serial_number = Some(serial.clone());
        let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
        let cert_pem = cert.pem();
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse leaf PEM")
            .into_iter()
            .next()
            .expect("leaf DER");

        GeneratedCert {
            cert_pem,
            key_pem: key_pair.serialize_pem(),
            cert_der,
            serial,
        }
    }

    fn generate_crl_pem(ca: &GeneratedCa, revoked_serials: &[SerialNumber]) -> String {
        let now = time::OffsetDateTime::now_utc();
        let revoked_certs = revoked_serials
            .iter()
            .cloned()
            .map(|serial_number| RevokedCertParams {
                serial_number,
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect();

        CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(30),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&ca.issuer)
        .expect("sign CRL")
        .pem()
        .expect("CRL to PEM")
    }

    fn write_file(dir: &TempDir, name: &str, data: &str) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, data).expect("write test file");
        path
    }

    fn parse_crls(pem: &str) -> Vec<CertificateRevocationListDer<'static>> {
        rustls_pemfile::crls(&mut pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse CRLs")
    }

    fn test_proxy() -> Proxy {
        Proxy {
            id: "proxy-1".to_string(),
            name: Some("proxy-1".to_string()),
            namespace: "ferrum".to_string(),
            hosts: vec!["example.com".to_string()],
            listen_path: Some("/".to_string()),
            backend_protocol: BackendProtocol::Https,
            backend_host: "localhost".to_string(),
            backend_port: 443,
            backend_path: None,
            strip_listen_path: true,
            preserve_host_header: false,
            backend_connect_timeout_ms: 1_000,
            backend_read_timeout_ms: 1_000,
            backend_write_timeout_ms: 1_000,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            resolved_tls: BackendTlsConfig::default_verify(),
            dns_override: None,
            dns_cache_ttl_seconds: None,
            auth_mode: AuthMode::default(),
            plugins: Vec::new(),
            pool_idle_timeout_seconds: None,
            pool_enable_http_keep_alive: None,
            pool_enable_http2: None,
            pool_tcp_keepalive_seconds: None,
            pool_http2_keep_alive_interval_seconds: None,
            pool_http2_keep_alive_timeout_seconds: None,
            pool_http2_initial_stream_window_size: None,
            pool_http2_initial_connection_window_size: None,
            pool_http2_adaptive_window: None,
            pool_http2_max_frame_size: None,
            pool_http2_max_concurrent_streams: None,
            pool_http3_connections_per_backend: None,
            upstream_id: None,
            circuit_breaker: None,
            retry: None,
            response_body_mode: Default::default(),
            listen_port: None,
            frontend_tls: false,
            passthrough: false,
            udp_idle_timeout_seconds: 60,
            udp_max_response_amplification_factor: None,
            tcp_idle_timeout_seconds: None,
            allowed_methods: None,
            allowed_ws_origins: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn builder_for<'a>(
        proxy: &'a Proxy,
        global_ca: Option<&'a Path>,
        global_no_verify: bool,
        global_client_cert: Option<&'a Path>,
        global_client_key: Option<&'a Path>,
        crls: &'a [CertificateRevocationListDer<'static>],
    ) -> BackendTlsConfigBuilder<'a> {
        BackendTlsConfigBuilder {
            proxy,
            policy: None,
            global_ca,
            global_no_verify,
            global_client_cert,
            global_client_key,
            crls,
        }
    }

    #[test]
    fn build_root_cert_store_prefers_proxy_ca_exclusively() {
        let dir = TempDir::new().unwrap();
        let proxy_ca = generate_ca("Proxy CA");
        let global_ca_a = generate_ca("Global CA A");
        let global_ca_b = generate_ca("Global CA B");
        let proxy_path = write_file(&dir, "proxy-ca.pem", &proxy_ca.cert_pem);
        let global_path = write_file(
            &dir,
            "global-ca.pem",
            &(global_ca_a.cert_pem.clone() + &global_ca_b.cert_pem),
        );

        let store =
            build_root_cert_store(Some(&proxy_path), Some(&global_path), &[]).expect("root store");

        assert_eq!(store.roots.len(), 1);
    }

    #[test]
    fn build_root_cert_store_uses_global_ca_when_proxy_ca_is_absent() {
        let dir = TempDir::new().unwrap();
        let global_ca_a = generate_ca("Global CA A");
        let global_ca_b = generate_ca("Global CA B");
        let global_path = write_file(
            &dir,
            "global-ca.pem",
            &(global_ca_a.cert_pem.clone() + &global_ca_b.cert_pem),
        );

        let store = build_root_cert_store(None, Some(&global_path), &[]).expect("root store");

        assert_eq!(store.roots.len(), 2);
    }

    #[test]
    fn build_root_cert_store_falls_back_to_webpki_roots() {
        let store = build_root_cert_store(None, None, &[]).expect("root store");
        assert_eq!(store.roots.len(), webpki_roots::TLS_SERVER_ROOTS.len());
    }

    #[test]
    fn build_rustls_requires_client_cert_and_key_as_a_pair() {
        let dir = TempDir::new().unwrap();
        let ca = generate_ca("CA");
        let client = generate_signed_cert(&ca, "client", &["localhost"]);
        let cert_path = write_file(&dir, "client.crt", &client.cert_pem);
        let key_path = write_file(&dir, "client.key", &client.key_pem);

        let mut proxy = test_proxy();
        proxy.resolved_tls.client_cert_path = Some(cert_path.display().to_string());

        let err = builder_for(&proxy, None, false, None, None, &[])
            .build_rustls()
            .unwrap_err();
        assert!(matches!(err, TlsError::Pem(_)));

        proxy.resolved_tls.client_cert_path = None;
        proxy.resolved_tls.client_key_path = Some(key_path.display().to_string());

        let err = builder_for(&proxy, None, false, None, None, &[])
            .build_rustls()
            .unwrap_err();
        assert!(matches!(err, TlsError::Pem(_)));
    }

    #[test]
    fn build_rustls_skips_ca_loading_when_proxy_disables_verification() {
        ensure_crypto_provider();
        let mut proxy = test_proxy();
        proxy.resolved_tls.server_ca_cert_path = Some("/does/not/exist.pem".to_string());
        proxy.resolved_tls.verify_server_cert = false;

        builder_for(&proxy, None, false, None, None, &[])
            .build_rustls()
            .expect("skip-verify should bypass CA loading");
    }

    #[test]
    fn build_rustls_skips_ca_loading_when_global_no_verify_is_enabled() {
        ensure_crypto_provider();
        let mut proxy = test_proxy();
        proxy.resolved_tls.server_ca_cert_path = Some("/does/not/exist.pem".to_string());

        builder_for(&proxy, None, true, None, None, &[])
            .build_rustls()
            .expect("global no-verify should bypass CA loading");
    }

    #[test]
    fn build_server_verifier_rejects_revoked_end_entity_cert() {
        ensure_crypto_provider();
        let dir = TempDir::new().unwrap();
        let ca = generate_ca("Revoking CA");
        let leaf = generate_signed_cert(&ca, "localhost", &["localhost"]);
        let ca_path = write_file(&dir, "ca.pem", &ca.cert_pem);
        let crl_path = write_file(&dir, "revoked.crl", &generate_crl_pem(&ca, &[leaf.serial]));
        let crls = parse_crls(&fs::read_to_string(crl_path).unwrap());

        let mut proxy = test_proxy();
        proxy.resolved_tls.server_ca_cert_path = Some(ca_path.display().to_string());
        let verifier = builder_for(&proxy, None, false, None, None, &crls)
            .build_server_verifier()
            .expect("verifier");

        let result = verifier.verify_server_cert(
            &leaf.cert_der,
            &[],
            &rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn build_server_verifier_allows_unknown_revocation_status() {
        ensure_crypto_provider();
        let dir = TempDir::new().unwrap();
        let trusted_ca = generate_ca("Trusted CA");
        let unrelated_crl_ca = generate_ca("CRL CA");
        let leaf = generate_signed_cert(&trusted_ca, "localhost", &["localhost"]);
        let ca_path = write_file(&dir, "ca.pem", &trusted_ca.cert_pem);
        let crl_path = write_file(
            &dir,
            "unrelated.crl",
            &generate_crl_pem(&unrelated_crl_ca, &[SerialNumber::from(99u64)]),
        );
        let crls = parse_crls(&fs::read_to_string(crl_path).unwrap());

        let mut proxy = test_proxy();
        proxy.resolved_tls.server_ca_cert_path = Some(ca_path.display().to_string());
        let verifier = builder_for(&proxy, None, false, None, None, &crls)
            .build_server_verifier()
            .expect("verifier");

        verifier
            .verify_server_cert(
                &leaf.cert_der,
                &[],
                &rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .expect("unrelated CRL should not reject trusted cert");
    }

    #[test]
    fn build_rustls_errors_when_client_cert_file_disappears() {
        let dir = TempDir::new().unwrap();
        let ca = generate_ca("Client CA");
        let client = generate_signed_cert(&ca, "client", &["localhost"]);
        let missing_cert = dir.path().join("missing-client.crt");
        let key_path = write_file(&dir, "client.key", &client.key_pem);

        let mut proxy = test_proxy();
        proxy.resolved_tls.client_cert_path = Some(missing_cert.display().to_string());
        proxy.resolved_tls.client_key_path = Some(key_path.display().to_string());
        proxy.resolved_tls.verify_server_cert = false;

        let err = builder_for(&proxy, None, false, None, None, &[])
            .build_rustls()
            .unwrap_err();
        assert!(matches!(err, TlsError::Io(_)));
    }

    #[test]
    fn build_reqwest_uses_preconfigured_tls_with_custom_ca() {
        let dir = TempDir::new().unwrap();
        let ca = generate_ca("Reqwest CA");
        let ca_path = write_file(&dir, "ca.pem", &ca.cert_pem);

        let mut proxy = test_proxy();
        proxy.resolved_tls.server_ca_cert_path = Some(ca_path.display().to_string());

        let _ = builder_for(&proxy, None, false, None, None, &[])
            .build_reqwest()
            .expect("reqwest builder");
    }
}
