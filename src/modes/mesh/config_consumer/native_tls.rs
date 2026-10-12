//! Closed-set native MeshSubscribe TLS verification diagnostics.
//!
//! Tonic/hyper flatten rustls `CertificateError` values into generic transport
//! failures (`error trying to connect`, handshake EOF, connection reset) before
//! the live classifier can see `UnknownIssuer` versus `NotValidForName`. This
//! module wraps the exclusive configured CA in a standard WebPKI verifier and
//! records only a closed-set reason when that verifier rejects the peer.
//!
//! The handshake still fails for the original rustls reason. The recorded label
//! is `client_tls_verify` or `client_tls_name` and never includes PEM, SANs,
//! tokens, or rustls `Display` text.

use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error as RustlsError};
use tonic::transport::{ClientTlsConfig, Endpoint, Identity};

use crate::grpc::dp_client::DpGrpcTlsConfig;

const OBSERVED_NONE: u8 = 0;
const OBSERVED_VERIFY: u8 = 1;
const OBSERVED_NAME: u8 = 2;

/// Closed-set client-side native MeshSubscribe TLS failure class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeTlsClass {
    /// Configured trust root did not validate the server certificate.
    Verify,
    /// Signing CA was trusted; hostname/SAN validation failed.
    Name,
}

impl NativeTlsClass {
    pub const VERIFY_LABEL: &'static str = "client_tls_verify";
    pub const NAME_LABEL: &'static str = "client_tls_name";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verify => Self::VERIFY_LABEL,
            Self::Name => Self::NAME_LABEL,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            OBSERVED_VERIFY => Some(Self::Verify),
            OBSERVED_NAME => Some(Self::Name),
            _ => None,
        }
    }

    fn as_code(self) -> u8 {
        match self {
            Self::Verify => OBSERVED_VERIFY,
            Self::Name => OBSERVED_NAME,
        }
    }

    /// Map a rustls error to verify vs name. Other TLS failures stay unclassified
    /// so a generic handshake is never relabeled.
    pub fn from_rustls(err: &RustlsError) -> Option<Self> {
        let RustlsError::InvalidCertificate(cert_err) = err else {
            return None;
        };
        match cert_err {
            CertificateError::UnknownIssuer => Some(Self::Verify),
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                Some(Self::Name)
            }
            _ => None,
        }
    }
}

/// WebPKI server verifier that records a closed-set class on CA or name failure.
pub struct ObservingServerCertVerifier {
    inner: Arc<WebPkiServerVerifier>,
    last: AtomicU8,
}

impl ObservingServerCertVerifier {
    pub fn from_ca_pem(ca_pem: &[u8]) -> Result<Self, anyhow::Error> {
        let roots = crate::tls::root_cert_store_from_pem_bundle(
            ca_pem,
            "Mesh native MeshSubscribe TLS CA",
            "configured mesh gRPC CA bundle",
        )?;
        // DP-to-CP gRPC does not apply the gateway CRL surface.
        let inner = crate::tls::build_server_verifier_with_crls(roots, &[])?;
        Ok(Self {
            inner,
            last: AtomicU8::new(OBSERVED_NONE),
        })
    }

    pub fn observed(&self) -> Option<NativeTlsClass> {
        NativeTlsClass::from_code(self.last.load(Ordering::Acquire))
    }

    fn record(&self, class: Option<NativeTlsClass>) {
        self.last.store(
            class.map(NativeTlsClass::as_code).unwrap_or(OBSERVED_NONE),
            Ordering::Release,
        );
    }
}

impl fmt::Debug for ObservingServerCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservingServerCertVerifier")
            .field("observed", &self.observed())
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for ObservingServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => {
                self.record(None);
                Ok(verified)
            }
            Err(err) => {
                self.record(NativeTlsClass::from_rustls(&err));
                Err(err)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// Walk a flattened tonic/io chain for the same closed-set rustls reasons.
pub fn classify_native_tls_error(err: &(dyn Error + 'static)) -> Option<NativeTlsClass> {
    let mut current = Some(err);
    while let Some(node) = current {
        if let Some(rustls_err) = node.downcast_ref::<RustlsError>()
            && let Some(class) = NativeTlsClass::from_rustls(rustls_err)
        {
            return Some(class);
        }
        if let Some(io_err) = node.downcast_ref::<std::io::Error>()
            && let Some(inner) = io_err.get_ref()
            && let Some(rustls_err) = inner.downcast_ref::<RustlsError>()
            && let Some(class) = NativeTlsClass::from_rustls(rustls_err)
        {
            return Some(class);
        }
        current = node.source();
    }
    None
}

/// Prepared native MeshSubscribe TLS: identity + exclusive CA observer.
pub struct NativeMeshTlsPrep {
    client_tls: ClientTlsConfig,
    observer: Option<Arc<ObservingServerCertVerifier>>,
}

impl NativeMeshTlsPrep {
    pub fn observer(&self) -> Option<&ObservingServerCertVerifier> {
        self.observer.as_deref()
    }

    pub fn apply(
        self,
        endpoint: Endpoint,
    ) -> Result<(Endpoint, Option<Arc<ObservingServerCertVerifier>>), tonic::transport::Error> {
        match self.observer {
            Some(observer) => {
                let verifier: Arc<dyn ServerCertVerifier> = observer.clone();
                Ok((
                    endpoint.tls_config_with_verifier(self.client_tls, verifier)?,
                    Some(observer),
                ))
            }
            None => Ok((endpoint.tls_config(self.client_tls)?, None)),
        }
    }
}

/// Build native MeshSubscribe TLS.
///
/// When a CA bundle is configured, the exclusive WebPKI verifier is installed
/// through tonic's custom-verifier API (CA PEM must not also be set on
/// `ClientTlsConfig`). Without a CA, this uses the shared tonic identity path,
/// which trusts the bundled Mozilla (webpki) roots.
pub fn prepare_native_mesh_tls(
    tls: &DpGrpcTlsConfig,
    host: Option<&str>,
) -> Result<NativeMeshTlsPrep, anyhow::Error> {
    let Some(ca_pem) = tls.ca_cert_pem.as_deref() else {
        let mut client_tls = super::common::tonic_tls_config(tls);
        if let Some(host) = host {
            client_tls = client_tls.domain_name(host);
        }
        return Ok(NativeMeshTlsPrep {
            client_tls,
            observer: None,
        });
    };

    let mut client_tls = ClientTlsConfig::new();
    if let (Some(cert_pem), Some(key_pem)) = (&tls.client_cert_pem, &tls.client_key_pem) {
        client_tls = client_tls.identity(Identity::from_pem(cert_pem, key_pem));
    }
    if let Some(host) = host {
        client_tls = client_tls.domain_name(host);
    }
    let observer = Arc::new(ObservingServerCertVerifier::from_ca_pem(ca_pem)?);
    Ok(NativeMeshTlsPrep {
        client_tls,
        observer: Some(observer),
    })
}

#[derive(Debug)]
struct NativeMeshConnectFailure {
    tls_class: NativeTlsClass,
    source: anyhow::Error,
}

impl fmt::Display for NativeMeshConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, f)
    }
}

impl Error for NativeMeshConnectFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Attach a closed-set class when the observing verifier or rustls chain has one.
pub fn annotate_connect_error(
    err: impl Into<anyhow::Error>,
    observer: Option<&ObservingServerCertVerifier>,
) -> anyhow::Error {
    let source = err.into();
    let tls_class = observer
        .and_then(ObservingServerCertVerifier::observed)
        .or_else(|| classify_native_tls_error(source.as_ref()));
    match tls_class {
        Some(tls_class) => NativeMeshConnectFailure { tls_class, source }.into(),
        None => source,
    }
}

pub fn observed_class_from_error(err: &anyhow::Error) -> Option<NativeTlsClass> {
    err.downcast_ref::<NativeMeshConnectFailure>()
        .map(|failure| failure.tls_class)
        .or_else(|| classify_native_tls_error(err.as_ref()))
}
