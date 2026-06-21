//! SPIFFE Workload API gRPC client.
//!
//! Speaks to a SPIRE agent (or any other Workload API server) over a Unix
//! domain socket. The default socket path follows the SPIFFE convention:
//! `/run/spire/agent/agent.sock`. Operators may override via
//! `FERRUM_MESH_WORKLOAD_API_SOCKET`.
//!
//! The client exposes:
//! - [`WorkloadApiClient::fetch_x509_svid_stream`] — long-lived bidirectional
//!   stream returning fresh [`SvidBundle`] every time the agent rotates the
//!   SVID or a federated bundle changes.
//! - [`WorkloadApiClient::fetch_x509_svid_once`] — convenience helper that
//!   returns the FIRST bundle from the stream and drops the connection.

#[cfg(unix)]
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::Request;
use tonic::metadata::AsciiMetadataValue;
use tonic::transport::Channel;
#[cfg(unix)]
use tonic::transport::Endpoint;
#[cfg(unix)]
use tower::service_fn;
#[cfg(unix)]
use tracing::info;
use tracing::{debug, warn};

use super::proto::X509svidRequest;
use super::proto::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use crate::identity::spiffe::{SpiffeId, TrustDomain};
use crate::identity::{SvidBundle, TrustBundle, TrustBundleSet};

/// Default Unix-socket path used when `FERRUM_MESH_WORKLOAD_API_SOCKET` is unset.
pub const DEFAULT_WORKLOAD_API_SOCKET: &str = "/run/spire/agent/agent.sock";

/// SPIFFE Workload API security header. Per the SPIFFE Workload Endpoint spec
/// (`SPIFFE_Workload_Endpoint.md`), every RPC must carry this metadata; servers
/// MUST reject calls that omit it. We attach it to every request via
/// [`workload_request`].
const WORKLOAD_METADATA_KEY: &str = "workload.spiffe.io";
const WORKLOAD_METADATA_VAL: &str = "true";

/// Wrap a payload into a `tonic::Request` carrying the SPIFFE Workload API
/// security metadata. Use this for every Workload API RPC.
fn workload_request<T>(payload: T) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut().insert(
        WORKLOAD_METADATA_KEY,
        AsciiMetadataValue::from_static(WORKLOAD_METADATA_VAL),
    );
    req
}

/// gRPC client wrapper.
pub struct WorkloadApiClient {
    inner: SpiffeWorkloadApiClient<Channel>,
    socket_path: String,
}

impl WorkloadApiClient {
    /// Connect to the SPIRE agent at `socket_path`.
    ///
    /// Tonic's default HTTP connector cannot dial a Unix socket — formatting
    /// `unix://...` into an `Endpoint::connect()` URL produces a TCP attempt
    /// against the path-as-hostname. We instead build the channel with
    /// [`Endpoint::connect_with_connector`] and a `tower::service_fn`
    /// connector that opens a [`tokio::net::UnixStream`] for every dial,
    /// wrapping it via [`hyper_util::rt::TokioIo`] so hyper sees the
    /// expected `Read + Write` shape. The base URI is a dummy — it's only
    /// used as the HTTP/2 `:authority`; the actual transport is the UDS
    /// the connector returns.
    #[cfg(unix)]
    pub async fn connect(socket_path: impl Into<String>) -> Result<Self, WorkloadApiClientError> {
        let socket_path = socket_path.into();
        let socket_for_connector = socket_path.clone();

        let endpoint = Endpoint::try_from("http://[::1]:0")
            .map_err(|e| {
                WorkloadApiClientError::Config(format!("workload API endpoint init: {e}"))
            })?
            .connect_timeout(Duration::from_secs(5));

        let channel = endpoint
            .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
                let path = socket_for_connector.clone();
                async move {
                    let stream = UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await
            .map_err(|e| WorkloadApiClientError::Transport(e.to_string()))?;

        let inner = SpiffeWorkloadApiClient::new(channel);
        info!(socket = %socket_path, "connected to SPIFFE Workload API agent");
        Ok(Self { inner, socket_path })
    }

    #[cfg(not(unix))]
    pub async fn connect(socket_path: impl Into<String>) -> Result<Self, WorkloadApiClientError> {
        let socket_path = socket_path.into();
        Err(WorkloadApiClientError::Config(format!(
            "SPIFFE Workload API Unix-socket transport is only supported on Unix platforms (requested {socket_path})"
        )))
    }

    /// The underlying socket path, useful for diagnostics.
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    /// Open the streaming `FetchX509SVID` RPC and translate each agent
    /// response into a [`SvidBundle`].
    ///
    /// Returns a `Stream` plus a oneshot signal that fires once the FIRST
    /// SvidBundle has been observed — useful for startup paths that need to
    /// "wait for an SVID to be ready" before proceeding.
    pub async fn fetch_x509_svid_stream(
        &mut self,
        expected_spiffe_id: Option<SpiffeId>,
    ) -> Result<
        (
            impl Stream<Item = Result<SvidBundle, WorkloadApiClientError>> + Send + 'static,
            mpsc::UnboundedReceiver<()>,
        ),
        WorkloadApiClientError,
    > {
        let response = self
            .inner
            .fetch_x509svid(workload_request(X509svidRequest {}))
            .await
            .map_err(|e| WorkloadApiClientError::Rpc(e.to_string()))?;
        let mut inbound = response.into_inner();

        // Inner channel relays decoded bundles. Notify channel fires once
        // when the FIRST bundle arrives so callers can do "wait for ready"
        // synchronisation independently of consuming the stream.
        let (out_tx, out_rx) =
            mpsc::unbounded_channel::<Result<SvidBundle, WorkloadApiClientError>>();
        let (notify_tx, notify_rx) = mpsc::unbounded_channel::<()>();

        tokio::spawn(async move {
            let mut sent_first = false;
            while let Some(msg_result) = inbound.next().await {
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(e) => {
                        let _ = out_tx.send(Err(WorkloadApiClientError::Rpc(format!(
                            "Workload API stream error: {e}"
                        ))));
                        return;
                    }
                };
                if msg.svids.is_empty() {
                    debug!("Workload API server pushed an empty X509SVIDResponse — skipping");
                    continue;
                }
                let bundle_res = svid_response_to_bundle(msg, expected_spiffe_id.as_ref());
                let was_ok = bundle_res.is_ok();
                if out_tx.send(bundle_res).is_err() {
                    return;
                }
                if was_ok && !sent_first {
                    let _ = notify_tx.send(());
                    sent_first = true;
                }
            }
        });

        Ok((UnboundedReceiverStream::new(out_rx), notify_rx))
    }

    /// Helper for callers that just want to grab the first SvidBundle and
    /// move on. Production paths should keep the stream open and consume
    /// rotations via [`fetch_x509_svid_stream`](Self::fetch_x509_svid_stream).
    pub async fn fetch_x509_svid_once(&mut self) -> Result<SvidBundle, WorkloadApiClientError> {
        let (mut stream, _) = self.fetch_x509_svid_stream(None).await?;
        stream
            .next()
            .await
            .ok_or_else(|| WorkloadApiClientError::Rpc("stream closed before first SVID".into()))?
    }
}

/// Parse a federated bundle map key into a [`TrustDomain`].
///
/// The SPIFFE Workload API allows bundle map keys in either plain trust-domain
/// form (`example.org`) or SPIFFE URI form (`spiffe://example.org`). We strip
/// the `spiffe://` prefix and any trailing path before parsing.
fn parse_trust_domain_key(key: &str) -> Result<TrustDomain, String> {
    let domain_str = key
        .strip_prefix("spiffe://")
        .unwrap_or(key)
        .split('/')
        .next()
        .unwrap_or(key);
    TrustDomain::new(domain_str.to_string()).map_err(|e| e.to_string())
}

/// Convert one `X509SVIDResponse` into a [`SvidBundle`]. When an expected
/// SPIFFE ID is provided, select that exact SVID; otherwise pick the first SVID
/// in the response (per spec, the "default identity" for the workload).
fn svid_response_to_bundle(
    msg: super::proto::X509svidResponse,
    expected_spiffe_id: Option<&SpiffeId>,
) -> Result<SvidBundle, WorkloadApiClientError> {
    let first = if let Some(expected) = expected_spiffe_id {
        let mut returned = Vec::with_capacity(msg.svids.len());
        let selected = msg.svids.into_iter().find(|svid| {
            returned.push(svid.spiffe_id.clone());
            svid.spiffe_id == expected.as_str()
        });
        selected.ok_or_else(|| {
            WorkloadApiClientError::Rpc(format!(
                "X509SVIDResponse did not include configured SPIFFE ID '{}' (returned: {})",
                expected,
                returned.join(", ")
            ))
        })?
    } else {
        msg.svids
            .into_iter()
            .next()
            .ok_or_else(|| WorkloadApiClientError::Rpc("X509SVIDResponse has no SVIDs".into()))?
    };

    let spiffe_id = SpiffeId::new(first.spiffe_id.clone()).map_err(|e| {
        WorkloadApiClientError::Rpc(format!(
            "agent returned malformed SPIFFE ID '{}': {}",
            first.spiffe_id, e
        ))
    })?;
    let trust_domain = spiffe_id.trust_domain().clone();

    // Cert chain is a single byte blob containing one or more concatenated
    // DER certs (leaf first). We use rustls-pemfile-style splitter: parse
    // each ASN.1 SEQUENCE and slice at its end.
    let cert_chain_der = split_concatenated_der(&first.x509_svid)
        .map_err(|e| WorkloadApiClientError::Rpc(format!("SVID chain parse failed: {e}")))?;
    if cert_chain_der.is_empty() {
        return Err(WorkloadApiClientError::Rpc(
            "SVID has no certificates".into(),
        ));
    }

    // Pin the protobuf `X509SVID.spiffe_id` field to the actual leaf certificate's
    // URI SAN. They must agree: `SvidBundle.spiffe_id` drives HBONE / source
    // identity and the configured-workload pin, while peers authenticate against
    // the leaf the TLS handshake presents. A response whose field matches but
    // whose leaf SAN differs would let those two identities diverge, so reject it
    // before the bundle is installed.
    let leaf_spiffe_id = crate::identity::spiffe::extract_spiffe_id_from_cert(&cert_chain_der[0])
        .map_err(|e| {
        WorkloadApiClientError::Rpc(format!(
            "SVID leaf certificate has no usable SPIFFE URI SAN: {e}"
        ))
    })?;
    if leaf_spiffe_id != spiffe_id {
        return Err(WorkloadApiClientError::Rpc(format!(
            "SVID leaf certificate SPIFFE ID '{leaf_spiffe_id}' does not match the X509SVID \
             spiffe_id field '{spiffe_id}'"
        )));
    }

    // Hold the streamed SVID to the same bar as the file-based loader
    // (`load_svid_bundle_from_sources`): the leaf must be currently valid and not
    // a CA, and the accompanying private key must match it. A SPIRE response that
    // is expired / not-yet-valid, a CA cert, or whose key and leaf disagree would
    // otherwise install and then fail every mesh-mTLS handshake — and, with the
    // CA-backed inbound identity, as the served certificate too.
    let leaf_der = &cert_chain_der[0];
    crate::identity::file_loader::validate_cert_is_current(leaf_der, "SVID leaf certificate")
        .map_err(|e| WorkloadApiClientError::Rpc(e.to_string()))?;
    crate::identity::file_loader::validate_leaf_is_not_ca(leaf_der)
        .map_err(|e| WorkloadApiClientError::Rpc(e.to_string()))?;
    crate::identity::file_loader::verify_leaf_key_match(leaf_der, &first.x509_svid_key)
        .map_err(|e| WorkloadApiClientError::Rpc(e.to_string()))?;

    let local_bundle_der = split_concatenated_der(&first.bundle)
        .map_err(|e| WorkloadApiClientError::Rpc(format!("trust bundle parse failed: {e}")))?;
    // Reject an empty local trust bundle the same way the file loader does (its
    // `read_cert_chain_source` errors on no certs). An SVID with no roots cannot
    // verify peers, so installing it would let STRICT inbound and HBONE/mesh-mTLS
    // handshakes fail after listeners bind rather than failing closed here.
    if local_bundle_der.is_empty() {
        return Err(WorkloadApiClientError::Rpc(
            "Workload API X509SVID has an empty trust bundle (no root certificates); peers \
             cannot be verified"
                .into(),
        ));
    }

    let mut trust_bundles = TrustBundleSet {
        local: TrustBundle {
            trust_domain: trust_domain.clone(),
            x509_authorities: local_bundle_der,
            jwt_authorities: Vec::new(),
            // The SPIFFE Workload API X509SVID stream is event-driven —
            // the server pushes updates eagerly when the SVID rotates or
            // the bundle changes. There is no per-SVID refresh hint on the
            // wire, so leave this `None`. (The `X509SVID.hint` field is an
            // operator-provided workload-matching hint, not a timestamp.)
            refresh_hint_seconds: None,
        },
        federated: Default::default(),
    };

    for (td_str, bundle_bytes) in msg.federated_bundles {
        match parse_trust_domain_key(&td_str) {
            Ok(td) => match split_concatenated_der(&bundle_bytes) {
                Ok(certs) => {
                    trust_bundles.federated.insert(
                        td.clone(),
                        TrustBundle {
                            trust_domain: td,
                            x509_authorities: certs,
                            jwt_authorities: Vec::new(),
                            refresh_hint_seconds: None,
                        },
                    );
                }
                Err(e) => warn!("federated bundle for '{}' is malformed: {}", td_str, e),
            },
            Err(e) => warn!(
                "federated bundle key '{}' is not a trust domain: {}",
                td_str, e
            ),
        }
    }

    Ok(SvidBundle {
        spiffe_id,
        cert_chain_der,
        private_key_pkcs8_der: first.x509_svid_key.into(),
        trust_bundles,
    })
}

/// Split a buffer that holds one or more concatenated DER certs. Each cert
/// starts with the ASN.1 SEQUENCE tag (0x30) followed by a length-of-length
/// byte. We parse just enough to slice at the next boundary.
///
/// **DER-only**: the BER indefinite-length form (`0x80` length byte) is
/// rejected. Real X.509 certs are always DER (RFC 5280 §4.1) so this is a
/// strictness, not a compatibility, requirement — and silently accepting
/// indefinite-length here would yield an empty (zero-length) cert that
/// blows up downstream with a less clear error.
fn split_concatenated_der(buf: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while cursor < buf.len() {
        if buf[cursor] != 0x30 {
            return Err(format!("expected SEQUENCE tag at offset {cursor}"));
        }
        if cursor + 2 > buf.len() {
            return Err("buffer ends mid-tag".to_string());
        }
        let first_len = buf[cursor + 1];
        if first_len == 0x80 {
            return Err(
                "BER indefinite-length encoding is not allowed in DER-encoded certificates"
                    .to_string(),
            );
        }
        let (header_len, content_len) = if first_len & 0x80 == 0 {
            (2, first_len as usize)
        } else {
            let n = (first_len & 0x7f) as usize;
            if cursor + 2 + n > buf.len() {
                return Err("buffer ends inside multi-byte length".to_string());
            }
            let mut content_len = 0usize;
            for i in 0..n {
                content_len = (content_len << 8) | buf[cursor + 2 + i] as usize;
            }
            (2 + n, content_len)
        };
        let total = header_len + content_len;
        if cursor + total > buf.len() {
            return Err("DER length exceeds buffer".to_string());
        }
        out.push(buf[cursor..cursor + total].to_vec());
        cursor += total;
    }
    Ok(out)
}

#[cfg(test)]
mod der_split_tests {
    use super::split_concatenated_der;

    #[test]
    fn rejects_ber_indefinite_length() {
        // SEQUENCE tag (0x30) + indefinite-length form (0x80). DER must use
        // a definite length; this is a BER-only encoding that real X.509
        // certs never produce.
        let buf = [0x30u8, 0x80, 0x00, 0x00];
        let err = split_concatenated_der(&buf).unwrap_err();
        assert!(err.contains("indefinite-length"));
    }

    #[test]
    fn accepts_short_form_length() {
        // SEQUENCE, length=2, two content bytes.
        let buf = [0x30u8, 0x02, 0xAA, 0xBB];
        let parsed = split_concatenated_der(&buf).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], buf);
    }

    #[test]
    fn rejects_truncated_buffer() {
        // SEQUENCE, claimed length=10, only 1 content byte present.
        let buf = [0x30u8, 0x0A, 0xAA];
        assert!(split_concatenated_der(&buf).is_err());
    }
}

/// Errors raised by the Workload API client.
#[derive(Debug, thiserror::Error)]
pub enum WorkloadApiClientError {
    #[error("Workload API client config error: {0}")]
    Config(String),
    #[error("Workload API transport error: {0}")]
    Transport(String),
    #[error("Workload API RPC error: {0}")]
    Rpc(String),
}

#[cfg(test)]
mod tests {
    use super::{split_concatenated_der, svid_response_to_bundle};
    use crate::identity::SpiffeId;
    use crate::identity::workload_api::proto::{X509svid, X509svidResponse};

    #[test]
    fn split_empty_buffer() {
        assert!(split_concatenated_der(&[]).unwrap().is_empty());
    }

    #[test]
    fn split_two_short_form_certs() {
        // Two minimal "SEQUENCE { OCTET STRING <empty> }" blobs concatenated:
        // 0x30 0x02 0x04 0x00  (4 bytes each)
        let blob = [0x30, 0x02, 0x04, 0x00, 0x30, 0x02, 0x04, 0x00];
        let out = split_concatenated_der(&blob).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], vec![0x30, 0x02, 0x04, 0x00]);
        assert_eq!(out[1], vec![0x30, 0x02, 0x04, 0x00]);
    }

    #[test]
    fn split_long_form_length() {
        // 0x30 0x81 0x05 followed by 5 content bytes.
        let blob = [0x30, 0x81, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let out = split_concatenated_der(&blob).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 8);
    }

    #[test]
    fn split_rejects_non_sequence_tag() {
        let blob = [0x31, 0x00];
        assert!(split_concatenated_der(&blob).is_err());
    }

    // Mint a real self-signed leaf carrying `spiffe_id` as a URI SAN. The bundle
    // parser now verifies the leaf's SAN against the protobuf `spiffe_id` field
    // (identity-divergence guard), so the fixture must be a genuine certificate,
    // not an ASN.1 stub. Each call uses a fresh key, so distinct SVIDs are
    // distinguishable by their cert/key bytes.
    fn test_x509_svid(spiffe_id: &str) -> X509svid {
        use crate::identity::spiffe::spiffe_id_to_san;
        use rcgen::{CertificateParams, DistinguishedName, IsCa, KeyPair};
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        // The bundle parser now enforces the same leaf checks as the file loader
        // (currently-valid + non-CA + key match), so the fixture must be a current,
        // non-CA leaf.
        params.is_ca = IsCa::ExplicitNoCa;
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
        let id = SpiffeId::new(spiffe_id).expect("valid SPIFFE ID");
        params
            .subject_alt_names
            .push(spiffe_id_to_san(&id).expect("spiffe SAN"));
        let cert = params.self_signed(&key).expect("self-signed leaf");
        X509svid {
            spiffe_id: spiffe_id.to_string(),
            x509_svid: cert.der().as_ref().to_vec(),
            x509_svid_key: key.serialize_der(),
            bundle: cert.der().as_ref().to_vec(),
            hint: String::new(),
        }
    }

    #[test]
    fn selects_configured_spiffe_id_from_multi_svid_response() {
        let expected = SpiffeId::new("spiffe://td/ns/default/sa/edge").unwrap();
        let first = test_x509_svid("spiffe://td/ns/default/sa/first");
        let wanted = test_x509_svid(expected.as_str());
        let wanted_leaf = wanted.x509_svid.clone();
        let wanted_key = wanted.x509_svid_key.clone();
        let response = X509svidResponse {
            svids: vec![first, wanted],
            crl: Vec::new(),
            federated_bundles: Default::default(),
        };

        let bundle = svid_response_to_bundle(response, Some(&expected)).expect("selected bundle");

        assert_eq!(bundle.spiffe_id, expected);
        assert_eq!(bundle.cert_chain_der, vec![wanted_leaf]);
        assert_eq!(
            bundle.private_key_pkcs8_der.as_slice(),
            wanted_key.as_slice()
        );
    }

    #[test]
    fn rejects_multi_svid_response_without_configured_spiffe_id() {
        let expected = SpiffeId::new("spiffe://td/ns/default/sa/missing").unwrap();
        let response = X509svidResponse {
            svids: vec![test_x509_svid("spiffe://td/ns/default/sa/first")],
            crl: Vec::new(),
            federated_bundles: Default::default(),
        };

        let err = svid_response_to_bundle(response, Some(&expected)).unwrap_err();

        assert!(
            err.to_string()
                .contains("did not include configured SPIFFE ID")
        );
    }

    #[test]
    fn rejects_empty_workload_api_trust_bundle() {
        // An SVID whose local trust bundle has no roots cannot verify peers; reject
        // it before install, matching the file loader.
        let expected = SpiffeId::new("spiffe://td/ns/default/sa/edge").unwrap();
        let mut svid = test_x509_svid(expected.as_str());
        svid.bundle = Vec::new();
        let response = X509svidResponse {
            svids: vec![svid],
            crl: Vec::new(),
            federated_bundles: Default::default(),
        };

        let err = svid_response_to_bundle(response, Some(&expected)).unwrap_err();
        assert!(
            err.to_string().contains("empty trust bundle"),
            "expected empty-trust-bundle rejection, got: {err}"
        );
    }
}

#[cfg(test)]
mod trust_domain_key_tests {
    use super::parse_trust_domain_key;

    #[test]
    fn plain_trust_domain() {
        let td = parse_trust_domain_key("example.org").unwrap();
        assert_eq!(td.as_str(), "example.org");
    }

    #[test]
    fn spiffe_uri_form() {
        let td = parse_trust_domain_key("spiffe://example.org").unwrap();
        assert_eq!(td.as_str(), "example.org");
    }

    #[test]
    fn spiffe_uri_with_path() {
        let td = parse_trust_domain_key("spiffe://example.org/ns/foo").unwrap();
        assert_eq!(td.as_str(), "example.org");
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_trust_domain_key("").is_err());
    }

    #[test]
    fn rejects_spiffe_prefix_only() {
        assert!(parse_trust_domain_key("spiffe://").is_err());
    }
}
