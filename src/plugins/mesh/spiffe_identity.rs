//! SPIFFE Identity Extraction Plugin
//!
//! Extracts a SPIFFE ID from the peer certificate's URI SAN and populates
//! `ctx.peer_spiffe_id`. Mesh deployments add this plugin to their proxy
//! config; non-mesh deployments never instantiate it — zero cost.
//!
//! The extracted principal is admitted together with the leaf certificate's
//! `notAfter` as its authorization deadline (GHSA-qqg9-3r2g-fh44). The normal
//! mesh injection installs this plugin plus `mesh_authz` and does NOT require
//! `mtls_auth`, so on a SPIFFE-only policy chain this identity is the only
//! thing authorizing the request or stream. Publishing the identity without its
//! temporal bound left exactly those chains outside the leaf-expiry and
//! finite-authenticated-stream-lifetime protections that `mtls_auth` already
//! implements for Consumer-mapped certificates (issue #3816).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use serde_json::Value;
use tracing::debug;
use x509_parser::prelude::*;

use crate::identity::SpiffeId;
use crate::identity::spiffe::UriSanError;
use crate::plugins::utils::auth_flow::{self, CredentialDeadline};
use crate::plugins::utils::cert_validity::CertValidityWindow;
use crate::plugins::{
    HTTP_FAMILY_AND_STREAM_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext,
    StreamConnectionContext, priority,
};

/// Fixed, material-free reason recorded when a peer SVID cannot be admitted for
/// a temporal reason. Never interpolates `notBefore`, `notAfter`, the observed
/// time, the SPIFFE ID, or any certificate field.
const SVID_NOT_CURRENTLY_VALID: &str = "peer SVID is outside its validity interval";

/// Outcome of extracting a SPIFFE ID from a peer certificate. The peer
/// certificate is fixed for the lifetime of a TLS connection, so the outcome
/// is immutable once derived and safe to share across every multiplexed
/// request on the connection.
///
/// Crate-private: it carries the shared `CertValidityWindow`, which is itself
/// crate-internal, and no caller outside this module ever names the outcome.
#[derive(Debug, Clone)]
pub(crate) enum PeerSpiffeExtraction {
    /// The certificate carries exactly one valid SPIFFE URI SAN, together with
    /// the leaf's authoritative validity window and — once the first successful
    /// admission converts `notAfter` — the monotonic deadline every later cache
    /// hit must return unchanged.
    ///
    /// Deliberately does NOT record "was valid when extracted": the Unix window
    /// is re-checked on every request, but the monotonic Instant is captured
    /// once so a wall-clock rollback cannot recreate a later deadline. Mirrors
    /// `mtls_auth`'s cached evaluation exactly.
    Id {
        id: SpiffeId,
        validity: CertValidityWindow,
        monotonic_expiry: OnceLock<tokio::time::Instant>,
    },
    /// The certificate has no SPIFFE URI SAN (or no SAN extension): no-op.
    NoSpiffeId,
    /// Multiple URI SANs, a malformed `spiffe://` URI, or a validity interval
    /// that is not usable at all: reject 403. Carries a material-free reason for
    /// debug logs.
    Invalid(String),
    /// The DER did not parse as X.509: log-and-continue. Carries the error
    /// display for debug logs.
    Unparsed(String),
}

fn derive_peer_spiffe_extraction(der: &[u8]) -> PeerSpiffeExtraction {
    // One parse for both the URI SAN and the validity window; the SAN walk and
    // the temporal bound describe the same certificate and must not be able to
    // disagree about which one they read.
    let parsed = match X509Certificate::from_der(der) {
        Ok((_, parsed)) => parsed,
        Err(e) => {
            return PeerSpiffeExtraction::Unparsed(
                UriSanError::ParseFailure(e.to_string()).to_string(),
            );
        }
    };

    match crate::identity::spiffe::try_extract_spiffe_id_from_parsed(&parsed) {
        Ok(Some(id)) => match CertValidityWindow::from_certificate(&parsed) {
            Some(validity) => PeerSpiffeExtraction::Id {
                id,
                validity,
                monotonic_expiry: OnceLock::new(),
            },
            // A malformed, overflowing, or inverted ASN.1 interval can never be
            // valid, so the identity behind it is refused rather than admitted
            // with no enforceable bound.
            None => PeerSpiffeExtraction::Invalid(SVID_NOT_CURRENTLY_VALID.to_string()),
        },
        Ok(None) => PeerSpiffeExtraction::NoSpiffeId,
        Err(error) if uri_san_error_requires_rejection(&error) => {
            PeerSpiffeExtraction::Invalid(error.to_string())
        }
        Err(error) => PeerSpiffeExtraction::Unparsed(error.to_string()),
    }
}

/// Re-check the retained window against wall-clock now and return the immutable
/// monotonic authorization deadline for this admission.
///
/// [`CredentialDeadline::Invalid`] refuses the identity. Mirrors
/// `mtls_auth::evaluation_outcome`: X.509 validity is defined against
/// wall-clock time, so the Unix window is consulted on every request, while the
/// monotonic Instant is converted exactly once and every later cache hit admits
/// against that captured value — a wall-clock rollback cannot recreate a later
/// deadline, and an unusable interval fails closed without populating the slot.
///
/// [`CredentialDeadline::Unbounded`] is an admission, not a refusal (issue
/// #5396): a valid SVID whose `notAfter` simply outruns the representable
/// monotonic range carries no upper bound of its own, and the finite
/// authenticated-stream maximum bounds the session instead.
fn admission_deadline(
    validity: &CertValidityWindow,
    monotonic_expiry: &OnceLock<tokio::time::Instant>,
) -> CredentialDeadline {
    let now_unix = x509_parser::time::ASN1Time::now().timestamp();
    if !validity.contains(now_unix) {
        return CredentialDeadline::Invalid;
    }

    if let Some(&deadline) = monotonic_expiry.get() {
        // Cache hit: admit against the Instant captured at first success. An
        // already-elapsed bound refuses, never a fresh conversion that could
        // land later after a wall-clock rollback.
        if tokio::time::Instant::now() >= deadline {
            return CredentialDeadline::Invalid;
        }
        return CredentialDeadline::Bounded(deadline);
    }

    let converted =
        auth_flow::try_credential_deadline_from_unix_seconds(validity.not_after_unix, 0);
    let CredentialDeadline::Bounded(deadline) = converted else {
        // Neither an unbounded nor a refused conversion populates the slot, so a
        // later request converts again rather than caching a bogus Instant.
        return converted;
    };
    let deadline = match monotonic_expiry.set(deadline) {
        Ok(()) => deadline,
        Err(_) => monotonic_expiry.get().copied().unwrap_or(deadline),
    };
    CredentialDeadline::Bounded(deadline)
}

/// Connection-local cache of the peer-cert SPIFFE extraction outcome.
///
/// HTTP-family listeners create one cache per mTLS transport connection
/// (alongside `MtlsAuthConnectionCache`) and share it across multiplexed
/// request contexts, so the full X.509 DER parse in `try_extract_spiffe_id`
/// runs at most once per connection instead of once per request. After the
/// first request the hot path is a single lock-free `OnceLock::get` load;
/// only the first extraction on a connection is serialized.
///
/// What is cached is certificate-*invariant* — the identity plus its validity
/// window — never "this was valid". Admission re-decides the temporal question
/// on every request.
#[derive(Default)]
pub struct SpiffeIdentityConnectionCache {
    outcome: OnceLock<PeerSpiffeExtraction>,
    extraction_count: AtomicUsize,
}

impl std::fmt::Debug for SpiffeIdentityConnectionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeIdentityConnectionCache")
            .field("outcome", &self.outcome.get())
            .field("extraction_count", &self.extraction_count())
            .finish()
    }
}

impl SpiffeIdentityConnectionCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of certificate DER extractions performed through this cache.
    /// Exposed for instrumentation-backed regression tests.
    pub fn extraction_count(&self) -> usize {
        self.extraction_count.load(Ordering::Relaxed)
    }

    fn outcome(&self, der: &[u8]) -> &PeerSpiffeExtraction {
        self.outcome.get_or_init(|| {
            self.extraction_count.fetch_add(1, Ordering::Relaxed);
            derive_peer_spiffe_extraction(der)
        })
    }
}

pub struct SpiffeIdentity;

impl SpiffeIdentity {
    pub fn new(config: &Value) -> Result<Self, String> {
        match config {
            Value::Null => Ok(Self),
            Value::Object(obj) if obj.is_empty() => Ok(Self),
            Value::Object(_) => {
                Err("spiffe_identity: no configuration fields are supported".to_string())
            }
            other => Err(format!(
                "spiffe_identity: config must be an object, got: {other}"
            )),
        }
    }
}

fn uri_san_error_requires_rejection(error: &UriSanError) -> bool {
    matches!(
        error,
        UriSanError::MultipleUriSans { .. } | UriSanError::InvalidSpiffeId { .. }
    )
}

fn invalid_svid_reject(error: impl std::fmt::Display) -> PluginResult {
    debug!(
        "spiffe_identity: rejecting peer cert with invalid SPIFFE URI SAN: {}",
        error
    );
    PluginResult::Reject {
        status_code: 403,
        body: serde_json::json!({"error": "invalid SPIFFE identity certificate"}).to_string(),
        headers: std::collections::HashMap::new(),
    }
}

#[async_trait]
impl Plugin for SpiffeIdentity {
    fn name(&self) -> &str {
        "spiffe_identity"
    }

    fn priority(&self) -> u16 {
        priority::SPIFFE_IDENTITY
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        HTTP_FAMILY_AND_STREAM_PROTOCOLS
    }

    /// `on_stream_connect` below admits a certificate-derived SPIFFE principal
    /// and contributes the leaf's `notAfter` as the session authorization
    /// deadline, so a listener carrying this plugin can never be handed to
    /// kernel TLS: the `splice(2)` relay cannot be bounded by that deadline
    /// (issue #3816, GHSA-qqg9-3r2g-fh44).
    fn admits_authenticated_stream_principal(&self) -> bool {
        true
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        if ctx.peer_spiffe_id.is_some() {
            return PluginResult::Continue;
        }
        let Some(der) = ctx.tls_client_cert_der.clone() else {
            return PluginResult::Continue;
        };
        // Consume the connection-scoped outcome when the listener wired one
        // (H1/H2/H3 mTLS connections): the DER parse then runs at most once
        // per connection and every later multiplexed request reuses the
        // immutable outcome via a lock-free load. Contexts without a cache
        // (direct library callers, tests) derive inline with identical
        // semantics at per-request cost.
        let cache = ctx.peer_spiffe_extraction_cache.clone();
        let derived;
        let outcome = match cache.as_deref() {
            Some(cache) => cache.outcome(der.as_ref()),
            None => {
                derived = derive_peer_spiffe_extraction(der.as_ref());
                &derived
            }
        };
        match outcome {
            PeerSpiffeExtraction::Id {
                id,
                validity,
                monotonic_expiry,
            } => {
                // Time-dependent, so re-decided per request even behind the
                // connection cache: an H1 keep-alive connection and an H2/H3
                // connection both serve new requests long after the handshake.
                let deadline = match admission_deadline(validity, monotonic_expiry) {
                    CredentialDeadline::Bounded(deadline) => Some(deadline),
                    CredentialDeadline::Unbounded => None,
                    CredentialDeadline::Invalid => {
                        return invalid_svid_reject(SVID_NOT_CURRENTLY_VALID);
                    }
                };
                debug!("spiffe_identity: peer SPIFFE ID extracted: {}", id);
                ctx.admit_certificate_spiffe_principal(id.clone(), deadline);
                PluginResult::Continue
            }
            PeerSpiffeExtraction::NoSpiffeId => PluginResult::Continue,
            PeerSpiffeExtraction::Invalid(error) => invalid_svid_reject(error),
            PeerSpiffeExtraction::Unparsed(error) => {
                debug!(
                    "spiffe_identity: could not parse peer cert for SPIFFE ID: {}",
                    error
                );
                PluginResult::Continue
            }
        }
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        // A pre-stamped peer identity (e.g. the node-waypoint eBPF-attested pod
        // SPIFFE ID set by the stream accept loop) must win over peer-cert
        // derivation here, mirroring the on_request_received guard. Otherwise a
        // TcpTls peer cert would clobber the kernel-attested pod principal that
        // mesh_authz uses for source-principal matching.
        if ctx
            .metadata
            .as_ref()
            .is_some_and(|m| m.contains_key("peer_spiffe_id"))
        {
            return PluginResult::Continue;
        }
        // Cloned rather than borrowed: the arms below take `&mut ctx` to admit
        // the principal, and an `Arc` clone is cheaper than restructuring the
        // hook around the borrow.
        let Some(der) = ctx.tls_client_cert_der.clone() else {
            return PluginResult::Continue;
        };
        match derive_peer_spiffe_extraction(der.as_ref()) {
            PeerSpiffeExtraction::Id {
                id,
                validity,
                monotonic_expiry,
            } => {
                // `on_stream_connect` runs exactly once, at admission, and is
                // never repeated — without the deadline the raw TCP/TLS and
                // DTLS relays would have no bound at all.
                let deadline = match admission_deadline(&validity, &monotonic_expiry) {
                    CredentialDeadline::Bounded(deadline) => Some(deadline),
                    CredentialDeadline::Unbounded => None,
                    CredentialDeadline::Invalid => {
                        return invalid_svid_reject(SVID_NOT_CURRENTLY_VALID);
                    }
                };
                debug!("spiffe_identity: stream peer SPIFFE ID: {}", id);
                ctx.admit_certificate_spiffe_principal(&id, deadline);
                PluginResult::Continue
            }
            PeerSpiffeExtraction::NoSpiffeId => PluginResult::Continue,
            PeerSpiffeExtraction::Invalid(error) => invalid_svid_reject(error),
            PeerSpiffeExtraction::Unparsed(error) => {
                debug!(
                    "spiffe_identity: could not parse stream peer cert for SPIFFE ID: {}",
                    error
                );
                PluginResult::Continue
            }
        }
    }
}
