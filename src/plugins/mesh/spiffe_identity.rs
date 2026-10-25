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

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use http::HeaderName;
use serde_json::{Map, Value};
use tracing::debug;
use x509_parser::prelude::*;

use crate::identity::SpiffeId;
use crate::identity::spiffe::{SpiffeIdError, TrustDomain, UriSanError};
use crate::plugins::mesh::telemetry_facts::RemoteSourceFacts;
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

/// Fixed reason for a certificate carrying more than one URI SAN beside a
/// SPIFFE one (SPIFFE X.509-SVID §4.1).
const MULTIPLE_URI_SANS: &str = "peer certificate carries more than one URI SAN";

/// Upper bound on `allowed_trust_domains` entries. The list is scanned per
/// admission, so it stays small by construction.
const MAX_ALLOWED_TRUST_DOMAINS: usize = 64;

/// Every configuration key the constructor admits.
const SUPPORTED_CONFIG_FIELDS: &[&str] = &[
    "require_identity",
    "allowed_trust_domains",
    "forward_header",
];

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
    /// that is not usable at all: reject 403. Carries a fixed, material-free
    /// reason for debug logs — never the rejected URI, its userinfo, query, or
    /// fragment, nor the nested parser error that would echo them.
    Invalid(&'static str),
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
            None => PeerSpiffeExtraction::Invalid(SVID_NOT_CURRENTLY_VALID),
        },
        Ok(None) => PeerSpiffeExtraction::NoSpiffeId,
        Err(UriSanError::MultipleUriSans { .. }) => {
            PeerSpiffeExtraction::Invalid(MULTIPLE_URI_SANS)
        }
        // The displayed `InvalidSpiffeId` error owns the complete rejected URI
        // (and its nested parser error repeats it), so a CA-signed certificate
        // whose URI SAN carries a credential in its userinfo or query would
        // reach the debug log verbatim. Only a fixed reason crosses this
        // boundary.
        Err(UriSanError::InvalidSpiffeId { source, .. }) => {
            PeerSpiffeExtraction::Invalid(invalid_spiffe_id_reason(&source))
        }
        // `NoSanExtension` / `NoSpiffeUri` are mapped to `Ok(None)` above and
        // `ParseFailure` describes the DER, not a URI: none of them carries
        // certificate SAN material.
        Err(error) => PeerSpiffeExtraction::Unparsed(error.to_string()),
    }
}

/// A fixed, material-free description of why a `spiffe://` URI SAN is not a
/// valid SPIFFE ID. Never interpolates the URI or any part of it.
fn invalid_spiffe_id_reason(error: &SpiffeIdError) -> &'static str {
    match error {
        SpiffeIdError::Empty => "SPIFFE URI SAN is empty",
        SpiffeIdError::TooLong(..) => "SPIFFE URI SAN exceeds the SPIFFE ID length bound",
        SpiffeIdError::InvalidScheme(_) => "SPIFFE URI SAN does not use the `spiffe` scheme",
        SpiffeIdError::Malformed(_) => "SPIFFE URI SAN is not of the form spiffe://<td>/<path>",
        SpiffeIdError::HasQuery(_) => "SPIFFE URI SAN carries a query component",
        SpiffeIdError::HasFragment(_) => "SPIFFE URI SAN carries a fragment",
        SpiffeIdError::TrailingSlash(_) => "SPIFFE URI SAN has a trailing slash",
        SpiffeIdError::EmptyPathSegment { .. } => "SPIFFE URI SAN has an empty path segment",
        SpiffeIdError::DotPathSegment { .. } => "SPIFFE URI SAN has a dot-only path segment",
        SpiffeIdError::InvalidPathChar { .. } => {
            "SPIFFE URI SAN path contains an invalid character"
        }
        SpiffeIdError::InvalidTrustDomain(..) => "SPIFFE URI SAN has an invalid trust domain",
    }
}

/// Whether the retained window and the once-captured monotonic deadline both
/// still admit the identity right now, without converting or capturing
/// anything.
///
/// The ONE admission predicate: [`admission_deadline`] refuses exactly when
/// this is false, and [`has_verified_peer_spiffe_identity`] answers with it, so
/// the two can never disagree after the captured deadline elapses under a
/// wall-clock rollback.
fn currently_admissible(
    validity: &CertValidityWindow,
    monotonic_expiry: &OnceLock<tokio::time::Instant>,
) -> bool {
    let now_unix = x509_parser::time::ASN1Time::now().timestamp();
    if !validity.contains(now_unix) {
        return false;
    }
    // A captured bound that has elapsed refuses, never a fresh conversion that
    // could land later after a wall-clock rollback.
    monotonic_expiry
        .get()
        .is_none_or(|&deadline| tokio::time::Instant::now() < deadline)
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
    if !currently_admissible(validity, monotonic_expiry) {
        return CredentialDeadline::Invalid;
    }

    if let Some(&deadline) = monotonic_expiry.get() {
        // Cache hit: admit against the Instant captured at first success,
        // which `currently_admissible` has just found unelapsed.
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
    /// The extracted peer's typed telemetry labels as a remote mesh source,
    /// built at most once per connection (issue #6793).
    remote_source_facts: OnceLock<Arc<RemoteSourceFacts>>,
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

    /// Typed telemetry facts for this connection's peer as a remote mesh
    /// source (issue #6793), resolved once per connection instead of once per
    /// multiplexed request.
    ///
    /// `Some` only when `identity` is exactly the SPIFFE ID this connection's
    /// certificate yielded, so an honored HBONE assertion (or any other source)
    /// never reuses the certificate peer's labels. These are labels only: the
    /// plugin still decides admission — validity window and trust — per request.
    pub(crate) fn remote_source_facts(
        &self,
        identity: &SpiffeId,
    ) -> Option<Arc<RemoteSourceFacts>> {
        let PeerSpiffeExtraction::Id { id, .. } = self.outcome.get()? else {
            return None;
        };
        if id != identity {
            return None;
        }
        Some(Arc::clone(
            self.remote_source_facts
                .get_or_init(|| Arc::new(RemoteSourceFacts::new(Some(id)))),
        ))
    }

    /// The admitted leaf's own credential deadline, from the extraction this
    /// connection already performed — never a fresh X.509 parse (issue #5568).
    ///
    /// `None` means this cache holds no leaf-derived identity to bound: either
    /// nothing has been extracted on this connection yet, or the peer's
    /// certificate carried no usable SPIFFE SAN. A caller that needs a deadline
    /// for a certificate it knows was admitted must then parse the retained DER
    /// itself.
    ///
    /// On an H2 mesh listener many CONNECTs multiplex over one connection, so
    /// the HBONE admission fence reads this rather than re-parsing the same
    /// leaf once per tunnel. The returned value is exactly what
    /// [`admission_deadline`] admitted the principal with: the monotonic
    /// `Instant` captured at the first successful admission when one exists,
    /// and otherwise the same conversion of the retained window — so the fence
    /// and the request path can never disagree about when the credential ends.
    pub(crate) fn admitted_leaf_deadline(&self) -> Option<CredentialDeadline> {
        let PeerSpiffeExtraction::Id {
            validity,
            monotonic_expiry,
            ..
        } = self.outcome.get()?
        else {
            return None;
        };
        if let Some(&deadline) = monotonic_expiry.get() {
            return Some(CredentialDeadline::Bounded(deadline));
        }
        let unix = validity.not_after_unix;
        Some(auth_flow::try_credential_deadline_from_unix_seconds(
            unix, 0,
        ))
    }
}

/// Whether `ctx` carries, or would admit, a verified peer SPIFFE identity
/// (issue #5763).
///
/// True when a principal is already published on `ctx.peer_spiffe_id`, or when
/// the connection's client certificate yields exactly the identity
/// [`SpiffeIdentity::on_request_received`] would admit: one valid SPIFFE URI
/// SAN inside a currently valid window whose once-captured monotonic deadline
/// (when an earlier request on the connection captured one) has not elapsed —
/// the same [`currently_admissible`] predicate admission uses. Per-instance
/// policy (`allowed_trust_domains`) is not consulted: this classifies the
/// peer's credential, not a route's policy. A certificate the listener's verifier
/// accepted but that carries no usable SPIFFE ID is NOT a verified peer: the
/// HBONE handlers refuse it as unauthenticated. Reads the connection-scoped
/// extraction cache, so it adds no parse the plugin would not perform anyway;
/// it never publishes a principal or captures a deadline on `ctx`.
pub(crate) fn has_verified_peer_spiffe_identity(ctx: &RequestContext) -> bool {
    if ctx.peer_spiffe_id.is_some() {
        return true;
    }
    let Some(der) = ctx.tls_client_cert_der.as_deref() else {
        return false;
    };
    let derived;
    let outcome = match ctx.peer_spiffe_extraction_cache.as_deref() {
        Some(cache) => cache.outcome(der),
        None => {
            derived = derive_peer_spiffe_extraction(der);
            &derived
        }
    };
    match outcome {
        PeerSpiffeExtraction::Id {
            validity,
            monotonic_expiry,
            ..
        } => currently_admissible(validity, monotonic_expiry),
        PeerSpiffeExtraction::NoSpiffeId
        | PeerSpiffeExtraction::Invalid(_)
        | PeerSpiffeExtraction::Unparsed(_) => false,
    }
}

/// The `spiffe_identity` plugin instance.
///
/// The default (`{}` / `null`) is the historical extraction-only behavior: no
/// identity is required, every trust domain the listener's verifier accepted
/// is admitted, and nothing is forwarded to the backend. Each field below is an
/// opt-in tightening of that default.
#[derive(Debug, Default)]
pub struct SpiffeIdentity {
    /// Refuse (`403`) a request or stream that reaches this plugin without a
    /// usable SPIFFE identity: no client certificate, a certificate with no
    /// SPIFFE URI SAN, or DER that does not parse.
    require_identity: bool,
    /// When set, admit only identities whose trust domain is listed. Applies
    /// to certificate-derived and pre-stamped identities alike.
    allowed_trust_domains: Option<Vec<TrustDomain>>,
    /// Lowercase request header the admitted identity is forwarded to the
    /// backend in. Every client-supplied copy (compared as a CGI-style backend
    /// reads names) is removed first, whether or not an identity is forwarded.
    forward_header: Option<String>,
}

impl SpiffeIdentity {
    pub fn new(config: &Value) -> Result<Self, String> {
        let obj = match config {
            Value::Null => return Ok(Self::default()),
            Value::Object(obj) => obj,
            // Name only the JSON type: echoing the rejected value would copy an
            // arbitrarily large admin payload into the error and the logs.
            other => {
                return Err(format!(
                    "spiffe_identity: `config` must be an object, got a JSON {}",
                    json_type_name(other)
                ));
            }
        };
        // Name only the supported set, never the rejected key, for the same
        // reason.
        if obj
            .keys()
            .any(|key| !SUPPORTED_CONFIG_FIELDS.contains(&key.as_str()))
        {
            return Err(
                "spiffe_identity: unsupported configuration field; supported fields \
                 are `require_identity`, `allowed_trust_domains`, and `forward_header`"
                    .to_string(),
            );
        }
        Ok(Self {
            require_identity: parse_require_identity(obj)?,
            allowed_trust_domains: parse_allowed_trust_domains(obj)?,
            forward_header: parse_forward_header(obj)?,
        })
    }

    fn admits_trust_domain(&self, trust_domain: &TrustDomain) -> bool {
        self.allowed_trust_domains
            .as_ref()
            .is_none_or(|allowed| allowed.contains(trust_domain))
    }

    /// The verdict for a request or stream that carries no usable identity.
    fn on_missing_identity(&self) -> PluginResult {
        if self.require_identity {
            identity_required_reject()
        } else {
            PluginResult::Continue
        }
    }
}

fn parse_require_identity(obj: &Map<String, Value>) -> Result<bool, String> {
    match obj.get("require_identity") {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(other) => Err(format!(
            "spiffe_identity: `require_identity` must be a boolean, got a JSON {}",
            json_type_name(other)
        )),
    }
}

fn parse_allowed_trust_domains(
    obj: &Map<String, Value>,
) -> Result<Option<Vec<TrustDomain>>, String> {
    let Some(value) = obj.get("allowed_trust_domains") else {
        return Ok(None);
    };
    let Value::Array(entries) = value else {
        return Err(format!(
            "spiffe_identity: `allowed_trust_domains` must be an array of strings, got a JSON {}",
            json_type_name(value)
        ));
    };
    // An explicit empty list would read as "admit nothing" to one operator and
    // "no restriction" to another; refuse it instead of picking one.
    if entries.is_empty() {
        return Err(
            "spiffe_identity: `allowed_trust_domains` must list at least one trust domain; \
             omit it to admit every trust domain"
                .to_string(),
        );
    }
    if entries.len() > MAX_ALLOWED_TRUST_DOMAINS {
        return Err(format!(
            "spiffe_identity: `allowed_trust_domains` admits at most \
             {MAX_ALLOWED_TRUST_DOMAINS} entries"
        ));
    }
    let mut domains: Vec<TrustDomain> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let Value::String(raw) = entry else {
            return Err(format!(
                "spiffe_identity: `allowed_trust_domains[{index}]` must be a string, got a JSON {}",
                json_type_name(entry)
            ));
        };
        // Name only the index: the trust-domain error echoes the value.
        let domain = TrustDomain::new(raw.as_str()).map_err(|_| {
            format!(
                "spiffe_identity: `allowed_trust_domains[{index}]` is not a valid SPIFFE trust \
                 domain (a bare lowercase trust domain such as `prod.example.com`, without the \
                 `spiffe://` scheme)"
            )
        })?;
        if domains.contains(&domain) {
            return Err(format!(
                "spiffe_identity: `allowed_trust_domains[{index}]` duplicates an earlier entry"
            ));
        }
        domains.push(domain);
    }
    Ok(Some(domains))
}

fn parse_forward_header(obj: &Map<String, Value>) -> Result<Option<String>, String> {
    let Some(value) = obj.get("forward_header") else {
        return Ok(None);
    };
    let Value::String(raw) = value else {
        return Err(format!(
            "spiffe_identity: `forward_header` must be a string, got a JSON {}",
            json_type_name(value)
        ));
    };
    let name = HeaderName::from_bytes(raw.as_bytes()).map_err(|_| {
        "spiffe_identity: `forward_header` is not a valid HTTP header name".to_string()
    })?;
    // The same refusal set claim-to-header mappings use — hop-by-hop and
    // framing fields, credentials, `x-consumer-*`, `x-forwarded-*`,
    // `x-ferrum-*`, `forwarded`, and the rest of the gateway-owned names —
    // plus the remaining gateway assertions (`x-geo-country`, the
    // `x-path-param-*` route captures), all compared as a CGI-style backend
    // reads them.
    if crate::plugins::utils::claim_header_fanout::is_output_claim_reserved_header(name.as_str())
        || crate::proxy::headers::is_gateway_assertion_header(name.as_str())
        || crate::proxy::headers::is_path_param_assertion_header(name.as_str())
    {
        return Err(
            "spiffe_identity: `forward_header` cannot target a gateway-owned, hop-by-hop, or \
             credential-bearing header"
                .to_string(),
        );
    }
    Ok(Some(name.as_str().to_string()))
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn fixed_reject(error: &'static str) -> PluginResult {
    PluginResult::Reject {
        status_code: 403,
        body: serde_json::json!({ "error": error }).to_string(),
        headers: HashMap::new(),
    }
}

/// `reason` is always one of this module's fixed, material-free strings.
fn invalid_svid_reject(reason: &'static str) -> PluginResult {
    debug!(
        "spiffe_identity: rejecting peer cert with invalid SPIFFE URI SAN: {}",
        reason
    );
    fixed_reject("invalid SPIFFE identity certificate")
}

fn identity_required_reject() -> PluginResult {
    debug!("spiffe_identity: rejecting peer without a usable SPIFFE identity (require_identity)");
    fixed_reject("SPIFFE identity required")
}

fn trust_domain_not_allowed_reject() -> PluginResult {
    debug!("spiffe_identity: rejecting peer SPIFFE identity outside allowed_trust_domains");
    fixed_reject("SPIFFE trust domain not allowed")
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

    /// Reusable (issue #5583) — the one credential-bearing plugin that is, and
    /// only because the credential it reads is the exact one the HBONE
    /// admission fence bounds.
    ///
    /// This plugin takes one per-request decision: derive the peer principal
    /// from the connection's mTLS leaf and re-decide that leaf's time validity,
    /// rejecting `403` once it is no longer current. Everything but the clock
    /// is fixed for the tunnel's whole life — an established inbound mTLS
    /// session is never re-handshaked, so every CONNECT on it carries the same
    /// leaf and derives the same principal. The clock half is precisely what
    /// the fence's credential gate re-issues (issue #5568): it retains that
    /// leaf's `notAfter` as a monotonic `AdmittedLeafExpiry` and revokes the
    /// tunnel `peer_expired` when it elapses (a bounded expiry watcher parks on
    /// the earliest live deadline, so the revocation does not wait for a
    /// publication), and it re-verifies the retained chain against the inbound
    /// admission anchors in force, revoking `peer_trust` when it no longer
    /// anchors. So the decision reuse elides is re-issued for the tunnel's
    /// whole life, by the deadline AND by the trust change — case (2) of the
    /// trait contract.
    ///
    /// This is NOT a precedent for bearer-credential plugins. The fence tracks
    /// the mTLS leaf and nothing else; a `jwt_auth`/`oidc`/`key_auth` token's
    /// own expiry reaches no live tunnel, and those plugins must keep refusing.
    ///
    /// An instance carrying an operator admission policy (`require_identity`
    /// or `allowed_trust_domains`) refuses: that verdict is a per-CONNECT
    /// decision no sweep re-issues, so a reload that tightens it must withdraw
    /// reuse (`reuse_withdrawn`) and force a fresh CONNECT judged by the new
    /// policy. `forward_header` only rewrites the CONNECT's own headers and
    /// leaves the classification unchanged.
    fn allows_hbone_inner_reuse(&self) -> bool {
        !self.require_identity && self.allowed_trust_domains.is_none()
    }

    /// Only an instance that forwards the identity to the backend touches
    /// backend-visible headers (`before_proxy`).
    fn modifies_request_headers(&self) -> bool {
        self.forward_header.is_some()
    }

    /// Audited (issue #6793): this plugin reads only the peer certificate and
    /// writes only the peer identity; it never reads, iterates or forwards the
    /// `mesh.*` workload labels in either metadata map.
    fn observes_mesh_label_metadata(&self) -> bool {
        false
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // A pre-stamped identity keeps precedence over peer-cert derivation;
        // only this instance's trust-domain policy still applies to it.
        if let Some(id) = ctx.peer_spiffe_id.as_ref() {
            if !self.admits_trust_domain(id.trust_domain()) {
                return trust_domain_not_allowed_reject();
            }
            return PluginResult::Continue;
        }
        let Some(der) = ctx.tls_client_cert_der.clone() else {
            return self.on_missing_identity();
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
                if !self.admits_trust_domain(id.trust_domain()) {
                    return trust_domain_not_allowed_reject();
                }
                debug!("spiffe_identity: peer SPIFFE ID extracted: {}", id);
                ctx.admit_certificate_spiffe_principal(id.clone(), deadline);
                PluginResult::Continue
            }
            PeerSpiffeExtraction::NoSpiffeId => self.on_missing_identity(),
            PeerSpiffeExtraction::Invalid(reason) => invalid_svid_reject(*reason),
            PeerSpiffeExtraction::Unparsed(error) => {
                debug!(
                    "spiffe_identity: could not parse peer cert for SPIFFE ID: {}",
                    error
                );
                self.on_missing_identity()
            }
        }
    }

    /// Forward the admitted identity to the backend when `forward_header` is
    /// configured. Every client-supplied copy is removed first — case-
    /// insensitively and with `_` read as `-`, the way a CGI-style backend
    /// folds names — so the backend never sees a value the client chose, even
    /// on a request that carries no identity.
    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let Some(forward_header) = self.forward_header.as_deref() else {
            return PluginResult::Continue;
        };
        headers.retain(|name, _| {
            !crate::proxy::headers::field_names_equivalent_for_backends(name, forward_header)
        });
        if let Some(id) = ctx.peer_spiffe_id.as_ref() {
            headers.insert(forward_header.to_string(), id.as_str().to_string());
        }
        PluginResult::Continue
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        // A pre-stamped peer identity (e.g. the node-waypoint eBPF-attested pod
        // SPIFFE ID set by the stream accept loop) must win over peer-cert
        // derivation here, mirroring the on_request_received guard. Otherwise a
        // TcpTls peer cert would clobber the kernel-attested pod principal that
        // mesh_authz uses for source-principal matching.
        if let Some(pre_stamped) = ctx.metadata.as_ref().and_then(|m| m.get("peer_spiffe_id")) {
            // Only this instance's trust-domain policy applies to it; a value
            // that does not even parse cannot be shown to be in an allowed
            // trust domain.
            if self.allowed_trust_domains.is_some()
                && !SpiffeId::new(pre_stamped.as_str())
                    .is_ok_and(|id| self.admits_trust_domain(id.trust_domain()))
            {
                return trust_domain_not_allowed_reject();
            }
            return PluginResult::Continue;
        }
        // Cloned rather than borrowed: the arms below take `&mut ctx` to admit
        // the principal, and an `Arc` clone is cheaper than restructuring the
        // hook around the borrow.
        let Some(der) = ctx.tls_client_cert_der.clone() else {
            return self.on_missing_identity();
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
                if !self.admits_trust_domain(id.trust_domain()) {
                    return trust_domain_not_allowed_reject();
                }
                debug!("spiffe_identity: stream peer SPIFFE ID: {}", id);
                ctx.admit_certificate_spiffe_principal(&id, deadline);
                PluginResult::Continue
            }
            PeerSpiffeExtraction::NoSpiffeId => self.on_missing_identity(),
            PeerSpiffeExtraction::Invalid(reason) => invalid_svid_reject(reason),
            PeerSpiffeExtraction::Unparsed(error) => {
                debug!(
                    "spiffe_identity: could not parse stream peer cert for SPIFFE ID: {}",
                    error
                );
                self.on_missing_identity()
            }
        }
    }
}
