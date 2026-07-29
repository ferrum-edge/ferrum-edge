//! CP-side namespace-bound verification credentials for the CP/DP control
//! plane (advisory GHSA-3f2j-wwqw-grmg).
//!
//! # Why a shared HS256 secret is not an authorization boundary
//!
//! Before this module every data plane, mesh node, and xDS client received the
//! fleet-wide `FERRUM_CP_DP_GRPC_JWT_SECRET` and minted its own HS256 token
//! carrying a self-asserted `ns` claim. The CP verified the signature with the
//! *same* value and then trusted the claim. Signature validation therefore
//! proved possession of a key every tenant already held; it could not
//! establish that the signer was entitled to the namespace it wrote into `ns`.
//! A compromised tenant-A node could re-sign `ns = "tenant-b"` and subscribe to
//! tenant B's ConfigSync, native mesh, or xDS configuration.
//!
//! # The binding
//!
//! Authorization is now **server-derived**. The CP loads a trust bundle
//! ([`CpDpTrustBundle`], `FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH`) in which every
//! verification credential is immutably bound by *CP-side configuration* to a
//! namespace allow-list:
//!
//! - The JWT header `kid` selects **which key verifies the signature**. It is
//!   never an authorization input: a bearer that names another tenant's `kid`
//!   simply fails the signature check, because it does not hold that key.
//! - The selected key's `namespaces` list is the ceiling. The token's `ns`
//!   claim may only **narrow** it (set intersection), never widen it.
//! - When the connection carries an authenticated mTLS peer whose certificate
//!   encodes a SPIFFE identity, the namespace derived from that identity is
//!   intersected too. A shared-CA certificate that encodes no SPIFFE namespace
//!   contributes nothing — certificate validation alone is not namespace
//!   authorization, and it can never widen the bound set.
//! - An empty intersection is refused before any tenant state is serialized.
//!
//! Asymmetric keys (`RS*`/`PS*`/`ES*`/`EdDSA`) are the preferred deployment:
//! the CP holds only public material, so no signing authority exists on any
//! data plane at all. The symmetric migration path (`HS*`) remains usable only
//! because each secret is *per-credential* and bound, CP-side, to the
//! namespaces that credential may reach.
//!
//! # Fail-closed startup
//!
//! A multi-namespace CP (`FERRUM_CP_NAMESPACES` naming a set, or `*`) refuses
//! to start when the only configured credential is the legacy fleet-wide
//! self-minting secret — see
//! [`CpDpVerifier::validate_for_scope`]. There is deliberately no unsafe
//! override and no legacy shim.
//!
//! Bundle loading also refuses a symmetric credential backed by the fleet-wide
//! `FERRUM_CP_DP_GRPC_JWT_SECRET` — by variable name for `secret_env`, and by
//! resolved bytes for `secret` / `secret_path`. Such a credential is
//! structurally valid but semantically identical to the pre-advisory posture:
//! every data plane already holds that value, so any of them could name the
//! credential's `kid` and reach its namespaces.
//!
//! # Disclosure discipline
//!
//! Nothing in this module renders key material, token bytes, or claim values.
//! Request-time rejections use the closed [`TenantAuthRejectReason`] set, whose
//! labels are compile-time constants suitable for metrics and audit records.
//! Startup errors name only operator-authored identifiers (`kid`, file path)
//! that the operator already wrote into their own configuration.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;

/// Upper bound on the trust-bundle document size. The file is operator-owned,
/// but a bounded read keeps a mistyped path (a device node, a huge log) from
/// allocating without limit during startup.
const TRUST_BUNDLE_MAX_BYTES: u64 = 1024 * 1024;

/// Upper bound on an operator-authored identifier (`kid`). Bounded so a
/// hostile-looking bundle cannot smuggle an unbounded string into startup
/// diagnostics.
const MAX_KEY_ID_LEN: usize = 128;

/// Minimum length for a symmetric (`HS*`) verification secret, matching the
/// admin-JWT convention elsewhere in the gateway.
const MIN_HS_SECRET_LEN: usize = 32;

/// The fleet-wide CP/DP secret. Backing a *bound* credential with this value
/// silently re-creates the advisory: every data plane already holds it, so any
/// of them could name that credential's `kid` and reach its namespaces. The
/// bundle would be structurally valid and semantically identical to the
/// pre-advisory posture, so loading refuses it outright.
const FLEET_SECRET_ENV: &str = "FERRUM_CP_DP_GRPC_JWT_SECRET";

/// Why a request-time tenant-authorization decision failed.
///
/// A closed, compile-time set used as a bounded metric/audit label. It is never
/// derived from caller-supplied bytes and never carries the token, a claim
/// value, a namespace, or any key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantAuthRejectReason {
    /// The JWS header could not be parsed at all.
    MalformedHeader,
    /// The CP runs a trust bundle but the token names no `kid`, so no
    /// verification credential can be selected deterministically.
    MissingKeyId,
    /// The token names a `kid` this control plane does not trust.
    UnknownKeyId,
    /// The token's `alg` is not the algorithm this credential is configured
    /// for. Refused before verification so a credential can never be used
    /// under an algorithm it was not provisioned for.
    AlgorithmMismatch,
    /// Signature or standard-claim validation failed after credential
    /// selection. Shares the outward message with [`Self::UnknownKeyId`] and
    /// [`Self::AlgorithmMismatch`] so callers cannot enumerate the trusted
    /// inventory from response text.
    TokenValidation,
    /// The bearer's credential, its `ns` claim, and any authenticated peer
    /// identity intersect to no namespace at all.
    NoAuthorizedNamespace,
}

impl TenantAuthRejectReason {
    /// Fixed-cardinality label for metrics and audit records.
    ///
    /// Kept available (and pinned by tests) even where no metric consumes it
    /// yet: the point of the closed set is that any future audit/metric sink
    /// has a bounded label to reach for instead of interpolating token data.
    #[allow(dead_code)]
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::MalformedHeader => "malformed_header",
            Self::MissingKeyId => "missing_key_id",
            Self::UnknownKeyId => "unknown_key_id",
            Self::AlgorithmMismatch => "algorithm_mismatch",
            Self::TokenValidation => "token_validation",
            Self::NoAuthorizedNamespace => "no_authorized_namespace",
        }
    }

    /// Operator-facing message. Deliberately fixed strings: the rejected token,
    /// its `kid`, its claims, and the trusted key inventory are all withheld so
    /// an unauthenticated caller cannot probe the CP's tenant configuration.
    ///
    /// Unknown-key, algorithm-mismatch, and signature/claims-validation
    /// failures share one outward string so response text cannot reveal whether
    /// selection reached a known credential. Missing `kid` stays actionable for
    /// trust-bundle migration.
    pub const fn as_status_message(self) -> &'static str {
        match self {
            Self::MalformedHeader => "Invalid token: malformed JWS header",
            Self::MissingKeyId => {
                "Invalid token: this control plane selects verification credentials by JWS \
                 `kid`, and the token carries none"
            }
            // Shared outward surface: must not distinguish unknown kid /
            // algorithm / signature-or-claims failure.
            Self::UnknownKeyId | Self::AlgorithmMismatch | Self::TokenValidation => {
                "Invalid token: authentication failed"
            }
            Self::NoAuthorizedNamespace => {
                "The presented credential is not authorized for any namespace on this control \
                 plane"
            }
        }
    }
}

/// Namespace scope derived from an authenticated mTLS peer certificate.
///
/// Populated only from a SPIFFE URI SAN of the Istio shape
/// `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`. A peer whose
/// certificate carries no SPIFFE namespace yields `None` — the connection is
/// still authenticated at the TLS layer, it simply contributes no namespace
/// evidence. This is the whole point of the advisory's "shared-CA certificate
/// validation alone is not namespace authorization" requirement: the value can
/// only ever *narrow* what a credential already permits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerNamespaceScope {
    namespaces: Arc<HashSet<String>>,
}

impl PeerNamespaceScope {
    /// Build a scope from a single namespace.
    pub fn single(namespace: impl Into<String>) -> Self {
        let mut set = HashSet::with_capacity(1);
        set.insert(namespace.into());
        Self {
            namespaces: Arc::new(set),
        }
    }

    pub fn namespaces(&self) -> &HashSet<String> {
        &self.namespaces
    }

    /// Derive the scope from a peer certificate chain, using the leaf.
    ///
    /// Returns `None` when there is no leaf, the leaf does not parse, it
    /// carries no SPIFFE URI SAN, or the SPIFFE path encodes no namespace.
    /// Every one of those is "no server-derived evidence", never "authorize
    /// everything".
    pub fn from_peer_cert_der(leaf_der: &[u8]) -> Option<Self> {
        let spiffe_id = crate::identity::spiffe::extract_spiffe_id_from_cert(leaf_der).ok()?;
        let namespace = spiffe_id.namespace()?;
        if namespace.is_empty() {
            return None;
        }
        Some(Self::single(namespace))
    }
}

/// Per-connection information the CP gRPC listener attaches to every request.
///
/// Replaces tonic's `TcpConnectInfo` so the mTLS peer's SPIFFE-derived
/// namespace scope — computed once at handshake completion, not per request —
/// travels with the connection. Requests arriving on a plaintext or
/// non-SPIFFE connection simply carry `peer_namespace_scope: None`.
#[derive(Clone, Debug, Default)]
pub struct CpGrpcConnectInfo {
    /// Preserved from tonic's `TcpConnectInfo`, which this type replaces, so
    /// swapping the connect-info type does not silently drop addresses a
    /// future handler or access log needs.
    #[allow(dead_code)]
    pub local_addr: Option<SocketAddr>,
    #[allow(dead_code)]
    pub remote_addr: Option<SocketAddr>,
    pub peer_namespace_scope: Option<PeerNamespaceScope>,
}

/// One trusted verification credential, bound to a namespace allow-list by
/// control-plane configuration.
pub struct TrustedKey {
    kid: String,
    algorithm: Algorithm,
    decoding_key: DecodingKey,
    /// Immutable namespace ceiling for every token this key verifies. Sourced
    /// exclusively from trusted CP configuration; a bearer can never change it.
    namespaces: HashSet<String>,
}

impl std::fmt::Debug for TrustedKey {
    /// Renders the operator-authored `kid` and algorithm only. The decoding key
    /// is credential material and is never formatted, even under `{:#?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedKey")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .field("namespace_count", &self.namespaces.len())
            .finish_non_exhaustive()
    }
}

/// The CP's trusted verification credentials, indexed by `kid`.
pub struct CpDpTrustBundle {
    keys: HashMap<String, TrustedKey>,
}

impl std::fmt::Debug for CpDpTrustBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CpDpTrustBundle")
            .field("key_count", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl CpDpTrustBundle {
    /// Load and validate a trust bundle document from `path`.
    ///
    /// Every failure is fatal at startup: a control plane that cannot state
    /// which credential may reach which tenant must not serve multi-tenant
    /// configuration at all.
    ///
    /// `fleet_secret` is the effective `FERRUM_CP_DP_GRPC_JWT_SECRET`, when the
    /// operator configured one. It is used only to *refuse* a bound credential
    /// backed by that value; it is never rendered.
    pub fn load_from_path(path: &str, fleet_secret: Option<&str>) -> Result<Self, String> {
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("failed to stat CP/DP trust bundle '{path}': {e}"))?;
        if !metadata.is_file() {
            return Err(format!("CP/DP trust bundle '{path}' is not a regular file"));
        }
        if metadata.len() > TRUST_BUNDLE_MAX_BYTES {
            return Err(format!(
                "CP/DP trust bundle '{path}' is {} bytes, above the {TRUST_BUNDLE_MAX_BYTES}-byte limit",
                metadata.len()
            ));
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read CP/DP trust bundle '{path}': {e}"))?;
        Self::from_document_str(&raw, path, fleet_secret)
    }

    /// Parse and validate a trust-bundle document. `origin` is used only in
    /// error text so an operator can tell which file failed. `fleet_secret` is
    /// the effective `FERRUM_CP_DP_GRPC_JWT_SECRET`, used only to refuse a
    /// credential backed by it.
    pub fn from_document_str(
        raw: &str,
        origin: &str,
        fleet_secret: Option<&str>,
    ) -> Result<Self, String> {
        let document: TrustBundleDocument = serde_json::from_str(raw)
            .map_err(|e| format!("CP/DP trust bundle '{origin}' is not valid JSON: {e}"))?;
        if let Some(version) = document.version
            && version != 1
        {
            return Err(format!(
                "CP/DP trust bundle '{origin}' declares unsupported version {version}; only \
                 version 1 is understood"
            ));
        }
        if document.keys.is_empty() {
            return Err(format!(
                "CP/DP trust bundle '{origin}' declares no keys; a control plane with no \
                 verification credential can authorize nothing"
            ));
        }

        let mut keys: HashMap<String, TrustedKey> = HashMap::with_capacity(document.keys.len());
        for entry in document.keys {
            let key = entry.into_trusted_key(origin, fleet_secret)?;
            if keys.contains_key(&key.kid) {
                // Ambiguous key selection is a configuration error, not a
                // runtime tie-break: two credentials answering to one `kid`
                // would make which namespaces a token can reach depend on map
                // ordering.
                return Err(format!(
                    "CP/DP trust bundle '{origin}' declares duplicate kid '{}'; key selection \
                     must be unambiguous",
                    key.kid
                ));
            }
            keys.insert(key.kid.clone(), key);
        }

        Ok(Self { keys })
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Every namespace any trusted credential may reach. Startup uses this to
    /// warn about served namespaces no credential can subscribe to.
    pub fn bound_namespaces(&self) -> HashSet<&str> {
        self.keys
            .values()
            .flat_map(|key| key.namespaces.iter().map(String::as_str))
            .collect()
    }

    /// Select the verification credential for a token header.
    ///
    /// `kid` is a **selector**, never an authorization input: naming another
    /// tenant's key without holding it fails the subsequent signature check.
    /// `alg` must equal the credential's configured algorithm, so a credential
    /// can never be exercised under an algorithm it was not provisioned for.
    pub fn select(
        &self,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<&TrustedKey, TenantAuthRejectReason> {
        let kid = kid
            .map(str::trim)
            .filter(|kid| !kid.is_empty())
            .ok_or(TenantAuthRejectReason::MissingKeyId)?;
        let key = self
            .keys
            .get(kid)
            .ok_or(TenantAuthRejectReason::UnknownKeyId)?;
        if key.algorithm != alg {
            return Err(TenantAuthRejectReason::AlgorithmMismatch);
        }
        Ok(key)
    }
}

/// How the control plane verifies inbound CP/DP gRPC tokens.
pub enum CpDpVerifier {
    /// Legacy fleet-wide HS256 secret (`FERRUM_CP_DP_GRPC_JWT_SECRET`).
    ///
    /// Provides **no** server-derived namespace binding: everyone who can
    /// present a token can also mint one. It stays supported only where it is
    /// security-equivalent — a genuinely single-namespace control plane, where
    /// there is no second tenant to cross into. Multi-namespace startup
    /// refuses it (see [`CpDpVerifier::validate_for_scope`]).
    SharedSecret(String),
    /// Namespace-bound verification credentials selected by JWS `kid`.
    TrustBundle(CpDpTrustBundle),
}

impl std::fmt::Debug for CpDpVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The secret is credential material and is never rendered.
            Self::SharedSecret(_) => f.write_str("CpDpVerifier::SharedSecret(<redacted>)"),
            Self::TrustBundle(bundle) => f
                .debug_tuple("CpDpVerifier::TrustBundle")
                .field(bundle)
                .finish(),
        }
    }
}

impl CpDpVerifier {
    /// True when this verifier provides server-derived namespace binding.
    pub fn has_namespace_binding(&self) -> bool {
        matches!(self, Self::TrustBundle(_))
    }

    /// Fixed-cardinality description for startup logs. Never renders material.
    pub fn describe(&self) -> String {
        match self {
            Self::SharedSecret(_) => {
                "legacy fleet-wide FERRUM_CP_DP_GRPC_JWT_SECRET (no namespace binding)".to_string()
            }
            Self::TrustBundle(bundle) => format!(
                "namespace-bound trust bundle ({} verification credential(s))",
                bundle.key_count()
            ),
        }
    }

    /// Refuse a multi-namespace control plane whose only credential is the
    /// fleet-wide self-minting secret.
    ///
    /// This is the advisory's fail-closed startup requirement. A single
    /// namespace stays usable with the legacy secret because it is genuinely
    /// security-equivalent: there is no other tenant on this control plane for
    /// a forged `ns` claim to reach, and the CP scope check refuses anything
    /// else regardless.
    pub fn validate_for_scope(&self, multi_namespace: bool) -> Result<(), String> {
        if !multi_namespace || self.has_namespace_binding() {
            return Ok(());
        }
        Err(
            "Refusing to start a multi-namespace control plane with only the fleet-wide \
             FERRUM_CP_DP_GRPC_JWT_SECRET. That value is distributed to the very data planes and \
             mesh nodes it is used to authorize, so any tenant holding it can re-sign an `ns` \
             claim naming another tenant (advisory GHSA-3f2j-wwqw-grmg). Configure \
             FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH with per-tenant verification credentials — \
             preferably asymmetric public keys, so no signing authority exists on any data plane \
             — or run one single-namespace control plane per tenant."
                .to_string(),
        )
    }

    /// Resolve the credential for `kid`/`alg` and hand it to `f`.
    ///
    /// The closure form exists because the legacy shared-secret arm has to
    /// build its `DecodingKey` on the fly (the secret is stored as a `String`),
    /// so it cannot lend one out. Both arms therefore go through one seam and
    /// the caller never branches on the verifier shape.
    pub fn with_decoding_key<T>(
        &self,
        kid: Option<&str>,
        alg: Algorithm,
        f: impl FnOnce(&DecodingKey, Algorithm, Option<&HashSet<String>>) -> T,
    ) -> Result<T, TenantAuthRejectReason> {
        match self {
            Self::SharedSecret(secret) => {
                if alg != Algorithm::HS256 {
                    return Err(TenantAuthRejectReason::AlgorithmMismatch);
                }
                // Defense in depth. Startup refuses an empty
                // FERRUM_CP_DP_GRPC_JWT_SECRET when no trust bundle is
                // configured, and a bundle-configured CP replaces this arm
                // outright — but every server builder still *seeds* itself
                // with `SharedSecret(jwt_secret)`, and a trust-bundle CP
                // threads `cp_dp_grpc_jwt_secret.unwrap_or_default()` (i.e.
                // `""`) into those builders for token *minting*. A future
                // call site that forgot `.verifier(..)` would otherwise
                // verify against the empty HS256 key and accept anything.
                if secret.is_empty() {
                    return Err(TenantAuthRejectReason::TokenValidation);
                }
                let key = DecodingKey::from_secret(secret.as_bytes());
                Ok(f(&key, Algorithm::HS256, None))
            }
            Self::TrustBundle(bundle) => {
                let key = bundle.select(kid, alg)?;
                Ok(f(&key.decoding_key, key.algorithm, Some(&key.namespaces)))
            }
        }
    }
}

/// Intersect the credential's namespace ceiling with the bearer's `ns` claim
/// and any authenticated peer scope.
///
/// Order matters only for readability; intersection is commutative. What is
/// load-bearing is that **every** input can only remove namespaces:
///
/// - `bound` — CP configuration. The ceiling. `None` for the legacy shared
///   secret, which supplies no ceiling at all (single-namespace CPs only).
/// - `peer` — server-derived mTLS/SPIFFE evidence, when present.
/// - `claim` — the bearer's self-asserted `ns`. Narrows, never widens.
///
/// An empty result is an error, not an empty allow-set, so a mis-scoped
/// credential fails loudly at authentication instead of silently failing every
/// later namespace check.
pub fn resolve_authorized_namespaces(
    bound: Option<&HashSet<String>>,
    peer: Option<&PeerNamespaceScope>,
    claim: Option<&HashSet<String>>,
) -> Result<Option<HashSet<String>>, TenantAuthRejectReason> {
    let mut server_scope: Option<HashSet<String>> = bound.cloned();

    if let Some(peer) = peer {
        server_scope = Some(match server_scope {
            Some(scope) => scope
                .intersection(peer.namespaces())
                .cloned()
                .collect::<HashSet<String>>(),
            None => peer.namespaces().clone(),
        });
    }

    let Some(server_scope) = server_scope else {
        // Legacy shared secret with no peer identity: there is no
        // server-derived scope to intersect, so the claim carries through
        // unchanged. Reachable only on single-namespace control planes —
        // `CpDpVerifier::validate_for_scope` refuses this combination for
        // `Set`/`All` at startup.
        return Ok(claim.cloned());
    };

    let effective: HashSet<String> = match claim {
        Some(claim) => server_scope.intersection(claim).cloned().collect(),
        None => server_scope,
    };

    if effective.is_empty() {
        return Err(TenantAuthRejectReason::NoAuthorizedNamespace);
    }
    Ok(Some(effective))
}

// ── Trust-bundle document ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustBundleDocument {
    #[serde(default)]
    version: Option<u32>,
    keys: Vec<TrustBundleKeyDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustBundleKeyDocument {
    /// Selector matched against the JWS header `kid`.
    kid: String,
    /// JWS algorithm this credential verifies, e.g. `RS256`, `ES256`,
    /// `EdDSA`, or `HS256` for the symmetric migration path.
    algorithm: String,
    /// The immutable namespace allow-list for this credential.
    namespaces: Vec<String>,
    /// Symmetric secret, inline. Prefer `secret_env` or `secret_path`.
    #[serde(default)]
    secret: Option<String>,
    /// Name of an environment variable holding the symmetric secret.
    #[serde(default)]
    secret_env: Option<String>,
    /// Path to a file holding the symmetric secret.
    #[serde(default)]
    secret_path: Option<String>,
    /// PEM-encoded public key, inline. Public material, never a secret.
    #[serde(default)]
    public_key_pem: Option<String>,
    /// Path to a PEM-encoded public key.
    #[serde(default)]
    public_key_path: Option<String>,
}

/// Renders only operator-authored identifiers. The `secret` field carries raw
/// symmetric key material, so the derived `Debug` is deliberately not used —
/// this mirrors [`TrustedKey`]'s hand-written impl and keeps an accidental
/// `{:?}` in an error path from printing a tenant's signing secret.
impl std::fmt::Debug for TrustBundleKeyDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustBundleKeyDocument")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .field("namespaces", &self.namespaces)
            .field("secret", &"<redacted>")
            .field("secret_env", &self.secret_env)
            .field("secret_path", &self.secret_path)
            .field("public_key_pem", &self.public_key_pem)
            .field("public_key_path", &self.public_key_path)
            .finish()
    }
}

/// Diagnostic for a bound credential backed by the fleet-wide secret.
///
/// Renders only operator-authored identifiers (`origin`, `kid`) and the
/// variable *name*; no key material of either credential is included.
fn fleet_secret_reuse_error(origin: &str, kid: &str) -> String {
    format!(
        "CP/DP trust bundle '{origin}': key '{kid}' is backed by the fleet-wide \
         {FLEET_SECRET_ENV}. Every data plane holds that value, so any of them could name this \
         `kid` and reach this credential's namespaces — the cross-tenant forgery advisory \
         GHSA-3f2j-wwqw-grmg exists to close. Give each credential its own material, or use an \
         asymmetric public key so no data plane can sign at all."
    )
}

impl TrustBundleKeyDocument {
    fn into_trusted_key(
        self,
        origin: &str,
        fleet_secret: Option<&str>,
    ) -> Result<TrustedKey, String> {
        let kid = self.kid.trim().to_string();
        if kid.is_empty() {
            return Err(format!(
                "CP/DP trust bundle '{origin}': every key requires a non-empty `kid`"
            ));
        }
        if kid.len() > MAX_KEY_ID_LEN {
            return Err(format!(
                "CP/DP trust bundle '{origin}': `kid` exceeds {MAX_KEY_ID_LEN} bytes"
            ));
        }
        if kid.chars().any(char::is_control) {
            return Err(format!(
                "CP/DP trust bundle '{origin}': `kid` must not contain control characters"
            ));
        }

        let algorithm: Algorithm = self.algorithm.trim().parse().map_err(|_| {
            format!(
                "CP/DP trust bundle '{origin}': key '{kid}' declares unsupported algorithm '{}'",
                self.algorithm.trim()
            )
        })?;

        let mut namespaces = HashSet::with_capacity(self.namespaces.len());
        for raw in &self.namespaces {
            let namespace = raw.trim();
            if namespace.is_empty() {
                return Err(format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' lists an empty namespace"
                ));
            }
            if namespace.chars().any(char::is_control) {
                return Err(format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' lists a namespace containing \
                     control characters"
                ));
            }
            namespaces.insert(namespace.to_string());
        }
        if namespaces.is_empty() {
            // A credential bound to nothing would authenticate and then
            // authorize nothing. That is almost certainly an operator mistake,
            // and accepting it silently would hide a broken tenant rollout.
            return Err(format!(
                "CP/DP trust bundle '{origin}': key '{kid}' must list at least one namespace"
            ));
        }

        let symmetric = matches!(
            algorithm,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        );
        let secret_sources = usize::from(self.secret.is_some())
            + usize::from(self.secret_env.is_some())
            + usize::from(self.secret_path.is_some());
        let public_sources = usize::from(self.public_key_pem.is_some())
            + usize::from(self.public_key_path.is_some());

        if secret_sources + public_sources != 1 {
            return Err(format!(
                "CP/DP trust bundle '{origin}': key '{kid}' must declare exactly one of \
                 `secret`, `secret_env`, `secret_path`, `public_key_pem`, or `public_key_path` \
                 (found {})",
                secret_sources + public_sources
            ));
        }
        if symmetric && public_sources == 1 {
            return Err(format!(
                "CP/DP trust bundle '{origin}': key '{kid}' declares symmetric algorithm \
                 '{algorithm:?}' with public-key material"
            ));
        }
        if !symmetric && secret_sources == 1 {
            return Err(format!(
                "CP/DP trust bundle '{origin}': key '{kid}' declares asymmetric algorithm \
                 '{algorithm:?}' with symmetric secret material"
            ));
        }

        let decoding_key = if symmetric {
            let secret = if let Some(inline) = self.secret {
                inline
            } else if let Some(var) = self.secret_env.as_deref() {
                // Naming the fleet variable is refused by *name*, before the
                // read: it is unambiguous operator intent to bind a credential
                // to the value every data plane already holds, and the
                // by-value check below cannot see it when the effective
                // secret was configured through `ferrum.conf` instead.
                if var.trim() == FLEET_SECRET_ENV {
                    return Err(fleet_secret_reuse_error(origin, &kid));
                }
                std::env::var(var).map_err(|_| {
                    format!(
                        "CP/DP trust bundle '{origin}': key '{kid}' references environment \
                         variable '{var}', which is unset or not valid UTF-8"
                    )
                })?
            } else if let Some(path) = self.secret_path.as_deref() {
                std::fs::read_to_string(path)
                    .map_err(|e| {
                        format!(
                            "CP/DP trust bundle '{origin}': key '{kid}' secret file '{path}' \
                             could not be read: {e}"
                        )
                    })?
                    .trim()
                    .to_string()
            } else {
                // Unreachable: the source-count check above admits exactly one.
                return Err(format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' has no readable secret source"
                ));
            };
            if secret.len() < MIN_HS_SECRET_LEN {
                // Length only — the value itself is never rendered.
                return Err(format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' symmetric secret must be at \
                     least {MIN_HS_SECRET_LEN} bytes"
                ));
            }
            // Whatever source it came from — inline, env, or file — a bound
            // credential must not carry the fleet-wide secret. Comparing the
            // resolved bytes is what makes `secret_path` (a symlink or copy of
            // the same material) detectable at all.
            if fleet_secret.is_some_and(|fleet| !fleet.is_empty() && fleet == secret.as_str()) {
                return Err(fleet_secret_reuse_error(origin, &kid));
            }
            DecodingKey::from_secret(secret.as_bytes())
        } else {
            let pem = if let Some(inline) = self.public_key_pem {
                inline
            } else if let Some(path) = self.public_key_path.as_deref() {
                std::fs::read_to_string(path).map_err(|e| {
                    format!(
                        "CP/DP trust bundle '{origin}': key '{kid}' public key file '{path}' \
                         could not be read: {e}"
                    )
                })?
            } else {
                return Err(format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' has no readable public key source"
                ));
            };
            let bytes = pem.as_bytes();
            let parsed = match algorithm {
                Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512 => DecodingKey::from_rsa_pem(bytes),
                Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(bytes),
                Algorithm::EdDSA => DecodingKey::from_ed_pem(bytes),
                Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                    // Unreachable: `symmetric` covers these above.
                    return Err(format!(
                        "CP/DP trust bundle '{origin}': key '{kid}' algorithm/material mismatch"
                    ));
                }
            };
            parsed.map_err(|e| {
                format!(
                    "CP/DP trust bundle '{origin}': key '{kid}' public key is not valid PEM for \
                     '{algorithm:?}': {e}"
                )
            })?
        };

        Ok(TrustedKey {
            kid,
            algorithm,
            decoding_key,
            namespaces,
        })
    }
}
