//! Shared authentication helpers for Ferrum control-plane gRPC surfaces.
//!
//! `ConfigSync` and xDS ADS are separate services, but both enforce the same
//! CP/DP security boundary: HS256 JWT in `authorization` metadata, standard
//! time claims required, and issuer pinned to `FERRUM_CP_DP_GRPC_JWT_ISSUER`.
//!
//! # Audience binding (issue #2475)
//!
//! Issuer + expiry + signature bind a token to a *credential*, not to a
//! *destination*. Two clusters that share the deprecated fallback
//! `FERRUM_CP_DP_GRPC_JWT_SECRET` and the same issuer therefore used to accept
//! each other's cross-cluster remote-discovery tokens. Every gRPC surface now
//! runs an explicit [`GrpcAudiencePolicy`] on top of the existing checks:
//!
//! - Cross-cluster mesh **remote discovery** (`MeshSubscribe` with
//!   `remote_discovery = true`) requires exactly one `aud`, equal to
//!   [`remote_discovery_audience`] of the *receiving* cluster's configured
//!   `FERRUM_MESH_CLUSTER_AUDIENCE`. Missing, malformed, multiple/ambiguous,
//!   or mismatched audiences are refused, and so is an unconfigured receiver.
//! - Ordinary local mesh `MeshSubscribe` requires exactly one `aud`, equal to
//!   [`MESH_LOCAL_SUBSCRIBE_AUDIENCE`]. Requiring a distinct local purpose
//!   prevents a legacy no-audience token from selecting the local branch by
//!   sending the proto3 default `remote_discovery = false`.
//! - Ordinary CP↔DP `ConfigSync` and xDS ADS remain unchanged and run
//!   [`GrpcAudiencePolicy::ReservedForbidden`]: those token classes carry no
//!   `aud`, so any audience at all is refused, preserving `jsonwebtoken`'s
//!   strict `validate_aud` posture.

use jsonwebtoken::{Validation, decode, decode_header};
use serde_json::Value;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio::time::{Instant, Sleep};
use tonic::Status;
use tracing::{info, warn};

use super::cp_trust::{
    CpDpVerifier, CpDpVerifierSnapshot, CpDpVerifierStore, CpGrpcConnectInfo,
    TenantAuthRejectReason, VerificationCredentialIdentity, resolve_authorized_namespaces,
};

/// `jsonwebtoken`'s accepted clock leeway, pinned explicitly so the
/// post-verification stream deadline uses exactly the same allowance as the
/// signature/claim verifier instead of silently drifting with a dependency
/// default.
pub const GRPC_JWT_LEEWAY_SECONDS: u64 = 60;

/// Default independent server-side ceiling for authenticated configuration
/// streams. The operator may lower or raise it within the validated bounds,
/// but cannot disable it.
pub const DEFAULT_GRPC_MAX_STREAM_LIFETIME_SECONDS: u64 = 3_600;
pub const MIN_GRPC_MAX_STREAM_LIFETIME_SECONDS: u64 = 60;
pub const MAX_GRPC_MAX_STREAM_LIFETIME_SECONDS: u64 = 86_400;

fn bounded_server_lifetime(lifetime: Duration) -> Duration {
    lifetime.min(Duration::from_secs(MAX_GRPC_MAX_STREAM_LIFETIME_SECONDS))
}

/// Reserved JWT `aud` prefix for cross-cluster mesh **remote-discovery**
/// tokens. The prefix is what makes the token class self-describing: any
/// surface that is not the remote-discovery verifier refuses a token carrying
/// it, so the class cannot be silently substituted for an ordinary CP↔DP or
/// local mesh subscription token.
pub const MESH_REMOTE_DISCOVERY_AUDIENCE_PREFIX: &str = "ferrum-mesh-discovery:";

/// Stable JWT `aud` for an ordinary local mesh `MeshSubscribe`.
///
/// This is a purpose identifier, not a target-cluster identifier. Local mesh
/// subscriptions and cross-cluster discovery must remain cryptographically
/// distinct even when they share the same HS256 secret and issuer.
pub const MESH_LOCAL_SUBSCRIBE_AUDIENCE: &str = "ferrum-mesh-subscribe:local";

/// Build the remote-discovery audience for a target cluster.
///
/// `cluster_id` is the **stable, operator-visible** target-cluster identifier —
/// `RemoteCluster.name` on the polling data plane and
/// `FERRUM_MESH_CLUSTER_AUDIENCE` on the receiving control plane. It is
/// deliberately independent of `control_plane_url`: the endpoint is mutable
/// (DNS, ports, migration between load balancers) and must never be the thing a
/// credential is bound to.
///
/// Mesh validation rejects leading/trailing whitespace on `RemoteCluster.name`
/// (and `local_cluster`) so the configured identity matches this audience
/// one-to-one. `trim()` here remains defense in depth for the already-canonical
/// `FERRUM_MESH_CLUSTER_AUDIENCE` env path.
pub fn remote_discovery_audience(cluster_id: &str) -> String {
    format!(
        "{MESH_REMOTE_DISCOVERY_AUDIENCE_PREFIX}{}",
        cluster_id.trim()
    )
}

/// What a gRPC surface accepts in the JWT `aud` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcAudiencePolicy<'a> {
    /// The surface has no audience of its own, so a token must carry none.
    ///
    /// This preserves `jsonwebtoken`'s strict `validate_aud = true` posture for
    /// these surfaces (RFC 7519 §4.1.3): a token stamped for *some* audience
    /// was minted for a purpose this surface cannot check, and honoring it
    /// whenever the HS256 secret is shared is exactly the substitution this
    /// binding exists to prevent. A MeshSubscribe-purpose audience is reported
    /// separately from an unrelated one so operators can tell a cross-surface
    /// replay attempt apart from a misconfigured token minter.
    ReservedForbidden,
    /// The surface requires exactly one audience, equal to this value.
    Required(&'a str),
    /// The surface requires an audience but none is configured. Always fails
    /// closed — a receiver that cannot state its own identity must not accept
    /// a cross-cluster credential.
    Unconfigured,
}

/// Why an audience check failed. A closed, compile-time set used as a bounded
/// metric/audit label — never a caller-supplied string, and never the token or
/// any part of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudienceRejectReason {
    /// The surface requires an audience and the token carries none.
    Missing,
    /// The `aud` claim is present but not a non-empty string / array of
    /// non-empty strings.
    Malformed,
    /// The `aud` claim carries more than one value, so the intended target is
    /// ambiguous. Fail closed rather than accepting on any match.
    Ambiguous,
    /// A single, well-formed audience that is not this surface's audience.
    Mismatch,
    /// The receiver has no audience configured but the request requires one.
    Unconfigured,
    /// A reserved MeshSubscribe audience reached a non-MeshSubscribe surface.
    ReservedAudience,
    /// A surface that expects no audience received a token carrying one.
    UnexpectedAudience,
}

impl AudienceRejectReason {
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::Ambiguous => "ambiguous",
            Self::Mismatch => "mismatch",
            Self::Unconfigured => "unconfigured",
            Self::ReservedAudience => "reserved_audience",
            Self::UnexpectedAudience => "unexpected_audience",
        }
    }

    /// Operator-facing message. Deliberately fixed strings: the rejected token
    /// (and any claim value inside it) is credential material and is never
    /// echoed back to the caller or into a log line.
    pub const fn as_status_message(self) -> &'static str {
        match self {
            Self::Missing => "Invalid token: required audience claim is missing",
            Self::Malformed => "Invalid token: audience claim is malformed",
            Self::Ambiguous => "Invalid token: audience claim is ambiguous",
            Self::Mismatch => {
                "Invalid token: audience claim does not match this subscription purpose"
            }
            Self::Unconfigured => {
                "Remote-cluster discovery is not enabled here: this control plane has no \
                 FERRUM_MESH_CLUSTER_AUDIENCE configured"
            }
            Self::ReservedAudience => {
                "Invalid token: audience claim is reserved for another subscription purpose"
            }
            Self::UnexpectedAudience => "Invalid token: this surface accepts no audience claim",
        }
    }
}

/// Normalize the `aud` claim into at most one audience value.
///
/// RFC 7519 allows `aud` to be a string or an array of strings. Ferrum accepts
/// both shapes but only a *single* value: a multi-audience token does not state
/// an unambiguous target, and honoring it on any match would reintroduce the
/// cross-cluster acceptance this binding exists to prevent.
fn parse_audience_claim(claims: &Value) -> Result<Option<String>, AudienceRejectReason> {
    let raw = match claims.get("aud") {
        Some(value) => value,
        None => return Ok(None),
    };

    if let Some(single) = raw.as_str() {
        let trimmed = single.trim();
        if trimmed.is_empty() {
            return Err(AudienceRejectReason::Malformed);
        }
        return Ok(Some(trimmed.to_string()));
    }

    if let Some(values) = raw.as_array() {
        if values.is_empty() {
            // Present but empty: an explicit, unusable claim. Never downgrade
            // it to "absent" — that would let a malformed token fall through
            // to a policy that only checks for a reserved prefix.
            return Err(AudienceRejectReason::Malformed);
        }
        let mut normalized = Vec::with_capacity(values.len());
        for value in values {
            let Some(entry) = value.as_str() else {
                return Err(AudienceRejectReason::Malformed);
            };
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                return Err(AudienceRejectReason::Malformed);
            }
            normalized.push(trimmed.to_string());
        }
        if normalized.len() > 1 {
            return Err(AudienceRejectReason::Ambiguous);
        }
        // `normalized` is non-empty here (the empty array returned above and
        // dedup cannot empty a non-empty vector).
        return Ok(normalized.pop());
    }

    Err(AudienceRejectReason::Malformed)
}

/// Apply a [`GrpcAudiencePolicy`] to the decoded claims.
fn enforce_audience(
    claims: &Value,
    policy: GrpcAudiencePolicy<'_>,
) -> Result<(), AudienceRejectReason> {
    // The claim is parsed (and can be rejected as malformed/ambiguous) under
    // every policy, including `ReservedForbidden`, so a hostile shape never
    // reaches a surface by being unreadable.
    let audience = parse_audience_claim(claims)?;
    match policy {
        GrpcAudiencePolicy::Unconfigured => Err(AudienceRejectReason::Unconfigured),
        GrpcAudiencePolicy::Required(expected) => match audience {
            Some(found) if found == expected => Ok(()),
            Some(_) => Err(AudienceRejectReason::Mismatch),
            None => Err(AudienceRejectReason::Missing),
        },
        GrpcAudiencePolicy::ReservedForbidden => match audience {
            None => Ok(()),
            Some(found)
                if found == MESH_LOCAL_SUBSCRIBE_AUDIENCE
                    || found.starts_with(MESH_REMOTE_DISCOVERY_AUDIENCE_PREFIX) =>
            {
                Err(AudienceRejectReason::ReservedAudience)
            }
            Some(_) => Err(AudienceRejectReason::UnexpectedAudience),
        },
    }
}

/// Namespaces a DP ConfigSync JWT bearer is authorised to subscribe to.
///
/// Two independent facts are tracked:
///
/// - **Claim presence** ([`Self::is_present`]) — whether the JWT body
///   contained an `ns` claim at all (including an empty array). Multi-namespace
///   CP scopes, and single-namespace CPs with
///   `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM=true`, require this to be true. A
///   server-derived ceiling (trust-bundle credential or SPIFFE peer) must
///   never make a missing claim look present.
/// - **Effective set** ([`Self::effective_namespaces`], [`Self::allows`],
///   [`Self::sole_namespace`]) — the authorized namespaces after
///   credential ∩ peer ∩ claim. Mesh/xDS bearer filtering and per-request
///   namespace checks use this set. It may be `Some` even when the token
///   carried no `ns` claim (single-scope CP with `require_ns_claim=false`
///   still applies the intersected bound).
///
/// The admin JWT parser only sees the claim (no server-derived ceiling), so
/// for that path claim presence and the effective set stay aligned via
/// [`Self::claimed`] / [`Self::empty`].
///
/// Tokens may carry the claim as either a single string (`"ns": "prod"`) or
/// an array (`"ns": ["prod","staging"]`). The verifier normalises both into
/// a `HashSet<String>` here so callers don't have to branch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowedNamespaces {
    /// Whether the JWT body contained an `ns` claim (any value, even empty).
    claim_present: bool,
    /// Authorized namespaces after credential ∩ peer ∩ claim.
    ///
    /// `None` only when there is no server-derived ceiling and the token
    /// carried no claim (legacy single-namespace shared-secret path).
    effective: Option<HashSet<String>>,
}

impl AllowedNamespaces {
    /// Empty (no claim present, no effective bound).
    pub fn empty() -> Self {
        Self {
            claim_present: false,
            effective: None,
        }
    }

    /// Construct from a parsed `ns` claim. Marks the claim present.
    ///
    /// Used by the admin JWT parser and by unit tests that model a claim
    /// without going through CP-side credential intersection.
    pub fn claimed(set: HashSet<String>) -> Self {
        Self {
            claim_present: true,
            effective: Some(set),
        }
    }

    /// Server-resolved authorization: claim presence tracked separately from
    /// the effective intersection produced by credential ∩ peer ∩ claim.
    pub(crate) fn resolved(claim_present: bool, effective: Option<HashSet<String>>) -> Self {
        Self {
            claim_present,
            effective,
        }
    }

    /// True when the JWT contained an `ns` claim (any value, even empty array).
    ///
    /// Independent of whether a trust-bundle or SPIFFE peer later produced an
    /// effective namespace set. This is the contract the admin API and
    /// `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM` rely on.
    pub fn is_present(&self) -> bool {
        self.claim_present
    }

    /// Effective authorized namespaces after credential ∩ peer ∩ claim.
    ///
    /// Used by mesh/xDS bearer filtering. `None` means no server-derived
    /// ceiling and no claim (legacy single-namespace shared-secret path).
    pub fn effective_namespaces(&self) -> Option<&HashSet<String>> {
        self.effective.as_ref()
    }

    /// True when the bearer is authorised for `namespace` under the effective
    /// set. Returns `false` when there is no effective set — callers must
    /// combine with the back-compat fallback logic for legacy single-namespace
    /// shared-secret tokens that carry no claim.
    pub fn allows(&self, namespace: &str) -> bool {
        match &self.effective {
            Some(set) => set.contains(namespace),
            None => false,
        }
    }

    /// Return the only authorised namespace when the effective set contains
    /// exactly one namespace. Protocols without an explicit namespace request
    /// use this to avoid guessing tenant identity from node metadata.
    pub fn sole_namespace(&self) -> Option<&str> {
        let set = self.effective.as_ref()?;
        if set.len() == 1 {
            set.iter().next().map(String::as_str)
        } else {
            None
        }
    }
}

#[allow(clippy::result_large_err, dead_code)]
pub(crate) fn verify_grpc_jwt_metadata(
    metadata: &tonic::metadata::MetadataMap,
    verifier: &CpDpVerifier,
    expected_issuer: &str,
) -> Result<(), Status> {
    verify_grpc_jwt_metadata_with_claims(metadata, verifier, expected_issuer, None).map(|_| ())
}

/// Authenticated gRPC bearer identity: tenant namespace ceiling plus the JWT
/// `sub` used as the canonical DP node identity (issue #3265).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGrpcIdentity {
    pub allowed_namespaces: AllowedNamespaces,
    /// Non-empty JWT `sub`. Callers must treat this as the sole trusted node
    /// identity and must not prefer any caller-supplied display field.
    pub subject: String,
    /// Monotonic authorization deadline derived from the `exp` value in the
    /// claims object returned by successful signature/issuer/time validation,
    /// including the verifier's accepted leeway.
    pub authorization_deadline: Instant,
    /// Monotonic instant at which verification completed. Server maximum
    /// lifetime is anchored here, before snapshot construction can consume
    /// part of the admitted lifetime.
    admitted_at: Instant,
    /// Exact credential selected during successful verification. Opaque and
    /// never logged or exported.
    pub(crate) credential: VerificationCredentialIdentity,
    /// Store generation in which this exact credential was admitted. A key
    /// removed and later re-added receives a new generation, so old streams
    /// cannot survive by missing a rapid remove/re-add notification.
    pub(crate) credential_generation: u64,
}

impl VerifiedGrpcIdentity {
    fn bind_to_store(
        mut self,
        snapshot: &CpDpVerifierSnapshot,
        verifier: &CpDpVerifierStore,
    ) -> Result<Self, Status> {
        let generation = verifier
            .active_generation_from_snapshot(snapshot, &self.credential)
            .ok_or_else(|| {
                Status::permission_denied("Stream verification credential is no longer trusted")
            })?;
        self.credential_generation = generation;
        Ok(self)
    }
}

impl CpDpVerifierSnapshot {
    /// Verify under this immutable snapshot and bind the admitted identity to
    /// the exact credential generation captured with it.
    ///
    /// The final current-store comparison fails closed if the credential was
    /// removed after this snapshot was loaded, including when the same opaque
    /// credential identity has already been re-added under a new generation.
    #[allow(clippy::result_large_err)]
    pub fn verify_and_bind_grpc_identity(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        expected_issuer: &str,
        peer: Option<&CpGrpcConnectInfo>,
        verifier: &CpDpVerifierStore,
    ) -> Result<VerifiedGrpcIdentity, Status> {
        verify_grpc_jwt_metadata_identity(metadata, self.verifier(), expected_issuer, peer)
            .and_then(|identity| identity.bind_to_store(self, verifier))
    }

    #[allow(clippy::result_large_err, clippy::type_complexity)]
    pub(crate) fn verify_and_bind_grpc_identity_with_audience(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        expected_issuer: &str,
        audience_policy: GrpcAudiencePolicy<'_>,
        peer: Option<&CpGrpcConnectInfo>,
        verifier: &CpDpVerifierStore,
    ) -> Result<VerifiedGrpcIdentity, (Status, Option<AudienceRejectReason>)> {
        verify_grpc_jwt_metadata_with_audience(
            metadata,
            self.verifier(),
            expected_issuer,
            audience_policy,
            peer,
        )
        .and_then(|identity| {
            identity
                .bind_to_store(self, verifier)
                .map_err(|status| (status, None))
        })
    }
}

/// Closed stream classes used by metrics and structured audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamAuthSurface {
    ConfigSync,
    MeshSubscribeLocal,
    MeshSubscribeRemote,
    XdsSotw,
    XdsDelta,
}

impl StreamAuthSurface {
    const fn label(self) -> &'static str {
        match self {
            Self::ConfigSync => "configsync_subscribe",
            Self::MeshSubscribeLocal => "mesh_subscribe_local",
            Self::MeshSubscribeRemote => "mesh_subscribe_remote",
            Self::XdsSotw => "xds_sotw_ads",
            Self::XdsDelta => "xds_delta_ads",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::ConfigSync => 0,
            Self::MeshSubscribeLocal => 1,
            Self::MeshSubscribeRemote => 2,
            Self::XdsSotw => 3,
            Self::XdsDelta => 4,
        }
    }
}

/// Why an admitted long-lived configuration stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamAuthEndReason {
    Expired,
    VerificationKeyRemoved,
    ServerMaxLifetime,
    TransportClosed,
}

impl StreamAuthEndReason {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::VerificationKeyRemoved => "verification_key_removed",
            Self::ServerMaxLifetime => "server_max_lifetime",
            Self::TransportClosed => "transport_closed",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Expired => 0,
            Self::VerificationKeyRemoved => 1,
            Self::ServerMaxLifetime => 2,
            Self::TransportClosed => 3,
        }
    }

    pub fn status(self) -> Status {
        match self {
            Self::Expired => Status::unauthenticated("Stream authorization expired"),
            Self::VerificationKeyRemoved => {
                Status::permission_denied("Stream verification credential is no longer trusted")
            }
            Self::ServerMaxLifetime => {
                Status::unauthenticated("Authenticated stream reached server maximum lifetime")
            }
            Self::TransportClosed => Status::unavailable("Configuration stream transport closed"),
        }
    }
}

static STREAM_AUTH_ENDS: [[AtomicU64; 4]; 5] = [
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
    [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
];

/// Append the fixed-cardinality stream authorization lifecycle metric.
pub fn render_stream_auth_metrics(output: &mut String, gateway_ns_label: &str) {
    output.push_str(
        "# HELP ferrum_grpc_config_stream_terminations_total Authenticated configuration streams ended by fixed surface and reason.\n",
    );
    output.push_str("# TYPE ferrum_grpc_config_stream_terminations_total counter\n");
    for surface in [
        StreamAuthSurface::ConfigSync,
        StreamAuthSurface::MeshSubscribeLocal,
        StreamAuthSurface::MeshSubscribeRemote,
        StreamAuthSurface::XdsSotw,
        StreamAuthSurface::XdsDelta,
    ] {
        for reason in [
            StreamAuthEndReason::Expired,
            StreamAuthEndReason::VerificationKeyRemoved,
            StreamAuthEndReason::ServerMaxLifetime,
            StreamAuthEndReason::TransportClosed,
        ] {
            output.push_str(&format!(
                "ferrum_grpc_config_stream_terminations_total{{surface=\"{}\",reason=\"{}\"{}}} {}\n",
                surface.label(),
                reason.label(),
                gateway_ns_label,
                STREAM_AUTH_ENDS[surface.index()][reason.index()].load(Ordering::Relaxed),
            ));
        }
    }
}

/// Records exactly one terminal reason for an admitted stream, including
/// ordinary client/transport closure when no authorization branch fired.
pub struct StreamAuthTerminationGuard {
    surface: StreamAuthSurface,
    reason: StreamAuthEndReason,
}

impl StreamAuthTerminationGuard {
    pub fn new(surface: StreamAuthSurface) -> Self {
        Self {
            surface,
            reason: StreamAuthEndReason::TransportClosed,
        }
    }

    pub fn set_reason(&mut self, reason: StreamAuthEndReason) {
        self.reason = reason;
    }
}

impl Drop for StreamAuthTerminationGuard {
    fn drop(&mut self) {
        STREAM_AUTH_ENDS[self.surface.index()][self.reason.index()].fetch_add(1, Ordering::Relaxed);
        if self.reason == StreamAuthEndReason::TransportClosed {
            info!(
                audit.event = "grpc_config_stream_ended",
                surface = self.surface.label(),
                reason = self.reason.label(),
                "Authenticated configuration stream ended"
            );
        } else {
            warn!(
                audit.event = "grpc_config_stream_authorization_ended",
                surface = self.surface.label(),
                reason = self.reason.label(),
                "Authenticated configuration stream authorization ended"
            );
        }
    }
}

/// Immutable authorization lease for one admitted bearer stream.
pub struct StreamAuthorizationLease {
    authorization_deadline: Instant,
    server_deadline: Instant,
    credential: VerificationCredentialIdentity,
    credential_generation: u64,
    verifier: Arc<CpDpVerifierStore>,
}

impl StreamAuthorizationLease {
    pub fn new(
        identity: &VerifiedGrpcIdentity,
        verifier: Arc<CpDpVerifierStore>,
        max_lifetime: Duration,
    ) -> Self {
        let max_lifetime = bounded_server_lifetime(max_lifetime);
        Self {
            authorization_deadline: identity.authorization_deadline,
            server_deadline: identity.admitted_at + max_lifetime,
            credential: identity.credential.clone(),
            credential_generation: identity.credential_generation,
            verifier,
        }
    }

    fn credential_is_active(&self) -> bool {
        self.verifier
            .credential_is_active(&self.credential, self.credential_generation)
    }

    /// Wait without polling. Used by the task-owned bidirectional ADS loops.
    pub async fn wait_for_end(&self) -> StreamAuthEndReason {
        let mut revisions = self.verifier.subscribe();
        loop {
            // Credential removal is an authorization decision, so it wins
            // over a coincident expiry/server deadline. Checking the live
            // generation directly also closes the remove-then-readd gap even
            // when the watch receiver coalesces both revisions.
            if !self.credential_is_active() {
                return StreamAuthEndReason::VerificationKeyRemoved;
            }
            tokio::select! {
                biased;
                changed = revisions.changed() => {
                    if changed.is_err() || !self.credential_is_active() {
                        return StreamAuthEndReason::VerificationKeyRemoved;
                    }
                }
                _ = tokio::time::sleep_until(self.authorization_deadline) => {
                    // A verifier update can make this arm ready in the same
                    // wakeup as a coalesced revocation. Re-check before
                    // classifying the closure as expiry.
                    if !self.credential_is_active() {
                        return StreamAuthEndReason::VerificationKeyRemoved;
                    }
                    return StreamAuthEndReason::Expired;
                }
                _ = tokio::time::sleep_until(self.server_deadline) => {
                    if !self.credential_is_active() {
                        return StreamAuthEndReason::VerificationKeyRemoved;
                    }
                    return StreamAuthEndReason::ServerMaxLifetime;
                }
            }
        }
    }
}

/// Pinned `watch::Receiver::changed()` future used by response streams. Kept
/// as an explicit state machine so a retained-key reload re-arms without the
/// `WatchStream` follow-up-poll hazard that can leave an idle tonic stream
/// unwakeable for the next removal.
type VerifierWatchFuture = Pin<
    Box<dyn Future<Output = (Result<(), watch::error::RecvError>, watch::Receiver<u64>)> + Send>,
>;

struct VerifierWatch {
    future: VerifierWatchFuture,
}

impl VerifierWatch {
    fn new(rx: watch::Receiver<u64>) -> Self {
        Self {
            future: Self::wait(rx),
        }
    }

    fn wait(mut rx: watch::Receiver<u64>) -> VerifierWatchFuture {
        Box::pin(async move {
            let result = rx.changed().await;
            (result, rx)
        })
    }

    fn poll_changed(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), watch::error::RecvError>> {
        match self.future.as_mut().poll(cx) {
            Poll::Ready((result, rx)) => {
                self.future = Self::wait(rx);
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Deadline/revocation wrapper for authenticated server responses. Timers are
/// fixed at admission; inner traffic and heartbeat activity cannot modify
/// them. Verifier reloads are observed through the store's watch channel, so
/// idle streams do not need periodic revocation polling.
pub struct AuthorizedResponseStream<S> {
    inner: Pin<Box<S>>,
    authorization_sleep: Pin<Box<Sleep>>,
    server_sleep: Pin<Box<Sleep>>,
    verifier_watch: VerifierWatch,
    credential: VerificationCredentialIdentity,
    credential_generation: u64,
    verifier: Arc<CpDpVerifierStore>,
    terminal_sent: bool,
    guard: StreamAuthTerminationGuard,
}

impl<S> AuthorizedResponseStream<S> {
    pub fn new(
        inner: S,
        identity: &VerifiedGrpcIdentity,
        verifier: Arc<CpDpVerifierStore>,
        max_lifetime: Duration,
        surface: StreamAuthSurface,
    ) -> Self {
        let max_lifetime = bounded_server_lifetime(max_lifetime);
        let server_deadline = identity.admitted_at + max_lifetime;
        Self {
            inner: Box::pin(inner),
            authorization_sleep: Box::pin(tokio::time::sleep_until(
                identity.authorization_deadline,
            )),
            server_sleep: Box::pin(tokio::time::sleep_until(server_deadline)),
            verifier_watch: VerifierWatch::new(verifier.subscribe()),
            credential: identity.credential.clone(),
            credential_generation: identity.credential_generation,
            verifier,
            terminal_sent: false,
            guard: StreamAuthTerminationGuard::new(surface),
        }
    }

    fn terminate<T>(&mut self, reason: StreamAuthEndReason) -> Poll<Option<Result<T, Status>>> {
        self.terminal_sent = true;
        self.guard.set_reason(reason);
        Poll::Ready(Some(Err(reason.status())))
    }

    fn credential_is_active(&self) -> bool {
        self.verifier
            .credential_is_active(&self.credential, self.credential_generation)
    }

    /// Resolve a closed authorization boundary in deterministic priority
    /// order. The direct generation read is load-bearing: the watch channel is
    /// a wake-up mechanism, not the source of truth, and may coalesce a rapid
    /// remove/re-add into one notification.
    fn authorization_end(&mut self, cx: &mut Context<'_>) -> Option<StreamAuthEndReason> {
        if !self.credential_is_active() {
            return Some(StreamAuthEndReason::VerificationKeyRemoved);
        }
        if self.authorization_sleep.as_mut().poll(cx).is_ready() {
            return Some(if !self.credential_is_active() {
                StreamAuthEndReason::VerificationKeyRemoved
            } else {
                StreamAuthEndReason::Expired
            });
        }
        if self.server_sleep.as_mut().poll(cx).is_ready() {
            return Some(if !self.credential_is_active() {
                StreamAuthEndReason::VerificationKeyRemoved
            } else {
                StreamAuthEndReason::ServerMaxLifetime
            });
        }
        match self.verifier_watch.poll_changed(cx) {
            Poll::Ready(Err(_)) => Some(StreamAuthEndReason::VerificationKeyRemoved),
            Poll::Ready(Ok(())) => {
                // Re-arm immediately so a retained-key reload cannot leave the
                // next removal without a parked `changed()` waker. The
                // generation read below is authoritative for this wakeup.
                cx.waker().wake_by_ref();
                if !self.credential_is_active() {
                    Some(StreamAuthEndReason::VerificationKeyRemoved)
                } else {
                    None
                }
            }
            Poll::Pending => None,
        }
    }
}

impl<S, T> tokio_stream::Stream for AuthorizedResponseStream<S>
where
    S: tokio_stream::Stream<Item = Result<T, Status>>,
{
    type Item = Result<T, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.terminal_sent {
            return Poll::Ready(None);
        }
        if let Some(reason) = self.authorization_end(cx) {
            return self.terminate(reason);
        }

        let next = self.inner.as_mut().poll_next(cx);

        // An inner stream can make a buffered response ready in the same poll
        // that a verifier reload or deadline closes authorization. Re-check at
        // the delivery boundary so that item is discarded in favor of the one
        // terminal status. This also covers an inner terminal item/closure and
        // preserves the authorization status taxonomy.
        if next.is_ready()
            && let Some(reason) = self.authorization_end(cx)
        {
            return self.terminate(reason);
        }
        next
    }
}

/// Verify the JWT and return any `ns` claim it carried. Use this variant
/// whenever the caller needs the tenancy-claim path (CP `Subscribe` and
/// `GetFullConfig` today). The verification logic is identical to
/// [`verify_grpc_jwt_metadata`]; the only difference is the extra claim
/// extraction.
///
/// Audience posture is [`GrpcAudiencePolicy::ReservedForbidden`]: these
/// surfaces do not mint or expect an audience, but they must never honor a
/// token minted for the cross-cluster remote-discovery purpose. Surfaces that
/// need a real audience check call
/// [`verify_grpc_jwt_metadata_with_audience`].
#[allow(clippy::result_large_err)]
pub(crate) fn verify_grpc_jwt_metadata_with_claims(
    metadata: &tonic::metadata::MetadataMap,
    verifier: &CpDpVerifier,
    expected_issuer: &str,
    peer: Option<&CpGrpcConnectInfo>,
) -> Result<AllowedNamespaces, Status> {
    verify_grpc_jwt_metadata_with_audience(
        metadata,
        verifier,
        expected_issuer,
        GrpcAudiencePolicy::ReservedForbidden,
        peer,
    )
    .map(|identity| identity.allowed_namespaces)
    .map_err(|(status, _)| status)
}

/// Reserved-audience verification variant for long-lived ConfigSync and ADS
/// streams that must retain the trusted post-verification authorization lease.
#[allow(clippy::result_large_err)]
pub(crate) fn verify_grpc_jwt_metadata_identity(
    metadata: &tonic::metadata::MetadataMap,
    verifier: &CpDpVerifier,
    expected_issuer: &str,
    peer: Option<&CpGrpcConnectInfo>,
) -> Result<VerifiedGrpcIdentity, Status> {
    verify_grpc_jwt_metadata_with_audience(
        metadata,
        verifier,
        expected_issuer,
        GrpcAudiencePolicy::ReservedForbidden,
        peer,
    )
    .map_err(|(status, _)| status)
}

/// Verify the JWT under an explicit [`GrpcAudiencePolicy`].
///
/// On failure the bounded [`AudienceRejectReason`] is returned alongside the
/// `Status` **only** when the audience check is what failed, so callers can
/// record a fixed-cardinality audit/metric label without re-deriving it from
/// the (never-logged) token. Signature/expiry/issuer/`ns` failures return
/// `None` and keep their existing messages.
#[allow(clippy::result_large_err, clippy::type_complexity)]
pub(crate) fn verify_grpc_jwt_metadata_with_audience(
    metadata: &tonic::metadata::MetadataMap,
    verifier: &CpDpVerifier,
    expected_issuer: &str,
    audience_policy: GrpcAudiencePolicy<'_>,
    peer: Option<&CpGrpcConnectInfo>,
) -> Result<VerifiedGrpcIdentity, (Status, Option<AudienceRejectReason>)> {
    let token = metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.strip_prefix("Bearer ").unwrap_or(value))
        .ok_or_else(|| {
            (
                Status::unauthenticated("Missing authorization token"),
                None::<AudienceRejectReason>,
            )
        })?;

    // The JWS header selects WHICH credential must verify the signature. It is
    // read before verification because it has to be — but it authorizes
    // nothing: naming another tenant's `kid` without holding that key fails the
    // signature check below, and the namespace ceiling comes from CP-side
    // configuration attached to the selected key, never from the token.
    let header = decode_header(token).map_err(|_| {
        let reason = TenantAuthRejectReason::MalformedHeader;
        (
            Status::unauthenticated(reason.as_status_message()),
            None::<AudienceRejectReason>,
        )
    })?;

    let mut validation = Validation::new(header.alg);
    validation.validate_exp = true;
    validation.leeway = GRPC_JWT_LEEWAY_SECONDS;
    validation.required_spec_claims = required_grpc_claims();
    validation.set_issuer(&[expected_issuer]);
    // Audience enforcement is Ferrum's own (`enforce_audience`) so every
    // rejection carries a bounded reason label and multi-valued claims fail
    // closed instead of matching on any element.
    validation.validate_aud = false;

    let (decoded, bound_namespaces, credential) = verifier
        .with_decoding_key(
            header.kid.as_deref(),
            header.alg,
            |key, algorithm, bound, credential| {
                // `algorithm` is the credential's configured algorithm, which
                // `with_decoding_key` already proved equal to the header's. Pin the
                // validation to it rather than to the header so a future selection
                // change cannot silently widen the accepted algorithm set.
                validation.algorithms = vec![algorithm];
                (
                    decode::<Value>(token, key, &validation),
                    bound.cloned(),
                    credential.clone(),
                )
            },
        )
        .map_err(|reason| {
            (
                Status::unauthenticated(reason.as_status_message()),
                None::<AudienceRejectReason>,
            )
        })?;

    // Signature and standard-claim validation failures share the same outward
    // message as unknown-key / algorithm mismatch so an unauthenticated caller
    // cannot tell whether selection reached a known credential.
    let token_data = decoded.map_err(|_| {
        let reason = TenantAuthRejectReason::TokenValidation;
        (
            Status::unauthenticated(reason.as_status_message()),
            None::<AudienceRejectReason>,
        )
    })?;

    if let Err(reason) = enforce_audience(&token_data.claims, audience_policy) {
        return Err((
            Status::unauthenticated(reason.as_status_message()),
            Some(reason),
        ));
    }

    let subject = extract_subject_claim(&token_data.claims).map_err(|status| (status, None))?;
    let admitted_at = Instant::now();
    let authorization_deadline = authorization_deadline_from_verified_claims(
        &token_data.claims,
        SystemTime::now(),
        admitted_at,
    )
    .map_err(|status| (status, None))?;

    let claim = extract_ns_claim(&token_data.claims).map_err(|status| (status, None))?;
    let claim_present = claim.is_present();
    let claim_namespaces = claim.effective_namespaces().cloned();

    // Server-derived binding. The claim can only narrow what the CP already
    // decided this credential (and, when present, this authenticated peer) may
    // reach — so a re-signed `ns` naming another tenant resolves to an empty
    // set and is refused here, before any tenant configuration is serialized.
    // Claim *presence* is preserved separately: a missing claim must not look
    // present merely because a trust bundle or SPIFFE peer produced a set.
    let effective = resolve_authorized_namespaces(
        bound_namespaces.as_ref(),
        peer.and_then(|info| info.peer_namespace_scope.as_ref()),
        claim_namespaces.as_ref(),
    )
    .map_err(|reason| {
        (
            Status::permission_denied(reason.as_status_message()),
            None::<AudienceRejectReason>,
        )
    })?;

    Ok(VerifiedGrpcIdentity {
        allowed_namespaces: AllowedNamespaces::resolved(claim_present, effective),
        subject,
        authorization_deadline,
        admitted_at,
        credential,
        credential_generation: 0,
    })
}

/// Convert the already verified `exp` claim into a monotonic deadline. This
/// function never sees an unverified decode: callers pass only the claims from
/// `jsonwebtoken::decode` after signature, issuer, required-claim, and time
/// validation succeeded.
fn authorization_deadline_from_verified_claims(
    claims: &Value,
    now_wall: SystemTime,
    now_monotonic: Instant,
) -> Result<Instant, Status> {
    let exp = claims
        .get("exp")
        .and_then(Value::as_f64)
        .filter(|exp| exp.is_finite() && *exp >= 0.0)
        .ok_or_else(|| Status::unauthenticated("Invalid token: expiry claim is malformed"))?;
    let now_wall = now_wall
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Status::internal("System clock is before the Unix epoch"))?
        .as_secs_f64();
    let remaining = (exp + GRPC_JWT_LEEWAY_SECONDS as f64 - now_wall).max(0.0);
    // The independently enforced server ceiling is at most one day. Bounding
    // this conversion avoids an `Instant` overflow for a hostile far-future
    // NumericDate while preserving the exact effective deadline throughout
    // every lifetime that the server could actually allow.
    let bounded = remaining.min(MAX_GRPC_MAX_STREAM_LIFETIME_SECONDS as f64 + 1.0);
    now_monotonic
        .checked_add(Duration::from_secs_f64(bounded))
        .ok_or_else(|| Status::unauthenticated("Invalid token: expiry is out of range"))
}

/// Pull the JWT `sub` claim. `sub` is already in the required-claim set, but
/// we still fail closed on blank/whitespace subjects so they cannot become a
/// registry key.
fn extract_subject_claim(claims: &Value) -> Result<String, Status> {
    let Some(raw) = claims.get("sub") else {
        return Err(Status::unauthenticated(
            "Invalid token: required subject claim is missing",
        ));
    };
    let Some(subject) = raw.as_str() else {
        return Err(Status::unauthenticated(
            "Invalid token: subject claim must be a string",
        ));
    };
    let trimmed = subject.trim();
    if trimmed.is_empty() {
        return Err(Status::unauthenticated(
            "Invalid token: subject claim must not be empty",
        ));
    }
    Ok(trimmed.to_string())
}

fn required_grpc_claims() -> HashSet<String> {
    ["exp", "iat", "sub", "iss"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// Pull the `ns` claim out of the decoded JWT body. Accepted shapes:
/// - missing — `AllowedNamespaces::empty()`
/// - `"ns": "production"` — single-namespace claim, single-element set
/// - `"ns": ["production","staging"]` — multi-namespace claim
///
/// Invalid shapes are rejected rather than downgraded to "no claim"; treating
/// a malformed tenant claim as absent would let an ambiguous token fall back
/// to legacy scope-only authorization on multi-namespace CPs.
#[allow(clippy::result_large_err)]
fn extract_ns_claim(claims: &Value) -> Result<AllowedNamespaces, Status> {
    parse_ns_claim(claims).map_err(Status::unauthenticated)
}

/// Transport-agnostic `ns` claim parser shared by the CP/DP gRPC surface and
/// the REST admin API (`FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM`). Both planes
/// must accept identical claim shapes so one operator-minted token can carry
/// tenancy for either surface without drift.
pub(crate) fn parse_ns_claim(claims: &Value) -> Result<AllowedNamespaces, String> {
    let raw = match claims.get("ns") {
        Some(v) => v,
        None => return Ok(AllowedNamespaces::empty()),
    };

    if let Some(s) = raw.as_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err("JWT `ns` claim must not be an empty string".to_string());
        }
        let mut set = HashSet::new();
        set.insert(trimmed.to_string());
        return Ok(AllowedNamespaces::claimed(set));
    }

    if let Some(arr) = raw.as_array() {
        let mut set = HashSet::new();
        for value in arr {
            let Some(raw) = value.as_str() else {
                return Err("JWT `ns` array claim must contain only strings".to_string());
            };
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err("JWT `ns` array claim must not contain empty strings".to_string());
            }
            set.insert(trimmed.to_string());
        }
        return Ok(AllowedNamespaces::claimed(set));
    }

    Err("JWT `ns` claim must be a string or an array of strings".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ns_claim_absent_yields_empty() {
        let claims = json!({ "sub": "node-a", "iss": "ferrum-edge-cp-dp" });
        assert_eq!(
            extract_ns_claim(&claims).expect("absent claim is valid"),
            AllowedNamespaces::empty()
        );
    }

    #[test]
    fn ns_claim_string_normalised_to_single_element_set() {
        let claims = json!({ "ns": "production" });
        let allowed = extract_ns_claim(&claims).expect("string claim is valid");
        assert!(allowed.is_present());
        assert!(allowed.allows("production"));
        assert!(!allowed.allows("staging"));
        assert_eq!(allowed.sole_namespace(), Some("production"));
    }

    #[test]
    fn ns_claim_array_normalised_to_set() {
        let claims = json!({ "ns": ["prod", "staging", "prod"] });
        let allowed = extract_ns_claim(&claims).expect("array claim is valid");
        let inner = allowed
            .effective_namespaces()
            .expect("set should be present");
        assert_eq!(inner.len(), 2);
        assert!(inner.contains("prod"));
        assert!(inner.contains("staging"));
    }

    #[test]
    fn resolved_without_claim_keeps_is_present_false() {
        // A trust-bundle / SPIFFE ceiling must not make a missing `ns` claim
        // look present — that would bypass multi-namespace claim requirements.
        let mut effective = HashSet::new();
        effective.insert("tenant-a".to_string());
        let allowed = AllowedNamespaces::resolved(false, Some(effective));
        assert!(!allowed.is_present());
        assert!(allowed.allows("tenant-a"));
        assert_eq!(allowed.sole_namespace(), Some("tenant-a"));
    }

    #[test]
    fn ns_claim_empty_string_rejected() {
        let claims = json!({ "ns": "  " });
        assert!(extract_ns_claim(&claims).is_err());
    }

    #[test]
    fn ns_claim_empty_array_is_present_but_empty() {
        // Empty array is still a "present" claim — operator explicitly
        // assigned no namespaces, which means the bearer can subscribe to
        // nothing. The CP rejects every namespace; we keep semantics
        // distinct from the missing-claim case.
        let claims = json!({ "ns": [] });
        let allowed = extract_ns_claim(&claims).expect("empty array is valid");
        assert!(allowed.is_present());
        assert!(!allowed.allows("prod"));
        assert_eq!(allowed.sole_namespace(), None);
    }

    #[test]
    fn ns_claim_array_rejects_non_strings() {
        let claims = json!({ "ns": [1, "prod", null, "staging"] });
        assert!(extract_ns_claim(&claims).is_err());
    }

    #[test]
    fn ns_claim_non_string_non_array_rejected() {
        let claims = json!({ "ns": 42 });
        assert!(extract_ns_claim(&claims).is_err());
    }

    // ── Audience binding (issue #2475) ────────────────────────────────────

    const CLUSTER_B_AUD: &str = "ferrum-mesh-discovery:cluster-b";

    #[test]
    fn audience_claim_accepts_string_and_single_element_array() {
        assert_eq!(
            parse_audience_claim(&json!({ "aud": " cluster-b " })).expect("string aud"),
            Some("cluster-b".to_string())
        );
        assert_eq!(
            parse_audience_claim(&json!({ "aud": ["cluster-b"] })).expect("array aud"),
            Some("cluster-b".to_string())
        );
        assert_eq!(
            parse_audience_claim(&json!({ "sub": "n" })).expect("absent"),
            None
        );
    }

    #[test]
    fn audience_claim_malformed_and_ambiguous_shapes_rejected() {
        for malformed in [
            json!({ "aud": "" }),
            json!({ "aud": "   " }),
            json!({ "aud": [] }),
            json!({ "aud": ["cluster-b", ""] }),
            json!({ "aud": [1, 2] }),
            json!({ "aud": 42 }),
            json!({ "aud": { "cluster": "b" } }),
        ] {
            assert_eq!(
                parse_audience_claim(&malformed),
                Err(AudienceRejectReason::Malformed),
                "expected malformed rejection for {malformed}"
            );
        }
        assert_eq!(
            parse_audience_claim(&json!({ "aud": ["cluster-b", "cluster-c"] })),
            Err(AudienceRejectReason::Ambiguous)
        );
        assert_eq!(
            parse_audience_claim(&json!({ "aud": ["cluster-b", "cluster-b"] })),
            Err(AudienceRejectReason::Ambiguous)
        );
    }

    #[test]
    fn required_policy_binds_to_exactly_one_audience() {
        let policy = GrpcAudiencePolicy::Required(CLUSTER_B_AUD);
        assert!(enforce_audience(&json!({ "aud": CLUSTER_B_AUD }), policy).is_ok());
        // Cluster C's verifier refuses B's token even with the same secret+issuer.
        assert_eq!(
            enforce_audience(
                &json!({ "aud": CLUSTER_B_AUD }),
                GrpcAudiencePolicy::Required("ferrum-mesh-discovery:cluster-c")
            ),
            Err(AudienceRejectReason::Mismatch)
        );
        assert_eq!(
            enforce_audience(&json!({ "sub": "dp" }), policy),
            Err(AudienceRejectReason::Missing)
        );
        assert_eq!(
            enforce_audience(
                &json!({ "aud": [CLUSTER_B_AUD, "ferrum-mesh-discovery:cluster-c"] }),
                policy
            ),
            Err(AudienceRejectReason::Ambiguous)
        );
        assert_eq!(
            enforce_audience(&json!({ "aud": 7 }), policy),
            Err(AudienceRejectReason::Malformed)
        );
    }

    #[test]
    fn local_mesh_and_remote_discovery_purposes_are_distinct() {
        let local_policy = GrpcAudiencePolicy::Required(MESH_LOCAL_SUBSCRIBE_AUDIENCE);
        assert!(
            enforce_audience(
                &json!({ "aud": MESH_LOCAL_SUBSCRIBE_AUDIENCE }),
                local_policy
            )
            .is_ok()
        );
        assert_eq!(
            enforce_audience(&json!({ "sub": "legacy-mesh-node" }), local_policy),
            Err(AudienceRejectReason::Missing)
        );
        assert_eq!(
            enforce_audience(&json!({ "aud": CLUSTER_B_AUD }), local_policy),
            Err(AudienceRejectReason::Mismatch)
        );
        assert_eq!(
            enforce_audience(
                &json!({ "aud": MESH_LOCAL_SUBSCRIBE_AUDIENCE }),
                GrpcAudiencePolicy::Required(CLUSTER_B_AUD)
            ),
            Err(AudienceRejectReason::Mismatch)
        );
    }

    #[test]
    fn unconfigured_policy_always_fails_closed() {
        assert_eq!(
            enforce_audience(
                &json!({ "aud": CLUSTER_B_AUD }),
                GrpcAudiencePolicy::Unconfigured
            ),
            Err(AudienceRejectReason::Unconfigured)
        );
        assert_eq!(
            enforce_audience(&json!({ "sub": "dp" }), GrpcAudiencePolicy::Unconfigured),
            Err(AudienceRejectReason::Unconfigured)
        );
    }

    #[test]
    fn reserved_forbidden_policy_separates_the_token_purposes() {
        let policy = GrpcAudiencePolicy::ReservedForbidden;
        // Ordinary CP↔DP ConfigSync and xDS tokens carry no audience:
        // unchanged.
        assert!(enforce_audience(&json!({ "sub": "dp" }), policy).is_ok());
        // A token minted for ANY other audience is refused, preserving
        // jsonwebtoken's strict `validate_aud` posture for these surfaces.
        assert_eq!(
            enforce_audience(&json!({ "aud": "internal-tooling" }), policy),
            Err(AudienceRejectReason::UnexpectedAudience)
        );
        // A remote-discovery token can never be replayed as a local one.
        assert_eq!(
            enforce_audience(&json!({ "aud": CLUSTER_B_AUD }), policy),
            Err(AudienceRejectReason::ReservedAudience)
        );
        assert_eq!(
            enforce_audience(&json!({ "aud": MESH_LOCAL_SUBSCRIBE_AUDIENCE }), policy),
            Err(AudienceRejectReason::ReservedAudience)
        );
        // Malformed shapes still fail closed on this policy.
        assert_eq!(
            enforce_audience(&json!({ "aud": [] }), policy),
            Err(AudienceRejectReason::Malformed)
        );
    }

    #[test]
    fn remote_discovery_audience_is_prefixed_and_trimmed() {
        assert_eq!(remote_discovery_audience(" cluster-b "), CLUSTER_B_AUD);
        assert!(
            remote_discovery_audience("cluster-b")
                .starts_with(MESH_REMOTE_DISCOVERY_AUDIENCE_PREFIX)
        );
    }
}
