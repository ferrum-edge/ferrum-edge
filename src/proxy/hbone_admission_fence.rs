//! Receiver-side admission fence for live HBONE tunnels (issues #5042, #5568
//! and #5574).
//!
//! An HBONE CONNECT is admitted exactly once: the peer identity gate, the
//! effective PeerAuthentication transport mode, the relay-destination
//! ownership guard, and the authorize-phase plugin chain (`mesh_authz`) all
//! judge the CONNECT request, and the relay then byte-copies for as long as the
//! tunnel lives. Without this fence a tunnel admitted under one policy
//! generation kept flowing after the operator published a tighter one, and
//! NOTHING bounded it: an established inbound HBONE mTLS session is never
//! re-handshaked, so neither the peer SVID's expiry nor a later trust decision
//! ends it. That is also what blocks source-side inner-connection reuse
//! (#5042 step 2): a reused tunnel would carry later requests under a stale
//! decision.
//!
//! The fence keeps a registry of live admitted tunnels, each holding the
//! admission snapshot those gates evaluated. Every request-epoch publication
//! and every inbound PeerAuthentication swap schedules ONE sweep (concurrent
//! requests coalesce) that re-applies the gates to every live tunnel against
//! the CURRENT epoch and policy. A tunnel that would no longer be admitted is
//! revoked: its relay observes the cancellation as a terminal transport error,
//! which resets the CONNECT stream toward the peer and closes the backend leg
//! through the relay's ordinary teardown path.
//!
//! Sweeps run off the request path on one background task at a time, and only
//! authorize plugins that declare themselves re-evaluation-safe
//! ([`crate::plugins::Plugin::reevaluates_live_admission`]) are re-run. That
//! keeps a publication's cost to local policy evaluation over the live
//! tunnels — microseconds per tunnel, no external call and no consumed budget —
//! so a routine config apply can never drain a real client's rate-limit budget
//! or mass-revoke healthy tunnels because an external authorizer is briefly
//! unreachable. Within `mesh_authz`, `CUSTOM` (`ext_authz`) delegations are
//! additionally NOT re-consulted (see
//! [`crate::plugins::mesh::authz::MESH_AUTHZ_REEVALUATION_METADATA_KEY`]): the
//! provider's admission-time verdict stands for the tunnel's life, exactly as
//! before, while the local DENY/ALLOW tiers are re-applied.
//!
//! Inner-reuse classification is also re-folded over the current chain for
//! every tunnel admitted with the capability. The snapshot retains the
//! admitting listener facts in `HboneReuseContext`; every sweep uses those
//! same facts. Registry reuse is advertised only for CONNECTs the registry did
//! not decide: a matching Outbound listener may terminate CONNECT, and a sweep
//! never re-runs its per-operation registry lookup. A new scope that would
//! enforce on the recorded listener therefore revokes `ReuseWithdrawn`.
//!
//! The fence bounds TWO dimensions, POLICY and CREDENTIALS (issues #5568 and
//! #5574). Beside the policy gates, a sweep re-checks the credential the
//! CONNECT was admitted on: the admitted leaf's `notAfter`, and — when the
//! inbound admission trust has put new material in force since the chain was
//! last verified — whether the retained peer chain still anchors in it and
//! carries no certificate the operator has revoked.
//!
//! The CREDENTIAL dimension also runs on the ADMISSION path, and it has to.
//! Many CONNECTs multiplex over one pooled inbound mTLS session that is never
//! re-handshaked, so a CONNECT arriving after a trust change has not been
//! verified against that change by anything: the handshake predates it and the
//! request path does no chain work. Seeding a tunnel's last-verified revision
//! from the revision its CONNECT merely READ therefore disabled the trust gate
//! for exactly the tunnel that needed it — the replacement a revoked peer
//! opens on the same connection a millisecond later. So
//! `HbonePeerCredential::from_admitted_connect` re-verifies the retained chain
//! against the anchors currently in force and REFUSES the CONNECT when it does
//! not anchor; what a tunnel records as verified is then a verification
//! that actually happened. The anchors are compiled once per in-force revision
//! and cached, so the admission cost is one certificate path validation.
//!
//! The trust the credential gate reads is the INBOUND ADMISSION TRUST: the very
//! `tls::SharedBundleSlot` the mesh inbound SPIFFE client-certificate verifier
//! reads on every handshake ([`MeshInboundAdmissionTrust`], installed by mesh
//! startup). That is load-bearing and was got wrong once. The fence's contract
//! is defined relative to ADMISSION — "a tunnel that would no longer be
//! admitted is revoked" — so the anchors it judges a live tunnel against must
//! be the anchors that tunnel's peer would be re-handshaked against, not the
//! anchors of the request epoch. The two are built by different code from
//! different material: `ProxyState::install_gateway_runtime_svid_bundle`
//! REPLACES the epoch's trust bundles with the CP/slice override, while
//! `publish_runtime_svid_to_inbound_slot` merges the SVID source's own roots
//! ADDITIVELY into the inbound slot and files a slice-local bundle of a
//! different trust domain as federated. Judging live tunnels by the epoch
//! therefore revoked healthy peers on a SPIRE CA rotation (a root the inbound
//! verifier had just accepted but the epoch did not carry) and silently
//! exempted peers in the gateway SVID's own trust domain whenever the slice
//! named a different local domain.
//!
//! Every publication into that slot goes through
//! `ProxyState::publish_mesh_inbound_trust_bundle`, which stores, advances the
//! trust in force when the TRUST material actually changed AND the candidate
//! compiles, and only then requests a sweep — the same publish-then-recheck
//! ordering `publish_mesh_inbound_tls_policy` relies on. A bounded expiry
//! watcher runs the one non-publication sweep, so an expired SVID is revoked on
//! a mesh where nothing is being republished at all.
//!
//! The operator's ENFORCED REVOCATION LIST is part of that same in-force cell
//! (issue #5574), not a second input consulted beside it. A CRL that revokes a
//! workload's leaf must refuse that peer's next handshake — but an established
//! inbound session is never re-handshaked, and many CONNECTs multiplex over
//! one, so without the fence the revoked peer kept every tunnel it already had
//! AND could open more. The anchors in force are therefore compiled WITH the
//! enforced records, which makes one compiled artifact answer the whole
//! credential question the next handshake would: does this chain still anchor,
//! and is nothing on it revoked.
//! `ProxyState::publish_mesh_inbound_crls` goes through the same single
//! publisher the trust bundle does ([`HboneAdmissionFence::publish_inbound_admission_crls`]):
//! it recompiles the cached anchors with the new records, advances the ONE
//! in-force revision from the same fence-wide sequence, and only then requests
//! the sweep. There is no second generation and no second skip key — a
//! publication of either kind moves one revision, and a tunnel whose
//! last-verified revision matches it does no path building at all.
//!
//! THE HANDSHAKE READS THE SAME ARTIFACT. `ProxyState::mesh_inbound_admission`
//! ([`crate::tls::InboundAdmissionArtifact`]) carries the enforced records AND
//! the compiled anchors in force, and the inbound SPIFFE client-certificate
//! verifier verifies against those anchors whenever any are in force. Its own
//! compile — `SpiffePeerVerifierCache`, from the raw SVID slot plus the raw
//! records, with last-known-good retention — is ONLY the startup fallback for a
//! listener whose fence has never published, never a second opinion once
//! something is in force. Two independently retained histories let the two
//! surfaces disagree indefinitely: a trust candidate the fence refuses to put in
//! force is still STORED in the slot (the same slot backs the listener's server
//! identity), so the verifier kept failing to build from it and kept returning
//! its own previous set — which meant a CRL published afterwards, one the fence
//! had already compiled into its anchors, never reached a single handshake. The
//! handshake admitted a revoked leaf while the fence revoked its tunnels and
//! refused its CONNECTs, and a later CRL REMOVAL produced the mirror image.
//! `tls::SvidServerCertResolver` still reads the raw slot, because the server
//! identity must follow a leaf/key rotation immediately and that material is no
//! part of what a peer chain anchors in.
//!
//! WHICH RELOAD PATH ACTUALLY REPUBLISHES THE RECORDS (issue #5574 re-review).
//! Exactly one production caller reaches `ProxyState::publish_mesh_inbound_crls`:
//! the BACKEND TLS live-reload task, through
//! `ProxyState::reload_backend_tls_material`. `FERRUM_TLS_CRL_FILE_PATH` is one
//! process-wide source rather than a frontend or backend one, and the backend
//! watcher is the one that arms in a mesh deployment — the frontend task
//! additionally requires `FERRUM_FRONTEND_TLS_CERT_PATH`/`_KEY_PATH`, which a
//! mesh serving its SVID as its inbound server identity does not set. So the
//! prerequisites for a rotation to reach live tunnels without a restart are:
//! `FERRUM_BACKEND_TLS_LIVE_RELOAD_ENABLED` (default `true`), a refreshable CRL
//! source, and the poll cadence — `FERRUM_BACKEND_TLS_WATCH_INTERVAL_SECONDS`
//! (default 30s) for file-backed sources, the source's own `?poll=` or
//! `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` otherwise. That task validates the
//! backend TLS surface one destination at a time (issue #6105): a destination
//! whose material no longer builds is warned and skipped, so it cannot withhold
//! the mesh inbound publication; only a CRL candidate that fails to load does.
//! Disabling backend live reload pins the mesh inbound enforced set at its
//! startup snapshot.
//!
//! ALL THREE PUBLISHERS SHARE ONE FENCE-OWNED LOCK
//! ([`HboneAdmissionFence::publication_lock`]), taken by the trust install, the
//! trust publication, and the CRL publication alike, and every equality
//! comparison that decides what goes in force is re-taken under it — against
//! both the published records and the records the anchors in force were
//! compiled with. The lock has to exist from `HboneAdmissionFence::new` rather
//! than per installed trust, because the install itself is one of the racers:
//! production starts the backend CRL watcher before mesh installs its inbound
//! slot, so a CRL publisher could read "no trust installed", be overtaken by an
//! install that compiled against the records in force at that instant, and then
//! store newer records with nothing recompiled — leaving the verifier on one
//! list and the fence's anchors on another, permanently, because a
//! byte-identical republish returns early and can never repair it.
//!
//! The all-or-nothing rule covers the records too. A candidate CRL that is
//! unparseable, not yet valid, carries no `nextUpdate`, or has already reached
//! it takes NO force: the records are not published, the revision does not move,
//! nothing is revoked, and a sampled operator line says so — exactly as a trust
//! candidate that does not compile is refused. That is the verifier's own
//! behavior, which is the point: a list the verifier cannot use must not become
//! the list the fence judges by.
//!
//! "In force" is the verifier's own rule, not a second opinion. The inbound
//! SPIFFE verifier compiles a candidate trust set ATOMICALLY and keeps its
//! last-known-good set when the candidate fails, so a candidate the fence
//! cannot compile does not replace what the fence judges against either. Judging
//! per trust domain instead would have revoked tunnels in the domains that did
//! compile — and judged every other domain against material the verifier had
//! not adopted — while the verifier was still admitting those very peers.
//!
//! What remains outside the fence is narrow and deliberate: an `action: CUSTOM`
//! ext_authz delegation is not re-consulted (below). See `docs/mesh.md` →
//! "HBONE Admission Fence".

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use arc_swap::{ArcSwap, ArcSwapOption};
use dashmap::DashMap;
use futures_util::FutureExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::hbone_proxy::{
    admitting_chain_allows_inner_reuse, inbound_hbone_relay_effective_destination_decision,
    inbound_ingress_relay_effective_destination_allowed,
};
use super::{
    MeshInboundTlsPolicy, SharedMeshInboundTlsPolicy, inbound_hbone_relay_destination_decision,
    mesh_egress_udp_destination_allowed, mesh_inbound_peer_auth_transport_mismatch_for_policy,
    sidecar_inbound_refuses_matched_http_connect,
};
use crate::config::types::{Proxy, UpstreamTarget};
use crate::plugin_cache::PluginCacheRequestView;
use crate::plugins::mesh::authz::MESH_AUTHZ_REEVALUATION_METADATA_KEY;
use crate::plugins::{HboneReuseContext, Plugin, PluginResult, ProxyProtocol, RequestContext};
use crate::request_epoch::{RequestEpoch, RequestEpochStore};
use crate::tls::CrlList;
use crate::tls::crl_policy::{crl_records_equal, publish_enforced_crl_set, usable_crl_records};
use crate::tls::spiffe::{
    AdmittedPeerTrustAnchors, AdmittedPeerTrustVerdict, SharedInboundAdmissionArtifact,
};

/// Client-visible / log-visible message for a tunnel the fence revoked. A
/// compiled-in literal: no policy name, principal, or destination.
pub const HBONE_ADMISSION_REVOKED_MESSAGE: &str =
    "HBONE tunnel terminated: mesh admission revoked by a later policy generation";

/// Why a sweep revoked a live tunnel. Fixed cardinality; used as a metric label.
///
/// The variants are declared, indexed, and rendered in GATE ORDER — the order
/// [`HboneAdmissionFence::reevaluate`] applies them, which is the order the
/// CONNECT path applies them — with [`Self::ReuseWithdrawn`], the only reason
/// that is not a refusal, after every gate that is, and the fail-closed arm
/// last. The `reason` label is an operator's only attribution, so a tunnel
/// failing two gates must carry the one its peer's next CONNECT would actually
/// be refused with.
///
/// The three credential arms sit in the order the inbound handshake verifier
/// itself would report them, derived from webpki's own path-building sequence
/// (`rustls-webpki::verify_cert::build_chain_inner`) rather than chosen here:
///
/// 1. [`Self::PeerExpired`] — `check_issuer_independent_properties` validates
///    the certificate's `notAfter` BEFORE the trust-anchor loop is entered, and
///    propagates with `?`. An aged-out leaf is therefore refused with
///    `CertExpired` whatever the anchors or the CRLs would have said.
/// 2. [`Self::PeerTrust`] — the anchor loop seeds its error with
///    `Error::UnknownIssuer` and only calls `check_signed_chain` — the one
///    place revocation is consulted — after a candidate anchor's subject
///    matches the certificate's issuer. A chain that anchors nowhere never
///    reaches the CRL at all, so it reads as a trust withdrawal even when the
///    enforced list also names it.
/// 3. [`Self::PeerRevoked`] — reported only once a complete path to an anchor
///    exists and the enforced CRL lists a certificate on it. Where several
///    anchors are tried and only some match, `Error::most_specific` decides,
///    and it ranks `CertRevoked` (270) far above `UnknownIssuer` (0) — so a
///    chain that anchors somewhere and is revoked there is `peer_revoked`, not
///    `peer_trust`, which is the same answer the peer's next handshake gets.
///
/// `peer_expired` outranks both on the same scale (`CertExpired` is 290), which
/// is the second reason the fence decides expiry first; the first is that the
/// chain re-verification validates at the current instant and would otherwise
/// report an aged-out leaf as an anchoring failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HboneRevocationReason {
    /// The admitting configured proxy is gone from the published generation
    /// (or was deleted and recreated, which is a new incarnation).
    ProxyWithdrawn,
    /// The admitted peer SVID has passed its `notAfter` (issue #5568). An
    /// established inbound mTLS session is never re-handshaked, so this is the
    /// only thing that ends a tunnel whose credential simply aged out.
    PeerExpired,
    /// The peer's chain no longer anchors in the trust the inbound admission
    /// slot has IN FORCE — the issuing CA was removed, or the federated trust
    /// domain was retired (issue #5568). Judged against the anchors the peer's
    /// next handshake would apply, which is what makes the verdict mean "would
    /// no longer be admitted"; the same anchors refuse that peer's next CONNECT
    /// on its existing pooled session.
    PeerTrust,
    /// The peer's chain still anchors, but the CRL set the mesh inbound SPIFFE
    /// verifier enforces now revokes a certificate on it — the leaf itself or
    /// an issuing intermediate, since the shared CRL policy is full-chain
    /// (issue #5574). An established inbound mTLS session is never
    /// re-handshaked, so before this a revoked workload credential kept its
    /// already-admitted tunnels flowing until they ended on their own.
    PeerRevoked,
    /// The authorize-phase chain now denies the admitted CONNECT.
    AuthorizationDenied,
    /// The tunnel's transport no longer satisfies the effective
    /// PeerAuthentication mode for its application port.
    PeerAuthTransport,
    /// The relay destination is no longer one this terminator owns.
    RelayDestination,
    /// This tunnel was admitted with INNER REUSE advertised, and the chain that
    /// would admit its peer's next CONNECT no longer permits reuse (issue
    /// #5583) — a `CUSTOM` `mesh_authz` policy now selects this workload, a
    /// `rate_limiting` row was added, an unclassified plugin was attached.
    ///
    /// The only reason on this list whose tunnel would still be ADMITTED. The
    /// capability, not the admission, was withdrawn: the source was told it
    /// could keep one application connection inside this tunnel and elide the
    /// CONNECTs for every later operation, and the plugin that now wants a
    /// per-operation decision would never see them. Revoking is what restores
    /// it — the source's next operation performs a fresh CONNECT, under the new
    /// chain, and is charged, mirrored, or externally authorized exactly as
    /// that chain requires. Every other gate here outranks it, because every
    /// other gate describes a refusal and this one does not; a tunnel that
    /// fails one of them must carry that reason instead.
    ///
    /// Only tunnels that ADVERTISED reuse are judged. A tunnel admitted without
    /// the advertisement already performs one CONNECT per operation, so there
    /// is nothing for a later chain to miss.
    ReuseWithdrawn,
    /// Re-evaluation itself could not produce a verdict: an authorize plugin
    /// unwound, the retained peer leaf is not parseable (or not retained) at
    /// all, or the CRL authoritative for the chain has reached `nextUpdate` by
    /// the time the chain is re-verified against it, so the revocation question
    /// can no longer be answered (issue #5574). Fail closed: an un-judgeable
    /// tunnel is cut rather than left serving under a generation nothing
    /// checked it against — which is also what the peer's next handshake does,
    /// since `enforce_revocation_expiration` refuses a chain an expired CRL
    /// covers. The aged-out case is bounded by the skip key: a tunnel that
    /// already verified under the current revision is not re-verified, so it is
    /// observed on the next publication that moves the revision rather than at
    /// the instant the record expires. That is deliberate — the peer's next
    /// handshake is refused immediately either way, and re-reading the clock
    /// per tunnel per sweep is exactly the certificate work this gate exists to
    /// avoid.
    ///
    /// A published trust bundle that does not compile is deliberately NOT one of
    /// these, and neither is an unusable CRL CANDIDATE: such a publication is
    /// not in force for the inbound verifier either, so it does not replace
    /// what the fence judges against.
    ReevaluationFailed,
}

impl HboneRevocationReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProxyWithdrawn => "proxy_withdrawn",
            Self::PeerExpired => "peer_expired",
            Self::PeerTrust => "peer_trust",
            Self::PeerRevoked => "peer_revoked",
            Self::AuthorizationDenied => "authorization_denied",
            Self::PeerAuthTransport => "peer_auth_transport",
            Self::RelayDestination => "relay_destination",
            Self::ReuseWithdrawn => "reuse_withdrawn",
            Self::ReevaluationFailed => "reevaluation_failed",
        }
    }

    /// Every reason, in GATE ORDER. The metric's closed label set: the
    /// per-reason counters are indexed by [`Self::index`] into an array of this
    /// length, and the contract tests assert the rendered order against THIS
    /// rather than against a handwritten copy of it — a copy would silently
    /// stop describing the enum the moment a reason was inserted.
    pub const ALL: [Self; 9] = [
        Self::ProxyWithdrawn,
        Self::PeerExpired,
        Self::PeerTrust,
        Self::PeerRevoked,
        Self::AuthorizationDenied,
        Self::PeerAuthTransport,
        Self::RelayDestination,
        Self::ReuseWithdrawn,
        Self::ReevaluationFailed,
    ];

    /// This reason's position in [`Self::ALL`], which is also its counter slot.
    pub const fn index(self) -> usize {
        match self {
            Self::ProxyWithdrawn => 0,
            Self::PeerExpired => 1,
            Self::PeerTrust => 2,
            Self::PeerRevoked => 3,
            Self::AuthorizationDenied => 4,
            Self::PeerAuthTransport => 5,
            Self::RelayDestination => 6,
            Self::ReuseWithdrawn => 7,
            Self::ReevaluationFailed => 8,
        }
    }

    fn from_index(index: u8) -> Option<Self> {
        Self::ALL.get(usize::from(index)).copied()
    }
}

/// Which relay-destination ownership guard admitted the tunnel, so the sweep
/// re-applies exactly that guard (`handle_hbone_request` /
/// `handle_hbone_udp_request` parity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HboneRelayDestinationGate {
    /// Synthesized Ambient/NodeWaypoint/ServiceWaypoint inbound relay: the
    /// destination must remain one this proxy terminates for.
    InboundRelay,
    /// Synthesized Sidecar `ingress[]` remap: the declared listener →
    /// `defaultEndpoint` mapping must remain intact.
    IngressRelay,
    /// Datagram-over-HBONE relay: a terminator-owned local destination, or an
    /// admitted EgressGateway external UDP endpoint.
    Datagram,
    /// Explicitly configured proxy: no ownership guard applies; presence in the
    /// published generation is the gate, plus the Sidecar refusal of a bare
    /// CONNECT that matched an HTTP route on the inbound listener (issue
    /// #6110).
    Configured,
}

/// The peer credential an HBONE CONNECT was admitted on, retained so a sweep
/// can re-decide the credential question a later generation asks (issue #5568).
///
/// Built once, at admission, from material the connection already holds: both
/// DER fields are `Arc` clones of exactly what the accept path took out of the
/// rustls session (the snapshot's `RequestContext` holds the same two `Arc`s),
/// so the retention costs two refcount bumps rather than a copy of the chain,
/// and `leaf_expiry` is read from the connection's existing SPIFFE extraction
/// cache rather than parsed again. Nothing certificate-shaped is re-derived per
/// sweep, and a tunnel rebuilds a certificate path only when the inbound
/// admission trust it last verified against has actually been replaced.
///
/// Building it is also the CONNECT's own trust gate: `from_admitted_connect`
/// refuses the CONNECT outright, rather than returning a credential, when the
/// chain does not anchor under the trust in force.
///
/// Carries no private key and no rendered subject/SAN: `spiffe_id` is the
/// identity the request path already published, and the DER is the peer's own
/// public chain.
pub struct HbonePeerCredential {
    /// The peer SPIFFE identity the CONNECT was authorized under. Its trust
    /// domain is what the re-check looks the published bundles up by.
    pub spiffe_id: crate::identity::SpiffeId,
    /// The admitted leaf, DER-encoded — the certificate `spiffe_id` was read
    /// from. Retaining it is what lets a sweep re-verify the chain against a
    /// later generation's anchors instead of trusting a remembered verdict.
    pub leaf_der: Arc<Vec<u8>>,
    /// The intermediates the peer offered, in chain order. `None` when it
    /// presented a leaf only, which is the ordinary SPIFFE SVID shape.
    pub intermediates_der: Option<Arc<Vec<Vec<u8>>>>,
    /// When the admitted leaf's own `notAfter` ends this credential.
    pub leaf_expiry: AdmittedLeafExpiry,
    /// Whether the CONNECT's chain was POSITIVELY VERIFIED against the inbound
    /// admission trust in force at admission.
    ///
    /// `true` means exactly that: this CONNECT re-ran a certificate path
    /// validation against the anchors [`admitted_trust_revision`] names and it
    /// succeeded. A chain that did not anchor never becomes a tunnel at all —
    /// the CONNECT is refused.
    ///
    /// `false` therefore means only "there was nothing in force to verify
    /// against": no [`MeshInboundAdmissionTrust`] is installed (a chain-only
    /// inbound posture, where peers are verified against the operator
    /// client-CA bundle and `tls::client_trust` already bounds them separately
    /// — issue #3857), or the installed slot has not yet put any set in force.
    /// It leaves the TRUST half of the gate inapplicable for this tunnel's
    /// whole life, which is the guard against a false mass revocation: the
    /// fence only ever revokes for a trust change it can observe as a
    /// REGRESSION from a state it saw. The expiry half still applies.
    ///
    /// [`admitted_trust_revision`]: Self::admitted_trust_revision
    pub anchored_at_admission: bool,
    /// The [`MeshInboundAdmissionTrust`] revision this CONNECT's chain was
    /// verified against, or `0` when no inbound admission trust is installed.
    ///
    /// The initial value of the tunnel's own last-VERIFIED revision, and it is
    /// a value that was genuinely verified rather than merely observed: the
    /// chain is re-checked at the CONNECT, not at the handshake. That
    /// distinction is load-bearing. Many CONNECTs multiplex over one pooled
    /// inbound mTLS session that is NEVER re-handshaked, so seeding this from
    /// the revision a CONNECT merely read would let a peer whose issuing root
    /// had just been retired re-open a tunnel, record the current revision as
    /// "verified", and skip the trust gate for the rest of that tunnel's life.
    ///
    /// The sweep advances the tunnel's copy on every later `Trusted` verdict, so
    /// a tunnel pays certificate path building once per trust change, never once
    /// per sweep.
    pub admitted_trust_revision: u64,
}

/// What the credential half of CONNECT admission decided (issue #5568).
pub(crate) enum HboneConnectCredential {
    /// Admit the CONNECT. `Some` is the credential the fence retains for the
    /// tunnel's life; `None` means the CONNECT carries no certificate-derived
    /// peer credential to bound at all.
    Admit(Option<HbonePeerCredential>),
    /// Refuse the CONNECT: the peer's retained chain does not survive the
    /// inbound admission trust currently IN FORCE, so this peer's next
    /// handshake here would be refused too. Refusing is what makes the
    /// credential gate survive connection pooling — a revoked tunnel's peer
    /// reconnects on the same never-re-handshaked mTLS session, and admitting
    /// that CONNECT would hand it a tunnel seeded as if the current trust had
    /// verified it. The payload is the fixed attribution the refusal is logged
    /// and recorded with.
    Refuse(HboneConnectRefusal),
}

/// Why the credential gate refused a CONNECT. Fixed cardinality; rendered as a
/// `deny_policy` / rejected-request reason, never a metric label.
///
/// Two values rather than one because they are different operator events with
/// different remediation — a trust anchor the operator retired versus a
/// workload credential the operator revoked — and the sweep already attributes
/// the corresponding live-tunnel revocation to
/// [`HboneRevocationReason::PeerTrust`] and
/// [`HboneRevocationReason::PeerRevoked`] separately (issue #5574). Collapsing
/// them would leave a CRL rollout's CONNECT refusals indistinguishable from a
/// CA rotation's in the one place an operator looks first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HboneConnectRefusal {
    /// The chain no longer anchors in the trust in force, or could not be
    /// judged against it at all. Fail-closed, so it also covers the
    /// un-judgeable case: a peer the fence cannot verify is a peer a fresh
    /// handshake here would not admit.
    TrustWithdrawn,
    /// The chain still anchors, but the enforced CRL records revoke a
    /// certificate on it.
    Revoked,
}

impl HboneConnectRefusal {
    /// The rejected-request reason for a byte-stream CONNECT.
    pub(crate) const fn connect_reason(self) -> &'static str {
        match self {
            Self::TrustWithdrawn => "hbone_peer_trust_withdrawn",
            Self::Revoked => "hbone_peer_revoked",
        }
    }

    /// The rejected-request reason for a datagram (`CONNECT-UDP`) tunnel. A
    /// separate literal rather than a runtime prefix so the complete reason set
    /// stays greppable and fixed.
    pub(crate) const fn udp_connect_reason(self) -> &'static str {
        match self {
            Self::TrustWithdrawn => "hbone_udp_peer_trust_withdrawn",
            Self::Revoked => "hbone_udp_peer_revoked",
        }
    }
}

/// When an admitted peer leaf's own `notAfter` ends the credential (issue
/// #5568).
///
/// Resolved once, at admission, from the connection's existing
/// `SpiffeIdentityConnectionCache` when one is wired (the ordinary H1/H2/H3
/// mesh listener) and otherwise by parsing the retained leaf. Read rather than
/// re-derived because `RequestContext::credential_deadline_at` is the MINIMUM
/// across every accepted credential on the request — a JWT `exp` from mesh
/// `RequestAuthentication` lands on it too — and a `peer_expired` revocation
/// must describe the peer's SVID, not whichever credential happened to expire
/// first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmittedLeafExpiry {
    /// The leaf's `notAfter`, converted ONCE to the monotonic clock at
    /// admission. Monotonic on purpose: a wall-clock rollback must not be able
    /// to extend a live tunnel's credential.
    At(tokio::time::Instant),
    /// The leaf's `notAfter` outruns the representable monotonic range (issue
    /// #5396) — a certificate with no practical expiration rather than an
    /// unbounded admission. Nothing for the expiry half to decide.
    Unbounded,
    /// The retained leaf could not be parsed, or its ASN.1 interval is not
    /// coherent. The CONNECT that carried it was admitted against a verifier
    /// that DID parse it, so this is a fence failure rather than a statement
    /// about the peer: it revokes as
    /// [`HboneRevocationReason::ReevaluationFailed`], never as
    /// [`HboneRevocationReason::PeerExpired`], because the `reason` label is
    /// the operator's only attribution and must not point at SVID lifetimes for
    /// a parser problem.
    Unparseable,
}

impl HbonePeerCredential {
    /// Decide the credential half of one CONNECT's admission: capture the
    /// credential a sweep will re-check, or refuse the CONNECT outright.
    ///
    /// An `Admit(None)` covers every shape with no certificate-derived peer
    /// identity to bound: a PERMISSIVE plaintext-admitted tunnel, a peer that
    /// presented no certificate, and a kernel-attested (node-waypoint eBPF) or
    /// HBONE-asserted `peer_spiffe_id`, which carries no leaf and therefore no
    /// validity window — bounding one by a certificate deadline would be a
    /// fiction, exactly as `RequestContext::has_certificate_spiffe_principal`
    /// records.
    ///
    /// Otherwise the retained chain is RE-VERIFIED here, against the anchors the
    /// fence's inbound admission trust currently has in force — not against the
    /// verdict the mTLS handshake reached, which for a pooled inbound session
    /// may be arbitrarily old. Those anchors were compiled once, when that trust
    /// revision was published, so the cost is one certificate path validation
    /// per CONNECT and no trust-store construction. A chain that does not
    /// anchor, or that the enforced CRL records revoke, is
    /// [`HboneConnectCredential::Refuse`]: the peer's next handshake would be
    /// refused, so its next CONNECT must be too. The records are part of those
    /// same anchors (issue #5574), so the revocation half costs nothing extra —
    /// one path validation answers both.
    ///
    /// With nothing in force there is nothing to verify against — no inbound
    /// admission trust installed (a chain-only posture), or an installed slot
    /// whose publications have not produced a usable set, in which case the
    /// inbound SPIFFE verifier has no last-known-good cache either and cannot
    /// be what admitted this peer. The CONNECT is admitted with the trust half
    /// inapplicable rather than refused for a state the fence never observed as
    /// good.
    pub(crate) fn from_admitted_connect(
        ctx: &RequestContext,
        fence: &HboneAdmissionFence,
    ) -> HboneConnectCredential {
        if !ctx.has_certificate_spiffe_principal() {
            return HboneConnectCredential::Admit(None);
        }
        let (Some(spiffe_id), Some(leaf_der)) =
            (ctx.peer_spiffe_id.clone(), ctx.tls_client_cert_der.as_ref())
        else {
            return HboneConnectCredential::Admit(None);
        };
        let leaf_der = Arc::clone(leaf_der);
        let intermediates_der = ctx.tls_client_cert_chain_der.clone();

        let trust = fence.inbound_trust_snapshot();
        let anchors = trust.as_ref().and_then(InboundTrustSnapshot::anchors);
        let anchored_at_admission = match anchors {
            // Nothing is in force, so there is nothing to verify against: the
            // trust half stays inapplicable for this tunnel's whole life.
            None => false,
            Some(anchors) => {
                let intermediates: &[Vec<u8>] = intermediates_der
                    .as_ref()
                    .map_or(&[], |chain| chain.as_slice());
                let verdict = anchors.recheck(spiffe_id.trust_domain(), &leaf_der, intermediates);
                // Fail closed on anything but `Trusted`: a withdrawn anchor, a
                // revoked certificate, and a chain the fence cannot judge are
                // equally "this peer would not get through a fresh handshake
                // here". The attribution still distinguishes revocation, which
                // is what the peer's own handshake would report.
                match verdict {
                    AdmittedPeerTrustVerdict::Trusted => true,
                    AdmittedPeerTrustVerdict::Revoked => {
                        fence.record_connect_trust_refusal();
                        return HboneConnectCredential::Refuse(HboneConnectRefusal::Revoked);
                    }
                    AdmittedPeerTrustVerdict::Withdrawn
                    | AdmittedPeerTrustVerdict::Unverifiable => {
                        fence.record_connect_trust_refusal();
                        return HboneConnectCredential::Refuse(HboneConnectRefusal::TrustWithdrawn);
                    }
                }
            }
        };
        let admitted_trust_revision = trust.map_or(0, |trust| trust.revision());

        let credential = Self {
            spiffe_id,
            leaf_der: Arc::clone(&leaf_der),
            intermediates_der,
            leaf_expiry: admitted_leaf_expiry(ctx, leaf_der.as_slice()),
            anchored_at_admission,
            admitted_trust_revision,
        };
        HboneConnectCredential::Admit(Some(credential))
    }
}

/// Resolve the admitted leaf's own expiry without re-parsing a certificate the
/// connection has already parsed.
///
/// `spiffe_identity` parses the peer leaf once per mTLS CONNECTION and caches
/// both the parse and the leaf's monotonic `notAfter`
/// (`SpiffeIdentityConnectionCache`). Many CONNECTs multiplex over one H2 mesh
/// session, so reading that cache keeps this at one parse per connection rather
/// than one per tunnel — and, more importantly, keeps the fence's deadline
/// byte-identical to the one the request path admitted the principal with.
///
/// The parse fallback covers a context with no connection cache wired (a direct
/// library caller, a synthetic fixture) and a cache whose extraction produced
/// no leaf-derived identity.
fn admitted_leaf_expiry(ctx: &RequestContext, leaf_der: &[u8]) -> AdmittedLeafExpiry {
    use crate::plugins::utils::auth_flow::CredentialDeadline;

    let cached = ctx
        .peer_spiffe_extraction_cache
        .as_deref()
        .and_then(|cache| cache.admitted_leaf_deadline());
    let deadline = match cached {
        Some(deadline) => deadline,
        None => parse_leaf_credential_deadline(leaf_der),
    };
    match deadline {
        CredentialDeadline::Bounded(deadline) => AdmittedLeafExpiry::At(deadline),
        CredentialDeadline::Unbounded => AdmittedLeafExpiry::Unbounded,
        CredentialDeadline::Invalid => AdmittedLeafExpiry::Unparseable,
    }
}

/// The monotonic conversion of a leaf's `notAfter`, parsed from the retained
/// DER. The same conversion `spiffe_identity` performs
/// (`plugins::utils::auth_flow::try_credential_deadline_from_unix_seconds`), so
/// the two cannot disagree about which instant a certificate ends at.
///
/// `pub(crate)` because the SOURCE side bounds every pooled inner application
/// connection by the gateway leaf's own `notAfter` through this same
/// conversion; see `HboneConnectionPool::source_credential_identity`. A leaf
/// neither side can parse is `CredentialDeadline::Invalid`, which the source
/// pool folds to an already-elapsed deadline so an unparseable credential is
/// never poolable. (`CredentialDeadline` is named in prose rather than linked:
/// it is imported per function body here, so an intra-doc link would not
/// resolve.)
pub(crate) fn parse_leaf_credential_deadline(
    leaf_der: &[u8],
) -> crate::plugins::utils::auth_flow::CredentialDeadline {
    use crate::plugins::utils::auth_flow::{
        CredentialDeadline, try_credential_deadline_from_unix_seconds,
    };
    use crate::plugins::utils::cert_validity::CertValidityWindow;
    use x509_parser::prelude::*;

    let Ok((_, parsed)) = X509Certificate::from_der(leaf_der) else {
        return CredentialDeadline::Invalid;
    };
    let Some(validity) = CertValidityWindow::from_certificate(&parsed) else {
        return CredentialDeadline::Invalid;
    };
    try_credential_deadline_from_unix_seconds(validity.not_after_unix, 0)
}

/// Everything the CONNECT admission gates evaluated, captured after admission
/// so a sweep can re-run the same decision against a later generation.
pub struct HboneAdmissionSnapshot {
    /// Request context after the authorize and `before_proxy` phases. Cloned
    /// per sweep because `authorize` takes `&mut`.
    pub ctx: RequestContext,
    /// The effective (post-route-override) proxy the relay dialed through.
    pub proxy: Arc<Proxy>,
    pub upstream_target: Option<Arc<UpstreamTarget>>,
    pub is_tls: bool,
    pub has_verified_peer_certificate: bool,
    pub mesh_inbound_pre_handshake_app_port: Option<u16>,
    pub destination_gate: HboneRelayDestinationGate,
    /// The address the relay actually dialled, when one was resolved. The
    /// ordinary inbound relay screens post-DNS loopback answers before the
    /// dial, and the sweep re-applies that screen to this address — authority
    /// matching admits a declared hostname without resolving it, so the
    /// authority decision alone cannot see a tunnel pinned to `127.0.0.0/8`.
    pub resolved_ip: Option<IpAddr>,
    /// `Some` only for a proxy present in the published configuration;
    /// synthesized relay proxies are absent from every generation by design.
    pub proxy_lifecycle_generation: Option<u64>,
    /// The protocol the request path resolved the admitting plugin view with.
    /// The authorize chain is protocol-scoped and an HBONE CONNECT carrying
    /// `content-type: application/grpc` classifies as gRPC, so the sweep must
    /// re-resolve the SAME view rather than assume plain HTTP.
    pub request_protocol: ProxyProtocol,
    /// Whether the admitting view came from `grpc_web_request_view` rather than
    /// `request_view`; see [`Self::request_protocol`].
    pub grpc_web_request: bool,
    /// [`HboneAdmissionFence::sweep_epoch`] as captured BEFORE the request path
    /// read the epoch and PeerAuthentication policy these gates judged. See
    /// [`HboneAdmissionFence::admit`] for the publish-then-recheck contract.
    pub admission_sweep_epoch: u64,
    /// The peer credential this tunnel was admitted on, when the CONNECT
    /// carried a certificate-derived SPIFFE principal. `None` leaves the
    /// credential gate inapplicable — see
    /// [`HbonePeerCredential::from_admitted_connect`].
    pub peer_credential: Option<HbonePeerCredential>,
    /// Whether the admitting plugin chain classified this CONNECT's tunnel as
    /// safe to carry LATER application operations without running again — the
    /// chain half of the `x-ferrum-mesh-tunnel-reuse` advertisement (issue
    /// #5583).
    ///
    /// Recorded here, BEFORE [`HboneAdmissionFence::admit`] registers the
    /// tunnel, because it is what the CONNECT response then reads to decide
    /// whether to stamp the header: the two cannot disagree, because there is
    /// only one value. The response ANDs it with
    /// [`AdmittedHboneTunnel::fence_in_force`], which cannot be evaluated
    /// before registration and needs no recording — a tunnel the fence does not
    /// hold is not in the registry, so no sweep reaches it either way.
    ///
    /// `true` obliges the fence to keep re-deciding it: a tunnel admitted with
    /// the advertisement is carrying operations the source will not re-CONNECT
    /// for, so every sweep re-folds the CURRENT chain and revokes on
    /// [`HboneRevocationReason::ReuseWithdrawn`] when it no longer permits
    /// reuse. `false` obliges nothing — that tunnel already performs one full
    /// destination admission per operation.
    pub advertised_inner_reuse: bool,
    /// The listener facts the admitting classification used. Sweeps keep these
    /// unchanged even while re-folding a new plugin generation or authorizing
    /// with a mutable clone of `ctx`.
    pub reuse_context: HboneReuseContext,
}

struct AdmittedHboneTunnelInner {
    id: u64,
    token: CancellationToken,
    /// ONE terminal-state word: `TUNNEL_LIVE`, `TUNNEL_RETIRED`, or
    /// `TUNNEL_REVOKED_BASE + HboneRevocationReason::index()`. See those
    /// constants for why retirement and revocation share it.
    state: AtomicU8,
    /// The inbound admission trust revision this tunnel's chain was last
    /// VERIFIED against (issue #5568).
    ///
    /// Seeded from [`HbonePeerCredential::admitted_trust_revision`] and
    /// advanced by every `Trusted` sweep verdict, so a tunnel admitted under an
    /// older revision pays certificate path building ONCE per trust change
    /// rather than once per sweep for the rest of its life. Kept out of the
    /// immutable [`HboneAdmissionSnapshot`] deliberately: the snapshot records
    /// what admission decided and must not be rewritten, while this records
    /// what the fence has since confirmed.
    verified_trust_revision: AtomicU64,
    snapshot: HboneAdmissionSnapshot,
    fence: Weak<HboneAdmissionFence>,
}

/// The relay is still carrying bytes and no sweep has claimed the tunnel.
///
/// `AdmittedHboneTunnel::retire` and `AdmittedHboneTunnel::claim_revocation`
/// are the ONLY writers and each is a single compare-exchange out of this
/// value, so exactly one of them wins. Two separate atomics could not give
/// that: a sweep that read "not retired" microseconds before the relay ended
/// still counted, logged and metered a revocation for a tunnel carrying no
/// bytes, and the datagram relay — which reads `revoked_reason()` after
/// `retire()` and has no `first_failure` to cross-check against — then reported
/// an ordinary idle/EOF close as an admission revocation.
const TUNNEL_LIVE: u8 = 0;
/// The relay ended first. The tunnel is neither swept, counted, nor classified
/// as revoked.
const TUNNEL_RETIRED: u8 = 1;
/// A sweep claimed the tunnel; the value is this base plus
/// `HboneRevocationReason::index()`. The reason stays readable after the relay
/// calls `retire()`, which is how the datagram relay classifies its own close.
const TUNNEL_REVOKED_BASE: u8 = 2;

impl Drop for AdmittedHboneTunnelInner {
    fn drop(&mut self) {
        if let Some(fence) = self.fence.upgrade() {
            let ptr = std::ptr::from_mut(self).cast_const();
            fence
                .tunnels
                .remove_if(&self.id, |_, weak| std::ptr::eq(weak.as_ptr(), ptr));
        }
    }
}

/// One live admitted tunnel. Held by the relay task; dropping the last handle
/// deregisters the tunnel. Cheap to clone (one `Arc` bump).
#[derive(Clone)]
pub struct AdmittedHboneTunnel {
    inner: Arc<AdmittedHboneTunnelInner>,
}

impl AdmittedHboneTunnel {
    /// The admission snapshot; the relay reads its `ctx` for the transaction
    /// summary so the tunnel is cloned once, not twice.
    pub fn snapshot(&self) -> &HboneAdmissionSnapshot {
        &self.inner.snapshot
    }

    /// Owned cancellation handle for the relay's termination bound.
    pub fn revocation_token(&self) -> CancellationToken {
        self.inner.token.clone()
    }

    /// The admitted credential's monotonic expiry, when this tunnel carries
    /// one. `None` for a tunnel with no certificate-derived peer credential and
    /// for a leaf whose `notAfter` is beyond the representable monotonic range
    /// or could not be parsed (the latter is revoked by the next sweep as a
    /// fence failure, so it needs no timer).
    fn credential_deadline(&self) -> Option<tokio::time::Instant> {
        match self.inner.snapshot.peer_credential.as_ref()?.leaf_expiry {
            AdmittedLeafExpiry::At(deadline) => Some(deadline),
            AdmittedLeafExpiry::Unbounded | AdmittedLeafExpiry::Unparseable => None,
        }
    }

    /// Whether this tunnel is REGISTERED with a live fence right now: the
    /// registry holds exactly this entry, and neither a sweep nor the relay has
    /// claimed it (issue #5042 step 2).
    ///
    /// This is the predicate the CONNECT `200` advertises through
    /// [`crate::modes::mesh::hbone::TUNNEL_REUSE_HEADER`]. Source-side reuse of
    /// the application connection inside a tunnel is admissible ONLY because a
    /// later policy or credential generation can still reach that tunnel and
    /// cut it; a tunnel nothing can reach is judged by nothing, so it must not
    /// advertise the capability and the source keeps per-request behaviour for
    /// it.
    ///
    /// Deliberately an observation of the REGISTRY rather than of the fact that
    /// [`HboneAdmissionFence::admit`] returned: the entry is a `Weak`, the
    /// fence itself is held by `ProxyState` behind an `Arc`, and both
    /// `retire()` and `Drop` deregister. Asking the registry is the only form of
    /// the question that stays true to what a sweep would actually find, and it
    /// costs one `DashMap` lookup per CONNECT — off the byte-relay path.
    pub fn fence_in_force(&self) -> bool {
        let Some(fence) = self.inner.fence.upgrade() else {
            return false;
        };
        if self.inner.state.load(Ordering::Acquire) != TUNNEL_LIVE {
            return false;
        }
        let ptr = Arc::as_ptr(&self.inner);
        fence
            .tunnels
            .get(&self.inner.id)
            .is_some_and(|entry| std::ptr::eq(entry.value().as_ptr(), ptr))
    }

    /// Whether a sweep revoked this tunnel, and why. `None` for a tunnel that
    /// is still live and for one whose relay retired it first.
    pub fn revoked_reason(&self) -> Option<HboneRevocationReason> {
        self.inner
            .state
            .load(Ordering::Acquire)
            .checked_sub(TUNNEL_REVOKED_BASE)
            .and_then(HboneRevocationReason::from_index)
    }

    /// Deregister the tunnel the instant its relay ends, before the transaction
    /// summary and the operator logging chain run. `true` means this call won
    /// the terminal transition — the relay ended before any sweep claimed the
    /// tunnel; `false` means a sweep had already claimed it and its reason
    /// stays readable through [`Self::revoked_reason`].
    ///
    /// The transition is ONE compare-exchange against the same word
    /// [`Self::claim_revocation`] uses, so a sweep judging this tunnel and the
    /// relay ending cannot both win: `ferrum_mesh_hbone_tunnel_revocations_total`
    /// and [`HboneAdmissionFence::live_tunnels`] count only tunnels that were
    /// still carrying bytes. `Drop` stays the safety net for every path that
    /// cannot reach this call.
    pub fn retire(&self) -> bool {
        let won = self.transition_from_live(TUNNEL_RETIRED);
        if let Some(fence) = self.inner.fence.upgrade() {
            let ptr = Arc::as_ptr(&self.inner);
            fence
                .tunnels
                .remove_if(&self.inner.id, |_, weak| std::ptr::eq(weak.as_ptr(), ptr));
        }
        won
    }

    /// Claim this tunnel for revocation and record the reason, WITHOUT
    /// cancelling yet. `true` means this caller won the claim and owns the
    /// accounting; the cancellation edge is published afterwards by
    /// [`Self::publish_revocation`]. A tunnel the relay already retired, or one
    /// a previous sweep already claimed, refuses the claim.
    ///
    /// The reason is recorded before the cancellation because the relay reads
    /// `revoked_reason()` as soon as it observes the cancellation, and the
    /// datagram relay has no first-failure record to classify instead, so a
    /// cancellation the reason has not caught up with would be reported as a
    /// transport failure. Nothing depends on seeing the cancellation edge
    /// first: the only `is_cancelled()` reader is the sweep loop, and sweeps
    /// are serialized by `sweep_serial`.
    fn claim_revocation(&self, reason: HboneRevocationReason) -> bool {
        self.transition_from_live(TUNNEL_REVOKED_BASE + reason.index() as u8)
    }

    /// The ONE write that ends a tunnel: a single compare-exchange out of
    /// [`TUNNEL_LIVE`]. `true` means this caller won.
    fn transition_from_live(&self, terminal: u8) -> bool {
        self.inner
            .state
            .compare_exchange(TUNNEL_LIVE, terminal, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Publish the cancellation edge for a tunnel already claimed by
    /// [`Self::claim_revocation`].
    ///
    /// This is the LAST step of a revocation, after the counter, the metric,
    /// and the log. Cancellation is the only edge anything outside the sweep
    /// waits on — the relay's revocation bound, and an operator or test reading
    /// [`HboneAdmissionFence::revocations`] the moment a tunnel ends — so
    /// anything that observes it must already be able to observe the
    /// accounting. Cancelling first left a real window in which a revoked
    /// tunnel was reported by nothing at all.
    fn publish_revocation(&self) {
        self.inner.token.cancel();
    }
}

/// Process-wide registry of live admitted HBONE tunnels plus the sweep that
/// re-applies their admission gates. One per `ProxyState`.
pub struct HboneAdmissionFence {
    tunnels: DashMap<u64, Weak<AdmittedHboneTunnelInner>>,
    next_id: AtomicU64,
    sweeps_requested: AtomicU64,
    sweeps_completed: AtomicU64,
    /// Serializes sweeps; a request that arrives mid-sweep is folded into the
    /// next pass by the requested/completed counters.
    sweep_serial: tokio::sync::Mutex<()>,
    revocations: [AtomicU64; HboneRevocationReason::ALL.len()],
    reevaluations: AtomicU64,
    /// Certificate path builds a SWEEP's credential gate performed. A trust
    /// publication that changes nothing must not move this, and neither may a
    /// CONNECT — the CONNECT-side path validation is counted separately so this
    /// stays the observable form of "an ordinary publication costs no path
    /// building".
    trust_rechecks: AtomicU64,
    /// CONNECTs refused because the peer's retained chain does not anchor under
    /// the inbound admission trust in force (issue #5568 review). The
    /// counterpart of a `peer_trust` revocation on the admission path: a peer
    /// whose trust was retired is revoked once and then refused on every
    /// reconnect over its pooled inbound session.
    connect_trust_refusals: AtomicU64,
    /// Times the inbound admission trust's anchors were compiled. Advances once
    /// per in-force revision — never per sweep and never per CONNECT — so a
    /// contract test can pin that the per-CONNECT cost is one path validation
    /// against cached verifiers.
    trust_anchor_builds: AtomicU64,
    /// Monotonic nanoseconds of the last "publication is not in force" warning,
    /// [`NO_DEADLINE`] when none has been emitted. A malformed federated bundle
    /// republished on every slice apply must not print once per apply.
    trust_not_in_force_warned_at: AtomicU64,
    /// `true` while the bounded expiry watcher task is running. At most one
    /// exists; it exits once no live tunnel carries a finite credential
    /// deadline, so a mesh with no SVID-bearing tunnels runs no timer at all.
    expiry_watcher: AtomicBool,
    /// The credential deadline the expiry watcher is currently parked on, as
    /// monotonic nanoseconds since [`Self::clock_base`]; [`NO_DEADLINE`] when
    /// no watcher is parked.
    ///
    /// This is what keeps `admit` off the registry: without it every admitted
    /// tunnel carrying a finite deadline — the ordinary case — woke the watcher
    /// into a full `DashMap` scan that upgraded every `Weak`, so a burst of N
    /// CONNECTs cost O(N²) and saturated a core rediscovering a deadline it was
    /// already parked on. Published through `fetch_min`, and reset to
    /// [`NO_DEADLINE`] before each re-scan so a tunnel admitted during the scan
    /// still lowers it and therefore still nudges.
    expiry_parked_deadline: AtomicU64,
    /// Base for [`Self::expiry_parked_deadline`]. Captured once so two
    /// `tokio::time::Instant`s can be compared as one atomic word.
    clock_base: tokio::time::Instant,
    /// Re-arm signal for the expiry watcher. A tunnel admitted with an EARLIER
    /// deadline than the one the watcher is parked on must not wait for that
    /// later deadline to fire.
    expiry_wakeup: tokio::sync::Notify,
    /// The inbound mTLS admission trust the credential gate judges CONNECTs and
    /// live tunnels against, installed by mesh startup. `None` on every
    /// non-mesh listener and on a chain-only mesh inbound posture, which leaves
    /// the trust half of the credential gate inapplicable exactly as
    /// [`HbonePeerCredential::anchored_at_admission`] `== false` does.
    inbound_trust: ArcSwapOption<MeshInboundAdmissionTrust>,
    /// The ONE strictly increasing sequence every in-force trust revision is
    /// drawn from; see `InForceInboundTrust::revision` for why it is fence-wide
    /// rather than per-slot.
    trust_revision_seq: AtomicU64,
    request_epoch: Arc<RequestEpochStore>,
    mesh_inbound_tls_policy: SharedMeshInboundTlsPolicy,
    /// The ONE accepted inbound admission artifact (issue #5574): the enforced
    /// CRL records the mesh inbound SPIFFE peer verifier polices, and the cell
    /// naming the compiled anchors currently IN FORCE. The very object the
    /// verifier holds, so a sweep, a CONNECT, and a handshake all decide from
    /// one compiled set rather than from three independently retained ones.
    mesh_inbound_admission: SharedInboundAdmissionArtifact,
    /// Serializes install → compare → store → in-force advance across ALL THREE
    /// publishers (trust install, trust publication, CRL publication).
    ///
    /// Fence-owned and created in [`Self::new`], deliberately not per installed
    /// trust: the install itself has to be inside it. A CRL publisher that read
    /// "no trust installed" outside a lock could otherwise be overtaken by
    /// startup's install — which compiles against the records in force at that
    /// instant — and then store newer records with nothing recompiled, leaving
    /// the verifier on one list and the fence's anchors on another with no
    /// later publication able to repair it (a byte-identical republish returns
    /// early). Production really does start the backend CRL watcher before mesh
    /// installs its inbound slot, so that is a startup interleaving rather than
    /// a misuse of a test helper.
    publish_lock: std::sync::Mutex<()>,
}

/// No expiry watcher is parked on any deadline.
const NO_DEADLINE: u64 = u64::MAX;

/// Sampling window for the "inbound admission trust publication is not in
/// force" warning. Long enough that a persistently malformed bundle
/// republished on every slice apply prints once a minute, short enough that an
/// operator investigating a rollout sees it.
const TRUST_NOT_IN_FORCE_WARN_INTERVAL_NANOS: u64 = 60 * 1_000_000_000;

impl HboneAdmissionFence {
    pub fn new(
        request_epoch: Arc<RequestEpochStore>,
        mesh_inbound_tls_policy: SharedMeshInboundTlsPolicy,
        mesh_inbound_admission: SharedInboundAdmissionArtifact,
    ) -> Self {
        Self {
            tunnels: DashMap::new(),
            next_id: AtomicU64::new(1),
            sweeps_requested: AtomicU64::new(0),
            sweeps_completed: AtomicU64::new(0),
            sweep_serial: tokio::sync::Mutex::new(()),
            revocations: Default::default(),
            reevaluations: AtomicU64::new(0),
            trust_rechecks: AtomicU64::new(0),
            connect_trust_refusals: AtomicU64::new(0),
            trust_anchor_builds: AtomicU64::new(0),
            trust_not_in_force_warned_at: AtomicU64::new(NO_DEADLINE),
            expiry_watcher: AtomicBool::new(false),
            expiry_parked_deadline: AtomicU64::new(NO_DEADLINE),
            clock_base: tokio::time::Instant::now(),
            expiry_wakeup: tokio::sync::Notify::new(),
            inbound_trust: ArcSwapOption::empty(),
            trust_revision_seq: AtomicU64::new(0),
            request_epoch,
            mesh_inbound_tls_policy,
            mesh_inbound_admission,
            publish_lock: std::sync::Mutex::new(()),
        }
    }

    /// Bind the inbound mTLS verifier's trust slot to the fence (issue #5568).
    ///
    /// Mesh startup calls this for the ONE slot the inbound SPIFFE
    /// client-certificate verifier reads, so the credential gate judges CONNECTs
    /// and live tunnels against the anchors their peers' next handshake would
    /// actually apply. Idempotent for the same slot: re-installing keeps the
    /// running revision and its compiled anchors, so a second wiring call cannot
    /// make every live tunnel rebuild its certificate path.
    ///
    /// A DIFFERENT slot replaces the binding and takes a FRESH revision from the
    /// fence's own sequence, never a restarted per-slot counter — so a revision
    /// can never name two different sets of anchors and the credential gate's
    /// inequality comparison stays sound across a rebind. Whatever the slot
    /// already carries is compiled here, so a CONNECT arriving before the first
    /// publication is judged against the material actually installed.
    ///
    /// A rebind whose material does NOT compile takes the same last-known-good
    /// posture a rejected trust or CRL candidate takes (issue #5574 re-review):
    /// the binding already in force is KEPT — not replaced, not cleared, and not
    /// given a new revision — and one sampled `warn!` names it. Replacing it
    /// would clear the shared anchors while an already-built verifier went on
    /// reading its ORIGINAL slot (installation does not reach a verifier that
    /// exists), so the handshake would fall back to its own compile of the old
    /// slot while the fence lost its anchors entirely: arriving CONNECTs would
    /// take the unanchored path and every credential admitted that way skips
    /// trust reevaluation for the rest of its tunnel's life.
    ///
    /// A FIRST install that compiles nothing is different and unchanged: nothing
    /// is in force to keep, the verifier's own compile of that slot is the
    /// documented pre-first-publication fallback, and the trust half of the
    /// credential gate stays inapplicable until something does compile.
    pub fn install_inbound_admission_trust(&self, slot: &crate::tls::SharedBundleSlot) {
        let _publication = self.publication_lock();
        self.install_inbound_admission_trust_locked(slot);
    }

    /// [`Self::install_inbound_admission_trust`] with the publication lock
    /// already held, returning the binding in force afterwards.
    ///
    /// Separate because the trust publisher must install and publish as ONE
    /// critical section: the lock is not reentrant, and a publisher that
    /// released it between the two would reopen the interleaving the lock
    /// exists to close.
    fn install_inbound_admission_trust_locked(
        &self,
        slot: &crate::tls::SharedBundleSlot,
    ) -> Arc<MeshInboundAdmissionTrust> {
        let bound = self.inbound_trust.load_full();
        if let Some(installed) = &bound
            && Arc::ptr_eq(&installed.slot, slot)
        {
            return Arc::clone(installed);
        }
        let current = slot.load_full();
        let crls = self.enforced_crl_records();
        let material = current.as_ref().as_ref().map(|svid| &svid.trust_bundles);
        let compiled = match self.compile_in_force(material, &crls) {
            Ok(compiled) => Some(compiled),
            Err(trust_domain_class) => {
                // Last-known-good, exactly as a rejected trust or CRL candidate
                // is treated: a rebind that compiles nothing while anchors ARE
                // in force keeps the binding it would have replaced. Clearing
                // the artifact here would leave a live fence with no anchors
                // while an existing verifier kept reading its own original
                // slot — see the public installer's doc comment.
                let keep = bound.filter(|installed| installed.has_anchors_in_force());
                if let Some(installed) = keep {
                    self.warn_rebind_not_in_force(trust_domain_class);
                    return installed;
                }
                None
            }
        };
        // The handshake verifier adopts the binding's anchors too, and the cell
        // is never cleared: `put_in_force` takes the anchors themselves, so a
        // binding with nothing compiled simply leaves whatever is in force
        // alone — which, on this branch, is nothing.
        if let Some(compiled) = &compiled {
            self.mesh_inbound_admission
                .put_in_force(Arc::clone(&compiled.anchors));
        }
        let in_force = InForceInboundTrust {
            revision: self.next_trust_revision(),
            compiled,
        };
        let installed = Arc::new(MeshInboundAdmissionTrust::wrap(slot.clone(), in_force));
        self.inbound_trust.store(Some(Arc::clone(&installed)));
        installed
    }

    /// The one publication lock, recovering a poisoned guard's contents (it
    /// guards no data, only ordering).
    fn publication_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.publish_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Put `compiled` in force: publish its anchors to the shared artifact the
    /// handshake verifier reads, then advance the in-force revision.
    ///
    /// The two stores are NOT one atomic step, and the artifact goes first
    /// deliberately, so the revision is drawn after: a reader that observes a
    /// revision observes anchors at least as new as it names, which is what
    /// keeps the credential gate's skip key sound (a tunnel that skips
    /// re-verification because its last-verified revision matches can never
    /// have been verified against anchors OLDER than that revision).
    ///
    /// The cost is a window — bounded by this critical section under
    /// [`Self::publication_lock`], not by any wall-clock figure, since a thread
    /// can be preempted anywhere inside it — in which a handshake verifies
    /// against anchors ONE GENERATION NEWER than the fence's in-force snapshot.
    /// Which surface is stricter there depends on the change, and the ordering
    /// does not make the handshake universally stricter (issue #5574
    /// verification re-review):
    ///
    /// - A CRL ADDITION or a trust WITHDRAWAL makes the handshake stricter: it
    ///   already refuses a peer the fence's CONNECT gate would still admit,
    ///   until the revision advances.
    /// - A CRL REMOVAL or a trust ADDITION makes the handshake LOOSER: it
    ///   admits a peer the fence still refuses, and the CONNECT gate then
    ///   refuses the tunnel that handshake just established, again until the
    ///   revision advances.
    ///
    /// Both directions fail closed — the stricter of the two surfaces decides,
    /// because a CONNECT is required before any byte is relayed — and the two
    /// converge as soon as the publication completes. A handshake or CONNECT
    /// already in flight finishes against the snapshot it loaded.
    ///
    /// Callers hold [`Self::publication_lock`].
    fn store_in_force(&self, trust: &MeshInboundAdmissionTrust, compiled: CompiledInboundTrust) {
        self.mesh_inbound_admission
            .put_in_force(Arc::clone(&compiled.anchors));
        trust.in_force.store(Arc::new(InForceInboundTrust {
            revision: self.next_trust_revision(),
            compiled: Some(compiled),
        }));
    }

    /// The CRL records the mesh inbound SPIFFE verifier enforces right now, as
    /// one `Arc` clone.
    ///
    /// Read from the SLOT the verifier itself reads rather than from any
    /// configuration generation: the enforced revocation list is the operator's
    /// standing list, not part of an accepted config, and the whole point of
    /// issue #5574 is that both surfaces police the same records.
    fn enforced_crl_records(&self) -> CrlList {
        Arc::clone(self.mesh_inbound_admission.crls().load().crls())
    }

    /// The next value of the fence's single strictly-increasing trust-revision
    /// sequence. `0` is never handed out, so it stays reserved for "no inbound
    /// admission trust installed" and a tunnel admitted with no slot can never
    /// compare equal to one that has one.
    fn next_trust_revision(&self) -> u64 {
        self.trust_revision_seq.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Compile a published bundle into the anchors that go IN FORCE, or report
    /// why the publication takes no force at all.
    ///
    /// "In force" means exactly what it means for the inbound SPIFFE verifier,
    /// which is the whole point (issue #5568 review). That verifier compiles a
    /// candidate ATOMICALLY and, when it fails, logs
    /// "candidate trust update rejected; keeping last-known-good set" and keeps
    /// serving the previous one; an absent bundle is the same story. So a
    /// candidate this cannot compile must not replace what the fence judges
    /// against either — otherwise the fence would revoke tunnels the verifier is
    /// still admitting, and judge every other trust domain against material the
    /// verifier never adopted.
    ///
    /// `crls` is folded into the SAME compiled artifact rather than consulted
    /// beside it (issue #5574). The enforced revocation list is part of the
    /// question the peer's next handshake asks — the inbound verifier attaches
    /// exactly these records to exactly these anchors — so compiling them
    /// together is what makes one `recheck` answer "would this still be
    /// admitted" instead of a trust-only approximation of it. It also keeps the
    /// cost where it belongs: the records are attached once per in-force
    /// revision, never per sweep and never per CONNECT.
    ///
    /// The `Err` is the operator label for why: the trust-domain CLASS, or
    /// `absent` for a slot carrying no bundle at all. A trust-domain NAME is a
    /// CP-supplied value, so the detail stays at `debug!` inside
    /// `AdmittedPeerTrustAnchors::compile`. Reporting is the caller's, because
    /// only a PUBLICATION that fails to take force is worth an operator line:
    /// the same `Err` at install time is just a slot whose first SVID has not
    /// arrived yet.
    fn compile_in_force(
        &self,
        material: Option<&crate::identity::TrustBundleSet>,
        crls: &CrlList,
    ) -> Result<CompiledInboundTrust, &'static str> {
        let Some(material) = material else {
            return Err("absent");
        };
        match AdmittedPeerTrustAnchors::compile(material, crls.as_slice()) {
            Ok(anchors) => {
                self.trust_anchor_builds.fetch_add(1, Ordering::Relaxed);
                Ok(CompiledInboundTrust {
                    material: material.clone(),
                    crls: Arc::clone(crls),
                    anchors: Arc::new(anchors),
                })
            }
            Err(class) => Err(class.as_str()),
        }
    }

    /// One CONNECT refused by the credential gate: the retained chain does not
    /// anchor under the trust in force, or the enforced records revoke a
    /// certificate on it. Counted here rather than at the call site so the gate
    /// and the counter cannot drift apart.
    fn record_connect_trust_refusal(&self) {
        self.connect_trust_refusals.fetch_add(1, Ordering::Relaxed);
    }

    /// Whether a "publication is not in force" line is due in this sampling
    /// window, claiming the window when it is.
    ///
    /// One window shared by every not-in-force warning, so a deployment failing
    /// several of them at once prints one line per window rather than one per
    /// cause.
    fn not_in_force_warning_due(&self) -> bool {
        let now = self.monotonic_nanos(tokio::time::Instant::now());
        let last = self.trust_not_in_force_warned_at.load(Ordering::Relaxed);
        let due = last == NO_DEADLINE
            || now.saturating_sub(last) >= TRUST_NOT_IN_FORCE_WARN_INTERVAL_NANOS;
        due && self
            .trust_not_in_force_warned_at
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// One sampled operator line per [`TRUST_NOT_IN_FORCE_WARN_INTERVAL_NANOS`]
    /// window. A slice apply republishes the inbound slot from unchanged inputs,
    /// so a set that carries, say, a JWT-only federated trust domain would
    /// otherwise print on every apply for as long as it is configured.
    fn warn_trust_not_in_force(&self, trust_domain_class: &'static str) {
        if !self.not_in_force_warning_due() {
            return;
        }
        warn!(
            trust_domain_class,
            "Inbound admission trust publication is not in force: a declared trust domain does \
             not compile into a usable peer verifier, so the inbound mTLS verifier keeps its \
             last-known-good set and live HBONE tunnels keep being judged against the trust \
             revision still in force"
        );
    }

    /// The rebind form of [`Self::warn_trust_not_in_force`], on the same shared
    /// sampling window.
    ///
    /// Named separately because the operator remediation is different: the
    /// material that failed to compile is a DIFFERENT trust slot's, so the
    /// binding an operator would inspect is not the one now being judged
    /// against.
    fn warn_rebind_not_in_force(&self, trust_domain_class: &'static str) {
        if !self.not_in_force_warning_due() {
            return;
        }
        warn!(
            trust_domain_class,
            "Inbound admission trust rebind is not in force: the replacement trust slot's \
             material does not compile into a usable peer verifier, so the previously installed \
             slot stays in force on both the inbound mTLS handshake and the HBONE credential \
             gate rather than leaving either surface with no anchors at all"
        );
    }

    /// Publish `bundle` into the inbound mTLS verifier's trust slot and re-judge
    /// every live tunnel against it (issue #5568).
    ///
    /// The ONE writer of that slot. Storing directly would leave live tunnels
    /// judged against material the verifier has already stopped using, and
    /// would leave the slot's trust revision — the fence's skip key — behind
    /// the bytes it names.
    ///
    /// Ordering is publish-then-recheck, identical to
    /// `ProxyState::publish_mesh_inbound_tls_policy`: the store and the
    /// in-force advance both land BEFORE the sweep request, so a CONNECT that
    /// read the superseded trust necessarily captured a stale sweep counter too
    /// and [`Self::admit`] turns that into a fresh sweep.
    ///
    /// The sweep is requested unconditionally, including for a republish that
    /// changes no trust material at all: it is the policy gates' publication
    /// too, and an unchanged republish costs no certificate path building
    /// because the revision did not move.
    ///
    /// The bundle is stored unconditionally even when only the leaf and key
    /// moved: the same slot backs the inbound listener's server identity
    /// (`tls::SvidServerCertResolver`), which must see a rotation immediately.
    /// What goes IN FORCE for the fence is conditional on BOTH the trust
    /// material actually changing and the candidate compiling as one atomic set
    /// — see `compile_in_force`.
    ///
    /// The store lands FIRST inside the critical section, ahead of the binding,
    /// for two reasons: the candidate is what a first bind of an unbound slot
    /// should compile (so one publication costs one compile and one revision,
    /// not two of each), and the slot written is the CALLER's, so a rebind the
    /// fence refuses still delivers the server identity to the slot it was
    /// published for instead of into the slot that stayed in force.
    pub fn publish_inbound_admission_trust(
        self: &Arc<Self>,
        slot: &crate::tls::SharedBundleSlot,
        bundle: Arc<Option<crate::identity::SvidBundle>>,
    ) {
        {
            // ONE critical section covering the store, install, compare and the
            // in-force advance. Installing inside it is what keeps a concurrent
            // CRL publisher from deciding "no trust installed" against a
            // binding this call is in the middle of creating.
            let _publication = self.publication_lock();
            slot.store(Arc::clone(&bundle));
            let trust = self.install_inbound_admission_trust_locked(slot);
            let in_force = trust.in_force.load_full();
            let candidate = (*bundle).as_ref().map(|bundle| &bundle.trust_bundles);
            let crls = self.enforced_crl_records();
            // Compared against what is IN FORCE, never against the slot's
            // current bytes: a candidate the fence refused is in the slot but is
            // not what anything is judged against, so re-publishing the set that
            // IS in force must stay a no-op.
            //
            // The enforced CRL records are part of that comparison because they
            // are part of the compiled artifact (issue #5574): a trust
            // publication that arrives while the records in force are stale —
            // a CRL rotation that landed before any trust was in force, so it
            // had no anchors to recompile — must pick them up rather than
            // compile the new material against the old list. Both halves are
            // read under the lock, so neither can move between the comparison
            // and the compile.
            let crls_changed = in_force
                .crls()
                .is_some_and(|current| !crl_records_equal(current, &crls));
            let changed = !trust_material_eq(in_force.material(), candidate) || crls_changed;
            let compiled = if changed {
                match self.compile_in_force(candidate, &crls) {
                    Ok(compiled) => Some(compiled),
                    Err(trust_domain_class) => {
                        // A publication that silently stops taking effect is the
                        // one failure mode an operator cannot see from the
                        // outside: the verifier keeps admitting and the fence
                        // keeps judging, both against the previous set.
                        self.warn_trust_not_in_force(trust_domain_class);
                        None
                    }
                }
            } else {
                None
            };
            if let Some(compiled) = compiled {
                self.store_in_force(&trust, compiled);
            }
        }
        self.request_sweep();
    }

    /// Publish the CRL records the mesh inbound SPIFFE verifier enforces, and
    /// re-judge every live tunnel against them (issue #5574).
    ///
    /// The ONE writer of that slot, for the same reason
    /// [`Self::publish_inbound_admission_trust`] is the one writer of the trust
    /// slot: the records are an input to the SAME compiled anchors the
    /// credential gate judges live tunnels and arriving CONNECTs against. A
    /// direct `slot.store()` would leave the verifier enforcing one list while
    /// the fence's cached anchors policed another, and would leave the in-force
    /// revision — the gate's only skip key — behind the records it names, so
    /// every tunnel would skip re-verification exactly when a revocation
    /// arrived.
    ///
    /// Returns whether the enforced set actually changed. Three things are
    /// deliberately no-ops:
    ///
    /// - Byte-identical records. A periodic reload of an unchanged CRL file
    ///   re-parses the same bytes into a fresh allocation, and treating that as
    ///   a publication would make the reload cadence rebuild every live
    ///   tunnel's certificate path for no decision at all.
    /// - A candidate that is not USABLE — unparseable, not yet valid, carrying
    ///   no `nextUpdate`, or already past it. The records are not published,
    ///   the revision does not move, nothing is revoked, and a sampled operator
    ///   line says so. That is the verifier's own all-or-nothing rule
    ///   (`crl_policy::validate_crl_windows` at admission, and a builder that
    ///   refuses the record at handshake time): a list the verifier cannot use
    ///   must not become the list the fence judges by, and must certainly not
    ///   mass-revoke healthy tunnels as un-judgeable.
    /// - A candidate the anchors in force cannot be recompiled with. Same rule,
    ///   reached only if webpki refuses a record this already admitted.
    ///
    /// Ordering is publish-then-recheck: the records land in the slot and the
    /// in-force revision advances BEFORE the sweep is requested, so a CONNECT
    /// that read the superseded set necessarily captured a stale sweep counter
    /// too and [`Self::admit`] turns that into a fresh pass.
    pub fn publish_inbound_admission_crls(self: &Arc<Self>, crls: CrlList) -> bool {
        // The fence owns the verifier's slot; there is deliberately no slot
        // parameter, so a caller cannot publish records into one slot while the
        // anchors in force were compiled against another.
        //
        // Compared against what the VERIFIER enforces, which is also the
        // baseline `enforced_crl_records` hands every compile: a republish of
        // the live records changes nothing on either surface. Checked outside
        // the lock because an unchanged reload is the common case and must cost
        // nothing; every decision this check gates is re-taken under the lock.
        if crl_records_equal(self.enforced_crl_slot().load().crls(), &crls) {
            return false;
        }
        if let Err(class) = usable_crl_records(&crls) {
            self.warn_crls_not_in_force(class);
            return false;
        }
        let published = self.publish_usable_inbound_admission_crls(crls);
        if published {
            self.request_sweep();
        }
        published
    }

    /// The locked half of [`Self::publish_inbound_admission_crls`], for a
    /// candidate already known to be usable.
    ///
    /// Everything that decides what goes in force is re-taken here, under the
    /// one fence-wide publication lock, because every input can move between
    /// the outer checks and this point:
    ///
    /// - The enforced records: two publishers can pass the outer equality check
    ///   with the SAME candidate. The loser must recompile nothing and advance
    ///   nothing — an identical publication that moved the revision would make
    ///   every live tunnel rebuild its certificate path for a decision that did
    ///   not change.
    /// - Whether any inbound admission trust is installed: production starts
    ///   the backend CRL watcher before mesh installs its inbound slot, so a
    ///   publisher really can read "nothing installed" and be overtaken by the
    ///   install. Re-reading it under the lock is what makes the installer's
    ///   compile and this publication one order rather than two.
    /// - The records the anchors in force were compiled WITH: if the installer
    ///   (or the trust publisher) already compiled against exactly these
    ///   records, there is nothing to recompile and no revision to move, and
    ///   storing them is all that is left.
    fn publish_usable_inbound_admission_crls(&self, crls: CrlList) -> bool {
        let _publication = self.publication_lock();
        let slot = self.enforced_crl_slot();
        if crl_records_equal(slot.load().crls(), &crls) {
            return false;
        }
        let Some(trust) = self.inbound_trust.load_full() else {
            // No inbound admission trust is installed, so nothing has anchors
            // for these records to police and the credential gate's trust half
            // is inapplicable for every live tunnel. Publishing them for the
            // verifier is the whole job; the sweep still runs because the
            // policy gates are re-applied on every publication. Under the lock
            // this really does mean nothing is installed: an installer that
            // arrives next compiles against the records stored here.
            return publish_enforced_crl_set(slot, crls);
        };
        let in_force = trust.in_force.load_full();
        // Recompiled from the material already IN FORCE, not from the slot's
        // current bytes: a trust candidate the fence refused is in the slot but
        // is not what anything is judged against, and a CRL rotation must not
        // be the thing that quietly adopts it.
        let compiled = match in_force.material() {
            None => None,
            Some(_) if in_force.crls().is_some_and(|c| crl_records_equal(c, &crls)) => {
                // The anchors in force were ALREADY compiled with exactly these
                // records — an installer or a trust publisher that ran between
                // the outer check and this lock picked them up first. Storing
                // the records for the verifier is all that remains; recompiling
                // would rebuild identical anchors and advancing the revision
                // would charge every live tunnel a certificate path build for
                // nothing.
                None
            }
            Some(material) => match self.compile_in_force(Some(material), &crls) {
                Ok(compiled) => Some(compiled),
                Err(trust_domain_class) => {
                    self.warn_trust_not_in_force(trust_domain_class);
                    return false;
                }
            },
        };
        let changed = publish_enforced_crl_set(slot, crls);
        if let Some(compiled) = compiled
            && changed
        {
            // Only on a real change. `publish_enforced_crl_set` reporting
            // `false` here would mean the records were already enforced, and
            // advancing the revision for records nothing is newly policing is
            // exactly the wasted full-registry re-verification the skip key
            // exists to prevent.
            self.store_in_force(&trust, compiled);
        }
        changed
    }

    /// The enforced CRL slot inside the shared inbound admission artifact.
    fn enforced_crl_slot(&self) -> &crate::tls::crl_policy::SharedEnforcedCrlSet {
        self.mesh_inbound_admission.crls()
    }

    /// One sampled operator line for an enforced-CRL candidate that took no
    /// force, on the same window as [`Self::warn_trust_not_in_force`] and
    /// sharing its timestamp so a deployment failing both prints one line per
    /// window rather than two.
    fn warn_crls_not_in_force(&self, record_class: &'static str) {
        if !self.not_in_force_warning_due() {
            return;
        }
        warn!(
            record_class,
            "Mesh inbound CRL publication is not in force: a candidate record is not usable, so \
             the inbound mTLS verifier keeps enforcing the records already published and live \
             HBONE tunnels keep being judged against the trust revision still in force"
        );
    }

    /// The inbound admission trust IN FORCE, as ONE immutable cell.
    ///
    /// A single `ArcSwap` load: the revision and the anchors it names are
    /// published together and can never be torn apart. That is not an
    /// optimization — a new revision paired with old anchors would let a tunnel
    /// record a revision it was never judged against and skip the material that
    /// actually replaced it.
    pub(crate) fn inbound_trust_snapshot(&self) -> Option<InboundTrustSnapshot> {
        self.inbound_trust.load_full().map(|trust| trust.snapshot())
    }

    /// The trust revision the inbound admission slot currently has in force, or
    /// `None` when no slot is installed.
    ///
    /// The credential gate's skip key: it advances only when the published
    /// X.509 material actually changed AND compiled, so an operator (or a
    /// contract test) watching it sees exactly the publications that can cost
    /// certificate path building.
    pub fn inbound_trust_revision(&self) -> Option<u64> {
        self.inbound_trust
            .load_full()
            .map(|trust| trust.in_force.load().revision)
    }

    /// Apply `inspect` to every live tunnel's admission snapshot.
    ///
    /// The fence holds the only reachable handle to a relayed tunnel's
    /// snapshot — the relay task owns its `AdmittedHboneTunnel` and never
    /// publishes it — so this is how anything else observes what admission
    /// actually captured, including the admission-capture contract tests that
    /// prove [`HbonePeerCredential`] is built from the inbound verifier's own
    /// trust rather than from the request epoch.
    pub fn inspect_live_tunnels<T>(
        &self,
        inspect: impl Fn(&HboneAdmissionSnapshot) -> T,
    ) -> Vec<T> {
        // Upgraded and collected BEFORE any handle is released, exactly as
        // `sweep_once` does: `AdmittedHboneTunnelInner::drop` deregisters
        // through `tunnels.remove_if`, so letting the last strong reference
        // fall while a `DashMap` iterator still holds a shard would deadlock.
        let live: Vec<Arc<AdmittedHboneTunnelInner>> = self
            .tunnels
            .iter()
            .filter_map(|entry| entry.value().upgrade())
            .collect();
        live.iter()
            .filter(|inner| inner.state.load(Ordering::Acquire) == TUNNEL_LIVE)
            .map(|inner| inspect(&inner.snapshot))
            .collect()
    }

    /// Register an admitted tunnel. The returned handle keeps it sweepable
    /// until the relay retires or drops it.
    ///
    /// Publish-then-recheck closes the admission race. The request path spends
    /// the whole authenticate/authorize/`before_proxy` chain, the
    /// circuit-breaker check, the upgrade-handle extraction, and a full backend
    /// dial between reading the epoch and reaching this insert, and a
    /// publication landing inside that window schedules a sweep whose registry
    /// read — including the `tunnels.is_empty()` fast path — can complete
    /// BEFORE the insert. Such a tunnel would then be judged only by the
    /// superseded generation, and, because sweeps are exclusively
    /// publication-driven, would never be re-judged on a quiet mesh.
    ///
    /// The request path therefore captures [`Self::sweep_epoch`] BEFORE it
    /// reads the epoch and the PeerAuthentication policy the gates evaluate
    /// (both publishers bump the counter AFTER their store, so a gate that read
    /// stale state necessarily captured a stale counter too). If the counter
    /// has moved by the time the tunnel is registered, this schedules a fresh
    /// sweep that is guaranteed to see it. The insert and the
    /// sequentially-consistent load below are ordered against
    /// [`Self::request_sweep`]'s increment and its registry read, so at least
    /// one of the two sides observes the other.
    pub fn admit(self: &Arc<Self>, snapshot: HboneAdmissionSnapshot) -> AdmittedHboneTunnel {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let admission_sweep_epoch = snapshot.admission_sweep_epoch;
        let verified_trust_revision = snapshot
            .peer_credential
            .as_ref()
            .map_or(0, |credential| credential.admitted_trust_revision);
        let inner = Arc::new(AdmittedHboneTunnelInner {
            id,
            token: CancellationToken::new(),
            state: AtomicU8::new(TUNNEL_LIVE),
            verified_trust_revision: AtomicU64::new(verified_trust_revision),
            snapshot,
            fence: Arc::downgrade(self),
        });
        self.tunnels.insert(id, Arc::downgrade(&inner));
        let tunnel = AdmittedHboneTunnel { inner };
        if self.sweeps_requested.load(Ordering::SeqCst) != admission_sweep_epoch {
            self.request_sweep();
        }
        if let Some(deadline) = tunnel.credential_deadline() {
            self.arm_expiry_watcher(deadline);
        }
        tunnel
    }

    /// Make sure the bounded expiry watcher is running and will not sleep past
    /// `deadline` (issue #5568).
    ///
    /// Sweeps are otherwise exclusively publication-driven, so on a quiet mesh
    /// nothing would ever notice that an admitted SVID aged out. The watcher is
    /// the one timer this fence owns: at most one task, parked on an exact
    /// `sleep_until`, re-armed from the registry after every pass, and gone as
    /// soon as no live tunnel carries a finite deadline.
    ///
    /// The nudge is CONDITIONAL. Every admitted tunnel with a finite deadline
    /// reaches this, which is the ordinary case, and an unconditional
    /// `notify_one` woke the watcher into a full registry scan per CONNECT
    /// (upgrading every `Weak` and collecting them) to rediscover a deadline it
    /// was almost always already parked on. `fetch_min` publishes this
    /// tunnel's deadline and notifies only when it actually LOWERED the parked
    /// one — and the watcher resets the word to [`NO_DEADLINE`] before each
    /// re-scan, so a tunnel admitted while that scan runs still lowers it from
    /// `NO_DEADLINE` and still nudges. An equal deadline needs no nudge: the
    /// watcher already wakes at that exact instant and re-scans.
    fn arm_expiry_watcher(self: &Arc<Self>, deadline: tokio::time::Instant) {
        let deadline_nanos = self.monotonic_nanos(deadline);
        let previously_parked = self
            .expiry_parked_deadline
            .fetch_min(deadline_nanos, Ordering::SeqCst);
        if deadline_nanos < previously_parked {
            // `Notify::notify_one` stores a permit when there is no waiter, so
            // a nudge that races the watcher's own re-arm is not lost.
            self.expiry_wakeup.notify_one();
        }
        if self.expiry_watcher.load(Ordering::Acquire) {
            return;
        }
        // Resolved BEFORE the flag is claimed: swapping first and clearing on a
        // missing runtime leaves a window in which a concurrent runtime-bearing
        // caller sees the flag set, declines to spawn, and is then cleared —
        // no watcher at all until the next admit.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            warn!(
                live_tunnels = self.tunnels.len(),
                "HBONE admission fence expiry watcher could not start outside a tokio runtime; \
                 an admitted peer SVID that expires will not be revoked until the next publication"
            );
            return;
        };
        if self.expiry_watcher.swap(true, Ordering::AcqRel) {
            return;
        }
        let fence = Arc::clone(self);
        handle.spawn(async move {
            fence.run_expiry_watcher().await;
        });
    }

    /// `at` as nanoseconds since [`Self::clock_base`], saturating.
    ///
    /// An instant BEFORE the base clamps to `0`, which reads as "earlier than
    /// anything parked" and therefore over-notifies. That is the safe
    /// direction; the opposite would drop a wake-up. Production deadlines are
    /// always later than the base, which is captured when the fence is built.
    fn monotonic_nanos(&self, at: tokio::time::Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.clock_base).as_nanos())
            .unwrap_or(NO_DEADLINE - 1)
    }

    async fn run_expiry_watcher(self: Arc<Self>) {
        loop {
            // Reset BEFORE the scan. A tunnel admitted while the scan runs then
            // lowers the word from `NO_DEADLINE` and nudges, so its deadline
            // can never be lost to a scan that did not see its insert.
            self.expiry_parked_deadline
                .store(NO_DEADLINE, Ordering::SeqCst);
            let Some(deadline) = self.earliest_live_credential_deadline() else {
                // Clear the flag, then re-read the registry: a tunnel admitted
                // between the scan above and this store would otherwise find
                // the flag still set, skip arming, and never be watched.
                self.expiry_watcher.store(false, Ordering::Release);
                if self.earliest_live_credential_deadline().is_some()
                    && !self.expiry_watcher.swap(true, Ordering::AcqRel)
                {
                    continue;
                }
                return;
            };
            let deadline_nanos = self.monotonic_nanos(deadline);
            self.expiry_parked_deadline
                .fetch_min(deadline_nanos, Ordering::SeqCst);
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    // Await the sweep rather than firing and forgetting: the
                    // re-arm below reads the registry, and a tunnel this pass
                    // has not yet claimed would still publish the deadline that
                    // just fired, spinning the watcher until the relay caught
                    // up.
                    self.sweep_and_settle().await;
                }
                _ = self.expiry_wakeup.notified() => {}
            }
        }
    }

    /// The earliest credential deadline across tunnels that are still LIVE.
    ///
    /// A revoked or retired tunnel is excluded so an elapsed deadline stops
    /// being re-armed the moment a sweep claims it, without waiting for the
    /// relay to deregister.
    fn earliest_live_credential_deadline(&self) -> Option<tokio::time::Instant> {
        // Collected BEFORE any handle is released, exactly as `sweep_once`
        // does: `AdmittedHboneTunnelInner::drop` deregisters through
        // `tunnels.remove_if`, so letting the last strong reference fall while
        // a `DashMap` iterator still holds a shard would deadlock the fence.
        let live: Vec<Arc<AdmittedHboneTunnelInner>> = self
            .tunnels
            .iter()
            .filter_map(|entry| entry.value().upgrade())
            .collect();
        live.into_iter()
            .filter(|inner| inner.state.load(Ordering::Acquire) == TUNNEL_LIVE)
            .filter_map(
                |inner| match inner.snapshot.peer_credential.as_ref()?.leaf_expiry {
                    AdmittedLeafExpiry::At(deadline) => Some(deadline),
                    AdmittedLeafExpiry::Unbounded | AdmittedLeafExpiry::Unparseable => None,
                },
            )
            .min()
    }

    /// Run ONE fresh pass and await it. Only the expiry watcher uses it; every
    /// publication path stays fire-and-forget through [`Self::request_sweep`].
    ///
    /// Deliberately not `request_sweep` + await. Coalescing would let this fold
    /// into a pass that had already read the clock BEFORE the deadline fired,
    /// which leaves the expired tunnel live and the watcher re-arming on the
    /// same elapsed deadline — a spin, not a revocation. Taking the serial lock
    /// and sweeping directly guarantees a pass whose `Instant::now()` is after
    /// the wake.
    ///
    /// The completed counter still advances only to the request count read
    /// BEFORE the pass, exactly as [`Self::run_pending_sweeps`] does, so a
    /// publication that lands mid-pass is not falsely reported as swept.
    async fn sweep_and_settle(&self) {
        let _serial = self.sweep_serial.lock().await;
        let requested = self.sweeps_requested.load(Ordering::Acquire);
        self.sweep_once().await;
        self.sweeps_completed.fetch_max(requested, Ordering::AcqRel);
    }

    /// The sweep-request counter as of this call.
    ///
    /// The HBONE request path captures it before loading the request epoch it
    /// admits against and carries it in
    /// [`HboneAdmissionSnapshot::admission_sweep_epoch`]; [`Self::admit`]
    /// compares it against the live counter to detect a publication that raced
    /// the admission. Two relaxed-cost atomic loads per CONNECT, nothing on the
    /// byte-relay path.
    pub fn sweep_epoch(&self) -> u64 {
        self.sweeps_requested.load(Ordering::SeqCst)
    }

    /// Number of tunnels currently registered.
    pub fn live_tunnels(&self) -> usize {
        self.tunnels.len()
    }

    /// Revocations recorded for `reason` since process start.
    ///
    /// A revoked tunnel is counted here BEFORE its cancellation token fires, so
    /// anything woken by that cancellation — the relay, an operator poll, a
    /// test — already observes the increment.
    pub fn revocations(&self, reason: HboneRevocationReason) -> u64 {
        self.revocations[reason.index()].load(Ordering::Acquire)
    }

    /// Live-tunnel authorize-chain re-evaluations performed by sweeps.
    pub fn reevaluations(&self) -> u64 {
        self.reevaluations.load(Ordering::Relaxed)
    }

    /// Certificate path builds a SWEEP's credential gate performed (issue
    /// #5568).
    ///
    /// The observable form of "no path building on an ordinary publication": a
    /// sweep triggered by a republish that changed no X.509 trust material, and
    /// every sweep after the one that verified a tunnel against the current
    /// revision, must leave this unchanged. CONNECT-time verification is
    /// deliberately not counted here — see [`Self::connect_trust_refusals`].
    pub fn trust_rechecks(&self) -> u64 {
        self.trust_rechecks.load(Ordering::Relaxed)
    }

    /// CONNECTs refused because the peer's chain no longer anchors in the
    /// inbound admission trust in force (issue #5568 review).
    ///
    /// A revoked tunnel's peer retries on the SAME pooled inbound mTLS session,
    /// which is never re-handshaked, so this is what stops the replacement
    /// CONNECT from being admitted under trust that would refuse its chain.
    pub fn connect_trust_refusals(&self) -> u64 {
        self.connect_trust_refusals.load(Ordering::Relaxed)
    }

    /// Times the inbound admission trust's anchors were compiled.
    ///
    /// Once per in-force revision. A burst of CONNECTs, or a sweep over
    /// thousands of live tunnels, must leave this unchanged: both read the
    /// cached verifiers that publication built.
    pub fn trust_anchor_builds(&self) -> u64 {
        self.trust_anchor_builds.load(Ordering::Relaxed)
    }

    /// Sweeps that have run to completion.
    pub fn sweeps_completed(&self) -> u64 {
        self.sweeps_completed.load(Ordering::Acquire)
    }

    /// Schedule a sweep against the current request epoch and inbound
    /// PeerAuthentication policy. Returns immediately; the sweep runs on the
    /// ambient tokio runtime.
    ///
    /// Outside a runtime the request cannot be scheduled at all, so it is
    /// dropped with a `warn!` naming the live-tunnel count it could not
    /// re-judge — the one place this fence can silently stop being a fence.
    /// Every production publication path (`ProxyState::update_config` /
    /// `update_mesh_config` / the incremental applies,
    /// `apply_mesh_inbound_tls_reload`, and the TLS material reload tasks that
    /// call `publish_mesh_inbound_crls`) runs inside the runtime,
    /// `spawn_blocking` workers carry a runtime context, and startup
    /// publication precedes every live tunnel.
    pub fn request_sweep(self: &Arc<Self>) {
        // Sequentially consistent: `admit` inserts into the registry and then
        // loads this counter, while this increments the counter and then reads
        // the registry. One of the two must observe the other, or an admission
        // racing this publication would escape the fence entirely.
        self.sweeps_requested.fetch_add(1, Ordering::SeqCst);
        if self.tunnels.is_empty() {
            // Nothing to fence; account the sweep as complete so waiters see a
            // settled state without spawning.
            let requested = self.sweeps_requested.load(Ordering::Acquire);
            self.sweeps_completed.fetch_max(requested, Ordering::AcqRel);
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            warn!(
                requested = self.sweeps_requested.load(Ordering::Acquire),
                completed = self.sweeps_completed.load(Ordering::Acquire),
                live_tunnels = self.tunnels.len(),
                "HBONE admission fence sweep requested outside a tokio runtime; live tunnels \
                 will not be re-judged until the next in-runtime publication"
            );
            return;
        };
        let fence = Arc::clone(self);
        handle.spawn(async move {
            fence.run_pending_sweeps().await;
        });
    }

    async fn run_pending_sweeps(self: Arc<Self>) {
        let _serial = self.sweep_serial.lock().await;
        loop {
            let requested = self.sweeps_requested.load(Ordering::Acquire);
            if self.sweeps_completed.load(Ordering::Acquire) >= requested {
                return;
            }
            self.sweep_once().await;
            self.sweeps_completed.fetch_max(requested, Ordering::AcqRel);
        }
    }

    async fn sweep_once(&self) {
        let epoch = self.request_epoch.load();
        let policy = self.mesh_inbound_tls_policy.load_full();
        // One immutable cell: the anchors were compiled when this revision was
        // published, so a sweep over thousands of tunnels builds no verifier at
        // all and a tunnel whose last-verified revision already matches does no
        // path building either.
        let trust = self.inbound_trust_snapshot();
        let live: Vec<AdmittedHboneTunnel> = self
            .tunnels
            .iter()
            .filter_map(|entry| entry.value().upgrade())
            .map(|inner| AdmittedHboneTunnel { inner })
            .collect();
        let mut revoked = 0usize;
        for tunnel in live {
            // Cheap pre-filter only: a tunnel that retires or is claimed after
            // this load is refused by `claim_revocation`'s compare-exchange
            // against the same word, so nothing depends on the check being
            // current.
            if tunnel.inner.state.load(Ordering::Acquire) != TUNNEL_LIVE {
                continue;
            }
            // One authorize plugin that unwinds must not take the rest of the
            // sweep — and every later publication — with it: the task would die
            // before `sweeps_completed` advanced, leaving every tunnel after it
            // in iteration order permanently un-swept while the log showed only
            // a task panic. Fail closed on the tunnel whose verdict is missing.
            // The shipped `release` profile is `panic = "abort"`, so this is the
            // dev/test-profile net; under `abort` the process is gone and no
            // tunnel is left silently unfenced either way.
            let reevaluate = self.reevaluate(&tunnel.inner, &epoch, &policy, trust.as_ref());
            let outcome = std::panic::AssertUnwindSafe(reevaluate)
                .catch_unwind()
                .await;
            let reason = match outcome {
                Ok(reason) => reason,
                Err(_) => {
                    error!(
                        proxy_id = %tunnel.inner.snapshot.proxy.id,
                        config_generation = epoch.config_generation(),
                        "HBONE admission fence re-evaluation panicked; revoking the tunnel it \
                         could not judge"
                    );
                    Some(HboneRevocationReason::ReevaluationFailed)
                }
            };
            let Some(reason) = reason else {
                continue;
            };
            if tunnel.claim_revocation(reason) {
                revoked += 1;
                // Account BEFORE the cancellation edge is published: the relay
                // and every `revocations()` reader wake on that edge, so a
                // counter incremented afterwards is observably missing exactly
                // when someone looks. `Release` pairs with the `Acquire` load in
                // `revocations()` through the cancellation's own ordering.
                self.revocations[reason.index()].fetch_add(1, Ordering::Release);
                crate::plugins::prometheus_metrics::global_registry()
                    .record_hbone_tunnel_revocation(&tunnel.inner.snapshot.proxy.id, reason);
                // Per-TUNNEL record at `debug`: a namespace-wide DENY across a
                // few thousand live tunnels emits one of these each, which is
                // drill-down, not an operator event. The per-SWEEP `info!`
                // summary below is the operator line.
                debug!(
                    proxy_id = %tunnel.inner.snapshot.proxy.id,
                    reason = reason.as_str(),
                    config_generation = epoch.config_generation(),
                    "Revoked a live HBONE tunnel: its CONNECT would no longer be admitted \
                     under the current policy generation"
                );
                tunnel.publish_revocation();
            }
        }
        if revoked > 0 {
            info!(
                revoked,
                config_generation = epoch.config_generation(),
                "HBONE admission fence sweep revoked live tunnels"
            );
        } else {
            debug!(
                config_generation = epoch.config_generation(),
                "HBONE admission fence sweep left every live tunnel admitted"
            );
        }
    }

    /// Re-apply the CONNECT admission gates to one snapshot. `Some(reason)`
    /// means the tunnel must be revoked.
    ///
    /// Gate order is the CONNECT path's order, because the `reason` label on
    /// `ferrum_mesh_hbone_tunnel_revocations_total` and the sweep's log line
    /// are an operator's only attribution: a tunnel that fails two gates must
    /// be attributed the one the peer's next CONNECT would actually be refused
    /// with, or the rollout dashboard and the client-visible failure disagree.
    /// The peer's credential is decided by the mTLS handshake and
    /// `spiffe_identity` before any request exists, so the credential gate
    /// precedes the policy gates. The request path then authorizes in
    /// `handle_proxy_request_inner` BEFORE it branches into
    /// `handle_hbone_request`, which re-verifies that credential and then
    /// checks the PeerAuthentication transport mode and the relay-destination
    /// ownership guard — so the order here is credential, authorize, transport,
    /// destination. One asymmetry is deliberate: because the authorize chain
    /// runs before the HBONE handler, a peer failing BOTH its credential and
    /// its policy is refused `authorization_denied` on the wire while a sweep
    /// attributes `peer_trust`. The credential is the narrower, peer-specific
    /// fact and the one an operator acts on, so the sweep keeps it first rather
    /// than relabelling every existing diagnostic. The proxy
    /// lifecycle check below is not one of those gates: a withdrawn proxy is
    /// never routed to at all, so it necessarily precedes every one of them.
    ///
    /// One check follows all four and is not a CONNECT gate either: INNER REUSE
    /// eligibility (issue #5583). A tunnel admitted with the capability
    /// advertised is carrying operations its source is not re-CONNECTing for,
    /// so a chain that stops permitting reuse has to reach it — but that
    /// tunnel's CONNECT would still be ADMITTED, so every gate above outranks
    /// it and it is judged last.
    async fn reevaluate(
        &self,
        tunnel: &AdmittedHboneTunnelInner,
        epoch: &RequestEpoch,
        policy: &MeshInboundTlsPolicy,
        trust: Option<&InboundTrustSnapshot>,
    ) -> Option<HboneRevocationReason> {
        let snapshot = &tunnel.snapshot;
        let proxy = &snapshot.proxy;
        // A configured proxy must still be published under the same lifecycle
        // incarnation. Synthesized relay proxies are never in `config.proxies`;
        // their ownership guard below is the presence check.
        if let Some(admitted_generation) = snapshot.proxy_lifecycle_generation
            && epoch
                .plugin_cache
                .proxy_lifecycle_generation(&proxy.namespace, &proxy.id)
                != Some(admitted_generation)
        {
            return Some(HboneRevocationReason::ProxyWithdrawn);
        }

        if let Some(reason) = self.peer_credential_revocation(tunnel, trust) {
            return Some(reason);
        }

        // Resolved ONCE, from the generation now current, and shared by the two
        // gates below that need it. `authorize_chain_denies` resolved it
        // unconditionally before the reuse gate existed — including for the
        // chains it then finds nothing to re-run in — so hoisting it costs
        // nothing and keeps the reuse fold from resolving a second copy.
        let view = admitting_request_view(snapshot, epoch);

        // The request path refuses a view that omits the route's admission
        // policy before any plugin runs, ahead of the authorize chain. A reload
        // that adds an HTTP-only admission plugin to this route therefore
        // refuses the peer's next CONNECT on a gRPC-classified view, so the
        // live tunnel must not outlive it. A capability bit read; no hook runs.
        if view
            .capabilities()
            .has(crate::plugin_cache::PluginCapabilities::OMITS_ROUTE_ADMISSION_POLICY)
        {
            return Some(HboneRevocationReason::AuthorizationDenied);
        }

        if self.authorize_chain_denies(snapshot, &view).await {
            return Some(HboneRevocationReason::AuthorizationDenied);
        }

        if mesh_inbound_peer_auth_transport_mismatch_for_policy(
            policy,
            snapshot.ctx.mesh_direction,
            snapshot.mesh_inbound_pre_handshake_app_port,
            proxy,
            snapshot.upstream_target.as_deref(),
            snapshot.is_tls,
            snapshot.has_verified_peer_certificate,
        )
        .is_some()
        {
            return Some(HboneRevocationReason::PeerAuthTransport);
        }

        let mesh = epoch.config.mesh.as_deref();
        let destination_owned = match snapshot.destination_gate {
            HboneRelayDestinationGate::InboundRelay => {
                let authority_owned = inbound_hbone_relay_effective_destination_decision(
                    proxy,
                    snapshot.upstream_target.as_deref(),
                    mesh,
                    snapshot.ctx.mesh_inbound_terminator_ip,
                )
                .is_ok();
                authority_owned && inbound_relay_resolved_ip_admitted(mesh, snapshot.resolved_ip)
            }
            HboneRelayDestinationGate::IngressRelay => {
                inbound_ingress_relay_effective_destination_allowed(
                    proxy,
                    snapshot.upstream_target.as_deref(),
                    mesh,
                    snapshot.ctx.mesh_inbound_listener_authz_port,
                )
            }
            HboneRelayDestinationGate::Datagram => {
                let (app_host, app_port) = snapshot
                    .upstream_target
                    .as_deref()
                    .map(|target| (target.host.as_str(), target.port))
                    .unwrap_or((proxy.backend_host.as_str(), proxy.backend_port));
                inbound_hbone_relay_destination_decision(
                    app_host,
                    app_port,
                    mesh,
                    snapshot.ctx.mesh_inbound_terminator_ip,
                )
                .is_ok()
                    || mesh_egress_udp_destination_allowed(app_host, app_port, mesh)
            }
            HboneRelayDestinationGate::Configured => {
                // A configured route has no ownership guard, but a reload can
                // make it an HTTP route on the Sidecar inbound listener, where
                // the peer's next bare CONNECT would be refused (issue #6110).
                let direction = snapshot.ctx.mesh_direction;
                !sidecar_inbound_refuses_matched_http_connect(proxy, direction, mesh)
            }
        };
        if !destination_owned {
            return Some(HboneRevocationReason::RelayDestination);
        }

        // LAST of the gates, because it is the only one whose tunnel would
        // still be ADMITTED: a tunnel that also fails one of the gates above
        // must carry that gate's reason, which is the one its peer's next
        // CONNECT would actually be refused with.
        //
        // The CONNECT admission decision is re-issued for a reusable tunnel's
        // whole life by the sweep and the credential gate; what is NOT
        // re-issued is anything a plugin decides per OPERATION, and reuse means
        // the source stops making the CONNECTs that would carry those
        // decisions. So the eligibility itself is re-judged here, for every
        // tunnel that was admitted with the capability advertised. Revoking is
        // the restoration: the source's next operation performs a fresh CONNECT
        // under the new chain, which is exactly the per-operation admission the
        // new chain asked for.
        //
        // A pure boolean fold over the CURRENT chain, and nothing else. It must
        // never run `authorize`, `on_request_received`, or any other hook — a
        // sweep provokes no request, so charging a token, taking a permit, or
        // issuing an external check here would do to every live tunnel exactly
        // what `Plugin::reevaluates_live_admission` exists to prevent.
        //
        // It is also the SAME function the CONNECT path folded, using the
        // recorded listener facts with the current chain, so "still reusable"
        // here means exactly what "reusable" meant there.
        if snapshot.advertised_inner_reuse {
            let current_chain = view.plugins();
            if !admitting_chain_allows_inner_reuse(&current_chain, &snapshot.reuse_context) {
                return Some(HboneRevocationReason::ReuseWithdrawn);
            }
        }

        None
    }

    /// Re-run the re-evaluation-safe part of the admitting authorize chain
    /// against `view`, the admitting view re-resolved from the generation this
    /// sweep is judging (see [`admitting_request_view`]). `true` denies, which
    /// the caller turns into [`HboneRevocationReason::AuthorizationDenied`].
    async fn authorize_chain_denies(
        &self,
        snapshot: &HboneAdmissionSnapshot,
        view: &PluginCacheRequestView,
    ) -> bool {
        let proxy = &snapshot.proxy;
        // Only plugins whose `authorize` is free of side effects and external
        // I/O are re-run (`Plugin::reevaluates_live_admission`). A sweep that
        // consumed a rate-limit token or issued one ext_authz/OPA call per live
        // tunnel would revoke healthy, policy-compliant tunnels and drain a real
        // client's budget — a worse outcome than the stale admission this fence
        // exists to close.
        let authorize = view.authorize_plugins();
        let reevaluated: Vec<&Arc<dyn Plugin>> = authorize
            .iter()
            .filter(|plugin| plugin.reevaluates_live_admission())
            .collect();
        if reevaluated.is_empty() {
            return false;
        }
        self.reevaluations.fetch_add(1, Ordering::Relaxed);
        let mut ctx = snapshot.ctx.clone();
        ctx.metadata.insert(
            MESH_AUTHZ_REEVALUATION_METADATA_KEY.to_string(),
            "true".to_string(),
        );
        for plugin in reevaluated {
            match plugin.authorize(&mut ctx).await {
                PluginResult::Continue => {}
                PluginResult::Reject { .. } | PluginResult::RejectBinary { .. } => {
                    debug!(
                        proxy_id = %proxy.id,
                        plugin = plugin.name(),
                        deny_policy = ctx
                            .metadata
                            .get("mesh_authz.deny_policy")
                            .map(String::as_str)
                            .unwrap_or("<unset>"),
                        "Authorize chain denies a live HBONE tunnel's CONNECT under the current \
                         generation"
                    );
                    return true;
                }
            }
        }
        false
    }
}

/// Re-resolve, from the generation a sweep is judging, the SAME plugin view the
/// request path resolved when it admitted this tunnel.
///
/// The admitting view is protocol-scoped and the selector is peer-influenced:
/// an HBONE CONNECT carrying `content-type: application/grpc` classifies as
/// gRPC, and a gRPC-Web request resolves an entirely separate view. The
/// snapshot records which one `plugin_cache_view` picked, so the sweep must
/// replay that selector rather than assume plain HTTP. Only the GENERATION
/// differs between this and the admitting resolution: the view key is
/// `namespace|id`, which a route override never moves.
///
/// Both sweep gates that need plugins read this one resolution.
/// [`PluginCacheRequestView::plugins`] is the same slice
/// `handle_proxy_request_inner` binds as `plugins` and hands to
/// `handle_hbone_request`, which is what makes the reuse fold here comparable
/// with the fold the CONNECT path performed.
fn admitting_request_view(
    snapshot: &HboneAdmissionSnapshot,
    epoch: &RequestEpoch,
) -> PluginCacheRequestView {
    let proxy = &snapshot.proxy;
    if snapshot.grpc_web_request {
        epoch
            .plugin_cache
            .grpc_web_request_view(&proxy.namespace, &proxy.id)
    } else {
        epoch
            .plugin_cache
            .request_view(&proxy.namespace, &proxy.id, snapshot.request_protocol)
    }
}

/// The inbound mTLS admission trust: the very `tls::SharedBundleSlot` the mesh
/// SPIFFE client-certificate verifier reads on every handshake, plus the ONE
/// cell naming the trust that is currently IN FORCE (issue #5568).
///
/// This is the fence's trust input, and it has to be — the fence's contract is
/// "a tunnel that would no longer be admitted is revoked, and a CONNECT that
/// would no longer be admitted is refused", which is defined relative to what
/// the peer's NEXT handshake would apply, not to what the request epoch happens
/// to carry. See the module header for the two concrete failures that follow
/// from reading the epoch instead.
pub struct MeshInboundAdmissionTrust {
    slot: crate::tls::SharedBundleSlot,
    /// The revision, the material it names, and the anchors compiled from that
    /// material — published together as one immutable cell so nothing can read
    /// a revision beside anchors it does not name.
    in_force: ArcSwap<InForceInboundTrust>,
}

/// One generation of inbound admission trust.
struct InForceInboundTrust {
    /// Always a value drawn from the fence's own `trust_revision_seq`, never a
    /// per-slot counter. Drawing from ONE strictly increasing sequence is what
    /// lets the credential gate compare for plain INEQUALITY: a per-slot counter
    /// would restart at the same low values if the fence were ever rebound to a
    /// second slot, and a tunnel whose last-verified revision happened to match
    /// one of them would then skip re-verification against entirely different
    /// material.
    revision: u64,
    /// `None` while nothing is in force: no bundle has been published yet, or
    /// every candidate so far failed to compile as one atomic set. The inbound
    /// SPIFFE verifier is in exactly that state too (it has no last-known-good
    /// cache to fall back on), so the trust half of the credential gate stays
    /// inapplicable rather than refusing peers the fence never saw admitted.
    compiled: Option<CompiledInboundTrust>,
}

impl InForceInboundTrust {
    /// The X.509 material this revision names, or `None` while nothing is in
    /// force.
    fn material(&self) -> Option<&crate::identity::TrustBundleSet> {
        self.compiled.as_ref().map(|compiled| &compiled.material)
    }

    /// The enforced CRL records this revision's anchors were compiled with, or
    /// `None` while nothing is in force (issue #5574).
    fn crls(&self) -> Option<&CrlList> {
        self.compiled.as_ref().map(|compiled| &compiled.crls)
    }
}

/// The material one in-force revision names, and the verifiers compiled from it.
struct CompiledInboundTrust {
    /// The X.509 trust material `anchors` were compiled from, kept as the
    /// comparison baseline for the next publication. Cloned out of the published
    /// bundle rather than retaining it, so the in-force cell never holds a
    /// rotated SVID's leaf or private key alive.
    material: crate::identity::TrustBundleSet,
    /// The enforced CRL records `anchors` were compiled WITH (issue #5574),
    /// kept as the other half of that comparison baseline. One `Arc` clone of
    /// the records the verifier's slot holds, never a copy of the DER.
    crls: CrlList,
    /// Compiled ONCE, here, at publication — never per sweep and never per
    /// CONNECT. Shared by `Arc` with the inbound admission artifact the
    /// handshake verifier reads, so "in force" is literally the same object on
    /// both surfaces rather than two compiles of the same inputs.
    anchors: Arc<AdmittedPeerTrustAnchors>,
}

impl MeshInboundAdmissionTrust {
    fn wrap(slot: crate::tls::SharedBundleSlot, in_force: InForceInboundTrust) -> Self {
        Self {
            slot,
            in_force: ArcSwap::from_pointee(in_force),
        }
    }

    fn snapshot(&self) -> InboundTrustSnapshot {
        InboundTrustSnapshot(self.in_force.load_full())
    }

    /// Whether this binding currently has compiled anchors in force.
    ///
    /// The rebind guard's question: with anchors in force, the shared artifact
    /// the handshake reads is non-empty and every live tunnel is being judged
    /// against them, so a replacement that compiles nothing must be refused
    /// rather than allowed to strand both surfaces.
    fn has_anchors_in_force(&self) -> bool {
        self.in_force.load().compiled.is_some()
    }
}

/// One coherent read of [`MeshInboundAdmissionTrust`]: a single `ArcSwap` load
/// of an immutable cell, so the revision and the anchors it names are always
/// the same generation.
pub(crate) struct InboundTrustSnapshot(Arc<InForceInboundTrust>);

impl InboundTrustSnapshot {
    /// The revision currently in force. `0` is never one of them — it is
    /// reserved for "no inbound admission trust installed".
    fn revision(&self) -> u64 {
        self.0.revision
    }

    /// The anchors in force, or `None` when nothing is (see
    /// [`InForceInboundTrust::compiled`]).
    fn anchors(&self) -> Option<&AdmittedPeerTrustAnchors> {
        self.0
            .compiled
            .as_ref()
            .map(|compiled| compiled.anchors.as_ref())
    }
}

/// Whether two published sets carry the same X.509 trust material.
///
/// Only the X.509 authorities and the trust domains that declare them matter:
/// they are the entire input to [`AdmittedPeerTrustAnchors::compile`]. The
/// SVID's own leaf, key and JWT authorities are deliberately excluded —
/// rotating them changes nothing a peer chain anchors in, and treating a leaf
/// rotation as a trust change would make every live tunnel rebuild its
/// certificate path on every SVID refresh.
fn trust_material_eq(
    current: Option<&crate::identity::TrustBundleSet>,
    next: Option<&crate::identity::TrustBundleSet>,
) -> bool {
    match (current, next) {
        (None, None) => true,
        (Some(current), Some(next)) => trust_bundle_set_eq(current, next),
        _ => false,
    }
}

fn trust_bundle_set_eq(
    current: &crate::identity::TrustBundleSet,
    next: &crate::identity::TrustBundleSet,
) -> bool {
    if !trust_bundle_eq(&current.local, &next.local) {
        return false;
    }
    if current.federated.len() != next.federated.len() {
        return false;
    }
    for (trust_domain, bundle) in &current.federated {
        let Some(other) = next.federated.get(trust_domain) else {
            return false;
        };
        if !trust_bundle_eq(bundle, other) {
            return false;
        }
    }
    true
}

fn trust_bundle_eq(
    current: &crate::identity::TrustBundle,
    next: &crate::identity::TrustBundle,
) -> bool {
    current.trust_domain == next.trust_domain && current.x509_authorities == next.x509_authorities
}

impl HboneAdmissionFence {
    /// Re-decide the credential half of admission for one live tunnel (issue
    /// #5568).
    ///
    /// Order inside the gate is expiry, then fence-failure, then trust, and it
    /// is load-bearing: the chain re-verification validates at the current
    /// instant, so an aged-out leaf would fail it as an anchoring failure and
    /// be reported as `peer_trust`. The narrower, peer-specific fact has to
    /// win, or an operator watching a CA rotation sees expiries filed under
    /// trust withdrawal.
    fn peer_credential_revocation(
        &self,
        tunnel: &AdmittedHboneTunnelInner,
        trust: Option<&InboundTrustSnapshot>,
    ) -> Option<HboneRevocationReason> {
        let credential = tunnel.snapshot.peer_credential.as_ref()?;

        match credential.leaf_expiry {
            AdmittedLeafExpiry::At(not_after) if tokio::time::Instant::now() >= not_after => {
                return Some(HboneRevocationReason::PeerExpired);
            }
            // The retained leaf is not parseable, so this fence cannot bound
            // the credential at all. Unreachable while
            // `has_certificate_spiffe_principal()` is set only by an admission
            // that already parsed the same DER — but if that ever decouples,
            // the operator must be pointed at a fence failure, not at SVID
            // lifetimes.
            AdmittedLeafExpiry::Unparseable => {
                return Some(HboneRevocationReason::ReevaluationFailed);
            }
            AdmittedLeafExpiry::At(_) | AdmittedLeafExpiry::Unbounded => {}
        }

        // A tunnel whose CONNECT verified nothing — a chain-only inbound
        // posture with no gateway SVID material, or a slot with nothing yet in
        // force — has no trust state to regress from, so this gate can only
        // produce false positives for it. Every other tunnel WAS positively
        // verified at its CONNECT, which is what makes the comparison below a
        // regression check rather than a guess.
        if !credential.anchored_at_admission {
            return None;
        }
        let Some(published) = trust else {
            // The slot that anchored this tunnel is no longer bound to the
            // fence. Nothing published can be compared against what admitted
            // it, so there is no regression to observe.
            return None;
        };
        // Unchanged revision ⇒ unchanged trust material AND unchanged enforced
        // records: skip the path building entirely. ONE revision covers both
        // (issue #5574), because both are inputs to the same compiled anchors
        // and both publishers advance the same sequence — a second generation
        // beside it could only disagree with it. Compared against what this
        // tunnel last VERIFIED, not against what admitted it, so a tunnel that
        // survives one publication does not re-verify on every later sweep.
        if tunnel.verified_trust_revision.load(Ordering::Acquire) == published.revision() {
            return None;
        }
        let Some(anchors) = published.anchors() else {
            // Nothing is in force, while this tunnel was verified against
            // material that anchored it. Only a rebind to a different slot
            // reaches this (a publication that does not compile leaves the
            // previous revision in force rather than emptying it), and a
            // different slot means a different verifier — a definite answer,
            // nothing is trusted, rather than an inability to judge.
            return Some(HboneRevocationReason::PeerTrust);
        };
        let intermediates: &[Vec<u8>] = credential
            .intermediates_der
            .as_ref()
            .map_or(&[], |chain| chain.as_slice());
        self.trust_rechecks.fetch_add(1, Ordering::Relaxed);
        match anchors.recheck(
            credential.spiffe_id.trust_domain(),
            &credential.leaf_der,
            intermediates,
        ) {
            AdmittedPeerTrustVerdict::Trusted => {
                // Record what was verified, so this tunnel pays for path
                // building once per trust change rather than once per sweep for
                // the rest of its life.
                tunnel
                    .verified_trust_revision
                    .store(published.revision(), Ordering::Release);
                None
            }
            AdmittedPeerTrustVerdict::Withdrawn => Some(HboneRevocationReason::PeerTrust),
            // The chain anchors, but the enforced records revoke a certificate
            // on it (issue #5574). A distinct reason because a revoked workload
            // credential and a retired CA are different operator events, and
            // because it is the reason the peer's next handshake — and its next
            // CONNECT through the gate above — would produce.
            AdmittedPeerTrustVerdict::Revoked => Some(HboneRevocationReason::PeerRevoked),
            // Nothing was retained to verify, or the authoritative CRL has
            // itself aged out. Fail closed exactly like an authorize plugin that
            // unwound: a tunnel whose credential cannot be judged is cut, not
            // left serving.
            AdmittedPeerTrustVerdict::Unverifiable => {
                Some(HboneRevocationReason::ReevaluationFailed)
            }
        }
    }
}

/// Re-apply `connect_backend`'s post-DNS loopback screen
/// (`screen_ordinary_inbound_hbone_relay_dns_candidates`) to the address the
/// ordinary inbound relay actually dialled.
///
/// Authority matching admits a declared hostname WITHOUT resolving it, so the
/// authority decision alone cannot see a live tunnel pinned to `127.0.0.0/8`,
/// `::1`, or mapped IPv4 loopback. A slice change that withdraws the Sidecar
/// own-namespace privilege (Sidecar → Ambient/waypoint posture on the same
/// host/port) must cut that tunnel, exactly as it would refuse a fresh CONNECT.
/// `None` means nothing was resolved, so there is no screen to re-apply; a
/// missing mesh snapshot is already refused by the authority decision.
fn inbound_relay_resolved_ip_admitted(
    mesh: Option<&crate::modes::mesh::config::MeshConfig>,
    resolved_ip: Option<IpAddr>,
) -> bool {
    let (Some(mesh), Some(ip)) = (mesh, resolved_ip) else {
        return true;
    };
    mesh.screen_inbound_relay_resolved_ips([ip]).is_ok()
}
