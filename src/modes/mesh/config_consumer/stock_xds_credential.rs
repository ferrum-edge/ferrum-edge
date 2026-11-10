//! Finite authorization lifetime for the stock xDS bearer credential
//! (issue #3852).
//!
//! `FERRUM_MESH_STOCK_XDS_TOKEN_FILE` names an **externally issued** bearer —
//! typically a projected Kubernetes service-account token. Before this module
//! the client read it once per connection attempt, captured it in the tonic
//! interceptor, and then let the stream live for as long as the third-party
//! control plane was willing to hold it open. A stock ADS server that validates
//! only at RPC admission would therefore keep pushing discovery over a session
//! opened with a credential that had since expired or been revoked, and the
//! effective access lifetime became the lifetime of the TCP/H2 stream rather
//! than the token's TTL.
//!
//! The fix has three parts, all of them here:
//!
//! 1. **Change detection.** A watcher re-reads the configured source on a
//!    bounded cadence through the *same* hardened credential reader the connect
//!    path uses (`secrets::credential_file`): `O_NONBLOCK` open, regular-file
//!    check on the **opened** descriptor (so a projected-secret symlink swap
//!    resolves while a FIFO/socket/device is refused), a metadata fast-reject
//!    plus `take(limit + 1)` ceiling, UTF-8 validation, and an empty-after-trim
//!    rejection — all on a detached OS thread, never on a Tokio core worker.
//!    Both symlink swaps and in-place rewrites are detected because the
//!    comparison is over **content**, not inode identity.
//! 2. **A local authorization deadline.** A JWT-shaped token contributes its
//!    `exp` as a *reconnect scheduling hint only*, after a bounded, non-verifying
//!    local decode. It is never treated as proof of anything — but it is also
//!    never allowed to schedule *past* `exp`. RFC 7519 NumericDate may be a
//!    non-integer JSON number; a present numeric `exp` is floored to whole
//!    seconds so the deadline cannot fall after the mathematical expiration.
//!    A token that is already expired — including a syntactically valid
//!    NumericDate of zero, a negative value, or a fractional value that floors
//!    to Unix epoch zero or earlier (those are plainly expired, not "no
//!    hint") — or whose remaining lifetime cannot leave a positive window once
//!    the configured skew is subtracted, is **refused**: it becomes an invalid
//!    credential source rather than being clamped up to some floor. An opaque
//!    token gets the operator-visible maximum stream lifetime, which also caps
//!    any JWT-derived deadline.
//!
//!    The deadline is ABSOLUTE and is stamped at **admission**, not at stream
//!    open. Materialization happens before the channel is dialed, so deriving
//!    the deadline from stream-open time would silently extend a JWT past `exp`
//!    by however long connect and RPC setup took. [`StockBearerCredential`]
//!    therefore carries a monotonic deadline instant, and a credential whose
//!    deadline has already been reached refuses to be attached at all.
//! 3. **Fail-closed reconnection.** An invalid source does not merely fail the
//!    next read: it *prevents* reconnection. There is no freshness-only path and
//!    no fallback to the previously read token. Expired and too-short material
//!    lands in that same closed invalid state, so the bounded invalid-source
//!    retry (plus the watcher wakeup on replacement material) is what avoids a
//!    hot loop — never a floor that admits the stale token anyway.
//!
//! File reads are serialized by the one-permit semaphore, but publication is
//! deliberately *not* done while that permit is held (the watch send lock must
//! not nest with the reader slot or the commit-admission read guard, and the
//! watch lock must never be held across `.await`). The reconnect path can
//! therefore finish an older read, drop the permit, and be descheduled while
//! the watcher completes a newer read and publishes it. An internal monotonic
//! **read epoch** is stamped the moment a caller becomes the serialized
//! reader; [`StockCredentialWatch::publish_observed`] then refuses any
//! observation whose epoch is not strictly newer than the last completed read.
//! An older valid token cannot resurrect past a newer valid replacement or a
//! newer invalidation, and the reconnect path will not bind a connection fence
//! or open an ADS RPC with material that already lost.
//!
//! Nothing here ever logs, metrics, or otherwise renders token bytes, decoded
//! claims, the configured path, a digest of any of them, or the internal read
//! epoch. The content fingerprint exists solely for in-process equality and is
//! never exposed.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime};

use tokio::sync::{Semaphore, watch};
use tonic::metadata::MetadataValue;
use tracing::{info, warn};

use super::stream_lifecycle::MeshConfigStreamCredential;
use crate::secrets::credential_file::{
    CredentialFileError, CredentialTrim, DEFAULT_CREDENTIAL_FILE_MAX_BYTES,
    read_credential_file_detached_guarded,
};

pub type BearerToken = MetadataValue<tonic::metadata::Ascii>;

/// Bound the complete stock bearer-token admission attempt, including waiting
/// for an earlier timed-out reader to leave the kernel.
pub const STOCK_XDS_TOKEN_FILE_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// A timed-out mount read may keep its detached OS thread blocked. The permit
/// moves into that thread, so repeated ADS reconnects and watcher polls cannot
/// accumulate more blocked readers while the same credential source remains
/// unavailable.
static STOCK_XDS_TOKEN_FILE_READ_LIMIT: std::sync::OnceLock<Arc<Semaphore>> =
    std::sync::OnceLock::new();

pub(crate) fn stock_xds_token_file_read_limit() -> Arc<Semaphore> {
    Arc::clone(STOCK_XDS_TOKEN_FILE_READ_LIMIT.get_or_init(|| Arc::new(Semaphore::new(1))))
}

/// Monotonic identity of one completed serialized credential read.
///
/// Assigned when a caller acquires the one-reader permit — the same order the
/// authoritative file reads complete — and consumed at publication so a
/// delayed older result cannot overwrite a newer one. The numeric value is
/// never logged, exported, or rendered on an admin surface.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StockCredentialReadEpoch(u64);

impl StockCredentialReadEpoch {
    fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Debug for StockCredentialReadEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StockCredentialReadEpoch(<redacted>)")
    }
}

/// Process-wide counter shared by the serialized reader and by synthetic test
/// publications. It exists only to totally-order completed reads; the value
/// is never an authorization input.
static STOCK_XDS_CREDENTIAL_READ_EPOCH: AtomicU64 = AtomicU64::new(0);

fn alloc_read_epoch() -> StockCredentialReadEpoch {
    StockCredentialReadEpoch(STOCK_XDS_CREDENTIAL_READ_EPOCH.fetch_add(1, Ordering::AcqRel) + 1)
}

/// Longest JWT segment this decoder will look at.
///
/// A bearer is already capped at 64 KiB by the credential reader; this bounds
/// the *parsing* work on a value that is untrusted input from an external
/// issuer. Anything larger simply has no `exp` hint. It also bounds the
/// decoded payload handed to the JSON parser: unpadded base64url of at most
/// 8 KiB decodes to at most 6 KiB.
const MAX_JWT_SEGMENT_BYTES: usize = 8 * 1024;

/// In-process content identity of a bearer credential.
///
/// SHA-256 of the trimmed token bytes. Used ONLY to answer "is this the same
/// credential I connected with" without retaining a second copy of the secret
/// for comparison. It is never logged, exported, exposed on an admin surface,
/// or used as an authorization input — a digest of a secret is still an offline
/// oracle for it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StockCredentialFingerprint([u8; 32]);

impl StockCredentialFingerprint {
    fn of(raw_token: &str) -> Self {
        Self(crate::fips::approved::Sha256::digest(raw_token.as_bytes()))
    }
}

impl std::fmt::Debug for StockCredentialFingerprint {
    /// Deliberately opaque: a fingerprint that reaches a `Debug` log line is
    /// still credential-derived material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StockCredentialFingerprint(<redacted>)")
    }
}

/// Closed set of reasons a configured credential source is unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockCredentialInvalidReason {
    /// The configured pathname does not exist, or a projected symlink's target
    /// is missing.
    Missing,
    /// The opened target is not a regular file.
    NotRegularFile,
    /// Open/read failed for another reason.
    Unreadable,
    /// Empty after trimming.
    Empty,
    /// Exceeds the credential-file ceiling.
    Oversized,
    /// Not valid UTF-8.
    InvalidEncoding,
    /// Valid UTF-8 but not admissible as ASCII gRPC metadata.
    NotAsciiMetadata,
    /// The bounded read did not complete in time.
    ReadTimeout,
    /// The shared reader permit could not be acquired (shutdown).
    ReaderUnavailable,
    /// A JWT-shaped token whose locally decoded `exp` is already in the past
    /// — including Unix epoch zero and negative NumericDate values — or whose
    /// issuer's clock is far enough ahead of this node's that it reads that
    /// way. Refused outright: opening an authenticated stream with it would
    /// be knowingly presenting expired material.
    Expired,
    /// A JWT-shaped token that is not yet expired but cannot leave a positive
    /// pre-expiry window once the configured refresh skew is subtracted. Using
    /// it would schedule the reconnect at or after `exp`.
    ExpiresWithinSkew,
    /// The credential's absolute local authorization deadline was already
    /// reached before it could be attached to a streaming RPC — for example
    /// because dialing the control plane took longer than the token's remaining
    /// lifetime. The stream is refused rather than opened past the deadline.
    DeadlineReached,
}

impl StockCredentialInvalidReason {
    /// Fixed-cardinality label. Never carries the path or the credential.
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::Missing => "token_source_missing",
            Self::NotRegularFile => "token_source_not_regular_file",
            Self::Unreadable => "token_source_unreadable",
            Self::Empty => "token_source_empty",
            Self::Oversized => "token_source_oversized",
            Self::InvalidEncoding => "token_source_invalid_encoding",
            Self::NotAsciiMetadata => "token_source_not_ascii_metadata",
            Self::ReadTimeout => "token_source_read_timeout",
            Self::ReaderUnavailable => "token_reader_unavailable",
            Self::Expired => "token_expired",
            Self::ExpiresWithinSkew => "token_expires_within_skew",
            Self::DeadlineReached => "token_deadline_reached",
        }
    }

    fn from_credential_file_error(error: &CredentialFileError) -> Self {
        match error {
            CredentialFileError::PathNotFound => Self::Missing,
            CredentialFileError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
                Self::Missing
            }
            CredentialFileError::Io(_) => Self::Unreadable,
            CredentialFileError::NotRegularFile => Self::NotRegularFile,
            CredentialFileError::Oversized { .. } => Self::Oversized,
            CredentialFileError::InvalidUtf8 => Self::InvalidEncoding,
            CredentialFileError::Empty => Self::Empty,
            // A caller-side limit misconfiguration is impossible here (the
            // ceiling is a constant), but treat it as an unusable source rather
            // than silently succeeding.
            CredentialFileError::InvalidLimit { .. } => Self::Unreadable,
        }
    }
}

impl std::fmt::Display for StockCredentialInvalidReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_metric_label())
    }
}

impl std::error::Error for StockCredentialInvalidReason {}

/// What the last completed observation of the configured source found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockCredentialState {
    /// No `FERRUM_MESH_STOCK_XDS_TOKEN_FILE` is configured; the stream carries
    /// no `authorization` metadata at all.
    NotConfigured,
    /// Configured but not yet observed. Reconnection proceeds — the connect
    /// path performs its own authoritative read and publishes the result.
    Unknown,
    Valid {
        fingerprint: StockCredentialFingerprint,
    },
    Invalid {
        reason: StockCredentialInvalidReason,
    },
}

impl StockCredentialState {
    pub fn is_invalid(self) -> bool {
        matches!(self, Self::Invalid { .. })
    }

    /// Health projection for the authenticated `/health` mesh detail.
    pub fn health(self) -> MeshConfigStreamCredential {
        match self {
            Self::NotConfigured => MeshConfigStreamCredential::NotConfigured,
            // An unobserved configured source is not yet a failure, but it is
            // not proof of validity either — and it is emphatically NOT
            // "not configured", which would tell the operator their own
            // configured token file is absent.
            Self::Unknown => MeshConfigStreamCredential::Unobserved,
            Self::Valid { .. } => MeshConfigStreamCredential::Valid,
            Self::Invalid { .. } => MeshConfigStreamCredential::SourceInvalid,
        }
    }
}

/// One published observation. `generation` advances only when `state` actually
/// changes, so an unchanged token never churns the ADS stream.
///
/// `read_epoch` is the internal total order of completed serialized reads. It
/// is omitted from [`Debug`] and is never a log, metric, or admin field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StockCredentialObservation {
    pub generation: u64,
    pub state: StockCredentialState,
    read_epoch: u64,
}

impl std::fmt::Debug for StockCredentialObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StockCredentialObservation")
            .field("generation", &self.generation)
            .field("state", &self.state)
            .finish()
    }
}

/// Result of publishing one observation into [`StockCredentialWatch`].
///
/// `Accepted` means this material is still the newest authoritative
/// observation (or an older read of the *same* material, which must not churn).
/// `Superseded` means a newer completed read already won; the caller must not
/// bind a fence or open a stream with the losing material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockCredentialPublish {
    Accepted {
        generation: u64,
        generation_changed: bool,
    },
    Superseded {
        state: StockCredentialState,
        generation: u64,
    },
}

impl StockCredentialPublish {
    pub fn generation_changed(self) -> bool {
        matches!(
            self,
            Self::Accepted {
                generation_changed: true,
                ..
            }
        )
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted { .. })
    }
}

/// Shared change-detection channel for the configured credential source.
///
/// Both the watcher task and the connect path publish into it. Publication is
/// last-completed-read, not last-started: each serialized read carries a
/// monotonic epoch stamped under the one-reader permit, and an observation
/// whose epoch is older than the last completed read is dropped rather than
/// resurrecting stale material. Unchanged content still does not consume a
/// generation, so an unchanged token never churns the ADS stream.
#[derive(Clone)]
pub struct StockCredentialWatch {
    tx: Arc<watch::Sender<StockCredentialObservation>>,
    rx: watch::Receiver<StockCredentialObservation>,
}

impl StockCredentialWatch {
    pub fn new(initial: StockCredentialState) -> Self {
        let (tx, rx) = watch::channel(StockCredentialObservation {
            generation: 0,
            state: initial,
            read_epoch: 0,
        });
        Self {
            tx: Arc::new(tx),
            rx,
        }
    }

    pub fn receiver(&self) -> watch::Receiver<StockCredentialObservation> {
        self.rx.clone()
    }

    pub fn latest(&self) -> StockCredentialObservation {
        *self.rx.borrow()
    }

    /// Publish a synthetic observation that is newer than every completed
    /// read so far. Returns `true` when the state changed and a generation
    /// was consumed.
    ///
    /// Production watcher and connect paths must use
    /// [`Self::publish_observed`] with the epoch from the serialized read.
    /// This helper exists for tests that inject a state without going through
    /// the reader.
    pub fn publish(&self, state: StockCredentialState) -> bool {
        self.publish_observed(Some(alloc_read_epoch()), state)
            .generation_changed()
    }

    /// Publish an observation derived from a serialized read.
    ///
    /// Runs under the watch send lock with no `.await`. An epoch that is not
    /// strictly newer than the last completed read cannot change `state`; if
    /// the losing material still matches the current observation the publish
    /// is treated as accepted (unchanged-token no-churn), otherwise it is
    /// superseded. A missing epoch is a non-authoritative attempt (timed out
    /// before acquiring the reader permit) and never overwrites.
    pub fn publish_observed(
        &self,
        epoch: Option<StockCredentialReadEpoch>,
        state: StockCredentialState,
    ) -> StockCredentialPublish {
        let Some(epoch) = epoch else {
            let current = self.latest();
            return StockCredentialPublish::Superseded {
                state: current.state,
                generation: current.generation,
            };
        };
        let mut result = StockCredentialPublish::Superseded {
            state,
            generation: 0,
        };
        self.tx.send_if_modified(|current| {
            if epoch.as_u64() <= current.read_epoch {
                result = if current.state == state {
                    StockCredentialPublish::Accepted {
                        generation: current.generation,
                        generation_changed: false,
                    }
                } else {
                    StockCredentialPublish::Superseded {
                        state: current.state,
                        generation: current.generation,
                    }
                };
                return false;
            }
            current.read_epoch = epoch.as_u64();
            if current.state == state {
                result = StockCredentialPublish::Accepted {
                    generation: current.generation,
                    generation_changed: false,
                };
                return false;
            }
            current.generation = current.generation.saturating_add(1);
            current.state = state;
            result = StockCredentialPublish::Accepted {
                generation: current.generation,
                generation_changed: true,
            };
            true
        });
        result
    }

    /// Admit a serialized read as the current observation, or report the
    /// newer observation that already won.
    ///
    /// On `Ok(generation)` the caller may bind a connection fence to that
    /// generation — captured under the send lock, so it cannot be a later
    /// observation's generation while this material is older. On `Err` the
    /// caller must refuse to dial or open with the losing material.
    pub fn admit_observation(
        &self,
        epoch: Option<StockCredentialReadEpoch>,
        state: StockCredentialState,
    ) -> Result<u64, StockCredentialState> {
        match self.publish_observed(epoch, state) {
            StockCredentialPublish::Accepted { generation, .. } => Ok(generation),
            StockCredentialPublish::Superseded { state, .. } => Err(state),
        }
    }
}

/// Operator-visible lifetime policy for a stock bearer-authenticated stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockCredentialLifetimePolicy {
    /// `FERRUM_MESH_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECONDS`. The finite,
    /// documented maximum authenticated stream lifetime. Applies to opaque
    /// tokens and also caps any JWT-derived deadline.
    pub max_stream_lifetime: Duration,
    /// `FERRUM_MESH_STOCK_XDS_TOKEN_REFRESH_SKEW_SECONDS`. How far before a
    /// JWT-shaped token's `exp` the stream is retired.
    pub refresh_skew: Duration,
    /// `FERRUM_MESH_STOCK_XDS_TOKEN_WATCH_INTERVAL_SECONDS`. Credential-source
    /// re-read cadence.
    pub watch_interval: Duration,
}

impl Default for StockCredentialLifetimePolicy {
    fn default() -> Self {
        Self {
            max_stream_lifetime: Duration::from_secs(
                DEFAULT_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS,
            ),
            refresh_skew: Duration::from_secs(DEFAULT_STOCK_XDS_TOKEN_REFRESH_SKEW_SECS),
            watch_interval: Duration::from_secs(DEFAULT_STOCK_XDS_TOKEN_WATCH_INTERVAL_SECS),
        }
    }
}

pub const DEFAULT_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS: u64 = 3600;
pub const DEFAULT_STOCK_XDS_TOKEN_REFRESH_SKEW_SECS: u64 = 60;
pub const DEFAULT_STOCK_XDS_TOKEN_WATCH_INTERVAL_SECS: u64 = 10;
/// Lowest maximum stream lifetime an OPERATOR may configure. Below this the
/// reconnect cadence is itself the availability problem, so
/// `FERRUM_MESH_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECONDS` is refused at
/// configuration admission (`MeshRuntimeConfig::from_env_config`) rather than
/// silently rounded up.
pub const MIN_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS: u64 = 60;
/// Highest admissible maximum stream lifetime (24h). Enforced BOTH at
/// configuration admission and in code: this is the bound that makes an opaque
/// bearer's authorization lifetime finite, so it may never be bypassed.
pub const MAX_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS: u64 = 86_400;
/// Absolute in-code floor. Not an operator-facing knob — it only stops a
/// programmatically constructed policy of `0` from producing an
/// already-elapsed deadline. The operator-facing floor is
/// [`MIN_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS`], enforced when the env var
/// is parsed, and hosted tests use the gap between the two to prove the
/// opaque-token deadline live without sleeping for a production minute.
const ABSOLUTE_MAX_STREAM_LIFETIME_FLOOR: Duration = Duration::from_secs(1);
/// When `refresh_skew` is zero, pull a JWT-shaped stream deadline this far
/// before `exp` so the next attempt can still admit the same not-yet-expired
/// token. This is a scheduling slack, not a refusal threshold: a token whose
/// remaining window is already this small keeps that short deadline, matching
/// the "do not clamp a short JWT up" rule. Operator skew already supplies a
/// reconnect window when it is set, so slack is not stacked on top of it.
const JWT_ZERO_SKEW_RECONNECT_SLACK: Duration = Duration::from_secs(1);

/// The configured credential source plus its lifetime policy.
#[derive(Clone, PartialEq, Eq)]
pub struct StockXdsCredentialSource {
    /// `None` sends no `authorization` metadata at all.
    path: Option<String>,
    policy: StockCredentialLifetimePolicy,
}

impl std::fmt::Debug for StockXdsCredentialSource {
    /// The pathname is credential metadata. An otherwise innocent `Debug`
    /// rendering of this source — or of `StockXdsClientConfig`, which embeds
    /// it — must never print it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StockXdsCredentialSource")
            .field("configured", &self.path.is_some())
            .field("policy", &self.policy)
            .finish()
    }
}

impl StockXdsCredentialSource {
    pub fn new(path: Option<String>, policy: StockCredentialLifetimePolicy) -> Self {
        Self { path, policy }
    }

    // Constructed by the external mesh stock-xDS test suites, which drive the
    // production client with no bearer configured. The binary target has no
    // downstream consumer, so the accessor is dead there by construction.
    #[allow(dead_code)]
    pub fn unauthenticated() -> Self {
        Self {
            path: None,
            policy: StockCredentialLifetimePolicy::default(),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.path.is_some()
    }

    pub fn policy(&self) -> StockCredentialLifetimePolicy {
        self.policy
    }

    pub fn initial_state(&self) -> StockCredentialState {
        if self.path.is_some() {
            StockCredentialState::Unknown
        } else {
            StockCredentialState::NotConfigured
        }
    }

    /// Read and admit the configured credential.
    ///
    /// `Ok(None)` means no credential is configured. Everything else is either
    /// a usable credential or a closed-set invalidity reason — there is no
    /// "keep the previous token" path.
    pub async fn materialize(
        &self,
    ) -> Result<Option<StockBearerCredential>, StockCredentialInvalidReason> {
        self.observe().await.into_outcome()
    }

    /// Read and admit the configured credential, retaining the serialized-read
    /// epoch so publication can preserve last-completed-read order.
    pub async fn observe(&self) -> StockCredentialRead {
        let Some(path) = self.path.as_deref() else {
            return StockCredentialRead {
                epoch: Some(alloc_read_epoch()),
                outcome: Ok(None),
            };
        };
        let (epoch, raw) = read_stock_bearer_token_raw(path).await;
        let outcome = match raw {
            Ok(token) => StockBearerCredential::admit(&token, self.policy).map(Some),
            Err(reason) => Err(reason),
        };
        StockCredentialRead { epoch, outcome }
    }
}

/// One serialized credential-source read, with the epoch stamped when this
/// caller became the single reader (or `None` if it never acquired the permit).
///
/// The epoch is omitted from [`Debug`]. Token bytes live only inside
/// [`StockBearerCredential`], whose own `Debug` is redacted.
pub struct StockCredentialRead {
    epoch: Option<StockCredentialReadEpoch>,
    outcome: Result<Option<StockBearerCredential>, StockCredentialInvalidReason>,
}

impl StockCredentialRead {
    pub fn epoch(&self) -> Option<StockCredentialReadEpoch> {
        self.epoch
    }

    pub fn into_outcome(
        self,
    ) -> Result<Option<StockBearerCredential>, StockCredentialInvalidReason> {
        self.outcome
    }

    pub fn observed_state(&self) -> StockCredentialState {
        match &self.outcome {
            Ok(Some(credential)) => credential.observed_state(),
            Ok(None) => StockCredentialState::NotConfigured,
            Err(reason) => StockCredentialState::Invalid { reason: *reason },
        }
    }
}

impl std::fmt::Debug for StockCredentialRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StockCredentialRead")
            .field("authoritative", &self.epoch.is_some())
            .field("state", &self.observed_state())
            .finish()
    }
}

/// Why a credential-driven stream deadline was chosen. Fixed cardinality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockCredentialDeadlineBasis {
    /// Locally decoded JWT `exp`, minus the configured skew. A *scheduling
    /// hint*, never an authorization decision.
    JwtExpirationHint,
    /// The operator-visible maximum authenticated stream lifetime.
    MaxStreamLifetime,
}

impl StockCredentialDeadlineBasis {
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::JwtExpirationHint => "jwt_exp_hint",
            Self::MaxStreamLifetime => "max_stream_lifetime",
        }
    }
}

/// A materialized, admitted bearer credential with a finite local
/// authorization lifetime.
pub struct StockBearerCredential {
    token: BearerToken,
    fingerprint: StockCredentialFingerprint,
    lifetime: Duration,
    /// ABSOLUTE monotonic deadline, stamped at admission. Connect latency,
    /// TLS handshake, and RPC setup all consume it rather than extend it.
    deadline: tokio::time::Instant,
    basis: StockCredentialDeadlineBasis,
}

impl StockBearerCredential {
    /// Build the `authorization` metadata value, the content fingerprint, and
    /// the absolute local authorization deadline for one raw token.
    ///
    /// Fails closed for a JWT-shaped token that is already past `exp` —
    /// including Unix epoch zero and negative NumericDate values — or that
    /// cannot leave a positive pre-expiry window after the configured skew.
    /// Also fails closed when the raw token is not ASCII: tonic/`http`
    /// `HeaderValue` admits obs-text bytes (128–255), which must never become
    /// gRPC bearer metadata. The refusal is the closed-set
    /// [`StockCredentialInvalidReason::NotAsciiMetadata`] and never renders
    /// token bytes.
    pub fn admit(
        raw_token: &str,
        policy: StockCredentialLifetimePolicy,
    ) -> Result<Self, StockCredentialInvalidReason> {
        // Explicit ASCII boundary BEFORE constructing metadata. `str::parse`
        // into `MetadataValue<Ascii>` is not this gate: HTTP header values
        // historically allow opaque high bytes, so a UTF-8 token such as
        // `tökén` would otherwise be attached.
        if !raw_token.is_ascii() {
            return Err(StockCredentialInvalidReason::NotAsciiMetadata);
        }
        let token: BearerToken = format!("Bearer {raw_token}")
            .parse()
            // The parse error would echo the token, so it is deliberately
            // dropped and replaced with a closed-set reason. Survives as
            // defense in depth for ASCII-but-not-metadata values (NUL, DEL).
            .map_err(|_| StockCredentialInvalidReason::NotAsciiMetadata)?;
        let fingerprint = StockCredentialFingerprint::of(raw_token);
        // Both clocks are read at the SAME point so the wall-clock `exp`
        // arithmetic and the monotonic deadline describe one instant.
        let admitted_at = tokio::time::Instant::now();
        let (lifetime, basis) = credential_lifetime(raw_token, policy, SystemTime::now())?;
        Ok(Self {
            token,
            fingerprint,
            lifetime,
            deadline: admitted_at + lifetime,
            basis,
        })
    }

    pub fn token(&self) -> &BearerToken {
        &self.token
    }

    /// The in-process content identity. Read by the external credential tests
    /// to prove a rotation is observed as a CONTENT change (production compares
    /// through `observed_state`), so it is dead in the binary target.
    #[allow(dead_code)]
    pub fn fingerprint(&self) -> StockCredentialFingerprint {
        self.fingerprint
    }

    /// The authorization lifetime granted at ADMISSION. Observability only —
    /// the enforced value is [`Self::deadline`], which does not move.
    pub fn lifetime(&self) -> Duration {
        self.lifetime
    }

    /// The absolute monotonic instant at which this stream must be retired.
    pub fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    /// True once the absolute deadline has been reached. Checked before the
    /// credential is attached to a streaming RPC so connect latency can never
    /// buy time past `exp`.
    pub fn deadline_reached(&self) -> bool {
        tokio::time::Instant::now() >= self.deadline
    }

    pub fn deadline_basis(&self) -> StockCredentialDeadlineBasis {
        self.basis
    }

    pub fn observed_state(&self) -> StockCredentialState {
        StockCredentialState::Valid {
            fingerprint: self.fingerprint,
        }
    }
}

impl std::fmt::Debug for StockBearerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StockBearerCredential")
            .field("token", &"<redacted>")
            .field("lifetime_secs", &self.lifetime.as_secs())
            .field("basis", &self.basis.as_metric_label())
            .finish()
    }
}

/// Resolve the finite authorization lifetime for one raw token.
///
/// Exposed for external tests so the JWT-hint / opaque-bound split, the skew,
/// the maximum-lifetime cap, and the fail-closed expiry handling are all
/// provable without a control plane.
///
/// The returned duration is measured from `now`. There is NO floor: a JWT whose
/// usable window is empty is an error, not a short lifetime. Clamping it upward
/// would schedule the retirement after `exp` and knowingly hold an
/// authenticated stream open with expired material — the exact defect
/// issue #3852 is about.
pub fn credential_lifetime(
    raw_token: &str,
    policy: StockCredentialLifetimePolicy,
    now: SystemTime,
) -> Result<(Duration, StockCredentialDeadlineBasis), StockCredentialInvalidReason> {
    let opaque = clamp_max_stream_lifetime(policy.max_stream_lifetime);
    let Some(exp) = jwt_expiration_hint(raw_token) else {
        // Opaque (or non-JWS, or `exp`-less / non-numeric `exp`) material:
        // there is no local hint at all, so the operator-visible finite
        // maximum is the whole policy.
        return Ok((opaque, StockCredentialDeadlineBasis::MaxStreamLifetime));
    };
    // Unix epoch zero and negative NumericDate values are plainly expired.
    // They must not be treated as "no hint" (which would grant the opaque
    // maximum) and must not be cast to `u64` (which would wrap into a
    // far-future deadline).
    if exp <= 0 {
        return Err(StockCredentialInvalidReason::Expired);
    }
    let Some(exp_at) = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(exp as u64)) else {
        // A positive NumericDate that cannot be represented as `SystemTime`
        // is not a usable scheduling hint.
        return Ok((opaque, StockCredentialDeadlineBasis::MaxStreamLifetime));
    };
    // The decode is NOT authorization proof. It is only ever used to make the
    // deadline EARLIER than it would otherwise be, or to refuse outright.
    let Ok(remaining) = exp_at.duration_since(now) else {
        return Err(StockCredentialInvalidReason::Expired);
    };
    // Remaining wall-clock lifetime of zero (exact-at-`exp`) is already
    // expired. A *positive* lifetime that the refresh skew then consumes is
    // the distinct `ExpiresWithinSkew` case. Do not collapse the two: a
    // token that has no remaining lifetime must never attach.
    if remaining.is_zero() {
        return Err(StockCredentialInvalidReason::Expired);
    }
    let before_exp = remaining.saturating_sub(policy.refresh_skew);
    if before_exp.is_zero() {
        return Err(StockCredentialInvalidReason::ExpiresWithinSkew);
    }
    // A zero-skew policy would otherwise schedule retirement *at* `exp`. The
    // next attempt then sees remaining == 0 and fail-closed refuses the same
    // still-current token, so no second RPC is ever opened. Pull the deadline
    // forward only when there is slack to spend; do not refuse a shorter JWT.
    let scheduled = if policy.refresh_skew.is_zero() && before_exp > JWT_ZERO_SKEW_RECONNECT_SLACK {
        before_exp - JWT_ZERO_SKEW_RECONNECT_SLACK
    } else {
        before_exp
    };
    Ok((
        scheduled.min(opaque),
        StockCredentialDeadlineBasis::JwtExpirationHint,
    ))
}

/// Keep the configured maximum stream lifetime finite and non-zero.
///
/// The upper bound is the security property (an opaque bearer must not hold a
/// stream indefinitely) and is enforced unconditionally. The lower bound here is
/// only the absolute floor that prevents a zero-length deadline; the
/// operator-facing 60s minimum is enforced where the operator sets it.
fn clamp_max_stream_lifetime(configured: Duration) -> Duration {
    configured
        .max(ABSOLUTE_MAX_STREAM_LIFETIME_FLOOR)
        .min(Duration::from_secs(
            MAX_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS,
        ))
}

#[derive(serde::Deserialize)]
struct JwtExpClaim {
    /// RFC 7519 NumericDate as the exact JSON lexeme. A present JSON number —
    /// integer, fractional, or exponent form — is floored to whole seconds.
    /// Any other shape is simply "no hint".
    exp: Option<Box<serde_json::value::RawValue>>,
}

/// Bounded, **non-verifying** local decode of a JWT-shaped token's `exp`.
///
/// This is a reconnect *scheduling hint* only. The signature is not checked,
/// the issuer/audience are not checked, and no other claim is read or retained.
///
/// `None` means the token is not a three-segment JWS or the payload has no
/// usable NumericDate `exp` (malformed, oversized, missing, a non-number
/// shape, or a positive value that cannot be represented as `i64`).
/// [`credential_lifetime`] treats that as opaque.
///
/// `Some(n)` is the conservative whole-second floor of the payload's
/// NumericDate, including zero, negative, and fractional values. A fractional
/// JSON number is floored (never rounded up) so the scheduled deadline cannot
/// fall after the mathematical expiration. Zero, negative, and negative
/// fractional values are already expired (Unix epoch zero and earlier) and
/// must never be collapsed into "no hint". This function does not convert the
/// NumericDate into a `SystemTime` or a `Duration`, so a negative value cannot
/// wrap or panic here.
pub fn jwt_expiration_hint(raw_token: &str) -> Option<i64> {
    use base64::Engine as _;

    let mut segments = raw_token.split('.');
    let _header = segments.next()?;
    let payload = segments.next()?;
    let signature = segments.next()?;
    // Exactly three segments, all non-empty: anything else is not a JWS.
    if segments.next().is_some() || payload.is_empty() || signature.is_empty() {
        return None;
    }
    if payload.len() > MAX_JWT_SEGMENT_BYTES {
        return None;
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claim: JwtExpClaim = serde_json::from_slice(&decoded).ok()?;
    numeric_date_floor_secs(claim.exp?.get())
}

/// Conservative whole-second floor of an RFC 7519 NumericDate JSON number.
///
/// The lexeme is preserved (via [`serde_json::value::RawValue`]) so this never
/// parses through `f64`, which cannot represent every integer above 2^53 and
/// can round a fraction upward across a second boundary. In-range integers
/// keep their exact value. Unrepresentable positive magnitudes yield `None`
/// (the opaque cap still applies). Unrepresentable negative magnitudes yield
/// [`i64::MIN`], which remains expired rather than opaque.
fn numeric_date_floor_secs(lexeme: &str) -> Option<i64> {
    let first = *lexeme.as_bytes().first()?;
    if first != b'-' && !first.is_ascii_digit() {
        return None;
    }
    if is_json_integer_lexeme(lexeme) {
        return match lexeme.parse::<i64>() {
            Ok(value) => Some(value),
            Err(_) if first == b'-' => Some(i64::MIN),
            Err(_) => None,
        };
    }
    floor_json_number_to_i64(parse_json_number_lexeme(lexeme)?)
}

fn is_json_integer_lexeme(lexeme: &str) -> bool {
    let bytes = lexeme.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let digits = match bytes[0] {
        b'-' => {
            if bytes.len() == 1 {
                return false;
            }
            &bytes[1..]
        }
        _ => bytes,
    };
    digits.iter().all(u8::is_ascii_digit)
}

struct JsonNumber<'a> {
    negative: bool,
    int_digits: &'a [u8],
    frac_digits: &'a [u8],
    exponent: i32,
}

fn parse_json_number_lexeme(lexeme: &str) -> Option<JsonNumber<'_>> {
    let bytes = lexeme.as_bytes();
    let mut i = 0usize;
    let negative = if bytes.first().copied() == Some(b'-') {
        i = 1;
        true
    } else {
        false
    };
    if i >= bytes.len() {
        return None;
    }

    let int_start = i;
    if bytes[i] == b'0' {
        i += 1;
    } else if bytes[i].is_ascii_digit() {
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    } else {
        return None;
    }
    let int_digits = &bytes[int_start..i];
    if int_digits.is_empty() {
        return None;
    }

    let frac_digits = if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        let frac_start = i;
        if i >= bytes.len() || !bytes[i].is_ascii_digit() {
            return None;
        }
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        &bytes[frac_start..i]
    } else {
        &[]
    };

    let mut exponent = 0i32;
    if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
        i += 1;
        if i >= bytes.len() {
            return None;
        }
        let exp_negative = match bytes[i] {
            b'-' => {
                i += 1;
                true
            }
            b'+' => {
                i += 1;
                false
            }
            _ => false,
        };
        if i >= bytes.len() || !bytes[i].is_ascii_digit() {
            return None;
        }
        let exp_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        exponent = parse_json_exponent(&bytes[exp_start..i], exp_negative)?;
    }

    if i != bytes.len() {
        return None;
    }

    Some(JsonNumber {
        negative,
        int_digits,
        frac_digits,
        exponent,
    })
}

fn parse_json_exponent(digits: &[u8], negative: bool) -> Option<i32> {
    if digits.is_empty() {
        return None;
    }
    // Nine digits always fit in i32. Longer exponents are saturated to a
    // magnitude that already overflows any i64 second count.
    if digits.len() > 9 {
        return Some(if negative {
            -1_000_000_000
        } else {
            1_000_000_000
        });
    }
    let mut value = 0i32;
    for &digit in digits {
        value = value
            .checked_mul(10)?
            .checked_add(i32::from(digit - b'0'))?;
    }
    if negative { Some(-value) } else { Some(value) }
}

fn floor_json_number_to_i64(number: JsonNumber<'_>) -> Option<i64> {
    let JsonNumber {
        negative,
        int_digits,
        frac_digits,
        exponent,
    } = number;

    if digits_all_zero(int_digits) && digits_all_zero(frac_digits) {
        return Some(0);
    }

    let int_len = i64::try_from(int_digits.len()).ok()?;
    let point = int_len.checked_add(i64::from(exponent))?;
    if point <= 0 {
        return Some(if negative { -1 } else { 0 });
    }

    let sig_len = int_digits.len() + frac_digits.len();
    let Ok(point_us) = usize::try_from(point) else {
        return overflow_numeric_date_hint(negative);
    };

    let (prefix_len, trailing_zeros, has_remainder) = if point_us >= sig_len {
        (sig_len, point_us - sig_len, false)
    } else {
        (
            point_us,
            0,
            significand_has_nonzero(int_digits, frac_digits, point_us),
        )
    };

    let Some(magnitude) =
        parse_u64_significand_prefix(int_digits, frac_digits, prefix_len, trailing_zeros)
    else {
        return overflow_numeric_date_hint(negative);
    };
    signed_floor(negative, magnitude, has_remainder)
}

fn overflow_numeric_date_hint(negative: bool) -> Option<i64> {
    if negative { Some(i64::MIN) } else { None }
}

fn digits_all_zero(digits: &[u8]) -> bool {
    digits.iter().all(|&digit| digit == b'0')
}

fn significand_digit(int_digits: &[u8], frac_digits: &[u8], index: usize) -> Option<u8> {
    if index < int_digits.len() {
        Some(int_digits[index])
    } else {
        frac_digits.get(index - int_digits.len()).copied()
    }
}

fn significand_has_nonzero(int_digits: &[u8], frac_digits: &[u8], from: usize) -> bool {
    let len = int_digits.len() + frac_digits.len();
    (from..len).any(|index| significand_digit(int_digits, frac_digits, index) != Some(b'0'))
}

fn parse_u64_significand_prefix(
    int_digits: &[u8],
    frac_digits: &[u8],
    prefix_len: usize,
    trailing_zeros: usize,
) -> Option<u64> {
    // 10^20 already overflows u64 for any non-zero prefix.
    if trailing_zeros > 20 {
        return None;
    }
    let mut value = 0u64;
    let mut saw_nonzero = false;
    for index in 0..prefix_len {
        let digit = significand_digit(int_digits, frac_digits, index)?;
        if digit == b'0' && !saw_nonzero {
            continue;
        }
        saw_nonzero = true;
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(digit - b'0'))?;
    }
    if !saw_nonzero {
        return Some(0);
    }
    for _ in 0..trailing_zeros {
        value = value.checked_mul(10)?;
    }
    Some(value)
}

fn signed_floor(negative: bool, magnitude: u64, has_remainder: bool) -> Option<i64> {
    if !negative {
        return i64::try_from(magnitude).ok();
    }
    if magnitude == 0 {
        return Some(if has_remainder { -1 } else { 0 });
    }
    let Ok(positive) = i64::try_from(magnitude) else {
        // Includes 2^63 (i64::MIN) and every more-negative overflow.
        return Some(i64::MIN);
    };
    let negated = -positive;
    if has_remainder {
        Some(negated.saturating_sub(1))
    } else {
        Some(negated)
    }
}

/// Read the raw bearer token through the shared hardened credential boundary.
///
/// The whole attempt — including waiting behind an earlier timed-out reader —
/// is bounded by [`STOCK_XDS_TOKEN_FILE_READ_TIMEOUT`]. The open/read itself
/// runs on a detached OS thread that owns the permit, so a stalled mount can
/// never pin a Tokio worker and repeated attempts cannot accumulate blocked
/// readers.
///
/// The epoch is stamped immediately after the permit is acquired, before the
/// detached read is spawned, so it follows the same total order as the
/// serialized reads even if this future later times out. A timeout that fires
/// *before* the permit is acquired returns `None` for the epoch: that attempt
/// never became the authoritative reader and must not publish.
async fn read_stock_bearer_token_raw(
    path: &str,
) -> (
    Option<StockCredentialReadEpoch>,
    Result<String, StockCredentialInvalidReason>,
) {
    let stamped = Arc::new(AtomicU64::new(0));
    let stamp_slot = Arc::clone(&stamped);
    let path = path.to_string();
    let read = async move {
        let permit = stock_xds_token_file_read_limit()
            .acquire_owned()
            .await
            .map_err(|_| StockCredentialInvalidReason::ReaderUnavailable)?;
        let epoch = alloc_read_epoch();
        stamp_slot.store(epoch.as_u64(), Ordering::Release);
        read_credential_file_detached_guarded(
            &path,
            DEFAULT_CREDENTIAL_FILE_MAX_BYTES,
            CredentialTrim::Ends,
            "ferrum-stock-xds-token-file",
            permit,
        )
        .await
        .map_err(|error| StockCredentialInvalidReason::from_credential_file_error(&error))
    };
    let outcome = match tokio::time::timeout(STOCK_XDS_TOKEN_FILE_READ_TIMEOUT, read).await {
        Ok(result) => result,
        Err(_) => Err(StockCredentialInvalidReason::ReadTimeout),
    };
    let epoch = match stamped.load(Ordering::Acquire) {
        0 => None,
        n => Some(StockCredentialReadEpoch(n)),
    };
    (epoch, outcome)
}

/// Watch the configured credential source and publish content/validity changes.
///
/// Runs until shutdown and is joined with the other mesh background tasks.
/// Joining that async task does **not** join a timed-out detached OS reader: a
/// stalled mount can keep its OS thread blocked after the async timeout, and
/// that is intentional. The bounded invariant is the single global reader
/// permit, which moves into that thread so reconnects and later watcher polls
/// cannot accumulate more blocked readers.
///
/// It never publishes the credential itself — only the closed-set state and a
/// private content fingerprint — and it never widens the client's
/// authorization: a `Valid` observation is only permission to *attempt* a
/// connection, which then performs its own authoritative read. Publications
/// carry the serialized-read epoch so an older completed read cannot overwrite
/// a newer one.
pub async fn start_stock_credential_watcher_with_shutdown(
    source: StockXdsCredentialSource,
    watch_handle: StockCredentialWatch,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if !source.is_configured() {
        // Nothing to observe; park until shutdown so the join is uniform.
        super::common::wait_for_shutdown(&mut shutdown_rx).await;
        return;
    }
    let interval = source.policy().watch_interval.max(Duration::from_secs(1));
    info!(
        watch_interval_secs = %crate::startup::sanitize_startup_scalar(interval.as_secs()),
        max_stream_lifetime_secs = %crate::startup::sanitize_startup_scalar(
            clamp_max_stream_lifetime(source.policy().max_stream_lifetime).as_secs()
        ),
        refresh_skew_secs = %crate::startup::sanitize_startup_scalar(source.policy().refresh_skew.as_secs()),
        "Stock xDS bearer-credential watcher starting; ADS streams are retired when the source \
         rotates, becomes invalid, or reaches its authorization deadline"
    );

    let mut observed_valid_before = false;
    loop {
        let read = source.observe().await;
        let next_state = match read.observed_state() {
            // `is_configured()` was checked above, so `NotConfigured` is
            // unreachable; treat it as unusable rather than silently valid.
            StockCredentialState::NotConfigured => StockCredentialState::Invalid {
                reason: StockCredentialInvalidReason::Missing,
            },
            state => state,
        };
        let published = watch_handle.publish_observed(read.epoch(), next_state);
        if published.generation_changed() {
            match next_state {
                StockCredentialState::Invalid { reason } => warn!(
                    reason = reason.as_metric_label(),
                    "Stock xDS bearer-credential source became invalid; retiring the ADS stream \
                     and refusing reconnection until valid material is available"
                ),
                StockCredentialState::Valid { .. } if observed_valid_before => info!(
                    "Stock xDS bearer credential rotated; retiring the ADS stream and \
                     reconnecting with the replacement material"
                ),
                StockCredentialState::Valid { .. } => {
                    info!("Stock xDS bearer-credential source observed valid; ADS streams may open")
                }
                StockCredentialState::NotConfigured | StockCredentialState::Unknown => {}
            }
        }
        if published.accepted() {
            observed_valid_before |= matches!(next_state, StockCredentialState::Valid { .. });
        }

        tokio::select! {
            biased;
            _ = super::common::wait_for_shutdown(&mut shutdown_rx) => {
                info!("Stock xDS bearer-credential watcher shutting down");
                return;
            }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}
